//! USB HID transport, over `hidapi`.
//!
//! A Ledger speaks APDUs over 64-byte HID reports framed exactly as
//! [`crate::framing`] describes. This module is the I/O half of that: it finds
//! the device, picks a channel, writes the frames [`crate::framing::hid_frames`]
//! produces, and feeds input reports to a [`crate::framing::Deframer`] until
//! it yields a payload.
//!
//! # Interface selection
//!
//! A Ledger exposes several HID interfaces and only one carries APDUs. It is
//! identified by usage page [`LEDGER_HID_USAGE_PAGE`] (`0xFFA0`), which the
//! `hidapi` backend this crate builds with reports on every platform: on
//! Linux the default `linux-static-hidraw` backend parses the report
//! descriptor itself, out of sysfs, so the page is available there too (it is
//! the *libusb* backends that cannot report it). When no interface of any
//! attached Ledger advertises a usage page at all — a backend that cannot read
//! them — [`ledger_apdu_interfaces`] falls back to interface number `0`, the
//! APDU interface on every current model, and the test
//! `@ledgerhq/hw-transport-node-hid` makes unconditionally on Linux
//! (`filterInterface`: the usage page on Windows and macOS, `interface === 0`
//! elsewhere). The fallback is taken only when nothing advertises the page,
//! so it can never *prefer* the wrong interface.
//!
//! # Several devices
//!
//! With more than one Ledger attached, [`HidTransport::open_first`] opens the
//! first APDU interface the OS enumerates, and which device that belongs to
//! is not specified. A wallet that pairs and signs against a particular
//! device lists them with [`ledger_apdu_interfaces`], picks one — by serial
//! number, say — opens it with `DeviceInfo::open_device`, and wraps it with
//! [`HidTransport::from_device`]. The session's identity binding refuses to
//! *sign* on the wrong device; nothing binds a pairing, so the choice matters
//! most there.
//!
//! # Channel
//!
//! Each connection picks a random 2-byte channel, the convention every Ledger
//! host transport follows (`WebHidApduSender`:
//! `Math.floor(Math.random() * 0xffff)`). The device echoes it and
//! [`crate::framing::Deframer::hid`] checks it, so a reply belonging to another
//! host process on the same device — every process with the node open sees
//! every input report on Linux — is skipped rather than spliced in, and
//! rather than taken for a failure of this connection.
//!
//! The randomness comes from `RandomState`, which the standard library seeds
//! from the OS. The channel is a demultiplexing tag, not a secret — it protects
//! against confusion, not against an attacker — so this is the right strength
//! and it saves the crate a dependency on `rand`.
//!
//! # Timeouts and the review screen
//!
//! Two replies in a ceremony do not arrive until a human acts: the one to the
//! packet carrying `P2_PCZT_FINISHED`, and the one to each `PCZT_SIGN_*`
//! command that follows the approval. `hidapi`'s `read_timeout` takes `-1` for
//! "block", which is what [`Deadline::UserReview`] selects; every other exchange
//! runs under [`HidTransport::timeout`], which bounds the whole exchange — the
//! write and every read of the reply together, measured from before the first
//! report goes out — and fails with [`TransportError::Timeout`]. A budget
//! already spent when the exchange starts, which a zero timeout is, fails
//! before anything is written and leaves the link clean. A blocking read that returns with
//! no report at all — which `hidapi`'s Windows backend does for a device gone
//! away — is [`TransportError::ConnectionClosed`]. A review wait has no clock,
//! but it is not unbounded in every direction: an exchange that takes more
//! input reports than any reply could run to — another host process streaming
//! on the same device node — ends there, with [`TransportError::Io`].
//!
//! # Stale reports and poisoning
//!
//! The channel is fixed for the life of a connection, so the deframer cannot
//! tell a late reply to an earlier command from the reply to the current one.
//! Two rules keep them apart:
//!
//! - Before a command is written, every input report already waiting in the
//!   OS buffer is read and discarded. Those are the frames of a reply that
//!   arrived after its own exchange had given up, or the remainder of a reply
//!   whose reassembly was abandoned on a bad frame.
//! - An exchange that fails once its command is on the wire — a timeout, a
//!   frame that will not reassemble, an I/O error mid-reply — poisons the
//!   connection: the device still owes a reply, and it may arrive at any
//!   moment, including between the drain and the next write. Every later
//!   exchange answers [`TransportError::Poisoned`], and the recovery is a new
//!   connection, which starts with a fresh channel and an empty buffer.
//!
//! The drain handles what has already arrived; the poison handles what is
//! still on its way. Neither alone is enough.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::time::{Duration, Instant};

use hidapi::{DeviceInfo, HidApi, HidDevice};
use zeroize::Zeroizing;

use crate::framing::{hid_frames, Deframer, HidChannel, HID_FRAME_SIZE};
use crate::session::Deadline;
use crate::transport::{Transport, TransportError, DEFAULT_TIMEOUT};

/// Ledger's USB vendor id.
pub const LEDGER_USB_VENDOR_ID: u16 = 0x2C97;

/// HID usage page of the Ledger APDU interface.
///
/// A Ledger device exposes more than one HID interface; only the one with this
/// usage page carries APDUs.
pub const LEDGER_HID_USAGE_PAGE: u16 = 0xFFA0;

/// Interface number of the APDU interface, used only when no interface reports
/// a usage page (see the module docs).
const LEDGER_APDU_INTERFACE: i32 = 0;

/// The report-ID byte `hidapi` expects at the front of every write buffer.
///
/// Ledger devices use numbered-report-free output, so the ID is zero; the byte
/// is not part of the 64-byte frame.
const REPORT_ID: u8 = 0x00;

/// `hidapi`'s "block until a report arrives" timeout.
const READ_BLOCKING: i32 = -1;

/// `hidapi`'s "return at once" timeout: what is already in the OS buffer, or
/// nothing.
const READ_NON_BLOCKING: i32 = 0;

/// The most stale input reports the pre-command drain will discard.
///
/// The longest reply the Zcash app sends is a viewing-key chunk of a few
/// hundred bytes, under ten reports, so a buffer that is still yielding
/// reports after this many is not a Ledger's reply to anything; the drain
/// stops rather than spin on a device that streams unsolicited reports.
const MAX_STALE_REPORTS: usize = 1024;

/// The most input reports one exchange will take before its reply
/// reassembles.
///
/// A report tagged with another host process's channel is skipped rather than
/// refused — on Linux every process with the device node open sees every
/// input report — and under [`Deadline::UserReview`], which has no clock,
/// nothing else counts it, so a process streaming on the same node would
/// otherwise park the reply loop for ever. A Ledger's own reply cannot come
/// near this bound: the longest a frame 0 can declare is `u16::MAX` bytes,
/// which is 1111 reports, and the Zcash app's longest reply is a viewing-key
/// chunk of a few hundred bytes, under ten.
const MAX_REPLY_REPORTS: usize = 2048;

fn io(e: hidapi::HidError) -> TransportError {
    let kind = match &e {
        hidapi::HidError::IoError { error } => error.kind(),
        hidapi::HidError::HidApiError { message } => kind_from_message(message),
        _ => std::io::ErrorKind::Other,
    };
    TransportError::Io {
        kind,
        message: e.to_string(),
    }
}

/// Recovers an [`std::io::ErrorKind`] from the C `hidapi` backend's error
/// text.
///
/// The backends this crate builds with never produce `HidError::IoError`:
/// the C library reports a failed call as `strerror(errno)` text with no
/// errno attached (`etc/hidapi/linux/hid.c`, `hid_write` and
/// `hid_read_timeout` register `strerror(errno)` verbatim), and the Rust
/// wrapper turns every `-1` into `HidError::HidApiError { message }`. The
/// kinds a caller branches on — a signal interrupting the call, a device
/// gone away — are recovered from glibc's strings; anything else, and every
/// other platform's wording, is `Other`.
pub(crate) fn kind_from_message(message: &str) -> std::io::ErrorKind {
    use std::io::ErrorKind;
    if message.contains("Interrupted system call") {
        ErrorKind::Interrupted
    } else if message.contains("No such device") || message.contains("device disconnected") {
        ErrorKind::NotConnected
    } else if message.contains("Permission denied") {
        ErrorKind::PermissionDenied
    } else if message.contains("Resource temporarily unavailable") {
        ErrorKind::WouldBlock
    } else if message.contains("Broken pipe") {
        ErrorKind::BrokenPipe
    } else {
        ErrorKind::Other
    }
}

/// Every attached Ledger HID interface that speaks APDUs, in the order the OS
/// enumerates them; see the module docs for how one is recognised and for
/// what to do with more than one.
pub fn ledger_apdu_interfaces(api: &HidApi) -> Vec<&DeviceInfo> {
    let ledgers: Vec<&DeviceInfo> = api
        .device_list()
        .filter(|d| d.vendor_id() == LEDGER_USB_VENDOR_ID)
        .collect();
    let by_usage_page: Vec<&DeviceInfo> = ledgers
        .iter()
        .copied()
        .filter(|d| d.usage_page() == LEDGER_HID_USAGE_PAGE)
        .collect();
    if !by_usage_page.is_empty() {
        return by_usage_page;
    }
    // Only when *nothing* advertised a usage page, so this cannot outrank a
    // correct match.
    if ledgers.iter().all(|d| d.usage_page() == 0) {
        ledgers
            .into_iter()
            .filter(|d| d.interface_number() == LEDGER_APDU_INTERFACE)
            .collect()
    } else {
        Vec::new()
    }
}

/// A random 2-byte channel for one connection.
fn random_channel() -> HidChannel {
    let mut hasher = RandomState::new().build_hasher();
    // The seed alone already differs per `RandomState`; hashing a constant just
    // runs the finalizer over it.
    hasher.write_u8(0);
    HidChannel::new(hasher.finish() as u16)
}

/// The two raw report operations the transport needs from a HID device.
///
/// [`HidDevice`] is the one real implementation. The seam exists so that the
/// exchange logic — the stale-report drain and the poisoning rule above all —
/// can be exercised in CI against a scripted device, since a hardware check
/// cannot run there.
pub(crate) trait HidReports {
    /// Writes one output report, report-ID byte included.
    fn write_report(&self, report: &[u8]) -> Result<(), TransportError>;

    /// Reads one input report into `buf`, waiting at most `timeout_ms`
    /// ([`READ_BLOCKING`] waits indefinitely, [`READ_NON_BLOCKING`] not at
    /// all). `Ok(0)` means none arrived in time.
    fn read_report(&self, buf: &mut [u8], timeout_ms: i32) -> Result<usize, TransportError>;
}

impl HidReports for HidDevice {
    fn write_report(&self, report: &[u8]) -> Result<(), TransportError> {
        let written = self.write(report).map_err(io)?;
        if written != report.len() {
            return Err(TransportError::ShortWrite {
                written,
                expected: report.len(),
            });
        }
        Ok(())
    }

    fn read_report(&self, buf: &mut [u8], timeout_ms: i32) -> Result<usize, TransportError> {
        self.read_timeout(buf, timeout_ms).map_err(io)
    }
}

/// The per-connection state the exchange logic runs on, kept apart from the
/// device so the logic can be driven by a scripted one.
pub(crate) struct Link {
    channel: HidChannel,
    timeout: Duration,
    /// The failure that poisoned this connection, if one has; see the module
    /// docs.
    poisoned: Option<Box<TransportError>>,
}

impl Link {
    pub(crate) fn new(channel: HidChannel, timeout: Duration) -> Self {
        Link {
            channel,
            timeout,
            poisoned: None,
        }
    }

    pub(crate) fn is_poisoned(&self) -> bool {
        self.poisoned.is_some()
    }
}

/// Whether an I/O failure is a signal interrupting the call rather than the
/// device or the OS failing.
///
/// `hidapi`'s Linux backend waits in `poll`, which returns `-1` with `EINTR`
/// when a signal handler runs on the calling thread, and `hidapi` surfaces
/// that as an error like any other, with `strerror(EINTR)` as its text (see
/// [`kind_from_message`]). A host that installs handlers would otherwise see
/// the exchange fail for a reason unrelated to the device — and, once the
/// command is on the wire, the link poisoned. An interrupted call is simply
/// made again.
fn is_interrupted(e: &TransportError) -> bool {
    matches!(
        e,
        TransportError::Io {
            kind: std::io::ErrorKind::Interrupted,
            ..
        }
    )
}

/// What is left of a [`Deadline::Normal`] exchange's budget.
///
/// The budget covers the whole exchange — the write and every read of the
/// reply together — so it is measured from an [`Instant`] taken before the
/// first report goes out. A [`Deadline::UserReview`] exchange has no budget
/// and never asks for one.
///
/// # Errors
///
/// [`TransportError::Timeout`] once the budget is spent, which a zero
/// [`HidTransport::timeout`] is from the start.
fn budget_left(timeout: Duration, started: Instant) -> Result<Duration, TransportError> {
    timeout
        .checked_sub(started.elapsed())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| TransportError::Timeout {
            waited: started.elapsed(),
        })
}

/// [`HidReports::write_report`], made again while a signal interrupts it.
///
/// The retries are bounded the way the reply loop's wait is: under
/// [`Deadline::Normal`] a retry that finds the exchange's budget spent gives
/// up with [`TransportError::Timeout`], so a host whose handlers fire faster
/// than the write completes cannot spin here for ever. A
/// [`Deadline::UserReview`] exchange has no budget, and retries for as long
/// as the read that follows would block.
fn write_uninterrupted<D: HidReports>(
    device: &D,
    report: &[u8],
    link: &Link,
    deadline: Deadline,
    started: Instant,
) -> Result<(), TransportError> {
    loop {
        match device.write_report(report) {
            Err(e) if is_interrupted(&e) => {
                if deadline == Deadline::Normal {
                    budget_left(link.timeout, started)?;
                }
            }
            other => return other,
        }
    }
}

/// Reads and discards every input report already waiting in the OS buffer.
fn drain<D: HidReports>(device: &D) -> Result<(), TransportError> {
    // Stale reports are a reply too; the buffer is wiped on the way out.
    let mut buf = Zeroizing::new([0u8; HID_FRAME_SIZE]);
    for _ in 0..MAX_STALE_REPORTS {
        match device.read_report(&mut buf[..], READ_NON_BLOCKING) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(e) if is_interrupted(&e) => {}
            Err(e) => return Err(e),
        }
    }
    Err(TransportError::Io {
        kind: std::io::ErrorKind::Other,
        message: format!(
            "input reports were still arriving after {MAX_STALE_REPORTS} stale ones were \
             discarded; this is not a Ledger's reply to anything"
        ),
    })
}

/// One exchange over `device`: drain, write, read until a payload reassembles.
///
/// Refuses to run on a poisoned link, and poisons it on any failure once the
/// command has started onto the wire.
pub(crate) fn exchange_over<D: HidReports>(
    device: &D,
    link: &mut Link,
    apdu: &[u8],
    deadline: Deadline,
) -> Result<Vec<u8>, TransportError> {
    if let Some(cause) = &link.poisoned {
        return Err(TransportError::Poisoned {
            source: cause.clone(),
        });
    }
    // `hid_frames` yields no reports for an empty APDU, so nothing would go
    // out and the reply loop would take whatever arrived next for its answer.
    // Refused before the drain: nothing of this exchange happens at all.
    if apdu.is_empty() {
        return Err(TransportError::EmptyRequest);
    }

    // Anything already waiting belongs to an exchange that is over. Failing
    // here leaves the link clean: nothing of this command has gone out.
    drain(device)?;

    let mut on_the_wire = false;
    let result = exchange_unpoisoned(device, link, apdu, deadline, &mut on_the_wire);
    if let Err(e) = &result {
        if on_the_wire {
            link.poisoned = Some(Box::new(e.clone()));
        }
    }
    result
}

fn exchange_unpoisoned<D: HidReports>(
    device: &D,
    link: &Link,
    apdu: &[u8],
    deadline: Deadline,
    on_the_wire: &mut bool,
) -> Result<Vec<u8>, TransportError> {
    // The frames and the report buffer carry the command's payload — action
    // secrets on a `PCZT_*_ACTION` command — and the read buffer carries the
    // reply; all three are wiped when the exchange ends, whichever way.
    let frames = Zeroizing::new(hid_frames(link.channel, apdu)?);
    let mut report = Zeroizing::new([0u8; HID_FRAME_SIZE + 1]);
    report[0] = REPORT_ID;

    // The budget covers the write as well as the reply, so the clock starts
    // before the first report goes out.
    let started = Instant::now();
    if deadline == Deadline::Normal {
        // Nothing has gone out: a budget that is already spent fails here
        // without poisoning the link, the way the speculos transport refuses
        // a zero timeout before its write.
        budget_left(link.timeout, started)?;
    }

    // `hid_frames` fails only for an APDU longer than a frame 0 can declare,
    // before anything is written, so the link is not poisoned by it.
    for frame in frames.iter() {
        report[1..].copy_from_slice(frame);
        // Set before the attempt: a write that fails part-way has still put
        // something in front of the device.
        *on_the_wire = true;
        write_uninterrupted(device, &report[..], link, deadline, started)?;
    }
    drop(report);

    let mut deframer = Deframer::hid(link.channel);
    let mut buf = Zeroizing::new([0u8; HID_FRAME_SIZE]);
    // Reports that did not finish the reply; bounded, see `MAX_REPLY_REPORTS`.
    let mut unfinished_reports = 0usize;

    loop {
        let wait_ms = match deadline {
            Deadline::UserReview => READ_BLOCKING,
            // `as` saturates nothing, so clamp before the cast: a timeout
            // above ~24 days would otherwise wrap to a small positive value,
            // or to `-1` and block forever.
            Deadline::Normal => budget_left(link.timeout, started)?
                .as_millis()
                .min(i32::MAX as u128) as i32,
        };

        let read = match device.read_report(&mut buf[..], wait_ms) {
            Ok(read) => read,
            // Back to the top, where the wait is recomputed from the clock.
            Err(e) if is_interrupted(&e) => continue,
            Err(e) => return Err(e),
        };
        if read == 0 {
            // `hidapi` returns 0 for "timed out". A blocking wait cannot
            // time out, so a zero-length read under one is the wait ending
            // with no report — which the Windows backend reports for a
            // device gone away (`WAIT_FAILED`); on Linux a yanked device is
            // a read error instead.
            return Err(match deadline {
                Deadline::Normal => TransportError::Timeout {
                    waited: started.elapsed(),
                },
                Deadline::UserReview => TransportError::ConnectionClosed,
            });
        }

        // A report shorter than the frame is a partial read, which the
        // deframer refuses rather than reassembling a shifted reply; the
        // link is poisoned with it, since the rest of the reply is still
        // coming.
        match deframer.push(&buf[..read]) {
            Ok(Some(payload)) => return Ok(payload),
            // Either a continuation frame of this reply, or a frame the
            // deframer skipped because it carries another host process's
            // channel. Under `Deadline::UserReview` the clock counts neither,
            // so this does.
            Ok(None) => {
                unfinished_reports += 1;
                if unfinished_reports >= MAX_REPLY_REPORTS {
                    return Err(TransportError::Io {
                        kind: std::io::ErrorKind::Other,
                        message: format!(
                            "no reply reassembled after {MAX_REPLY_REPORTS} input reports; a \
                             Ledger's reply is a few of them, so these belong to another host \
                             process on this device node"
                        ),
                    });
                }
            }
            // The rest of this reply may still be arriving; the caller poisons
            // the link, and a fresh connection starts with a fresh deframer.
            Err(e) => return Err(e.into()),
        }
    }
}

/// One open Ledger, ready to exchange APDUs.
pub struct HidTransport {
    device: HidDevice,
    link: Link,
    label: String,
}

impl core::fmt::Debug for HidTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HidTransport")
            .field("channel", &self.link.channel)
            .field("timeout", &self.link.timeout)
            .field("poisoned", &self.link.is_poisoned())
            .field("device", &self.label)
            .finish()
    }
}

impl HidTransport {
    /// Opens the first Ledger device whose HID interface speaks APDUs.
    ///
    /// With several Ledgers attached, which one this is is not specified: it
    /// is the first APDU interface the OS enumerates. See the module docs for
    /// choosing one. It does *not* check which app is running, and nothing in
    /// this crate identifies the app: `GET_FIRMWARE_VERSION` and the
    /// `GET_WALLET_PUBLIC_KEY` identity probe are legacy instructions that
    /// every app of the Bitcoin family answers. A device in the dashboard
    /// answers the first with `WrongApp`; another app of that family passes
    /// both probes and is refused at the first PCZT instruction it does not
    /// know.
    ///
    /// # Errors
    ///
    /// [`TransportError::DeviceNotFound`] when no device with vendor id
    /// [`LEDGER_USB_VENDOR_ID`] is attached, or none of the attached ones
    /// exposes an interface [`ledger_apdu_interfaces`] recognises;
    /// [`TransportError::Io`] when `hidapi` cannot be initialised or the
    /// device cannot be opened (on Linux, typically a missing udev rule).
    pub fn open_first() -> Result<Self, TransportError> {
        let api = HidApi::new().map_err(io)?;
        Self::open_first_with(&api)
    }

    /// [`HidTransport::open_first`] against an already-built [`HidApi`].
    ///
    /// Building a `HidApi` enumerates every HID device on the system, so a
    /// caller that opens several devices — or reopens one after a restarted
    /// session — should build it once and pass it here.
    ///
    /// # Errors
    ///
    /// As [`HidTransport::open_first`].
    pub fn open_first_with(api: &HidApi) -> Result<Self, TransportError> {
        let candidates = ledger_apdu_interfaces(api);
        let chosen = candidates.first().ok_or_else(|| {
            let ledgers = api
                .device_list()
                .filter(|d| d.vendor_id() == LEDGER_USB_VENDOR_ID)
                .count();
            TransportError::DeviceNotFound {
                looked_for: if ledgers == 0 {
                    format!("USB vendor id {LEDGER_USB_VENDOR_ID:#06x}")
                } else {
                    format!(
                        "a HID interface with usage page {LEDGER_HID_USAGE_PAGE:#06x} on one of \
                         {ledgers} Ledger interface(s)"
                    )
                },
            }
        })?;

        let label = format!(
            "{} (pid {:#06x}, interface {})",
            chosen.product_string().unwrap_or("Ledger"),
            chosen.product_id(),
            chosen.interface_number()
        );
        let device = chosen.open_device(api).map_err(io)?;

        Ok(HidTransport {
            device,
            link: Link::new(random_channel(), DEFAULT_TIMEOUT),
            label,
        })
    }

    /// Wraps an already-open device, for callers that select it themselves.
    pub fn from_device(device: HidDevice) -> Self {
        let label = device
            .get_product_string()
            .ok()
            .flatten()
            .unwrap_or_else(|| "Ledger".to_string());
        HidTransport {
            device,
            link: Link::new(random_channel(), DEFAULT_TIMEOUT),
            label,
        }
    }

    /// The channel this connection uses.
    pub fn channel(&self) -> HidChannel {
        self.link.channel
    }

    /// The per-exchange timeout for exchanges that do not wait on the user:
    /// the write and every read of the reply together.
    pub fn timeout(&self) -> Duration {
        self.link.timeout
    }

    /// Sets the per-exchange timeout, which bounds the write and every read
    /// of the reply together. [`Deadline::UserReview`] ignores it.
    ///
    /// A zero timeout makes every [`Deadline::Normal`] exchange answer
    /// [`TransportError::Timeout`] before anything is written, leaving the
    /// link clean, as the speculos transport does with the same setting.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.link.timeout = timeout;
    }

    /// Builder form of [`HidTransport::set_timeout`].
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.link.timeout = timeout;
        self
    }

    /// Whether an earlier exchange has poisoned this connection, so that every
    /// further one answers [`TransportError::Poisoned`]. See the module docs.
    pub fn is_poisoned(&self) -> bool {
        self.link.is_poisoned()
    }
}

impl Transport for HidTransport {
    fn exchange_with(
        &mut self,
        apdu: &[u8],
        deadline: Deadline,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        exchange_over(&self.device, &mut self.link, apdu, deadline).map(Zeroizing::new)
    }

    fn describe(&self) -> String {
        format!("USB HID: {} on channel {}", self.label, self.link.channel)
    }
}

#[cfg(test)]
mod tests;
