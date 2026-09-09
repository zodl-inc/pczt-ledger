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
//! identified by usage page [`LEDGER_HID_USAGE_PAGE`] (`0xFFA0`) — the same test
//! `@ledgerhq/hw-transport-node-hid` makes. On Linux, `hidraw` reports a usage
//! page of `0` for every interface unless the kernel parsed the report
//! descriptor, so [`HidTransport::open_first`] falls back to interface number `0`, which is
//! the APDU interface on every current model. The fallback is only taken when no
//! interface advertises the usage page at all, so it can never *prefer* the
//! wrong one.
//!
//! # Channel
//!
//! Each connection picks a random 2-byte channel, the convention every Ledger
//! host transport follows (`WebHidApduSender`:
//! `Math.floor(Math.random() * 0xffff)`). The device echoes it and
//! [`crate::framing::Deframer::hid`] checks it, so a reply belonging to another
//! host process on the same device is rejected rather than spliced in.
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
//! runs under [`HidTransport::timeout`] and fails with
//! [`TransportError::Timeout`].
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

use hidapi::{HidApi, HidDevice};

use crate::framing::{hid_frames, Deframer, HID_FRAME_SIZE};
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

fn io(e: hidapi::HidError) -> TransportError {
    let kind = match &e {
        hidapi::HidError::IoError { error } => error.kind(),
        _ => std::io::ErrorKind::Other,
    };
    TransportError::Io {
        kind,
        message: e.to_string(),
    }
}

/// A random 2-byte channel for one connection.
fn random_channel() -> u16 {
    let mut hasher = RandomState::new().build_hasher();
    // The seed alone already differs per `RandomState`; hashing a constant just
    // runs the finalizer over it.
    hasher.write_u8(0);
    hasher.finish() as u16
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
        self.write(report).map(|_| ()).map_err(io)
    }

    fn read_report(&self, buf: &mut [u8], timeout_ms: i32) -> Result<usize, TransportError> {
        self.read_timeout(buf, timeout_ms).map_err(io)
    }
}

/// The per-connection state the exchange logic runs on, kept apart from the
/// device so the logic can be driven by a scripted one.
pub(crate) struct Link {
    channel: u16,
    timeout: Duration,
    /// The failure that poisoned this connection, if one has; see the module
    /// docs.
    poisoned: Option<Box<TransportError>>,
}

impl Link {
    pub(crate) fn new(channel: u16, timeout: Duration) -> Self {
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

/// Reads and discards every input report already waiting in the OS buffer.
fn drain<D: HidReports>(device: &D) -> Result<(), TransportError> {
    let mut buf = [0u8; HID_FRAME_SIZE];
    for _ in 0..MAX_STALE_REPORTS {
        if device.read_report(&mut buf, READ_NON_BLOCKING)? == 0 {
            return Ok(());
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
    let mut report = [0u8; HID_FRAME_SIZE + 1];
    report[0] = REPORT_ID;
    for frame in hid_frames(link.channel, apdu) {
        report[1..].copy_from_slice(&frame);
        // Set before the attempt: a write that fails part-way has still put
        // something in front of the device.
        *on_the_wire = true;
        device.write_report(&report)?;
    }

    let mut deframer = Deframer::hid(link.channel);
    let started = Instant::now();
    let mut buf = [0u8; HID_FRAME_SIZE];

    loop {
        let wait_ms = match deadline {
            Deadline::UserReview => READ_BLOCKING,
            Deadline::Normal => match link.timeout.checked_sub(started.elapsed()) {
                // `as` saturates nothing, so clamp before the cast: a
                // timeout above ~24 days would otherwise wrap to a small
                // positive value, or to `-1` and block forever.
                Some(left) => left.as_millis().min(i32::MAX as u128) as i32,
                None => {
                    return Err(TransportError::Timeout {
                        waited: started.elapsed(),
                    })
                }
            },
        };

        let read = device.read_report(&mut buf, wait_ms)?;
        if read == 0 {
            // `hidapi` returns 0 for "timed out". With `-1` it cannot, so
            // this is only reachable under `Deadline::Normal`; a device
            // yanked mid-review surfaces as a read error instead.
            return Err(TransportError::Timeout {
                waited: started.elapsed(),
            });
        }

        match deframer.push(&buf[..read]) {
            Ok(Some(payload)) => return Ok(payload),
            Ok(None) => {}
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
            .field("channel", &format_args!("{:#06x}", self.link.channel))
            .field("timeout", &self.link.timeout)
            .field("poisoned", &self.link.is_poisoned())
            .field("device", &self.label)
            .finish()
    }
}

impl HidTransport {
    /// Opens the first Ledger device whose HID interface speaks APDUs.
    ///
    /// Fails with [`TransportError::DeviceNotFound`] when no device with vendor
    /// id [`LEDGER_USB_VENDOR_ID`] is attached. It does *not* check which app is
    /// running: that is what `GET_FIRMWARE_VERSION` is for, and a device in the
    /// dashboard answers it with `WrongApp` rather than not answering.
    pub fn open_first() -> Result<Self, TransportError> {
        let api = HidApi::new().map_err(io)?;
        Self::open_first_with(&api)
    }

    /// [`HidTransport::open_first`] against an already-built [`HidApi`].
    ///
    /// Building a `HidApi` enumerates every HID device on the system, so a
    /// caller that opens several devices — or reopens one after a restarted
    /// session — should build it once and pass it here.
    pub fn open_first_with(api: &HidApi) -> Result<Self, TransportError> {
        let ledgers: Vec<_> = api
            .device_list()
            .filter(|d| d.vendor_id() == LEDGER_USB_VENDOR_ID)
            .collect();

        if ledgers.is_empty() {
            return Err(TransportError::DeviceNotFound {
                looked_for: format!("USB vendor id {LEDGER_USB_VENDOR_ID:#06x}"),
            });
        }

        let chosen = ledgers
            .iter()
            .find(|d| d.usage_page() == LEDGER_HID_USAGE_PAGE)
            .or_else(|| {
                // Only when *nothing* advertised a usage page, so this cannot
                // outrank a correct match.
                if ledgers.iter().all(|d| d.usage_page() == 0) {
                    ledgers
                        .iter()
                        .find(|d| d.interface_number() == LEDGER_APDU_INTERFACE)
                } else {
                    None
                }
            })
            .ok_or_else(|| TransportError::DeviceNotFound {
                looked_for: format!(
                    "a HID interface with usage page {LEDGER_HID_USAGE_PAGE:#06x} on one of \
                     {} Ledger interface(s)",
                    ledgers.len()
                ),
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
    pub fn channel(&self) -> u16 {
        self.link.channel
    }

    /// The per-call timeout for exchanges that do not wait on the user.
    pub fn timeout(&self) -> Duration {
        self.link.timeout
    }

    /// Sets the per-call timeout. [`Deadline::UserReview`] ignores it.
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
    ) -> Result<Vec<u8>, TransportError> {
        exchange_over(&self.device, &mut self.link, apdu, deadline)
    }

    fn describe(&self) -> String {
        format!(
            "USB HID: {} on channel {:#06x}",
            self.label, self.link.channel
        )
    }
}
