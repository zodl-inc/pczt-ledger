//! Transports.
//!
//! The engine itself is transport-agnostic on purpose: [`crate::apdu`] produces
//! [`crate::apdu::Apdu`] values, [`crate::framing`] turns them into wire frames,
//! and [`crate::session::LedgerSignSession`] is a pull pump that performs no
//! I/O. What lives here is the small amount of glue that *does* open a device,
//! for the embeddings that want it.
//!
//! - `hid` — USB HID over `hidapi`, behind the `transport-hid` feature. The
//!   real transport for a physical Nano.
//! - `speculos` — a TCP socket to the speculos emulator's raw-APDU port,
//!   behind the `transport-speculos` feature. No HID framing at all: speculos
//!   speaks whole APDUs behind a 4-byte length prefix.
//!
//! (The two are named without links because each module exists only when
//! its feature is on, and this page is built for every feature set.)
//! - BLE has no module: an embedding sends the frames through the platform's
//!   Bluetooth stack, so [`crate::framing::ble_frames`] and
//!   [`crate::framing::Deframer`] are the whole Rust surface.
//!
//! The [`Transport`] trait is a blocking request/response channel. The two
//! concrete transports implement it, and so may an embedding's own — a serial
//! bridge, a test double — under the contract its docs state, so that a
//! caller can choose among them at runtime. Nothing in [`crate::session`] or
//! [`crate::pairing`] refers to it; an async or callback embedding is free to
//! ignore it entirely. [`crate::ceremony`] is the blocking runner over it.

use std::time::Duration;

use zeroize::Zeroizing;

use crate::framing::FramingError;
use crate::session::Deadline;

#[cfg(feature = "transport-hid")]
pub mod hid;
#[cfg(feature = "transport-speculos")]
pub mod speculos;

/// The default wait for a reply the device produces on its own: two minutes.
///
/// Every APDU not exchanged under [`Deadline::UserReview`] is answered by
/// computation alone, in
/// well under a second on hardware, so this is generous by two orders of
/// magnitude — deliberately, because a timeout poisons the connection and a
/// spurious one costs the user a restart. Under speculos the same commands
/// are slower than on hardware but still nowhere near this.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// A transport that could not carry one exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportError {
    /// No Ledger device was found, or none running an interface that speaks
    /// APDUs.
    DeviceNotFound {
        /// What was looked for, for the error message.
        looked_for: String,
    },
    /// The underlying I/O failed.
    Io {
        /// The [`std::io::ErrorKind`], for callers that branch on it. From
        /// the speculos socket it is the socket's own; from the C `hidapi`
        /// backend, which attaches no errno, it is recovered from the error
        /// text (a signal interrupting the call, a device gone away, a
        /// permission refused), and [`std::io::ErrorKind::Other`] when it
        /// cannot be.
        kind: std::io::ErrorKind,
        /// The underlying error's message.
        message: String,
    },
    /// The reply did not arrive inside the deadline.
    ///
    /// This is never returned for [`Deadline::UserReview`], which has no
    /// deadline.
    Timeout {
        /// How long was waited.
        waited: Duration,
    },
    /// The connection closed during an exchange.
    ///
    /// From the speculos transport: EOF, a reset or a broken pipe on the
    /// socket, before or during the reply. From the HID transport: a blocking
    /// read ([`Deadline::UserReview`]) that returned with no report, which
    /// `hidapi`'s Windows backend does for a device gone away; on Linux a
    /// yanked device is an I/O error ([`TransportError::Io`]) instead, and a
    /// short read is a framing error
    /// ([`crate::framing::FramingError::BadFrameLength`]).
    ConnectionClosed,
    /// A frame could not be reassembled.
    Framing(FramingError),
    /// The device announced a response larger than this transport will buffer.
    ///
    /// Only speculos can produce one: its length prefix is 32 bits wide, while
    /// every reply the Zcash app actually sends is at most a few hundred bytes.
    /// The cap turns a desynchronized socket into an error rather than an
    /// allocation.
    ResponseTooLarge {
        /// The length the peer declared.
        declared: usize,
        /// The largest this transport accepts.
        max: usize,
    },
    /// The OS took fewer bytes of an output report than the report holds.
    ///
    /// Only the HID transport produces it. The device has a partial frame in
    /// front of it and the rest of the command never goes out, so the
    /// exchange fails and, the command having started onto the wire, the
    /// link is poisoned.
    ShortWrite {
        /// Bytes the OS took.
        written: usize,
        /// Bytes the report holds.
        expected: usize,
    },
    /// A command longer than the transport's length prefix can count.
    ///
    /// Only speculos can produce one, for a slice of 4 GiB or more; nothing
    /// this crate builds comes near, so this is for a caller framing bytes of
    /// its own. Refused before anything is written.
    RequestTooLarge {
        /// The length asked for.
        len: usize,
        /// The most the prefix can count.
        max: usize,
    },
    /// A command with no bytes.
    ///
    /// Every APDU begins with `CLA INS P1 P2`, so an empty one is a caller's
    /// mistake, and every transport here refuses it before anything is
    /// written. The HID framing produces no reports at all for it, so a
    /// transport that let it through would read whatever arrived next on the
    /// channel as the reply to a command the device never saw.
    EmptyRequest,
    /// The connection is poisoned: an earlier exchange put a command on the
    /// wire and then failed before the device's reply was collected — it
    /// timed out, or the reply could not be reassembled — so a reply arriving
    /// later cannot be attributed to a command. A late reply to the failed
    /// exchange would otherwise be taken for the reply to the next one, and
    /// every reply after that for the wrong command's, for the life of the
    /// connection.
    ///
    /// A poisoned connection refuses every further exchange. The recovery is
    /// to drop it and open a new one, which starts with a fresh channel and an
    /// empty buffer.
    Poisoned {
        /// The failure that poisoned the connection.
        source: Box<TransportError>,
    },
}

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TransportError::DeviceNotFound { looked_for } => {
                write!(f, "no Ledger device found ({looked_for})")
            }
            TransportError::Io { message, .. } => write!(f, "transport I/O error: {message}"),
            TransportError::Timeout { waited } => {
                write!(f, "no reply after {waited:?}")
            }
            TransportError::ConnectionClosed => {
                write!(f, "the device closed the connection mid-response")
            }
            TransportError::Framing(e) => write!(f, "framing: {e}"),
            TransportError::ResponseTooLarge { declared, max } => write!(
                f,
                "device declared a {declared}-byte response, above the {max}-byte cap"
            ),
            TransportError::ShortWrite { written, expected } => write!(
                f,
                "the OS took {written} of a {expected}-byte output report; the device has a \
                 partial frame in front of it"
            ),
            TransportError::RequestTooLarge { len, max } => write!(
                f,
                "a {len}-byte command cannot be sent; the length prefix counts at most {max}"
            ),
            TransportError::EmptyRequest => write!(
                f,
                "an empty command cannot be sent; every APDU begins with CLA INS P1 P2"
            ),
            TransportError::Poisoned { source } => write!(
                f,
                "the connection is poisoned: an earlier exchange left the device's reply \
                 uncollected ({source}), so no later reply can be attributed to a command; \
                 open a new connection"
            ),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TransportError::Framing(e) => Some(e),
            TransportError::Poisoned { source } => Some(source.as_ref()),
            _ => None,
        }
    }
}

impl From<FramingError> for TransportError {
    fn from(e: FramingError) -> Self {
        TransportError::Framing(e)
    }
}

/// A blocking request/response channel to one device.
///
/// The returned buffer is the raw transport payload — response data followed by
/// the two-byte status word — which is exactly what
/// [`crate::session::LedgerSignSession::process_response`] and the
/// [`crate::pairing`] parsers take. It comes wrapped in [`Zeroizing`]: a reply
/// may carry the account's address (`GET_WALLET_PUBLIC_KEY` answers it whether
/// or not it was wanted) or a viewing-key chunk, and is wiped when dropped,
/// whoever the caller is. A transport never inspects the status word; a
/// device that says "denied" is a successful exchange.
///
/// # One reply per command
///
/// An exchange that fails after its command has gone onto the wire leaves the
/// device's reply uncollected, and a transport must not let that reply be read
/// as the answer to the next command. The two transports here poison
/// themselves in that case and answer [`TransportError::Poisoned`] from then
/// on, and the recovery is a new connection; an embedding's own transport
/// must do the same. Draining the channel before the next command is not
/// enough on its own: the uncollected reply may arrive after the drain and
/// before the next reply, and the device may answer it at any time — the
/// HID transport drains *and* poisons, and needs both. Nor may a transport
/// resend a command on its own initiative: every PCZT instruction resets the
/// device's transaction context on a refusal, so a resend after a failure
/// can only fail again, and a resend of a `PCZT_SIGN_*` command after its
/// reply was lost is refused as already signed — after the user has
/// approved. The one legitimate resend, the device SDK's `0x6901`, is the
/// session's decision ([`crate::session::SessionStatus::RetrySameApdu`]),
/// never the transport's.
///
/// # An empty command is refused
///
/// A command of no bytes is [`TransportError::EmptyRequest`] on every
/// transport here, refused before anything goes out; an embedding's own
/// transport does the same. It is not a command — an APDU begins with
/// `CLA INS P1 P2` — and a transport that wrote nothing for it would take the
/// next thing to arrive for its reply.
///
/// `Send` is a supertrait because sessions get driven from worker threads and
/// FFI shims: a wallet daemon parks the ceremony on a blocking thread, and a
/// mobile embedding hands the transport across whatever thread its runtime
/// calls back on.
pub trait Transport: Send {
    /// Sends one command and returns its reply, waiting under `deadline`.
    ///
    /// # Errors
    ///
    /// [`TransportError::EmptyRequest`] for an `apdu` of no bytes, from every
    /// transport; otherwise any [`TransportError`], and which ones a transport
    /// produces is on each.
    fn exchange_with(
        &mut self,
        apdu: &[u8],
        deadline: Deadline,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError>;

    /// [`Transport::exchange_with`] under [`Deadline::Normal`].
    ///
    /// # Errors
    ///
    /// As [`Transport::exchange_with`].
    fn exchange(&mut self, apdu: &[u8]) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        self.exchange_with(apdu, Deadline::Normal)
    }

    /// A short description of what is on the other end, for logging.
    fn describe(&self) -> String;
}

/// Forwards every method, `exchange` included, so a boxed transport behaves as
/// the one inside it even where that one overrides the default.
impl<T: Transport + ?Sized> Transport for Box<T> {
    fn exchange_with(
        &mut self,
        apdu: &[u8],
        deadline: Deadline,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        (**self).exchange_with(apdu, deadline)
    }

    fn exchange(&mut self, apdu: &[u8]) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        (**self).exchange(apdu)
    }

    fn describe(&self) -> String {
        (**self).describe()
    }
}
