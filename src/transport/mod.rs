//! Transports.
//!
//! The engine itself is transport-agnostic on purpose: [`crate::apdu`] produces
//! [`crate::apdu::Apdu`] values, [`crate::framing`] turns them into wire frames,
//! and [`crate::session::LedgerSignSession`] is a pull pump that performs no
//! I/O. What lives here is the small amount of glue that *does* open a device,
//! for the embeddings that want it.
//!
//! - [`hid`] — USB HID over `hidapi`, behind the `transport-hid` feature. The
//!   real transport for a physical Nano.
//! - [`speculos`] — a TCP socket to the speculos emulator's raw-APDU port,
//!   behind the `transport-speculos` feature. No HID framing at all: speculos
//!   speaks whole APDUs behind a 4-byte length prefix.
//! - BLE has no module: an embedding sends the frames through the platform's
//!   Bluetooth stack, so [`crate::framing::ble_frames`] and
//!   [`crate::framing::Deframer`] are the whole Rust surface.
//!
//! The [`Transport`] trait describes only the two concrete transports — a
//! blocking request/response channel — so an embedding can choose between them
//! at runtime. Nothing in [`crate::session`] or [`crate::pairing`] refers to
//! it; an async or callback embedding is free to ignore it entirely.
//! [`crate::ceremony`] is the blocking runner over it.

use std::time::Duration;

use crate::framing::FramingError;
use crate::session::Deadline;

#[cfg(feature = "transport-hid")]
pub mod hid;
#[cfg(feature = "transport-speculos")]
pub mod speculos;

/// The default wait for a reply the device produces on its own.
///
/// Every APDU except the two review points is answered by computation alone, so
/// a few seconds is generous. Under speculos the same commands are slower than
/// on hardware but still nowhere near this.
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
        /// The [`std::io::ErrorKind`], for callers that branch on it;
        /// [`std::io::ErrorKind::Other`] when the failure did not come through
        /// `std::io` (e.g. a `hidapi` error with no I/O cause).
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
    /// The device closed the connection, or returned a short read, part way
    /// through a response.
    ///
    /// For HID this is a zero-length report with frames still outstanding; for
    /// speculos, EOF mid-packet.
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
/// [`crate::pairing`] parsers take. A transport never inspects the status word;
/// a device that says "denied" is a successful exchange.
///
/// # One reply per command
///
/// An exchange that fails after its command has gone onto the wire leaves the
/// device's reply uncollected, and a transport must not let that reply be read
/// as the answer to the next command. The two transports here poison
/// themselves in that case and answer [`TransportError::Poisoned`] from then
/// on; an embedding's own transport should do the same, or drain and
/// re-synchronize its channel before the next command.
///
/// `Send` is a supertrait because sessions get driven from worker threads and
/// FFI shims: a wallet daemon parks the ceremony on a blocking thread, and a
/// mobile embedding hands the transport across whatever thread its runtime
/// calls back on.
pub trait Transport: Send {
    /// Sends one command and returns its reply, waiting under `deadline`.
    fn exchange_with(&mut self, apdu: &[u8], deadline: Deadline)
        -> Result<Vec<u8>, TransportError>;

    /// [`Transport::exchange_with`] under [`Deadline::Normal`].
    fn exchange(&mut self, apdu: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.exchange_with(apdu, Deadline::Normal)
    }

    /// A short description of what is on the other end, for logging.
    fn describe(&self) -> String;
}

impl<T: Transport + ?Sized> Transport for Box<T> {
    fn exchange_with(
        &mut self,
        apdu: &[u8],
        deadline: Deadline,
    ) -> Result<Vec<u8>, TransportError> {
        (**self).exchange_with(apdu, deadline)
    }

    fn describe(&self) -> String {
        (**self).describe()
    }
}
