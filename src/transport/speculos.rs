//! Speculos transport: a TCP socket to the emulator's raw-APDU port.
//!
//! Speculos exposes the app's APDU channel on a TCP port (`--apdu-port`,
//! default `9999`). It is *not* HID: the emulator sits above the SE/MCU split,
//! so there is no report size, no channel, and no [`crate::framing`] involvement
//! at all. Whole APDUs cross the socket behind a 4-byte big-endian length.
//!
//! # Wire protocol
//!
//! `speculos/mcu/apdu.py`, both directions:
//!
//! ```text
//! host   → device:  len(apdu) as u32 BE   ‖ apdu
//! device → host:    len(reply) - 2 as u32 ‖ reply          (reply = data ‖ SW)
//! ```
//!
//! The asymmetry is deliberate on the emulator's side: it computes its prefix
//! as `size = (len(packet) - 2) & 0xffffffff` and
//! then sends the *whole* packet, status word included — so a reader that
//! consumes only `size` bytes desynchronizes the socket by two bytes per
//! exchange, and one that treats `size` as the data length and stops there
//! throws the status word away. [`SpeculosTransport`] reads `size + 2` bytes and
//! returns them whole, which is the payload shape
//! [`crate::session::LedgerSignSession::process_response`] expects.
//!
//! This matches `ledgercomm`'s own TCP client, which reads the length, then the
//! data, then two further bytes for the status word.
//!
//! # Timeouts and the review screen
//!
//! Under speculos "the user reviews on the device" means an automation script,
//! a human clicking in the emulator's UI, or nothing at all, so the same
//! [`Deadline::UserReview`] rule applies: the read timeout is cleared for those
//! exchanges rather than merely lengthened.
//!
//! # Poisoning
//!
//! The socket carries no channel, so a reply that arrives after its exchange
//! has given up is indistinguishable from the reply to the next command — and
//! an exchange that stopped part-way through a reply leaves the rest of it in
//! the stream. Any failure once a request is on the wire therefore poisons the
//! connection, exactly as [`crate::transport::hid`] does: every later exchange
//! answers [`TransportError::Poisoned`], and the recovery is a new connection.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::session::Deadline;
use crate::transport::{Transport, TransportError, DEFAULT_TIMEOUT};

/// The address to use when neither a flag nor the environment names one.
pub const DEFAULT_SPECULOS_ADDR: &str = "127.0.0.1:9999";

/// Environment variable naming the speculos APDU port.
///
/// Reading it is also the gate the speculos integration tests use: unset means
/// "no emulator here", and the test skips.
pub const SPECULOS_ADDR_ENV: &str = "SPECULOS_APDU_ADDR";

/// The 4-byte big-endian length prefix on every packet, both directions.
const LENGTH_PREFIX_LEN: usize = 4;

/// Bytes of status word that follow the length-prefixed data.
///
/// Speculos subtracts these from the prefix it writes; see the module docs.
const STATUS_WORD_LEN: usize = 2;

/// The largest reply this transport will buffer.
///
/// The prefix is 32 bits wide while the Zcash app's longest reply is a chunked
/// viewing key at 255 bytes, so anything near this cap means the stream has
/// desynchronized. Erroring beats allocating four gigabytes.
pub const MAX_RESPONSE_LEN: usize = 64 * 1024;

fn io(e: std::io::Error) -> TransportError {
    TransportError::Io {
        kind: e.kind(),
        message: e.to_string(),
    }
}

/// The address speculos should be reached at, from the environment.
///
/// Returns `None` when [`SPECULOS_ADDR_ENV`] is unset or empty, which callers
/// treat as "no emulator configured" rather than as an error.
pub fn addr_from_env() -> Option<String> {
    match std::env::var(SPECULOS_ADDR_ENV) {
        Ok(v) if !v.trim().is_empty() => Some(v.trim().to_string()),
        _ => None,
    }
}

/// [`addr_from_env`] with [`DEFAULT_SPECULOS_ADDR`] as the fallback.
pub fn addr_or_default() -> String {
    addr_from_env().unwrap_or_else(|| DEFAULT_SPECULOS_ADDR.to_string())
}

/// A connection to a running speculos instance.
#[derive(Debug)]
pub struct SpeculosTransport {
    stream: TcpStream,
    timeout: Duration,
    label: String,
    /// The failure that poisoned this connection, if one has; see the module
    /// docs.
    poisoned: Option<Box<TransportError>>,
}

impl SpeculosTransport {
    /// Connects to `addr`.
    pub fn connect<A: ToSocketAddrs + core::fmt::Display>(addr: A) -> Result<Self, TransportError> {
        let label = addr.to_string();
        let stream = TcpStream::connect(&addr).map_err(io)?;
        // Ledger APDUs are small and strictly request/response; batching one
        // exchange's frames into a later packet only adds latency.
        stream.set_nodelay(true).map_err(io)?;
        Ok(SpeculosTransport {
            stream,
            timeout: DEFAULT_TIMEOUT,
            label,
            poisoned: None,
        })
    }

    /// Connects to [`addr_or_default`].
    pub fn connect_default() -> Result<Self, TransportError> {
        Self::connect(addr_or_default())
    }

    /// Connects to the address in [`SPECULOS_ADDR_ENV`], or `None` if it is
    /// unset.
    ///
    /// The skip-cleanly path for tests.
    pub fn connect_from_env() -> Option<Result<Self, TransportError>> {
        addr_from_env().map(Self::connect)
    }

    /// The per-call timeout for exchanges that do not wait on the user.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Sets the per-call timeout. [`Deadline::UserReview`] ignores it.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Builder form of [`SpeculosTransport::set_timeout`].
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Whether an earlier exchange has poisoned this connection, so that every
    /// further one answers [`TransportError::Poisoned`]. See the module docs.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.is_some()
    }

    /// Applies `deadline` to the socket's read timeout.
    ///
    /// `set_read_timeout(None)` is "block forever", which is exactly what a
    /// review needs.
    fn arm(&self, deadline: Deadline) -> Result<(), TransportError> {
        let value = match deadline {
            Deadline::UserReview => None,
            Deadline::Normal => Some(self.timeout),
        };
        self.stream.set_read_timeout(value).map_err(io)
    }

    fn read_exact(&mut self, buf: &mut [u8], started: Instant) -> Result<(), TransportError> {
        match self.stream.read_exact(buf) {
            Ok(()) => Ok(()),
            Err(e) => Err(match e.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                    TransportError::Timeout {
                        waited: started.elapsed(),
                    }
                }
                std::io::ErrorKind::UnexpectedEof => TransportError::ConnectionClosed,
                _ => io(e),
            }),
        }
    }
}

impl SpeculosTransport {
    /// The exchange proper, once the link is known to be clean. Every error
    /// after the request has started onto the wire poisons the connection.
    fn exchange_unpoisoned(
        &mut self,
        apdu: &[u8],
        deadline: Deadline,
    ) -> Result<Vec<u8>, TransportError> {
        self.arm(deadline)?;
        let started = Instant::now();

        let mut request = Vec::with_capacity(LENGTH_PREFIX_LEN + apdu.len());
        request.extend_from_slice(&(apdu.len() as u32).to_be_bytes());
        request.extend_from_slice(apdu);
        let result = self
            .stream
            .write_all(&request)
            .and_then(|()| self.stream.flush())
            .map_err(io)
            .and_then(|()| {
                let mut prefix = [0u8; LENGTH_PREFIX_LEN];
                self.read_exact(&mut prefix, started)?;
                let data_len = u32::from_be_bytes(prefix) as usize;
                if data_len > MAX_RESPONSE_LEN {
                    return Err(TransportError::ResponseTooLarge {
                        declared: data_len,
                        max: MAX_RESPONSE_LEN,
                    });
                }

                // The prefix excludes the status word, which follows the data.
                let mut payload = vec![0u8; data_len + STATUS_WORD_LEN];
                self.read_exact(&mut payload, started)?;
                Ok(payload)
            });
        if let Err(e) = &result {
            self.poisoned = Some(Box::new(e.clone()));
        }
        result
    }
}

impl Transport for SpeculosTransport {
    fn exchange_with(
        &mut self,
        apdu: &[u8],
        deadline: Deadline,
    ) -> Result<Vec<u8>, TransportError> {
        if let Some(cause) = &self.poisoned {
            return Err(TransportError::Poisoned {
                source: cause.clone(),
            });
        }
        self.exchange_unpoisoned(apdu, deadline)
    }

    fn describe(&self) -> String {
        format!("speculos APDU socket at {}", self.label)
    }
}

/// Frames a request the way [`SpeculosTransport`] puts it on the wire.
///
/// Exposed so a test — or a fake emulator — can build the same bytes without a
/// socket.
pub fn frame_request(apdu: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(LENGTH_PREFIX_LEN + apdu.len());
    out.extend_from_slice(&(apdu.len() as u32).to_be_bytes());
    out.extend_from_slice(apdu);
    out
}

/// Frames a reply the way speculos does: the prefix counts the data only, and
/// the status word follows outside it.
///
/// `reply` is the whole payload, data and status word together — the shape
/// [`Transport::exchange`] hands back.
///
/// Returns `None` for a reply too short to contain a status word, which the
/// emulator's own `len(packet) - 2` would underflow on.
pub fn frame_reply(reply: &[u8]) -> Option<Vec<u8>> {
    let data_len = reply.len().checked_sub(STATUS_WORD_LEN)?;
    let mut out = Vec::with_capacity(LENGTH_PREFIX_LEN + reply.len());
    out.extend_from_slice(&(data_len as u32).to_be_bytes());
    out.extend_from_slice(reply);
    Some(out)
}
