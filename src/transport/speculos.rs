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
//! exchanges rather than merely lengthened. Under [`Deadline::Normal`] the
//! timeout bounds the whole exchange — the write and every read of the reply
//! together — the way the HID transport's does, not each read on its own: a
//! peer that trickles one byte per timeout period cannot hold an exchange
//! open past it.
//!
//! # Poisoning
//!
//! The socket carries no channel, so a reply that arrives after its exchange
//! has given up is indistinguishable from the reply to the next command — and
//! an exchange that stopped part-way through a reply leaves the rest of it in
//! the stream. Any failure once a request is on the wire therefore poisons the
//! connection, exactly as the HID transport does: every later exchange
//! answers [`TransportError::Poisoned`], and the recovery is a new connection.
//!
//! On speculos itself a new connection is not the whole recovery. The
//! emulator keeps one current client and forwards whatever the SE next emits
//! to it (`speculos/mcu/apdu.py`, `ApduServer.forward_to_client`), so a reply
//! still owed to a poisoned connection is delivered to the *next* connection
//! and answers its first command. The session's first command is the identity
//! probe, whose parser refuses a reply of any other shape, so the outcome is
//! a refusal rather than a misattributed signature; a wallet that reconnects
//! after a poisoning should nevertheless restart the emulator, or wait the
//! late reply out. A bridge that copies speculos's routing has the same
//! property, and needs per-connection routing for the new-connection recovery
//! to hold.
//!
//! # Security
//!
//! The socket is plaintext and unauthenticated. Everything a session streams
//! crosses it — the per-action secrets `alpha`, `rcv` and `rseed`, every
//! recipient and value, and the viewing key a `GET_VK` exports — and nothing
//! here checks who is listening. It is for an emulator on a loopback or
//! otherwise trusted link; a wallet that drives a remote signer over a network
//! has to wrap the link itself. [`connect_default`](SpeculosTransport::connect_default)
//! and [`addr_or_default`] read the address from the environment as a
//! developer convenience, which means anything able to set
//! [`SPECULOS_ADDR_ENV`] in the wallet's environment picks where the stream
//! goes; a wallet pins its own address with
//! [`connect`](SpeculosTransport::connect). Speculos itself listens on every
//! interface (`speculos/main.py`: `ApduServer(host="0.0.0.0", ..)`), so "the
//! emulator's port" is not loopback-only by default either.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::apdu::{Deadline, STATUS_WORD_LEN};
use crate::transport::{Transport, TransportError, DEFAULT_TIMEOUT};

/// The address to use when the environment names none.
pub const DEFAULT_SPECULOS_ADDR: &str = "127.0.0.1:9999";

/// Environment variable naming the speculos APDU port.
///
/// The gate an emulator-backed test should read: unset or empty means "no
/// emulator here", and such a test skips; a value that is not Unicode is an
/// error rather than a silent skip. This crate's own tests do not read it —
/// none of them needs an emulator; the transport is tested against a loopback
/// fake — so no CI job has to guard it.
pub const SPECULOS_ADDR_ENV: &str = "SPECULOS_APDU_ADDR";

/// The 4-byte big-endian length prefix on every packet, both directions.
const LENGTH_PREFIX_LEN: usize = 4;

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
/// `Ok(None)` when [`SPECULOS_ADDR_ENV`] is unset or blank, which callers
/// treat as "no emulator configured" rather than as an error; surrounding
/// whitespace is trimmed.
///
/// # Errors
///
/// [`TransportError::Io`] with kind [`std::io::ErrorKind::InvalidData`] when
/// the variable is set to something that is not Unicode: a mis-set value is
/// reported, not read as "unset".
pub fn addr_from_env() -> Result<Option<String>, TransportError> {
    match std::env::var(SPECULOS_ADDR_ENV) {
        Ok(v) if !v.trim().is_empty() => Ok(Some(v.trim().to_string())),
        Ok(_) | Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(TransportError::Io {
            kind: std::io::ErrorKind::InvalidData,
            message: format!("{SPECULOS_ADDR_ENV} is set to a value that is not Unicode"),
        }),
    }
}

/// [`addr_from_env`] with [`DEFAULT_SPECULOS_ADDR`] as the fallback.
///
/// # Errors
///
/// As [`addr_from_env`].
pub fn addr_or_default() -> Result<String, TransportError> {
    Ok(addr_from_env()?.unwrap_or_else(|| DEFAULT_SPECULOS_ADDR.to_string()))
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
    ///
    /// # Errors
    ///
    /// [`TransportError::Io`] when the connection cannot be made or the socket
    /// cannot be configured.
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
    ///
    /// # Errors
    ///
    /// As [`addr_or_default`] and [`SpeculosTransport::connect`].
    pub fn connect_default() -> Result<Self, TransportError> {
        Self::connect(addr_or_default()?)
    }

    /// Connects to the address in [`SPECULOS_ADDR_ENV`], or `None` if it is
    /// unset or blank.
    ///
    /// The skip-cleanly path for tests.
    ///
    /// # Errors
    ///
    /// `Some(Err(..))` as [`addr_from_env`] and [`SpeculosTransport::connect`].
    pub fn connect_from_env() -> Option<Result<Self, TransportError>> {
        match addr_from_env() {
            Ok(Some(addr)) => Some(Self::connect(addr)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }

    /// The per-exchange timeout for exchanges that do not wait on the user:
    /// the write and every read of the reply together.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Sets the per-exchange timeout. [`Deadline::UserReview`] ignores it.
    ///
    /// A zero timeout makes every [`Deadline::Normal`] exchange answer
    /// [`TransportError::Timeout`] before anything is written, as the HID
    /// transport does with the same setting.
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

    /// Applies `deadline` to the socket's write and read timeouts.
    ///
    /// `None` is "block forever", which is exactly what a review needs. Under
    /// [`Deadline::Normal`] this arms the write and the first read with the
    /// whole budget; [`SpeculosTransport::read_exact`] re-arms every later
    /// read with what is left of it.
    fn arm(&self, deadline: Deadline) -> Result<(), TransportError> {
        let value = match deadline {
            Deadline::UserReview => None,
            Deadline::Normal => Some(self.timeout),
        };
        self.stream.set_write_timeout(value).map_err(io)?;
        self.stream.set_read_timeout(value).map_err(io)
    }

    /// Fills `buf`, re-arming the read timeout with what is left of the
    /// exchange's budget before every read, so that the budget bounds the
    /// exchange and not each read.
    fn read_exact(
        &mut self,
        buf: &mut [u8],
        deadline: Deadline,
        started: Instant,
    ) -> Result<(), TransportError> {
        let mut filled = 0;
        while filled < buf.len() {
            if deadline == Deadline::Normal {
                let left = self
                    .timeout
                    .checked_sub(started.elapsed())
                    .filter(|left| !left.is_zero())
                    .ok_or(TransportError::Timeout {
                        waited: started.elapsed(),
                    })?;
                self.stream.set_read_timeout(Some(left)).map_err(io)?;
            }
            match self.stream.read(&mut buf[filled..]) {
                Ok(0) => return Err(TransportError::ConnectionClosed),
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(classify(e, started)),
            }
        }
        Ok(())
    }
}

/// Maps a socket error to the transport's vocabulary.
fn classify(e: std::io::Error, started: Instant) -> TransportError {
    match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => TransportError::Timeout {
            waited: started.elapsed(),
        },
        std::io::ErrorKind::UnexpectedEof
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::BrokenPipe => TransportError::ConnectionClosed,
        _ => io(e),
    }
}

impl SpeculosTransport {
    /// The exchange proper, once the link is known to be clean. Every error
    /// after the request has started onto the wire poisons the connection.
    fn exchange_unpoisoned(
        &mut self,
        apdu: &[u8],
        deadline: Deadline,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        // Nothing has gone out: none of these poisons.
        if apdu.is_empty() {
            return Err(TransportError::EmptyRequest);
        }
        if deadline == Deadline::Normal && self.timeout.is_zero() {
            return Err(TransportError::Timeout {
                waited: Duration::ZERO,
            });
        }
        // The request carries the command's payload; wiped when the exchange
        // ends.
        let request = Zeroizing::new(frame_request(apdu)?);
        self.arm(deadline)?;
        let started = Instant::now();

        let result = self
            .stream
            .write_all(&request)
            .and_then(|()| self.stream.flush())
            .map_err(|e| classify(e, started))
            .and_then(|()| {
                let mut prefix = [0u8; LENGTH_PREFIX_LEN];
                self.read_exact(&mut prefix, deadline, started)?;
                let data_len = u32::from_be_bytes(prefix) as usize;
                if data_len > MAX_RESPONSE_LEN {
                    return Err(TransportError::ResponseTooLarge {
                        declared: data_len,
                        max: MAX_RESPONSE_LEN,
                    });
                }

                // The prefix excludes the status word, which follows the
                // data. Wiped on every path, not only the successful one: a
                // read that fails partway through has already put reply bytes
                // — an address, a viewing-key chunk — into this buffer.
                let mut payload = Zeroizing::new(vec![0u8; data_len + STATUS_WORD_LEN]);
                self.read_exact(&mut payload, deadline, started)?;
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
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
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

/// The request as [`SpeculosTransport`] puts it on the wire: the 4-byte
/// big-endian length, then the APDU.
///
/// Refuses an APDU the prefix cannot count rather than declaring its length
/// modulo 2^32; nothing this crate builds comes near.
pub(crate) fn frame_request(apdu: &[u8]) -> Result<Vec<u8>, TransportError> {
    let len = u32::try_from(apdu.len()).map_err(|_| TransportError::RequestTooLarge {
        len: apdu.len(),
        max: u32::MAX as usize,
    })?;
    let mut out = Vec::with_capacity(LENGTH_PREFIX_LEN + apdu.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(apdu);
    Ok(out)
}

/// A reply as speculos puts it on the wire: the prefix counts the data only,
/// and the status word follows outside it.
///
/// `reply` is the whole payload, data and status word together — the shape
/// [`Transport::exchange`] hands back. `None` for a reply too short to contain
/// a status word, which the emulator's own `len(packet) - 2` would underflow
/// on.
#[cfg(test)]
pub(crate) fn frame_reply(reply: &[u8]) -> Option<Vec<u8>> {
    let data_len = reply.len().checked_sub(STATUS_WORD_LEN)?;
    let mut out = Vec::with_capacity(LENGTH_PREFIX_LEN + reply.len());
    out.extend_from_slice(&(data_len as u32).to_be_bytes());
    out.extend_from_slice(reply);
    Some(out)
}

#[cfg(test)]
mod tests;
