//! Response parsing, per `docs/APDU.md` (`LedgerHQ/app-zcash` @ `22dc385`).
//!
//! A response payload here is what the transport hands back: response data
//! followed by the two-byte status word. [`split_status_word`] separates them;
//! everything else in this module takes the data half.

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::StatusWord;

/// Length of an Orchard / Ironwood spend-authorization signature.
///
/// `handler_pczt_sign_orchard` and `handler_pczt_sign_ironwood` both append a
/// RedPallas `SpendAuthSig`; `docs/APDU.md` states `[u8; 64]` for each.
pub const SPEND_AUTH_SIG_LEN: usize = 64;

/// Length of the raw Orchard FVK returned by `GET_VK` with P2 `0x01`.
pub const ORCHARD_FVK_LEN: usize = 96;

/// Length of the `GET_FIRMWARE_VERSION` reply.
pub const FIRMWARE_VERSION_LEN: usize = 8;

/// Length of the uncompressed secp256k1 public key in a
/// `GET_WALLET_PUBLIC_KEY` reply.
///
/// `ExtendedPublicKey::public_key_len` is 65 on every model the app builds for;
/// the reply carries the length as its first byte all the same, and this
/// parser refuses any other value rather than guessing at the field boundaries
/// that follow it.
pub const WALLET_PUBLIC_KEY_LEN: usize = 65;

/// Length of the chain code trailing a `GET_WALLET_PUBLIC_KEY` reply.
///
/// `handler_get_public_key`: "Don't encode chain code length, it's always 32
/// bytes."
pub const CHAIN_CODE_LEN: usize = 32;

/// How many `GET_VK` continuations a response may need.
///
/// `MAX_VK_CONTINUATIONS` in `tests/application_client/zcash_command_sender.py`
/// (`LedgerHQ/app-zcash` @ `cfbf096`): "The device streams a viewing key in
/// chunks of MAX_APDU_LEN (`VK_RESPONSE_CHUNK_LEN` in
/// `src/handlers/get_vk.rs`) … A unified viewing key runs a little over 300
/// bytes, so one continuation is the real case and the Orchard-only mode needs
/// none. This ceiling is several times that, high enough never to trip on a
/// longer key."
pub const MAX_VK_CONTINUATIONS: usize = 4;

/// The largest `GET_VK` response [`VkReassembler`] will assemble: the two
/// length bytes plus a full chunk for the request and each continuation.
pub const MAX_VK_RESPONSE_LEN: usize = 2 + super::MAX_APDU_DATA * (MAX_VK_CONTINUATIONS + 1);

/// `LEGACY_VERSION_PREFIX` in `src/handlers/get_version.rs`.
pub const LEGACY_VERSION_PREFIX: u8 = 0x38;
/// `ARCH_ID` in `src/handlers/get_version.rs`.
pub const ARCH_ID: u8 = 0x30;

/// A response that did not have the shape the protocol promises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Fewer bytes than the two-byte status word.
    TooShortForStatusWord {
        /// Bytes received.
        got: usize,
    },
    /// The command failed; the status word says how.
    Status(StatusWord),
    /// A fixed-length reply arrived at the wrong length.
    UnexpectedLength {
        /// What was being parsed.
        what: &'static str,
        /// Length required.
        expected: usize,
        /// Length received.
        got: usize,
    },
    /// A `GET_WALLET_PUBLIC_KEY` reply carried bytes that are not a point on
    /// the secp256k1 curve.
    ///
    /// Checked here rather than left to the caller because the identity this
    /// key is hashed into ([`crate::pairing::DeviceIdentity`]) is only
    /// meaningful if the bytes really are a public key: compressing them is
    /// what makes two encodings of one key hash the same, and only a valid
    /// point can be compressed.
    InvalidPublicKey {
        /// What `secp256k1` said about the 65 bytes.
        reason: String,
    },
    /// A reply was shorter than its own minimum.
    Truncated {
        /// What was being parsed.
        what: &'static str,
        /// Smallest acceptable length.
        min: usize,
        /// Length received.
        got: usize,
    },
    /// The `GET_FIRMWARE_VERSION` reply did not start with the two constant
    /// bytes `0x38 0x30`.
    BadVersionPrefix {
        /// The two leading bytes received.
        got: [u8; 2],
    },
    /// A string response was not valid UTF-8.
    NotUtf8,
    /// More response bytes arrived than the reply declared.
    Overrun {
        /// Bytes expected in total.
        expected: usize,
        /// Bytes accumulated.
        got: usize,
    },
    /// A `GET_VK` reply announced a length beyond what the device can stream.
    ///
    /// The two leading bytes of a UFVK response are the host's only statement
    /// of how long the transfer is, and they come from the device. Believing an
    /// announcement larger than the device could ever deliver is what makes a
    /// collector ask for continuations forever (`LedgerHQ/app-zcash` @
    /// `cfbf096`: "driven by a device that announces ten bytes it never sends,
    /// the old loop was still asking after two hundred thousand
    /// continuations").
    VkResponseTooLong {
        /// The length the reply announced.
        announced: usize,
        /// [`MAX_VK_RESPONSE_LEN`].
        max: usize,
    },
    /// A `GET_VK` reply carried no data while the response was still short.
    ///
    /// An empty chunk leaves the accumulated length where it was, so a caller
    /// driven by "keep going until it is complete" would ask again with the
    /// same result. The status word is `0x9000` in this case, so nothing else
    /// stops it.
    VkNoProgress {
        /// Bytes accumulated so far.
        got: usize,
        /// Bytes the reply announced in total.
        expected: usize,
    },
    /// A `GET_VK` response was still incomplete after
    /// [`MAX_VK_CONTINUATIONS`] continuations.
    ///
    /// Bounds a device that keeps adding a byte at a time, which the length
    /// ceiling alone does not.
    VkTooManyChunks {
        /// Bytes accumulated so far.
        got: usize,
        /// Bytes the reply announced in total.
        expected: usize,
        /// [`MAX_VK_CONTINUATIONS`].
        max_continuations: usize,
    },
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::TooShortForStatusWord { got } => {
                write!(f, "response of {got} bytes carries no status word")
            }
            DecodeError::Status(sw) => write!(f, "device returned {:#06x}", sw.to_u16()),
            DecodeError::UnexpectedLength {
                what,
                expected,
                got,
            } => write!(f, "{what} must be {expected} bytes, got {got}"),
            DecodeError::InvalidPublicKey { reason } => {
                write!(
                    f,
                    "the device returned bytes that are not a public key: {reason}"
                )
            }
            DecodeError::Truncated { what, min, got } => {
                write!(f, "{what} needs at least {min} bytes, got {got}")
            }
            DecodeError::BadVersionPrefix { got } => write!(
                f,
                "firmware version prefix {:#04x} {:#04x}, expected 0x38 0x30",
                got[0], got[1]
            ),
            DecodeError::NotUtf8 => write!(f, "string response is not valid UTF-8"),
            DecodeError::Overrun { expected, got } => {
                write!(f, "response overran: expected {expected} bytes, got {got}")
            }
            DecodeError::VkResponseTooLong { announced, max } => write!(
                f,
                "device announced a {announced}-byte viewing-key response, beyond the {max} \
                 bytes this collector will assemble"
            ),
            DecodeError::VkNoProgress { got, expected } => write!(
                f,
                "viewing-key continuation returned no data, {got} of {expected} bytes collected"
            ),
            DecodeError::VkTooManyChunks {
                got,
                expected,
                max_continuations,
            } => write!(
                f,
                "viewing-key response still short of the announced {expected} bytes ({got} \
                 collected) after {max_continuations} continuations"
            ),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Splits the trailing status word off a response payload.
///
/// The status word is the last two bytes, big-endian.
pub fn split_status_word(resp: &[u8]) -> Result<(&[u8], StatusWord), DecodeError> {
    if resp.len() < 2 {
        return Err(DecodeError::TooShortForStatusWord { got: resp.len() });
    }
    let split = resp.len() - 2;
    let sw = u16::from_be_bytes([resp[split], resp[split + 1]]);
    Ok((&resp[..split], StatusWord::from_u16(sw)))
}

/// Splits off the status word and fails on anything but `0x9000`.
pub fn expect_ok(resp: &[u8]) -> Result<&[u8], DecodeError> {
    let (data, sw) = split_status_word(resp)?;
    if sw.is_ok() {
        Ok(data)
    } else {
        Err(DecodeError::Status(sw))
    }
}

/// The `GET_FIRMWARE_VERSION` reply.
///
/// `docs/APDU.md` and `src/handlers/get_version.rs`: eight bytes —
/// `0x38`, `0x30`, app major, app minor, app patch, SDK major, SDK minor,
/// API level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirmwareVersion {
    /// App major version.
    pub major: u8,
    /// App minor version.
    pub minor: u8,
    /// App patch version.
    pub patch: u8,
    /// Ledger SDK major version.
    pub sdk_major: u8,
    /// Ledger SDK minor version.
    pub sdk_minor: u8,
    /// Ledger API level.
    pub api_level: u8,
}

impl core::fmt::Display for FirmwareVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Parses the eight-byte `GET_FIRMWARE_VERSION` reply data.
pub fn parse_firmware_version(data: &[u8]) -> Result<FirmwareVersion, DecodeError> {
    if data.len() != FIRMWARE_VERSION_LEN {
        return Err(DecodeError::UnexpectedLength {
            what: "firmware version",
            expected: FIRMWARE_VERSION_LEN,
            got: data.len(),
        });
    }
    if data[0] != LEGACY_VERSION_PREFIX || data[1] != ARCH_ID {
        return Err(DecodeError::BadVersionPrefix {
            got: [data[0], data[1]],
        });
    }
    Ok(FirmwareVersion {
        major: data[2],
        minor: data[3],
        patch: data[4],
        sdk_major: data[5],
        sdk_minor: data[6],
        api_level: data[7],
    })
}

/// The `GET_WALLET_PUBLIC_KEY` reply, less its address.
///
/// `docs/APDU.md` and `handler_get_public_key` @ `22dc385`:
/// `public_key_len u8` ‖ public key ‖ `address_len u8` ‖ address ASCII ‖
/// `chain_code [u8; 32]`.
///
/// # The address is discarded
///
/// The reply carries the **account's own receiving address** at the path that
/// was asked for. It is what a `display = true` call puts on the device's
/// screen for a human to compare; the host has no use for it — a wallet
/// derives its own addresses from its own keys — and an identity probe is not
/// a request to reveal one, so [`parse_wallet_public_key`] validates the
/// field's shape and drops it. Nothing of it reaches this type.
///
/// The key and chain code that remain name the account's transparent chain,
/// so `Debug` redacts them too; a signer's stderr may end up in a wallet
/// daemon's log.
#[derive(Clone, PartialEq, Eq)]
pub struct WalletPublicKey {
    public_key: [u8; WALLET_PUBLIC_KEY_LEN],
    chain_code: [u8; CHAIN_CODE_LEN],
}

impl core::fmt::Debug for WalletPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WalletPublicKey")
            .field("public_key", &"[redacted]")
            .field("chain_code", &"[redacted]")
            .finish()
    }
}

impl WalletPublicKey {
    /// The uncompressed secp256k1 public key, [`WALLET_PUBLIC_KEY_LEN`] bytes.
    ///
    /// Checked to be a point on the curve by [`parse_wallet_public_key`].
    pub fn public_key(&self) -> &[u8; WALLET_PUBLIC_KEY_LEN] {
        &self.public_key
    }

    /// The BIP 32 chain code at the derived path.
    pub fn chain_code(&self) -> &[u8; CHAIN_CODE_LEN] {
        &self.chain_code
    }

    /// The 33-byte compressed encoding of [`WalletPublicKey::public_key`].
    ///
    /// The compressed form is the one every other part of this crate names a
    /// transparent key by — `bip32_derivation` entries, [`crate::shape`]'s
    /// change pubkey, and the identity in [`crate::pairing`] — so a device
    /// reply is converted once, here, rather than in each caller.
    pub fn compressed(&self) -> Result<[u8; super::encode::COMPRESSED_PUBKEY_SIZE], DecodeError> {
        Ok(secp256k1::PublicKey::from_slice(&self.public_key)
            .map_err(|e| DecodeError::InvalidPublicKey {
                reason: e.to_string(),
            })?
            .serialize())
    }
}

/// Parses a `GET_WALLET_PUBLIC_KEY` reply's data.
///
/// Every field boundary is taken from a length the device sent, and each is
/// checked against what remains before it is used, so a truncated or padded
/// reply is refused rather than re-cut. The public key must be a point on the
/// curve and the address must be ASCII — it is base58, and a non-ASCII byte
/// there means the reply is not the shape the protocol promises. The address
/// is then discarded; see [`WalletPublicKey`].
pub fn parse_wallet_public_key(data: &[u8]) -> Result<WalletPublicKey, DecodeError> {
    // `1 + 65 + 1 + 0 + 32`, an address of length zero included so that the
    // length byte itself is what refuses it below rather than this bound.
    const MIN: usize = 2 + WALLET_PUBLIC_KEY_LEN + CHAIN_CODE_LEN;
    if data.len() < MIN {
        return Err(DecodeError::Truncated {
            what: "wallet public key",
            min: MIN,
            got: data.len(),
        });
    }

    let pk_len = data[0] as usize;
    if pk_len != WALLET_PUBLIC_KEY_LEN {
        return Err(DecodeError::UnexpectedLength {
            what: "wallet public key",
            expected: WALLET_PUBLIC_KEY_LEN,
            got: pk_len,
        });
    }
    let mut public_key = [0u8; WALLET_PUBLIC_KEY_LEN];
    public_key.copy_from_slice(&data[1..1 + WALLET_PUBLIC_KEY_LEN]);
    secp256k1::PublicKey::from_slice(&public_key).map_err(|e| DecodeError::InvalidPublicKey {
        reason: e.to_string(),
    })?;

    let rest = &data[1 + WALLET_PUBLIC_KEY_LEN..];
    let addr_len = rest[0] as usize;
    let expected = 1 + addr_len + CHAIN_CODE_LEN;
    if rest.len() != expected {
        return Err(DecodeError::UnexpectedLength {
            what: "wallet public key address and chain code",
            expected,
            got: rest.len(),
        });
    }
    // The address is checked for shape and never copied out of the reply.
    let address_bytes = &rest[1..1 + addr_len];
    if !address_bytes.is_ascii() {
        // The field is base58, so this is the same failure as a string
        // response that is not text at all.
        return Err(DecodeError::NotUtf8);
    }

    let mut chain_code = [0u8; CHAIN_CODE_LEN];
    chain_code.copy_from_slice(&rest[1 + addr_len..]);

    Ok(WalletPublicKey {
        public_key,
        chain_code,
    })
}

/// The `PCZT_SIGN_TRANSPARENT` reply.
///
/// `docs/APDU.md`: "DER-encoded secp256k1 signature bytes" then
/// "`sighash_type u8`, currently `0x01`". The sighash byte is the last one, so
/// the DER blob is everything before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentSignature {
    /// The DER-encoded secp256k1 signature, without the sighash byte.
    pub der: Vec<u8>,
    /// The trailing sighash type, `SIGHASH_ALL`.
    pub sighash_type: u8,
}

/// Parses the transparent signing reply data.
///
/// The shortest well-formed DER ECDSA signature is 8 bytes
/// (`30 06 02 01 r 02 01 s`), so a reply under 9 bytes cannot be one.
pub fn parse_transparent_signature(data: &[u8]) -> Result<TransparentSignature, DecodeError> {
    const MIN: usize = 9;
    if data.len() < MIN {
        return Err(DecodeError::Truncated {
            what: "transparent signature",
            min: MIN,
            got: data.len(),
        });
    }
    let split = data.len() - 1;
    Ok(TransparentSignature {
        der: data[..split].to_vec(),
        sighash_type: data[split],
    })
}

/// Parses an Orchard or Ironwood spend-authorization signature: exactly 64
/// bytes, no trailer.
pub fn parse_shielded_signature(data: &[u8]) -> Result<[u8; SPEND_AUTH_SIG_LEN], DecodeError> {
    if data.len() != SPEND_AUTH_SIG_LEN {
        return Err(DecodeError::UnexpectedLength {
            what: "spend authorization signature",
            expected: SPEND_AUTH_SIG_LEN,
            got: data.len(),
        });
    }
    let mut sig = [0u8; SPEND_AUTH_SIG_LEN];
    sig.copy_from_slice(data);
    Ok(sig)
}

/// Which `GET_VK` response is being reassembled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VkKind {
    /// P2 `0x00`: a string response — `len u16` big-endian, then UTF-8 bytes.
    Ufvk,
    /// P2 `0x01`: [`ORCHARD_FVK_LEN`] raw bytes, with no length prefix, so the
    /// total is known up front.
    OrchardFvk,
}

/// A completed `GET_VK` response.
///
/// A viewing key identifies and decrypts every note of the account, so
/// `Debug` shows only which kind and how long. The value is handed to the
/// caller by move and is not wiped on drop — a `Drop` impl would stop the
/// caller taking the key out by pattern — but it implements [`Zeroize`], so
/// the caller can wipe it once it has been stored.
#[derive(Clone, PartialEq, Eq, Zeroize)]
pub enum VkResponse {
    /// The unified full viewing key string.
    Ufvk(String),
    /// The raw Orchard full viewing key.
    OrchardFvk(Vec<u8>),
}

impl core::fmt::Debug for VkResponse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VkResponse::Ufvk(s) => write!(f, "Ufvk([redacted; {} chars])", s.len()),
            VkResponse::OrchardFvk(b) => write!(f, "OrchardFvk([redacted; {} bytes])", b.len()),
        }
    }
}

/// Reassembles a chunked `GET_VK` response.
///
/// `handler_get_vk` emits at most `VK_RESPONSE_CHUNK_LEN` (255) bytes per
/// reply and keeps the rest pending; the host asks for the remainder with
/// P1 `0x80` and empty data ([`super::encode::get_vk_continue_apdu`]) until
/// [`VkReassembler::push`] reports completion.
///
/// For the UFVK, `docs/APDU.md`: "the first two response bytes encode the
/// total UTF-8 string length" — so the total transfer is `2 + len` bytes.
///
/// The buffer holds viewing-key bytes, so it is wiped on drop and `Debug`
/// reports only its length.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VkReassembler {
    #[zeroize(skip)]
    kind: VkKind,
    buf: Vec<u8>,
    /// Replies absorbed so far, the request's own included.
    #[zeroize(skip)]
    chunks: usize,
}

impl core::fmt::Debug for VkReassembler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VkReassembler")
            .field("kind", &self.kind)
            .field("buf", &format_args!("[redacted; {} bytes]", self.buf.len()))
            .field("chunks", &self.chunks)
            .finish()
    }
}

impl VkReassembler {
    /// Starts a reassembly for the given response kind.
    pub fn new(kind: VkKind) -> Self {
        VkReassembler {
            kind,
            buf: Vec::new(),
            chunks: 0,
        }
    }

    /// Bytes accumulated so far.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether nothing has been accumulated yet.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The total transfer length, once it is known.
    ///
    /// For [`VkKind::OrchardFvk`] this is known immediately; for
    /// [`VkKind::Ufvk`] it takes the first two bytes.
    pub fn total_len(&self) -> Option<usize> {
        match self.kind {
            VkKind::OrchardFvk => Some(ORCHARD_FVK_LEN),
            VkKind::Ufvk => {
                if self.buf.len() < 2 {
                    None
                } else {
                    Some(2 + u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize)
                }
            }
        }
    }

    /// Absorbs one response chunk, returning the response once it is complete.
    ///
    /// The caller passes the reply *data* (status word already stripped).
    ///
    /// # Bounds
    ///
    /// Three guards, mirroring `LedgerHQ/app-zcash` @ `cfbf096` on the
    /// firmware's own test client. All three exist for one failure: a device
    /// that announces a response it will not deliver, against a caller whose
    /// loop is "ask again until it is complete".
    ///
    /// 1. the announced length may not exceed [`MAX_VK_RESPONSE_LEN`];
    /// 2. a chunk that carries no data is refused, since it leaves the
    ///    accumulated length untouched and its status word is `0x9000`;
    /// 3. the response must complete within [`MAX_VK_CONTINUATIONS`]
    ///    continuations, which bounds a device adding a byte at a time.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Option<VkResponse>, DecodeError> {
        // Announced-length guard first, so a chunk is never appended to a
        // buffer that is already growing towards a length this will not serve.
        if let Some(announced) = self.total_len() {
            if announced > MAX_VK_RESPONSE_LEN {
                return Err(DecodeError::VkResponseTooLong {
                    announced,
                    max: MAX_VK_RESPONSE_LEN,
                });
            }
        }

        if chunk.is_empty() {
            return Err(DecodeError::VkNoProgress {
                got: self.buf.len(),
                expected: self.total_len().unwrap_or(0),
            });
        }

        self.buf.extend_from_slice(chunk);
        self.chunks += 1;

        let Some(total) = self.total_len() else {
            return Err(DecodeError::Truncated {
                what: "viewing key length prefix",
                min: 2,
                got: self.buf.len(),
            });
        };
        if total > MAX_VK_RESPONSE_LEN {
            return Err(DecodeError::VkResponseTooLong {
                announced: total,
                max: MAX_VK_RESPONSE_LEN,
            });
        }
        if self.buf.len() < total {
            // `chunks` counts the request's reply too, so the continuation
            // budget is spent once it passes `MAX_VK_CONTINUATIONS + 1`.
            if self.chunks > MAX_VK_CONTINUATIONS {
                return Err(DecodeError::VkTooManyChunks {
                    got: self.buf.len(),
                    expected: total,
                    max_continuations: MAX_VK_CONTINUATIONS,
                });
            }
            return Ok(None);
        }
        if self.buf.len() > total {
            return Err(DecodeError::Overrun {
                expected: total,
                got: self.buf.len(),
            });
        }

        match self.kind {
            VkKind::OrchardFvk => Ok(Some(VkResponse::OrchardFvk(core::mem::take(&mut self.buf)))),
            VkKind::Ufvk => {
                let s =
                    String::from_utf8(self.buf[2..].to_vec()).map_err(|_| DecodeError::NotUtf8)?;
                self.buf.zeroize();
                Ok(Some(VkResponse::Ufvk(s)))
            }
        }
    }
}

/// Parses a whole string response — `len u16` big-endian then UTF-8 bytes.
///
/// `encode_string_response` in `src/utils.rs`. Used for the unified address
/// (`GET_SHIELD_ADDR` P2 `0x00`), which is short enough to arrive in one
/// reply.
pub fn parse_string_response(data: &[u8]) -> Result<String, DecodeError> {
    if data.len() < 2 {
        return Err(DecodeError::Truncated {
            what: "string response",
            min: 2,
            got: data.len(),
        });
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() != 2 + len {
        return Err(DecodeError::UnexpectedLength {
            what: "string response",
            expected: 2 + len,
            got: data.len(),
        });
    }
    String::from_utf8(data[2..].to_vec()).map_err(|_| DecodeError::NotUtf8)
}
