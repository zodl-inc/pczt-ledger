//! Response parsing, per `docs/APDU.md` (`LedgerHQ/app-zcash` @ `22dc385`).
//!
//! A response payload here is what the transport hands back: response data
//! followed by the two-byte status word. [`split_status_word`] separates them;
//! everything else in this module takes the data half.

use alloc::{
    borrow::ToOwned,
    string::{String, ToString},
    vec::Vec,
};

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{StatusWord, STATUS_WORD_LEN};

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
/// The device streams a viewing key in chunks of `VK_RESPONSE_CHUNK_LEN`
/// (`src/handlers/get_vk.rs`), so a unified viewing key of a little over 300
/// bytes takes one continuation and the Orchard-only mode takes none. This
/// ceiling is several times that, and is the value the firmware's own test
/// client uses (`MAX_VK_CONTINUATIONS` in
/// `tests/application_client/zcash_command_sender.py` @ `22dc385`).
pub const MAX_VK_CONTINUATIONS: usize = 4;

/// The largest `GET_VK` response [`VkReassembler`] will assemble: a full
/// chunk for the request and each continuation. The two length bytes are
/// inside the first chunk, not on top of it.
pub const MAX_VK_RESPONSE_LEN: usize = super::MAX_APDU_DATA * (MAX_VK_CONTINUATIONS + 1);

/// `LEGACY_VERSION_PREFIX` in `src/handlers/get_version.rs`.
pub const LEGACY_VERSION_PREFIX: u8 = 0x38;
/// `ARCH_ID` in `src/handlers/get_version.rs`.
pub const ARCH_ID: u8 = 0x30;

/// A response that did not have the shape the protocol promises.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    /// of how long the transfer is, and they come from the device. Refusing an
    /// announcement above [`MAX_VK_RESPONSE_LEN`] is what keeps a collector
    /// whose loop is "ask again until it is complete" from following a device
    /// that announces more than it will ever send.
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
    /// A chunk was offered to a [`VkReassembler`] whose transfer had already
    /// ended, in a complete response or in an error.
    ///
    /// A reassembly ends on its first error: the bytes collected so far are
    /// wiped and nothing more is absorbed, so a caller whose loop is "ask
    /// again until it is complete" cannot resume a transfer the device has
    /// already got wrong, and cannot restart one in a buffer that no longer
    /// holds its beginning.
    VkAbandoned,
    /// A `PCZT_SIGN_TRANSPARENT` reply is not the shape `append_signature`
    /// writes: a DER `SEQUENCE` whose tag may carry the device's `y`-parity
    /// bit, a length the reply matches exactly, and one trailing
    /// [`SIGHASH_ALL`](crate::apdu::encode::SIGHASH_ALL) byte.
    InvalidTransparentSignature {
        /// Which of those rules the reply broke.
        reason: &'static str,
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
            DecodeError::VkAbandoned => write!(
                f,
                "viewing-key reassembly has already ended; the chunk was not absorbed"
            ),
            DecodeError::InvalidTransparentSignature { reason } => write!(
                f,
                "the transparent signing reply is not the shape the device writes: {reason}"
            ),
        }
    }
}

impl core::error::Error for DecodeError {}

/// Splits the trailing status word off a response payload.
///
/// The status word is the last two bytes, big-endian.
///
/// # Errors
///
/// [`DecodeError::TooShortForStatusWord`] when `resp` is shorter than the two
/// status bytes.
pub fn split_status_word(resp: &[u8]) -> Result<(&[u8], StatusWord), DecodeError> {
    if resp.len() < STATUS_WORD_LEN {
        return Err(DecodeError::TooShortForStatusWord { got: resp.len() });
    }
    let split = resp.len() - STATUS_WORD_LEN;
    let sw = u16::from_be_bytes([resp[split], resp[split + 1]]);
    Ok((&resp[..split], StatusWord::from_u16(sw)))
}

/// Splits off the status word and fails on anything but `0x9000`.
///
/// # Errors
///
/// [`DecodeError::TooShortForStatusWord`] as [`split_status_word`], and
/// [`DecodeError::Status`] carrying any status word but `0x9000`.
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
    pub(crate) major: u8,
    /// App minor version.
    pub(crate) minor: u8,
    /// App patch version.
    pub(crate) patch: u8,
    /// Ledger SDK major version.
    pub(crate) sdk_major: u8,
    /// Ledger SDK minor version.
    pub(crate) sdk_minor: u8,
    /// Ledger API level.
    pub(crate) api_level: u8,
}

impl FirmwareVersion {
    /// App major version.
    pub fn major(&self) -> u8 {
        self.major
    }

    /// App minor version.
    pub fn minor(&self) -> u8 {
        self.minor
    }

    /// App patch version.
    pub fn patch(&self) -> u8 {
        self.patch
    }

    /// Ledger SDK major version.
    pub fn sdk_major(&self) -> u8 {
        self.sdk_major
    }

    /// Ledger SDK minor version.
    pub fn sdk_minor(&self) -> u8 {
        self.sdk_minor
    }

    /// Ledger API level.
    pub fn api_level(&self) -> u8 {
        self.api_level
    }
}

impl core::fmt::Display for FirmwareVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Parses the eight-byte `GET_FIRMWARE_VERSION` reply data.
///
/// # Errors
///
/// [`DecodeError::UnexpectedLength`] when `data` is not exactly eight bytes,
/// and [`DecodeError::BadVersionPrefix`] when it does not open with the legacy
/// `0x38 0x30` prefix.
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
    ///
    /// # Errors
    ///
    /// [`DecodeError::InvalidPublicKey`] when the 65 bytes are not a point on
    /// the curve — which [`parse_wallet_public_key`] has already refused, so
    /// this is the conversion being fallible by signature.
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
///
/// # Errors
///
/// [`DecodeError::Truncated`] and [`DecodeError::UnexpectedLength`] for a reply
/// cut short of, or padded past, its own length fields;
/// [`DecodeError::InvalidPublicKey`] for a key that is not a point on the
/// curve; [`DecodeError::NotUtf8`] for an address that is not ASCII.
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
///
/// # The DER stays encoded
///
/// Nothing here decodes the signature. [`crate::apply::normalize_ledger_der`]
/// does, over the whole reply — DER blob and sighash byte rejoined — on the
/// way to the `pczt` Signer role: it clears the y-parity bit the device ORs
/// into the SEQUENCE tag, strips the sighash byte, and requires the parsed
/// signature to re-serialize to exactly the bytes it was handed, which is what
/// catches a non-canonical encoding. That comparison means something only
/// against the bytes the device sent, so decoding here would not save a round
/// trip; it would cost the check. The layering says the same: `apdu` is the
/// bottom of the stack and `apply` sits above it, so a decode here would be a
/// second copy of that function rather than a call to it.
///
/// `Debug` shows the blob's length and the sighash byte, not the blob: the
/// signature appears verbatim in the `scriptSig` once the transaction is
/// mined, so a logged one joins the log line to the chain.
#[derive(Clone, PartialEq, Eq)]
pub struct TransparentSignature {
    /// The DER-encoded secp256k1 signature, without the sighash byte.
    pub(crate) der: Vec<u8>,
    /// The trailing sighash type, `SIGHASH_ALL`.
    pub(crate) sighash_type: u8,
}

impl core::fmt::Debug for TransparentSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TransparentSignature")
            .field("der", &format_args!("[{} bytes]", self.der.len()))
            .field("sighash_type", &format_args!("{:#04x}", self.sighash_type))
            .finish()
    }
}

impl TransparentSignature {
    /// The DER-encoded secp256k1 signature, without the sighash byte and
    /// with the device's quirks intact; see
    /// [`crate::apply::normalize_ledger_der`].
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The trailing sighash type byte.
    pub fn sighash_type(&self) -> u8 {
        self.sighash_type
    }
}

/// Parses the transparent signing reply data.
///
/// `append_signature` (`src/handlers/sign_tx.rs` @ `22dc385`) writes the DER
/// signature the device SDK produced — with the `y`-parity bit ORed into the
/// `SEQUENCE` tag when the `y` coordinate is odd, turning `0x30` into
/// `0x31` — and then one sighash byte, which is the sighash type the PCZT
/// declared and `parse_transparent_input_sighash_type` already pinned to
/// [`SIGHASH_ALL`](crate::apdu::encode::SIGHASH_ALL) on the way in. This
/// checks the reply against that shape whole, rather than splitting the last
/// byte off and leaving the rest to
/// [`crate::apply::normalize_ledger_der`]: every other reply arm is exact
/// about its shape, and a transport one reply behind would otherwise have a
/// 64-byte shielded signature absorbed as a transparent one, the session
/// report itself complete, and the ceremony fail only in
/// [`crate::session::LedgerSignSession::finish`] — after the user has
/// approved.
///
/// The bytes are kept as the device sent them, both quirks intact; undoing
/// them and parsing the signature is
/// [`crate::apply::normalize_ledger_der`]'s job.
///
/// # Errors
///
/// [`DecodeError::Truncated`] when the reply is shorter than the shortest DER
/// signature plus the sighash byte; [`DecodeError::UnexpectedLength`] when it
/// is longer than the longest signature the device's SDK emits, or when its
/// length is not the one the DER header declares plus that byte; and
/// [`DecodeError::InvalidTransparentSignature`] when the header byte is
/// neither `0x30` nor the device's odd-`y` `0x31`, or when the trailing byte
/// is not [`SIGHASH_ALL`](crate::apdu::encode::SIGHASH_ALL).
pub fn parse_transparent_signature(data: &[u8]) -> Result<TransparentSignature, DecodeError> {
    /// How the reply is named in the errors below.
    const WHAT: &str = "transparent signature";
    /// The shortest well-formed DER ECDSA signature is 8 bytes
    /// (`30 06 02 01 r 02 01 s`), and the device appends the sighash byte.
    const MIN: usize = 9;
    /// The longest DER signature the `ledger_device_sdk` ECDSA output holds —
    /// the `SEQUENCE` header plus two `INTEGER`s of a 32-byte scalar, each
    /// with the leading zero byte a high bit forces, `2 + 2 * (2 + 33)` —
    /// plus the sighash byte.
    const MAX: usize = 72 + 1;
    /// The DER `SEQUENCE` tag, which an even-`y` signature carries unchanged.
    const SEQUENCE_TAG: u8 = 0x30;
    /// The same tag with the `y`-parity bit `append_signature` ORs into it
    /// when the `y` coordinate is odd. The crate tolerates both: the device
    /// emits the canonical tag whenever the parity bit is clear.
    const SEQUENCE_TAG_ODD_Y: u8 = 0x31;
    /// Tag, length byte, the content the length byte declares, and the
    /// trailing sighash byte.
    const FRAMING_BYTES: usize = 3;

    if data.len() < MIN {
        return Err(DecodeError::Truncated {
            what: WHAT,
            min: MIN,
            got: data.len(),
        });
    }
    if data.len() > MAX {
        return Err(DecodeError::UnexpectedLength {
            what: WHAT,
            expected: MAX,
            got: data.len(),
        });
    }
    if data[0] != SEQUENCE_TAG && data[0] != SEQUENCE_TAG_ODD_Y {
        return Err(DecodeError::InvalidTransparentSignature {
            reason: "the first byte is neither the DER SEQUENCE tag nor the device's odd-y form",
        });
    }
    // A long-form length byte needs no check of its own: it declares at least
    // 128 content bytes, which no reply inside `MAX` can carry, so the
    // equality below refuses it.
    let declared = usize::from(data[1]) + FRAMING_BYTES;
    if data.len() != declared {
        return Err(DecodeError::UnexpectedLength {
            what: WHAT,
            expected: declared,
            got: data.len(),
        });
    }

    let split = data.len() - 1;
    let sighash_type = data[split];
    if sighash_type != crate::apdu::encode::SIGHASH_ALL {
        return Err(DecodeError::InvalidTransparentSignature {
            reason: "the trailing byte is a sighash type other than SIGHASH_ALL",
        });
    }

    Ok(TransparentSignature {
        der: data[..split].to_vec(),
        sighash_type,
    })
}

/// Parses an Orchard or Ironwood spend-authorization signature: exactly 64
/// bytes, no trailer.
///
/// # Errors
///
/// [`DecodeError::UnexpectedLength`] when the reply is not exactly 64 bytes.
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
/// reports only its length. The reassembler is not `Clone`: a cloned buffer
/// lacks the capacity [`VkReassembler::new`] reserves, so the copy would
/// reallocate as it grew and leave the key bytes it held behind, unwiped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VkReassembler {
    #[zeroize(skip)]
    kind: VkKind,
    buf: Vec<u8>,
    /// Replies absorbed so far, the request's own included.
    #[zeroize(skip)]
    chunks: usize,
    #[zeroize(skip)]
    state: Reassembly,
}

/// Whether a [`VkReassembler`] is still absorbing chunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reassembly {
    /// Chunks are being absorbed.
    Open,
    /// The transfer ended — in a complete response or in an error — and the
    /// buffer has been wiped; nothing more is absorbed.
    Ended,
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
            buf: Vec::with_capacity(Self::capacity(kind)),
            chunks: 0,
            state: Reassembly::Open,
        }
    }

    /// The buffer size [`VkReassembler::new`] reserves for a kind: the largest
    /// response it can announce.
    ///
    /// The buffer is never grown past it. A buffer that grows reallocates, and
    /// the allocation it grew out of keeps its copy of the key bytes past the
    /// wipe, so this is a bound on the transfer and not merely a hint.
    const fn capacity(kind: VkKind) -> usize {
        match kind {
            VkKind::OrchardFvk => ORCHARD_FVK_LEN,
            VkKind::Ufvk => MAX_VK_RESPONSE_LEN,
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
    /// Three guards, matching the ones the firmware's own test client applies
    /// (`tests/application_client/zcash_command_sender.py` @ `22dc385`). All
    /// three bound one failure: a device that announces a response it will not
    /// deliver, against a caller whose loop is "ask again until it is
    /// complete".
    ///
    /// 1. the announced length may not exceed [`MAX_VK_RESPONSE_LEN`];
    /// 2. a chunk that carries no data is refused, since it leaves the
    ///    accumulated length untouched and its status word is `0x9000`;
    /// 3. the response must complete within [`MAX_VK_CONTINUATIONS`]
    ///    continuations, which bounds a device adding a byte at a time.
    ///
    /// A chunk that would take the buffer past the length the reply announced,
    /// or — before that length is known — past the capacity reserved for the
    /// kind, is refused *before* it is appended: the buffer is sized once so
    /// that the key bytes in it never move, and nothing between the deframer
    /// and here bounds what a reply carries.
    ///
    /// # End of the transfer
    ///
    /// A reassembly ends on its first error and on the completed response. The
    /// buffer is wiped and every later chunk is [`DecodeError::VkAbandoned`],
    /// so a caller that keeps pushing can neither resume a transfer the device
    /// got wrong nor start a second one in this buffer.
    ///
    /// # Errors
    ///
    /// [`DecodeError::VkResponseTooLong`] when the declared length is past
    /// [`MAX_VK_RESPONSE_LEN`]; [`DecodeError::VkTooManyChunks`] past
    /// [`MAX_VK_CONTINUATIONS`] continuations; [`DecodeError::VkNoProgress`]
    /// for a chunk that carries nothing; [`DecodeError::Overrun`] for data past
    /// the declared length; [`DecodeError::Truncated`] for a first chunk
    /// without its length prefix; [`DecodeError::NotUtf8`] for a unified key
    /// that is not UTF-8; [`DecodeError::VkAbandoned`] for a chunk offered
    /// after the transfer ended.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Option<VkResponse>, DecodeError> {
        if self.state == Reassembly::Ended {
            return Err(DecodeError::VkAbandoned);
        }
        let result = self.absorb(chunk);
        if !matches!(result, Ok(None)) {
            // Everything but "more to come" ends the transfer. The completed
            // response has been moved out; what stays behind is wiped either
            // way, so a later push cannot append to a partial key.
            self.state = Reassembly::Ended;
            self.buf.zeroize();
        }
        result
    }

    /// [`VkReassembler::push`] without the end-of-transfer latch.
    fn absorb(&mut self, chunk: &[u8]) -> Result<Option<VkResponse>, DecodeError> {
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

        // Then the length this chunk would take the buffer to, against the
        // announced total or, until the prefix has arrived, the reserved
        // capacity. Appending first and checking after would reallocate the
        // buffer that [`VkReassembler::capacity`] sized precisely so the key
        // bytes never move, leaving a copy in a block nothing wipes.
        let limit = self
            .total_len()
            .unwrap_or_else(|| Self::capacity(self.kind));
        let would_be = self.buf.len().saturating_add(chunk.len());
        if would_be > limit {
            return Err(DecodeError::Overrun {
                expected: limit,
                got: would_be,
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
                // Checked in place, so bytes that are not UTF-8 are never
                // copied into an error value that would drop them unwiped,
                // and the buffer is wiped on both paths.
                let parsed = core::str::from_utf8(&self.buf[2..]).map(str::to_owned);
                self.buf.zeroize();
                match parsed {
                    Ok(s) => Ok(Some(VkResponse::Ufvk(s))),
                    Err(_) => Err(DecodeError::NotUtf8),
                }
            }
        }
    }
}

/// Parses a whole string response — `len u16` big-endian then UTF-8 bytes.
///
/// `encode_string_response` in `src/utils.rs`. Used for the unified address
/// (`GET_SHIELD_ADDR` P2 `0x00`), which is short enough to arrive in one
/// reply.
///
/// # Errors
///
/// [`DecodeError::Truncated`] for fewer than the two length bytes,
/// [`DecodeError::UnexpectedLength`] when the data is not exactly the declared
/// length, and [`DecodeError::NotUtf8`] for bytes that are not UTF-8.
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

#[cfg(test)]
mod tests;
