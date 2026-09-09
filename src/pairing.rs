//! Pairing wrappers: firmware probe, viewing-key export, address display, and
//! the device's identity.
//!
//! Thin state over [`crate::apdu::encode`] and [`crate::apdu::decode`]. Like
//! [`crate::session`], nothing here performs I/O.

use crate::apdu::decode::{
    parse_firmware_version, parse_string_response, parse_wallet_public_key, split_status_word,
    DecodeError, FirmwareVersion, VkKind, VkReassembler, VkResponse, WalletPublicKey,
};
use crate::apdu::encode::{
    get_firmware_version_apdu, get_orchard_address_apdu, get_orchard_fvk_apdu, get_ufvk_apdu,
    get_unified_address_apdu, get_vk_continue_apdu, get_wallet_public_key_apdu, DerivationPath,
    EncodeError, COMPRESSED_PUBKEY_SIZE,
};
use crate::apdu::{p2, StatusClass, StatusWord, MAX_CMD_NOT_ACCEPTED_RETRIES};
use crate::limits::{DeviceCaps, Network};

/// BIP 32 hardening bit.
const HARDENED: u32 = 0x8000_0000;

/// `MAX_BIP44_ADDRESS_INDEX_RECOMMENDED` in `src/utils.rs` @ `22dc385`.
///
/// `check_bip44_compliance(Bip44CheckMode::Full { .. })` refuses a path whose
/// address index exceeds it. From `22dc385` the value is compared **unmasked**:
/// "Change and address index are the non-hardened half of BIP-44, and both are
/// read unmasked: a hardened value exceeds the bound below on its own, so it
/// cannot pass for the small index it would be mistaken for." So a hardened
/// index is refused by the same comparison, and this crate refuses it here
/// rather than spending a round trip on `IncorrectData`.
pub const MAX_BIP44_ADDRESS_INDEX: u32 = 50_000;

/// A pairing command that did not go through.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PairingError {
    /// The reply did not have the shape the protocol promises.
    Decode(DecodeError),
    /// A path could not be encoded.
    Encode(EncodeError),
    /// The user declined on the device.
    UserRejected,
    /// The device is not running the Zcash app, or not a version that knows
    /// this instruction.
    WrongApp {
        /// The status word received.
        status: StatusWord,
    },
    /// The device refused the command.
    Device {
        /// The status word received.
        status: StatusWord,
    },
    /// A path component outside what `check_bip44_compliance` accepts.
    ///
    /// Today one thing lands here: an address index above
    /// [`MAX_BIP44_ADDRESS_INDEX`], hardened values included, since the device
    /// compares the raw value.
    PathOutOfRange {
        /// What the component is.
        what: &'static str,
        /// The value supplied.
        index: u32,
        /// The largest value the device accepts.
        max: u32,
    },
    /// The per-run Orchard derivation budget is spent (`0x6A84` in answer to a
    /// pairing command).
    ///
    /// `consume_orchard_derivation_budget` (`src/zip32.rs` @ `22dc385`) caps a
    /// run of the app at `MAX_ORCHARD_DERIVATIONS` (50) calls to
    /// `zip32_orchard_derive`, because "the Secure Element does not reclaim
    /// what such a derivation consumes until the next power cycle" and every
    /// later derivation — including the ones a transaction needs — would come
    /// back as a technical error.
    ///
    /// The status word is deliberately *not* that technical error: "a caller
    /// that hits the ceiling should be able to tell a spent budget, which a
    /// restart clears, from a derivation that genuinely failed." The distinct
    /// variant carries the concrete advice — close and reopen the app —
    /// instead of a `Device { status: NotEnoughMemorySpace }` the caller has
    /// to interpret.
    ///
    /// Only pairing commands map `0x6A84` this way. On a `PCZT_*` command the
    /// same status word means a bundle or a memo the device could not hold, so
    /// [`crate::session`] leaves it as a device refusal.
    DerivationBudgetExhausted,
    /// The device SDK refused the frame before the application saw it
    /// (`0x6901`, `CmdNotAccepted`). Nothing was parsed on the device; the
    /// cure is to resend the identical APDU.
    ///
    /// [`VkExchange`] absorbs this itself. It surfaces from the one-shot
    /// parsers ([`parse_unified_address`], [`parse_orchard_address`],
    /// [`parse_firmware_version_response`]) because those hold no state to
    /// retry from, so the caller owning the APDU has to.
    CmdNotAccepted,
    /// A continuation was requested with no response pending, or a reply was
    /// offered to an exchange that had already completed or failed.
    OutOfOrder,
}

impl core::fmt::Display for PairingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PairingError::Decode(inner) => write!(f, "malformed device reply: {inner}"),
            PairingError::Encode(inner) => write!(f, "the command could not be encoded: {inner}"),
            PairingError::UserRejected => write!(f, "the user declined on the device"),
            PairingError::WrongApp { status } => write!(
                f,
                "the device is not running the Zcash app, or not a version that knows this \
                 instruction (status {:#06x})",
                status.to_u16()
            ),
            PairingError::Device { status } => write!(
                f,
                "the device refused the command with status {status:?} ({:#06x})",
                status.to_u16()
            ),
            PairingError::PathOutOfRange { what, index, max } => write!(
                f,
                "{what} {index:#x} is outside what the device accepts (at most {max}, compared \
                 unmasked)"
            ),
            PairingError::DerivationBudgetExhausted => write!(
                f,
                "the app's per-run Orchard derivation budget is spent; close and reopen the app \
                 on the device, then retry"
            ),
            PairingError::CmdNotAccepted => write!(
                f,
                "the device SDK refused the frame before the app saw it (0x6901); resend the \
                 identical APDU"
            ),
            PairingError::OutOfOrder => write!(
                f,
                "a continuation was requested with no response pending, or a reply was offered \
                 to an exchange that had already completed or failed"
            ),
        }
    }
}

impl std::error::Error for PairingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PairingError::Decode(inner) => Some(inner),
            PairingError::Encode(inner) => Some(inner),
            _ => None,
        }
    }
}

impl From<DecodeError> for PairingError {
    fn from(e: DecodeError) -> Self {
        PairingError::Decode(e)
    }
}

impl From<EncodeError> for PairingError {
    fn from(e: EncodeError) -> Self {
        PairingError::Encode(e)
    }
}

/// Splits a reply and classifies its status word.
fn ok_data(rapdu: &[u8]) -> Result<&[u8], PairingError> {
    let (data, status) = split_status_word(rapdu)?;
    match status.class() {
        StatusClass::Ok => Ok(data),
        StatusClass::Retriable => Err(PairingError::CmdNotAccepted),
        StatusClass::UserCancel => Err(PairingError::UserRejected),
        StatusClass::WrongApp => Err(PairingError::WrongApp { status }),
        StatusClass::Fatal if status == StatusWord::NotEnoughMemorySpace => {
            Err(PairingError::DerivationBudgetExhausted)
        }
        StatusClass::Fatal => Err(PairingError::Device { status }),
    }
}

/// The ZIP 32 shielded account path `m/32'/coin'/account'`.
///
/// `handler_get_vk` and `handler_get_shielded_addr` both require exactly this
/// three-component hardened form (`check_bip44_compliance` with
/// `Bip44CheckMode::Zip32Only`) and answer `IncorrectData` for anything else.
pub fn shielded_account_path(network: Network, account: u32) -> DerivationPath {
    DerivationPath(vec![
        crate::shape::ZIP32_PURPOSE | HARDENED,
        network.coin_type() | HARDENED,
        account | HARDENED,
    ])
}

/// The BIP 44 transparent account path `m/44'/coin'/account'`, which the
/// unified `GET_VK` mode pairs with the shielded one.
pub fn transparent_account_path(network: Network, account: u32) -> DerivationPath {
    DerivationPath(vec![
        crate::shape::BIP44_PURPOSE | HARDENED,
        network.coin_type() | HARDENED,
        account | HARDENED,
    ])
}

/// The full BIP 44 transparent address path
/// `m/44'/coin'/account'/scope/index`, which `GET_SHIELD_ADDR` requires (it
/// checks with `Bip44CheckMode::Full { is_change_path: false }`, so `scope` must
/// be the external chain `0`).
///
/// `address_index` is bounded by [`MAX_BIP44_ADDRESS_INDEX`] and must be
/// unhardened. Both are the same device rule read two ways: from `22dc385` the
/// index is compared unmasked, so a hardened value exceeds the bound on its own
/// and is refused as an over-large index. Refusing here names it instead.
pub fn transparent_address_path(
    network: Network,
    account: u32,
    scope: u32,
    address_index: u32,
) -> Result<DerivationPath, PairingError> {
    if address_index > MAX_BIP44_ADDRESS_INDEX {
        return Err(PairingError::PathOutOfRange {
            what: "transparent address index",
            index: address_index,
            max: MAX_BIP44_ADDRESS_INDEX,
        });
    }
    Ok(DerivationPath(vec![
        crate::shape::BIP44_PURPOSE | HARDENED,
        network.coin_type() | HARDENED,
        account | HARDENED,
        scope,
        address_index,
    ]))
}

/// The external-chain address path `m/44'/coin'/account'/0/index`.
///
/// The external chain (`0`) is the one whose keys a wallet's *receiving*
/// addresses come from, and the one an account's transparent full viewing key
/// derives with `TransparentKeyScope::EXTERNAL`. Naming it here means a caller
/// comparing a device-derived key with a cache-derived one cannot pick a
/// different scope on one side than on the other.
pub fn transparent_external_address_path(
    network: Network,
    account: u32,
    address_index: u32,
) -> Result<DerivationPath, PairingError> {
    transparent_address_path(network, account, 0, address_index)
}

// ---------------------------------------------------------------------------
// Device identity
// ---------------------------------------------------------------------------

/// BLAKE2b personalization for [`DeviceIdentity`], 16 bytes as BLAKE2b
/// requires.
///
/// Versioned in the string itself: a future identity derived from anything else
/// gets `_1` and therefore a disjoint output space, so an old and a new
/// identity can never collide.
pub const DEVICE_IDENTITY_PERSONALIZATION: &[u8; 16] = b"PcztLedgerDvId_0";

/// The prefix every [`DeviceIdentity`] string carries.
///
/// `tpk0` for "the transparent public key at account 0"; the separator is `-`
/// rather than `:` so that the whole string is a valid directory name on every
/// operating system and can key an on-disk per-account cache.
pub const DEVICE_IDENTITY_PREFIX: &str = "tpk0-";

/// Length of the hex half of a [`DeviceIdentity`] string.
const DEVICE_IDENTITY_HEX_LEN: usize = 64;

/// A stable name for one physical device on one network.
///
/// # What it is
///
/// BLAKE2b-256, personalized with [`DEVICE_IDENTITY_PERSONALIZATION`], over the
/// **33-byte compressed** public key the device derives at
/// [`device_identity_path`] — `m/44'/coin'/0'/0/0`.
///
/// # Why a hash, and why that path
///
/// BOLOS never hands an application the seed, so there is no ZIP 32 seed
/// fingerprint to ask a Ledger for. What the app will answer, with no screen
/// and no Orchard derivation budget, is `GET_WALLET_PUBLIC_KEY` at a fixed
/// path. Two devices restored from one seed answer identically — which is the
/// wanted behaviour, since they hold the same keys — and two devices with
/// different seeds do not.
///
/// It is the *hash* rather than the key because this string is stored in a
/// wallet database and reported by wallet RPCs: an address-controlling public
/// key would leak an account's transparent chain to anything that could read
/// an account listing, and nothing here needs the key itself.
///
/// # Per network by construction
///
/// The coin type is a component of the path, so one device has one identity on
/// mainnet and a different one on testnet — deliberately: a wallet's database
/// and caches and the device's own firmware build are all per network already.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceIdentity([u8; 32]);

impl DeviceIdentity {
    /// Hashes the compressed public key at [`device_identity_path`].
    pub fn from_compressed_pubkey(pubkey: &[u8; COMPRESSED_PUBKEY_SIZE]) -> Self {
        let hash = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(DEVICE_IDENTITY_PERSONALIZATION)
            .to_state()
            .update(pubkey)
            .finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_bytes());
        DeviceIdentity(out)
    }

    /// The identity in a `GET_WALLET_PUBLIC_KEY` reply.
    ///
    /// The reply carries the uncompressed key; it is compressed first, so that
    /// the identity is a function of the key and not of the encoding the
    /// firmware happened to choose.
    ///
    /// The caller is responsible for having asked at [`device_identity_path`]:
    /// this cannot tell which path produced the reply, and an identity taken
    /// from any other path is a different device's name for the same device.
    pub fn from_wallet_public_key(reply: &WalletPublicKey) -> Result<Self, DecodeError> {
        Ok(Self::from_compressed_pubkey(&reply.compressed()?))
    }

    /// The raw hash.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parses the `tpk0-<64 lowercase hex>` form.
    ///
    /// Strict on all three counts — prefix, length, and lowercase — because
    /// this string is a directory name as well as an identifier: accepting
    /// `TPK0-AB…` would make one device two cache directories on a
    /// case-sensitive filesystem and one on a case-insensitive one.
    pub fn parse(s: &str) -> Result<Self, InvalidDeviceIdentity> {
        let hex_part = s
            .strip_prefix(DEVICE_IDENTITY_PREFIX)
            .ok_or(InvalidDeviceIdentity::MissingPrefix)?;
        if hex_part.len() != DEVICE_IDENTITY_HEX_LEN {
            return Err(InvalidDeviceIdentity::BadLength {
                got: hex_part.len(),
            });
        }
        if !hex_part
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(InvalidDeviceIdentity::NotLowercaseHex);
        }

        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex_part[i * 2..i * 2 + 2], 16)
                .map_err(|_| InvalidDeviceIdentity::NotLowercaseHex)?;
        }
        Ok(DeviceIdentity(out))
    }
}

impl core::fmt::Display for DeviceIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(DEVICE_IDENTITY_PREFIX)?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl core::str::FromStr for DeviceIdentity {
    type Err = InvalidDeviceIdentity;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DeviceIdentity::parse(s)
    }
}

/// Why a string is not a [`DeviceIdentity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidDeviceIdentity {
    /// It does not start with [`DEVICE_IDENTITY_PREFIX`].
    MissingPrefix,
    /// The part after the prefix is not 64 hex characters.
    BadLength {
        /// How many characters followed the prefix.
        got: usize,
    },
    /// The part after the prefix is not lowercase hexadecimal.
    NotLowercaseHex,
}

impl core::fmt::Display for InvalidDeviceIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InvalidDeviceIdentity::MissingPrefix => write!(
                f,
                "a device identity starts with {DEVICE_IDENTITY_PREFIX:?}"
            ),
            InvalidDeviceIdentity::BadLength { got } => write!(
                f,
                "a device identity carries {DEVICE_IDENTITY_HEX_LEN} hex characters after \
                 {DEVICE_IDENTITY_PREFIX:?}, got {got}"
            ),
            InvalidDeviceIdentity::NotLowercaseHex => write!(
                f,
                "a device identity is lowercase hexadecimal after {DEVICE_IDENTITY_PREFIX:?}"
            ),
        }
    }
}

impl std::error::Error for InvalidDeviceIdentity {}

/// The fixed path a device is identified by: `m/44'/coin'/0'/0/0`.
///
/// Account 0, the external chain, address index 0 — the first address of the
/// first account, which every seed has and no wallet policy can move. It is
/// the account-0, index-0 case of [`transparent_external_address_path`], and
/// infallible because both indices are constants inside every bound.
pub fn device_identity_path(network: Network) -> DerivationPath {
    DerivationPath(vec![
        crate::shape::BIP44_PURPOSE | HARDENED,
        network.coin_type() | HARDENED,
        HARDENED,
        0,
        0,
    ])
}

/// The command that identifies a device: a silent `GET_WALLET_PUBLIC_KEY` at
/// [`device_identity_path`].
///
/// Silent, so it shows no screen and can run in the middle of a ceremony; a
/// transparent derivation, so it costs none of the per-run Orchard derivation
/// budget. [`parse_device_identity_response`] turns the reply into a
/// [`DeviceIdentity`], and [`crate::session::LedgerSignSession`] sends this
/// same command first, before any transaction byte, to confirm the connected
/// device is the one it was built for.
pub fn device_identity_apdu(network: Network) -> Result<Vec<u8>, PairingError> {
    wallet_public_key_apdu(&device_identity_path(network), false)
}

/// Parses the reply to [`device_identity_apdu`] into the device's identity.
///
/// The reply carries the account's first receiving address alongside the key.
/// It is checked as part of the reply's shape and discarded here; nothing of
/// it survives in the identity, which is a hash of the compressed key alone.
pub fn parse_device_identity_response(rapdu: &[u8]) -> Result<DeviceIdentity, PairingError> {
    let reply = parse_wallet_public_key_response(rapdu)?;
    Ok(DeviceIdentity::from_wallet_public_key(&reply)?)
}

/// The `GET_WALLET_PUBLIC_KEY` command for one path.
///
/// `display` shows the transparent address for approval before replying; with
/// it false the device answers silently and leaves no status screen behind, so
/// the next command may go out immediately.
pub fn wallet_public_key_apdu(
    path: &DerivationPath,
    display: bool,
) -> Result<Vec<u8>, PairingError> {
    Ok(get_wallet_public_key_apdu(path, display)?.to_bytes())
}

/// Parses a `GET_WALLET_PUBLIC_KEY` reply.
///
/// The reply carries the account's own first receiving address, whether or
/// not it was wanted. The parser checks its shape and discards it — an
/// identity probe is not a request to disclose an address — so nothing of it
/// reaches the [`WalletPublicKey`] returned here.
pub fn parse_wallet_public_key_response(rapdu: &[u8]) -> Result<WalletPublicKey, PairingError> {
    Ok(parse_wallet_public_key(ok_data(rapdu)?)?)
}

// ---------------------------------------------------------------------------
// Firmware probe
// ---------------------------------------------------------------------------

/// The `GET_FIRMWARE_VERSION` command.
pub fn firmware_version_apdu() -> Vec<u8> {
    get_firmware_version_apdu().to_bytes()
}

/// Parses the `GET_FIRMWARE_VERSION` reply.
pub fn parse_firmware_version_response(rapdu: &[u8]) -> Result<FirmwareVersion, PairingError> {
    Ok(parse_firmware_version(ok_data(rapdu)?)?)
}

/// Derives [`DeviceCaps`] from a `GET_FIRMWARE_VERSION` reply.
///
/// The app answers an instruction it does not know with `InsNotSupported`
/// (`0x6D00`) and no diagnostic, so the version read here is the only way to
/// gate the PCZT and Ironwood commands before sending them.
pub fn device_caps(rapdu: &[u8]) -> Result<DeviceCaps, PairingError> {
    let v = parse_firmware_version_response(rapdu)?;
    Ok(DeviceCaps::from_version(v.major, v.minor, v.patch))
}

// ---------------------------------------------------------------------------
// GET_VK
// ---------------------------------------------------------------------------

/// A `GET_VK` exchange: one request plus however many continuations the
/// response length needs.
///
/// The device emits at most `VK_RESPONSE_CHUNK_LEN` (255) bytes per reply and
/// keeps the rest pending; the host asks for the remainder with P1 `0x80` and
/// empty data until the reassembler reports completion.
///
/// # P2 on a continuation
///
/// A continuation repeats the P2 of the request that started the response.
/// `handler_get_vk` ignores the mode once a response is pending, but
/// `Instruction::try_from` in `src/main.rs` parses P2 into `P2VkMode` for
/// *every* `INS_GET_VK`, continuations included, and answers `WrongP1P2` for
/// anything that is not `0x00` or `0x01`. Repeating the request's mode is
/// therefore both accepted and self-describing. Sending `0x00` for an
/// Orchard-FVK continuation would also be accepted today, but only by accident
/// of the mode being unused; this behaviour is one of the items still to be
/// confirmed against hardware.
///
/// # Failure is terminal
///
/// The one reply this exchange absorbs and retries is `0x6901`, which means
/// the frame never reached the app. Every other error — the user's `Deny`, a
/// device refusal, a reply that does not reassemble, the retry budget running
/// out — ends the exchange: [`VkExchange::next_apdu`] hands out nothing more
/// and [`VkExchange::process_response`] answers [`PairingError::OutOfOrder`].
/// A pump that treats errors as retriable therefore cannot re-issue the
/// request, which on this command would put the key-export approval screen
/// back in front of a user who has just declined it.
#[derive(Clone)]
pub struct VkExchange {
    mode: u8,
    first: Option<crate::apdu::Apdu>,
    reassembler: VkReassembler,
    done: bool,
    /// Latched by the first error other than `0x6901`; see "Failure is
    /// terminal" above.
    failed: bool,
    /// The command handed out and not yet answered, kept so that a `0x6901`
    /// can be answered by resending the identical bytes.
    pending: Option<Vec<u8>>,
    /// Consecutive `0x6901` replies to [`Self::pending`].
    retries: u32,
}

impl core::fmt::Debug for VkExchange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VkExchange")
            .field("mode", &format_args!("{:#04x}", self.mode))
            .field("sent_request", &self.first.is_none())
            .field("reassembler", &self.reassembler)
            .field("done", &self.done)
            .field("failed", &self.failed)
            .field("pending", &self.pending.as_ref().map(Vec::len))
            .field("retries", &self.retries)
            .finish()
    }
}

impl VkExchange {
    /// Starts a unified full viewing key export for one account.
    ///
    /// The device requires the shielded and transparent account paths to carry
    /// the same account index; both are derived from `account` here so they
    /// cannot drift.
    pub fn ufvk(network: Network, account: u32) -> Result<Self, PairingError> {
        let apdu = get_ufvk_apdu(
            &shielded_account_path(network, account),
            &transparent_account_path(network, account),
        )?;
        Ok(VkExchange {
            mode: p2::VK_UFVK,
            first: Some(apdu),
            reassembler: VkReassembler::new(VkKind::Ufvk),
            done: false,
            failed: false,
            pending: None,
            retries: 0,
        })
    }

    /// Starts a raw Orchard full viewing key export.
    pub fn orchard_fvk(network: Network, account: u32) -> Result<Self, PairingError> {
        let apdu = get_orchard_fvk_apdu(&shielded_account_path(network, account))?;
        Ok(VkExchange {
            mode: p2::VK_ORCHARD_FVK,
            first: Some(apdu),
            reassembler: VkReassembler::new(VkKind::OrchardFvk),
            done: false,
            failed: false,
            pending: None,
            retries: 0,
        })
    }

    /// The next command to send, or `None` once the response is complete or
    /// the exchange has failed.
    ///
    /// After a `0x6901` this hands out the *same* bytes again rather than
    /// moving on to a continuation: the refused frame never reached the
    /// application, so the device is still waiting for the command it names.
    pub fn next_apdu(&mut self) -> Option<Vec<u8>> {
        if self.done || self.failed {
            return None;
        }
        if let Some(bytes) = &self.pending {
            return Some(bytes.clone());
        }
        let bytes = match self.first.take() {
            Some(apdu) => apdu.to_bytes(),
            None => get_vk_continue_apdu(self.mode).to_bytes(),
        };
        self.pending = Some(bytes.clone());
        Some(bytes)
    }

    /// Response bytes accumulated so far.
    ///
    /// Zero until the device has answered the request that carries the
    /// approval screen, which is the only exchange of this ceremony that waits
    /// on a human — so a transport can lift its timeout on exactly that one.
    pub fn bytes_received(&self) -> usize {
        self.reassembler.len()
    }

    /// Absorbs one reply, returning the viewing key once every chunk has
    /// arrived.
    ///
    /// The device displays the key and waits for approval before the *first*
    /// chunk, so that reply is the one that blocks on the user.
    ///
    /// # Errors
    ///
    /// Every error but the absorbed `0x6901` is terminal (see the type's
    /// documentation): it is returned once, and the exchange then answers
    /// [`PairingError::OutOfOrder`] to any further reply and hands out no
    /// further command.
    pub fn process_response(&mut self, rapdu: &[u8]) -> Result<Option<VkResponse>, PairingError> {
        if self.done || self.failed {
            return Err(PairingError::OutOfOrder);
        }
        let data = match ok_data(rapdu) {
            Ok(data) => data,
            Err(PairingError::CmdNotAccepted) => {
                self.retries += 1;
                if self.retries > MAX_CMD_NOT_ACCEPTED_RETRIES {
                    return Err(self.fail(PairingError::Device {
                        status: StatusWord::CmdNotAccepted,
                    }));
                }
                // `pending` is kept, so `next_apdu` resends the same command.
                return Ok(None);
            }
            Err(e) => return Err(self.fail(e)),
        };
        self.pending = None;
        self.retries = 0;
        let response = match self.reassembler.push(data) {
            Ok(response) => response,
            Err(e) => return Err(self.fail(e.into())),
        };
        if response.is_some() {
            self.done = true;
        }
        Ok(response)
    }

    /// Whether every chunk has arrived.
    pub fn is_complete(&self) -> bool {
        self.done
    }

    /// Whether the exchange ended in an error, after which nothing more is
    /// sent.
    pub fn is_failed(&self) -> bool {
        self.failed
    }

    /// Ends the exchange, so that no command — the approval-screen request in
    /// particular — is ever handed out again.
    fn fail(&mut self, error: PairingError) -> PairingError {
        self.failed = true;
        self.pending = None;
        error
    }
}

// ---------------------------------------------------------------------------
// GET_SHIELD_ADDR
// ---------------------------------------------------------------------------

/// The `GET_SHIELD_ADDR` command for a unified address.
///
/// `display` shows the address for approval before replying; the device then
/// answers `Deny` with an empty response if the user refuses.
pub fn unified_address_apdu(
    network: Network,
    account: u32,
    address_index: u32,
    display: bool,
) -> Result<Vec<u8>, PairingError> {
    Ok(get_unified_address_apdu(
        &shielded_account_path(network, account),
        // External chain: `handler_get_shielded_addr` checks the transparent
        // path with `Bip44CheckMode::Full { is_change_path: false }`.
        &transparent_address_path(network, account, 0, address_index)?,
        display,
    )?
    .to_bytes())
}

/// Parses a unified-address reply.
pub fn parse_unified_address(rapdu: &[u8]) -> Result<String, PairingError> {
    Ok(parse_string_response(ok_data(rapdu)?)?)
}

/// The `GET_SHIELD_ADDR` command for a raw Orchard address.
pub fn orchard_address_apdu(
    network: Network,
    account: u32,
    display: bool,
) -> Result<Vec<u8>, PairingError> {
    Ok(get_orchard_address_apdu(&shielded_account_path(network, account), display)?.to_bytes())
}

/// Parses a raw Orchard address reply — 43 bytes, no length prefix.
pub fn parse_orchard_address(
    rapdu: &[u8],
) -> Result<[u8; crate::apdu::encode::ORCHARD_RAW_ADDRESS_SIZE], PairingError> {
    let data = ok_data(rapdu)?;
    data.try_into().map_err(|_| {
        PairingError::Decode(DecodeError::UnexpectedLength {
            what: "orchard address",
            expected: crate::apdu::encode::ORCHARD_RAW_ADDRESS_SIZE,
            got: data.len(),
        })
    })
}
