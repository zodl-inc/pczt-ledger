//! Pairing wrappers: firmware probe, viewing-key export, address display, and
//! the device's identity.
//!
//! Thin state over [`crate::apdu::encode`] and [`crate::apdu::decode`]. Like
//! [`crate::session`], nothing here performs I/O.
//!
//! # No device binding on the pairing commands
//!
//! A signing session refuses to send a transaction byte until the connected
//! device has answered as the paired [`DeviceIdentity`]. The commands here
//! have no such check: `GET_VK`, `GET_SHIELD_ADDR` and a displayed
//! `GET_WALLET_PUBLIC_KEY` are one-shot, and each answers for whatever device
//! the transport is open to. With two Ledgers attached, a wallet that pairs
//! "the first device" can store one device's identity next to the other's
//! viewing key; nothing fails until a signing session — bound to the stored
//! identity — is refused by the device whose keys the wallet has, or streams
//! to the device whose keys it does not. A wallet pairing an account should
//! therefore run [`device_identity_apdu`] on the connection it is about to
//! export from, and again after the export, and keep the viewing key only if
//! both answers are the identity it stores with it.

use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};

use crate::apdu::decode::{
    parse_firmware_version, parse_string_response, parse_wallet_public_key, split_status_word,
    DecodeError, FirmwareVersion, VkKind, VkReassembler, VkResponse, WalletPublicKey,
    ORCHARD_FVK_LEN,
};
use crate::apdu::encode::{
    get_firmware_version_apdu, get_orchard_address_apdu, get_orchard_fvk_apdu, get_ufvk_apdu,
    get_unified_address_apdu, get_vk_continue_apdu, get_wallet_public_key_apdu, DerivationPath,
    EncodeError, COMPRESSED_PUBKEY_SIZE,
};
use crate::apdu::{p2, Deadline, StatusClass, StatusWord, MAX_CMD_NOT_ACCEPTED_RETRIES};
use crate::limits::{DeviceCaps, Network};
use crate::shape::HARDENED;
use zcash_address::unified::{self, Encoding, Revision};
use zcash_protocol::consensus::NetworkType;
use zcash_transparent::keys::{NonHardenedChildIndex, TransparentKeyScope};
use zip32::AccountId;

pub use crate::limits::{MAX_BIP44_ACCOUNT, MAX_BIP44_ADDRESS_INDEX};

/// The [ZIP 316] revision of every unified container this crate accepts from
/// a device.
///
/// The pinned app encodes both of its containers with a `zcash_address` whose
/// only revision is this one: `handler_get_vk`
/// (`src/handlers/get_vk.rs` @ `22dc385`) for the unified full viewing key,
/// `handler_get_shielded_addr` (`src/handlers/get_shielded_addr.rs`) for the
/// unified address. A device that answers in another revision is one this
/// crate has not been checked against, and its reply is refused with
/// [`PairingError::UnsupportedUnifiedRevision`]; moving the firmware pin is
/// what revisits that.
///
/// [ZIP 316]: https://zips.z.cash/zip-0316
pub const DEVICE_UNIFIED_REVISION: Revision = Revision::R0;

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
    /// A path component outside what `check_bip44_compliance` accepts: an
    /// account above [`MAX_BIP44_ACCOUNT`], an address index above
    /// [`MAX_BIP44_ADDRESS_INDEX`], or a scope other than the external chain.
    /// Hardened values cannot reach here; the index types exclude them.
    ///
    /// The value is not carried: the caller supplied it, and an account or
    /// address index is not for an error a wallet logs.
    PathOutOfRange {
        /// What the component is.
        what: &'static str,
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
    /// Only the commands that derive an Orchard key — `GET_VK` and
    /// `GET_SHIELD_ADDR` — map `0x6A84` this way. `GET_WALLET_PUBLIC_KEY` and
    /// `GET_FIRMWARE_VERSION` derive none, so from them it stays
    /// [`PairingError::Device`]; and on a `PCZT_*` command the same status
    /// word means a bundle or a memo the device could not hold, so
    /// [`crate::session`] leaves it as a device refusal too.
    DerivationBudgetExhausted,
    /// The device SDK refused the frame before the application saw it
    /// (`0x6901`, `CmdNotAccepted`). Nothing was parsed on the device; the
    /// cure is to resend the identical APDU.
    ///
    /// Only a `0x6901` with an empty body is this. The SDK's refusal never
    /// carries data, so a body means the reply belongs to another command;
    /// that is [`PairingError::Decode`], since resending would widen the gap
    /// rather than close it.
    ///
    /// [`VkExchange`] absorbs this itself. It surfaces from the one-shot
    /// parsers ([`parse_unified_address`], [`parse_orchard_address`],
    /// [`parse_firmware_version_response`]) because those hold no state to
    /// retry from, so the caller owning the APDU has to.
    CmdNotAccepted,
    /// A reply was offered to a [`VkExchange`] with no command outstanding —
    /// before [`VkExchange::next_apdu`] handed one out, or a second reply to
    /// one command — or to an exchange that had already completed or failed.
    ///
    /// The first kind leaves the exchange as it was; the second is the
    /// terminal state answering, and stays.
    OutOfOrder,
    /// The reply to a unified-address request is not a unified address.
    ///
    /// Carries `zcash_address::unified::ParseError`'s message; the error
    /// itself is not `Clone`.
    UnifiedAddress(String),
    /// The reply to a unified-address request encodes an address for another
    /// network than the one the request was built for.
    AddressNetworkMismatch {
        /// The network the request named.
        expected: Network,
        /// The network the reply's prefix names.
        found: NetworkType,
    },
    /// The reply to a raw Orchard address request is 43 bytes whose `pk_d`
    /// half is not a valid Pallas point, so it is no address.
    InvalidOrchardAddress,
    /// The reply to a unified full viewing key request is not a unified full
    /// viewing key: the string does not decode (Bech32m checksum, prefix, or
    /// item encoding).
    ///
    /// Carries `zcash_address::unified::ParseError`'s message; the error
    /// itself is not `Clone`.
    UnifiedViewingKey(String),
    /// The reply to a unified full viewing key request encodes a key for
    /// another network than the one the request was built for.
    ViewingKeyNetworkMismatch {
        /// The network the request named.
        expected: Network,
        /// The network the reply's prefix names.
        found: NetworkType,
    },
    /// The reply to a raw Orchard full viewing key request is 96 bytes that
    /// encode no key: `ak` is not a point, or `nk` or `rivk` is not a field
    /// element.
    InvalidOrchardViewingKey,
    /// The reply to a unified-address or unified full viewing key request
    /// encodes its container in a revision other than
    /// [`DEVICE_UNIFIED_REVISION`].
    ///
    /// The revision is carried by the human-readable prefix, and two
    /// revisions of the same network have different prefixes, so the network
    /// checks above do not see it.
    UnsupportedUnifiedRevision {
        /// The revision the reply's prefix names.
        found: Revision,
    },
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
            PairingError::PathOutOfRange { what, max } => write!(
                f,
                "{what} is outside what the device accepts (at most {max}, compared unmasked)"
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
            PairingError::UnifiedAddress(message) => write!(
                f,
                "the reply to the unified-address request is not a unified address: {message}"
            ),
            PairingError::AddressNetworkMismatch { expected, found } => write!(
                f,
                "the reply to the unified-address request is an address for {found:?}, and the \
                 request was for {expected:?}"
            ),
            PairingError::InvalidOrchardAddress => write!(
                f,
                "the reply to the Orchard address request is 43 bytes that do not encode an \
                 address: pk_d is not a point"
            ),
            PairingError::UnifiedViewingKey(message) => write!(
                f,
                "the reply to the unified viewing key request is not a unified full viewing \
                 key: {message}"
            ),
            PairingError::ViewingKeyNetworkMismatch { expected, found } => write!(
                f,
                "the reply to the unified viewing key request is a key for {found:?}, and the \
                 request was for {expected:?}"
            ),
            PairingError::InvalidOrchardViewingKey => write!(
                f,
                "the reply to the Orchard viewing key request is 96 bytes that do not encode a \
                 full viewing key"
            ),
            PairingError::UnsupportedUnifiedRevision { found } => write!(
                f,
                "the reply encodes a unified container of ZIP 316 revision {found}, and the \
                 pinned app produces only revision {DEVICE_UNIFIED_REVISION}"
            ),
        }
    }
}

impl core::error::Error for PairingError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
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

/// Refuses a unified container the pinned app does not encode.
///
/// Compared against [`DEVICE_UNIFIED_REVISION`] rather than matched, so a
/// revision added after this was written is refused too.
fn check_unified_revision(found: Revision) -> Result<(), PairingError> {
    if found == DEVICE_UNIFIED_REVISION {
        Ok(())
    } else {
        Err(PairingError::UnsupportedUnifiedRevision { found })
    }
}

/// What a command derives on the device, which decides what `0x6A84` in its
/// reply means; see [`PairingError::DerivationBudgetExhausted`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Derives {
    /// `GET_VK` and `GET_SHIELD_ADDR`: an Orchard key, so `0x6A84` is the
    /// per-run derivation budget running out.
    OrchardKey,
    /// `GET_WALLET_PUBLIC_KEY` and `GET_FIRMWARE_VERSION`: no Orchard key, so
    /// `0x6A84` is whatever the device meant by it.
    NoOrchardKey,
}

/// Splits a reply and classifies its status word.
///
/// A `0x6901` that carries a body is not the SDK's refusal: the SDK's never
/// has one, so a body means the reply belongs to another command and the
/// channel is a reply out of step. That is [`PairingError::Decode`] rather
/// than [`PairingError::CmdNotAccepted`], because resending the command — what
/// the refusal asks for — would only widen the gap.
fn ok_data(rapdu: &[u8], derives: Derives) -> Result<&[u8], PairingError> {
    let (data, status) = split_status_word(rapdu)?;
    match status.class() {
        StatusClass::Ok => Ok(data),
        StatusClass::Retriable if !data.is_empty() => {
            Err(PairingError::Decode(DecodeError::UnexpectedLength {
                what: "0x6901 refusal",
                expected: 0,
                got: data.len(),
            }))
        }
        StatusClass::Retriable => Err(PairingError::CmdNotAccepted),
        StatusClass::UserCancel => Err(PairingError::UserRejected),
        StatusClass::WrongApp => Err(PairingError::WrongApp { status }),
        StatusClass::Fatal
            if status == StatusWord::NotEnoughMemorySpace && derives == Derives::OrchardKey =>
        {
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
pub fn shielded_account_path(network: Network, account: AccountId) -> DerivationPath {
    DerivationPath(vec![
        crate::shape::ZIP32_PURPOSE | HARDENED,
        network.coin_type() | HARDENED,
        u32::from(account) | HARDENED,
    ])
}

/// The BIP 44 transparent account path `m/44'/coin'/account'`, which the
/// unified `GET_VK` mode pairs with the shielded one.
pub fn transparent_account_path(network: Network, account: AccountId) -> DerivationPath {
    DerivationPath(vec![
        crate::shape::BIP44_PURPOSE | HARDENED,
        network.coin_type() | HARDENED,
        u32::from(account) | HARDENED,
    ])
}

/// The full BIP 44 transparent address path
/// `m/44'/coin'/account'/scope/index`, which `GET_SHIELD_ADDR` requires (it
/// checks with `Bip44CheckMode::Full { is_change_path: false }`, so `scope` must
/// be [`TransparentKeyScope::EXTERNAL`]; the parameter is there so that a
/// caller naming another scope gets the device's refusal by name, before the
/// round trip).
///
/// `account` is bounded by [`MAX_BIP44_ACCOUNT`] and `address_index` by
/// [`MAX_BIP44_ADDRESS_INDEX`]. The types rule out hardened values, which
/// the device — comparing the index unmasked, from `22dc385` — would refuse
/// as over-large indices.
///
/// # Errors
///
/// [`PairingError::PathOutOfRange`] for an account above [`MAX_BIP44_ACCOUNT`],
/// a scope other than [`TransparentKeyScope::EXTERNAL`], or an address index
/// above [`MAX_BIP44_ADDRESS_INDEX`].
pub fn transparent_address_path(
    network: Network,
    account: AccountId,
    scope: TransparentKeyScope,
    address_index: NonHardenedChildIndex,
) -> Result<DerivationPath, PairingError> {
    let account = u32::from(account);
    let address_index = address_index.index();
    if account > MAX_BIP44_ACCOUNT {
        return Err(PairingError::PathOutOfRange {
            what: "transparent account index",
            max: MAX_BIP44_ACCOUNT,
        });
    }
    if scope != TransparentKeyScope::EXTERNAL {
        return Err(PairingError::PathOutOfRange {
            what: "transparent address scope (the device displays external-chain addresses only)",
            max: crate::shape::TRANSPARENT_EXTERNAL_SCOPE,
        });
    }
    if address_index > MAX_BIP44_ADDRESS_INDEX {
        return Err(PairingError::PathOutOfRange {
            what: "transparent address index",
            max: MAX_BIP44_ADDRESS_INDEX,
        });
    }
    Ok(DerivationPath(vec![
        crate::shape::BIP44_PURPOSE | HARDENED,
        network.coin_type() | HARDENED,
        account | HARDENED,
        crate::shape::TRANSPARENT_EXTERNAL_SCOPE,
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
///
/// # Errors
///
/// As [`transparent_address_path`].
pub fn transparent_external_address_path(
    network: Network,
    account: AccountId,
    address_index: NonHardenedChildIndex,
) -> Result<DerivationPath, PairingError> {
    transparent_address_path(
        network,
        account,
        TransparentKeyScope::EXTERNAL,
        address_index,
    )
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
///
/// # What it is not
///
/// It is a *name*, not an attestation. `GET_WALLET_PUBLIC_KEY` is a static,
/// silent query with no challenge in it, so the reply is a constant for one
/// device and one path: anything that has observed it once — a device
/// emulator, an interposed transport — can replay it and pass
/// [`crate::session::SessionError::DeviceMismatch`]'s check. The binding
/// that check provides is against honest confusion (two Ledgers attached,
/// a device swapped between pairing and signing), which is what it is
/// documented for; nothing here proves that the far end holds a key, and
/// the pinned firmware has no command that could. A device that passes it
/// and is not the paired one still cannot produce a signature the wallet
/// can use, since every signature is verified in [`crate::apply`] against
/// the paired keys' `rk` and pubkeys — but it does see the whole
/// transaction, `alpha`, `rcv` and `rseed` included.
///
/// It is also *unsalted*: the hash is over the public key alone, and that
/// key is published on chain the first time `m/44'/coin'/0'/0/0` is spent
/// from. Anyone who can enumerate spent P2PKH pubkeys can hash each under
/// [`DEVICE_IDENTITY_PERSONALIZATION`] and match a published identity
/// string to that address, and from there to the account's transparent
/// activity. The hash hides *which* address only from a reader who cannot
/// see the chain; a wallet that exposes the string beyond its own storage
/// should treat it as it would treat the address. A salt would close that
/// and is deliberately not used: two wallets pairing the same device must
/// agree on its name.
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
    ///
    /// # Errors
    ///
    /// As [`WalletPublicKey::compressed`].
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
    ///
    /// # Errors
    ///
    /// [`InvalidDeviceIdentity::MissingPrefix`] when the string does not start
    /// with [`DEVICE_IDENTITY_PREFIX`],
    /// [`InvalidDeviceIdentity::NotLowercaseHex`] when what follows is not
    /// lowercase hex, and [`InvalidDeviceIdentity::BadLength`] when it does not
    /// decode to 32 bytes.
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
#[non_exhaustive]
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

impl core::error::Error for InvalidDeviceIdentity {}

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
///
/// # Errors
///
/// [`PairingError::Encode`] when the identity path cannot be encoded, which the
/// fixed five-component path never is.
pub fn device_identity_apdu(network: Network) -> Result<Vec<u8>, PairingError> {
    wallet_public_key_apdu(&device_identity_path(network), false)
}

/// Parses the reply to [`device_identity_apdu`] into the device's identity.
///
/// The reply carries the account's first receiving address alongside the key.
/// It is checked as part of the reply's shape and discarded here; nothing of
/// it survives in the identity, which is a hash of the compressed key alone.
///
/// # Errors
///
/// As [`parse_wallet_public_key_response`].
pub fn parse_device_identity_response(rapdu: &[u8]) -> Result<DeviceIdentity, PairingError> {
    let reply = parse_wallet_public_key_response(rapdu)?;
    Ok(DeviceIdentity::from_wallet_public_key(&reply)?)
}

/// The `GET_WALLET_PUBLIC_KEY` command for one path.
///
/// `display` shows the transparent address for approval before replying; with
/// it false the device answers silently and leaves no status screen behind, so
/// the next command may go out immediately.
///
/// # Errors
///
/// [`PairingError::Encode`] when `path` cannot be encoded
/// ([`EncodeError::PathTooLong`]).
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
///
/// # Errors
///
/// The reply-level errors every parser here shares —
/// [`PairingError::CmdNotAccepted`], for the caller to resend;
/// [`PairingError::UserRejected`]; [`PairingError::WrongApp`];
/// [`PairingError::Device`] — and [`PairingError::Decode`] when the data is not
/// the shape [`parse_wallet_public_key`] expects.
pub fn parse_wallet_public_key_response(rapdu: &[u8]) -> Result<WalletPublicKey, PairingError> {
    Ok(parse_wallet_public_key(ok_data(
        rapdu,
        Derives::NoOrchardKey,
    )?)?)
}

// ---------------------------------------------------------------------------
// Firmware probe
// ---------------------------------------------------------------------------

/// The `GET_FIRMWARE_VERSION` command.
pub fn firmware_version_apdu() -> Vec<u8> {
    get_firmware_version_apdu().to_bytes()
}

/// Parses the `GET_FIRMWARE_VERSION` reply.
///
/// # Errors
///
/// As [`parse_wallet_public_key_response`], with [`PairingError::Decode`] for
/// data that is not the eight-byte version.
pub fn parse_firmware_version_response(rapdu: &[u8]) -> Result<FirmwareVersion, PairingError> {
    Ok(parse_firmware_version(ok_data(
        rapdu,
        Derives::NoOrchardKey,
    )?)?)
}

/// Derives [`DeviceCaps`] from a `GET_FIRMWARE_VERSION` reply.
///
/// The app answers an instruction it does not know with `InsNotSupported`
/// (`0x6D00`) and no diagnostic, so the version read here is the only way to
/// gate the PCZT and Ironwood commands before sending them.
///
/// # Errors
///
/// As [`parse_firmware_version_response`].
pub fn device_caps(rapdu: &[u8]) -> Result<DeviceCaps, PairingError> {
    let v = parse_firmware_version_response(rapdu)?;
    Ok(DeviceCaps::from_version(v.major, v.minor, v.patch))
}

// ---------------------------------------------------------------------------
// GET_VK
// ---------------------------------------------------------------------------

/// What one reply did to a [`VkExchange`].
///
/// The two non-final outcomes are told apart because a pump handles them
/// differently: after [`VkStep::RetrySameApdu`] the same command goes out
/// again, best after `ceremony::CMD_NOT_ACCEPTED_BACKOFF` so the
/// screen that refused it can clear; after [`VkStep::MoreChunks`] a
/// continuation goes out at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VkStep {
    /// The chunk was absorbed and more are pending; [`VkExchange::next_apdu`]
    /// hands out a continuation.
    MoreChunks,
    /// The device SDK refused the frame (`0x6901`) and the application never
    /// saw it; [`VkExchange::next_apdu`] hands out the same command again.
    RetrySameApdu,
    /// Every chunk has arrived, and the reply decodes as the key the request
    /// asked for: a unified full viewing key for the exchange's network in
    /// [`DEVICE_UNIFIED_REVISION`], or 96 bytes that are an Orchard full
    /// viewing key.
    Complete(VkResponse),
}

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
/// # The exported key is not bound to a device
///
/// This exchange proves only that *some* device holding the Zcash app answered
/// the request for this network: it runs no identity probe, so any well-formed
/// unified full viewing key for the exchange's network is accepted. Truncation
/// is closed — the length bound plus the Bech32m and HRP re-decode — but
/// substitution is not. With two Ledgers attached, a wallet that exports from
/// "the first device" can store one device's key beside the other's
/// [`DeviceIdentity`], and nothing fails until a signing session, bound to the
/// stored identity, meets the device whose keys the wallet does not have.
///
/// A wallet pairing an account must therefore bracket the export: run
/// [`device_identity_apdu`] on the same connection before the first command
/// here and again after the last, and keep the key only if both replies are
/// the identity it stores with it. The exchange cannot do this itself —
/// nothing in this crate performs I/O, and the probes have to travel the
/// connection the caller owns.
///
/// # Failure is terminal
///
/// The one reply this exchange absorbs and retries is an empty-bodied
/// `0x6901`, which means the frame never reached the app. Every other error
/// — a `0x6901` with a body, the user's `Deny`, a
/// device refusal, a reply that does not reassemble or does not decode as
/// the key it claims to be, the retry budget running out — ends the
/// exchange: [`VkExchange::next_apdu`] hands out nothing more
/// and [`VkExchange::process_response`] answers [`PairingError::OutOfOrder`].
/// A pump that treats errors as retriable therefore cannot re-issue the
/// request, which on this command would put the key-export approval screen
/// back in front of a user who has just declined it. For the same reason the
/// exchange is not `Clone`: a copy taken before the decline would not carry
/// the latch, and driving it would re-issue the request.
pub struct VkExchange {
    /// The network the request was built for, which the reply's prefix must
    /// name.
    network: Network,
    mode: u8,
    first: Option<crate::apdu::Apdu>,
    reassembler: VkReassembler,
    done: bool,
    /// Latched by the first error other than `0x6901`; see "Failure is
    /// terminal" above.
    failed: bool,
    /// The command handed out, and what [`VkExchange::next_apdu`] does with
    /// it.
    outstanding: Outstanding,
    /// Consecutive `0x6901` replies to [`Self::outstanding`].
    retries: u32,
}

/// The command a [`VkExchange`] has handed out, and what happens to it next.
///
/// A `GET_VK` request raises the key-export approval screen, so the exchange
/// hands one out only when the device is waiting for one: a second copy in
/// flight would raise a second screen against a reply that is still coming.
enum Outstanding {
    /// Nothing is in flight; the next command is built when it is asked for.
    Idle,
    /// A command is in flight and its reply has not been processed. Nothing
    /// new goes out until it has.
    AwaitingReply(Vec<u8>),
    /// The device SDK refused the frame (`0x6901`) before the application saw
    /// it, so the device is still waiting for the command it names: these
    /// identical bytes go out again.
    Resend(Vec<u8>),
}

impl core::fmt::Debug for VkExchange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VkExchange")
            .field("network", &self.network)
            .field("mode", &format_args!("{:#04x}", self.mode))
            .field("sent_request", &self.first.is_none())
            .field("reassembler", &self.reassembler)
            .field("done", &self.done)
            .field("failed", &self.failed)
            .field("outstanding", &self.outstanding)
            .field("retries", &self.retries)
            .finish()
    }
}

impl core::fmt::Debug for Outstanding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Outstanding::Idle => f.write_str("Idle"),
            Outstanding::AwaitingReply(bytes) => {
                write!(f, "AwaitingReply([{} bytes])", bytes.len())
            }
            Outstanding::Resend(bytes) => write!(f, "Resend([{} bytes])", bytes.len()),
        }
    }
}

impl VkExchange {
    /// Starts a unified full viewing key export for one account.
    ///
    /// The device requires the shielded and transparent account paths to carry
    /// the same account index; both are derived from `account` here so they
    /// cannot drift.
    ///
    /// # Errors
    ///
    /// [`PairingError::Encode`] when the account paths cannot be encoded, which
    /// the three-component account paths never are.
    pub fn ufvk(network: Network, account: AccountId) -> Result<Self, PairingError> {
        let apdu = get_ufvk_apdu(
            &shielded_account_path(network, account),
            &transparent_account_path(network, account),
        )?;
        Ok(VkExchange {
            network,
            mode: p2::VK_UFVK,
            first: Some(apdu),
            reassembler: VkReassembler::new(VkKind::Ufvk),
            done: false,
            failed: false,
            outstanding: Outstanding::Idle,
            retries: 0,
        })
    }

    /// Starts a raw Orchard full viewing key export.
    ///
    /// # Errors
    ///
    /// [`PairingError::Encode`] when the account path cannot be encoded, which
    /// the three-component account path never is.
    pub fn orchard_fvk(network: Network, account: AccountId) -> Result<Self, PairingError> {
        let apdu = get_orchard_fvk_apdu(&shielded_account_path(network, account))?;
        Ok(VkExchange {
            network,
            mode: p2::VK_ORCHARD_FVK,
            first: Some(apdu),
            reassembler: VkReassembler::new(VkKind::OrchardFvk),
            done: false,
            failed: false,
            outstanding: Outstanding::Idle,
            retries: 0,
        })
    }

    /// The next command to send, or `None` when there is nothing to send.
    ///
    /// After a `0x6901` this hands out the *same* bytes again rather than
    /// moving on to a continuation: the refused frame never reached the
    /// application, so the device is still waiting for the command it names.
    ///
    /// `None` means the exchange is complete ([`VkExchange::is_complete`]), has
    /// failed ([`VkExchange::is_failed`]), or is waiting for the reply to the
    /// command it has already handed out. The last case is why a second call
    /// with nothing else having happened does not hand the command out twice:
    /// the `GET_VK` request raises the key-export approval screen, and a driver
    /// that swallowed a timeout would otherwise raise a second screen with two
    /// commands in flight.
    pub fn next_apdu(&mut self) -> Option<Vec<u8>> {
        if self.done || self.failed {
            return None;
        }
        match core::mem::replace(&mut self.outstanding, Outstanding::Idle) {
            Outstanding::AwaitingReply(bytes) => {
                self.outstanding = Outstanding::AwaitingReply(bytes);
                None
            }
            Outstanding::Resend(bytes) => {
                self.outstanding = Outstanding::AwaitingReply(bytes.clone());
                Some(bytes)
            }
            Outstanding::Idle => {
                let bytes = match self.first.take() {
                    Some(apdu) => apdu.to_bytes(),
                    None => get_vk_continue_apdu(self.mode).to_bytes(),
                };
                self.outstanding = Outstanding::AwaitingReply(bytes.clone());
                Some(bytes)
            }
        }
    }

    /// Whether a command has been handed out and its reply not yet processed.
    ///
    /// The one case in which [`VkExchange::next_apdu`] answers `None` while the
    /// exchange is neither complete nor failed.
    pub fn is_awaiting_reply(&self) -> bool {
        matches!(self.outstanding, Outstanding::AwaitingReply(_))
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
    /// arrived and the whole decodes as the key the request asked for.
    ///
    /// The device displays the key and waits for approval before the *first*
    /// chunk, so that reply is the one that blocks on the user; see
    /// [`VkExchange::next_deadline`].
    ///
    /// # Errors
    ///
    /// [`PairingError::OutOfOrder`] when no command is awaiting a reply —
    /// before [`VkExchange::next_apdu`] handed one out, a second reply to one
    /// command, or a reply arriving between a `0x6901` and the resend it asks
    /// for. The reply is not absorbed, and the exchange is otherwise
    /// unchanged. Every other
    /// error but the absorbed `0x6901` is terminal (see the type's
    /// documentation): it is returned once, and the exchange then answers
    /// [`PairingError::OutOfOrder`] to any further reply and hands out no
    /// further command. Besides the reply-level errors and the reassembler's
    /// ([`PairingError::Decode`]), a complete reply that is not the key it
    /// claims to be is [`PairingError::UnifiedViewingKey`],
    /// [`PairingError::ViewingKeyNetworkMismatch`],
    /// [`PairingError::UnsupportedUnifiedRevision`] or
    /// [`PairingError::InvalidOrchardViewingKey`].
    pub fn process_response(&mut self, rapdu: &[u8]) -> Result<VkStep, PairingError> {
        if self.done || self.failed || !self.is_awaiting_reply() {
            return Err(PairingError::OutOfOrder);
        }
        let data = match ok_data(rapdu, Derives::OrchardKey) {
            Ok(data) => data,
            Err(PairingError::CmdNotAccepted) => {
                self.retries += 1;
                if self.retries > MAX_CMD_NOT_ACCEPTED_RETRIES {
                    return Err(self.fail(PairingError::Device {
                        status: StatusWord::CmdNotAccepted,
                    }));
                }
                // The bytes are kept for `next_apdu` to hand out again, and
                // nothing else goes out until it does.
                self.outstanding =
                    match core::mem::replace(&mut self.outstanding, Outstanding::Idle) {
                        // `AwaitingReply` by the check above; the other arms
                        // keep this total rather than assuming it.
                        Outstanding::AwaitingReply(bytes) | Outstanding::Resend(bytes) => {
                            Outstanding::Resend(bytes)
                        }
                        Outstanding::Idle => Outstanding::Idle,
                    };
                return Ok(VkStep::RetrySameApdu);
            }
            Err(e) => return Err(self.fail(e)),
        };
        self.outstanding = Outstanding::Idle;
        self.retries = 0;
        match self.reassembler.push(data) {
            Ok(Some(response)) => {
                if let Err(e) = self.validate(&response) {
                    return Err(self.fail(e));
                }
                self.done = true;
                Ok(VkStep::Complete(response))
            }
            Ok(None) => Ok(VkStep::MoreChunks),
            Err(e) => Err(self.fail(e.into())),
        }
    }

    /// Checks a complete reply against what the request asked for.
    ///
    /// The reassembler bounds lengths and chunk counts; it cannot tell a key
    /// from any other string or 96 bytes. A garbling transport, a firmware
    /// fault or a truncation landing on a chunk boundary reassembles into
    /// something it accepts, and a wallet that stored it would find out at
    /// its own decode or at first sync, with no diagnostic naming the reply.
    /// Decoding here refuses it where the diagnostic is. The decoded copy is
    /// dropped; the key is handed back as the device sent it.
    fn validate(&self, response: &VkResponse) -> Result<(), PairingError> {
        match response {
            VkResponse::Ufvk(encoded) => {
                let (found, revision, _ufvk) = unified::Ufvk::decode(encoded)
                    .map_err(|e| PairingError::UnifiedViewingKey(e.to_string()))?;
                if found != self.network.network_type() {
                    return Err(PairingError::ViewingKeyNetworkMismatch {
                        expected: self.network,
                        found,
                    });
                }
                check_unified_revision(revision)
            }
            VkResponse::OrchardFvk(bytes) => {
                // The reassembler delivers exactly `ORCHARD_FVK_LEN` bytes for
                // this kind; the conversion is fallible by signature.
                let raw: &[u8; ORCHARD_FVK_LEN] = bytes.as_slice().try_into().map_err(|_| {
                    PairingError::Decode(DecodeError::UnexpectedLength {
                        what: "orchard full viewing key",
                        expected: ORCHARD_FVK_LEN,
                        got: bytes.len(),
                    })
                })?;
                orchard::keys::FullViewingKey::from_bytes(raw)
                    .map(|_| ())
                    .ok_or(PairingError::InvalidOrchardViewingKey)
            }
        }
    }

    /// How long to wait for the reply to the command [`VkExchange::next_apdu`]
    /// hands out next.
    ///
    /// The request that opens the exchange puts the key-export approval screen
    /// in front of the user, and its reply arrives only once they have
    /// answered: [`Deadline::UserReview`] until the first chunk is in,
    /// including a resend of that request after a `0x6901`. Continuations are
    /// answered at once.
    pub fn next_deadline(&self) -> Deadline {
        if self.reassembler.is_empty() {
            Deadline::UserReview
        } else {
            Deadline::Normal
        }
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
        self.outstanding = Outstanding::Idle;
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
///
/// # What `transparent_address_index` selects
///
/// Nothing in the reply. `handler_get_shielded_addr`
/// (`src/handlers/get_shielded_addr.rs` @ `22dc385`; its unified-address
/// arm is unchanged from `0e048bb`) always encodes the account's Orchard
/// receiver at diversifier index 0, and nothing else, and answers with that
/// unified address, whatever the index; the
/// transparent path is put through the BIP 44 check and, under `display`,
/// derives the transparent address the screen shows next to the unified
/// one. A request for index 7 is answered exactly as one for index 0, so a
/// wallet comparing the reply with its own address at index 7 gets a
/// mismatch that means nothing, and one comparing with index 0 gets a match
/// that says nothing about index 7. Pass the index of the transparent
/// address the user should see on the device, and compare the reply with a
/// unified address built from the account's Orchard receiver at diversifier
/// index 0 alone: the account's full unified address carries a transparent
/// receiver too, which the reply does not, so it never matches.
///
/// # Errors
///
/// As [`transparent_address_path`], plus [`PairingError::Encode`] when either
/// path cannot be encoded.
pub fn unified_address_apdu(
    network: Network,
    account: AccountId,
    transparent_address_index: NonHardenedChildIndex,
    display: bool,
) -> Result<Vec<u8>, PairingError> {
    Ok(get_unified_address_apdu(
        &shielded_account_path(network, account),
        // External chain: `handler_get_shielded_addr` checks the transparent
        // path with `Bip44CheckMode::Full { is_change_path: false }`.
        &transparent_address_path(
            network,
            account,
            TransparentKeyScope::EXTERNAL,
            transparent_address_index,
        )?,
        display,
    )?
    .to_bytes())
}

/// Parses a unified-address reply and checks it against the network the
/// request was built for.
///
/// The firmware encodes the reply from a `UnifiedAddress` holding the
/// account's Orchard receiver at diversifier index 0, whatever transparent
/// address index the request named (`handler_get_shielded_addr`,
/// `src/handlers/get_shielded_addr.rs` @ `22dc385`; see
/// [`unified_address_apdu`]), so the reply is handed
/// back as that type rather than as its string: a garbled reply fails the
/// Bech32m checksum here instead of in the wallet, and a reply encoded for
/// another network is refused rather than compared. The type's `Debug`
/// prints the receivers — an address is what the user is about to be shown,
/// but an embedding that logs replies should know it is there.
///
/// # Errors
///
/// [`PairingError::UnifiedAddress`] when the reply is not a unified address,
/// [`PairingError::AddressNetworkMismatch`] when it is one for another
/// network, [`PairingError::UnsupportedUnifiedRevision`] when it is one of
/// another revision, and the reply-level errors every parser here shares:
/// [`PairingError::UserRejected`] when the user declined the display,
/// [`PairingError::DerivationBudgetExhausted`], [`PairingError::CmdNotAccepted`]
/// (for the caller to resend), [`PairingError::WrongApp`],
/// [`PairingError::Device`] and [`PairingError::Decode`].
pub fn parse_unified_address(
    rapdu: &[u8],
    network: Network,
) -> Result<unified::Address, PairingError> {
    let encoded = parse_string_response(ok_data(rapdu, Derives::OrchardKey)?)?;
    let (found, revision, address) = unified::Address::decode(&encoded)
        .map_err(|e| PairingError::UnifiedAddress(e.to_string()))?;
    if found != network.network_type() {
        return Err(PairingError::AddressNetworkMismatch {
            expected: network,
            found,
        });
    }
    check_unified_revision(revision)?;
    Ok(address)
}

/// The `GET_SHIELD_ADDR` command for a raw Orchard address.
///
/// # Errors
///
/// [`PairingError::Encode`] with
/// [`EncodeError::OrchardAddressCannotBeDisplayed`] when `display` is set,
/// which the device refuses with `WrongP1P2`.
pub fn orchard_address_apdu(
    network: Network,
    account: AccountId,
    display: bool,
) -> Result<Vec<u8>, PairingError> {
    Ok(get_orchard_address_apdu(&shielded_account_path(network, account), display)?.to_bytes())
}

/// Parses a raw Orchard address reply — 43 bytes, no length prefix — into
/// the address it encodes.
///
/// The firmware answers with `Address::to_raw_address_bytes()`; the inverse
/// checks that the `pk_d` half is a point, which 43 arbitrary bytes need not
/// be. The type's `Debug` prints the diversifier and `pk_d`, as
/// [`parse_unified_address`]'s does the receivers.
///
/// # Errors
///
/// [`PairingError::InvalidOrchardAddress`] when the 43 bytes encode no
/// address, [`PairingError::Decode`] when there are not 43 of them, and the
/// reply-level errors listed on [`parse_unified_address`].
pub fn parse_orchard_address(rapdu: &[u8]) -> Result<orchard::Address, PairingError> {
    let data = ok_data(rapdu, Derives::OrchardKey)?;
    let raw: [u8; crate::apdu::encode::ORCHARD_RAW_ADDRESS_SIZE] =
        data.try_into().map_err(|_| {
            PairingError::Decode(DecodeError::UnexpectedLength {
                what: "orchard address",
                expected: crate::apdu::encode::ORCHARD_RAW_ADDRESS_SIZE,
                got: data.len(),
            })
        })?;
    Option::from(orchard::Address::from_raw_address_bytes(&raw))
        .ok_or(PairingError::InvalidOrchardAddress)
}

#[cfg(test)]
mod tests;
