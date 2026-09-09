//! The device-shaping Updater pass, run once before streaming.
//!
//! A PCZT produced by `zcash_client_backend`'s `create_pczt_from_proposal` and
//! redacted with `redact_pczt_for_signer(SignerView::Full)` is *not* yet in the
//! shape the Ledger app requires:
//!
//! - `zip32_derivation` is stamped only on actions that still need a signature
//!   (`wallet.rs`, `update_orchard_with`), and only when the account has a
//!   stored derivation at all. The device builds one signing record per action
//!   and rejects any action without a path, dummies included.
//! - `bip32_derivation` is stamped on transparent *inputs* only, never on the
//!   change output. Without it the device shows the wallet's own change as a
//!   third-party recipient.
//!
//! This module runs the `pczt` **Updater** role to close both gaps, on the same
//! contract `LedgerHQ/ledger-zcash-utils` states in
//! `crates/zcash-crypto/src/craft.rs` (`stamp_spend_derivations`,
//! `stamp_transparent_derivations`).
//!
//! # Where this is stricter than the host contract
//!
//! `craft.rs` stamps the change derivation without checking it against the
//! output script. The device re-derives the pubkey from the path and compares it
//! with the supplied one — a mismatch there aborts — but a pubkey that derives
//! correctly and yet does not hash to the *output's* script is not an abort:
//! `check_output_displayable` simply classifies the output as a third-party
//! recipient, and a different output may then be taken for change. This module
//! therefore verifies `HASH160(pubkey) == <the output's P2PKH hash>` before
//! stamping and fails closed otherwise.

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use pczt::{roles::updater::Updater, Pczt};
use zcash_transparent::keys::{AccountPubKey, NonHardenedChildIndex, TransparentKeyScope};
use zip32::AccountId;

use crate::apdu::encode::TxFormat;
use crate::apdu::encode::{
    COMPRESSED_PUBKEY_SIZE, PCZT_VERSION_V5, PCZT_VERSION_V6, SEED_FINGERPRINT_SIZE,
};
use crate::limits::{Section, MAX_BIP44_ACCOUNT, MAX_BIP44_ADDRESS_INDEX};
use crate::plan::{read_global, PlanError};

pub use crate::limits::{hash160, p2pkh_hash};

/// What `Debug` prints in place of the seed fingerprint.
const REDACTED: &str = "[redacted]";

/// BIP 32 hardening bit.
/// The BIP 32 hardened-index bit, `2^31`. A hardened child index is the
/// unhardened one with this bit set.
pub const HARDENED: u32 = 0x8000_0000;

/// ZIP 32 purpose for the shielded tree (`m/32'/…`), which the device's
/// `check_bip44_compliance(Bip44CheckMode::Zip32Only)` requires.
pub const ZIP32_PURPOSE: u32 = 32;

/// BIP 44 purpose for the transparent tree (`m/44'/…`).
pub const BIP44_PURPOSE: u32 = 44;

/// BIP 44 external (receiving) scope, which the device's address-display
/// commands require (`Bip44CheckMode::Full { is_change_path: false }`).
pub const TRANSPARENT_EXTERNAL_SCOPE: u32 = 0;

/// BIP 44 internal (change) scope. The device checks the change output's path
/// with `Bip44CheckMode::Full { is_change_path: true }`, which requires it.
pub const TRANSPARENT_INTERNAL_SCOPE: u32 = 1;

/// The account component of a derivation path, hardening bit included.
///
/// Mirrors `derivation_account` in `src/utils.rs` @ `22dc385` exactly,
/// including its refusal to mask: "The account is what separates two key
/// trees, so an unhardened value must not compare equal to the hardened one:
/// masking here would let `m/44'/133'/2/0/0` pass for account `2'` while
/// deriving somewhere else entirely."
///
/// `None` for any path that is neither the five-component BIP 44 form nor the
/// three-component ZIP 32 one — the two depths at which the app places an
/// account.
pub fn derivation_account(path: &[u32]) -> Option<u32> {
    match path.len() {
        5 | 3 => Some(path[2]),
        _ => None,
    }
}

/// The transparent change output to mark for the device.
///
/// The pubkey names one of the account's change addresses, so `Debug` redacts
/// it.
///
/// The only way to build one is [`ChangeInfo::derive`], which checks that the
/// address index really derives the pubkey and that the pubkey really pays
/// the output; the fields are read-only so that a hint cannot be assembled
/// from parts that were never checked against each other.
#[derive(Clone, PartialEq, Eq)]
pub struct ChangeInfo {
    /// Index of the change output in the PCZT's transparent bundle.
    pub(crate) output_index: usize,
    /// Compressed secp256k1 public key controlling the change output.
    pub(crate) pubkey: [u8; COMPRESSED_PUBKEY_SIZE],
    /// BIP 44 address index; the scope is always
    /// [`TRANSPARENT_INTERNAL_SCOPE`].
    pub(crate) address_index: NonHardenedChildIndex,
}

impl core::fmt::Debug for ChangeInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChangeInfo")
            .field("output_index", &self.output_index)
            .field("pubkey", &"[redacted]")
            .field("address_index", &self.address_index.index())
            .finish()
    }
}

/// A change output that cannot be described by [`ChangeInfo::derive`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChangeDeriveError {
    /// The named key scope is not the internal (change) chain.
    ///
    /// The device checks a change output's path with
    /// `Bip44CheckMode::Full { is_change_path: true }`, which requires
    /// `m/44'/coin'/account'/1/index`. An output on the external (`0`) or
    /// ephemeral (`2`) chain is genuinely the account paying itself at a
    /// receiving address, not change, and the firmware has no way to say so.
    NotInternalScope {
        /// The scope supplied.
        scope: u32,
    },
    /// The BIP 32 derivation itself failed. A viewing key for a different
    /// account is the usual cause.
    Derivation(String),
    /// The output's `script_pubkey` is not a standard P2PKH script, so no
    /// derived pubkey could be matched against it.
    NotP2pkh,
    /// The derived pubkey's `HASH160` is not the hash the output pays. The
    /// derivation parameters and the script disagree about who owns the
    /// output — honestly (a viewing key for another account) or not (a PCZT
    /// edited to point the change at somebody else's key) — and neither is
    /// signable.
    ///
    /// Neither hash is carried: a P2PKH hash *is* the transparent address up
    /// to a prefix and a checksum, and an error is what a wallet logs.
    PubkeyMismatch {
        /// Index of the output in the transparent bundle.
        output_index: usize,
        /// The address index the pubkey was derived at.
        address_index: u32,
    },
}

impl core::fmt::Display for ChangeDeriveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChangeDeriveError::NotInternalScope { scope } => write!(
                f,
                "the output is on key scope {scope}, not the internal chain \
                 ({TRANSPARENT_INTERNAL_SCOPE}); the device can only present an internal-chain \
                 output as change"
            ),
            ChangeDeriveError::Derivation(message) => {
                write!(
                    f,
                    "deriving the change pubkey from the account's transparent viewing key: \
                     {message}"
                )
            }
            ChangeDeriveError::NotP2pkh => write!(
                f,
                "the output's script_pubkey is not a standard P2PKH script, so no derived pubkey \
                 could be matched against it"
            ),
            ChangeDeriveError::PubkeyMismatch {
                output_index,
                address_index,
            } => {
                write!(
                    f,
                    "the change pubkey derived at address index {address_index} does not hash \
                     to what transparent output {output_index} pays; the derivation parameters \
                     and the script disagree about who owns this output"
                )
            }
        }
    }
}

impl core::error::Error for ChangeDeriveError {}

impl ChangeInfo {
    /// Derives the change pubkey named by `(scope, address_index)` from the
    /// account's transparent full viewing key, and verifies it against the
    /// output's script before anything is stamped.
    ///
    /// A P2PKH `script_pubkey` commits only to `HASH160(pubkey)`, which is not
    /// invertible, so the device needs the pubkey itself and the host has to
    /// derive it. The derivation goes through
    /// [`AccountPubKey::derive_address_pubkey`] — `zcash_transparent`'s own
    /// BIP 32 derivation, never a hand-rolled one — and the result must hash
    /// to exactly the script the device will see: the device re-derives the
    /// pubkey from the stamped path and a mismatch against the *supplied*
    /// pubkey aborts, but a pubkey that derives correctly and does not hash to
    /// the output's script is silently shown as a third-party recipient
    /// instead, which is why this fails closed here.
    ///
    /// `output_index` is where the output sits in the PCZT's transparent
    /// bundle, and `script_pubkey` must be that output's script.
    ///
    /// # Errors
    ///
    /// [`ChangeDeriveError::NotInternalScope`] for a scope other than the
    /// internal chain, [`ChangeDeriveError::Derivation`] when the account key
    /// cannot derive the pubkey, [`ChangeDeriveError::NotP2pkh`] when
    /// `script_pubkey` is not a standard P2PKH script, and
    /// [`ChangeDeriveError::PubkeyMismatch`] when the derived pubkey does not
    /// hash to it.
    pub fn derive(
        fvk: &AccountPubKey,
        scope: u32,
        address_index: NonHardenedChildIndex,
        output_index: usize,
        script_pubkey: &[u8],
    ) -> Result<Self, ChangeDeriveError> {
        // The stamped path always uses the internal scope
        // (`ShapeParams::transparent_change_path`), so deriving under any
        // other scope would produce a key the device cannot re-derive from
        // that path.
        if scope != TRANSPARENT_INTERNAL_SCOPE {
            return Err(ChangeDeriveError::NotInternalScope { scope });
        }
        let pubkey = fvk
            .derive_address_pubkey(TransparentKeyScope::INTERNAL, address_index)
            .map_err(|e| ChangeDeriveError::Derivation(e.to_string()))?
            .serialize();

        let script_hash = p2pkh_hash(script_pubkey).ok_or(ChangeDeriveError::NotP2pkh)?;
        if script_hash != hash160(&pubkey) {
            return Err(ChangeDeriveError::PubkeyMismatch {
                output_index,
                address_index: address_index.index(),
            });
        }

        Ok(ChangeInfo {
            output_index,
            pubkey,
            address_index,
        })
    }

    /// Index of the change output in the PCZT's transparent bundle.
    pub fn output_index(&self) -> usize {
        self.output_index
    }

    /// The compressed secp256k1 public key controlling the change output.
    pub fn pubkey(&self) -> &[u8; COMPRESSED_PUBKEY_SIZE] {
        &self.pubkey
    }

    /// The BIP 44 address index under [`TRANSPARENT_INTERNAL_SCOPE`] that
    /// derives the pubkey.
    pub fn address_index(&self) -> NonHardenedChildIndex {
        self.address_index
    }
}

/// What the shaping pass needs from the caller.
///
/// `Debug` redacts the seed fingerprint, a stable identifier of the wallet's
/// seed; the change hint redacts its own pubkey.
#[derive(Clone, PartialEq, Eq)]
pub struct ShapeParams {
    /// SLIP 44 coin type, which must match both the PCZT's `coin_type` and the
    /// device build's `ZCASH_BIP44_COIN_TYPE`.
    pub(crate) coin_type: u32,
    /// The ZIP 32 account, shared by the shielded and transparent paths and
    /// hardened on the wire.
    pub(crate) zip32_account: AccountId,
    /// The wallet's ZIP 32 seed fingerprint, if known.
    ///
    /// The firmware never checks the 32-byte fingerprint half of a
    /// `zip32_derivation` — only the path — so a PCZT from a UFVK-imported
    /// account with no derivation anywhere can be shaped with the zeroed
    /// default. When the PCZT already carries derivations — on its transparent
    /// inputs, which a seeded wallet always stamps, on a change output it
    /// arrived with, or on shielded actions — their fingerprint is adopted
    /// unless this field contradicts it, so that every derivation the shaped
    /// PCZT carries names the same seed and the wallet can attribute the
    /// change output it gets back.
    pub(crate) seed_fingerprint: Option<[u8; SEED_FINGERPRINT_SIZE]>,
    /// The transparent change output, if the transaction has one.
    pub(crate) change: Option<ChangeInfo>,
}

impl core::fmt::Debug for ShapeParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShapeParams")
            .field("coin_type", &self.coin_type)
            .field("zip32_account", &self.zip32_account)
            .field(
                "seed_fingerprint",
                &self.seed_fingerprint.as_ref().map(|_| REDACTED),
            )
            .field("change", &self.change)
            .finish()
    }
}

impl ShapeParams {
    /// Parameters for one account on one network, with no seed fingerprint
    /// and no change output; the `with_*` methods add each.
    pub fn new(coin_type: u32, zip32_account: AccountId) -> Self {
        ShapeParams {
            coin_type,
            zip32_account,
            seed_fingerprint: None,
            change: None,
        }
    }

    /// Sets the wallet's ZIP 32 seed fingerprint; see
    /// [`ShapeParams::seed_fingerprint`].
    pub fn with_seed_fingerprint(
        mut self,
        seed_fingerprint: Option<[u8; SEED_FINGERPRINT_SIZE]>,
    ) -> Self {
        self.seed_fingerprint = seed_fingerprint;
        self
    }

    /// Sets the transparent change output.
    pub fn with_change(mut self, change: Option<ChangeInfo>) -> Self {
        self.change = change;
        self
    }

    /// The SLIP 44 coin type.
    pub fn coin_type(&self) -> u32 {
        self.coin_type
    }

    /// The ZIP 32 account.
    pub fn zip32_account(&self) -> AccountId {
        self.zip32_account
    }

    /// The wallet's ZIP 32 seed fingerprint, if known.
    pub fn seed_fingerprint(&self) -> Option<[u8; SEED_FINGERPRINT_SIZE]> {
        self.seed_fingerprint
    }

    /// The transparent change output, if the transaction has one.
    pub fn change(&self) -> Option<&ChangeInfo> {
        self.change.as_ref()
    }

    /// The shielded account path `m/32'/coin'/account'`, in raw (hardened)
    /// indices.
    pub fn shielded_account_path(&self) -> Vec<u32> {
        vec![
            ZIP32_PURPOSE | HARDENED,
            self.coin_type | HARDENED,
            u32::from(self.zip32_account) | HARDENED,
        ]
    }

    /// The transparent change path `m/44'/coin'/account'/1/index`, in raw
    /// indices (the last two non-hardened).
    pub fn transparent_change_path(&self, address_index: NonHardenedChildIndex) -> Vec<u32> {
        vec![
            BIP44_PURPOSE | HARDENED,
            self.coin_type | HARDENED,
            u32::from(self.zip32_account) | HARDENED,
            TRANSPARENT_INTERNAL_SCOPE,
            address_index.index(),
        ]
    }
}

/// A PCZT shaped for the device, together with the encoding version it
/// serializes in.
///
/// The PCZT carries the transaction's per-action secrets. `Debug` shows none
/// of it; the `pczt` crate's own types are not so careful, and a caller that
/// logs [`Shaped::pczt`] with `{:?}` logs everything in it.
///
/// The two parts describe one PCZT and are read-only, so that the version the
/// device is told to expect and the structure a plan is built from cannot be
/// swapped apart from each other after shaping.
#[derive(Clone)]
pub struct Shaped {
    /// The shaped PCZT. This is what [`crate::plan::build_plan`] and, at the end
    /// of the ceremony, [`crate::apply`] operate on.
    pczt: Pczt,
    /// The PCZT wire-format revision `pczt` serializes in: [`PCZT_VERSION_V5`]
    /// for V5, [`PCZT_VERSION_V6`] for V6. Verified to match the transaction
    /// version.
    encoding_version: u32,
}

impl Shaped {
    /// The shaped PCZT: what [`crate::plan::build_plan`] and, at the end of
    /// the ceremony, [`crate::apply`] operate on.
    pub fn pczt(&self) -> &Pczt {
        &self.pczt
    }

    /// The shaped PCZT, taken out.
    pub fn into_pczt(self) -> Pczt {
        self.pczt
    }

    /// The PCZT wire-format revision [`Shaped::pczt`] serializes in:
    /// [`PCZT_VERSION_V5`] for V5, [`PCZT_VERSION_V6`] for V6. Verified to
    /// match the transaction version.
    pub fn encoding_version(&self) -> u32 {
        self.encoding_version
    }
}

impl core::fmt::Debug for Shaped {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Shaped")
            .field("pczt", &"[redacted]")
            .field("encoding_version", &self.encoding_version)
            .finish()
    }
}

/// A PCZT that cannot be shaped for the device.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ShapeError {
    /// The PCZT's global fields could not be read, or describe an unsupported
    /// transaction version.
    Plan(PlanError),
    /// The PCZT's `coin_type` disagrees with the caller's.
    CoinTypeMismatch {
        /// The value in the PCZT.
        pczt: u32,
        /// The value the caller supplied.
        params: u32,
    },
    /// An index that must be non-hardened has the hardening bit set.
    IndexMustBeUnhardened {
        /// What the index is.
        what: &'static str,
        /// The value supplied.
        index: u32,
    },
    /// The change output's path would name an account index above the
    /// device's bound.
    ///
    /// `check_bip44_compliance` in `Bip44CheckMode::Full` refuses
    /// `account > MAX_BIP44_ACCOUNT_RECOMMENDED` on a transparent output's
    /// derivation (`src/utils.rs` @ `22dc385`), mid-stream and after the
    /// inputs have gone out. Signing paths are not bound by it, so the same
    /// account can sign a transaction without transparent change.
    ChangeAccountAboveDeviceBound {
        /// The account index supplied.
        account: u32,
        /// The largest the device accepts on a change path.
        max: u32,
    },
    /// The change output's address index is above the device's bound
    /// (`MAX_BIP44_ADDRESS_INDEX_RECOMMENDED`), under the same rule as
    /// [`ShapeError::ChangeAccountAboveDeviceBound`].
    ChangeIndexAboveDeviceBound {
        /// The address index supplied.
        index: u32,
        /// The largest the device accepts on a change path.
        max: u32,
    },
    /// An action already carries a `zip32_derivation` whose path is not the
    /// `m/32'/coin'/account'` account path the device accepts, or is not the
    /// one the caller asked for. The device derives one account key per PCZT.
    ///
    /// Neither path is carried: the one found names an account, and possibly
    /// an address, of the wallet's own seed, and an error is what a wallet
    /// logs. The section and index say which record to look at.
    NonUniformPath {
        /// Which pool.
        section: Section,
        /// Index of the action.
        index: usize,
    },
    /// Two records — shielded actions, transparent inputs or outputs — carry
    /// different seed fingerprints, or the caller's fingerprint contradicts
    /// one already in the PCZT.
    NonUniformSeedFingerprint,
    /// The change output index is past the end of the transparent bundle.
    ChangeOutputIndexOutOfRange {
        /// The index supplied.
        index: usize,
        /// Number of transparent outputs.
        outputs: usize,
    },
    /// The change output's `script_pubkey` is not a standard P2PKH script, so
    /// the device cannot match a re-derived pubkey against it.
    ChangeOutputNotP2pkh {
        /// The index supplied.
        index: usize,
    },
    /// `HASH160(pubkey)` does not equal the change output's script hash.
    ///
    /// Neither hash is carried: a P2PKH hash *is* the transparent address up
    /// to a prefix and a checksum, and an error is what a wallet logs.
    ChangeOutputHashMismatch {
        /// The index supplied.
        index: usize,
    },
    /// The `pczt` Updater role rejected the update.
    Updater(String),
    /// The shaped PCZT's content needs an encoding other than the one the
    /// device's parser assumes for its transaction version: `1` for V5, `2`
    /// for V6.
    ///
    /// The header the crate streams is computed from the transaction version
    /// alone and always agrees with it, so the device would not refuse the
    /// header; what this catches is *content* the assumed encoding cannot
    /// carry. `Pczt::serialize` writes the minimal encoding able to hold the
    /// PCZT — v1 whenever it can — and v1 cannot hold a V6 transaction at
    /// all, so only a V5 PCZT lands here: one that needs v2 (an Orchard
    /// note-plaintext version v1 cannot carry, or non-canonical Ironwood
    /// data), which the device would otherwise parse under an encoding it
    /// was not written in.
    EncodingVersionMismatch {
        /// The version the content needs.
        got: u32,
        /// The version the device requires.
        expected: u32,
    },
}

impl core::fmt::Display for ShapeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ShapeError::Plan(inner) => write!(f, "{inner}"),
            ShapeError::CoinTypeMismatch { pczt, params } => write!(
                f,
                "the PCZT's coin type ({pczt}) disagrees with the session's ({params}); the PCZT \
                 was built for a different network"
            ),
            ShapeError::IndexMustBeUnhardened { what, index } => write!(
                f,
                "{what} {index:#x} has the hardening bit set; it must be supplied unhardened"
            ),
            ShapeError::ChangeAccountAboveDeviceBound { account, max } => write!(
                f,
                "account index {account} is above the largest ({max}) the device accepts on a \
                 transparent change output's path; the device would refuse the change output \
                 mid-stream"
            ),
            ShapeError::ChangeIndexAboveDeviceBound { index, max } => write!(
                f,
                "change address index {index} is above the largest ({max}) the device accepts \
                 on a transparent change output's path; the device would refuse the change \
                 output mid-stream"
            ),
            ShapeError::NonUniformPath { section, index } => write!(
                f,
                "{section} {index} already carries a zip32_derivation path that is not the \
                 account path this session derives; the device derives one account key per PCZT"
            ),
            ShapeError::NonUniformSeedFingerprint => write!(
                f,
                "two records of this PCZT carry different seed fingerprints, or the supplied \
                 fingerprint contradicts one already in it"
            ),
            ShapeError::ChangeOutputIndexOutOfRange { index, outputs } => write!(
                f,
                "change output index {index} is past the end of the transparent bundle \
                 ({outputs} output(s))"
            ),
            ShapeError::ChangeOutputNotP2pkh { index } => write!(
                f,
                "transparent output {index} was named as change but its script_pubkey is not a \
                 standard P2PKH script, so the device cannot match a re-derived pubkey against it"
            ),
            ShapeError::ChangeOutputHashMismatch { index } => write!(
                f,
                "the supplied change pubkey does not hash to what transparent output {index} \
                 pays; stamping it would make the device show the wallet's own change as a \
                 third-party recipient"
            ),
            ShapeError::Updater(message) => {
                write!(f, "the PCZT Updater role rejected the update: {message}")
            }
            ShapeError::EncodingVersionMismatch { got, expected } => write!(
                f,
                "the shaped PCZT needs encoding version {got}, but the device requires version \
                 {expected} for this transaction version"
            ),
        }
    }
}

impl core::error::Error for ShapeError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            ShapeError::Plan(inner) => Some(inner),
            _ => None,
        }
    }
}

impl From<PlanError> for ShapeError {
    fn from(e: PlanError) -> Self {
        ShapeError::Plan(e)
    }
}

/// Runs the shaping pass.
///
/// In order:
///
/// 1. the caller's `coin_type` and account index are checked against the PCZT,
///    and the transparent change output, when the caller names one, against
///    its script;
/// 2. every Orchard action's existing `zip32_derivation` is collected, its path
///    checked against `m/32'/coin'/account'` and its fingerprint checked for
///    uniformity — the same for the Ironwood bundle on a V6 transaction — and
///    the fingerprints on the transparent inputs and outputs are checked for
///    uniformity with those;
/// 3. actions with no derivation are stamped with that path and the agreed
///    fingerprint (the caller's, else the one already present, else zeroed);
/// 4. the change output is stamped with `m/44'/coin'/account'/1/index` and
///    the same fingerprint; recipient outputs are left untouched so the device
///    displays them;
/// 5. the encoding the result serializes in is checked against the
///    transaction version, without serializing it.
///
/// One `Updater` carries the PCZT through steps 2 to 4; the surveys read
/// through it and change nothing.
///
/// # Errors
///
/// From the parameter checks, [`ShapeError::CoinTypeMismatch`],
/// [`ShapeError::IndexMustBeUnhardened`],
/// [`ShapeError::ChangeAccountAboveDeviceBound`] and
/// [`ShapeError::ChangeIndexAboveDeviceBound`]; from the named change output,
/// [`ShapeError::ChangeOutputIndexOutOfRange`],
/// [`ShapeError::ChangeOutputNotP2pkh`] and
/// [`ShapeError::ChangeOutputHashMismatch`]; from the survey,
/// [`ShapeError::NonUniformPath`] and
/// [`ShapeError::NonUniformSeedFingerprint`]; [`ShapeError::Plan`] when the
/// `Global` cannot be read; [`ShapeError::Updater`] when the `pczt` Updater
/// role refuses; and [`ShapeError::EncodingVersionMismatch`] when the PCZT's
/// content needs an encoding other than the one the device assumes for the
/// transaction version.
pub fn shape_for_device(pczt: Pczt, params: &ShapeParams) -> Result<Shaped, ShapeError> {
    let global = read_global(&pczt)?;
    let format = global.format()?;

    if global.coin_type() != params.coin_type {
        return Err(ShapeError::CoinTypeMismatch {
            pczt: global.coin_type(),
            params: params.coin_type,
        });
    }
    if params.coin_type & HARDENED != 0 {
        return Err(ShapeError::IndexMustBeUnhardened {
            what: "coin_type",
            index: params.coin_type,
        });
    }
    if let Some(change) = &params.change {
        // The device checks the change path in `Bip44CheckMode::Full`, which
        // bounds both indices; a signing path is not bound, so these apply
        // only when a change output is going to be stamped.
        if u32::from(params.zip32_account) > MAX_BIP44_ACCOUNT {
            return Err(ShapeError::ChangeAccountAboveDeviceBound {
                account: u32::from(params.zip32_account),
                max: MAX_BIP44_ACCOUNT,
            });
        }
        if change.address_index.index() > MAX_BIP44_ADDRESS_INDEX {
            return Err(ShapeError::ChangeIndexAboveDeviceBound {
                index: change.address_index.index(),
                max: MAX_BIP44_ADDRESS_INDEX,
            });
        }
    }

    // The change output's script, read before the Updater takes the PCZT.
    if let Some(change) = &params.change {
        let outputs = pczt.transparent().outputs();
        let output =
            outputs
                .get(change.output_index)
                .ok_or(ShapeError::ChangeOutputIndexOutOfRange {
                    index: change.output_index,
                    outputs: outputs.len(),
                })?;

        let script_hash =
            p2pkh_hash(output.script_pubkey()).ok_or(ShapeError::ChangeOutputNotP2pkh {
                index: change.output_index,
            })?;
        if script_hash != hash160(&change.pubkey) {
            return Err(ShapeError::ChangeOutputHashMismatch {
                index: change.output_index,
            });
        }
    }

    let expected_path = params.shielded_account_path();
    let mut updater = Updater::new(pczt);

    // ---- 2. survey the derivations already present -------------------------
    let mut agreed_fingerprint = params.seed_fingerprint;
    updater = survey_pool(
        updater,
        Section::Orchard,
        &expected_path,
        &mut agreed_fingerprint,
    )?;
    if format == TxFormat::V6 {
        updater = survey_pool(
            updater,
            Section::Ironwood,
            &expected_path,
            &mut agreed_fingerprint,
        )?;
    }
    updater = survey_transparent(updater, &mut agreed_fingerprint)?;
    let fingerprint = agreed_fingerprint.unwrap_or([0u8; SEED_FINGERPRINT_SIZE]);

    // ---- 3. stamp the missing shielded derivations -------------------------
    updater = updater
        .update_orchard_with(|mut u| stamp_pool(&mut u, fingerprint, &expected_path))
        .map_err(|e| ShapeError::Updater(format!("orchard zip32: {e:?}")))?;

    if format == TxFormat::V6 {
        updater = updater
            .update_ironwood_with(|mut u| stamp_pool(&mut u, fingerprint, &expected_path))
            .map_err(|e| ShapeError::Updater(format!("ironwood zip32: {e:?}")))?;
    }

    // ---- 4. stamp the transparent change output ----------------------------
    if let Some(change) = &params.change {
        let path = params.transparent_change_path(change.address_index);
        let derivation = zcash_transparent::pczt::Bip32Derivation::parse(fingerprint, path)
            .map_err(|e| {
                ShapeError::Updater(format!("transparent change bip32 derivation: {e:?}"))
            })?;

        updater = updater
            .update_transparent_with(|mut u| {
                u.update_output_with(change.output_index, |mut o| {
                    o.set_bip32_derivation(change.pubkey, derivation);
                    Ok(())
                })
            })
            .map_err(|e| ShapeError::Updater(format!("transparent change: {e:?}")))?;
    }

    // ---- 5. check the encoding version -------------------------------------
    let shaped = updater.finish();
    // `Pczt::serialize` writes v1 whenever v1 can carry the PCZT, and v1
    // carries no V6 transaction, so only a V5 PCZT has an encoding to check.
    // `v1::Pczt::try_from` is the encoder's own test of what v1 carries, run
    // on a copy it consumes; nothing is serialized.
    let encoding_version = match format {
        TxFormat::V5 => match pczt::v1::Pczt::try_from(shaped.clone()) {
            Ok(_) => PCZT_VERSION_V5,
            Err(_) => PCZT_VERSION_V6,
        },
        TxFormat::V6 => PCZT_VERSION_V6,
    };
    let expected = format.pczt_version();
    if encoding_version != expected {
        return Err(ShapeError::EncodingVersionMismatch {
            got: encoding_version,
            expected,
        });
    }

    Ok(Shaped {
        pczt: shaped,
        encoding_version,
    })
}

/// Checks the paths and fingerprints already present in one shielded pool.
///
/// Reads through the Updater's own borrow of the parsed bundle (the only place
/// `zip32_derivation` has an accessor) without mutating anything, and hands
/// the Updater back.
fn survey_pool(
    updater: Updater,
    section: Section,
    expected_path: &[u32],
    agreed_fingerprint: &mut Option<[u8; SEED_FINGERPRINT_SIZE]>,
) -> Result<Updater, ShapeError> {
    let mut violation: Option<ShapeError> = None;

    let inspect = |u: orchard::pczt::Updater<'_>,
                   violation: &mut Option<ShapeError>,
                   agreed: &mut Option<[u8; SEED_FINGERPRINT_SIZE]>| {
        for (index, action) in u.bundle().actions().iter().enumerate() {
            let Some(derivation) = action.spend().zip32_derivation().as_ref() else {
                continue;
            };
            let found = derivation.derivation_path().iter().map(|c| c.index());
            if !found.eq(expected_path.iter().copied()) {
                *violation = Some(ShapeError::NonUniformPath { section, index });
                return;
            }
            if let Err(e) = agree(agreed, derivation.seed_fingerprint()) {
                *violation = Some(e);
                return;
            }
        }
    };

    let result = match section {
        Section::Ironwood => updater.update_ironwood_with(|u| {
            inspect(u, &mut violation, agreed_fingerprint);
            Ok(())
        }),
        Section::Orchard => updater.update_orchard_with(|u| {
            inspect(u, &mut violation, agreed_fingerprint);
            Ok(())
        }),
        Section::TransparentInput | Section::TransparentOutput => {
            return Err(ShapeError::Updater(format!(
                "internal error: {section:?} has no shielded pool to survey"
            )))
        }
    };
    let updater = result.map_err(|e| ShapeError::Updater(format!("{section:?} survey: {e:?}")))?;

    match violation {
        Some(e) => Err(e),
        None => Ok(updater),
    }
}

/// Checks the fingerprints on the transparent records' `bip32_derivation`s —
/// the inputs' signing-key locators, and any change output the PCZT arrived
/// with — against the agreed one, and hands the Updater back.
///
/// The paths are not checked here: the session checks every transparent path
/// for BIP 44 compliance and account binding once the PCZT is shaped.
fn survey_transparent(
    updater: Updater,
    agreed_fingerprint: &mut Option<[u8; SEED_FINGERPRINT_SIZE]>,
) -> Result<Updater, ShapeError> {
    let mut violation: Option<ShapeError> = None;

    let updater = updater
        .update_transparent_with(|u| {
            let bundle = u.bundle();
            let inputs = bundle
                .inputs()
                .iter()
                .flat_map(|input| input.bip32_derivation().values());
            let outputs = bundle
                .outputs()
                .iter()
                .flat_map(|output| output.bip32_derivation().values());
            for derivation in inputs.chain(outputs) {
                if let Err(e) = agree(agreed_fingerprint, derivation.seed_fingerprint()) {
                    violation = Some(e);
                    break;
                }
            }
            Ok(())
        })
        .map_err(|e| ShapeError::Updater(format!("transparent survey: {e:?}")))?;

    match violation {
        Some(e) => Err(e),
        None => Ok(updater),
    }
}

/// Folds one record's seed fingerprint into the agreed one: the first record
/// seen sets it when the caller supplied none, and every later one must match.
fn agree(
    agreed: &mut Option<[u8; SEED_FINGERPRINT_SIZE]>,
    found: &[u8; SEED_FINGERPRINT_SIZE],
) -> Result<(), ShapeError> {
    match agreed {
        Some(fp) if fp != found => Err(ShapeError::NonUniformSeedFingerprint),
        Some(_) => Ok(()),
        None => {
            *agreed = Some(*found);
            Ok(())
        }
    }
}

/// Stamps `m/32'/coin'/account'` on every action of one pool that lacks a
/// derivation, dummies included.
///
/// Dummies must be stamped: the device builds one signing record per action and
/// aborts on any action without a path. It is safe because the IO Finalizer
/// already self-signed them with their `dummy_sk`, so the host never asks the
/// device for those indices — and the device would refuse them anyway.
fn stamp_pool(
    updater: &mut orchard::pczt::Updater<'_>,
    fingerprint: [u8; SEED_FINGERPRINT_SIZE],
    path: &[u32],
) -> Result<(), orchard::pczt::UpdaterError> {
    let needs_stamp: Vec<usize> = updater
        .bundle()
        .actions()
        .iter()
        .enumerate()
        .filter(|(_, a)| a.spend().zip32_derivation().is_none())
        .map(|(i, _)| i)
        .collect();

    for index in needs_stamp {
        // Rebuilt per action rather than hoisted out of the loop:
        // `Zip32Derivation` is not `Clone` and `parse` takes the path by
        // value, so each action needs its own. `parse` rejects only a
        // non-hardened index and every component here is hardened by
        // construction, so the error arm is unreachable; the map only
        // satisfies the closure's error type.
        let derivation = orchard::pczt::Zip32Derivation::parse(fingerprint, path.to_vec())
            .map_err(|_| orchard::pczt::UpdaterError::InvalidIndex)?;
        updater.update_action_with(index, |mut action| {
            action.set_spend_zip32_derivation(derivation);
            Ok(())
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests;
