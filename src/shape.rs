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

use pczt::{roles::updater::Updater, Pczt};
use zcash_transparent::keys::{AccountPubKey, NonHardenedChildIndex, TransparentKeyScope};
use zeroize::Zeroizing;

use crate::apdu::encode::{COMPRESSED_PUBKEY_SIZE, SEED_FINGERPRINT_SIZE};
use crate::limits::Section;
use crate::plan::{is_v6_transaction, pczt_version_for, read_global, PlanError};

pub use crate::limits::{hash160, p2pkh_hash};

/// BIP 32 hardening bit.
const HARDENED: u32 = 0x8000_0000;

/// ZIP 32 purpose for the shielded tree (`m/32'/…`), which the device's
/// `check_bip44_compliance(Bip44CheckMode::Zip32Only)` requires.
pub const ZIP32_PURPOSE: u32 = 32;

/// BIP 44 purpose for the transparent tree (`m/44'/…`).
pub const BIP44_PURPOSE: u32 = 44;

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
#[derive(Clone, PartialEq, Eq)]
pub struct ChangeInfo {
    /// Index of the change output in the PCZT's transparent bundle.
    pub output_index: usize,
    /// Compressed secp256k1 public key controlling the change output.
    pub pubkey: [u8; COMPRESSED_PUBKEY_SIZE],
    /// Non-hardened BIP 44 address index; the scope is always
    /// [`TRANSPARENT_INTERNAL_SCOPE`].
    pub address_index: u32,
}

impl core::fmt::Debug for ChangeInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChangeInfo")
            .field("output_index", &self.output_index)
            .field("pubkey", &"[redacted]")
            .field("address_index", &self.address_index)
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
    /// The address index has the BIP 32 hardening bit set; a BIP 44 address
    /// index must not.
    AddressIndexHardened {
        /// The index supplied.
        index: u32,
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
    PubkeyMismatch {
        /// The hash in the output's script.
        script_hash: [u8; 20],
        /// `HASH160` of the derived pubkey.
        pubkey_hash: [u8; 20],
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
            ChangeDeriveError::AddressIndexHardened { index } => write!(
                f,
                "address index {index:#x} has the hardening bit set; a BIP 44 address index must \
                 not"
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
                script_hash,
                pubkey_hash,
            } => {
                write!(
                    f,
                    "the derived pubkey hashes to {} but the output pays {}; the derivation \
                     parameters and the script disagree about who owns this output",
                    Hex(pubkey_hash),
                    Hex(script_hash),
                )
            }
        }
    }
}

impl std::error::Error for ChangeDeriveError {}

/// Lowercase-hex display for a byte slice, for error messages.
struct Hex<'a>(&'a [u8]);

impl core::fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

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
    pub fn derive(
        fvk: &AccountPubKey,
        scope: u32,
        address_index: u32,
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
        let address_index_t = NonHardenedChildIndex::from_index(address_index).ok_or(
            ChangeDeriveError::AddressIndexHardened {
                index: address_index,
            },
        )?;

        let pubkey = fvk
            .derive_address_pubkey(TransparentKeyScope::INTERNAL, address_index_t)
            .map_err(|e| ChangeDeriveError::Derivation(e.to_string()))?
            .serialize();

        let script_hash = p2pkh_hash(script_pubkey).ok_or(ChangeDeriveError::NotP2pkh)?;
        let pubkey_hash = hash160(&pubkey);
        if script_hash != pubkey_hash {
            return Err(ChangeDeriveError::PubkeyMismatch {
                script_hash,
                pubkey_hash,
            });
        }

        Ok(ChangeInfo {
            output_index,
            pubkey,
            address_index,
        })
    }
}

/// What the shaping pass needs from the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapeParams {
    /// SLIP 44 coin type, which must match both the PCZT's `coin_type` and the
    /// device build's `ZCASH_BIP44_COIN_TYPE`.
    pub coin_type: u32,
    /// ZIP 32 account index (unhardened form), shared by the shielded and
    /// transparent paths.
    pub zip32_account: u32,
    /// The wallet's ZIP 32 seed fingerprint, if known.
    ///
    /// The firmware never checks the 32-byte fingerprint half of a
    /// `zip32_derivation` — only the path — so a PCZT from a UFVK-imported
    /// account with no stored derivation can be shaped with the zeroed default.
    /// When the PCZT already carries derivations, their fingerprint is adopted
    /// unless this field contradicts it.
    pub seed_fingerprint: Option<[u8; SEED_FINGERPRINT_SIZE]>,
    /// The transparent change output, if the transaction has one.
    pub change: Option<ChangeInfo>,
}

impl ShapeParams {
    /// The shielded account path `m/32'/coin'/account'`, in raw (hardened)
    /// indices.
    pub fn shielded_account_path(&self) -> Vec<u32> {
        vec![
            ZIP32_PURPOSE | HARDENED,
            self.coin_type | HARDENED,
            self.zip32_account | HARDENED,
        ]
    }

    /// The transparent change path `m/44'/coin'/account'/1/index`, in raw
    /// indices (the last two non-hardened).
    pub fn transparent_change_path(&self, address_index: u32) -> Vec<u32> {
        vec![
            BIP44_PURPOSE | HARDENED,
            self.coin_type | HARDENED,
            self.zip32_account | HARDENED,
            TRANSPARENT_INTERNAL_SCOPE,
            address_index,
        ]
    }
}

/// A PCZT shaped for the device, together with how it serializes.
///
/// Both the PCZT and its serialization carry the transaction's per-action
/// secrets. `Debug` shows neither, and the serialization is wiped when it is
/// dropped; the `pczt` crate's own types are not, and a caller that logs
/// [`Shaped::pczt`] with `{:?}` logs everything in it.
#[derive(Clone)]
pub struct Shaped {
    /// The shaped PCZT. This is what [`crate::plan::build_plan`] and, at the end
    /// of the ceremony, [`crate::apply`] operate on.
    pub pczt: Pczt,
    /// The canonical serialization of [`Shaped::pczt`].
    pub bytes: Zeroizing<Vec<u8>>,
    /// The PCZT wire-format revision `bytes` actually carries: `1` for V5, `2`
    /// for V6. Verified to match the transaction version.
    pub encoding_version: u32,
}

impl core::fmt::Debug for Shaped {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Shaped")
            .field("pczt", &"[redacted]")
            .field("bytes", &format_args!("[{} bytes]", self.bytes.len()))
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
    /// An account index that cannot be hardened.
    AccountOutOfRange {
        /// The index supplied.
        account: u32,
    },
    /// An index that must be non-hardened has the hardening bit set.
    IndexMustBeUnhardened {
        /// What the index is.
        what: &'static str,
        /// The value supplied.
        index: u32,
    },
    /// An action already carries a `zip32_derivation` whose path is not the
    /// `m/32'/coin'/account'` account path the device accepts, or is not the
    /// one the caller asked for. The device derives one account key per PCZT.
    NonUniformPath {
        /// Which pool.
        section: Section,
        /// Index of the action.
        index: usize,
        /// The path found, in raw indices.
        found: Vec<u32>,
        /// The path required.
        expected: Vec<u32>,
    },
    /// Two actions carry different seed fingerprints, or the caller's
    /// fingerprint contradicts one already in the PCZT.
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
    ChangeOutputHashMismatch {
        /// The index supplied.
        index: usize,
        /// The hash in the output's script.
        script_hash: [u8; 20],
        /// `HASH160` of the supplied pubkey.
        pubkey_hash: [u8; 20],
    },
    /// The `pczt` Updater role rejected the update.
    Updater(String),
    /// Serializing the shaped PCZT failed.
    Encoding(String),
    /// `Pczt::serialize()` chose an encoding the device will not accept for
    /// this transaction version: `1` is required for V5 and `2` for V6.
    ///
    /// `Pczt::serialize()` emits the *minimal* encoding capable of carrying the
    /// content — v1 whenever the PCZT is v1-representable — so a V5 PCZT that
    /// somehow needs v2 (an Orchard note-plaintext version v1 cannot carry, or
    /// non-canonical Ironwood data), and a V6 PCZT forced down to v1, both land
    /// here rather than being streamed under a header the device rejects.
    EncodingVersionMismatch {
        /// The version the encoder chose.
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
            ShapeError::AccountOutOfRange { account } => write!(
                f,
                "account index {account:#x} has the hardening bit set already and cannot be \
                 hardened"
            ),
            ShapeError::IndexMustBeUnhardened { what, index } => write!(
                f,
                "{what} {index:#x} has the hardening bit set; it must be supplied unhardened"
            ),
            ShapeError::NonUniformPath {
                section,
                index,
                found,
                expected,
            } => write!(
                f,
                "{section} {index} already carries a zip32_derivation path {found:?}, not the \
                 account path {expected:?} this session derives; the device derives one account \
                 key per PCZT"
            ),
            ShapeError::NonUniformSeedFingerprint => write!(
                f,
                "two actions carry different seed fingerprints, or the supplied fingerprint \
                 contradicts one already in the PCZT"
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
            ShapeError::ChangeOutputHashMismatch {
                index,
                script_hash,
                pubkey_hash,
            } => write!(
                f,
                "the supplied change pubkey hashes to {} but transparent output {index} pays {}; \
                 stamping it would make the device show the wallet's own change as a third-party \
                 recipient",
                Hex(pubkey_hash),
                Hex(script_hash),
            ),
            ShapeError::Updater(message) => {
                write!(f, "the PCZT Updater role rejected the update: {message}")
            }
            ShapeError::Encoding(message) => {
                write!(f, "serializing the shaped PCZT failed: {message}")
            }
            ShapeError::EncodingVersionMismatch { got, expected } => write!(
                f,
                "the shaped PCZT serialized as encoding version {got}, but the device requires \
                 version {expected} for this transaction version"
            ),
        }
    }
}

impl std::error::Error for ShapeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
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
/// 1. the caller's `coin_type` and account index are checked against the PCZT;
/// 2. every Orchard action's existing `zip32_derivation` is collected, its path
///    checked against `m/32'/coin'/account'` and its fingerprint checked for
///    uniformity — and the same for the Ironwood bundle on a V6 transaction;
/// 3. actions with no derivation are stamped with that path and the agreed
///    fingerprint (the caller's, else the one already present, else zeroed);
/// 4. the transparent change output, when the caller names one, is checked
///    against its script and stamped with `m/44'/coin'/account'/1/index`;
///    recipient outputs are left untouched so the device displays them;
/// 5. the result is serialized and the chosen encoding version is checked
///    against the transaction version.
pub fn shape_for_device(pczt: Pczt, params: &ShapeParams) -> Result<Shaped, ShapeError> {
    let global = read_global(&pczt)?;
    let is_v6 = is_v6_transaction(&global)?;

    if global.coin_type != params.coin_type {
        return Err(ShapeError::CoinTypeMismatch {
            pczt: global.coin_type,
            params: params.coin_type,
        });
    }
    if params.zip32_account & HARDENED != 0 {
        return Err(ShapeError::AccountOutOfRange {
            account: params.zip32_account,
        });
    }
    if params.coin_type & HARDENED != 0 {
        return Err(ShapeError::IndexMustBeUnhardened {
            what: "coin_type",
            index: params.coin_type,
        });
    }
    if let Some(change) = &params.change {
        if change.address_index & HARDENED != 0 {
            return Err(ShapeError::IndexMustBeUnhardened {
                what: "change address index",
                index: change.address_index,
            });
        }
    }

    let expected_path = params.shielded_account_path();

    // ---- 2. survey the derivations already present -------------------------
    let mut agreed_fingerprint = params.seed_fingerprint;
    survey_pool(
        &pczt,
        Section::Orchard,
        &expected_path,
        &mut agreed_fingerprint,
    )?;
    if is_v6 {
        survey_pool(
            &pczt,
            Section::Ironwood,
            &expected_path,
            &mut agreed_fingerprint,
        )?;
    }
    let fingerprint = agreed_fingerprint.unwrap_or([0u8; SEED_FINGERPRINT_SIZE]);

    // ---- 3. stamp the missing shielded derivations -------------------------
    let mut updater = Updater::new(pczt);

    updater = updater
        .update_orchard_with(|mut u| stamp_pool(&mut u, fingerprint, &expected_path))
        .map_err(|e| ShapeError::Updater(format!("orchard zip32: {e:?}")))?;

    if is_v6 {
        updater = updater
            .update_ironwood_with(|mut u| stamp_pool(&mut u, fingerprint, &expected_path))
            .map_err(|e| ShapeError::Updater(format!("ironwood zip32: {e:?}")))?;
    }

    // ---- 4. stamp the transparent change output ----------------------------
    if let Some(change) = &params.change {
        let pczt = updater.finish();

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
        let pubkey_hash = hash160(&change.pubkey);
        if script_hash != pubkey_hash {
            return Err(ShapeError::ChangeOutputHashMismatch {
                index: change.output_index,
                script_hash,
                pubkey_hash,
            });
        }

        let path = params.transparent_change_path(change.address_index);
        let derivation = zcash_transparent::pczt::Bip32Derivation::parse(fingerprint, path)
            .map_err(|e| {
                ShapeError::Updater(format!("transparent change bip32 derivation: {e:?}"))
            })?;

        updater = Updater::new(pczt)
            .update_transparent_with(|mut u| {
                u.update_output_with(change.output_index, |mut o| {
                    o.set_bip32_derivation(change.pubkey, derivation);
                    Ok(())
                })
            })
            .map_err(|e| ShapeError::Updater(format!("transparent change: {e:?}")))?;
    }

    // ---- 5. serialize and check the encoding version -----------------------
    let shaped = updater.finish();
    let bytes = Zeroizing::new(
        shaped
            .clone()
            .serialize()
            .map_err(|e| ShapeError::Encoding(format!("{e:?}")))?,
    );

    let version_bytes: [u8; 4] = bytes
        .get(4..8)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| {
            ShapeError::Encoding("the serialized PCZT is shorter than its 8-byte header".into())
        })?;
    let encoding_version = u32::from_le_bytes(version_bytes);
    let expected = pczt_version_for(is_v6);
    if encoding_version != expected {
        return Err(ShapeError::EncodingVersionMismatch {
            got: encoding_version,
            expected,
        });
    }

    Ok(Shaped {
        pczt: shaped,
        bytes,
        encoding_version,
    })
}

/// Checks the paths and fingerprints already present in one pool.
///
/// Reads through the Updater's own borrow of the parsed bundle (the only place
/// `zip32_derivation` has an accessor) without mutating anything.
fn survey_pool(
    pczt: &Pczt,
    section: Section,
    expected_path: &[u32],
    agreed_fingerprint: &mut Option<[u8; SEED_FINGERPRINT_SIZE]>,
) -> Result<(), ShapeError> {
    let mut violation: Option<ShapeError> = None;

    let inspect = |u: orchard::pczt::Updater<'_>,
                   violation: &mut Option<ShapeError>,
                   agreed: &mut Option<[u8; SEED_FINGERPRINT_SIZE]>| {
        for (index, action) in u.bundle().actions().iter().enumerate() {
            let Some(derivation) = action.spend().zip32_derivation().as_ref() else {
                continue;
            };
            let found: Vec<u32> = derivation
                .derivation_path()
                .iter()
                .map(|c| c.index())
                .collect();
            if found != expected_path {
                *violation = Some(ShapeError::NonUniformPath {
                    section,
                    index,
                    found,
                    expected: expected_path.to_vec(),
                });
                return;
            }
            match agreed {
                Some(fp) if fp != derivation.seed_fingerprint() => {
                    *violation = Some(ShapeError::NonUniformSeedFingerprint);
                    return;
                }
                Some(_) => {}
                None => *agreed = Some(*derivation.seed_fingerprint()),
            }
        }
    };

    // `Updater` is used here purely as the read path onto the parsed bundle;
    // the closure performs no mutation, and the PCZT it returns is discarded.
    let updater = Updater::new(pczt.clone());
    let result = match section {
        Section::Ironwood => updater.update_ironwood_with(|u| {
            inspect(u, &mut violation, agreed_fingerprint);
            Ok(())
        }),
        _ => updater.update_orchard_with(|u| {
            inspect(u, &mut violation, agreed_fingerprint);
            Ok(())
        }),
    };
    result.map_err(|e| ShapeError::Updater(format!("{section:?} survey: {e:?}")))?;

    match violation {
        Some(e) => Err(e),
        None => Ok(()),
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
        // Every index is hardened by construction, so `parse` cannot fail here;
        // the map only satisfies the closure's error type.
        let derivation = orchard::pczt::Zip32Derivation::parse(fingerprint, path.to_vec())
            .map_err(|_| orchard::pczt::UpdaterError::InvalidIndex)?;
        updater.update_action_with(index, |mut action| {
            action.set_spend_zip32_derivation(derivation);
            Ok(())
        })?;
    }

    Ok(())
}
