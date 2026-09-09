//! Device limits and capability gating.
//!
//! The numbers come from `src/consts.rs` in `LedgerHQ/app-zcash` and are
//! restated in `docs/PCZT_APDU.md`. Checking them on the host is not
//! redundant: the device answers a violation with a status word that resets
//! the whole transaction context, so a stream that cannot succeed is better
//! stopped before its first APDU.
//!
//! # The counts move with the app version
//!
//! v3.9.3 (`22dc385`) raised three of the four record bounds and added a
//! budget that did not exist before, so a single set of constants would be
//! wrong for one firmware or the other. [`DeviceBounds`] carries one set,
//! [`DeviceBounds::for_caps`] picks the set for a reported version, and
//! [`validate_records`] takes the set rather than reading a constant.
//!
//! Unknown versions fail closed on [`DeviceBounds::V3_9_2`]: refusing a
//! transaction a newer device would have taken is recoverable, streaming one
//! an older device will refuse mid-review is not.
//!
//! This module validates a [`StreamPlan`] — counts, script shapes, field
//! widths, version coherence. The *PCZT-level* checks (that the records agree
//! with the PCZT they came from) belong to the session layer.

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::apdu::encode::{
    BundleTrailerRecord, ShieldedActionRecord, StreamPlan, TransparentInputRecord,
    TransparentOutputRecord, ENC_CIPHERTEXT_SIZE, MAX_PATH_COMPONENTS, NOTE_VERSION_IRONWOOD,
    OUT_CIPHERTEXT_SIZE, PCZT_VERSION_V5, PCZT_VERSION_V6, SIGHASH_ALL,
};

/// `MAX_PCZT_TRANSPARENT_OUTPUTS_NUMBER` — unchanged across every supported
/// app version; also carried in [`DeviceBounds`] for uniformity.
pub const MAX_TRANSPARENT_OUTPUTS: usize = 10;

/// The record bounds one app version enforces.
///
/// Each field is the largest count `src/parser/pczt/*.rs` accepts at the
/// section's count packet; a bundle declaring more is refused there, before
/// any per-record field is read (`docs/PCZT_APDU.md` @ `22dc385`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceBounds {
    /// `MAX_PCZT_TRANSPARENT_INPUTS_NUMBER`.
    pub transparent_inputs: usize,
    /// `MAX_PCZT_TRANSPARENT_OUTPUTS_NUMBER`.
    pub transparent_outputs: usize,
    /// `MAX_PCZT_ORCHARD_ACTIONS_NUMBER`.
    pub orchard_actions: usize,
    /// `MAX_PCZT_IRONWOOD_ACTIONS_NUMBER`.
    pub ironwood_actions: usize,
    /// `MAX_PCZT_SHIELDED_DISPLAYED_OUTPUTS_NUMBER`, counted across *both*
    /// shielded pools; `None` on an app that has no such budget.
    ///
    /// See [`crate::plan::Plan::displayed_shielded_outputs`] for what the host
    /// can and cannot count against it.
    pub displayed_shielded_outputs: Option<usize>,
}

impl DeviceBounds {
    /// v3.6.0 through v3.9.2: ten of everything, and no display budget.
    ///
    /// `src/consts.rs` @ `0e048bb`, all four "due to device memory
    /// constraints".
    pub const V3_9_2: DeviceBounds = DeviceBounds {
        transparent_inputs: 10,
        transparent_outputs: MAX_TRANSPARENT_OUTPUTS,
        orchard_actions: 10,
        ironwood_actions: 10,
        displayed_shielded_outputs: None,
    };

    /// v3.9.3 and later.
    ///
    /// `src/consts.rs` @ `22dc385`: the transparent-input bound became 32
    /// ("32 inputs parse, review and sign on Nano X, with the run failing well
    /// above"), both shielded bounds became 32, the transparent-output bound
    /// stayed at 10, and `MAX_PCZT_SHIELDED_DISPLAYED_OUTPUTS_NUMBER = 4`
    /// appeared to bound the *review* separately from the spend — which is
    /// what let the action bounds rise at all.
    pub const V3_9_3: DeviceBounds = DeviceBounds {
        transparent_inputs: 32,
        transparent_outputs: MAX_TRANSPARENT_OUTPUTS,
        orchard_actions: 32,
        ironwood_actions: 32,
        displayed_shielded_outputs: Some(4),
    };

    /// What to use when the app version is not known.
    ///
    /// The older, smaller set, deliberately: a plan validated against it is
    /// streamable to *every* supported app, while the reverse is not true.
    pub const UNKNOWN_VERSION: DeviceBounds = DeviceBounds::V3_9_2;

    /// The most permissive set any supported app enforces.
    ///
    /// For the one caller that must not refuse before it knows what it is
    /// talking to: a pre-flight check run before `GET_FIRMWARE_VERSION`, whose
    /// job is to catch what *no* firmware would accept. The authoritative,
    /// version-gated check runs afterwards, in
    /// [`crate::session::LedgerSignSession::new`]. The display budget is
    /// `None` here for the same reason.
    pub const MOST_PERMISSIVE: DeviceBounds = DeviceBounds {
        transparent_inputs: 32,
        transparent_outputs: MAX_TRANSPARENT_OUTPUTS,
        orchard_actions: 32,
        ironwood_actions: 32,
        displayed_shielded_outputs: None,
    };

    /// The bounds a reported app version enforces.
    ///
    /// Anything below [`MIN_VERSION_RAISED_BOUNDS`] — including a version this
    /// crate predates knowing about — gets [`DeviceBounds::V3_9_2`].
    pub const fn for_caps(caps: &DeviceCaps) -> DeviceBounds {
        if version_at_least(caps.version, MIN_VERSION_RAISED_BOUNDS) {
            DeviceBounds::V3_9_3
        } else {
            DeviceBounds::V3_9_2
        }
    }
}

/// `(major, minor, patch)` comparison, in a `const fn` because tuple `PartialOrd`
/// is not one.
const fn version_at_least(got: (u8, u8, u8), want: (u8, u8, u8)) -> bool {
    if got.0 != want.0 {
        return got.0 > want.0;
    }
    if got.1 != want.1 {
        return got.1 > want.1;
    }
    got.2 >= want.2
}

/// `MAX_PCZT_SCRIPT_SIZE` — the raw `script_pubkey` bound, prefix excluded.
///
/// `src/consts.rs`: "PCZT path, where every transparent input's script is
/// retained for the session. 252 is the host's own limit, the single-byte
/// CompactSize boundary."
pub const MAX_SCRIPT_SIZE: usize = 252;

/// `V5_TX_VERSION`.
pub const V5_TX_VERSION: u32 = 5;
/// `V5_VERSION_GROUP_ID`.
pub const V5_VERSION_GROUP_ID: u32 = 0x26A7_270A;
/// `V6_TX_VERSION` (`src/consts.rs`).
pub const V6_TX_VERSION: u32 = 6;
/// `V6_VERSION_GROUP_ID` (`src/consts.rs`).
pub const V6_VERSION_GROUP_ID: u32 = 0xD884_B698;

/// Zcash mainnet BIP 44 coin type.
pub const COIN_TYPE_MAINNET: u32 = 133;
/// Zcash testnet BIP 44 coin type.
pub const COIN_TYPE_TESTNET: u32 = 1;

/// Which Zcash network the transaction is for.
///
/// The device build is network-specific: `ZCASH_BIP44_COIN_TYPE` is a compile
/// time constant, and `parse_global` answers `"Unsupported PCZT coin_type"` for
/// anything else. A testnet PCZT on a mainnet device therefore fails at the
/// header, whatever the host does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Mainnet, SLIP 44 coin type 133.
    Main,
    /// Testnet, SLIP 44 coin type 1.
    Test,
}

impl Network {
    /// The SLIP 44 coin type.
    pub const fn coin_type(self) -> u32 {
        match self {
            Network::Main => COIN_TYPE_MAINNET,
            Network::Test => COIN_TYPE_TESTNET,
        }
    }
}

/// A [`zcash_protocol::consensus::NetworkType`] with no Ledger app build.
///
/// Regtest is the one refused value, and the refusal is deliberate: the device
/// build's coin type is a compile-time constant with no regtest value, and
/// regtest shares SLIP 44 coin type 1 with testnet — so a regtest transaction
/// signed "as testnet" would be signed silently rather than knowingly. A caller
/// that really wants to drive a testnet device against a regtest chain has to
/// say [`Network::Test`] itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedNetwork(pub zcash_protocol::consensus::NetworkType);

impl core::fmt::Display for UnsupportedNetwork {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "no Ledger Zcash app build exists for {:?}: the app's coin type is a compile-time \
             constant with only mainnet and testnet values",
            self.0
        )
    }
}

impl std::error::Error for UnsupportedNetwork {}

impl TryFrom<zcash_protocol::consensus::NetworkType> for Network {
    type Error = UnsupportedNetwork;

    fn try_from(value: zcash_protocol::consensus::NetworkType) -> Result<Self, Self::Error> {
        use zcash_protocol::consensus::NetworkType;
        match value {
            NetworkType::Main => Ok(Network::Main),
            NetworkType::Test => Ok(Network::Test),
            // See [`UnsupportedNetwork`]: regtest is refused, not mapped.
            NetworkType::Regtest => Err(UnsupportedNetwork(value)),
        }
    }
}

/// First app version to speak the PCZT instructions at all.
pub const MIN_VERSION_PCZT: (u8, u8, u8) = (3, 6, 0);
/// First app version with the Ironwood pool (`INS_PCZT_IRONWOOD_ACTION`).
///
/// 3.9.0 and 3.9.1 were never released — the app's tags jump from 3.6.0 to
/// 3.9.2 — so this is the conservative floor for the 3.9.x line rather than a
/// version that shipped. Nothing is mis-gated by it: a pre-Ironwood build
/// answers the instruction with `InsNotSupported` and fails closed as
/// `WrongApp` anyway.
pub const MIN_VERSION_IRONWOOD: (u8, u8, u8) = (3, 9, 0);
/// First app version with the raised record bounds and the shielded
/// displayed-output budget (`src/consts.rs` @ `22dc385`).
pub const MIN_VERSION_RAISED_BOUNDS: (u8, u8, u8) = (3, 9, 3);

/// What a connected device can do, derived from its reported app version.
///
/// An older app answers an instruction it does not know with
/// `InsNotSupported` (`0x6D00`) and no diagnostic, so the host has to gate on
/// the version it read from `GET_FIRMWARE_VERSION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceCaps {
    /// The app version reported by `GET_FIRMWARE_VERSION`.
    pub version: (u8, u8, u8),
    /// Whether the `PCZT_*` instructions are available.
    pub pczt: bool,
    /// Whether `PCZT_IRONWOOD_ACTION` / `PCZT_SIGN_IRONWOOD` are available,
    /// i.e. whether a V6 transaction can be signed at all.
    pub ironwood: bool,
}

impl DeviceCaps {
    /// Derives capabilities from a reported app version.
    pub fn from_version(major: u8, minor: u8, patch: u8) -> Self {
        let v = (major, minor, patch);
        DeviceCaps {
            version: v,
            pczt: v >= MIN_VERSION_PCZT,
            ironwood: v >= MIN_VERSION_IRONWOOD,
        }
    }

    /// The record bounds this app version enforces.
    pub const fn bounds(&self) -> DeviceBounds {
        DeviceBounds::for_caps(self)
    }
}

/// A way a plan cannot be streamed to the device.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LimitViolation {
    /// More records of one kind than the device can hold.
    TooManyRecords {
        /// Which section.
        section: Section,
        /// Records in the plan.
        got: usize,
        /// The device's cap.
        max: usize,
    },
    /// A `script_pubkey` exceeds [`MAX_SCRIPT_SIZE`].
    ScriptTooLong {
        /// Which section the script belongs to.
        section: Section,
        /// Index within that section.
        index: usize,
        /// Raw script length.
        got: usize,
    },
    /// A transparent *input*'s `script_pubkey` is not the 25-byte P2PKH form.
    ///
    /// `output_script_is_regular` applied to inputs in
    /// `src/parser/pczt/transparent.rs` @ `22dc385`, refusing with
    /// `IncorrectData`: "the only key this app derives on the transparent tree
    /// pays to a P2PKH hash. Any other shape is one it cannot produce a valid
    /// signature for — a P2SH input would need a redeem script the wire format
    /// does not carry — so accepting it would sign something unspendable."
    ///
    /// Checked for **every** app version, not only v3.9.3. The reasoning holds
    /// on v3.9.2 too: it has no such check, so it signs the input and returns
    /// a signature that cannot spend it. Turning a silently useless signature
    /// into a pre-flight refusal is not a regression for that device.
    NonP2pkhInputScript {
        /// Index of the input.
        index: usize,
    },
    /// A transparent output script is neither P2PKH nor P2SH.
    ///
    /// `docs/APDU.md`: "An output's `script_pubkey` must be a standard P2PKH
    /// or P2SH script. Any other form, including OP_RETURN, is refused with
    /// `IncorrectData`."
    NonStandardOutputScript {
        /// Index of the output.
        index: usize,
    },
    /// A transparent record's `bip32_derivation` names a pubkey that does not
    /// pay the record's `script_pubkey`: the script is not P2PKH, or its hash
    /// is not `HASH160(pubkey)`.
    ///
    /// For an **input**, the derivation is the device's signing-key locator,
    /// so the device would sign with a key that cannot spend the coin. Nothing
    /// on the device catches it, and the host's own return path fails only at
    /// [`crate::apply`] — after the user has reviewed and approved the whole
    /// transaction. That burned approval is what this pre-flight prevents.
    ///
    /// For an **output**, the derivation is what marks it as change. The
    /// device re-derives the pubkey from the path and compares it with the one
    /// supplied, but a pubkey that derives correctly and does not hash to the
    /// output's script is not an abort there: `check_output_displayable`
    /// classifies the output as a third-party recipient, and the wallet's own
    /// change is shown to the user as a payment to someone else. The shaping
    /// pass applies this rule to the change output it stamps; this is the same
    /// rule applied to a derivation the PCZT arrived with.
    DerivationPubkeyMismatch {
        /// Which section.
        section: Section,
        /// Index within that section.
        index: usize,
    },
    /// A transparent input declares a sighash type other than `SIGHASH_ALL`.
    UnsupportedSighashType {
        /// Index of the input.
        index: usize,
        /// The type declared.
        got: u8,
    },
    /// A derivation path is longer than the device's `MAX_ZCASH_BIP32_PATH`.
    PathTooLong {
        /// Which section.
        section: Section,
        /// Index within that section.
        index: usize,
        /// Number of components.
        got: usize,
    },
    /// A ciphertext is not the fixed length the device requires.
    BadCiphertextLength {
        /// Which section.
        section: Section,
        /// Index within that section.
        index: usize,
        /// Which of the two ciphertexts.
        field: &'static str,
        /// Length required.
        expected: usize,
        /// Length in the record.
        got: usize,
    },
    /// The PCZT version does not match the transaction version: version 1 is
    /// required for V5, version 2 for V6.
    PcztVersionMismatch {
        /// The PCZT version in the header.
        pczt_version: u32,
        /// The transaction version in the header.
        tx_version: u32,
    },
    /// `tx_version` / `version_group_id` are not a recognised pair.
    UnsupportedTxVersion {
        /// The transaction version.
        tx_version: u32,
        /// The version group id.
        version_group_id: u32,
    },
    /// An Ironwood bundle on a plan that declares V5, which
    /// `parse_ironwood_actions_start` rejects outright, or a V6 plan with no
    /// Ironwood bundle at all, which leaves the transaction reviewed by
    /// nothing and therefore unsignable.
    IronwoodBundleMismatch {
        /// The transaction version in the header.
        tx_version: u32,
        /// Whether the plan carries an Ironwood bundle.
        has_ironwood: bool,
    },
    /// A non-empty bundle without its trailer, or a trailer on an empty
    /// bundle.
    TrailerMismatch {
        /// Which pool.
        section: Section,
        /// Number of actions.
        actions: usize,
        /// Whether a trailer is present.
        has_trailer: bool,
    },
    /// An Orchard action carries a `notePlaintextVersion` byte, which
    /// `parse_orchard_output_metadata` has no 116-byte form for, or an
    /// Ironwood action carries one that is not `0x03`.
    BadNotePlaintextVersion {
        /// Which pool.
        section: Section,
        /// Index of the action.
        index: usize,
        /// The byte in the record, if any.
        got: Option<u8>,
    },
    /// The `coin_type` is neither mainnet nor testnet. The device compares it
    /// against its own build constant, so even a valid-looking value can be
    /// refused by the wrong build.
    UnknownCoinType {
        /// The value in the header.
        got: u32,
    },
    /// The connected app is too old for the PCZT instructions.
    PcztUnsupported {
        /// The version reported by the device.
        version: (u8, u8, u8),
        /// The version that first supports them.
        required: (u8, u8, u8),
    },
    /// More shielded outputs would reach the device's review screen than its
    /// `MAX_PCZT_SHIELDED_DISPLAYED_OUTPUTS_NUMBER` budget allows.
    ///
    /// `claim_displayed_shielded_output` (`src/parser/pczt.rs` @ `22dc385`)
    /// refuses the one past the budget with `NotEnoughMemorySpace`
    /// (`0x6A84`) — mid-stream, at whichever action packet happens to cross
    /// it, taking the transaction context with it. Counting on the host turns
    /// that into a refusal before the first APDU.
    ///
    /// `got` is [`crate::plan::Plan::displayed_shielded_outputs`]; `exact`
    /// says whether that is the device's own count or an upper bound on it.
    TooManyDisplayedShieldedOutputs {
        /// Outputs this plan is expected to display, across both pools.
        got: usize,
        /// The device's budget.
        max: usize,
        /// Whether `got` is the count the device itself would reach.
        ///
        /// `true` when the plan was built with the account's viewing keys, so
        /// change outputs were discounted and zero-valued outputs classified
        /// exactly as the device does. `false` when it was not: `got` is then
        /// a count over the nonzero outputs, change included, and a refusal
        /// may be one the device would not make. See
        /// [`crate::plan::Plan::displayed_shielded_outputs`].
        exact: bool,
    },
    /// The transaction carries more than one change output, which the device
    /// refuses with `"Multiple change outputs detected"`.
    ///
    /// The budget is one, for the whole transaction, across every pool:
    /// `TxInfo::is_change_found` is cleared when the transparent output count
    /// arrives and set by the change branch of the transparent, Orchard and
    /// Ironwood parsers alike (`src/parser/pczt/transparent.rs:748`,
    /// `orchard.rs:803`, `ironwood.rs:831` @ `22dc385`). The second change
    /// output the device meets ends the transaction mid-stream.
    ///
    /// A wallet whose note-management policy splits change across several notes
    /// produces exactly this, and the transaction has to be rebuilt with a
    /// single change note before the device will take it.
    ///
    /// The transparent half needs no key: an output is change to the device
    /// exactly when it carries a `bip32_derivation`, which is in the plan. The
    /// shielded half is counted only for a plan built with the account's
    /// viewing keys — without them the host cannot tell a shielded change
    /// output from a payment — so `shielded` is `None` for a plan built
    /// without them, and `got` then counts transparent change alone. A refusal
    /// raised without keys is one the device would make too; the keys only
    /// let it be raised for shielded change as well. See
    /// [`crate::plan::Plan::shielded_change_outputs`].
    MultipleChangeOutputs {
        /// Change outputs found, across every pool that could be counted.
        got: usize,
        /// How many of those are shielded, or `None` when the plan was built
        /// without viewing keys and shielded change could not be counted.
        shielded: Option<usize>,
    },
    /// The connected app is too old for the Ironwood pool.
    IronwoodUnsupported {
        /// The version reported by the device.
        version: (u8, u8, u8),
        /// The version that first supports it.
        required: (u8, u8, u8),
    },
}

/// Which part of a plan a violation refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    /// `PCZT_TRANSPARENT_INPUT`.
    TransparentInput,
    /// `PCZT_TRANSPARENT_OUTPUT`.
    TransparentOutput,
    /// `PCZT_ORCHARD_ACTION`.
    Orchard,
    /// `PCZT_IRONWOOD_ACTION`.
    Ironwood,
}

impl core::fmt::Display for Section {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Section::TransparentInput => "transparent input",
            Section::TransparentOutput => "transparent output",
            Section::Orchard => "Orchard action",
            Section::Ironwood => "Ironwood action",
        })
    }
}

impl core::fmt::Display for LimitViolation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LimitViolation::TooManyRecords { section, got, max } => write!(
                f,
                "the transaction has {got} {section}(s), and the connected device holds at most \
                 {max}"
            ),
            LimitViolation::ScriptTooLong {
                section,
                index,
                got,
            } => write!(
                f,
                "{section} {index} carries a {got}-byte script_pubkey, above the device's \
                 {MAX_SCRIPT_SIZE}-byte cap"
            ),
            LimitViolation::NonP2pkhInputScript { index } => write!(
                f,
                "transparent input {index}'s script_pubkey is not the 25-byte P2PKH form, the \
                 only script this app can produce a spendable signature for"
            ),
            LimitViolation::NonStandardOutputScript { index } => write!(
                f,
                "transparent output {index}'s script_pubkey is neither P2PKH nor P2SH, which the \
                 device refuses"
            ),
            LimitViolation::DerivationPubkeyMismatch { section, index } => write!(
                f,
                "{section} {index}'s bip32_derivation names a pubkey that does not pay its \
                 script_pubkey; {}",
                match section {
                    Section::TransparentInput => {
                        "the device would sign with a key that cannot spend the coin, and the \
                         signature could never be applied"
                    }
                    _ => {
                        "the device would show the wallet's own change as a third-party \
                         recipient"
                    }
                }
            ),
            LimitViolation::UnsupportedSighashType { index, got } => write!(
                f,
                "transparent input {index} declares sighash type {got:#04x}; the device signs \
                 SIGHASH_ALL (0x01) only"
            ),
            LimitViolation::PathTooLong {
                section,
                index,
                got,
            } => write!(
                f,
                "{section} {index} carries a {got}-component derivation path, above the device's \
                 maximum of {}",
                crate::apdu::encode::MAX_PATH_COMPONENTS
            ),
            LimitViolation::BadCiphertextLength {
                section,
                index,
                field,
                expected,
                got,
            } => write!(
                f,
                "{section} {index}'s {field} is {got} bytes; the device requires exactly \
                 {expected}"
            ),
            LimitViolation::PcztVersionMismatch {
                pczt_version,
                tx_version,
            } => write!(
                f,
                "PCZT encoding version {pczt_version} does not match transaction version \
                 {tx_version}: the device requires encoding 1 for V5 and 2 for V6"
            ),
            LimitViolation::UnsupportedTxVersion {
                tx_version,
                version_group_id,
            } => write!(
                f,
                "tx_version {tx_version} with version_group_id {version_group_id:#010x} is \
                 neither the V5 nor the V6 pair the device accepts"
            ),
            LimitViolation::IronwoodBundleMismatch {
                tx_version,
                has_ironwood,
            } => {
                if *has_ironwood {
                    write!(
                        f,
                        "the plan carries an Ironwood bundle on a V{tx_version} transaction, \
                         which the device rejects outright"
                    )
                } else {
                    write!(
                        f,
                        "a V{tx_version} plan carries no Ironwood bundle, leaving the \
                         transaction reviewed by nothing and therefore unsignable"
                    )
                }
            }
            LimitViolation::TrailerMismatch {
                section,
                actions,
                has_trailer,
            } => write!(
                f,
                "the {section} bundle has {actions} action(s) but its trailer is {}: a non-empty \
                 bundle requires one and an empty bundle forbids it",
                if *has_trailer { "present" } else { "absent" },
            ),
            LimitViolation::BadNotePlaintextVersion {
                section,
                index,
                got,
            } => match got {
                Some(got) => write!(
                    f,
                    "{section} {index} carries notePlaintextVersion {got:#04x}; an Orchard \
                     action must carry none and an Ironwood action only 0x03"
                ),
                None => write!(
                    f,
                    "{section} {index} carries no notePlaintextVersion byte where one was \
                     expected"
                ),
            },
            LimitViolation::UnknownCoinType { got } => write!(
                f,
                "coin type {got} is neither mainnet (133) nor testnet (1); no device build \
                 accepts it"
            ),
            LimitViolation::PcztUnsupported { version, required } => write!(
                f,
                "the connected app is v{}.{}.{}, and the PCZT instructions first appear in \
                 v{}.{}.{}",
                version.0, version.1, version.2, required.0, required.1, required.2,
            ),
            LimitViolation::TooManyDisplayedShieldedOutputs {
                got,
                max,
                exact: true,
            } => write!(
                f,
                "this transaction would put {got} shielded outputs on the device's review \
                 screen, and it displays at most {max}; build the transaction with fewer \
                 recipients"
            ),
            LimitViolation::TooManyDisplayedShieldedOutputs {
                got,
                max,
                exact: false,
            } => write!(
                f,
                "this transaction would put about {got} shielded outputs on the device's \
                 review screen, and it displays at most {max}. {got} is a count over the nonzero \
                 outputs, not the device's own: without the account's viewing keys every \
                 nonzero output is counted, change included, so a transaction the device would \
                 accept can be refused here. Provide the account's viewing keys via \
                 SessionParams to make the displayed-output count exact."
            ),
            LimitViolation::MultipleChangeOutputs { got, shielded } => {
                write!(f, "this transaction has {got} change output(s) (")?;
                match shielded {
                    Some(shielded) => write!(f, "{shielded} shielded")?,
                    None => write!(
                        f,
                        "all transparent; shielded change was not counted, since no viewing \
                         keys were supplied"
                    )?,
                }
                write!(
                    f,
                    "), and the device accepts at most one across all pools — a second one is \
                     refused mid-stream with \"Multiple change outputs detected\". The \
                     transaction splits change across multiple outputs, which the device cannot \
                     present; build it with a single change output."
                )
            }
            LimitViolation::IronwoodUnsupported { version, required } => write!(
                f,
                "the connected app is v{}.{}.{}, and the Ironwood pool first appears in \
                 v{}.{}.{}",
                version.0, version.1, version.2, required.0, required.1, required.2,
            ),
        }
    }
}

impl std::error::Error for LimitViolation {}

/// `HASH160(x) = RIPEMD160(SHA256(x))`.
///
/// The same primitives `zcash_transparent::util::hash160` composes; the
/// function is here because it is what a P2PKH `scriptPubKey` commits to, and
/// this module is where scripts are checked.
pub fn hash160(bytes: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(bytes);
    let out = Ripemd160::digest(sha);
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&out);
    hash
}

/// The 20-byte hash of a standard P2PKH `scriptPubKey`, or `None`.
///
/// `OP_DUP OP_HASH160 <20> … OP_EQUALVERIFY OP_CHECKSIG`. Shares its shape test
/// with [`is_p2pkh_script`], which is the same predicate the device applies.
pub fn p2pkh_hash(script: &[u8]) -> Option<[u8; 20]> {
    if is_p2pkh_script(script) {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&script[3..23]);
        Some(hash)
    } else {
        None
    }
}

/// Whether a `bip32_derivation` pubkey pays a P2PKH script: the script has
/// that shape and its hash is `HASH160(pubkey)`.
fn derivation_pays_script(pubkey: &[u8], script: &[u8]) -> bool {
    p2pkh_hash(script).is_some_and(|hash| hash == hash160(pubkey))
}

/// Whether a script is the 25-byte P2PKH `scriptPubKey`
/// `76 a9 14 <hash160> 88 ac`.
///
/// `output_script_is_regular` in `ledger_zcash_crypto::transparent_script`, the
/// predicate the device applies to every transparent input from `22dc385`
/// (`docs/PCZT_APDU.md`: "An **input**'s `script_pubkey` must additionally be
/// the 25-byte P2PKH shape").
pub fn is_p2pkh_script(script: &[u8]) -> bool {
    script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xA9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xAC
}

/// Whether a script is a standard P2PKH or P2SH `scriptPubKey`.
///
/// - P2PKH: `OP_DUP OP_HASH160 <20> … OP_EQUALVERIFY OP_CHECKSIG` — 25 bytes.
/// - P2SH: `OP_HASH160 <20> … OP_EQUAL` — 23 bytes.
///
/// This is the *output* rule, and it stayed as it was: `docs/PCZT_APDU.md` @
/// `22dc385`, "Output scripts keep accepting P2PKH and P2SH."
pub fn is_standard_output_script(script: &[u8]) -> bool {
    let p2sh = script.len() == 23 && script[0] == 0xA9 && script[1] == 0x14 && script[22] == 0x87;
    is_p2pkh_script(script) || p2sh
}

fn check_transparent_input(
    index: usize,
    input: &TransparentInputRecord,
    out: &mut Vec<LimitViolation>,
) {
    if input.script_pubkey.len() > MAX_SCRIPT_SIZE {
        out.push(LimitViolation::ScriptTooLong {
            section: Section::TransparentInput,
            index,
            got: input.script_pubkey.len(),
        });
    }
    if !is_p2pkh_script(&input.script_pubkey) {
        out.push(LimitViolation::NonP2pkhInputScript { index });
    } else if !derivation_pays_script(&input.derivation.pubkey, &input.script_pubkey) {
        // Only for a script of the right shape: a non-P2PKH input is already
        // refused above, and cannot be paid by any derivation.
        out.push(LimitViolation::DerivationPubkeyMismatch {
            section: Section::TransparentInput,
            index,
        });
    }
    if input.sighash_type != SIGHASH_ALL {
        out.push(LimitViolation::UnsupportedSighashType {
            index,
            got: input.sighash_type,
        });
    }
    if input.derivation.path.0.len() > MAX_PATH_COMPONENTS {
        out.push(LimitViolation::PathTooLong {
            section: Section::TransparentInput,
            index,
            got: input.derivation.path.0.len(),
        });
    }
}

fn check_transparent_output(
    index: usize,
    output: &TransparentOutputRecord,
    out: &mut Vec<LimitViolation>,
) {
    if output.script_pubkey.len() > MAX_SCRIPT_SIZE {
        out.push(LimitViolation::ScriptTooLong {
            section: Section::TransparentOutput,
            index,
            got: output.script_pubkey.len(),
        });
    }
    if !is_standard_output_script(&output.script_pubkey) {
        out.push(LimitViolation::NonStandardOutputScript { index });
    }
    if let Some(d) = &output.derivation {
        if d.path.0.len() > MAX_PATH_COMPONENTS {
            out.push(LimitViolation::PathTooLong {
                section: Section::TransparentOutput,
                index,
                got: d.path.0.len(),
            });
        }
        // A derivation is a claim that this output is the wallet's own
        // change; the claim is only true of a P2PKH output paying that key.
        if !derivation_pays_script(&d.pubkey, &output.script_pubkey) {
            out.push(LimitViolation::DerivationPubkeyMismatch {
                section: Section::TransparentOutput,
                index,
            });
        }
    }
}

fn check_shielded_bundle(
    section: Section,
    actions: &[ShieldedActionRecord],
    trailer: Option<&BundleTrailerRecord>,
    max: usize,
    out: &mut Vec<LimitViolation>,
) {
    if actions.len() > max {
        out.push(LimitViolation::TooManyRecords {
            section,
            got: actions.len(),
            max,
        });
    }

    if actions.is_empty() != trailer.is_none() {
        out.push(LimitViolation::TrailerMismatch {
            section,
            actions: actions.len(),
            has_trailer: trailer.is_some(),
        });
    }

    for (index, a) in actions.iter().enumerate() {
        if a.enc_ciphertext.len() != ENC_CIPHERTEXT_SIZE {
            out.push(LimitViolation::BadCiphertextLength {
                section,
                index,
                field: "enc_ciphertext",
                expected: ENC_CIPHERTEXT_SIZE,
                got: a.enc_ciphertext.len(),
            });
        }
        if a.out_ciphertext.len() != OUT_CIPHERTEXT_SIZE {
            out.push(LimitViolation::BadCiphertextLength {
                section,
                index,
                field: "out_ciphertext",
                expected: OUT_CIPHERTEXT_SIZE,
                got: a.out_ciphertext.len(),
            });
        }
        if a.zip32_derivation.path.0.len() > MAX_PATH_COMPONENTS {
            out.push(LimitViolation::PathTooLong {
                section,
                index,
                got: a.zip32_derivation.path.0.len(),
            });
        }

        let note_version_ok = match (section, a.note_plaintext_version) {
            // `parse_orchard_output_metadata` accepts only the 115-byte
            // packet, so an Orchard action must not carry the byte.
            (Section::Orchard, v) => v.is_none(),
            // Ironwood accepts 115 (implying 0x03) or 116 with 0x03.
            (Section::Ironwood, None) => true,
            (Section::Ironwood, Some(v)) => v == NOTE_VERSION_IRONWOOD,
            _ => true,
        };
        if !note_version_ok {
            out.push(LimitViolation::BadNotePlaintextVersion {
                section,
                index,
                got: a.note_plaintext_version,
            });
        }
    }
}

/// Checks a plan against everything the device will check, before the first
/// APDU goes out.
///
/// `bounds` is the record-count set the connected app enforces; see
/// [`DeviceBounds`] for why it is a parameter and not a constant, and
/// [`DeviceBounds::UNKNOWN_VERSION`] for the fail-closed default.
///
/// Returns every violation found rather than the first, so a caller can report
/// them all at once. An empty result means the plan is streamable as far as
/// this layer can tell. The shielded displayed-output budget is *not* checked
/// here: it is counted from the PCZT rather than from the wire records, so it
/// lives in [`validate_plan`].
pub fn validate_records(
    plan: &StreamPlan,
    bounds: &DeviceBounds,
) -> Result<(), Vec<LimitViolation>> {
    let mut out = Vec::new();
    let h = &plan.header;

    // Version coherence, mirroring `parse_global`.
    let is_v5 = h.tx_version == V5_TX_VERSION && h.version_group_id == V5_VERSION_GROUP_ID;
    let is_v6 = h.tx_version == V6_TX_VERSION && h.version_group_id == V6_VERSION_GROUP_ID;
    if !is_v5 && !is_v6 {
        out.push(LimitViolation::UnsupportedTxVersion {
            tx_version: h.tx_version,
            version_group_id: h.version_group_id,
        });
    } else {
        let want = if is_v5 {
            PCZT_VERSION_V5
        } else {
            PCZT_VERSION_V6
        };
        if h.pczt_version != want {
            out.push(LimitViolation::PcztVersionMismatch {
                pczt_version: h.pczt_version,
                tx_version: h.tx_version,
            });
        }
        // A V6 transaction must send `PCZT_IRONWOOD_ACTION` — even with count
        // zero, since that is the command that triggers the review. A V5 one
        // must not send it at all.
        if is_v6 != plan.ironwood_actions.is_some() {
            out.push(LimitViolation::IronwoodBundleMismatch {
                tx_version: h.tx_version,
                has_ironwood: plan.ironwood_actions.is_some(),
            });
        }
    }

    if h.coin_type != COIN_TYPE_MAINNET && h.coin_type != COIN_TYPE_TESTNET {
        out.push(LimitViolation::UnknownCoinType { got: h.coin_type });
    }

    if plan.transparent_inputs.len() > bounds.transparent_inputs {
        out.push(LimitViolation::TooManyRecords {
            section: Section::TransparentInput,
            got: plan.transparent_inputs.len(),
            max: bounds.transparent_inputs,
        });
    }
    for (i, input) in plan.transparent_inputs.iter().enumerate() {
        check_transparent_input(i, input, &mut out);
    }

    if plan.transparent_outputs.len() > bounds.transparent_outputs {
        out.push(LimitViolation::TooManyRecords {
            section: Section::TransparentOutput,
            got: plan.transparent_outputs.len(),
            max: bounds.transparent_outputs,
        });
    }
    for (i, output) in plan.transparent_outputs.iter().enumerate() {
        check_transparent_output(i, output, &mut out);
    }

    check_shielded_bundle(
        Section::Orchard,
        &plan.orchard_actions,
        plan.orchard_trailer.as_ref(),
        bounds.orchard_actions,
        &mut out,
    );

    if let Some(ironwood) = &plan.ironwood_actions {
        check_shielded_bundle(
            Section::Ironwood,
            ironwood,
            plan.ironwood_trailer.as_ref(),
            bounds.ironwood_actions,
            &mut out,
        );
    }

    if out.is_empty() {
        Ok(())
    } else {
        Err(out)
    }
}

/// [`validate_records`] plus the checks that need the whole [`crate::plan::Plan`]
/// rather than only its wire records.
///
/// Two checks: the shielded displayed-output budget, which is counted from the
/// PCZT (see [`crate::plan::Plan::displayed_shielded_outputs`]) and has no
/// representation in the [`StreamPlan`] the device is sent — an app with no
/// such budget (`bounds.displayed_shielded_outputs == None`, i.e. anything
/// before v3.9.3) skips it entirely — and the device's one-change-output rule,
/// whose shielded half is likewise counted from the PCZT and whose transparent
/// half is read off the records.
pub fn validate_plan(
    plan: &crate::plan::Plan,
    bounds: &DeviceBounds,
) -> Result<(), Vec<LimitViolation>> {
    let mut out = match validate_records(&plan.stream, bounds) {
        Ok(()) => Vec::new(),
        Err(violations) => violations,
    };

    if let Some(max) = bounds.displayed_shielded_outputs {
        if plan.displayed_shielded_outputs > max {
            out.push(LimitViolation::TooManyDisplayedShieldedOutputs {
                got: plan.displayed_shielded_outputs,
                max,
                exact: plan.displayed_count_is_exact(),
            });
        }
    }

    // Not version-gated: every firmware that has the PCZT parser at all has the
    // single-change rule, and it is not a budget that a newer app raised.
    //
    // The transparent half needs no key: a transparent output is change to the
    // device exactly when it carries a `bip32_derivation` — the one the shaping
    // pass stamps, or one the PCZT arrived with, which shaping leaves in place.
    // The shielded half is countable only with the account's viewing keys,
    // which are what turn a shielded output into "change" rather than "a
    // payment"; without them it contributes nothing and is reported as
    // uncounted, so a transaction with two transparent change outputs is still
    // refused here rather than mid-stream.
    let transparent = plan
        .stream
        .transparent_outputs
        .iter()
        .filter(|o| o.derivation.is_some())
        .count();
    let shielded = plan.shielded_change_outputs;
    let got = shielded.unwrap_or(0) + transparent;
    if got > 1 {
        out.push(LimitViolation::MultipleChangeOutputs { got, shielded });
    }

    if out.is_empty() {
        Ok(())
    } else {
        Err(out)
    }
}

/// Checks a plan against what the connected app version supports.
pub fn validate_against_caps(
    plan: &StreamPlan,
    caps: &DeviceCaps,
) -> Result<(), Vec<LimitViolation>> {
    let mut out = Vec::new();
    if !caps.pczt {
        out.push(LimitViolation::PcztUnsupported {
            version: caps.version,
            required: MIN_VERSION_PCZT,
        });
    }
    if plan.is_v6() && !caps.ironwood {
        out.push(LimitViolation::IronwoodUnsupported {
            version: caps.version,
            required: MIN_VERSION_IRONWOOD,
        });
    }
    if out.is_empty() {
        Ok(())
    } else {
        Err(out)
    }
}
