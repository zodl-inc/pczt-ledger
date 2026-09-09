//! PCZT → [`StreamPlan`] mapping.
//!
//! Every field the device sees is read through the `pczt` crate's **Verifier**
//! role (`pczt::roles::verifier::Verifier`), which hands out the fully-typed
//! protocol bundles (`orchard::pczt::Bundle`, `transparent::pczt::Bundle`).
//! Nothing here touches PCZT bytes: the crate charter forbids hand-rolled PCZT
//! parsing, and the typed bundles are also the only place several fields have
//! accessors at all.
//!
//! The mapping mirrors `crates/zcash-crypto/src/parse.rs` in
//! `LedgerHQ/ledger-zcash-utils` (`parse_pczt`), which is the host contract the
//! device was developed against; deviations from it are called out in the item
//! docs below.
//!
//! # Where each field comes from
//!
//! - **Global** — `Pczt::global()` getters, plus a serde read for the three
//!   fields the `pczt` crate keeps without one (see [`GlobalFields`]).
//! - **Transparent** — the *wire* bundle (`Pczt::transparent()`) for
//!   `prevout_txid`, `prevout_index`, `sequence`, `value` and `script_pubkey`,
//!   which all have public getters and are already in exactly the device's
//!   representation; the Verifier's parsed bundle for `sighash_type`,
//!   `bip32_derivation` and the BIP 370 lock-time requirements, which have
//!   none.
//! - **Orchard / Ironwood** — entirely from the Verifier's parsed bundle: the
//!   wire type exposes no getter for `recipient`, `value`, `rho`, `rseed`,
//!   `alpha` or `zip32_derivation`.

use std::collections::BTreeMap;

use ff::PrimeField;
use pczt::{
    roles::verifier::{OrchardError, TransparentError, Verifier},
    Pczt,
};

use crate::apdu::encode::{
    BundleTrailerRecord, DerivationPath, ShieldedActionRecord, StreamPlan, TransparentDerivation,
    TransparentInputRecord, TransparentOutputRecord, Zip32Derivation, ENC_CIPHERTEXT_SIZE,
    NOTE_VERSION_IRONWOOD, ORCHARD_RAW_ADDRESS_SIZE, OUT_CIPHERTEXT_SIZE, PCZT_VERSION_V5,
    PCZT_VERSION_V6,
};
use crate::limits::{
    Section, V5_TX_VERSION, V5_VERSION_GROUP_ID, V6_TX_VERSION, V6_VERSION_GROUP_ID,
};

/// The `common::Global` fields the `PCZT_HEADER` record needs.
///
/// `tx_version`, `version_group_id`, `consensus_branch_id` and `expiry_height`
/// have `#[getset(get = "pub")]` accessors. `coin_type`, `fallback_lock_time`
/// and `tx_modifiable` do not — they are `pub(crate)` with no getter in
/// `pczt::common::Global` — so they are read from the serde representation, the
/// route `ledger-zcash-utils`' `parse_global` takes for exactly these three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalFields {
    /// `tx_version` — 5 or 6.
    pub tx_version: u32,
    /// `version_group_id`.
    pub version_group_id: u32,
    /// `consensus_branch_id`.
    pub consensus_branch_id: u32,
    /// `fallback_lock_time`, mirrored verbatim — see [`build_plan`] for why
    /// that is only sound when no transparent input imposes a lock time.
    pub fallback_lock_time: Option<u32>,
    /// `expiry_height`.
    pub expiry_height: u32,
    /// SLIP 44 coin type (133 mainnet, 1 testnet).
    pub coin_type: u32,
    /// `tx_modifiable` flags byte.
    pub tx_modifiable: u8,
}

/// The three `Global` fields without getters, named as serde sees them.
///
/// Every field is required, `fallback_lock_time` included: `pczt` serializes
/// an absent lock time as an explicit `null`, so a missing key can only mean
/// the field was renamed or restructured upstream. That must fail here rather
/// than read as `None`, because the device applies
/// `locktime = fallback_lock_time.unwrap_or_default()` to whatever the header
/// says, and a silently defaulted `None` would have it sign against a lock
/// time of 0 while the host finalizes with the real one.
///
/// serde's derive treats a missing `Option` field as `None` on its own, so the
/// requirement has to be spelled out: naming a `deserialize_with` function
/// turns a missing key into a `missing field` error while `null` still reads
/// as `None`.
#[derive(serde::Deserialize)]
struct GlobalSerdeView {
    coin_type: u32,
    #[serde(deserialize_with = "Option::deserialize")]
    fallback_lock_time: Option<u32>,
    tx_modifiable: u8,
}

/// A PCZT this crate cannot turn into a device stream.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlanError {
    /// A `Global` field could not be read through serde.
    GlobalUnreadable(String),
    /// `tx_version` / `version_group_id` are not a V5 or V6 pair.
    UnsupportedTxVersion {
        /// The transaction version.
        tx_version: u32,
        /// The version group id.
        version_group_id: u32,
    },
    /// The transparent bundle failed to parse.
    TransparentParse(String),
    /// The Orchard bundle failed to parse.
    OrchardParse(String),
    /// The Ironwood bundle failed to parse.
    IronwoodParse(String),
    /// A field the wire record needs is absent from the PCZT.
    MissingField {
        /// Which section.
        section: Section,
        /// Index within that section.
        index: usize,
        /// The PCZT field name.
        field: &'static str,
    },
    /// A transparent input does not carry exactly one `bip32_derivation`
    /// entry. The device reads the signing key locator from that entry alone
    /// (`PCZT_SIGN_TRANSPARENT` carries no path), so zero entries make the
    /// input unsignable and more than one is unrepresentable on the wire.
    TransparentDerivationCount {
        /// Index of the input.
        index: usize,
        /// Number of entries found.
        got: usize,
    },
    /// A transparent output carries more than one `bip32_derivation` entry;
    /// the wire format has a slot for zero or one.
    OutputDerivationCount {
        /// Index of the output.
        index: usize,
        /// Number of entries found.
        got: usize,
    },
    /// A transparent input requires a lock time.
    ///
    /// The device does not run the BIP 370 lock-time determination: the
    /// per-input `required_time_lock_time` / `required_height_lock_time` fields
    /// are not part of the compact APDU subset, and `parse_global` assigns
    /// `locktime = fallback_lock_time.unwrap_or_default()` outright. A PCZT
    /// whose inputs impose a lock time would therefore be signed against a
    /// different `nLockTime` than the host computes, so it is refused rather
    /// than silently mis-signed.
    TransparentLockTimeRequired {
        /// Index of the input.
        index: usize,
    },
    /// A non-empty shielded bundle whose wire `anchor` is absent.
    ///
    /// [ZIP 374] lets a v6 PCZT defer its anchors to proving time, and the
    /// `pczt` parser then substitutes the empty-tree placeholder. Streaming
    /// that placeholder would hand the device an anchor the transaction does
    /// not use, so an absent anchor is refused here.
    ///
    /// [ZIP 374]: https://zips.z.cash/zip-0374
    MissingAnchor {
        /// Which pool.
        section: Section,
    },
    /// The device's dummy-spend rule and the host's needs-a-signature rule
    /// disagree about this action.
    ///
    /// The device treats `spend_value == 0` as a dummy and refuses to sign it
    /// (`"PCZT orchard dummy spend must not be signed by the device"`), while
    /// the host-side finaliser treats "`spend_auth_sig` is absent" as needing a
    /// device signature. The two agree exactly when the IO Finalizer self-signed
    /// every zero-valued spend. They diverge for
    ///
    /// - a real spend of a zero-valued note, and
    /// - the wallet-controlled zero-value spends the post-NU6.3 Orchard builder
    ///   pairs with change outputs under the cross-address restriction,
    ///
    /// both of which leave a `spend_auth_sig` the device will never produce.
    /// Detecting it here fails closed before the first APDU instead of at the
    /// end of the ceremony.
    SpendClassificationMismatch {
        /// Which pool.
        section: Section,
        /// Index of the action.
        index: usize,
        /// The action's `spend_value`.
        spend_value: u64,
        /// Whether the action already carries a `spend_auth_sig`.
        already_signed: bool,
    },
    /// A shielded bundle's `value_sum` does not fit in the `i64` the wire
    /// trailer carries.
    ValueSumOutOfRange {
        /// Which pool.
        section: Section,
    },
    /// A bundle's flags are not representable under its own `BundleVersion`.
    /// Cannot happen for a bundle the `orchard` crate parsed, but the
    /// conversion is fallible upstream.
    FlagsNotRepresentable {
        /// Which pool.
        section: Section,
    },
    /// An Ironwood bundle whose note-plaintext version is not V3, which the
    /// device rejects with `"Bad PCZT ironwood notePlaintextVersion"`.
    UnexpectedNoteVersion {
        /// Which pool.
        section: Section,
    },
    /// A V5 transaction whose Ironwood bundle carries actions.
    ///
    /// The Ironwood pool exists only from V6, so a V5 stream never sends
    /// `PCZT_IRONWOOD_ACTION` and the device never sees the bundle: its
    /// actions would be invisible to both the on-device review and the
    /// device's signatures. This is the hazard class
    /// [`crate::session::LedgerViolation::SaplingPresent`] refuses for the
    /// Sapling pool, and the same predicate `Pczt::has_data_in_pool` applies.
    IronwoodOnV5 {
        /// Actions in the Ironwood bundle.
        actions: usize,
    },
}

impl core::fmt::Display for PlanError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PlanError::GlobalUnreadable(message) => {
                write!(f, "the PCZT's global fields could not be read: {message}")
            }
            PlanError::UnsupportedTxVersion {
                tx_version,
                version_group_id,
            } => write!(
                f,
                "tx_version {tx_version} with version_group_id {version_group_id:#010x} is \
                 neither the V5 nor the V6 pair the device accepts"
            ),
            PlanError::TransparentParse(message) => {
                write!(f, "the transparent bundle failed to parse: {message}")
            }
            PlanError::OrchardParse(message) => {
                write!(f, "the Orchard bundle failed to parse: {message}")
            }
            PlanError::IronwoodParse(message) => {
                write!(f, "the Ironwood bundle failed to parse: {message}")
            }
            PlanError::MissingField {
                section,
                index,
                field,
            } => write!(
                f,
                "{section} {index} is missing the `{field}` field the wire record needs"
            ),
            PlanError::TransparentDerivationCount { index, got } => write!(
                f,
                "transparent input {index} carries {got} bip32_derivation entries; the device \
                 reads the signing-key locator from exactly one"
            ),
            PlanError::OutputDerivationCount { index, got } => write!(
                f,
                "transparent output {index} carries {got} bip32_derivation entries; the wire \
                 format has a slot for zero or one"
            ),
            PlanError::TransparentLockTimeRequired { index } => write!(
                f,
                "transparent input {index} requires a lock time, which the device's compact APDU \
                 subset does not carry; signing would commit to a different nLockTime than the \
                 host computes"
            ),
            PlanError::MissingAnchor { section } => write!(
                f,
                "the {section} bundle is non-empty but its anchor is deferred (absent); \
                 streaming the parser's empty-tree placeholder would hand the device an anchor \
                 the transaction does not use"
            ),
            PlanError::SpendClassificationMismatch {
                section,
                index,
                spend_value,
                already_signed,
            } => write!(
                f,
                "{section} {index} (spend_value {spend_value}, spend_auth_sig {}) is classified \
                 differently by the device's dummy rule (value == 0) and the host's \
                 needs-a-signature rule (signature absent); the two signing loops would count \
                 different sets",
                if *already_signed { "present" } else { "absent" },
            ),
            PlanError::ValueSumOutOfRange { section } => write!(
                f,
                "the {section} bundle's value_sum does not fit in the i64 the wire trailer \
                 carries"
            ),
            PlanError::FlagsNotRepresentable { section } => write!(
                f,
                "the {section} bundle's flags are not representable under its own BundleVersion"
            ),
            PlanError::UnexpectedNoteVersion { section } => write!(
                f,
                "the {section} bundle's note-plaintext version is not V3, which the device \
                 rejects"
            ),
            PlanError::IronwoodOnV5 { actions } => write!(
                f,
                "a V5 transaction carries {actions} Ironwood action(s); the Ironwood pool exists \
                 only from V6, so a V5 stream never sends them and they would be invisible to \
                 both the on-device review and the device's signatures"
            ),
        }
    }
}

impl std::error::Error for PlanError {}

/// A [`StreamPlan`] plus the bookkeeping the session layer needs on top of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The records to stream, in wire order.
    pub stream: StreamPlan,
    /// The `Global` fields the header was built from.
    pub global: GlobalFields,
    /// Indices of Orchard actions the device will sign, ascending. Dummies are
    /// excluded: the device refuses them and counts its signing loop over this
    /// set only.
    pub orchard_real_spends: Vec<usize>,
    /// The same for the Ironwood bundle.
    pub ironwood_real_spends: Vec<usize>,
    /// How many shielded outputs the device will put on its review screen,
    /// counted across *both* pools — the quantity
    /// `MAX_PCZT_SHIELDED_DISPLAYED_OUTPUTS_NUMBER` bounds on v3.9.3 and later
    /// (`claim_displayed_shielded_output` in `src/parser/pczt.rs` @
    /// `22dc385`).
    ///
    /// # The device's rule
    ///
    /// The device runs a decryption trial per action
    /// (`try_decipher_current_orchard_output`, `src/parser/pczt/orchard.rs`,
    /// and its Ironwood twin), in this order:
    ///
    /// 1. the output opens under the account's **internal IVK** → it is change:
    ///    kept off the review, and it claims no slot;
    /// 2. else it opens under the account's **external OVK** → it is displayed
    ///    and claims a slot;
    /// 3. else it must be a zero-valued dummy whose `cmx` re-derives
    ///    (`validate_current_orchard_dummy_output`) → not shown, no slot;
    /// 4. else the device refuses the transaction outright, with
    ///    `"PCZT orchard output could not be decrypted"`.
    ///
    /// # What this field holds
    ///
    /// **With the account's viewing keys** — a
    /// [`AccountViewingKeys`](crate::viewing::AccountViewingKeys) passed to
    /// [`build_plan_with_keys`] — this is the device's own count. An output is
    /// counted iff its recipient is not one of the account's internal-scope
    /// addresses (step 1, reproduced exactly by
    /// [`AccountViewingKeys::is_internal_recipient`](crate::viewing::AccountViewingKeys::is_internal_recipient))
    /// *and* either its value is nonzero or it opens under the account's
    /// external OVK (step 2, reproduced by
    /// [`AccountViewingKeys::recovers_output`](crate::viewing::AccountViewingKeys::recovers_output)).
    /// The OVK trial matters for zero-valued outputs alone: the device runs it
    /// *before* the dummy check, so a memo-only output the wallet encrypted
    /// under the account's own OVK takes a slot even though its value is zero,
    /// while a padding dummy — encrypted under a throwaway key — does not. A
    /// nonzero output is counted without the trial, which is the fail-closed
    /// direction; see below for why.
    ///
    /// **Without them** this is a bound the host can only take over the
    /// *nonzero* outputs: every one of them is counted, change included, and
    /// no zero-valued output is. It over-counts once a wallet splits its
    /// change — a note-management policy targeting four change notes turns a
    /// one-recipient send into five nonzero outputs, counted here as five
    /// against a budget of four while the device counts one — and it
    /// *under*-counts a zero-valued output the account's OVK opens, which the
    /// device displays and the host cannot recognise without the key. The
    /// second gap cannot be closed blind: nothing in the PCZT plaintext tells
    /// such an output from a padding dummy, and counting every zero-valued
    /// output would refuse every padded bundle. A caller that wants the
    /// budget checked exactly supplies the keys.
    ///
    /// [`Plan::displayed_count_is_exact`] says which of the two a given plan
    /// carries, and [`crate::limits::LimitViolation::TooManyDisplayedShieldedOutputs`]
    /// reports it.
    ///
    /// # Why step 4 is not pre-flighted
    ///
    /// A nonzero output that opens under neither key is refused by the device
    /// mid-stream, and the host *could* mirror that by trial-recovering each
    /// nonzero output under the external OVK. It deliberately does not:
    ///
    /// - Not checking is safe. Such an output is counted as displayed here,
    ///   which is the fail-closed direction: the host either refuses it for the
    ///   budget or streams it and the device refuses it. Nothing is signed
    ///   either way.
    /// - Checking is not. A host-side recovery that failed where the device's
    ///   succeeds would refuse a transaction the device would have accepted —
    ///   the one failure mode this whole pre-flight exists to avoid.
    /// - There is nothing to catch. The output is built by the wallet that owns
    ///   this account, from the account's own OVK; an output that opens under
    ///   neither key means the PCZT was not built for this account at all,
    ///   which the session's account binding check already refuses on the
    ///   spend side.
    ///
    /// The zero-valued case runs the trial because there the divergence risk
    /// points the other way: a recovery that failed on the host where the
    /// device's succeeds would leave the count short, which is the mid-stream
    /// `NotEnoughMemorySpace` refusal this count exists to pull forward, while
    /// a recovery that succeeded where the device's fails can only over-count.
    pub displayed_shielded_outputs: usize,
    /// How many shielded outputs, across both pools, open under the account's
    /// **internal** scope — the device's `is_change` outputs.
    ///
    /// `None` when [`build_plan`] was given no viewing keys, which is also what
    /// makes [`Self::displayed_shielded_outputs`] an upper bound rather than
    /// the device's count.
    ///
    /// The device tolerates **at most one** change output in a transaction,
    /// across the shielded pools and the transparent one together
    /// (`is_change_found` in `TxInfo`, reset when the transparent output count
    /// arrives and set by every pool's change branch; a second one is
    /// `"Multiple change outputs detected"`). That is checked in
    /// [`crate::limits::validate_plan`], which is the only place that can see
    /// the transparent half as well.
    pub shielded_change_outputs: Option<usize>,
    /// Actions whose `zip32_derivation` was absent and was replaced by a
    /// placeholder so the plan could still be built for validation.
    ///
    /// A plan built after [`crate::shape`] has run must have this empty; the
    /// session layer asserts that.
    pub missing_zip32: Vec<(Section, usize)>,
}

impl Plan {
    /// Whether the plan describes a V6 transaction.
    pub fn is_v6(&self) -> bool {
        self.stream.is_v6()
    }

    /// Whether [`Self::displayed_shielded_outputs`] is the device's own count
    /// (`true`) or an upper bound on it (`false`).
    ///
    /// It is exact exactly when the plan was built with the account's viewing
    /// keys; see that field's docs.
    pub fn displayed_count_is_exact(&self) -> bool {
        self.shielded_change_outputs.is_some()
    }
}

/// Reads the `common::Global` fields.
///
/// See [`GlobalFields`] for why three of them go through serde.
pub fn read_global(pczt: &Pczt) -> Result<GlobalFields, PlanError> {
    let global = pczt.global();

    let value = serde_json::to_value(global)
        .map_err(|e| PlanError::GlobalUnreadable(format!("serialize: {e}")))?;
    let view: GlobalSerdeView = serde_json::from_value(value)
        .map_err(|e| PlanError::GlobalUnreadable(format!("deserialize: {e}")))?;

    Ok(GlobalFields {
        tx_version: *global.tx_version(),
        version_group_id: *global.version_group_id(),
        consensus_branch_id: *global.consensus_branch_id(),
        fallback_lock_time: view.fallback_lock_time,
        expiry_height: *global.expiry_height(),
        coin_type: view.coin_type,
        tx_modifiable: view.tx_modifiable,
    })
}

/// Whether these global fields describe a V6 (Ironwood-carrying) transaction.
///
/// Mirrors `parse_global` in the device's `src/parser/pczt/common.rs`, which
/// accepts only these two `(tx_version, version_group_id)` pairs.
pub fn is_v6_transaction(global: &GlobalFields) -> Result<bool, PlanError> {
    match (global.tx_version, global.version_group_id) {
        (V5_TX_VERSION, V5_VERSION_GROUP_ID) => Ok(false),
        (V6_TX_VERSION, V6_VERSION_GROUP_ID) => Ok(true),
        (tx_version, version_group_id) => Err(PlanError::UnsupportedTxVersion {
            tx_version,
            version_group_id,
        }),
    }
}

/// The PCZT wire-format revision the device requires for this transaction
/// version: `1` for V5, `2` for V6.
pub const fn pczt_version_for(is_v6: bool) -> u32 {
    if is_v6 {
        PCZT_VERSION_V6
    } else {
        PCZT_VERSION_V5
    }
}

/// Maps a PCZT onto the device's wire records.
///
/// # `fallback_lock_time`
///
/// The field is mirrored verbatim, as `ledger-zcash-utils`' `parse_global`
/// does. That is only equivalent to the BIP 370 determination when no
/// transparent input imposes a lock time, because the device applies
/// `locktime = fallback_lock_time.unwrap_or_default()` directly and never sees
/// the per-input requirements. [`PlanError::TransparentLockTimeRequired`]
/// enforces the precondition rather than leaving it implicit.
///
/// # `sequence`
///
/// Also mirrored verbatim (`Option<u32>`, `None` meaning the device's
/// `DEFAULT_SEQUENCE`), matching both the PCZT field and the host contract.
///
/// # Missing `zip32_derivation`
///
/// An action without one gets a placeholder (zeroed fingerprint, empty path)
/// and is recorded in [`Plan::missing_zip32`], so that a plan can be built for
/// validation *before* [`crate::shape`] stamps the real paths. A plan whose
/// `missing_zip32` is non-empty must never be streamed: the device rejects an
/// action with no path.
pub fn build_plan(pczt: &Pczt) -> Result<Plan, PlanError> {
    build_plan_with_keys(pczt, None)
}

/// [`build_plan`], with the account's shielded viewing keys.
///
/// The keys are used for one thing: classifying each shielded output as change
/// or as displayed, the way the device does. With them,
/// [`Plan::displayed_shielded_outputs`] is the device's own count and
/// [`Plan::shielded_change_outputs`] is populated; without them the first is an
/// upper bound and the second is `None`. Everything else about the plan is
/// identical, so a caller with no key loses nothing but precision.
pub fn build_plan_with_keys(
    pczt: &Pczt,
    keys: Option<&crate::viewing::AccountViewingKeys>,
) -> Result<Plan, PlanError> {
    let global = read_global(pczt)?;
    let is_v6 = is_v6_transaction(&global)?;

    // The Ironwood section is parsed only for V6 below, so a V5 PCZT that
    // carries Ironwood actions has to be refused here rather than silently
    // planned without them. `validate_records`' "V6 iff Ironwood" check cannot
    // catch it: it compares against `stream.ironwood_actions`, which a V5 plan
    // leaves `None` by construction.
    if !is_v6 {
        let actions = pczt.ironwood().actions().len();
        if actions != 0 {
            return Err(PlanError::IronwoodOnV5 { actions });
        }
    }

    let header = crate::apdu::encode::HeaderRecord {
        pczt_version: pczt_version_for(is_v6),
        tx_version: global.tx_version,
        version_group_id: global.version_group_id,
        consensus_branch_id: global.consensus_branch_id,
        fallback_lock_time: global.fallback_lock_time,
        expiry_height: global.expiry_height,
        coin_type: global.coin_type,
        tx_modifiable: global.tx_modifiable,
    };

    // Wire-side transparent fields, which are already in the device's
    // representation and need no parse.
    let wire_inputs = pczt.transparent().inputs();
    let wire_outputs = pczt.transparent().outputs();

    // Anchors are read from the wire bundle so that a *deferred* (absent)
    // anchor is distinguishable from a real one: the parser substitutes the
    // empty-tree placeholder for an absent anchor, and the parsed bundle then
    // cannot tell the two apart.
    let wire_orchard_anchor = *pczt.orchard().anchor();
    let wire_ironwood_anchor = *pczt.ironwood().anchor();

    let mut transparent_inputs = Vec::with_capacity(wire_inputs.len());
    let mut transparent_outputs = Vec::with_capacity(wire_outputs.len());
    let mut orchard = BundleRecords::default();
    let mut ironwood = BundleRecords::default();

    // The Verifier consumes the PCZT and lends the parsed bundles inside a
    // closure, so the conversions write into the slots above.
    let verifier = Verifier::new(pczt.clone())
        .with_transparent::<PlanError, _>(|bundle| {
            for (index, input) in bundle.inputs().iter().enumerate() {
                if input.required_time_lock_time().is_some()
                    || input.required_height_lock_time().is_some()
                {
                    return Err(TransparentError::Custom(
                        PlanError::TransparentLockTimeRequired { index },
                    ));
                }

                let wire = wire_inputs.get(index).ok_or_else(|| {
                    TransparentError::Custom(PlanError::TransparentParse(format!(
                        "input {index} is missing from the wire bundle"
                    )))
                })?;
                let derivation = sole_derivation(input.bip32_derivation()).ok_or(
                    TransparentError::Custom(PlanError::TransparentDerivationCount {
                        index,
                        got: input.bip32_derivation().len(),
                    }),
                )?;

                transparent_inputs.push(TransparentInputRecord {
                    prevout_txid: *wire.prevout_txid(),
                    prevout_index: *wire.prevout_index(),
                    sequence: *wire.sequence(),
                    value: *wire.value(),
                    script_pubkey: wire.script_pubkey().clone(),
                    sighash_type: input.sighash_type().encode(),
                    derivation,
                });
            }

            for (index, output) in bundle.outputs().iter().enumerate() {
                let wire = wire_outputs.get(index).ok_or_else(|| {
                    TransparentError::Custom(PlanError::TransparentParse(format!(
                        "output {index} is missing from the wire bundle"
                    )))
                })?;
                let derivation = match output.bip32_derivation().len() {
                    0 => None,
                    1 => Some(sole_derivation(output.bip32_derivation()).expect("len == 1")),
                    got => {
                        return Err(TransparentError::Custom(PlanError::OutputDerivationCount {
                            index,
                            got,
                        }))
                    }
                };

                transparent_outputs.push(TransparentOutputRecord {
                    value: *wire.value(),
                    script_pubkey: wire.script_pubkey().clone(),
                    derivation,
                });
            }

            Ok(())
        })
        .map_err(|e| match e {
            TransparentError::Custom(inner) => inner,
            other => PlanError::TransparentParse(format!("{other:?}")),
        })?;

    let verifier = verifier
        .with_orchard::<PlanError, _>(|bundle| {
            orchard = convert_bundle(Section::Orchard, bundle, wire_orchard_anchor, keys)
                .map_err(OrchardError::Custom)?;
            Ok(())
        })
        .map_err(|e| match e {
            OrchardError::Custom(inner) => inner,
            other => PlanError::OrchardParse(format!("{other:?}")),
        })?;

    // The Ironwood pool exists only from V6; below that the section is the
    // canonical empty bundle and parsing it would be meaningless work.
    if is_v6 {
        verifier
            .with_ironwood::<PlanError, _>(|bundle| {
                ironwood = convert_bundle(Section::Ironwood, bundle, wire_ironwood_anchor, keys)
                    .map_err(OrchardError::Custom)?;
                Ok(())
            })
            .map_err(|e| match e {
                OrchardError::Custom(inner) => inner,
                other => PlanError::IronwoodParse(format!("{other:?}")),
            })?;
    }

    let mut missing_zip32 = orchard.missing_zip32.clone();
    missing_zip32.extend(ironwood.missing_zip32.iter().copied());

    let stream = StreamPlan {
        header,
        transparent_inputs,
        transparent_outputs,
        orchard_actions: orchard.actions,
        orchard_trailer: orchard.trailer,
        ironwood_actions: is_v6.then_some(ironwood.actions),
        ironwood_trailer: ironwood.trailer,
    };

    Ok(Plan {
        stream,
        global,
        orchard_real_spends: orchard.real_spends,
        ironwood_real_spends: ironwood.real_spends,
        // Across both pools: the device's budget is one counter shared by them
        // (`claim_displayed_shielded_output` takes `TxInfo`, not a per-pool
        // slot, "for the same reason the memo rendering is: Ironwood repeats
        // Orchard's note format, so a per-pool copy of a budget is a budget
        // that comes apart").
        displayed_shielded_outputs: orchard.displayed_outputs + ironwood.displayed_outputs,
        shielded_change_outputs: keys.map(|_| orchard.change_outputs + ironwood.change_outputs),
        missing_zip32,
    })
}

/// One converted shielded bundle.
#[derive(Debug, Default)]
struct BundleRecords {
    actions: Vec<ShieldedActionRecord>,
    trailer: Option<BundleTrailerRecord>,
    real_spends: Vec<usize>,
    /// Outputs of this bundle the device will display. See
    /// [`Plan::displayed_shielded_outputs`] for the rule and its fallback.
    displayed_outputs: usize,
    /// Outputs of this bundle addressed to the account's internal scope. Zero
    /// when no viewing keys were supplied, in which case the caller discards
    /// it rather than reporting it as a count.
    change_outputs: usize,
    missing_zip32: Vec<(Section, usize)>,
}

/// Extracts the single `bip32_derivation` entry of a transparent input or
/// output, or `None` if the map does not hold exactly one.
fn sole_derivation(
    map: &BTreeMap<[u8; 33], zcash_transparent::pczt::Bip32Derivation>,
) -> Option<TransparentDerivation> {
    if map.len() != 1 {
        return None;
    }
    let (pubkey, derivation) = map.iter().next().expect("len == 1");
    Some(TransparentDerivation {
        pubkey: *pubkey,
        seed_fingerprint: *derivation.seed_fingerprint(),
        path: DerivationPath(
            derivation
                .derivation_path()
                .iter()
                .copied()
                .map(u32::from)
                .collect(),
        ),
    })
}

/// Converts one parsed Orchard-protocol bundle into wire records.
fn convert_bundle(
    section: Section,
    bundle: &orchard::pczt::Bundle,
    wire_anchor: Option<[u8; 32]>,
    keys: Option<&crate::viewing::AccountViewingKeys>,
) -> Result<BundleRecords, PlanError> {
    let mut out = BundleRecords::default();

    // Sized up front: the records are wiped on drop, but a `Vec` that grows
    // moves them and leaves the old buffer behind unwiped.
    out.actions.reserve_exact(bundle.actions().len());

    if bundle.actions().is_empty() {
        // An empty bundle carries no trailer: `docs/PCZT_APDU.md`, "Bundle
        // trailer packet, only when the action count is greater than 0".
        return Ok(out);
    }

    // Every action in a bundle carries the bundle's own note version (the
    // `orchard` parser rejects a disagreement), so the bundle version is the
    // authoritative source for the Ironwood lead byte rather than a constant at
    // the call site.
    let note_version = bundle.bundle_version().note_version();
    let note_plaintext_version = match section {
        // `parse_orchard_output_metadata` accepts only the 115-byte packet, so
        // an Orchard action must not carry the byte at all.
        Section::Orchard => None,
        Section::Ironwood => {
            if note_version != orchard::note::NoteVersion::V3 {
                return Err(PlanError::UnexpectedNoteVersion { section });
            }
            // Emit the 116-byte form explicitly. The 115-byte form means the
            // same thing (the device's per-action reset leaves the field at
            // 0x03), but the host contract
            // (`ledger-zcash-utils::parse::ParsedIronwoodAction`) always carries
            // the byte, so emitting it keeps a capture diff against that
            // implementation byte-for-byte comparable.
            Some(NOTE_VERSION_IRONWOOD)
        }
        _ => None,
    };

    for (index, action) in bundle.actions().iter().enumerate() {
        let spend = action.spend();
        let output = action.output();

        let missing = |field| PlanError::MissingField {
            section,
            index,
            field,
        };

        let spend_recipient: [u8; ORCHARD_RAW_ADDRESS_SIZE] = spend
            .recipient()
            .map(|r| r.to_raw_address_bytes())
            .ok_or_else(|| missing("spend.recipient"))?;
        let spend_value = spend
            .value()
            .map(|v| v.inner())
            .ok_or_else(|| missing("spend.value"))?;
        let spend_rho = spend
            .rho()
            .map(|r| r.to_bytes())
            .ok_or_else(|| missing("spend.rho"))?;
        let spend_rseed = spend
            .rseed()
            .map(|r| *r.as_bytes())
            .ok_or_else(|| missing("spend.rseed"))?;
        let alpha = spend
            .alpha()
            .map(|a| a.to_repr())
            .ok_or_else(|| missing("spend.alpha"))?;

        let zip32_derivation = match spend.zip32_derivation().as_ref() {
            Some(d) => Zip32Derivation {
                seed_fingerprint: *d.seed_fingerprint(),
                path: DerivationPath(d.derivation_path().iter().map(|c| c.index()).collect()),
            },
            None => {
                out.missing_zip32.push((section, index));
                Zip32Derivation {
                    seed_fingerprint: [0u8; 32],
                    path: DerivationPath(Vec::new()),
                }
            }
        };

        let recipient_address = output
            .recipient()
            .ok_or_else(|| missing("output.recipient"))?;
        let recipient: [u8; ORCHARD_RAW_ADDRESS_SIZE] = recipient_address.to_raw_address_bytes();
        let value = output
            .value()
            .map(|v| v.inner())
            .ok_or_else(|| missing("output.value"))?;
        let rseed = output
            .rseed()
            .map(|r| *r.as_bytes())
            .ok_or_else(|| missing("output.rseed"))?;
        let rcv = action
            .rcv()
            .as_ref()
            .map(|r| r.to_bytes())
            .ok_or_else(|| missing("rcv"))?;

        let note = output.encrypted_note();
        debug_assert_eq!(note.enc_ciphertext.len(), ENC_CIPHERTEXT_SIZE);
        debug_assert_eq!(note.out_ciphertext.len(), OUT_CIPHERTEXT_SIZE);

        // The device's rule (`is_real_spend = spend_value != 0`,
        // `src/parser/pczt/orchard.rs`) and the host's rule (an action needs a
        // device signature iff its `spend_auth_sig` is absent) must agree, or
        // the signing loops would count different sets.
        let already_signed = spend.spend_auth_sig().is_some();
        let device_would_sign = spend_value != 0;
        if device_would_sign == already_signed {
            return Err(PlanError::SpendClassificationMismatch {
                section,
                index,
                spend_value,
                already_signed,
            });
        }
        if device_would_sign {
            out.real_spends.push(index);
        }

        // The review-budget count. `value` is the *output's* value, not the
        // spend's: it is the output that gets a screen.
        //
        // The device's order is: internal IVK (change, no screen) → external
        // OVK (displayed) → zero-valued dummy (no screen).
        // `is_internal_recipient` reproduces the change branch exactly. A
        // nonzero output is then displayed without asking (a nonzero output
        // that opens under neither key is one the device refuses outright, and
        // counting it is the safe direction); a zero-valued one is displayed
        // iff the external OVK opens it, which is what tells a memo-only
        // output from a padding dummy. See [`Plan::displayed_shielded_outputs`]
        // for the reasoning, and for what this count means when `keys` is
        // `None`.
        let is_change = keys.is_some_and(|k| k.is_internal_recipient(&recipient_address));
        if is_change {
            out.change_outputs += 1;
        }
        let displayed = value != 0 || keys.is_some_and(|k| k.recovers_output(note_version, action));
        if displayed && !is_change {
            out.displayed_outputs += 1;
        }

        out.actions.push(ShieldedActionRecord {
            cv_net: action.cv_net().to_bytes(),
            nullifier: spend.nullifier().to_bytes(),
            rk: spend.rk().into(),
            spend_recipient,
            spend_value,
            spend_rho,
            spend_rseed,
            alpha,
            zip32_derivation,
            cmx: output.cmx().to_bytes(),
            ephemeral_key: note.epk_bytes,
            enc_ciphertext: note.enc_ciphertext.to_vec(),
            out_ciphertext: note.out_ciphertext.to_vec(),
            recipient,
            value,
            rseed,
            rcv,
            note_plaintext_version,
        });
    }

    let anchor = wire_anchor.ok_or(PlanError::MissingAnchor { section })?;

    let (magnitude, sign) = bundle.value_sum().magnitude_sign();
    let value_sum = i64::try_from(magnitude)
        .map(|m| {
            if matches!(sign, orchard::value::Sign::Negative) {
                -m
            } else {
                m
            }
        })
        .map_err(|_| PlanError::ValueSumOutOfRange { section })?;

    out.trailer = Some(BundleTrailerRecord {
        flags: bundle
            .flags()
            .to_byte(*bundle.bundle_version())
            .ok_or(PlanError::FlagsNotRepresentable { section })?,
        value_sum,
        anchor,
    });

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::GlobalSerdeView;

    /// The serde view is strict: a `null` lock time is `None`, a number is
    /// `Some`, and a *missing* key is an error rather than a default.
    #[test]
    fn the_global_view_requires_every_field() {
        let present: GlobalSerdeView = serde_json::from_value(serde_json::json!({
            "coin_type": 133,
            "fallback_lock_time": null,
            "tx_modifiable": 0,
        }))
        .expect("an explicit null is how pczt writes an absent lock time");
        assert_eq!(present.fallback_lock_time, None);

        let set: GlobalSerdeView = serde_json::from_value(serde_json::json!({
            "coin_type": 133,
            "fallback_lock_time": 7,
            "tx_modifiable": 0,
        }))
        .expect("a number is a lock time");
        assert_eq!(set.fallback_lock_time, Some(7));

        // A renamed or dropped field must not read as `None`.
        assert!(
            serde_json::from_value::<GlobalSerdeView>(serde_json::json!({
                "coin_type": 133,
                "tx_modifiable": 0,
            }))
            .is_err()
        );
    }
}
