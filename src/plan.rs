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
//! - **Global** — `Pczt::global()` getters (see [`GlobalFields`]).
//! - **Transparent** — the *wire* bundle (`Pczt::transparent()`) for
//!   `prevout_txid`, `prevout_index`, `sequence`, `value` and `script_pubkey`,
//!   which all have public getters and are already in exactly the device's
//!   representation; the Verifier's parsed bundle for `sighash_type`,
//!   `bip32_derivation` and the BIP 370 lock-time requirements, which have
//!   none.
//! - **Orchard / Ironwood** — entirely from the Verifier's parsed bundle: the
//!   wire type exposes no getter for `recipient`, `value`, `rho`, `rseed`,
//!   `alpha` or `zip32_derivation`.

use alloc::{collections::BTreeMap, format, string::String, vec::Vec};

use ff::PrimeField;
use orchard::{
    bundle::BundleVersion,
    pczt::{UnsupportedBundleVersion, VerifyError},
};
use pczt::{
    roles::verifier::{OrchardError, TransparentError, Verifier},
    Pczt,
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, OrchardProtocolRevision},
    value::Zatoshis,
};

use crate::apdu::encode::{
    BundleTrailerRecord, DerivationPath, ShieldedActionRecord, StreamPlan, TransparentDerivation,
    TransparentInputRecord, TransparentOutputRecord, TxFormat, Zip32Derivation,
    NOTE_VERSION_IRONWOOD, ORCHARD_RAW_ADDRESS_SIZE, SEED_FINGERPRINT_SIZE,
};
use crate::limits::{
    hash160, p2pkh_hash, validate_records, DeviceBounds, LimitViolation, Section,
    MEMO_HASH_DISPLAY_LEN, V5_TX_VERSION, V5_VERSION_GROUP_ID, V6_TX_VERSION, V6_VERSION_GROUP_ID,
};

/// The `common::Global` fields the `PCZT_HEADER` record needs.
///
/// Each is read through `pczt::common::Global`'s own accessor; see
/// [`read_global`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalFields {
    /// `tx_version` — 5 or 6.
    pub(crate) tx_version: u32,
    /// `version_group_id`.
    pub(crate) version_group_id: u32,
    /// `consensus_branch_id`, already a branch the protocol crate knows.
    pub(crate) consensus_branch_id: BranchId,
    /// `fallback_lock_time`, mirrored verbatim — see [`build_plan`] for why
    /// that is only sound when no transparent input imposes a lock time.
    pub(crate) fallback_lock_time: Option<u32>,
    /// `expiry_height`.
    pub(crate) expiry_height: BlockHeight,
    /// SLIP 44 coin type (133 mainnet, 1 testnet).
    pub(crate) coin_type: u32,
    /// `tx_modifiable` flags byte.
    pub(crate) tx_modifiable: u8,
}

impl GlobalFields {
    /// `tx_version` — 5 or 6.
    pub fn tx_version(&self) -> u32 {
        self.tx_version
    }

    /// `version_group_id`.
    pub fn version_group_id(&self) -> u32 {
        self.version_group_id
    }

    /// The consensus branch the transaction is built for.
    pub fn consensus_branch_id(&self) -> BranchId {
        self.consensus_branch_id
    }

    /// `fallback_lock_time`, mirrored verbatim.
    pub fn fallback_lock_time(&self) -> Option<u32> {
        self.fallback_lock_time
    }

    /// `expiry_height`.
    pub fn expiry_height(&self) -> BlockHeight {
        self.expiry_height
    }

    /// SLIP 44 coin type (133 mainnet, 1 testnet).
    pub fn coin_type(&self) -> u32 {
        self.coin_type
    }

    /// The `tx_modifiable` flags byte.
    pub fn tx_modifiable(&self) -> u8 {
        self.tx_modifiable
    }

    /// The transaction format these fields describe.
    ///
    /// Mirrors `parse_global` in the device's `src/parser/pczt/common.rs`,
    /// which accepts only the two `(tx_version, version_group_id)` pairs
    /// [`TxFormat`] names; anything else is
    /// [`PlanError::UnsupportedTxVersion`].
    ///
    /// # Errors
    ///
    /// [`PlanError::UnsupportedTxVersion`] when the transaction version and
    /// version group id are neither V5's nor V6's.
    pub fn format(&self) -> Result<TxFormat, PlanError> {
        match (self.tx_version, self.version_group_id) {
            (V5_TX_VERSION, V5_VERSION_GROUP_ID) => Ok(TxFormat::V5),
            (V6_TX_VERSION, V6_VERSION_GROUP_ID) => Ok(TxFormat::V6),
            (tx_version, version_group_id) => Err(PlanError::UnsupportedTxVersion {
                tx_version,
                version_group_id,
            }),
        }
    }
}

/// A PCZT this crate cannot turn into a device stream.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlanError {
    /// `tx_version` / `version_group_id` are not a V5 or V6 pair.
    UnsupportedTxVersion {
        /// The transaction version.
        tx_version: u32,
        /// The version group id.
        version_group_id: u32,
    },
    /// `consensus_branch_id` is not a branch the pinned `zcash_protocol`
    /// knows.
    ///
    /// The device refuses it at the header (`BranchId::try_from` in
    /// `parse_global`, `src/parser/pczt/common.rs` @ `22dc385`) and the `pczt`
    /// extractor refuses it in the return path (`UnknownConsensusBranchId`);
    /// the two accepted sets are identical at the current pins.
    UnknownBranchId {
        /// The value in the PCZT.
        got: u32,
    },
    /// `consensus_branch_id` names a network upgrade the v5 and v6 transaction
    /// formats predate (Sprout through Canopy), under which the `pczt`
    /// extractor can produce no transaction (`UnsupportedConsensusBranchId`).
    BranchIdPredatesV5 {
        /// The value in the PCZT.
        got: u32,
    },
    /// A V6 transaction tagged with a branch whose Orchard protocol revision
    /// is below V3 — NU5 through NU6.2 — although the v6 format exists only
    /// from NU6.3.
    ///
    /// Nothing before the return path notices: the host's version check reads
    /// only the `(tx_version, version_group_id)` pair, the `pczt` Verifier
    /// accepts any branch from NU5 on, and the device accepts whatever
    /// `BranchId::try_from` accepts and uses it only in its digest
    /// personalization. The user would review and approve, the device would
    /// sign, and `Pczt::extract_tx_data` would then refuse the result with
    /// `UnsupportedConsensusBranchId`. The `pczt` Creator never builds such a
    /// PCZT; the edit is five bytes of the serialized `Global`.
    BranchIdVersionMismatch {
        /// The value in the PCZT.
        got: u32,
        /// The transaction version it was paired with.
        tx_version: u32,
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
    /// A transparent input carries a `redeem_script`.
    ///
    /// The field belongs to a P2SH coin, and the only input this app signs
    /// for is P2PKH ([`crate::limits::LimitViolation::NonP2pkhInputScript`]);
    /// `zcash_transparent`'s own `Input::verify` refuses the combination as
    /// `NotP2sh`. It matters before that: the `pczt` Signer role keys an
    /// input's script code off `redeem_script.unwrap_or(script_pubkey)`
    /// (`append_signature`, `zcash_transparent` 0.10), so with the field set
    /// it looks the pubkey up under the redeem script's hash, finds no
    /// preimage, and refuses the device's signature — after the user has
    /// reviewed and approved the transaction and the device has signed the
    /// P2PKH digest, which the field does not change. No honest builder sets
    /// it on a P2PKH input; a hand-built or Combiner-modified PCZT can.
    RedeemScriptPresent {
        /// Index of the input.
        index: usize,
    },
    /// A non-empty shielded bundle whose wire `anchor` is absent.
    ///
    /// [ZIP 374] lets a V6 PCZT defer its anchors to proving time — the
    /// `SignerView::Compact` shape — and the `pczt` parser then substitutes
    /// the empty-tree placeholder. The bundle trailer the device reads
    /// carries the anchor and has no encoding for an absent one, so the only
    /// thing this crate could stream is the placeholder: an anchor the
    /// transaction does not carry. It is refused instead; the input to this
    /// crate is the `SignerView::Full` redaction, which keeps the anchor.
    /// (The V6 sighash does not commit to the anchor, so this is a matter of
    /// not sending the device invented data, not of a wrong digest.)
    ///
    /// On V5 the `pczt` parser refuses an absent anchor before this runs, as
    /// [`PlanError::OrchardParse`].
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
    ///
    /// The unsigned zero-valued spend is the shape the post-NU6.3 builder
    /// emits for Orchard change (cross-address transfers are disabled at
    /// `orchard_v3`, so change is paired with a wallet-controlled zero-value
    /// spend the device will never sign): a transaction of that shape cannot
    /// be signed on this device at all.
    ///
    /// The action's value is deliberately not carried: it is a shielded
    /// amount, and an error is what a wallet logs.
    SpendClassificationMismatch {
        /// Which pool.
        section: Section,
        /// Index of the action.
        index: usize,
        /// Whether the action already carries a `spend_auth_sig`. `false`
        /// means an unsigned zero-valued spend; `true` a signed real one.
        already_signed: bool,
    },
    /// A spend still carries its `dummy_sk`.
    ///
    /// [ZIP 374]: "Signers MUST reject PCZTs that contain `dummy_sk` values".
    /// The IO Finalizer signs a dummy spend with its `dummy_sk` and clears
    /// the field; a PCZT that reaches a signer with one present has not been
    /// finalized, and is refused before the first APDU.
    ///
    /// [ZIP 374]: https://zips.z.cash/zip-0374
    DummySpendingKeyPresent {
        /// Which pool.
        section: Section,
        /// Index of the action.
        index: usize,
    },
    /// A real spend carries no `fvk`.
    ///
    /// `Signer::apply_orchard_spend_auth_signature` (`pczt` 0.9.3) checks the
    /// spend's nullifier against its note components before it stores the
    /// device's signature, and tolerates only the four `Missing*` errors a
    /// compact view leaves behind; a missing `fvk` is not among them. Nothing
    /// on the wire needs the field, so a PCZT without it streams, is reviewed
    /// and approved, and fails in [`crate::apply`] afterwards. That is exactly
    /// what `zcash_client_backend::redact_pczt_for_batch_signer` produces — it
    /// clears the field by design — and why the input to this crate is the
    /// `SignerView::Full` redaction, which keeps it.
    MissingSpendFvk {
        /// Which pool.
        section: Section,
        /// Index of the action.
        index: usize,
    },
    /// An action's components do not agree with each other in a way the
    /// device, the `pczt` Signer role or the prover refuses.
    ///
    /// `check` names the field: `alpha` (zero, so `rk` would be the
    /// unrandomized `ak`), `cv_net` (not the commitment to the two values
    /// under `rcv`), `nullifier` (a real spend's note fields do not produce
    /// it under its `fvk`), `rk` (not `ak` randomized by `alpha`), or `cmx`
    /// (the output's recipient, value and `rseed` do not commit to it). The
    /// device runs the `cv_net`, `nullifier` and `rk` checks with its own key
    /// mid-stream and the `cmx` check for zero-valued outputs only; the
    /// Signer role runs the nullifier check before it stores a signature; the
    /// prover builds the output note from the declared `rseed` and fails on a
    /// `cmx` it does not commit to. Each is run here first, so that an opaque
    /// device refusal, or a failure after the review, is a named host error.
    ActionInconsistent {
        /// Which pool.
        section: Section,
        /// Index of the action.
        index: usize,
        /// Which check failed.
        check: &'static str,
        /// The `orchard` verifier's own error.
        error: String,
    },
    /// A real spend's `fvk` is not the caller's viewing key.
    ///
    /// The keys passed to [`build_plan_with_keys`] decide which outputs count
    /// as change and which the device will display; a key for another
    /// account would silently disable both accountings while the plan still
    /// reported its counts as exact, and the device — deriving its own key
    /// from the action's path — would refuse mid-stream. `orchard`'s
    /// `verify_nullifier` and `verify_rk` check the spend's `fvk` against the
    /// supplied key for every real spend, which is what binds the key to the
    /// PCZT.
    ViewingKeyMismatch {
        /// Which pool.
        section: Section,
        /// Index of the action.
        index: usize,
    },
    /// A shielded bundle whose version selects no note encryption domain, so
    /// the account's viewing keys cannot be applied to its outputs at all.
    ///
    /// Which domain an output was encrypted under is a property of its
    /// bundle — the value pool paired with the protocol version — and
    /// `orchard` owns that mapping ([`UnsupportedBundleVersion`]).
    /// For a pair it has no domain for, neither of the two trials
    /// [`Plan::displayed_shielded_outputs`] reproduces can be run, so the
    /// output is not classifiable as change, as displayed or as a dummy.
    ///
    /// Reading that as "the keys did not open it" would count every output of
    /// such a bundle as displayed and none as change: the host asserting an
    /// exact count for a bundle class it cannot interpret, against a device
    /// that would classify it some other way. It is refused before the first
    /// APDU instead. Without keys no trial is attempted at all, and the
    /// value-only count applies as it does for any bundle.
    ///
    /// No constructor of [`BundleVersion`] produces such a pair today, so no
    /// PCZT reaches this; it exists because
    /// a future pairing of variants `orchard` already has would change no
    /// enum and so break no exhaustive match upstream.
    UnsupportedBundleVersion {
        /// Which pool.
        section: Section,
        /// Index of the action.
        index: usize,
        /// The bundle version that has no note encryption domain.
        bundle_version: BundleVersion,
    },
    /// A nonzero shielded output that opens under neither of the account's
    /// keys, which the device refuses mid-stream with `"PCZT orchard output
    /// could not be decrypted"`.
    ///
    /// The device's trial order is internal IVK (change), then external OVK
    /// (displayed), then the zero-value dummy check; a nonzero output that
    /// fails the first two has nowhere to go. With the account's viewing keys
    /// the host runs the same two trials, so this is exactly the device's
    /// refusal pulled forward. It reaches every nonzero output the wallet did
    /// not encrypt under the account's own external OVK — `OvkPolicy::Discard`,
    /// which leaves no recoverable `out_ciphertext` (`ovk: None`), and
    /// `OvkPolicy::Custom` under any other key — and a PCZT built for another
    /// account whose spends do not name a key, a transparent-to-shielded
    /// transaction, which the spend-side binding cannot catch. Without keys
    /// the host cannot tell, and streams it. See
    /// [`Plan::displayed_shielded_outputs`], "Which outgoing viewing keys an
    /// account can use".
    UndecryptableOutput {
        /// Which pool.
        section: Section,
        /// Index of the action.
        index: usize,
    },
    /// A note value above `MAX_MONEY`, which the device refuses at the
    /// action's value packet (`read_orchard_value` goes through
    /// `Zatoshis::from_nonnegative_i64_le_bytes`) and `orchard::value::NoteValue`
    /// does not bound.
    ValueOutOfRange {
        /// Which pool.
        section: Section,
        /// Index of the action.
        index: usize,
        /// Which value.
        field: &'static str,
    },
    /// A shielded bundle's `value_sum` is not the sum of its spend values
    /// less the sum of its output values, which the device checks at the
    /// trailer (`finish_orchard_value_sum_sign`) and refuses mid-stream.
    ValueSumMismatch {
        /// Which pool.
        section: Section,
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
    /// An action's output pays a receiver other than its spent note's, in a
    /// bundle whose flags disable cross-address transfers.
    ///
    /// The Orchard pool's post-NU6.3 rule: a V6 transaction's Orchard bundle
    /// is `orchard_v3`, whose flags have no cross-address bit, so every
    /// action — padding included — must pay the receiver of the note it
    /// spends. `orchard` requires a signer to check it before signing
    /// (`Bundle::verify_cross_address_restriction`); the `pczt` Signer role
    /// does not, and the firmware reads the flags byte only to echo it
    /// (`parse_orchard_trailer`, `src/parser/pczt/orchard.rs` @ `22dc385`)
    /// and never compares the two receivers. Left unchecked, the whole
    /// transaction is streamed, reviewed, approved and signed, and refused
    /// by the IO Finalizer or the prover afterwards
    /// (`DisallowedCrossAddressTransfer`): a burnt approval for a condition
    /// the host could decide before the first APDU.
    CrossAddressTransferDisallowed {
        /// Which pool.
        section: Section,
    },
    /// The PCZT carries Sapling spends or outputs.
    ///
    /// The app has no PCZT Sapling command at all — the compact APDU subset
    /// covers transparent, Orchard and Ironwood only — so a Sapling bundle
    /// would be dropped from everything the user reviews and the device
    /// signs, and the signatures would commit to a sighash the finalized
    /// transaction does not have. The guard lives here rather than only in
    /// [`crate::session::validate_for_ledger`] so that
    /// [`build_plan`] cannot be used to plan such a transaction at all.
    SaplingPresent,
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
            PlanError::UnsupportedTxVersion {
                tx_version,
                version_group_id,
            } => write!(
                f,
                "tx_version {tx_version} with version_group_id {version_group_id:#010x} is \
                 neither the V5 nor the V6 pair the device accepts"
            ),
            PlanError::UnknownBranchId { got } => write!(
                f,
                "consensus branch id {got:#010x} is not a network upgrade this crate knows; the \
                 device refuses it at the header and the PCZT extractor in the return path"
            ),
            PlanError::BranchIdPredatesV5 { got } => write!(
                f,
                "consensus branch id {got:#010x} names a network upgrade the v5 and v6 \
                 transaction formats predate; no transaction can be extracted under it"
            ),
            PlanError::BranchIdVersionMismatch { got, tx_version } => write!(
                f,
                "a v{tx_version} transaction is tagged with consensus branch id {got:#010x}, \
                 whose Orchard protocol revision is below the one the v6 format requires \
                 (NU6.3); the device would sign it and the PCZT extractor would then refuse it"
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
            PlanError::RedeemScriptPresent { index } => write!(
                f,
                "transparent input {index} carries a redeem_script, which belongs to a P2SH coin; \
                 the app signs P2PKH inputs only, and the PCZT Signer role would key the script \
                 code off the redeem script and refuse the signature after the review"
            ),
            PlanError::MissingAnchor { section } => write!(
                f,
                "the {section} bundle is non-empty but its anchor is deferred (absent); the \
                 wire trailer has no encoding for an absent anchor, and this crate takes the \
                 SignerView::Full redaction, which keeps it"
            ),
            PlanError::SpendClassificationMismatch {
                section,
                index,
                already_signed: false,
            } => write!(
                f,
                "{section} {index} is a zero-valued spend with no spend_auth_sig: the device \
                 takes it for a dummy and will not sign it, and the host has nothing else to \
                 sign it with. This is the shape the post-NU6.3 builder gives Orchard change, \
                 and a transaction of that shape cannot be signed on this device"
            ),
            PlanError::SpendClassificationMismatch {
                section,
                index,
                already_signed: true,
            } => write!(
                f,
                "{section} {index} is a real spend that already carries a spend_auth_sig; \
                 the device would sign it again on request and the host would not ask, so the \
                 two signing loops would count different sets"
            ),
            PlanError::DummySpendingKeyPresent { section, index } => write!(
                f,
                "{section} {index} still carries its dummy_sk; ZIP 374 requires a signer to \
                 refuse it, and a PCZT with one has not been through the IO Finalizer"
            ),
            PlanError::MissingSpendFvk { section, index } => write!(
                f,
                "{section} {index} is a real spend with no `fvk`; the PCZT Signer role needs it \
                 to accept the device's signature, so the failure would land only after the \
                 review. Redact the PCZT with `SignerView::Full`; the batch-signer view clears \
                 the field"
            ),
            PlanError::ActionInconsistent {
                section,
                index,
                check,
                error,
            } => write!(
                f,
                "{section} {index} fails the {check} consistency check ({error}); the PCZT \
                 Signer role would refuse the device's signature after the review"
            ),
            PlanError::ViewingKeyMismatch { section, index } => write!(
                f,
                "{section} {index}'s `fvk` is not the viewing key supplied for this account; \
                 the PCZT was built for another account, or the wrong key was supplied"
            ),
            PlanError::UnsupportedBundleVersion {
                section,
                index,
                bundle_version,
            } => write!(
                f,
                "no note encryption domain is defined for the {section} bundle's {:?} value pool \
                 under protocol version {:?}, so neither of the decryption trials that classify \
                 {section} {index}'s output can be run; the host cannot reproduce the device's \
                 review of such a bundle and refuses before the first APDU",
                bundle_version.value_pool(),
                bundle_version.protocol_version()
            ),
            PlanError::UndecryptableOutput { section, index } => write!(
                f,
                "{section} {index} is a nonzero output that opens under neither the account's \
                 internal incoming viewing key nor its external outgoing viewing key; the \
                 device refuses it mid-stream as an output it cannot decrypt"
            ),
            PlanError::ValueOutOfRange {
                section,
                index,
                field,
            } => write!(
                f,
                "{section} {index}'s {field} is above MAX_MONEY, which the device refuses at \
                 the value packet"
            ),
            PlanError::ValueSumMismatch { section } => write!(
                f,
                "the {section} bundle's value_sum is not the sum of its spend values less the \
                 sum of its output values, which the device refuses at the trailer"
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
            PlanError::CrossAddressTransferDisallowed { section } => write!(
                f,
                "the {section} bundle pays an output to a receiver other than its spent note's, \
                 and the bundle's flags disable cross-address transfers; the device would sign \
                 it and the IO Finalizer or the prover would then refuse it"
            ),
            PlanError::SaplingPresent => write!(
                f,
                "the PCZT carries Sapling spends or outputs, and the app has no PCZT Sapling \
                 command: a Sapling bundle would be invisible to both the on-device review and \
                 the device's signatures"
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

impl core::error::Error for PlanError {}

/// How the device renders one displayed shielded output's memo, which is
/// what its memo retention budget is counted over.
///
/// Mirrors `memo_display` in `src/parser/pczt.rs` @ `1a0f649`, which
/// classifies memos as `22dc385` did. The budget
/// itself is applied in [`validate_plan`], in stream order,
/// because whether a text memo is kept as text depends on what the earlier
/// outputs retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoDisplay {
    /// An empty memo — `0xF6` followed by zeros, or all zeros — retains
    /// nothing.
    Empty,
    /// A memo the device shows as text when the text fits what is left of the
    /// budget: its tag byte is at most `0xF4` and the bytes up to the last
    /// nonzero one are printable ASCII. It then retains that many bytes; past
    /// the budget it is rendered as its hash instead.
    Text(usize),
    /// Any other memo is rendered as its hash and retains
    /// [`crate::limits::MEMO_HASH_DISPLAY_LEN`] bytes.
    Hashed,
}

/// The largest memo tag byte that marks a text memo (ZIP 302).
const MEMO_TEXT_MAX_TAG: u8 = 0xF4;

/// The tag byte of an empty memo (ZIP 302).
const MEMO_EMPTY_TAG: u8 = 0xF6;

/// Classifies a memo the way the device's `memo_display` does.
pub(crate) fn memo_display(memo: &[u8; crate::viewing::MEMO_SIZE]) -> MemoDisplay {
    if memo[0] == MEMO_EMPTY_TAG && memo[1..].iter().all(|byte| *byte == 0) {
        return MemoDisplay::Empty;
    }
    let Some(len) = memo
        .iter()
        .rposition(|byte| *byte != 0)
        .map(|index| index + 1)
    else {
        return MemoDisplay::Empty;
    };
    // Printable ASCII is valid UTF-8, so the firmware's `from_utf8` step is
    // implied by its `is_displayable_memo_text`.
    let printable = memo[..len].iter().all(|byte| (0x20..=0x7E).contains(byte));
    if memo[0] <= MEMO_TEXT_MAX_TAG && printable {
        MemoDisplay::Text(len)
    } else {
        MemoDisplay::Hashed
    }
}

/// A [`StreamPlan`] plus the bookkeeping the session layer needs on top of it.
///
/// # Seed fingerprints are not sent
///
/// Every derivation record on the wire carries zeros where the PCZT carries
/// the wallet's ZIP 32 seed fingerprint: the fingerprint is a stable
/// identifier of the seed, with no business crossing the device link — a BLE
/// link in particular — on every transaction. Withholding it costs nothing,
/// because the pinned firmware reads the field out of every derivation and
/// only logs it, in the transparent, Orchard and Ironwood parsers alike
/// (`src/parser/pczt/transparent.rs`, `orchard.rs` and `ironwood.rs` @
/// `22dc385`). The PCZT itself is not touched: [`crate::shape`] keeps the real fingerprint on every derivation
/// it stamps, so the PCZT a wallet gets back is attributable. A firmware that
/// starts checking the field moves the pin; the crate docs list it among the
/// things a pin move re-checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The records to stream, in wire order.
    pub(crate) stream: StreamPlan,
    /// The `Global` fields the header was built from.
    pub(crate) global: GlobalFields,
    /// Indices of Orchard actions the device will sign, ascending. Dummies are
    /// excluded: the device refuses them and counts its signing loop over this
    /// set only.
    pub(crate) orchard_real_spends: Vec<usize>,
    /// The same for the Ironwood bundle.
    pub(crate) ironwood_real_spends: Vec<usize>,
    /// How many shielded outputs the device will put on its review screen,
    /// counted across *both* pools — the quantity
    /// `MAX_PCZT_SHIELDED_DISPLAYED_OUTPUTS_NUMBER` bounds on v3.9.3 and later
    /// (`claim_displayed_shielded_output` in `src/parser/pczt.rs` @
    /// `22dc385`), and [`crate::limits::DeviceBounds`] bounds on every
    /// version.
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
    /// # Which outgoing viewing keys an account can use
    ///
    /// Both trials run under keys the device derives from its own account
    /// key, and only those: `OrchardDecipherKeys::from_fvk`
    /// (`src/parser/orchard_decipher.rs` @ `22dc385`) holds the internal IVK
    /// and the external OVK, and there is no third trial. So an output whose
    /// `out_ciphertext` does not open under the account's **external** OVK
    /// falls to step 3, and a nonzero one is refused there at step 4. In the
    /// terms a wallet builds transactions with, `OvkPolicy::Sender` is the
    /// only policy a Ledger account can use: under `OvkPolicy::Discard` there
    /// is no recoverable `out_ciphertext` at all, and `OvkPolicy::Custom` is
    /// refused unless the key it names is the account's own external OVK.
    /// Change is unaffected — step 1 is an IVK trial, which no outgoing
    /// viewing key takes part in — so what the refusal reaches is exactly the
    /// nonzero outputs that are not change.
    ///
    /// # What this field holds
    ///
    /// **With the account's viewing keys** — a
    /// [`AccountViewingKeys`](crate::viewing::AccountViewingKeys) passed to
    /// [`build_plan_with_keys`] — this is the device's own count. An output is
    /// counted iff it does not open under the account's internal IVK (step 1,
    /// reproduced by
    /// [`AccountViewingKeys::opens_as_change`](crate::viewing::AccountViewingKeys::opens_as_change))
    /// *and* either its value is nonzero or it opens under the account's
    /// external OVK (step 2, reproduced by
    /// [`AccountViewingKeys::recover_output`](crate::viewing::AccountViewingKeys::recover_output)).
    /// The OVK trial matters for zero-valued outputs alone: the device runs it
    /// *before* the dummy check, so a memo-only output the wallet encrypted
    /// under the account's own OVK takes a slot even though its value is zero,
    /// while a padding dummy — encrypted under a throwaway key — does not. A
    /// nonzero output is counted without the trial, which is the fail-closed
    /// direction; see below for why.
    ///
    /// **Without them** this is the count of the *nonzero* outputs, change
    /// included, and no zero-valued output is counted. It is neither an upper
    /// bound on the device's count nor a lower one. It over-counts once a
    /// wallet splits its change — a note-management policy targeting four
    /// change notes turns a one-recipient send into five nonzero outputs,
    /// counted here as five against a budget of four while the device counts
    /// one — and it *under*-counts a zero-valued output the account's OVK
    /// opens, which the device displays and the host cannot recognise without
    /// the key: four recipients plus one such output pass a budget of four
    /// here and are refused at the fifth slot on the device. The second gap
    /// cannot be closed blind: nothing in the PCZT plaintext tells such an
    /// output from a padding dummy, and counting every zero-valued output
    /// would refuse every padded bundle. A caller that wants the budget
    /// checked exactly supplies the keys.
    ///
    /// [`Plan::displayed_count_is_exact`] says which of the two a given plan
    /// carries, and [`crate::limits::LimitViolation::TooManyDisplayedShieldedOutputs`]
    /// reports it.
    ///
    /// # Step 4, with keys
    ///
    /// A nonzero output that opens under neither key is refused by the device
    /// mid-stream, and with the account's keys the host refuses it first
    /// ([`PlanError::UndecryptableOutput`]): the two trials it runs are the
    /// device's own, under the device's own key, on the same bytes, so the
    /// refusal is exact. Such an output is a note built with no outgoing
    /// viewing key, a PCZT built for another account whose spends name no key
    /// at all, or an output addressed to one of the account's own internal
    /// addresses whose ciphertext does not open — which the device does not
    /// take for change either. Without keys the output is counted as
    /// displayed, which is the fail-closed direction: the host either refuses
    /// it for the budget or streams it and the device refuses it. Nothing is
    /// signed either way.
    pub(crate) displayed_shielded_outputs: usize,
    /// How many shielded outputs, across both pools, open under the account's
    /// **internal** scope — the device's `is_change` outputs.
    ///
    /// `None` when [`build_plan`] was given no viewing keys, which is also what
    /// leaves [`Self::displayed_shielded_outputs`] a count over the nonzero
    /// outputs rather than the device's own.
    ///
    /// The device limits the change outputs in a transaction, across the
    /// shielded pools and the transparent one together
    /// ([`crate::limits::DeviceBounds::change_outputs`], one on every known
    /// version). That is checked in [`validate_plan`], which is the only place
    /// that can see the transparent half as well.
    pub(crate) shielded_change_outputs: Option<usize>,
    /// The memo of every displayed shielded output, classified the way the
    /// device's `memo_display` classifies it, in the order the device meets
    /// them — every Orchard action, then every Ironwood one.
    ///
    /// `None` when [`build_plan`] was given no viewing keys: the memos are
    /// recovered under the account's external OVK, so without the key the
    /// device is the first to count them against its retention budget
    /// ([`crate::limits::DeviceBounds::retained_memo_bytes`]).
    pub(crate) displayed_memos: Option<Vec<(Section, usize, MemoDisplay)>>,
    /// Actions whose `zip32_derivation` was absent and was replaced by a
    /// placeholder so the plan could still be built for validation.
    ///
    /// A plan built after [`crate::shape`] has run must have this empty; the
    /// session layer asserts that.
    pub(crate) missing_zip32: Vec<(Section, usize)>,
}

impl Plan {
    /// The wire records, in stream order.
    pub fn stream(&self) -> &StreamPlan {
        &self.stream
    }

    /// The header fields the plan was built from.
    pub fn global(&self) -> &GlobalFields {
        &self.global
    }

    /// Indices of the Orchard actions the device is asked to sign.
    pub fn orchard_real_spends(&self) -> &[usize] {
        &self.orchard_real_spends
    }

    /// Indices of the Ironwood actions the device is asked to sign.
    pub fn ironwood_real_spends(&self) -> &[usize] {
        &self.ironwood_real_spends
    }

    /// The actions that carried no `zip32_derivation`, as `(section, index)`.
    pub fn missing_zip32(&self) -> &[(Section, usize)] {
        &self.missing_zip32
    }

    /// How many shielded outputs the device will put on its screen, or, for a
    /// plan built without viewing keys, how many nonzero shielded outputs the
    /// transaction has — a count the device's own can be above or below; see
    /// the field's docs and [`Plan::displayed_count_is_exact`].
    pub fn displayed_shielded_outputs(&self) -> usize {
        self.displayed_shielded_outputs
    }

    /// How many shielded outputs the account's viewing keys recognise as
    /// change, or `None` when the plan was built without them.
    pub fn shielded_change_outputs(&self) -> Option<usize> {
        self.shielded_change_outputs
    }

    /// The memo each displayed output shows, in stream order, or `None` when
    /// the plan was built without the viewing keys that reveal them.
    pub fn displayed_memos(&self) -> Option<&[(Section, usize, MemoDisplay)]> {
        self.displayed_memos.as_deref()
    }

    /// The transaction format the plan streams.
    pub fn format(&self) -> TxFormat {
        self.stream.format()
    }

    /// Whether [`Self::displayed_shielded_outputs`] is the device's own count
    /// (`true`) or the count of the nonzero outputs (`false`), which the
    /// device's can exceed as well as fall short of.
    ///
    /// It is exact exactly when the plan was built with the account's viewing
    /// keys; see that field's docs.
    pub fn displayed_count_is_exact(&self) -> bool {
        self.shielded_change_outputs.is_some()
    }
}

/// Reads the `common::Global` fields.
///
/// Every field is taken through `pczt::common::Global`'s own accessor; see
/// [`PlanError::UnknownBranchId`] for the one conversion applied here.
///
/// # Errors
///
/// [`PlanError::UnknownBranchId`] when `consensus_branch_id` is not a branch
/// this crate's `zcash_protocol` knows.
pub fn read_global(pczt: &Pczt) -> Result<GlobalFields, PlanError> {
    let global = pczt.global();

    let got = *global.consensus_branch_id();
    let consensus_branch_id =
        BranchId::try_from(got).map_err(|_| PlanError::UnknownBranchId { got })?;

    Ok(GlobalFields {
        tx_version: *global.tx_version(),
        version_group_id: *global.version_group_id(),
        consensus_branch_id,
        fallback_lock_time: *global.fallback_lock_time(),
        expiry_height: BlockHeight::from_u32(*global.expiry_height()),
        coin_type: *global.coin_type(),
        tx_modifiable: *global.tx_modifiable(),
    })
}

/// [`validate_records`] plus the checks that need the whole [`Plan`]
/// rather than only its wire records.
///
/// Those are: the shielded displayed-output budget, which is counted from the
/// PCZT (see [`Plan::displayed_shielded_outputs`]) and has no representation
/// in the [`crate::apdu::encode::StreamPlan`] the device is sent; the memo
/// retention budget and, on an app before v3.9.4, any memo the review would
/// hash, for a plan built with viewing keys; a review with no output on it,
/// likewise with keys; the device's
/// change-output limit, whose
/// shielded half is likewise counted from the PCZT and whose transparent half
/// is read off the records; and the unmarked twin of a change output, which
/// the device would display as a third-party recipient.
///
/// # Errors
///
/// `Err` with every violation [`validate_records`] finds plus, from the whole
/// plan, [`LimitViolation::TooManyDisplayedShieldedOutputs`],
/// [`LimitViolation::MemoRetentionBudgetExceeded`],
/// [`LimitViolation::HashedMemoUnsupported`],
/// [`LimitViolation::NoReviewableOutputs`],
/// [`LimitViolation::TooManyChangeOutputs`] and
/// [`LimitViolation::UnmarkedChangeOutput`].
pub fn validate_plan(plan: &Plan, bounds: &DeviceBounds) -> Result<(), Vec<LimitViolation>> {
    let mut out = match validate_records(&plan.stream, bounds) {
        Ok(()) => Vec::new(),
        Err(violations) => violations,
    };

    let max = bounds.displayed_shielded_outputs;
    if plan.displayed_shielded_outputs > max {
        out.push(LimitViolation::TooManyDisplayedShieldedOutputs {
            got: plan.displayed_shielded_outputs,
            max,
            exact: plan.displayed_count_is_exact(),
        });
    }

    // `memo_display`'s accounting, run over the displayed outputs in the order
    // the device meets them. Only a plan built with the account's viewing keys
    // knows the memos; without them the budget cannot be checked here and the
    // device is the first to see it.
    if let Some(memos) = &plan.displayed_memos {
        let max = bounds.retained_memo_bytes;
        let mut retained = 0usize;
        for &(section, index, memo) in memos {
            let budget = max.saturating_sub(retained);
            match memo {
                MemoDisplay::Empty => {}
                MemoDisplay::Text(len) if len <= budget => retained += len,
                // Text past the budget is shown as its hash, like a hashed memo.
                MemoDisplay::Text(_) | MemoDisplay::Hashed => {
                    if MEMO_HASH_DISPLAY_LEN > budget {
                        out.push(LimitViolation::MemoRetentionBudgetExceeded {
                            section,
                            index,
                            max,
                        });
                        break;
                    }
                    // An app before v3.9.4 hashes it with an uninitialized
                    // context; see `DeviceBounds::hashed_memo_review`.
                    if !bounds.hashed_memo_review {
                        out.push(LimitViolation::HashedMemoUnsupported { section, index });
                    }
                    retained += MEMO_HASH_DISPLAY_LEN;
                }
            }
        }
    }

    // `review_outputs` refuses a review with nothing on it. The device lists
    // every transparent output and every shielded output it opens, change
    // included; with the keys the plan's counts are the device's own, and
    // without them a zero-valued output the OVK opens is invisible, so the
    // check runs only with them. See `LimitViolation::NoReviewableOutputs`.
    if plan.stream.transparent_outputs.is_empty()
        && plan.shielded_change_outputs == Some(0)
        && plan.displayed_shielded_outputs == 0
    {
        out.push(LimitViolation::NoReviewableOutputs);
    }

    // The change-output limit, per app version (`DeviceBounds::change_outputs`).
    //
    // The transparent half needs no key: a transparent output is change to the
    // device exactly when it carries a `bip32_derivation` — the one the shaping
    // pass stamps, or one the PCZT arrived with, which shaping leaves in place
    // (`change_pk_hash` is cleared as every output's script starts, in
    // `parse_transparent_output_script_start` @ `22dc385`).
    // The shielded half is countable only with the account's viewing keys,
    // which are what turn a shielded output into "change" rather than "a
    // payment"; without them it contributes nothing and is reported as
    // uncounted, so a transaction with too many transparent change outputs is
    // still refused here rather than mid-stream.
    let transparent = plan
        .stream
        .transparent_outputs
        .iter()
        .filter(|o| o.derivation.is_some())
        .count();
    let shielded = plan.shielded_change_outputs;
    let got = shielded.unwrap_or(0) + transparent;
    let max = bounds.change_outputs;
    if got > max {
        out.push(LimitViolation::TooManyChangeOutputs { got, max, shielded });
    }

    // The same per-output rule means an unmarked output paying the change
    // address is shown as a payment to a third party; see
    // `LimitViolation::UnmarkedChangeOutput`.
    let outputs = &plan.stream.transparent_outputs;
    for (change, marked) in outputs.iter().enumerate() {
        let Some(derivation) = &marked.derivation else {
            continue;
        };
        let change_hash = hash160(&derivation.pubkey);
        for (index, other) in outputs.iter().enumerate() {
            if other.derivation.is_none() && p2pkh_hash(&other.script_pubkey) == Some(change_hash) {
                out.push(LimitViolation::UnmarkedChangeOutput { change, index });
            }
        }
    }

    if out.is_empty() {
        Ok(())
    } else {
        Err(out)
    }
}

/// Checks `consensus_branch_id` the way `Pczt::extract_tx_data` (`pczt`
/// 0.9.3) checks it in the return path, so that a PCZT the extractor would
/// refuse after the ceremony is refused before the first APDU.
///
/// The extractor's rules, in its order: the id must be a known branch
/// ([`PlanError::UnknownBranchId`], applied by [`read_global`]); that branch
/// must have an Orchard protocol revision, i.e. be NU5 or later
/// ([`PlanError::BranchIdPredatesV5`]); and a V6 transaction requires revision
/// V3 or later, i.e. NU6.3 ([`PlanError::BranchIdVersionMismatch`]). A V5
/// transaction is accepted under any NU5-or-later branch, as the extractor
/// accepts it.
///
/// # Errors
///
/// [`PlanError::BranchIdPredatesV5`] for a branch older than the transaction
/// version's first, and [`PlanError::BranchIdVersionMismatch`] when the branch
/// and the version disagree about which format is current.
pub fn check_branch_id(global: &GlobalFields, format: TxFormat) -> Result<(), PlanError> {
    let got = u32::from(global.consensus_branch_id);
    let revision = global
        .consensus_branch_id
        .orchard_protocol_revision()
        .ok_or(PlanError::BranchIdPredatesV5 { got })?;
    if format == TxFormat::V6 && revision < OrchardProtocolRevision::V3 {
        return Err(PlanError::BranchIdVersionMismatch {
            got,
            tx_version: global.tx_version,
        });
    }
    Ok(())
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
///
/// # Errors
///
/// As [`build_plan_with_keys`].
pub fn build_plan(pczt: &Pczt) -> Result<Plan, PlanError> {
    build_plan_with_keys(pczt, None)
}

/// [`build_plan`], with the account's shielded viewing keys.
///
/// The keys do two things. They classify each shielded output as change or as
/// displayed, the way the device does: with them,
/// [`Plan::displayed_shielded_outputs`] is the device's own count and
/// [`Plan::shielded_change_outputs`] is populated; without them the first is a
/// count over the nonzero outputs, which the device's own can exceed as well
/// as fall short of, and the second is `None`. And they are bound to the PCZT:
/// every real spend's `fvk` must be the supplied key
/// ([`PlanError::ViewingKeyMismatch`]), and its `rk` must be that key's `ak`
/// randomized by the streamed `alpha`, which is the check the device runs with
/// its own key mid-stream. Everything else about the plan is identical, so a
/// caller with no key loses nothing but precision.
///
/// # The shielded bundles
///
/// The wire records are the device's whole view of the transaction, so each
/// Orchard-protocol bundle must arrive complete and self-consistent; the
/// input this crate is written for is the `SignerView::Full` redaction of a
/// PCZT the IO Finalizer has finished with.
///
/// Complete: every action carries its spend's `recipient`, `value`, `rho`,
/// `rseed` and `alpha`, its output's `recipient`, `value` and `rseed`, and the
/// action's own `rcv`; every real spend carries its `fvk`; and a non-empty
/// bundle carries its anchor. `zip32_derivation` is the one field a plan can
/// be built without — see "Missing `zip32_derivation`" on [`build_plan`]. The
/// `Compact` redaction, which drops the `fvk` and the anchors, is not enough.
///
/// Self-consistent: no spend carries a `dummy_sk` or a zero `alpha`;
/// `spend_auth_sig` is present on exactly the zero-valued spends, because the
/// device signs exactly the others; no value exceeds `MAX_MONEY`; and the
/// bundle's `value_sum` is what its actions add up to and fits in an `i64`.
/// Each action's components must agree — `cv_net` with the two values under
/// `rcv`, `cmx` with the output's recipient, value and `rseed`, and a real
/// spend's `rk` and nullifier with its `fvk` — and, where the bundle's flags
/// disable cross-address transfers, every output must pay the receiver of the
/// note its action spends.
///
/// Each of those has a [`PlanError`] of its own, whose docs say what refuses
/// it and when: the host here, the device mid-stream, the `pczt` Signer role
/// in the return path, or the prover.
///
/// # One signer
///
/// Every action is taken to be this account's: the device is asked to sign
/// exactly the real spends that arrive without a `spend_auth_sig`. A PCZT
/// still travelling between signers, whose unsigned real spends are not all
/// this device's, is planned as if the device could produce every one of
/// them, and the device would sign each with the key it derives at that
/// action's own path. Two checks stand in the way: with the account's viewing
/// keys, every real spend's `fvk` must be the supplied key
/// ([`PlanError::ViewingKeyMismatch`]), and [`crate::shape`] refuses a bundle
/// whose actions do not share one account path
/// ([`crate::shape::ShapeError::NonUniformPath`]). Neither reaches a
/// co-signer's action at that same path whose derivation the PCZT does not
/// carry, so a multi-party PCZT has to be split by signer before it gets
/// here.
///
/// # Errors
///
/// Every [`PlanError`]: [`PlanError::SaplingPresent`] for a Sapling bundle;
/// what [`read_global`], [`GlobalFields::format`] and [`check_branch_id`]
/// refuse in the `Global`; [`PlanError::TransparentParse`],
/// [`PlanError::OrchardParse`] and [`PlanError::IronwoodParse`] when an
/// upstream parser refuses a bundle; [`PlanError::IronwoodOnV5`] for Ironwood
/// actions on a V5 transaction; [`PlanError::CrossAddressTransferDisallowed`]
/// for an action of a restricted bundle that pays a receiver other than the
/// one it spends from; per transparent record
/// [`PlanError::TransparentLockTimeRequired`],
/// [`PlanError::RedeemScriptPresent`],
/// [`PlanError::TransparentDerivationCount`] and
/// [`PlanError::OutputDerivationCount`]; and per action a missing field, a
/// value past `MAX_MONEY`, a component that does not agree with the others
/// ([`PlanError::ActionInconsistent`]), a spend that contradicts its
/// classification, a dummy spending key left in place, a missing anchor, a
/// value sum that is not the actions' or does not fit the trailer, and,
/// with keys, a viewing key for another account or an output that opens
/// under neither key.
pub fn build_plan_with_keys(
    pczt: &Pczt,
    keys: Option<&crate::viewing::AccountViewingKeys>,
) -> Result<Plan, PlanError> {
    // No pool this plan cannot carry may hold data: a bundle the stream
    // never sends would be invisible to the review and the signatures alike.
    if pczt.has_data_in_pool(zcash_protocol::PoolType::SAPLING) {
        return Err(PlanError::SaplingPresent);
    }

    let global = read_global(pczt)?;
    let format = global.format()?;
    check_branch_id(&global, format)?;

    // The Ironwood section is parsed only for V6 below, so a V5 PCZT that
    // carries Ironwood actions has to be refused here rather than silently
    // planned without them. `validate_records`' "V6 iff Ironwood" check cannot
    // catch it: it compares against `stream.ironwood_actions`, which a V5 plan
    // leaves `None` by construction.
    if format == TxFormat::V5 {
        let actions = pczt.ironwood().actions().len();
        if actions != 0 {
            return Err(PlanError::IronwoodOnV5 { actions });
        }
    }

    let header = crate::apdu::encode::HeaderRecord {
        pczt_version: format.pczt_version(),
        tx_version: global.tx_version,
        version_group_id: global.version_group_id,
        consensus_branch_id: u32::from(global.consensus_branch_id),
        fallback_lock_time: global.fallback_lock_time,
        expiry_height: u32::from(global.expiry_height),
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
    // The clone copies every `alpha`, `rcv` and `rseed` into `pczt` types
    // that do not zeroize, as does every intermediate bundle the Verifier
    // builds; `Verifier::new` takes ownership and nothing upstream wipes, so
    // the `reserve_exact` discipline below covers this crate's own buffers
    // only.
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

                // A `redeem_script` belongs to a P2SH coin. On the P2PKH
                // inputs this app signs it only redirects the `pczt` Signer's
                // script code, and the signature the user approved fails to
                // apply; refused here rather than at `finish`.
                if input.redeem_script().is_some() {
                    return Err(TransparentError::Custom(PlanError::RedeemScriptPresent {
                        index,
                    }));
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
    if format == TxFormat::V6 {
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

    let mut missing_zip32 = orchard.missing_zip32;
    missing_zip32.extend(ironwood.missing_zip32);

    let stream = StreamPlan {
        header,
        transparent_inputs,
        transparent_outputs,
        orchard_actions: orchard.actions,
        orchard_trailer: orchard.trailer,
        ironwood_actions: (format == TxFormat::V6).then_some(ironwood.actions),
        ironwood_trailer: ironwood.trailer,
    };

    Ok(Plan {
        stream,
        global,
        orchard_real_spends: orchard.real_spends,
        ironwood_real_spends: ironwood.real_spends,
        // Across both pools: the device spends one shared budget, because
        // Ironwood repeats Orchard's note format
        // (`claim_displayed_shielded_output` takes `TxInfo`, not a per-pool
        // slot).
        displayed_shielded_outputs: orchard.displayed_outputs + ironwood.displayed_outputs,
        shielded_change_outputs: keys.map(|_| orchard.change_outputs + ironwood.change_outputs),
        displayed_memos: keys.map(|_| {
            let mut memos = orchard.displayed_memos;
            memos.extend(ironwood.displayed_memos);
            memos
        }),
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
    /// The displayed outputs' memos, classified, in action order. Empty when
    /// no viewing keys were supplied.
    displayed_memos: Vec<(Section, usize, MemoDisplay)>,
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
        // Zeros on the wire; see `Plan`.
        seed_fingerprint: [0u8; SEED_FINGERPRINT_SIZE],
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
///
/// What the bundle must carry for this to succeed is the caller's contract,
/// and is documented as such under "The shielded bundles" in
/// [`build_plan_with_keys`].
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

    // The bundle's value pool and protocol version, read once for the whole
    // bundle: they select the note encryption domain every trial decryption
    // below runs in, and they are what the trailer's flags byte is encoded
    // against. Both are properties of the bundle rather than of an action, so
    // an action is never asked for either.
    let bundle_version = *bundle.bundle_version();

    // Every action's note version is the bundle's: the `pczt` parser assigns
    // `bundle_version().note_version()` into each Spend and Output as it
    // parses them, so there is no per-action wire value that could disagree.
    // The Ironwood lead byte is fixed by the section rather than read from
    // either.
    let note_plaintext_version = match section {
        // `parse_orchard_output_metadata` accepts only the 115-byte packet, so
        // an Orchard action must not carry the byte at all.
        Section::Orchard => None,
        // The `pczt` parser hardcodes `BundleVersion::ironwood_v3()` for this
        // pool, whose note version is V3 by construction, so the lead byte is
        // a constant. Emit the 116-byte form explicitly: the 115-byte form
        // means the same thing — the device's per-action reset leaves the
        // field at 0x03 — but `ledger-zcash-utils::parse::ParsedIronwoodAction`,
        // the host contract the device was developed against, always carries
        // the byte.
        Section::Ironwood => Some(NOTE_VERSION_IRONWOOD),
        Section::TransparentInput | Section::TransparentOutput => None,
    };

    // The post-NU6.3 Orchard rule, run before the per-action checks so that
    // a missing recipient is still reported by name and index below: with
    // cross-address transfers disabled, every action's output must pay the
    // receiver of the note it spends. `orchard` requires a signer to check
    // it; the `pczt` Signer role does not, and the firmware only echoes the
    // flags byte, so nothing between here and the IO Finalizer would.
    match bundle.verify_cross_address_restriction() {
        Ok(()) | Err(VerifyError::MissingRecipient) => {}
        Err(_) => return Err(PlanError::CrossAddressTransferDisallowed { section }),
    }

    // Σ spend values − Σ output values, checked against the trailer below.
    let mut net_value: i128 = 0;

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
        // `rk = ak.randomize(alpha)`: a zero `alpha` puts `ak` itself on
        // chain as `rk`, and the device does not check for it either.
        if alpha == [0u8; 32] {
            return Err(PlanError::ActionInconsistent {
                section,
                index,
                check: "alpha",
                error: "alpha is zero, so rk would be the unrandomized ak".into(),
            });
        }
        if spend.dummy_sk().is_some() {
            return Err(PlanError::DummySpendingKeyPresent { section, index });
        }

        let zip32_derivation = match spend.zip32_derivation().as_ref() {
            Some(d) => Zip32Derivation {
                // Zeros on the wire; see `Plan`.
                seed_fingerprint: [0u8; SEED_FINGERPRINT_SIZE],
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

        // `read_orchard_value` on the device bounds both values at
        // `MAX_MONEY`; `orchard::value::NoteValue` does not.
        for (field, raw) in [("spend value", spend_value), ("output value", value)] {
            if Zatoshis::from_u64(raw).is_err() {
                return Err(PlanError::ValueOutOfRange {
                    section,
                    index,
                    field,
                });
            }
        }
        net_value += i128::from(spend_value) - i128::from(value);

        // `verify_current_orchard_cv_net` on the device recomputes the value
        // commitment from both values and `rcv`; every input to it is in the
        // record, so the same check runs here, without a key.
        if let Err(error) = action.verify_cv_net() {
            return Err(PlanError::ActionInconsistent {
                section,
                index,
                check: "cv_net",
                error: format!("{error:?}"),
            });
        }

        // `validate_current_orchard_dummy_output` on the device recomputes a
        // zero-valued output's note commitment from the streamed recipient,
        // value, `rseed` and the spend's nullifier, and refuses a mismatch
        // mid-stream; for an output it deciphers it never reads the streamed
        // `rseed` at all, so a declared `rseed` that disagrees with the
        // ciphertext's is reviewed, approved and signed, and fails only when
        // the prover builds the output note from it. Every input to the
        // check is in the record, so it runs here for every output, without
        // a key.
        if let Err(error) = output.verify_note_commitment(spend) {
            return Err(PlanError::ActionInconsistent {
                section,
                index,
                check: "cmx",
                error: format!("{error:?}"),
            });
        }

        let note = output.encrypted_note();

        // The device's rule (`is_real_spend = spend_value != 0`,
        // `src/parser/pczt/orchard.rs`) and the host's rule (an action needs a
        // device signature iff its `spend_auth_sig` is absent) must agree, or
        // the signing loops would count different sets. Both read the action
        // alone, so an unsigned real spend is taken to be this device's; see
        // "One signer" on `build_plan_with_keys` for what that assumes.
        let already_signed = spend.spend_auth_sig().is_some();
        let device_would_sign = spend_value != 0;
        if device_would_sign == already_signed {
            return Err(PlanError::SpendClassificationMismatch {
                section,
                index,
                already_signed,
            });
        }
        if device_would_sign {
            // What `Signer::apply_orchard_spend_auth_signature` runs before it
            // stores the device's signature, run here first, with the same
            // tolerance: the four `Missing*` errors of a compact view are not
            // failures, a missing `fvk` and everything else is. A PCZT that
            // fails here would otherwise fail in `apply`, after the review.
            match spend.verify_nullifier(None) {
                Ok(())
                | Err(
                    VerifyError::MissingRecipient
                    | VerifyError::MissingValue
                    | VerifyError::MissingRho
                    | VerifyError::MissingRandomSeed,
                ) => {}
                Err(VerifyError::MissingFullViewingKey) => {
                    return Err(PlanError::MissingSpendFvk { section, index });
                }
                Err(other) => {
                    return Err(PlanError::ActionInconsistent {
                        section,
                        index,
                        check: "nullifier",
                        error: format!("{other:?}"),
                    });
                }
            }

            // `verify_current_orchard_rk` on the device recomputes `rk` from
            // the key it derives at the action's path and the streamed
            // `alpha`, and refuses a mismatch mid-stream. Under the PCZT's own
            // `fvk` the identity is checkable here without a key; under the
            // caller's key it also binds that key to the PCZT, together with
            // the nullifier check, which `orchard` runs against the key the
            // spend names (`MismatchedFullViewingKey`).
            let expected_fvk = keys.map(|k| k.orchard_fvk());
            let checks = [
                ("rk", spend.verify_rk(expected_fvk)),
                (
                    "nullifier",
                    match expected_fvk {
                        Some(fvk) => spend.verify_nullifier(Some(fvk)),
                        None => Ok(()),
                    },
                ),
            ];
            for (check, result) in checks {
                match result {
                    Ok(()) => {}
                    Err(VerifyError::MismatchedFullViewingKey) => {
                        return Err(PlanError::ViewingKeyMismatch { section, index });
                    }
                    Err(other) => {
                        return Err(PlanError::ActionInconsistent {
                            section,
                            index,
                            check,
                            error: format!("{other:?}"),
                        });
                    }
                }
            }
            out.real_spends.push(index);
        }

        // The review-budget count. `value` is the *output's* value, not the
        // spend's: it is the output that gets a screen.
        //
        // The device's order is: internal IVK (change, no screen) → external
        // OVK (displayed) → zero-valued dummy (no screen) → refuse.
        // `opens_as_change` is the first trial, with the same key on the same
        // bytes. A nonzero output is then displayed without asking (a nonzero
        // output that opens under neither key is one the device refuses
        // outright, and counting it is the safe direction); a zero-valued one
        // is displayed iff the external OVK opens it, which is what tells a
        // memo-only output from a padding dummy. See
        // [`Plan::displayed_shielded_outputs`] for the reasoning, and for what
        // this count means when `keys` is `None`.
        //
        // Both trials select their domain from `bundle_version`, and a
        // version `orchard` has no domain for stops the classification rather
        // than answering it: see [`PlanError::UnsupportedBundleVersion`].
        let no_domain = |error: UnsupportedBundleVersion| PlanError::UnsupportedBundleVersion {
            section,
            index,
            bundle_version: error.bundle_version(),
        };
        let is_change = keys
            .map(|k| k.opens_as_change(action, bundle_version))
            .transpose()
            .map_err(no_domain)?
            .unwrap_or(false);
        if is_change {
            // Change gets no screen, and the device runs no further trial.
            out.change_outputs += 1;
        } else {
            // `transpose` rather than a flatten: the two comparisons below
            // read `None` (no keys were supplied) apart from `Some(None)`
            // (keys were supplied and did not open the output), and only the
            // second is the device's refusal.
            let recovered = keys
                .map(|k| k.recover_output(action, bundle_version))
                .transpose()
                .map_err(no_domain)?;
            // The device's fourth step: a nonzero output that opened under
            // neither key is refused outright, and with keys the host knows.
            if recovered == Some(None) && value != 0 {
                return Err(PlanError::UndecryptableOutput { section, index });
            }
            if value != 0 || matches!(recovered, Some(Some(_))) {
                out.displayed_outputs += 1;
                // With keys every displayed output was just opened, so its
                // memo is in hand for the retention budget.
                if let Some(Some(memo)) = &recovered {
                    out.displayed_memos
                        .push((section, index, memo_display(memo)));
                }
            }
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
            enc_ciphertext: note.enc_ciphertext,
            out_ciphertext: note.out_ciphertext,
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
    // `finish_orchard_value_sum_sign` refuses a trailer whose value sum is not
    // what the actions add up to; the sum needs no key.
    if i128::from(value_sum) != net_value {
        return Err(PlanError::ValueSumMismatch { section });
    }

    out.trailer = Some(BundleTrailerRecord {
        flags: bundle
            .flags()
            .to_byte(bundle_version)
            .ok_or(PlanError::FlagsNotRepresentable { section })?,
        value_sum,
        anchor,
    });

    Ok(out)
}

#[cfg(test)]
mod tests;
