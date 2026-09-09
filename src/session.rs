//! [`LedgerSignSession`] — the pull-pump signing state machine.
//!
//! The session performs no I/O. A transport asks for the next command with
//! [`LedgerSignSession::next_step`], sends it, and hands the reply back with
//! [`LedgerSignSession::process_response`]. That is the whole contract.
//!
//! # Ordering
//!
//! The command order is fixed by `docs/PCZT_APDU.md` and enforced here, not
//! merely documented:
//!
//! ```text
//! PCZT_HEADER
//! PCZT_TRANSPARENT_INPUT
//! PCZT_TRANSPARENT_OUTPUT
//! PCZT_ORCHARD_ACTION            [+ trailer]   (FINISHED marker for V5)
//! PCZT_IRONWOOD_ACTION           [+ trailer]   (FINISHED marker for V6)
//! PCZT_SIGN_ORCHARD    × real Orchard spends
//! PCZT_SIGN_IRONWOOD   × real Ironwood spends
//! PCZT_SIGN_TRANSPARENT × transparent inputs
//! ```
//!
//! Dummy action indices never appear in the signing phase: the device refuses
//! them (`"PCZT orchard dummy spend must not be signed by the device"`) and
//! counts its own signing loop over the real spends only.
//!
//! Ahead of all of it goes one command that is not part of the PCZT protocol:
//! a silent `GET_WALLET_PUBLIC_KEY` at the device identity path, whose reply
//! must hash to the [`DeviceIdentity`] in [`SessionParams::device`]. Until it
//! does, no transaction byte is sent; see [`SessionError::DeviceMismatch`].
//!
//! # Failure
//!
//! Every PCZT instruction tears down the device's transaction context on any
//! non-`0x9000` reply (`reset_pczt_parser_with_sw` / `map_pczt_parser_error` in
//! `src/handlers/pczt.rs`). A failed session is therefore dead, and the only
//! recovery is a *new* session streaming from `PCZT_HEADER`.
//! [`LedgerSignSession::is_restartable`] says whether that is worth attempting.
//!
//! The single exception is `0x6901` `CmdNotAccepted`, which the device SDK
//! raises *before* the application sees the frame — nothing was parsed and
//! nothing was reset. The pump answers it by handing the same APDU out again,
//! reporting [`SessionStatus::RetrySameApdu`] so a caller can tell a resend
//! from progress; [`MAX_CMD_NOT_ACCEPTED_RETRIES`] consecutive refusals on one
//! command end the session rather than spinning forever.

use pczt::Pczt;

use crate::apdu::decode::{
    parse_shielded_signature, parse_transparent_signature, parse_wallet_public_key,
    split_status_word, DecodeError, TransparentSignature, SPEND_AUTH_SIG_LEN,
};
use crate::apdu::encode::{
    get_wallet_public_key_apdu, sign_shielded_apdu, sign_transparent_apdu, ShieldedPool,
    SEED_FINGERPRINT_SIZE,
};
use crate::apdu::{Apdu, StatusClass, StatusWord};
use crate::apply::{apply_device_signatures_to_bytes, ApplyError, DeviceSignatures};
use crate::limits::{
    validate_against_caps, validate_plan, DeviceBounds, DeviceCaps, LimitViolation, Section,
};
use crate::pairing::{device_identity_path, DeviceIdentity};
use crate::plan::{build_plan_with_keys, Plan, PlanError};
use crate::shape::{derivation_account, ChangeInfo, ShapeError, ShapeParams};
use crate::viewing::AccountViewingKeys;

pub use crate::apdu::MAX_CMD_NOT_ACCEPTED_RETRIES;
pub use crate::limits::{Network, UnsupportedNetwork};

/// How long to wait for the reply to one command.
///
/// The distinction is not a tuning knob: some replies in a ceremony arrive only
/// once a human has pressed a button on the device, and no fixed timeout is
/// correct for those. [`LedgerSignSession::next_deadline`] picks the value for
/// a signing ceremony; a pairing flow maps the first reply of a
/// [`crate::pairing::VkExchange`] and any `display` request onto
/// [`Deadline::UserReview`] itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deadline {
    /// The transport's configured per-call timeout.
    Normal,
    /// The device is showing a review screen. Wait indefinitely: the only thing
    /// that ends the wait is the user, or unplugging the device.
    UserReview,
}

/// What a session needs beyond the PCZT itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionParams {
    /// The network, which fixes the coin type in both derivation paths.
    pub network: Network,
    /// The device this session may sign on, as
    /// [`crate::pairing::parse_device_identity_response`] produced it when the
    /// wallet paired the account.
    ///
    /// The session's first command re-derives the identity from whatever
    /// device is connected, and refuses to send a single transaction byte to
    /// any other — see [`SessionError::DeviceMismatch`]. Without the binding,
    /// two Ledgers attached at once, or a device swapped between pairing and
    /// signing, would receive the whole transaction — recipient addresses,
    /// values, `alpha`, `rcv`, `rseed` — for the wrong device's holder to
    /// review and approve, and the mismatch would surface only afterwards,
    /// at signature verification.
    pub device: DeviceIdentity,
    /// ZIP 32 account index (unhardened form).
    pub zip32_account: u32,
    /// The wallet's ZIP 32 seed fingerprint, if it has one.
    ///
    /// The firmware never checks this half of a `zip32_derivation`, so `None`
    /// (encoded as 32 zero bytes) is sound for a UFVK-imported account whose
    /// PCZTs carry no derivation at all. See [`ShapeParams::seed_fingerprint`].
    pub seed_fingerprint: Option<[u8; SEED_FINGERPRINT_SIZE]>,
    /// The transparent change output, if the transaction has one.
    pub change: Option<ChangeInfo>,
    /// The account's shielded viewing keys, if the caller has them.
    ///
    /// They change nothing about what is streamed. They let the display-budget
    /// and single-change checks reach the device's own answer instead of an
    /// approximation of it — see
    /// [`crate::plan::Plan::displayed_shielded_outputs`]. `None` refuses some
    /// transactions the device would have taken (split change), and lets one
    /// shape through that the device refuses mid-stream (a zero-valued output
    /// encrypted under the account's own OVK, which the host cannot tell from
    /// a padding dummy without the key); nothing is ever signed in either
    /// case.
    pub viewing_keys: Option<AccountViewingKeys>,
}

/// BIP 32 hardening bit.
const HARDENED: u32 = 0x8000_0000;

/// A way a PCZT cannot be signed by this device.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LedgerViolation {
    /// The PCZT could not be mapped onto the device's records.
    Plan(PlanError),
    /// The PCZT carries Sapling spends or outputs. The app has no PCZT Sapling
    /// command at all: the compact APDU subset covers transparent, Orchard and
    /// Ironwood only, so a Sapling bundle would be silently dropped from
    /// everything the user reviews and the device signs.
    SaplingPresent,
    /// A device limit or field-shape rule the plan breaks.
    Limit(LimitViolation),
}

impl core::fmt::Display for LedgerViolation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LedgerViolation::Plan(inner) => write!(f, "{inner}"),
            LedgerViolation::SaplingPresent => write!(
                f,
                "the PCZT carries Sapling spends or outputs, and the app has no PCZT Sapling \
                 command: a Sapling bundle would be invisible to both the on-device review and \
                 the device's signatures"
            ),
            LedgerViolation::Limit(inner) => write!(f, "{inner}"),
        }
    }
}

impl std::error::Error for LedgerViolation {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LedgerViolation::Plan(inner) => Some(inner),
            LedgerViolation::Limit(inner) => Some(inner),
            LedgerViolation::SaplingPresent => None,
        }
    }
}

/// Checks a PCZT against everything the device will check, before shaping.
///
/// This is the plan-plus-limits gate: it builds a [`Plan`] (which is where all
/// the PCZT-level structural rules live) and runs [`validate_plan`] over it,
/// and adds the one check that belongs to neither — that the PCZT has no
/// Sapling content.
///
/// It is deliberately callable *before* [`crate::shape`] has stamped the
/// derivation paths: [`build_plan_with_keys`] substitutes a placeholder for a missing
/// `zip32_derivation` and records it in [`Plan::missing_zip32`], so a
/// not-yet-shaped PCZT still validates. Returns every violation found, not just
/// the first.
///
/// # Choosing `bounds`
///
/// A caller that has run `GET_FIRMWARE_VERSION` passes
/// [`DeviceCaps::bounds`]. A caller that has not — a pre-flight run before any
/// device is opened — passes [`DeviceBounds::MOST_PERMISSIVE`], so that a
/// transaction only a newer app can take is not refused before its version has
/// been read; the version-gated check then runs inside
/// [`LedgerSignSession::new`]. [`DeviceBounds::UNKNOWN_VERSION`] is the
/// fail-closed choice for a caller that will never learn the version.
pub fn validate_for_ledger(
    pczt: &Pczt,
    bounds: &DeviceBounds,
) -> Result<Plan, Vec<LedgerViolation>> {
    validate_for_ledger_with_keys(pczt, bounds, None)
}

/// [`validate_for_ledger`], with the account's shielded viewing keys.
///
/// The keys make two of the checks exact rather than conservative: the
/// displayed-output budget, and the device's one-change-output rule (which is
/// not checkable at all without them). See
/// [`crate::plan::build_plan_with_keys`].
pub fn validate_for_ledger_with_keys(
    pczt: &Pczt,
    bounds: &DeviceBounds,
    keys: Option<&AccountViewingKeys>,
) -> Result<Plan, Vec<LedgerViolation>> {
    if pczt.has_data_in_pool(zcash_protocol::PoolType::SAPLING) {
        return Err(vec![LedgerViolation::SaplingPresent]);
    }

    let plan = build_plan_with_keys(pczt, keys).map_err(|e| vec![LedgerViolation::Plan(e)])?;

    validate_plan(&plan, bounds).map_err(|violations| {
        violations
            .into_iter()
            .map(LedgerViolation::Limit)
            .collect::<Vec<_>>()
    })?;

    Ok(plan)
}

/// Where the ceremony currently is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Confirming that the connected device is the one the session was built
    /// for, with a silent `GET_WALLET_PUBLIC_KEY` at the identity path. No
    /// transaction byte has gone out yet.
    IdentifyingDevice,
    /// Streaming the PCZT payload, `PCZT_HEADER` through the packet carrying
    /// `P2_PCZT_FINISHED`.
    Streaming,
    /// Collecting Orchard spend authorization signatures.
    SigningOrchard,
    /// Collecting Ironwood spend authorization signatures.
    SigningIronwood,
    /// Collecting transparent signatures.
    SigningTransparent,
    /// Every command has been answered.
    Complete,
    /// The session is dead. See [`LedgerSignSession::is_restartable`].
    Failed,
}

/// A point at which the device waits for the user before replying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserAction {
    /// The next APDU carries `P2_PCZT_FINISHED`, which triggers the on-device
    /// review. Its reply arrives only once the user approves or rejects, so a
    /// transport should lift its timeout and tell the user to look at the
    /// device.
    ReviewTransaction,
}

/// What [`LedgerSignSession::process_response`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    /// Call [`LedgerSignSession::next_step`] again.
    MoreApdus,
    /// The device SDK refused the frame (`0x6901`) without the application
    /// seeing it. [`LedgerSignSession::next_step`] will hand out the *same*
    /// APDU again; the ceremony has not advanced.
    RetrySameApdu,
    /// Call [`LedgerSignSession::next_step`] again, but expect its reply to
    /// block on the user.
    AwaitingUserAction {
        /// What the user is being asked for.
        stage: UserAction,
    },
    /// Every command has been answered; call [`LedgerSignSession::finish`].
    Complete,
}

/// Something that went wrong during the ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionError {
    /// The bytes handed to [`LedgerSignSession::new`] are not a PCZT.
    Parse(String),
    /// The PCZT is not signable by this device.
    Validation(Vec<LedgerViolation>),
    /// The shaping pass failed.
    Shape(ShapeError),
    /// Shaping left an action without a `zip32_derivation`, which the device
    /// rejects. A bug in this crate rather than a property of the input.
    UnshapedAction {
        /// Which pool.
        section: Section,
        /// Index of the action.
        index: usize,
    },
    /// A record could not be encoded onto the wire.
    Encode(crate::apdu::encode::EncodeError),
    /// The user declined on the device (`0x6985`, `AppSW::Deny`).
    UserRejected {
        /// Which command was outstanding.
        stage: Stage,
    },
    /// The connected device is not running the Zcash app, or is running a
    /// version that does not know this instruction.
    WrongApp {
        /// The status word received.
        status: StatusWord,
    },
    /// The connected device is not the one the session was built for.
    ///
    /// The session's first command is a silent `GET_WALLET_PUBLIC_KEY` at
    /// [`crate::pairing::device_identity_path`], and its reply hashes to a
    /// [`DeviceIdentity`] other than [`SessionParams::device`]. No transaction
    /// byte has been sent: the check runs before `PCZT_HEADER`, so the other
    /// device has seen nothing it could review, approve, or learn from. Not
    /// restartable — the same session over the same device fails the same
    /// way — and the remedy is to connect the paired device, or to pair the
    /// connected one.
    DeviceMismatch {
        /// The device the session was built for.
        expected: DeviceIdentity,
        /// The device that answered.
        found: DeviceIdentity,
    },
    /// The device refused the command. The transaction context is gone.
    Device {
        /// Which command was outstanding.
        stage: Stage,
        /// The status word received.
        status: StatusWord,
    },
    /// The reply did not have the shape the protocol promises.
    Decode(DecodeError),
    /// [`LedgerSignSession::process_response`] was called with nothing
    /// outstanding, or [`LedgerSignSession::finish`] before completion.
    OutOfOrder,
    /// Applying the collected signatures back onto the PCZT failed.
    Apply(ApplyError),
    /// A derivation path names an account other than the one this session
    /// signs for, which the device answers with `ConditionsOfUseNotSatisfied`
    /// *after* the user has approved the review.
    ///
    /// `check_change_returns_to_signing_account` (`src/tx.rs` @ `22dc385`) is
    /// called by every command that releases a signature, and compares the
    /// account component of the signing path with the account the transaction's
    /// hidden change returns to. The change account is recorded from the
    /// transparent change output's `bip32_derivation`, or from a shielded
    /// output that decrypts under the internal IVK, via that action's ZIP 32
    /// path.
    ///
    /// [`crate::shape`] makes every path it stamps agree with
    /// [`SessionParams::zip32_account`], so the change account is always that
    /// account when the transaction has change at all. Transparent *inputs*
    /// pass through unshaped, though, and a pre-existing `bip32_derivation` on
    /// a transparent output survives shaping untouched — so either can name a
    /// different account and turn the whole ceremony into a `0x6986` collected
    /// after the review. This is that failure, raised before the first APDU.
    AccountMismatch {
        /// Which section the path belongs to.
        section: Section,
        /// Index within that section.
        index: usize,
        /// The account the path names, or `None` if the path has no depth at
        /// which the app reads one.
        found: Option<u32>,
        /// The account this session signs for, hardened.
        expected: u32,
    },
    /// A derivation path the firmware's `check_bip44_compliance` (in its
    /// `OnlyCoinType` mode, the one every PCZT signing path goes through —
    /// `src/parser/pczt/transparent.rs`, `orchard.rs`, `ironwood.rs` and
    /// `src/handlers/sign_tx.rs` @ `22dc385`) would refuse: an unhardened or
    /// wrong purpose, a coin type other than the session network's, an
    /// unhardened account, or a depth that is neither the five-component
    /// BIP 44 form nor the three-component ZIP 32 one. The device answers such
    /// a path with `IncorrectData` mid-stream, so it is refused before the
    /// first APDU instead.
    NonCompliantPath {
        /// Which section the path belongs to.
        section: Section,
        /// Index within that section.
        index: usize,
        /// The path, in raw (hardened) indices.
        path: Vec<u32>,
        /// Which rule the path breaks.
        reason: &'static str,
    },
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SessionError::Parse(message) => {
                write!(f, "the input could not be parsed as a PCZT: {message}")
            }
            SessionError::Validation(violations) => {
                write!(
                    f,
                    "the PCZT cannot be signed by this device ({} violation(s)):",
                    violations.len()
                )?;
                for violation in violations {
                    write!(f, "\n  - {violation}")?;
                }
                Ok(())
            }
            SessionError::Shape(inner) => write!(f, "shaping the PCZT for the device: {inner}"),
            SessionError::UnshapedAction { section, index } => write!(
                f,
                "internal error: shaping left {section} action {index} without a \
                 zip32_derivation, which the device rejects"
            ),
            SessionError::Encode(inner) => write!(f, "encoding a wire record: {inner}"),
            SessionError::UserRejected { stage } => {
                write!(
                    f,
                    "the user declined on the device during the {stage:?} stage"
                )
            }
            SessionError::WrongApp { status } => write!(
                f,
                "the device is not running the Zcash app, or not a version that knows this \
                 instruction (status {:#06x})",
                status.to_u16()
            ),
            SessionError::DeviceMismatch { expected, found } => write!(
                f,
                "the connected device ({found}) is not the one this session was built for \
                 ({expected}); no transaction data was sent to it"
            ),
            SessionError::Device { stage, status } => write!(
                f,
                "the device refused the command during the {stage:?} stage with status {status:?} \
                 ({:#06x}); its transaction context is gone",
                status.to_u16()
            ),
            SessionError::Decode(inner) => write!(f, "malformed device reply: {inner}"),
            SessionError::OutOfOrder => write!(
                f,
                "session methods were called out of order: a response was processed with no \
                 command outstanding, or finish was called before completion or twice"
            ),
            SessionError::Apply(inner) => {
                write!(f, "applying the device signatures to the PCZT: {inner}")
            }
            SessionError::AccountMismatch {
                section,
                index,
                found,
                expected,
            } => {
                write!(f, "{section} {index} carries a derivation path for ")?;
                match found {
                    Some(found) => write!(f, "account {found:#010x}")?,
                    None => write!(f, "no account the app can read")?,
                }
                write!(
                    f,
                    ", while this session signs for account {expected:#010x}; the device would \
                     collect this as a refusal only after the user approves the review"
                )
            }
            SessionError::NonCompliantPath {
                section,
                index,
                path,
                reason,
            } => write!(
                f,
                "{section} {index} carries a derivation path ({path:?}) the firmware would \
                 refuse: {reason}"
            ),
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SessionError::Shape(inner) => Some(inner),
            SessionError::Encode(inner) => Some(inner),
            SessionError::Decode(inner) => Some(inner),
            SessionError::Apply(inner) => Some(inner),
            _ => None,
        }
    }
}

/// What one queued command is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepKind {
    /// The silent `GET_WALLET_PUBLIC_KEY` at the identity path, whose reply
    /// must hash to the session's [`DeviceIdentity`].
    IdentifyDevice,
    /// A packet of the PCZT payload. The reply is empty.
    Stream {
        /// Whether this packet carries `P2_PCZT_FINISHED`, i.e. whether its
        /// reply is the one that waits on the user's review.
        finished_marker: bool,
    },
    /// `PCZT_SIGN_ORCHARD` for this action index.
    SignOrchard(usize),
    /// `PCZT_SIGN_IRONWOOD` for this action index.
    SignIronwood(usize),
    /// `PCZT_SIGN_TRANSPARENT` for this input index.
    SignTransparent(usize),
}

impl StepKind {
    const fn stage(self) -> Stage {
        match self {
            StepKind::IdentifyDevice => Stage::IdentifyingDevice,
            StepKind::Stream { .. } => Stage::Streaming,
            StepKind::SignOrchard(_) => Stage::SigningOrchard,
            StepKind::SignIronwood(_) => Stage::SigningIronwood,
            StepKind::SignTransparent(_) => Stage::SigningTransparent,
        }
    }
}

#[derive(Debug, Clone)]
struct Step {
    apdu: Apdu,
    kind: StepKind,
}

/// The result of a completed ceremony.
///
/// `pczt_with_sigs` carries everything the PCZT does, per-action secrets
/// included, so `Debug` shows its length and the signatures alone; the bytes
/// are the caller's to wipe once handed on.
#[derive(Clone, PartialEq, Eq)]
pub struct SignOutcome {
    /// The shaped PCZT with every device signature applied, serialized. Ready
    /// for the downstream Combiner; proving and extraction happen there.
    pub pczt_with_sigs: Vec<u8>,
    /// `(action index, signature)` for the Orchard bundle, in signing order.
    pub orchard_sigs: Vec<(usize, [u8; SPEND_AUTH_SIG_LEN])>,
    /// The same for the Ironwood bundle.
    pub ironwood_sigs: Vec<(usize, [u8; SPEND_AUTH_SIG_LEN])>,
    /// `(input index, reply)` for each transparent input, as the device
    /// returned it — DER blob and sighash byte kept apart but not normalized.
    pub transparent_sigs: Vec<(usize, TransparentSignature)>,
}

impl core::fmt::Debug for SignOutcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignOutcome")
            .field(
                "pczt_with_sigs",
                &format_args!("[{} bytes]", self.pczt_with_sigs.len()),
            )
            .field("orchard_sigs", &self.orchard_sigs)
            .field("ironwood_sigs", &self.ironwood_sigs)
            .field("transparent_sigs", &self.transparent_sigs)
            .finish()
    }
}

/// What [`LedgerSignSession::next_step`] hands back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PumpStep {
    /// Send these bytes to the device and hand the reply to
    /// [`LedgerSignSession::process_response`].
    Send(Vec<u8>),
    /// A command is already outstanding; nothing new is handed out until its
    /// reply has been processed.
    AwaitingReply,
    /// Nothing more will ever be sent: the ceremony is complete, or the
    /// session has failed. [`LedgerSignSession::stage`] and
    /// [`LedgerSignSession::failure`] say which.
    Done,
}

/// A PCZT signing ceremony against one Ledger device.
///
/// `Debug` reports where the ceremony is and nothing of the PCZT: the shaped
/// PCZT, the plan and the queued APDUs all carry the transaction's secrets,
/// and a session is exactly the kind of value an embedding logs on failure.
pub struct LedgerSignSession {
    shaped: Pczt,
    plan: Plan,
    /// The device the session was built for; the first command checks it.
    device: DeviceIdentity,
    steps: Vec<Step>,
    cursor: usize,
    /// `Some` while a command has been handed out and not yet answered.
    outstanding: Option<usize>,
    stage: Stage,
    failure: Option<SessionError>,
    signatures: DeviceSignatures,
    transparent_sigs: Vec<(usize, TransparentSignature)>,
    /// Consecutive `0x6901` replies to the command at [`Self::cursor`].
    cmd_not_accepted_retries: u32,
    /// Whether the packet carrying `P2_PCZT_FINISHED` has been handed out.
    /// From that point every reply may wait on the user.
    review_handed_out: bool,
    /// Whether [`Self::finish`] has already produced its outcome.
    finished: bool,
}

impl core::fmt::Debug for LedgerSignSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LedgerSignSession")
            .field("device", &self.device)
            .field("stage", &self.stage)
            .field("steps", &self.steps.len())
            .field("cursor", &self.cursor)
            .field("outstanding", &self.outstanding)
            .field("failure", &self.failure)
            .field("orchard_sigs", &self.signatures.orchard.len())
            .field("ironwood_sigs", &self.signatures.ironwood.len())
            .field("transparent_sigs", &self.transparent_sigs.len())
            .field("cmd_not_accepted_retries", &self.cmd_not_accepted_retries)
            .field("review_handed_out", &self.review_handed_out)
            .field("finished", &self.finished)
            .finish()
    }
}

impl LedgerSignSession {
    /// [`LedgerSignSession::new_from_pczt`], from serialized PCZT bytes.
    pub fn new(
        redacted_pczt: &[u8],
        caps: DeviceCaps,
        params: SessionParams,
    ) -> Result<Self, SessionError> {
        let pczt = Pczt::parse(redacted_pczt).map_err(|e| SessionError::Parse(format!("{e:?}")))?;
        Self::new_from_pczt(pczt, caps, params)
    }

    /// Prepares a ceremony for a redacted PCZT.
    ///
    /// In order: [`validate_for_ledger`] on the PCZT as given, then
    /// [`crate::shape::shape_for_device`], then a fresh plan over the
    /// shaped PCZT (so the stamped derivations are the ones streamed), then
    /// [`validate_plan`] and [`validate_against_caps`], and finally the APDU
    /// queue. No APDU is produced for a plan that cannot succeed.
    ///
    /// The queue opens with the device identity probe, ahead of
    /// `PCZT_HEADER`: the ceremony sends nothing of the transaction until the
    /// connected device has answered as [`SessionParams::device`].
    pub fn new_from_pczt(
        pczt: Pczt,
        caps: DeviceCaps,
        params: SessionParams,
    ) -> Result<Self, SessionError> {
        // Against the *connected* app's bounds, which is what makes a
        // transaction of eleven actions refused here for a v3.9.2 device and
        // accepted for a v3.9.3 one.
        let bounds = caps.bounds();
        validate_for_ledger_with_keys(&pczt, &bounds, params.viewing_keys.as_ref())
            .map_err(SessionError::Validation)?;

        let shaped = crate::shape::shape_for_device(
            pczt,
            &ShapeParams {
                coin_type: params.network.coin_type(),
                zip32_account: params.zip32_account,
                seed_fingerprint: params.seed_fingerprint,
                change: params.change.clone(),
            },
        )
        .map_err(SessionError::Shape)?;

        let plan = build_plan_with_keys(&shaped.pczt, params.viewing_keys.as_ref())
            .map_err(|e| SessionError::Validation(vec![LedgerViolation::Plan(e)]))?;

        // Shaping is supposed to have removed every gap; if one survived, the
        // device would answer `IncorrectData` mid-stream.
        if let Some((section, index)) = plan.missing_zip32.first().copied() {
            return Err(SessionError::UnshapedAction { section, index });
        }

        check_path_compliance(&plan, params.network.coin_type(), params.zip32_account)?;

        validate_plan(&plan, &bounds).map_err(|v| {
            SessionError::Validation(v.into_iter().map(LedgerViolation::Limit).collect())
        })?;
        validate_against_caps(&plan.stream, &caps).map_err(|v| {
            SessionError::Validation(v.into_iter().map(LedgerViolation::Limit).collect())
        })?;

        let probe = get_wallet_public_key_apdu(&device_identity_path(params.network), false)
            .map_err(SessionError::Encode)?;
        let steps = build_steps(probe, &plan).map_err(SessionError::Encode)?;

        Ok(LedgerSignSession {
            shaped: shaped.pczt,
            plan,
            device: params.device,
            steps,
            cursor: 0,
            outstanding: None,
            stage: Stage::Streaming,
            failure: None,
            signatures: DeviceSignatures::default(),
            transparent_sigs: Vec::new(),
            cmd_not_accepted_retries: 0,
            review_handed_out: false,
            finished: false,
        })
    }

    /// The plan this session streams.
    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    /// The device this session was built for, which the first command checks
    /// the connected device against.
    pub fn device(&self) -> DeviceIdentity {
        self.device
    }

    /// The shaped PCZT the session was built from.
    pub fn shaped_pczt(&self) -> &Pczt {
        &self.shaped
    }

    /// Where the ceremony is.
    pub fn stage(&self) -> Stage {
        self.stage
    }

    /// The failure that killed the session, if any.
    pub fn failure(&self) -> Option<&SessionError> {
        self.failure.as_ref()
    }

    /// Whether restarting the *whole* ceremony from `PCZT_HEADER` could
    /// succeed.
    ///
    /// This never means "resend the last APDU". The device resets its
    /// transaction context on any non-`0x9000` reply, so a resend can only fail
    /// again — with `BadState`, if it is not the header. A fresh
    /// [`LedgerSignSession`] is the only recovery, and this says whether one is
    /// worth building:
    ///
    /// - **`true`** after a user rejection or a device-side refusal: the user
    ///   may approve on a second pass, and a transient device condition
    ///   (`MemoryProblem`, `TechnicalProblem`, a `BadState` from a desynchronized
    ///   transport) clears with the context.
    /// - **`false`** when the device is not running the Zcash app, when the
    ///   reply was malformed (a protocol mismatch a retry cannot fix), and for
    ///   every host-side failure, which is deterministic in the input.
    pub fn is_restartable(&self) -> bool {
        match &self.failure {
            None => false,
            Some(SessionError::UserRejected { .. }) | Some(SessionError::Device { .. }) => true,
            Some(_) => false,
        }
    }

    /// Hands out the next command, or says why there is none.
    ///
    /// [`PumpStep::Send`] carries the bytes to exchange; the reply goes to
    /// [`LedgerSignSession::process_response`] before this hands anything else
    /// out. A `0x6901` refusal makes the *same* bytes come out again on the
    /// next call.
    pub fn next_step(&mut self) -> PumpStep {
        if matches!(self.stage, Stage::Complete | Stage::Failed) {
            return PumpStep::Done;
        }
        if self.outstanding.is_some() {
            return PumpStep::AwaitingReply;
        }
        let Some(step) = self.steps.get(self.cursor) else {
            return PumpStep::Done;
        };
        self.stage = step.kind.stage();
        self.outstanding = Some(self.cursor);
        if matches!(
            step.kind,
            StepKind::Stream {
                finished_marker: true
            }
        ) {
            self.review_handed_out = true;
        }
        PumpStep::Send(step.apdu.to_bytes())
    }

    /// Whether the command [`LedgerSignSession::next_step`] will hand out next
    /// blocks on the user.
    pub fn pending_user_action(&self) -> Option<UserAction> {
        match self.steps.get(self.cursor)?.kind {
            StepKind::Stream {
                finished_marker: true,
            } => Some(UserAction::ReviewTransaction),
            _ => None,
        }
    }

    /// Whether the packet carrying `P2_PCZT_FINISHED` has been handed out.
    ///
    /// From that point on, every reply may block on the user: the review
    /// itself, and — depending on how the app is built — per-signature
    /// confirmations behind the `PCZT_SIGN_*` commands. A runner keeps its
    /// deadline lifted for the rest of the session rather than guessing.
    pub fn is_past_review(&self) -> bool {
        self.review_handed_out
    }

    /// The deadline under which to wait for the current (or next) command's
    /// reply.
    ///
    /// [`Deadline::UserReview`] from the moment the review packet is about to
    /// go out, through the end of the session; [`Deadline::Normal`] before it.
    pub fn next_deadline(&self) -> Deadline {
        if self.review_handed_out || self.pending_user_action().is_some() {
            Deadline::UserReview
        } else {
            Deadline::Normal
        }
    }

    /// Absorbs the reply to the outstanding command.
    ///
    /// `rapdu` is the raw transport payload: response data followed by the
    /// two-byte status word.
    pub fn process_response(&mut self, rapdu: &[u8]) -> Result<SessionStatus, SessionError> {
        let index = self.outstanding.take().ok_or(SessionError::OutOfOrder)?;
        let kind = self.steps[index].kind;

        let (data, status) = match split_status_word(rapdu) {
            Ok(parts) => parts,
            Err(e) => return Err(self.fail(SessionError::Decode(e))),
        };

        match status.class() {
            StatusClass::Ok => {}
            StatusClass::Retriable => {
                // The frame never reached the application, so the device's
                // transaction context is untouched and the cursor must not
                // advance: `next_step` hands the same command out again.
                self.cmd_not_accepted_retries += 1;
                if self.cmd_not_accepted_retries > MAX_CMD_NOT_ACCEPTED_RETRIES {
                    return Err(self.fail(SessionError::Device {
                        stage: kind.stage(),
                        status,
                    }));
                }
                self.stage = kind.stage();
                return Ok(SessionStatus::RetrySameApdu);
            }
            StatusClass::UserCancel => {
                return Err(self.fail(SessionError::UserRejected {
                    stage: kind.stage(),
                }))
            }
            StatusClass::WrongApp => return Err(self.fail(SessionError::WrongApp { status })),
            StatusClass::Fatal => {
                return Err(self.fail(SessionError::Device {
                    stage: kind.stage(),
                    status,
                }))
            }
        }

        if let Err(e) = self.absorb(kind, data) {
            return Err(self.fail(e));
        }

        self.cmd_not_accepted_retries = 0;
        self.cursor = index + 1;
        if self.cursor == self.steps.len() {
            self.stage = Stage::Complete;
            return Ok(SessionStatus::Complete);
        }

        Ok(match self.pending_user_action() {
            Some(stage) => SessionStatus::AwaitingUserAction { stage },
            None => SessionStatus::MoreApdus,
        })
    }

    /// Records the reply data for one command.
    fn absorb(&mut self, kind: StepKind, data: &[u8]) -> Result<(), SessionError> {
        match kind {
            StepKind::IdentifyDevice => {
                // The reply also carries the account's first address; it is
                // dropped with the reply at the end of this arm, unlogged.
                let reply = parse_wallet_public_key(data).map_err(SessionError::Decode)?;
                let found =
                    DeviceIdentity::from_wallet_public_key(&reply).map_err(SessionError::Decode)?;
                if found != self.device {
                    return Err(SessionError::DeviceMismatch {
                        expected: self.device,
                        found,
                    });
                }
                Ok(())
            }
            StepKind::Stream { .. } => Ok(()),
            StepKind::SignOrchard(action) => {
                let sig = parse_shielded_signature(data).map_err(SessionError::Decode)?;
                self.signatures.orchard.push((action, sig));
                Ok(())
            }
            StepKind::SignIronwood(action) => {
                let sig = parse_shielded_signature(data).map_err(SessionError::Decode)?;
                self.signatures.ironwood.push((action, sig));
                Ok(())
            }
            StepKind::SignTransparent(input) => {
                // Kept whole here; `finish` re-joins the DER blob and the
                // sighash byte for `normalize_ledger_der`, which is written
                // against the reply as a capture holds it.
                let sig = parse_transparent_signature(data).map_err(SessionError::Decode)?;
                self.transparent_sigs.push((input, sig));
                Ok(())
            }
        }
    }

    /// Kills the session, remembering why.
    fn fail(&mut self, error: SessionError) -> SessionError {
        self.stage = Stage::Failed;
        self.failure = Some(error.clone());
        error
    }

    /// Applies the collected signatures and returns the signed PCZT.
    ///
    /// Only valid once [`SessionStatus::Complete`] has been reported, and only
    /// once: a second call — like a call before completion — answers
    /// [`SessionError::OutOfOrder`] without disturbing the session's state, so
    /// the accessors ([`LedgerSignSession::plan`],
    /// [`LedgerSignSession::shaped_pczt`], …) keep working afterwards.
    pub fn finish(&mut self) -> Result<SignOutcome, SessionError> {
        if self.stage != Stage::Complete || self.finished {
            return Err(SessionError::OutOfOrder);
        }

        // The device returns the DER blob and the sighash byte separately, but
        // `normalize_ledger_der` is written against the whole reply (that is
        // what a capture holds), so the byte is re-appended before it runs.
        let mut signatures = self.signatures.clone();
        signatures.transparent = self
            .transparent_sigs
            .iter()
            .map(|(index, sig)| {
                let mut blob = sig.der.clone();
                blob.push(sig.sighash_type);
                (*index, blob)
            })
            .collect();

        let pczt_with_sigs = apply_device_signatures_to_bytes(self.shaped.clone(), &signatures)
            .map_err(SessionError::Apply)?;

        self.finished = true;
        Ok(SignOutcome {
            pczt_with_sigs,
            orchard_sigs: self.signatures.orchard.clone(),
            ironwood_sigs: self.signatures.ironwood.clone(),
            transparent_sigs: self.transparent_sigs.clone(),
        })
    }
}

/// Why one derivation path fails the firmware's
/// `check_bip44_compliance(OnlyCoinType)`, or `None` if it passes.
///
/// Mirrors `src/utils.rs` @ `22dc385`, which every PCZT signing path goes
/// through: hardened purpose (`44'` for the five-component transparent form,
/// `32'` for the three-component shielded one), hardened coin type equal to
/// the app build's, hardened account. Purpose and coin type are compared with
/// the hardening bit *included*, for the firmware's own reason: an unhardened
/// prefix is a path the OS refuses to derive by taking the app down rather
/// than by a status word.
pub(crate) fn path_compliance_error(path: &[u32], coin_type: u32) -> Option<&'static str> {
    match path.len() {
        3 => {
            if path[0] != crate::shape::ZIP32_PURPOSE | HARDENED {
                Some("a three-component shielded path must begin with hardened purpose 32'")
            } else if path[1] != coin_type | HARDENED {
                Some("the coin type must be hardened and equal the session network's")
            } else if path[2] & HARDENED == 0 {
                Some("the account component must be hardened")
            } else {
                None
            }
        }
        5 => {
            if path[0] != crate::shape::BIP44_PURPOSE | HARDENED {
                Some("a five-component transparent path must begin with hardened purpose 44'")
            } else if path[1] != coin_type | HARDENED {
                Some("the coin type must be hardened and equal the session network's")
            } else if path[2] & HARDENED == 0 {
                Some("the account component must be hardened")
            } else {
                None
            }
        }
        _ => Some(
            "the app reads only the five-component BIP 44 form and the three-component ZIP 32 \
             account form",
        ),
    }
}

/// Refuses a plan any of whose derivation paths the firmware would refuse, or
/// which names a different account from the one being signed for.
///
/// Two firmware checks are mirrored here, both of which fire only *after* the
/// host has streamed (and possibly the user has reviewed) the transaction:
///
/// - `check_bip44_compliance(OnlyCoinType)` — see [`path_compliance_error`] —
///   which every signing path is put through as it is parsed, answering
///   `IncorrectData` mid-stream;
/// - `check_change_returns_to_signing_account` (`src/tx.rs` @ `22dc385`),
///   which compares the account component of every signing path with the
///   account the transaction's hidden change returns to, at signing time —
///   after the review has been approved — so getting it wrong costs the user a
///   confirmation and the ceremony a restart.
///
/// Nothing here can be discovered only on the device: every path involved is
/// in the plan. Every section is checked, not only the ones shaping leaves
/// alone, because the check is free and a shaping bug should surface here
/// rather than on a device:
///
/// - **transparent inputs** carry the wallet's own `bip32_derivation` from the
///   PCZT and are never rewritten, so they are the section this exists for;
/// - **transparent outputs** are rewritten only at the index the caller names
///   as change — a derivation already present on any other output survives
///   shaping and would still record a change account on the device;
/// - **shielded actions** are stamped by [`crate::shape`] with the session's
///   own account path, so a mismatch here is a bug in this crate.
fn check_path_compliance(
    plan: &Plan,
    coin_type: u32,
    zip32_account: u32,
) -> Result<(), SessionError> {
    let expected = zip32_account | HARDENED;

    let check = |section: Section, index: usize, path: &[u32]| {
        if let Some(reason) = path_compliance_error(path, coin_type) {
            return Err(SessionError::NonCompliantPath {
                section,
                index,
                path: path.to_vec(),
                reason,
            });
        }
        let found = derivation_account(path);
        if found == Some(expected) {
            Ok(())
        } else {
            Err(SessionError::AccountMismatch {
                section,
                index,
                found,
                expected,
            })
        }
    };

    for (index, input) in plan.stream.transparent_inputs.iter().enumerate() {
        check(Section::TransparentInput, index, &input.derivation.path.0)?;
    }
    for (index, output) in plan.stream.transparent_outputs.iter().enumerate() {
        if let Some(derivation) = &output.derivation {
            check(Section::TransparentOutput, index, &derivation.path.0)?;
        }
    }
    for (index, action) in plan.stream.orchard_actions.iter().enumerate() {
        check(Section::Orchard, index, &action.zip32_derivation.path.0)?;
    }
    for (index, action) in plan.stream.ironwood_actions.iter().flatten().enumerate() {
        check(Section::Ironwood, index, &action.zip32_derivation.path.0)?;
    }

    Ok(())
}

/// Builds the full command queue for a plan.
///
/// The identity `probe` goes first, before any transaction byte. The signing
/// commands come after the streaming ones, pool by pool, and only for real
/// spends: `orchard_signature_count()` on the device is
/// `orchard_real_spend_count`, so asking for a dummy index would both be
/// refused and push the device's count past its own quota.
fn build_steps(probe: Apdu, plan: &Plan) -> Result<Vec<Step>, crate::apdu::encode::EncodeError> {
    let stream = plan.stream.to_apdus()?;
    let last = stream.len() - 1;

    let mut steps = vec![Step {
        apdu: probe,
        kind: StepKind::IdentifyDevice,
    }];
    steps.extend(stream.into_iter().enumerate().map(|(i, apdu)| Step {
        apdu,
        kind: StepKind::Stream {
            finished_marker: i == last,
        },
    }));

    for &index in &plan.orchard_real_spends {
        steps.push(Step {
            apdu: sign_shielded_apdu(ShieldedPool::Orchard, index as u8),
            kind: StepKind::SignOrchard(index),
        });
    }
    for &index in &plan.ironwood_real_spends {
        steps.push(Step {
            apdu: sign_shielded_apdu(ShieldedPool::Ironwood, index as u8),
            kind: StepKind::SignIronwood(index),
        });
    }
    for index in 0..plan.stream.transparent_inputs.len() {
        steps.push(Step {
            apdu: sign_transparent_apdu(index as u8),
            kind: StepKind::SignTransparent(index),
        });
    }

    Ok(steps)
}
