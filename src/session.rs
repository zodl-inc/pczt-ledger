//! [`LedgerSignSession`] — the pull-pump signing state machine.
//!
//! The session performs no I/O. A transport asks for the next command with
//! [`LedgerSignSession::next_step`], sends it, and hands the reply back with
//! [`LedgerSignSession::process_response`]. That is the whole contract, with
//! one rule the transport has to keep on its own: a reply is only ever the
//! answer to the command last handed out, so an exchange that fails once its
//! command is on the wire ends the session and the channel both — see
//! [`LedgerSignSession::process_response`].
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
//! Ahead of all of it go two commands that are not part of the PCZT protocol:
//! a `GET_FIRMWARE_VERSION`, whose reply must derive the [`DeviceCaps`] the
//! session was built against (see [`SessionError::CapsMismatch`]), and a
//! silent `GET_WALLET_PUBLIC_KEY` at the device identity path, whose reply
//! must hash to the [`DeviceIdentity`] in [`SessionParams::device`] (see
//! [`SessionError::DeviceMismatch`]). Until both agree, no transaction byte
//! is sent: the session has proved what the device is and whose it is.
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

use alloc::{format, string::String, vec, vec::Vec};

use pczt::Pczt;
use zcash_transparent::keys::NonHardenedChildIndex;
use zeroize::Zeroizing;
use zip32::AccountId;

use crate::apdu::decode::{
    parse_firmware_version, parse_shielded_signature, parse_transparent_signature,
    parse_wallet_public_key, split_status_word, DecodeError, TransparentSignature,
    SPEND_AUTH_SIG_LEN,
};
use crate::apdu::encode::{
    get_firmware_version_apdu, get_wallet_public_key_apdu, sign_shielded_apdu,
    sign_transparent_apdu, ShieldedPool, TransparentDerivation, SEED_FINGERPRINT_SIZE,
};
use crate::apdu::{Apdu, StatusClass, StatusWord};
use crate::apply::{apply_device_signatures_to_bytes, ApplyError, DeviceSignatures};
use crate::limits::{validate_against_caps, DeviceBounds, DeviceCaps, LimitViolation, Section};
use crate::pairing::{device_identity_path, DeviceIdentity};
use crate::plan::{build_plan_with_keys, validate_plan, Plan, PlanError};
use crate::shape::{derivation_account, ChangeInfo, ShapeError, ShapeParams, HARDENED};
use crate::viewing::{AccountViewingKeys, TransparentAccountKey};

pub use crate::apdu::{Deadline, MAX_CMD_NOT_ACCEPTED_RETRIES};
pub use crate::limits::{Network, UnsupportedNetwork};

/// What `Debug` prints in place of a field that identifies the wallet.
const REDACTED: &str = "[redacted]";

/// What a session needs beyond the PCZT itself.
///
/// `Debug` shows every field but the seed fingerprint, which it redacts: the
/// fingerprint is a stable identifier of the wallet's seed, the same on every
/// PCZT the wallet ever produces, and the wire records redact it for the same
/// reason. The change hint and the two keys redact themselves.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionParams {
    /// The network, which fixes the coin type in both derivation paths.
    pub(crate) network: Network,
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
    pub(crate) device: DeviceIdentity,
    /// The ZIP 32 account: the index the shielded and transparent paths
    /// share, hardened on the wire.
    pub(crate) zip32_account: AccountId,
    /// The wallet's ZIP 32 seed fingerprint, if it has one.
    ///
    /// The firmware never checks this half of a `zip32_derivation`, so `None`
    /// (encoded as 32 zero bytes) is sound for a UFVK-imported account whose
    /// PCZTs carry no derivation at all — which only a shielded-only PCZT can
    /// be. Shaping stamps shielded derivations and the transparent change
    /// output, never a transparent input, and a transparent input without
    /// exactly one `bip32_derivation` is refused before the first APDU
    /// ([`crate::plan::PlanError::TransparentDerivationCount`]): the device
    /// reads its signing path from it. An account that spends transparent
    /// funds therefore needs a wallet that stamps those, fingerprint included.
    /// See [`ShapeParams::seed_fingerprint`].
    pub(crate) seed_fingerprint: Option<[u8; SEED_FINGERPRINT_SIZE]>,
    /// The transparent change output, if the transaction has one.
    ///
    /// `None` on a transaction that does have change is not refused, and is
    /// not safe: shaping then stamps no derivation on the output, so the device
    /// cannot tell it is change and shows the wallet's own change address as a
    /// third-party recipient for the user to approve (`check_output_displayable`
    /// classifies an output without a change pubkey as displayable,
    /// `src/parser/pczt/transparent.rs` @ `22dc385`). Nothing is mis-signed
    /// and the totals are right; the review is misleading, which is the second
    /// half of what this crate exists to prevent. A wallet whose transaction
    /// has transparent change must say so here.
    pub(crate) change: Option<ChangeInfo>,
    /// The account's transparent full viewing key, required whenever the
    /// transaction carries a transparent input or a transparent change output.
    ///
    /// Every transparent `bip32_derivation` is a path *and* a pubkey, and the
    /// device uses only the path: it signs an input with the key it derives
    /// there and never compares that key with the supplied pubkey (it does so
    /// for outputs alone, and only mid-stream). The host's return path verifies
    /// the device's signature against the pubkey. A derivation whose path
    /// derives a different key than its pubkey therefore passes every other
    /// check, is reviewed and approved, and fails in [`crate::apply`]. With
    /// this key the session re-derives the pubkey from every transparent path
    /// before the first APDU — see [`SessionError::TransparentKeyMismatch`] —
    /// and refuses to proceed without it when there is a path to check
    /// ([`SessionError::TransparentAccountKeyRequired`]). A transaction with
    /// no transparent derivation does not need it.
    pub(crate) transparent_account_key: Option<TransparentAccountKey>,
    /// The account's shielded viewing keys, if the caller has them.
    ///
    /// They change nothing about what is streamed. They let the display-budget
    /// and change-output checks reach the device's own answer instead of an
    /// approximation of it — see
    /// [`crate::plan::Plan::displayed_shielded_outputs`] — and they are what
    /// makes three more of the device's checks possible at all: the
    /// undecryptable-output refusal, the memo retention budget
    /// ([`crate::plan::Plan::displayed_memos`]) and the binding of the key
    /// itself to every real spend. `None` refuses some transactions the device
    /// would have taken (split change), and lets shapes through that the
    /// device refuses mid-stream (a zero-valued output encrypted under the
    /// account's own OVK, which the host cannot tell from a padding dummy
    /// without the key; a nonzero output no key opens; memos past the
    /// retention budget); nothing is ever signed in any of these cases.
    pub(crate) viewing_keys: Option<AccountViewingKeys>,
    /// Which bounds an app version this crate has not been checked against is
    /// held to, if such a device is to be accepted at all.
    ///
    /// [`DeviceCaps::bounds`] answers `None` for a version above the newer
    /// firmware pin: a newer app is not assumed to be at least as permissive,
    /// and this crate has not read its constants either, so there is no set
    /// to derive. `None` here refuses such a device before any transaction
    /// byte goes out ([`SessionError::UnknownDeviceVersion`]); `Some` takes
    /// the choice explicitly, and the two sets that make it are
    /// [`DeviceBounds::MOST_RESTRICTIVE`] — the strictest combination of every
    /// known set, so a plan that passes is one every known app would take —
    /// and [`DeviceBounds::MOST_PERMISSIVE`].
    ///
    /// It selects record bounds and nothing else. The session's first command
    /// still reads the connected device's version and refuses to continue
    /// unless it derives the session's [`DeviceCaps`]
    /// ([`SessionError::CapsMismatch`]), and every other rule — the instruction
    /// gating, the field shapes, the review budgets — is unchanged.
    pub(crate) unknown_version_bounds: Option<DeviceBounds>,
}

impl core::fmt::Debug for SessionParams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionParams")
            .field("network", &self.network)
            .field("device", &self.device)
            .field("zip32_account", &self.zip32_account)
            .field(
                "seed_fingerprint",
                &self.seed_fingerprint.as_ref().map(|_| REDACTED),
            )
            .field("change", &self.change)
            .field("transparent_account_key", &self.transparent_account_key)
            .field("viewing_keys", &self.viewing_keys)
            .field("unknown_version_bounds", &self.unknown_version_bounds)
            .finish()
    }
}

impl SessionParams {
    /// Parameters for one account on one device, with no seed fingerprint,
    /// no change output, no transparent account key, no viewing keys and no
    /// bounds for an unrecognised app version; the `with_*` methods add each.
    pub fn new(network: Network, device: DeviceIdentity, zip32_account: AccountId) -> Self {
        SessionParams {
            network,
            device,
            zip32_account,
            seed_fingerprint: None,
            change: None,
            transparent_account_key: None,
            viewing_keys: None,
            unknown_version_bounds: None,
        }
    }

    /// Sets the wallet's ZIP 32 seed fingerprint; see
    /// [`SessionParams::seed_fingerprint`].
    pub fn with_seed_fingerprint(
        mut self,
        seed_fingerprint: Option<[u8; SEED_FINGERPRINT_SIZE]>,
    ) -> Self {
        self.seed_fingerprint = seed_fingerprint;
        self
    }

    /// Sets the transparent change output; see [`SessionParams::change`].
    pub fn with_change(mut self, change: Option<ChangeInfo>) -> Self {
        self.change = change;
        self
    }

    /// Sets the account's transparent key; see
    /// [`SessionParams::transparent_account_key`].
    pub fn with_transparent_account_key(mut self, key: Option<TransparentAccountKey>) -> Self {
        self.transparent_account_key = key;
        self
    }

    /// Sets the account's shielded viewing keys; see
    /// [`SessionParams::viewing_keys`].
    pub fn with_viewing_keys(mut self, keys: Option<AccountViewingKeys>) -> Self {
        self.viewing_keys = keys;
        self
    }

    /// Sets the bounds an app version this crate has not been checked against
    /// is held to; see [`SessionParams::unknown_version_bounds`].
    ///
    /// `Some(DeviceBounds::MOST_RESTRICTIVE)` is the conservative choice,
    /// though not a promise about the newer app's own bounds (see
    /// [`DeviceBounds::MOST_RESTRICTIVE`]). `None`, the default, refuses such a
    /// device instead.
    pub fn with_unknown_version_bounds(mut self, bounds: Option<DeviceBounds>) -> Self {
        self.unknown_version_bounds = bounds;
        self
    }

    /// The network the session signs for.
    pub fn network(&self) -> Network {
        self.network
    }

    /// The device the session is bound to.
    pub fn device(&self) -> &DeviceIdentity {
        &self.device
    }

    /// The ZIP 32 account.
    pub fn zip32_account(&self) -> AccountId {
        self.zip32_account
    }

    /// The wallet's ZIP 32 seed fingerprint, if it has one.
    pub fn seed_fingerprint(&self) -> Option<[u8; SEED_FINGERPRINT_SIZE]> {
        self.seed_fingerprint
    }

    /// The transparent change output, if the transaction has one.
    pub fn change(&self) -> Option<&ChangeInfo> {
        self.change.as_ref()
    }

    /// The account's transparent key, if supplied.
    pub fn transparent_account_key(&self) -> Option<&TransparentAccountKey> {
        self.transparent_account_key.as_ref()
    }

    /// The account's shielded viewing keys, if supplied.
    pub fn viewing_keys(&self) -> Option<&AccountViewingKeys> {
        self.viewing_keys.as_ref()
    }

    /// The bounds an app version this crate has not been checked against is
    /// held to, if the caller chose any.
    pub fn unknown_version_bounds(&self) -> Option<DeviceBounds> {
        self.unknown_version_bounds
    }
}

/// A way a PCZT cannot be signed by this device.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LedgerViolation {
    /// The PCZT could not be mapped onto the device's records.
    Plan(PlanError),
    /// The PCZT carries Sapling spends or outputs. The app has no PCZT Sapling
    /// command at all: the compact APDU subset covers transparent, Orchard and
    /// Ironwood only, so a Sapling bundle would be silently dropped from
    /// everything the user reviews and the device signs. Raised by the plan
    /// ([`PlanError::SaplingPresent`]) and reported here as its own variant.
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

impl core::error::Error for LedgerViolation {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            LedgerViolation::Plan(inner) => Some(inner),
            LedgerViolation::Limit(inner) => Some(inner),
            LedgerViolation::SaplingPresent => None,
        }
    }
}

/// The checks that need no session parameters, before shaping: it builds a
/// [`Plan`] (which is where all the PCZT-level structural rules live, the
/// no-Sapling rule included) and runs [`validate_plan`] over it.
///
/// It is not everything the device will check. Shaping, path compliance,
/// account and key binding and the caps check all need the
/// [`SessionParams`], and run only in [`preflight`] and
/// [`LedgerSignSession::new`]; a wallet that wants the full pre-flight — a
/// green result here can still be refused by `new` with an
/// [`SessionError::AccountMismatch`], say — uses [`preflight`].
///
/// It is deliberately callable *before* [`crate::shape`] has stamped the
/// derivation paths: [`build_plan_with_keys`] substitutes a placeholder for a missing
/// `zip32_derivation` and records it in [`Plan::missing_zip32`], so a
/// not-yet-shaped PCZT still validates. Returns every violation found, not just
/// the first.
///
/// # Choosing `bounds`
///
/// A caller that has run `GET_FIRMWARE_VERSION` passes what
/// [`DeviceCaps::bounds`] returned. A caller that has not — a pre-flight run
/// before any device is opened — passes [`DeviceBounds::MOST_PERMISSIVE`], so
/// that a transaction only a newer app can take is not refused before its
/// version has been read; the version-gated check then runs inside
/// [`LedgerSignSession::new`]. [`DeviceBounds::MOST_RESTRICTIVE`] is the
/// conservative choice, for a caller that will never learn the version or that
/// reads a version above the newer firmware pin, for which
/// [`DeviceCaps::bounds`] returns `None` rather than choosing.
///
/// # Errors
///
/// As [`validate_for_ledger_with_keys`].
pub fn validate_for_ledger(
    pczt: &Pczt,
    bounds: &DeviceBounds,
) -> Result<Plan, Vec<LedgerViolation>> {
    validate_for_ledger_with_keys(pczt, bounds, None)
}

/// [`validate_for_ledger`], with the account's shielded viewing keys.
///
/// The keys make two of the checks exact. Without them the displayed-output
/// budget is checked against a count of the nonzero shielded outputs, which
/// the device's own count can exceed as well as fall short of, so a pass
/// there is no promise; and the device's change-output limit is checked for
/// transparent change alone. See [`crate::plan::build_plan_with_keys`].
///
/// # Errors
///
/// `Err` with every [`LedgerViolation`] found:
/// [`LedgerViolation::SaplingPresent`] for a Sapling bundle,
/// [`LedgerViolation::Plan`] when the plan cannot be built (see
/// [`build_plan_with_keys`]), and one [`LedgerViolation::Limit`] per violation
/// [`validate_plan`] reports.
pub fn validate_for_ledger_with_keys(
    pczt: &Pczt,
    bounds: &DeviceBounds,
    keys: Option<&AccountViewingKeys>,
) -> Result<Plan, Vec<LedgerViolation>> {
    let plan = build_plan_with_keys(pczt, keys).map_err(|e| match e {
        PlanError::SaplingPresent => vec![LedgerViolation::SaplingPresent],
        other => vec![LedgerViolation::Plan(other)],
    })?;

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
    /// Confirming that the connected device is what the session was built
    /// for — a `GET_FIRMWARE_VERSION` checked against its [`DeviceCaps`] —
    /// and whose it is — a silent `GET_WALLET_PUBLIC_KEY` at the identity
    /// path. No transaction byte has gone out yet.
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

impl core::fmt::Display for Stage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Stage::IdentifyingDevice => "device identification",
            Stage::Streaming => "transaction streaming",
            Stage::SigningOrchard => "Orchard signing",
            Stage::SigningIronwood => "Ironwood signing",
            Stage::SigningTransparent => "transparent signing",
            Stage::Complete => "completion",
            Stage::Failed => "failure",
        })
    }
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
        action: UserAction,
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
    ///
    /// Not expected once [`crate::limits::validate_records`] has passed —
    /// every length the encoder refuses is one it checks first — but the
    /// encoder is fallible by signature, and this is the honest encoding of
    /// that rather than a panic on the signing path.
    Encode(crate::apdu::encode::EncodeError),
    /// A plan encoded to no APDUs at all, so no packet would carry
    /// `P2_PCZT_FINISHED` and the device would never be asked to review.
    ///
    /// Not reachable through this crate — every plan has a `PCZT_HEADER` — and
    /// kept because the command queue is built from a length rather than from
    /// a non-empty type, and an empty one must not be papered over on the
    /// signing path.
    EmptyStream,
    /// A record index does not fit the one-byte index a `PCZT_SIGN_*` command
    /// carries it in.
    ///
    /// Not reachable through this crate — every [`DeviceBounds`] set caps each
    /// section far below what one byte holds, and [`validate_plan`] has run by
    /// the time the queue is built — and named rather than truncated because
    /// this is the one place a narrowing would ask the device to sign a
    /// different action than the host files the signature under.
    SigningIndexTooLarge {
        /// Which section the index counts within.
        section: Section,
        /// The index that does not fit.
        index: usize,
    },
    /// The user declined on the device (`0x6985`, `AppSW::Deny`).
    UserRejected {
        /// Which command was outstanding.
        stage: Stage,
    },
    /// The device reports an app version this crate has not been checked
    /// against, and no bounds were chosen for such a version.
    ///
    /// [`DeviceCaps::bounds`] answers `None` above the newer firmware pin
    /// rather than assuming a newer app is at least as permissive. Set
    /// [`SessionParams::unknown_version_bounds`] — to
    /// [`DeviceBounds::MOST_RESTRICTIVE`], the strictest combination of every
    /// known set, or to [`DeviceBounds::MOST_PERMISSIVE`] — to accept such a
    /// device.
    UnknownDeviceVersion {
        /// The app version the session was built for, `(major, minor, patch)`.
        version: (u8, u8, u8),
    },
    /// The connected device is not running the Zcash app, or is running a
    /// version that does not know this instruction.
    WrongApp {
        /// The status word received.
        status: StatusWord,
    },
    /// The connected device is not running the app version the session was
    /// built for.
    ///
    /// The session's first command is a `GET_FIRMWARE_VERSION`, and the
    /// [`DeviceCaps`] its reply derives must equal the caps the session was
    /// given: every version-gated bound was validated against those, so a
    /// different version would move a refusal from before the first APDU to
    /// mid-stream (a 3.9.2 device asked for 32 actions refuses at the count
    /// packet; a 3.9.3 device asked for five displayed outputs refuses at the
    /// fifth). No transaction byte has been sent. Not restartable: the remedy
    /// is to build the session from the connected device's own
    /// [`crate::pairing::device_caps`].
    CapsMismatch {
        /// The caps the session was built against.
        expected: DeviceCaps,
        /// The caps the connected device's version derives.
        found: DeviceCaps,
    },
    /// The connected device is not the one the session was built for.
    ///
    /// The session's second command is a silent `GET_WALLET_PUBLIC_KEY` at
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
        /// Which section.
        section: Section,
        /// Index of the record.
        index: usize,
    },
    /// A derivation path the firmware's `check_bip44_compliance` would refuse.
    ///
    /// Signing paths — transparent inputs and shielded actions — go through
    /// its `OnlyCoinType` mode (`src/parser/pczt/transparent.rs`,
    /// `orchard.rs`, `ironwood.rs` and `src/handlers/sign_tx.rs` @ `22dc385`):
    /// an unhardened or wrong purpose, a coin type other than the session
    /// network's, an unhardened account, or a depth that is neither the
    /// five-component BIP 44 form nor the three-component ZIP 32 one. A
    /// transparent output's derivation goes through
    /// `Full { is_change_path: true }`, which additionally refuses the ZIP 32
    /// form, an account index above
    /// [`MAX_BIP44_ACCOUNT`](crate::limits::MAX_BIP44_ACCOUNT), any scope but
    /// the internal (change) one, and an address index above
    /// [`MAX_BIP44_ADDRESS_INDEX`](crate::limits::MAX_BIP44_ADDRESS_INDEX).
    /// The device answers such a path with `IncorrectData` mid-stream, so it
    /// is refused before the first APDU instead.
    NonCompliantPath {
        /// Which section.
        section: Section,
        /// Index of the record.
        index: usize,
        /// Which rule the path fails, in the firmware's words.
        reason: &'static str,
    },
    /// A transparent `bip32_derivation` names a pubkey its own path does not
    /// derive under [`SessionParams::transparent_account_key`].
    ///
    /// For an input this is the burned approval
    /// [`crate::limits::LimitViolation::DerivationPubkeyMismatch`] does not
    /// cover: that check binds the pubkey to the input's script, this one binds
    /// the path to the pubkey. The device signs with the key it derives at the
    /// path and never compares it with the supplied pubkey (`append_signature`,
    /// `src/handlers/sign_tx.rs` @ `22dc385`; the input parser reads the pubkey
    /// for a log line only), while the `pczt` Signer verifies the signature
    /// against the pubkey. A path moved one address index along, with the
    /// pubkey left alone, therefore streams, is reviewed and approved, and is
    /// refused in [`crate::apply`]. For an output the device does re-derive and
    /// compare, but only mid-stream. Both are refused here, before the first
    /// APDU.
    TransparentKeyMismatch {
        /// Which section the derivation belongs to.
        section: Section,
        /// Index within that section.
        index: usize,
    },
    /// The plan carries a transparent derivation and
    /// [`SessionParams::transparent_account_key`] is `None`, so the check
    /// behind [`SessionError::TransparentKeyMismatch`] cannot run.
    TransparentAccountKeyRequired {
        /// Which section the derivation belongs to.
        section: Section,
        /// Index within that section.
        index: usize,
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
            SessionError::EmptyStream => write!(
                f,
                "internal error: the plan encoded to no APDUs, so no packet would carry the \
                 finished marker and the device would never be asked to review"
            ),
            SessionError::SigningIndexTooLarge { section, index } => write!(
                f,
                "internal error: {section} {index} does not fit the one-byte index a signing \
                 command carries, so the device would be asked to sign a different record"
            ),
            SessionError::UnknownDeviceVersion { version } => write!(
                f,
                "app v{}.{}.{} is newer than any version this crate has been checked against, \
                 and no bounds were chosen for such a version; pass \
                 SessionParams::with_unknown_version_bounds to hold it to the most restrictive \
                 or the most permissive known set",
                version.0, version.1, version.2
            ),
            SessionError::UserRejected { stage } => {
                write!(f, "the user declined on the device during {stage}")
            }
            SessionError::WrongApp { status } => write!(
                f,
                "the device is not running the Zcash app, or not a version that knows this \
                 instruction (status {:#06x})",
                status.to_u16()
            ),
            SessionError::CapsMismatch { expected, found } => write!(
                f,
                "the connected device runs app v{}.{}.{}, and this session was built for \
                 v{}.{}.{}; no transaction data was sent to it — build the session from the \
                 connected device's own capabilities",
                found.version().0,
                found.version().1,
                found.version().2,
                expected.version().0,
                expected.version().1,
                expected.version().2,
            ),
            SessionError::DeviceMismatch { expected, found } => write!(
                f,
                "the connected device ({found}) is not the one this session was built for \
                 ({expected}); no transaction data was sent to it"
            ),
            SessionError::Device { stage, status } => write!(
                f,
                "the device refused the command during {stage} with status {status:?} \
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
            SessionError::AccountMismatch { section, index } => write!(
                f,
                "{section} {index} carries a derivation path for an account other than the \
                 one this session signs for; the device would collect this as a refusal only \
                 after the user approves the review"
            ),
            SessionError::NonCompliantPath {
                section,
                index,
                reason,
            } => write!(
                f,
                "{section} {index} carries a derivation path the firmware would refuse: {reason}"
            ),
            SessionError::TransparentKeyMismatch { section, index } => write!(
                f,
                "{section} {index}'s bip32_derivation path does not derive its pubkey under the \
                 account's transparent key; the device would sign with the key at the path, and \
                 that signature could never be applied"
            ),
            SessionError::TransparentAccountKeyRequired { section, index } => write!(
                f,
                "{section} {index} carries a bip32_derivation, and no transparent account key \
                 was supplied to check its path against (SessionParams::transparent_account_key)"
            ),
        }
    }
}

impl core::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
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
    /// The `GET_FIRMWARE_VERSION` whose reply must derive the session's
    /// [`DeviceCaps`].
    ProbeVersion,
    /// The silent `GET_WALLET_PUBLIC_KEY` at the identity path, whose reply
    /// must hash to the session's [`DeviceIdentity`].
    IdentifyDevice,
    /// A packet of the PCZT payload. The reply is empty, and a reply that is
    /// not ends the session.
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
            StepKind::ProbeVersion | StepKind::IdentifyDevice => Stage::IdentifyingDevice,
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
/// included, so `Debug` shows its length and the signatures alone, and the
/// bytes are wiped when the outcome is dropped; a copy the caller takes out
/// of the [`Zeroizing`] wrapper is the caller's to wipe.
#[derive(Clone, PartialEq, Eq)]
pub struct SignOutcome {
    /// The shaped PCZT with every device signature applied, serialized. Ready
    /// for the downstream Combiner; proving and extraction happen there.
    pub(crate) pczt_with_sigs: Zeroizing<Vec<u8>>,
    /// `(action index, signature)` for the Orchard bundle, in signing order.
    pub(crate) orchard_sigs: Vec<(usize, [u8; SPEND_AUTH_SIG_LEN])>,
    /// The same for the Ironwood bundle.
    pub(crate) ironwood_sigs: Vec<(usize, [u8; SPEND_AUTH_SIG_LEN])>,
    /// `(input index, reply)` for each transparent input, as the device
    /// returned it — DER blob and sighash byte kept apart but not normalized.
    pub(crate) transparent_sigs: Vec<(usize, TransparentSignature)>,
}

impl core::fmt::Debug for SignOutcome {
    // Counts only: a signature appears verbatim on chain once the transaction
    // is mined, so a logged one joins the log line to the transaction.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignOutcome")
            .field(
                "pczt_with_sigs",
                &format_args!("[{} bytes]", self.pczt_with_sigs.len()),
            )
            .field(
                "orchard_sigs",
                &format_args!("[{} signatures]", self.orchard_sigs.len()),
            )
            .field(
                "ironwood_sigs",
                &format_args!("[{} signatures]", self.ironwood_sigs.len()),
            )
            .field(
                "transparent_sigs",
                &format_args!("[{} signatures]", self.transparent_sigs.len()),
            )
            .finish()
    }
}

impl SignOutcome {
    /// The PCZT with every device signature applied, serialized; wiped on
    /// drop.
    pub fn pczt_with_sigs(&self) -> &[u8] {
        &self.pczt_with_sigs
    }

    /// `(action index, signature)` for each Orchard action the device signed.
    ///
    /// The signatures are plain byte arrays, which `Debug` prints in full;
    /// each appears verbatim on chain once the transaction is mined, so a
    /// logged slice joins the log line to the transaction.
    pub fn orchard_sigs(&self) -> &[(usize, [u8; SPEND_AUTH_SIG_LEN])] {
        &self.orchard_sigs
    }

    /// The same for the Ironwood bundle, with the same caution about logging.
    pub fn ironwood_sigs(&self) -> &[(usize, [u8; SPEND_AUTH_SIG_LEN])] {
        &self.ironwood_sigs
    }

    /// `(input index, signature)` for each transparent input, as the device
    /// returned it. [`TransparentSignature`]'s `Debug` shows the blob's length
    /// only.
    pub fn transparent_sigs(&self) -> &[(usize, TransparentSignature)] {
        &self.transparent_sigs
    }
}

/// What [`LedgerSignSession::next_step`] hands back.
///
/// `Debug` shows the length of a [`PumpStep::Send`] and not its bytes: a
/// `PCZT_ORCHARD_ACTION` packet carries the action's `alpha`, `rcv` and
/// `rseed` and both raw addresses in clear, and this is the one value that
/// crosses the crate boundary on every iteration of a transport loop — the
/// natural thing to log. [`Apdu`] and
/// [`crate::apdu::encode::ShieldedActionRecord`] redact the same bytes for the
/// same reason.
#[derive(Clone, PartialEq, Eq)]
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

impl core::fmt::Debug for PumpStep {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PumpStep::Send(bytes) => write!(f, "Send([{} bytes])", bytes.len()),
            PumpStep::AwaitingReply => f.write_str("AwaitingReply"),
            PumpStep::Done => f.write_str("Done"),
        }
    }
}

/// A PCZT signing ceremony against one Ledger device.
///
/// `Debug` reports where the ceremony is and nothing of the PCZT: the shaped
/// PCZT, the plan and the queued APDUs all carry the transaction's secrets,
/// and a session is exactly the kind of value an embedding logs on failure.
pub struct LedgerSignSession {
    shaped: Pczt,
    plan: Plan,
    /// The app version the session was validated against; the first command
    /// checks it.
    caps: DeviceCaps,
    /// The device the session was built for; the second command checks it.
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
            .field("caps", &self.caps)
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

/// Everything [`LedgerSignSession::new`] checks and prepares before it
/// builds the command list: the parameter-free validation, shaping, the plan
/// over the shaped PCZT, path compliance and account binding, the device
/// bounds and the caps.
///
/// # Why the plan is built twice
///
/// The pass before shaping is for attribution, and it is not redundant: it
/// names the fault in the PCZT the caller supplied, while the pass after
/// shaping can only name what survives into the PCZT that is streamed. An
/// Ironwood bundle on a transaction tagged V5 is refused here as
/// [`crate::plan::PlanError::IronwoodOnV5`]; with only the second pass, the
/// same PCZT dies in shaping as `EncodingVersionMismatch`. A transparent
/// input whose derivation does not pay its own script is refused here as
/// [`crate::limits::LimitViolation::DerivationPubkeyMismatch`]; with only the
/// second pass it is a `TransparentKeyMismatch` from the account binding.
///
/// The pass after shaping is not redundant either: shaping stamps derivations
/// and marks the change output, so a PCZT that satisfies every rule as it
/// arrives can break one once shaped — naming a second change output is the
/// case that matters — and it is the shaped bytes that reach the device.
///
/// Both passes are wanted, so both run. The cost is one extra plan build per
/// call, which for a transaction carrying viewing keys is also one extra
/// trial decryption per action.
fn prepare(
    pczt: Pczt,
    caps: &DeviceCaps,
    params: &SessionParams,
) -> Result<(crate::shape::Shaped, Plan), SessionError> {
    // Against the *connected* app's bounds, which is what makes a
    // transaction of eleven actions refused here for a v3.9.2 device and
    // accepted for a v3.9.3 one. A version above the newer firmware pin has
    // no set of its own, and this crate does not choose one on the caller's
    // behalf: either the caller said which bounds such a device is held to,
    // or the session refuses it before the first APDU.
    let bounds = match caps.bounds() {
        Some(bounds) => bounds,
        None => params
            .unknown_version_bounds
            .ok_or(SessionError::UnknownDeviceVersion {
                version: caps.version(),
            })?,
    };
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

    let plan = build_plan_with_keys(shaped.pczt(), params.viewing_keys.as_ref())
        .map_err(|e| SessionError::Validation(vec![LedgerViolation::Plan(e)]))?;

    // Shaping is supposed to have removed every gap; if one survived, the
    // device would answer `IncorrectData` mid-stream.
    if let Some((section, index)) = plan.missing_zip32.first().copied() {
        return Err(SessionError::UnshapedAction { section, index });
    }

    check_path_compliance(
        &plan,
        params.network.coin_type(),
        params.zip32_account,
        params.transparent_account_key.as_ref(),
    )?;

    validate_plan(&plan, &bounds).map_err(|v| {
        SessionError::Validation(v.into_iter().map(LedgerViolation::Limit).collect())
    })?;
    validate_against_caps(plan.stream(), caps).map_err(|v| {
        SessionError::Validation(v.into_iter().map(LedgerViolation::Limit).collect())
    })?;

    Ok((shaped, plan))
}

/// Runs everything [`LedgerSignSession::new`] would refuse on, without
/// building a session: the gate a wallet shows the user before it opens a
/// device.
///
/// This is the full set — [`validate_for_ledger`]'s parameter-free checks,
/// then shaping, the plan over the shaped PCZT, path compliance and account
/// binding, the device bounds and the caps — so a PCZT that passes here is
/// one [`LedgerSignSession::new`] accepts with the same `caps` and `params`.
/// The plan returned is the one the session would stream, with its
/// displayed-output count; the PCZT is cloned to shape it.
///
/// # Errors
///
/// Everything [`LedgerSignSession::new_from_pczt`] refuses at construction,
/// from the same checks: [`SessionError::UnknownDeviceVersion`],
/// [`SessionError::Shape`], [`SessionError::Validation`],
/// [`SessionError::NonCompliantPath`], [`SessionError::AccountMismatch`],
/// [`SessionError::TransparentAccountKeyRequired`] and
/// [`SessionError::TransparentKeyMismatch`].
pub fn preflight(
    pczt: &Pczt,
    caps: DeviceCaps,
    params: &SessionParams,
) -> Result<Plan, SessionError> {
    prepare(pczt.clone(), &caps, params).map(|(_, plan)| plan)
}

impl LedgerSignSession {
    /// [`LedgerSignSession::new_from_pczt`], from serialized PCZT bytes.
    ///
    /// # Errors
    ///
    /// [`SessionError::Parse`] when `bytes` are not a PCZT, then as
    /// [`LedgerSignSession::new_from_pczt`].
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
    /// The PCZT is expected as `zcash_client_backend`'s
    /// `redact_pczt_for_signer(SignerView::Full)` produces it: every field the
    /// device streams, the `pczt` Verifier parses and the `pczt` Signer checks
    /// is present. The batch-signer view (`redact_pczt_for_batch_signer`) is
    /// not an input for this crate — it clears each spend's `fvk`, which the
    /// Signer role needs before it will accept a signature — and is refused
    /// here with [`PlanError::MissingSpendFvk`] rather than at the end of the
    /// ceremony.
    ///
    /// In order: [`validate_for_ledger`] on the PCZT as given, then
    /// [`crate::shape::shape_for_device`], then a fresh plan over the
    /// shaped PCZT (so the stamped derivations are the ones streamed), then
    /// [`validate_plan`] and [`validate_against_caps`], and finally the APDU
    /// queue. No APDU is produced for a plan that cannot succeed.
    ///
    /// The queue opens with two probes, ahead of `PCZT_HEADER`: a
    /// `GET_FIRMWARE_VERSION` that must derive `caps` — the version every
    /// bound above was validated against, which the caller obtained from
    /// [`crate::pairing::device_caps`] and which the session does not take on
    /// trust — and the device identity probe. The ceremony sends nothing of
    /// the transaction until the connected device has answered as that
    /// version and as [`SessionParams::device`].
    ///
    /// # Errors
    ///
    /// As [`preflight`], plus the three the command queue can raise:
    /// [`SessionError::Encode`] when a record cannot be encoded,
    /// [`SessionError::EmptyStream`] when the plan encodes to no APDUs, and
    /// [`SessionError::SigningIndexTooLarge`] when a record index does not fit
    /// a signing command's one-byte index. All three are unreachable after
    /// validation, and are errors rather than panics because this is the
    /// signing path.
    pub fn new_from_pczt(
        pczt: Pczt,
        caps: DeviceCaps,
        params: SessionParams,
    ) -> Result<Self, SessionError> {
        let (shaped, plan) = prepare(pczt, &caps, &params)?;

        let version_probe = get_firmware_version_apdu();
        let identity_probe =
            get_wallet_public_key_apdu(&device_identity_path(params.network), false)
                .map_err(SessionError::Encode)?;
        let steps = build_steps(version_probe, identity_probe, &plan)?;

        Ok(LedgerSignSession {
            shaped: shaped.into_pczt(),
            plan,
            caps,
            device: params.device,
            steps,
            cursor: 0,
            outstanding: None,
            // What step 0 is: no transaction byte goes out before the probes.
            stage: Stage::IdentifyingDevice,
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

    /// The device this session was built for, which the second command checks
    /// the connected device against.
    pub fn device(&self) -> DeviceIdentity {
        self.device
    }

    /// The app version this session was validated against, which the first
    /// command checks the connected device against.
    pub fn caps(&self) -> DeviceCaps {
        self.caps
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
    /// - **`true`** after a user rejection — the user may approve on a second
    ///   pass — and after a device refusal whose status word
    ///   [`StatusWord::is_transient`]: a device condition (`MemoryProblem`, a
    ///   `BadState` from a desynchronized transport, a locked device, a spent
    ///   `0x6901` budget) that clears with the context.
    /// - **`false`** for a device refusal that is a deterministic function of
    ///   what was sent (`IncorrectData`, `WrongP1P2`, `NotEnoughMemorySpace`,
    ///   `ConditionsOfUseNotSatisfied`, …), which a fresh stream of the same
    ///   bytes only repeats — for `ConditionsOfUseNotSatisfied` at the cost of
    ///   another full review, since it is raised by the `PCZT_SIGN_*` commands
    ///   after the user has approved; for `TechnicalProblem`, whose one cause
    ///   that is not a function of the input, the Secure Element's derivation
    ///   drain, lasts until the device is power-cycled, so a restart would
    ///   fail at the same packet after another review; when the device is not
    ///   running the Zcash app; when the reply was malformed (a protocol
    ///   mismatch a retry cannot fix); and for every host-side failure, which
    ///   is deterministic in the input.
    pub fn is_restartable(&self) -> bool {
        match &self.failure {
            None => false,
            Some(SessionError::UserRejected { .. }) => true,
            Some(SessionError::Device { status, .. }) => status.is_transient(),
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

    /// Whether the command at the cursor blocks on the user: the one
    /// [`LedgerSignSession::next_step`] hands out next, or the one already
    /// handed out and awaiting its reply.
    ///
    /// The cursor moves only when a reply is processed, so this stays
    /// `Some(ReviewTransaction)` from the moment the review packet is the
    /// next command until its reply has been absorbed. A UI that polls it
    /// while that exchange is in flight keeps showing "check your device",
    /// which is what it should show.
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
    ///
    /// # One reply per command
    ///
    /// The session takes `rapdu` to be the reply to the command
    /// [`LedgerSignSession::next_step`] last handed out; nothing in a reply
    /// says which command it answers. An embedding that drives the pump over
    /// its own channel — BLE, an async or FFI loop — therefore owns the same
    /// rule the `transport::Transport` implementations keep: if the
    /// exchange that carried the outstanding command failed after the command
    /// went out (a timeout, a frame that would not reassemble), the device's
    /// reply is still coming and no later reply on that channel can be
    /// attributed to a command. Do not hand such a reply here, and do not send
    /// the command again on the same session: drop the session and reopen the
    /// channel. A reply with data where none is expected ends the session
    /// ([`SessionError::Decode`]) as the first sign of a channel one reply
    /// out of step, but only the transport can prevent the step.
    ///
    /// # Errors
    ///
    /// [`SessionError::OutOfOrder`] with no command outstanding;
    /// [`SessionError::Decode`] for a reply that is not the shape the
    /// outstanding command's parser expects; [`SessionError::CapsMismatch`] and
    /// [`SessionError::DeviceMismatch`] when the two probes' replies are not
    /// what the session was built against; and, from the status word,
    /// [`SessionError::UserRejected`], [`SessionError::WrongApp`] and
    /// [`SessionError::Device`] for every other refusal. A `0x6901` is not an
    /// error; see [`SessionStatus::RetrySameApdu`].
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
                // The SDK's refusal carries no data; a body means the reply
                // belongs to another command.
                if !data.is_empty() {
                    return Err(
                        self.fail(SessionError::Decode(DecodeError::UnexpectedLength {
                            what: "0x6901 refusal",
                            expected: 0,
                            got: data.len(),
                        })),
                    );
                }
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
            Some(action) => SessionStatus::AwaitingUserAction { action },
            None => SessionStatus::MoreApdus,
        })
    }

    /// Records the reply data for one command.
    fn absorb(&mut self, kind: StepKind, data: &[u8]) -> Result<(), SessionError> {
        match kind {
            StepKind::ProbeVersion => {
                let version = parse_firmware_version(data).map_err(SessionError::Decode)?;
                let found = DeviceCaps::from_version(version.major, version.minor, version.patch);
                if found != self.caps {
                    return Err(SessionError::CapsMismatch {
                        expected: self.caps,
                        found,
                    });
                }
                Ok(())
            }
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
            StepKind::Stream { .. } => {
                // No PCZT stream handler appends reply data (`handlers/pczt.rs`
                // @ `22dc385`: only the `PCZT_SIGN_*` handlers do), so a body
                // here is the reply to some other command — a transport that
                // mis-attributes replies by one. Left unchecked, that stays
                // invisible from `PCZT_HEADER` to the review packet and
                // surfaces only as a malformed signature reply, after the user
                // has approved.
                if data.is_empty() {
                    Ok(())
                } else {
                    Err(SessionError::Decode(DecodeError::UnexpectedLength {
                        what: "PCZT stream acknowledgement",
                        expected: 0,
                        got: data.len(),
                    }))
                }
            }
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
                // sighash byte for `normalize_ledger_der`, which takes the
                // device's reply as a single buffer.
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
    /// once, whether it succeeds or fails: a second call — like a call before
    /// completion — answers [`SessionError::OutOfOrder`] without disturbing
    /// the session's state, so the accessors ([`LedgerSignSession::plan`],
    /// [`LedgerSignSession::shaped_pczt`], …) keep working afterwards. A
    /// failed apply also ends the session as [`Stage::Failed`], with the
    /// [`SessionError::Apply`] as its [`LedgerSignSession::failure`]: the
    /// signatures it holds cannot be applied, and running the apply again
    /// over the same clone of the PCZT could only fail the same way.
    ///
    /// # Errors
    ///
    /// [`SessionError::OutOfOrder`] before the session is complete, and on a
    /// second call; [`SessionError::Apply`] when a signature the device
    /// returned does not verify or cannot be applied.
    pub fn finish(&mut self) -> Result<SignOutcome, SessionError> {
        if self.stage != Stage::Complete || self.finished {
            return Err(SessionError::OutOfOrder);
        }
        // Latched before the apply runs, so that a failed apply is not run
        // again — over another unwiped clone of the shaped PCZT — by a
        // second call.
        self.finished = true;

        // The device returns the DER blob and the sighash byte separately, but
        // `normalize_ledger_der` takes the whole reply as a single buffer, so
        // the byte is re-appended before it runs.
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

        let pczt_with_sigs =
            match apply_device_signatures_to_bytes(self.shaped.clone(), &signatures) {
                Ok(bytes) => Zeroizing::new(bytes),
                Err(e) => return Err(self.fail(SessionError::Apply(e))),
            };

        Ok(SignOutcome {
            pczt_with_sigs,
            orchard_sigs: self.signatures.orchard.clone(),
            ironwood_sigs: self.signatures.ironwood.clone(),
            transparent_sigs: self.transparent_sigs.clone(),
        })
    }
}

/// The mode a derivation path is checked under.
///
/// `check_bip44_compliance` (`src/utils.rs` @ `22dc385`) takes a
/// `Bip44CheckMode` saying how strict the check is, and which mode a path gets
/// depends on where in the PCZT it was found. `Bip44CheckMode` is a firmware
/// type with no counterpart in this crate, so its variants are named here in
/// prose rather than linked; this enum is the host-side mirror of the choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathRule {
    /// A variant indicating that the path should be validated using
    /// `Bip44CheckMode::OnlyCoinType`, the mode every signing path — a
    /// transparent input's or a shielded action's — is parsed under.
    SigningPath,
    /// A variant indicating that the path should be validated using
    /// `Bip44CheckMode::Full { is_change_path: true }`, the mode a transparent
    /// *output*'s derivation is parsed under
    /// (`finish_transparent_output_bip32_derivation`,
    /// `src/parser/pczt/transparent.rs`).
    ///
    /// On top of the signing-path rules it requires the five-component BIP 44
    /// form (a ZIP 32 shape is refused outright), an account index at most
    /// [`MAX_BIP44_ACCOUNT`](crate::limits::MAX_BIP44_ACCOUNT), the internal
    /// (change) scope, and an address index at most
    /// [`MAX_BIP44_ADDRESS_INDEX`](crate::limits::MAX_BIP44_ADDRESS_INDEX).
    ChangeOutput,
}

/// Why one derivation path fails the firmware's `check_bip44_compliance` under
/// `rule`, or `None` if it passes.
///
/// Mirrors `src/utils.rs` @ `22dc385`. Under [`PathRule::SigningPath`]:
/// hardened purpose (`44'` for the five-component transparent form, `32'` for
/// the three-component shielded one), hardened coin type equal to the app
/// build's, hardened account. Purpose and coin type are compared with the
/// hardening bit *included*, for the firmware's own reason: an unhardened
/// prefix is a path the OS refuses to derive by taking the app down rather
/// than by a status word. [`PathRule::ChangeOutput`] adds the four rules its
/// docs list, in the firmware's order.
pub(crate) fn path_compliance_error(
    path: &[u32],
    coin_type: u32,
    rule: PathRule,
) -> Option<&'static str> {
    match path.len() {
        3 => {
            if rule == PathRule::ChangeOutput {
                Some(
                    "a change output's path must be the five-component BIP 44 form; the \
                     firmware refuses the three-component ZIP 32 form there",
                )
            } else if path[0] != crate::shape::ZIP32_PURPOSE | HARDENED {
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
            } else if rule == PathRule::SigningPath {
                None
            } else if path[2] & !HARDENED > crate::limits::MAX_BIP44_ACCOUNT {
                Some(
                    "a change output's account index must be at most 100 \
                     (MAX_BIP44_ACCOUNT_RECOMMENDED)",
                )
            } else if path[3] != crate::shape::TRANSPARENT_INTERNAL_SCOPE {
                Some(
                    "a change output's path must be on the internal (change) chain, scope 1; \
                     the firmware cannot present an external- or ephemeral-chain output as \
                     change",
                )
            } else if path[4] > crate::limits::MAX_BIP44_ADDRESS_INDEX {
                Some(
                    "a change output's address index must be at most 50000 \
                     (MAX_BIP44_ADDRESS_INDEX_RECOMMENDED)",
                )
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
///
/// Transparent derivations get a third check that no firmware runs for
/// inputs: with the account's transparent key, the pubkey each path derives
/// must be the pubkey the derivation names — see
/// [`SessionError::TransparentKeyMismatch`]. It runs after the two above, so a
/// path that is wrong in a way the firmware would name is reported that way.
fn check_path_compliance(
    plan: &Plan,
    coin_type: u32,
    zip32_account: AccountId,
    transparent_key: Option<&TransparentAccountKey>,
) -> Result<(), SessionError> {
    let expected = u32::from(zip32_account) | HARDENED;

    let check = |section: Section, index: usize, path: &[u32]| {
        let rule = match section {
            Section::TransparentOutput => PathRule::ChangeOutput,
            _ => PathRule::SigningPath,
        };
        if let Some(reason) = path_compliance_error(path, coin_type, rule) {
            return Err(SessionError::NonCompliantPath {
                section,
                index,
                reason,
            });
        }
        if derivation_account(path) == Some(expected) {
            Ok(())
        } else {
            Err(SessionError::AccountMismatch { section, index })
        }
    };

    // The path names the account (checked above) and then a `scope/index`
    // pair; the key at that pair must be the pubkey the derivation carries. A
    // path of any other depth derives no address key at all.
    let bind = |section: Section, index: usize, derivation: &TransparentDerivation| {
        let Some(key) = transparent_key else {
            return Err(SessionError::TransparentAccountKeyRequired { section, index });
        };
        let derived = match derivation.path.0.as_slice() {
            [_, _, _, scope, address_index] => NonHardenedChildIndex::from_index(*address_index)
                .and_then(|address_index| key.address_pubkey(*scope, address_index)),
            _ => None,
        };
        if derived == Some(derivation.pubkey) {
            Ok(())
        } else {
            Err(SessionError::TransparentKeyMismatch { section, index })
        }
    };

    for (index, input) in plan.stream().transparent_inputs.iter().enumerate() {
        check(Section::TransparentInput, index, &input.derivation.path.0)?;
        bind(Section::TransparentInput, index, &input.derivation)?;
    }
    for (index, output) in plan.stream().transparent_outputs.iter().enumerate() {
        if let Some(derivation) = &output.derivation {
            check(Section::TransparentOutput, index, &derivation.path.0)?;
            bind(Section::TransparentOutput, index, derivation)?;
        }
    }
    for (index, action) in plan.stream().orchard_actions.iter().enumerate() {
        check(Section::Orchard, index, &action.zip32_derivation.path.0)?;
    }
    for (index, action) in plan.stream().ironwood_actions.iter().flatten().enumerate() {
        check(Section::Ironwood, index, &action.zip32_derivation.path.0)?;
    }

    Ok(())
}

/// Builds the full command queue for a plan.
///
/// The two probes go first, before any transaction byte: the version probe,
/// then the identity probe. The signing commands come after the streaming
/// ones, pool by pool, and only for real spends: `orchard_signature_count()`
/// on the device is `orchard_real_spend_count`, so asking for a dummy index
/// would both be refused and push the device's count past its own quota.
fn build_steps(
    version_probe: Apdu,
    identity_probe: Apdu,
    plan: &Plan,
) -> Result<Vec<Step>, SessionError> {
    let stream = plan.stream().to_apdus().map_err(SessionError::Encode)?;
    let last = stream
        .len()
        .checked_sub(1)
        .ok_or(SessionError::EmptyStream)?;

    let mut steps = vec![
        Step {
            apdu: version_probe,
            kind: StepKind::ProbeVersion,
        },
        Step {
            apdu: identity_probe,
            kind: StepKind::IdentifyDevice,
        },
    ];
    steps.extend(stream.into_iter().enumerate().map(|(i, apdu)| Step {
        apdu,
        kind: StepKind::Stream {
            finished_marker: i == last,
        },
    }));

    for &index in &plan.orchard_real_spends {
        steps.push(Step {
            apdu: sign_shielded_apdu(
                ShieldedPool::Orchard,
                signing_index(Section::Orchard, index)?,
            ),
            kind: StepKind::SignOrchard(index),
        });
    }
    for &index in &plan.ironwood_real_spends {
        steps.push(Step {
            apdu: sign_shielded_apdu(
                ShieldedPool::Ironwood,
                signing_index(Section::Ironwood, index)?,
            ),
            kind: StepKind::SignIronwood(index),
        });
    }
    for index in 0..plan.stream().transparent_inputs.len() {
        steps.push(Step {
            apdu: sign_transparent_apdu(signing_index(Section::TransparentInput, index)?),
            kind: StepKind::SignTransparent(index),
        });
    }

    Ok(steps)
}

/// Narrows a record index to the one-byte index a `PCZT_SIGN_*` command
/// carries it in.
///
/// The bounds make the narrowing infallible, so this is a tripwire rather than
/// a check the caller has to reason about: the device resolves the index
/// itself, and a truncated one would have it sign a record other than the one
/// the host files the signature under.
fn signing_index(section: Section, index: usize) -> Result<u8, SessionError> {
    u8::try_from(index).map_err(|_| SessionError::SigningIndexTooLarge { section, index })
}

#[cfg(test)]
mod tests;
