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
//! v3.9.3 (`22dc385`) raised three of the four record bounds, so a single
//! set of constants would be wrong for one firmware or the other. v3.9.4
//! (`1a0f649`) kept v3.9.3's bounds and fixed how the review hashes a memo it
//! cannot show as text; [`DeviceBounds::hashed_memo_review`] carries that
//! difference.
//! [`DeviceBounds`] carries one set, [`DeviceBounds::for_caps`] picks the
//! set for a reported version, and [`validate_records`] takes the set rather
//! than reading a constant. The two review budgets v3.9.3 added are the one
//! thing every set shares: the firmware that lacks them exits the app when
//! the review it was sent does not fit, so the host holds every version to
//! them (see [`DeviceBounds::displayed_shielded_outputs`]).
//!
//! A version this crate has not been checked against has no set of its own:
//! [`DeviceBounds::for_caps`] answers `None` rather than picking one, and the
//! caller says which bounds such a device is held to.
//! [`DeviceBounds::MOST_RESTRICTIVE`] is the conservative choice — the
//! strictest combination of every known set, which refuses host-side any
//! count a known app would refuse mid-stream — and
//! [`DeviceBounds::MOST_PERMISSIVE`] is the other. Neither is the newer app's
//! own set: an app that lowers a bound below every known set refuses,
//! mid-stream, a plan either of them passes.
//!
//! This module validates a [`StreamPlan`] — counts, script shapes, field
//! widths, version coherence. The *PCZT-level* checks (that the records agree
//! with the PCZT they came from) belong to the session layer.

use alloc::vec::Vec;

use crate::apdu::encode::{
    BundleTrailerRecord, ShieldedActionRecord, StreamPlan, TransparentInputRecord,
    TransparentOutputRecord, TxFormat, MAX_PATH_COMPONENTS, NOTE_VERSION_IRONWOOD, PCZT_VERSION_V5,
    PCZT_VERSION_V6, SIGHASH_ALL,
};
use zcash_protocol::consensus::NetworkType;

/// `MAX_PCZT_TRANSPARENT_OUTPUTS_NUMBER` — unchanged across every supported
/// app version; also carried in [`DeviceBounds`] for uniformity.
pub const MAX_TRANSPARENT_OUTPUTS: usize = 10;

/// `MAX_PCZT_SHIELDED_DISPLAYED_OUTPUTS_NUMBER` — the shielded outputs one
/// transaction may put on the review screen, across both shielded pools
/// (`src/consts.rs` @ `22dc385`: "half the count the device was measured to
/// survive, so the budget holds even with memo retention and address
/// encoding at their worst"). New in v3.9.3, and applied by this crate on
/// every version; see [`DeviceBounds::displayed_shielded_outputs`].
pub const MAX_DISPLAYED_SHIELDED_OUTPUTS: usize = 4;

/// `MAX_RETAINED_MEMO_BYTES` — the bytes of memo text one transaction may keep
/// for its review, across both shielded pools (`src/parser/pczt.rs` @
/// `22dc385`, "set to hold two maximum-length memos verbatim"). New in v3.9.3,
/// and applied by this crate on every version; see
/// [`DeviceBounds::retained_memo_bytes`] for the rule.
pub const MAX_RETAINED_MEMO_BYTES: usize = 1024;

/// The change outputs every known app version accepts in one transaction,
/// across every pool together; see [`DeviceBounds::change_outputs`].
pub const MAX_CHANGE_OUTPUTS: usize = 1;

/// `MEMO_HASH_DISPLAY_LEN` — what a memo rendered as its hash retains: 64
/// hex characters (`src/parser/pczt.rs` @ `22dc385`).
pub const MEMO_HASH_DISPLAY_LEN: usize = 64;

/// The record bounds one app version enforces.
///
/// Each bound is the largest count `src/parser/pczt/*.rs` accepts at the
/// section's count packet; a bundle declaring more is refused there, before
/// any per-record field is read (`docs/PCZT_APDU.md` @ `22dc385`).
///
/// The only values are the named sets below and what [`DeviceBounds::for_caps`]
/// picks among them: a set no firmware enforces cannot be built, so every
/// record index a signing command carries is inside the one byte it has room
/// for (see [`crate::session::SessionError::SigningIndexTooLarge`], the
/// tripwire that says so).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceBounds {
    /// `MAX_PCZT_TRANSPARENT_INPUTS_NUMBER`.
    pub(crate) transparent_inputs: usize,
    /// `MAX_PCZT_TRANSPARENT_OUTPUTS_NUMBER`.
    pub(crate) transparent_outputs: usize,
    /// `MAX_PCZT_ORCHARD_ACTIONS_NUMBER`.
    pub(crate) orchard_actions: usize,
    /// `MAX_PCZT_IRONWOOD_ACTIONS_NUMBER`.
    pub(crate) ironwood_actions: usize,
    /// `MAX_PCZT_SHIELDED_DISPLAYED_OUTPUTS_NUMBER`, counted across *both*
    /// shielded pools.
    ///
    /// The budget exists in the firmware from v3.9.3, and this crate applies
    /// it on every version, because an app without it has nothing in its
    /// place: every displayed output holds an encoded address, an output
    /// record and its review fields for as long as the review is on screen,
    /// and the allocation the heap cannot serve is not a status word but a
    /// panic, whose handler exits the app (`src/main.rs` @ `0e048bb`,
    /// `panic_handler`; `src/consts.rs` and `src/parser/pczt.rs` @ `22dc385`
    /// on why the budgets were added). The budget is half the count the
    /// device was measured to survive, so holding a v3.9.2 app to it is what
    /// keeps that app from being taken down by the review it was sent.
    ///
    /// See [`crate::plan::Plan::displayed_shielded_outputs`] for what the host
    /// can and cannot count against it.
    pub(crate) displayed_shielded_outputs: usize,
    /// `MAX_RETAINED_MEMO_BYTES`, the memo retention budget across both
    /// shielded pools, applied on every version for the reason
    /// [`DeviceBounds::displayed_shielded_outputs`] gives.
    ///
    /// `memo_display` (`src/parser/pczt.rs` @ `22dc385`) runs for every
    /// displayed output, in stream order: an empty memo retains nothing; a
    /// printable-ASCII memo that fits what is left of the budget retains its
    /// length; anything else retains [`MEMO_HASH_DISPLAY_LEN`] for its hash,
    /// and when even that does not fit the device refuses with
    /// `NotEnoughMemorySpace` mid-stream. A v3.9.2 app renders memos the same
    /// way but keeps a text memo whole where v3.9.3 would hash it. Under a
    /// display budget of [`MAX_DISPLAYED_SHIELDED_OUTPUTS`] the first two
    /// memos always fit this budget, so only the third and the fourth can be
    /// kept whole where the host counted a hash, each by up to a 512-byte
    /// memo less [`MEMO_HASH_DISPLAY_LEN`]: v3.9.2 retains at most 896 bytes
    /// more than the host counted for it. The
    /// host can only run the accounting with the account's viewing keys,
    /// which is what recovers the memos; see
    /// [`crate::plan::Plan::displayed_memos`].
    pub(crate) retained_memo_bytes: usize,
    /// Whether the app shows a memo it cannot render as text as the correct
    /// BLAKE2b-256 digest of the memo field.
    ///
    /// `memo_display` renders a memo as text only when every byte is printable
    /// ASCII and it fits what is left of the retention budget; anything else —
    /// a line break, a tab, an emoji, any non-ASCII byte, a lead byte above the
    /// text tag, or text past the budget — is shown as a hash. Up to v3.9.3
    /// that hash is taken with `Blake2b_256::default()`, a context the app
    /// never initializes (`src/parser/pczt.rs` @ `22dc385`,
    /// `src/parser/pczt/orchard.rs` @ `0e048bb`), so what the review shows, if
    /// it gets that far, is not the memo's digest. v3.9.4 initializes it
    /// (`c07c46e`, "fix(pczt): initialize the memo hasher before use").
    ///
    /// When this is `false`, a plan built with the account's viewing keys is
    /// refused before the first APDU if any displayed memo would reach the hash
    /// ([`LimitViolation::HashedMemoUnsupported`]). Without the keys the memos
    /// cannot be recovered, so such a plan is streamed and the app's hashing
    /// is the user's only view of the memo.
    pub(crate) hashed_memo_review: bool,
    /// The change outputs one transaction may carry, across every pool
    /// together.
    ///
    /// One on every known version: `TxInfo::is_change_found` is cleared when
    /// the transparent output count arrives and set by the change branch of
    /// the transparent, Orchard and Ironwood parsers alike, and the second
    /// change output the device meets is refused mid-stream with `"Multiple
    /// change outputs detected"` (`finish_transparent_output`,
    /// `push_deciphered_orchard_output` and `push_deciphered_ironwood_output`,
    /// the same at `0e048bb`, `22dc385` and `1a0f649`). A firmware that
    /// raises it gets a set saying so when the pin moves.
    ///
    /// A wallet that splits change across several notes reads this before it
    /// builds the transaction, from the bounds of the version the device
    /// reports, and splits into no more notes than it allows. See
    /// [`LimitViolation::TooManyChangeOutputs`] for the check.
    pub(crate) change_outputs: usize,
    /// Whether the app accepts the NU7 consensus branch id (`0x77190AD9`).
    ///
    /// No known version does. Every supported app links `zcash_protocol`
    /// 0.10.4 (`Cargo.lock` at `0e048bb`, `22dc385` and `1a0f649`), where
    /// `BranchId::Nu7` exists only under `cfg(zcash_unstable = "nu7")`, which
    /// the app's build does not set, so `parse_global`'s `BranchId::try_from`
    /// refuses the id at the header. This crate's `zcash_protocol` 0.11
    /// accepts it unconditionally, so without this the refusal would come from
    /// the device instead of before the first APDU. See
    /// [`LimitViolation::BranchIdUnsupportedByDevice`].
    pub(crate) nu7_branch: bool,
}

impl DeviceBounds {
    /// `MAX_PCZT_TRANSPARENT_INPUTS_NUMBER`.
    pub const fn transparent_inputs(&self) -> usize {
        self.transparent_inputs
    }

    /// `MAX_PCZT_TRANSPARENT_OUTPUTS_NUMBER`.
    pub const fn transparent_outputs(&self) -> usize {
        self.transparent_outputs
    }

    /// `MAX_PCZT_ORCHARD_ACTIONS_NUMBER`.
    pub const fn orchard_actions(&self) -> usize {
        self.orchard_actions
    }

    /// `MAX_PCZT_IRONWOOD_ACTIONS_NUMBER`.
    pub const fn ironwood_actions(&self) -> usize {
        self.ironwood_actions
    }

    /// `MAX_PCZT_SHIELDED_DISPLAYED_OUTPUTS_NUMBER`, counted across both
    /// shielded pools and applied on every app version.
    pub const fn displayed_shielded_outputs(&self) -> usize {
        self.displayed_shielded_outputs
    }

    /// `MAX_RETAINED_MEMO_BYTES`, the memo retention budget across both
    /// shielded pools, applied on every app version.
    pub const fn retained_memo_bytes(&self) -> usize {
        self.retained_memo_bytes
    }

    /// Whether the app shows a hashed memo as its correct digest; see
    /// [`LimitViolation::HashedMemoUnsupported`] for what `false` refuses.
    pub const fn hashed_memo_review(&self) -> bool {
        self.hashed_memo_review
    }

    /// The change outputs one transaction may carry, across every pool
    /// together: how many notes a wallet may split its change into. One on
    /// every known version; see [`LimitViolation::TooManyChangeOutputs`].
    pub const fn change_outputs(&self) -> usize {
        self.change_outputs
    }

    /// Whether the app accepts the NU7 consensus branch id; `false` on every
    /// known version. See [`LimitViolation::BranchIdUnsupportedByDevice`].
    pub const fn nu7_branch(&self) -> bool {
        self.nu7_branch
    }

    /// v3.6.0 through v3.9.2: ten of everything (`src/consts.rs` @
    /// `0e048bb`, all four "due to device memory constraints"), and the two
    /// review budgets the app itself does not have.
    ///
    /// Without them an app of this line holds every displayed output's
    /// address and memo for the review with no bound but the heap, and the
    /// allocation it cannot serve exits the app instead of answering a status
    /// word. The budgets are the envelope the same hardware was measured to
    /// survive, so they are applied here as well; see
    /// [`DeviceBounds::displayed_shielded_outputs`]. Its memo hash is taken
    /// with an uninitialized context; see
    /// [`DeviceBounds::hashed_memo_review`].
    pub const V3_9_2: DeviceBounds = DeviceBounds {
        transparent_inputs: 10,
        transparent_outputs: MAX_TRANSPARENT_OUTPUTS,
        orchard_actions: 10,
        ironwood_actions: 10,
        displayed_shielded_outputs: MAX_DISPLAYED_SHIELDED_OUTPUTS,
        retained_memo_bytes: MAX_RETAINED_MEMO_BYTES,
        hashed_memo_review: false,
        change_outputs: MAX_CHANGE_OUTPUTS,
        nu7_branch: false,
    };

    /// v3.9.3.
    ///
    /// `src/consts.rs` @ `22dc385`: the transparent-input bound became 32
    /// ("32 inputs parse, review and sign on Nano X, with the run failing well
    /// above"), both shielded bounds became 32, the transparent-output bound
    /// stayed at 10, and `MAX_PCZT_SHIELDED_DISPLAYED_OUTPUTS_NUMBER = 4`
    /// appeared to bound the *review* separately from the spend — which is
    /// what let the action bounds rise at all. `src/parser/pczt.rs` added the
    /// memo retention budget, [`MAX_RETAINED_MEMO_BYTES`], for the same
    /// reason. Its memo hash is still taken with an uninitialized context;
    /// see [`DeviceBounds::hashed_memo_review`].
    pub const V3_9_3: DeviceBounds = DeviceBounds {
        transparent_inputs: 32,
        transparent_outputs: MAX_TRANSPARENT_OUTPUTS,
        orchard_actions: 32,
        ironwood_actions: 32,
        displayed_shielded_outputs: MAX_DISPLAYED_SHIELDED_OUTPUTS,
        retained_memo_bytes: MAX_RETAINED_MEMO_BYTES,
        hashed_memo_review: false,
        change_outputs: MAX_CHANGE_OUTPUTS,
        nu7_branch: false,
    };

    /// v3.9.4, the firmware pin.
    ///
    /// v3.9.3's record bounds and review budgets, unchanged: between
    /// `22dc385` and `1a0f649` neither `src/consts.rs` nor any parser but
    /// `memo_display` moved. The one runtime change is that the memo hash is
    /// taken with an initialized context, so a hashed memo is reviewable; see
    /// [`DeviceBounds::hashed_memo_review`].
    pub const V3_9_4: DeviceBounds = DeviceBounds {
        transparent_inputs: 32,
        transparent_outputs: MAX_TRANSPARENT_OUTPUTS,
        orchard_actions: 32,
        ironwood_actions: 32,
        displayed_shielded_outputs: MAX_DISPLAYED_SHIELDED_OUTPUTS,
        retained_memo_bytes: MAX_RETAINED_MEMO_BYTES,
        hashed_memo_review: true,
        change_outputs: MAX_CHANGE_OUTPUTS,
        nu7_branch: false,
    };

    /// The strictest set any supported app is held to.
    ///
    /// The strictest combination of every known set, deliberately: the
    /// smallest count of each kind, the smallest of each budget, and no
    /// hashed memo on the review. A plan
    /// validated against it is streamable to *every* app this crate knows,
    /// while the reverse is not true. It promises nothing about an app this
    /// crate does not know: one that lowers a bound below every known set
    /// refuses, mid-stream, a plan this set passes. At the current pins the
    /// combination is [`DeviceBounds::V3_9_2`], number for number; the two are
    /// kept apart because they are chosen for different reasons and need not
    /// stay equal.
    ///
    /// This is one of the two sets a caller chooses between for an app version
    /// this crate has not been checked against, which
    /// [`DeviceBounds::for_caps`] declines to choose for it; the other is
    /// [`DeviceBounds::MOST_PERMISSIVE`].
    pub const MOST_RESTRICTIVE: DeviceBounds = DeviceBounds {
        transparent_inputs: 10,
        transparent_outputs: MAX_TRANSPARENT_OUTPUTS,
        orchard_actions: 10,
        ironwood_actions: 10,
        displayed_shielded_outputs: MAX_DISPLAYED_SHIELDED_OUTPUTS,
        retained_memo_bytes: MAX_RETAINED_MEMO_BYTES,
        hashed_memo_review: false,
        change_outputs: MAX_CHANGE_OUTPUTS,
        nu7_branch: false,
    };

    /// The most permissive set any supported app is held to.
    ///
    /// For the caller that must not refuse before it knows what it is talking
    /// to: a pre-flight check run before `GET_FIRMWARE_VERSION`, whose job is
    /// to catch what *no* firmware would accept. The authoritative,
    /// version-gated check runs afterwards, in
    /// [`crate::session::LedgerSignSession::new`]. The two budgets are the
    /// same on every set, so they are here as well: no app version is sent
    /// more than they allow.
    ///
    /// It is also the other of the two sets a caller chooses between for an
    /// app version this crate has not been checked against — see
    /// [`DeviceBounds::MOST_RESTRICTIVE`], which is the conservative one of the
    /// two.
    pub const MOST_PERMISSIVE: DeviceBounds = DeviceBounds {
        transparent_inputs: 32,
        transparent_outputs: MAX_TRANSPARENT_OUTPUTS,
        orchard_actions: 32,
        ironwood_actions: 32,
        displayed_shielded_outputs: MAX_DISPLAYED_SHIELDED_OUTPUTS,
        retained_memo_bytes: MAX_RETAINED_MEMO_BYTES,
        hashed_memo_review: true,
        change_outputs: MAX_CHANGE_OUTPUTS,
        nu7_branch: false,
    };

    /// The bounds a reported app version enforces, or `None` for a version
    /// this crate has not been checked against.
    ///
    /// Exactly [`MIN_VERSION_MEMO_HASH_FIX`] gets [`DeviceBounds::V3_9_4`] and
    /// exactly [`MIN_VERSION_RAISED_BOUNDS`] gets [`DeviceBounds::V3_9_3`];
    /// anything below that — v3.6.0 through v3.9.2, the versions that share
    /// `0e048bb`'s constants — gets [`DeviceBounds::V3_9_2`]; anything above
    /// v3.9.4 answers `None`. A newer app is *not* assumed to be at least as
    /// permissive, and this crate has not read its constants either, so there
    /// is no set to return: moving the firmware pin is the deliberate step
    /// that gives such a version one.
    ///
    /// Until then the choice belongs to the caller, explicitly:
    /// [`DeviceBounds::MOST_RESTRICTIVE`] to hold the device to what every
    /// known app takes, or [`DeviceBounds::MOST_PERMISSIVE`] to hold it to
    /// what the most permissive known app takes. See
    /// [`crate::session::SessionParams::unknown_version_bounds`] for where a
    /// signing session takes that choice.
    #[must_use]
    pub const fn for_caps(caps: &DeviceCaps) -> Option<DeviceBounds> {
        if version_equals(caps.version, MIN_VERSION_MEMO_HASH_FIX) {
            Some(DeviceBounds::V3_9_4)
        } else if version_equals(caps.version, MIN_VERSION_RAISED_BOUNDS) {
            Some(DeviceBounds::V3_9_3)
        } else if version_at_least(caps.version, MIN_VERSION_RAISED_BOUNDS) {
            None
        } else {
            Some(DeviceBounds::V3_9_2)
        }
    }
}

/// `(major, minor, patch)` equality, in a `const fn` because tuple
/// `PartialEq` is not one.
const fn version_equals(got: (u8, u8, u8), want: (u8, u8, u8)) -> bool {
    got.0 == want.0 && got.1 == want.1 && got.2 == want.2
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

// The transaction versions and version group ids the app accepts
// (`src/consts.rs` @ `22dc385`), re-exported from `zcash_protocol` rather than
// restated so that they cannot drift from the protocol crate. The firmware's
// values are pinned by `apdu::encode::tests::version_constants_match_the_firmware`.
pub use zcash_protocol::constants::{
    V5_TX_VERSION, V5_VERSION_GROUP_ID, V6_TX_VERSION, V6_VERSION_GROUP_ID,
};

/// `MAX_BIP44_ACCOUNT_RECOMMENDED` — the largest account index a transparent
/// change output's derivation path may name.
///
/// `check_bip44_compliance` in `Bip44CheckMode::Full` (`src/utils.rs` @
/// `22dc385`, the same at `0e048bb`), which every transparent *output*
/// derivation is put through (`finish_transparent_output_bip32_derivation`,
/// `src/parser/pczt/transparent.rs`). Signing paths are checked in
/// `OnlyCoinType` mode and are not bound by it, so a shielded-only transaction
/// from a higher account is fine; one with transparent change is refused
/// mid-stream unless it is refused here first.
pub const MAX_BIP44_ACCOUNT: u32 = 100;

/// `MAX_BIP44_ADDRESS_INDEX_RECOMMENDED` — the largest address index a
/// transparent change output's derivation path may name, under the same rule
/// as [`MAX_BIP44_ACCOUNT`]. Read unmasked by the firmware, so a hardened
/// index exceeds it on its own.
pub const MAX_BIP44_ADDRESS_INDEX: u32 = 50_000;

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

    /// The network as the address encodings name it.
    pub const fn network_type(self) -> NetworkType {
        match self {
            Network::Main => NetworkType::Main,
            Network::Test => NetworkType::Test,
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
pub struct UnsupportedNetwork(NetworkType);

impl UnsupportedNetwork {
    /// The network that was refused.
    pub const fn network_type(&self) -> NetworkType {
        self.0
    }
}

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

impl core::error::Error for UnsupportedNetwork {}

impl TryFrom<NetworkType> for Network {
    type Error = UnsupportedNetwork;

    fn try_from(value: NetworkType) -> Result<Self, Self::Error> {
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
/// First app version whose review shows a hashed memo as its correct digest
/// (`c07c46e`, released as `1a0f649`); see
/// [`DeviceBounds::hashed_memo_review`].
pub const MIN_VERSION_MEMO_HASH_FIX: (u8, u8, u8) = (3, 9, 4);

/// What a connected device can do, derived from its reported app version.
///
/// An older app answers an instruction it does not know with
/// `InsNotSupported` (`0x6D00`) and no diagnostic, so the host has to gate on
/// the version it read from `GET_FIRMWARE_VERSION`.
///
/// [`DeviceCaps::from_version`] is the only constructor, so every value is a
/// function of a version: a session takes the caller's caps as the version
/// it *expects*, and its first command reads the connected device's version
/// and refuses to continue on a disagreement
/// ([`crate::session::SessionError::CapsMismatch`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceCaps {
    /// The app version reported by `GET_FIRMWARE_VERSION`.
    pub(crate) version: (u8, u8, u8),
    /// Whether the `PCZT_*` instructions are available.
    pub(crate) pczt: bool,
    /// Whether `PCZT_IRONWOOD_ACTION` / `PCZT_SIGN_IRONWOOD` are available,
    /// i.e. whether a V6 transaction can be signed at all.
    pub(crate) ironwood: bool,
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

    /// The app version, as `(major, minor, patch)`.
    pub const fn version(&self) -> (u8, u8, u8) {
        self.version
    }

    /// Whether the `PCZT_*` instructions are available.
    pub const fn pczt(&self) -> bool {
        self.pczt
    }

    /// Whether the Ironwood pool's instructions are available, i.e. whether a
    /// V6 transaction can be signed at all.
    pub const fn ironwood(&self) -> bool {
        self.ironwood
    }

    /// The record bounds this app version enforces, or `None` for a version
    /// above the newer firmware pin; see [`DeviceBounds::for_caps`] for the
    /// choice `None` leaves to the caller.
    #[must_use]
    pub const fn bounds(&self) -> Option<DeviceBounds> {
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
    /// A transparent output carries no value.
    ///
    /// `check_output_displayable` (`ledger_zcash_crypto/src/transparent_script.rs`,
    /// both pins) answers `CheckDispOutput::None` for `amount == 0` before it
    /// looks at the script, and `finish_transparent_output` turns that into
    /// `"Unsupported transparent output script cannot be safely reviewed"` —
    /// `IncorrectData`, mid-stream, after the inputs have gone out. The rule
    /// is the same class as the script-shape rule above, and is mirrored here
    /// for the same reason.
    ZeroValuedTransparentOutput {
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
    /// More shielded outputs would reach the device's review screen than the
    /// `MAX_PCZT_SHIELDED_DISPLAYED_OUTPUTS_NUMBER` budget allows.
    ///
    /// `claim_displayed_shielded_output` (`src/parser/pczt.rs` @ `22dc385`)
    /// refuses the one past the budget with `NotEnoughMemorySpace`
    /// (`0x6A84`) — mid-stream, at whichever action packet happens to cross
    /// it, taking the transaction context with it. An app before v3.9.3 has
    /// no budget and no refusal: it holds every displayed output for the
    /// review until the heap gives out, and then exits. Counting on the host
    /// turns both into a refusal before the first APDU; see
    /// [`DeviceBounds::displayed_shielded_outputs`].
    ///
    /// `got` is [`crate::plan::Plan::displayed_shielded_outputs`]; `exact`
    /// says whether that is the device's own count or the count of the
    /// nonzero outputs, which the device's can exceed as well as fall short
    /// of.
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
        /// a count over the nonzero outputs, change included, so a refusal
        /// may be one the device would not make, and a pass is no promise — a
        /// zero-valued output the account's OVK opens takes a slot on the
        /// device and none here. See
        /// [`crate::plan::Plan::displayed_shielded_outputs`].
        exact: bool,
    },
    /// The displayed outputs' memos would exhaust the memo retention budget,
    /// [`MAX_RETAINED_MEMO_BYTES`], which a v3.9.3 app refuses mid-stream
    /// with `NotEnoughMemorySpace` (`0x6A84`) at the offending action and an
    /// older app does not bound at all.
    ///
    /// Counted only for a plan built with the account's viewing keys, which
    /// are what recover the memos; see [`DeviceBounds::retained_memo_bytes`]
    /// for the rule and [`crate::plan::Plan::displayed_memos`] for the count.
    MemoRetentionBudgetExceeded {
        /// Which pool the offending output is in.
        section: Section,
        /// Index of the action whose memo does not fit.
        index: usize,
        /// The device's budget.
        max: usize,
    },
    /// A displayed memo would be shown as its hash on an app that computes
    /// that hash with an uninitialized context (every version before v3.9.4;
    /// see [`DeviceBounds::hashed_memo_review`]).
    ///
    /// The memo reaches the hash when it is not all printable ASCII — a line
    /// break, a tab, an emoji, any non-ASCII text, a lead byte above the text
    /// tag — or when it is text that no longer fits the retention budget. The
    /// user would be asked to approve a digest that is not the memo's, if the
    /// app gets as far as showing one. Updating the Ledger Zcash app to v3.9.4
    /// or later removes the refusal; so does a memo of printable ASCII within
    /// the budget.
    ///
    /// Raised only for a plan built with the account's viewing keys, which are
    /// what recover the memos; see [`crate::plan::Plan::displayed_memos`].
    HashedMemoUnsupported {
        /// Which pool the offending output is in.
        section: Section,
        /// Index of the action whose memo would be hashed.
        index: usize,
    },
    /// `consensus_branch_id` is a branch this crate knows and the connected
    /// app does not: NU7 (`0x77190AD9`), on every known version. The app
    /// refuses it at the header APDU (`BranchId::try_from` in `parse_global`,
    /// `src/parser/pczt/common.rs`), so nothing would be signed; this pulls
    /// the refusal before the first APDU. See [`DeviceBounds::nu7_branch`].
    BranchIdUnsupportedByDevice {
        /// The value in the PCZT.
        got: u32,
    },
    /// The transaction carries more change outputs than the connected app
    /// accepts, [`DeviceBounds::change_outputs`], which it refuses mid-stream
    /// with `"Multiple change outputs detected"` at the first one past the
    /// limit — before the review, so nothing is approved, but after every
    /// record before it has been streamed, and as a bare `IncorrectData` the
    /// host cannot tell from any other parse failure.
    ///
    /// The limit is for the whole transaction, across every pool; it is one
    /// on every known version. A wallet whose note-management policy splits
    /// change across several notes produces this, and has to build with no
    /// more change notes than the limit; reading
    /// [`DeviceBounds::change_outputs`] before building is how it avoids
    /// the refusal altogether.
    ///
    /// The transparent half needs no key: an output is change to the device
    /// exactly when it carries a `bip32_derivation`, which is in the plan
    /// (`change_pk_hash` is cleared as every output's script starts, in
    /// `parse_transparent_output_script_start` at both pins, so no output is
    /// classified from another's derivation). The
    /// shielded half is counted only for a plan built with the account's
    /// viewing keys — without them the host cannot tell a shielded change
    /// output from a payment — so `shielded` is `None` for a plan built
    /// without them, and `got` then counts transparent change alone. A refusal
    /// raised without keys is one the device would make too; the keys only
    /// let it be raised for shielded change as well. See
    /// [`crate::plan::Plan::shielded_change_outputs`].
    TooManyChangeOutputs {
        /// Change outputs found, across every pool that could be counted.
        got: usize,
        /// The connected app's limit.
        max: usize,
        /// How many of those are shielded, or `None` when the plan was built
        /// without viewing keys and shielded change could not be counted.
        shielded: Option<usize>,
    },
    /// A transparent output with no `bip32_derivation` pays the same P2PKH
    /// hash as one that carries one: the wallet's own change address, paid
    /// twice, with only one of the two marked.
    ///
    /// The device classifies an output as change from that output's own
    /// derivation alone (`change_pk_hash` is cleared as every output's script
    /// starts, in `parse_transparent_output_script_start` at both pins), so
    /// the unmarked one is displayed as a payment to a third
    /// party — at the wallet's own change address. Marking both is not an
    /// option either: the device refuses the second change output it meets
    /// ([`LimitViolation::TooManyChangeOutputs`]). The host cannot tell such
    /// an output from a payment the user deliberately addressed to their own
    /// change address, and refuses both; the transaction has to be rebuilt
    /// with a single change output.
    UnmarkedChangeOutput {
        /// Index of the output that carries the derivation.
        change: usize,
        /// Index of the unmarked output paying the same hash.
        index: usize,
    },
    /// The transaction's fee is negative: its transparent inputs plus its
    /// shielded value balances are less than its transparent outputs.
    ///
    /// `review_outputs` (`src/parser/pczt/common.rs`, the same at `22dc385`
    /// and `0e048bb`) computes the fee as the transparent input total plus
    /// the Orchard and Ironwood `value_sum`s less the transparent output
    /// total, and refuses a negative one with `IncorrectData` at the packet
    /// carrying `P2_PCZT_FINISHED` — before the review, so no approval is
    /// burnt, but after the whole transaction has been streamed. Every term
    /// is in the plan, so it is refused here first.
    NegativeFee,
    /// The device would have no output to put on the review: no transparent
    /// output, and no shielded output that opens under the account's external
    /// OVK or internal IVK — every shielded output a padding dummy, so the
    /// whole transaction goes to the fee.
    ///
    /// `review_outputs` (`src/parser/pczt/common.rs`, the same at `0e048bb`,
    /// `22dc385` and `1a0f649`) refuses it
    /// with `IncorrectData` at the packet carrying `P2_PCZT_FINISHED`, "No
    /// PCZT outputs to display", after every action's `alpha`, `rcv` and
    /// `rseed` has been streamed. The device's list holds every transparent
    /// output it accepts and every shielded output it could open, change
    /// included, so it is empty exactly when this plan counts no transparent
    /// output, no displayed shielded output and no shielded change.
    ///
    /// Raised only for a plan built with the account's viewing keys, whose
    /// shielded counts are the device's own. Without them the host cannot
    /// tell a zero-valued output the account's OVK opens — which the device
    /// lists — from a padding dummy, so a plan with no nonzero output is
    /// streamed and the device decides. Only a degenerate or tampered PCZT
    /// has this shape; no wallet builds one to spend.
    NoReviewableOutputs,
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
            LimitViolation::ZeroValuedTransparentOutput { index } => write!(
                f,
                "transparent output {index} carries no value, which the device refuses as an \
                 output it cannot safely review"
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
                    Section::TransparentOutput => {
                        "the device would show the wallet's own change as a third-party \
                         recipient"
                    }
                    Section::Orchard | Section::Ironwood => {
                        "internal error: a shielded action carries no bip32_derivation"
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
            LimitViolation::MemoRetentionBudgetExceeded {
                section,
                index,
                max,
            } => write!(
                f,
                "{section} {index}'s memo does not fit what is left of the device's {max}-byte \
                 memo retention budget, which the earlier displayed outputs' memos have used up; \
                 the device refuses it mid-stream. Send fewer or shorter memos in one transaction"
            ),
            LimitViolation::HashedMemoUnsupported { section, index } => write!(
                f,
                "{section} {index}'s memo would be shown on the device as a hash, and apps before \
                 v3.9.4 compute that hash with an uninitialized context, so the review would not \
                 show the memo's digest. Update the Ledger Zcash app to v3.9.4 or later, or send \
                 the memo as printable ASCII"
            ),
            LimitViolation::BranchIdUnsupportedByDevice { got } => write!(
                f,
                "consensus branch id {got:#010x} is not one the connected Ledger Zcash app \
                 accepts; it refuses the transaction at the header"
            ),
            LimitViolation::UnmarkedChangeOutput { change, index } => write!(
                f,
                "transparent output {index} pays the same address as change output {change} \
                 without being marked as change; the device would show the wallet's own change \
                 as a third-party recipient. Rebuild the transaction with a single change output"
            ),
            LimitViolation::TooManyChangeOutputs { got, max, shielded } => {
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
                    "), and the connected app accepts at most {max} across all pools; it refuses \
                     the next one mid-stream with \"Multiple change outputs detected\". Build the \
                     transaction with at most {max} change output(s)."
                )
            }
            LimitViolation::NegativeFee => write!(
                f,
                "the transaction's transparent inputs plus its shielded value balances are less \
                 than its transparent outputs, so its fee is negative, which the device refuses \
                 at the review"
            ),
            LimitViolation::NoReviewableOutputs => write!(
                f,
                "the transaction has no output the device could review: no transparent output, \
                 and every shielded output is padding the account's keys do not open, so its whole \
                 value would go to the fee; the device refuses it after the whole transaction has \
                 been streamed"
            ),
            LimitViolation::IronwoodUnsupported { version, required } => write!(
                f,
                "the connected app is v{}.{}.{}, and the Ironwood pool first appears in \
                 v{}.{}.{}",
                version.0, version.1, version.2, required.0, required.1, required.2,
            ),
        }
    }
}

impl core::error::Error for LimitViolation {}

/// `HASH160(x) = RIPEMD160(SHA256(x))`.
///
/// `zcash_transparent`'s own composition, the one its P2PKH addresses are
/// built from; the function lives here because it is what a P2PKH
/// `scriptPubKey` commits to, and this module is where scripts are checked.
pub fn hash160(bytes: &[u8]) -> [u8; 20] {
    zcash_transparent::util::hash160::hash(bytes)
}

/// The length of the `HASH160` a standard script commits to.
const HASH160_LEN: usize = 20;

/// `REGULAR_OUTPUT_SCRIPT_LEN` in `ledger_zcash_crypto::transparent_script`.
const P2PKH_SCRIPT_LEN: usize = 3 + HASH160_LEN + 2;

/// `REGULAR_OUTPUT_PREFIX`: `OP_DUP OP_HASH160 OP_PUSHBYTES_20`.
const P2PKH_PREFIX: [u8; 3] = [0x76, 0xA9, 0x14];

/// `REGULAR_OUTPUT_POSTFIX`: `OP_EQUALVERIFY OP_CHECKSIG`.
const P2PKH_POSTFIX: [u8; 2] = [0x88, 0xAC];

/// `P2SH_OUTPUT_SCRIPT_LEN` in `ledger_zcash_crypto::transparent_script`.
const P2SH_SCRIPT_LEN: usize = 2 + HASH160_LEN + 1;

/// `P2SH_OUTPUT_PREFIX`: `OP_HASH160 OP_PUSHBYTES_20`.
const P2SH_PREFIX: [u8; 2] = [0xA9, 0x14];

/// `P2SH_OUTPUT_POSTFIX`: `OP_EQUAL`.
const P2SH_POSTFIX: u8 = 0x87;

/// The 20-byte hash of a standard P2PKH `scriptPubKey`, or `None`.
///
/// `OP_DUP OP_HASH160 <20> … OP_EQUALVERIFY OP_CHECKSIG`. Shares its shape test
/// with [`is_p2pkh_script`], which is the same predicate the device applies.
pub fn p2pkh_hash(script: &[u8]) -> Option<[u8; 20]> {
    if is_p2pkh_script(script) {
        let mut hash = [0u8; HASH160_LEN];
        hash.copy_from_slice(&script[P2PKH_PREFIX.len()..P2PKH_PREFIX.len() + HASH160_LEN]);
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
///
/// Byte-exact rather than a call into a general standard-script solver: what
/// the host has to reproduce is the device's refusal, and a predicate that
/// accepted a wider set would let a script through here that the device
/// rejects mid-stream, after the user has begun approving.
pub fn is_p2pkh_script(script: &[u8]) -> bool {
    script.len() == P2PKH_SCRIPT_LEN
        && script[..P2PKH_PREFIX.len()] == P2PKH_PREFIX
        && script[P2PKH_SCRIPT_LEN - P2PKH_POSTFIX.len()..] == P2PKH_POSTFIX
}

/// Whether a script is a standard P2PKH or P2SH `scriptPubKey`.
///
/// - P2PKH: `OP_DUP OP_HASH160 <20> … OP_EQUALVERIFY OP_CHECKSIG` — 25 bytes.
/// - P2SH: `OP_HASH160 <20> … OP_EQUAL` — 23 bytes.
///
/// This is the *output* rule, and it stayed as it was: `docs/PCZT_APDU.md` @
/// `22dc385`, "Output scripts keep accepting P2PKH and P2SH."
pub fn is_standard_output_script(script: &[u8]) -> bool {
    let p2sh = script.len() == P2SH_SCRIPT_LEN
        && script[..P2SH_PREFIX.len()] == P2SH_PREFIX
        && script[P2SH_SCRIPT_LEN - 1] == P2SH_POSTFIX;
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
    if output.value == 0 {
        out.push(LimitViolation::ZeroValuedTransparentOutput { index });
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
            // Not a shielded action; the field is never set.
            (Section::TransparentInput | Section::TransparentOutput, _) => true,
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
/// [`DeviceBounds::MOST_RESTRICTIVE`] for the conservative choice when the
/// version is one this crate has not been checked against.
///
/// Returns every violation found rather than the first, so a caller can report
/// them all at once. An empty result means the plan is streamable as far as
/// this layer can tell. The shielded displayed-output budget is *not* checked
/// here: it is counted from the PCZT rather than from the wire records, so it
/// lives in [`crate::plan::validate_plan`].
///
/// # Errors
///
/// `Err` with every [`LimitViolation`] found, never only the first: the count
/// bounds, the script, sighash and derivation checks on each transparent
/// record, the ciphertext and note-version checks on each shielded action, the
/// trailer rule, the header's version, encoding and coin type, and the sign of
/// the fee.
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
    } else if plan.ironwood_trailer.is_some() {
        // A trailer for a pool the plan does not stream at all: the same
        // violation `check_shielded_bundle` reports for a trailer on an empty
        // bundle, which does not run for a bundle the plan leaves `None`.
        out.push(LimitViolation::TrailerMismatch {
            section: Section::Ironwood,
            actions: 0,
            has_trailer: true,
        });
    }

    // `review_outputs` on the device computes the fee from the four totals it
    // read and refuses a negative one at the review, after the whole
    // transaction has been streamed; every term is in the plan, so the same
    // sum runs here first. A trailer's `value_sum` is checked against its own
    // actions only for a plan `crate::plan::build_plan` produced
    // (`PlanError::ValueSumMismatch`), so this takes each trailer at its word,
    // exactly as the device does.
    let transparent_in: i128 = plan
        .transparent_inputs
        .iter()
        .map(|input| i128::from(input.value))
        .sum();
    let transparent_out: i128 = plan
        .transparent_outputs
        .iter()
        .map(|output| i128::from(output.value))
        .sum();
    // Only the trailers the stream carries: `shielded_action_groups` sends a
    // bundle's trailer with its actions and omits it from an empty bundle, and
    // a V5 plan does not send the Ironwood command at all. A trailer the
    // device never reads pays for nothing on either side, and the shapes that
    // carry one are refused above rather than silently valued here.
    let orchard_trailer = plan
        .orchard_trailer
        .as_ref()
        .filter(|_| !plan.orchard_actions.is_empty());
    let ironwood_trailer = plan.ironwood_trailer.as_ref().filter(|_| {
        plan.ironwood_actions
            .as_deref()
            .is_some_and(|actions| !actions.is_empty())
    });
    let shielded: i128 = [orchard_trailer, ironwood_trailer]
        .into_iter()
        .flatten()
        .map(|trailer| i128::from(trailer.value_sum))
        .sum();
    if transparent_in + shielded - transparent_out < 0 {
        out.push(LimitViolation::NegativeFee);
    }

    if out.is_empty() {
        Ok(())
    } else {
        Err(out)
    }
}

/// Checks a plan against what the connected app version supports.
///
/// # Errors
///
/// `Err` with [`LimitViolation::PcztUnsupported`] when the app predates the
/// PCZT protocol, and [`LimitViolation::IronwoodUnsupported`] for a V6 plan on
/// an app without the Ironwood pool.
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
    if plan.format() == TxFormat::V6 && !caps.ironwood {
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

#[cfg(test)]
mod tests;
