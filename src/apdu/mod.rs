//! APDU layer: constants, command framing and the ≤255-byte chunker.
//!
//! Every constant and rule in this module is pinned to `LedgerHQ/app-zcash`
//! commit `22dc385` (v3.9.3, `develop`). v3.9.2 (`0e048bb`) is still
//! supported; where the two differ, the difference is version-gated through
//! [`crate::limits::DeviceBounds`] rather than recompiled.
//!
//! - `docs/APDU.md` — instruction table, P1/P2 semantics, response shapes.
//! - `docs/PCZT_APDU.md` — PCZT payload framing and the packet-sequence rules.
//! - `src/consts.rs` — the numeric constants, reproduced verbatim below.
//! - `src/main.rs` (`enum AppSW`, `impl TryFrom<ApduHeader> for Instruction`) —
//!   the status words and the exact P1/P2 combinations the device accepts.

use alloc::{vec, vec::Vec};

use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod decode;
pub mod encode;

/// Class byte for every app-specific command.
///
/// `src/consts.rs`: `pub const ZCASH_CLA: u8 = 0xE0;`
pub const CLA: u8 = 0xE0;

/// Maximum `data` bytes in a single APDU.
///
/// `docs/PCZT_APDU.md`: "Every APDU `data` payload MUST be at most 255 bytes."
pub const MAX_APDU_DATA: usize = 255;

/// Instruction bytes, from `src/consts.rs` (only the ones this crate drives).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Ins {
    /// `INS_GET_WALLET_PUBLIC_KEY` — `0x40`.
    ///
    /// Data is one length-prefixed BIP 32 path; P1 is `0x00` (derive with no
    /// screen) or `0x01` (display the transparent address for approval); **P2
    /// must be `0x00`** — `Instruction::try_from` in `src/main.rs` matches the
    /// literal `0` and answers `WrongP1P2` for anything else.
    ///
    /// The path is checked with `Bip44CheckMode::PrefixOnly`
    /// (`handler_get_public_key` @ `22dc385`): only purpose (`44'` or `32'`)
    /// and coin type are constrained, both hardened, at any depth from two
    /// components up. A path outside those prefixes — including a mainnet coin
    /// type on a testnet build — is `IncorrectData` (`0x6A80`), which makes
    /// this command a wrong-build probe as well.
    ///
    /// With `display = false` the handler shows **nothing** and, unlike
    /// `GET_VK`, leaves no status screen behind afterwards
    /// (`show_status_and_home_if_needed` is not reached), so the next command
    /// may be sent immediately. It also derives no Orchard key, so it costs
    /// none of the per-run Orchard derivation budget
    /// ([`crate::pairing::PairingError::DerivationBudgetExhausted`]).
    GetWalletPublicKey = 0x40,
    /// `INS_GET_FIRMWARE_VERSION` — `0xC4`, P1 = P2 = 0, empty data, 8-byte reply.
    GetFirmwareVersion = 0xC4,
    /// `INS_GET_VK` — `0x50`.
    GetVk = 0x50,
    /// `INS_GET_SHIELD_ADDR` — `0x51`.
    GetShieldAddr = 0x51,
    /// `INS_PCZT_HEADER` — `0x52`. Single packet, P1 = P2 = 0.
    PcztHeader = 0x52,
    /// `INS_PCZT_TRANSPARENT_INPUT` — `0x53`.
    PcztTransparentInput = 0x53,
    /// `INS_PCZT_TRANSPARENT_OUTPUT` — `0x54`.
    PcztTransparentOutput = 0x54,
    /// `INS_PCZT_SIGN_TRANSPARENT` — `0x55`. P1 = 0, P2 = input index.
    PcztSignTransparent = 0x55,
    /// `INS_PCZT_ORCHARD_ACTION` — `0x56`.
    PcztOrchardAction = 0x56,
    /// `INS_PCZT_SIGN_ORCHARD` — `0x57`. P1 = 0, P2 = action index.
    PcztSignOrchard = 0x57,
    /// `INS_PCZT_IRONWOOD_ACTION` — `0x58`.
    PcztIronwoodAction = 0x58,
    /// `INS_PCZT_SIGN_IRONWOOD` — `0x59`. P1 = 0, P2 = action index.
    PcztSignIronwood = 0x59,
}

impl Ins {
    /// The raw instruction byte.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// The firmware's name for the instruction: `src/consts.rs` without the
    /// `INS_` prefix.
    pub const fn name(self) -> &'static str {
        match self {
            Ins::GetWalletPublicKey => "GET_WALLET_PUBLIC_KEY",
            Ins::GetFirmwareVersion => "GET_FIRMWARE_VERSION",
            Ins::GetVk => "GET_VK",
            Ins::GetShieldAddr => "GET_SHIELD_ADDR",
            Ins::PcztHeader => "PCZT_HEADER",
            Ins::PcztTransparentInput => "PCZT_TRANSPARENT_INPUT",
            Ins::PcztTransparentOutput => "PCZT_TRANSPARENT_OUTPUT",
            Ins::PcztSignTransparent => "PCZT_SIGN_TRANSPARENT",
            Ins::PcztOrchardAction => "PCZT_ORCHARD_ACTION",
            Ins::PcztSignOrchard => "PCZT_SIGN_ORCHARD",
            Ins::PcztIronwoodAction => "PCZT_IRONWOOD_ACTION",
            Ins::PcztSignIronwood => "PCZT_SIGN_IRONWOOD",
        }
    }
}

impl core::fmt::Display for Ins {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// Bytes of status word at the end of every device response, big-endian.
pub const STATUS_WORD_LEN: usize = 2;

/// How long to wait for the reply to one command.
///
/// The distinction is not a tuning knob: some replies in a ceremony arrive only
/// once a human has pressed a button on the device, and no fixed timeout is
/// correct for those. [`crate::session::LedgerSignSession::next_deadline`]
/// picks the value for a signing ceremony and
/// [`crate::pairing::VkExchange::next_deadline`] for a viewing-key export; a
/// pairing flow maps an address request made with `display` onto
/// [`Deadline::UserReview`] itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deadline {
    /// The transport's configured per-call timeout.
    Normal,
    /// The device is showing a review screen. Wait indefinitely: the only thing
    /// that ends the wait is the user, or unplugging the device.
    UserReview,
}

/// P1 values framing a multi-packet `PCZT_*` command (`src/consts.rs`).
///
/// `docs/PCZT_APDU.md`: "`P1_FIRST`, `P1_NEXT`, and `P1_LAST` frame the APDU
/// packet sequence for one `PCZT_*` command. A one-packet command uses
/// `P1_FIRST`."
pub mod p1 {
    /// `P1_FIRST` — first packet of the command, and the *only* P1 a
    /// single-packet command uses.
    pub const FIRST: u8 = 0x00;
    /// `P1_NEXT` — continuation packet.
    pub const NEXT: u8 = 0x80;
    /// `P1_LAST` — last packet of a multi-packet command.
    pub const LAST: u8 = 0x01;

    /// `P1_GET_VK_FIRST` / `P1_GET_PUBLIC_KEY_NO_DISPLAY` — derive silently.
    pub const NO_DISPLAY: u8 = 0x00;
    /// `P1_GET_PUBLIC_KEY_DISPLAY` — show for user approval before replying.
    pub const DISPLAY: u8 = 0x01;
    /// `P1_GET_VK_CONTINUE` — request the next chunk of a pending VK response.
    pub const GET_VK_CONTINUE: u8 = 0x80;
}

/// P2 values (`src/consts.rs`).
pub mod p2 {
    /// `P2_PCZT_CONTINUE` — more PCZT bundle commands may follow.
    pub const PCZT_CONTINUE: u8 = 0x00;
    /// `P2_PCZT_FINISHED` — last packet of the last bundle command; the device
    /// runs its review and only then accepts signing commands.
    pub const PCZT_FINISHED: u8 = 0x01;

    /// `P2VkMode::Ufvk` — unified full viewing key, as a string response.
    pub const VK_UFVK: u8 = 0x00;
    /// `P2VkMode::OrchardFvk` — raw Orchard FVK bytes.
    pub const VK_ORCHARD_FVK: u8 = 0x01;

    /// The only P2 `INS_GET_WALLET_PUBLIC_KEY` accepts.
    ///
    /// `Instruction::try_from` matches `(INS_GET_WALLET_PUBLIC_KEY, P1_…, 0)`
    /// on the literal zero, so any other value is `WrongP1P2` (`0x6B00`)
    /// before the handler runs.
    pub const WALLET_PUBLIC_KEY: u8 = 0x00;

    /// `P2ShieldedAddrMode::UAddress` — unified address, as a string response.
    pub const ADDR_UNIFIED: u8 = 0x00;
    /// `P2ShieldedAddrMode::OrchardAddress` — raw Orchard address bytes.
    pub const ADDR_ORCHARD: u8 = 0x01;
}

/// Where the `P2_PCZT_FINISHED` marker goes for a bundle command.
///
/// `docs/PCZT_APDU.md`: "`P2_PCZT_FINISHED` is set on the last APDU packet of
/// the **last bundle command**. For V5 transactions this is the last packet of
/// `PCZT_ORCHARD_ACTION`. For V6 transactions this is the last packet of
/// `PCZT_IRONWOOD_ACTION`; the last `PCZT_ORCHARD_ACTION` packet must use
/// `P2_PCZT_CONTINUE` instead."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finish {
    /// Every packet of the command carries `P2_PCZT_CONTINUE`.
    Continue,
    /// The last packet of the command carries `P2_PCZT_FINISHED`.
    Finished,
}

impl Finish {
    /// P2 for the packet at `index` of a command with `total` packets.
    const fn p2_for(self, index: usize, total: usize) -> u8 {
        match self {
            Finish::Finished if index + 1 == total => p2::PCZT_FINISHED,
            _ => p2::PCZT_CONTINUE,
        }
    }
}

/// One command APDU, ready to hand to a transport.
///
/// The data of a `PCZT_ORCHARD_ACTION` packet carries the action's secrets
/// (see [`encode::ShieldedActionRecord`]), so an `Apdu` is wiped on drop and
/// its `Debug` form shows the data's length rather than its bytes.
/// [`Apdu::to_bytes`] hands out a copy the caller owns, and owns the wiping
/// of.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Apdu {
    /// Class byte; always [`CLA`] for this app.
    cla: u8,
    /// Instruction byte.
    ins: u8,
    /// Parameter 1.
    p1: u8,
    /// Parameter 2.
    p2: u8,
    /// Command data, at most [`MAX_APDU_DATA`] bytes: both constructors
    /// bound it, and nothing else can set it, so `Lc` always fits its byte.
    data: Vec<u8>,
}

impl core::fmt::Debug for Apdu {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Apdu")
            .field("cla", &format_args!("{:#04x}", self.cla))
            .field("ins", &format_args!("{:#04x}", self.ins))
            .field("p1", &format_args!("{:#04x}", self.p1))
            .field("p2", &format_args!("{:#04x}", self.p2))
            .field("data", &format_args!("[{} bytes]", self.data.len()))
            .finish()
    }
}

/// A `data` payload longer than [`MAX_APDU_DATA`], which no APDU can carry:
/// the wire form's `Lc` is a single byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApduDataTooLong {
    /// The length supplied.
    got: usize,
}

impl ApduDataTooLong {
    /// The length supplied.
    pub fn got(&self) -> usize {
        self.got
    }
}

impl core::fmt::Display for ApduDataTooLong {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "an APDU data payload holds at most {MAX_APDU_DATA} bytes, got {}",
            self.got
        )
    }
}

impl core::error::Error for ApduDataTooLong {}

impl Apdu {
    /// Builds an APDU for this app's [`CLA`], refusing a `data` payload over
    /// [`MAX_APDU_DATA`] bytes.
    ///
    /// # Errors
    ///
    /// [`ApduDataTooLong`] when `data` is longer than [`MAX_APDU_DATA`] bytes.
    pub fn try_new(ins: Ins, p1: u8, p2: u8, data: Vec<u8>) -> Result<Self, ApduDataTooLong> {
        if data.len() > MAX_APDU_DATA {
            return Err(ApduDataTooLong { got: data.len() });
        }
        Ok(Apdu {
            cla: CLA,
            ins: ins.code(),
            p1,
            p2,
            data,
        })
    }

    /// [`Apdu::try_new`] for callers that guarantee the length bound.
    ///
    /// Every internal call site feeds this from the chunker or from a
    /// fixed-size payload, neither of which can exceed [`MAX_APDU_DATA`]; the
    /// assertion documents that invariant rather than validating input.
    pub(crate) fn new(ins: Ins, p1: u8, p2: u8, data: Vec<u8>) -> Self {
        debug_assert!(
            data.len() <= MAX_APDU_DATA,
            "APDU data payload must be at most {MAX_APDU_DATA} bytes, got {}",
            data.len()
        );
        Apdu {
            cla: CLA,
            ins: ins.code(),
            p1,
            p2,
            data,
        }
    }

    /// Serializes to the wire form `CLA INS P1 P2 Lc [data]`.
    ///
    /// `Lc` is always present, including for the empty-data commands
    /// (`GET_FIRMWARE_VERSION`, the three `PCZT_SIGN_*`, and a `GET_VK`
    /// continuation), which is what the Ledger transport layer expects.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Not a cast: a payload past the bound must never reach the wire
        // with a wrapped `Lc`, and the constructors make one impossible.
        let lc = u8::try_from(self.data.len())
            .expect("Apdu::try_new and Apdu::new bound the data at MAX_APDU_DATA");
        let mut out = Vec::with_capacity(5 + self.data.len());
        out.push(self.cla);
        out.push(self.ins);
        out.push(self.p1);
        out.push(self.p2);
        out.push(lc);
        out.extend_from_slice(&self.data);
        out
    }

    /// The command data, at most [`MAX_APDU_DATA`] bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// The class byte.
    pub fn cla(&self) -> u8 {
        self.cla
    }

    /// The instruction byte.
    pub fn ins(&self) -> u8 {
        self.ins
    }

    /// Parameter 1.
    pub fn p1(&self) -> u8 {
        self.p1
    }

    /// Parameter 2.
    pub fn p2(&self) -> u8 {
        self.p2
    }
}

/// Splits a flat payload into ≤255-byte pieces.
///
/// An empty payload yields a single empty piece: a command always occupies at
/// least one APDU packet.
pub fn chunk_bytes(data: &[u8]) -> Vec<&[u8]> {
    if data.is_empty() {
        return vec![&data[..0]];
    }
    data.chunks(MAX_APDU_DATA).collect()
}

/// Packs *field groups* into APDU packets.
///
/// A "group" is a run of bytes the device's parser must see terminated by an
/// APDU boundary. This is not stylistic: each state handler in
/// `src/parser/pczt/*.rs` ends by asserting the reader is drained — e.g.
/// `parse_transparent_input` returns *"PCZT transparent input scriptPubKey must
/// start in a separate APDU"* when bytes remain after the value, and
/// `ensure_orchard_apdu_group_end` returns *"Unexpected data after PCZT orchard
/// APDU field group"*. So groups are never merged into one packet, and a group
/// longer than 255 bytes is the only thing that ever spans packets.
///
/// Mirrors `docs/PCZT_APDU.md`: "Small neighboring fields may be grouped into
/// one APDU packet. Large `Vec<u8>` fields are sent as their own APDU packet
/// sequence."
///
/// An empty group yields an empty packet, which the device's parse loops do
/// nothing with — except that an empty *last* packet still carries `P1_LAST`
/// and the [`Finish`] marker, so it ends the command like any other. Nothing
/// this crate builds is empty: every group opens with a `CompactSize` or a
/// fixed field.
pub fn pack_groups(groups: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    for group in groups {
        for chunk in chunk_bytes(group) {
            packets.push(chunk.to_vec());
        }
    }
    if packets.is_empty() {
        packets.push(Vec::new());
    }
    packets
}

/// Assigns the P1 sequence and the [`Finish`] P2 marker over packed groups.
///
/// P1 rule (`docs/PCZT_APDU.md`, cross-checked against `Instruction::try_from`
/// in `src/main.rs`, which accepts only `P1_FIRST | P1_NEXT | P1_LAST` on the
/// bundle instructions):
///
/// - one packet → `[P1_FIRST]`
/// - n ≥ 2 packets → `[P1_FIRST, P1_NEXT × (n − 2), P1_LAST]`
///
/// `finish` is meaningful on the shielded bundle commands only: the
/// transparent commands ignore P2 and the crate's encoders pass
/// [`Finish::Continue`] for them.
pub fn chunk_command(ins: Ins, groups: &[Vec<u8>], finish: Finish) -> Vec<Apdu> {
    let packets = pack_groups(groups);
    let total = packets.len();

    packets
        .into_iter()
        .enumerate()
        .map(|(i, data)| {
            // `i == 0` first, so a single-packet command lands on `P1_FIRST`
            // rather than `P1_LAST`.
            let p1 = if i == 0 {
                p1::FIRST
            } else if i + 1 == total {
                p1::LAST
            } else {
                p1::NEXT
            };
            Apdu::new(ins, p1, finish.p2_for(i, total), data)
        })
        .collect()
}

/// How many consecutive `0x6901` replies to one command a pump tolerates.
///
/// `0x6901` means the device SDK's legacy I/O layer dropped the frame while a
/// review was on screen (`docs/APDU.md` @ `22dc385`), which clears as soon as
/// the screen does. A device that keeps refusing is not going to stop, and a
/// pump that keeps asking would hang a wallet daemon with no diagnostic. Both
/// [`crate::session::LedgerSignSession`] and [`crate::pairing::VkExchange`]
/// apply this budget, as does `ceremony::query`.
pub const MAX_CMD_NOT_ACCEPTED_RETRIES: u32 = 32;

/// Status words the device can return: `enum AppSW` in `src/main.rs`, plus
/// the three the device SDK's legacy I/O layer answers on the app's behalf
/// ([`StatusWord::CmdNotAccepted`], [`StatusWord::DeviceLocked`],
/// [`StatusWord::AppPanicked`]).
///
/// Three `AppSW` words are defined and never emitted at `22dc385`
/// ([`StatusWord::SecurityStatusNotSatisfied`], [`StatusWord::TxParsingFail`],
/// [`StatusWord::MemoryProblem`]); they are kept so that a future app that
/// does emit them is not an [`StatusWord::Unknown`]. Anything else surfaces as
/// that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusWord {
    /// `0x9000` — success.
    Ok,
    /// `0x6985` — `AppSW::Deny`, the user rejected the review or the address.
    ///
    /// Note the app's own comment: 0x6985 is *user denial* here, and the ISO
    /// "conditions of use not satisfied" meaning moved to the adjacent
    /// [`StatusWord::ConditionsOfUseNotSatisfied`] (`0x6986`).
    Deny,
    /// `0x6986` — `AppSW::ConditionsOfUseNotSatisfied`: the request
    /// contradicts what the user approved. Chiefly a change output bound to an
    /// account other than the one being spent
    /// (`check_change_returns_to_signing_account`, run by every command that
    /// releases a signature — `docs/APDU.md` @ `22dc385`); also a signing
    /// command that arrives before the PCZT was finished and reviewed.
    ConditionsOfUseNotSatisfied,
    /// `0x6A80` — `AppSW::IncorrectData`: payload rejected by the parser.
    IncorrectData,
    /// `0x6A84` — `AppSW::NotEnoughMemorySpace`: a device-side budget ran
    /// out. Three on v3.9.3:
    ///
    /// - the displayed-output budget, which [`crate::plan::validate_plan`]
    ///   pre-flights (exactly, with the account's viewing keys; over the
    ///   nonzero outputs without, which the device's count can exceed);
    /// - the memo retention budget (`MAX_RETAINED_MEMO_BYTES`), pre-flighted
    ///   only when the plan was built with the viewing keys, since only they
    ///   reveal the memos;
    /// - the Orchard key-derivation budget (`MAX_ORCHARD_DERIVATIONS`, 50 per
    ///   run of the app, `src/zip32.rs` @ `22dc385`), a counter only quitting
    ///   the app resets. One signing session, one `GET_VK` and one
    ///   `GET_SHIELD_ADDR` each spend a derivation, so after about fifty such
    ///   operations without leaving the app every shielded command answers
    ///   this. No host-side check can see it — it is the device's history —
    ///   and the remedy is to have the user reopen the app.
    NotEnoughMemorySpace,
    /// `0x6700` — `AppSW::WrongApduLength`.
    WrongApduLength,
    /// `0x6B00` — `AppSW::WrongP1P2`.
    WrongP1P2,
    /// `0x6D00` — `AppSW::InsNotSupported`.
    InsNotSupported,
    /// `0x6E00` — `AppSW::ClaNotSupported`: a different app is open.
    ClaNotSupported,
    /// `0x6982` — `AppSW::SecurityStatusNotSatisfied`, an alias of the SDK's
    /// `StatusWords::NothingReceived`. Defined and never emitted: neither the
    /// app (`22dc385`) nor the SDK's legacy I/O layer (`ledger_device_sdk`
    /// 1.37.0, `src/io_legacy.rs`) answers it. A locked device answers
    /// [`StatusWord::DeviceLocked`].
    SecurityStatusNotSatisfied,
    /// `0x6F00` — `AppSW::TechnicalProblem`.
    ///
    /// Not transient. No emitter of it at `22dc385` clears on a fresh stream:
    /// the Secure Element's key-derivation syscall fails once its resources
    /// are drained and stays failed until the next power cycle
    /// (`derive_orchard_sk_bytes`, `src/zip32.rs`); every other emitter
    /// behind an instruction this crate sends — a hash or point operation
    /// over the bytes the host sent — is a deterministic function of the
    /// input; and the one that is neither, the legacy trusted-input
    /// handler's HMAC key, left unset when the RNG failed at app start
    /// (`init_trusted_input_key_storage`, `src/main.rs`), answers an
    /// instruction this crate never sends and clears only when the app is
    /// relaunched. See [`StatusWord::is_transient`].
    TechnicalProblem,
    /// `0x6F01` — `AppSW::VersionParsingFail`.
    VersionParsingFail,
    /// `0x6F02` — `AppSW::TxParsingFail`. Defined and never emitted at
    /// `22dc385`; the parsers answer [`StatusWord::IncorrectData`].
    TxParsingFail,
    /// `0x6F03` — `AppSW::RngFailure`: the hardware random number generator
    /// reported a failure. **No signature was produced.**
    ///
    /// New in v3.9.3 (`src/main.rs`, `enum AppSW`). `src/rng.rs` explains why
    /// it exists: the SDK's `rand_bytes` is built on a `void` syscall that
    /// "exposes no status, so a caller cannot tell a successful draw from a
    /// failed one … a failure yields all-zero randomness that looks like a
    /// valid draw", and a zero RedPallas nonce "discloses the spend
    /// authorizing key from a single signature". The app now draws through the
    /// fallible `cx_get_random_bytes` and reports this instead.
    ///
    /// Fatal, and not worth a retry on the same device: the failure is in the
    /// hardware, not in what the host sent.
    RngFailure,
    /// `0x9240` — `AppSW::MemoryProblem`. Defined and never emitted at
    /// `22dc385`; a budget running out is [`StatusWord::NotEnoughMemorySpace`]
    /// and an allocator giving out is [`StatusWord::AppPanicked`].
    MemoryProblem,
    /// `0xB007` — `AppSW::BadState`: a command arrived out of order.
    BadState,
    /// `0x6901` — `CmdNotAccepted`, from the *device SDK* rather than from this
    /// app.
    ///
    /// `docs/APDU.md` (@ `22dc385`): "From SDK 1.37 the legacy I/O layer
    /// refuses a frame it takes for an APDU while a review is on screen, and it
    /// can answer the first display command of a session. A host does better to
    /// tolerate and retry it than to surface it as a failure."
    ///
    /// It is the one status word that does **not** mean the device dropped its
    /// transaction context: the frame never reached the application at all, so
    /// the cure is to resend the identical APDU. See
    /// [`StatusWord::is_retriable`].
    CmdNotAccepted,
    /// `0x5515` — `StatusWords::DeviceLocked`, from the device SDK rather
    /// than from this app.
    ///
    /// The SDK's legacy I/O layer answers it to any APDU while the PIN is set
    /// and not validated (`ledger_device_sdk` 1.37.0, `src/io_legacy.rs`:
    /// `if os_perso_is_pin_set() && !os_global_pin_is_validated() {
    /// self.reply(StatusWords::DeviceLocked) }`), before the application sees
    /// the command. The remedy is to unlock the device; whether the app's
    /// transaction context survives the lock is not something the host can
    /// know, so the session ends and a fresh stream is the way back.
    DeviceLocked,
    /// `0xE000` — `StatusWords::Panic`, from the device SDK rather than from
    /// this app.
    ///
    /// The SDK's panic handler (`ledger_device_sdk` 1.37.0, `src/lib.rs`,
    /// `exiting_panic`) replies it and then exits the app, so this is the
    /// last word the app says: the next command reaches the dashboard and is
    /// answered as a wrong app. What the host sees when the app's allocator
    /// gives out.
    AppPanicked,
    /// Anything not in the table above.
    Unknown(u16),
}

/// How a caller should treat a [`StatusWord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusClass {
    /// `0x9000`; carry on.
    Ok,
    /// The user declined on the device. Not an error to report as a fault.
    UserCancel,
    /// The device is not running the Zcash app (or not a version that knows
    /// this instruction). Ask the user to open the right app.
    WrongApp,
    /// The device SDK refused the frame before the application saw it
    /// (`0x6901`). The transaction context is intact; resend the same APDU.
    Retriable,
    /// The session is over. Every PCZT instruction resets the device's
    /// transaction context on any non-`0x9000` reply
    /// (`reset_pczt_parser_with_sw` / `map_pczt_parser_error` in
    /// `src/handlers/pczt.rs`), so the stream must be restarted from
    /// `PCZT_HEADER`.
    Fatal,
}

impl StatusWord {
    /// Decodes the two trailing status bytes of a response.
    pub const fn from_u16(sw: u16) -> Self {
        match sw {
            0x9000 => StatusWord::Ok,
            0x6985 => StatusWord::Deny,
            0x6986 => StatusWord::ConditionsOfUseNotSatisfied,
            0x6A80 => StatusWord::IncorrectData,
            0x6A84 => StatusWord::NotEnoughMemorySpace,
            0x6700 => StatusWord::WrongApduLength,
            0x6B00 => StatusWord::WrongP1P2,
            0x6D00 => StatusWord::InsNotSupported,
            0x6E00 => StatusWord::ClaNotSupported,
            0x6982 => StatusWord::SecurityStatusNotSatisfied,
            0x6F00 => StatusWord::TechnicalProblem,
            0x6F01 => StatusWord::VersionParsingFail,
            0x6F02 => StatusWord::TxParsingFail,
            0x6F03 => StatusWord::RngFailure,
            0x9240 => StatusWord::MemoryProblem,
            0xB007 => StatusWord::BadState,
            0x6901 => StatusWord::CmdNotAccepted,
            0x5515 => StatusWord::DeviceLocked,
            0xE000 => StatusWord::AppPanicked,
            other => StatusWord::Unknown(other),
        }
    }

    /// The numeric status word.
    pub const fn to_u16(self) -> u16 {
        match self {
            StatusWord::Ok => 0x9000,
            StatusWord::Deny => 0x6985,
            StatusWord::ConditionsOfUseNotSatisfied => 0x6986,
            StatusWord::IncorrectData => 0x6A80,
            StatusWord::NotEnoughMemorySpace => 0x6A84,
            StatusWord::WrongApduLength => 0x6700,
            StatusWord::WrongP1P2 => 0x6B00,
            StatusWord::InsNotSupported => 0x6D00,
            StatusWord::ClaNotSupported => 0x6E00,
            StatusWord::SecurityStatusNotSatisfied => 0x6982,
            StatusWord::TechnicalProblem => 0x6F00,
            StatusWord::VersionParsingFail => 0x6F01,
            StatusWord::TxParsingFail => 0x6F02,
            StatusWord::RngFailure => 0x6F03,
            StatusWord::MemoryProblem => 0x9240,
            StatusWord::BadState => 0xB007,
            StatusWord::CmdNotAccepted => 0x6901,
            StatusWord::DeviceLocked => 0x5515,
            StatusWord::AppPanicked => 0xE000,
            StatusWord::Unknown(sw) => sw,
        }
    }

    /// Whether the command succeeded.
    pub const fn is_ok(self) -> bool {
        matches!(self, StatusWord::Ok)
    }

    /// Coarse handling class.
    ///
    /// Spelled out per word rather than with a catch-all, so that a status
    /// word added when the firmware pin moves is a compile error here until
    /// someone decides what a host does with it.
    pub const fn class(self) -> StatusClass {
        match self {
            StatusWord::Ok => StatusClass::Ok,
            StatusWord::Deny => StatusClass::UserCancel,
            StatusWord::ClaNotSupported | StatusWord::InsNotSupported => StatusClass::WrongApp,
            StatusWord::CmdNotAccepted => StatusClass::Retriable,
            StatusWord::ConditionsOfUseNotSatisfied
            | StatusWord::IncorrectData
            | StatusWord::NotEnoughMemorySpace
            | StatusWord::WrongApduLength
            | StatusWord::WrongP1P2
            | StatusWord::SecurityStatusNotSatisfied
            | StatusWord::TechnicalProblem
            | StatusWord::VersionParsingFail
            | StatusWord::TxParsingFail
            | StatusWord::RngFailure
            | StatusWord::MemoryProblem
            | StatusWord::BadState
            | StatusWord::DeviceLocked
            | StatusWord::AppPanicked
            | StatusWord::Unknown(_) => StatusClass::Fatal,
        }
    }

    /// Whether resending the *identical* APDU is the right response.
    ///
    /// True for exactly one status word, [`StatusWord::CmdNotAccepted`]
    /// (`0x6901`). Everything else is false because the app tears down its
    /// transaction context on any non-`0x9000` reply to a PCZT instruction
    /// (`reset_pczt_parser_with_sw` / `map_pczt_parser_error` in
    /// `src/handlers/pczt.rs`), so a resend can only fail again — with
    /// `BadState`, if it is not the header — and the only recovery is a fresh
    /// stream from `PCZT_HEADER`.
    ///
    /// `0x6901` is different in kind: it is emitted by the device SDK's legacy
    /// I/O layer, not by `enum AppSW`, and it means the frame was never
    /// delivered to the application. Nothing was parsed, nothing was reset.
    ///
    /// Applied regardless of the app version. A pre-3.9.3 app is built against
    /// an older SDK that does not emit it, so tolerating it there costs
    /// nothing.
    pub const fn is_retriable(self) -> bool {
        matches!(self, StatusWord::CmdNotAccepted)
    }

    /// Whether a refusal with this status word can clear on its own, so that
    /// a *fresh* stream of the same bytes could succeed.
    ///
    /// True for the words that describe the device's state rather than the
    /// host's input: `MemoryProblem` (a device-side resource failure, which
    /// nothing at the pin emits), `BadState` (a command out of order, which a
    /// desynchronized transport produces and a fresh stream cures),
    /// `DeviceLocked` (unlocking clears it), and `CmdNotAccepted` once its
    /// retry budget is spent (a screen was up for the whole budget).
    ///
    /// False for every word that is a deterministic function of what the host
    /// sent — `IncorrectData`, `WrongApduLength`, `WrongP1P2`,
    /// `VersionParsingFail`, `TxParsingFail`, `ConditionsOfUseNotSatisfied`,
    /// `NotEnoughMemorySpace` (a budget this transaction exceeds, or a
    /// per-run derivation budget only restarting the app clears) — for
    /// `TechnicalProblem`, whose one cause behind this crate's instructions
    /// that is not a function of the input, the Secure Element's derivation
    /// drain, lasts until the device is power-cycled, so that a fresh stream
    /// fails at the same packet after another full review; for `RngFailure`,
    /// whose failure is in the
    /// hardware, for `AppPanicked`, whose app is gone and whose cause may well
    /// be this transaction, for `SecurityStatusNotSatisfied`, which nothing
    /// emits, and for anything not in the table. `Ok`, `Deny` and the
    /// wrong-app words are not refusals of this kind and answer false too.
    pub const fn is_transient(self) -> bool {
        matches!(
            self,
            StatusWord::MemoryProblem
                | StatusWord::BadState
                | StatusWord::DeviceLocked
                | StatusWord::CmdNotAccepted
        )
    }
}

#[cfg(test)]
mod tests;
