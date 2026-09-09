//! `pczt_ledger` — the APDU engine for the Ledger embedded Zcash app.
//!
//! This crate turns a redacted PCZT (ZIP 374) into the APDU stream the device
//! consumes, and parses what comes back. It performs no I/O: transports (USB
//! HID, BLE, an emulator socket) live above it.
//!
//! # Normative sources
//!
//! **All protocol knowledge here is pinned to `LedgerHQ/app-zcash` commit
//! `22dc385`** (v3.9.3, `develop`). Anything that moves the firmware moves
//! this pin, deliberately.
//!
//! **v3.9.2 (`0e048bb`) remains supported.** v3.9.3 is a security release and
//! it moved the device contract: three of the four record bounds rose, a
//! shielded displayed-output budget appeared, transparent input scripts were
//! narrowed to P2PKH, change gained an account binding, and the SDK's `0x6901`
//! became something a host has to tolerate. Where the two versions disagree
//! about what a device will *accept*, the difference is gated on the version
//! `GET_FIRMWARE_VERSION` reports — see [`limits::DeviceBounds`] — rather than
//! compiled in; an unknown version falls back to the v3.9.2 set. Where the
//! newer rule only converts a late device refusal, or a signature that could
//! never be spent, into a pre-flight error, it is applied on every version.
//!
//! - `docs/APDU.md` — the instruction table, P1/P2 semantics and response
//!   shapes.
//! - `docs/PCZT_APDU.md` — the PCZT payload framing.
//! - `src/consts.rs`, `src/main.rs`, `src/parser/pczt/*.rs`,
//!   `src/handlers/*.rs` — the device implementation the docs describe; every
//!   claim in this crate was cross-checked against it, and the citations are
//!   in the module and item docs.
//!
//! Transport framing follows `LedgerHQ/device-sdk-ts`,
//! `packages/device-management-kit` — see [`framing`].
//!
//! # Layout
//!
//! - [`apdu`] — instruction constants, status words, the `Apdu` type and the
//!   ≤255-byte chunker.
//! - [`apdu::encode`] — one payload builder per wire record, taking plain
//!   record structs of raw fields.
//! - [`apdu::decode`] — response parsing.
//! - [`framing`] — HID and BLE frame construction and reassembly.
//! - [`limits`] — device limits, capability gating and plan validation.
//! - [`plan`] — PCZT → [`apdu::encode::StreamPlan`], through the `pczt`
//!   Verifier role.
//! - [`shape`] — the Updater pass that puts a wallet PCZT into the shape the
//!   device requires (derivation paths, change marking).
//! - [`pairing`] — firmware probe, viewing-key export, address display, the
//!   `GET_WALLET_PUBLIC_KEY` probe and the [`pairing::DeviceIdentity`] it
//!   hashes out of a fixed transparent path.
//! - [`session`] — [`session::LedgerSignSession`], the pull-pump signing state
//!   machine, bound to one [`pairing::DeviceIdentity`].
//! - [`apply`] — device signatures back onto the PCZT, through the `pczt`
//!   Signer and Updater roles.
//! - [`viewing`] — the account's shielded viewing keys, which make the
//!   displayed-output count exact rather than an upper bound.
//! - [`transport`] — the blocking [`transport::Transport`] trait and the two
//!   optional concrete transports, USB HID and speculos. Nothing in [`session`]
//!   or [`pairing`] refers to it.
//! - [`ceremony`] — the blocking runner over that trait:
//!   [`ceremony::run_session`] / [`ceremony::sign`] drive a signing session,
//!   and [`ceremony::query`] runs a one-shot pairing command with the `0x6901`
//!   retry policy applied.
//!
//! # Shape of one ceremony
//!
//! ```text
//! pairing::parse_device_identity_response(GET_WALLET_PUBLIC_KEY reply)  (once, when pairing)
//! pairing::device_caps(GET_FIRMWARE_VERSION reply)
//!   → LedgerSignSession::new(redacted pczt, caps, params { device, .. })
//!        validate_for_ledger → shape_for_device → build_plan → limits
//!   → GET_WALLET_PUBLIC_KEY at the identity path; the reply must match `device`
//!   → loop { next_step() → transport → process_response() }
//!   → finish() → SignOutcome { pczt_with_sigs, .. }
//! ```
//!
//! All PCZT access goes through the `pczt` crate's roles; this crate never
//! parses PCZT bytes itself.
//!
//! # Known discrepancies in the normative sources
//!
//! Recorded here because they are load-bearing for what this crate does, and
//! because each has to be re-checked when the firmware pin moves.
//!
//! **All four were re-verified against `22dc385` and still hold**, at the
//! lines cited below; none of the v3.9.3 changes touched them.
//!
//! 1. **Empty Ironwood bundle.** `docs/APDU.md:353`
//!    (`INS_PCZT_IRONWOOD_ACTION`) says "The Ironwood action count must be at
//!    least `1`; a count of `0` is rejected." `docs/PCZT_APDU.md` says the
//!    opposite, at length, and the device agrees with it:
//!    `parse_ironwood_actions_start` (`src/parser/pczt/ironwood.rs:59`) accepts
//!    `action_count == 0` and calls `finalize_ironwood_actions`, which is what
//!    runs the review for a V6 transaction. This crate follows the parser, so a
//!    V6 Orchard-only transaction is streamed with an empty Ironwood command
//!    that carries the `P2_PCZT_FINISHED` marker. `docs/APDU.md` is wrong.
//! 2. **Zero-valued real spends.** The device classifies a spend as a dummy
//!    purely by `spend_value == 0` (`is_real_spend`,
//!    `src/parser/pczt/orchard.rs:564` and `ironwood.rs:586`), and refuses to
//!    sign it (`orchard.rs:1176`). The host-side rule
//!    is "needs a signature iff `spend_auth_sig` is absent". The two agree only
//!    because the IO Finalizer self-signs exactly the padding dummies. Under
//!    the post-NU6.3 Orchard cross-address restriction the builder emits
//!    wallet-controlled *zero-value* spends paired with change outputs, which
//!    are left unsigned and would therefore need a device signature the device
//!    will never produce. [`plan::PlanError::SpendClassificationMismatch`]
//!    detects the divergence before the first APDU.
//! 3. **Lock times.** The device applies
//!    `locktime = fallback_lock_time.unwrap_or_default()`
//!    (`src/parser/pczt/common.rs:70`) directly; the
//!    per-input BIP 370 lock-time requirements are not part of the compact APDU
//!    subset at all. Mirroring `fallback_lock_time` verbatim (which is what the
//!    host contract does) is therefore only correct while no transparent input
//!    imposes one — enforced by
//!    [`plan::PlanError::TransparentLockTimeRequired`].
//! 4. **Transparent DER quirks.** The `0x31` header byte (`sig[0] |= 0x01` on
//!    an odd `y`, `src/handlers/sign_tx.rs:356`) and the trailing sighash byte
//!    (`comm.append(&[sighash_type])`, `:362`) that
//!    [`apply::normalize_ledger_der`] undoes are read from the firmware source,
//!    not from bytes a physical device returned. They fail
//!    closed, but capturing a real reply is open work — as is confirming that a
//!    `GET_VK` continuation is happy with the mode byte repeated in P2 (see
//!    [`pairing::VkExchange`]).
//!
//! # Example
//!
//! Building the APDU stream for a plan and framing the first command for HID:
//!
//! ```
//! use pczt_ledger::apdu::encode::{header_apdu, HeaderRecord, PCZT_VERSION_V5};
//! use pczt_ledger::framing::hid_frames;
//!
//! let header = HeaderRecord {
//!     pczt_version: PCZT_VERSION_V5,
//!     tx_version: 5,
//!     version_group_id: 0x26A7_270A,
//!     consensus_branch_id: 0xC2D6_D0B4,
//!     fallback_lock_time: None,
//!     expiry_height: 2_500_000,
//!     coin_type: 133,
//!     tx_modifiable: 0x00,
//! };
//!
//! let apdu = header_apdu(&header);
//! assert_eq!(apdu.data.len(), 30);
//!
//! let frames = hid_frames(0x1234, &apdu.to_bytes());
//! assert_eq!(frames.len(), 1);
//! ```

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod apdu;
pub mod apply;
pub mod ceremony;
pub mod framing;
pub mod limits;
pub mod pairing;
pub mod plan;
pub mod session;
pub mod shape;
pub mod transport;
pub mod viewing;

pub use session::Network;

#[cfg(test)]
mod tests;
