//! `pczt_ledger` — the APDU engine for the Ledger embedded Zcash app.
//!
//! This crate turns a redacted PCZT (ZIP 374) into the APDU stream the device
//! consumes, and parses what comes back. It performs no I/O: transports (USB
//! HID, BLE, an emulator socket) live above it.
//!
//! The redaction it takes is `zcash_client_backend`'s
//! `redact_pczt_for_signer(SignerView::Full)`; the batch-signer view clears the
//! spend `fvk` the `pczt` Signer role needs, and is refused before the first
//! APDU (see [`session::LedgerSignSession::new_from_pczt`]).
//!
//! # Normative sources
//!
//! **All protocol knowledge here is pinned to `LedgerHQ/app-zcash` commit
//! `1a0f649`** (v3.9.4, `main`). Anything that moves the firmware moves this
//! pin, deliberately. v3.9.4 differs from v3.9.3 (`22dc385`) at runtime only
//! in `memo_display` (`src/parser/pczt.rs`), which now initializes the context
//! it hashes an undisplayable memo with; every other file this crate cites is
//! the same at both commits, which is why most citations below still name
//! `22dc385`. The Known discrepancies below were re-checked at `1a0f649`.
//!
//! **v3.9.3 (`22dc385`) and v3.9.2 (`0e048bb`) remain supported**, except
//! that a plan whose review would hash a memo is refused on them when the
//! host can see the memos ([`limits::DeviceBounds::hashed_memo_review`]).
//! v3.9.3 is a security release and
//! it moved the device contract: three of the four record bounds rose, a
//! shielded displayed-output budget and a memo retention budget appeared,
//! transparent input scripts were narrowed to P2PKH, change gained an account
//! binding, and the SDK's `0x6901` became something a host has to tolerate. Where the two versions disagree
//! about what a device will *accept*, the difference is gated on the version
//! `GET_FIRMWARE_VERSION` reports — see [`limits::DeviceBounds`] — rather than
//! compiled in; a version this crate has not been checked against gets no set
//! at all ([`limits::DeviceBounds::for_caps`] answers `None`), and the caller
//! says which bounds such a device is held to, the strictest combination of
//! the known sets ([`limits::DeviceBounds::MOST_RESTRICTIVE`]) or the most
//! permissive one. Where the
//! newer rule only converts a late device refusal, or a signature that could
//! never be spent, into a pre-flight error, it is applied on every version;
//! so are the two review budgets, since the app that lacks them exits when
//! the review it was sent does not fit ([`limits::DeviceBounds`]).
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
//!   displayed-output count the device's own rather than a count over the
//!   nonzero outputs.
//! - `transport` (`std` feature) — the blocking `transport::Transport` trait
//!   and the two optional concrete transports, USB HID and speculos. Nothing
//!   in [`session`] or [`pairing`] refers to it.
//! - `ceremony` (`std` feature) — the blocking runner over that trait:
//!   `ceremony::run_session` / `ceremony::sign` drive a signing session, and
//!   `ceremony::query` runs a one-shot pairing command with the `0x6901`
//!   retry policy applied.
//! - [`Network`] — re-exported at the root from [`session`] (it is defined in
//!   [`limits`]), since every entry point takes one.
//!
//! # `no_std`
//!
//! The crate is `#![no_std]` (with `alloc`) unless the `std` feature is on,
//! and `std` is on by default. Without it the whole signing path is there —
//! pre-flight, shaping, planning, the session state machine, the pairing
//! parsers and `apply` — and only the I/O is not: the `transport` module,
//! whose error carries a `std::io::ErrorKind`, and the blocking `ceremony`
//! runner, which sleeps between `0x6901` resends. `transport-hid` and
//! `transport-speculos` imply `std`. An embedding on a target with no
//! `getrandom` backend enables `getrandom`'s `custom` feature and registers
//! one (`getrandom::register_custom_getrandom!`), since `pczt`'s Signer role
//! depends on the crate; `ci/nostd` is such an embedding, and CI builds it
//! for `thumbv7em-none-eabihf`.
//!
//! # Shape of one ceremony
//!
//! ```text
//! pairing::parse_device_identity_response(GET_WALLET_PUBLIC_KEY reply)  (once, when pairing)
//! pairing::device_caps(GET_FIRMWARE_VERSION reply)
//!   → LedgerSignSession::new(redacted pczt, caps, params { device, .. })
//!        validate_for_ledger → shape_for_device → build_plan → limits
//!   → GET_FIRMWARE_VERSION; the reply must derive `caps`
//!   → GET_WALLET_PUBLIC_KEY at the identity path; the reply must match `device`
//!   → loop { next_step() → transport → process_response() }
//!   → finish() → SignOutcome { pczt_with_sigs, .. }
//! ```
//!
//! All PCZT access goes through the `pczt` crate's roles and accessors; no
//! part of this crate reads or writes PCZT bytes.
//!
//! # Known discrepancies in the normative sources
//!
//! Recorded here because they are load-bearing for what this crate does, and
//! because each has to be re-checked when the firmware pin moves.
//!
//! 1. **Empty Ironwood bundle.** `docs/APDU.md`
//!    (`INS_PCZT_IRONWOOD_ACTION`) says "The Ironwood action count must be at
//!    least `1`; a count of `0` is rejected." `docs/PCZT_APDU.md` says the
//!    opposite, at length, and the device agrees with it:
//!    `parse_ironwood_actions_start` (`src/parser/pczt/ironwood.rs`) accepts
//!    `action_count == 0` and calls `finalize_ironwood_actions`, which is what
//!    runs the review for a V6 transaction. This crate follows the parser, so a
//!    V6 Orchard-only transaction is streamed with an empty Ironwood command
//!    that carries the `P2_PCZT_FINISHED` marker. `docs/APDU.md` is wrong.
//! 2. **Zero-valued real spends.** The device classifies a spend as a dummy
//!    purely by `spend_value == 0` (`is_real_spend` in
//!    `finish_current_orchard_action` and `finish_current_ironwood_action`),
//!    and refuses to sign it (`ensure_signature_digest_for_orchard`, and
//!    `ensure_signature_digest_for_ironwood` for Ironwood). The host-side rule
//!    is "needs a signature iff `spend_auth_sig` is absent". The two agree only
//!    because the IO Finalizer self-signs exactly the padding dummies. Under
//!    the post-NU6.3 Orchard cross-address restriction the builder emits
//!    wallet-controlled *zero-value* spends paired with change outputs, which
//!    are left unsigned and would therefore need a device signature the device
//!    will never produce. [`plan::PlanError::SpendClassificationMismatch`]
//!    detects the divergence before the first APDU.
//! 3. **Lock times.** The device applies
//!    `locktime = fallback_lock_time.unwrap_or_default()`
//!    (`parse_global` in `src/parser/pczt/common.rs`) directly; the
//!    per-input BIP 370 lock-time requirements are not part of the compact APDU
//!    subset at all. Mirroring `fallback_lock_time` verbatim (which is what the
//!    host contract does) is therefore only correct while no transparent input
//!    imposes one — enforced by
//!    [`plan::PlanError::TransparentLockTimeRequired`].
//! 4. **Transparent DER quirks.** The `0x31` header byte (`sig[0] |= 0x01` on
//!    an odd `y`) and the trailing sighash byte (`comm.append(&[sighash_type])`)
//!    that [`apply::normalize_ledger_der`] undoes are in `handler_hash_sign`
//!    (`src/handlers/sign_tx.rs`) and in neither APDU document. A reply with
//!    the canonical header is accepted too, and one without the trailing byte
//!    is refused, so a firmware that dropped either quirk would fail closed at
//!    the first signature. The same holds for the mode byte a `GET_VK`
//!    continuation repeats in P2 (see [`pairing::VkExchange`]): in the
//!    handler, in neither document.
//! 5. **Seed fingerprints.** The device reads the 32-byte fingerprint of
//!    every derivation record and only logs it, in the transparent, Orchard
//!    and Ironwood parsers alike (`src/parser/pczt/transparent.rs`,
//!    `orchard.rs` and `ironwood.rs`). This crate sends zeros in its place and keeps the
//!    wallet's real fingerprint in the PCZT it hands back (see [`plan::Plan`]);
//!    a firmware that starts checking the field moves this pin.
//!
//! # Example
//!
//! Building the APDU stream for a plan and framing the first command for HID:
//!
//! ```
//! use pczt_ledger::apdu::encode::{header_apdu, HeaderRecord, PCZT_VERSION_V5};
//! use pczt_ledger::framing::{hid_frames, HidChannel};
//!
//! // PCZT version 1 (V5), NU6.3, no fallback lock time, mainnet.
//! let header = HeaderRecord::new(
//!     PCZT_VERSION_V5,
//!     5,
//!     0x26A7_270A,
//!     0x37A5_165B,
//!     None,
//!     3_500_000,
//!     133,
//!     0x00,
//! );
//!
//! let apdu = header_apdu(&header);
//! assert_eq!(apdu.data().len(), 30);
//!
//! let frames = hid_frames(HidChannel::new(0x1234), &apdu.to_bytes())
//!     .expect("an APDU is at most 260 bytes, far below what a frame 0 can declare");
//! assert_eq!(frames.len(), 1);
//! ```

#![deny(missing_docs)]
#![forbid(unsafe_code)]
// `std` is a feature. Without it the crate is `#![no_std]` with `alloc` —
// the build a firmware-side or FFI embedding makes. Tests keep the standard
// library either way; the harness needs it, and it changes nothing they test.
#![cfg_attr(not(any(feature = "std", test)), no_std)]
// docs.rs builds with `--cfg docsrs` (see `[package.metadata.docs.rs]` in
// Cargo.toml) on nightly, where `doc_cfg` labels every feature-gated item
// with the feature that enables it. Inert on stable.
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

pub mod apdu;
pub mod apply;
#[cfg(feature = "std")]
pub mod ceremony;
pub mod framing;
pub mod limits;
pub mod pairing;
pub mod plan;
pub mod session;
pub mod shape;
#[cfg(feature = "std")]
pub mod transport;
pub mod viewing;

pub use session::Network;

#[cfg(test)]
pub(crate) mod test_support;
