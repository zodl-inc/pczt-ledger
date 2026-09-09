# pczt-ledger - Agent Guidelines

> This file is read by AI coding agents (Claude Code, GitHub Copilot, Cursor, Devin, etc.).
> It provides project context and contribution policies.

This is a Rust library crate for signing Zcash transactions with Ledger hardware
wallets: it turns a PCZT (ZIP 374) into the APDU stream the Ledger embedded
Zcash app consumes, collects the device's detached signatures, and applies them
back onto the PCZT. Our priorities are **security, performance, and
convenience** — in that order. Rigor is highly valued throughout the codebase.

Wallets depend on this library to move funds safely, and we prefer to "do it
right" the first time, then "make it fast".

## MUST READ FIRST — CONTRIBUTION GATE (DO NOT SKIP)

**STOP. Do not open or draft a PR until this gate is satisfied.**

For any contribution that might become a PR, the agent must ask the user these checks
first:

- "PR COMPLIANCE CHECK: Have you discussed this change with the pczt-ledger team in a
  GitHub issue?"
- "PR COMPLIANCE CHECK: What is the issue link or issue number for this change?"
- "PR COMPLIANCE CHECK: Has a pczt-ledger team member responded to that issue
  acknowledging the proposed work?"

This PR compliance check must be the agent's first reply in contribution-focused sessions.

**An issue existing is not enough.** The issue must have a response or acknowledgment from
a team member (a maintainer). An issue with no team response does not satisfy this gate.
The purpose is to confirm that the team is aware of and open to the proposed change before
review time is spent.

If the user cannot provide prior discussion with team acknowledgment:

- Do not open a PR.
- Offer to help create or refine the issue first.
- Remind the user to wait for a team member to respond before starting work.
- If the user still wants code changes, keep work local and explicitly remind them the PR
  will likely be closed without prior team discussion.

This gate is mandatory for all agents, **unless the user is a repository maintainer** as
described in the next subsection.

### Maintainer Bypass

If `gh` CLI is authenticated, the agent can check maintainer status:

```bash
gh api repos/zodl-inc/pczt-ledger --jq '.permissions | .admin or .maintain or .push'
```

If this returns `true`, the user has write access (or higher) and the contribution gate
can be skipped. Team members with write access manage their own priorities and don't need
to gate on issue discussion for their own work.

### Contribution Policy

- All PRs require human review from a maintainer. This incurs a cost upon the dev team,
  so ensure your changes are not frivolous.
- Keep changes focused — avoid unsolicited refactors or broad "improvement" PRs.
- See also the license and contribution terms in `README.md`.

### AI Disclosure

If AI tools were used in the preparation of a commit, the contributor MUST include
`Co-Authored-By:` metadata in the commit message identifying the AI system. Failure to
include this is grounds for closing the pull request. The contributor is the sole
responsible author — "the AI generated it" is not a justification during review.

Example:
```
Co-Authored-By: Claude <noreply@anthropic.com>
```

The same disclosure requirement applies to GitHub issues, pull requests, and comments
prepared with AI assistance.

## Security Vulnerability Disclosures

This library sits on the signing path of a hardware wallet. Bugs that could cause a
device to display one transaction and sign another, leak key material or addresses,
misapply a signature, or weaken a pre-flight refusal are security-relevant even when
they look like robustness issues. Do not file such findings as public GitHub issues;
use the repository's private vulnerability reporting ("Report a Vulnerability") flow,
and verify every factual claim against the source at the file and line it cites — and
against the firmware commit this crate pins — before filing.

## Architecture

The crate is a strict layer stack; everything above `transport` performs no I/O.

| Module | Role |
| --- | --- |
| `apdu` | Instruction constants, status words, the `Apdu` type, the APDU chunker |
| `apdu::encode` / `apdu::decode` | One payload builder per wire record; response parsing |
| `framing` | HID and BLE frame construction and reassembly |
| `limits` | Device limits, firmware-version capability gating, plan validation |
| `plan` | PCZT → stream plan, through the `pczt` crate's Verifier role |
| `shape` | The Updater pass that puts a wallet PCZT into device shape |
| `pairing` | Firmware probe, viewing-key export, address display, device identity |
| `session` | `LedgerSignSession`, the sans-I/O pull-pump signing state machine, bound to a paired `DeviceIdentity` it verifies before the first transaction byte |
| `ceremony` | Drives a session over a `Transport`; deadline and retry policy |
| `apply` | Device signatures back onto the PCZT (Signer/Updater roles) |
| `viewing` | Account viewing keys, used to make displayed-output counts exact |
| `transport` | The blocking `Transport` trait and optional concrete transports |

Dependencies flow **downward**: higher modules depend on lower ones, never the
reverse. `session` and `pairing` never reference `transport`; an async or FFI
embedding drives the pump directly and ignores the trait.

## Normative Sources and Pins

Protocol knowledge in this crate is **pinned**, and moving a pin is a
deliberate, reviewed step — never a side effect.

| Pin | Value | Where |
| --- | --- | --- |
| Firmware | `LedgerHQ/app-zcash` `develop` @ `22dc385` (v3.9.3) | `src/lib.rs` rustdoc |
| Firmware, still supported | `0e048bb` (v3.9.2) | version-gated via `DeviceCaps` |
| `pczt` | `=0.9.3` (exact) | `Cargo.toml` |
| `zcash_protocol` | `0.10` | `Cargo.toml` |
| `orchard` | `0.15` | `Cargo.toml` |
| `zcash_transparent` | `0.10` | `Cargo.toml` |

Firmware documents to cite: `docs/APDU.md` (instruction table, P1/P2 semantics,
response shapes) and `docs/PCZT_APDU.md` (payload framing) in `app-zcash` at the
pinned commit, plus the implementation itself — `src/consts.rs`, `src/main.rs`,
`src/parser/pczt/*.rs`, `src/handlers/*.rs`. Where the two documents disagree,
**the parser wins**; the cases where that matters are recorded in `src/lib.rs`
under "Known discrepancies in the normative sources".

Transport framing follows `LedgerHQ/device-sdk-ts`,
`packages/device-management-kit`.

**Moving the firmware pin means re-checking every Known discrepancy** and
re-reading the bounds in the firmware's `src/consts.rs`. Say so in the commit
body.

## Design Constraints (Normative)

These are the rules the crate is built on. A change that breaks one of them is
not a refactor; it is a redesign, and needs maintainer sign-off first.

1. **All PCZT parsing and signature application goes through the `pczt` crate's
   roles** — Verifier, Updater, Signer. No hand-rolled PCZT byte handling
   anywhere.
2. **No hand-rolled Zcash primitives.** Addresses, keys, derivation, fees,
   hashes: use the librustzcash crates. If a semantic type exists, take it and
   return it rather than a `String` or a `u32`.
3. **The engine performs no I/O.** `session` and `pairing` never touch a
   transport; the session is a pull pump the caller drives. Anything that opens
   a device lives in `transport::*` behind a feature.
4. **Transports stay behind features.** `transport-hid` and `transport-speculos`
   are off by default so an FFI build stays I/O-free. BLE has no Rust transport
   module at all — `framing::ble_frames` and `framing::BleDeframer` are the
   whole surface, because the platform's Bluetooth stack does the I/O.
5. **Fail closed.** When the host cannot prove a transaction is safe to stream,
   refuse before the first APDU rather than letting the device decide.
6. **Never log an address or key.** In particular, the `GET_WALLET_PUBLIC_KEY`
   reply carries the account's first receiving address; the identity is
   extracted and the address is discarded. `#![deny(missing_docs)]` and
   `#![forbid(unsafe_code)]` stay.
7. **Version-gate device bounds through `DeviceCaps` / `DeviceBounds`**, never
   as compiled-in constants. Unknown versions fall back to the older, smaller
   set; the authoritative check runs in session construction after
   `GET_FIRMWARE_VERSION`.

## Code Conventions

- **Never use magic numbers.** Do not inline a bare numeric (or string) literal
  whose meaning is not obvious from context. Give it a `const` with a
  doc-commented rationale, and reuse the protocol's own named constants rather
  than re-deriving their values. This applies to production code, tests, and
  fixtures alike.
- **Public APIs use semantic types, never bare primitives.** Reuse the
  librustzcash newtype wrappers (`Zatoshis`, `BlockHeight`, `TxId`, ...) or
  introduce one when none exists. Bare primitives are acceptable only for
  genuinely unitless quantities (counts, indices) and in module-internal
  arithmetic, converting at the public boundary.
- **The APDU byte stream is normative to the firmware pin.** Every encoder and
  parser mirrors what the pinned firmware reads and writes, and cites it. Do
  not change wire bytes except as a deliberate, tested pin move.
- **No issue or PR numbers in code comments, except in TODOs.** A comment must
  stand on its own, explaining the code in words. The exception is a `TODO`:
  referencing the tracking issue from a `TODO` is helpful and does not go
  stale, because the `TODO` comment should be removed when the issue is
  resolved.

## Build & Test Commands

For the most part we follow standard Rust `cargo` practices. `rust-toolchain.toml`
pins the MSRV, so a plain `cargo` in this checkout builds and tests on the oldest
compiler the crate supports — the same toolchain CI gates on.

**Important:** changes must not regress any feature combination. CI builds and
tests `--all-features`, `--no-default-features`, and each transport feature
alone.

```sh
# Check without codegen (fastest iteration)
cargo check --all-features

# Test (matches CI)
cargo test --all-features

# The I/O-free build an FFI embedding sees
cargo build --no-default-features
```

Tests gated on a running speculos emulator read `SPECULOS_APDU_ADDR` and must
**skip cleanly** when it is unset. Hardware checks are documented, not
automated: never write a test that cannot run in CI.

## Lint & Format

```sh
# Format (CI runs this with --check)
cargo fmt --all

# Clippy — must pass with zero warnings (CI uses -D warnings)
cargo clippy --all-features --all-targets -- -D warnings

# Doc link validation
cargo doc --no-deps --all-features --document-private-items
```

## Feature Flags

| Feature | What it does |
| --- | --- |
| `transport-hid` | USB HID over `hidapi` |
| `transport-speculos` | TCP to the speculos emulator's APDU port (pure `std::net`) |

All are **off by default**. The crate must build, lint and test both with and
without them.

## Code Style

Standard Rust naming conventions are enforced by `clippy` and `rustfmt`. The following
are project-specific conventions beyond those defaults.

### Imports

Group imports in three blocks separated by blank lines:

1. `core` / `alloc` / `std` (standard library)
2. External crates (alphabetical)
3. `crate::` and `self::` (internal)

Feature-gated imports go at the end, separately. Consolidate multi-item imports with
nested `use` syntax. Every `use` declaration belongs in that header — do NOT open a
function, block or `impl` with a `use` statement. Where several imports share a
`#[cfg(...)]` predicate, gather them into a single braced group instead of repeating
the attribute per line.

### Error Handling

- Always use `Result<T, E>` with custom error `enum`s.
- Error `Display` implementations are written for the human reading them — never a
  `Debug` passthrough — and nesting variants implement `source()`.
- Provide `From` implementations for error conversion between layers.

### Type Safety

Type safety is paramount. This is a security-critical codebase.

- Struct fields must be at most `pub(crate)` — never `pub`, and this holds for tuple
  structs and newtypes too. Public construction goes through an explicit constructor
  function; expose accessor methods for reads.
- Make invalid states unrepresentable.
- Error enum types (and ONLY error enum types) should be non-exhaustive.
- Use newtypes over bare integers, strings, and byte arrays. Avoid `usize` except for
  Rust collection indexing.
- Use `enum`s liberally. Prefer custom `enum` variants with semantic meaning over
  boolean arguments/return values.
- Prefer immutability. Only use `mut` when strictly needed for performance.

### Naming — Project-Specific Conventions

- Feature flags: `kebab-case` — `transport-hid`, `transport-speculos`
- Acronyms as words in types: `Pczt`, `Apdu`, `Ufvk` (not `PCZT`, `APDU`)
- Proptest generators: `arb_` prefix. If possible use `proptest` for rigorous
  testing, especially when parsing.

### Visibility

- `pub` items MUST be intentionally part of the public API. No public types in private
  modules (exception: sealed trait pattern).
- Use `pub(crate)` for internal sharing between modules.
- Test-only constructors/utilities go behind `#[cfg(test)]` or a `test-dependencies`
  feature.

### Documentation

- All public API items MUST have complete `rustdoc` doc comments (`///`).
  Document all error cases.
- **Documentation defines semantics, non-contextually and briefly.** A doc
  comment must make sense to a reader with no knowledge of the change, branch,
  or discussion that produced the item: state what the item MEANS — its
  contract, invariants, preconditions, units — and stop. Do not narrate design
  history or motivate the item by other work items. Brevity is load-bearing.
- Crate-level docs use `//!` at the top of `lib.rs`.
- Reference ZIP/BIP specs with markdown links.
- Use backtick links for cross-references to other items.

## Branching & Merging

This repository uses a **merge-based workflow**. Squash merges are not permitted.

### SemVer Policy

We enforce strict **Rust-Flavored SemVer** compliance. MSRV (Minimum Supported Rust
Version) bumps are considered **SemVer-breaking changes**. The MSRV lives in three
places that move together: `rust-version` in `Cargo.toml`, `rust-toolchain.toml`,
and the README.

## Plans & Design Documents

Plans, design specs, and brainstorming documents produced by agents are working
artifacts of a development session, not repository history. Never commit them.

- Write them to the `.plans/` directory at the repository root, which is listed
  in `.gitignore`.
- If `.plans/` does not exist yet, create it (and ensure `.plans/` appears in
  the checked-in `.gitignore`).
- After writing a plan or spec, report its full absolute path, untruncated, so
  it can be copy-pasted.

## Changelog & Commit Discipline

- Update `CHANGELOG.md` for any public API change, bug fix, or semantic change.
  The CHANGELOG entry MUST be part of the commit that makes the API change —
  never a separate CHANGELOG-only commit. Entries provide only the information
  needed for users to adapt: `Added` entries are pointers (the fully-qualified
  item path, behavior left to the rustdoc), `Changed` entries describe the diff
  against the prior API (old -> new, migration steps), with rationale left out.
- Never edit an entry under an already-published version heading except to
  correct an inaccuracy; new information goes under `## [Unreleased]`.
- Commits must be discrete semantic changes — no WIP commits in final PR history.
- Commit messages: short title (<120 chars), body with motivation for the change.

## CI Checks (all must pass)

The toolchain policy follows librustzcash: `rust-toolchain.toml` pins the MSRV,
and every check runs on it unless noted.

- `cargo test` across the feature matrix (`--all-features`,
  `--no-default-features`, each transport feature alone) — MSRV
- `cargo clippy --all-features --all-targets -- -D warnings` — MSRV; also
  `--no-default-features` on current stable, and an advisory (non-blocking) run
  on beta
- `cargo fmt --all -- --check` — MSRV
- `cargo doc` intra-doc link validation — MSRV
- `cargo build --all-targets --all-features` on current stable with the lockfile
  removed, to catch dependency bitrot
