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

Dependencies flow **downward**, in this order: `apdu` → `framing` → `limits`
→ `viewing` → `plan` → `shape` → `apply` → `pairing` → `session` → `transport`
→ `ceremony`. A module uses only modules earlier in that list (`plan` validates
its own `Plan` against `limits`, never the reverse; `transport` takes
`apdu::Deadline`, which `session` re-exports, and `session` never references
`transport`). An async or
FFI embedding drives the pump directly and ignores the `Transport` trait.

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
| `zcash_address` | `0.13` | `Cargo.toml` — parses the unified address the device displays |
| `zcash_encoding` | `0.4` | `Cargo.toml` — writes the `CompactSize` prefixes the device's PCZT parser reads |
| `secp256k1` | `0.29` | `Cargo.toml` — parses and normalizes the device's DER signatures |
| `blake2b_simd` | `1` | `Cargo.toml` — the personalized hash behind `DeviceIdentity` |

Only `pczt` is pinned exactly, because it defines the byte stream the firmware
parses. The other crates are caret ranges; what keeps them from moving silently
is the committed `Cargo.lock`, which CI builds with `--locked`, so any move is
a reviewable diff to the lockfile rather than a side effect of `cargo update`.

**Temporary:** the table gives each crate's version requirement, but `pczt`,
`orchard` and the librustzcash crates they share are currently taken from git
rather than from crates.io. The `[patch.crates-io]` block at the end of
`Cargo.toml` names the revisions — zcash/librustzcash#3041 and
zcash/orchard#560, both merged, so each crate comes from its own upstream
repository at the `main` revision carrying the change, until the next release
of each — and says what each adds and why patching one crate patches its
workspace siblings. The same block is repeated in `ci/nostd/Cargo.toml`, which
is its own workspace and so is not reached by the crate's. The blocks, this
note and the CI step that guards them all go once both changes reach a
crates.io release, at the same version requirements the table already gives.

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
   module at all — `framing::ble_frames` and `framing::Deframer::ble` are the
   whole surface, because the platform's Bluetooth stack does the I/O.
5. **Fail closed.** When the host cannot prove a transaction is safe to stream,
   refuse before the first APDU rather than letting the device decide.
6. **Never log an address or key.** In particular, the `GET_WALLET_PUBLIC_KEY`
   reply carries the account's first receiving address; the identity is
   extracted and the address is discarded. `#![deny(missing_docs)]` and
   `#![forbid(unsafe_code)]` stay.
7. **Version-gate device bounds through `DeviceCaps` / `DeviceBounds`**, never
   as compiled-in constants. The only version refusal is an app older than
   v3.6.0, which has no PCZT instructions. Versions from v3.6.0 up to the
   older pin share its constants and get its bounds. A version above the
   newer pin is one the crate has not been checked against, and it gets no
   set: `DeviceBounds::for_caps` answers `None` rather than choosing one,
   since a newer app is never assumed to be at least as permissive and the
   crate has not read its constants either. The choice is the caller's and is
   made explicitly — `SessionParams::with_unknown_version_bounds`, holding the
   device to `DeviceBounds::MOST_RESTRICTIVE` (the strictest combination of the
   known sets) or to `DeviceBounds::MOST_PERMISSIVE` — and a session built
   without one refuses such a device before the first APDU
   (`SessionError::UnknownDeviceVersion`). The session's first command is a
   `GET_FIRMWARE_VERSION` whose reply must derive the caps the session was
   built against, so the authoritative check cannot be skipped.

## Code Conventions

- **Never use magic numbers.** Do not inline a bare numeric (or string) literal
  whose meaning is not obvious from context. Give it a `const` with a
  doc-commented rationale, and reuse the protocol's own named constants rather
  than re-deriving their values. This applies to production code, tests, and
  fixtures alike, with one exemption: a golden wire vector, or an assertion that
  pins a named constant to its protocol value, is literal by nature.
- **Public APIs use semantic types, never bare primitives.** Reuse the
  librustzcash newtype wrappers (`Zatoshis`, `BlockHeight`, `TxId`, ...) or
  introduce one when none exists. Bare primitives are acceptable only for
  genuinely unitless quantities (counts, indices) and in module-internal
  arithmetic, converting at the public boundary.
- **The APDU byte stream is normative to the firmware pin.** Every encoder and
  parser mirrors what the pinned firmware reads and writes, and cites it. Do
  not change wire bytes except as a deliberate, tested pin move.
- **Cite the firmware by name, not by line number.** A comment or doc that
  points into `app-zcash` names the function, constant or document section it
  means. Names survive a pin move; a bare line number silently comes to point
  at unrelated code. Keep a line number only where the name is ambiguous.
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
tests `--all-features`, `--no-default-features` (the `no_std` build), `std`
alone, and each transport feature alone, and builds the `no_std` half for a
bare-metal target.

```sh
# Check without codegen (fastest iteration)
cargo check --all-features

# Test (matches CI)
cargo test --all-features

# The `no_std` build a firmware-side or FFI embedding sees: no transports, no
# runner, no standard library. `ci/nostd` builds it for a bare-metal target.
cargo build --no-default-features

# `std` without the transports
cargo build --no-default-features --features std
```

`tests/speculos.rs` runs signing ceremonies against the app itself in the
[Speculos] emulator: the firmware's parser, validation and review, not the
end-to-end suite's model of them. Its module docs give the three commands
that build the app at the pinned commit, launch the emulator, and run the
tests. Those tests read `SPECULOS_APDU_ADDR`
(`transport::speculos::SPECULOS_ADDR_ENV`) and **skip cleanly** when it is
unset, which is what every emulator-backed test must do; the one test there
that needs no emulator pins the host's key derivation to the UFVK Ledger's
own suite records for the emulator's default seed, and runs in CI. Hardware
checks are documented, not automated: never write a test that cannot run in
CI.

[Speculos]: https://github.com/LedgerHQ/speculos

## Lint & Format

```sh
# Format (CI runs this with --check)
cargo fmt --all

# Clippy — must pass with zero warnings (CI runs this for every feature set)
cargo clippy --all-features --all-targets -- -D warnings

# Doc link validation (CI runs this with RUSTDOCFLAGS="-D warnings", with all
# features and with none: a link into a feature-gated module dangles when the
# feature is off)
cargo doc --no-deps --all-features --document-private-items
cargo doc --no-deps --no-default-features --document-private-items

# Advisories, licences and dependency sources (`cargo install cargo-deny`)
cargo deny --all-features --locked check
```

## Feature Flags

| Feature | What it does |
| --- | --- |
| `std` | The standard library: the `transport` module and the `ceremony` runner. Without it the crate is `#![no_std]` with `alloc` |
| `transport-hid` | USB HID over `hidapi`. Implies `std` |
| `transport-speculos` | TCP to the speculos emulator's APDU port (pure `std::net`). Implies `std` |

`std` is **on by default**; the transports are off. An FFI or firmware-side
build takes `default-features = false`. The crate must build, lint and test
with every feature set CI runs.

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

The toolchain policy follows librustzcash: `rust-toolchain.toml` pins the MSRV.
The checks are defined once, in `.github/workflows/checks.yml`, and `ci.yml`
runs that workflow twice — on the MSRV, and on current stable, which
`.github/actions/rust` selects by overriding the pin for the job. The MSRV leg
is the promise; the stable leg is the early warning, since a new compiler
brings new lints and a new rustdoc brings new link checks. On both toolchains:

- `cargo test --locked` across the feature matrix (`--all-features`,
  `--no-default-features`, `std` alone, each transport feature alone)
- `cargo clippy --locked --all-targets -- -D warnings` across the same feature
  matrix
- `cargo fmt --all -- --check`
- `cargo doc --locked --no-deps --document-private-items` under
  `RUSTDOCFLAGS=-D warnings` across the same feature matrix, for intra-doc
  link validation
- `cargo build --locked --target thumbv7em-none-eabihf` of `ci/nostd`, a
  `#![no_std]` embedding of the crate without its `std` feature: the proof
  that the `no_std` half really is. The embedding is its own workspace with
  its own committed lockfile, `ci/nostd/Cargo.lock`, which may pin nothing
  the crate's `Cargo.lock` does not (the job checks it, and says how to
  regenerate it)

And once, from `ci.yml` itself:

- `cargo test --all-features` on current stable with the lockfile removed, to
  catch dependency bitrot (`build-latest`)
- a check that the MSRV in `Cargo.toml`, `rust-toolchain.toml` and the README
  agree, which needs no compiler
- `cargo deny check` (`.github/workflows/audit.yml`, configured by `deny.toml`):
  RustSec advisories, yanked versions, licences, duplicate versions and
  dependency sources — also weekly on a schedule, since advisories arrive on
  their own clock
- `required-checks` aggregates the blocking jobs above into the one status
  branch protection requires

`--locked` is the lockfile discipline: a `Cargo.toml` change without its
`Cargo.lock` fails as "lockfile out of date" rather than testing whatever
resolves that day. Every third-party action in the workflows is pinned to a
commit, with the tag the commit came from in the comment; Dependabot proposes
the bumps for the actions and for Cargo dependencies alike.
