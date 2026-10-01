# pczt_ledger

A transport-agnostic Rust engine for signing Zcash transactions with Ledger
hardware wallets.

`pczt_ledger` turns a [PCZT] (ZIP 374) into the APDU stream the Ledger embedded
Zcash app consumes, collects the device's detached signatures, and applies them
back onto the PCZT — ready for the wallet to combine, finalize, and extract. It
is the Signer step of the PCZT role model, plus the two Updater passes that step
needs: one that puts the PCZT into the shape the device requires (derivation
paths, change marking) before anything is streamed, and one that stamps the
`hash160_preimage`s the transparent signatures attach to. The PCZT that comes
back therefore differs from the one that went in by more than its signatures.
The wallet owns transaction construction, proving, and broadcast.

[PCZT]: https://zips.z.cash/zip-0374

## Design

- **`no_std` core.** Everything from the redacted PCZT to the APDU bytes, and
  from the device's replies back onto the PCZT, builds without the standard
  library (`default-features = false`, with `alloc`): the build a
  firmware-side or FFI embedding makes. The `std` feature, on by default, adds
  the blocking `Transport` trait, the two optional transports and the
  `ceremony` runner. CI builds the `no_std` half into a bare-metal target.
- **Sans-I/O core.** The signing session is a pull-pump state machine; it hands
  out APDU bytes and absorbs replies, and never touches a device. Any
  embedding — a CLI, a wallet daemon, a mobile app driving Bluetooth from the
  platform side — carries the bytes however it likes.
- **Optional transports.** A blocking `Transport` trait ships with two concrete
  implementations behind off-by-default features that imply `std`:
  `transport-hid` (USB HID via `hidapi`) and `transport-speculos` (TCP to the
  [speculos] emulator). BLE
  embeddings use the frame codec in `framing` directly.
- **Pinned firmware.** Written against `LedgerHQ/app-zcash` v3.9.4
  (`1a0f649`), with v3.9.3 (`22dc385`) and v3.9.2 (`0e048bb`) supported
  through runtime version gating of the device bounds. An app older than
  v3.6.0 has no PCZT instructions and is refused before a transaction byte is
  sent. v3.9.4 and v3.9.3 share their bounds, and v3.6.0 through v3.9.2 are
  held to v3.9.2's, whose record counts they share. Before v3.9.4 the app
  hashes a memo it cannot show as text with an uninitialized context, so on
  those versions a transaction whose review would show a hashed memo is
  refused, when viewing keys let the host see the memos. An app newer than
  v3.9.4 is one the crate
  has not been checked against: it is refused before a transaction byte is
  sent unless the caller names the bounds to hold it to
  (`SessionParams::with_unknown_version_bounds`).
- **Fail closed, as far as the host can see.** Everything the host can check
  is checked before the first APDU: a transaction the device would refuse, or
  could display misleadingly, is rejected host-side. What the host cannot see
  stays with the device — the memo display budget when no viewing keys are
  supplied, the app's own per-run key-derivation budget, a change output the
  wallet did not declare — and the crate documentation names each such case
  where it arises.
- **Shielded outputs the device can open.** The app reviews a shielded output
  only by decrypting it: change under the account's internal IVK, anything
  else under the account's external OVK. A Ledger account's transactions must
  therefore build every other shielded output with `OvkPolicy::Sender`. One
  built with `OvkPolicy::Discard`, or under any other outgoing viewing key, is
  refused: before the first APDU when the session has the account's viewing
  keys (`PlanError::UndecryptableOutput`), and by the device mid-stream when
  it does not. Only internal-scope outputs are change: an output to one of
  the account's own external addresses is reviewed as a payment, with no
  mark that it is the user's own.

[speculos]: https://github.com/LedgerHQ/speculos

## Documentation

API documentation — including the normative firmware pin, the known
discrepancies in the firmware's own documents, and the wire-contract notes — is
in the crate rustdoc. Until the first crates.io release it is built locally:

```sh
cargo doc --no-deps --all-features --open
```

## Security

A finding that could make the device display one transaction and sign another,
leak key material or an address, misapply a signature, or weaken a host-side
refusal is a security issue. Please report it privately, as
[SECURITY.md](SECURITY.md) describes, rather than in a public issue.

## Contributing

Open an issue and wait for a maintainer to acknowledge the proposed change
before starting on a pull request; a PR without that prior discussion is likely
to be closed. Every change must pass the full CI matrix (tests, clippy, rustfmt
and rustdoc for every feature set, on the MSRV and on current stable). If AI
tools were used in preparing a commit, its message must carry a
`Co-Authored-By:` trailer naming the system, and the contributor remains the
sole responsible author. `AGENTS.md` has the full policy and the crate's
engineering rules.

## Minimum Supported Rust Version

Rust **1.88** or newer.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
