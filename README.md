# pczt_ledger

A transport-agnostic Rust engine for signing Zcash transactions with Ledger
hardware wallets.

`pczt_ledger` turns a [PCZT] (ZIP 374) into the APDU stream the Ledger embedded
Zcash app consumes, collects the device's detached signatures, and applies them
back onto the PCZT — ready for the wallet to combine, finalize, and extract. It
is the Signer step of the PCZT role model, and nothing else: the wallet owns
transaction construction, proving, and broadcast.

[PCZT]: https://zips.z.cash/zip-0374

## Design

- **Sans-I/O core.** The signing session is a pull-pump state machine; it hands
  out APDU bytes and absorbs replies, and never touches a device. Any
  embedding — a CLI, a wallet daemon, a mobile app driving Bluetooth from the
  platform side — carries the bytes however it likes.
- **Optional transports.** A blocking `Transport` trait ships with two concrete
  implementations behind off-by-default features: `transport-hid` (USB HID via
  `hidapi`) and `transport-speculos` (TCP to the [speculos] emulator). BLE
  embeddings use the frame codec in `framing` directly.
- **Fail closed.** Transactions the device would refuse — or could display
  misleadingly — are rejected host-side before the first APDU is sent.

[speculos]: https://github.com/LedgerHQ/speculos

## Documentation

API documentation, including the normative firmware pin and the wire-contract
notes, lives in the crate rustdoc: <https://docs.rs/pczt_ledger>.

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
