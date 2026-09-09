# pczt_ledger

A transport-agnostic Rust engine for signing Zcash transactions with Ledger
hardware wallets.

`pczt_ledger` turns a [PCZT] (ZIP 374) into the APDU stream the Ledger embedded
Zcash app consumes, collects the device's detached signatures, and applies them
back onto the PCZT — ready for the wallet to combine, finalize, and extract. It
is the Signer step of the PCZT role model, and nothing else: the wallet owns
transaction construction, proving, and broadcast.

[PCZT]: https://zips.z.cash/zip-0374
