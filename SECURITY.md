# Security policy

`pczt_ledger` sits on the signing path of a hardware wallet. A bug that could
make a device display one transaction and sign another, leak key material or
an address, misapply a signature, or weaken one of the host-side refusals is a
security issue even when it looks like a robustness problem.

## Reporting

Please do not open a public issue for such a finding. Use GitHub's private
vulnerability reporting for this repository ("Security" → "Report a
vulnerability"), which reaches the maintainers without publishing the report.

Include the file and line the finding is about, the firmware commit you checked
it against, and a reproduction if you have one. This crate pins
`LedgerHQ/app-zcash` `1a0f649` (v3.9.4) and supports v3.9.3 (`22dc385`) and
v3.9.2 (`0e048bb`); the
crate documentation in `src/lib.rs` lists the normative sources. Please verify
each factual claim against the source at the line it cites before filing —
the review standard this project holds itself to.

## Scope

In scope: everything under `src/` — the pre-flight checks (the crate's promise
is to refuse, before the first APDU, anything the device would refuse or could
display misleadingly), the wire encoding and parsing, framing and transports,
and the path that applies the device's signatures to the PCZT.

Out of scope: the Ledger app itself (report to Ledger), the `pczt` and
`librustzcash` crates (report upstream), and a host that is already
compromised — the crate does not defend a wallet against its own machine.

## Supported versions

There is no released version yet. Reports are taken against the `main` branch,
and fixes land there.
