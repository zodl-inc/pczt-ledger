//! Builds `pczt_ledger` without its `std` feature into a crate with no
//! standard library. See `Cargo.toml` here and `.github/workflows/checks.yml`.
#![no_std]

pub use pczt_ledger;

/// The `getrandom` backend this target lacks. It refuses every request:
/// `pczt_ledger` applies signatures the device made and makes none itself, and
/// the `pczt` Signer calls it makes draw no randomness. An embedding with a
/// hardware generator registers that instead.
fn no_randomness(_dest: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

getrandom::register_custom_getrandom!(no_randomness);
