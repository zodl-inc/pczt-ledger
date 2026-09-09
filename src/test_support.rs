//! Fixtures and generators shared by more than one module's tests: the golden
//! record vectors, the transparent record fixtures, the command and reply
//! constants, and two `proptest` generators.
//!
//! The property tests themselves live with the module each one exercises.
//! AGENTS.md asks for `proptest` "especially when parsing", with `arb_`
//! generators, and three shapes recur across them. A *no-panic* property
//! feeds arbitrary bytes and asks only that the parser answer `Ok` or `Err`:
//! every parser indexes by a length the device declared, and the bug this
//! catches is an index past the slice. A *round-trip* property builds a value
//! with the crate's own encoder and asks the decoder for it back, over every
//! length and parameter in range rather than the handful a hand-written test
//! names. A *mutation* property corrupts one thing about a valid input and
//! asks that the parser notice.

use proptest::prelude::*;

use crate::apdu::encode::*;
use crate::limits::hash160;

/// `GET_FIRMWARE_VERSION`, as `firmware_version_apdu` builds it.
pub(crate) const VERSION_APDU: [u8; 5] = [0xE0, 0xC4, 0x00, 0x00, 0x00];

/// Its reply for app 3.9.3 on SDK 1.0, API level 3, plus `0x9000`: the
/// `0x38 0x30` legacy prefix and the layout `handler_get_firmware_version`
/// produces (`src/handlers/get_version.rs` @ `22dc385`).
pub(crate) const VERSION_REPLY: [u8; 10] = [0x38, 0x30, 3, 9, 3, 1, 0, 3, 0x90, 0x00];

/// The header vector, derived from `docs/PCZT_APDU.md#pczt_header`:
///
/// | field                 | value                     | LE bytes     |
/// |-----------------------|---------------------------|--------------|
/// | magic                 | `"PCZT"`                  | `50435a54`   |
/// | PCZT version          | 1 (required for V5)       | `01000000`   |
/// | `tx_version`          | 5                         | `05000000`   |
/// | `version_group_id`    | `0x26A7270A` (V5)         | `0a27a726`   |
/// | `consensus_branch_id` | `0xC2D6D0B4` (NU5)        | `b4d0d6c2`   |
/// | `fallback_lock_time`  | `None` → tag 0            | `00`         |
/// | `expiry_height`       | 2_500_000 = `0x2625A0`    | `a0252600`   |
/// | `coin_type`           | 133 (mainnet)             | `85000000`   |
/// | `tx_modifiable`       | `0x00`                    | `00`         |
///
/// Total 30 bytes; every integer little-endian, per `read_u32_le` in
/// `src/parser/reader.rs`.
pub(crate) fn header_vector() -> HeaderRecord {
    HeaderRecord {
        pczt_version: PCZT_VERSION_V5,
        tx_version: 5,
        version_group_id: 0x26A7_270A,
        consensus_branch_id: 0xC2D6_D0B4,
        fallback_lock_time: None,
        expiry_height: 2_500_000,
        coin_type: 133,
        tx_modifiable: 0x00,
    }
}

/// One Orchard action, every field filled with a distinct repeated byte so a
/// misordered field shows up immediately.
///
/// Field order and widths from `docs/PCZT_APDU.md#pczt_orchard_action`,
/// cross-checked against `parse_orchard_action`, `parse_orchard_output`,
/// `parse_orchard_output_metadata` and `parse_orchard_trailer` in
/// `src/parser/pczt/orchard.rs`:
///
/// - spend small fields: `cv_net` `nullifier` `rk` (32 each), `spend_recipient`
///   (43), `spend_value` (u64 LE), `spend_rho` `spend_rseed` `alpha` (32
///   each) = 243 bytes;
/// - `zip32_derivation`: `seed_fingerprint` (32) then the `Bip32Path`, with no
///   entry count — unlike the transparent one;
/// - output small fields: `cmx` `ephemeral_key` = 64 bytes;
/// - `enc_ciphertext`: CompactSize(580) + 580 = 583 bytes;
/// - `out_ciphertext`: CompactSize(80) + 80 = 81 bytes;
/// - output metadata: `recipient` (43), `value` (u64 LE), `rseed` (32), `rcv`
///   (32) = 115 bytes, the only length `parse_orchard_output_metadata` accepts.
pub(crate) fn orchard_action_vector() -> ShieldedActionRecord {
    ShieldedActionRecord {
        cv_net: [0x01; 32],
        nullifier: [0x02; 32],
        rk: [0x03; 32],
        spend_recipient: [0x04; 43],
        spend_value: 100_000_000,
        spend_rho: [0x05; 32],
        spend_rseed: [0x06; 32],
        alpha: [0x07; 32],
        zip32_derivation: Zip32Derivation {
            seed_fingerprint: [0x08; 32],
            path: DerivationPath(vec![0x8000_0020, 0x8000_0085, 0x8000_0000]),
        },
        cmx: [0x09; 32],
        ephemeral_key: [0x0A; 32],
        enc_ciphertext: [0x0B; ENC_CIPHERTEXT_SIZE],
        out_ciphertext: [0x0C; OUT_CIPHERTEXT_SIZE],
        recipient: [0x0D; 43],
        value: 90_000_000,
        rseed: [0x0E; 32],
        rcv: [0x0F; 32],
        note_plaintext_version: None,
    }
}

/// The matching trailer. `value_sum` = 100_000_000 − 90_000_000 = 10_000_000,
/// which the device cross-checks against the action sums in
/// `finish_orchard_value_sum_sign`.
pub(crate) fn orchard_trailer_vector() -> BundleTrailerRecord {
    BundleTrailerRecord {
        flags: 0x03,
        value_sum: 10_000_000,
        anchor: [0x10; 32],
    }
}

/// The pubkey every transparent test record is keyed by. Not a curve point —
/// nothing here derives from it — but `HASH160` of it is what
/// [`p2pkh_script`] pays, so the records are internally consistent.
pub(crate) const TEST_PUBKEY: [u8; 33] = [0x21; 33];

/// The P2PKH `scriptPubKey` paying [`TEST_PUBKEY`].
pub(crate) fn p2pkh_script() -> Vec<u8> {
    let mut s = vec![0x76, 0xA9, 0x14];
    s.extend_from_slice(&hash160(&TEST_PUBKEY));
    s.extend_from_slice(&[0x88, 0xAC]);
    s
}

pub(crate) fn transparent_derivation() -> TransparentDerivation {
    TransparentDerivation {
        pubkey: TEST_PUBKEY,
        seed_fingerprint: [0x22; 32],
        path: DerivationPath(vec![
            0x8000_002C,
            0x8000_0085,
            0x8000_0000,
            0x0000_0000,
            0x0000_0000,
        ]),
    }
}

/// The five-component transparent path the identity probe uses, on testnet:
/// `m/44'/1'/0'/0/0`.
pub(crate) fn testnet_identity_path() -> DerivationPath {
    DerivationPath(vec![0x8000_002C, 0x8000_0001, 0x8000_0000, 0, 0])
}

/// The secp256k1 generator point, uncompressed — a real curve point to stand in
/// for whatever key a device would derive, so that the parser is checked
/// against something `secp256k1` accepts rather than against 65 arbitrary
/// bytes.
pub(crate) const GENERATOR_UNCOMPRESSED: [u8; 65] = [
    0x04, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
    0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
    0x98, 0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08,
    0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4,
    0xB8,
];

/// A base58 address of the length a testnet P2PKH address really has.
pub(crate) const SAMPLE_ADDRESS: &str = "tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU";

/// Builds a reply body: `pk_len ‖ pk ‖ addr_len ‖ addr ‖ chain_code`.
pub(crate) fn wallet_public_key_reply(pk: &[u8], address: &[u8], chain_code: &[u8]) -> Vec<u8> {
    let mut out = vec![pk.len() as u8];
    out.extend_from_slice(pk);
    out.push(address.len() as u8);
    out.extend_from_slice(address);
    out.extend_from_slice(chain_code);
    out
}

pub(crate) fn v5_plan() -> StreamPlan {
    StreamPlan {
        header: header_vector(),
        transparent_inputs: Vec::new(),
        transparent_outputs: Vec::new(),
        orchard_actions: vec![orchard_action_vector()],
        orchard_trailer: Some(orchard_trailer_vector()),
        ironwood_actions: None,
        ironwood_trailer: None,
    }
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/// Arbitrary bytes of a bounded length, for the no-panic properties.
pub(crate) fn arb_bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=max)
}

pub(crate) fn arb_secret_key() -> impl Strategy<Value = secp256k1::SecretKey> {
    any::<[u8; 32]>().prop_filter_map("not a secp256k1 scalar", |bytes| {
        secp256k1::SecretKey::from_slice(&bytes).ok()
    })
}
