//! Unit tests.
//!
//! The golden vectors are constructed here rather than captured from a device:
//! each one is derived field by field from `docs/PCZT_APDU.md` and
//! `docs/APDU.md` at `LedgerHQ/app-zcash` `0e048bb`, and the derivation is
//! spelled out in the test that uses it. The framing vectors are the ones in
//! `DefaultApduSenderService.test.ts` in `LedgerHQ/device-sdk-ts`.

use crate::apdu::decode::*;
use crate::apdu::encode::*;
use crate::apdu::*;
use crate::framing::*;
use crate::limits::*;

// ---------------------------------------------------------------------------
// Chunker
// ---------------------------------------------------------------------------

#[test]
fn chunk_bytes_empty_yields_one_empty_piece() {
    // A command always occupies at least one packet, even with no payload.
    let chunks = chunk_bytes(&[]);
    assert_eq!(chunks.len(), 1);
    assert!(chunks[0].is_empty());
}

#[test]
fn chunk_bytes_exactly_255_is_one_piece() {
    let data = vec![0xAA; 255];
    let chunks = chunk_bytes(&data);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].len(), 255);
}

#[test]
fn chunk_bytes_256_splits_255_plus_1() {
    let data = vec![0xAA; 256];
    let chunks = chunk_bytes(&data);
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].len(), 255);
    assert_eq!(chunks[1].len(), 1);
}

#[test]
fn chunk_bytes_multi_chunk_lengths() {
    let data = vec![0xAA; 583]; // an `enc_ciphertext` group: 3 + 580.
    let chunks = chunk_bytes(&data);
    assert_eq!(
        chunks.iter().map(|c| c.len()).collect::<Vec<_>>(),
        vec![255, 255, 73]
    );
}

#[test]
fn single_packet_command_uses_p1_first_not_p1_last() {
    // `docs/PCZT_APDU.md`: "A one-packet command uses `P1_FIRST`."
    let apdus = chunk_command(Ins::PcztOrchardAction, &[vec![0x00]], Finish::Continue);
    assert_eq!(apdus.len(), 1);
    assert_eq!(apdus[0].p1, p1::FIRST);
    assert_eq!(apdus[0].p2, p2::PCZT_CONTINUE);
}

#[test]
fn two_packet_command_is_first_then_last() {
    let apdus = chunk_command(
        Ins::PcztTransparentInput,
        &[vec![0x11; 256]],
        Finish::Continue,
    );
    assert_eq!(apdus.len(), 2);
    assert_eq!(apdus[0].p1, p1::FIRST);
    assert_eq!(apdus[1].p1, p1::LAST);
}

#[test]
fn many_packet_command_is_first_next_last() {
    let apdus = chunk_command(
        Ins::PcztOrchardAction,
        &[vec![0x22; 1000]],
        Finish::Continue,
    );
    // 1000 = 255 * 3 + 235
    assert_eq!(apdus.len(), 4);
    assert_eq!(
        apdus.iter().map(|a| a.p1).collect::<Vec<_>>(),
        vec![p1::FIRST, p1::NEXT, p1::NEXT, p1::LAST]
    );
}

#[test]
fn finished_marker_lands_only_on_the_last_packet() {
    let apdus = chunk_command(
        Ins::PcztIronwoodAction,
        &[vec![0x33; 600]],
        Finish::Finished,
    );
    assert_eq!(apdus.len(), 3);
    assert_eq!(apdus[0].p2, p2::PCZT_CONTINUE);
    assert_eq!(apdus[1].p2, p2::PCZT_CONTINUE);
    assert_eq!(apdus[2].p2, p2::PCZT_FINISHED);
}

#[test]
fn finished_marker_on_a_single_packet_command() {
    // The empty-Ironwood-bundle case: the count packet is the whole command,
    // so it carries both `P1_FIRST` and `P2_PCZT_FINISHED`.
    let apdus = shielded_action_apdus(ShieldedPool::Ironwood, &[], None, Finish::Finished).unwrap();
    assert_eq!(apdus.len(), 1);
    assert_eq!(apdus[0].data, vec![0x00]);
    assert_eq!(apdus[0].p1, p1::FIRST);
    assert_eq!(apdus[0].p2, p2::PCZT_FINISHED);
    assert_eq!(apdus[0].ins, Ins::PcztIronwoodAction.code());
}

#[test]
fn groups_never_share_a_packet() {
    // Two 10-byte groups would fit in one 255-byte packet, but the device's
    // parser asserts the reader is drained at each group boundary.
    let packets = pack_groups(&[vec![0xAA; 10], vec![0xBB; 10]]);
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].len(), 10);
    assert_eq!(packets[1].len(), 10);
}

// ---------------------------------------------------------------------------
// Status words
// ---------------------------------------------------------------------------

#[test]
fn status_word_mapping_round_trips() {
    for sw in [
        StatusWord::Ok,
        StatusWord::Deny,
        StatusWord::ConditionsOfUseNotSatisfied,
        StatusWord::IncorrectData,
        StatusWord::NotEnoughMemorySpace,
        StatusWord::WrongApduLength,
        StatusWord::WrongP1P2,
        StatusWord::InsNotSupported,
        StatusWord::ClaNotSupported,
        StatusWord::SecurityStatusNotSatisfied,
        StatusWord::TechnicalProblem,
        StatusWord::VersionParsingFail,
        StatusWord::TxParsingFail,
        StatusWord::RngFailure,
        StatusWord::MemoryProblem,
        StatusWord::BadState,
        StatusWord::CmdNotAccepted,
    ] {
        assert_eq!(StatusWord::from_u16(sw.to_u16()), sw);
    }
}

#[test]
fn status_word_numeric_values_match_app_sw() {
    // `enum AppSW` in `src/main.rs`.
    assert_eq!(StatusWord::Ok.to_u16(), 0x9000);
    assert_eq!(StatusWord::Deny.to_u16(), 0x6985);
    assert_eq!(StatusWord::ConditionsOfUseNotSatisfied.to_u16(), 0x6986);
    assert_eq!(StatusWord::IncorrectData.to_u16(), 0x6A80);
    assert_eq!(StatusWord::NotEnoughMemorySpace.to_u16(), 0x6A84);
    assert_eq!(StatusWord::WrongApduLength.to_u16(), 0x6700);
    assert_eq!(StatusWord::WrongP1P2.to_u16(), 0x6B00);
    assert_eq!(StatusWord::InsNotSupported.to_u16(), 0x6D00);
    assert_eq!(StatusWord::ClaNotSupported.to_u16(), 0x6E00);
    assert_eq!(StatusWord::TechnicalProblem.to_u16(), 0x6F00);
    assert_eq!(StatusWord::VersionParsingFail.to_u16(), 0x6F01);
    assert_eq!(StatusWord::TxParsingFail.to_u16(), 0x6F02);
    // New in v3.9.3.
    assert_eq!(StatusWord::RngFailure.to_u16(), 0x6F03);
    assert_eq!(StatusWord::MemoryProblem.to_u16(), 0x9240);
    assert_eq!(StatusWord::BadState.to_u16(), 0xB007);
    // Not from `enum AppSW` at all: the device SDK's legacy I/O layer raises
    // it (`docs/APDU.md` @ `22dc385`).
    assert_eq!(StatusWord::CmdNotAccepted.to_u16(), 0x6901);
}

#[test]
fn status_word_classification() {
    assert_eq!(StatusWord::Ok.class(), StatusClass::Ok);
    // 0x6985 is user denial in this app, not "conditions of use".
    assert_eq!(StatusWord::Deny.class(), StatusClass::UserCancel);
    assert_eq!(StatusWord::ClaNotSupported.class(), StatusClass::WrongApp);
    assert_eq!(StatusWord::InsNotSupported.class(), StatusClass::WrongApp);
    assert_eq!(
        StatusWord::ConditionsOfUseNotSatisfied.class(),
        StatusClass::Fatal
    );
    assert_eq!(StatusWord::BadState.class(), StatusClass::Fatal);
    // A hardware RNG failure is fatal, and no retry on the same device helps.
    assert_eq!(StatusWord::RngFailure.class(), StatusClass::Fatal);
    assert!(!StatusWord::RngFailure.is_retriable());
    assert_eq!(StatusWord::Unknown(0x1234).class(), StatusClass::Fatal);

    // `0x6901` is the one frame-level refusal: the app never saw the command,
    // so its transaction context is intact and the same APDU can go again.
    assert_eq!(StatusWord::CmdNotAccepted.class(), StatusClass::Retriable);
    assert!(StatusWord::CmdNotAccepted.is_retriable());

    // Everything else stays non-retriable: any non-`0x9000` reply the *app*
    // produces has already reset its tx context.
    for sw in [
        StatusWord::Deny,
        StatusWord::BadState,
        StatusWord::IncorrectData,
        StatusWord::NotEnoughMemorySpace,
        StatusWord::Unknown(0x1234),
    ] {
        assert!(!sw.is_retriable());
    }
}

// ---------------------------------------------------------------------------
// CompactSize
// ---------------------------------------------------------------------------

#[test]
fn compact_size_boundaries() {
    let enc = |n| {
        let mut v = Vec::new();
        write_compact_size(&mut v, n);
        v
    };
    assert_eq!(enc(0), vec![0x00]);
    assert_eq!(enc(1), vec![0x01]);
    // 252 is the largest single-byte CompactSize, which is exactly why the
    // device caps `script_pubkey` there (`MAX_PCZT_SCRIPT_SIZE`).
    assert_eq!(enc(252), vec![0xFC]);
    assert_eq!(enc(253), vec![0xFD, 0xFD, 0x00]);
    // 580 = `ORCHARD_ENC_CIPHERTEXT_SIZE` = 0x0244.
    assert_eq!(enc(580), vec![0xFD, 0x44, 0x02]);
    assert_eq!(enc(0x1_0000), vec![0xFE, 0x00, 0x00, 0x01, 0x00]);
}

#[test]
fn optional_u32_tagging() {
    let mut v = Vec::new();
    write_optional_u32(&mut v, None);
    assert_eq!(v, vec![0x00]);

    let mut v = Vec::new();
    write_optional_u32(&mut v, Some(0xDEAD_BEEF));
    // Tag 1, then little-endian.
    assert_eq!(v, vec![0x01, 0xEF, 0xBE, 0xAD, 0xDE]);
}

#[test]
fn derivation_path_components_are_big_endian() {
    // `docs/APDU.md`: "`m/32'/133'/0'` is encoded as one length byte `0x03`,
    // followed by three big-endian `u32` components." Confirmed by
    // `Bip32Path::from_dpath`, which uses `u32::from_be_bytes`.
    let path = DerivationPath(vec![0x8000_0020, 0x8000_0085, 0x8000_0000]);
    assert_eq!(
        hex::encode(path.to_bytes().unwrap()),
        "03800000208000008580000000"
    );
}

#[test]
fn derivation_path_longer_than_ten_is_rejected() {
    let path = DerivationPath(vec![0; 11]);
    assert_eq!(path.to_bytes(), Err(EncodeError::PathTooLong(11)));
}

// ---------------------------------------------------------------------------
// Golden: PCZT_HEADER
// ---------------------------------------------------------------------------

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
fn header_vector() -> HeaderRecord {
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

#[test]
fn golden_header_payload() {
    let payload = header_vector().payload();
    assert_eq!(payload.len(), 30);
    assert_eq!(
        hex::encode(&payload),
        "50435a5401000000050000000a27a726b4d0d6c200a02526008500000000"
    );
}

#[test]
fn golden_header_apdu_bytes() {
    // `docs/APDU.md`: INS 0x52, P1 0x00, P2 0x00, single packet. Lc = 30 = 0x1e.
    let apdu = header_apdu(&header_vector());
    assert_eq!(apdu.cla, 0xE0);
    assert_eq!(apdu.ins, 0x52);
    assert_eq!(apdu.p1, 0x00);
    assert_eq!(apdu.p2, 0x00);

    let wire = apdu.to_bytes();
    assert_eq!(&wire[..5], &[0xE0, 0x52, 0x00, 0x00, 0x1E]);
    assert_eq!(wire.len(), 35);
}

#[test]
fn header_with_lock_time_is_four_bytes_longer() {
    let mut h = header_vector();
    h.fallback_lock_time = Some(0);
    assert_eq!(h.payload().len(), 34);
    // Tag byte flips from 0 to 1, at offset 4+4+4+4+4 = 20.
    assert_eq!(h.payload()[20], 0x01);
}

// ---------------------------------------------------------------------------
// Golden: PCZT_ORCHARD_ACTION
// ---------------------------------------------------------------------------

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
fn orchard_action_vector() -> ShieldedActionRecord {
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
        enc_ciphertext: vec![0x0B; ENC_CIPHERTEXT_SIZE],
        out_ciphertext: vec![0x0C; OUT_CIPHERTEXT_SIZE],
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
fn orchard_trailer_vector() -> BundleTrailerRecord {
    BundleTrailerRecord {
        flags: 0x03,
        value_sum: 10_000_000,
        anchor: [0x10; 32],
    }
}

#[test]
fn golden_orchard_action_group_layout() {
    let groups =
        shielded_action_groups(&[orchard_action_vector()], Some(&orchard_trailer_vector()))
            .unwrap();

    // count, spend, zip32, output, enc, out_ct, metadata, trailer
    assert_eq!(
        groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
        vec![1, 243, 45, 64, 583, 81, 115, 42]
    );
}

#[test]
fn golden_orchard_spend_packet_bytes() {
    let groups =
        shielded_action_groups(&[orchard_action_vector()], Some(&orchard_trailer_vector()))
            .unwrap();

    let expected = format!(
        "{}{}{}{}{}{}{}{}",
        "01".repeat(32), // cv_net
        "02".repeat(32), // nullifier
        "03".repeat(32), // rk
        "04".repeat(43), // spend_recipient
        // spend_value 100_000_000 = 0x05F5E100, little-endian.
        "00e1f50500000000",
        "05".repeat(32), // spend_rho
        "06".repeat(32), // spend_rseed
        "07".repeat(32), // alpha
    );
    assert_eq!(hex::encode(&groups[1]), expected);
}

#[test]
fn golden_orchard_zip32_packet_bytes() {
    let groups =
        shielded_action_groups(&[orchard_action_vector()], Some(&orchard_trailer_vector()))
            .unwrap();

    // seed fingerprint, then `path_len` and three big-endian components:
    // m/32'/133'/0' = 0x80000020, 0x80000085, 0x80000000.
    let expected = format!("{}03800000208000008580000000", "08".repeat(32));
    assert_eq!(hex::encode(&groups[2]), expected);
}

#[test]
fn golden_orchard_ciphertext_groups_carry_their_compact_size() {
    let groups =
        shielded_action_groups(&[orchard_action_vector()], Some(&orchard_trailer_vector()))
            .unwrap();

    assert_eq!(&groups[4][..3], &[0xFD, 0x44, 0x02]); // CompactSize(580)
    assert!(groups[4][3..].iter().all(|b| *b == 0x0B));
    assert_eq!(groups[5][0], 0x50); // CompactSize(80)
    assert!(groups[5][1..].iter().all(|b| *b == 0x0C));
}

#[test]
fn golden_orchard_metadata_packet_bytes() {
    let groups =
        shielded_action_groups(&[orchard_action_vector()], Some(&orchard_trailer_vector()))
            .unwrap();

    let expected = format!(
        "{}{}{}{}",
        "0d".repeat(43),
        // value 90_000_000 = 0x055D4A80, little-endian.
        "804a5d0500000000",
        "0e".repeat(32),
        "0f".repeat(32),
    );
    assert_eq!(hex::encode(&groups[6]), expected);
    assert_eq!(groups[6].len(), 115);
}

#[test]
fn golden_orchard_trailer_packet_bytes() {
    let groups =
        shielded_action_groups(&[orchard_action_vector()], Some(&orchard_trailer_vector()))
            .unwrap();

    let expected = format!(
        "{}{}{}{}",
        "03",               // flags
        "8096980000000000", // magnitude 10_000_000 = 0x00989680, LE
        "00",               // sign: 0 = positive
        "10".repeat(32),    // anchor
    );
    assert_eq!(hex::encode(&groups[7]), expected);
}

#[test]
fn value_sum_sign_byte_is_one_when_negative() {
    // `finish_orchard_value_sum_sign`: byte 0 is `+magnitude`, byte 1 is
    // `-magnitude`.
    let t = BundleTrailerRecord {
        flags: 0x00,
        value_sum: -10_000_000,
        anchor: [0x00; 32],
    };
    let p = t.payload().unwrap();
    assert_eq!(&p[1..9], &10_000_000u64.to_le_bytes());
    assert_eq!(p[9], 0x01);
}

#[test]
fn value_sum_of_i64_min_is_rejected() {
    // The device converts the magnitude back with `i64::try_from`, so
    // `-(i64::MIN)` has no representable magnitude.
    let t = BundleTrailerRecord {
        flags: 0x00,
        value_sum: i64::MIN,
        anchor: [0x00; 32],
    };
    assert!(matches!(
        t.payload(),
        Err(EncodeError::ValueSumOutOfRange(_))
    ));
}

#[test]
fn golden_orchard_command_packet_sequence() {
    let apdus = shielded_action_apdus(
        ShieldedPool::Orchard,
        &[orchard_action_vector()],
        Some(&orchard_trailer_vector()),
        Finish::Finished,
    )
    .unwrap();

    // Groups [1, 243, 45, 64, 583, 81, 115, 42]; only the 583-byte
    // `enc_ciphertext` group spans packets, as 255 + 255 + 73.
    assert_eq!(
        apdus.iter().map(|a| a.data.len()).collect::<Vec<_>>(),
        vec![1, 243, 45, 64, 255, 255, 73, 81, 115, 42]
    );
    assert_eq!(
        apdus.iter().map(|a| a.p1).collect::<Vec<_>>(),
        vec![
            p1::FIRST,
            p1::NEXT,
            p1::NEXT,
            p1::NEXT,
            p1::NEXT,
            p1::NEXT,
            p1::NEXT,
            p1::NEXT,
            p1::NEXT,
            p1::LAST
        ]
    );
    let p2s: Vec<u8> = apdus.iter().map(|a| a.p2).collect();
    assert!(p2s[..9].iter().all(|p| *p == p2::PCZT_CONTINUE));
    assert_eq!(p2s[9], p2::PCZT_FINISHED);
    assert!(apdus.iter().all(|a| a.ins == 0x56));
}

#[test]
fn empty_orchard_bundle_is_a_single_count_packet() {
    // "This command is still sent when a transaction has no Orchard actions.
    // In that case its payload is only the CompactSize action count `0`."
    let apdus = shielded_action_apdus(ShieldedPool::Orchard, &[], None, Finish::Finished).unwrap();
    assert_eq!(apdus.len(), 1);
    assert_eq!(apdus[0].data, vec![0x00]);
}

#[test]
fn ironwood_note_plaintext_version_makes_metadata_116_bytes() {
    let mut action = orchard_action_vector();
    action.note_plaintext_version = Some(NOTE_VERSION_IRONWOOD);
    let groups = shielded_action_groups(&[action], Some(&orchard_trailer_vector())).unwrap();
    assert_eq!(groups[6].len(), 116);
    assert_eq!(*groups[6].last().unwrap(), 0x03);
}

#[test]
fn wrong_ciphertext_length_is_rejected() {
    let mut action = orchard_action_vector();
    action.enc_ciphertext = vec![0x00; 579];
    assert_eq!(
        shielded_action_groups(&[action], None),
        Err(EncodeError::BadCiphertextLength {
            field: "enc_ciphertext",
            expected: 580,
            got: 579,
        })
    );
}

// ---------------------------------------------------------------------------
// Transparent records
// ---------------------------------------------------------------------------

/// The pubkey every transparent test record is keyed by. Not a curve point —
/// nothing here derives from it — but `HASH160` of it is what
/// [`p2pkh_script`] pays, so the records are internally consistent.
const TEST_PUBKEY: [u8; 33] = [0x21; 33];

/// The P2PKH `scriptPubKey` paying [`TEST_PUBKEY`].
fn p2pkh_script() -> Vec<u8> {
    let mut s = vec![0x76, 0xA9, 0x14];
    s.extend_from_slice(&hash160(&TEST_PUBKEY));
    s.extend_from_slice(&[0x88, 0xAC]);
    s
}

fn transparent_derivation() -> TransparentDerivation {
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

#[test]
fn transparent_input_group_layout() {
    let input = TransparentInputRecord {
        prevout_txid: [0x31; 32],
        prevout_index: 1,
        sequence: None,
        value: 50_000,
        script_pubkey: p2pkh_script(),
        sighash_type: SIGHASH_ALL,
        derivation: transparent_derivation(),
    };
    let groups = transparent_input_groups(&[input]).unwrap();

    // count | prevout(36) + sequence tag(1) + value(8) = 45 | 1 + 25 script |
    // sighash(1) + count(1) + pubkey(33) + fingerprint(32) + path(21) = 88
    assert_eq!(
        groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
        vec![1, 45, 26, 88]
    );
    assert_eq!(groups[0], vec![0x01]);
    // prevout_index is little-endian.
    assert_eq!(&groups[1][32..36], &[0x01, 0x00, 0x00, 0x00]);
    // `None` sequence is the bare 0 tag.
    assert_eq!(groups[1][36], 0x00);
    assert_eq!(&groups[1][37..], &50_000u64.to_le_bytes());
    // The script group carries its own CompactSize.
    assert_eq!(groups[2][0], 25);
    // The signing packet leads with the sighash type then the entry count.
    assert_eq!(groups[3][0], SIGHASH_ALL);
    assert_eq!(groups[3][1], 0x01);
}

#[test]
fn transparent_input_with_explicit_sequence_is_four_bytes_longer() {
    let input = TransparentInputRecord {
        prevout_txid: [0x31; 32],
        prevout_index: 0,
        sequence: Some(0xFFFF_FFFE),
        value: 1,
        script_pubkey: p2pkh_script(),
        sighash_type: SIGHASH_ALL,
        derivation: transparent_derivation(),
    };
    let groups = transparent_input_groups(&[input]).unwrap();
    assert_eq!(groups[1].len(), 49);
    assert_eq!(groups[1][36], 0x01);
    assert_eq!(&groups[1][37..41], &[0xFE, 0xFF, 0xFF, 0xFF]);
}

#[test]
fn transparent_output_without_derivation_ends_in_a_zero_count() {
    let output = TransparentOutputRecord {
        value: 42,
        script_pubkey: p2pkh_script(),
        derivation: None,
    };
    let groups = transparent_output_groups(&[output]).unwrap();
    assert_eq!(
        groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
        vec![1, 8, 26, 1]
    );
    assert_eq!(groups[1], 42u64.to_le_bytes().to_vec());
    assert_eq!(groups[3], vec![0x00]);
}

#[test]
fn transparent_output_with_change_derivation() {
    let output = TransparentOutputRecord {
        value: 42,
        script_pubkey: p2pkh_script(),
        derivation: Some(transparent_derivation()),
    };
    let groups = transparent_output_groups(&[output]).unwrap();
    // 1 count + 33 pubkey + 32 fingerprint + 21 path
    assert_eq!(groups[3].len(), 87);
    assert_eq!(groups[3][0], 0x01);
}

#[test]
fn empty_transparent_sections_are_still_sent() {
    // "`PCZT_TRANSPARENT_INPUT` and `PCZT_TRANSPARENT_OUTPUT` are always sent.
    // Use count `0` when either transparent section is empty."
    let inputs = transparent_input_apdus(&[]).unwrap();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].data, vec![0x00]);
    assert_eq!(inputs[0].p2, p2::PCZT_CONTINUE);

    let outputs = transparent_output_apdus(&[]).unwrap();
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].data, vec![0x00]);
}

#[test]
fn a_252_byte_script_still_uses_a_single_byte_compact_size() {
    let input = TransparentInputRecord {
        prevout_txid: [0; 32],
        prevout_index: 0,
        sequence: None,
        value: 0,
        script_pubkey: vec![0x51; MAX_SCRIPT_SIZE],
        sighash_type: SIGHASH_ALL,
        derivation: transparent_derivation(),
    };
    let groups = transparent_input_groups(std::slice::from_ref(&input)).unwrap();
    // 252 = 0xFC, the largest single-byte CompactSize.
    assert_eq!(groups[2][0], 0xFC);
    assert_eq!(groups[2].len(), 253);

    // 253 still fits one packet, which is the point of the 252-byte cap: no
    // transparent script ever spans APDUs, so the device's script state
    // machine only ever needs its single-packet path here.
    let apdus = transparent_input_apdus(&[input]).unwrap();
    assert_eq!(
        apdus.iter().map(|a| a.data.len()).collect::<Vec<_>>(),
        vec![1, 45, 253, 88]
    );
}

// ---------------------------------------------------------------------------
// Sign / key / version commands
// ---------------------------------------------------------------------------

#[test]
fn sign_commands_are_bare_headers_with_the_index_in_p2() {
    let t = sign_transparent_apdu(3);
    assert_eq!(t.to_bytes(), vec![0xE0, 0x55, 0x00, 0x03, 0x00]);

    let o = sign_shielded_apdu(ShieldedPool::Orchard, 0);
    assert_eq!(o.to_bytes(), vec![0xE0, 0x57, 0x00, 0x00, 0x00]);

    let i = sign_shielded_apdu(ShieldedPool::Ironwood, 9);
    assert_eq!(i.to_bytes(), vec![0xE0, 0x59, 0x00, 0x09, 0x00]);
}

#[test]
fn get_firmware_version_is_a_bare_header() {
    assert_eq!(
        get_firmware_version_apdu().to_bytes(),
        vec![0xE0, 0xC4, 0x00, 0x00, 0x00]
    );
}

#[test]
fn get_ufvk_carries_two_length_prefixed_paths() {
    let orchard = DerivationPath(vec![0x8000_0020, 0x8000_0085, 0x8000_0000]);
    let transparent = DerivationPath(vec![0x8000_002C, 0x8000_0085, 0x8000_0000]);
    let apdu = get_ufvk_apdu(&orchard, &transparent).unwrap();

    assert_eq!(apdu.ins, 0x50);
    assert_eq!(apdu.p1, 0x00);
    assert_eq!(apdu.p2, 0x00);
    assert_eq!(
        hex::encode(&apdu.data),
        "03800000208000008580000000038000002c8000008580000000"
    );
    // Two three-component paths: 2 * (1 + 12).
    assert_eq!(apdu.data.len(), 26);
}

#[test]
fn get_vk_continue_is_empty_with_p1_80() {
    let apdu = get_vk_continue_apdu(p2::VK_UFVK);
    assert_eq!(apdu.to_bytes(), vec![0xE0, 0x50, 0x80, 0x00, 0x00]);
}

#[test]
fn get_shield_addr_display_flag_lives_in_p1() {
    let orchard = DerivationPath(vec![0x8000_0020, 0x8000_0085, 0x8000_0000]);
    let silent = get_orchard_address_apdu(&orchard, false).unwrap();
    assert_eq!(silent.p1, 0x00);
    assert_eq!(silent.p2, p2::ADDR_ORCHARD);

    let transparent = DerivationPath(vec![0x8000_002C, 0x8000_0085, 0x8000_0000, 0, 7]);
    let shown = get_unified_address_apdu(&orchard, &transparent, true).unwrap();
    assert_eq!(shown.p1, 0x01);
    assert_eq!(shown.p2, p2::ADDR_UNIFIED);
}

/// P1 `0x01` with P2 `0x01` is refused before the APDU exists.
///
/// `handler_get_shielded_addr` @ `22dc385` answers it `WrongP1P2` ahead of the
/// derivation: a raw Orchard receiver has no screen to show.
#[test]
fn a_raw_orchard_receiver_cannot_be_displayed() {
    let orchard = DerivationPath(vec![0x8000_0020, 0x8000_0085, 0x8000_0000]);
    assert_eq!(
        get_orchard_address_apdu(&orchard, true),
        Err(EncodeError::OrchardAddressCannotBeDisplayed),
    );
}

/// The five-component transparent path the identity probe uses, on testnet:
/// `m/44'/1'/0'/0/0`.
fn testnet_identity_path() -> DerivationPath {
    DerivationPath(vec![0x8000_002C, 0x8000_0001, 0x8000_0000, 0, 0])
}

/// The golden `GET_WALLET_PUBLIC_KEY` command for that path.
///
/// `E0 40 00 00 15` then `05` and five big-endian components. `Lc` is `0x15` =
/// 21 = one length byte plus five `u32`s, and P2 is zero because
/// `Instruction::try_from` matches that literal and answers `WrongP1P2`
/// otherwise.
#[test]
fn golden_wallet_public_key_apdu_bytes() {
    let apdu = get_wallet_public_key_apdu(&testnet_identity_path(), false).expect("a path encodes");

    assert_eq!(
        hex::encode(apdu.to_bytes()),
        "e040000015058000002c80000001800000000000000000000000"
    );
    assert_eq!(apdu.p2, p2::WALLET_PUBLIC_KEY);
}

/// The display flag is P1, exactly as on `GET_SHIELD_ADDR`, and nothing else
/// about the command moves.
#[test]
fn the_wallet_public_key_display_flag_lives_in_p1() {
    let silent = get_wallet_public_key_apdu(&testnet_identity_path(), false).expect("encodes");
    let shown = get_wallet_public_key_apdu(&testnet_identity_path(), true).expect("encodes");

    assert_eq!(silent.p1, p1::NO_DISPLAY);
    assert_eq!(shown.p1, p1::DISPLAY);
    assert_eq!(shown.to_bytes()[..4], [0xE0, 0x40, 0x01, 0x00]);
    assert_eq!(silent.data, shown.data);
}

/// The path length rule is the shared one: eleven components do not encode.
#[test]
fn a_wallet_public_key_path_longer_than_ten_is_rejected() {
    let path = DerivationPath(vec![0x8000_002C; 11]);
    assert_eq!(
        get_wallet_public_key_apdu(&path, false),
        Err(EncodeError::PathTooLong(11))
    );
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

#[test]
fn status_word_is_the_last_two_bytes() {
    let (data, sw) = split_status_word(&[0xAA, 0xBB, 0x90, 0x00]).unwrap();
    assert_eq!(data, &[0xAA, 0xBB]);
    assert_eq!(sw, StatusWord::Ok);

    let (data, sw) = split_status_word(&[0x69, 0x85]).unwrap();
    assert!(data.is_empty());
    assert_eq!(sw, StatusWord::Deny);

    assert_eq!(
        split_status_word(&[0x00]),
        Err(DecodeError::TooShortForStatusWord { got: 1 })
    );
}

#[test]
fn expect_ok_surfaces_the_failure_status() {
    assert_eq!(
        expect_ok(&[0xB0, 0x07]),
        Err(DecodeError::Status(StatusWord::BadState))
    );
    assert_eq!(expect_ok(&[0x01, 0x90, 0x00]).unwrap(), &[0x01]);
}

#[test]
fn firmware_version_parse() {
    // 0x38, 0x30, then app 3.9.2, SDK 1.0, API level 3.
    let data = [0x38, 0x30, 3, 9, 2, 1, 0, 3];
    let v = parse_firmware_version(&data).unwrap();
    assert_eq!((v.major, v.minor, v.patch), (3, 9, 2));
    assert_eq!(v.api_level, 3);
    assert_eq!(v.to_string(), "3.9.2");

    let mut bad = data;
    bad[0] = 0x39;
    assert!(matches!(
        parse_firmware_version(&bad),
        Err(DecodeError::BadVersionPrefix { .. })
    ));

    assert!(matches!(
        parse_firmware_version(&data[..7]),
        Err(DecodeError::UnexpectedLength { .. })
    ));
}

#[test]
fn transparent_signature_splits_off_the_trailing_sighash_byte() {
    // A minimal DER signature followed by SIGHASH_ALL.
    let der = vec![0x30, 0x44, 0x02, 0x20, 0xAA, 0x02, 0x20, 0xBB, 0xCC, 0xDD];
    let mut data = der.clone();
    data.push(0x01);

    let sig = parse_transparent_signature(&data).unwrap();
    assert_eq!(sig.der, der);
    assert_eq!(sig.sighash_type, SIGHASH_ALL);

    assert!(matches!(
        parse_transparent_signature(&[0x30, 0x06]),
        Err(DecodeError::Truncated { .. })
    ));
}

// ---------------------------------------------------------------------------
// GET_WALLET_PUBLIC_KEY replies
// ---------------------------------------------------------------------------

/// The secp256k1 generator point, uncompressed — a real curve point to stand in
/// for whatever key a device would derive, so that the parser is checked
/// against something `secp256k1` accepts rather than against 65 arbitrary
/// bytes.
const GENERATOR_UNCOMPRESSED: [u8; 65] = [
    0x04, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
    0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
    0x98, 0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08,
    0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4,
    0xB8,
];

/// A base58 address of the length a testnet P2PKH address really has.
const SAMPLE_ADDRESS: &str = "tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU";

/// Builds a reply body: `pk_len ‖ pk ‖ addr_len ‖ addr ‖ chain_code`.
fn wallet_public_key_reply(pk: &[u8], address: &[u8], chain_code: &[u8]) -> Vec<u8> {
    let mut out = vec![pk.len() as u8];
    out.extend_from_slice(pk);
    out.push(address.len() as u8);
    out.extend_from_slice(address);
    out.extend_from_slice(chain_code);
    out
}

/// The key and chain code come through; the address is checked and dropped,
/// and nothing the reply carried appears in the parsed value's `Debug` form.
#[test]
fn a_wallet_public_key_reply_keeps_the_key_and_drops_the_address() {
    let data = wallet_public_key_reply(
        &GENERATOR_UNCOMPRESSED,
        SAMPLE_ADDRESS.as_bytes(),
        &[0x3C; CHAIN_CODE_LEN],
    );
    let parsed = parse_wallet_public_key(&data).expect("a well-formed reply");

    assert_eq!(parsed.public_key(), &GENERATOR_UNCOMPRESSED);
    assert_eq!(parsed.chain_code(), &[0x3C; CHAIN_CODE_LEN]);

    let shown = format!("{parsed:?}");
    assert!(!shown.contains(SAMPLE_ADDRESS));
    assert!(
        !shown.contains("121"),
        "0x79, the key's first coordinate byte"
    );
    assert!(!shown.contains("60"), "0x3C, the chain code");
    assert!(shown.contains("[redacted]"));
}

/// The action record's `Debug` form publishes what the chain publishes and
/// nothing that opens or links it: `alpha`, `rcv`, both `rseed`s, both
/// addresses and the ciphertexts are redacted.
#[test]
fn a_shielded_action_record_redacts_its_secrets_in_debug() {
    let shown = format!("{:?}", orchard_action_vector());

    // Shown: cv_net (1), nullifier (2), rk (3), spend_rho (5), cmx (9),
    // ephemeral_key (10), the two values, and the derivation.
    for public in [
        "[1, 1, 1",
        "[2, 2, 2",
        "[3, 3, 3",
        "[5, 5, 5",
        "[9, 9, 9",
        "[10, 10, 10",
    ] {
        assert!(
            shown.contains(public),
            "{public} should be shown in {shown}"
        );
    }
    assert!(shown.contains("100000000") && shown.contains("90000000"));
    assert!(shown.contains("2147483680"), "the derivation path is shown");

    // Redacted: spend_recipient (4), spend_rseed (6), alpha (7), the
    // ciphertexts (11, 12), recipient (13), rseed (14), rcv (15).
    for secret in [
        "[4, 4", "[6, 6", "[7, 7", "[11, 11", "[12, 12", "[13, 13", "[14, 14", "[15, 15",
    ] {
        assert!(!shown.contains(secret), "{secret} leaked into {shown}");
    }
    assert!(shown.contains("alpha: \"[redacted]\""));
    assert!(shown.contains("enc_ciphertext: [redacted; 580 bytes]"));

    // And an APDU built from it shows only its data length.
    let apdus = shielded_action_apdus(
        ShieldedPool::Orchard,
        &[orchard_action_vector()],
        Some(&orchard_trailer_vector()),
        Finish::Finished,
    )
    .unwrap();
    let shown = format!("{:?}", apdus[1]);
    assert!(shown.contains("data: [243 bytes]"), "{shown}");
    assert!(!shown.contains("[7, 7"));
}

/// The transparent records redact the address-bearing fields the same way.
#[test]
fn transparent_records_redact_keys_and_scripts_in_debug() {
    let input = TransparentInputRecord {
        prevout_txid: [0x31; 32],
        prevout_index: 1,
        sequence: None,
        value: 50_000,
        script_pubkey: p2pkh_script(),
        sighash_type: SIGHASH_ALL,
        derivation: transparent_derivation(),
    };
    let shown = format!("{input:?}");
    assert!(
        shown.contains("script_pubkey: [redacted; 25 bytes]"),
        "{shown}"
    );
    assert!(shown.contains("pubkey: \"[redacted]\""), "{shown}");
    assert!(!shown.contains("[33, 33"), "TEST_PUBKEY leaked: {shown}");
    assert!(
        !shown.contains("118, 169, 20"),
        "the script leaked: {shown}"
    );
    assert!(
        shown.contains("[34, 34"),
        "the seed fingerprint is not secret"
    );
}

/// `compressed()` is `secp256k1`'s own compression, not a re-implementation of
/// it: the same key through both routes is the same 33 bytes.
#[test]
fn the_compressed_key_is_what_secp256k1_produces() {
    let data = wallet_public_key_reply(
        &GENERATOR_UNCOMPRESSED,
        SAMPLE_ADDRESS.as_bytes(),
        &[0; CHAIN_CODE_LEN],
    );
    let parsed = parse_wallet_public_key(&data).expect("a well-formed reply");

    let expected = secp256k1::PublicKey::from_slice(&GENERATOR_UNCOMPRESSED)
        .expect("the generator is on the curve")
        .serialize();
    assert_eq!(parsed.compressed().expect("a checked key"), expected);
    assert_eq!(expected.len(), COMPRESSED_PUBKEY_SIZE);
}

/// A device announcing a 33-byte key is refused rather than re-cut: every
/// field boundary after it would move, and the app returns 65.
#[test]
fn a_compressed_public_key_in_the_reply_is_refused() {
    let compressed = secp256k1::PublicKey::from_slice(&GENERATOR_UNCOMPRESSED)
        .expect("on the curve")
        .serialize();
    let data =
        wallet_public_key_reply(&compressed, SAMPLE_ADDRESS.as_bytes(), &[0; CHAIN_CODE_LEN]);
    assert!(matches!(
        parse_wallet_public_key(&data),
        Err(DecodeError::UnexpectedLength {
            what: "wallet public key",
            expected: 65,
            got: 33
        })
    ));
}

/// One byte short and one byte long are both failures: the reply's own lengths
/// have to account for every byte it carries.
#[test]
fn a_truncated_or_padded_wallet_public_key_reply_is_refused() {
    let data = wallet_public_key_reply(
        &GENERATOR_UNCOMPRESSED,
        SAMPLE_ADDRESS.as_bytes(),
        &[0; CHAIN_CODE_LEN],
    );

    let short = &data[..data.len() - 1];
    assert!(
        matches!(
            parse_wallet_public_key(short),
            Err(DecodeError::UnexpectedLength { .. })
        ),
        "a missing chain-code byte must be refused"
    );

    let mut long = data.clone();
    long.push(0x00);
    assert!(
        matches!(
            parse_wallet_public_key(&long),
            Err(DecodeError::UnexpectedLength { .. })
        ),
        "a trailing byte must be refused"
    );

    // Shorter than the fixed fields can fit at all.
    assert!(matches!(
        parse_wallet_public_key(&data[..40]),
        Err(DecodeError::Truncated {
            what: "wallet public key",
            ..
        })
    ));
}

#[test]
fn a_non_ascii_address_is_refused() {
    let data = wallet_public_key_reply(
        &GENERATOR_UNCOMPRESSED,
        &[0xE2, 0x82, 0xAC, 0xFF],
        &[0; CHAIN_CODE_LEN],
    );
    assert_eq!(parse_wallet_public_key(&data), Err(DecodeError::NotUtf8));
}

/// Sixty-five bytes that are not a point on the curve are not a public key,
/// and the identity that would be hashed out of them would be meaningless.
#[test]
fn a_key_that_is_not_on_the_curve_is_refused() {
    let mut off_curve = GENERATOR_UNCOMPRESSED;
    off_curve[64] ^= 0x01;
    let data = wallet_public_key_reply(&off_curve, SAMPLE_ADDRESS.as_bytes(), &[0; CHAIN_CODE_LEN]);
    assert!(matches!(
        parse_wallet_public_key(&data),
        Err(DecodeError::InvalidPublicKey { .. })
    ));
}

#[test]
fn shielded_signature_must_be_exactly_64_bytes() {
    let sig = parse_shielded_signature(&[0x5A; 64]).unwrap();
    assert_eq!(sig, [0x5A; 64]);
    assert!(matches!(
        parse_shielded_signature(&[0x5A; 63]),
        Err(DecodeError::UnexpectedLength { expected: 64, .. })
    ));
}

#[test]
fn chunked_ufvk_reassembles_across_replies() {
    // A 300-byte UFVK string forces two replies: the device caps each at 255
    // bytes (`VK_RESPONSE_CHUNK_LEN`), and the total transfer is 2 + 300.
    let ufvk: String = "u".repeat(300);
    let mut wire = (ufvk.len() as u16).to_be_bytes().to_vec();
    wire.extend_from_slice(ufvk.as_bytes());
    assert_eq!(wire.len(), 302);

    let mut r = VkReassembler::new(VkKind::Ufvk);
    assert_eq!(r.total_len(), None);
    assert_eq!(r.push(&wire[..255]).unwrap(), None);
    assert_eq!(r.total_len(), Some(302));
    let done = r.push(&wire[255..]).unwrap();
    assert_eq!(done, Some(VkResponse::Ufvk(ufvk)));
}

#[test]
fn orchard_fvk_reassembly_knows_its_length_up_front() {
    let mut r = VkReassembler::new(VkKind::OrchardFvk);
    assert_eq!(r.total_len(), Some(ORCHARD_FVK_LEN));
    assert!(r.is_empty());
    assert_eq!(r.push(&[0x01; 50]).unwrap(), None);
    assert_eq!(r.len(), 50);
    let done = r.push(&[0x02; 46]).unwrap();
    match done {
        Some(VkResponse::OrchardFvk(bytes)) => assert_eq!(bytes.len(), 96),
        other => panic!("expected a completed FVK, got {other:?}"),
    }
}

#[test]
fn vk_reassembly_rejects_an_overrun() {
    let mut r = VkReassembler::new(VkKind::OrchardFvk);
    assert!(matches!(
        r.push(&[0x00; 97]),
        Err(DecodeError::Overrun {
            expected: 96,
            got: 97
        })
    ));
}

#[test]
fn string_response_length_prefix_is_big_endian() {
    let mut wire = 3u16.to_be_bytes().to_vec();
    wire.extend_from_slice(b"u1a");
    assert_eq!(parse_string_response(&wire).unwrap(), "u1a");
    assert!(matches!(
        parse_string_response(&[0x00, 0x05, 0x61]),
        Err(DecodeError::UnexpectedLength { .. })
    ));
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

#[test]
fn hid_golden_single_frame() {
    // `DefaultApduSenderService.test.ts`: channel 0x1234, APDU e0 01 00 00 00.
    let frames = hid_frames(0x1234, &[0xE0, 0x01, 0x00, 0x00, 0x00]);
    assert_eq!(frames.len(), 1);
    assert_eq!(
        &frames[0][..12],
        &[0x12, 0x34, 0x05, 0x00, 0x00, 0x00, 0x05, 0xE0, 0x01, 0x00, 0x00, 0x00]
    );
    // Padding is zeros, and it fills the whole report even for a lone frame.
    assert!(frames[0][12..].iter().all(|b| *b == 0x00));
    assert_eq!(frames[0].len(), 64);
}

#[test]
fn hid_golden_two_frames() {
    // 69 bytes = 0x45: 57 in frame 0 (64 - 7 header), 12 in frame 1.
    let apdu: Vec<u8> = (0..69).map(|i| i as u8).collect();
    let frames = hid_frames(0x1234, &apdu);
    assert_eq!(frames.len(), 2);
    assert_eq!(&frames[0][..7], &[0x12, 0x34, 0x05, 0x00, 0x00, 0x00, 0x45]);
    assert_eq!(&frames[0][7..64], &apdu[..57]);
    assert_eq!(&frames[1][..5], &[0x12, 0x34, 0x05, 0x00, 0x01]);
    assert_eq!(&frames[1][5..17], &apdu[57..]);
    assert!(frames[1][17..].iter().all(|b| *b == 0x00));
}

#[test]
fn ble_golden_three_frames() {
    // `DefaultApduSenderService.test.ts`, "[BLE] Without padding nor channel":
    // frameSize 10, a 17-byte payload. Frame 0 holds 5 bytes (10 - 5 header),
    // the rest hold 7 (10 - 3), and the last frame is left short.
    let apdu = [
        0x01, 0x05, 0x4F, 0x4C, 0x4F, 0x53, 0x00, 0x07, 0x2E, 0x32, 0x2E, 0x34, 0x2D, 0x32, 0x00,
        0x90, 0x00,
    ];
    let frames = ble_frames(&apdu, 10).unwrap();
    assert_eq!(
        frames,
        vec![
            vec![0x05, 0x00, 0x00, 0x00, 0x11, 0x01, 0x05, 0x4F, 0x4C, 0x4F],
            vec![0x05, 0x00, 0x01, 0x53, 0x00, 0x07, 0x2E, 0x32, 0x2E, 0x34],
            vec![0x05, 0x00, 0x02, 0x2D, 0x32, 0x00, 0x90, 0x00],
        ]
    );
}

#[test]
fn ble_golden_single_frame() {
    // frameSize 123 with a 5-byte APDU: one 10-byte frame, unpadded.
    let frames = ble_frames(&[0xE0, 0x01, 0x00, 0x00, 0x00], 123).unwrap();
    assert_eq!(
        frames,
        vec![vec![
            0x05, 0x00, 0x00, 0x00, 0x05, 0xE0, 0x01, 0x00, 0x00, 0x00
        ]]
    );
}

#[test]
fn ble_frame_size_must_exceed_the_frame_zero_header() {
    assert_eq!(
        ble_frames(&[0x00], 5),
        Err(FramingError::FrameSizeTooSmall { got: 5, min: 6 })
    );
    assert!(ble_frames(&[0x00], 6).is_ok());
}

#[test]
fn empty_apdu_yields_no_frames() {
    assert!(hid_frames(0x0001, &[]).is_empty());
    assert!(ble_frames(&[], 64).unwrap().is_empty());
}

#[test]
fn hid_round_trip() {
    // Lengths start at 2: the deframer reassembles *responses*, and a
    // response always carries at least its status word. 56/57/58 straddle the
    // 57-byte frame-0 capacity.
    for len in [2usize, 56, 57, 58, 200, 512, 1174] {
        let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let frames = hid_frames(0xBEEF, &payload);

        let mut d = Deframer::hid(0xBEEF);
        let mut got = None;
        for f in &frames {
            if let Some(p) = d.push(f).unwrap() {
                got = Some(p);
            }
        }
        assert_eq!(got.as_deref(), Some(payload.as_slice()), "len {len}");
        assert!(d.is_idle());
    }
}

#[test]
fn ble_round_trip_at_common_mtus() {
    // 20 is the BLE 4.0 default ATT MTU, 153 the Ledger Nano X value, and 64
    // a common negotiated size.
    for mtu in [20usize, 153, 64] {
        for len in [2usize, 15, 16, 17, 100, 302, 1174] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let frames = ble_frames(&payload, mtu).unwrap();
            assert!(frames.iter().all(|f| f.len() <= mtu));

            let mut d = Deframer::ble();
            let mut got = None;
            for f in &frames {
                if let Some(p) = d.push(f).unwrap() {
                    got = Some(p);
                }
            }
            assert_eq!(
                got.as_deref(),
                Some(payload.as_slice()),
                "mtu {mtu}, len {len}"
            );
        }
    }
}

#[test]
fn deframer_rejects_a_foreign_channel() {
    let frames = hid_frames(0x0001, &[0x90, 0x00]);
    let mut d = Deframer::hid(0x0002);
    assert_eq!(
        d.push(&frames[0]),
        Err(FramingError::ChannelMismatch {
            expected: 0x0002,
            got: 0x0001
        })
    );
}

#[test]
fn deframer_rejects_a_bad_tag() {
    let mut frame = hid_frames(0x0001, &[0x90, 0x00])[0];
    frame[2] = 0x06;
    let mut d = Deframer::hid(0x0001);
    assert_eq!(d.push(&frame), Err(FramingError::BadTag { got: 0x06 }));
}

#[test]
fn deframer_rejects_a_sequence_gap() {
    let payload: Vec<u8> = (0..200).map(|i| i as u8).collect();
    let frames = hid_frames(0x0001, &payload);
    assert!(frames.len() >= 3);

    let mut d = Deframer::hid(0x0001);
    assert_eq!(d.push(&frames[0]).unwrap(), None);
    // Skipping frame 1 must not silently splice frame 2 in.
    assert_eq!(
        d.push(&frames[2]),
        Err(FramingError::UnexpectedSequence {
            expected: 1,
            got: 2
        })
    );
}

#[test]
fn deframer_rejects_a_continuation_with_nothing_pending() {
    let payload: Vec<u8> = (0..200).map(|i| i as u8).collect();
    let frames = hid_frames(0x0001, &payload);
    let mut d = Deframer::hid(0x0001);
    assert_eq!(d.push(&frames[1]), Err(FramingError::OutOfOrderFrame));
}

#[test]
fn deframer_rejects_a_response_too_short_for_a_status_word() {
    let frames = hid_frames(0x0001, &[0x90]);
    let mut d = Deframer::hid(0x0001);
    assert_eq!(
        d.push(&frames[0]),
        Err(FramingError::DeclaredLengthTooShort { got: 1 })
    );
}

#[test]
fn deframer_reset_clears_a_partial_response() {
    let payload: Vec<u8> = (0..200).map(|i| i as u8).collect();
    let frames = hid_frames(0x0001, &payload);
    let mut d = Deframer::hid(0x0001);
    d.push(&frames[0]).unwrap();
    assert!(!d.is_idle());
    d.reset();
    assert!(d.is_idle());
}

#[test]
fn ble_mtu_handshake() {
    assert_eq!(ble_mtu_request(), [0x08, 0x00, 0x00, 0x00, 0x00]);

    // DMK's own fixture, `08 00 00 00 00 20`.
    assert_eq!(
        parse_ble_mtu_response(&[0x08, 0, 0, 0, 0, 0x20]).unwrap(),
        32
    );
    // What a real device sends: a declared 1-byte payload.
    assert_eq!(
        parse_ble_mtu_response(&[0x08, 0, 0, 0, 1, 0x99]).unwrap(),
        153
    );

    assert_eq!(
        parse_ble_mtu_response(&[0x08, 0, 0, 0, 1]),
        Err(FramingError::BadMtuResponse)
    );
    assert_eq!(
        parse_ble_mtu_response(&[0x05, 0, 0, 0, 1, 0x99]),
        Err(FramingError::BadMtuResponse)
    );
    assert_eq!(
        parse_ble_mtu_response(&[0x08, 0, 0, 0, 1, 0x00]),
        Err(FramingError::BadMtuResponse)
    );
}

#[test]
fn a_response_declares_its_status_word_in_its_length() {
    // Framing a response is framing `data || SW`, so the declared length is
    // two more than the data — which is how `DefaultApduReceiverService`
    // reads it back.
    let mut response = vec![0x38, 0x30, 3, 9, 2, 1, 0, 3];
    response.extend_from_slice(&[0x90, 0x00]);

    let frames = hid_frames(0x0001, &response);
    let mut d = Deframer::hid(0x0001);
    let payload = d.push(&frames[0]).unwrap().unwrap();
    assert_eq!(payload.len(), 10);

    let data = expect_ok(&payload).unwrap();
    assert_eq!(parse_firmware_version(data).unwrap().to_string(), "3.9.2");
}

// ---------------------------------------------------------------------------
// Limits and capabilities
// ---------------------------------------------------------------------------

#[test]
fn device_caps_thresholds() {
    let old = DeviceCaps::from_version(3, 5, 9);
    assert!(!old.pczt);
    assert!(!old.ironwood);

    let pczt_only = DeviceCaps::from_version(3, 6, 0);
    assert!(pczt_only.pczt);
    assert!(!pczt_only.ironwood);

    let full = DeviceCaps::from_version(3, 9, 2);
    assert!(full.pczt);
    assert!(full.ironwood);
}

#[test]
fn standard_script_detection() {
    assert!(is_standard_output_script(&p2pkh_script()));

    let mut p2sh = vec![0xA9, 0x14];
    p2sh.extend_from_slice(&[0x33; 20]);
    p2sh.push(0x87);
    assert!(is_standard_output_script(&p2sh));

    // OP_RETURN is refused with `IncorrectData` by the device.
    assert!(!is_standard_output_script(&[0x6A, 0x04, 1, 2, 3, 4]));
    assert!(!is_standard_output_script(&[]));
}

fn v5_plan() -> StreamPlan {
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

#[test]
fn a_well_formed_v5_plan_validates() {
    assert_eq!(validate_records(&v5_plan(), &DeviceBounds::V3_9_2), Ok(()));
}

#[test]
fn v5_plan_puts_the_finished_marker_on_the_orchard_command() {
    let apdus = v5_plan().to_apdus().unwrap();
    // header + 1 transparent-input + 1 transparent-output + 10 orchard
    assert_eq!(apdus.len(), 13);
    assert_eq!(apdus[0].ins, 0x52);
    assert_eq!(apdus[1].ins, 0x53);
    assert_eq!(apdus[2].ins, 0x54);
    assert!(apdus[3..].iter().all(|a| a.ins == 0x56));
    assert_eq!(apdus.last().unwrap().p2, p2::PCZT_FINISHED);
    assert_eq!(apdus.last().unwrap().p1, p1::LAST);
    assert!(apdus[..apdus.len() - 1]
        .iter()
        .all(|a| a.p2 == p2::PCZT_CONTINUE));
}

fn v6_plan() -> StreamPlan {
    let mut plan = v5_plan();
    plan.header.pczt_version = PCZT_VERSION_V6;
    plan.header.tx_version = 6;
    plan.header.version_group_id = V6_VERSION_GROUP_ID;
    plan.ironwood_actions = Some(Vec::new());
    plan
}

#[test]
fn v6_plan_moves_the_finished_marker_to_the_ironwood_command() {
    let plan = v6_plan();
    assert_eq!(validate_records(&plan, &DeviceBounds::V3_9_2), Ok(()));

    let apdus = plan.to_apdus().unwrap();
    let last = apdus.last().unwrap();
    assert_eq!(last.ins, 0x58);
    assert_eq!(last.p1, p1::FIRST); // the empty bundle is one packet
    assert_eq!(last.p2, p2::PCZT_FINISHED);
    assert_eq!(last.data, vec![0x00]);

    // Every Orchard packet, including the last, continues.
    assert!(apdus
        .iter()
        .filter(|a| a.ins == 0x56)
        .all(|a| a.p2 == p2::PCZT_CONTINUE));
}

#[test]
fn a_v6_plan_without_an_ironwood_bundle_is_rejected() {
    let mut plan = v6_plan();
    plan.ironwood_actions = None;
    let errs = validate_records(&plan, &DeviceBounds::V3_9_2).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, LimitViolation::IronwoodBundleMismatch { .. })));
}

#[test]
fn an_ironwood_bundle_on_a_v5_plan_is_rejected() {
    let mut plan = v5_plan();
    plan.ironwood_actions = Some(Vec::new());
    let errs = validate_records(&plan, &DeviceBounds::V3_9_2).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, LimitViolation::IronwoodBundleMismatch { .. })));
}

#[test]
fn a_pczt_version_mismatch_is_rejected() {
    let mut plan = v5_plan();
    plan.header.pczt_version = PCZT_VERSION_V6;
    let errs = validate_records(&plan, &DeviceBounds::V3_9_2).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, LimitViolation::PcztVersionMismatch { .. })));
}

#[test]
fn eleven_actions_exceed_the_device_limit() {
    let mut plan = v5_plan();
    plan.orchard_actions = vec![orchard_action_vector(); 11];
    let errs = validate_records(&plan, &DeviceBounds::V3_9_2).unwrap_err();
    assert!(errs.iter().any(|e| matches!(
        e,
        LimitViolation::TooManyRecords {
            section: Section::Orchard,
            got: 11,
            max: 10
        }
    )));
}

#[test]
fn an_oversized_script_is_rejected() {
    let mut plan = v5_plan();
    plan.transparent_inputs.push(TransparentInputRecord {
        prevout_txid: [0; 32],
        prevout_index: 0,
        sequence: None,
        value: 0,
        script_pubkey: vec![0x00; MAX_SCRIPT_SIZE + 1],
        sighash_type: SIGHASH_ALL,
        derivation: transparent_derivation(),
    });
    let errs = validate_records(&plan, &DeviceBounds::V3_9_2).unwrap_err();
    assert!(errs.iter().any(|e| matches!(
        e,
        LimitViolation::ScriptTooLong {
            section: Section::TransparentInput,
            index: 0,
            got: 253
        }
    )));
}

#[test]
fn a_non_standard_output_script_is_rejected() {
    let mut plan = v5_plan();
    plan.transparent_outputs.push(TransparentOutputRecord {
        value: 1,
        script_pubkey: vec![0x6A, 0x04, 1, 2, 3, 4], // OP_RETURN
        derivation: None,
    });
    let errs = validate_records(&plan, &DeviceBounds::V3_9_2).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, LimitViolation::NonStandardOutputScript { index: 0 })));
}

/// The signing-key locator has to pay the input, or the device signs with a
/// key that cannot spend it and the signature is never applicable.
#[test]
fn an_input_whose_derivation_does_not_pay_its_script_is_rejected() {
    let mut plan = v5_plan();
    let mut derivation = transparent_derivation();
    derivation.pubkey[1] ^= 0xFF;
    plan.transparent_inputs.push(TransparentInputRecord {
        prevout_txid: [0; 32],
        prevout_index: 0,
        sequence: None,
        value: 0,
        script_pubkey: p2pkh_script(),
        sighash_type: SIGHASH_ALL,
        derivation,
    });
    let errs = validate_records(&plan, &DeviceBounds::V3_9_2).unwrap_err();
    assert_eq!(
        errs,
        vec![LimitViolation::DerivationPubkeyMismatch {
            section: Section::TransparentInput,
            index: 0
        }]
    );

    // The consistent record passes, so it is the key and not the shape.
    plan.transparent_inputs[0].derivation = transparent_derivation();
    assert_eq!(validate_records(&plan, &DeviceBounds::V3_9_2), Ok(()));
}

/// The same rule for an output that arrives with a derivation: it claims to be
/// change, and the claim is only true of a P2PKH output paying that key.
#[test]
fn an_output_whose_derivation_does_not_pay_its_script_is_rejected() {
    let mut plan = v5_plan();
    let mut derivation = transparent_derivation();
    derivation.pubkey[1] ^= 0xFF;
    plan.transparent_outputs.push(TransparentOutputRecord {
        value: 1,
        script_pubkey: p2pkh_script(),
        derivation: Some(derivation),
    });
    let errs = validate_records(&plan, &DeviceBounds::V3_9_2).unwrap_err();
    assert_eq!(
        errs,
        vec![LimitViolation::DerivationPubkeyMismatch {
            section: Section::TransparentOutput,
            index: 0
        }]
    );

    // A P2SH output is a standard output, but no derivation can pay it.
    let mut p2sh = vec![0xA9, 0x14];
    p2sh.extend_from_slice(&[0x33; 20]);
    p2sh.push(0x87);
    plan.transparent_outputs[0] = TransparentOutputRecord {
        value: 1,
        script_pubkey: p2sh,
        derivation: Some(transparent_derivation()),
    };
    let errs = validate_records(&plan, &DeviceBounds::V3_9_2).unwrap_err();
    assert_eq!(
        errs,
        vec![LimitViolation::DerivationPubkeyMismatch {
            section: Section::TransparentOutput,
            index: 0
        }]
    );

    // Consistent, and without a derivation at all, both pass.
    plan.transparent_outputs[0] = TransparentOutputRecord {
        value: 1,
        script_pubkey: p2pkh_script(),
        derivation: Some(transparent_derivation()),
    };
    assert_eq!(validate_records(&plan, &DeviceBounds::V3_9_2), Ok(()));
    plan.transparent_outputs[0].derivation = None;
    assert_eq!(validate_records(&plan, &DeviceBounds::V3_9_2), Ok(()));
}

#[test]
fn a_non_sighash_all_input_is_rejected() {
    let mut plan = v5_plan();
    plan.transparent_inputs.push(TransparentInputRecord {
        prevout_txid: [0; 32],
        prevout_index: 0,
        sequence: None,
        value: 0,
        script_pubkey: p2pkh_script(),
        sighash_type: 0x81, // SIGHASH_ALL | ANYONECANPAY
        derivation: transparent_derivation(),
    });
    let errs = validate_records(&plan, &DeviceBounds::V3_9_2).unwrap_err();
    assert!(errs.iter().any(|e| matches!(
        e,
        LimitViolation::UnsupportedSighashType {
            index: 0,
            got: 0x81
        }
    )));
}

#[test]
fn a_missing_bundle_trailer_is_rejected() {
    let mut plan = v5_plan();
    plan.orchard_trailer = None;
    let errs = validate_records(&plan, &DeviceBounds::V3_9_2).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, LimitViolation::TrailerMismatch { .. })));
}

#[test]
fn an_orchard_action_may_not_carry_a_note_plaintext_version() {
    let mut plan = v5_plan();
    plan.orchard_actions[0].note_plaintext_version = Some(NOTE_VERSION_IRONWOOD);
    let errs = validate_records(&plan, &DeviceBounds::V3_9_2).unwrap_err();
    assert!(errs.iter().any(|e| matches!(
        e,
        LimitViolation::BadNotePlaintextVersion {
            section: Section::Orchard,
            ..
        }
    )));
}

#[test]
fn an_ironwood_action_must_declare_note_version_three() {
    let mut plan = v6_plan();
    let mut action = orchard_action_vector();
    action.note_plaintext_version = Some(0x02);
    plan.ironwood_actions = Some(vec![action]);
    plan.ironwood_trailer = Some(orchard_trailer_vector());

    let errs = validate_records(&plan, &DeviceBounds::V3_9_2).unwrap_err();
    assert!(errs.iter().any(|e| matches!(
        e,
        LimitViolation::BadNotePlaintextVersion {
            section: Section::Ironwood,
            got: Some(0x02),
            ..
        }
    )));
}

#[test]
fn an_unknown_coin_type_is_rejected() {
    let mut plan = v5_plan();
    plan.header.coin_type = 0;
    let errs = validate_records(&plan, &DeviceBounds::V3_9_2).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, LimitViolation::UnknownCoinType { got: 0 })));
}

/// Two transparent change outputs are refused with no viewing key at all: the
/// transparent half of the one-change rule is read off the records, so it does
/// not wait for the shielded half to become countable.
#[test]
fn two_transparent_change_outputs_are_refused_without_viewing_keys() {
    let change = || TransparentOutputRecord {
        value: 1,
        script_pubkey: p2pkh_script(),
        derivation: Some(transparent_derivation()),
    };
    let plan = |outputs: Vec<TransparentOutputRecord>| crate::plan::Plan {
        stream: StreamPlan {
            transparent_outputs: outputs,
            ..v5_plan()
        },
        global: crate::plan::GlobalFields {
            tx_version: 5,
            version_group_id: V5_VERSION_GROUP_ID,
            consensus_branch_id: 0xC2D6_D0B4,
            fallback_lock_time: None,
            expiry_height: 2_500_000,
            coin_type: COIN_TYPE_MAINNET,
            tx_modifiable: 0,
        },
        orchard_real_spends: Vec::new(),
        ironwood_real_spends: Vec::new(),
        displayed_shielded_outputs: 1,
        shielded_change_outputs: None,
        missing_zip32: Vec::new(),
    };

    assert_eq!(
        validate_plan(&plan(vec![change()]), &DeviceBounds::V3_9_2),
        Ok(())
    );

    let errs = validate_plan(&plan(vec![change(), change()]), &DeviceBounds::V3_9_2).unwrap_err();
    assert_eq!(
        errs,
        vec![LimitViolation::MultipleChangeOutputs {
            got: 2,
            shielded: None
        }]
    );
}

#[test]
fn caps_gate_a_v6_plan_on_an_old_app() {
    let caps = DeviceCaps::from_version(3, 8, 0);
    assert_eq!(validate_against_caps(&v5_plan(), &caps), Ok(()));

    let errs = validate_against_caps(&v6_plan(), &caps).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, LimitViolation::IronwoodUnsupported { .. })));
}

#[test]
fn caps_gate_everything_on_a_pre_pczt_app() {
    let caps = DeviceCaps::from_version(3, 5, 0);
    let errs = validate_against_caps(&v5_plan(), &caps).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| matches!(e, LimitViolation::PcztUnsupported { .. })));
}

// ---------------------------------------------------------------------------
// Transports
// ---------------------------------------------------------------------------
//
// These exercise the two transports' *framing* against the deframers and the
// emulator's own protocol. Neither needs hardware: the HID side is checked by
// running the exact bytes `HidTransport` would write back through
// `Deframer::hid`, and the speculos side against a loopback fake that
// reimplements `speculos/mcu/apdu.py`'s arithmetic independently.

#[cfg(feature = "transport-speculos")]
mod speculos_transport {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use crate::session::Deadline;
    use crate::transport::speculos::{frame_reply, frame_request, SpeculosTransport};
    use crate::transport::{Transport, TransportError};

    /// Reads one length-prefixed request the way the emulator does.
    fn read_request(stream: &mut TcpStream) -> Option<Vec<u8>> {
        let mut prefix = [0u8; 4];
        stream.read_exact(&mut prefix).ok()?;
        let len = u32::from_be_bytes(prefix) as usize;
        let mut apdu = vec![0u8; len];
        stream.read_exact(&mut apdu).ok()?;
        Some(apdu)
    }

    /// A fake emulator that answers each request from `replies`, in order.
    ///
    /// `replies` are whole payloads (data ‖ SW); the fake applies the
    /// `len(packet) - 2` prefix itself, written out here rather than reusing
    /// [`frame_reply`] so the test is not checking the code against itself.
    fn fake_speculos(replies: Vec<Vec<u8>>) -> (String, thread::JoinHandle<Vec<Vec<u8>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr").to_string();

        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut seen = Vec::new();
            for reply in replies {
                match read_request(&mut stream) {
                    Some(apdu) => seen.push(apdu),
                    None => break,
                }
                let mut packet = ((reply.len() - 2) as u32).to_be_bytes().to_vec();
                packet.extend_from_slice(&reply);
                stream.write_all(&packet).expect("write reply");
            }
            seen
        });

        (addr, handle)
    }

    #[test]
    fn the_request_prefix_is_the_whole_apdu_length() {
        let apdu = [0xE0, 0xC4, 0x00, 0x00, 0x00];
        assert_eq!(
            frame_request(&apdu),
            vec![0x00, 0x00, 0x00, 0x05, 0xE0, 0xC4, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn the_reply_prefix_excludes_the_status_word() {
        // `apdu.py`: `size = (len(packet) - 2) & 0xffffffff`, then the whole
        // packet — status word included — is written after it.
        let reply = [0x03, 0x09, 0x02, 0x00, 0x02, 0x01, 0x00, 0x14, 0x90, 0x00];
        let framed = frame_reply(&reply).expect("long enough for a status word");
        assert_eq!(&framed[..4], &[0x00, 0x00, 0x00, 0x08]);
        assert_eq!(&framed[4..], &reply);
        assert_eq!(framed.len(), 4 + reply.len());
    }

    #[test]
    fn a_reply_with_no_room_for_a_status_word_is_refused() {
        assert_eq!(frame_reply(&[0x90]), None);
        assert_eq!(frame_reply(&[]), None);
    }

    #[test]
    fn an_empty_data_reply_still_carries_its_status_word() {
        // Every `PCZT_*` streaming command answers with `9000` and no data,
        // which is the case a prefix-only reader would swallow entirely.
        let framed = frame_reply(&[0x90, 0x00]).expect("two bytes is a status word");
        assert_eq!(framed, vec![0x00, 0x00, 0x00, 0x00, 0x90, 0x00]);
    }

    #[test]
    fn an_exchange_round_trips_through_a_loopback_emulator() {
        let version = vec![0x03, 0x09, 0x02, 0x00, 0x02, 0x01, 0x00, 0x14, 0x90, 0x00];
        let streamed = vec![0x90, 0x00];
        let (addr, server) = fake_speculos(vec![version.clone(), streamed.clone()]);

        let mut transport = SpeculosTransport::connect(addr).expect("connect");
        let apdu = [0xE0, 0xC4, 0x00, 0x00, 0x00];
        assert_eq!(transport.exchange(&apdu).expect("version reply"), version);

        // A zero-length data reply must not be mistaken for a closed socket.
        let stream_apdu = [0xE0, 0x52, 0x00, 0x00, 0x02, 0xAA, 0xBB];
        assert_eq!(
            transport
                .exchange_with(&stream_apdu, Deadline::UserReview)
                .expect("streaming reply"),
            streamed
        );

        let seen = server.join().expect("server thread");
        assert_eq!(seen, vec![apdu.to_vec(), stream_apdu.to_vec()]);
    }

    #[test]
    fn a_closed_socket_is_reported_as_such() {
        // The fake consumes the request before hanging up, so the client sees
        // an orderly FIN on the read rather than a reset provoked by writing to
        // an already-closed socket.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr").to_string();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let _ = read_request(&mut stream);
        });

        let mut transport = SpeculosTransport::connect(addr).expect("connect");
        let err = transport
            .exchange(&[0xE0, 0xC4, 0x00, 0x00, 0x00])
            .expect_err("the fake answers nothing and hangs up");
        assert!(
            matches!(err, TransportError::ConnectionClosed),
            "unexpected error: {err}"
        );
        server.join().expect("server thread");
    }

    /// A reply that arrives after its exchange timed out must not be read as
    /// the reply to the next command: the timeout poisons the connection, and
    /// the next exchange is refused with the late reply still in the socket.
    #[test]
    fn a_timed_out_exchange_poisons_the_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr").to_string();
        let late_reply = vec![0x38, 0x30, 3, 9, 3, 1, 0, 3, 0x90, 0x00];
        let server = thread::spawn({
            let late_reply = late_reply.clone();
            move || {
                let (mut stream, _) = listener.accept().expect("accept");
                let request = read_request(&mut stream);
                // Answer well after the client has given up.
                thread::sleep(std::time::Duration::from_millis(400));
                let mut packet = ((late_reply.len() - 2) as u32).to_be_bytes().to_vec();
                packet.extend_from_slice(&late_reply);
                let _ = stream.write_all(&packet);
                request
            }
        });

        let mut transport = SpeculosTransport::connect(addr)
            .expect("connect")
            .with_timeout(std::time::Duration::from_millis(100));
        let version = [0xE0, 0xC4, 0x00, 0x00, 0x00];
        let err = transport.exchange(&version).expect_err("the reply is late");
        assert!(matches!(err, TransportError::Timeout { .. }), "{err}");
        assert!(transport.is_poisoned());

        // Wait until the late reply is certainly sitting in the socket, then
        // ask again: without poisoning this would return the version reply as
        // the answer to a header command.
        server.join().expect("server thread");
        let header = [0xE0, 0x52, 0x00, 0x00, 0x02, 0xAA, 0xBB];
        let err = transport
            .exchange(&header)
            .expect_err("a poisoned connection refuses every exchange");
        assert!(
            matches!(
                &err,
                TransportError::Poisoned { source }
                    if matches!(**source, TransportError::Timeout { .. })
            ),
            "{err}"
        );
    }

    #[test]
    fn a_normal_deadline_times_out_rather_than_hanging() {
        // A fake that accepts and then never answers: the socket stays open, so
        // only the read timeout can end this.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr").to_string();
        let held = std::thread::spawn(move || listener.accept().map(|(s, _)| s));

        let mut transport = SpeculosTransport::connect(addr)
            .expect("connect")
            .with_timeout(std::time::Duration::from_millis(150));
        let err = transport
            .exchange(&[0xE0, 0xC4, 0x00, 0x00, 0x00])
            .expect_err("nobody answers");
        assert!(
            matches!(err, TransportError::Timeout { .. }),
            "unexpected error: {err}"
        );
        drop(held.join().expect("accept thread"));
    }
}

#[cfg(feature = "transport-hid")]
mod hid_transport {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::time::Duration;

    use crate::framing::{hid_frames, Deframer, HID_FRAME_SIZE};
    use crate::session::Deadline;
    use crate::transport::hid::{
        exchange_over, HidReports, Link, LEDGER_HID_USAGE_PAGE, LEDGER_USB_VENDOR_ID,
    };
    use crate::transport::TransportError;

    /// The device's echo of one host frame: same channel, same tag, same index,
    /// with the declared length re-read as a *response* length (which includes
    /// the status word, unlike the outbound one).
    fn device_frames(channel: u16, payload: &[u8]) -> Vec<[u8; HID_FRAME_SIZE]> {
        hid_frames(channel, payload)
    }

    const CHANNEL: u16 = 0x4A4A;
    const TIMEOUT: Duration = Duration::from_millis(50);

    /// A scripted HID device.
    ///
    /// `stale` is what already sits in the OS buffer before the command is
    /// written; `reply` is what the device sends *in answer to* the command,
    /// so it becomes readable only once the first report has been written.
    struct ScriptedHid {
        stale: RefCell<VecDeque<Vec<u8>>>,
        reply: RefCell<Option<Vec<[u8; HID_FRAME_SIZE]>>>,
        /// Every output report written, and how many reports were still
        /// waiting when the first of each command went out.
        written: RefCell<Vec<Vec<u8>>>,
        waiting_at_write: RefCell<Vec<usize>>,
        /// Fail the next read with an I/O error, once.
        fail_next_read: RefCell<bool>,
    }

    impl ScriptedHid {
        fn new(stale: Vec<Vec<u8>>, reply: Option<Vec<[u8; HID_FRAME_SIZE]>>) -> Self {
            ScriptedHid {
                stale: RefCell::new(stale.into()),
                reply: RefCell::new(reply),
                written: RefCell::new(Vec::new()),
                waiting_at_write: RefCell::new(Vec::new()),
                fail_next_read: RefCell::new(false),
            }
        }
    }

    impl HidReports for ScriptedHid {
        fn write_report(&self, report: &[u8]) -> Result<(), TransportError> {
            assert_eq!(report.len(), HID_FRAME_SIZE + 1);
            assert_eq!(report[0], 0x00, "report ID");
            self.waiting_at_write
                .borrow_mut()
                .push(self.stale.borrow().len());
            self.written.borrow_mut().push(report.to_vec());
            if let Some(frames) = self.reply.borrow_mut().take() {
                self.stale
                    .borrow_mut()
                    .extend(frames.into_iter().map(|f| f.to_vec()));
            }
            Ok(())
        }

        fn read_report(&self, buf: &mut [u8], _timeout_ms: i32) -> Result<usize, TransportError> {
            if self.fail_next_read.replace(false) {
                return Err(TransportError::Io {
                    kind: std::io::ErrorKind::Other,
                    message: "scripted".into(),
                });
            }
            match self.stale.borrow_mut().pop_front() {
                Some(report) => {
                    buf[..report.len()].copy_from_slice(&report);
                    Ok(report.len())
                }
                None => Ok(0),
            }
        }
    }

    const VERSION_REPLY: [u8; 10] = [0x38, 0x30, 3, 9, 3, 1, 0, 3, 0x90, 0x00];
    const VERSION_APDU: [u8; 5] = [0xE0, 0xC4, 0x00, 0x00, 0x00];

    /// Reports already in the OS buffer — a late reply to a command whose
    /// exchange gave up — are discarded before the command goes out, so the
    /// real reply is the one returned.
    #[test]
    fn stale_input_reports_are_drained_before_a_command_is_written() {
        let late_reply: Vec<Vec<u8>> = device_frames(CHANNEL, &[0x90, 0x00])
            .into_iter()
            .map(|f| f.to_vec())
            .collect();
        let device = ScriptedHid::new(late_reply, Some(device_frames(CHANNEL, &VERSION_REPLY)));
        let mut link = Link::new(CHANNEL, TIMEOUT);

        let reply = exchange_over(&device, &mut link, &VERSION_APDU, Deadline::Normal)
            .expect("the real reply reassembles");
        assert_eq!(reply, VERSION_REPLY);
        assert_eq!(
            device.waiting_at_write.borrow().as_slice(),
            &[0],
            "the buffer must be empty when the command goes out"
        );
        assert!(!link.is_poisoned());
    }

    /// A timeout leaves the device's reply uncollected, so it poisons the
    /// link: the next exchange is refused before anything is written.
    #[test]
    fn a_timeout_poisons_the_link() {
        let device = ScriptedHid::new(Vec::new(), None);
        let mut link = Link::new(CHANNEL, TIMEOUT);

        let err = exchange_over(&device, &mut link, &VERSION_APDU, Deadline::Normal)
            .expect_err("nothing answers");
        assert!(matches!(err, TransportError::Timeout { .. }), "{err}");
        assert!(link.is_poisoned());
        let written = device.written.borrow().len();
        assert_eq!(written, 1);

        // The late reply lands; the next command must not collect it.
        device.stale.borrow_mut().extend(
            device_frames(CHANNEL, &VERSION_REPLY)
                .into_iter()
                .map(|f| f.to_vec()),
        );
        let err = exchange_over(&device, &mut link, &VERSION_APDU, Deadline::Normal)
            .expect_err("a poisoned link refuses every exchange");
        assert!(
            matches!(
                &err,
                TransportError::Poisoned { source } if matches!(**source, TransportError::Timeout { .. })
            ),
            "{err}"
        );
        assert_eq!(
            device.written.borrow().len(),
            written,
            "nothing more is written"
        );
        // The cause is chained as the error's source.
        let cause = std::error::Error::source(&err).expect("a poisoned error names its cause");
        assert!(cause.to_string().starts_with("no reply after"), "{cause}");
    }

    /// A reply that does not reassemble may still be arriving, so a framing
    /// error poisons the link too.
    #[test]
    fn a_bad_frame_poisons_the_link() {
        let mut frames = device_frames(CHANNEL, &VERSION_REPLY);
        frames[0][2] = 0x06; // not HEAD_TAG
        let device = ScriptedHid::new(Vec::new(), Some(frames));
        let mut link = Link::new(CHANNEL, TIMEOUT);

        let err = exchange_over(&device, &mut link, &VERSION_APDU, Deadline::Normal)
            .expect_err("the frame is bad");
        assert!(matches!(err, TransportError::Framing(_)), "{err}");
        assert!(link.is_poisoned());
        assert!(matches!(
            exchange_over(&device, &mut link, &VERSION_APDU, Deadline::Normal),
            Err(TransportError::Poisoned { .. })
        ));
    }

    /// A failure before anything has gone out — here, in the drain — leaves
    /// the link clean: the device owes nothing.
    #[test]
    fn a_failure_before_the_wire_does_not_poison_the_link() {
        let device = ScriptedHid::new(Vec::new(), Some(device_frames(CHANNEL, &VERSION_REPLY)));
        *device.fail_next_read.borrow_mut() = true;
        let mut link = Link::new(CHANNEL, TIMEOUT);

        let err = exchange_over(&device, &mut link, &VERSION_APDU, Deadline::Normal)
            .expect_err("the drain fails");
        assert!(matches!(err, TransportError::Io { .. }), "{err}");
        assert!(!link.is_poisoned());
        assert!(device.written.borrow().is_empty());

        // And the next exchange proceeds normally.
        let reply = exchange_over(&device, &mut link, &VERSION_APDU, Deadline::Normal)
            .expect("the link is clean");
        assert_eq!(reply, VERSION_REPLY);
    }

    #[test]
    fn the_vendor_id_and_usage_page_are_the_documented_ones() {
        assert_eq!(LEDGER_USB_VENDOR_ID, 0x2C97);
        assert_eq!(LEDGER_HID_USAGE_PAGE, 0xFFA0);
    }

    #[test]
    fn the_bytes_the_transport_writes_reassemble_on_the_same_channel() {
        // What `HidTransport::write_frames` puts on the wire is exactly
        // `hid_frames(channel, apdu)` with a report-ID byte in front, so
        // running those frames back through the deframer is the round trip the
        // device performs.
        let channel = 0x3F1Cu16;
        let apdu: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();

        let frames = hid_frames(channel, &apdu);
        assert!(frames.len() > 1, "300 bytes needs several 64-byte reports");
        assert!(frames.iter().all(|f| f.len() == HID_FRAME_SIZE));

        let mut deframer = Deframer::hid(channel);
        let mut done = None;
        for frame in &frames {
            if let Some(payload) = deframer.push(frame).expect("well-formed frame") {
                done = Some(payload);
            }
        }
        assert_eq!(done.as_deref(), Some(&apdu[..]));
    }

    #[test]
    fn a_reply_on_another_channel_is_rejected() {
        // Two host processes on one device: the frames of the other session
        // must not be spliced into this one's response.
        let mut deframer = Deframer::hid(0x1111);
        let stray = device_frames(0x2222, &[0x90, 0x00]);
        assert!(deframer.push(&stray[0]).is_err());
    }

    #[test]
    fn a_short_read_is_not_treated_as_a_frame() {
        // `read_timeout` can return fewer bytes than a full report; the
        // deframer sees the slice it actually read.
        let mut deframer = Deframer::hid(0x0001);
        assert!(deframer.push(&[0x00, 0x01, 0x05]).is_err());
    }
}

// ---------------------------------------------------------------------------
// Device identity
// ---------------------------------------------------------------------------

mod device_identity {
    use super::{
        testnet_identity_path, wallet_public_key_reply, GENERATOR_UNCOMPRESSED, SAMPLE_ADDRESS,
    };
    use crate::apdu::decode::CHAIN_CODE_LEN;
    use crate::apdu::{p1, Ins, StatusWord};
    use crate::pairing::{
        device_identity_apdu, device_identity_path, parse_device_identity_response,
        transparent_external_address_path, DeviceIdentity, InvalidDeviceIdentity,
        DEVICE_IDENTITY_PERSONALIZATION, DEVICE_IDENTITY_PREFIX,
    };
    use crate::session::Network;

    /// The generator point, compressed — a fixed key to pin the hash against.
    const GENERATOR_COMPRESSED: [u8; 33] = [
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ];

    /// The pinned identity vector.
    ///
    /// BLAKE2b-256 with personalization `PcztLedgerDvId_0` over the compressed
    /// secp256k1 generator point, cross-checked against an independent
    /// implementation (Python's `hashlib.blake2b(pk, digest_size=32,
    /// person=b"PcztLedgerDvId_0")`) rather than only against this crate's own
    /// output.
    ///
    /// Nothing about this repository may change it: it is the string a paired
    /// account is stored under, and a different value here would orphan every
    /// account already paired. A deliberate change to the derivation moves the
    /// version suffix in the personalization instead, which gives the new
    /// scheme a disjoint output space.
    const PINNED: &str = "tpk0-b1e9b1e524e494f1714baba8de4dbbd7e106c3ad22e1459ea7b7ef9729bd272c";

    #[test]
    fn the_personalization_is_sixteen_bytes() {
        // BLAKE2b takes exactly 16; `Params::personal` panics otherwise, and a
        // panic inside a derivation is not where that should be discovered.
        assert_eq!(DEVICE_IDENTITY_PERSONALIZATION.len(), 16);
    }

    #[test]
    fn the_identity_vector_is_pinned() {
        let id = DeviceIdentity::from_compressed_pubkey(&GENERATOR_COMPRESSED);
        assert_eq!(id.to_string(), PINNED);
    }

    #[test]
    fn display_and_parse_round_trip() {
        let id = DeviceIdentity::from_compressed_pubkey(&GENERATOR_COMPRESSED);
        let text = id.to_string();
        assert!(text.starts_with(DEVICE_IDENTITY_PREFIX));
        assert_eq!(text.len(), DEVICE_IDENTITY_PREFIX.len() + 64);
        assert_eq!(DeviceIdentity::parse(&text).expect("its own form"), id);
        assert_eq!(text.parse::<DeviceIdentity>().expect("FromStr"), id);
    }

    /// A different key is a different identity — the property the whole
    /// mechanism rests on.
    #[test]
    fn a_different_key_is_a_different_identity() {
        let mut other = GENERATOR_COMPRESSED;
        other[0] = 0x03; // the other parity of the same x coordinate.
        assert_ne!(
            DeviceIdentity::from_compressed_pubkey(&GENERATOR_COMPRESSED),
            DeviceIdentity::from_compressed_pubkey(&other),
        );
    }

    #[test]
    fn a_string_without_the_prefix_is_refused() {
        let hex = &PINNED[DEVICE_IDENTITY_PREFIX.len()..];
        assert_eq!(
            DeviceIdentity::parse(hex),
            Err(InvalidDeviceIdentity::MissingPrefix)
        );
        assert_eq!(
            DeviceIdentity::parse("nano-s-plus-01"),
            Err(InvalidDeviceIdentity::MissingPrefix)
        );
        // An empty string is not an identity either.
        assert_eq!(
            DeviceIdentity::parse(""),
            Err(InvalidDeviceIdentity::MissingPrefix)
        );
    }

    #[test]
    fn a_string_of_the_wrong_length_is_refused() {
        assert_eq!(
            DeviceIdentity::parse(&PINNED[..PINNED.len() - 1]),
            Err(InvalidDeviceIdentity::BadLength { got: 63 })
        );
        assert_eq!(
            DeviceIdentity::parse(&format!("{PINNED}0")),
            Err(InvalidDeviceIdentity::BadLength { got: 65 })
        );
    }

    /// Uppercase hex names the same bytes and is still refused: the string is a
    /// directory name, and two spellings of one device would be two caches on a
    /// case-sensitive filesystem.
    #[test]
    fn uppercase_hex_is_refused() {
        let shouted = format!(
            "{DEVICE_IDENTITY_PREFIX}{}",
            PINNED[DEVICE_IDENTITY_PREFIX.len()..].to_uppercase()
        );
        assert_eq!(
            DeviceIdentity::parse(&shouted),
            Err(InvalidDeviceIdentity::NotLowercaseHex)
        );
        assert_eq!(
            DeviceIdentity::parse(&format!("{DEVICE_IDENTITY_PREFIX}{}", "z".repeat(64))),
            Err(InvalidDeviceIdentity::NotLowercaseHex)
        );
    }

    /// The identity path is account 0's first external address, and its coin
    /// type is the network's — which is what makes one device two identities.
    #[test]
    fn the_identity_path_is_the_networks_first_external_address() {
        let main = device_identity_path(Network::Main);
        let test = device_identity_path(Network::Test);
        assert_eq!(main.0, vec![0x8000_002C, 0x8000_0085, 0x8000_0000, 0, 0]);
        assert_eq!(test.0, vec![0x8000_002C, 0x8000_0001, 0x8000_0000, 0, 0]);
        assert_ne!(main.0, test.0);

        // And it is exactly the account-0 case of the per-account path the
        // sign-time cross-check uses.
        assert_eq!(
            transparent_external_address_path(Network::Test, 0, 0).expect("account 0"),
            test
        );
        assert_eq!(
            transparent_external_address_path(Network::Test, 7, 0)
                .expect("account 7")
                .0,
            vec![0x8000_002C, 0x8000_0001, 0x8000_0007, 0, 0]
        );
    }

    /// The identity probe is the silent `GET_WALLET_PUBLIC_KEY` at that path:
    /// no screen, so it can open a signing ceremony without a prompt.
    #[test]
    fn the_identity_probe_is_the_silent_wallet_public_key_command() {
        let apdu = device_identity_apdu(Network::Test).expect("encodes");
        assert_eq!(apdu[1], Ins::GetWalletPublicKey.code());
        assert_eq!(apdu[2], p1::NO_DISPLAY);
        assert_eq!(
            &apdu[5..],
            &testnet_identity_path().to_bytes().expect("encodes")[..]
        );
    }

    /// The reply parses to the same identity the compressed key hashes to,
    /// so the pinned vector holds through the whole probe.
    #[test]
    fn the_probe_reply_parses_to_the_pinned_identity() {
        let mut rapdu = wallet_public_key_reply(
            &GENERATOR_UNCOMPRESSED,
            SAMPLE_ADDRESS.as_bytes(),
            &[0x3C; CHAIN_CODE_LEN],
        );
        rapdu.extend_from_slice(&StatusWord::Ok.to_u16().to_be_bytes());
        let id = parse_device_identity_response(&rapdu).expect("a well-formed reply");
        assert_eq!(id.to_string(), PINNED);
        assert_eq!(
            id,
            DeviceIdentity::from_compressed_pubkey(&GENERATOR_COMPRESSED)
        );

        // A refusal is a typed error, not an identity.
        assert!(matches!(
            parse_device_identity_response(&StatusWord::IncorrectData.to_u16().to_be_bytes()),
            Err(crate::pairing::PairingError::Device { .. })
        ));
    }
}

// ---------------------------------------------------------------------------
// Path compliance
// ---------------------------------------------------------------------------

mod path_compliance {
    use crate::session::path_compliance_error;

    const HARDENED: u32 = 0x8000_0000;
    const COIN: u32 = 133;

    #[test]
    fn the_two_compliant_shapes_pass() {
        // m/32'/133'/0'
        assert_eq!(
            path_compliance_error(&[32 | HARDENED, COIN | HARDENED, HARDENED], COIN),
            None
        );
        // m/44'/133'/7'/1/3
        assert_eq!(
            path_compliance_error(&[44 | HARDENED, COIN | HARDENED, 7 | HARDENED, 1, 3], COIN),
            None
        );
    }

    /// The firmware compares the purpose with the hardening bit included: an
    /// unhardened `m/44/133'/0'/0/0` is a path the OS answers by taking the
    /// app down, so `check_bip44_compliance` refuses it up front and this
    /// crate must too.
    #[test]
    fn an_unhardened_purpose_is_refused() {
        assert!(path_compliance_error(&[44, COIN | HARDENED, HARDENED, 0, 0], COIN).is_some());
        assert!(path_compliance_error(&[32, COIN | HARDENED, HARDENED], COIN).is_some());
    }

    #[test]
    fn a_wrong_or_unhardened_coin_type_is_refused() {
        // Testnet coin type on a mainnet session, and vice versa.
        assert!(
            path_compliance_error(&[44 | HARDENED, 1 | HARDENED, HARDENED, 0, 0], COIN).is_some()
        );
        assert!(path_compliance_error(&[32 | HARDENED, COIN | HARDENED, HARDENED], 1).is_some());
        // Unhardened coin type.
        assert!(path_compliance_error(&[44 | HARDENED, COIN, HARDENED, 0, 0], COIN).is_some());
    }

    #[test]
    fn an_unhardened_account_is_refused() {
        assert!(path_compliance_error(&[44 | HARDENED, COIN | HARDENED, 2, 0, 0], COIN).is_some());
        assert!(path_compliance_error(&[32 | HARDENED, COIN | HARDENED, 2], COIN).is_some());
    }

    #[test]
    fn a_depth_the_app_does_not_read_is_refused() {
        // Neither the 3- nor the 5-component form.
        for path in [
            &[][..],
            &[44 | HARDENED][..],
            &[44 | HARDENED, COIN | HARDENED][..],
            &[44 | HARDENED, COIN | HARDENED, HARDENED, 0][..],
            &[44 | HARDENED, COIN | HARDENED, HARDENED, 0, 0, 0][..],
        ] {
            assert!(path_compliance_error(path, COIN).is_some(), "{path:?}");
        }
    }

    /// The purpose byte must match the depth: a 3-deep path is the ZIP 32
    /// shape (purpose 32'), a 5-deep one the BIP 44 shape (purpose 44').
    #[test]
    fn a_purpose_on_the_wrong_depth_is_refused() {
        assert!(path_compliance_error(&[44 | HARDENED, COIN | HARDENED, HARDENED], COIN).is_some());
        assert!(
            path_compliance_error(&[32 | HARDENED, COIN | HARDENED, HARDENED, 0, 0], COIN)
                .is_some()
        );
    }
}

// ---------------------------------------------------------------------------
// Network mapping
// ---------------------------------------------------------------------------

mod network_type {
    use crate::session::{Network, UnsupportedNetwork};
    use zcash_protocol::consensus::NetworkType;

    #[test]
    fn main_and_test_map_and_regtest_is_refused() {
        assert_eq!(Network::try_from(NetworkType::Main), Ok(Network::Main));
        assert_eq!(Network::try_from(NetworkType::Test), Ok(Network::Test));
        assert_eq!(
            Network::try_from(NetworkType::Regtest),
            Err(UnsupportedNetwork(NetworkType::Regtest)),
        );
    }
}

// ---------------------------------------------------------------------------
// Change derivation
// ---------------------------------------------------------------------------

mod change_derive {
    use crate::shape::{hash160, ChangeDeriveError, ChangeInfo, TRANSPARENT_INTERNAL_SCOPE};
    use zcash_transparent::keys::{AccountPrivKey, IncomingViewingKey, TransparentKeyScope};

    const HARDENED: u32 = 0x8000_0000;

    fn fvk() -> zcash_transparent::keys::AccountPubKey {
        AccountPrivKey::from_seed(
            &zcash_protocol::consensus::TEST_NETWORK,
            &[1u8; 32],
            zip32::AccountId::ZERO,
        )
        .expect("the seed derives an account key")
        .to_account_pubkey()
    }

    /// The P2PKH scriptPubKey paying `HASH160(pubkey)`.
    fn p2pkh_script_for(pubkey: &[u8; 33]) -> Vec<u8> {
        let mut script = vec![0x76, 0xA9, 0x14];
        script.extend_from_slice(&hash160(pubkey));
        script.extend_from_slice(&[0x88, 0xAC]);
        script
    }

    /// The internal address index the account's default change address uses,
    /// and the pubkey the account pays it with.
    fn internal_pubkey_and_index() -> ([u8; 33], u32) {
        let fvk = fvk();
        let (_, index) = fvk
            .derive_internal_ivk()
            .expect("an internal ivk")
            .default_address();
        let pubkey = fvk
            .derive_address_pubkey(TransparentKeyScope::INTERNAL, index)
            .expect("derives")
            .serialize();
        (pubkey, index.index())
    }

    #[test]
    fn a_matching_output_derives() {
        let (pubkey, index) = internal_pubkey_and_index();
        let script = p2pkh_script_for(&pubkey);

        let change = ChangeInfo::derive(&fvk(), TRANSPARENT_INTERNAL_SCOPE, index, 2, &script)
            .expect("the hints match the script");
        assert_eq!(change.output_index, 2);
        assert_eq!(change.address_index, index);
        assert_eq!(change.pubkey, pubkey);
    }

    /// An output on the external chain is the account paying itself at a
    /// receiving address, not change; the firmware has no way to present it.
    #[test]
    fn an_external_scope_is_refused() {
        let (pubkey, index) = internal_pubkey_and_index();
        let script = p2pkh_script_for(&pubkey);
        assert_eq!(
            ChangeInfo::derive(&fvk(), 0, index, 0, &script),
            Err(ChangeDeriveError::NotInternalScope { scope: 0 }),
        );
    }

    #[test]
    fn a_hardened_address_index_is_refused() {
        let (pubkey, _) = internal_pubkey_and_index();
        let script = p2pkh_script_for(&pubkey);
        assert_eq!(
            ChangeInfo::derive(&fvk(), TRANSPARENT_INTERNAL_SCOPE, 5 | HARDENED, 0, &script),
            Err(ChangeDeriveError::AddressIndexHardened {
                index: 5 | HARDENED
            }),
        );
    }

    #[test]
    fn a_non_p2pkh_script_is_refused() {
        let (_, index) = internal_pubkey_and_index();
        assert_eq!(
            ChangeInfo::derive(
                &fvk(),
                TRANSPARENT_INTERNAL_SCOPE,
                index,
                0,
                &[0x6A, 0x01, 0x00]
            ),
            Err(ChangeDeriveError::NotP2pkh),
        );
    }

    /// The fail-closed case: an index whose derived key does not control the
    /// output. The device would not abort on it — it would show the output as
    /// a third-party recipient — so the host has to.
    #[test]
    fn a_pubkey_that_does_not_pay_the_script_is_refused() {
        let (pubkey, index) = internal_pubkey_and_index();
        let script = p2pkh_script_for(&pubkey);
        assert!(matches!(
            ChangeInfo::derive(&fvk(), TRANSPARENT_INTERNAL_SCOPE, index + 1, 0, &script),
            Err(ChangeDeriveError::PubkeyMismatch { .. }),
        ));
    }
}

// ---------------------------------------------------------------------------
// Constructor bounds
// ---------------------------------------------------------------------------

#[test]
fn a_derivation_path_of_eleven_components_cannot_be_constructed() {
    assert_eq!(
        DerivationPath::new(vec![0; 11]),
        Err(EncodeError::PathTooLong(11))
    );
    let path = DerivationPath::new(vec![0x8000_0020; 3]).expect("three components");
    assert_eq!(path.components(), &[0x8000_0020; 3]);
}

#[test]
fn an_apdu_with_over_long_data_cannot_be_constructed() {
    assert_eq!(
        Apdu::try_new(Ins::PcztHeader, 0, 0, vec![0; MAX_APDU_DATA + 1]),
        Err(ApduDataTooLong {
            got: MAX_APDU_DATA + 1
        }),
    );
    let apdu = Apdu::try_new(Ins::PcztHeader, 0, 0, vec![0; MAX_APDU_DATA]).expect("at the bound");
    assert_eq!(apdu.data.len(), MAX_APDU_DATA);
}
