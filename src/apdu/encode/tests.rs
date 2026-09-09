//! Unit tests.
//!
//! The golden vectors are constructed here rather than captured from a device:
//! each one is derived field by field from `docs/PCZT_APDU.md` and
//! `docs/APDU.md` at `LedgerHQ/app-zcash` `22dc385`, and the derivation is
//! spelled out in the test that uses it. The framing vectors are the ones in
//! `DefaultApduSenderService.test.ts` in `LedgerHQ/device-sdk-ts`.

use proptest::prelude::*;

use crate::apdu::encode::*;
use crate::apdu::*;
use crate::limits::*;
use crate::test_support::{
    header_vector, orchard_action_vector, orchard_trailer_vector, p2pkh_script,
    testnet_identity_path, transparent_derivation, TEST_PUBKEY, VERSION_APDU,
};

// ---------------------------------------------------------------------------
// CompactSize
// ---------------------------------------------------------------------------

/// The version constants are re-exports from `zcash_protocol`; the values the
/// firmware compares against (`src/consts.rs` @ `22dc385`) are pinned here so
/// that a protocol-crate change cannot silently move the wire contract.
#[test]
fn version_constants_match_the_firmware() {
    assert_eq!(V5_TX_VERSION, 5);
    assert_eq!(V5_VERSION_GROUP_ID, 0x26A7_270A);
    assert_eq!(V6_TX_VERSION, 6);
    assert_eq!(V6_VERSION_GROUP_ID, 0xD884_B698);
}

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
    assert_eq!(apdu.cla(), 0xE0);
    assert_eq!(apdu.ins(), 0x52);
    assert_eq!(apdu.p1(), 0x00);
    assert_eq!(apdu.p2(), 0x00);

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
        apdus.iter().map(|a| a.data().len()).collect::<Vec<_>>(),
        vec![1, 243, 45, 64, 255, 255, 73, 81, 115, 42]
    );
    assert_eq!(
        apdus.iter().map(|a| a.p1()).collect::<Vec<_>>(),
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
    let p2s: Vec<u8> = apdus.iter().map(|a| a.p2()).collect();
    assert!(p2s[..9].iter().all(|p| *p == p2::PCZT_CONTINUE));
    assert_eq!(p2s[9], p2::PCZT_FINISHED);
    assert!(apdus.iter().all(|a| a.ins() == 0x56));
}

#[test]
fn empty_orchard_bundle_is_a_single_count_packet() {
    // "This command is still sent when a transaction has no Orchard actions.
    // In that case its payload is only the CompactSize action count `0`."
    let apdus = shielded_action_apdus(ShieldedPool::Orchard, &[], None, Finish::Finished).unwrap();
    assert_eq!(apdus.len(), 1);
    assert_eq!(apdus[0].data(), [0x00]);
}

#[test]
fn ironwood_note_plaintext_version_makes_metadata_116_bytes() {
    let mut action = orchard_action_vector();
    action.note_plaintext_version = Some(NOTE_VERSION_IRONWOOD);
    let groups = shielded_action_groups(&[action], Some(&orchard_trailer_vector())).unwrap();
    assert_eq!(groups[6].len(), 116);
    assert_eq!(*groups[6].last().unwrap(), 0x03);
}

/// The action record's `Debug` form publishes what the chain publishes and
/// nothing that opens or links it: `alpha`, `rcv`, both `rseed`s, both
/// addresses and the ciphertexts are redacted.
#[test]
fn a_shielded_action_record_redacts_its_secrets_in_debug() {
    let shown = format!("{:?}", orchard_action_vector());

    // Shown: what the chain publishes — cv_net (1), nullifier (2), rk (3),
    // cmx (9), ephemeral_key (10) — and the derivation path.
    for public in [
        "[1, 1, 1",
        "[2, 2, 2",
        "[3, 3, 3",
        "[9, 9, 9",
        "[10, 10, 10",
    ] {
        assert!(
            shown.contains(public),
            "{public} should be shown in {shown}"
        );
    }
    assert!(shown.contains("2147483680"), "the derivation path is shown");

    // Redacted: spend_recipient (4), spend_rho (5), spend_rseed (6), alpha
    // (7), the seed fingerprint (8), the ciphertexts (11, 12), recipient
    // (13), rseed (14), rcv (15), and both values.
    for secret in [
        "[4, 4", "[5, 5", "[6, 6", "[7, 7", "[8, 8", "[11, 11", "[12, 12", "[13, 13", "[14, 14",
        "[15, 15",
    ] {
        assert!(!shown.contains(secret), "{secret} leaked into {shown}");
    }
    assert!(
        !shown.contains("100000000") && !shown.contains("90000000"),
        "the values are not published by the chain: {shown}"
    );
    assert!(shown.contains("alpha: \"[redacted]\""));
    assert!(shown.contains("spend_rho: \"[redacted]\""));
    assert!(shown.contains("spend_value: \"[redacted]\""));
    assert!(shown.contains("seed_fingerprint: \"[redacted]\""));
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

    // And so does the pump step that carries that APDU across the crate
    // boundary, which is the value a transport loop logs.
    let step = crate::session::PumpStep::Send(apdus[1].to_bytes());
    let shown = format!("{step:?}");
    assert_eq!(shown, "Send([248 bytes])");
    assert!(!shown.contains("[7, 7"));
    assert_eq!(
        format!("{:?}", crate::session::PumpStep::AwaitingReply),
        "AwaitingReply"
    );
    assert_eq!(format!("{:?}", crate::session::PumpStep::Done), "Done");
}

// ---------------------------------------------------------------------------
// Transparent records
// ---------------------------------------------------------------------------

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
    // The signing packet, byte for byte: sighash type, entry count, pubkey,
    // fingerprint, then the `Bip32Path` as a count and big-endian components
    // (`docs/PCZT_APDU.md#pczt_transparent_input` @ `22dc385`).
    let mut expected = vec![SIGHASH_ALL, 0x01];
    expected.extend_from_slice(&TEST_PUBKEY);
    expected.extend_from_slice(&[0x22; 32]);
    expected.extend_from_slice(&[
        0x05, 0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x00, 0x85, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    assert_eq!(groups[3], expected);
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
    // 1 count + 33 pubkey + 32 fingerprint + 21 path, byte for byte
    // (`docs/PCZT_APDU.md#pczt_transparent_output` @ `22dc385`).
    let mut expected = vec![0x01];
    expected.extend_from_slice(&TEST_PUBKEY);
    expected.extend_from_slice(&[0x22; 32]);
    expected.extend_from_slice(&[
        0x05, 0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x00, 0x85, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    assert_eq!(groups[3].len(), 87);
    assert_eq!(groups[3], expected);
}

#[test]
fn empty_transparent_sections_are_still_sent() {
    // "`PCZT_TRANSPARENT_INPUT` and `PCZT_TRANSPARENT_OUTPUT` are always sent.
    // Use count `0` when either transparent section is empty."
    let inputs = transparent_input_apdus(&[]).unwrap();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].data(), [0x00]);
    assert_eq!(inputs[0].p2(), p2::PCZT_CONTINUE);

    let outputs = transparent_output_apdus(&[]).unwrap();
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].data(), [0x00]);
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
        apdus.iter().map(|a| a.data().len()).collect::<Vec<_>>(),
        vec![1, 45, 253, 88]
    );
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
        !shown.contains("[34, 34") && shown.contains("seed_fingerprint: \"[redacted]\""),
        "the seed fingerprint identifies the wallet: {shown}"
    );
    assert!(
        !shown.contains("[49, 49") && shown.contains("prevout_txid: \"[redacted]\""),
        "the outpoint is one lookup from the address: {shown}"
    );
    assert!(shown.contains("prevout_index: 1"), "{shown}");
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
        VERSION_APDU.to_vec()
    );
}

#[test]
fn get_ufvk_carries_two_length_prefixed_paths() {
    let orchard = DerivationPath(vec![0x8000_0020, 0x8000_0085, 0x8000_0000]);
    let transparent = DerivationPath(vec![0x8000_002C, 0x8000_0085, 0x8000_0000]);
    let apdu = get_ufvk_apdu(&orchard, &transparent).unwrap();

    assert_eq!(apdu.ins(), 0x50);
    assert_eq!(apdu.p1(), 0x00);
    assert_eq!(apdu.p2(), 0x00);
    assert_eq!(
        hex::encode(apdu.data()),
        "03800000208000008580000000038000002c8000008580000000"
    );
    // Two three-component paths: 2 * (1 + 12).
    assert_eq!(apdu.data().len(), 26);
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
    assert_eq!(silent.p1(), 0x00);
    assert_eq!(silent.p2(), p2::ADDR_ORCHARD);

    let transparent = DerivationPath(vec![0x8000_002C, 0x8000_0085, 0x8000_0000, 0, 7]);
    let shown = get_unified_address_apdu(&orchard, &transparent, true).unwrap();
    assert_eq!(shown.p1(), 0x01);
    assert_eq!(shown.p2(), p2::ADDR_UNIFIED);
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
    assert_eq!(apdu.p2(), p2::WALLET_PUBLIC_KEY);
}

/// The display flag is P1, exactly as on `GET_SHIELD_ADDR`, and nothing else
/// about the command moves.
#[test]
fn the_wallet_public_key_display_flag_lives_in_p1() {
    let silent = get_wallet_public_key_apdu(&testnet_identity_path(), false).expect("encodes");
    let shown = get_wallet_public_key_apdu(&testnet_identity_path(), true).expect("encodes");

    assert_eq!(silent.p1(), p1::NO_DISPLAY);
    assert_eq!(shown.p1(), p1::DISPLAY);
    assert_eq!(shown.to_bytes()[..4], [0xE0, 0x40, 0x01, 0x00]);
    assert_eq!(silent.data(), shown.data());
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

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

/// A value from each width class of the CompactSize encoding.
/// One value from each `CompactSize` width. The widest is expressible only
/// where `usize` is wider than 32 bits, so it is filtered rather than assumed.
fn arb_compact_size_value() -> impl Strategy<Value = usize> {
    prop_oneof![
        0u64..=252,
        253u64..=0xFFFF,
        0x1_0000u64..=0xFFFF_FFFF,
        0x1_0000_0000u64..=u64::MAX,
    ]
    .prop_filter_map("value fits in usize", |n| usize::try_from(n).ok())
}

proptest! {
    /// `write_compact_size` round-trips through `zcash_encoding::CompactSize`,
    /// the reader the firmware's PCZT parser uses, in width and value — and
    /// that reader refuses everything above its 32 MiB consensus bound, so no
    /// larger size can reach the device.
    #[test]
    fn compact_size_matches_the_reference_reader(n in arb_compact_size_value()) {
        let mut enc = Vec::new();
        write_compact_size(&mut enc, n);
        let width = match n {
            0..=252 => 1,
            253..=0xFFFF => 3,
            0x1_0000..=0xFFFF_FFFF => 5,
            _ => 9,
        };
        prop_assert_eq!(enc.len(), width);

        let announced = u64::try_from(n).expect("usize fits in u64");
        let read = zcash_encoding::CompactSize::read(enc.as_slice());
        if announced <= u64::from(zcash_encoding::MAX_COMPACT_SIZE) {
            prop_assert_eq!(read.ok(), Some(announced));
        } else {
            prop_assert!(read.is_err(), "the reference accepted {n}");
        }
    }
}

/// The width boundaries by hand, since the strategy above samples them
/// rarely: the largest value of each width and the first of the next.
#[test]
fn compact_size_widths_at_the_boundaries() {
    let enc = |n: usize| {
        let mut v = Vec::new();
        write_compact_size(&mut v, n);
        v
    };
    assert_eq!(enc(0xFFFF), vec![0xFD, 0xFF, 0xFF]);
    assert_eq!(enc(0x1_0000), vec![0xFE, 0x00, 0x00, 0x01, 0x00]);
    assert_eq!(enc(0xFFFF_FFFF), vec![0xFE, 0xFF, 0xFF, 0xFF, 0xFF]);
    // The nine-byte width exists only where `usize` is wider than 32 bits.
    if let Ok(n) = usize::try_from(0x1_0000_0000u64) {
        assert_eq!(
            enc(n),
            vec![0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]
        );
    }
    for n in [0xFFFFu64, 0x1_0000, 0x0200_0000] {
        let n = usize::try_from(n).expect("under 2^32");
        assert_eq!(
            zcash_encoding::CompactSize::read(enc(n).as_slice()).ok(),
            u64::try_from(n).ok()
        );
    }
    assert!(zcash_encoding::CompactSize::read(enc(0x0200_0001).as_slice()).is_err());
}
