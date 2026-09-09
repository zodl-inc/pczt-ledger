use crate::apdu::encode::*;
use crate::apdu::*;
use crate::limits::*;
use crate::session::Network;
use crate::test_support::{
    orchard_action_vector, orchard_trailer_vector, p2pkh_script, transparent_derivation, v5_plan,
};
use zcash_protocol::consensus::NetworkType;

// ---------------------------------------------------------------------------
// Limits and capabilities
// ---------------------------------------------------------------------------

#[test]
fn device_caps_thresholds() {
    let old = DeviceCaps::from_version(3, 5, 9);
    assert!(!old.pczt());
    assert!(!old.ironwood());

    let pczt_only = DeviceCaps::from_version(3, 6, 0);
    assert!(pczt_only.pczt());
    assert!(!pczt_only.ironwood());

    let full = DeviceCaps::from_version(3, 9, 2);
    assert!(full.pczt());
    assert!(full.ironwood());
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

    // Right length, wrong opcodes: the shape is exact at both ends.
    let mut bad_prefix = p2pkh_script();
    bad_prefix[0] = 0x77;
    assert!(!is_standard_output_script(&bad_prefix));

    let mut bad_postfix = p2pkh_script();
    let last = bad_postfix.len() - 1;
    bad_postfix[last] = 0xAD;
    assert!(!is_standard_output_script(&bad_postfix));

    let mut bad_p2sh_postfix = p2sh.clone();
    let last = bad_p2sh_postfix.len() - 1;
    bad_p2sh_postfix[last] = 0x88;
    assert!(!is_standard_output_script(&bad_p2sh_postfix));
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
    assert_eq!(apdus[0].ins(), 0x52);
    assert_eq!(apdus[1].ins(), 0x53);
    assert_eq!(apdus[2].ins(), 0x54);
    assert!(apdus[3..].iter().all(|a| a.ins() == 0x56));
    assert_eq!(apdus.last().unwrap().p2(), p2::PCZT_FINISHED);
    assert_eq!(apdus.last().unwrap().p1(), p1::LAST);
    assert!(apdus[..apdus.len() - 1]
        .iter()
        .all(|a| a.p2() == p2::PCZT_CONTINUE));
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
    assert_eq!(last.ins(), 0x58);
    assert_eq!(last.p1(), p1::FIRST); // the empty bundle is one packet
    assert_eq!(last.p2(), p2::PCZT_FINISHED);
    assert_eq!(last.data(), [0x00]);

    // Every Orchard packet, including the last, continues.
    assert!(apdus
        .iter()
        .filter(|a| a.ins() == 0x56)
        .all(|a| a.p2() == p2::PCZT_CONTINUE));
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

/// `TooManyRecords` for every section on every bounds set: exactly the bound
/// passes and one more fails, so the tables in `DeviceBounds` are what the
/// validator enforces — the two transparent-input cells the v3.9.3 pin moved,
/// the output bound it left alone, and both fallback sets included.
#[test]
fn every_record_bound_is_enforced_on_every_bounds_set() {
    let input = || TransparentInputRecord {
        prevout_txid: [0x31; 32],
        prevout_index: 1,
        sequence: None,
        value: 50_000,
        script_pubkey: p2pkh_script(),
        sighash_type: SIGHASH_ALL,
        derivation: transparent_derivation(),
    };
    let output = || TransparentOutputRecord {
        value: 40_000,
        script_pubkey: p2pkh_script(),
        derivation: None,
    };
    let sections = [
        Section::TransparentInput,
        Section::TransparentOutput,
        Section::Orchard,
        Section::Ironwood,
    ];
    for (name, bounds) in [
        ("3.9.2", DeviceBounds::V3_9_2),
        ("3.9.3", DeviceBounds::V3_9_3),
        ("most restrictive", DeviceBounds::MOST_RESTRICTIVE),
        ("most permissive", DeviceBounds::MOST_PERMISSIVE),
    ] {
        for section in sections {
            let max = match section {
                Section::TransparentInput => bounds.transparent_inputs(),
                Section::TransparentOutput => bounds.transparent_outputs(),
                Section::Orchard => bounds.orchard_actions(),
                Section::Ironwood => bounds.ironwood_actions(),
            };
            let plan_with = |n: usize| {
                let mut plan = if section == Section::Ironwood {
                    v6_plan()
                } else {
                    v5_plan()
                };
                match section {
                    Section::TransparentInput => {
                        plan.transparent_inputs = (0..n).map(|_| input()).collect();
                    }
                    Section::TransparentOutput => {
                        plan.transparent_outputs = (0..n).map(|_| output()).collect();
                    }
                    Section::Orchard => plan.orchard_actions = vec![orchard_action_vector(); n],
                    Section::Ironwood => {
                        plan.ironwood_actions = Some(vec![orchard_action_vector(); n]);
                        plan.ironwood_trailer = Some(orchard_trailer_vector());
                    }
                }
                plan
            };
            let too_many = |violations: &[LimitViolation]| {
                violations.iter().find_map(|v| match v {
                    LimitViolation::TooManyRecords {
                        section: s,
                        got,
                        max,
                    } if *s == section => Some((*got, *max)),
                    _ => None,
                })
            };

            let at_bound = validate_records(&plan_with(max), &bounds)
                .err()
                .unwrap_or_default();
            assert_eq!(
                too_many(&at_bound),
                None,
                "{name}: {section:?} at its bound of {max}"
            );
            let over = validate_records(&plan_with(max + 1), &bounds)
                .expect_err("one past the bound is refused");
            assert_eq!(
                too_many(&over),
                Some((max + 1, max)),
                "{name}: {section:?} one past its bound: {over:?}"
            );
        }
    }
}

/// `MOST_PERMISSIVE` is, count for count, the largest of the real sets;
/// `MOST_RESTRICTIVE` is the smallest; and every set carries both review
/// budgets, at the one value the firmware defines. They are the two sets a
/// caller chooses between for a version the crate has not been checked
/// against, and each is a hand-maintained copy of the same numbers: a pin move
/// that raises a bound and forgets one of them would turn a pre-flight into a
/// spurious refusal, or an unrecognised app into an optimistic one.
#[test]
fn the_fallback_bounds_bracket_every_real_set() {
    let real = [DeviceBounds::V3_9_2, DeviceBounds::V3_9_3];
    let most = DeviceBounds::MOST_PERMISSIVE;
    let strictest = DeviceBounds::MOST_RESTRICTIVE;

    /// A count's name and how to read it off a bounds set.
    type Count = (&'static str, fn(&DeviceBounds) -> usize);
    let counts: [Count; 4] = [
        ("transparent inputs", |b| b.transparent_inputs()),
        ("transparent outputs", |b| b.transparent_outputs()),
        ("Orchard actions", |b| b.orchard_actions()),
        ("Ironwood actions", |b| b.ironwood_actions()),
    ];
    for (what, count) in counts {
        let over_real = real.iter().map(count);
        assert_eq!(count(&most), over_real.clone().max().unwrap(), "{what}");
        assert_eq!(count(&strictest), over_real.min().unwrap(), "{what}");
    }

    for bounds in [most, strictest].iter().chain(real.iter()) {
        assert_eq!(
            bounds.displayed_shielded_outputs(),
            MAX_DISPLAYED_SHIELDED_OUTPUTS
        );
        assert_eq!(bounds.retained_memo_bytes(), MAX_RETAINED_MEMO_BYTES);
    }
    // The budgets are the firmware's, exactly (`src/consts.rs` and
    // `src/parser/pczt.rs` @ `22dc385`).
    assert_eq!(MAX_DISPLAYED_SHIELDED_OUTPUTS, 4);
    assert_eq!(MAX_RETAINED_MEMO_BYTES, 1024);
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

/// `check_output_displayable` answers `None` for a zero-valued output before
/// it looks at the script, on both pins, so the value is checked here like the
/// script shape is.
#[test]
fn a_zero_valued_transparent_output_is_rejected() {
    let mut plan = v5_plan();
    plan.transparent_outputs.push(TransparentOutputRecord {
        value: 0,
        script_pubkey: p2pkh_script(),
        derivation: None,
    });
    let errs = validate_records(&plan, &DeviceBounds::V3_9_3).unwrap_err();
    assert_eq!(
        errs,
        vec![LimitViolation::ZeroValuedTransparentOutput { index: 0 }]
    );

    // One zatoshi is an output the device reviews.
    plan.transparent_outputs[0].value = 1;
    validate_records(&plan, &DeviceBounds::V3_9_3).expect("a valued P2PKH output is accepted");
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

    // The mirror: both coin types with a device build are accepted.
    for coin_type in [COIN_TYPE_MAINNET, COIN_TYPE_TESTNET] {
        let mut plan = v5_plan();
        plan.header.coin_type = coin_type;
        assert_eq!(
            validate_records(&plan, &DeviceBounds::V3_9_2),
            Ok(()),
            "{coin_type}"
        );
    }
}

/// A trailer on an empty bundle is the other half of the rule a missing
/// trailer breaks: an empty bundle forbids one.
#[test]
fn a_trailer_on_an_empty_bundle_is_rejected() {
    let mut plan = v5_plan();
    plan.orchard_actions = Vec::new();
    let errs = validate_records(&plan, &DeviceBounds::V3_9_2).unwrap_err();
    assert!(errs.iter().any(|e| matches!(
        e,
        LimitViolation::TrailerMismatch {
            section: Section::Orchard,
            actions: 0,
            has_trailer: true
        }
    )));
}

/// An Ironwood action may declare note version three or leave the byte out;
/// only another version is refused.
#[test]
fn an_ironwood_action_may_declare_note_version_three_or_nothing() {
    for version in [Some(NOTE_VERSION_IRONWOOD), None] {
        let mut plan = v6_plan();
        let mut action = orchard_action_vector();
        action.note_plaintext_version = version;
        plan.ironwood_actions = Some(vec![action]);
        plan.ironwood_trailer = Some(orchard_trailer_vector());
        let violations = validate_records(&plan, &DeviceBounds::V3_9_2)
            .err()
            .unwrap_or_default();
        assert!(
            !violations
                .iter()
                .any(|e| matches!(e, LimitViolation::BadNotePlaintextVersion { .. })),
            "{version:?}: {violations:?}"
        );
    }
}

/// A well-formed input paying [`p2pkh_script`] with [`transparent_derivation`]
/// as its signing-key locator.
fn transparent_input_record() -> TransparentInputRecord {
    TransparentInputRecord {
        prevout_txid: [0x11; 32],
        prevout_index: 0,
        sequence: None,
        value: 1_000_000,
        script_pubkey: p2pkh_script(),
        sighash_type: SIGHASH_ALL,
        derivation: transparent_derivation(),
    }
}

/// A signing path longer than the firmware's `Bip32Path` holds is refused at
/// the records, naming the input, rather than by the encoder.
#[test]
fn an_over_long_input_path_is_rejected() {
    let mut plan = v5_plan();
    let mut input = transparent_input_record();
    input.derivation.path = DerivationPath(vec![0x8000_002C; MAX_PATH_COMPONENTS + 1]);
    plan.transparent_inputs = vec![input];
    let errs = validate_records(&plan, &DeviceBounds::V3_9_2).unwrap_err();
    assert!(
        errs.iter().any(|e| matches!(
            e,
            LimitViolation::PathTooLong {
                section: Section::TransparentInput,
                index: 0,
                got,
            } if *got == MAX_PATH_COMPONENTS + 1
        )),
        "{errs:?}"
    );

    // At the bound, the path is fine.
    let mut plan = v5_plan();
    let mut input = transparent_input_record();
    input.derivation.path = DerivationPath(vec![0x8000_002C; MAX_PATH_COMPONENTS]);
    plan.transparent_inputs = vec![input];
    assert!(!validate_records(&plan, &DeviceBounds::V3_9_2)
        .err()
        .unwrap_or_default()
        .iter()
        .any(|e| matches!(e, LimitViolation::PathTooLong { .. })));
}

/// A transaction version the device has no parser for is refused at the
/// header.
#[test]
fn an_unsupported_tx_version_is_rejected() {
    let mut plan = v5_plan();
    plan.header.tx_version = 4;
    let errs = validate_records(&plan, &DeviceBounds::V3_9_2).unwrap_err();
    assert!(
        errs.iter().any(|e| matches!(
            e,
            LimitViolation::UnsupportedTxVersion {
                tx_version: 4,
                version_group_id: V5_VERSION_GROUP_ID,
            }
        )),
        "{errs:?}"
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
// Network mapping
// ---------------------------------------------------------------------------

#[test]
fn main_and_test_map_and_regtest_is_refused() {
    assert_eq!(Network::try_from(NetworkType::Main), Ok(Network::Main));
    assert_eq!(Network::try_from(NetworkType::Test), Ok(Network::Test));
    let refused = Network::try_from(NetworkType::Regtest);
    assert_eq!(refused, Err(UnsupportedNetwork(NetworkType::Regtest)));
    assert_eq!(
        refused.map_err(|e| e.network_type()),
        Err(NetworkType::Regtest)
    );
}

// ---------------------------------------------------------------------------
// Fee
// ---------------------------------------------------------------------------

/// The device's fee check, run on the plan: `review_outputs`
/// (`src/parser/pczt/common.rs`, the same at `22dc385` and `0e048bb`)
/// refuses a transaction whose transparent inputs plus shielded value
/// balances are less than its transparent outputs, at the packet carrying
/// `P2_PCZT_FINISHED`, after everything has been streamed.
#[test]
fn a_negative_fee_is_rejected() {
    let paying = |value: u64| TransparentOutputRecord {
        value,
        script_pubkey: p2pkh_script(),
        derivation: None,
    };
    let negative_fee = |errs: &[LimitViolation]| {
        errs.iter()
            .any(|e| matches!(e, LimitViolation::NegativeFee))
    };

    // No transparent input; the Orchard trailer contributes +10_000_000.
    let mut plan = v5_plan();
    assert_eq!(
        plan.orchard_trailer.as_ref().map(|t| t.value_sum),
        Some(10_000_000)
    );
    plan.transparent_outputs = vec![paying(50_000_000)];
    let errs = validate_records(&plan, &DeviceBounds::V3_9_3).unwrap_err();
    assert!(negative_fee(&errs), "{errs:?}");

    // Exactly the shielded balance out is a zero fee, which the device takes.
    plan.transparent_outputs = vec![paying(10_000_000)];
    assert_eq!(validate_records(&plan, &DeviceBounds::V3_9_3), Ok(()));

    // A transparent input makes up the difference; one zatoshi less does not.
    plan.transparent_outputs = vec![paying(50_000_000)];
    plan.transparent_inputs = vec![TransparentInputRecord {
        value: 40_000_000,
        ..transparent_input_record()
    }];
    assert_eq!(validate_records(&plan, &DeviceBounds::V3_9_3), Ok(()));
    plan.transparent_inputs[0].value = 39_999_999;
    let errs = validate_records(&plan, &DeviceBounds::V3_9_3).unwrap_err();
    assert!(negative_fee(&errs), "{errs:?}");

    // A negative shielded balance — a shielded output paid from transparent
    // inputs — counts against the fee the same way.
    let mut plan = v5_plan();
    plan.orchard_trailer.as_mut().expect("a trailer").value_sum = -10_000_000;
    plan.transparent_inputs = vec![TransparentInputRecord {
        value: 9_999_999,
        ..transparent_input_record()
    }];
    let errs = validate_records(&plan, &DeviceBounds::V3_9_3).unwrap_err();
    assert!(negative_fee(&errs), "{errs:?}");
    plan.transparent_inputs[0].value = 10_000_000;
    assert_eq!(validate_records(&plan, &DeviceBounds::V3_9_3), Ok(()));
}
