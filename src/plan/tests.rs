use crate::apdu::encode::*;
use crate::limits::*;
use crate::plan::validate_plan;
use crate::test_support::{p2pkh_script, transparent_derivation, v5_plan};

/// Two transparent change outputs are refused with no viewing key at all: the
/// transparent half of the change-output limit is read off the records, so it does
/// not wait for the shielded half to become countable.
#[test]
fn two_transparent_change_outputs_are_refused_without_viewing_keys() {
    let change = || TransparentOutputRecord {
        value: 1,
        script_pubkey: p2pkh_script(),
        derivation: Some(transparent_derivation()),
    };

    assert_eq!(
        validate_plan(&v5_plan_with_outputs(vec![change()]), &DeviceBounds::V3_9_2),
        Ok(())
    );

    let errs = validate_plan(
        &v5_plan_with_outputs(vec![change(), change()]),
        &DeviceBounds::V3_9_2,
    )
    .unwrap_err();
    assert_eq!(
        errs,
        vec![LimitViolation::TooManyChangeOutputs {
            got: 2,
            max: 1,
            shielded: None
        }]
    );
}

/// The change-output check reads the limit from the bounds rather than
/// assuming one, so a firmware that raises it needs only a new set: under a
/// limit of two, two transparent change outputs pass and a third is refused.
#[test]
fn the_change_output_limit_comes_from_the_bounds() {
    let change = || TransparentOutputRecord {
        value: 1,
        script_pubkey: p2pkh_script(),
        derivation: Some(transparent_derivation()),
    };
    let raised = DeviceBounds {
        change_outputs: 2,
        ..DeviceBounds::V3_9_4
    };

    assert_eq!(
        validate_plan(&v5_plan_with_outputs(vec![change(), change()]), &raised),
        Ok(())
    );
    let errs = validate_plan(
        &v5_plan_with_outputs(vec![change(), change(), change()]),
        &raised,
    )
    .unwrap_err();
    assert!(
        errs.contains(&LimitViolation::TooManyChangeOutputs {
            got: 3,
            max: 2,
            shielded: None
        }),
        "{errs:?}"
    );
}

/// A plan with nothing for the device to review — no transparent output, no
/// displayed shielded output, no shielded change — is refused when the keys
/// make those counts exact, and streamed when they do not.
#[test]
fn a_review_with_no_outputs_is_refused_with_viewing_keys() {
    let empty_review = |displayed: usize, change: Option<usize>| crate::plan::Plan {
        displayed_shielded_outputs: displayed,
        shielded_change_outputs: change,
        ..v5_plan_with_outputs(Vec::new())
    };
    let refused = |plan: &crate::plan::Plan| {
        validate_plan(plan, &DeviceBounds::V3_9_4)
            .err()
            .unwrap_or_default()
            .contains(&LimitViolation::NoReviewableOutputs)
    };

    assert!(refused(&empty_review(0, Some(0))));
    // A shielded change output is on the device's list, and so is a
    // displayed one; either is enough.
    assert!(!refused(&empty_review(0, Some(1))));
    assert!(!refused(&empty_review(1, Some(0))));
    // Without keys a zero-valued output the OVK opens cannot be told from
    // padding, so nothing is refused.
    assert!(!refused(&empty_review(0, None)));
    // A transparent output is always on the list.
    let with_transparent = crate::plan::Plan {
        displayed_shielded_outputs: 0,
        shielded_change_outputs: Some(0),
        ..v5_plan_with_outputs(vec![TransparentOutputRecord {
            value: 1,
            script_pubkey: p2pkh_script(),
            derivation: None,
        }])
    };
    assert!(!refused(&with_transparent));
}

/// A V5 plan with no transparent inputs and the given outputs, built without
/// viewing keys.
fn v5_plan_with_outputs(outputs: Vec<TransparentOutputRecord>) -> crate::plan::Plan {
    crate::plan::Plan {
        stream: StreamPlan {
            transparent_outputs: outputs,
            ..v5_plan()
        },
        global: crate::plan::GlobalFields {
            tx_version: 5,
            version_group_id: V5_VERSION_GROUP_ID,
            consensus_branch_id: zcash_protocol::consensus::BranchId::Nu5,
            fallback_lock_time: None,
            expiry_height: zcash_protocol::consensus::BlockHeight::from_u32(2_500_000),
            coin_type: COIN_TYPE_MAINNET,
            tx_modifiable: 0,
        },
        orchard_real_spends: Vec::new(),
        ironwood_real_spends: Vec::new(),
        displayed_shielded_outputs: 1,
        shielded_change_outputs: None,
        displayed_memos: None,
        missing_zip32: Vec::new(),
    }
}

/// An unmarked output paying the change output's address is refused, on
/// either side of it: the device classifies change per output, so it would
/// show this one as a payment to a third party. An unmarked output paying
/// anywhere else is the ordinary recipient.
#[test]
fn an_unmarked_output_paying_the_change_address_is_refused() {
    let change = TransparentOutputRecord {
        value: 1,
        script_pubkey: p2pkh_script(),
        derivation: Some(transparent_derivation()),
    };
    let twin = TransparentOutputRecord {
        value: 2,
        script_pubkey: p2pkh_script(),
        derivation: None,
    };
    let mut elsewhere = vec![0x76, 0xA9, 0x14];
    elsewhere.extend_from_slice(&[0x42; 20]);
    elsewhere.extend_from_slice(&[0x88, 0xAC]);
    let recipient = TransparentOutputRecord {
        value: 3,
        script_pubkey: elsewhere,
        derivation: None,
    };

    assert_eq!(
        validate_plan(
            &v5_plan_with_outputs(vec![change.clone(), recipient]),
            &DeviceBounds::V3_9_2
        ),
        Ok(())
    );

    let errs = validate_plan(
        &v5_plan_with_outputs(vec![change.clone(), twin.clone()]),
        &DeviceBounds::V3_9_2,
    )
    .unwrap_err();
    assert_eq!(
        errs,
        vec![LimitViolation::UnmarkedChangeOutput {
            change: 0,
            index: 1
        }]
    );

    let errs = validate_plan(
        &v5_plan_with_outputs(vec![twin, change]),
        &DeviceBounds::V3_9_2,
    )
    .unwrap_err();
    assert_eq!(
        errs,
        vec![LimitViolation::UnmarkedChangeOutput {
            change: 1,
            index: 0
        }]
    );
}

// ---------------------------------------------------------------------------
// Memo rendering
// ---------------------------------------------------------------------------

/// `memo_display`'s classification, case by case as the firmware's
/// `memo_display` (`src/parser/pczt.rs` @ `22dc385`) reads a memo.
#[test]
fn memos_are_classified_the_way_the_device_renders_them() {
    use crate::plan::{memo_display, MemoDisplay};

    let mut memo = [0u8; 512];
    assert_eq!(memo_display(&memo), MemoDisplay::Empty, "all zeros");
    memo[0] = 0xF6;
    assert_eq!(
        memo_display(&memo),
        MemoDisplay::Empty,
        "the empty-memo tag"
    );

    let mut memo = [0u8; 512];
    memo[..5].copy_from_slice(b"hello");
    assert_eq!(
        memo_display(&memo),
        MemoDisplay::Text(5),
        "text retains its length up to the last nonzero byte"
    );
    assert_eq!(memo_display(&[b'x'; 512]), MemoDisplay::Text(512));

    // A control byte, a non-ASCII byte, or a tag past 0xF4 is hashed.
    let mut memo = [0u8; 512];
    memo[..3].copy_from_slice(b"a\x01b");
    assert_eq!(memo_display(&memo), MemoDisplay::Hashed);
    let mut memo = [0u8; 512];
    memo[..2].copy_from_slice("é".as_bytes());
    assert_eq!(memo_display(&memo), MemoDisplay::Hashed);
    let mut memo = [0u8; 512];
    memo[0] = 0xF5;
    assert_eq!(memo_display(&memo), MemoDisplay::Hashed);
    let mut memo = [0u8; 512];
    memo[0] = 0xF6;
    memo[1] = 0x01;
    assert_eq!(
        memo_display(&memo),
        MemoDisplay::Hashed,
        "the empty tag followed by anything nonzero is not an empty memo"
    );
}
