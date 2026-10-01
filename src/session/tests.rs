use proptest::prelude::*;

use crate::limits::{DeviceBounds, Section, MAX_BIP44_ACCOUNT, MAX_BIP44_ADDRESS_INDEX};
use crate::pairing::DeviceIdentity;
use crate::session::{
    path_compliance_error, signing_index, Network, PathRule, SessionError, SessionParams,
};
use crate::shape::{
    derivation_account, BIP44_PURPOSE, HARDENED, TRANSPARENT_INTERNAL_SCOPE, ZIP32_PURPOSE,
};

/// The session parameters print everything but the seed fingerprint, a
/// stable identifier of the wallet's seed: a wallet that logs the parameters
/// it passed — on an error from `LedgerSignSession::new`, say — must not log
/// that.
#[test]
fn session_params_redact_the_seed_fingerprint_in_debug() {
    let fingerprint = [0x5A; 32];
    let params = SessionParams::new(
        Network::Test,
        DeviceIdentity::from_compressed_pubkey(&[0x02; 33]),
        zip32::AccountId::ZERO,
    )
    .with_seed_fingerprint(Some(fingerprint));

    let shown = format!("{params:?}");
    assert!(
        shown.contains("seed_fingerprint: Some(\"[redacted]\")"),
        "{shown}"
    );
    assert!(
        !shown.contains("[90, 90"),
        "0x5A, the fingerprint's bytes: {shown}"
    );
    assert!(shown.contains("network: Test"), "{shown}");
    let without = format!("{:?}", params.with_seed_fingerprint(None));
    assert!(without.contains("seed_fingerprint: None"), "{without}");
}

/// `Stage` renders as the phrase the error messages embed it in.
#[test]
fn every_stage_has_a_display_name() {
    use crate::session::Stage;
    for (stage, name) in [
        (Stage::IdentifyingDevice, "device identification"),
        (Stage::Streaming, "transaction streaming"),
        (Stage::SigningOrchard, "Orchard signing"),
        (Stage::SigningIronwood, "Ironwood signing"),
        (Stage::SigningTransparent, "transparent signing"),
        (Stage::Complete, "completion"),
        (Stage::Failed, "failure"),
    ] {
        assert_eq!(stage.to_string(), name);
    }
}

// ---------------------------------------------------------------------------
// Path compliance
// ---------------------------------------------------------------------------

const COIN: u32 = 133;

#[test]
fn the_two_compliant_shapes_pass() {
    // m/32'/133'/0'
    assert_eq!(
        path_compliance_error(
            &[32 | HARDENED, COIN | HARDENED, HARDENED],
            COIN,
            PathRule::SigningPath
        ),
        None
    );
    // m/44'/133'/7'/1/3
    assert_eq!(
        path_compliance_error(
            &[44 | HARDENED, COIN | HARDENED, 7 | HARDENED, 1, 3],
            COIN,
            PathRule::SigningPath
        ),
        None
    );
}

/// The firmware compares the purpose with the hardening bit included: an
/// unhardened `m/44/133'/0'/0/0` is a path the OS answers by taking the
/// app down, so `check_bip44_compliance` refuses it up front and this
/// crate must too.
#[test]
fn an_unhardened_purpose_is_refused() {
    assert!(path_compliance_error(
        &[44, COIN | HARDENED, HARDENED, 0, 0],
        COIN,
        PathRule::SigningPath
    )
    .is_some());
    assert!(path_compliance_error(
        &[32, COIN | HARDENED, HARDENED],
        COIN,
        PathRule::SigningPath
    )
    .is_some());
}

#[test]
fn a_wrong_or_unhardened_coin_type_is_refused() {
    // Testnet coin type on a mainnet session, and vice versa.
    assert!(path_compliance_error(
        &[44 | HARDENED, 1 | HARDENED, HARDENED, 0, 0],
        COIN,
        PathRule::SigningPath
    )
    .is_some());
    assert!(path_compliance_error(
        &[32 | HARDENED, COIN | HARDENED, HARDENED],
        1,
        PathRule::SigningPath
    )
    .is_some());
    // Unhardened coin type.
    assert!(path_compliance_error(
        &[44 | HARDENED, COIN, HARDENED, 0, 0],
        COIN,
        PathRule::SigningPath
    )
    .is_some());
}

#[test]
fn an_unhardened_account_is_refused() {
    assert!(path_compliance_error(
        &[44 | HARDENED, COIN | HARDENED, 2, 0, 0],
        COIN,
        PathRule::SigningPath
    )
    .is_some());
    assert!(path_compliance_error(
        &[32 | HARDENED, COIN | HARDENED, 2],
        COIN,
        PathRule::SigningPath
    )
    .is_some());
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
        assert!(
            path_compliance_error(path, COIN, PathRule::SigningPath).is_some(),
            "{path:?}"
        );
    }
}

/// The purpose byte must match the depth: a 3-deep path is the ZIP 32
/// shape (purpose 32'), a 5-deep one the BIP 44 shape (purpose 44').
#[test]
fn a_purpose_on_the_wrong_depth_is_refused() {
    assert!(path_compliance_error(
        &[44 | HARDENED, COIN | HARDENED, HARDENED],
        COIN,
        PathRule::SigningPath
    )
    .is_some());
    assert!(path_compliance_error(
        &[32 | HARDENED, COIN | HARDENED, HARDENED, 0, 0],
        COIN,
        PathRule::SigningPath
    )
    .is_some());
}

/// A transparent output's derivation is checked in the firmware's `Full`
/// mode, which adds four rules to the signing-path ones, in this order:
/// no ZIP 32 shape, account at most 100, the internal scope, address
/// index at most 50000.
#[test]
fn the_change_output_rule_adds_the_full_mode_bounds() {
    let ok = [44 | HARDENED, COIN | HARDENED, 7 | HARDENED, 1, 50_000];
    assert_eq!(
        path_compliance_error(&ok, COIN, PathRule::ChangeOutput),
        None
    );
    assert_eq!(
        path_compliance_error(&ok, COIN, PathRule::SigningPath),
        None
    );

    // Every rule the change mode adds passes the signing-path mode.
    let refused_only_as_change = [
        &[32 | HARDENED, COIN | HARDENED, HARDENED][..],
        &[44 | HARDENED, COIN | HARDENED, 101 | HARDENED, 1, 0][..],
        &[44 | HARDENED, COIN | HARDENED, HARDENED, 0, 0][..],
        &[44 | HARDENED, COIN | HARDENED, HARDENED, 2, 0][..],
        &[44 | HARDENED, COIN | HARDENED, HARDENED, 1, 50_001][..],
        // A hardened index is above the bound on its own.
        &[44 | HARDENED, COIN | HARDENED, HARDENED, 1, HARDENED][..],
    ];
    for path in refused_only_as_change {
        assert!(
            path_compliance_error(path, COIN, PathRule::ChangeOutput).is_some(),
            "{path:?}"
        );
        assert_eq!(
            path_compliance_error(path, COIN, PathRule::SigningPath),
            None,
            "{path:?}"
        );
    }
    // The bounds are the firmware's, exactly.
    assert_eq!(crate::limits::MAX_BIP44_ACCOUNT, 100);
    assert_eq!(crate::limits::MAX_BIP44_ADDRESS_INDEX, 50_000);
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

/// A coin type and a derivation path: random components, or a path shaped
/// like one of the two forms the firmware accepts with each component free to
/// be right or wrong, so that both answers are reached.
fn arb_coin_and_path() -> impl Strategy<Value = (u32, Vec<u32>)> {
    let coin = prop_oneof![Just(133u32), Just(1u32)];
    let random = (coin.clone(), prop::collection::vec(any::<u32>(), 0..=12));
    let shaped = (
        coin,
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        0u32..=120,
        any::<bool>(),
        0u32..=2,
        prop_oneof![0u32..=60_000, any::<u32>()],
    )
        .prop_map(
            |(coin, five, purpose_ok, coin_ok, account, hardened, scope, index)| {
                let purpose = if five { BIP44_PURPOSE } else { ZIP32_PURPOSE };
                let mut path = vec![
                    if purpose_ok {
                        purpose | HARDENED
                    } else {
                        purpose
                    },
                    if coin_ok { coin | HARDENED } else { coin },
                    if hardened {
                        account | HARDENED
                    } else {
                        account
                    },
                ];
                if five {
                    path.push(scope);
                    path.push(index);
                }
                (coin, path)
            },
        );
    prop_oneof![random, shaped]
}

/// `check_bip44_compliance` under `OnlyCoinType`, as the firmware states it.
fn signing_path_ok(path: &[u32], coin: u32) -> bool {
    let purpose = match path.len() {
        3 => ZIP32_PURPOSE,
        5 => BIP44_PURPOSE,
        _ => return false,
    };
    path[0] == purpose | HARDENED && path[1] == coin | HARDENED && path[2] & HARDENED != 0
}

/// `check_bip44_compliance` under `Full { is_change_path: true }`.
fn change_output_ok(path: &[u32], coin: u32) -> bool {
    path.len() == 5
        && signing_path_ok(path, coin)
        && path[2] & !HARDENED <= MAX_BIP44_ACCOUNT
        && path[3] == TRANSPARENT_INTERNAL_SCOPE
        && path[4] <= MAX_BIP44_ADDRESS_INDEX
}

proptest! {
    /// `path_compliance_error` and `derivation_account` agree with the
    /// firmware's rules as restated here, for every path shape.
    #[test]
    fn path_compliance_matches_the_firmware_rules((coin, path) in arb_coin_and_path()) {
        prop_assert_eq!(
            path_compliance_error(&path, coin, PathRule::SigningPath).is_none(),
            signing_path_ok(&path, coin),
            "signing path {:x?}", path
        );
        prop_assert_eq!(
            path_compliance_error(&path, coin, PathRule::ChangeOutput).is_none(),
            change_output_ok(&path, coin),
            "change output {:x?}", path
        );
        let account = if matches!(path.len(), 3 | 5) { Some(path[2]) } else { None };
        prop_assert_eq!(derivation_account(&path), account);
    }
}

/// Every `PCZT_SIGN_*` command carries its record index in one byte, and
/// `signing_index` is the narrowing. Every index a validated plan can present
/// is well inside a byte, so it always succeeds there; past a byte it names
/// the record rather than truncating, which would have the device sign a
/// record other than the one the host files the signature under.
#[test]
fn a_signing_index_past_one_byte_is_named_not_truncated() {
    let widest = DeviceBounds::MOST_PERMISSIVE;
    for (section, count) in [
        (Section::TransparentInput, widest.transparent_inputs()),
        (Section::Orchard, widest.orchard_actions()),
        (Section::Ironwood, widest.ironwood_actions()),
    ] {
        for index in 0..count {
            assert!(
                signing_index(section, index).is_ok(),
                "{section} {index} is within the widest bounds"
            );
        }
    }

    let past_one_byte = usize::from(u8::MAX) + 1;
    assert_eq!(
        signing_index(Section::Orchard, past_one_byte - 1),
        Ok(u8::MAX)
    );
    for (section, index) in [
        (Section::TransparentInput, past_one_byte),
        (Section::Orchard, past_one_byte),
        (Section::Ironwood, usize::MAX),
    ] {
        assert_eq!(
            signing_index(section, index),
            Err(SessionError::SigningIndexTooLarge { section, index })
        );
    }
}
