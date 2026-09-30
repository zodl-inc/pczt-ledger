use crate::shape::{
    hash160, ChangeDeriveError, ChangeInfo, ShapeParams, TRANSPARENT_INTERNAL_SCOPE,
};
use zcash_transparent::keys::{
    AccountPrivKey, IncomingViewingKey, NonHardenedChildIndex, TransparentKeyScope,
};

/// The shaping parameters print everything but the seed fingerprint, a
/// stable identifier of the wallet's seed.
#[test]
fn shape_params_redact_the_seed_fingerprint_in_debug() {
    let params =
        ShapeParams::new(133, zip32::AccountId::ZERO).with_seed_fingerprint(Some([0x5A; 32]));
    let shown = format!("{params:?}");
    assert!(
        shown.contains("seed_fingerprint: Some(\"[redacted]\")"),
        "{shown}"
    );
    assert!(
        !shown.contains("[90, 90"),
        "0x5A, the fingerprint's bytes: {shown}"
    );
    assert!(shown.contains("coin_type: 133"), "{shown}");
    let without = format!("{:?}", params.with_seed_fingerprint(None));
    assert!(without.contains("seed_fingerprint: None"), "{without}");
}

// ---------------------------------------------------------------------------
// Change derivation
// ---------------------------------------------------------------------------

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
fn internal_pubkey_and_index() -> ([u8; 33], NonHardenedChildIndex) {
    let fvk = fvk();
    let (_, index) = fvk
        .derive_internal_ivk()
        .expect("an internal ivk")
        .default_address();
    let pubkey = fvk
        .derive_address_pubkey(TransparentKeyScope::INTERNAL, index)
        .expect("derives")
        .serialize();
    (pubkey, index)
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
    let next = NonHardenedChildIndex::from_index(index.index() + 1).expect("unhardened");
    let err = ChangeInfo::derive(&fvk(), TRANSPARENT_INTERNAL_SCOPE, next, 0, &script)
        .expect_err("a wrong index is refused");
    assert_eq!(
        err,
        ChangeDeriveError::PubkeyMismatch {
            output_index: 0,
            address_index: next.index(),
        }
    );

    // Neither hash is in the error: a P2PKH hash is the address, and an
    // error is what a wallet logs.
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let script_hash = hex(&script[3..23]);
    for rendered in [format!("{err}"), format!("{err:?}")] {
        assert!(!rendered.contains(&script_hash), "{rendered}");
    }
}
