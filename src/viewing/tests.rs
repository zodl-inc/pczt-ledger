use super::*;

use orchard::keys::SpendingKey;
use zcash_transparent::keys::AccountPrivKey;

/// Neither key type shows anything of its key in `Debug`: a full viewing key
/// identifies and decrypts every note of the account, and the transparent
/// account key links every address the account has ever used.
#[test]
fn the_account_keys_redact_themselves_in_debug() {
    let sk = SpendingKey::from_bytes([3; 32]).expect("a valid spending key");
    let shielded = AccountViewingKeys::from_orchard_fvk(FullViewingKey::from(&sk));
    assert_eq!(format!("{shielded:?}"), "AccountViewingKeys([redacted])");

    let account = AccountPrivKey::from_seed(
        &zcash_protocol::consensus::TEST_NETWORK,
        &[1u8; 32],
        zip32::AccountId::ZERO,
    )
    .expect("the seed derives an account key")
    .to_account_pubkey();
    let transparent = TransparentAccountKey::from_account_pubkey(account);
    assert_eq!(
        format!("{transparent:?}"),
        "TransparentAccountKey([redacted])"
    );
}
