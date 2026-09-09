//! The account's shielded viewing keys, as the device derives them.
//!
//! # Why the host wants them
//!
//! The device classifies every shielded output by trial decryption
//! (`try_decipher_current_orchard_output`, `src/parser/pczt/orchard.rs` @
//! `22dc385`, and its Ironwood twin): an output that opens under the account's
//! **internal IVK** is change and is kept off the review screen; one that then
//! opens under the account's **external OVK** is displayed and claims a slot of
//! the `MAX_PCZT_SHIELDED_DISPLAYED_OUTPUTS_NUMBER` budget.
//!
//! Without the key the host can only count nonzero outputs, which over-counts
//! change: a wallet that splits change across several notes produces a bundle
//! a value-only count refuses even though the device would display a single
//! output. With the key the host reaches the device's own answer. See
//! [`crate::plan::Plan::displayed_shielded_outputs`].
//!
//! # One key, both pools
//!
//! Ironwood has no viewing keys of its own. The device derives the same
//! [`FullViewingKey`] for both pools — `parse_orchard_action_metadata` and
//! `parse_ironwood_action_metadata` both call `derive_orchard_fvk_from_sk` on
//! the account's Orchard spending key and hand the result to
//! `OrchardDecipherKeys::from_fvk` — and the two decryption paths differ only in
//! the note-plaintext version constant they demand (`NOTE_VERSION_ORCHARD` vs
//! `NOTE_VERSION_IRONWOOD`). Hence a single Orchard FVK here, applied to both
//! bundles by [`crate::plan`]. The export path matches: the UFVK the device
//! returns over `GET_VK` carries Orchard and P2PKH items and no Ironwood item.
//!
//! This is a *viewing* key: it identifies and decrypts the account's own notes
//! and authorizes nothing.

use orchard::{
    keys::{FullViewingKey, Scope},
    note_encryption::{IronwoodDomain, OrchardDomain},
    NoteVersion,
};
use zcash_note_encryption::try_output_recovery_with_ovk;

/// The account's shielded viewing keys, in the form the display count needs.
///
/// Built by the caller from the Orchard item of the account's UFVK
/// (`zcash_keys::keys::UnifiedFullViewingKey::decode(…).orchard()`); this crate
/// deliberately does not depend on `zcash_keys`, so the decode happens above
/// it.
///
/// `Debug` shows nothing of the key: it identifies and decrypts every note the
/// account has ever received.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountViewingKeys {
    fvk: FullViewingKey,
}

impl core::fmt::Debug for AccountViewingKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AccountViewingKeys([redacted])")
    }
}

impl AccountViewingKeys {
    /// Wraps the account's Orchard full viewing key.
    ///
    /// The same key covers the Ironwood pool; see the module docs.
    pub fn from_orchard_fvk(fvk: FullViewingKey) -> Self {
        Self { fvk }
    }

    /// The Orchard full viewing key, for a caller that needs it directly.
    pub fn orchard_fvk(&self) -> &FullViewingKey {
        &self.fvk
    }

    /// Whether an output's recipient is one of this account's **internal**
    /// (change) addresses.
    ///
    /// # Why re-deriving the address is the same test the device runs
    ///
    /// The device decrypts the compact note under the internal IVK and then
    /// requires the recovered address to equal the PCZT's `recipient`
    /// (`validate_deciphered_orchard_output`). A compact decryption recovers the
    /// diversifier `d` from the note plaintext and reconstructs `pk_d` as
    /// `ivk ⋅ g_d`, so "the internal IVK opens this note *and* agrees with
    /// `recipient`" holds exactly when `recipient == (d, ivk_internal ⋅ g_d)`
    /// — which is what this computes, without the note ciphertext.
    ///
    /// This is exact for change, because change is always addressed to the
    /// internal scope: a note the wallet sent to its own internal address is
    /// the only thing that satisfies it, and it satisfies it for every such
    /// note.
    pub fn is_internal_recipient(&self, recipient: &orchard::Address) -> bool {
        self.fvk
            .address(recipient.diversifier(), Scope::Internal)
            .to_raw_address_bytes()
            == recipient.to_raw_address_bytes()
    }

    /// Whether an action's output opens under this account's **external**
    /// outgoing viewing key — the device's second decryption trial, the one
    /// that puts an output on the review screen.
    ///
    /// This is the sender-side recovery of [Zcash Protocol Specification
    /// §4.20.3][decryptovk], run through `zcash_note_encryption` under the
    /// domain `note_version` selects: the Orchard domain for V2 notes and the
    /// Ironwood domain for V3 ones, exactly as the device pairs
    /// `NOTE_VERSION_ORCHARD` and `NOTE_VERSION_IRONWOOD` with the one FVK it
    /// derives for both pools. The recovered note and memo are discarded; only
    /// whether recovery succeeded is reported.
    ///
    /// [decryptovk]: https://zips.z.cash/protocol/protocol.pdf#decryptovk
    pub fn recovers_output(
        &self,
        note_version: NoteVersion,
        action: &orchard::pczt::Action,
    ) -> bool {
        let ovk = self.fvk.to_ovk(Scope::External);
        let out_ciphertext = &action.output().encrypted_note().out_ciphertext;
        match note_version {
            NoteVersion::V2 => try_output_recovery_with_ovk(
                &OrchardDomain::for_pczt_action(action),
                &ovk,
                action,
                action.cv_net(),
                out_ciphertext,
            )
            .is_some(),
            NoteVersion::V3 => try_output_recovery_with_ovk(
                &IronwoodDomain::for_pczt_action(action),
                &ovk,
                action,
                action.cv_net(),
                out_ciphertext,
            )
            .is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use orchard::keys::SpendingKey;

    fn keys(seed: u8) -> AccountViewingKeys {
        let sk = SpendingKey::from_bytes([seed; 32]).expect("a valid spending key");
        AccountViewingKeys::from_orchard_fvk(FullViewingKey::from(&sk))
    }

    /// Every diversifier index of the internal scope is recognised, not just
    /// index 0: the wallet picks the change address, and nothing binds it to
    /// the default one.
    #[test]
    fn internal_addresses_are_recognised_at_any_diversifier_index() {
        let k = keys(3);
        for j in [0u32, 1, 2, 17, 4096] {
            let address = k.orchard_fvk().address_at(j, Scope::Internal);
            assert!(
                k.is_internal_recipient(&address),
                "internal address at index {j} was not recognised"
            );
        }
    }

    /// The account's *own* external addresses are not change. This is the
    /// self-send case: the device displays it, and so must the host count.
    #[test]
    fn external_addresses_of_the_same_account_are_not_internal() {
        let k = keys(3);
        for j in [0u32, 1, 9] {
            let address = k.orchard_fvk().address_at(j, Scope::External);
            assert!(
                !k.is_internal_recipient(&address),
                "external address at index {j} was taken for change"
            );
        }
    }

    /// Another account's internal address is not this account's change.
    #[test]
    fn another_accounts_internal_address_is_not_internal_here() {
        let mine = keys(3);
        let theirs = keys(4);
        let address = theirs.orchard_fvk().address_at(0u32, Scope::Internal);
        assert!(!mine.is_internal_recipient(&address));
    }
}
