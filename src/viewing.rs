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
//! change — a wallet that splits change across several notes produces a bundle
//! a value-only count refuses even though the device would display a single
//! output — and under-counts a zero-valued output the account's OVK opens,
//! which the device displays. With the key the host reaches the device's own
//! answer. See [`crate::plan::Plan::displayed_shielded_outputs`].
//!
//! The same trials are why a Ledger account can only build shielded outputs
//! with `OvkPolicy::Sender`. The device has no other way to review a
//! non-change output than to open it under the external OVK, so a nonzero
//! output built with `OvkPolicy::Discard` (no recoverable `out_ciphertext`) or
//! under another key is refused mid-stream, "PCZT orchard output could not be
//! decrypted". With these keys the host runs the device's two trials first and
//! refuses such an output before the first APDU
//! ([`crate::plan::PlanError::UndecryptableOutput`]); without them it cannot
//! tell, and the device refuses it after the review has begun.
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
    bundle::BundleVersion,
    keys::{FullViewingKey, PreparedIncomingViewingKey, Scope},
    pczt::UnsupportedBundleVersion,
};
use subtle::ConstantTimeEq;
use zcash_transparent::keys::{AccountPubKey, NonHardenedChildIndex, TransparentKeyScope};

use crate::apdu::encode::COMPRESSED_PUBKEY_SIZE;

/// Size of a shielded note's memo field, in bytes (ZIP 302).
pub const MEMO_SIZE: usize = 512;

/// The account's transparent full viewing key: the BIP 44 account-level public
/// key (`m/44'/coin'/account'`) the account's UFVK carries as its P2PKH item.
///
/// # Why the host wants it
///
/// A transparent `bip32_derivation` is a path *and* a pubkey, and the device
/// uses only the path: it signs an input with the key it derives there
/// (`append_signature`, `src/handlers/sign_tx.rs` @ `22dc385`) and reads the
/// supplied pubkey for a log line and nothing else. The host's return path
/// verifies the device's signature against the supplied pubkey. A derivation
/// whose path derives a different key than its pubkey is therefore signed by
/// the device, reviewed and approved by the user, and refused by the `pczt`
/// Signer afterwards. Re-deriving each path's pubkey from this key beforehand
/// closes that gap, and it needs no secret: it is the derivation
/// [`crate::shape::ChangeInfo::derive`] already runs for the change output,
/// applied to every transparent input and output the plan carries. See
/// [`crate::session::SessionParams::transparent_account_key`].
///
/// This is a *viewing* key: it derives the account's transparent addresses and
/// authorizes nothing. `Debug` shows none of it, since it links every
/// transparent address the account has ever used.
#[derive(Clone)]
pub struct TransparentAccountKey {
    key: AccountPubKey,
}

impl core::fmt::Debug for TransparentAccountKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TransparentAccountKey([redacted])")
    }
}

impl PartialEq for TransparentAccountKey {
    fn eq(&self, other: &Self) -> bool {
        self.key.serialize() == other.key.serialize()
    }
}

impl Eq for TransparentAccountKey {}

impl TransparentAccountKey {
    /// Wraps the account-level key.
    pub fn from_account_pubkey(key: AccountPubKey) -> Self {
        Self { key }
    }

    /// The account-level key, for a caller that needs it directly — to build
    /// a [`crate::shape::ChangeInfo`], for instance.
    pub fn account_pubkey(&self) -> &AccountPubKey {
        &self.key
    }

    /// The compressed pubkey at `<account>/scope/index` under this key, or
    /// `None` when `scope` carries the hardening bit — a value BIP 44 does not
    /// use at that depth and the derivation does not accept.
    ///
    /// The derivation is `zcash_transparent`'s own
    /// (`AccountPubKey::derive_address_pubkey`), never a hand-rolled one.
    pub fn address_pubkey(
        &self,
        scope: u32,
        index: NonHardenedChildIndex,
    ) -> Option<[u8; COMPRESSED_PUBKEY_SIZE]> {
        let scope = TransparentKeyScope::custom(scope)?;
        self.key
            .derive_address_pubkey(scope, index)
            .ok()
            .map(|pubkey| pubkey.serialize())
    }
}

/// The account's shielded viewing keys, in the form the display count needs.
///
/// Built by the caller from the Orchard item of the account's UFVK
/// (`zcash_keys::keys::UnifiedFullViewingKey::decode(…).orchard()`); this crate
/// deliberately does not depend on `zcash_keys`, so the decode happens above
/// it.
///
/// This wrapper's `Debug` shows nothing of the key: it identifies and decrypts
/// every note the account has ever received. The `orchard::keys::FullViewingKey`
/// it wraps is not so careful — its own `Debug` prints `ak`, `nk` and `rivk` —
/// so a caller that holds the key it passed in must not log it.
#[derive(Clone)]
pub struct AccountViewingKeys {
    fvk: FullViewingKey,
    /// The internal incoming viewing key, precomputed for trial decryption.
    ///
    /// Derived from `fvk` at construction rather than per action: the
    /// precomputation is the expensive half of a trial, and a plan runs one
    /// trial per action of both shielded bundles.
    internal_ivk: PreparedIncomingViewingKey,
}

impl core::fmt::Debug for AccountViewingKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AccountViewingKeys([redacted])")
    }
}

/// Two wrappers are equal exactly when they wrap the same full viewing key;
/// the prepared incoming viewing key is derived from it.
impl PartialEq for AccountViewingKeys {
    fn eq(&self, other: &Self) -> bool {
        self.fvk == other.fvk
    }
}

impl Eq for AccountViewingKeys {}

impl AccountViewingKeys {
    /// Wraps the account's Orchard full viewing key.
    ///
    /// The same key covers the Ironwood pool; see the module docs.
    pub fn from_orchard_fvk(fvk: FullViewingKey) -> Self {
        let internal_ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::Internal));
        Self { fvk, internal_ivk }
    }

    /// The Orchard full viewing key, for a caller that needs it directly.
    pub(crate) fn orchard_fvk(&self) -> &FullViewingKey {
        &self.fvk
    }

    /// Whether the device would keep an action's output off the review as
    /// **change**: its first decryption trial, run here with the same key on
    /// the same bytes.
    ///
    /// `try_decipher_current_orchard_output` (`src/parser/pczt/orchard.rs` @
    /// `22dc385`, and its Ironwood twin) opens the *compact* note ciphertext
    /// — the prefix of the full one — under the account's internal IVK, in the
    /// pool's note encryption domain, and then requires the recovered note's
    /// value and recipient to equal the ones the host streamed
    /// (`validate_deciphered_orchard_output`). Both halves are reproduced here:
    /// the trial is `orchard`'s own
    /// ([`Action::decrypt_compact_output_with_ivk`]); the comparison against
    /// the action's declared `recipient` and `value` is this crate's, because a
    /// successful compact decryption binds the note to the action's `cmx` and
    /// says nothing about those two separately-transmitted fields. An output
    /// addressed to one of the account's internal addresses whose ciphertext
    /// does not open under the internal IVK is therefore *not* change: the
    /// device goes on to its OVK trial and displays it, or refuses it, and so
    /// does the host ([`crate::plan::Plan::displayed_shielded_outputs`]).
    ///
    /// Only the **internal** scope is change. An output to one of the
    /// account's own *external* addresses — a deliberate send to self, or a
    /// note-management split a wallet addresses externally — does not open
    /// under the internal IVK, so the device shows it as a payment like any
    /// other, with its address and no mark that it is the account's own: the
    /// review's only classification is by pool (`TransferType::classify`,
    /// `src/tx.rs` @ `22dc385`). The user has to recognise the address. The
    /// one exception is a transaction with no non-change output at all, whose
    /// change outputs the device reveals instead (`review_outputs`,
    /// `src/parser/pczt/common.rs`).
    ///
    /// `bundle_version` is the version of the bundle `action` belongs to
    /// ([`Bundle::bundle_version`]): its value pool and protocol version
    /// together select the note encryption domain. A version that is not this
    /// bundle's, but has a domain, selects one the output was not encrypted
    /// under, and the trial then simply does not match — `Ok(false)`, not an
    /// error. A version that has *no* domain is the third outcome and a
    /// different one: no trial ran, so nothing was learned about the output,
    /// and answering `Ok(false)` would classify it as not-change on no
    /// evidence. Thread it from the bundle being walked; never rebuild one
    /// from a pool.
    ///
    /// The comparisons are constant-time: one side of each derives from the
    /// account key.
    ///
    /// # Errors
    ///
    /// Returns [`UnsupportedBundleVersion`] when `orchard` defines no note
    /// encryption domain for `bundle_version`.
    ///
    /// [`Action::decrypt_compact_output_with_ivk`]: orchard::pczt::Action::decrypt_compact_output_with_ivk
    /// [`Bundle::bundle_version`]: orchard::pczt::Bundle::bundle_version
    pub fn opens_as_change(
        &self,
        action: &orchard::pczt::Action,
        bundle_version: BundleVersion,
    ) -> Result<bool, UnsupportedBundleVersion> {
        let Some((note, recipient)) =
            action.decrypt_compact_output_with_ivk(&self.internal_ivk, bundle_version)?
        else {
            return Ok(false);
        };
        let output = action.output();
        let (Some(declared_recipient), Some(declared_value)) = (output.recipient(), output.value())
        else {
            return Ok(false);
        };
        let same_value = note.value().inner().ct_eq(&declared_value.inner());
        let same_recipient = recipient.to_raw_address_bytes()[..]
            .ct_eq(&declared_recipient.to_raw_address_bytes()[..]);
        Ok(bool::from(same_value & same_recipient))
    }

    /// Opens an action's output under this account's **external** outgoing
    /// viewing key — the device's second decryption trial, the one that puts
    /// an output on the review screen — and returns its memo, or `Ok(None)`
    /// when the key does not open it.
    ///
    /// This is the sender-side recovery of [Zcash Protocol Specification
    /// §4.20.3][decryptovk] ([`Action::recover_output_with_ovk`]), run in the
    /// pool's note encryption domain against the one FVK the device derives
    /// for both pools. The recovered note is discarded; the memo is what the
    /// device's retention budget is counted over
    /// ([`crate::plan::MemoDisplay`]).
    ///
    /// `bundle_version` is the version of the bundle `action` belongs to
    /// ([`Bundle::bundle_version`]): its value pool and protocol version
    /// together select the note encryption domain — the Orchard domain for an
    /// Orchard bundle, the Ironwood domain for an Ironwood one. A version that
    /// is not this bundle's, but has a domain, selects one the output was not
    /// encrypted under, and the recovery then simply does not match —
    /// `Ok(None)`, not an error. A version that has *no* domain is the third
    /// outcome and a different one: no recovery ran, so nothing was learned
    /// about the output, and answering `Ok(None)` would report "this account
    /// did not create it" on no evidence. Thread it from the bundle being
    /// walked; never rebuild one from a pool.
    ///
    /// # Errors
    ///
    /// Returns [`UnsupportedBundleVersion`] when `orchard` defines no note
    /// encryption domain for `bundle_version`.
    ///
    /// [decryptovk]: https://zips.z.cash/protocol/protocol.pdf#decryptovk
    /// [`Action::recover_output_with_ovk`]: orchard::pczt::Action::recover_output_with_ovk
    /// [`Bundle::bundle_version`]: orchard::pczt::Bundle::bundle_version
    pub fn recover_output(
        &self,
        action: &orchard::pczt::Action,
        bundle_version: BundleVersion,
    ) -> Result<Option<[u8; MEMO_SIZE]>, UnsupportedBundleVersion> {
        Ok(action
            .recover_output_with_ovk(&self.fvk.to_ovk(Scope::External), bundle_version)?
            .map(|(_note, _recipient, memo)| memo))
    }
}

#[cfg(test)]
mod tests;
