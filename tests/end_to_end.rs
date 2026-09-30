//! End-to-end tests for the session layer.
//!
//! Fixtures are built the way `librustzcash`'s own `pczt/tests/end_to_end.rs`
//! builds them — `Builder::build_for_pczt` → `Creator::build_from_parts` →
//! `IoFinalizer` — and then put through the same redaction
//! `zcash_client_backend::data_api::wallet::redact_pczt_for_signer` applies for
//! `SignerView::Full` (clear each action's spend witness and dummy spending
//! key), reproduced here with the `pczt` Redactor role so the tests do not need
//! `zcash_client_backend`.
//!
//! Nothing is proven: the device stream carries no proofs, and neither the
//! Signer nor the Updater roles need them.
//!
//! # What the device model proves, and what it does not
//!
//! `Grammar` replicates the firmware's PCZT command grammar from
//! `src/parser/pczt.rs` and `src/parser/pczt/*.rs` @ `22dc385`, written from
//! the firmware rather than from this crate's encoder, and every command a
//! `FakeDevice` answers goes through it. What it models is the **framing and
//! layout**: the instruction, P1 and P2 rules, the packet boundaries and the
//! order of the record groups, field widths and endianness, `CompactSize`
//! canonicity, the 255-byte data bound, `MAX_PCZT_SCRIPT_SIZE`,
//! `MAX_ZCASH_BIP32_PATH`, the two `(tx_version, version_group_id)` pairs
//! with their encoding versions and the coin type, `SIGHASH_ALL`, the
//! derivation-count rules, the ciphertext lengths, the Ironwood
//! note-version byte and the Ironwood bundle's V6-only rule, the state in
//! which `P2_PCZT_FINISHED` is accepted, and the signing gate — after the
//! FINISHED packet, within the declared count, never a zero-valued spend.
//! `the_device_reads_the_pczts_own_values` then compares every field the
//! model read against the PCZT it was read from.
//!
//! What it does not model is the firmware's **validation**. There is no bound
//! on the declared record counts (`MAX_PCZT_TRANSPARENT_INPUTS_NUMBER` and
//! its siblings), no script-shape or zero-valued-output refusal, no
//! `check_bip44_compliance`, no re-derivation of a change output's pubkey, no
//! `change_account` binding and no `is_change_found`, and no `cv_net`, `rk`,
//! nullifier, `cmx` or `value_sum` check. The review is a point in the stream
//! rather than a decision: `outputs_reviewed` is set when the last bundle
//! ends, with none of `review_outputs`'s own refusals — the sign of the fee,
//! the display and memo budgets, the user's answer. And a repeated signing
//! index is accepted, where `mark_orchard_action_signed` answers
//! `IncorrectData` and resets the parser.
//!
//! So what these tests establish is that the firmware's parser consumes the
//! stream without a framing error, that what it reads is the PCZT's own
//! values, and that signing is ordered and gated. What the device refuses on
//! content is covered instead by the tests over `StreamPlan` and
//! `pczt_ledger::limits`, whose checks are written from the same firmware.

use std::collections::HashMap;

use orchard::{
    bundle::BundleVersion,
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{Note, NoteVersion, RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use pczt::{
    roles::{
        creator::Creator, io_finalizer::IoFinalizer, redactor::Redactor, signer::Signer,
        updater::Updater, verifier::Verifier,
    },
    Pczt,
};
use rand_core::OsRng;
use zcash_address::unified::Encoding;
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding, PcztResult},
    fees::zip317,
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, NetworkType},
    local_consensus::LocalNetwork,
    memo::MemoBytes,
    value::Zatoshis,
};
use zcash_transparent::{
    address::TransparentAddress,
    bundle::{OutPoint, TxOut},
    keys::{AccountPrivKey, IncomingViewingKey, NonHardenedChildIndex},
};
#[cfg(feature = "std")]
use zeroize::Zeroizing;

use pczt_ledger::{
    apdu::{
        decode::{
            split_status_word, DecodeError, VkKind, VkReassembler, MAX_VK_CONTINUATIONS,
            MAX_VK_RESPONSE_LEN,
        },
        encode::{
            BundleTrailerRecord, StreamPlan, TransparentInputRecord, TransparentOutputRecord,
            TxFormat, SIGHASH_ALL,
        },
        Ins, StatusWord,
    },
    apply::{apply_device_signatures, normalize_ledger_der, ApplyError, DeviceSignatures},
    limits::{DeviceBounds, DeviceCaps, LimitViolation, Section},
    pairing::{self, VkStep},
    plan::{build_plan, build_plan_with_keys, validate_plan, PlanError},
    session::{
        validate_for_ledger, validate_for_ledger_with_keys, Deadline, LedgerSignSession,
        LedgerViolation, Network, PumpStep, SessionError, SessionParams, SessionStatus, Stage,
        UserAction,
    },
    shape::{
        derivation_account, hash160, shape_for_device, ChangeInfo, ShapeError, ShapeParams,
        HARDENED, TRANSPARENT_INTERNAL_SCOPE,
    },
    viewing::{AccountViewingKeys, TransparentAccountKey},
};
#[cfg(feature = "std")]
use pczt_ledger::{
    ceremony::{self, CeremonyError, QueryError},
    transport::{Transport, TransportError},
};

// ---------------------------------------------------------------------------
// Networks
// ---------------------------------------------------------------------------

/// A regtest network stopping at NU6.2, so the builder emits V5 transactions.
fn v5_network() -> LocalNetwork {
    LocalNetwork {
        overwinter: Some(BlockHeight::from_u32(1)),
        sapling: Some(BlockHeight::from_u32(2)),
        blossom: Some(BlockHeight::from_u32(3)),
        heartwood: Some(BlockHeight::from_u32(4)),
        canopy: Some(BlockHeight::from_u32(5)),
        nu5: Some(BlockHeight::from_u32(6)),
        nu6: Some(BlockHeight::from_u32(7)),
        nu6_1: Some(BlockHeight::from_u32(8)),
        nu6_2: Some(BlockHeight::from_u32(9)),
        nu6_3: None,
    }
}

/// A regtest network with NU6.3 active, so the builder emits V6 transactions
/// and the Ironwood pool exists.
fn v6_network() -> LocalNetwork {
    LocalNetwork {
        nu6_3: Some(BlockHeight::from_u32(10)),
        ..v5_network()
    }
}

/// The coin type both regtest networks report, and therefore the one the
/// session must be parameterised with.
const FIXTURE_COIN_TYPE: u32 = Network::Test.coin_type();

/// The ZIP 316 revision the fixtures encode the device's unified containers
/// in. The app builds them with `Ufvk::try_from_items` (`handler_get_vk`,
/// `src/handlers/get_vk.rs` @ `22dc385`) and `UnifiedAddress::try_from_items`
/// (`handler_get_shielded_addr`, `src/handlers/get_shielded_addr.rs`) against
/// `zcash_address` 0.13.0, whose containers are Revision 0: the `u` and
/// `uview` HRPs, and no metadata items. Taken from the crate so the fixtures
/// and the check cannot drift apart.
const DEVICE_UNIFIED_REVISION: zcash_address::unified::Revision = pairing::DEVICE_UNIFIED_REVISION;

/// A revision the app does not encode, used to check that one is refused.
const OTHER_UNIFIED_REVISION: zcash_address::unified::Revision =
    zcash_address::unified::Revision::R2;

/// The two exchanges every session opens with before the PCZT stream: the
/// firmware version probe and the device identity probe.
const PROBE_EXCHANGES: usize = 2;

/// The key the scripted device answers the identity probe with. Any curve
/// point does; it is fixed so the paired identity can be computed up front.
fn fake_device_key() -> secp256k1::PublicKey {
    let sk = secp256k1::SecretKey::from_slice(&[0x5Du8; 32]).expect("a valid secret key");
    secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::signing_only(), &sk)
}

/// The identity the fixtures are paired with: the scripted device's.
fn fake_device_identity() -> pairing::DeviceIdentity {
    pairing::DeviceIdentity::from_compressed_pubkey(&fake_device_key().serialize())
}

const TARGET_HEIGHT: u32 = 10_000_000;
const ACCOUNT: u32 = 0;

/// [`ACCOUNT`] as the session and shaping parameters take it.
fn account() -> zip32::AccountId {
    zip32::AccountId::try_from(ACCOUNT).expect("an unhardened account")
}
const SEED: [u8; 32] = [1; 32];
const SEED_FINGERPRINT: [u8; 32] = [0x7c; 32];

/// The DER `SEQUENCE` tag as the device emits it when the signature's y
/// coordinate is odd: it ORs the parity bit into `0x30`
/// (`src/handlers/sign_tx.rs` @ `22dc385`), and
/// [`normalize_ledger_der`] undoes it.
const LEDGER_DER_PARITY_TAG: u8 = 0x31;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A built PCZT plus the key material a test needs to play the device.
struct Fixture {
    /// The redacted PCZT, serialized — what a wallet hands the session.
    bytes: Vec<u8>,
    /// The Orchard spend authorizing key, for producing canned signatures.
    orchard_ask: SpendAuthorizingKey,
    /// The transparent signing key, for producing canned DER signatures.
    transparent_sk: Option<secp256k1::SecretKey>,
    /// The compressed pubkey controlling the transparent change output.
    change_pubkey: [u8; 33],
    /// Index of that output in the transparent bundle.
    change_output_index: Option<usize>,
}

impl Fixture {
    fn pczt(&self) -> Pczt {
        Pczt::parse(&self.bytes).expect("fixture PCZT parses")
    }

    fn params(&self, change: Option<ChangeInfo>) -> SessionParams {
        SessionParams::new(Network::Test, fake_device_identity(), account())
            .with_seed_fingerprint(Some(SEED_FINGERPRINT))
            .with_change(change)
            .with_transparent_account_key(Some(transparent_account_key()))
    }

    /// The same, with the Orchard viewing key the fixture's outputs were
    /// addressed under.
    fn params_with_keys(
        &self,
        change: Option<ChangeInfo>,
        keys: AccountViewingKeys,
    ) -> SessionParams {
        self.params(change).with_viewing_keys(Some(keys))
    }

    fn change_info(&self) -> Option<ChangeInfo> {
        self.change_output_index
            .map(|output_index| change_info_at(fixture_change_index(), output_index))
    }
}

/// The internal (change) address index the fixtures pay change to: the
/// account's default internal address.
fn fixture_change_index() -> u32 {
    account_pubkey()
        .derive_internal_ivk()
        .expect("internal ivk")
        .default_address()
        .1
        .index()
}

/// A change hint for the account's internal address at `index`, derived
/// against the P2PKH script that address pays. `ChangeInfo::derive` is the
/// only constructor, so a hint that does not fit the PCZT under test is built
/// honestly for some other address and handed to a PCZT that pays a different
/// one.
/// The seed fingerprint on every Orchard action's `zip32_derivation`, read off
/// the PCZT itself: the wire records carry zeros in its place.
fn orchard_fingerprints(pczt: Pczt) -> Vec<Option<[u8; 32]>> {
    let mut out = Vec::new();
    Updater::new(pczt)
        .update_orchard_with(|updater| {
            out = updater
                .bundle()
                .actions()
                .iter()
                .map(|action| {
                    action
                        .spend()
                        .zip32_derivation()
                        .as_ref()
                        .map(|d| *d.seed_fingerprint())
                })
                .collect();
            Ok(())
        })
        .expect("updater");
    out
}

/// The seed fingerprint on a transparent output's `bip32_derivation`, read off
/// the PCZT itself.
fn transparent_output_fingerprint(pczt: Pczt, index: usize) -> Option<[u8; 32]> {
    let mut out = None;
    Updater::new(pczt)
        .update_transparent_with(|updater| {
            out = updater.bundle().outputs()[index]
                .bip32_derivation()
                .values()
                .next()
                .map(|d| *d.seed_fingerprint());
            Ok(())
        })
        .expect("updater");
    out
}

fn change_info_at(index: u32, output_index: usize) -> ChangeInfo {
    let index = NonHardenedChildIndex::from_index(index).expect("a non-hardened index");
    let pubkey = account_pubkey()
        .derive_address_pubkey(
            zcash_transparent::keys::TransparentKeyScope::INTERNAL,
            index,
        )
        .expect("the address pubkey derives")
        .serialize();
    let mut script = vec![0x76, 0xa9, 0x14];
    script.extend_from_slice(&hash160(&pubkey));
    script.extend_from_slice(&[0x88, 0xac]);
    ChangeInfo::derive(
        &account_pubkey(),
        TRANSPARENT_INTERNAL_SCOPE,
        index,
        output_index,
        &script,
    )
    .expect("a hint derived against its own script")
}

fn orchard_keys() -> (SpendingKey, FullViewingKey) {
    let sk = SpendingKey::from_bytes([0; 32]).expect("valid spending key");
    let fvk = FullViewingKey::from(&sk);
    (sk, fvk)
}

/// The fixture account's BIP 44 account-level public key, from which every
/// transparent pubkey the fixtures stamp derives. Both fixture networks share
/// the testnet coin type, so one key serves them all.
fn account_pubkey() -> zcash_transparent::keys::AccountPubKey {
    AccountPrivKey::from_seed(&v5_network(), &SEED, zip32::AccountId::ZERO)
        .expect("account key derives")
        .to_account_pubkey()
}

/// [`account_pubkey`] as the session takes it.
fn transparent_account_key() -> TransparentAccountKey {
    TransparentAccountKey::from_account_pubkey(account_pubkey())
}

/// Transparent key material for the fixture account: the external spending key
/// and address, plus the internal (change) pubkey and address.
struct TransparentKeys {
    sk: secp256k1::SecretKey,
    pubkey: secp256k1::PublicKey,
    address: TransparentAddress,
    change_pubkey: secp256k1::PublicKey,
    change_address: TransparentAddress,
}

fn transparent_keys(params: &LocalNetwork) -> TransparentKeys {
    let account_sk = AccountPrivKey::from_seed(params, &SEED, zip32::AccountId::ZERO)
        .expect("account key derives");
    let secp = secp256k1::Secp256k1::signing_only();

    let (_, external_index) = account_sk
        .to_account_pubkey()
        .derive_external_ivk()
        .expect("external ivk")
        .default_address();
    let sk = account_sk
        .derive_external_secret_key(external_index)
        .expect("external sk");
    let pubkey = sk.public_key(&secp);

    let (_, internal_index) = account_sk
        .to_account_pubkey()
        .derive_internal_ivk()
        .expect("internal ivk")
        .default_address();
    let change_sk = account_sk
        .derive_internal_secret_key(internal_index)
        .expect("internal sk");
    let change_pubkey = change_sk.public_key(&secp);

    TransparentKeys {
        sk,
        address: TransparentAddress::from_pubkey(&pubkey),
        pubkey,
        change_address: TransparentAddress::from_pubkey(&change_pubkey),
        change_pubkey,
    }
}

/// The redaction `redact_pczt_for_signer(SignerView::Full)` performs on the
/// shielded pools: clear each action's spend witness and dummy spending key.
///
/// The other half of that view — dropping wallet proprietary metadata — is
/// irrelevant here, because nothing in this crate reads it.
fn redact_signer_view_full(pczt: Pczt) -> Pczt {
    fn redact(mut redactor: pczt::roles::redactor::orchard::OrchardRedactor<'_>) {
        redactor.redact_actions(|mut action| {
            action.clear_spend_witness();
            action.clear_spend_dummy_sk();
        });
    }

    Redactor::new(pczt)
        .redact_orchard_with(redact)
        .redact_ironwood_with(redact)
        .finish()
}

/// Stamps the BIP 44 derivation `zcash_client_backend` puts on every transparent
/// input (`m/44'/coin'/account'/0/index`, keyed by the controlling pubkey).
///
/// The builder leaves `bip32_derivation` empty; the device reads the signing-key
/// locator from it alone, so a PCZT without it is unsignable.
fn stamp_transparent_input_derivations(pczt: Pczt, pubkey: [u8; 33]) -> Pczt {
    let path = vec![
        44 | HARDENED,
        FIXTURE_COIN_TYPE | HARDENED,
        ACCOUNT | HARDENED,
        0,
        0,
    ];

    Updater::new(pczt)
        .update_transparent_with(|mut updater| {
            let count = updater.bundle().inputs().len();
            for index in 0..count {
                let derivation =
                    zcash_transparent::pczt::Bip32Derivation::parse(SEED_FINGERPRINT, path.clone())
                        .expect("valid derivation");
                updater.update_input_with(index, |mut input| {
                    input.set_bip32_derivation(pubkey, derivation);
                    Ok(())
                })?;
            }
            Ok(())
        })
        .expect("transparent updater")
        .finish()
}

/// Wraps builder parts into a redacted, input-stamped PCZT.
fn finish_fixture(pczt_parts: PcztResult<LocalNetwork>, pubkey: Option<[u8; 33]>) -> Vec<u8> {
    let pczt = Creator::build_from_parts(pczt_parts.pczt_parts).expect("creator");
    let pczt = IoFinalizer::new(pczt).finalize_io().expect("io finalizer");
    let pczt = match pubkey {
        Some(pubkey) => stamp_transparent_input_derivations(pczt, pubkey),
        None => pczt,
    };
    redact_signer_view_full(pczt)
        .serialize()
        .expect("fixture serializes")
}

/// V5, transparent input → two Orchard outputs.
///
/// The Orchard bundle is all padding: two actions, both with `spend_value == 0`
/// and a `spend_auth_sig` the IO Finalizer produced. Neither carries a
/// `zip32_derivation`, so the shaping pass has to stamp both.
fn fixture_v5_transparent_to_orchard() -> Fixture {
    let t = transparent_keys(&v5_network());
    fixture_v5_transparent_to_orchard_stamped(t.pubkey.serialize())
}

/// [`fixture_v5_transparent_to_orchard`] with the input's `bip32_derivation`
/// keyed by `stamp_pubkey` instead of the key that really pays the input.
///
/// With the honest key this is the same fixture; with any other it is the
/// PCZT the reviewer of a signing path has to worry about — one whose signing
/// key locator does not control the coin.
fn fixture_v5_transparent_to_orchard_stamped(stamp_pubkey: [u8; 33]) -> Fixture {
    let params = v5_network();
    let t = transparent_keys(&params);
    let (sk, fvk) = orchard_keys();

    let mut builder = Builder::new(
        params,
        TARGET_HEIGHT.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_transparent_p2pkh_input(
            t.pubkey,
            OutPoint::new([1u8; 32], 1),
            TxOut::new(
                Zatoshis::const_from_u64(1_000_000),
                t.address.script().into(),
            ),
        )
        .expect("transparent input");
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(fvk.to_ovk(Scope::External)),
            fvk.address_at(0u32, Scope::External),
            Zatoshis::const_from_u64(100_000),
            MemoBytes::empty(),
        )
        .expect("orchard output");
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(fvk.to_ovk(Scope::Internal)),
            fvk.address_at(0u32, Scope::Internal),
            Zatoshis::const_from_u64(885_000),
            MemoBytes::empty(),
        )
        .expect("orchard change");

    let parts = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt");

    Fixture {
        bytes: finish_fixture(parts, Some(stamp_pubkey)),
        orchard_ask: SpendAuthorizingKey::from(&sk),
        transparent_sk: Some(t.sk),
        change_pubkey: t.change_pubkey.serialize(),
        change_output_index: None,
    }
}

/// V5, transparent in → transparent out, and nothing shielded at all: the one
/// shape that needs no proof, so a ceremony over it can be finalized and
/// extracted in a test. The output is the account's change address, so the
/// fixture also exercises change marking. The Orchard command is still sent,
/// with count `0`, since that is where a V5 review runs.
fn fixture_v5_transparent_only() -> Fixture {
    fixture_v5_transparent_only_with(Some(transparent_keys(&v5_network()).pubkey.serialize()))
}

/// [`fixture_v5_transparent_only`], with the input's `bip32_derivation` left
/// unstamped when `stamp_pubkey` is `None` — the shape a PCZT has before the
/// wallet's own Updater pass, and the one whose transparent maps are empty.
fn fixture_v5_transparent_only_with(stamp_pubkey: Option<[u8; 33]>) -> Fixture {
    let params = v5_network();
    let t = transparent_keys(&params);

    let mut builder = Builder::new(
        params,
        TARGET_HEIGHT.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: None,
            orchard_padding: BundlePadding {
                bundle_required: false,
                pad_to_minimum: None,
            },
            ironwood_padding: BundlePadding {
                bundle_required: false,
                pad_to_minimum: None,
            },
        },
    );
    builder
        .add_transparent_p2pkh_input(
            t.pubkey,
            OutPoint::new([1u8; 32], 1),
            TxOut::new(
                Zatoshis::const_from_u64(1_000_000),
                t.address.script().into(),
            ),
        )
        .expect("transparent input");
    // 1_000_000 less the ZIP 317 fee for one input and one output.
    builder
        .add_transparent_output(&t.change_address, Zatoshis::const_from_u64(990_000))
        .expect("transparent output");

    let parts = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt");

    Fixture {
        bytes: finish_fixture(parts, stamp_pubkey),
        orchard_ask: SpendAuthorizingKey::from(&orchard_keys().0),
        transparent_sk: Some(t.sk),
        change_pubkey: t.change_pubkey.serialize(),
        change_output_index: Some(0),
    }
}

/// V5, *two* transparent inputs → one transparent output, nothing shielded:
/// the fixture with more than one transparent signature to collect and
/// apply, so the per-input `P2` and the per-input signature slots are
/// exercised past index 0. Both inputs are the account's external address.
fn fixture_v5_two_transparent_inputs() -> Fixture {
    let params = v5_network();
    let t = transparent_keys(&params);

    let mut builder = Builder::new(
        params,
        TARGET_HEIGHT.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: None,
            orchard_padding: BundlePadding {
                bundle_required: false,
                pad_to_minimum: None,
            },
            ironwood_padding: BundlePadding {
                bundle_required: false,
                pad_to_minimum: None,
            },
        },
    );
    for index in 0..2u32 {
        builder
            .add_transparent_p2pkh_input(
                t.pubkey,
                OutPoint::new([1u8; 32], index),
                TxOut::new(Zatoshis::const_from_u64(500_000), t.address.script().into()),
            )
            .expect("transparent input");
    }
    // 1_000_000 in, less the ZIP 317 fee for two inputs and one output.
    builder
        .add_transparent_output(&t.change_address, Zatoshis::const_from_u64(990_000))
        .expect("transparent output");

    let parts = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt");

    Fixture {
        bytes: finish_fixture(parts, Some(t.pubkey.serialize())),
        orchard_ask: SpendAuthorizingKey::from(&orchard_keys().0),
        transparent_sk: Some(t.sk),
        change_pubkey: t.change_pubkey.serialize(),
        change_output_index: Some(0),
    }
}

/// V5, a real Orchard spend → one Orchard output plus a transparent change
/// output the wallet controls.
///
/// This is the fixture with a real device-signable spend, and the one that
/// exercises change-output stamping.
fn fixture_v5_orchard_spend() -> Fixture {
    let t = transparent_keys(&v5_network());
    let (sk, _) = orchard_keys();
    Fixture {
        bytes: finish_fixture(orchard_spend_parts(), None),
        orchard_ask: SpendAuthorizingKey::from(&sk),
        transparent_sk: None,
        change_pubkey: t.change_pubkey.serialize(),
        change_output_index: Some(0),
    }
}

/// The builder output behind [`fixture_v5_orchard_spend`], before the Creator,
/// the IO Finalizer and the redaction.
fn orchard_spend_parts() -> PcztResult<LocalNetwork> {
    let params = v5_network();
    let t = transparent_keys(&params);
    let (_, fvk) = orchard_keys();

    let (note, merkle_path, anchor) = synthetic_note(&fvk, 1_000_000, NoteVersion::V2);

    let mut builder = Builder::new(
        params,
        TARGET_HEIGHT.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(anchor),
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_orchard_spend::<zip317::FeeRule>(fvk.clone(), note, merkle_path)
        .expect("orchard spend");
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(fvk.to_ovk(Scope::External)),
            fvk.address_at(0u32, Scope::External),
            Zatoshis::const_from_u64(100_000),
            MemoBytes::empty(),
        )
        .expect("orchard output");
    builder
        .add_transparent_output(&t.change_address, Zatoshis::const_from_u64(885_000))
        .expect("transparent change output");

    builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt")
}

/// V5, a real Orchard spend → one transparent output and nothing shielded:
/// the Orchard bundle is the real spend plus padding, every output a
/// zero-valued dummy. What is left to check with a viewing key is the spend.
fn fixture_v5_orchard_spend_to_transparent() -> Fixture {
    let params = v5_network();
    let t = transparent_keys(&params);
    let (sk, fvk) = orchard_keys();

    let (note, merkle_path, anchor) = synthetic_note(&fvk, 1_000_000, NoteVersion::V2);

    let mut builder = Builder::new(
        params,
        TARGET_HEIGHT.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(anchor),
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_orchard_spend::<zip317::FeeRule>(fvk.clone(), note, merkle_path)
        .expect("orchard spend");
    // Two Orchard actions and one transparent output are three logical
    // actions: a 15 000 zatoshi ZIP 317 fee, exactly.
    builder
        .add_transparent_output(&t.address, Zatoshis::const_from_u64(985_000))
        .expect("transparent output");

    let parts = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt");

    Fixture {
        bytes: finish_fixture(parts, None),
        orchard_ask: SpendAuthorizingKey::from(&sk),
        transparent_sk: None,
        change_pubkey: t.change_pubkey.serialize(),
        change_output_index: None,
    }
}

/// V5, a real Orchard spend → one Orchard output plus **two** transparent
/// outputs to the account's internal chain, the second of which already
/// carries a compliant, same-account `bip32_derivation` when the PCZT arrives.
///
/// Shaping leaves a pre-existing derivation alone and stamps the one the
/// caller names, so a session asked to mark output 0 as change ends up with
/// two change outputs — the shape the device refuses mid-stream with
/// "Multiple change outputs detected", and one the host can see without any
/// viewing key.
fn fixture_v5_orchard_spend_two_transparent_change() -> Fixture {
    let params = v5_network();
    let t = transparent_keys(&params);
    let (sk, fvk) = orchard_keys();

    // A second internal-chain key, at address index 1.
    let account_sk = AccountPrivKey::from_seed(&params, &SEED, zip32::AccountId::ZERO)
        .expect("account key derives");
    let second_index = NonHardenedChildIndex::from_index(1).expect("1 is unhardened");
    let second_pubkey = account_sk
        .derive_internal_secret_key(second_index)
        .expect("internal sk")
        .public_key(&secp256k1::Secp256k1::signing_only());
    let second_address = TransparentAddress::from_pubkey(&second_pubkey);

    let (note, merkle_path, anchor) = synthetic_note(&fvk, 1_000_000, NoteVersion::V2);

    let mut builder = Builder::new(
        params,
        TARGET_HEIGHT.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(anchor),
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_orchard_spend::<zip317::FeeRule>(fvk.clone(), note, merkle_path)
        .expect("orchard spend");
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(fvk.to_ovk(Scope::External)),
            fvk.address_at(0u32, Scope::External),
            Zatoshis::const_from_u64(100_000),
            MemoBytes::empty(),
        )
        .expect("orchard output");
    // 1_000_000 in, 100_000 out, less the 20_000 ZIP 317 fee for two
    // transparent outputs plus two (padded) Orchard actions.
    builder
        .add_transparent_output(&t.change_address, Zatoshis::const_from_u64(500_000))
        .expect("transparent change output");
    builder
        .add_transparent_output(&second_address, Zatoshis::const_from_u64(380_000))
        .expect("second transparent output");

    let parts = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt");
    let bytes = finish_fixture(parts, None);

    // Pre-stamp output 1 the way a wallet that marks its own change would.
    let path = vec![
        44 | HARDENED,
        FIXTURE_COIN_TYPE | HARDENED,
        ACCOUNT | HARDENED,
        1,
        second_index.index(),
    ];
    let derivation = zcash_transparent::pczt::Bip32Derivation::parse(SEED_FINGERPRINT, path)
        .expect("valid derivation");
    let stamped = Updater::new(Pczt::parse(&bytes).expect("parses"))
        .update_transparent_with(|mut updater| {
            updater.update_output_with(1, |mut output| {
                output.set_bip32_derivation(second_pubkey.serialize(), derivation);
                Ok(())
            })
        })
        .expect("transparent updater")
        .finish();

    Fixture {
        bytes: stamped.serialize().expect("serializes"),
        orchard_ask: SpendAuthorizingKey::from(&sk),
        transparent_sk: None,
        change_pubkey: t.change_pubkey.serialize(),
        change_output_index: Some(0),
    }
}

/// V5, a real Orchard spend → one Orchard output plus *two* transparent
/// outputs to the account's change address, neither marked.
///
/// The device classifies change per output, so whichever of the two the
/// caller names, the other is shown as a payment to a third party — at the
/// wallet's own change address.
fn fixture_v5_orchard_spend_change_paid_twice() -> Fixture {
    let params = v5_network();
    let t = transparent_keys(&params);
    let (sk, fvk) = orchard_keys();

    let (note, merkle_path, anchor) = synthetic_note(&fvk, 1_000_000, NoteVersion::V2);

    let mut builder = Builder::new(
        params,
        TARGET_HEIGHT.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(anchor),
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_orchard_spend::<zip317::FeeRule>(fvk.clone(), note, merkle_path)
        .expect("orchard spend");
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(fvk.to_ovk(Scope::External)),
            fvk.address_at(0u32, Scope::External),
            Zatoshis::const_from_u64(100_000),
            MemoBytes::empty(),
        )
        .expect("orchard output");
    // 1_000_000 in, 100_000 out, less the 20_000 ZIP 317 fee for two
    // transparent outputs plus two (padded) Orchard actions.
    builder
        .add_transparent_output(&t.change_address, Zatoshis::const_from_u64(500_000))
        .expect("first output to the change address");
    builder
        .add_transparent_output(&t.change_address, Zatoshis::const_from_u64(380_000))
        .expect("second output to the change address");

    let parts = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt");

    Fixture {
        bytes: finish_fixture(parts, None),
        orchard_ask: SpendAuthorizingKey::from(&sk),
        transparent_sk: None,
        change_pubkey: t.change_pubkey.serialize(),
        change_output_index: Some(0),
    }
}

/// V6, transparent input → Ironwood output.
///
/// The Orchard bundle is empty (its command still goes out with count `0`), and
/// the Ironwood bundle carries the padding actions plus the trailer that
/// receives the `P2_PCZT_FINISHED` marker.
fn fixture_v6_ironwood() -> Fixture {
    let params = v6_network();
    let t = transparent_keys(&params);
    let (sk, fvk) = orchard_keys();

    let mut builder = Builder::new(
        params,
        TARGET_HEIGHT.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(orchard::Anchor::empty_tree()),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_transparent_p2pkh_input(
            t.pubkey,
            OutPoint::new([1u8; 32], 1),
            TxOut::new(
                Zatoshis::const_from_u64(1_000_000),
                t.address.script().into(),
            ),
        )
        .expect("transparent input");
    builder
        .add_ironwood_output::<zip317::FeeRule>(
            Some(fvk.to_ovk(Scope::External)),
            fvk.address_at(0u32, Scope::External),
            Zatoshis::const_from_u64(985_000),
            MemoBytes::empty(),
        )
        .expect("ironwood output");

    let parts = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt");

    Fixture {
        bytes: finish_fixture(parts, Some(t.pubkey.serialize())),
        orchard_ask: SpendAuthorizingKey::from(&sk),
        transparent_sk: Some(t.sk),
        change_pubkey: t.change_pubkey.serialize(),
        change_output_index: None,
    }
}

/// V6, transparent input → one external Ironwood output plus one
/// **internal-scope** one.
///
/// The point of it is the key: the change output is addressed to
/// `Scope::Internal` of the same *Orchard* full viewing key, which is the only
/// key the device has for the Ironwood pool too.
fn fixture_v6_ironwood_with_change() -> Fixture {
    let params = v6_network();
    let t = transparent_keys(&params);
    let (sk, fvk) = orchard_keys();

    let mut builder = Builder::new(
        params,
        TARGET_HEIGHT.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(orchard::Anchor::empty_tree()),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_transparent_p2pkh_input(
            t.pubkey,
            OutPoint::new([1u8; 32], 1),
            TxOut::new(
                Zatoshis::const_from_u64(1_000_000),
                t.address.script().into(),
            ),
        )
        .expect("transparent input");
    builder
        .add_ironwood_output::<zip317::FeeRule>(
            Some(fvk.to_ovk(Scope::External)),
            fvk.address_at(0u32, Scope::External),
            Zatoshis::const_from_u64(100_000),
            MemoBytes::empty(),
        )
        .expect("ironwood output");
    builder
        .add_ironwood_output::<zip317::FeeRule>(
            Some(fvk.to_ovk(Scope::Internal)),
            fvk.address_at(0u32, Scope::Internal),
            Zatoshis::const_from_u64(885_000),
            MemoBytes::empty(),
        )
        .expect("ironwood change");

    let parts = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt");

    Fixture {
        bytes: finish_fixture(parts, Some(t.pubkey.serialize())),
        orchard_ask: SpendAuthorizingKey::from(&sk),
        transparent_sk: Some(t.sk),
        change_pubkey: t.change_pubkey.serialize(),
        change_output_index: None,
    }
}

/// V6, a real Ironwood spend → one external Ironwood output plus one
/// internal-scope one.
///
/// No transparent input or output at all, which is what makes this fixture
/// representable in JSON: the transparent bundle's `bip32_derivation` and
/// preimage maps are keyed by raw bytes, which `serde_json` refuses, and
/// [`retag_as_v5`] needs the whole PCZT to round-trip through serde.
fn fixture_v6_ironwood_spend() -> Fixture {
    v6_ironwood_spend_fixture(None)
}

/// [`fixture_v6_ironwood_spend`] with an Orchard bundle of two padding
/// actions besides: a V6 Orchard bundle, which the `pczt` parser types as
/// `orchard_v3` and which is therefore under the cross-address restriction.
fn fixture_v6_ironwood_spend_with_orchard_padding() -> Fixture {
    v6_ironwood_spend_fixture(Some(2))
}

fn v6_ironwood_spend_fixture(orchard_pad_to: Option<u8>) -> Fixture {
    let params = v6_network();
    let t = transparent_keys(&params);
    let (sk, fvk) = orchard_keys();

    let (note, merkle_path, anchor) = synthetic_note(&fvk, 1_000_000, NoteVersion::V3);

    let mut builder = Builder::new(
        params,
        TARGET_HEIGHT.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: orchard_pad_to.map(|_| orchard::Anchor::empty_tree()),
            ironwood_anchor: Some(anchor),
            orchard_padding: match orchard_pad_to {
                Some(pad_to_minimum) => BundlePadding {
                    bundle_required: true,
                    pad_to_minimum: Some(pad_to_minimum),
                },
                None => BundlePadding::DEFAULT,
            },
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_ironwood_spend::<zip317::FeeRule>(fvk.clone(), note, merkle_path)
        .expect("ironwood spend");
    builder
        .add_ironwood_output::<zip317::FeeRule>(
            Some(fvk.to_ovk(Scope::External)),
            fvk.address_at(0u32, Scope::External),
            Zatoshis::const_from_u64(100_000),
            MemoBytes::empty(),
        )
        .expect("ironwood output");
    // 1_000_000 in, 100_000 out, less the ZIP 317 fee: 5_000 per logical
    // action, for the two Ironwood actions and whatever the Orchard bundle
    // is padded to.
    let fee = 5_000 * (2 + u64::from(orchard_pad_to.unwrap_or(0)));
    builder
        .add_ironwood_output::<zip317::FeeRule>(
            Some(fvk.to_ovk(Scope::Internal)),
            fvk.address_at(0u32, Scope::Internal),
            Zatoshis::from_u64(1_000_000 - 100_000 - fee).expect("a valid amount"),
            MemoBytes::empty(),
        )
        .expect("ironwood change");

    let parts = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt");

    Fixture {
        bytes: finish_fixture(parts, None),
        orchard_ask: SpendAuthorizingKey::from(&sk),
        transparent_sk: None,
        change_pubkey: t.change_pubkey.serialize(),
        change_output_index: None,
    }
}

/// Rewrites a PCZT's global header to the V5 `(tx_version, version_group_id)`
/// pair, leaving every bundle — the Ironwood one included — exactly as it was.
///
/// The `pczt` crate offers no setter for either field, so the rewrite goes
/// through the v2 encoding's serde form: `pczt::v2::Pczt` derives
/// `Serialize`/`Deserialize`, and JSON is self-describing enough to patch two
/// integers in place. The result is what a malformed or adversarially edited
/// PCZT looks like, not something any builder produces.
fn retag_as_v5(pczt: Pczt) -> Pczt {
    let v2 = pczt::v2::Pczt::try_from(pczt).expect("encodes as PCZT v2");
    let mut value = serde_json::to_value(&v2).expect("a PCZT without transparent maps is JSON");
    value["global"]["tx_version"] = serde_json::json!(pczt_ledger::limits::V5_TX_VERSION);
    value["global"]["version_group_id"] =
        serde_json::json!(pczt_ledger::limits::V5_VERSION_GROUP_ID);
    let patched: pczt::v2::Pczt = serde_json::from_value(value).expect("the patched form parses");
    Pczt::parse(&patched.serialize()).expect("the v2 encoding parses")
}

/// V5, transparent input → one Orchard output, in a bundle padded to eleven
/// actions: one action past a v3.9.2 app's
/// `MAX_PCZT_ORCHARD_ACTIONS_NUMBER`, and comfortably inside a v3.9.3 one's.
///
/// Nothing about it is malformed — it is a transaction the network would accept
/// — which is what makes it the fixture for "refused for a device limit, and
/// only for that" on both sides of the crate boundary. Two properties are
/// deliberate and load-bearing:
///
/// - no transparent *output*, so the host's transparent-change refusal does
///   not fire first and mask the limit;
/// - the extra actions come from `pad_to_minimum` rather than from more
///   recipients, so the bundle shows the user **one** output. A fixture of
///   eleven recipients would also exceed
///   `MAX_PCZT_SHIELDED_DISPLAYED_OUTPUTS_NUMBER` on a v3.9.3 app, and a test
///   asserting that such a device accepts it would be asserting something
///   false. [`fixture_v5_five_orchard_recipients`] is the fixture for *that*
///   bound.
fn fixture_v5_eleven_orchard_actions() -> Fixture {
    // 1_160_000 in, less the 60_000 ZIP 317 fee for one transparent input plus
    // eleven Orchard actions, leaves exactly this and so needs no change.
    orchard_output_fixture(1, Some(11), 1_100_000)
}

/// V5, transparent input → five Orchard recipients, unpadded: one displayed
/// shielded output past `MAX_PCZT_SHIELDED_DISPLAYED_OUTPUTS_NUMBER` (4) on a
/// v3.9.3 app, while its five actions are inside every record bound that app
/// enforces.
fn fixture_v5_five_orchard_recipients() -> Fixture {
    // 1_160_000 in, less the 30_000 fee for one transparent input plus five
    // Orchard actions, split five ways.
    orchard_output_fixture(5, None, 226_000)
}

/// V5, one real Orchard spend → one external recipient plus `change_notes`
/// separate **internal-scope** outputs: the shape a wallet produces when its
/// note-management policy splits change across several notes.
///
/// A wallet daemon whose note-management policy targets four change notes
/// turns a one-recipient send into one payment and four change notes, all
/// nonzero — five displayed outputs by a value-only count, against a v3.9.3
/// budget of four, and one displayed output by the device's own count.
///
/// The Orchard key is the one the fixture *seed* derives, so a downstream test
/// can build the matching UFVK from [`SEED`] alone and put it in a cache.
///
/// No transparent output: the transparent-change refusal would otherwise fire
/// first and mask what this fixture is for.
fn fixture_v5_seed_orchard_split_change(change_notes: u32) -> Fixture {
    seed_orchard_change_fixture(change_notes, None)
}

/// [`fixture_v5_seed_orchard_split_change`] with one Orchard change note and
/// a transparent change output of `transparent_change` zatoshis besides: the
/// shape whose two change outputs the device counts together.
fn fixture_v5_seed_orchard_and_transparent_change(transparent_change: u64) -> Fixture {
    seed_orchard_change_fixture(1, Some(transparent_change))
}

fn seed_orchard_change_fixture(change_notes: u32, transparent_change: Option<u64>) -> Fixture {
    let params = v5_network();
    let t = transparent_keys(&params);
    let sk = SpendingKey::from_zip32_seed(&SEED, FIXTURE_COIN_TYPE, zip32::AccountId::ZERO)
        .expect("the fixture seed derives an Orchard spending key");
    let fvk = FullViewingKey::from(&sk);

    let (note, merkle_path, anchor) = synthetic_note(&fvk, 1_000_000, NoteVersion::V2);

    let mut builder = Builder::new(
        params,
        TARGET_HEIGHT.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(anchor),
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_orchard_spend::<zip317::FeeRule>(fvk.clone(), note, merkle_path)
        .expect("orchard spend");
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(fvk.to_ovk(Scope::External)),
            fvk.address_at(0u32, Scope::External),
            Zatoshis::const_from_u64(100_000),
            MemoBytes::empty(),
        )
        .expect("orchard output");

    // 1_000_000 in, 100_000 to the recipient, less the ZIP 317 fee for a bundle
    // of `1 + change_notes` logical actions (plus one for a transparent
    // output), split evenly across the change notes. Each change note goes to
    // a *different* internal diversifier index, which is what a wallet does
    // and what keeps the test from passing by accident on a single hard-coded
    // address.
    let logical_actions = u64::from(1 + change_notes) + u64::from(transparent_change.is_some());
    let fee = 5_000 * logical_actions.max(2);
    let transparent = transparent_change.unwrap_or(0);
    if let Some(amount) = transparent_change {
        builder
            .add_transparent_output(&t.change_address, Zatoshis::const_from_u64(amount))
            .expect("transparent change output");
    }
    let change_total = 1_000_000 - 100_000 - transparent - fee;
    for j in 0..change_notes {
        let mut amount = change_total / u64::from(change_notes);
        if j == 0 {
            amount += change_total % u64::from(change_notes);
        }
        builder
            .add_orchard_output::<zip317::FeeRule>(
                Some(fvk.to_ovk(Scope::Internal)),
                fvk.address_at(j, Scope::Internal),
                Zatoshis::from_u64(amount).expect("a valid amount"),
                MemoBytes::empty(),
            )
            .expect("orchard change");
    }

    let parts = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt");

    Fixture {
        bytes: finish_fixture(parts, None),
        orchard_ask: SpendAuthorizingKey::from(&sk),
        transparent_sk: None,
        change_pubkey: t.change_pubkey.serialize(),
        change_output_index: transparent_change.map(|_| 0),
    }
}

/// The Orchard viewing key the seed-derived fixtures are built under — the same
/// key a wallet finds in the Orchard item of the account's cached UFVK.
fn seed_viewing_keys() -> AccountViewingKeys {
    let sk = SpendingKey::from_zip32_seed(&SEED, FIXTURE_COIN_TYPE, zip32::AccountId::ZERO)
        .expect("the fixture seed derives an Orchard spending key");
    AccountViewingKeys::from_orchard_fvk(FullViewingKey::from(&sk))
}

/// The viewing key the *other* fixtures are built under: `SpendingKey::from_bytes([0; 32])`,
/// which no seed produces.
fn canned_viewing_keys() -> AccountViewingKeys {
    AccountViewingKeys::from_orchard_fvk(orchard_keys().1)
}

/// V5, transparent input → four nonzero Orchard recipients plus one
/// **zero-valued** output to a fifth, encrypted under `ovk`.
///
/// With the account's external OVK this is the memo-only send: the device
/// opens the fifth output under that key before it looks at the value, and
/// gives it the fifth review slot. With no OVK it is indistinguishable from a
/// padding dummy to the device as well, and takes no slot.
fn fixture_v5_four_recipients_plus_zero_valued(
    ovk: Option<orchard::keys::OutgoingViewingKey>,
) -> Fixture {
    let params = v5_network();
    let t = transparent_keys(&params);
    let (sk, fvk) = orchard_keys();

    let mut builder = Builder::new(
        params,
        TARGET_HEIGHT.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
            ironwood_anchor: None,
            orchard_padding: BundlePadding {
                bundle_required: false,
                pad_to_minimum: None,
            },
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_transparent_p2pkh_input(
            t.pubkey,
            OutPoint::new([1u8; 32], 1),
            TxOut::new(
                Zatoshis::const_from_u64(1_160_000),
                t.address.script().into(),
            ),
        )
        .expect("transparent input");
    // 1_160_000 in, less the 30_000 fee for one transparent input plus five
    // Orchard actions, split four ways; the fifth output carries nothing.
    for i in 0..4u32 {
        builder
            .add_orchard_output::<zip317::FeeRule>(
                Some(fvk.to_ovk(Scope::External)),
                fvk.address_at(i, Scope::External),
                Zatoshis::const_from_u64(282_500),
                MemoBytes::empty(),
            )
            .expect("orchard output");
    }
    builder
        .add_orchard_output::<zip317::FeeRule>(
            ovk,
            fvk.address_at(4u32, Scope::External),
            Zatoshis::ZERO,
            MemoBytes::empty(),
        )
        .expect("zero-valued orchard output");

    let parts = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt");

    Fixture {
        bytes: finish_fixture(parts, Some(t.pubkey.serialize())),
        orchard_ask: SpendAuthorizingKey::from(&sk),
        transparent_sk: Some(t.sk),
        change_pubkey: t.change_pubkey.serialize(),
        change_output_index: None,
    }
}

/// One transparent input paying `recipients` distinct external Orchard
/// addresses `each` zatoshis, with the bundle padded to `pad_to` actions.
fn orchard_output_fixture(recipients: u32, pad_to: Option<u8>, each: u64) -> Fixture {
    let params = v5_network();
    let t = transparent_keys(&params);
    let (sk, fvk) = orchard_keys();

    let mut builder = Builder::new(
        params,
        TARGET_HEIGHT.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
            ironwood_anchor: None,
            orchard_padding: BundlePadding {
                bundle_required: false,
                pad_to_minimum: pad_to,
            },
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_transparent_p2pkh_input(
            t.pubkey,
            OutPoint::new([1u8; 32], 1),
            TxOut::new(
                Zatoshis::const_from_u64(1_160_000),
                t.address.script().into(),
            ),
        )
        .expect("transparent input");
    for i in 0..recipients {
        builder
            .add_orchard_output::<zip317::FeeRule>(
                Some(fvk.to_ovk(Scope::External)),
                fvk.address_at(i, Scope::External),
                Zatoshis::from_u64(each).expect("a valid amount"),
                MemoBytes::empty(),
            )
            .expect("orchard output");
    }

    let parts = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt");

    Fixture {
        bytes: finish_fixture(parts, Some(t.pubkey.serialize())),
        orchard_ask: SpendAuthorizingKey::from(&sk),
        transparent_sk: Some(t.sk),
        change_pubkey: t.change_pubkey.serialize(),
        change_output_index: None,
    }
}

/// V5, transparent input → one Orchard recipient per memo, each output
/// encrypted under the account's external OVK and carrying its memo. `each`
/// is the per-recipient amount, chosen so the ZIP 317 fee is exact.
fn orchard_output_fixture_with_memos(memos: Vec<MemoBytes>, each: u64) -> Fixture {
    let params = v5_network();
    let t = transparent_keys(&params);
    let (sk, fvk) = orchard_keys();

    let mut builder = Builder::new(
        params,
        TARGET_HEIGHT.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_transparent_p2pkh_input(
            t.pubkey,
            OutPoint::new([1u8; 32], 1),
            TxOut::new(
                Zatoshis::const_from_u64(1_160_000),
                t.address.script().into(),
            ),
        )
        .expect("transparent input");
    for (i, memo) in memos.into_iter().enumerate() {
        builder
            .add_orchard_output::<zip317::FeeRule>(
                Some(fvk.to_ovk(Scope::External)),
                fvk.address_at(i as u32, Scope::External),
                Zatoshis::from_u64(each).expect("a valid amount"),
                memo,
            )
            .expect("orchard output");
    }

    let parts = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt");

    Fixture {
        bytes: finish_fixture(parts, Some(t.pubkey.serialize())),
        orchard_ask: SpendAuthorizingKey::from(&sk),
        transparent_sk: Some(t.sk),
        change_pubkey: t.change_pubkey.serialize(),
        change_output_index: None,
    }
}

/// V5, transparent input → one nonzero Orchard output built with **no**
/// outgoing viewing key, plus a padding dummy. No key opens the output.
fn fixture_v5_orchard_output_without_ovk() -> Fixture {
    let params = v5_network();
    let t = transparent_keys(&params);
    let (sk, fvk) = orchard_keys();

    let mut builder = Builder::new(
        params,
        TARGET_HEIGHT.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_transparent_p2pkh_input(
            t.pubkey,
            OutPoint::new([1u8; 32], 1),
            TxOut::new(
                Zatoshis::const_from_u64(1_000_000),
                t.address.script().into(),
            ),
        )
        .expect("transparent input");
    builder
        .add_orchard_output::<zip317::FeeRule>(
            None,
            fvk.address_at(0u32, Scope::External),
            Zatoshis::const_from_u64(985_000),
            MemoBytes::empty(),
        )
        .expect("orchard output");

    let parts = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt");

    Fixture {
        bytes: finish_fixture(parts, Some(t.pubkey.serialize())),
        orchard_ask: SpendAuthorizingKey::from(&sk),
        transparent_sk: Some(t.sk),
        change_pubkey: t.change_pubkey.serialize(),
        change_output_index: None,
    }
}

/// V5, transparent input → transparent output, with the Orchard bundle padded
/// to two zero-valued dummy outputs and nothing else in it.
fn fixture_v5_two_dummy_outputs() -> Fixture {
    let params = v5_network();
    let t = transparent_keys(&params);
    let (sk, _) = orchard_keys();

    let mut builder = Builder::new(
        params,
        TARGET_HEIGHT.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
            ironwood_anchor: None,
            orchard_padding: BundlePadding {
                bundle_required: true,
                pad_to_minimum: Some(2),
            },
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_transparent_p2pkh_input(
            t.pubkey,
            OutPoint::new([1u8; 32], 1),
            TxOut::new(
                Zatoshis::const_from_u64(1_000_000),
                t.address.script().into(),
            ),
        )
        .expect("transparent input");
    // One transparent input, one transparent output and two Orchard actions
    // are three logical actions: a 15 000 zatoshi ZIP 317 fee, exactly.
    builder
        .add_transparent_output(&t.address, Zatoshis::const_from_u64(985_000))
        .expect("transparent output");

    let parts = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt");

    Fixture {
        bytes: finish_fixture(parts, Some(t.pubkey.serialize())),
        orchard_ask: SpendAuthorizingKey::from(&sk),
        transparent_sk: Some(t.sk),
        change_pubkey: t.change_pubkey.serialize(),
        change_output_index: None,
    }
}

/// A note the wallet "already received", with a synthetic witness whose root is
/// used as the bundle anchor. Nothing here is proven, so the path only has to
/// be well-formed.
fn synthetic_note(
    fvk: &FullViewingKey,
    value: u64,
    version: NoteVersion,
) -> (Note, MerklePath, orchard::Anchor) {
    let recipient = fvk.address_at(0u32, Scope::External);

    let mut rho_bytes = [0u8; 32];
    rho_bytes[0] = 1;
    let rho = Option::<Rho>::from(Rho::from_bytes(&rho_bytes)).expect("valid rho");

    let mut note = None;
    for seed in 0u8..=255 {
        let Some(rseed) = Option::<RandomSeed>::from(RandomSeed::from_bytes([seed; 32], &rho))
        else {
            continue;
        };
        if let Some(n) = Option::<Note>::from(Note::from_parts(
            recipient,
            NoteValue::from_raw(value),
            rho,
            rseed,
            version,
        )) {
            note = Some(n);
            break;
        }
    }
    let note = note.expect("a valid note exists for some rseed");

    let empty = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&[0u8; 32]))
        .expect("zero is a valid Pallas base");
    let merkle_path = MerklePath::from_parts(0, [empty; 32]);
    let anchor = merkle_path.root(note.commitment().into());

    (note, merkle_path, anchor)
}

// ---------------------------------------------------------------------------
// A scripted device
// ---------------------------------------------------------------------------

/// A scripted stand-in for the Ledger app.
///
/// It answers from canned signatures, records the instruction sequence so the
/// ordering can be asserted, and can be told to return a chosen status word at
/// a chosen point in the ceremony.
struct FakeDevice {
    /// The key it answers `GET_WALLET_PUBLIC_KEY` with, whatever the path.
    identity_key: secp256k1::PublicKey,
    /// The app version it answers `GET_FIRMWARE_VERSION` with.
    version: (u8, u8, u8),
    orchard: HashMap<u8, [u8; 64]>,
    ironwood: HashMap<u8, [u8; 64]>,
    transparent: HashMap<u8, Vec<u8>>,
    /// `(exchange index, status word)`; the exchange is answered with that
    /// status word and no data.
    fail_at: Option<(usize, u16)>,
    /// `(first exchange index, how many)`; those exchanges are answered with
    /// `0x6901` `CmdNotAccepted` and no data, as the device SDK's legacy I/O
    /// layer does while a review is on screen.
    refuse_from: Option<(usize, u32)>,
    seen: usize,
    log: Vec<(u8, u8, u8)>,
    /// Every command APDU received, whole, so a resend can be compared with
    /// what it resends.
    received: Vec<Vec<u8>>,
    /// The firmware's PCZT grammar, which every `PCZT_*` packet that reaches
    /// the app is parsed by, byte for byte. A packet the device would refuse
    /// fails the test at that packet; what it would read is kept in
    /// [`Grammar::wire`].
    grammar: Grammar,
}

impl FakeDevice {
    fn new() -> Self {
        FakeDevice {
            identity_key: fake_device_key(),
            version: (3, 9, 2),
            orchard: HashMap::new(),
            ironwood: HashMap::new(),
            transparent: HashMap::new(),
            fail_at: None,
            refuse_from: None,
            seen: 0,
            log: Vec::new(),
            received: Vec::new(),
            grammar: Grammar::new(),
        }
    }

    /// Everything the device read off the wire.
    fn wire(&self) -> &Wire {
        &self.grammar.wire
    }

    fn exchange(&mut self, capdu: &[u8]) -> Vec<u8> {
        assert!(capdu.len() >= 5, "an APDU is at least CLA INS P1 P2 Lc");
        assert_eq!(capdu[0], pczt_ledger::apdu::CLA, "class byte");
        let (ins, p1, p2) = (capdu[1], capdu[2], capdu[3]);
        assert_eq!(
            capdu[4] as usize,
            capdu.len() - 5,
            "Lc must match the data length"
        );
        self.log.push((ins, p1, p2));
        self.received.push(capdu.to_vec());

        let index = self.seen;
        self.seen += 1;

        if let Some((at, remaining)) = &mut self.refuse_from {
            if index >= *at && *remaining > 0 {
                *remaining -= 1;
                return StatusWord::CmdNotAccepted.to_u16().to_be_bytes().to_vec();
            }
        }

        // A `0x6901` never reached the app; everything else did, and the app
        // parses it before it answers.
        self.grammar.packet(ins, p1, p2, &capdu[5..]);

        if let Some((at, sw)) = self.fail_at {
            if at == index {
                return sw.to_be_bytes().to_vec();
            }
        }

        let mut out = match ins {
            // `LEGACY_VERSION_PREFIX ‖ ARCH_ID ‖ major ‖ minor ‖ patch ‖ sdk_major ‖
            // sdk_minor ‖ api_level`, the reply shape `handler_get_firmware_version`
            // produces.
            x if x == Ins::GetFirmwareVersion.code() => {
                let (major, minor, patch) = self.version;
                vec![0x38, 0x30, major, minor, patch, 2, 3, 22]
            }
            // `pk_len ‖ pk ‖ addr_len ‖ addr ‖ chain_code`, the reply shape
            // `handler_get_public_key` produces; the address is any ASCII.
            x if x == Ins::GetWalletPublicKey.code() => {
                let pk = self.identity_key.serialize_uncompressed();
                let address = b"tmFakeDeviceFirstAddress";
                let mut reply = vec![pk.len() as u8];
                reply.extend_from_slice(&pk);
                reply.push(address.len() as u8);
                reply.extend_from_slice(address);
                reply.extend_from_slice(&[0x11; 32]);
                reply
            }
            x if x == Ins::PcztSignOrchard.code() => self
                .orchard
                .get(&p2)
                .unwrap_or_else(|| panic!("no canned Orchard signature for action {p2}"))
                .to_vec(),
            x if x == Ins::PcztSignIronwood.code() => self
                .ironwood
                .get(&p2)
                .unwrap_or_else(|| panic!("no canned Ironwood signature for action {p2}"))
                .to_vec(),
            x if x == Ins::PcztSignTransparent.code() => self
                .transparent
                .get(&p2)
                .unwrap_or_else(|| panic!("no canned transparent signature for input {p2}"))
                .clone(),
            _ => Vec::new(),
        };
        out.extend_from_slice(&StatusWord::Ok.to_u16().to_be_bytes());
        out
    }

    /// The instruction bytes seen, in order, deduplicated across the packets of
    /// one multi-packet command.
    fn command_sequence(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        for (ins, _, _) in &self.log {
            if out.last() != Some(ins) {
                out.push(*ins);
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// The device's PCZT grammar
// ---------------------------------------------------------------------------

/// A replica of the firmware's PCZT command grammar — `src/parser/pczt.rs`
/// and `src/parser/pczt/*.rs` @ `22dc385` — driven packet by packet the way
/// `main.rs` drives the handlers: the handler is chosen by INS, the packet
/// data becomes a `ByteReader`, and the parser loops
/// `while reader.remaining_len() > 0`. Every packet-boundary assertion the
/// firmware makes is reproduced, and every value it reads is recorded in
/// [`Wire`], so a test can compare what the device was told with what the
/// PCZT holds — independently of the encoder that produced the bytes.
struct Grammar {
    state: GrammarState,
    /// `(INS, P1)` of the previous packet, for the P1 framing rule.
    prev: Option<(u8, u8)>,
    is_v6: bool,
    /// Bytes of the ciphertext currently being accumulated.
    pool_bytes: usize,
    t_in_count: usize,
    t_out_count: usize,
    act_count: usize,
    act_parsed: usize,
    has_orchard: bool,
    has_ironwood: bool,
    in_ironwood: bool,
    outputs_reviewed: bool,
    /// The transparent input or output, or shielded action, under
    /// construction across its packets.
    t_in: WireTransparentInput,
    t_out: WireTransparentOutput,
    action: WireAction,
    wire: Wire,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrammarState {
    Header,
    TInCount,
    TIn,
    TInScript,
    TInScriptBody { remaining: usize },
    TInSighash,
    TInDeriv,
    TInDone,
    TOut,
    TOutScript,
    TOutScriptBody { remaining: usize },
    TOutDeriv,
    TOutDone,
    Action,
    Zip32,
    Output,
    EncLen,
    EncBody,
    OutLen,
    OutBody,
    Meta,
    Trailer,
    OrchardDone,
    IronwoodDone,
}

/// The `PCZT_HEADER` fields as the device reads them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct WireHeader {
    pczt_version: u32,
    tx_version: u32,
    version_group_id: u32,
    consensus_branch_id: u32,
    fallback_lock_time: Option<u32>,
    expiry_height: u32,
    coin_type: u32,
    tx_modifiable: u8,
}

/// A `bip32_derivation` entry as the device reads it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct WireDerivation {
    pubkey: Vec<u8>,
    seed_fingerprint: Vec<u8>,
    path: Vec<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct WireTransparentInput {
    prevout_txid: Vec<u8>,
    prevout_index: u32,
    sequence: Option<u32>,
    value: u64,
    script_pubkey: Vec<u8>,
    sighash_type: u8,
    derivation: Option<WireDerivation>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct WireTransparentOutput {
    value: u64,
    script_pubkey: Vec<u8>,
    derivation: Option<WireDerivation>,
}

/// One shielded action as the device reads it, across its six packet groups.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct WireAction {
    cv_net: Vec<u8>,
    nullifier: Vec<u8>,
    rk: Vec<u8>,
    spend_recipient: Vec<u8>,
    spend_value: u64,
    spend_rho: Vec<u8>,
    spend_rseed: Vec<u8>,
    alpha: Vec<u8>,
    seed_fingerprint: Vec<u8>,
    path: Vec<u32>,
    cmx: Vec<u8>,
    ephemeral_key: Vec<u8>,
    enc_ciphertext: Vec<u8>,
    out_ciphertext: Vec<u8>,
    recipient: Vec<u8>,
    value: u64,
    rseed: Vec<u8>,
    rcv: Vec<u8>,
    /// The Ironwood lead byte, absent on an Orchard action.
    note_plaintext_version: Option<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct WireTrailer {
    flags: u8,
    value_sum_magnitude: u64,
    value_sum_negative: bool,
    anchor: Vec<u8>,
}

/// Everything the device read off the wire, in stream order.
#[derive(Debug, Default)]
struct Wire {
    header: Option<WireHeader>,
    transparent_inputs: Vec<WireTransparentInput>,
    transparent_outputs: Vec<WireTransparentOutput>,
    /// The declared action counts, `None` until the count packet arrives.
    orchard_count: Option<usize>,
    ironwood_count: Option<usize>,
    orchard_actions: Vec<WireAction>,
    ironwood_actions: Vec<WireAction>,
    orchard_trailer: Option<WireTrailer>,
    ironwood_trailer: Option<WireTrailer>,
    /// Whether the `P2_PCZT_FINISHED` packet has been accepted.
    finished: bool,
    /// `(INS, index)` of every signing command accepted.
    signed: Vec<(u8, u8)>,
}

/// The firmware's `ByteReader` over one packet's data.
struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn rem(&self) -> usize {
        self.b.len() - self.p
    }

    fn take(&mut self, n: usize) -> &'a [u8] {
        assert!(
            self.rem() >= n,
            "packet underrun: the device reads {n} bytes where {} remain",
            self.rem()
        );
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        s
    }

    fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }

    fn u32le(&mut self) -> u32 {
        u32::from_le_bytes(self.take(4).try_into().unwrap())
    }

    fn u64le(&mut self) -> u64 {
        u64::from_le_bytes(self.take(8).try_into().unwrap())
    }

    /// Path components are the one big-endian field on the wire
    /// (`src/parser/bip32_path.rs`: `u32::from_be_bytes`).
    fn u32be(&mut self) -> u32 {
        u32::from_be_bytes(self.take(4).try_into().unwrap())
    }

    /// The minimal `CompactSize` the firmware's `zcash_encoding` accepts.
    fn compact(&mut self) -> u64 {
        match self.u8() {
            n @ 0..=252 => u64::from(n),
            253 => {
                let v = u64::from(u16::from_le_bytes(self.take(2).try_into().unwrap()));
                assert!(v >= 253, "non-canonical CompactSize");
                v
            }
            254 => {
                let v = u64::from(u32::from_le_bytes(self.take(4).try_into().unwrap()));
                assert!(v > u64::from(u16::MAX), "non-canonical CompactSize");
                v
            }
            _ => panic!("the CompactSize u64 form is not used on this wire"),
        }
    }

    /// `read_optional_u32`: tag `0` is `None`, tag `1` is `Some`.
    fn opt_u32(&mut self) -> Option<u32> {
        match self.u8() {
            0 => None,
            1 => Some(self.u32le()),
            t => panic!("bad Option<u32> tag {t}"),
        }
    }

    /// The device requires the packet to end exactly here.
    fn end(&self, what: &str) {
        assert_eq!(
            self.rem(),
            0,
            "the device requires the packet to end at {what}; {} bytes follow",
            self.rem()
        );
    }

    /// `pubkey ‖ seed_fingerprint ‖ path_len ‖ path`, the entry the device
    /// reads for every `bip32_derivation`.
    fn derivation(&mut self) -> WireDerivation {
        let pubkey = self.take(33).to_vec();
        let seed_fingerprint = self.take(32).to_vec();
        let n = usize::from(self.u8());
        assert!(n <= 10, "path over MAX_ZCASH_BIP32_PATH");
        let path = (0..n).map(|_| self.u32be()).collect();
        WireDerivation {
            pubkey,
            seed_fingerprint,
            path,
        }
    }
}

const GRAMMAR_MAX_SCRIPT: usize = 252;
const GRAMMAR_ENC: usize = 580;
const GRAMMAR_OUT: usize = 80;
const GRAMMAR_RAW_ADDR: usize = 43;
const GRAMMAR_MAX_APDU_DATA: usize = 255;

impl Grammar {
    fn new() -> Self {
        Grammar {
            state: GrammarState::Header,
            prev: None,
            is_v6: false,
            pool_bytes: 0,
            t_in_count: 0,
            t_out_count: 0,
            act_count: 0,
            act_parsed: 0,
            has_orchard: false,
            has_ironwood: false,
            in_ironwood: false,
            outputs_reviewed: false,
            t_in: WireTransparentInput::default(),
            t_out: WireTransparentOutput::default(),
            action: WireAction::default(),
            wire: Wire::default(),
        }
    }

    /// `is_ready_to_sign`: every bundle the transaction has is parsed and the
    /// review has run.
    fn is_ready_to_sign(&self) -> bool {
        let orchard_done = !self.has_orchard
            || matches!(
                self.state,
                GrammarState::OrchardDone | GrammarState::IronwoodDone
            );
        let ironwood_done = !self.has_ironwood || self.state == GrammarState::IronwoodDone;
        orchard_done && ironwood_done && self.outputs_reviewed
    }

    /// One command APDU, as `main.rs` dispatches it. Commands outside the
    /// PCZT grammar (the probes, `GET_VK`, `GET_SHIELD_ADDR`) pass through.
    fn packet(&mut self, ins: u8, p1: u8, p2: u8, data: &[u8]) {
        const HEADER: u8 = Ins::PcztHeader.code();
        const TIN: u8 = Ins::PcztTransparentInput.code();
        const TOUT: u8 = Ins::PcztTransparentOutput.code();
        const ORCHARD: u8 = Ins::PcztOrchardAction.code();
        const IRONWOOD: u8 = Ins::PcztIronwoodAction.code();
        const SIGN_T: u8 = Ins::PcztSignTransparent.code();
        const SIGN_O: u8 = Ins::PcztSignOrchard.code();
        const SIGN_I: u8 = Ins::PcztSignIronwood.code();

        match ins {
            HEADER | TIN | TOUT | ORCHARD | IRONWOOD => {}
            SIGN_T | SIGN_O | SIGN_I => {
                self.signing(ins, p1, p2, data);
                self.prev = Some((ins, p1));
                return;
            }
            _ => return,
        }

        // `Instruction::try_from` (`main.rs`): P1 is one of the three framing
        // values, and the FINISHED flag is accepted only on the two
        // shielded-bundle instructions.
        assert!(
            matches!(
                p1,
                pczt_ledger::apdu::p1::FIRST
                    | pczt_ledger::apdu::p1::NEXT
                    | pczt_ledger::apdu::p1::LAST
            ),
            "bad P1 {p1:#04x} on INS {ins:#04x}"
        );
        match ins {
            HEADER => assert_eq!(
                (p1, p2),
                (
                    pczt_ledger::apdu::p1::FIRST,
                    pczt_ledger::apdu::p2::PCZT_CONTINUE
                ),
                "PCZT_HEADER is a single packet without the FINISHED flag"
            ),
            TIN | TOUT => assert_eq!(
                p2,
                pczt_ledger::apdu::p2::PCZT_CONTINUE,
                "P2 on INS {ins:#04x}"
            ),
            _ => assert!(
                matches!(
                    p2,
                    pczt_ledger::apdu::p2::PCZT_CONTINUE | pczt_ledger::apdu::p2::PCZT_FINISHED
                ),
                "bad P2 {p2:#04x} on INS {ins:#04x}"
            ),
        }
        // The P1 framing: FIRST opens a command, NEXT and LAST continue one,
        // and nothing follows LAST under the same instruction.
        match self.prev {
            Some((prev_ins, prev_p1)) if prev_ins == ins => {
                assert_ne!(
                    prev_p1,
                    pczt_ledger::apdu::p1::LAST,
                    "a packet followed the LAST packet of INS {ins:#04x}"
                );
                assert_ne!(
                    p1,
                    pczt_ledger::apdu::p1::FIRST,
                    "a continuation packet of INS {ins:#04x} carries P1_FIRST"
                );
            }
            _ => assert_eq!(
                p1,
                pczt_ledger::apdu::p1::FIRST,
                "the first packet of INS {ins:#04x} must carry P1_FIRST"
            ),
        }
        self.prev = Some((ins, p1));
        assert!(
            data.len() <= GRAMMAR_MAX_APDU_DATA,
            "APDU data over 255 bytes"
        );

        let mut r = Reader { b: data, p: 0 };
        match ins {
            HEADER => self.header(&mut r),
            TIN => self.transparent_inputs(&mut r),
            TOUT => self.transparent_outputs(&mut r),
            _ => self.shielded(ins == IRONWOOD, p2, &mut r),
        }
    }

    fn header(&mut self, r: &mut Reader<'_>) {
        assert_eq!(self.state, GrammarState::Header, "PCZT_HEADER out of order");
        assert_eq!(r.take(4), b"PCZT", "the header magic");
        let header = WireHeader {
            pczt_version: r.u32le(),
            tx_version: r.u32le(),
            version_group_id: r.u32le(),
            consensus_branch_id: r.u32le(),
            fallback_lock_time: r.opt_u32(),
            expiry_height: r.u32le(),
            coin_type: r.u32le(),
            tx_modifiable: r.u8(),
        };
        let is_v5 = header.tx_version == pczt_ledger::limits::V5_TX_VERSION
            && header.version_group_id == pczt_ledger::limits::V5_VERSION_GROUP_ID;
        let is_v6 = header.tx_version == pczt_ledger::limits::V6_TX_VERSION
            && header.version_group_id == pczt_ledger::limits::V6_VERSION_GROUP_ID;
        assert!(is_v5 || is_v6, "unsupported tx version pair");
        assert_eq!(
            header.pczt_version,
            if is_v6 { 2 } else { 1 },
            "PCZT/tx version pairing"
        );
        assert!(
            header.coin_type == 133 || header.coin_type == 1,
            "coin type"
        );
        r.end("the end of the global fields");
        self.is_v6 = is_v6;
        self.wire.header = Some(header);
        self.state = GrammarState::TInCount;
    }

    fn transparent_inputs(&mut self, r: &mut Reader<'_>) {
        while r.rem() > 0 {
            match self.state {
                GrammarState::TInCount => {
                    self.t_in_count = r.compact() as usize;
                    r.end("the transparent input count");
                    self.state = if self.t_in_count == 0 {
                        GrammarState::TInDone
                    } else {
                        GrammarState::TIn
                    };
                }
                GrammarState::TIn => {
                    assert!(self.wire.transparent_inputs.len() < self.t_in_count);
                    self.t_in = WireTransparentInput {
                        prevout_txid: r.take(32).to_vec(),
                        prevout_index: r.u32le(),
                        sequence: r.opt_u32(),
                        value: r.u64le(),
                        ..WireTransparentInput::default()
                    };
                    self.state = GrammarState::TInScript;
                    r.end("the transparent input prevout/value group");
                }
                GrammarState::TInScript => {
                    let size = r.compact() as usize;
                    assert!(
                        size <= GRAMMAR_MAX_SCRIPT,
                        "input script over MAX_PCZT_SCRIPT_SIZE"
                    );
                    if size == 0 {
                        r.end("an empty input scriptPubKey");
                        self.state = GrammarState::TInSighash;
                    } else {
                        assert!(r.rem() > 0, "at least one script byte must follow the size");
                        let n = std::cmp::min(size, r.rem());
                        self.t_in.script_pubkey.extend_from_slice(r.take(n));
                        if n == size {
                            r.end("the end of the input scriptPubKey");
                            self.state = GrammarState::TInSighash;
                        } else {
                            self.state = GrammarState::TInScriptBody {
                                remaining: size - n,
                            };
                        }
                    }
                }
                GrammarState::TInScriptBody { remaining } => {
                    let n = std::cmp::min(remaining, r.rem());
                    self.t_in.script_pubkey.extend_from_slice(r.take(n));
                    if n == remaining {
                        r.end("the end of the input scriptPubKey");
                        self.state = GrammarState::TInSighash;
                    } else {
                        self.state = GrammarState::TInScriptBody {
                            remaining: remaining - n,
                        };
                    }
                }
                GrammarState::TInSighash => {
                    self.t_in.sighash_type = r.u8();
                    assert_eq!(self.t_in.sighash_type, SIGHASH_ALL, "SIGHASH_ALL only");
                    assert!(r.rem() > 0, "the derivation must follow in the same packet");
                    self.state = GrammarState::TInDeriv;
                }
                GrammarState::TInDeriv => {
                    assert_eq!(r.compact(), 1, "exactly one input bip32_derivation");
                    assert!(r.rem() > 0, "derivation bytes missing");
                    self.t_in.derivation = Some(r.derivation());
                    r.end("the end of the input bip32_derivation entry");
                    self.wire
                        .transparent_inputs
                        .push(std::mem::take(&mut self.t_in));
                    self.state = if self.wire.transparent_inputs.len() == self.t_in_count {
                        GrammarState::TInDone
                    } else {
                        GrammarState::TIn
                    };
                }
                s => panic!("BadState: PCZT_TRANSPARENT_INPUT in state {s:?}"),
            }
        }
    }

    fn transparent_outputs(&mut self, r: &mut Reader<'_>) {
        while r.rem() > 0 {
            match self.state {
                GrammarState::TInDone => {
                    self.t_out_count = r.compact() as usize;
                    r.end("the transparent output count");
                    self.state = if self.t_out_count == 0 {
                        GrammarState::TOutDone
                    } else {
                        GrammarState::TOut
                    };
                }
                GrammarState::TOut => {
                    assert!(self.wire.transparent_outputs.len() < self.t_out_count);
                    self.t_out = WireTransparentOutput {
                        value: r.u64le(),
                        ..WireTransparentOutput::default()
                    };
                    self.state = GrammarState::TOutScript;
                    r.end("the transparent output value");
                }
                GrammarState::TOutScript => {
                    let size = r.compact() as usize;
                    assert!(
                        size <= GRAMMAR_MAX_SCRIPT,
                        "output script over MAX_PCZT_SCRIPT_SIZE"
                    );
                    if size == 0 {
                        r.end("an empty output scriptPubKey");
                        self.state = GrammarState::TOutDeriv;
                    } else {
                        assert!(r.rem() > 0, "at least one script byte must follow the size");
                        let n = std::cmp::min(size, r.rem());
                        self.t_out.script_pubkey.extend_from_slice(r.take(n));
                        if n == size {
                            r.end("the end of the output scriptPubKey");
                            self.state = GrammarState::TOutDeriv;
                        } else {
                            self.state = GrammarState::TOutScriptBody {
                                remaining: size - n,
                            };
                        }
                    }
                }
                GrammarState::TOutScriptBody { remaining } => {
                    let n = std::cmp::min(remaining, r.rem());
                    self.t_out.script_pubkey.extend_from_slice(r.take(n));
                    if n == remaining {
                        r.end("the end of the output scriptPubKey");
                        self.state = GrammarState::TOutDeriv;
                    } else {
                        self.state = GrammarState::TOutScriptBody {
                            remaining: remaining - n,
                        };
                    }
                }
                GrammarState::TOutDeriv => {
                    let count = r.compact();
                    assert!(count <= 1, "at most one output bip32_derivation");
                    if count == 1 {
                        assert!(r.rem() > 0, "derivation bytes missing");
                        self.t_out.derivation = Some(r.derivation());
                    }
                    r.end("the end of the output bip32_derivation packet");
                    self.wire
                        .transparent_outputs
                        .push(std::mem::take(&mut self.t_out));
                    self.state = if self.wire.transparent_outputs.len() == self.t_out_count {
                        GrammarState::TOutDone
                    } else {
                        GrammarState::TOut
                    };
                }
                s => panic!("BadState: PCZT_TRANSPARENT_OUTPUT in state {s:?}"),
            }
        }
    }

    fn shielded(&mut self, iron: bool, p2: u8, r: &mut Reader<'_>) {
        // The entry states are pool-specific: Orchard starts from TOutDone,
        // Ironwood from OrchardDone.
        let entry = if iron {
            GrammarState::OrchardDone
        } else {
            GrammarState::TOutDone
        };
        while r.rem() > 0 {
            match self.state {
                s if s == entry => {
                    if iron {
                        assert!(self.is_v6, "Ironwood bundle on a non-V6 transaction");
                    }
                    self.in_ironwood = iron;
                    self.act_count = r.compact() as usize;
                    self.act_parsed = 0;
                    r.end("the shielded action count");
                    if iron {
                        self.wire.ironwood_count = Some(self.act_count);
                    } else {
                        self.wire.orchard_count = Some(self.act_count);
                    }
                    if self.act_count == 0 {
                        // `finalize_*_actions`: no trailer follows an empty
                        // bundle, and this is where a V5 review, or a V6 one
                        // on the Ironwood command, runs.
                        self.state = if iron {
                            GrammarState::IronwoodDone
                        } else {
                            GrammarState::OrchardDone
                        };
                        if iron || !self.is_v6 {
                            self.outputs_reviewed = true;
                        }
                    } else {
                        if iron {
                            self.has_ironwood = true;
                        } else {
                            self.has_orchard = true;
                        }
                        self.state = GrammarState::Action;
                    }
                }
                GrammarState::Action => {
                    assert_eq!(
                        self.in_ironwood, iron,
                        "bundle instruction switched mid-bundle"
                    );
                    self.action = WireAction {
                        cv_net: r.take(32).to_vec(),
                        nullifier: r.take(32).to_vec(),
                        rk: r.take(32).to_vec(),
                        spend_recipient: r.take(GRAMMAR_RAW_ADDR).to_vec(),
                        spend_value: r.u64le(),
                        spend_rho: r.take(32).to_vec(),
                        spend_rseed: r.take(32).to_vec(),
                        alpha: r.take(32).to_vec(),
                        ..WireAction::default()
                    };
                    r.end("the end of the spend group");
                    self.state = GrammarState::Zip32;
                }
                GrammarState::Zip32 => {
                    self.action.seed_fingerprint = r.take(32).to_vec();
                    let n = usize::from(r.u8());
                    assert!(n <= 10, "path over MAX_ZCASH_BIP32_PATH");
                    self.action.path = (0..n).map(|_| r.u32be()).collect();
                    r.end("the end of the zip32_derivation packet");
                    self.state = GrammarState::Output;
                }
                GrammarState::Output => {
                    self.action.cmx = r.take(32).to_vec();
                    self.action.ephemeral_key = r.take(32).to_vec();
                    r.end("the end of the cmx/ephemeral_key group");
                    self.state = GrammarState::EncLen;
                }
                GrammarState::EncLen => {
                    assert_eq!(r.compact() as usize, GRAMMAR_ENC, "enc_ciphertext size");
                    assert!(r.rem() > 0, "enc_ciphertext bytes must follow the size");
                    self.pool_bytes = 0;
                    self.state = GrammarState::EncBody;
                }
                GrammarState::EncBody => {
                    let n = std::cmp::min(GRAMMAR_ENC - self.pool_bytes, r.rem());
                    self.action.enc_ciphertext.extend_from_slice(r.take(n));
                    self.pool_bytes += n;
                    if self.pool_bytes == GRAMMAR_ENC {
                        r.end("the end of enc_ciphertext");
                        self.pool_bytes = 0;
                        self.state = GrammarState::OutLen;
                    }
                }
                GrammarState::OutLen => {
                    assert_eq!(r.compact() as usize, GRAMMAR_OUT, "out_ciphertext size");
                    assert!(r.rem() > 0, "out_ciphertext bytes must follow the size");
                    self.pool_bytes = 0;
                    self.state = GrammarState::OutBody;
                }
                GrammarState::OutBody => {
                    let n = std::cmp::min(GRAMMAR_OUT - self.pool_bytes, r.rem());
                    self.action.out_ciphertext.extend_from_slice(r.take(n));
                    self.pool_bytes += n;
                    if self.pool_bytes == GRAMMAR_OUT {
                        r.end("the end of out_ciphertext");
                        self.pool_bytes = 0;
                        self.state = GrammarState::Meta;
                    }
                }
                GrammarState::Meta => {
                    self.action.recipient = r.take(GRAMMAR_RAW_ADDR).to_vec();
                    self.action.value = r.u64le();
                    self.action.rseed = r.take(32).to_vec();
                    self.action.rcv = r.take(32).to_vec();
                    if iron {
                        let version = r.u8();
                        assert_eq!(version, 0x03, "NOTE_VERSION_IRONWOOD");
                        self.action.note_plaintext_version = Some(version);
                    }
                    r.end("the end of the output metadata group");
                    let action = std::mem::take(&mut self.action);
                    if iron {
                        self.wire.ironwood_actions.push(action);
                    } else {
                        self.wire.orchard_actions.push(action);
                    }
                    self.act_parsed += 1;
                    self.state = if self.act_parsed == self.act_count {
                        GrammarState::Trailer
                    } else {
                        GrammarState::Action
                    };
                }
                GrammarState::Trailer => {
                    let flags = r.u8();
                    let value_sum_magnitude = r.u64le();
                    let sign = r.u8();
                    assert!(sign <= 1, "bad value_sum sign byte");
                    let anchor = r.take(32).to_vec();
                    r.end("the end of the bundle trailer");
                    let trailer = WireTrailer {
                        flags,
                        value_sum_magnitude,
                        value_sum_negative: sign == 1,
                        anchor,
                    };
                    if iron {
                        self.wire.ironwood_trailer = Some(trailer);
                        self.state = GrammarState::IronwoodDone;
                    } else {
                        self.wire.orchard_trailer = Some(trailer);
                        self.state = GrammarState::OrchardDone;
                    }
                    if iron || !self.is_v6 {
                        self.outputs_reviewed = true;
                    }
                }
                s => panic!(
                    "BadState: shielded bundle INS for {} in state {s:?}",
                    if iron { "Ironwood" } else { "Orchard" }
                ),
            }
        }
        // `finish_pczt_if_requested`.
        if p2 == pczt_ledger::apdu::p2::PCZT_FINISHED {
            assert!(
                self.is_ready_to_sign(),
                "FINISHED marker where the device answers BadState (state {:?}, \
                 outputs_reviewed {})",
                self.state,
                self.outputs_reviewed
            );
            self.wire.finished = true;
        }
    }

    /// A `PCZT_SIGN_*` command: only after the FINISHED packet, only for an
    /// index that exists, and never for a dummy spend.
    fn signing(&mut self, ins: u8, p1: u8, p2: u8, data: &[u8]) {
        assert!(
            self.wire.finished,
            "a signing command before the FINISHED marker"
        );
        assert_eq!(p1, 0x00, "signing P1");
        assert!(data.is_empty(), "signing commands carry no data");
        let index = usize::from(p2);
        if ins == Ins::PcztSignTransparent.code() {
            assert!(
                index < self.t_in_count,
                "sign index {index} past the transparent input count"
            );
        } else {
            let pool = if ins == Ins::PcztSignIronwood.code() {
                &self.wire.ironwood_actions
            } else {
                &self.wire.orchard_actions
            };
            assert!(
                index < pool.len(),
                "sign index {index} past the action count"
            );
            assert_ne!(
                pool[index].spend_value, 0,
                "the device refuses to sign a dummy spend"
            );
        }
        self.wire.signed.push((ins, p2));
    }
}

#[cfg(feature = "std")]
/// A [`Transport`] over a [`FakeDevice`], for driving [`ceremony`] itself.
///
/// It can be told to fail one exchange on the wire, which is the case that
/// leaves a session with a command outstanding.
struct FakeTransport {
    device: FakeDevice,
    /// The exchange index that never crosses the wire.
    fail_at: Option<usize>,
    exchanges: usize,
    /// The deadline every exchange was asked to wait under, in order.
    deadlines: Vec<Deadline>,
}

#[cfg(feature = "std")]
impl FakeTransport {
    fn new(device: FakeDevice) -> Self {
        FakeTransport {
            device,
            fail_at: None,
            exchanges: 0,
            deadlines: Vec::new(),
        }
    }
}

#[cfg(feature = "std")]
impl Transport for FakeTransport {
    fn exchange_with(
        &mut self,
        apdu: &[u8],
        deadline: Deadline,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        self.deadlines.push(deadline);
        let index = self.exchanges;
        self.exchanges += 1;
        if self.fail_at == Some(index) {
            return Err(TransportError::ConnectionClosed);
        }
        Ok(Zeroizing::new(self.device.exchange(apdu)))
    }

    fn describe(&self) -> String {
        "a scripted device".to_string()
    }
}

/// Produces the signatures a real device would return, by signing the shaped
/// PCZT host-side with the fixture's keys.
///
/// The shielded sighash does not commit to `zip32_derivation` or
/// `bip32_derivation`, so signing the shaped PCZT and signing the unshaped one
/// give the same bytes; the shaped one is used because that is what the session
/// will apply them to.
fn canned_signatures(
    fixture: &Fixture,
    shaped: &Pczt,
    device: &mut FakeDevice,
    ledger_quirks: bool,
) {
    let plan = build_plan(shaped).expect("shaped PCZT plans");

    for &index in plan.orchard_real_spends() {
        let mut signer = Signer::new(shaped.clone()).expect("signer");
        signer
            .sign_orchard(index, &fixture.orchard_ask)
            .expect("host-side orchard signature");
        let signed = signer.finish();
        device
            .orchard
            .insert(index as u8, orchard_sig(&signed, index, false));
    }
    for &index in plan.ironwood_real_spends() {
        let mut signer = Signer::new(shaped.clone()).expect("signer");
        signer
            .sign_ironwood(index, &fixture.orchard_ask)
            .expect("host-side ironwood signature");
        let signed = signer.finish();
        device
            .ironwood
            .insert(index as u8, orchard_sig(&signed, index, true));
    }

    if let Some(sk) = &fixture.transparent_sk {
        let signer = Signer::new(shaped.clone()).expect("signer");
        let secp = secp256k1::Secp256k1::signing_only();
        for index in 0..plan.stream().transparent_inputs().len() {
            let sighash = signer.transparent_sighash(index).expect("sighash");
            let sig = secp.sign_ecdsa(&secp256k1::Message::from_digest(sighash), sk);
            let mut der = sig.serialize_der().to_vec();
            if ledger_quirks {
                // The device ORs the y-parity bit into the DER SEQUENCE tag
                // when the y coordinate is odd. Forcing it here exercises the
                // normalization on every run rather than roughly half of them.
                der[0] = LEDGER_DER_PARITY_TAG;
            }
            // The device always appends the sighash type.
            der.push(SIGHASH_ALL);
            device.transparent.insert(index as u8, der);
        }
    }
}

/// The `spend_auth_sig` of one action of a signed PCZT.
fn orchard_sig(pczt: &Pczt, index: usize, ironwood: bool) -> [u8; 64] {
    let bundle = if ironwood {
        pczt.ironwood()
    } else {
        pczt.orchard()
    };
    bundle.actions()[index]
        .spend()
        .spend_auth_sig()
        .expect("the action was just signed")
}

/// The exchange index of the packet carrying `P2_PCZT_FINISHED`: the identity
/// probe, then the whole PCZT stream, of which it is the last packet.
fn review_exchange_index(session: &LedgerSignSession) -> usize {
    let stream_len = session
        .plan()
        .stream()
        .to_apdus()
        .expect("the plan encodes")
        .len();
    PROBE_EXCHANGES + stream_len - 1
}

/// Pumps the session until it hands out the first command with `ins`,
/// answering everything before it; that command is left outstanding and
/// returned.
fn drive_until_ins(session: &mut LedgerSignSession, device: &mut FakeDevice, ins: u8) -> Vec<u8> {
    loop {
        match session.next_step() {
            PumpStep::Send(capdu) => {
                if capdu[1] == ins {
                    return capdu;
                }
                let rapdu = device.exchange(&capdu);
                session
                    .process_response(&rapdu)
                    .expect("the exchanges before the target succeed");
            }
            other => panic!("the session ended before handing out INS {ins:#04x}: {other:?}"),
        }
    }
}

/// Drives a session to completion against a scripted device.
fn run_session(
    session: &mut LedgerSignSession,
    device: &mut FakeDevice,
) -> Result<Vec<SessionStatus>, SessionError> {
    let mut statuses = Vec::new();
    while let PumpStep::Send(capdu) = session.next_step() {
        let rapdu = device.exchange(&capdu);
        statuses.push(session.process_response(&rapdu)?);
    }
    Ok(statuses)
}

// ---------------------------------------------------------------------------
// Shaping
// ---------------------------------------------------------------------------

/// Every Orchard action must leave the shaping pass with a `zip32_derivation`,
/// dummies included: the device builds one signing record per action and aborts
/// on any action without a path.
#[test]
fn shaping_stamps_zip32_on_every_action_including_dummies() {
    let fixture = fixture_v5_transparent_to_orchard();
    let pczt = fixture.pczt();

    // Precondition: the builder stamped nothing, and every action is a dummy.
    let before = build_plan(&pczt).expect("plans");
    assert!(!before.stream().orchard_actions().is_empty());
    assert_eq!(
        before.missing_zip32().len(),
        before.stream().orchard_actions().len()
    );
    assert!(before.orchard_real_spends().is_empty());

    let shaped = shape_for_device(
        pczt,
        &ShapeParams::new(FIXTURE_COIN_TYPE, account())
            .with_seed_fingerprint(Some(SEED_FINGERPRINT))
            .with_change(None),
    )
    .expect("shapes");

    let after = build_plan(shaped.pczt()).expect("plans");
    assert!(after.missing_zip32().is_empty());
    for fingerprint in orchard_fingerprints(shaped.pczt().clone()) {
        assert_eq!(fingerprint, Some(SEED_FINGERPRINT));
    }
    for action in after.stream().orchard_actions() {
        assert_eq!(
            action.zip32_derivation().path().components(),
            vec![
                0x8000_0000 | 32,
                0x8000_0000 | FIXTURE_COIN_TYPE,
                0x8000_0000 | ACCOUNT
            ],
        );
    }
}

/// A V5 PCZT must serialize as PCZT v1; a V6 one as v2. `Pczt::serialize()`
/// picks the minimal encoding, so this is a property of the content, not a
/// choice this crate makes.
#[test]
fn shaping_reports_the_encoding_version_the_device_requires() {
    for (fixture, expected) in [
        (fixture_v5_transparent_to_orchard(), 1u32),
        (fixture_v6_ironwood(), 2u32),
    ] {
        let shaped = shape_for_device(
            fixture.pczt(),
            &ShapeParams::new(FIXTURE_COIN_TYPE, account())
                .with_seed_fingerprint(Some(SEED_FINGERPRINT))
                .with_change(None),
        )
        .expect("shapes");
        assert_eq!(shaped.encoding_version(), expected);

        // `Shaped::encoding_version` is the `pczt::EncodingVersion` the encoder
        // reported, mapped onto the number the device's parser reads.
        // Serializing here checks that mapping against the version the encoder
        // actually writes into the header.
        let bytes = shaped.pczt().clone().serialize().expect("serializes");
        assert_eq!(&bytes[..4], b"PCZT");
        assert_eq!(
            u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            expected
        );

        // The header record carries the same number.
        let plan = build_plan(shaped.pczt()).expect("plans");
        assert_eq!(plan.stream().header().pczt_version(), expected);
    }
}

/// The change output gets a derivation; recipient outputs do not.
#[test]
fn shaping_stamps_the_transparent_change_output() {
    let fixture = fixture_v5_orchard_spend();
    let change = fixture.change_info().expect("fixture has a change output");

    let shaped = shape_for_device(
        fixture.pczt(),
        &ShapeParams::new(FIXTURE_COIN_TYPE, account())
            .with_seed_fingerprint(Some(SEED_FINGERPRINT))
            .with_change(Some(change.clone())),
    )
    .expect("shapes");

    let plan = build_plan(shaped.pczt()).expect("plans");
    let output = &plan.stream().transparent_outputs()[change.output_index()];
    let derivation = output.derivation().expect("the change output is marked");
    assert_eq!(*derivation.pubkey(), fixture.change_pubkey);
    assert_eq!(
        derivation.path().components(),
        vec![
            0x8000_0000 | 44,
            0x8000_0000 | FIXTURE_COIN_TYPE,
            0x8000_0000 | ACCOUNT,
            1,
            0
        ],
    );
    // And the pubkey really does hash to the script the device will see.
    assert_eq!(
        &output.script_pubkey()[3..23],
        &hash160(derivation.pubkey())
    );
}

/// Stamping a change derivation whose pubkey does not hash to the output's
/// script is refused. The device would not abort on it — it would silently show
/// the output as a third-party recipient, and could take a different output for
/// change — so the host has to catch it.
#[test]
fn shaping_rejects_a_change_pubkey_that_does_not_match_the_script() {
    let fixture = fixture_v5_orchard_spend();
    // Derived honestly, for the account's next change address: it cannot hash
    // to the script of the output the fixture pays.
    let change = change_info_at(fixture_change_index() + 1, 0);

    let err = shape_for_device(
        fixture.pczt(),
        &ShapeParams::new(FIXTURE_COIN_TYPE, account())
            .with_seed_fingerprint(Some(SEED_FINGERPRINT))
            .with_change(Some(change.clone())),
    )
    .expect_err("mismatched change pubkey must be refused");

    assert!(
        matches!(err, ShapeError::ChangeOutputHashMismatch { .. }),
        "unexpected error: {err:?}"
    );

    // Neither hash is in the error: a P2PKH hash is the address, and an error
    // is what a wallet logs.
    let script = fixture.pczt().transparent().outputs()[0]
        .script_pubkey()
        .clone();
    let script_hash = hex(&script[3..23]);
    let pubkey_hash = hex(&hash160(change.pubkey()));
    for rendered in [format!("{err}"), format!("{err:?}")] {
        assert!(!rendered.contains(&script_hash), "{rendered}");
        assert!(!rendered.contains(&pubkey_hash), "{rendered}");
    }
}

/// The plan's records with transparent input 0 paying `script_pubkey`
/// instead: what a builder could never produce, rebuilt through the record
/// constructors so the validator can be shown refusing it.
fn with_input_script(plan: &pczt_ledger::plan::Plan, script_pubkey: Vec<u8>) -> StreamPlan {
    let stream = plan.stream();
    let input = &stream.transparent_inputs()[0];
    let patched = TransparentInputRecord::new(
        *input.prevout_txid(),
        input.prevout_index(),
        input.sequence(),
        input.value(),
        script_pubkey,
        input.sighash_type(),
        input.derivation().clone(),
    );
    let mut inputs = stream.transparent_inputs().to_vec();
    inputs[0] = patched;
    StreamPlan::new(
        stream.header().clone(),
        inputs,
        stream.transparent_outputs().to_vec(),
        stream.orchard_actions().to_vec(),
        stream.orchard_trailer().cloned(),
        stream.ironwood_actions().map(<[_]>::to_vec),
        stream.ironwood_trailer().cloned(),
    )
}

/// Lowercase hex, as an address-bearing hash would leak into a log line.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The device derives one account key per PCZT. An action already stamped with
/// a different account path makes the transaction unsignable, so shaping
/// refuses it rather than streaming a mixture the device answers `BadState` to.
#[test]
fn shaping_rejects_non_uniform_derivation_paths() {
    let fixture = fixture_v5_transparent_to_orchard();

    // Stamp action 0 with a *different* account than the session will use.
    let foreign = vec![32 | HARDENED, FIXTURE_COIN_TYPE | HARDENED, 7 | HARDENED];
    let pczt = Updater::new(fixture.pczt())
        .update_orchard_with(|mut updater| {
            let derivation = orchard::pczt::Zip32Derivation::parse(SEED_FINGERPRINT, foreign)
                .expect("valid derivation");
            updater.update_action_with(0, |mut action| {
                action.set_spend_zip32_derivation(derivation);
                Ok(())
            })
        })
        .expect("updater")
        .finish();

    let err = shape_for_device(
        pczt,
        &ShapeParams::new(FIXTURE_COIN_TYPE, account())
            .with_seed_fingerprint(Some(SEED_FINGERPRINT))
            .with_change(None),
    )
    .expect_err("a foreign account path must be refused");

    assert_eq!(
        err,
        ShapeError::NonUniformPath {
            section: Section::Orchard,
            index: 0,
        }
    );
}

/// Two actions stamped with different seed fingerprints are refused by
/// shaping: the device derives one account key per transaction, and a bundle
/// that names two seeds cannot be signed by it.
#[test]
fn shaping_rejects_non_uniform_seed_fingerprints() {
    let path = vec![
        32 | HARDENED,
        FIXTURE_COIN_TYPE | HARDENED,
        ACCOUNT | HARDENED,
    ];
    // An Orchard spend with no transparent input, so the only fingerprints in
    // the PCZT are the two stamped here.
    let pczt = Updater::new(fixture_v5_orchard_spend().pczt())
        .update_orchard_with(|mut u| {
            for (index, fingerprint) in [(0, [0x11u8; 32]), (1, [0x22u8; 32])] {
                let derivation = orchard::pczt::Zip32Derivation::parse(fingerprint, path.clone())
                    .expect("a hardened path");
                u.update_action_with(index, |mut action| {
                    action.set_spend_zip32_derivation(derivation);
                    Ok(())
                })?;
            }
            Ok(())
        })
        .expect("updater")
        .finish();

    let err = shape_for_device(
        pczt,
        &ShapeParams::new(FIXTURE_COIN_TYPE, account())
            .with_seed_fingerprint(Some([0x11; 32]))
            .with_change(None),
    )
    .expect_err("two seeds in one bundle");
    assert_eq!(err, ShapeError::NonUniformSeedFingerprint);
}

/// A PCZT from a UFVK-imported account carries no derivation anywhere and the
/// caller may have no seed fingerprint either. The firmware never checks the
/// fingerprint half, so the zeroed default is sound.
#[test]
fn shaping_synthesizes_a_zeroed_fingerprint_when_none_is_known() {
    // An Orchard spend with no transparent input: nothing in it names a seed.
    let fixture = fixture_v5_orchard_spend();

    let shaped = shape_for_device(
        fixture.pczt(),
        &ShapeParams::new(FIXTURE_COIN_TYPE, account())
            .with_seed_fingerprint(None)
            .with_change(None),
    )
    .expect("shapes");

    let fingerprints = orchard_fingerprints(shaped.into_pczt());
    assert!(!fingerprints.is_empty());
    for fingerprint in fingerprints {
        assert_eq!(fingerprint, Some([0u8; 32]));
    }
}

/// A seeded wallet stamps its transparent inputs with the real seed
/// fingerprint. With none supplied, shaping adopts it for the shielded actions
/// and for the change output, instead of handing back a PCZT that names one
/// seed on its inputs and a zeroed one everywhere else — a change derivation
/// the wallet could not attribute to its own seed.
#[test]
fn shaping_adopts_the_fingerprint_the_transparent_records_carry() {
    let params = ShapeParams::new(FIXTURE_COIN_TYPE, account()).with_seed_fingerprint(None);

    // The shielded actions take it from the input.
    let fixture = fixture_v5_transparent_to_orchard();
    let shaped =
        shape_for_device(fixture.pczt(), &params.clone().with_change(None)).expect("shapes");
    let fingerprints = orchard_fingerprints(shaped.pczt().clone());
    assert!(!fingerprints.is_empty());
    for fingerprint in fingerprints {
        assert_eq!(fingerprint, Some(SEED_FINGERPRINT));
    }

    // So does the change output.
    let fixture = fixture_v5_transparent_only();
    let change = fixture.change_info().expect("output 0 is the change");
    let shaped = shape_for_device(
        fixture.pczt(),
        &params.clone().with_change(Some(change.clone())),
    )
    .expect("shapes");
    assert_eq!(
        transparent_output_fingerprint(shaped.pczt().clone(), change.output_index()),
        Some(SEED_FINGERPRINT)
    );

    // The wire is another matter: the device never reads the fingerprint,
    // and it is a stable identifier of the seed, so every record streams
    // zeros in its place — inputs, the change output and the actions alike.
    let plan = build_plan(shaped.pczt()).expect("plans");
    let stream = plan.stream();
    for input in stream.transparent_inputs() {
        assert_eq!(*input.derivation().seed_fingerprint(), [0u8; 32]);
    }
    let derivation = stream.transparent_outputs()[change.output_index()]
        .derivation()
        .expect("the change output is marked");
    assert_eq!(*derivation.seed_fingerprint(), [0u8; 32]);
    let fixture = fixture_v5_transparent_to_orchard();
    let shaped = shape_for_device(fixture.pczt(), &params.with_change(None)).expect("shapes");
    let plan = build_plan(shaped.pczt()).expect("plans");
    for action in plan.stream().orchard_actions() {
        assert_eq!(*action.zip32_derivation().seed_fingerprint(), [0u8; 32]);
    }
}

/// A supplied fingerprint that contradicts the one on the transparent inputs
/// is refused, as one contradicting a shielded action's is.
#[test]
fn shaping_rejects_a_supplied_fingerprint_the_inputs_contradict() {
    let fixture = fixture_v5_transparent_to_orchard();

    let err = shape_for_device(
        fixture.pczt(),
        &ShapeParams::new(FIXTURE_COIN_TYPE, account())
            .with_seed_fingerprint(Some([0x11; 32]))
            .with_change(None),
    )
    .expect_err("the inputs name another seed");
    assert_eq!(err, ShapeError::NonUniformSeedFingerprint);
}

/// The Ironwood half of the path survey: an Ironwood action stamped with
/// another account's path is refused the way an Orchard one is.
#[test]
fn shaping_rejects_a_non_uniform_ironwood_derivation_path() {
    let fixture = fixture_v6_ironwood();
    let foreign = vec![32 | HARDENED, FIXTURE_COIN_TYPE | HARDENED, 7 | HARDENED];
    let pczt = Updater::new(fixture.pczt())
        .update_ironwood_with(|mut updater| {
            let derivation = orchard::pczt::Zip32Derivation::parse(SEED_FINGERPRINT, foreign)
                .expect("valid derivation");
            updater.update_action_with(0, |mut action| {
                action.set_spend_zip32_derivation(derivation);
                Ok(())
            })
        })
        .expect("updater")
        .finish();

    let err = shape_for_device(
        pczt,
        &ShapeParams::new(FIXTURE_COIN_TYPE, account())
            .with_seed_fingerprint(Some(SEED_FINGERPRINT))
            .with_change(None),
    )
    .expect_err("a foreign account path must be refused");
    assert_eq!(
        err,
        ShapeError::NonUniformPath {
            section: Section::Ironwood,
            index: 0,
        }
    );
}

/// The parameter checks that come before any survey: a hardened coin type,
/// a change index past the bundle, and a change output that is not P2PKH.
#[test]
fn shaping_refuses_bad_parameters_before_touching_the_pczt() {
    // A hardened coin type, on a PCZT that carries the same value, so that
    // the mismatch check is not what refuses it.
    let hardened = patch_json(fixture_v5_orchard_spend().pczt(), |v| {
        v["global"]["coin_type"] = serde_json::json!(FIXTURE_COIN_TYPE | HARDENED);
    });
    let err = shape_for_device(
        hardened,
        &ShapeParams::new(FIXTURE_COIN_TYPE | HARDENED, account()).with_change(None),
    )
    .expect_err("a hardened coin type");
    assert!(
        matches!(
            err,
            ShapeError::IndexMustBeUnhardened {
                what: "coin_type",
                ..
            }
        ),
        "{err:?}"
    );

    // A change index past the end of the bundle.
    let fixture = fixture_v5_orchard_spend();
    let err = shape_for_device(
        fixture.pczt(),
        &ShapeParams::new(FIXTURE_COIN_TYPE, account())
            .with_change(Some(change_info_at(fixture_change_index(), 5))),
    )
    .expect_err("output 5 of 1");
    assert_eq!(
        err,
        ShapeError::ChangeOutputIndexOutOfRange {
            index: 5,
            outputs: 1,
        }
    );

    // A change output whose script is P2SH.
    let mut p2sh = vec![0xA9, 0x14];
    p2sh.extend_from_slice(&[0x42; 20]);
    p2sh.push(0x87);
    let not_p2pkh = patch_json(fixture.pczt(), |v| {
        v["transparent"]["outputs"][0]["script_pubkey"] = serde_json::json!(p2sh);
    });
    let err = shape_for_device(
        not_p2pkh,
        &ShapeParams::new(FIXTURE_COIN_TYPE, account())
            .with_change(Some(change_info_at(fixture_change_index(), 0))),
    )
    .expect_err("a P2SH change output");
    assert_eq!(err, ShapeError::ChangeOutputNotP2pkh { index: 0 });
}

/// The `pczt`-pin tripwire: a PCZT whose content the encoding the device
/// assumes for its transaction version cannot carry — here, a V5 header over
/// Ironwood actions, which only PCZT v2 holds — is refused rather than
/// streamed under a header the device would read the other way.
#[test]
fn shaping_refuses_a_pczt_the_devices_encoding_cannot_carry() {
    let v5_over_ironwood = patch_json(fixture_v6_ironwood_spend().pczt(), |v| {
        v["global"]["tx_version"] = serde_json::json!(pczt_ledger::limits::V5_TX_VERSION);
        v["global"]["version_group_id"] =
            serde_json::json!(pczt_ledger::limits::V5_VERSION_GROUP_ID);
    });
    let err = shape_for_device(
        v5_over_ironwood,
        &ShapeParams::new(FIXTURE_COIN_TYPE, account())
            .with_seed_fingerprint(Some(SEED_FINGERPRINT))
            .with_change(None),
    )
    .expect_err("Ironwood content under a V5 header");
    assert_eq!(
        err,
        ShapeError::EncodingVersionMismatch {
            got: 2,
            expected: 1,
        }
    );
}

// ---------------------------------------------------------------------------
// validate_for_ledger
// ---------------------------------------------------------------------------

/// A PCZT whose spends carry no `fvk` — what `redact_pczt_for_batch_signer`
/// produces — is refused before the first APDU.
///
/// The `pczt` Signer role needs the field before it will accept the device's
/// signature, and nothing on the wire does; without this gate the ceremony
/// would run to completion, the user would approve, and `finish()` would fail
/// with `OrchardVerify(MissingFullViewingKey)`.
#[test]
fn a_pczt_without_spend_fvk_is_refused_before_the_first_apdu() {
    let fixture = fixture_v5_orchard_spend();
    let real_spends = build_plan(&fixture.pczt())
        .expect("the intact fixture plans")
        .orchard_real_spends()
        .to_vec();
    assert!(!real_spends.is_empty(), "the fixture has a real spend");

    let stripped = Redactor::new(fixture.pczt())
        .redact_orchard_with(|mut r| r.redact_actions(|mut a| a.clear_spend_fvk()))
        .finish();

    match build_plan(&stripped).expect_err("the plan refuses it") {
        PlanError::MissingSpendFvk {
            section: Section::Orchard,
            index,
        } => assert!(
            real_spends.contains(&index),
            "the refusal names a real spend, not a padding dummy"
        ),
        other => panic!("unexpected error: {other:?}"),
    }

    let bytes = stripped.serialize().expect("serializes");
    let err = LedgerSignSession::new(&bytes, caps(), fixture.params(fixture.change_info()))
        .expect_err("the session refuses it before any APDU is queued");
    assert!(
        matches!(
            &err,
            SessionError::Validation(v) if matches!(
                v.as_slice(),
                [LedgerViolation::Plan(PlanError::MissingSpendFvk { .. })]
            )
        ),
        "unexpected error: {err}"
    );
}

/// Rewrites the `consensus_branch_id` of a serialized PCZT.
///
/// The `Global` fields follow the 8-byte PCZT header as postcard varints, in
/// the order `tx_version`, `version_group_id`, `consensus_branch_id`; the third
/// is spliced out and re-encoded. This is the one edit the `pczt` Creator never
/// makes, and the roles offer no API for, which is why it is done on bytes.
fn patch_branch_id(mut bytes: Vec<u8>, branch_id: u32) -> Vec<u8> {
    const HEADER_LEN: usize = 8;

    fn read_varint(bytes: &[u8], mut at: usize) -> usize {
        while bytes[at] & 0x80 != 0 {
            at += 1;
        }
        at + 1
    }

    fn write_varint(mut value: u32) -> Vec<u8> {
        let mut out = Vec::new();
        while value >= 0x80 {
            out.push((value as u8 & 0x7F) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
        out
    }

    let after_tx_version = read_varint(&bytes, HEADER_LEN);
    let after_version_group_id = read_varint(&bytes, after_tx_version);
    let after_branch_id = read_varint(&bytes, after_version_group_id);
    bytes.splice(
        after_version_group_id..after_branch_id,
        write_varint(branch_id),
    );
    bytes
}

/// `consensus_branch_id` is checked the way the `pczt` extractor checks it in
/// the return path, so a PCZT the extractor would refuse after the ceremony is
/// refused before the first APDU.
///
/// The load-bearing case is a v6 transaction tagged with an NU5–NU6.2 branch:
/// the device accepts and signs it, and `Signer::new` refuses it afterwards.
#[test]
fn a_branch_id_the_extractor_refuses_is_refused_before_the_first_apdu() {
    let nu6_2 = u32::from(BranchId::Nu6_2);
    let nu6_3 = u32::from(BranchId::Nu6_3);
    let canopy = u32::from(BranchId::Canopy);
    let unknown = 0xDEAD_BEEFu32;

    let fixture = fixture_v6_ironwood();
    let patched = patch_branch_id(fixture.bytes.clone(), nu6_2);
    let pczt = Pczt::parse(&patched).expect("still parses");
    assert_eq!(*pczt.global().consensus_branch_id(), nu6_2);
    assert_eq!(
        build_plan(&pczt).expect_err("refused"),
        PlanError::BranchIdVersionMismatch {
            got: nu6_2,
            tx_version: 6,
        },
    );
    let err = LedgerSignSession::new(&patched, caps(), fixture.params(None))
        .expect_err("the session refuses it before any APDU is queued");
    assert!(
        matches!(
            &err,
            SessionError::Validation(v) if matches!(
                v.as_slice(),
                [LedgerViolation::Plan(PlanError::BranchIdVersionMismatch { .. })]
            )
        ),
        "unexpected error: {err}"
    );

    // Branch ids no extractor accepts get a first-class error each, ahead of
    // the Verifier's incidental `OrchardParse("UnsupportedConsensusBranchId")`.
    let fixture = fixture_v5_transparent_to_orchard();
    let pczt = Pczt::parse(&patch_branch_id(fixture.bytes.clone(), canopy)).expect("parses");
    assert_eq!(
        build_plan(&pczt).expect_err("refused"),
        PlanError::BranchIdPredatesV5 { got: canopy },
    );
    let pczt = Pczt::parse(&patch_branch_id(fixture.bytes.clone(), unknown)).expect("parses");
    assert_eq!(
        build_plan(&pczt).expect_err("refused"),
        PlanError::UnknownBranchId { got: unknown },
    );

    // A v5 transaction under NU6.3 is one the extractor accepts at the branch
    // check. What refuses this one is the Orchard pool's post-NU6.3 rule,
    // which the retag brings with it: the bundle becomes `orchard_v3`, and
    // its padding pairs a dummy spend with an output to someone else.
    let pczt = Pczt::parse(&patch_branch_id(fixture.bytes.clone(), nu6_3)).expect("parses");
    let global = pczt_ledger::plan::read_global(&pczt).expect("the branch is known");
    pczt_ledger::plan::check_branch_id(&global, TxFormat::V5)
        .expect("a v5 transaction under NU6.3 passes the extractor's branch check");
    assert_eq!(
        build_plan(&pczt).expect_err("refused"),
        PlanError::CrossAddressTransferDisallowed {
            section: Section::Orchard
        },
    );
}

/// The app has no PCZT Sapling command at all, so a Sapling bundle would be
/// invisible to both the review and the signature.
#[test]
fn validate_rejects_sapling_content() {
    let params = v5_network();
    let t = transparent_keys(&params);

    let extsk = sapling_crypto::zip32::ExtendedSpendingKey::master(&SEED);
    let (_, sapling_addr) = extsk.default_address();

    let mut builder = Builder::new(
        params,
        TARGET_HEIGHT.into(),
        BuildConfig::Standard {
            sapling_anchor: Some(sapling_crypto::Anchor::empty_tree()),
            orchard_anchor: None,
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_transparent_p2pkh_input(
            t.pubkey,
            OutPoint::new([1u8; 32], 1),
            TxOut::new(
                Zatoshis::const_from_u64(1_000_000),
                t.address.script().into(),
            ),
        )
        .expect("transparent input");
    builder
        .add_sapling_output::<zip317::FeeRule>(
            None,
            sapling_addr,
            Zatoshis::const_from_u64(985_000),
            MemoBytes::empty(),
        )
        .expect("sapling output");

    let parts = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt");
    let bytes = finish_fixture(parts, Some(t.pubkey.serialize()));
    let pczt = Pczt::parse(&bytes).expect("parses");

    assert!(pczt.has_data_in_pool(zcash_protocol::PoolType::SAPLING));
    let err =
        validate_for_ledger(&pczt, &DeviceBounds::V3_9_2).expect_err("Sapling must be refused");
    assert_eq!(err, vec![LedgerViolation::SaplingPresent]);

    // The guard is the plan's, so a caller that goes straight to `build_plan`
    // and `to_apdus` cannot stream a transaction with the bundle dropped.
    assert_eq!(
        build_plan(&pczt).expect_err("the plan refuses it too"),
        PlanError::SaplingPresent
    );
}

/// A V5 PCZT whose Ironwood bundle carries actions is refused, everywhere.
///
/// The Ironwood pool exists only from V6, so a V5 stream never sends
/// `PCZT_IRONWOOD_ACTION`: the actions would be dropped from the plan and
/// therefore from everything the user reviews and the device signs — the same
/// hazard [`LedgerViolation::SaplingPresent`] refuses for the Sapling pool. The
/// guard lives in [`build_plan`], so the standalone validators and the session
/// all inherit it.
#[test]
fn ironwood_actions_on_a_v5_transaction_are_refused() {
    let fixture = fixture_v6_ironwood_spend();

    // As built, a V6 transaction with a real Ironwood spend.
    let v6 = build_plan(&fixture.pczt()).expect("a V6 PCZT plans");
    assert!(v6.format() == TxFormat::V6);
    let actions = v6
        .stream()
        .ironwood_actions()
        .expect("V6 carries the Ironwood command")
        .len();
    assert!(
        actions >= 2,
        "a spend and two outputs pad to at least two actions"
    );
    assert_eq!(v6.ironwood_real_spends().len(), 1);

    // Retagged as V5 with the Ironwood bundle left in place.
    let retagged = retag_as_v5(fixture.pczt());
    assert!(retagged.has_data_in_pool(zcash_protocol::PoolType::IRONWOOD));
    assert_eq!(
        build_plan(&retagged),
        Err(pczt_ledger::plan::PlanError::IronwoodOnV5 { actions }),
    );
    assert_eq!(
        validate_for_ledger(&retagged, &DeviceBounds::V3_9_3),
        Err(vec![LedgerViolation::Plan(
            pczt_ledger::plan::PlanError::IronwoodOnV5 { actions }
        )]),
    );

    let bytes = retagged.serialize().expect("serializes");
    let err = LedgerSignSession::new(&bytes, caps(), fixture.params(None))
        .expect_err("a session must not be built over dropped actions");
    assert!(
        matches!(
            err,
            SessionError::Validation(ref v)
                if v == &[LedgerViolation::Plan(
                    pczt_ledger::plan::PlanError::IronwoodOnV5 { actions }
                )]
        ),
        "unexpected error: {err:?}"
    );
}

/// A v3.9.2 app holds at most 10 Orchard actions; a v3.9.3 one holds 32. The
/// same PCZT is refused against the first set of bounds and accepted against
/// the second, which is the whole of what version gating has to do.
///
/// `src/consts.rs` @ `0e048bb` vs `22dc385`.
#[test]
fn the_orchard_action_bound_moves_with_the_app_version() {
    let pczt = fixture_v5_eleven_orchard_actions().pczt();

    let violations = validate_for_ledger(&pczt, &DeviceBounds::V3_9_2)
        .expect_err("11 actions must be refused by a v3.9.2 app");
    assert!(
        violations.iter().any(|v| matches!(
            v,
            LedgerViolation::Limit(LimitViolation::TooManyRecords {
                section: Section::Orchard,
                got: 11,
                max: 10
            })
        )),
        "unexpected violations: {violations:?}"
    );

    validate_for_ledger(&pczt, &DeviceBounds::V3_9_3)
        .expect("11 actions are within a v3.9.3 app's bound of 32");
}

/// A session for an app version above the newer firmware pin refuses to build
/// unless the caller says which bounds that version is held to. Nothing is
/// chosen silently, and nothing is more permissive by default: the default,
/// no choice at all, is a refusal before the first APDU.
#[test]
fn an_unrecognised_app_version_needs_an_explicit_choice_of_bounds() {
    let fixture = fixture_v5_transparent_only();
    // One patch above the newer pin: `DeviceCaps::bounds` answers `None`.
    let newer = DeviceCaps::from_version(3, 9, 4);
    assert_eq!(newer.bounds(), None);

    let params = fixture.params(fixture.change_info());
    assert_eq!(params.unknown_version_bounds(), None);
    assert_eq!(
        LedgerSignSession::new(&fixture.bytes, newer, params.clone())
            .expect_err("no bounds were chosen for an unrecognised version"),
        SessionError::UnknownDeviceVersion { version: (3, 9, 4) }
    );

    // Either choice builds a session; each is the caller's, and made by name.
    for bounds in [
        DeviceBounds::MOST_RESTRICTIVE,
        DeviceBounds::MOST_PERMISSIVE,
    ] {
        let chosen = params.clone().with_unknown_version_bounds(Some(bounds));
        assert_eq!(chosen.unknown_version_bounds(), Some(bounds));
        LedgerSignSession::new(&fixture.bytes, newer, chosen)
            .expect("the caller chose the bounds for this version");
    }

    // A version the crate does know needs no choice, and ignores one.
    LedgerSignSession::new(&fixture.bytes, caps(), params)
        .expect("a recognised version derives its own bounds");
}

/// The bounds are derived from the version the device reported, and a version
/// above the newer pin gets no set at all rather than a silently chosen one.
#[test]
fn device_bounds_are_derived_from_the_reported_version() {
    assert_eq!(
        DeviceCaps::from_version(3, 9, 2).bounds(),
        Some(DeviceBounds::V3_9_2)
    );
    assert_eq!(
        DeviceCaps::from_version(3, 9, 3).bounds(),
        Some(DeviceBounds::V3_9_3)
    );
    // A version above the pin is one this crate has not been checked against:
    // it is not assumed to keep the raised bounds, and it is not assumed into
    // the strictest set either. The caller makes that choice.
    for v in [(3, 9, 4), (3, 10, 0), (4, 0, 0)] {
        assert_eq!(
            DeviceCaps::from_version(v.0, v.1, v.2).bounds(),
            None,
            "v{}.{}.{}",
            v.0,
            v.1,
            v.2
        );
    }
    // Everything older is the pre-3.9.3 set.
    for v in [(3, 9, 0), (3, 8, 9), (3, 6, 0), (2, 0, 0)] {
        assert_eq!(
            DeviceCaps::from_version(v.0, v.1, v.2).bounds(),
            Some(DeviceBounds::V3_9_2),
            "v{}.{}.{}",
            v.0,
            v.1,
            v.2
        );
    }
    // `MOST_RESTRICTIVE`, the conservative choice for such a version, is the
    // strictest combination of the known sets: no count and no budget above
    // either set's.
    for known in [DeviceBounds::V3_9_2, DeviceBounds::V3_9_3] {
        let strictest = DeviceBounds::MOST_RESTRICTIVE;
        assert!(strictest.transparent_inputs() <= known.transparent_inputs());
        assert!(strictest.transparent_outputs() <= known.transparent_outputs());
        assert!(strictest.orchard_actions() <= known.orchard_actions());
        assert!(strictest.ironwood_actions() <= known.ironwood_actions());
        assert!(strictest.displayed_shielded_outputs() <= known.displayed_shielded_outputs());
        assert!(strictest.retained_memo_bytes() <= known.retained_memo_bytes());
    }

    // The transparent-output bound did not move; the other three did.
    assert_eq!(
        DeviceBounds::V3_9_2.transparent_outputs(),
        DeviceBounds::V3_9_3.transparent_outputs()
    );
    assert_eq!(DeviceBounds::V3_9_3.transparent_inputs(), 32);
    assert_eq!(DeviceBounds::V3_9_3.orchard_actions(), 32);
    assert_eq!(DeviceBounds::V3_9_3.ironwood_actions(), 32);
}

/// A session built for a v3.9.2 device refuses the eleven-action PCZT; the
/// same bytes against a v3.9.3 device produce a streamable session.
#[test]
fn a_session_applies_the_bounds_of_the_device_it_was_built_for() {
    let fixture = fixture_v5_eleven_orchard_actions();

    let err = LedgerSignSession::new(
        &fixture.bytes,
        DeviceCaps::from_version(3, 9, 2),
        fixture.params(None),
    )
    .expect_err("a v3.9.2 device cannot take eleven actions");
    match err {
        SessionError::Validation(violations) => assert!(
            violations.iter().any(|v| matches!(
                v,
                LedgerViolation::Limit(LimitViolation::TooManyRecords {
                    section: Section::Orchard,
                    got: 11,
                    max: 10
                })
            )),
            "unexpected violations: {violations:?}"
        ),
        other => panic!("unexpected error: {other:?}"),
    }

    let session = LedgerSignSession::new(
        &fixture.bytes,
        DeviceCaps::from_version(3, 9, 3),
        fixture.params(None),
    )
    .expect("a v3.9.3 device takes eleven actions");
    assert_eq!(session.plan().stream().orchard_actions().len(), 11);
}

/// The shielded displayed-output budget
/// (`MAX_PCZT_SHIELDED_DISPLAYED_OUTPUTS_NUMBER = 4`, `src/consts.rs` @
/// `22dc385`), applied on every version.
///
/// A v3.9.3 app refuses the fifth displayed output mid-stream, with
/// `0x6A84`: exactly the kind of late refusal the host is here to pull
/// forward. A v3.9.2 app has no such budget and no such refusal — it holds
/// every displayed output for the review until the heap gives out, and then
/// exits — so the host holds it to the same budget.
#[test]
fn the_shielded_display_budget_is_counted_on_every_version() {
    let five = fixture_v5_five_orchard_recipients().pczt();
    let plan = build_plan(&five).expect("plans");

    // Five nonzero-value outputs; the bundle is unpadded, so there are no
    // dummies to discount.
    assert_eq!(plan.stream().orchard_actions().len(), 5);
    assert_eq!(plan.displayed_shielded_outputs(), 5);

    for bounds in [
        DeviceBounds::V3_9_2,
        DeviceBounds::V3_9_3,
        DeviceBounds::MOST_RESTRICTIVE,
        DeviceBounds::MOST_PERMISSIVE,
    ] {
        let violations = validate_for_ledger(&five, &bounds)
            .expect_err("every app is held to four displayed outputs");
        assert!(
            violations.iter().any(|v| matches!(
                v,
                LedgerViolation::Limit(LimitViolation::TooManyDisplayedShieldedOutputs {
                    got: 5,
                    max: 4,
                    // No viewing key was supplied, so the count is over the
                    // nonzero outputs, not the device's own.
                    exact: false,
                })
            )),
            "{bounds:?}: unexpected violations: {violations:?}"
        );
    }
}

/// Padding dummies carry a zero-valued output and are not displayed, so a
/// bundle of eleven actions showing one recipient sits well inside the budget.
///
/// This is the half of the approximation that has to hold for the raised action
/// bounds to be usable at all: the firmware raised them precisely because
/// "what an action costs is a signing record and one parse; what the *review*
/// costs is bounded separately".
#[test]
fn dummy_outputs_do_not_claim_a_display_slot() {
    let eleven = fixture_v5_eleven_orchard_actions().pczt();
    let plan = build_plan(&eleven).expect("plans");

    assert_eq!(plan.stream().orchard_actions().len(), 11);
    assert_eq!(plan.displayed_shielded_outputs(), 1);
    for (i, action) in plan.stream().orchard_actions().iter().enumerate() {
        if i != plan
            .stream()
            .orchard_actions()
            .iter()
            .position(|a| a.value() != 0)
            .expect("one real output")
        {
            assert_eq!(action.value(), 0, "action {i} should be a padding dummy");
        }
    }

    validate_for_ledger(&eleven, &DeviceBounds::V3_9_3)
        .expect("eleven actions showing one recipient are within both v3.9.3 bounds");
}

/// With the account's viewing key, the count is the device's: change is
/// discounted, and a payment to the account's *own external* address is not.
///
/// [`fixture_v5_transparent_to_orchard`] holds exactly that pair — one output
/// to `Scope::External` at diversifier 0, one to `Scope::Internal` at
/// diversifier 0, both of the same account, both nonzero — so the two rules can
/// only be told apart by the scope.
#[test]
fn the_viewing_key_discounts_change_and_keeps_a_self_send() {
    let pczt = fixture_v5_transparent_to_orchard().pczt();

    // Without a key: both nonzero outputs are counted, and the plan says so.
    let blind = build_plan(&pczt).expect("plans");
    assert_eq!(blind.displayed_shielded_outputs(), 2);
    assert_eq!(blind.shielded_change_outputs(), None);
    assert!(!blind.displayed_count_is_exact());

    // With it: the internal-scope output is change, the external-scope one is a
    // self-send the device still displays.
    let exact = build_plan_with_keys(&pczt, Some(&canned_viewing_keys())).expect("plans");
    assert_eq!(exact.displayed_shielded_outputs(), 1);
    assert_eq!(exact.shielded_change_outputs(), Some(1));
    assert!(exact.displayed_count_is_exact());
    assert_eq!(exact.stream().orchard_actions().len(), 2);
}

/// A key belonging to a different account classifies nothing as change, so the
/// count falls back to what the value-only rule produces.
///
/// This is what makes the exact count *exact for this account* rather than a
/// generic "is this change" oracle: the keys the caller supplies are the keys
/// the device will derive, or the answer is wrong in the safe direction.
#[test]
fn another_accounts_viewing_key_discounts_nothing() {
    // Two zero-valued padding outputs and no real spend: another account's
    // key opens nothing, which for a zero-valued output means "a dummy", and
    // there is no spend for the key binding to catch. Nothing is discounted.
    let pczt = fixture_v5_two_dummy_outputs().pczt();
    let plan = build_plan_with_keys(&pczt, Some(&seed_viewing_keys())).expect("plans");
    assert_eq!(plan.displayed_shielded_outputs(), 0);
    assert_eq!(plan.shielded_change_outputs(), Some(0));
}

/// A nonzero output that opens under neither of the account's keys is the
/// device's fourth trial step — a refusal — and with the keys the host makes
/// the same call first. Two ways to build one: a PCZT for another account
/// whose spends name no key (a transparent-to-shielded send, which the
/// spend-side binding cannot catch), and an output built with no outgoing
/// viewing key. Without the keys both stream, counted as displayed.
#[test]
fn an_output_that_opens_under_neither_key_is_refused_with_keys() {
    let for_another_account = fixture_v5_transparent_to_orchard().pczt();
    let err = build_plan_with_keys(&for_another_account, Some(&seed_viewing_keys()))
        .expect_err("another account's key opens neither trial");
    assert!(
        matches!(
            err,
            PlanError::UndecryptableOutput {
                section: Section::Orchard,
                ..
            }
        ),
        "{err:?}"
    );
    build_plan_with_keys(&for_another_account, Some(&canned_viewing_keys()))
        .expect("the account's own key opens the outputs");
    let blind = build_plan(&for_another_account).expect("without keys the nonzero outputs count");
    assert_eq!(blind.displayed_shielded_outputs(), 2);

    let without_ovk = fixture_v5_orchard_output_without_ovk();
    let err = build_plan_with_keys(&without_ovk.pczt(), Some(&canned_viewing_keys()))
        .expect_err("no key opens an output built without an OVK");
    assert!(
        matches!(
            err,
            PlanError::UndecryptableOutput {
                section: Section::Orchard,
                ..
            }
        ),
        "{err:?}"
    );
    let err = LedgerSignSession::new(
        &without_ovk.bytes,
        caps(),
        without_ovk.params_with_keys(None, canned_viewing_keys()),
    )
    .expect_err("the session refuses it before any APDU is queued");
    assert!(
        matches!(
            &err,
            SessionError::Validation(v) if matches!(
                v.as_slice(),
                [LedgerViolation::Plan(PlanError::UndecryptableOutput { .. })]
            )
        ),
        "{err}"
    );
    LedgerSignSession::new(&without_ovk.bytes, caps(), without_ovk.params(None))
        .expect("without keys the host cannot tell, and streams it");
}

/// v3.9.3's memo retention budget: 1024 bytes across the displayed outputs,
/// each text memo kept while it fits, otherwise hashed at 64 bytes, and the
/// output refused when even that does not fit. With the account's keys the
/// host runs the same accounting first, and holds a v3.9.2 app — which keeps
/// every displayed memo with no bound but the heap — to the same budget;
/// without the keys there is nothing to count.
#[test]
fn the_memo_retention_budget_is_counted_on_every_version() {
    let full_text = MemoBytes::from_bytes(&[b'm'; 512]).expect("a full text memo");
    let keys = canned_viewing_keys();

    // Three full text memos: the first two fill the budget, the third fits
    // neither as text nor as a hash.
    let three = orchard_output_fixture_with_memos(vec![full_text.clone(); 3], 380_000);
    let plan = build_plan_with_keys(&three.pczt(), Some(&keys)).expect("plans");
    assert_eq!(plan.displayed_memos().map(<[_]>::len), Some(3));
    let violations = validate_plan(&plan, &DeviceBounds::V3_9_3)
        .expect_err("the third memo does not fit on a v3.9.3 app");
    assert!(
        violations.iter().any(|v| matches!(
            v,
            LimitViolation::MemoRetentionBudgetExceeded {
                section: Section::Orchard,
                max: 1024,
                ..
            }
        )),
        "{violations:?}"
    );
    validate_plan(&plan, &DeviceBounds::V3_9_2)
        .expect_err("a v3.9.2 app is held to the same budget");
    let blind = build_plan(&three.pczt()).expect("plans without keys");
    assert!(blind.displayed_memos().is_none());
    validate_plan(&blind, &DeviceBounds::V3_9_3).expect("without keys the memos are unknown");

    let err = LedgerSignSession::new(
        &three.bytes,
        DeviceCaps::from_version(3, 9, 3),
        three.params_with_keys(None, keys.clone()),
    )
    .expect_err("the session refuses it before any APDU is queued");
    assert!(
        matches!(
            &err,
            SessionError::Validation(v) if v.iter().any(|x| matches!(
                x,
                LedgerViolation::Limit(LimitViolation::MemoRetentionBudgetExceeded { .. })
            ))
        ),
        "{err}"
    );

    // Two full text memos fill the budget exactly.
    let two = orchard_output_fixture_with_memos(vec![full_text; 2], 572_500);
    let plan = build_plan_with_keys(&two.pczt(), Some(&keys)).expect("plans");
    validate_plan(&plan, &DeviceBounds::V3_9_3).expect("two full memos fit exactly");

    // Three binary memos are hashed at 64 bytes each, well within it.
    let binary = MemoBytes::from_bytes(&[0xFF; 512]).expect("an arbitrary memo");
    let hashed = orchard_output_fixture_with_memos(vec![binary; 3], 380_000);
    let plan = build_plan_with_keys(&hashed.pczt(), Some(&keys)).expect("plans");
    assert!(plan
        .displayed_memos()
        .expect("counted")
        .iter()
        .all(|(_, _, memo)| *memo == pczt_ledger::plan::MemoDisplay::Hashed));
    validate_plan(&plan, &DeviceBounds::V3_9_3).expect("three hashes fit");
}

/// The caller's viewing key is bound to the PCZT at every real spend: a key
/// for another account is refused rather than silently disabling the change
/// and display accounting while the plan reports its counts as exact.
#[test]
fn a_viewing_key_for_another_account_is_refused() {
    // Every output is a zero-valued dummy, so the spend is the only place the
    // wrong key can be caught, whichever way the builder ordered the actions.
    let fixture = fixture_v5_orchard_spend_to_transparent();
    build_plan_with_keys(&fixture.pczt(), Some(&canned_viewing_keys()))
        .expect("the account's own key is bound");

    let err = build_plan_with_keys(&fixture.pczt(), Some(&seed_viewing_keys()))
        .expect_err("another account's key is refused");
    assert!(
        matches!(
            err,
            PlanError::ViewingKeyMismatch {
                section: Section::Orchard,
                ..
            }
        ),
        "{err:?}"
    );

    let err = LedgerSignSession::new(
        &fixture.bytes,
        caps(),
        fixture.params_with_keys(None, seed_viewing_keys()),
    )
    .expect_err("the session refuses it before any APDU is queued");
    assert!(
        matches!(
            &err,
            SessionError::Validation(v) if matches!(
                v.as_slice(),
                [LedgerViolation::Plan(PlanError::ViewingKeyMismatch { .. })]
            )
        ),
        "{err}"
    );
}

/// Split change: one recipient plus four change notes — five nonzero outputs,
/// which the value-only count reads as five displayed against a budget of
/// four. The device displays one. With the account's key the host says one
/// too.
#[test]
fn split_change_is_counted_the_way_the_device_counts_it() {
    let pczt = fixture_v5_seed_orchard_split_change(4).pczt();
    let keys = seed_viewing_keys();

    let blind = build_plan(&pczt).expect("plans");
    assert_eq!(blind.stream().orchard_actions().len(), 5);
    assert_eq!(blind.displayed_shielded_outputs(), 5);

    let exact = build_plan_with_keys(&pczt, Some(&keys)).expect("plans");
    assert_eq!(exact.displayed_shielded_outputs(), 1);
    assert_eq!(exact.shielded_change_outputs(), Some(4));

    // Blind, the display budget refuses it, and says the count is not exact.
    let violations = validate_for_ledger(&pczt, &DeviceBounds::V3_9_3)
        .expect_err("five nonzero outputs are over the blind budget");
    assert!(
        violations.iter().any(|v| matches!(
            v,
            LedgerViolation::Limit(LimitViolation::TooManyDisplayedShieldedOutputs {
                got: 5,
                max: 4,
                exact: false,
            })
        )),
        "unexpected violations: {violations:?}"
    );

    // With the key, the display budget is no longer the objection.
    let violations = validate_for_ledger_with_keys(&pczt, &DeviceBounds::V3_9_3, Some(&keys))
        .expect_err("but the device takes one change output, not four");
    assert!(
        !violations.iter().any(|v| matches!(
            v,
            LedgerViolation::Limit(LimitViolation::TooManyDisplayedShieldedOutputs { .. })
        )),
        "the display budget should no longer be exceeded: {violations:?}"
    );
}

/// The device tolerates one change output for the whole transaction, across
/// every pool (`is_change_found`, `src/parser/pczt/*.rs` @ `22dc385`), and
/// refuses the second mid-stream with `"Multiple change outputs detected"`.
///
/// Counting the change outputs is the same work the display count already does,
/// so pulling that refusal forward costs nothing — and it is the refusal a
/// split-change transaction actually meets once the display count stops being
/// the first objection.
#[test]
fn more_than_one_change_output_is_refused_before_the_first_apdu() {
    let keys = seed_viewing_keys();

    // One change note: fine on every version.
    let one = fixture_v5_seed_orchard_split_change(1).pczt();
    let plan = build_plan_with_keys(&one, Some(&keys)).expect("plans");
    assert_eq!(plan.shielded_change_outputs(), Some(1));
    validate_for_ledger_with_keys(&one, &DeviceBounds::V3_9_3, Some(&keys))
        .expect("one change output is what the device expects");

    // Two: refused, on the older bounds too, since this is not a budget any
    // firmware raised.
    let two = fixture_v5_seed_orchard_split_change(2).pczt();
    for bounds in [DeviceBounds::V3_9_2, DeviceBounds::V3_9_3] {
        let violations = validate_for_ledger_with_keys(&two, &bounds, Some(&keys))
            .expect_err("two change outputs are one too many");
        assert!(
            violations.iter().any(|v| matches!(
                v,
                LedgerViolation::Limit(LimitViolation::MultipleChangeOutputs {
                    got: 2,
                    shielded: Some(2)
                })
            )),
            "unexpected violations: {violations:?}"
        );
    }

    // Without the key it cannot be seen at all, and is not guessed at.
    let plan = build_plan(&two).expect("plans");
    assert_eq!(plan.shielded_change_outputs(), None);
    validate_for_ledger(&two, &DeviceBounds::V3_9_3)
        .expect("blind, two change outputs are within the blind display budget");
}

/// A shielded change output and a transparent one are one too many *together*:
/// the device's counter is shared across the pools.
///
/// The transparent half needs no viewing key — an output is change to the
/// device exactly when it carries the `bip32_derivation` the shaping pass
/// stamps — so the session sees it only on the plan built after shaping, and
/// that is where it refuses: the pre-shaping pass counts one change output,
/// the post-shaping one two.
#[test]
fn shielded_and_transparent_change_together_are_refused() {
    let fixture = fixture_v5_seed_orchard_and_transparent_change(200_000);
    let keys = seed_viewing_keys();

    // Before shaping, only the shielded change note counts.
    let plan = build_plan_with_keys(&fixture.pczt(), Some(&keys)).expect("plans");
    assert_eq!(plan.shielded_change_outputs(), Some(1));
    assert_eq!(plan.stream().transparent_outputs().len(), 1);
    pczt_ledger::plan::validate_plan(&plan, &DeviceBounds::V3_9_3)
        .expect("one shielded change output and an unmarked transparent output");

    // The session marks the transparent output as change and then refuses.
    let err = LedgerSignSession::new(
        &fixture.bytes,
        DeviceCaps::from_version(3, 9, 3),
        fixture.params_with_keys(fixture.change_info(), keys),
    )
    .expect_err("shielded change plus transparent change is two");
    match err {
        SessionError::Validation(violations) => assert!(
            violations.iter().any(|v| matches!(
                v,
                LedgerViolation::Limit(LimitViolation::MultipleChangeOutputs {
                    got: 2,
                    shielded: Some(1)
                })
            )),
            "unexpected violations: {violations:?}"
        ),
        other => panic!("unexpected error: {other:?}"),
    }
}

/// Two *transparent* change outputs are refused with no viewing key at all.
///
/// The transparent half of the one-change rule needs no key — an output is
/// change to the device exactly when it carries a `bip32_derivation` — so it
/// must not sit behind the shielded half, which does. The configuration is
/// `viewing_keys: None`, `change: Some(0)`, and an output 1 that arrived
/// already carrying a compliant same-account derivation shaping leaves
/// untouched. Before shaping there is one change output; after it, two.
#[test]
fn two_transparent_change_outputs_are_refused_without_a_viewing_key() {
    let fixture = fixture_v5_orchard_spend_two_transparent_change();
    let change = fixture.change_info().expect("output 0 is the named change");

    // As it arrives, one change output: fine.
    validate_for_ledger(&fixture.pczt(), &DeviceBounds::V3_9_3)
        .expect("one pre-stamped change output is what the device expects");

    // Naming output 0 as change makes two.
    let err = LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(Some(change)))
        .expect_err("two transparent change outputs are one too many");
    match err {
        SessionError::Validation(violations) => assert_eq!(
            violations,
            vec![LedgerViolation::Limit(
                LimitViolation::MultipleChangeOutputs {
                    got: 2,
                    shielded: None,
                }
            )],
        ),
        other => panic!("unexpected error: {other:?}"),
    }
}

/// Two outputs to the change address with one of them named: the device would
/// display the other as a payment to a third party, so the session refuses,
/// whichever of the two the caller names.
#[test]
fn an_unmarked_output_paying_the_change_address_is_refused() {
    let fixture = fixture_v5_orchard_spend_change_paid_twice();

    // Unmarked, both are recipients to the device, and nothing is wrong yet.
    validate_for_ledger(&fixture.pczt(), &DeviceBounds::V3_9_3)
        .expect("two unmarked outputs are two recipients");

    for (named, other) in [(0, 1), (1, 0)] {
        let change = change_info_at(fixture_change_index(), named);
        let err = LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(Some(change)))
            .expect_err("the twin would be shown as a recipient");
        match err {
            SessionError::Validation(violations) => assert_eq!(
                violations,
                vec![LedgerViolation::Limit(
                    LimitViolation::UnmarkedChangeOutput {
                        change: named,
                        index: other,
                    }
                )],
            ),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

/// A zero-valued output the account's OVK opens takes a review slot.
///
/// The device runs the external-OVK trial *before* the zero-value dummy check,
/// so a memo-only output encrypted under the account's own OVK is displayed
/// and claims a slot. With the key, the host runs the same trial and counts
/// it: four recipients plus that output is five against a v3.9.3 budget of
/// four, refused before the first APDU rather than mid-stream with `0x6A84`.
/// The same output with no OVK opens under nothing, falls through to the
/// dummy check on the device, and takes no slot — and the host agrees.
///
/// Without the key neither can be told from a padding dummy, so the blind
/// count stays at four for both; that residual is documented, not hidden.
#[test]
fn a_zero_valued_output_under_the_accounts_ovk_claims_a_display_slot() {
    let keys = canned_viewing_keys();
    let ovk = orchard_keys().1.to_ovk(Scope::External);

    let memo_only = fixture_v5_four_recipients_plus_zero_valued(Some(ovk)).pczt();
    let blind = build_plan(&memo_only).expect("plans");
    assert_eq!(blind.stream().orchard_actions().len(), 5);
    assert_eq!(
        blind.displayed_shielded_outputs(),
        4,
        "blind, the zero-valued output is unseen"
    );
    validate_for_ledger(&memo_only, &DeviceBounds::V3_9_3)
        .expect("blind, four is within the budget: the residual the docs describe");

    let exact = build_plan_with_keys(&memo_only, Some(&keys)).expect("plans");
    assert_eq!(exact.displayed_shielded_outputs(), 5);
    assert_eq!(exact.shielded_change_outputs(), Some(0));
    let violations = validate_for_ledger_with_keys(&memo_only, &DeviceBounds::V3_9_3, Some(&keys))
        .expect_err("the fifth output claims the fifth slot on the device");
    assert_eq!(
        violations,
        vec![LedgerViolation::Limit(
            LimitViolation::TooManyDisplayedShieldedOutputs {
                got: 5,
                max: 4,
                exact: true,
            }
        )],
    );

    // No OVK: the device cannot open it, the dummy check passes, no slot.
    let unrecoverable = fixture_v5_four_recipients_plus_zero_valued(None).pczt();
    let exact = build_plan_with_keys(&unrecoverable, Some(&keys)).expect("plans");
    assert_eq!(exact.stream().orchard_actions().len(), 5);
    assert_eq!(exact.displayed_shielded_outputs(), 4);
    validate_for_ledger_with_keys(&unrecoverable, &DeviceBounds::V3_9_3, Some(&keys))
        .expect("an output no key opens takes no slot");
}

/// The host's change test is the device's first decryption trial, not an
/// address comparison. An output addressed to the account's internal address
/// whose ciphertext does not open under the internal IVK is not change to
/// the device — `try_decipher_current_orchard_output` (`22dc385`) goes on to
/// the OVK trial, then to the dummy check, then refuses — and the host says
/// the same instead of hiding it behind a count it reports as exact.
#[test]
fn a_change_output_whose_ciphertext_does_not_open_is_not_change() {
    let keys = seed_viewing_keys();
    let sk = SpendingKey::from_zip32_seed(&SEED, FIXTURE_COIN_TYPE, zip32::AccountId::ZERO)
        .expect("the fixture seed derives an Orchard spending key");
    let internal = FullViewingKey::from(&sk)
        .address_at(0u32, Scope::Internal)
        .to_raw_address_bytes();

    let pczt = fixture_v5_seed_orchard_split_change(1).pczt();
    let change = (0..pczt.orchard().actions().len())
        .find(|i| pczt.orchard().actions()[*i].output().recipient() == &Some(internal))
        .expect("the fixture pays one change note to the internal address");
    let exact = build_plan_with_keys(&pczt, Some(&keys)).expect("plans");
    assert_eq!(exact.shielded_change_outputs(), Some(1));
    assert_eq!(exact.displayed_shielded_outputs(), 1);

    // One bit of the compact ciphertext — the bytes both trials read —
    // flipped; the declared recipient, value and `cmx` are left alone, so
    // nothing but the trials can tell.
    let tampered = patch_json(pczt, |v| {
        let slot = &mut v["orchard"]["actions"][change]["output"]["enc_ciphertext"]["Encrypted"][0];
        let byte = slot.as_u64().expect("a byte");
        *slot = serde_json::json!(byte ^ 1);
    });
    assert_eq!(
        build_plan_with_keys(&tampered, Some(&keys)).expect_err("refused"),
        PlanError::UndecryptableOutput {
            section: Section::Orchard,
            index: change,
        }
    );
    // Blind, the nonzero output is counted as displayed and streamed for the
    // device to refuse; nothing is signed either way.
    let blind = build_plan(&tampered).expect("plans without keys");
    assert_eq!(blind.displayed_shielded_outputs(), 2);
    assert_eq!(blind.shielded_change_outputs(), None);
}

/// The zero-value rule survives the exact count: padding dummies are excluded
/// with a key just as they are without one, and the key does not turn one into
/// change.
#[test]
fn zero_valued_outputs_are_excluded_with_a_key_too() {
    let eleven = fixture_v5_eleven_orchard_actions().pczt();
    let plan = build_plan_with_keys(&eleven, Some(&canned_viewing_keys())).expect("plans");

    assert_eq!(plan.stream().orchard_actions().len(), 11);
    assert_eq!(plan.displayed_shielded_outputs(), 1);
    // The dummies are addressed to throwaway keys, not to this account's
    // internal scope, so none of them counts as change either.
    assert_eq!(plan.shielded_change_outputs(), Some(0));
}

/// The Ironwood pool is classified by the *Orchard* viewing key.
///
/// The device derives one `FullViewingKey` per account and hands it to
/// `OrchardDecipherKeys::from_fvk` for both pools
/// (`parse_orchard_action_metadata` / `parse_ironwood_action_metadata` @
/// `22dc385`); the UFVK a Ledger exports has no Ironwood item to derive
/// anything else from. This is the test that the host agrees.
#[test]
fn ironwood_change_is_recognised_by_the_orchard_viewing_key() {
    let pczt = fixture_v6_ironwood_with_change().pczt();
    let keys = canned_viewing_keys();

    let blind = build_plan(&pczt).expect("plans");
    assert_eq!(blind.displayed_shielded_outputs(), 2);

    let exact = build_plan_with_keys(&pczt, Some(&keys)).expect("plans");
    assert!(exact.format() == TxFormat::V6);
    assert_eq!(exact.displayed_shielded_outputs(), 1);
    assert_eq!(exact.shielded_change_outputs(), Some(1));
}

/// The two note-encryption domains differ only in the note-plaintext lead
/// byte they accept, and which of them an output was encrypted under is a
/// property of its *bundle*. So the `bundle_version` argument of
/// `recover_output` is the whole difference between recognising Ironwood
/// change and not: the account's key opens its Orchard output under an Orchard
/// bundle version and not under an Ironwood one, and its Ironwood output under
/// an Ironwood bundle version and not under an Orchard one. Passing the wrong
/// bundle's version is the silent `Ok(None)` the argument exists to make the
/// caller's responsibility, which is why every caller threads it from the
/// bundle it is walking.
///
/// Both of today's pools have a defined note encryption domain, so the other
/// pool's version is a *negative trial* and not a refusal: the wrong-domain
/// case is `Ok(None)`, and stays distinct from the
/// `Err(UnsupportedBundleVersion)` that means no trial was attempted at all.
#[test]
fn output_recovery_uses_the_domain_of_the_bundle_version() {
    let keys = canned_viewing_keys();

    let mut opened = 0;
    let mut opened_in_the_other_pool = 0;
    Verifier::new(fixture_v5_orchard_spend().pczt())
        .with_orchard::<(), _>(|bundle| {
            let bundle_version = *bundle.bundle_version();
            for action in bundle.actions() {
                assert_eq!(*action.output().note_version(), NoteVersion::V2);
                opened += usize::from(
                    keys.recover_output(action, bundle_version)
                        .expect("the Orchard pool has a note encryption domain")
                        .is_some(),
                );
                opened_in_the_other_pool += usize::from(
                    keys.recover_output(action, BundleVersion::ironwood_v3())
                        .expect("the Ironwood pool has one too, so this is a trial, not a refusal")
                        .is_some(),
                );
            }
            Ok(())
        })
        .expect("the Orchard bundle verifies");
    assert!(
        opened >= 1,
        "the account's Orchard output opens under the Orchard domain"
    );
    assert_eq!(
        opened_in_the_other_pool, 0,
        "no Orchard output opens under the Ironwood domain"
    );

    let mut opened = 0;
    let mut opened_in_the_other_pool = 0;
    Verifier::new(fixture_v6_ironwood_with_change().pczt())
        .with_ironwood::<(), _>(|bundle| {
            let bundle_version = *bundle.bundle_version();
            for action in bundle.actions() {
                assert_eq!(*action.output().note_version(), NoteVersion::V3);
                opened += usize::from(
                    keys.recover_output(action, bundle_version)
                        .expect("the Ironwood pool has a note encryption domain")
                        .is_some(),
                );
                opened_in_the_other_pool += usize::from(
                    keys.recover_output(action, BundleVersion::orchard_v2())
                        .expect("the Orchard pool has one too, so this is a trial, not a refusal")
                        .is_some(),
                );
            }
            Ok(())
        })
        .expect("the Ironwood bundle verifies");
    assert!(
        opened >= 1,
        "the account's Ironwood output opens under the Ironwood domain"
    );
    assert_eq!(
        opened_in_the_other_pool, 0,
        "no Ironwood output opens under the Orchard domain"
    );
}

/// The display count reads three states out of one `Option<Option<_>>`, and
/// it is the *outer* layer that carries the part the plan cannot recover
/// afterwards: `None` means no keys were supplied, `Some(None)` means keys
/// were supplied and did not open this output, and `Some(Some(memo))` means
/// the account's external OVK opened it. Only the middle state is the
/// device's fourth trial step — the refusal — and only the last puts a
/// zero-valued output on the review screen. Flattening the two `None`s
/// together would make a keyless plan refuse a transaction it cannot judge,
/// or drop the refusal and the memo from one that it can.
#[test]
fn the_display_count_tells_no_keys_from_keys_that_did_not_open() {
    let keys = canned_viewing_keys();

    // `Some(None)` over a nonzero output: the device's refusal, pulled
    // forward. `None` over the same PCZT: nothing was tried, so the
    // value-only rule counts it and the stream goes out.
    let without_ovk = fixture_v5_orchard_output_without_ovk().pczt();
    let err = build_plan_with_keys(&without_ovk, Some(&keys))
        .expect_err("the keys are supplied and neither trial opens the output");
    assert!(
        matches!(
            err,
            PlanError::UndecryptableOutput {
                section: Section::Orchard,
                ..
            }
        ),
        "{err:?}"
    );
    let blind = build_plan(&without_ovk).expect("without keys nothing is tried");
    assert_eq!(blind.displayed_shielded_outputs(), 1);
    assert!(!blind.displayed_count_is_exact());
    assert_eq!(blind.displayed_memos(), None);

    // `Some(Some(memo))` over a zero-valued output: displayed, and its memo
    // enters the retention budget. `None` over the same PCZT: not counted,
    // and no memo is known.
    let ovk = orchard_keys().1.to_ovk(Scope::External);
    let memo_only = fixture_v5_four_recipients_plus_zero_valued(Some(ovk)).pczt();
    let exact = build_plan_with_keys(&memo_only, Some(&keys)).expect("plans");
    assert_eq!(exact.displayed_shielded_outputs(), 5);
    assert_eq!(
        exact.displayed_memos().expect("keys were supplied").len(),
        5
    );
    let blind = build_plan(&memo_only).expect("plans");
    assert_eq!(blind.displayed_shielded_outputs(), 4);
    assert_eq!(blind.displayed_memos(), None);

    // `Some(None)` over a *zero-valued* output: not displayed, and not a
    // refusal either — the refusal is guarded on a nonzero value, which is
    // what tells a padding dummy from an output the device cannot decrypt.
    let padding = fixture_v5_four_recipients_plus_zero_valued(None).pczt();
    let exact = build_plan_with_keys(&padding, Some(&keys))
        .expect("a zero-valued output that opens under nothing is the dummy the device expects");
    assert_eq!(exact.displayed_shielded_outputs(), 4);
    assert!(exact.displayed_count_is_exact());
    assert_eq!(
        build_plan(&padding)
            .expect("plans")
            .displayed_shielded_outputs(),
        4,
        "the two counts agree here; it is the states behind them that differ"
    );
}

/// The session carries the viewing keys through both of its plan builds — the
/// pre-shaping validation and the fresh plan over the shaped PCZT — so a
/// split-change transaction is refused by [`LedgerSignSession::new`] for the
/// device's one-change rule, and not for the display budget.
#[test]
fn a_session_refuses_split_change_when_it_holds_the_viewing_key() {
    let fixture = fixture_v5_seed_orchard_split_change(4);
    // v3.9.3: the version that has the displayed-output budget at all.
    let caps = DeviceCaps::from_version(3, 9, 3);

    // Blind, it is the display budget that objects.
    let err = LedgerSignSession::new(&fixture.bytes, caps, fixture.params(None))
        .expect_err("five nonzero outputs, blind");
    match err {
        SessionError::Validation(violations) => assert!(
            violations.iter().any(|v| matches!(
                v,
                LedgerViolation::Limit(LimitViolation::TooManyDisplayedShieldedOutputs {
                    exact: false,
                    ..
                })
            )),
            "unexpected violations: {violations:?}"
        ),
        other => panic!("unexpected error: {other:?}"),
    }

    // With the key, the count is right and the real objection surfaces.
    let err = LedgerSignSession::new(
        &fixture.bytes,
        caps,
        fixture.params_with_keys(None, seed_viewing_keys()),
    )
    .expect_err("the device takes one change output");
    match err {
        SessionError::Validation(violations) => {
            assert!(
                violations.iter().any(|v| matches!(
                    v,
                    LedgerViolation::Limit(LimitViolation::MultipleChangeOutputs {
                        got: 4,
                        shielded: Some(4)
                    })
                )),
                "unexpected violations: {violations:?}"
            );
            assert!(
                !violations.iter().any(|v| matches!(
                    v,
                    LedgerViolation::Limit(LimitViolation::TooManyDisplayedShieldedOutputs { .. })
                )),
                "the display budget should not object: {violations:?}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

/// An OP_RETURN output is refused: the device accepts only P2PKH and P2SH
/// `script_pubkey` forms, everything else with `IncorrectData`.
#[test]
fn validate_rejects_a_non_standard_transparent_output() {
    let params = v5_network();
    let t = transparent_keys(&params);
    let (_, fvk) = orchard_keys();

    let mut builder = Builder::new(
        params,
        TARGET_HEIGHT.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(orchard::Anchor::empty_tree()),
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_transparent_p2pkh_input(
            t.pubkey,
            OutPoint::new([1u8; 32], 1),
            TxOut::new(
                Zatoshis::const_from_u64(1_000_000),
                t.address.script().into(),
            ),
        )
        .expect("transparent input");
    builder
        .add_transparent_null_data_output::<zip317::FeeRule>(b"ledger")
        .expect("op_return output");
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(fvk.to_ovk(Scope::External)),
            fvk.address_at(0u32, Scope::External),
            Zatoshis::const_from_u64(985_000),
            MemoBytes::empty(),
        )
        .expect("orchard output");

    let parts = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt");
    let bytes = finish_fixture(parts, Some(t.pubkey.serialize()));
    let pczt = Pczt::parse(&bytes).expect("parses");

    let violations =
        validate_for_ledger(&pczt, &DeviceBounds::V3_9_2).expect_err("OP_RETURN must be refused");
    assert!(
        violations.iter().any(|v| matches!(
            v,
            LedgerViolation::Limit(LimitViolation::NonStandardOutputScript { .. })
        )),
        "unexpected violations: {violations:?}"
    );
}

/// A transparent input whose `script_pubkey` is not the 25-byte P2PKH shape is
/// refused, on every app version.
///
/// `src/parser/pczt/transparent.rs` @ `22dc385` applies
/// `output_script_is_regular` to inputs and answers `IncorrectData`. A P2SH
/// script is the interesting case: it passes the *output* rule, which did not
/// change, so this is not the output check reaching one section too far.
#[test]
fn a_transparent_input_must_be_p2pkh_on_every_version() {
    let fixture = fixture_v5_transparent_to_orchard();
    let plan = build_plan(&fixture.pczt()).expect("plans");

    // `OP_HASH160 <20> … OP_EQUAL`: a well-formed P2SH scriptPubKey.
    let mut p2sh = vec![0xA9, 0x14];
    p2sh.extend_from_slice(&[7u8; 20]);
    p2sh.push(0x87);
    assert!(pczt_ledger::limits::is_standard_output_script(&p2sh));
    assert!(!pczt_ledger::limits::is_p2pkh_script(&p2sh));

    // The unmodified fixture, whose input is a real P2PKH, passes.
    pczt_ledger::limits::validate_records(plan.stream(), &DeviceBounds::V3_9_2)
        .expect("a P2PKH input is fine");

    let stream = with_input_script(&plan, p2sh);

    for bounds in [DeviceBounds::V3_9_2, DeviceBounds::V3_9_3] {
        let violations = pczt_ledger::limits::validate_records(&stream, &bounds)
            .expect_err("a P2SH input cannot be signed by this app");
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, LimitViolation::NonP2pkhInputScript { index: 0 })),
            "unexpected violations: {violations:?}"
        );
    }
}

/// A transparent input whose `bip32_derivation` pubkey does not hash to its
/// P2PKH `script_pubkey` is refused before the first APDU.
///
/// The derivation is the device's signing-key locator, and nothing on the
/// device checks it against the coin: the device signs, the user has already
/// approved the review, and only then does the host's return path fail with a
/// missing-preimage or invalid-signature error out of `apply`. The path here is
/// compliant and the script is well-formed, so no other check fires first.
#[test]
fn an_input_derivation_that_does_not_pay_the_coin_is_refused_before_streaming() {
    let honest = fixture_v5_transparent_to_orchard();
    LedgerSignSession::new(&honest.bytes, caps(), honest.params(None))
        .expect("the key that pays the input is accepted");

    // The account's own change key: a real, compliant key that does not
    // control this particular coin.
    let fixture = fixture_v5_transparent_to_orchard_stamped(honest.change_pubkey);
    let expected = LedgerViolation::Limit(LimitViolation::DerivationPubkeyMismatch {
        section: Section::TransparentInput,
        index: 0,
    });

    assert_eq!(
        validate_for_ledger(&fixture.pczt(), &DeviceBounds::V3_9_3),
        Err(vec![expected.clone()]),
    );
    let err = LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(None))
        .expect_err("a locator that cannot spend the coin is refused");
    assert!(
        matches!(err, SessionError::Validation(ref v) if v == &[expected]),
        "unexpected error: {err:?}"
    );
}

/// A `script_pubkey` over `MAX_PCZT_SCRIPT_SIZE` is refused.
///
/// The transaction builder validates every input script against its pubkey's
/// hash, so an over-long one cannot be produced from a real PCZT; the check is
/// exercised against the plan the PCZT produced, through the very function
/// [`validate_for_ledger`] delegates to.
#[test]
fn validate_rejects_an_over_long_script() {
    let fixture = fixture_v5_transparent_to_orchard();
    let plan = build_plan(&fixture.pczt()).expect("plans");
    let stream = with_input_script(&plan, vec![0u8; 253]);

    let violations = pczt_ledger::limits::validate_records(&stream, &DeviceBounds::V3_9_2)
        .expect_err("253 bytes is too long");
    assert!(
        violations.iter().any(|v| matches!(
            v,
            LimitViolation::ScriptTooLong {
                section: Section::TransparentInput,
                index: 0,
                got: 253
            }
        )),
        "unexpected violations: {violations:?}"
    );
}

/// An Ironwood trailer on a V5 plan is refused, and pays for nothing.
///
/// `shielded_action_groups` sends a bundle's trailer only inside the bundle,
/// and `StreamPlan::to_apdus` does not send the Ironwood command at all for a
/// V5 transaction, so such a trailer is a record the device never reads.
/// Crediting its `value_sum` to the fee would hide a negative fee from
/// [`LimitViolation::NegativeFee`] and leave `review_outputs` to refuse the
/// transaction at the packet carrying `P2_PCZT_FINISHED` — after the whole of
/// it has been streamed. `build_plan` never produces this shape, but
/// `StreamPlan` is public and a hand-built one can.
#[test]
fn an_ironwood_trailer_on_a_v5_plan_is_refused_and_pays_for_nothing() {
    let fixture = fixture_v5_orchard_spend_to_transparent();
    let plan = build_plan(&fixture.pczt()).expect("plans");
    let stream = plan.stream();
    pczt_ledger::limits::validate_records(stream, &DeviceBounds::V3_9_3)
        .expect("the fixture itself is streamable");
    let orchard_trailer = stream.orchard_trailer().expect("the fixture has one");

    // The fee `review_outputs` computes, from the records the device reads.
    let transparent_in: i128 = stream
        .transparent_inputs()
        .iter()
        .map(|input| i128::from(input.value()))
        .sum();
    let transparent_out: i128 = stream
        .transparent_outputs()
        .iter()
        .map(|output| i128::from(output.value()))
        .sum();
    let fee = transparent_in + i128::from(orchard_trailer.value_sum()) - transparent_out;
    assert!(fee > 0, "the fixture pays a positive fee");

    // Raise the first output by the whole fee and one zatoshi more, so the
    // transaction can no longer pay for itself.
    let overspend = fee + 1;
    let mut outputs = stream.transparent_outputs().to_vec();
    let first = &outputs[0];
    outputs[0] = TransparentOutputRecord::new(
        u64::try_from(i128::from(first.value()) + overspend).expect("a fixture-sized value"),
        first.script_pubkey().to_vec(),
        first.derivation().cloned(),
    );

    // The Ironwood trailer a hand-built plan could copy out of the Orchard
    // slot, valued at exactly the overspend it would cover.
    let stray = BundleTrailerRecord::new(
        orchard_trailer.flags(),
        i64::try_from(overspend).expect("a fixture-sized value"),
        *orchard_trailer.anchor(),
    );
    let patched = StreamPlan::new(
        stream.header().clone(),
        stream.transparent_inputs().to_vec(),
        outputs,
        stream.orchard_actions().to_vec(),
        stream.orchard_trailer().cloned(),
        // `None`: a V5 plan does not send the Ironwood command.
        None,
        Some(stray),
    );
    assert_eq!(patched.format(), TxFormat::V5);

    let violations = pczt_ledger::limits::validate_records(&patched, &DeviceBounds::V3_9_3)
        .expect_err("a V5 plan carrying an Ironwood trailer is not streamable");
    assert!(
        violations.iter().any(|v| matches!(
            v,
            LimitViolation::TrailerMismatch {
                section: Section::Ironwood,
                actions: 0,
                has_trailer: true
            }
        )),
        "unexpected violations: {violations:?}"
    );
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, LimitViolation::NegativeFee)),
        "a trailer the device never reads must not pay the fee: {violations:?}"
    );
}

// ---------------------------------------------------------------------------
// The session pump
// ---------------------------------------------------------------------------

fn caps() -> DeviceCaps {
    DeviceCaps::from_version(3, 9, 2)
}

/// A full V5 ceremony: stream, sign the real Orchard spend, apply.
#[test]
fn v5_session_streams_signs_and_applies() {
    let fixture = fixture_v5_orchard_spend();
    let mut session = LedgerSignSession::new(
        &fixture.bytes,
        caps(),
        fixture.params(fixture.change_info()),
    )
    .expect("session");

    assert_eq!(session.plan().orchard_real_spends().len(), 1);
    assert!(session.plan().ironwood_real_spends().is_empty());

    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, true);

    let statuses = run_session(&mut session, &mut device).expect("ceremony completes");
    assert_eq!(statuses.last(), Some(&SessionStatus::Complete));
    assert_eq!(session.stage(), Stage::Complete);

    // Exactly one review prompt, and it is announced before the FINISHED packet.
    assert_eq!(
        statuses
            .iter()
            .filter(|s| matches!(s, SessionStatus::AwaitingUserAction { .. }))
            .count(),
        1,
    );

    // Command order: the identity probe, then header, t-in, t-out, orchard,
    // then the signing commands. There is no Ironwood command on a V5
    // transaction.
    assert_eq!(
        device.command_sequence(),
        vec![
            Ins::GetFirmwareVersion.code(),
            Ins::GetWalletPublicKey.code(),
            Ins::PcztHeader.code(),
            Ins::PcztTransparentInput.code(),
            Ins::PcztTransparentOutput.code(),
            Ins::PcztOrchardAction.code(),
            Ins::PcztSignOrchard.code(),
        ],
    );

    let outcome = session.finish().expect("finish");
    assert_eq!(outcome.orchard_sigs().len(), 1);
    assert!(outcome.ironwood_sigs().is_empty());
    assert!(outcome.transparent_sigs().is_empty());

    // The signature really landed, and the PCZT still parses.
    let signed = Pczt::parse(outcome.pczt_with_sigs()).expect("signed PCZT parses");
    let index = outcome.orchard_sigs()[0].0;
    assert_eq!(
        signed.orchard().actions()[index]
            .spend()
            .spend_auth_sig()
            .expect("signed"),
        outcome.orchard_sigs()[0].1,
    );
}

/// A completed ceremony goes past `apply`: the Spend Finalizer assembles the
/// `script_sig`, the Transaction Extractor produces a transaction, and the
/// pubkey in the assembled `script_sig` is the one controlling the coin.
/// `Input::append_signature` verified the device's signature against the
/// PCZT's own sighash before accepting it, so a serializable transaction here
/// is the end-to-end proof — for the one shape that needs no proof to extract.
#[test]
fn a_signed_pczt_finalizes_and_extracts_to_a_transaction() {
    let fixture = fixture_v5_transparent_only();
    let mut session = LedgerSignSession::new(
        &fixture.bytes,
        caps(),
        fixture.params(fixture.change_info()),
    )
    .expect("session");
    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, true);
    run_session(&mut session, &mut device).expect("ceremony completes");
    let outcome = session.finish().expect("finish");
    assert_eq!(outcome.transparent_sigs().len(), 1);

    let signed = Pczt::parse(outcome.pczt_with_sigs()).expect("the signed PCZT parses");
    let finalized = pczt::roles::spend_finalizer::SpendFinalizer::new(signed)
        .finalize_spends()
        .expect("the Spend Finalizer assembles the script_sig");
    let tx = pczt::roles::tx_extractor::TransactionExtractor::new(finalized)
        .extract()
        .expect("the signed PCZT extracts to a transaction");

    // `<push> <sig ‖ sighash_type> <push 33> <pubkey>`.
    let bundle = tx.transparent_bundle().expect("a transparent bundle");
    let script_sig: &[u8] = &bundle.vin[0].script_sig().0 .0;
    let sig_len = usize::from(script_sig[0]);
    let der = &script_sig[1..sig_len];
    let sighash_type = script_sig[sig_len];
    assert_eq!(script_sig[sig_len + 1], 33, "a compressed pubkey push");
    let pubkey = &script_sig[sig_len + 2..];
    assert_eq!(sighash_type, SIGHASH_ALL);
    secp256k1::ecdsa::Signature::from_der(der).expect("canonical DER in the script_sig");
    let pk = secp256k1::PublicKey::from_slice(pubkey).expect("a compressed pubkey");
    assert_eq!(
        TransparentAddress::from_pubkey(&pk),
        transparent_keys(&v5_network()).address,
        "the script_sig's pubkey is the one that controls the coin",
    );

    let mut raw = Vec::new();
    tx.write(&mut raw).expect("the transaction serializes");
    assert!(!raw.is_empty());
}

/// A full V6 ceremony. The Ironwood command is sent, carries the FINISHED
/// marker, and the Orchard command goes out with count `0` and
/// `P2_PCZT_CONTINUE`.
#[test]
fn v6_session_moves_the_finished_marker_to_ironwood() {
    let fixture = fixture_v6_ironwood();
    let mut session =
        LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(None)).expect("session");

    assert!(session.plan().format() == TxFormat::V6);
    assert_eq!(session.plan().stream().header().pczt_version(), 2);
    assert!(session.plan().stream().orchard_actions().is_empty());
    assert!(session.plan().stream().orchard_trailer().is_none());
    assert!(!session
        .plan()
        .stream()
        .ironwood_actions()
        .expect("V6 sends the command")
        .is_empty());

    // Every Ironwood action carries the note-plaintext lead byte, and it is the
    // ZIP 2005 value.
    for action in session.plan().stream().ironwood_actions().unwrap() {
        assert_eq!(action.note_plaintext_version(), Some(0x03));
    }

    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, false);

    let statuses = run_session(&mut session, &mut device).expect("ceremony completes");
    assert_eq!(statuses.last(), Some(&SessionStatus::Complete));

    assert_eq!(
        device.command_sequence(),
        vec![
            Ins::GetFirmwareVersion.code(),
            Ins::GetWalletPublicKey.code(),
            Ins::PcztHeader.code(),
            Ins::PcztTransparentInput.code(),
            Ins::PcztTransparentOutput.code(),
            Ins::PcztOrchardAction.code(),
            Ins::PcztIronwoodAction.code(),
            Ins::PcztSignTransparent.code(),
        ],
    );

    // The FINISHED marker is on the last Ironwood packet, and every Orchard
    // packet used CONTINUE.
    let finished: Vec<&(u8, u8, u8)> = device.log.iter().filter(|(_, _, p2)| *p2 == 0x01).collect();
    assert_eq!(finished.len(), 1);
    assert_eq!(finished[0].0, Ins::PcztIronwoodAction.code());
    assert!(device
        .log
        .iter()
        .filter(|(ins, _, _)| *ins == Ins::PcztOrchardAction.code())
        .all(|(_, _, p2)| *p2 == 0x00));

    let outcome = session.finish().expect("finish");
    assert_eq!(outcome.transparent_sigs().len(), 1);
    assert_eq!(outcome.transparent_sigs()[0].1.sighash_type(), SIGHASH_ALL);

    let signed = Pczt::parse(outcome.pczt_with_sigs()).expect("signed PCZT parses");
    assert_eq!(signed.transparent().inputs().len(), 1);
}

/// A user rejection mid-ceremony surfaces as a typed error, kills the session,
/// and is restartable — from `PCZT_HEADER`, never by resending.
#[test]
fn user_rejection_kills_the_session_and_is_restartable() {
    let fixture = fixture_v5_orchard_spend();
    let mut session = LedgerSignSession::new(
        &fixture.bytes,
        caps(),
        fixture.params(fixture.change_info()),
    )
    .expect("session");

    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, false);

    // The review happens on the last packet of the PCZT payload, which is the
    // one carrying `P2_PCZT_FINISHED`. Deny that one.
    device.fail_at = Some((review_exchange_index(&session), StatusWord::Deny.to_u16()));

    let err = run_session(&mut session, &mut device).expect_err("the user declined");
    assert!(
        matches!(
            err,
            SessionError::UserRejected {
                stage: Stage::Streaming
            }
        ),
        "unexpected error: {err:?}"
    );
    assert_eq!(session.stage(), Stage::Failed);
    assert!(session.is_restartable());
    // A dead session hands out nothing more, and never re-offers the same APDU.
    assert_eq!(session.next_step(), PumpStep::Done);
    assert!(session.finish().is_err());
}

/// A `BadState` reply is fatal: the device tore down its transaction context,
/// so the session is dead and the only recovery is a fresh one from
/// `PCZT_HEADER`.
#[test]
fn bad_state_resets_the_session() {
    let fixture = fixture_v5_transparent_to_orchard();
    let mut session =
        LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(None)).expect("session");

    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, false);
    // Fail on the third exchange, which is inside the streaming phase.
    device.fail_at = Some((2, StatusWord::BadState.to_u16()));

    let err = run_session(&mut session, &mut device).expect_err("BadState is fatal");
    assert!(
        matches!(
            err,
            SessionError::Device {
                status: StatusWord::BadState,
                ..
            }
        ),
        "unexpected error: {err:?}"
    );
    assert_eq!(session.stage(), Stage::Failed);
    assert!(session.is_restartable());
    assert_eq!(session.next_step(), PumpStep::Done);

    // Restarting means a *new* session over the same bytes, which is fine.
    let mut fresh =
        LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(None)).expect("session");
    let mut fresh_device = FakeDevice::new();
    canned_signatures(
        &fixture,
        &fresh.shaped_pczt().clone(),
        &mut fresh_device,
        false,
    );
    run_session(&mut fresh, &mut fresh_device).expect("the retry completes");
    assert_eq!(fresh.stage(), Stage::Complete);
}

/// The region after the approval — the `PCZT_SIGN_*` commands — is the one
/// the crate exists for: the user has read the screen and pressed approve,
/// and these commands turn that into signatures. For each pool, the signing
/// stage is observed while its command is outstanding, and a device refusal,
/// a user rejection and a malformed reply there are each reported against
/// that stage and end the session — the refusal as the burned-approval case a
/// fresh session must not repeat.
#[test]
fn failures_at_a_signing_step_are_reported_against_the_signing_stage() {
    /// A pool's name, its fixture, its signing stage and its signing command.
    type SigningCase = (&'static str, fn() -> Fixture, Stage, Ins);
    let cases: [SigningCase; 3] = [
        (
            "Orchard",
            fixture_v5_orchard_spend,
            Stage::SigningOrchard,
            Ins::PcztSignOrchard,
        ),
        (
            "Ironwood",
            fixture_v6_ironwood_spend,
            Stage::SigningIronwood,
            Ins::PcztSignIronwood,
        ),
        (
            "transparent",
            fixture_v5_transparent_only,
            Stage::SigningTransparent,
            Ins::PcztSignTransparent,
        ),
    ];
    for (name, fixture, stage, ins) in cases {
        let fixture = fixture();
        let new_session = || {
            LedgerSignSession::new(
                &fixture.bytes,
                caps(),
                fixture.params(fixture.change_info()),
            )
            .unwrap_or_else(|e| panic!("{name}: {e}"))
        };
        let scripted = |session: &LedgerSignSession| {
            let mut device = FakeDevice::new();
            canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, true);
            device
        };

        // The stage is observable while the signing command is outstanding,
        // the review is behind, and the deadline stays the review one: the
        // signing commands may be gated on further confirmations.
        let mut session = new_session();
        let mut device = scripted(&session);
        let capdu = drive_until_ins(&mut session, &mut device, ins.code());
        assert_eq!(session.stage(), stage, "{name}");
        assert!(session.is_past_review(), "{name}");
        assert!(session.pending_user_action().is_none(), "{name}");
        assert_eq!(session.next_deadline(), Deadline::UserReview, "{name}");
        assert_eq!(session.next_step(), PumpStep::AwaitingReply, "{name}");

        // A reply too short to be a signature fails closed at once.
        let mut reply = device.exchange(&capdu);
        let status = reply.split_off(reply.len() - 2);
        let keep = if ins == Ins::PcztSignTransparent {
            8
        } else {
            63
        };
        reply.truncate(keep);
        reply.extend_from_slice(&status);
        let err = session.process_response(&reply).expect_err(name);
        match ins {
            Ins::PcztSignTransparent => assert!(
                matches!(
                    err,
                    SessionError::Decode(DecodeError::Truncated {
                        what: "transparent signature",
                        min: 9,
                        got: 8
                    })
                ),
                "{name}: {err:?}"
            ),
            _ => assert!(
                matches!(
                    err,
                    SessionError::Decode(DecodeError::UnexpectedLength {
                        what: "spend authorization signature",
                        expected: 64,
                        got: 63
                    })
                ),
                "{name}: {err:?}"
            ),
        }
        assert_eq!(session.stage(), Stage::Failed, "{name}");
        assert!(!session.is_restartable(), "{name}");
        assert_eq!(session.next_step(), PumpStep::Done, "{name}");
        assert!(matches!(session.finish(), Err(SessionError::OutOfOrder)));

        // A refusal, and the user declining, at the same command.
        for (status, restartable) in [
            (StatusWord::ConditionsOfUseNotSatisfied, false),
            (StatusWord::Deny, true),
        ] {
            let mut session = new_session();
            let mut device = scripted(&session);
            let first_sign = review_exchange_index(&session) + 1;
            device.fail_at = Some((first_sign, status.to_u16()));
            let err = run_session(&mut session, &mut device).expect_err(name);
            assert_eq!(
                device.log[first_sign].0,
                ins.code(),
                "{name}: the injection landed on the signing command"
            );
            match status {
                StatusWord::Deny => assert!(
                    matches!(err, SessionError::UserRejected { stage: s } if s == stage),
                    "{name}: {err:?}"
                ),
                _ => assert!(
                    matches!(
                        err,
                        SessionError::Device { stage: s, status: got } if s == stage && got == status
                    ),
                    "{name}: {err:?}"
                ),
            }
            assert_eq!(session.stage(), Stage::Failed, "{name}: {status:?}");
            assert_eq!(
                session.is_restartable(),
                restartable,
                "{name}: {status:?} after the review"
            );
            assert_eq!(session.next_step(), PumpStep::Done, "{name}");
            assert!(matches!(session.finish(), Err(SessionError::OutOfOrder)));
        }
    }
}

/// A transparent signature reply long enough to be a DER blob and a sighash
/// byte, but not one, is refused at the reply rather than absorbed: its length
/// is not what its own DER header declares. Absorbing it would have the
/// session report itself complete and fail only in `finish`, after the user
/// had approved, with an error naming no input.
#[test]
fn a_transparent_signature_that_is_not_der_fails_at_the_reply() {
    let fixture = fixture_v5_transparent_only();
    let mut session = LedgerSignSession::new(
        &fixture.bytes,
        caps(),
        fixture.params(fixture.change_info()),
    )
    .expect("session");
    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, true);

    let capdu = drive_until_ins(&mut session, &mut device, Ins::PcztSignTransparent.code());
    let mut reply = device.exchange(&capdu);
    let status = reply.split_off(reply.len() - 2);
    // Drop the sighash byte and the last byte of the DER blob: what remains is
    // long enough to be "DER plus sighash", and is neither — its length no
    // longer matches what the DER header declares.
    let as_sent = reply.len();
    reply.truncate(reply.len() - 2);
    let truncated = reply.len();
    reply.extend_from_slice(&status);

    let err = session
        .process_response(&reply)
        .expect_err("a DER blob missing its last byte");
    // The DER header still declares the length the device sent, and the reply
    // is two bytes short of it.
    assert!(
        matches!(
            err,
            SessionError::Decode(DecodeError::UnexpectedLength { expected, got, .. })
                if expected == as_sent && got == truncated
        ),
        "unexpected error: {err:?}"
    );

    // The refusal ends the session: nothing was stored, so it never reports
    // itself complete, and `finish` is out of order.
    assert_eq!(session.stage(), Stage::Failed);
    assert_eq!(session.failure(), Some(&err));
    assert!(matches!(session.finish(), Err(SessionError::OutOfOrder)));
    assert_eq!(session.failure(), Some(&err));
    assert!(!session.plan().stream().transparent_inputs().is_empty());
}

/// A transparent signature reply carrying the all-zero signature is canonical
/// DER of the right shape, so the reply parser and `from_der` both accept it;
/// `finish()` refuses it by name, as an `Apply` error, rather than leaving it
/// to the verifier's opaque refusal.
#[test]
fn a_zero_transparent_signature_fails_at_finish_by_name() {
    let fixture = fixture_v5_transparent_only();
    let mut session = LedgerSignSession::new(
        &fixture.bytes,
        caps(),
        fixture.params(fixture.change_info()),
    )
    .expect("session");
    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, true);

    let capdu = drive_until_ins(&mut session, &mut device, Ins::PcztSignTransparent.code());
    let mut reply = device.exchange(&capdu);
    let status = reply.split_off(reply.len() - 2);
    // `02 01 00` twice — r = s = 0, canonical — plus the sighash byte.
    reply.clear();
    reply.extend_from_slice(&[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, SIGHASH_ALL]);
    reply.extend_from_slice(&status);
    session
        .process_response(&reply)
        .expect("the shape of the reply is accepted");
    run_session(&mut session, &mut device).expect("nothing else to exchange");
    assert_eq!(session.stage(), Stage::Complete);

    let err = session.finish().expect_err("a zero signature");
    let ApplyError::TransparentSignature { index, source } = (match &err {
        SessionError::Apply(inner) => inner.clone(),
        other => panic!("unexpected error: {other:?}"),
    }) else {
        panic!("unexpected error: {err:?}");
    };
    // The refusal names the input it was filed under, not just the fault.
    assert_eq!(index, 0);
    assert_eq!(*source, ApplyError::ZeroScalar { scalar: "r" });
    assert_eq!(session.stage(), Stage::Failed);
}

/// Whether a fresh session is worth building depends on the status word, not
/// on the fact that the device refused: a deterministic refusal repeats on the
/// same bytes, and `ConditionsOfUseNotSatisfied` — raised by the `PCZT_SIGN_*`
/// commands after the review — would repeat at the cost of another approval.
#[test]
fn a_deterministic_device_refusal_is_not_restartable() {
    for (status, restartable) in [
        (StatusWord::IncorrectData, false),
        (StatusWord::NotEnoughMemorySpace, false),
        (StatusWord::WrongP1P2, false),
        (StatusWord::RngFailure, false),
        (StatusWord::Unknown(0x6F42), false),
        (StatusWord::TechnicalProblem, false),
        (StatusWord::MemoryProblem, true),
        (StatusWord::BadState, true),
    ] {
        let fixture = fixture_v5_transparent_to_orchard();
        let mut session =
            LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(None)).expect("session");
        let mut device = FakeDevice::new();
        canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, false);
        device.fail_at = Some((PROBE_EXCHANGES, status.to_u16()));

        let err = run_session(&mut session, &mut device).expect_err("the device refused");
        assert!(
            matches!(&err, SessionError::Device { status: got, .. } if *got == status),
            "{status:?}: {err:?}"
        );
        assert_eq!(session.stage(), Stage::Failed);
        assert_eq!(session.is_restartable(), restartable, "{status:?}");
    }

    // After the review, `ConditionsOfUseNotSatisfied` is the account-binding
    // refusal; a restart would ask the user to approve the same thing again.
    let fixture = fixture_v5_orchard_spend();
    let mut session = LedgerSignSession::new(
        &fixture.bytes,
        caps(),
        fixture.params(fixture.change_info()),
    )
    .expect("session");
    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, false);
    device.fail_at = Some((
        review_exchange_index(&session) + 1,
        StatusWord::ConditionsOfUseNotSatisfied.to_u16(),
    ));
    let err = run_session(&mut session, &mut device).expect_err("refused at the first signature");
    assert!(
        matches!(
            err,
            SessionError::Device {
                stage: Stage::SigningOrchard,
                status: StatusWord::ConditionsOfUseNotSatisfied,
            }
        ),
        "{err:?}"
    );
    assert!(!session.is_restartable());
}

/// `0x6901` `CmdNotAccepted` is not a failure: the device SDK refused the frame
/// before the app saw it, so the pump resends the identical APDU and the
/// ceremony completes.
///
/// `docs/APDU.md` @ `22dc385`: "From SDK 1.37 the legacy I/O layer refuses a
/// frame it takes for an APDU while a review is on screen … A host does better
/// to tolerate and retry it than to surface it as a failure."
#[test]
fn cmd_not_accepted_is_answered_by_resending_the_same_apdu() {
    let fixture = fixture_v5_orchard_spend();
    let mut session = LedgerSignSession::new(
        &fixture.bytes,
        caps(),
        fixture.params(fixture.change_info()),
    )
    .expect("session");

    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, true);

    // The exchange that carries the review is the last streaming packet, which
    // is where the SDK actually raises this. Refusing three exchanges running
    // from the third one covers a mid-stream refusal too.
    device.refuse_from = Some((2, 3));

    let statuses = run_session(&mut session, &mut device).expect("the ceremony completes");
    assert_eq!(statuses.last(), Some(&SessionStatus::Complete));
    assert_eq!(session.stage(), Stage::Complete);

    // Three resends, and each resent APDU is byte-identical to the one refused.
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == SessionStatus::RetrySameApdu)
            .count(),
        3,
    );
    for i in 2..=4 {
        assert_eq!(
            device.received[i],
            device.received[i + 1],
            "exchange {} must resend exchange {i} verbatim",
            i + 1
        );
    }

    // And the transaction really was signed, not merely survived.
    let outcome = session.finish().expect("finish");
    assert_eq!(outcome.orchard_sigs().len(), 1);
}

/// A `0x6901` that carries a body is not the SDK's frame refusal.
///
/// The refusal never carries data, so a body means the reply belongs to
/// another command and the channel is one reply out of step. Resending the
/// command — what the refusal asks for — would act against that signal, so
/// the session ends on a decode failure and hands nothing more out.
#[test]
fn cmd_not_accepted_with_a_body_ends_the_session() {
    let fixture = fixture_v5_transparent_to_orchard();
    let mut session =
        LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(None)).expect("session");
    let refused = StatusWord::CmdNotAccepted.to_u16().to_be_bytes().to_vec();
    let mut bodied = vec![0xAA];
    bodied.extend_from_slice(&refused);

    // The empty form is the refusal: the same command goes out again.
    let PumpStep::Send(probe) = session.next_step() else {
        panic!("the first command goes out");
    };
    assert_eq!(
        session.process_response(&refused),
        Ok(SessionStatus::RetrySameApdu)
    );
    assert_eq!(session.next_step(), PumpStep::Send(probe));

    // The bodied form ends the session instead.
    assert_eq!(
        session.process_response(&bodied),
        Err(SessionError::Decode(DecodeError::UnexpectedLength {
            what: "0x6901 refusal",
            expected: 0,
            got: 1,
        }))
    );
    assert_eq!(session.stage(), Stage::Failed);
    assert_eq!(session.next_step(), PumpStep::Done);
}

/// A device that never stops refusing ends the session rather than the pump
/// spinning on it forever.
#[test]
fn endless_cmd_not_accepted_exhausts_the_retry_budget() {
    let fixture = fixture_v5_transparent_to_orchard();
    let mut session =
        LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(None)).expect("session");

    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, false);
    device.refuse_from = Some((0, pczt_ledger::session::MAX_CMD_NOT_ACCEPTED_RETRIES + 1));

    let err = run_session(&mut session, &mut device).expect_err("the budget runs out");
    // Spent on the very first command, which is the identity probe.
    assert!(
        matches!(
            err,
            SessionError::Device {
                status: StatusWord::CmdNotAccepted,
                stage: Stage::IdentifyingDevice,
            }
        ),
        "unexpected error: {err:?}"
    );
    assert_eq!(session.stage(), Stage::Failed);
    // Exactly the budget, plus the one that spent it.
    assert_eq!(
        device.seen,
        pczt_ledger::session::MAX_CMD_NOT_ACCEPTED_RETRIES as usize + 1
    );
}

/// The place the firmware documents `0x6901` as arising is while a review
/// is on screen: the budget spent at the review packet ends the session in
/// the streaming stage, and, a screen having stayed up for the whole budget,
/// the session is restartable.
#[test]
fn endless_cmd_not_accepted_at_the_review_packet_exhausts_the_budget_there() {
    let fixture = fixture_v5_transparent_to_orchard();
    let mut session =
        LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(None)).expect("session");
    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, false);
    let review = review_exchange_index(&session);
    let budget = pczt_ledger::session::MAX_CMD_NOT_ACCEPTED_RETRIES;
    device.refuse_from = Some((review, budget + 1));

    let err = run_session(&mut session, &mut device).expect_err("the budget runs out");
    assert_eq!(
        err,
        SessionError::Device {
            status: StatusWord::CmdNotAccepted,
            stage: Stage::Streaming,
        }
    );
    assert_eq!(session.stage(), Stage::Failed);
    assert!(session.is_restartable());
    assert_eq!(device.seen, review + budget as usize + 1);
}

/// A device in the dashboard, or running another app, answers the first
/// probe with a wrong-app status word: a typed, terminal error that names
/// the word, not restartable, and nothing more is sent.
#[test]
fn a_device_running_another_app_is_a_typed_terminal_error() {
    for status in [StatusWord::ClaNotSupported, StatusWord::InsNotSupported] {
        let fixture = fixture_v5_transparent_to_orchard();
        let mut session =
            LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(None)).expect("session");
        let mut device = FakeDevice::new();
        device.fail_at = Some((0, status.to_u16()));

        let err = run_session(&mut session, &mut device).expect_err("the wrong app");
        assert_eq!(err, SessionError::WrongApp { status });
        assert_eq!(session.stage(), Stage::Failed);
        assert!(!session.is_restartable());
        assert_eq!(device.seen, 1, "nothing after the probe");
    }
}

/// Every transparent input is signed at its own index: the `PCZT_SIGN_TRANSPARENT`
/// commands carry `P2` 0 and 1, the outcome holds a signature per input, and
/// both land on the PCZT.
#[test]
fn every_transparent_input_is_signed_at_its_own_index() {
    let fixture = fixture_v5_two_transparent_inputs();
    let mut session = LedgerSignSession::new(
        &fixture.bytes,
        caps(),
        fixture.params(fixture.change_info()),
    )
    .expect("session");
    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, true);
    run_session(&mut session, &mut device).expect("ceremony completes");

    let signed_at: Vec<u8> = device
        .log
        .iter()
        .filter(|(ins, _, _)| *ins == Ins::PcztSignTransparent.code())
        .map(|(_, _, p2)| *p2)
        .collect();
    assert_eq!(signed_at, vec![0, 1]);

    let outcome = session.finish().expect("finish");
    let indices: Vec<usize> = outcome.transparent_sigs().iter().map(|(i, _)| *i).collect();
    assert_eq!(indices, vec![0, 1]);

    let signed = Pczt::parse(outcome.pczt_with_sigs()).expect("parses");
    let mut signatures = 0usize;
    Verifier::new(signed)
        .with_transparent::<(), _>(|bundle| {
            assert_eq!(bundle.inputs().len(), 2);
            for input in bundle.inputs() {
                let pubkey = *input
                    .bip32_derivation()
                    .keys()
                    .next()
                    .expect("the fixture stamped a derivation");
                assert!(input.partial_signatures().contains_key(&pubkey));
                signatures += 1;
            }
            Ok(())
        })
        .expect("verifier");
    assert_eq!(signatures, 2);
}

/// A signature for an input that carries no derivation cannot be applied:
/// without the pubkey there is no `hash160_preimage` to stamp and no key to
/// attach the signature to.
#[test]
fn a_signature_for_an_input_without_a_derivation_cannot_be_applied() {
    let pczt = fixture_v5_transparent_only_with(None).pczt();
    let signatures = DeviceSignatures::new(
        Vec::new(),
        Vec::new(),
        vec![(0, vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])],
    );
    assert!(matches!(
        apply_device_signatures(pczt, &signatures),
        Err(ApplyError::MissingInputDerivation { index: 0 })
    ));
}

/// The `GET_VK` pump tolerates the same refusal, and resends the request rather
/// than moving on to a continuation — the refused frame never reached the app,
/// so no response is pending for a continuation to collect.
#[test]
fn a_refused_get_vk_request_is_resent_verbatim() {
    let mut exchange =
        pairing::VkExchange::orchard_fvk(Network::Test, zip32::AccountId::ZERO).expect("request");

    let first = exchange.next_apdu().expect("first request");
    assert_eq!(exchange.next_deadline(), Deadline::UserReview);
    assert_eq!(
        exchange.process_response(&StatusWord::CmdNotAccepted.to_u16().to_be_bytes()),
        Ok(VkStep::RetrySameApdu),
        "a refusal is not an error, and is told apart from an absorbed chunk"
    );
    assert_eq!(exchange.bytes_received(), 0);

    let resent = exchange.next_apdu().expect("the same request again");
    assert_eq!(resent, first, "a refused request is resent verbatim");
    assert_eq!(
        exchange.next_deadline(),
        Deadline::UserReview,
        "the resend puts the approval screen up, like the request it repeats"
    );

    // Then the real reply, which completes the 96-byte raw FVK in one chunk.
    let fvk = orchard_keys().1.to_bytes().to_vec();
    let mut reply = fvk.clone();
    reply.extend_from_slice(&StatusWord::Ok.to_u16().to_be_bytes());
    match exchange.process_response(&reply).expect("the chunk lands") {
        VkStep::Complete(pczt_ledger::apdu::decode::VkResponse::OrchardFvk(bytes)) => {
            assert_eq!(bytes, fvk)
        }
        other => panic!("unexpected response: {other:?}"),
    }
    assert!(exchange.next_apdu().is_none());
}

/// A transparent input whose `bip32_derivation` names a different account is
/// refused before the first APDU.
///
/// `check_change_returns_to_signing_account` (`src/tx.rs` @ `22dc385`) compares
/// the account component of every signing path with the account the hidden
/// change returns to, and answers `ConditionsOfUseNotSatisfied` (`0x6986`) when
/// they differ. It runs at *signing* time, which is after the review: the user
/// would approve a transaction and only then be told no. Transparent inputs are
/// the section shaping never rewrites, so they are where such a path can
/// survive to the device.
/// `validate_for_ledger` answers only the parameter-free checks; the full
/// set — path compliance and account binding among them — needs the session
/// parameters and runs in `preflight`, the gate a wallet shows the user. A
/// PCZT that `validate_for_ledger` passes and `new` refuses is refused by
/// `preflight` for the same reason, and one `preflight` accepts is accepted by
/// `new` with the same plan.
#[test]
fn preflight_runs_the_checks_validate_for_ledger_cannot() {
    let fixture = fixture_v5_transparent_to_orchard();
    let restamped = restamp_transparent_input_path(
        Pczt::parse(&fixture.bytes).expect("parses"),
        fixture_input_path(7),
    );

    validate_for_ledger(&restamped, &DeviceBounds::V3_9_2)
        .expect("nothing parameter-free is wrong with an input at account 7'");
    let err = pczt_ledger::session::preflight(&restamped, caps(), &fixture.params(None))
        .expect_err("preflight binds the account");
    assert!(
        matches!(
            err,
            SessionError::AccountMismatch {
                section: Section::TransparentInput,
                index: 0,
            }
        ),
        "unexpected error: {err:?}"
    );

    let plan = pczt_ledger::session::preflight(&fixture.pczt(), caps(), &fixture.params(None))
        .expect("the fixture is clean");
    let session =
        LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(None)).expect("session");
    assert_eq!(&plan, session.plan());
}

#[test]
fn a_transparent_input_from_another_account_is_refused_before_streaming() {
    let fixture = fixture_v5_transparent_to_orchard();

    // The same fixture signs fine for the account its paths name.
    LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(None))
        .expect("account 0 is what the fixture was stamped with");

    // Re-stamp the input at account 7', leaving everything else alone.
    let restamped = restamp_transparent_input_path(
        Pczt::parse(&fixture.bytes).expect("parses"),
        fixture_input_path(7),
    );
    let bytes = restamped.serialize().expect("serializes");

    let err = LedgerSignSession::new(&bytes, caps(), fixture.params(None))
        .expect_err("an input at account 7' cannot be signed for account 0");
    match err {
        SessionError::AccountMismatch {
            section: Section::TransparentInput,
            index: 0,
        } => {
            // Neither account index is in the message: with the seed
            // fingerprint from the same record it names the account's keys.
            let rendered = format!("{err}");
            assert!(!rendered.contains("0x80000007"), "{rendered}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

/// A path at a depth the app reads no account from is refused as
/// non-compliant: `check_bip44_compliance(OnlyCoinType)` accepts only the
/// five-component BIP 44 form and the three-component ZIP 32 one.
#[test]
fn a_transparent_input_path_of_the_wrong_depth_is_refused() {
    let fixture = fixture_v5_transparent_to_orchard();

    assert_eq!(
        derivation_account(&[
            44 | 0x8000_0000,
            FIXTURE_COIN_TYPE | 0x8000_0000,
            ACCOUNT | 0x8000_0000,
            0,
        ]),
        None,
        "four components is neither the BIP 44 nor the ZIP 32 shape",
    );

    let mut short = fixture_input_path(ACCOUNT);
    short.pop();
    let restamped =
        restamp_transparent_input_path(Pczt::parse(&fixture.bytes).expect("parses"), short);
    let bytes = restamped.serialize().expect("serializes");

    let err = LedgerSignSession::new(&bytes, caps(), fixture.params(None))
        .expect_err("a four-component path names no account");
    assert!(
        matches!(
            err,
            SessionError::NonCompliantPath {
                section: Section::TransparentInput,
                index: 0,
                ..
            }
        ),
        "unexpected error: {err:?}"
    );
}

/// The firmware's `check_bip44_compliance(OnlyCoinType)` is mirrored
/// pre-flight: an unhardened purpose — `m/44/1'/0'/0/0` — is a path the OS
/// refuses to derive, and the device refuses it with `IncorrectData`
/// mid-stream, so session construction refuses it up front.
#[test]
fn an_unhardened_purpose_is_refused_before_streaming() {
    let fixture = fixture_v5_transparent_to_orchard();

    let mut unhardened = fixture_input_path(ACCOUNT);
    unhardened[0] = 44; // strip the hardening bit from the purpose
    let restamped =
        restamp_transparent_input_path(Pczt::parse(&fixture.bytes).expect("parses"), unhardened);
    let bytes = restamped.serialize().expect("serializes");

    let err = LedgerSignSession::new(&bytes, caps(), fixture.params(None))
        .expect_err("an unhardened purpose is not BIP 44 compliant");
    assert!(
        matches!(
            err,
            SessionError::NonCompliantPath {
                section: Section::TransparentInput,
                index: 0,
                ..
            }
        ),
        "unexpected error: {err:?}"
    );
}

/// The coin-type half of the same firmware check: a path whose coin type is
/// not the session network's is refused pre-flight.
#[test]
fn a_foreign_coin_type_in_an_input_path_is_refused_before_streaming() {
    let fixture = fixture_v5_transparent_to_orchard();

    let mainnet_path = vec![
        44 | HARDENED,
        133 | HARDENED, // mainnet coin type on a testnet session
        ACCOUNT | HARDENED,
        0,
        0,
    ];
    let restamped =
        restamp_transparent_input_path(Pczt::parse(&fixture.bytes).expect("parses"), mainnet_path);
    let bytes = restamped.serialize().expect("serializes");

    let err = LedgerSignSession::new(&bytes, caps(), fixture.params(None))
        .expect_err("a mainnet coin type cannot be signed on a testnet session");
    assert!(
        matches!(
            err,
            SessionError::NonCompliantPath {
                section: Section::TransparentInput,
                index: 0,
                ..
            }
        ),
        "unexpected error: {err:?}"
    );
}

/// Rewrites every transparent input's `bip32_derivation` to `path`, keyed by
/// the pubkey already recorded there.
///
/// Reusing that key matters: `set_bip32_derivation` is keyed by pubkey, so a
/// different one would *add* a second entry and the plan would fail on
/// `TransparentDerivationCount` long before the account is looked at.
fn restamp_transparent_input_path(pczt: Pczt, path: Vec<u32>) -> Pczt {
    Updater::new(pczt)
        .update_transparent_with(|mut updater| {
            let keys: Vec<[u8; 33]> = updater
                .bundle()
                .inputs()
                .iter()
                .map(|input| {
                    *input
                        .bip32_derivation()
                        .keys()
                        .next()
                        .expect("the fixture stamped one")
                })
                .collect();
            for (index, pubkey) in keys.into_iter().enumerate() {
                let derivation =
                    zcash_transparent::pczt::Bip32Derivation::parse(SEED_FINGERPRINT, path.clone())
                        .expect("valid derivation");
                updater.update_input_with(index, |mut input| {
                    input.set_bip32_derivation(pubkey, derivation);
                    Ok(())
                })?;
            }
            Ok(())
        })
        .expect("transparent updater")
        .finish()
}

/// The five-component BIP 44 path for one account, as the fixtures stamp it.
fn fixture_input_path(account: u32) -> Vec<u32> {
    vec![
        44 | HARDENED,
        FIXTURE_COIN_TYPE | HARDENED,
        account | HARDENED,
        0,
        0,
    ]
}

/// Stamps `path` as the `bip32_derivation` of transparent output `index`,
/// keyed by `pubkey`: a derivation the PCZT arrived with, which shaping leaves
/// untouched.
fn stamp_transparent_output_path(
    pczt: Pczt,
    index: usize,
    pubkey: [u8; 33],
    path: Vec<u32>,
) -> Pczt {
    Updater::new(pczt)
        .update_transparent_with(|mut updater| {
            let derivation =
                zcash_transparent::pczt::Bip32Derivation::parse(SEED_FINGERPRINT, path)
                    .expect("valid derivation");
            updater.update_output_with(index, |mut output| {
                output.set_bip32_derivation(pubkey, derivation);
                Ok(())
            })
        })
        .expect("transparent updater")
        .finish()
}

/// A transparent input whose path derives a different key than its pubkey is
/// refused before the first APDU.
///
/// The pubkey-pays-script check binds the pubkey to the coin; this binds the
/// path to the pubkey. The device signs with the key at the path and never
/// compares it with the supplied pubkey, and the `pczt` Signer verifies the
/// signature against the pubkey, so without this gate the ceremony completes
/// and `finish()` fails with `InvalidExternalSignature`.
#[test]
fn an_input_path_that_derives_another_key_is_refused_before_streaming() {
    let fixture = fixture_v5_transparent_to_orchard();
    let mut path = fixture_input_path(ACCOUNT);
    // One address index along; the pubkey left in place still pays the coin.
    path[4] = 1;
    let bytes = restamp_transparent_input_path(fixture.pczt(), path)
        .serialize()
        .expect("serializes");

    validate_for_ledger(
        &Pczt::parse(&bytes).expect("parses"),
        &DeviceBounds::MOST_PERMISSIVE,
    )
    .expect("the pubkey still pays the coin, so the plan-level gate is silent");

    let err = LedgerSignSession::new(&bytes, caps(), fixture.params(None))
        .expect_err("the session refuses it before any APDU is queued");
    assert_eq!(
        err,
        SessionError::TransparentKeyMismatch {
            section: Section::TransparentInput,
            index: 0,
        },
    );

    // The fixture's own path derives its pubkey, so the honest PCZT is taken.
    LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(None))
        .expect("the honest derivation passes the same check");
}

/// The same for a derivation the PCZT arrived with on a transparent output:
/// the device would re-derive the pubkey from the path and refuse the mismatch
/// mid-stream; the host refuses it first.
#[test]
fn an_output_path_that_derives_another_key_is_refused_before_streaming() {
    let fixture = fixture_v5_orchard_spend();
    let path = vec![
        44 | HARDENED,
        FIXTURE_COIN_TYPE | HARDENED,
        ACCOUNT | HARDENED,
        1,
        7,
    ];
    let bytes = stamp_transparent_output_path(fixture.pczt(), 0, fixture.change_pubkey, path)
        .serialize()
        .expect("serializes");

    let err = LedgerSignSession::new(&bytes, caps(), fixture.params(None))
        .expect_err("the session refuses it before any APDU is queued");
    assert_eq!(
        err,
        SessionError::TransparentKeyMismatch {
            section: Section::TransparentOutput,
            index: 0,
        },
    );
}

/// A transparent output's derivation is checked under the firmware's
/// `Full { is_change_path: true }` mode rather than the `OnlyCoinType` mode
/// signing paths get: the five-component form, the internal scope, and the
/// account and address-index bounds. Each shape the device refuses mid-stream
/// is refused here first — the ones a PCZT can arrive with as
/// `NonCompliantPath`, the ones the crate would stamp itself at the shaping
/// parameters.
#[test]
fn a_change_derivation_the_firmware_refuses_is_refused_before_streaming() {
    let fixture = fixture_v5_orchard_spend();
    let path = |scope: u32, index: u32| {
        vec![
            44 | HARDENED,
            FIXTURE_COIN_TYPE | HARDENED,
            ACCOUNT | HARDENED,
            scope,
            index,
        ]
    };

    let honest =
        stamp_transparent_output_path(fixture.pczt(), 0, fixture.change_pubkey, path(1, 0))
            .serialize()
            .expect("serializes");
    LedgerSignSession::new(&honest, caps(), fixture.params(None))
        .expect("the compliant change path is accepted");

    for (name, path) in [
        ("the external scope", path(0, 0)),
        ("an address index above the bound", path(1, 50_001)),
        (
            "the three-component ZIP 32 form",
            vec![
                32 | HARDENED,
                FIXTURE_COIN_TYPE | HARDENED,
                ACCOUNT | HARDENED,
            ],
        ),
    ] {
        let bytes = stamp_transparent_output_path(fixture.pczt(), 0, fixture.change_pubkey, path)
            .serialize()
            .expect("serializes");
        let err = LedgerSignSession::new(&bytes, caps(), fixture.params(None)).expect_err(name);
        assert!(
            matches!(
                err,
                SessionError::NonCompliantPath {
                    section: Section::TransparentOutput,
                    index: 0,
                    ..
                }
            ),
            "{name}: {err}"
        );
    }

    // The path the crate stamps itself is bounded at the shaping parameters,
    // so an honest wallet learns before it builds the transaction.
    let params = SessionParams::new(
        Network::Test,
        fake_device_identity(),
        zip32::AccountId::try_from(101).expect("unhardened"),
    )
    .with_seed_fingerprint(Some(SEED_FINGERPRINT))
    .with_change(fixture.change_info())
    .with_transparent_account_key(Some(transparent_account_key()));
    assert_eq!(
        LedgerSignSession::new(&fixture.bytes, caps(), params).expect_err("account 101"),
        SessionError::Shape(ShapeError::ChangeAccountAboveDeviceBound {
            account: 101,
            max: 100,
        }),
    );
    // Derived honestly for index 50 001, so the bound is all that refuses it.
    let change = change_info_at(50_001, 0);
    assert_eq!(
        LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(Some(change)))
            .expect_err("index 50001"),
        SessionError::Shape(ShapeError::ChangeIndexAboveDeviceBound {
            index: 50_001,
            max: 50_000,
        }),
    );
}

/// The transparent account key is required exactly when there is a transparent
/// derivation to check against it.
#[test]
fn the_transparent_account_key_is_required_exactly_when_a_derivation_needs_it() {
    let fixture = fixture_v5_transparent_to_orchard();
    let params = fixture.params(None).with_transparent_account_key(None);
    let err = LedgerSignSession::new(&fixture.bytes, caps(), params).expect_err("refused");
    assert_eq!(
        err,
        SessionError::TransparentAccountKeyRequired {
            section: Section::TransparentInput,
            index: 0,
        },
    );

    // No transparent input and no change output named: nothing to check, no
    // key needed.
    let fixture = fixture_v5_orchard_spend();
    let params = fixture.params(None).with_transparent_account_key(None);
    LedgerSignSession::new(&fixture.bytes, caps(), params)
        .expect("a transaction with no transparent derivation needs no transparent key");
}

/// `PumpStep::Send` shows its length under `{:?}` and not the packet: an
/// action packet carries `alpha`, `rcv`, `rseed` and both raw addresses, and
/// the step is the one value a transport loop naturally logs on every
/// iteration.
#[test]
fn a_pump_step_redacts_the_packet_in_debug() {
    let fixture = fixture_v5_orchard_spend();
    let mut session = LedgerSignSession::new(
        &fixture.bytes,
        caps(),
        fixture.params(fixture.change_info()),
    )
    .expect("session");
    let index = session.plan().orchard_real_spends()[0];
    // The record keeps `alpha` to itself; the PCZT's parsed view has it.
    let mut alpha = [0u8; 32];
    Verifier::new(session.shaped_pczt().clone())
        .with_orchard::<(), _>(|bundle| {
            alpha =
                ff::PrimeField::to_repr(&bundle.actions()[index].spend().alpha().expect("alpha"));
            Ok(())
        })
        .expect("verifies");
    // How the derived `Debug` rendered the bytes: a decimal list.
    let alpha_in_clear = format!("{:?}", &alpha[..]);
    let alpha_in_clear = &alpha_in_clear[1..alpha_in_clear.len() - 1];

    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, false);

    let mut alpha_was_pumped = false;
    loop {
        let step = session.next_step();
        let rendered = format!("{step:?}");
        assert!(
            !rendered.contains(alpha_in_clear),
            "alpha rendered in clear: {rendered}"
        );
        let PumpStep::Send(capdu) = step else {
            break;
        };
        assert_eq!(rendered, format!("Send([{} bytes])", capdu.len()));
        if capdu.windows(alpha.len()).any(|window| window == alpha) {
            alpha_was_pumped = true;
        }
        let rapdu = device.exchange(&capdu);
        session
            .process_response(&rapdu)
            .expect("the fixture ceremony completes");
    }
    assert!(
        alpha_was_pumped,
        "the packet carrying alpha went through the pump"
    );
    assert_eq!(session.stage(), Stage::Complete);
}

/// The session refuses to hand out a second command before the first is
/// answered, and refuses a response with nothing outstanding.
#[test]
fn the_pump_enforces_one_outstanding_command() {
    let fixture = fixture_v5_transparent_to_orchard();
    let mut session =
        LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(None)).expect("session");

    assert!(matches!(
        session.process_response(&StatusWord::Ok.to_u16().to_be_bytes()),
        Err(SessionError::OutOfOrder)
    ));

    let first = match session.next_step() {
        PumpStep::Send(apdu) => apdu,
        other => panic!("expected the version probe, got {other:?}"),
    };
    assert_eq!(session.next_step(), PumpStep::AwaitingReply);
    assert_eq!(first[1], Ins::GetFirmwareVersion.code());
}

/// A streaming reply is an empty `0x9000`: no PCZT stream handler appends
/// data. A body is the reply to some other command — a transport off by one —
/// and ends the session at that packet, not after the review.
#[test]
fn a_stream_reply_with_a_body_ends_the_session() {
    let fixture = fixture_v5_transparent_to_orchard();
    let mut session =
        LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(None)).expect("session");
    let mut device = FakeDevice::new();

    for _ in 0..PROBE_EXCHANGES {
        let PumpStep::Send(capdu) = session.next_step() else {
            panic!("a probe is handed out first");
        };
        let rapdu = device.exchange(&capdu);
        session
            .process_response(&rapdu)
            .expect("the probe is answered");
    }

    let PumpStep::Send(header) = session.next_step() else {
        panic!("the header follows the probes");
    };
    assert_eq!(header[1], Ins::PcztHeader.code());
    let err = session
        .process_response(&[0xDE, 0xAD, 0xBE, 0xEF, 0x90, 0x00])
        .expect_err("a body is not an acknowledgement");
    assert!(
        matches!(
            err,
            SessionError::Decode(DecodeError::UnexpectedLength {
                expected: 0,
                got: 4,
                ..
            })
        ),
        "{err}"
    );
    assert_eq!(session.stage(), Stage::Failed);
    assert!(!session.is_restartable());
    assert_eq!(session.next_step(), PumpStep::Done);
}

/// The first command of every session is the silent identity probe at the
/// identity path, and nothing of the transaction precedes it.
#[test]
fn a_session_opens_with_the_silent_identity_probe() {
    let fixture = fixture_v5_orchard_spend();
    let mut session = LedgerSignSession::new(
        &fixture.bytes,
        caps(),
        fixture.params(fixture.change_info()),
    )
    .expect("session");
    assert_eq!(session.device(), fake_device_identity());

    assert_eq!(session.pending_user_action(), None);
    assert_eq!(session.next_deadline(), Deadline::Normal);
    assert_eq!(
        session.stage(),
        Stage::IdentifyingDevice,
        "a fresh session reports the stage its first step is, not the one after it"
    );

    // First the version probe, which the caps the session was built with
    // must match.
    let first = match session.next_step() {
        PumpStep::Send(apdu) => apdu,
        other => panic!("expected the version probe, got {other:?}"),
    };
    assert_eq!(session.stage(), Stage::IdentifyingDevice);
    assert_eq!(
        first,
        pairing::firmware_version_apdu(),
        "the probe is the pairing module's own version command"
    );
    let mut device = FakeDevice::new();
    let rapdu = device.exchange(&first);
    assert_eq!(
        session
            .process_response(&rapdu)
            .expect("the version matches"),
        SessionStatus::MoreApdus
    );

    // Then the identity probe, still before any transaction byte.
    let second = match session.next_step() {
        PumpStep::Send(apdu) => apdu,
        other => panic!("expected the identity probe, got {other:?}"),
    };
    assert_eq!(session.stage(), Stage::IdentifyingDevice);
    assert_eq!(
        second,
        pairing::device_identity_apdu(Network::Test).expect("encodes"),
        "the probe is the pairing module's own identity command"
    );
    assert_eq!(second[2], 0x00, "P1_GET_PUBLIC_KEY_NO_DISPLAY: no screen");
}

/// A device running another app version than the session was built for is
/// refused before the first transaction byte: it sees the version probe and
/// nothing else, the error names both versions, and the session is dead and
/// not restartable. Every version-gated bound was validated against the caps
/// the caller supplied, so a different device would move a refusal from
/// pre-flight to mid-stream.
#[test]
fn a_device_of_another_version_is_refused_before_the_first_pczt_apdu() {
    let fixture = fixture_v5_orchard_spend();
    let mut session = LedgerSignSession::new(
        &fixture.bytes,
        caps(),
        fixture.params(fixture.change_info()),
    )
    .expect("session");
    assert_eq!(session.caps(), caps());

    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, false);
    device.version = (3, 9, 3);

    let err = run_session(&mut session, &mut device).expect_err("the wrong version answered");
    assert_eq!(
        err,
        SessionError::CapsMismatch {
            expected: DeviceCaps::from_version(3, 9, 2),
            found: DeviceCaps::from_version(3, 9, 3),
        },
    );
    assert_eq!(
        device.command_sequence(),
        vec![Ins::GetFirmwareVersion.code()],
        "nothing of the transaction, not even the identity probe, reached the device"
    );
    assert_eq!(session.stage(), Stage::Failed);
    assert!(!session.is_restartable());
    assert_eq!(session.next_step(), PumpStep::Done);
    assert!(matches!(session.finish(), Err(SessionError::OutOfOrder)));
}

/// A device other than the paired one is refused before the first transaction
/// byte: it sees the identity probe and nothing else, the error names both
/// identities, and the session is dead and not restartable — the same session
/// on the same device fails the same way.
#[test]
fn a_different_device_is_refused_before_the_first_pczt_apdu() {
    let fixture = fixture_v5_orchard_spend();
    let mut session = LedgerSignSession::new(
        &fixture.bytes,
        caps(),
        fixture.params(fixture.change_info()),
    )
    .expect("session");

    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, false);
    // A second Ledger, restored from a different seed.
    let other_sk = secp256k1::SecretKey::from_slice(&[0x6Eu8; 32]).expect("valid");
    device.identity_key =
        secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::signing_only(), &other_sk);
    let other = pairing::DeviceIdentity::from_compressed_pubkey(&device.identity_key.serialize());
    assert_ne!(other, fake_device_identity());

    let err = run_session(&mut session, &mut device).expect_err("the wrong device answered");
    match err {
        SessionError::DeviceMismatch { expected, found } => {
            assert_eq!(expected, fake_device_identity());
            assert_eq!(found, other);
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert_eq!(
        device.command_sequence(),
        vec![
            Ins::GetFirmwareVersion.code(),
            Ins::GetWalletPublicKey.code()
        ],
        "nothing of the transaction reached the device"
    );
    assert_eq!(session.stage(), Stage::Failed);
    assert!(!session.is_restartable());
    assert_eq!(session.next_step(), PumpStep::Done);
    assert!(matches!(session.finish(), Err(SessionError::OutOfOrder)));
}

/// The device is told the review is coming before the packet that triggers it
/// goes out, so a transport can lift its timeout.
#[test]
fn the_review_prompt_is_announced_before_the_finished_packet() {
    let fixture = fixture_v5_transparent_to_orchard();
    let mut session =
        LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(None)).expect("session");

    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, false);

    let mut announced = false;
    while let PumpStep::Send(capdu) = session.next_step() {
        if announced {
            assert_eq!(capdu[3], 0x01, "the announced packet carries FINISHED");
            announced = false;
        }
        let rapdu = device.exchange(&capdu);
        if let SessionStatus::AwaitingUserAction { action } =
            session.process_response(&rapdu).expect("ok")
        {
            assert_eq!(action, UserAction::ReviewTransaction);
            announced = true;
        }
    }
    assert_eq!(session.stage(), Stage::Complete);
}

/// A mainnet session over a testnet PCZT is refused before a single APDU: the
/// coin types disagree, and the device build is per network anyway.
#[test]
fn a_session_is_not_created_for_the_wrong_network() {
    let fixture = fixture_v5_transparent_to_orchard();
    // A mainnet session over a testnet PCZT: the coin types disagree.
    let err = LedgerSignSession::new(
        &fixture.bytes,
        caps(),
        SessionParams::new(Network::Main, fake_device_identity(), account())
            .with_seed_fingerprint(Some(SEED_FINGERPRINT))
            .with_change(None)
            .with_transparent_account_key(Some(transparent_account_key()))
            .with_viewing_keys(None),
    )
    .expect_err("coin type mismatch");
    assert!(
        matches!(
            err,
            SessionError::Shape(ShapeError::CoinTypeMismatch { .. })
        ),
        "unexpected error: {err:?}"
    );
}

/// An app too old for the PCZT instructions is refused up front, because the
/// device would answer `InsNotSupported` with no diagnostic.
#[test]
fn a_session_is_not_created_for_an_incapable_device() {
    let fixture = fixture_v5_transparent_to_orchard();
    let err = LedgerSignSession::new(
        &fixture.bytes,
        DeviceCaps::from_version(3, 5, 0),
        fixture.params(None),
    )
    .expect_err("too old for PCZT");
    assert!(
        matches!(
            err,
            SessionError::Validation(ref v)
                if v.iter().any(|x| matches!(
                    x,
                    LedgerViolation::Limit(LimitViolation::PcztUnsupported { .. })
                ))
        ),
        "unexpected error: {err:?}"
    );
}

/// A V6 PCZT on an app without the Ironwood pool is refused up front.
#[test]
fn a_v6_session_is_not_created_for_a_pre_ironwood_device() {
    let fixture = fixture_v6_ironwood();
    let err = LedgerSignSession::new(
        &fixture.bytes,
        DeviceCaps::from_version(3, 8, 0),
        fixture.params(None),
    )
    .expect_err("too old for Ironwood");
    assert!(
        matches!(
            err,
            SessionError::Validation(ref v)
                if v.iter().any(|x| matches!(
                    x,
                    LedgerViolation::Limit(LimitViolation::IronwoodUnsupported { .. })
                ))
        ),
        "unexpected error: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// The blocking runner
// ---------------------------------------------------------------------------

#[cfg(feature = "std")]
/// A transport failure leaves the session with a command outstanding. Driving
/// the same session again must not report success: it exchanged nothing and
/// collected no signatures, and a wallet wrapping the runner in retry logic
/// would otherwise take an `Ok(())` for a signed transaction.
#[test]
fn the_runner_refuses_a_session_with_a_reply_outstanding() {
    let fixture = fixture_v5_transparent_to_orchard();
    let mut session =
        LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(None)).expect("session");
    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, false);
    let mut transport = FakeTransport::new(device);
    transport.fail_at = Some(2);

    let err = ceremony::run_session(&mut transport, &mut session, || {})
        .expect_err("the third exchange never crosses the wire");
    assert!(
        matches!(
            err,
            CeremonyError::Transport {
                stage: Stage::Streaming,
                source: TransportError::ConnectionClosed,
            }
        ),
        "unexpected error: {err}"
    );
    assert_eq!(session.next_step(), PumpStep::AwaitingReply);

    // The retry: nothing goes out, and the answer is not `Ok`.
    let before = transport.exchanges;
    let err = ceremony::run_session(&mut transport, &mut session, || {})
        .expect_err("a session with a reply outstanding cannot be resumed");
    assert!(
        matches!(
            err,
            CeremonyError::NotResumable {
                stage: Stage::Streaming
            }
        ),
        "unexpected error: {err}"
    );
    assert_eq!(
        transport.exchanges, before,
        "the retry must exchange nothing"
    );
    assert!(matches!(session.finish(), Err(SessionError::OutOfOrder)));
}

#[cfg(feature = "std")]
/// A session the device already killed reports its failure again, not
/// success.
#[test]
fn the_runner_reports_a_dead_session_rather_than_success() {
    let fixture = fixture_v5_orchard_spend();
    let mut session = LedgerSignSession::new(
        &fixture.bytes,
        caps(),
        fixture.params(fixture.change_info()),
    )
    .expect("session");
    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, false);
    device.fail_at = Some((review_exchange_index(&session), StatusWord::Deny.to_u16()));
    let mut transport = FakeTransport::new(device);

    let mut reviews = 0;
    let err = ceremony::run_session(&mut transport, &mut session, || reviews += 1)
        .expect_err("the user declined");
    assert!(
        matches!(
            err,
            CeremonyError::Session {
                source: SessionError::UserRejected {
                    stage: Stage::Streaming
                },
                restartable: true,
            }
        ),
        "unexpected error: {err}"
    );
    assert_eq!(reviews, 1);
    assert_eq!(session.stage(), Stage::Failed);

    let before = transport.exchanges;
    let err = ceremony::run_session(&mut transport, &mut session, || reviews += 1)
        .expect_err("a dead session stays dead");
    assert!(
        matches!(
            err,
            CeremonyError::Session {
                source: SessionError::UserRejected { .. },
                restartable: true,
            }
        ),
        "unexpected error: {err}"
    );
    assert_eq!(transport.exchanges, before);
    assert_eq!(reviews, 1, "no second review is announced");
}

#[cfg(feature = "std")]
/// `query` resends a one-shot command while the device SDK refuses the frame
/// with `0x6901`, and gives up after the first attempt plus the engine's
/// retry budget, reporting exactly how many times it sent.
#[test]
fn the_query_runner_resends_on_6901_and_stops_at_the_budget() {
    let budget = pczt_ledger::session::MAX_CMD_NOT_ACCEPTED_RETRIES;

    // Two refusals, then the answer.
    let mut transport = FakeTransport::new(FakeDevice::new());
    transport.device.refuse_from = Some((0, 2));
    let caps = ceremony::query(
        &mut transport,
        &pairing::firmware_version_apdu(),
        Deadline::Normal,
        Ins::GetFirmwareVersion,
        pairing::device_caps,
    )
    .expect("answered on the third attempt");
    assert_eq!(caps, DeviceCaps::from_version(3, 9, 2));
    assert_eq!(transport.exchanges, 3);
    assert!(
        transport.device.received.windows(2).all(|w| w[0] == w[1]),
        "every resend is the identical command"
    );

    // A device that never stops refusing.
    let mut transport = FakeTransport::new(FakeDevice::new());
    transport.device.refuse_from = Some((0, u32::MAX));
    let err = ceremony::query(
        &mut transport,
        &pairing::firmware_version_apdu(),
        Deadline::Normal,
        Ins::GetFirmwareVersion,
        pairing::device_caps,
    )
    .expect_err("the budget runs out");
    assert!(
        matches!(
            err,
            QueryError::RefusedRepeatedly {
                what: Ins::GetFirmwareVersion,
                attempts,
            } if attempts == budget + 1
        ),
        "{err:?}"
    );
    assert!(
        err.to_string().starts_with("GET_FIRMWARE_VERSION: "),
        "the command is named the way the firmware names it: {err}"
    );
    assert_eq!(transport.exchanges, (budget + 1) as usize);
}

#[cfg(feature = "std")]
/// A query tells a transport failure from a device refusal, and a refusal
/// that is not `0x6901` ends it after one exchange.
#[test]
fn a_query_reports_the_transport_and_the_device_apart() {
    let mut transport = FakeTransport::new(FakeDevice::new());
    transport.fail_at = Some(0);
    let err = ceremony::query(
        &mut transport,
        &pairing::firmware_version_apdu(),
        Deadline::Normal,
        Ins::GetFirmwareVersion,
        pairing::device_caps,
    )
    .expect_err("the wire failed");
    assert!(
        matches!(
            err,
            QueryError::Transport {
                what: Ins::GetFirmwareVersion,
                source: TransportError::ConnectionClosed,
            }
        ),
        "{err:?}"
    );
    assert_eq!(transport.exchanges, 1);

    let mut transport = FakeTransport::new(FakeDevice::new());
    transport.device.fail_at = Some((0, StatusWord::IncorrectData.to_u16()));
    let err = ceremony::query(
        &mut transport,
        &pairing::firmware_version_apdu(),
        Deadline::Normal,
        Ins::GetFirmwareVersion,
        pairing::device_caps,
    )
    .expect_err("the device refused");
    assert!(
        matches!(
            err,
            QueryError::Pairing {
                what: Ins::GetFirmwareVersion,
                source: pairing::PairingError::Device {
                    status: StatusWord::IncorrectData,
                },
            }
        ),
        "{err:?}"
    );
    assert_eq!(
        transport.exchanges, 1,
        "a refusal that is not 0x6901 is not retried"
    );
}

#[cfg(feature = "std")]
/// A completed session is the one state a second run may answer `Ok(())` to,
/// and it does so without touching the transport.
#[test]
fn the_runner_is_idempotent_once_the_session_is_complete() {
    let fixture = fixture_v5_transparent_to_orchard();
    let mut session =
        LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(None)).expect("session");
    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, false);
    let mut transport = FakeTransport::new(device);

    ceremony::run_session(&mut transport, &mut session, || {}).expect("the ceremony completes");
    assert_eq!(session.stage(), Stage::Complete);
    // The runner passes the session's deadline through: every exchange up
    // to the review packet is bounded, and from it on the wait is the user's.
    let review = review_exchange_index(&session);
    assert!(review > 0 && review < transport.deadlines.len());
    assert!(transport.deadlines[..review]
        .iter()
        .all(|&d| d == Deadline::Normal));
    assert!(transport.deadlines[review..]
        .iter()
        .all(|&d| d == Deadline::UserReview));
    let before = transport.exchanges;
    ceremony::run_session(&mut transport, &mut session, || {}).expect("already complete");
    assert_eq!(transport.exchanges, before);
    session.finish().expect("finish");
}

// ---------------------------------------------------------------------------
// The return path
// ---------------------------------------------------------------------------

/// The two device quirks are undone: the `0x31` header byte and the trailing
/// sighash byte.
#[test]
fn der_normalization_undoes_the_device_quirks() {
    let secp = secp256k1::Secp256k1::new();
    let sk = secp256k1::SecretKey::from_slice(&[9u8; 32]).expect("key");
    let sig = secp.sign_ecdsa(&secp256k1::Message::from_digest([3u8; 32]), &sk);
    let canonical = sig.serialize_der().to_vec();

    // With only the trailing sighash byte: the form the device sends for an
    // even-`y` signature.
    let mut with_sighash = canonical.clone();
    with_sighash.push(0x01);
    assert_eq!(
        normalize_ledger_der(&with_sighash)
            .expect("trailing byte stripped")
            .serialize_der()[..],
        canonical[..],
    );

    // A high-`s` signature is normalized to its low-`s` form — the one
    // `secp256k1`'s verifier, and so `Signer::append_transparent_signature`,
    // accepts.
    let mut compact = sig.serialize_compact();
    let s_bytes: [u8; 32] = compact[32..].try_into().expect("32 bytes");
    let s = secp256k1::Scalar::from_be_bytes(s_bytes).expect("a scalar");
    let order_minus_s = {
        // n - s, computed with the negation `SecretKey` exposes.
        let mut as_key = secp256k1::SecretKey::from_slice(&s_bytes).expect("s is a key");
        as_key = as_key.negate();
        as_key.secret_bytes()
    };
    let _ = s;
    compact[32..].copy_from_slice(&order_minus_s);
    let high_s = secp256k1::ecdsa::Signature::from_compact(&compact).expect("high-s parses");
    let mut high_s_der = high_s.serialize_der().to_vec();
    assert_ne!(
        high_s_der, canonical,
        "the crafted signature is the high-s form"
    );
    high_s_der.push(SIGHASH_ALL);
    assert_eq!(
        normalize_ledger_der(&high_s_der)
            .expect("high-s is normalized")
            .serialize_der()[..],
        canonical[..],
    );

    // A long-form length byte is refused by name, ahead of the parser: the
    // sighash checks read the short-form length, and `secp256k1` accepts a
    // minimally encoded long form.
    let mut long_form = vec![0x30, 0x81, (canonical.len() - 2) as u8];
    long_form.extend_from_slice(&canonical[2..]);
    long_form.push(SIGHASH_ALL);
    assert_eq!(
        normalize_ledger_der(&long_form),
        Err(ApplyError::DerLengthLongForm { got: 0x81 })
    );

    // No sighash byte at all is not a device reply: the device always appends
    // one, with or without the header quirk.
    for bare in [canonical.clone(), {
        let mut quirked = canonical.clone();
        quirked[0] = LEDGER_DER_PARITY_TAG;
        quirked
    }] {
        assert_eq!(
            normalize_ledger_der(&bare),
            Err(ApplyError::MissingSighashType {
                expected: canonical.len() + 1,
                got: canonical.len(),
            })
        );
    }
    // Nor is one with two bytes past the DER length.
    let mut two_trailing = with_sighash.clone();
    two_trailing.push(SIGHASH_ALL);
    assert_eq!(
        normalize_ledger_der(&two_trailing),
        Err(ApplyError::MissingSighashType {
            expected: canonical.len() + 1,
            got: canonical.len() + 2,
        })
    );

    // Too short to be anything.
    assert_eq!(
        normalize_ledger_der(&[0x30]),
        Err(ApplyError::DerTooShort { got: 1 })
    );

    // With both quirks.
    let mut both = with_sighash.clone();
    both[0] = LEDGER_DER_PARITY_TAG;
    assert_eq!(
        normalize_ledger_der(&both)
            .expect("both quirks undone")
            .serialize_der()[..],
        canonical[..],
    );

    // A trailing byte that is not SIGHASH_ALL is refused: the device only ever
    // signs SIGHASH_ALL, so anything else means the reply is not what it claims.
    let mut wrong = canonical.clone();
    wrong.push(0x02);
    assert!(matches!(
        normalize_ledger_der(&wrong),
        Err(ApplyError::UnexpectedSighashType { got: 0x02 })
    ));

    // Garbage is refused rather than silently mangled.
    assert!(matches!(
        normalize_ledger_der(&[0x30]),
        Err(ApplyError::DerTooShort { got: 1 })
    ));
    assert!(matches!(
        normalize_ledger_der(&[0x30, 0x02, 0x00, 0x00, SIGHASH_ALL]),
        Err(ApplyError::DerInvalid(_))
    ));

    // The all-zero signature is canonical DER, so neither `from_der` nor the
    // round trip refuses it; it is refused by name.
    assert_eq!(
        normalize_ledger_der(&[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, SIGHASH_ALL]),
        Err(ApplyError::ZeroScalar { scalar: "r" })
    );
}

/// Applying the return path stamps every transparent input's
/// `hash160_preimage`, which is what lets the downstream Spend Finalizer
/// assemble the `script_sig`.
#[test]
fn applying_signatures_stamps_the_hash160_preimages() {
    let fixture = fixture_v6_ironwood();
    let mut session =
        LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(None)).expect("session");

    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, true);
    run_session(&mut session, &mut device).expect("ceremony completes");
    let outcome = session.finish().expect("finish");

    let signed = Pczt::parse(outcome.pczt_with_sigs()).expect("parses");

    // Assert through the Verifier role, which is the only public read path onto
    // `hash160_preimages` and `partial_signatures`.
    let mut checked = 0usize;
    Verifier::new(signed)
        .with_transparent::<(), _>(|bundle| {
            for input in bundle.inputs() {
                let pubkey = *input
                    .bip32_derivation()
                    .keys()
                    .next()
                    .expect("the fixture stamped a derivation");
                assert_eq!(
                    input.hash160_preimages().get(&hash160(&pubkey)),
                    Some(&pubkey.to_vec()),
                    "the controlling pubkey must be recoverable from its hash",
                );
                assert!(
                    input.partial_signatures().contains_key(&pubkey),
                    "the device signature must be attached to its pubkey",
                );
                checked += 1;
            }
            Ok(())
        })
        .expect("verifier");
    assert_eq!(checked, 1);
}

/// A signature applied to the wrong action is rejected: the `orchard` crate
/// verifies each one against that action's randomized verification key.
#[test]
fn a_signature_for_the_wrong_action_is_rejected() {
    let fixture = fixture_v5_orchard_spend();
    let shaped = shape_for_device(
        fixture.pczt(),
        &ShapeParams::new(FIXTURE_COIN_TYPE, account())
            .with_seed_fingerprint(Some(SEED_FINGERPRINT))
            .with_change(fixture.change_info()),
    )
    .expect("shapes");

    let plan = build_plan(shaped.pczt()).expect("plans");
    let real = plan.orchard_real_spends()[0];

    let mut signer = Signer::new(shaped.pczt().clone()).expect("signer");
    signer
        .sign_orchard(real, &fixture.orchard_ask)
        .expect("sign");
    let sig = orchard_sig(&signer.finish(), real, false);

    // Point the same signature at a different action index.
    let other = (0..plan.stream().orchard_actions().len())
        .find(|i| *i != real)
        .expect("the bundle is padded to at least two actions");
    let err = apply_device_signatures(
        shaped.into_pczt(),
        &DeviceSignatures::new(vec![(other, sig)], Vec::new(), Vec::new()),
    )
    .expect_err("the signature does not verify against that action's rk");
    assert!(matches!(err, ApplyError::Signer(_)), "unexpected: {err:?}");
}

// ---------------------------------------------------------------------------
// Plan-level invariants
// ---------------------------------------------------------------------------

/// The device's dummy rule (`spend_value == 0`) and the host's
/// needs-a-signature rule (`spend_auth_sig` absent) must agree on every action,
/// or the two signing loops would count different sets. The fixtures satisfy it
/// because the IO Finalizer self-signs exactly the padding dummies.
#[test]
fn the_two_dummy_rules_agree_on_every_fixture() {
    let mut ironwood_actions_checked = 0;
    let mut real_ironwood_spends_checked = 0;
    for bytes in [
        fixture_v5_transparent_to_orchard().bytes,
        fixture_v5_orchard_spend().bytes,
        fixture_v6_ironwood().bytes,
        fixture_v6_ironwood_spend().bytes,
    ] {
        let pczt = Pczt::parse(&bytes).expect("parses");
        let plan = build_plan(&pczt).expect("a divergence would be an error here");

        for (index, action) in plan.stream().orchard_actions().iter().enumerate() {
            let real = plan.orchard_real_spends().contains(&index);
            assert_eq!(real, action.spend_value() != 0);
        }
        for (index, action) in plan
            .stream()
            .ironwood_actions()
            .into_iter()
            .flatten()
            .enumerate()
        {
            let real = plan.ironwood_real_spends().contains(&index);
            assert_eq!(real, action.spend_value() != 0);
            ironwood_actions_checked += 1;
            real_ironwood_spends_checked += usize::from(real);
        }
    }
    // The Ironwood rule was really exercised, on padding and on a real spend.
    assert!(ironwood_actions_checked >= 2);
    assert_eq!(real_ironwood_spends_checked, 1);
}

/// What the device reads off the wire is what the PCZT holds, field by field,
/// through a grammar written from the firmware rather than from the encoder,
/// for every shape the crate streams. An encoder that put a value, a nullifier
/// or a commitment in the wrong place would show the user one transaction and
/// have the device sign another, and nothing but this comparison would notice.
#[test]
fn the_device_reads_the_pczts_own_values() {
    for (name, fixture) in [
        ("transparent only", fixture_v5_transparent_only()),
        (
            "transparent to Orchard",
            fixture_v5_transparent_to_orchard(),
        ),
        (
            "Orchard spend with transparent change",
            fixture_v5_orchard_spend(),
        ),
        ("Ironwood spend", fixture_v6_ironwood_spend()),
    ] {
        let mut session = LedgerSignSession::new(
            &fixture.bytes,
            caps(),
            fixture.params(fixture.change_info()),
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        let shaped = session.shaped_pczt().clone();
        let mut device = FakeDevice::new();
        canned_signatures(&fixture, &shaped, &mut device, true);
        run_session(&mut session, &mut device).unwrap_or_else(|e| panic!("{name}: {e}"));
        session.finish().unwrap_or_else(|e| panic!("{name}: {e}"));

        assert_wire_matches(name, device.wire(), &shaped, session.plan());
    }
}

/// Every field the device read, against the (shaped) PCZT it was read from.
fn assert_wire_matches(name: &str, wire: &Wire, pczt: &Pczt, plan: &pczt_ledger::plan::Plan) {
    assert!(wire.finished, "{name}: the FINISHED marker was accepted");

    let header = wire.header.as_ref().expect("a header was streamed");
    let global = pczt.global();
    assert_eq!(
        header.tx_version,
        *global.tx_version(),
        "{name}: tx_version"
    );
    assert_eq!(
        header.version_group_id,
        *global.version_group_id(),
        "{name}: version_group_id"
    );
    assert_eq!(
        header.consensus_branch_id,
        *global.consensus_branch_id(),
        "{name}: consensus_branch_id"
    );
    assert_eq!(
        header.expiry_height,
        *global.expiry_height(),
        "{name}: expiry"
    );
    assert_eq!(header.coin_type, FIXTURE_COIN_TYPE, "{name}: coin type");
    assert_eq!(
        header.pczt_version,
        if plan.format() == TxFormat::V6 { 2 } else { 1 },
        "{name}"
    );
    assert_eq!(
        header.fallback_lock_time,
        plan.global().fallback_lock_time(),
        "{name}"
    );
    assert_eq!(
        header.tx_modifiable,
        plan.global().tx_modifiable(),
        "{name}"
    );

    let inputs = pczt.transparent().inputs();
    assert_eq!(
        wire.transparent_inputs.len(),
        inputs.len(),
        "{name}: input count"
    );
    for (i, (got, want)) in wire.transparent_inputs.iter().zip(inputs).enumerate() {
        assert_eq!(
            got.prevout_txid,
            want.prevout_txid().to_vec(),
            "{name}: input {i} txid"
        );
        assert_eq!(
            got.prevout_index,
            *want.prevout_index(),
            "{name}: input {i} vout"
        );
        assert_eq!(got.sequence, *want.sequence(), "{name}: input {i} sequence");
        assert_eq!(got.value, *want.value(), "{name}: input {i} value");
        assert_eq!(
            &got.script_pubkey,
            want.script_pubkey(),
            "{name}: input {i} script"
        );
    }

    let outputs = pczt.transparent().outputs();
    assert_eq!(
        wire.transparent_outputs.len(),
        outputs.len(),
        "{name}: output count"
    );
    for (i, (got, want)) in wire.transparent_outputs.iter().zip(outputs).enumerate() {
        assert_eq!(got.value, *want.value(), "{name}: output {i} value");
        assert_eq!(
            &got.script_pubkey,
            want.script_pubkey(),
            "{name}: output {i} script"
        );
    }

    assert_actions_match(
        name,
        "Orchard",
        &wire.orchard_actions,
        wire.orchard_trailer.as_ref(),
        pczt.orchard(),
        false,
    );
    assert_eq!(
        wire.orchard_count,
        Some(pczt.orchard().actions().len()),
        "{name}"
    );
    if plan.format() == TxFormat::V6 {
        assert_actions_match(
            name,
            "Ironwood",
            &wire.ironwood_actions,
            wire.ironwood_trailer.as_ref(),
            pczt.ironwood(),
            true,
        );
        assert_eq!(
            wire.ironwood_count,
            Some(pczt.ironwood().actions().len()),
            "{name}"
        );
    } else {
        assert!(
            wire.ironwood_actions.is_empty(),
            "{name}: no Ironwood command on V5"
        );
        assert_eq!(wire.ironwood_count, None, "{name}");
    }

    // The derivations, through the parsed view — the only place the
    // fingerprint and path are readable.
    let verifier = Verifier::new(pczt.clone())
        .with_transparent::<(), _>(|bundle| {
            for (i, input) in bundle.inputs().iter().enumerate() {
                assert_eq!(
                    wire.transparent_inputs[i].sighash_type,
                    input.sighash_type().encode(),
                    "{name}: input {i} sighash"
                );
                let (pubkey, want) = input.bip32_derivation().iter().next().expect("stamped");
                let got = wire.transparent_inputs[i]
                    .derivation
                    .as_ref()
                    .expect("every input carries its derivation");
                assert_eq!(got.pubkey, pubkey.to_vec());
                assert_eq!(got.seed_fingerprint, vec![0u8; 32]);
                assert_eq!(
                    got.path,
                    want.derivation_path()
                        .iter()
                        .copied()
                        .map(u32::from)
                        .collect::<Vec<_>>(),
                    "{name}: input {i} path"
                );
            }
            for (i, output) in bundle.outputs().iter().enumerate() {
                let want = output.bip32_derivation().iter().next();
                let got = wire.transparent_outputs[i].derivation.as_ref();
                assert_eq!(got.is_some(), want.is_some(), "{name}: output {i} marking");
                if let (Some(got), Some((pubkey, want))) = (got, want) {
                    assert_eq!(got.pubkey, pubkey.to_vec());
                    assert_eq!(got.seed_fingerprint, vec![0u8; 32]);
                    assert_eq!(
                        got.path,
                        want.derivation_path()
                            .iter()
                            .copied()
                            .map(u32::from)
                            .collect::<Vec<_>>(),
                        "{name}: output {i} path"
                    );
                }
            }
            Ok(())
        })
        .expect("the transparent bundle verifies");
    let check_pool = |pool: &str, got: &[WireAction], actions: &[orchard::pczt::Action]| {
        for (i, (got, action)) in got.iter().zip(actions).enumerate() {
            let at = format!("{name}: {pool} action {i}");
            let spend = action.spend();
            let want = spend
                .zip32_derivation()
                .as_ref()
                .expect("shaping stamps every action");
            assert_eq!(got.seed_fingerprint, vec![0u8; 32], "{at} fp");
            assert_eq!(
                got.path,
                want.derivation_path()
                    .iter()
                    .map(|c| c.index())
                    .collect::<Vec<_>>(),
                "{at} path"
            );
            // The spend-side fields the raw PCZT keeps to itself.
            assert_eq!(
                got.spend_recipient,
                spend
                    .recipient()
                    .expect("recipient")
                    .to_raw_address_bytes()
                    .to_vec(),
                "{at} spend recipient"
            );
            assert_eq!(
                got.spend_value,
                spend.value().expect("value").inner(),
                "{at} spend value"
            );
            assert_eq!(
                got.spend_rho,
                spend.rho().expect("rho").to_bytes().to_vec(),
                "{at} rho"
            );
            assert_eq!(
                got.spend_rseed,
                spend.rseed().expect("rseed").as_bytes().to_vec(),
                "{at} spend rseed"
            );
            assert_eq!(
                got.alpha,
                ff::PrimeField::to_repr(&spend.alpha().expect("alpha")).to_vec(),
                "{at} alpha"
            );
            assert_eq!(
                got.rcv,
                action.rcv().as_ref().expect("rcv").to_bytes().to_vec(),
                "{at} rcv"
            );
        }
    };
    let verifier = if pczt.orchard().actions().is_empty() {
        verifier
    } else {
        verifier
            .with_orchard::<(), _>(|bundle| {
                check_pool("Orchard", &wire.orchard_actions, bundle.actions());
                Ok(())
            })
            .expect("the Orchard bundle verifies")
    };
    if !pczt.ironwood().actions().is_empty() {
        verifier
            .with_ironwood::<(), _>(|bundle| {
                check_pool("Ironwood", &wire.ironwood_actions, bundle.actions());
                Ok(())
            })
            .expect("the Ironwood bundle verifies");
    }
}

/// One shielded pool's actions and trailer, against the PCZT's bundle.
fn assert_actions_match(
    name: &str,
    pool: &str,
    got: &[WireAction],
    trailer: Option<&WireTrailer>,
    bundle: &pczt::orchard::Bundle,
    ironwood: bool,
) {
    let actions = bundle.actions();
    assert_eq!(got.len(), actions.len(), "{name}: {pool} action count");
    for (i, (g, w)) in got.iter().zip(actions).enumerate() {
        let at = format!("{name}: {pool} action {i}");
        let spend = w.spend();
        let output = w.output();
        assert_eq!(
            g.cv_net,
            w.cv_net().expect("cv_net").to_vec(),
            "{at} cv_net"
        );
        assert_eq!(g.nullifier, spend.nullifier().to_vec(), "{at} nullifier");
        assert_eq!(g.rk, spend.rk().to_vec(), "{at} rk");
        assert_eq!(g.cmx, output.cmx().expect("cmx").to_vec(), "{at} cmx");
        assert_eq!(g.ephemeral_key, output.ephemeral_key().to_vec(), "{at} epk");
        assert_eq!(
            Some(g.enc_ciphertext.clone()),
            output.enc_ciphertext().clone().into_encrypted(),
            "{at} enc_ciphertext"
        );
        assert_eq!(
            &g.out_ciphertext,
            output.out_ciphertext(),
            "{at} out_ciphertext"
        );
        assert_eq!(
            g.recipient,
            output.recipient().expect("recipient").to_vec(),
            "{at} recipient"
        );
        assert_eq!(g.value, output.value().expect("value"), "{at} value");
        assert_eq!(
            g.rseed,
            output.rseed().expect("rseed").to_vec(),
            "{at} rseed"
        );
        assert_eq!(
            g.note_plaintext_version,
            if ironwood { Some(0x03) } else { None },
            "{at} note version byte"
        );
    }
    match trailer {
        None => assert!(
            actions.is_empty(),
            "{name}: {pool} has actions but no trailer"
        ),
        Some(t) => {
            assert!(
                !actions.is_empty(),
                "{name}: {pool} trailer without actions"
            );
            assert_eq!(t.flags, *bundle.flags(), "{name}: {pool} flags");
            assert_eq!(
                (t.value_sum_magnitude, t.value_sum_negative),
                *bundle.value_sum(),
                "{name}: {pool} value_sum"
            );
            assert_eq!(
                t.anchor,
                bundle.anchor().expect("anchor").to_vec(),
                "{name}: {pool} anchor"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Plan refusals
// ---------------------------------------------------------------------------

/// `read_global` reads a real `pczt::common::Global` — the three fields the
/// `pczt` crate exposes only through serde included — so an upstream rename or
/// retype of the struct is caught here, not only by the hand-written JSON the
/// unit test feeds the view.
#[test]
fn read_global_reads_a_real_global() {
    const LOCK_TIME: u32 = 0x89AB_CDEF;
    const EXPIRY: u32 = 3_400_000;
    const COIN_TYPE: u32 = 133;
    // `pczt::roles::creator::INITIAL_TX_MODIFIABLE`.
    const INITIAL_TX_MODIFIABLE: u8 = 0b1000_0011;
    let nu6_2 = u32::from(BranchId::Nu6_2);

    let pczt = Creator::new(nu6_2, EXPIRY, COIN_TYPE, Some([0u8; 32]), Some([0u8; 32]))
        .expect("a supported branch")
        .with_fallback_lock_time(LOCK_TIME)
        .build()
        .expect("an empty PCZT builds");

    let global = pczt_ledger::plan::read_global(&pczt).expect("read_global");
    assert_eq!(global.tx_version(), pczt_ledger::limits::V5_TX_VERSION);
    assert_eq!(
        global.version_group_id(),
        pczt_ledger::limits::V5_VERSION_GROUP_ID
    );
    assert_eq!(global.consensus_branch_id(), BranchId::Nu6_2);
    assert_eq!(global.expiry_height(), BlockHeight::from_u32(EXPIRY));
    assert_eq!(global.coin_type(), COIN_TYPE);
    assert_eq!(global.fallback_lock_time(), Some(LOCK_TIME));
    assert_eq!(global.tx_modifiable(), INITIAL_TX_MODIFIABLE);
    assert_eq!(global.format().expect("V5"), TxFormat::V5);
}

/// Re-encodes a PCZT through its JSON form with one field patched. Only a
/// PCZT whose transparent maps are empty is JSON, so the fixtures used with
/// this are built unstamped.
fn patch_json(pczt: Pczt, patch: impl FnOnce(&mut serde_json::Value)) -> Pczt {
    let v2 = pczt::v2::Pczt::try_from(pczt).expect("encodes as PCZT v2");
    let mut value = serde_json::to_value(&v2).expect("a PCZT without transparent maps is JSON");
    patch(&mut value);
    let patched: pczt::v2::Pczt = serde_json::from_value(value).expect("the patched form parses");
    Pczt::parse(&patched.serialize()).expect("the v2 encoding parses")
}

/// A `redeem_script` on a transparent input is refused before the first
/// APDU. The field belongs to a P2SH coin; on the P2PKH inputs this app
/// signs, the device signs the same digest regardless, but the `pczt` Signer
/// role keys the script code off `redeem_script.unwrap_or(script_pubkey)`
/// (`append_signature`, `zcash_transparent` 0.10) and finds no preimage
/// under it, so the signature the user approved could only fail to apply.
#[test]
fn a_redeem_script_on_a_transparent_input_is_refused() {
    // Built unstamped so that it is JSON, patched, then stamped the way a
    // wallet stamps it.
    let fixture = fixture_v5_transparent_only_with(None);
    let mut p2pkh = vec![0x76, 0xA9, 0x14];
    p2pkh.extend_from_slice(&[0x11; 20]);
    p2pkh.extend_from_slice(&[0x88, 0xAC]);
    let patched = patch_json(fixture.pczt(), |v| {
        v["transparent"]["inputs"][0]["redeem_script"] = serde_json::json!(p2pkh);
    });
    let pubkey = transparent_keys(&v5_network()).pubkey.serialize();
    let stamped = stamp_transparent_input_derivations(patched, pubkey);

    let refusal = PlanError::RedeemScriptPresent { index: 0 };
    assert_eq!(build_plan(&stamped).expect_err("refused"), refusal);

    let err = LedgerSignSession::new(
        &stamped.serialize().expect("serializes"),
        caps(),
        fixture.params(fixture.change_info()),
    )
    .expect_err("the session refuses it before any APDU is queued");
    assert_eq!(
        err,
        SessionError::Validation(vec![LedgerViolation::Plan(refusal)])
    );
}

/// A transparent record carries exactly one derivation or, for an output,
/// none: no derivation on an input leaves the device without a signing key,
/// and two on either record leave it without a single one.
#[test]
fn a_transparent_record_with_other_than_one_derivation_is_refused() {
    assert_eq!(
        build_plan(&fixture_v5_transparent_only_with(None).pczt()).expect_err("no derivation"),
        PlanError::TransparentDerivationCount { index: 0, got: 0 }
    );

    let path = vec![
        44 | HARDENED,
        FIXTURE_COIN_TYPE | HARDENED,
        ACCOUNT | HARDENED,
        0,
        0,
    ];
    let stamp_twice = |pczt: Pczt, on_output: bool| {
        Updater::new(pczt)
            .update_transparent_with(|mut updater| {
                for pubkey in [[0x02u8; 33], [0x03u8; 33]] {
                    let derivation = zcash_transparent::pczt::Bip32Derivation::parse(
                        SEED_FINGERPRINT,
                        path.clone(),
                    )
                    .expect("valid derivation");
                    if on_output {
                        updater.update_output_with(0, |mut output| {
                            output.set_bip32_derivation(pubkey, derivation);
                            Ok(())
                        })?;
                    } else {
                        updater.update_input_with(0, |mut input| {
                            input.set_bip32_derivation(pubkey, derivation);
                            Ok(())
                        })?;
                    }
                }
                Ok(())
            })
            .expect("updater")
            .finish()
    };
    let fixture = fixture_v5_transparent_only();
    assert_eq!(
        build_plan(&stamp_twice(fixture.pczt(), false)).expect_err("three on the input"),
        PlanError::TransparentDerivationCount { index: 0, got: 3 }
    );
    assert_eq!(
        build_plan(&stamp_twice(fixture.pczt(), true)).expect_err("two on the output"),
        PlanError::OutputDerivationCount { index: 0, got: 2 }
    );
}

/// A bundle the upstream parser refuses surfaces as that section's parse
/// error, with the parser's own reason.
#[test]
fn a_bundle_the_parser_refuses_is_a_parse_error() {
    let bad_sighash = patch_json(fixture_v5_transparent_only_with(None).pczt(), |v| {
        v["transparent"]["inputs"][0]["sighash_type"] = serde_json::json!(0xFF);
    });
    assert!(matches!(
        build_plan(&bad_sighash).expect_err("an invalid sighash type"),
        PlanError::TransparentParse(_)
    ));

    let bad_commitment = patch_json(fixture_v6_ironwood_spend().pczt(), |v| {
        v["ironwood"]["actions"][0]["cv_net"] = serde_json::json!(vec![0xFFu8; 32]);
    });
    assert!(matches!(
        build_plan(&bad_commitment).expect_err("cv_net is not a point"),
        PlanError::IronwoodParse(_)
    ));
}

/// The device refuses a trailer whose value sum is not what the actions add
/// up to, and cannot carry one past `i64`; both are refused here first. A
/// note value past `MAX_MONEY` is refused at the action.
#[test]
fn a_bundle_with_an_impossible_value_is_refused() {
    let off_by_one = patch_json(fixture_v5_orchard_spend().pczt(), |v| {
        let magnitude = v["orchard"]["value_sum"][0]
            .as_u64()
            .expect("the value sum's magnitude");
        v["orchard"]["value_sum"][0] = serde_json::json!(magnitude + 1);
    });
    assert_eq!(
        build_plan(&off_by_one).expect_err("a value sum off by one"),
        PlanError::ValueSumMismatch {
            section: Section::Orchard
        }
    );

    let past_i64 = patch_json(fixture_v5_orchard_spend().pczt(), |v| {
        v["orchard"]["value_sum"][0] = serde_json::json!(u64::MAX);
    });
    assert_eq!(
        build_plan(&past_i64).expect_err("a value sum past i64"),
        PlanError::ValueSumOutOfRange {
            section: Section::Orchard
        }
    );

    let past_max_money = patch_json(fixture_v5_orchard_spend().pczt(), |v| {
        v["orchard"]["actions"][0]["spend"]["value"] =
            serde_json::json!(zcash_protocol::value::MAX_MONEY + 1);
    });
    assert_eq!(
        build_plan(&past_max_money).expect_err("a spend past MAX_MONEY"),
        PlanError::ValueOutOfRange {
            section: Section::Orchard,
            index: 0,
            field: "spend value",
        }
    );
}

/// A transparent input that requires a lock time is refused before the first
/// APDU: the device's compact subset carries only `fallback_lock_time`, so a
/// signature over what the device computes would commit to a different
/// `nLockTime` than the host's transaction.
#[test]
fn a_required_lock_time_on_an_input_is_refused() {
    // A height, and a time (the `pczt` parser takes anything below
    // 500 000 000 for a height, as `nLockTime` does).
    for (field, lock) in [
        ("required_height_lock_time", 2_000_000u32),
        ("required_time_lock_time", 2_000_000_000u32),
    ] {
        let pczt = patch_json(fixture_v5_transparent_only_with(None).pczt(), |v| {
            v["transparent"]["inputs"][0][field] = serde_json::json!(lock);
        });
        assert_eq!(
            build_plan(&pczt).expect_err(field),
            PlanError::TransparentLockTimeRequired { index: 0 },
            "{field}"
        );
    }
}

/// A transaction version before V5 is refused by the plan itself, before the
/// device would.
#[test]
fn a_pre_v5_transaction_version_is_refused() {
    const V4_VERSION_GROUP_ID: u32 = 0x892F_2085;
    let pczt = patch_json(fixture_v5_transparent_only_with(None).pczt(), |v| {
        v["global"]["tx_version"] = serde_json::json!(4);
        v["global"]["version_group_id"] = serde_json::json!(V4_VERSION_GROUP_ID);
    });
    assert_eq!(
        build_plan(&pczt).expect_err("refused"),
        PlanError::UnsupportedTxVersion {
            tx_version: 4,
            version_group_id: V4_VERSION_GROUP_ID,
        }
    );
}

/// A zero-valued spend with no `spend_auth_sig` — the shape the post-NU6.3
/// builder emits for a wallet-controlled zero-value spend paired with change —
/// is where the host's rule ("needs a signature iff unsigned") and the
/// device's ("real iff `spend_value != 0`") part ways: the device would refuse
/// to sign it, after the review. Refused before the first APDU instead.
#[test]
fn an_unsigned_zero_valued_spend_is_refused_as_a_classification_mismatch() {
    let pczt = fixture_v5_orchard_spend().pczt();
    let plan = build_plan(&pczt).expect("plans");
    let dummy = (0..pczt.orchard().actions().len())
        .find(|i| !plan.orchard_real_spends().contains(i))
        .expect("the bundle is padded");

    let unsigned = Redactor::new(pczt)
        .redact_orchard_with(|mut r| r.redact_action(dummy, |mut a| a.clear_spend_auth_sig()))
        .finish();
    assert_eq!(
        build_plan(&unsigned).expect_err("refused"),
        PlanError::SpendClassificationMismatch {
            section: Section::Orchard,
            index: dummy,
            already_signed: false,
        }
    );
}

/// The other direction: a real spend that already carries a signature the
/// device did not produce. The device would sign it again on request and the
/// host would not ask; the plan refuses the disagreement outright.
#[test]
fn a_pre_signed_real_spend_is_refused_as_a_classification_mismatch() {
    let fixture = fixture_v5_orchard_spend();
    let pczt = fixture.pczt();
    let real = build_plan(&pczt).expect("plans").orchard_real_spends()[0];

    let mut signer = Signer::new(pczt).expect("signer");
    signer
        .sign_orchard(real, &fixture.orchard_ask)
        .expect("host-side signature");
    let signed = signer.finish();
    assert_eq!(
        build_plan(&signed).expect_err("refused"),
        PlanError::SpendClassificationMismatch {
            section: Section::Orchard,
            index: real,
            already_signed: true,
        }
    );
}

/// On V5 the `pczt` parser refuses an absent anchor before the plan's own
/// check runs, so the refusal arrives as a parse error; the plan's check is
/// what V6 reaches (next test).
#[test]
fn a_v5_bundle_without_an_anchor_is_refused_at_parse() {
    let stripped = Redactor::new(fixture_v5_orchard_spend().pczt())
        .redact_orchard_with(|mut r| r.clear_anchor())
        .finish();
    let err = build_plan(&stripped).expect_err("refused");
    assert!(
        matches!(&err, PlanError::OrchardParse(message) if message.contains("MissingAnchor")),
        "unexpected error: {err:?}"
    );
}

/// On V6 the `pczt` parser accepts a deferred (absent) anchor — the
/// `SignerView::Compact` shape — and the crate is what refuses it: the trailer
/// the device reads carries the anchor, and there is no encoding for an absent
/// one.
#[test]
fn a_deferred_v6_anchor_is_refused_as_missing() {
    let stripped = Redactor::new(fixture_v6_ironwood_spend().pczt())
        .redact_ironwood_with(|mut r| r.clear_anchor())
        .finish();
    let err = build_plan(&stripped).expect_err("refused");
    assert_eq!(
        err,
        PlanError::MissingAnchor {
            section: Section::Ironwood,
        },
        "unexpected error: {err:?}"
    );
}

/// A spend that still carries its `dummy_sk` — a PCZT that never went through
/// the IO Finalizer — is refused, as ZIP 374 requires of every signer, before
/// any other verdict on the action.
#[test]
fn a_spend_with_its_dummy_key_is_refused() {
    let unfinalized = Creator::build_from_parts(orchard_spend_parts().pczt_parts).expect("creator");
    let with_dummy_sk = (0..unfinalized.orchard().actions().len())
        .find(|i| {
            unfinalized.orchard().actions()[*i]
                .spend()
                .dummy_sk()
                .is_some()
        })
        .expect("the builder pads with a dummy that carries its key");
    assert_eq!(
        build_plan(&unfinalized).expect_err("refused"),
        PlanError::DummySpendingKeyPresent {
            section: Section::Orchard,
            index: with_dummy_sk,
        }
    );
}

/// A zero `alpha` would put the account's `ak` itself on chain as `rk`;
/// neither side checks for it in the signature path, so the plan does.
#[test]
fn a_zero_alpha_is_refused() {
    let zeroed = patch_json(fixture_v5_orchard_spend().pczt(), |v| {
        v["orchard"]["actions"][0]["spend"]["alpha"] = serde_json::json!([0u8; 32].to_vec());
    });
    let err = build_plan(&zeroed).expect_err("refused");
    assert!(
        matches!(
            &err,
            PlanError::ActionInconsistent {
                section: Section::Orchard,
                index: 0,
                check: "alpha",
                ..
            }
        ),
        "unexpected error: {err:?}"
    );
}

/// An output whose `cmx` is not the commitment of its declared recipient,
/// value and `rseed` is refused before the first APDU, whether it is a
/// padding dummy or a real output.
///
/// The device recomputes the commitment of a zero-valued output
/// (`validate_current_orchard_dummy_output`, `src/parser/pczt/orchard.rs` @
/// `22dc385`) and aborts mid-stream on a mismatch. For an output it
/// deciphers it never reads the streamed `rseed`: the user reviews the
/// recipient and value, the device signs, and the prover — which builds the
/// output note from the declared `rseed` against the declared `cmx` — emits
/// a proof that does not verify. Both are the one host check.
#[test]
fn an_output_whose_cmx_does_not_commit_to_its_note_is_refused() {
    let pczt = fixture_v5_orchard_spend().pczt();
    let is_dummy = |i: &usize| pczt.orchard().actions()[*i].output().value() == &Some(0);
    let actions = 0..pczt.orchard().actions().len();
    let dummy = actions
        .clone()
        .find(is_dummy)
        .expect("the builder pads with a zero-valued dummy output");
    let real = actions
        .clone()
        .find(|i| !is_dummy(i))
        .expect("the fixture pays one recipient");

    let flip_low_bit = |v: &mut serde_json::Value, index: usize, field: &str| {
        let slot = &mut v["orchard"]["actions"][index]["output"][field][0];
        let byte = slot.as_u64().expect("a byte");
        *slot = serde_json::json!(byte ^ 1);
    };
    // The dummy's `cmx`, one bit off; the real output's declared `rseed`,
    // one bit off with `cmx` and both ciphertexts intact, so the OVK trial
    // still opens it.
    let tampered = [
        (
            "dummy cmx",
            dummy,
            patch_json(pczt.clone(), |v| flip_low_bit(v, dummy, "cmx")),
        ),
        (
            "real rseed",
            real,
            patch_json(pczt, |v| flip_low_bit(v, real, "rseed")),
        ),
    ];
    for (name, index, pczt) in &tampered {
        for (keys, plan) in [
            ("blind", build_plan(pczt)),
            (
                "with keys",
                build_plan_with_keys(pczt, Some(&canned_viewing_keys())),
            ),
        ] {
            assert!(
                matches!(
                    &plan,
                    Err(PlanError::ActionInconsistent {
                        section: Section::Orchard,
                        index: i,
                        check: "cmx",
                        ..
                    }) if i == index
                ),
                "{name}, {keys}: {:?}",
                plan.err()
            );
        }
    }
}

/// The Orchard pool's post-NU6.3 rule, on the host: with cross-address
/// transfers disabled — as they are in every V6 Orchard bundle, which the
/// `pczt` parser types as `orchard_v3` — an action's output must pay the
/// receiver of the note it spends. Nothing after the host checks it: the
/// `pczt` Signer role does not, and the firmware only echoes the flags byte
/// (`parse_orchard_trailer`, `src/parser/pczt/orchard.rs` @ `22dc385`), so
/// an action paying elsewhere is streamed, reviewed, approved and signed,
/// and refused by the IO Finalizer or the prover afterwards.
#[test]
fn a_cross_address_transfer_in_a_restricted_bundle_is_refused() {
    let fixture = fixture_v6_ironwood_spend_with_orchard_padding();
    let pczt = fixture.pczt();
    // Padding pairs each dummy spend with a zero-valued output to the
    // dummy's own receiver, so the fixture as built passes.
    assert_eq!(pczt.orchard().actions().len(), 2);
    build_plan(&pczt).expect("padding actions pay their own receiver");

    let elsewhere = orchard_keys()
        .1
        .address_at(1u32, Scope::External)
        .to_raw_address_bytes();
    let tampered = patch_json(pczt, |v| {
        v["orchard"]["actions"][0]["output"]["recipient"] = serde_json::json!(elsewhere.to_vec());
    });
    let refusal = PlanError::CrossAddressTransferDisallowed {
        section: Section::Orchard,
    };
    assert_eq!(build_plan(&tampered).expect_err("refused"), refusal);

    let bytes = tampered.serialize().expect("serializes");
    let err = LedgerSignSession::new(&bytes, caps(), fixture.params(None))
        .expect_err("the session refuses it before any APDU is queued");
    assert_eq!(
        err,
        SessionError::Validation(vec![LedgerViolation::Plan(refusal)])
    );
}

/// An action missing a field the wire record needs is refused with the field
/// named, and the field name is the one a reader will look for in the record.
#[test]
fn an_action_missing_a_wire_field_is_refused_by_name() {
    let stripped = Redactor::new(fixture_v5_orchard_spend().pczt())
        .redact_orchard_with(|mut r| r.redact_action(1, |mut a| a.clear_output_value()))
        .finish();
    assert_eq!(
        build_plan(&stripped).expect_err("refused"),
        PlanError::MissingField {
            section: Section::Orchard,
            index: 1,
            field: "output.value",
        }
    );
}

/// `sequence` is mirrored from the PCZT verbatim, `None` and all.
#[test]
fn the_sequence_field_is_mirrored_verbatim() {
    let fixture = fixture_v5_transparent_to_orchard();
    let pczt = fixture.pczt();
    let plan = build_plan(&pczt).expect("plans");

    for (index, record) in plan.stream().transparent_inputs().iter().enumerate() {
        assert_eq!(
            record.sequence(),
            *pczt.transparent().inputs()[index].sequence()
        );
    }
}

/// The header mirrors the PCZT's own global fields, including the three the
/// `pczt` crate exposes only through serde.
#[test]
fn the_header_mirrors_the_pczt_global() {
    let fixture = fixture_v6_ironwood();
    let pczt = fixture.pczt();
    let plan = build_plan(&pczt).expect("plans");
    let header = plan.stream().header();

    assert_eq!(header.tx_version(), *pczt.global().tx_version());
    assert_eq!(header.version_group_id(), *pczt.global().version_group_id());
    assert_eq!(
        header.consensus_branch_id(),
        *pczt.global().consensus_branch_id()
    );
    assert_eq!(header.expiry_height(), *pczt.global().expiry_height());
    assert_eq!(header.coin_type(), FIXTURE_COIN_TYPE);
    assert_eq!(
        header.fallback_lock_time(),
        plan.global().fallback_lock_time()
    );
    assert_eq!(header.tx_modifiable(), plan.global().tx_modifiable());
}

/// A well-formed reply is never mistaken for a status word.
#[test]
fn responses_are_split_at_the_status_word() {
    let (data, sw) = split_status_word(&[1, 2, 3, 0x90, 0x00]).expect("splits");
    assert_eq!(data, &[1, 2, 3]);
    assert_eq!(sw, StatusWord::Ok);
}

// ---------------------------------------------------------------------------
// Pairing
// ---------------------------------------------------------------------------

/// The pairing flow: the firmware probe, the viewing-key export and the
/// address displays. A module so that `cargo test -- pairing` selects it.
mod pairing_flow {
    use super::*;

    /// The unified full viewing key a device exports for the fixture account
    /// on `network`, in `revision`: the Orchard item and the P2PKH item,
    /// which is what `GET_VK` returns and what makes the string long enough
    /// to need a continuation.
    fn fixture_ufvk(revision: zcash_address::unified::Revision, network: NetworkType) -> String {
        let p2pkh: [u8; 65] = account_pubkey()
            .serialize()
            .try_into()
            .expect("a pruned extended pubkey is 65 bytes");
        zcash_address::unified::Ufvk::try_from_items(
            revision,
            vec![
                zcash_address::unified::Uitem::Data(zcash_address::unified::Fvk::Orchard(
                    orchard_keys().1.to_bytes(),
                )),
                zcash_address::unified::Uitem::Data(zcash_address::unified::Fvk::P2pkh(p2pkh)),
            ],
        )
        .expect("an Orchard and a P2PKH item make a unified full viewing key")
        .encode(&network)
    }

    /// The unified address a device answers `GET_SHIELD_ADDR` with for the
    /// fixture account, in `revision`: the account's Orchard receiver at
    /// diversifier index 0, alone.
    fn fixture_unified_address(
        revision: zcash_address::unified::Revision,
    ) -> zcash_address::unified::Address {
        let (_, fvk) = orchard_keys();
        let receiver = fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
        zcash_address::unified::Address::try_from_items(
            revision,
            vec![zcash_address::unified::Uitem::Data(
                zcash_address::unified::Receiver::Orchard(receiver),
            )],
        )
        .expect("one Orchard receiver is a unified address")
    }

    /// Wraps an encoded string in the length-prefixed reply body the device
    /// sends, with its status word.
    fn string_reply(encoded: &str) -> Vec<u8> {
        let mut reply = (encoded.len() as u16).to_be_bytes().to_vec();
        reply.extend_from_slice(encoded.as_bytes());
        reply.extend_from_slice(&StatusWord::Ok.to_u16().to_be_bytes());
        reply
    }

    /// Feeds one whole UFVK reply, in chunks, to a fresh exchange, and
    /// returns the step that ended it along with the exchange.
    fn deliver_ufvk(encoded: &str) -> (Result<VkStep, pairing::PairingError>, pairing::VkExchange) {
        let mut exchange = pairing::VkExchange::ufvk(Network::Test, account()).expect("request");
        let mut payload = (encoded.len() as u16).to_be_bytes().to_vec();
        payload.extend_from_slice(encoded.as_bytes());
        let mut result = None;
        for chunk in payload.chunks(255) {
            let _ = exchange.next_apdu().expect("a command to answer");
            let mut reply = chunk.to_vec();
            reply.extend_from_slice(&StatusWord::Ok.to_u16().to_be_bytes());
            match exchange.process_response(&reply) {
                Ok(VkStep::MoreChunks) => {}
                other => {
                    result = Some(other);
                    break;
                }
            }
        }
        (result.expect("the reply completes or fails"), exchange)
    }

    /// The firmware probe maps a version onto capabilities. An older app answers an
    /// instruction it does not know with `InsNotSupported` and no diagnostic, so
    /// this is the only gate the host has.
    #[test]
    fn the_firmware_probe_derives_capabilities() {
        let apdu = pairing::firmware_version_apdu();
        assert_eq!(
            apdu,
            vec![
                pczt_ledger::apdu::CLA,
                Ins::GetFirmwareVersion.code(),
                0,
                0,
                0
            ],
        );

        let reply = |major, minor, patch| {
            let mut r = vec![0x38, 0x30, major, minor, patch, 2, 3, 22];
            r.extend_from_slice(&StatusWord::Ok.to_u16().to_be_bytes());
            r
        };

        let caps = pairing::device_caps(&reply(3, 9, 2)).expect("parses");
        assert!(caps.pczt());
        assert!(caps.ironwood());

        let caps = pairing::device_caps(&reply(3, 8, 0)).expect("parses");
        assert!(caps.pczt());
        assert!(!caps.ironwood());

        let caps = pairing::device_caps(&reply(3, 5, 0)).expect("parses");
        assert!(!caps.pczt());

        // A different app open on the device surfaces as a typed error, not a
        // malformed-response error.
        assert!(matches!(
            pairing::device_caps(&StatusWord::ClaNotSupported.to_u16().to_be_bytes()),
            Err(pairing::PairingError::WrongApp { .. })
        ));
    }

    /// The viewing-key reassembler will not follow a response that never ends.
    ///
    /// The three guards are the announced length, forward progress, and a
    /// continuation cap; together they bound a device that announces a
    /// response it never finishes sending.
    #[test]
    fn the_viewing_key_reassembler_is_bounded_in_three_ways() {
        assert_eq!(MAX_VK_CONTINUATIONS, 4);
        // Five chunks of at most 255 bytes; the two length bytes sit inside
        // the first.
        assert_eq!(MAX_VK_RESPONSE_LEN, 255 * 5);

        // 1. An announced length beyond what the device could stream.
        let mut vk = VkReassembler::new(VkKind::Ufvk);
        let announced = (MAX_VK_RESPONSE_LEN - 1) as u16;
        let mut first = announced.to_be_bytes().to_vec();
        first.extend_from_slice(&[0u8; 253]);
        assert_eq!(
            vk.push(&first),
            Err(DecodeError::VkResponseTooLong {
                announced: 2 + announced as usize,
                max: MAX_VK_RESPONSE_LEN,
            }),
        );

        // 2. A continuation that carries nothing. Its status word is 0x9000, so
        //    only this check stops the caller asking again.
        let mut vk = VkReassembler::new(VkKind::Ufvk);
        let mut first = 300u16.to_be_bytes().to_vec();
        first.extend_from_slice(&[1u8; 253]);
        assert_eq!(vk.push(&first), Ok(None));
        assert_eq!(
            vk.push(&[]),
            Err(DecodeError::VkNoProgress {
                got: 255,
                expected: 302,
            }),
        );

        // 3. A device adding a byte at a time, which the length ceiling alone does
        //    not bound.
        let mut vk = VkReassembler::new(VkKind::Ufvk);
        assert_eq!(vk.push(&300u16.to_be_bytes()), Ok(None));
        for _ in 0..MAX_VK_CONTINUATIONS - 1 {
            assert_eq!(vk.push(&[0xAA]), Ok(None));
        }
        match vk.push(&[0xAA]) {
            Err(DecodeError::VkTooManyChunks {
                expected: 302,
                max_continuations: 4,
                ..
            }) => {}
            other => panic!("unexpected result: {other:?}"),
        }

        // A legitimate UFVK — a little over 300 bytes, so one continuation — still
        // reassembles.
        let key = "u".repeat(300);
        let mut vk = VkReassembler::new(VkKind::Ufvk);
        let mut first = (key.len() as u16).to_be_bytes().to_vec();
        first.extend_from_slice(&key.as_bytes()[..253]);
        assert_eq!(vk.push(&first), Ok(None));
        assert_eq!(
            vk.push(&key.as_bytes()[253..]),
            Ok(Some(pczt_ledger::apdu::decode::VkResponse::Ufvk(key))),
        );
    }

    /// A chunked UFVK response is reassembled, and each continuation repeats the
    /// request's P2 mode byte.
    #[test]
    fn the_ufvk_exchange_reassembles_a_chunked_response() {
        let mut exchange = pairing::VkExchange::ufvk(Network::Test, account()).expect("request");

        let first = exchange.next_apdu().expect("first request");
        assert_eq!(first[1], Ins::GetVk.code());
        assert_eq!(first[2], 0x00, "P1_GET_VK_FIRST");
        assert_eq!(first[3], 0x00, "P2VkMode::Ufvk");
        // Two three-component paths, each one length byte plus 3 × 4 bytes.
        assert_eq!(first[4] as usize, 2 * (1 + 12));

        // The fixture account's UFVK, long enough to need two response chunks.
        let ufvk = fixture_ufvk(DEVICE_UNIFIED_REVISION, NetworkType::Test);
        assert!(ufvk.len() > 255, "one continuation: {}", ufvk.len());
        let mut payload = (ufvk.len() as u16).to_be_bytes().to_vec();
        payload.extend_from_slice(ufvk.as_bytes());

        assert_eq!(exchange.next_deadline(), Deadline::UserReview);
        let mut chunk = payload[..255].to_vec();
        chunk.extend_from_slice(&StatusWord::Ok.to_u16().to_be_bytes());
        assert_eq!(
            exchange.process_response(&chunk),
            Ok(VkStep::MoreChunks),
            "first chunk"
        );
        assert_eq!(
            exchange.next_deadline(),
            Deadline::Normal,
            "the approval was given before the first chunk; continuations are answered at once"
        );

        let next = exchange.next_apdu().expect("continuation");
        assert_eq!(next[2], 0x80, "P1_GET_VK_CONTINUE");
        assert_eq!(
            next[3], 0x00,
            "a continuation repeats the request's mode byte",
        );
        assert_eq!(next[4], 0, "a continuation carries no data");

        let mut chunk = payload[255..].to_vec();
        chunk.extend_from_slice(&StatusWord::Ok.to_u16().to_be_bytes());
        match exchange.process_response(&chunk).expect("second chunk") {
            VkStep::Complete(pczt_ledger::apdu::decode::VkResponse::Ufvk(s)) => assert_eq!(s, ufvk),
            other => panic!("unexpected response: {other:?}"),
        }
        assert!(exchange.is_complete());
        assert!(exchange.next_apdu().is_none());
    }

    /// A reply with no command outstanding is refused and not absorbed: before
    /// the request has been handed out, and a second time for one command. The
    /// exchange is left as it was, so the pump that made the mistake can go on.
    #[test]
    fn a_viewing_key_reply_with_nothing_outstanding_is_out_of_order() {
        let mut exchange =
            pairing::VkExchange::orchard_fvk(Network::Test, account()).expect("request");
        let mut reply = orchard_keys().1.to_bytes().to_vec();
        reply.extend_from_slice(&StatusWord::Ok.to_u16().to_be_bytes());

        // Nothing handed out yet.
        assert_eq!(
            exchange.process_response(&reply),
            Err(pairing::PairingError::OutOfOrder)
        );
        assert!(!exchange.is_failed());
        assert_eq!(exchange.bytes_received(), 0);

        // The request, its reply, and the reply again.
        let _ = exchange
            .next_apdu()
            .expect("the request is still available");
        assert!(matches!(
            exchange.process_response(&reply),
            Ok(VkStep::Complete(_))
        ));
        assert_eq!(
            exchange.process_response(&reply),
            Err(pairing::PairingError::OutOfOrder)
        );
        assert!(exchange.is_complete());
    }

    /// Declining the viewing-key display is a typed rejection, not a fault — and
    /// it is terminal. The exchange hands out nothing more, so a pump that treats
    /// errors as retriable cannot put the export-approval screen back in front of
    /// a user who has just said no.
    #[test]
    fn a_declined_viewing_key_is_a_typed_rejection_and_ends_the_exchange() {
        let mut exchange =
            pairing::VkExchange::orchard_fvk(Network::Test, account()).expect("request");
        let request = exchange.next_apdu().expect("request");
        assert_eq!(request[3], 0x01, "P2VkMode::OrchardFvk");

        assert!(matches!(
            exchange.process_response(&StatusWord::Deny.to_u16().to_be_bytes()),
            Err(pairing::PairingError::UserRejected)
        ));
        assert!(exchange.is_failed());
        assert!(!exchange.is_complete());
        assert_eq!(
            exchange.next_apdu(),
            None,
            "the request must not be re-issued"
        );

        // A late reply — say, the real one after a transport retry — is refused
        // rather than absorbed into a dead exchange.
        let mut reply = vec![7u8; 96];
        reply.extend_from_slice(&StatusWord::Ok.to_u16().to_be_bytes());
        assert_eq!(
            exchange.process_response(&reply),
            Err(pairing::PairingError::OutOfOrder)
        );
        assert_eq!(exchange.next_apdu(), None);
    }

    /// Every error other than the absorbed `0x6901` is terminal: a device refusal
    /// and a reply that does not reassemble both end the exchange the way a
    /// denial does.
    #[test]
    fn every_fatal_viewing_key_reply_ends_the_exchange() {
        // A device refusal.
        let mut exchange = pairing::VkExchange::ufvk(Network::Test, account()).expect("request");
        let _ = exchange.next_apdu().expect("request");
        assert_eq!(
            exchange.process_response(&StatusWord::IncorrectData.to_u16().to_be_bytes()),
            Err(pairing::PairingError::Device {
                status: StatusWord::IncorrectData
            }),
        );
        assert!(exchange.is_failed());
        assert_eq!(exchange.next_apdu(), None);

        // A reply that announces more than the device could ever stream.
        let mut exchange = pairing::VkExchange::ufvk(Network::Test, account()).expect("request");
        let _ = exchange.next_apdu().expect("request");
        let mut oversized = u16::MAX.to_be_bytes().to_vec();
        oversized.extend_from_slice(&[0u8; 253]);
        oversized.extend_from_slice(&StatusWord::Ok.to_u16().to_be_bytes());
        assert!(matches!(
            exchange.process_response(&oversized),
            Err(pairing::PairingError::Decode(
                pczt_ledger::apdu::decode::DecodeError::VkResponseTooLong { .. }
            ))
        ));
        assert!(exchange.is_failed());
        assert_eq!(exchange.next_apdu(), None);

        // The retry budget running out.
        let mut exchange = pairing::VkExchange::ufvk(Network::Test, account()).expect("request");
        let _ = exchange.next_apdu().expect("request");
        let refused = StatusWord::CmdNotAccepted.to_u16().to_be_bytes();
        for _ in 0..pczt_ledger::session::MAX_CMD_NOT_ACCEPTED_RETRIES {
            assert_eq!(
                exchange.process_response(&refused),
                Ok(VkStep::RetrySameApdu)
            );
            assert!(exchange.next_apdu().is_some(), "still within budget");
        }
        assert_eq!(
            exchange.process_response(&refused),
            Err(pairing::PairingError::Device {
                status: StatusWord::CmdNotAccepted
            }),
        );
        assert!(exchange.is_failed());
        assert_eq!(exchange.next_apdu(), None);
    }

    /// A complete reply that is not the key it claims to be ends the exchange
    /// where the diagnostic is, rather than in the wallet's own decode or at
    /// its first sync: a string that does not decode as a unified full
    /// viewing key, one for another network, and 96 bytes that are not an
    /// Orchard full viewing key.
    #[test]
    fn a_viewing_key_reply_that_is_not_a_key_ends_the_exchange() {
        let (result, exchange) = deliver_ufvk(&"u".repeat(300));
        assert!(
            matches!(result, Err(pairing::PairingError::UnifiedViewingKey(_))),
            "{result:?}"
        );
        assert!(exchange.is_failed());
        assert!(!exchange.is_complete());

        let (result, exchange) =
            deliver_ufvk(&fixture_ufvk(DEVICE_UNIFIED_REVISION, NetworkType::Main));
        assert_eq!(
            result,
            Err(pairing::PairingError::ViewingKeyNetworkMismatch {
                expected: Network::Test,
                found: NetworkType::Main,
            })
        );
        assert!(exchange.is_failed());

        let (result, exchange) =
            deliver_ufvk(&fixture_ufvk(DEVICE_UNIFIED_REVISION, NetworkType::Test));
        assert!(matches!(result, Ok(VkStep::Complete(_))), "{result:?}");
        assert!(exchange.is_complete());

        // 96 bytes whose `ak` is not a point: its x coordinate is not
        // canonical.
        let mut exchange =
            pairing::VkExchange::orchard_fvk(Network::Test, account()).expect("request");
        let _ = exchange.next_apdu().expect("request");
        let mut reply = vec![0xFFu8; 96];
        reply.extend_from_slice(&StatusWord::Ok.to_u16().to_be_bytes());
        assert_eq!(
            exchange.process_response(&reply),
            Err(pairing::PairingError::InvalidOrchardViewingKey)
        );
        assert!(exchange.is_failed());
        assert_eq!(exchange.next_apdu(), None);
    }

    /// The one-shot parsers hold no state to retry from, so a `0x6901` comes
    /// back to the caller as such, for it to resend the same command.
    #[test]
    fn the_one_shot_parsers_surface_a_frame_refusal_for_the_caller_to_resend() {
        let refused = StatusWord::CmdNotAccepted.to_u16().to_be_bytes();
        assert_eq!(
            pairing::parse_firmware_version_response(&refused),
            Err(pairing::PairingError::CmdNotAccepted)
        );
        assert_eq!(
            pairing::parse_wallet_public_key_response(&refused),
            Err(pairing::PairingError::CmdNotAccepted)
        );
        assert_eq!(
            pairing::parse_device_identity_response(&refused),
            Err(pairing::PairingError::CmdNotAccepted)
        );
        assert_eq!(
            pairing::parse_unified_address(&refused, Network::Test),
            Err(pairing::PairingError::CmdNotAccepted)
        );
        assert_eq!(
            pairing::parse_orchard_address(&refused),
            Err(pairing::PairingError::CmdNotAccepted)
        );
    }

    /// The unified-address command pairs the shielded account path with a *full*
    /// external BIP 44 address path, which is what the device checks for.
    /// The transparent address index is bounded on the host, at the same value the
    /// device applies (`MAX_BIP44_ADDRESS_INDEX_RECOMMENDED = 50000`,
    /// `src/utils.rs`).
    ///
    /// From `22dc385` the device compares the index unmasked, so a hardened value
    /// would exceed the bound on its own; the index type cannot express one, which
    /// leaves the bound itself as the crate's to check.
    #[test]
    fn the_transparent_address_index_is_bounded() {
        let max = pairing::MAX_BIP44_ADDRESS_INDEX;
        assert_eq!(max, 50_000);
        let index = |i: u32| NonHardenedChildIndex::from_index(i).expect("unhardened");
        let account = zip32::AccountId::ZERO;

        pairing::transparent_address_path(
            Network::Test,
            account,
            zcash_transparent::keys::TransparentKeyScope::EXTERNAL,
            index(max),
        )
        .expect("the bound is inclusive");
        pairing::unified_address_apdu(Network::Test, account, index(max), false)
            .expect("and so is the command");

        for over in [max + 1, 0x7FFF_FFFF] {
            let err = pairing::transparent_address_path(
                Network::Test,
                account,
                zcash_transparent::keys::TransparentKeyScope::EXTERNAL,
                index(over),
            )
            .expect_err("past the device's bound");
            assert_eq!(
                err,
                pairing::PairingError::PathOutOfRange {
                    what: "transparent address index",
                    max: 50_000,
                },
                "unexpected error for {over:#x}"
            );
            // The index is not in the error: an address index names an address.
            let rendered = format!("{err} {err:?}");
            assert!(!rendered.contains(&format!("{over}")), "{rendered}");
            assert!(!rendered.contains(&format!("{over:#x}")), "{rendered}");
            assert!(
                pairing::unified_address_apdu(Network::Test, account, index(over), false).is_err()
            );
        }
    }

    /// `GET_SHIELD_ADDR` P1 `0x01` with P2 `0x01` is refused before an APDU exists:
    /// from `22dc385` the device answers `WrongP1P2` ahead of the derivation.
    #[test]
    fn a_displayed_raw_orchard_address_is_never_requested() {
        assert!(
            pairing::orchard_address_apdu(Network::Test, zip32::AccountId::ZERO, true).is_err()
        );
        pairing::orchard_address_apdu(Network::Test, zip32::AccountId::ZERO, false)
            .expect("the silent form is fine");
    }

    /// `0x6A84` from a pairing command means the per-run Orchard derivation budget
    /// is spent (`consume_orchard_derivation_budget`, `src/zip32.rs` @ `22dc385`),
    /// which a restart of the app clears — advice worth a variant of its own.
    #[test]
    fn a_spent_derivation_budget_is_told_apart_from_a_device_refusal() {
        let mut exchange =
            pairing::VkExchange::ufvk(Network::Test, zip32::AccountId::ZERO).expect("request");
        let _ = exchange.next_apdu().expect("request");

        assert_eq!(
            exchange.process_response(&StatusWord::NotEnoughMemorySpace.to_u16().to_be_bytes()),
            Err(pairing::PairingError::DerivationBudgetExhausted),
        );

        // Every other fatal status word stays a plain device refusal.
        let mut exchange =
            pairing::VkExchange::ufvk(Network::Test, zip32::AccountId::ZERO).expect("request");
        let _ = exchange.next_apdu().expect("request");
        assert_eq!(
            exchange.process_response(&StatusWord::IncorrectData.to_u16().to_be_bytes()),
            Err(pairing::PairingError::Device {
                status: StatusWord::IncorrectData
            }),
        );
    }

    #[test]
    fn the_unified_address_command_sends_a_full_transparent_path() {
        let apdu = pairing::unified_address_apdu(
            Network::Test,
            account(),
            NonHardenedChildIndex::from_index(7).expect("unhardened"),
            true,
        )
        .expect("request");
        assert_eq!(apdu[1], Ins::GetShieldAddr.code());
        assert_eq!(apdu[2], 0x01, "display for approval");
        assert_eq!(apdu[3], 0x00, "P2ShieldedAddrMode::UAddress");
        // 3-component shielded path + 5-component transparent path.
        assert_eq!(apdu[4] as usize, (1 + 12) + (1 + 20));

        let address = fixture_unified_address(DEVICE_UNIFIED_REVISION);

        // The reply is handed back parsed, as the type the firmware encodes it
        // from.
        let encoded = address.encode(&NetworkType::Test);
        assert_eq!(
            pairing::parse_unified_address(&string_reply(&encoded), Network::Test).expect("parses"),
            address
        );

        // The transparent address index selects nothing in the reply: the
        // firmware encodes the Orchard receiver at diversifier index 0
        // whatever the index (`handler_get_shielded_addr` @ `22dc385`), and
        // reads the transparent path for its BIP 44 check and the transparent
        // address it shows beside the unified one. The request for index 0
        // differs from the one for index 7 in that path's last component
        // alone, and the one reply — index 0's receiver — answers both.
        let for_index_0 = pairing::unified_address_apdu(
            Network::Test,
            account(),
            NonHardenedChildIndex::ZERO,
            true,
        )
        .expect("request");
        let index_bytes = core::mem::size_of::<u32>();
        assert_eq!(for_index_0.len(), apdu.len());
        assert_eq!(
            for_index_0[..apdu.len() - index_bytes],
            apdu[..apdu.len() - index_bytes]
        );
        assert_ne!(for_index_0, apdu);
        assert_eq!(
            pairing::parse_unified_address(&string_reply(&encoded), Network::Test).expect("parses"),
            address,
            "the reply to the index-7 request is the index-0 unified address"
        );

        // And checked against the network the request was built for.
        assert_eq!(
            pairing::parse_unified_address(&string_reply(&encoded), Network::Main),
            Err(pairing::PairingError::AddressNetworkMismatch {
                expected: Network::Main,
                found: NetworkType::Test,
            })
        );

        // A string that is not a unified address is refused here, not in the
        // wallet.
        assert!(matches!(
            pairing::parse_unified_address(&string_reply("utx"), Network::Test),
            Err(pairing::PairingError::UnifiedAddress(_))
        ));
    }

    /// The container revision is the one the pinned app encodes, and nothing
    /// else. The revision rides in the prefix, and the two revisions of one
    /// network have different prefixes, so the network check cannot stand in
    /// for this: a Revision 2 address for the requested network passes it.
    #[test]
    fn a_unified_address_of_another_revision_is_refused() {
        let accepted = fixture_unified_address(DEVICE_UNIFIED_REVISION);
        assert_eq!(
            pairing::parse_unified_address(
                &string_reply(&accepted.encode(&NetworkType::Test)),
                Network::Test,
            )
            .expect("the revision the app encodes"),
            accepted
        );

        let refused = fixture_unified_address(OTHER_UNIFIED_REVISION);
        let encoded = refused.encode(&NetworkType::Test);
        // Bech32m puts the human-readable prefix before the last separator.
        let hrp = |s: &str| s.rsplit_once('1').map(|(hrp, _)| hrp.to_owned());
        assert_ne!(
            hrp(&encoded),
            hrp(&accepted.encode(&NetworkType::Test)),
            "the revisions differ in their prefix, and both name the requested network"
        );
        assert_eq!(
            pairing::parse_unified_address(&string_reply(&encoded), Network::Test),
            Err(pairing::PairingError::UnsupportedUnifiedRevision {
                found: OTHER_UNIFIED_REVISION,
            })
        );
    }

    /// The same for the viewing-key export: a Revision 2 UFVK for the
    /// exchange's network ends the exchange rather than reaching the wallet.
    #[test]
    fn a_viewing_key_export_of_another_revision_is_refused() {
        let (result, exchange) =
            deliver_ufvk(&fixture_ufvk(DEVICE_UNIFIED_REVISION, NetworkType::Test));
        assert!(matches!(result, Ok(VkStep::Complete(_))), "{result:?}");
        assert!(exchange.is_complete());

        let (result, mut exchange) =
            deliver_ufvk(&fixture_ufvk(OTHER_UNIFIED_REVISION, NetworkType::Test));
        assert_eq!(
            result,
            Err(pairing::PairingError::UnsupportedUnifiedRevision {
                found: OTHER_UNIFIED_REVISION,
            })
        );
        assert!(exchange.is_failed());
        assert!(!exchange.is_complete());
        assert_eq!(exchange.next_apdu(), None);
    }

    /// A raw Orchard address reply is 43 bytes whose `pk_d` half has to be a
    /// point; the reply is handed back as the address, and anything else is
    /// refused.
    #[test]
    fn a_raw_orchard_address_reply_is_parsed_as_an_address() {
        let (_, fvk) = orchard_keys();
        let address = fvk.address_at(0u32, Scope::External);

        let mut reply = address.to_raw_address_bytes().to_vec();
        reply.extend_from_slice(&StatusWord::Ok.to_u16().to_be_bytes());
        assert_eq!(
            pairing::parse_orchard_address(&reply).expect("parses"),
            address
        );

        // 43 bytes that are not an address.
        let mut reply = vec![0xFF; 43];
        reply.extend_from_slice(&StatusWord::Ok.to_u16().to_be_bytes());
        assert_eq!(
            pairing::parse_orchard_address(&reply),
            Err(pairing::PairingError::InvalidOrchardAddress)
        );

        // Not 43 bytes.
        let mut reply = vec![0x00; 42];
        reply.extend_from_slice(&StatusWord::Ok.to_u16().to_be_bytes());
        assert!(matches!(
            pairing::parse_orchard_address(&reply),
            Err(pairing::PairingError::Decode(
                DecodeError::UnexpectedLength { .. }
            ))
        ));
    }

    /// `0x6A84` means a spent Orchard derivation budget only from the commands
    /// that derive an Orchard key. From the identity probe and the firmware
    /// probe, which derive none, it is a plain device refusal.
    #[test]
    fn a_spent_derivation_budget_is_reported_only_by_orchard_deriving_commands() {
        let reply = StatusWord::NotEnoughMemorySpace.to_u16().to_be_bytes();
        assert_eq!(
            pairing::parse_wallet_public_key_response(&reply),
            Err(pairing::PairingError::Device {
                status: StatusWord::NotEnoughMemorySpace
            })
        );
        assert_eq!(
            pairing::parse_firmware_version_response(&reply),
            Err(pairing::PairingError::Device {
                status: StatusWord::NotEnoughMemorySpace
            })
        );
        assert_eq!(
            pairing::parse_unified_address(&reply, Network::Test),
            Err(pairing::PairingError::DerivationBudgetExhausted)
        );
        assert_eq!(
            pairing::parse_orchard_address(&reply),
            Err(pairing::PairingError::DerivationBudgetExhausted)
        );
    }
}

/// `finish` hands out its outcome once: a second call answers `OutOfOrder`
/// while the session's accessors keep working.
#[test]
fn finish_is_take_once_and_leaves_the_session_readable() {
    let fixture = fixture_v5_transparent_to_orchard();
    let mut session =
        LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(None)).expect("session");

    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, false);

    // Before completion, finish is out of order and changes nothing.
    assert!(matches!(session.finish(), Err(SessionError::OutOfOrder)));

    run_session(&mut session, &mut device).expect("ceremony completes");
    assert_eq!(session.stage(), Stage::Complete);

    let outcome = session.finish().expect("the first call succeeds");
    assert!(!outcome.pczt_with_sigs().is_empty());

    assert!(matches!(session.finish(), Err(SessionError::OutOfOrder)));
    // The failure path did not kill the session's state.
    assert_eq!(session.stage(), Stage::Complete);
    assert!(!session.plan().stream().orchard_actions().is_empty());
}

/// The deadline policy lives on the session: `Normal` until the packet
/// carrying `P2_PCZT_FINISHED` is about to go out, `UserReview` from then on —
/// signing commands included, since the app may gate them on further
/// confirmations.
#[test]
fn the_session_reports_user_review_deadlines_from_the_review_onward() {
    let fixture = fixture_v5_orchard_spend();
    let mut session = LedgerSignSession::new(
        &fixture.bytes,
        caps(),
        fixture.params(fixture.change_info()),
    )
    .expect("session");

    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, false);

    assert!(!session.is_past_review());
    assert_eq!(session.next_deadline(), Deadline::Normal);

    let mut saw_review_deadline_before_send = false;
    let mut deadlines_after_review = Vec::new();
    loop {
        // The packet that flips `is_past_review` is the FINISHED one; its own
        // reply, and every one after, waits on the user.
        let review_now = session.pending_user_action().is_some();
        let was_past_review = session.is_past_review();
        let PumpStep::Send(capdu) = session.next_step() else {
            break;
        };
        let deadline = session.next_deadline();
        if review_now {
            assert_eq!(deadline, Deadline::UserReview);
            assert!(session.is_past_review());
            saw_review_deadline_before_send = true;
        } else if was_past_review {
            deadlines_after_review.push(deadline);
        } else {
            assert_eq!(deadline, Deadline::Normal);
        }
        let rapdu = device.exchange(&capdu);
        session.process_response(&rapdu).expect("ok");
    }

    assert!(saw_review_deadline_before_send);
    // The signing commands follow the review, and each ran without a deadline.
    assert!(!deadlines_after_review.is_empty());
    assert!(deadlines_after_review
        .iter()
        .all(|d| *d == Deadline::UserReview));
    assert_eq!(session.stage(), Stage::Complete);
}

/// Bytes that are not a PCZT are refused with the parse variant, not with a
/// planning error dressed up as one.
#[test]
fn garbage_bytes_are_a_parse_error() {
    let err = LedgerSignSession::new(&[0xDE, 0xAD, 0xBE, 0xEF], caps(), {
        let fixture = fixture_v5_transparent_to_orchard();
        fixture.params(None)
    })
    .expect_err("four bytes are not a PCZT");
    assert!(
        matches!(err, SessionError::Parse(_)),
        "unexpected error: {err:?}"
    );
}
