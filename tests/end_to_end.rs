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

use std::collections::HashMap;

use orchard::{
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
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding, PcztResult},
    fees::zip317,
};
use zcash_protocol::{
    consensus::BlockHeight, local_consensus::LocalNetwork, memo::MemoBytes, value::Zatoshis,
};
use zcash_transparent::{
    address::TransparentAddress,
    bundle::{OutPoint, TxOut},
    keys::{AccountPrivKey, IncomingViewingKey, NonHardenedChildIndex},
};

use pczt_ledger::{
    apdu::{decode::split_status_word, Ins, StatusWord},
    apply::{apply_device_signatures, normalize_ledger_der, ApplyError, DeviceSignatures},
    ceremony::{self, CeremonyError},
    limits::{DeviceBounds, DeviceCaps, LimitViolation, Section},
    pairing,
    plan::{build_plan, build_plan_with_keys},
    session::{
        validate_for_ledger, validate_for_ledger_with_keys, Deadline, LedgerSignSession,
        LedgerViolation, Network, PumpStep, SessionError, SessionParams, SessionStatus, Stage,
        UserAction,
    },
    shape::{derivation_account, hash160, shape_for_device, ChangeInfo, ShapeError, ShapeParams},
    transport::{Transport, TransportError},
    viewing::AccountViewingKeys,
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

/// The one exchange every session opens with before the PCZT stream: the
/// device identity probe.
const IDENTITY_PROBE_EXCHANGES: usize = 1;

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
const SEED: [u8; 32] = [1; 32];
const SEED_FINGERPRINT: [u8; 32] = [0x7c; 32];

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
        SessionParams {
            network: Network::Test,
            device: fake_device_identity(),
            zip32_account: ACCOUNT,
            seed_fingerprint: Some(SEED_FINGERPRINT),
            change,
            viewing_keys: None,
        }
    }

    /// The same, with the Orchard viewing key the fixture's outputs were
    /// addressed under.
    fn params_with_keys(
        &self,
        change: Option<ChangeInfo>,
        keys: AccountViewingKeys,
    ) -> SessionParams {
        SessionParams {
            viewing_keys: Some(keys),
            ..self.params(change)
        }
    }

    fn change_info(&self) -> Option<ChangeInfo> {
        self.change_output_index.map(|output_index| ChangeInfo {
            output_index,
            pubkey: self.change_pubkey,
            address_index: 0,
        })
    }
}

fn orchard_keys() -> (SpendingKey, FullViewingKey) {
    let sk = SpendingKey::from_bytes([0; 32]).expect("valid spending key");
    let fvk = FullViewingKey::from(&sk);
    (sk, fvk)
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
    const HARDENED: u32 = 0x8000_0000;
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

/// V5, a real Orchard spend → one Orchard output plus a transparent change
/// output the wallet controls.
///
/// This is the fixture with a real device-signable spend, and the one that
/// exercises change-output stamping.
fn fixture_v5_orchard_spend() -> Fixture {
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
    builder
        .add_transparent_output(&t.change_address, Zatoshis::const_from_u64(885_000))
        .expect("transparent change output");

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
    const HARDENED: u32 = 0x8000_0000;
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
    let params = v6_network();
    let t = transparent_keys(&params);
    let (sk, fvk) = orchard_keys();

    let (note, merkle_path, anchor) = synthetic_note(&fvk, 1_000_000, NoteVersion::V3);

    let mut builder = Builder::new(
        params,
        TARGET_HEIGHT.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_padding: BundlePadding::DEFAULT,
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
    // 1_000_000 in, 100_000 out, less the 10_000 ZIP 317 fee for two actions.
    builder
        .add_ironwood_output::<zip317::FeeRule>(
            Some(fvk.to_ovk(Scope::Internal)),
            fvk.address_at(0u32, Scope::Internal),
            Zatoshis::const_from_u64(890_000),
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
    // of `1 + change_notes` logical actions, split evenly across the change
    // notes. Each change note goes to a *different* internal diversifier index,
    // which is what a wallet does and what keeps the test from passing by
    // accident on a single hard-coded address.
    let fee = 5_000 * u64::from(1 + change_notes).max(2);
    let change_total = 1_000_000 - 100_000 - fee;
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
        change_output_index: None,
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
}

impl FakeDevice {
    fn new() -> Self {
        FakeDevice {
            identity_key: fake_device_key(),
            orchard: HashMap::new(),
            ironwood: HashMap::new(),
            transparent: HashMap::new(),
            fail_at: None,
            refuse_from: None,
            seen: 0,
            log: Vec::new(),
            received: Vec::new(),
        }
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

        if let Some((at, sw)) = self.fail_at {
            if at == index {
                return sw.to_be_bytes().to_vec();
            }
        }

        let mut out = match ins {
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
        out.extend_from_slice(&0x9000u16.to_be_bytes());
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

/// A [`Transport`] over a [`FakeDevice`], for driving [`ceremony`] itself.
///
/// It can be told to fail one exchange on the wire, which is the case that
/// leaves a session with a command outstanding.
struct FakeTransport {
    device: FakeDevice,
    /// The exchange index that never crosses the wire.
    fail_at: Option<usize>,
    exchanges: usize,
}

impl Transport for FakeTransport {
    fn exchange_with(
        &mut self,
        apdu: &[u8],
        _deadline: Deadline,
    ) -> Result<Vec<u8>, TransportError> {
        let index = self.exchanges;
        self.exchanges += 1;
        if self.fail_at == Some(index) {
            return Err(TransportError::ConnectionClosed);
        }
        Ok(self.device.exchange(apdu))
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

    for &index in &plan.orchard_real_spends {
        let mut signer = Signer::new(shaped.clone()).expect("signer");
        signer
            .sign_orchard(index, &fixture.orchard_ask)
            .expect("host-side orchard signature");
        let signed = signer.finish();
        device
            .orchard
            .insert(index as u8, orchard_sig(&signed, index, false));
    }
    for &index in &plan.ironwood_real_spends {
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
        for index in 0..plan.stream.transparent_inputs.len() {
            let sighash = signer.transparent_sighash(index).expect("sighash");
            let sig = secp.sign_ecdsa(&secp256k1::Message::from_digest(sighash), sk);
            let mut der = sig.serialize_der().to_vec();
            if ledger_quirks {
                // The device ORs the y-parity bit into the DER SEQUENCE tag
                // when the y coordinate is odd. Forcing it here exercises the
                // normalization on every run rather than roughly half of them.
                der[0] = 0x31;
            }
            // The device always appends the sighash type.
            der.push(0x01);
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
        .stream
        .to_apdus()
        .expect("the plan encodes")
        .len();
    IDENTITY_PROBE_EXCHANGES + stream_len - 1
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
    assert!(!before.stream.orchard_actions.is_empty());
    assert_eq!(
        before.missing_zip32.len(),
        before.stream.orchard_actions.len()
    );
    assert!(before.orchard_real_spends.is_empty());

    let shaped = shape_for_device(
        pczt,
        &ShapeParams {
            coin_type: FIXTURE_COIN_TYPE,
            zip32_account: ACCOUNT,
            seed_fingerprint: Some(SEED_FINGERPRINT),
            change: None,
        },
    )
    .expect("shapes");

    let after = build_plan(&shaped.pczt).expect("plans");
    assert!(after.missing_zip32.is_empty());
    for action in &after.stream.orchard_actions {
        assert_eq!(action.zip32_derivation.seed_fingerprint, SEED_FINGERPRINT);
        assert_eq!(
            action.zip32_derivation.path.components(),
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
            &ShapeParams {
                coin_type: FIXTURE_COIN_TYPE,
                zip32_account: ACCOUNT,
                seed_fingerprint: Some(SEED_FINGERPRINT),
                change: None,
            },
        )
        .expect("shapes");
        assert_eq!(shaped.encoding_version, expected);
        assert_eq!(&shaped.bytes[..4], b"PCZT");
        assert_eq!(
            u32::from_le_bytes(shaped.bytes[4..8].try_into().unwrap()),
            expected,
        );

        // The header record carries the same number.
        let plan = build_plan(&shaped.pczt).expect("plans");
        assert_eq!(plan.stream.header.pczt_version, expected);
    }
}

/// The change output gets a derivation; recipient outputs do not.
#[test]
fn shaping_stamps_the_transparent_change_output() {
    let fixture = fixture_v5_orchard_spend();
    let change = fixture.change_info().expect("fixture has a change output");

    let shaped = shape_for_device(
        fixture.pczt(),
        &ShapeParams {
            coin_type: FIXTURE_COIN_TYPE,
            zip32_account: ACCOUNT,
            seed_fingerprint: Some(SEED_FINGERPRINT),
            change: Some(change.clone()),
        },
    )
    .expect("shapes");

    let plan = build_plan(&shaped.pczt).expect("plans");
    let output = &plan.stream.transparent_outputs[change.output_index];
    let derivation = output
        .derivation
        .as_ref()
        .expect("the change output is marked");
    assert_eq!(derivation.pubkey, fixture.change_pubkey);
    assert_eq!(
        derivation.path.components(),
        vec![
            0x8000_0000 | 44,
            0x8000_0000 | FIXTURE_COIN_TYPE,
            0x8000_0000 | ACCOUNT,
            1,
            0
        ],
    );
    // And the pubkey really does hash to the script the device will see.
    assert_eq!(&output.script_pubkey[3..23], &hash160(&derivation.pubkey));
}

/// Stamping a change derivation whose pubkey does not hash to the output's
/// script is refused. The device would not abort on it — it would silently show
/// the output as a third-party recipient, and could take a different output for
/// change — so the host has to catch it.
#[test]
fn shaping_rejects_a_change_pubkey_that_does_not_match_the_script() {
    let fixture = fixture_v5_orchard_spend();
    let mut change = fixture.change_info().expect("fixture has a change output");
    // A different valid compressed pubkey.
    change.pubkey[1] ^= 0xFF;

    let err = shape_for_device(
        fixture.pczt(),
        &ShapeParams {
            coin_type: FIXTURE_COIN_TYPE,
            zip32_account: ACCOUNT,
            seed_fingerprint: Some(SEED_FINGERPRINT),
            change: Some(change),
        },
    )
    .expect_err("mismatched change pubkey must be refused");

    assert!(
        matches!(err, ShapeError::ChangeOutputHashMismatch { .. }),
        "unexpected error: {err:?}"
    );
}

/// The device derives one account key per PCZT. An action already stamped with
/// a different account path makes the transaction unsignable, so shaping
/// refuses it rather than streaming a mixture the device answers `BadState` to.
#[test]
fn shaping_rejects_non_uniform_derivation_paths() {
    let fixture = fixture_v5_transparent_to_orchard();

    // Stamp action 0 with a *different* account than the session will use.
    const HARDENED: u32 = 0x8000_0000;
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
        &ShapeParams {
            coin_type: FIXTURE_COIN_TYPE,
            zip32_account: ACCOUNT,
            seed_fingerprint: Some(SEED_FINGERPRINT),
            change: None,
        },
    )
    .expect_err("a foreign account path must be refused");

    assert!(
        matches!(
            err,
            ShapeError::NonUniformPath {
                section: Section::Orchard,
                index: 0,
                ..
            }
        ),
        "unexpected error: {err:?}"
    );
}

/// A PCZT from a UFVK-imported account carries no `zip32_derivation` and the
/// caller may have no seed fingerprint either. The firmware never checks the
/// fingerprint half, so the zeroed default is sound.
#[test]
fn shaping_synthesizes_a_zeroed_fingerprint_when_none_is_known() {
    let fixture = fixture_v5_transparent_to_orchard();

    let shaped = shape_for_device(
        fixture.pczt(),
        &ShapeParams {
            coin_type: FIXTURE_COIN_TYPE,
            zip32_account: ACCOUNT,
            seed_fingerprint: None,
            change: None,
        },
    )
    .expect("shapes");

    let plan = build_plan(&shaped.pczt).expect("plans");
    for action in &plan.stream.orchard_actions {
        assert_eq!(action.zip32_derivation.seed_fingerprint, [0u8; 32]);
    }
}

// ---------------------------------------------------------------------------
// validate_for_ledger
// ---------------------------------------------------------------------------

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
    assert!(v6.is_v6());
    let actions = v6
        .stream
        .ironwood_actions
        .as_ref()
        .expect("V6 carries the Ironwood command")
        .len();
    assert!(
        actions >= 2,
        "a spend and two outputs pad to at least two actions"
    );
    assert_eq!(v6.ironwood_real_spends.len(), 1);

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

/// The bounds are chosen from the version the device reported, and an
/// unrecognised one falls back to the smaller, older set rather than the
/// newer one.
#[test]
fn device_bounds_are_derived_from_the_reported_version() {
    assert_eq!(
        DeviceCaps::from_version(3, 9, 2).bounds(),
        DeviceBounds::V3_9_2
    );
    assert_eq!(
        DeviceCaps::from_version(3, 9, 3).bounds(),
        DeviceBounds::V3_9_3
    );
    // Later versions keep the raised bounds until this crate learns otherwise.
    assert_eq!(
        DeviceCaps::from_version(4, 0, 0).bounds(),
        DeviceBounds::V3_9_3
    );
    // Everything older is the pre-3.9.3 set.
    for v in [(3, 9, 0), (3, 8, 9), (3, 6, 0), (2, 0, 0)] {
        assert_eq!(
            DeviceCaps::from_version(v.0, v.1, v.2).bounds(),
            DeviceBounds::V3_9_2,
            "v{}.{}.{}",
            v.0,
            v.1,
            v.2
        );
    }
    // And the no-device default is the fail-closed one.
    assert_eq!(DeviceBounds::UNKNOWN_VERSION, DeviceBounds::V3_9_2);

    // The transparent-output bound did not move; the other three did.
    assert_eq!(
        DeviceBounds::V3_9_2.transparent_outputs,
        DeviceBounds::V3_9_3.transparent_outputs
    );
    assert_eq!(DeviceBounds::V3_9_3.transparent_inputs, 32);
    assert_eq!(DeviceBounds::V3_9_3.orchard_actions, 32);
    assert_eq!(DeviceBounds::V3_9_3.ironwood_actions, 32);
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
    assert_eq!(session.plan().stream.orchard_actions.len(), 11);
}

/// The shielded displayed-output budget, which only exists from v3.9.3
/// (`MAX_PCZT_SHIELDED_DISPLAYED_OUTPUTS_NUMBER = 4`, `src/consts.rs` @
/// `22dc385`).
///
/// A v3.9.2 app has no such budget and never refuses for it; a v3.9.3 app
/// refuses the fifth displayed output mid-stream, with `0x6A84`, so this is
/// exactly the kind of late refusal the host is here to pull forward.
#[test]
fn the_shielded_display_budget_is_counted_and_version_gated() {
    let five = fixture_v5_five_orchard_recipients().pczt();
    let plan = build_plan(&five).expect("plans");

    // Five nonzero-value outputs; the bundle is unpadded, so there are no
    // dummies to discount.
    assert_eq!(plan.stream.orchard_actions.len(), 5);
    assert_eq!(plan.displayed_shielded_outputs, 5);

    // No budget before v3.9.3, so the same PCZT passes there.
    assert!(DeviceBounds::V3_9_2.displayed_shielded_outputs.is_none());
    validate_for_ledger(&five, &DeviceBounds::V3_9_2)
        .expect("a v3.9.2 app has no displayed-output budget");

    let violations = validate_for_ledger(&five, &DeviceBounds::V3_9_3)
        .expect_err("a v3.9.3 app displays at most four");
    assert!(
        violations.iter().any(|v| matches!(
            v,
            LedgerViolation::Limit(LimitViolation::TooManyDisplayedShieldedOutputs {
                got: 5,
                max: 4,
                // No viewing key was supplied, so the count is an upper bound.
                exact: false,
            })
        )),
        "unexpected violations: {violations:?}"
    );
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

    assert_eq!(plan.stream.orchard_actions.len(), 11);
    assert_eq!(plan.displayed_shielded_outputs, 1);
    for (i, action) in plan.stream.orchard_actions.iter().enumerate() {
        if i != plan
            .stream
            .orchard_actions
            .iter()
            .position(|a| a.value != 0)
            .expect("one real output")
        {
            assert_eq!(action.value, 0, "action {i} should be a padding dummy");
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
    assert_eq!(blind.displayed_shielded_outputs, 2);
    assert_eq!(blind.shielded_change_outputs, None);
    assert!(!blind.displayed_count_is_exact());

    // With it: the internal-scope output is change, the external-scope one is a
    // self-send the device still displays.
    let exact = build_plan_with_keys(&pczt, Some(&canned_viewing_keys())).expect("plans");
    assert_eq!(exact.displayed_shielded_outputs, 1);
    assert_eq!(exact.shielded_change_outputs, Some(1));
    assert!(exact.displayed_count_is_exact());
    assert_eq!(exact.stream.orchard_actions.len(), 2);
}

/// A key belonging to a different account classifies nothing as change, so the
/// count falls back to what the value-only rule produces.
///
/// This is what makes the exact count *exact for this account* rather than a
/// generic "is this change" oracle: the keys the caller supplies are the keys
/// the device will derive, or the answer is wrong in the safe direction.
#[test]
fn another_accounts_viewing_key_discounts_nothing() {
    let pczt = fixture_v5_transparent_to_orchard().pczt();
    let plan = build_plan_with_keys(&pczt, Some(&seed_viewing_keys())).expect("plans");
    assert_eq!(plan.displayed_shielded_outputs, 2);
    assert_eq!(plan.shielded_change_outputs, Some(0));
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
    assert_eq!(blind.stream.orchard_actions.len(), 5);
    assert_eq!(blind.displayed_shielded_outputs, 5);

    let exact = build_plan_with_keys(&pczt, Some(&keys)).expect("plans");
    assert_eq!(exact.displayed_shielded_outputs, 1);
    assert_eq!(exact.shielded_change_outputs, Some(4));

    // Blind, the display budget refuses it, and says the count is a bound.
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
    assert_eq!(plan.shielded_change_outputs, Some(1));
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
    assert_eq!(plan.shielded_change_outputs, None);
    validate_for_ledger(&two, &DeviceBounds::V3_9_3)
        .expect("blind, two change outputs are within the blind display budget");
}

/// A shielded change output and a transparent one are one too many *together*:
/// the device's counter is shared across the pools.
///
/// The transparent half needs no viewing key — an output is change to the
/// device exactly when it carries the `bip32_derivation` the shaping pass
/// stamps — so this is checked on the plan built after shaping, which is where
/// the session checks it.
#[test]
fn shielded_and_transparent_change_together_are_refused() {
    let fixture = fixture_v5_seed_orchard_split_change(1);
    let keys = seed_viewing_keys();

    // The fixture has no transparent output at all, so one is faked onto the
    // plan: what matters here is the pair of counters, not how the derivation
    // got there.
    let mut plan = build_plan_with_keys(&fixture.pczt(), Some(&keys)).expect("plans");
    assert_eq!(plan.shielded_change_outputs, Some(1));
    pczt_ledger::limits::validate_plan(&plan, &DeviceBounds::V3_9_3)
        .expect("one shielded change output on its own is fine");

    let mut script_pubkey = vec![0x76, 0xa9, 0x14];
    script_pubkey.extend_from_slice(&hash160(&[2u8; 33]));
    script_pubkey.extend_from_slice(&[0x88, 0xac]);
    plan.stream
        .transparent_outputs
        .push(pczt_ledger::apdu::encode::TransparentOutputRecord {
            value: 1,
            script_pubkey,
            derivation: Some(pczt_ledger::apdu::encode::TransparentDerivation {
                pubkey: [2u8; 33],
                seed_fingerprint: SEED_FINGERPRINT,
                path: pczt_ledger::apdu::encode::DerivationPath::new(vec![
                    44 | 0x8000_0000,
                    FIXTURE_COIN_TYPE | 0x8000_0000,
                    ACCOUNT | 0x8000_0000,
                    1,
                    0,
                ])
                .expect("five components"),
            }),
        });

    let violations = pczt_ledger::limits::validate_plan(&plan, &DeviceBounds::V3_9_3)
        .expect_err("shielded change plus transparent change is two");
    assert!(
        violations.iter().any(|v| matches!(
            v,
            LimitViolation::MultipleChangeOutputs {
                got: 2,
                shielded: Some(1)
            }
        )),
        "unexpected violations: {violations:?}"
    );
}

/// Two *transparent* change outputs are refused with no viewing key at all.
///
/// The transparent half of the one-change rule needs no key — an output is
/// change to the device exactly when it carries a `bip32_derivation` — so it
/// must not sit behind the shielded half, which does. The reviewer's case:
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
    assert_eq!(blind.stream.orchard_actions.len(), 5);
    assert_eq!(
        blind.displayed_shielded_outputs, 4,
        "blind, the zero-valued output is unseen"
    );
    validate_for_ledger(&memo_only, &DeviceBounds::V3_9_3)
        .expect("blind, four is within the budget: the residual the docs describe");

    let exact = build_plan_with_keys(&memo_only, Some(&keys)).expect("plans");
    assert_eq!(exact.displayed_shielded_outputs, 5);
    assert_eq!(exact.shielded_change_outputs, Some(0));
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
    assert_eq!(exact.stream.orchard_actions.len(), 5);
    assert_eq!(exact.displayed_shielded_outputs, 4);
    validate_for_ledger_with_keys(&unrecoverable, &DeviceBounds::V3_9_3, Some(&keys))
        .expect("an output no key opens takes no slot");
}

/// The zero-value rule survives the exact count: padding dummies are excluded
/// with a key just as they are without one, and the key does not turn one into
/// change.
#[test]
fn zero_valued_outputs_are_excluded_with_a_key_too() {
    let eleven = fixture_v5_eleven_orchard_actions().pczt();
    let plan = build_plan_with_keys(&eleven, Some(&canned_viewing_keys())).expect("plans");

    assert_eq!(plan.stream.orchard_actions.len(), 11);
    assert_eq!(plan.displayed_shielded_outputs, 1);
    // The dummies are addressed to throwaway keys, not to this account's
    // internal scope, so none of them counts as change either.
    assert_eq!(plan.shielded_change_outputs, Some(0));
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
    assert_eq!(blind.displayed_shielded_outputs, 2);

    let exact = build_plan_with_keys(&pczt, Some(&keys)).expect("plans");
    assert!(exact.is_v6());
    assert_eq!(exact.displayed_shielded_outputs, 1);
    assert_eq!(exact.shielded_change_outputs, Some(1));
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
    let mut plan = build_plan(&fixture.pczt()).expect("plans");

    // `OP_HASH160 <20> … OP_EQUAL`: a well-formed P2SH scriptPubKey.
    let mut p2sh = vec![0xA9, 0x14];
    p2sh.extend_from_slice(&[7u8; 20]);
    p2sh.push(0x87);
    assert!(pczt_ledger::limits::is_standard_output_script(&p2sh));
    assert!(!pczt_ledger::limits::is_p2pkh_script(&p2sh));

    // The unmodified fixture, whose input is a real P2PKH, passes.
    pczt_ledger::limits::validate_records(&plan.stream, &DeviceBounds::V3_9_2)
        .expect("a P2PKH input is fine");

    plan.stream.transparent_inputs[0].script_pubkey = p2sh;

    for bounds in [DeviceBounds::V3_9_2, DeviceBounds::V3_9_3] {
        let violations = pczt_ledger::limits::validate_records(&plan.stream, &bounds)
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
    let mut plan = build_plan(&fixture.pczt()).expect("plans");
    plan.stream.transparent_inputs[0].script_pubkey = vec![0u8; 253];

    let violations = pczt_ledger::limits::validate_records(&plan.stream, &DeviceBounds::V3_9_2)
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

    assert_eq!(session.plan().orchard_real_spends.len(), 1);
    assert!(session.plan().ironwood_real_spends.is_empty());

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
            Ins::GetWalletPublicKey.code(),
            Ins::PcztHeader.code(),
            Ins::PcztTransparentInput.code(),
            Ins::PcztTransparentOutput.code(),
            Ins::PcztOrchardAction.code(),
            Ins::PcztSignOrchard.code(),
        ],
    );

    let outcome = session.finish().expect("finish");
    assert_eq!(outcome.orchard_sigs.len(), 1);
    assert!(outcome.ironwood_sigs.is_empty());
    assert!(outcome.transparent_sigs.is_empty());

    // The signature really landed, and the PCZT still parses.
    let signed = Pczt::parse(&outcome.pczt_with_sigs).expect("signed PCZT parses");
    let index = outcome.orchard_sigs[0].0;
    assert_eq!(
        signed.orchard().actions()[index]
            .spend()
            .spend_auth_sig()
            .expect("signed"),
        outcome.orchard_sigs[0].1,
    );
}

/// A full V6 ceremony. The Ironwood command is sent, carries the FINISHED
/// marker, and the Orchard command goes out with count `0` and
/// `P2_PCZT_CONTINUE`.
#[test]
fn v6_session_moves_the_finished_marker_to_ironwood() {
    let fixture = fixture_v6_ironwood();
    let mut session =
        LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(None)).expect("session");

    assert!(session.plan().is_v6());
    assert_eq!(session.plan().stream.header.pczt_version, 2);
    assert!(session.plan().stream.orchard_actions.is_empty());
    assert!(session.plan().stream.orchard_trailer.is_none());
    assert!(!session
        .plan()
        .stream
        .ironwood_actions
        .as_ref()
        .expect("V6 sends the command")
        .is_empty());

    // Every Ironwood action carries the note-plaintext lead byte, and it is the
    // ZIP 2005 value.
    for action in session.plan().stream.ironwood_actions.as_ref().unwrap() {
        assert_eq!(action.note_plaintext_version, Some(0x03));
    }

    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, false);

    let statuses = run_session(&mut session, &mut device).expect("ceremony completes");
    assert_eq!(statuses.last(), Some(&SessionStatus::Complete));

    assert_eq!(
        device.command_sequence(),
        vec![
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
    assert_eq!(outcome.transparent_sigs.len(), 1);
    assert_eq!(outcome.transparent_sigs[0].1.sighash_type, 0x01);

    let signed = Pczt::parse(&outcome.pczt_with_sigs).expect("signed PCZT parses");
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
    assert_eq!(outcome.orchard_sigs.len(), 1);
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

/// The `GET_VK` pump tolerates the same refusal, and resends the request rather
/// than moving on to a continuation — the refused frame never reached the app,
/// so no response is pending for a continuation to collect.
#[test]
fn a_refused_get_vk_request_is_resent_verbatim() {
    let mut exchange = pairing::VkExchange::orchard_fvk(Network::Test, 0).expect("request");

    let first = exchange.next_apdu().expect("first request");
    assert!(exchange
        .process_response(&StatusWord::CmdNotAccepted.to_u16().to_be_bytes())
        .expect("a refusal is not an error")
        .is_none());
    assert_eq!(exchange.bytes_received(), 0);

    let resent = exchange.next_apdu().expect("the same request again");
    assert_eq!(resent, first, "a refused request is resent verbatim");

    // Then the real reply, which completes the 96-byte raw FVK in one chunk.
    let mut reply = vec![7u8; 96];
    reply.extend_from_slice(&StatusWord::Ok.to_u16().to_be_bytes());
    match exchange.process_response(&reply).expect("the chunk lands") {
        Some(pczt_ledger::apdu::decode::VkResponse::OrchardFvk(bytes)) => {
            assert_eq!(bytes, vec![7u8; 96])
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
            found,
            expected,
        } => {
            assert_eq!(found, Some(7 | 0x8000_0000));
            assert_eq!(expected, ACCOUNT | 0x8000_0000);
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

    const HARDENED: u32 = 0x8000_0000;
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
    const HARDENED: u32 = 0x8000_0000;
    vec![
        44 | HARDENED,
        FIXTURE_COIN_TYPE | HARDENED,
        account | HARDENED,
        0,
        0,
    ]
}

/// The session refuses to hand out a second command before the first is
/// answered, and refuses a response with nothing outstanding.
#[test]
fn the_pump_enforces_one_outstanding_command() {
    let fixture = fixture_v5_transparent_to_orchard();
    let mut session =
        LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(None)).expect("session");

    assert!(matches!(
        session.process_response(&[0x90, 0x00]),
        Err(SessionError::OutOfOrder)
    ));

    let first = match session.next_step() {
        PumpStep::Send(apdu) => apdu,
        other => panic!("expected the identity probe, got {other:?}"),
    };
    assert_eq!(session.next_step(), PumpStep::AwaitingReply);
    assert_eq!(first[1], Ins::GetWalletPublicKey.code());
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
    let first = match session.next_step() {
        PumpStep::Send(apdu) => apdu,
        other => panic!("expected the identity probe, got {other:?}"),
    };
    assert_eq!(session.stage(), Stage::IdentifyingDevice);
    assert_eq!(
        first,
        pairing::device_identity_apdu(Network::Test).expect("encodes"),
        "the probe is the pairing module's own identity command"
    );
    assert_eq!(first[2], 0x00, "P1_GET_PUBLIC_KEY_NO_DISPLAY: no screen");
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
        vec![Ins::GetWalletPublicKey.code()],
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
        if let SessionStatus::AwaitingUserAction { stage } =
            session.process_response(&rapdu).expect("ok")
        {
            assert_eq!(stage, UserAction::ReviewTransaction);
            announced = true;
        }
    }
    assert_eq!(session.stage(), Stage::Complete);
}

/// The session refuses a PCZT with more actions than the device can hold,
/// before producing a single APDU.
#[test]
fn a_session_is_not_created_for_an_invalid_pczt() {
    let fixture = fixture_v5_transparent_to_orchard();
    // A mainnet session over a testnet PCZT: the coin types disagree.
    let err = LedgerSignSession::new(
        &fixture.bytes,
        caps(),
        SessionParams {
            network: Network::Main,
            device: fake_device_identity(),
            zip32_account: ACCOUNT,
            seed_fingerprint: Some(SEED_FINGERPRINT),
            change: None,
            viewing_keys: None,
        },
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
    let mut transport = FakeTransport {
        device,
        fail_at: Some(2),
        exchanges: 0,
    };

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
    let mut transport = FakeTransport {
        device,
        fail_at: None,
        exchanges: 0,
    };

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

/// A completed session is the one state a second run may answer `Ok(())` to,
/// and it does so without touching the transport.
#[test]
fn the_runner_is_idempotent_once_the_session_is_complete() {
    let fixture = fixture_v5_transparent_to_orchard();
    let mut session =
        LedgerSignSession::new(&fixture.bytes, caps(), fixture.params(None)).expect("session");
    let mut device = FakeDevice::new();
    canned_signatures(&fixture, &session.shaped_pczt().clone(), &mut device, false);
    let mut transport = FakeTransport {
        device,
        fail_at: None,
        exchanges: 0,
    };

    ceremony::run_session(&mut transport, &mut session, || {}).expect("the ceremony completes");
    assert_eq!(session.stage(), Stage::Complete);
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

    // A canonical signature passes straight through.
    assert_eq!(
        normalize_ledger_der(&canonical)
            .expect("canonical")
            .serialize_der()[..],
        canonical[..],
    );

    // With only the trailing sighash byte.
    let mut with_sighash = canonical.clone();
    with_sighash.push(0x01);
    assert_eq!(
        normalize_ledger_der(&with_sighash)
            .expect("trailing byte stripped")
            .serialize_der()[..],
        canonical[..],
    );

    // With both quirks.
    let mut both = with_sighash.clone();
    both[0] = 0x31;
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
        normalize_ledger_der(&[0x30, 0x02, 0x00, 0x00]),
        Err(ApplyError::DerInvalid(_))
    ));
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

    let signed = Pczt::parse(&outcome.pczt_with_sigs).expect("parses");

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
        &ShapeParams {
            coin_type: FIXTURE_COIN_TYPE,
            zip32_account: ACCOUNT,
            seed_fingerprint: Some(SEED_FINGERPRINT),
            change: fixture.change_info(),
        },
    )
    .expect("shapes");

    let plan = build_plan(&shaped.pczt).expect("plans");
    let real = plan.orchard_real_spends[0];

    let mut signer = Signer::new(shaped.pczt.clone()).expect("signer");
    signer
        .sign_orchard(real, &fixture.orchard_ask)
        .expect("sign");
    let sig = orchard_sig(&signer.finish(), real, false);

    // Point the same signature at a different action index.
    let other = (0..plan.stream.orchard_actions.len())
        .find(|i| *i != real)
        .expect("the bundle is padded to at least two actions");
    let err = apply_device_signatures(
        shaped.pczt,
        &DeviceSignatures {
            orchard: vec![(other, sig)],
            ..DeviceSignatures::default()
        },
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
    for bytes in [
        fixture_v5_transparent_to_orchard().bytes,
        fixture_v5_orchard_spend().bytes,
        fixture_v6_ironwood().bytes,
    ] {
        let pczt = Pczt::parse(&bytes).expect("parses");
        let plan = build_plan(&pczt).expect("a divergence would be an error here");

        for (index, action) in plan.stream.orchard_actions.iter().enumerate() {
            let real = plan.orchard_real_spends.contains(&index);
            assert_eq!(real, action.spend_value != 0);
        }
    }
}

/// `sequence` is mirrored from the PCZT verbatim, `None` and all.
#[test]
fn the_sequence_field_is_mirrored_verbatim() {
    let fixture = fixture_v5_transparent_to_orchard();
    let pczt = fixture.pczt();
    let plan = build_plan(&pczt).expect("plans");

    for (index, record) in plan.stream.transparent_inputs.iter().enumerate() {
        assert_eq!(
            record.sequence,
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
    let header = &plan.stream.header;

    assert_eq!(header.tx_version, *pczt.global().tx_version());
    assert_eq!(header.version_group_id, *pczt.global().version_group_id());
    assert_eq!(
        header.consensus_branch_id,
        *pczt.global().consensus_branch_id()
    );
    assert_eq!(header.expiry_height, *pczt.global().expiry_height());
    assert_eq!(header.coin_type, FIXTURE_COIN_TYPE);
    assert_eq!(header.fallback_lock_time, plan.global.fallback_lock_time);
    assert_eq!(header.tx_modifiable, plan.global.tx_modifiable);
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
        r.extend_from_slice(&0x9000u16.to_be_bytes());
        r
    };

    let caps = pairing::device_caps(&reply(3, 9, 2)).expect("parses");
    assert!(caps.pczt);
    assert!(caps.ironwood);

    let caps = pairing::device_caps(&reply(3, 8, 0)).expect("parses");
    assert!(caps.pczt);
    assert!(!caps.ironwood);

    let caps = pairing::device_caps(&reply(3, 5, 0)).expect("parses");
    assert!(!caps.pczt);

    // A different app open on the device surfaces as a typed error, not a
    // malformed-response error.
    assert!(matches!(
        pairing::device_caps(&[0x6E, 0x00]),
        Err(pairing::PairingError::WrongApp { .. })
    ));
}

/// The viewing-key reassembler will not follow a response that never ends.
///
/// Mirrors `LedgerHQ/app-zcash` @ `cfbf096`, which fixed exactly this in the
/// firmware's own test client: "driven by a device that announces ten bytes it
/// never sends, the old loop was still asking after two hundred thousand
/// continuations." The three guards are the announced length, forward
/// progress, and a continuation cap.
#[test]
fn the_viewing_key_reassembler_is_bounded_in_three_ways() {
    use pczt_ledger::apdu::decode::{
        DecodeError, VkKind, VkReassembler, MAX_VK_CONTINUATIONS, MAX_VK_RESPONSE_LEN,
    };

    assert_eq!(MAX_VK_CONTINUATIONS, 4);
    assert_eq!(MAX_VK_RESPONSE_LEN, 2 + 255 * 5);

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
    let mut exchange = pairing::VkExchange::ufvk(Network::Test, ACCOUNT).expect("request");

    let first = exchange.next_apdu().expect("first request");
    assert_eq!(first[1], Ins::GetVk.code());
    assert_eq!(first[2], 0x00, "P1_GET_VK_FIRST");
    assert_eq!(first[3], 0x00, "P2VkMode::Ufvk");
    // Two three-component paths, each one length byte plus 3 × 4 bytes.
    assert_eq!(first[4] as usize, 2 * (1 + 12));

    // A UFVK long enough to need two response chunks.
    let ufvk = "u".repeat(300);
    let mut payload = (ufvk.len() as u16).to_be_bytes().to_vec();
    payload.extend_from_slice(ufvk.as_bytes());

    let mut chunk = payload[..255].to_vec();
    chunk.extend_from_slice(&0x9000u16.to_be_bytes());
    assert!(exchange
        .process_response(&chunk)
        .expect("first chunk")
        .is_none());

    let next = exchange.next_apdu().expect("continuation");
    assert_eq!(next[2], 0x80, "P1_GET_VK_CONTINUE");
    assert_eq!(
        next[3], 0x00,
        "a continuation repeats the request's mode byte",
    );
    assert_eq!(next[4], 0, "a continuation carries no data");

    let mut chunk = payload[255..].to_vec();
    chunk.extend_from_slice(&0x9000u16.to_be_bytes());
    match exchange.process_response(&chunk).expect("second chunk") {
        Some(pczt_ledger::apdu::decode::VkResponse::Ufvk(s)) => assert_eq!(s, ufvk),
        other => panic!("unexpected response: {other:?}"),
    }
    assert!(exchange.is_complete());
    assert!(exchange.next_apdu().is_none());
}

/// Declining the viewing-key display is a typed rejection, not a fault — and
/// it is terminal. The exchange hands out nothing more, so a pump that treats
/// errors as retriable cannot put the export-approval screen back in front of
/// a user who has just said no.
#[test]
fn a_declined_viewing_key_is_a_typed_rejection_and_ends_the_exchange() {
    let mut exchange = pairing::VkExchange::orchard_fvk(Network::Test, ACCOUNT).expect("request");
    let request = exchange.next_apdu().expect("request");
    assert_eq!(request[3], 0x01, "P2VkMode::OrchardFvk");

    assert!(matches!(
        exchange.process_response(&[0x69, 0x85]),
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
    let mut exchange = pairing::VkExchange::ufvk(Network::Test, ACCOUNT).expect("request");
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
    let mut exchange = pairing::VkExchange::ufvk(Network::Test, ACCOUNT).expect("request");
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
    let mut exchange = pairing::VkExchange::ufvk(Network::Test, ACCOUNT).expect("request");
    let _ = exchange.next_apdu().expect("request");
    let refused = StatusWord::CmdNotAccepted.to_u16().to_be_bytes();
    for _ in 0..pczt_ledger::session::MAX_CMD_NOT_ACCEPTED_RETRIES {
        assert_eq!(exchange.process_response(&refused), Ok(None));
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

/// The unified-address command pairs the shielded account path with a *full*
/// external BIP 44 address path, which is what the device checks for.
/// The transparent address index is bounded on the host, at the same value the
/// device applies (`MAX_BIP44_ADDRESS_INDEX_RECOMMENDED = 50000`,
/// `src/utils.rs`).
///
/// From `22dc385` the device compares the index unmasked, so a hardened value
/// exceeds the bound on its own — this crate must not mask it either, or it
/// would build an APDU the device refuses.
#[test]
fn the_transparent_address_index_is_bounded_and_unhardened() {
    let max = pairing::MAX_BIP44_ADDRESS_INDEX;
    assert_eq!(max, 50_000);

    pairing::transparent_address_path(Network::Test, 0, 0, max).expect("the bound is inclusive");
    pairing::unified_address_apdu(Network::Test, 0, max, false).expect("and so is the command");

    for index in [max + 1, 0x8000_0000, 0x8000_0000 | 7, u32::MAX] {
        let err = pairing::transparent_address_path(Network::Test, 0, 0, index)
            .expect_err("past the device's bound");
        assert!(
            matches!(
                err,
                pairing::PairingError::PathOutOfRange {
                    what: "transparent address index",
                    max: 50_000,
                    ..
                }
            ),
            "unexpected error for {index:#x}: {err:?}"
        );
        assert!(pairing::unified_address_apdu(Network::Test, 0, index, false).is_err());
    }
}

/// `GET_SHIELD_ADDR` P1 `0x01` with P2 `0x01` is refused before an APDU exists:
/// from `22dc385` the device answers `WrongP1P2` ahead of the derivation.
#[test]
fn a_displayed_raw_orchard_address_is_never_requested() {
    assert!(pairing::orchard_address_apdu(Network::Test, 0, true).is_err());
    pairing::orchard_address_apdu(Network::Test, 0, false).expect("the silent form is fine");
}

/// `0x6A84` from a pairing command means the per-run Orchard derivation budget
/// is spent (`consume_orchard_derivation_budget`, `src/zip32.rs` @ `22dc385`),
/// which a restart of the app clears — advice worth a variant of its own.
#[test]
fn a_spent_derivation_budget_is_told_apart_from_a_device_refusal() {
    let mut exchange = pairing::VkExchange::ufvk(Network::Test, 0).expect("request");
    let _ = exchange.next_apdu().expect("request");

    assert_eq!(
        exchange.process_response(&StatusWord::NotEnoughMemorySpace.to_u16().to_be_bytes()),
        Err(pairing::PairingError::DerivationBudgetExhausted),
    );

    // Every other fatal status word stays a plain device refusal.
    let mut exchange = pairing::VkExchange::ufvk(Network::Test, 0).expect("request");
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
    let apdu = pairing::unified_address_apdu(Network::Test, ACCOUNT, 7, true).expect("request");
    assert_eq!(apdu[1], Ins::GetShieldAddr.code());
    assert_eq!(apdu[2], 0x01, "display for approval");
    assert_eq!(apdu[3], 0x00, "P2ShieldedAddrMode::UAddress");
    // 3-component shielded path + 5-component transparent path.
    assert_eq!(apdu[4] as usize, (1 + 12) + (1 + 20));

    let mut reply = 3u16.to_be_bytes().to_vec();
    reply.extend_from_slice(b"utx");
    reply.extend_from_slice(&0x9000u16.to_be_bytes());
    assert_eq!(
        pairing::parse_unified_address(&reply).expect("parses"),
        "utx"
    );
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
    assert!(!outcome.pczt_with_sigs.is_empty());

    assert!(matches!(session.finish(), Err(SessionError::OutOfOrder)));
    // The failure path did not kill the session's state.
    assert_eq!(session.stage(), Stage::Complete);
    assert!(!session.plan().stream.orchard_actions.is_empty());
}

/// The deadline policy lives on the session: `Normal` until the packet
/// carrying `P2_PCZT_FINISHED` is about to go out, `UserReview` from then on —
/// signing commands included, since the app may gate them on further
/// confirmations.
#[test]
fn the_session_reports_user_review_deadlines_from_the_review_onward() {
    use pczt_ledger::session::Deadline;

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
