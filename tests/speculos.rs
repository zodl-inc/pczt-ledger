//! Signing ceremonies against the Ledger Zcash app running in Speculos.
//!
//! [Speculos] runs the app's own binary with the device OS emulated, so a
//! ceremony that completes here has passed the firmware's parser, its
//! validation and its review, not a model of them; the end-to-end suite's
//! `Grammar` models the parser alone. The signatures the emulator returns are
//! applied through the `pczt` Signer role, which verifies each one against the
//! PCZT's own sighash or `rk` before storing it, so a completed ceremony is
//! the proof that the device signed what the PCZT says.
//!
//! Every emulator test skips unless `SPECULOS_APDU_ADDR` names the emulator's
//! APDU port (`transport::speculos::SPECULOS_ADDR_ENV`). `SPECULOS_API_ADDR`
//! names its REST API, `127.0.0.1:5000` when unset; the tests press the
//! buttons that walk and approve the review through it, the way Ledger's own
//! Ragger suite does, so only a Nano-family model (`nanosp`, `nanox`) is
//! driven here.
//!
//! # Running the emulator
//!
//! From a checkout of `LedgerHQ/app-zcash` at the commit `src/lib.rs` pins,
//! with Ledger's builder image pinned by digest so the SDK and the emulator
//! it carries do not drift under the pinned app:
//!
//! ```text
//! docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/app" -w /app \
//!     ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools@sha256:4388cbb83c1a78181b04a3cabd6041b9e6044b47068a3aa63ae8e2a2b31acb66 \
//!     cargo ledger build nanosplus
//! docker run --rm -v "$PWD:/app:ro" -p 127.0.0.1:9999:9999 -p 127.0.0.1:5000:5000 \
//!     ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools@sha256:4388cbb83c1a78181b04a3cabd6041b9e6044b47068a3aa63ae8e2a2b31acb66 \
//!     speculos --display headless --model nanosp --apdu-port 9999 --api-port 5000 \
//!     /app/target/nanosplus/release/zcash
//! ```
//!
//! then, from this crate:
//!
//! ```text
//! SPECULOS_APDU_ADDR=127.0.0.1:9999 cargo test --features transport-speculos --test speculos
//! ```
//!
//! The default build of the app is mainnet (`ZCASH_BIP44_COIN_TYPE = 133`),
//! so the fixtures are mainnet transactions. Launch the emulator with its
//! default seed: [`SEED_HEX`] is that seed, and every key below derives from it.
//!
//! # Keys
//!
//! The emulator derives every key from its seed, which by default is the
//! BIP 39 mnemonic `DEFAULT_SEED` in `speculos/main.py`; [`SEED_HEX`] is that
//! mnemonic's 64-byte BIP 39 seed (PBKDF2-HMAC-SHA512, salt `"mnemonic"`,
//! 2048 rounds, empty passphrase). The host derives from it the way the
//! wallet stack does: `SpendingKey::from_zip32_seed` for Orchard and
//! `AccountPrivKey::from_seed` for the transparent tree. That this is what the
//! firmware derives is pinned by [`host_keys_match_the_firmwares_ufvk`]
//! against the UFVK Ledger's test suite records for the same seed, and
//! checked live by every ceremony, whose identity probe must hash the device's
//! own key at the identity path to the identity the host derives.
//!
//! [Speculos]: https://github.com/LedgerHQ/speculos
#![cfg(feature = "transport-speculos")]

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::{mpsc, Mutex},
    thread,
    time::Duration,
};

use orchard::{
    keys::{FullViewingKey, Scope, SpendingKey},
    note::{Note, NoteVersion, RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use pczt::{
    roles::{
        creator::Creator, io_finalizer::IoFinalizer, redactor::Redactor,
        spend_finalizer::SpendFinalizer, updater::Updater,
    },
    Pczt,
};
use rand_core::OsRng;
use zcash_address::unified::{Container, Encoding, Fvk, Ufvk};
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding, PcztResult},
    fees::zip317,
};
use zcash_protocol::{
    consensus::{MainNetwork, NetworkType},
    memo::MemoBytes,
    value::Zatoshis,
};
use zcash_transparent::{
    address::TransparentAddress,
    bundle::{OutPoint, TxOut},
    keys::{AccountPrivKey, AccountPubKey, NonHardenedChildIndex, TransparentKeyScope},
};
use zip32::{fingerprint::SeedFingerprint, AccountId};

use pczt_ledger::{
    apdu::{encode::SIGHASH_ALL, Ins},
    ceremony,
    limits::DeviceCaps,
    pairing::{self, DeviceIdentity},
    session::{Deadline, LedgerSignSession, Network, SessionParams, SignOutcome},
    shape::{hash160, ChangeInfo, HARDENED, TRANSPARENT_INTERNAL_SCOPE},
    transport::{speculos::SpeculosTransport, Transport},
    viewing::{AccountViewingKeys, TransparentAccountKey},
};

// ---------------------------------------------------------------------------
// The emulator's seed and the keys the host derives from it
// ---------------------------------------------------------------------------

/// The 64-byte BIP 39 seed of Speculos's default mnemonic (`DEFAULT_SEED` in
/// `speculos/main.py`: "glory promote mansion idle axis finger extra february
/// uncover one trip resource lawn turtle enact monster seven myth punch hobby
/// comfort wild raise skin"), as the emulator hands it to the OS.
const SEED_HEX: &str = "b11997faff420a331bb4a4ffdc8bdc8ba7c01732a99a30d83dbbebd469666c84\
                        b47d09d3f5f472b3b9384ac634beba2a440ba36ec7661144132f35e206873564";

/// The UFVK the app exports for account 0 of that seed, as
/// `tests/standalone/test_pubkey_cmd.py` in `LedgerHQ/app-zcash` @ `22dc385`
/// records it (`REF_UFVK_ACC_0`): the firmware's own derivation, captured
/// under Speculos.
const FIRMWARE_UFVK_ACCOUNT_0: &str = "uview1zkk7f8hp2m5v09kq7h29vkgngwhhvgy2ey32cy5j0kp69g7ju2vqjvnue03u99z382rtkgvj3f8vtqdtxfxvgjytezgt39dqc0lyt2sj084jdq4md69snc3wxdcl8uah8sxw3rrt9pnxnfl3r4xnczapts7gr4l0cuell7dcjv36gkdcsl4axps827xt6fgmfl78zlhddec72tn2p0eqnpkuy7a08puhj97v0ahxuqlyzmyqtldqnc0p3696d9ww8x6mpd56mz6w32twryevru2rx34lf8dtqsp50gar";

/// The app's default build is mainnet.
const NETWORK: Network = Network::Main;
const COIN_TYPE: u32 = NETWORK.coin_type();
const ACCOUNT: AccountId = AccountId::ZERO;

/// A mainnet height above NU6.2 and below NU6.3: the builder emits a V5
/// transaction under the NU6.2 branch.
const V5_HEIGHT: u32 = 3_400_000;
/// A mainnet height above NU6.3: a V6 transaction with the Ironwood pool.
const V6_HEIGHT: u32 = 3_500_000;

/// The address index every transparent key in these fixtures uses, on both
/// the external and the internal chain.
const ADDRESS_INDEX: u32 = 0;

fn seed() -> [u8; 64] {
    hex::decode(SEED_HEX)
        .expect("SEED_HEX is hex")
        .try_into()
        .expect("SEED_HEX is 64 bytes")
}

fn address_index() -> NonHardenedChildIndex {
    NonHardenedChildIndex::from_index(ADDRESS_INDEX).expect("an unhardened index")
}

/// Account 0 of the emulator's seed, as the host derives it.
struct AccountKeys {
    orchard_fvk: FullViewingKey,
    account_sk: AccountPrivKey,
    account_pubkey: AccountPubKey,
    fingerprint: [u8; 32],
}

impl AccountKeys {
    fn derive() -> Self {
        let seed = seed();
        let orchard_sk =
            SpendingKey::from_zip32_seed(&seed, COIN_TYPE, ACCOUNT).expect("orchard key derives");
        let account_sk =
            AccountPrivKey::from_seed(&MainNetwork, &seed, ACCOUNT).expect("account key derives");
        AccountKeys {
            orchard_fvk: FullViewingKey::from(&orchard_sk),
            account_pubkey: account_sk.to_account_pubkey(),
            account_sk,
            fingerprint: SeedFingerprint::from_seed(&seed)
                .expect("a 64-byte seed has a fingerprint")
                .to_bytes(),
        }
    }

    /// The key at `m/44'/133'/0'/0/ADDRESS_INDEX`, which the device signs a
    /// transparent input with.
    fn external_pubkey(&self) -> secp256k1::PublicKey {
        let sk = self
            .account_sk
            .derive_external_secret_key(address_index())
            .expect("external key derives");
        secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::signing_only(), &sk)
    }

    /// The key at `m/44'/133'/0'/1/ADDRESS_INDEX`, which the change output
    /// pays.
    fn change_pubkey(&self) -> secp256k1::PublicKey {
        self.account_pubkey
            .derive_address_pubkey(TransparentKeyScope::INTERNAL, address_index())
            .expect("internal key derives")
    }

    /// The identity the session must see: `HASH(pubkey at m/44'/133'/0'/0/0)`,
    /// derived here from the account key rather than read from the device.
    fn expected_identity(&self) -> DeviceIdentity {
        let pubkey = self
            .account_pubkey
            .derive_address_pubkey(
                TransparentKeyScope::EXTERNAL,
                NonHardenedChildIndex::from_index(0).expect("0 is unhardened"),
            )
            .expect("identity key derives");
        DeviceIdentity::from_compressed_pubkey(&pubkey.serialize())
    }

    fn session_params(
        &self,
        identity: DeviceIdentity,
        change: Option<ChangeInfo>,
    ) -> SessionParams {
        SessionParams::new(NETWORK, identity, ACCOUNT)
            .with_seed_fingerprint(Some(self.fingerprint))
            .with_change(change)
            .with_transparent_account_key(Some(TransparentAccountKey::from_account_pubkey(
                self.account_pubkey.clone(),
            )))
            .with_viewing_keys(Some(AccountViewingKeys::from_orchard_fvk(
                self.orchard_fvk.clone(),
            )))
    }
}

/// The host's derivation from [`SEED_HEX`] reproduces the firmware's: both items
/// of the UFVK the app exported for account 0 under Speculos are the keys
/// derived here. Needs no emulator, so it runs in CI, and it is what makes the
/// ceremonies below meaningful: a fixture built for the wrong keys would be
/// refused by the device, not signed.
#[test]
fn host_keys_match_the_firmwares_ufvk() {
    let keys = AccountKeys::derive();
    let (network, _revision, ufvk) =
        Ufvk::decode(FIRMWARE_UFVK_ACCOUNT_0).expect("the recorded UFVK decodes");
    assert_eq!(
        network,
        NetworkType::Main,
        "the app's default build is mainnet"
    );

    let mut orchard = None;
    let mut p2pkh = None;
    for item in ufvk.items() {
        match item {
            Fvk::Orchard(bytes) => orchard = Some(bytes),
            Fvk::P2pkh(bytes) => p2pkh = Some(bytes),
            _ => {}
        }
    }
    assert_eq!(
        orchard.expect("an Orchard item"),
        keys.orchard_fvk.to_bytes(),
        "SpendingKey::from_zip32_seed over the BIP 39 seed is the firmware's Orchard derivation",
    );
    assert_eq!(
        p2pkh.expect("a P2PKH item").to_vec(),
        keys.account_pubkey.serialize(),
        "AccountPrivKey::from_seed over the BIP 39 seed is the firmware's BIP 44 derivation",
    );
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// The redaction `redact_pczt_for_signer(SignerView::Full)` performs on the
/// shielded pools: clear each action's spend witness and dummy spending key.
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

/// Stamps `m/44'/133'/0'/0/ADDRESS_INDEX` on every transparent input, keyed by
/// the pubkey at that path: the signing-key locator the device reads.
fn stamp_transparent_input_derivations(pczt: Pczt, keys: &AccountKeys) -> Pczt {
    let pubkey = keys.external_pubkey().serialize();
    let path = vec![
        44 | HARDENED,
        COIN_TYPE | HARDENED,
        u32::from(ACCOUNT) | HARDENED,
        0,
        ADDRESS_INDEX,
    ];
    Updater::new(pczt)
        .update_transparent_with(|mut updater| {
            let count = updater.bundle().inputs().len();
            for index in 0..count {
                let derivation =
                    zcash_transparent::pczt::Bip32Derivation::parse(keys.fingerprint, path.clone())
                        .expect("a valid derivation");
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

/// Builder parts → Creator → IO Finalizer → input stamping → redaction: the
/// PCZT a wallet hands the session.
fn finish_fixture(parts: PcztResult<MainNetwork>, keys: &AccountKeys) -> Vec<u8> {
    let pczt = Creator::build_from_parts(parts.pczt_parts).expect("creator");
    let pczt = IoFinalizer::new(pczt).finalize_io().expect("io finalizer");
    let pczt = stamp_transparent_input_derivations(pczt, keys);
    redact_signer_view_full(pczt)
        .serialize()
        .expect("the fixture serializes")
}

/// A note of `value` to the account's first external address, at position 0
/// of a tree whose other leaves are empty. Nothing verifies the anchor: the
/// device receives no proof and the ceremony produces none.
fn synthetic_note(
    fvk: &FullViewingKey,
    value: u64,
    version: NoteVersion,
) -> (Note, MerklePath, orchard::Anchor) {
    let recipient = fvk.address_at(0u32, Scope::External);

    let mut rho_bytes = [0u8; 32];
    rho_bytes[0] = 1;
    let rho = Option::<Rho>::from(Rho::from_bytes(&rho_bytes)).expect("a valid rho");

    let note = (0u8..=255)
        .find_map(|seed| {
            let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes([seed; 32], &rho))?;
            Option::<Note>::from(Note::from_parts(
                recipient,
                NoteValue::from_raw(value),
                rho,
                rseed,
                version,
            ))
        })
        .expect("a valid note exists for some rseed");

    let empty = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&[0u8; 32]))
        .expect("zero is a valid Pallas base");
    let merkle_path = MerklePath::from_parts(0, [empty; 32]);
    let anchor = merkle_path.root(note.commitment().into());
    (note, merkle_path, anchor)
}

/// V5: a real Orchard spend of the account's note → one Orchard output back
/// to the account's external address, plus a transparent change output the
/// account controls. The device signs the spend, displays the output, and
/// hides the change; the ZIP 317 fee for three logical actions is 15 000.
fn v5_orchard_spend(keys: &AccountKeys) -> (Vec<u8>, ChangeInfo) {
    let fvk = &keys.orchard_fvk;
    let (note, merkle_path, anchor) = synthetic_note(fvk, 1_000_000, NoteVersion::V2);
    let change_address = TransparentAddress::from_pubkey(&keys.change_pubkey());

    let mut builder = Builder::new(
        MainNetwork,
        V5_HEIGHT.into(),
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
        .add_transparent_output(&change_address, Zatoshis::const_from_u64(885_000))
        .expect("transparent change output");
    let parts = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .expect("build_for_pczt");

    // `OP_DUP OP_HASH160 <20> … OP_EQUALVERIFY OP_CHECKSIG`: the P2PKH script
    // the output pays, as bytes.
    let mut change_script = vec![0x76, 0xa9, 0x14];
    change_script.extend_from_slice(&hash160(&keys.change_pubkey().serialize()));
    change_script.extend_from_slice(&[0x88, 0xac]);
    let change = ChangeInfo::derive(
        &keys.account_pubkey,
        TRANSPARENT_INTERNAL_SCOPE,
        address_index(),
        0,
        &change_script,
    )
    .expect("the change hint derives against its own script");

    (finish_fixture(parts, keys), change)
}

/// V6: a transparent input the device signs → one Ironwood output back to the
/// account's external address. Both Ironwood actions are padding on the spend
/// side, so the only signature is the transparent one; the ZIP 317 fee for
/// three logical actions is 15 000.
fn v6_transparent_input_to_ironwood(keys: &AccountKeys) -> Vec<u8> {
    let fvk = &keys.orchard_fvk;
    let pubkey = keys.external_pubkey();
    let address = TransparentAddress::from_pubkey(&pubkey);

    let mut builder = Builder::new(
        MainNetwork,
        V6_HEIGHT.into(),
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
            pubkey,
            OutPoint::new([1u8; 32], 1),
            TxOut::new(Zatoshis::const_from_u64(1_000_000), address.script().into()),
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

    finish_fixture(parts, keys)
}

// ---------------------------------------------------------------------------
// The emulator
// ---------------------------------------------------------------------------

/// The environment variable naming the emulator's REST API address.
const SPECULOS_API_ADDR_ENV: &str = "SPECULOS_API_ADDR";
/// Where the REST API is when [`SPECULOS_API_ADDR_ENV`] is unset:
/// `speculos --api-port` defaults to 5000.
const DEFAULT_SPECULOS_API_ADDR: &str = "127.0.0.1:5000";

/// The screen on which a both-button press approves the review, as the app
/// draws it on a Nano-family model (`src/app_ui/sign.rs` @ `22dc385`), and as
/// Ragger's `TX_REVIEW` scenario looks for it.
const SIGN_SCREEN: &str = "Sign transaction";
/// Right presses the review walker gives up after; a review of these fixtures
/// is a few pages.
const MAX_REVIEW_PAGES: usize = 200;
/// The polling interval for a screen change.
const SCREEN_SETTLE: Duration = Duration::from_millis(50);
/// How long a single screen change may take: the review's first page, which
/// the app draws once it has parsed the FINISHED packet, or the page after a
/// press.
const SCREEN_CHANGE_TIMEOUT: Duration = Duration::from_secs(60);
/// The first text of the review as the app draws it (`src/app_ui/sign.rs`
/// @ `22dc385`).
const REVIEW_INTRO: &str = "Review transaction to ";
/// The whole ceremony, streaming and review included, must finish within
/// this; the review exchange itself has no timeout by design.
const CEREMONY_TIMEOUT: Duration = Duration::from_secs(180);
/// A text the app's idle screen shows (`"Zcash" / "app is ready"`).
const IDLE_SCREEN: &str = "app is ready";
/// How long to wait for the app to be back on its idle screen.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The emulator is one device: ceremonies must not overlap.
static EMULATOR: Mutex<()> = Mutex::new(());

/// Speculos's REST API, enough of it to read the screen and press buttons.
#[derive(Clone)]
struct SpeculosApi {
    addr: String,
}

impl SpeculosApi {
    fn from_env() -> Self {
        SpeculosApi {
            addr: std::env::var(SPECULOS_API_ADDR_ENV)
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| DEFAULT_SPECULOS_API_ADDR.to_string()),
        }
    }

    /// One HTTP/1.0 request; the server answers with a `Content-Length` and
    /// closes, so the body is everything after the header block.
    fn request(&self, method: &str, path: &str, body: &str) -> String {
        let mut stream = TcpStream::connect(&self.addr)
            .unwrap_or_else(|e| panic!("connecting to the Speculos API at {}: {e}", self.addr));
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a read timeout can be set");
        let request = format!(
            "{method} {path} HTTP/1.0\r\nHost: {}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.addr,
            body.len(),
        );
        stream
            .write_all(request.as_bytes())
            .expect("the request is written");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("the response is read to its end");
        let (head, body) = response
            .split_once("\r\n\r\n")
            .expect("an HTTP response has a header block");
        let status = head.lines().next().unwrap_or_default();
        assert!(
            status.contains(" 200 "),
            "{method} {path} answered {status:?}: {body}"
        );
        body.to_string()
    }

    /// The text of every element on the current screen, top to bottom.
    fn current_screen(&self) -> Vec<String> {
        let body = self.request("GET", "/events?currentscreenonly=true", "");
        let events: serde_json::Value = serde_json::from_str(&body).expect("the events are JSON");
        events["events"]
            .as_array()
            .map(|events| {
                events
                    .iter()
                    .filter_map(|event| event["text"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// `right`, `left` or `both`, pressed and released.
    fn press(&self, button: &str) {
        self.request(
            "POST",
            &format!("/button/{button}"),
            r#"{"action":"press-and-release"}"#,
        );
    }
}

/// Polls the screen until `accept` holds of it, and returns that screen.
fn wait_for_screen(
    api: &SpeculosApi,
    what: &str,
    accept: impl Fn(&[String]) -> bool,
) -> Vec<String> {
    let started = std::time::Instant::now();
    loop {
        let screen = api.current_screen();
        if accept(&screen) {
            return screen;
        }
        assert!(
            started.elapsed() < SCREEN_CHANGE_TIMEOUT,
            "the emulator did not show {what} within {SCREEN_CHANGE_TIMEOUT:?}; it shows {screen:?}"
        );
        thread::sleep(SCREEN_SETTLE);
    }
}

/// Walks the review the way a user on a Nano does, and the way Ragger does:
/// waits for the review to be drawn, then presses right and waits for the
/// screen to change, page by page, until the screen is [`SIGN_SCREEN`], then
/// presses both to approve. Returns every screen text seen on the way, in
/// order.
fn approve_review(api: &SpeculosApi) -> Vec<String> {
    // The walker starts before the review packet goes out, so the first
    // screen it must not act on is the idle menu.
    let mut screen = wait_for_screen(api, "the review's first page", |screen| {
        screen.iter().any(|text| text.starts_with(REVIEW_INTRO))
    });
    let mut seen = screen.clone();
    for _ in 0..MAX_REVIEW_PAGES {
        if screen.iter().any(|text| text == SIGN_SCREEN) {
            api.press("both");
            return seen;
        }
        api.press("right");
        let previous = screen;
        screen = wait_for_screen(api, "the next page", |screen| screen != previous.as_slice());
        seen.extend(screen.iter().cloned());
    }
    panic!("the emulator never showed {SIGN_SCREEN:?} in {MAX_REVIEW_PAGES} pages; seen: {seen:?}");
}

/// Waits until the app is on its idle screen.
///
/// After the last signature the app shows a "Transaction signed" status
/// screen for a moment before returning to its menu, and an APDU that
/// arrives while that screen is up is not answered (observed on 3.9.3 under
/// Speculos: the request is forwarded and no reply ever comes). Ledger's own
/// suite waits for the screen; so does this, before the first command of
/// every ceremony and after its last.
fn wait_for_idle(api: &SpeculosApi) {
    let started = std::time::Instant::now();
    loop {
        let screen = api.current_screen();
        if screen.iter().any(|text| text == IDLE_SCREEN) {
            return;
        }
        assert!(
            started.elapsed() < IDLE_TIMEOUT,
            "the app did not return to its idle screen; it shows {screen:?}. Restart the emulator."
        );
        thread::sleep(SCREEN_SETTLE);
    }
}

/// Asserts that every text in `expected` appeared on the review, in that
/// order, with [`SIGN_SCREEN`] after all of them.
fn assert_review_shows(screens: &[String], expected: &[&str]) {
    let mut from = 0;
    for text in expected.iter().chain([&SIGN_SCREEN]) {
        match screens[from..].iter().position(|shown| shown == text) {
            Some(offset) => from += offset + 1,
            None => panic!("the review did not show {text:?} (after position {from}): {screens:?}"),
        }
    }
}

/// The emulator, if the environment names one, with the app idle; `None`
/// skips the test.
fn emulator() -> Option<(SpeculosTransport, SpeculosApi)> {
    let transport = match SpeculosTransport::connect_from_env() {
        None => {
            eprintln!(
                "skipped: {} is unset, so no Speculos emulator was named",
                pczt_ledger::transport::speculos::SPECULOS_ADDR_ENV
            );
            return None;
        }
        Some(transport) => transport.expect("the emulator's APDU port accepts a connection"),
    };
    let api = SpeculosApi::from_env();
    wait_for_idle(&api);
    Some((transport, api))
}

/// The two probes a session opens with, run here so the caps and identity the
/// session is built against are the connected emulator's own.
fn probe(transport: &mut dyn Transport) -> (DeviceCaps, DeviceIdentity) {
    let caps = ceremony::query(
        transport,
        &pairing::firmware_version_apdu(),
        Deadline::Normal,
        Ins::GetFirmwareVersion,
        pairing::device_caps,
    )
    .expect("GET_FIRMWARE_VERSION");
    let identity = ceremony::query(
        transport,
        &pairing::device_identity_apdu(NETWORK).expect("the identity path encodes"),
        Deadline::Normal,
        Ins::GetWalletPublicKey,
        pairing::parse_device_identity_response,
    )
    .expect("GET_WALLET_PUBLIC_KEY at the identity path");
    (caps, identity)
}

/// Runs a ceremony to completion, approving the review through the REST API
/// from a helper thread, under [`CEREMONY_TIMEOUT`]. Returns the outcome and
/// every screen text the review showed.
fn sign_on_emulator(
    mut transport: SpeculosTransport,
    api: SpeculosApi,
    session: LedgerSignSession,
) -> (SignOutcome, Vec<String>) {
    let (outcome_tx, outcome_rx) = mpsc::channel();
    let (screens_tx, screens_rx) = mpsc::channel();
    let api_for_after = api.clone();
    thread::spawn(move || {
        let outcome = ceremony::sign(&mut transport, session, || {
            // The review packet is about to go out; its reply arrives once
            // the review is approved, which the walker does from here.
            let api = api.clone();
            let screens_tx = screens_tx.clone();
            thread::spawn(move || {
                let _ = screens_tx.send(approve_review(&api));
            });
        });
        let _ = outcome_tx.send(outcome);
    });
    let outcome = outcome_rx
        .recv_timeout(CEREMONY_TIMEOUT)
        .expect("the ceremony finished within the timeout (is the emulator stuck on a screen?)")
        .expect("the ceremony completed");
    let screens = screens_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_default();
    // Leave the app idle for whatever runs next.
    wait_for_idle(&api_for_after);
    (outcome, screens)
}

// ---------------------------------------------------------------------------
// Ceremonies
// ---------------------------------------------------------------------------

/// The device signs a real Orchard spend of a V5 transaction, shows the
/// account's own output, and hides the transparent change; the signature it
/// returns verifies against the action's `rk` on the way onto the PCZT.
#[test]
fn v5_orchard_spend_is_signed_by_the_emulator() {
    let _one_at_a_time = EMULATOR.lock().unwrap_or_else(|e| e.into_inner());
    let Some((mut transport, api)) = emulator() else {
        return;
    };
    let keys = AccountKeys::derive();
    let (caps, identity) = probe(&mut transport);
    assert_eq!(
        identity,
        keys.expected_identity(),
        "the emulator's key at the identity path is the one the host derives from its seed",
    );

    let (bytes, change) = v5_orchard_spend(&keys);
    // Shown only when the test fails, so a refusal can be replayed byte for
    // byte against the emulator.
    eprintln!("fixture: {}", hex::encode(&bytes));
    let session = LedgerSignSession::new(&bytes, caps, keys.session_params(identity, Some(change)))
        .expect("the fixture passes pre-flight");
    assert_eq!(session.plan().orchard_real_spends().len(), 1);
    assert_eq!(session.plan().displayed_shielded_outputs(), 1);
    assert!(session.plan().displayed_count_is_exact());
    let real_spend = session.plan().orchard_real_spends()[0];

    let (outcome, screens) = sign_on_emulator(transport, api, session);

    // What the device showed: the account's own output as the one output,
    // no second output (the transparent change is hidden), and the fee.
    assert_review_shows(
        &screens,
        &[
            "Output #1 amount",
            "0.00100000 ZEC",
            "Fees",
            "0.00015000 ZEC",
        ],
    );
    assert!(
        !screens.iter().any(|text| text.starts_with("Output #2")),
        "the transparent change was shown as an output: {screens:?}"
    );
    assert_eq!(outcome.orchard_sigs().len(), 1);
    assert_eq!(outcome.orchard_sigs()[0].0, real_spend);
    assert!(outcome.ironwood_sigs().is_empty());
    assert!(outcome.transparent_sigs().is_empty());

    // `apply` already verified the signature against the action's `rk`; this
    // is that it landed on the action the device was asked to sign.
    let signed = Pczt::parse(outcome.pczt_with_sigs()).expect("the signed PCZT parses");
    assert_eq!(
        signed.orchard().actions()[real_spend]
            .spend()
            .spend_auth_sig()
            .expect("the real spend is signed"),
        outcome.orchard_sigs()[0].1,
    );
}

/// The device signs a transparent input of a V6 transaction with the key at
/// the stamped path; the DER reply survives `normalize_ledger_der`, verifies
/// against the input's sighash on the way onto the PCZT, and the Spend
/// Finalizer assembles a `script_sig` carrying that key.
#[test]
fn v6_transparent_input_is_signed_by_the_emulator() {
    let _one_at_a_time = EMULATOR.lock().unwrap_or_else(|e| e.into_inner());
    let Some((mut transport, api)) = emulator() else {
        return;
    };
    let keys = AccountKeys::derive();
    let (caps, identity) = probe(&mut transport);
    assert_eq!(identity, keys.expected_identity());

    let bytes = v6_transparent_input_to_ironwood(&keys);
    eprintln!("fixture: {}", hex::encode(&bytes));
    let session = LedgerSignSession::new(&bytes, caps, keys.session_params(identity, None))
        .expect("the fixture passes pre-flight");
    assert!(session.plan().orchard_real_spends().is_empty());
    assert!(session.plan().ironwood_real_spends().is_empty());
    assert_eq!(session.plan().stream().transparent_inputs().len(), 1);

    let (outcome, screens) = sign_on_emulator(transport, api, session);

    // What the device showed: the Ironwood output as the one output, and the
    // fee; the transparent input is not an output.
    assert_review_shows(
        &screens,
        &[
            "Output #1 amount",
            "0.00985000 ZEC",
            "Fees",
            "0.00015000 ZEC",
        ],
    );
    assert!(
        !screens.iter().any(|text| text.starts_with("Output #2")),
        "a second output was shown: {screens:?}"
    );
    assert!(outcome.orchard_sigs().is_empty());
    assert!(outcome.ironwood_sigs().is_empty());
    assert_eq!(outcome.transparent_sigs().len(), 1);
    assert_eq!(outcome.transparent_sigs()[0].0, 0);

    // `apply` verified the DER signature against the input's sighash and the
    // stamped pubkey before filing it; this is that it was filed under the key
    // at the stamped path, as `<DER> ‖ SIGHASH_ALL`.
    let expected_pubkey = keys.external_pubkey().serialize();
    let signed = Pczt::parse(outcome.pczt_with_sigs()).expect("the signed PCZT parses");
    let mut partial_signatures = None;
    Updater::new(signed.clone())
        .update_transparent_with(|updater| {
            partial_signatures = Some(updater.bundle().inputs()[0].partial_signatures().clone());
            Ok(())
        })
        .expect("transparent updater");
    let partial_signatures = partial_signatures.expect("the closure ran");
    assert_eq!(partial_signatures.len(), 1);
    let sig = partial_signatures
        .get(&expected_pubkey)
        .expect("the signature is filed under the key at the stamped path");
    assert_eq!(sig.last().copied(), Some(SIGHASH_ALL));
    secp256k1::ecdsa::Signature::from_der(&sig[..sig.len() - 1])
        .expect("canonical DER, the device's quirks undone");

    // And the Spend Finalizer, the next role downstream, assembles a
    // `script_sig` from it.
    let finalized = SpendFinalizer::new(signed)
        .finalize_spends()
        .expect("the Spend Finalizer assembles the script_sig");
    let mut has_script_sig = false;
    Updater::new(finalized)
        .update_transparent_with(|updater| {
            has_script_sig = updater.bundle().inputs()[0].script_sig().is_some();
            Ok(())
        })
        .expect("transparent updater");
    assert!(has_script_sig, "the finalized input carries a script_sig");
}
