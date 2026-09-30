use proptest::prelude::*;
use zip32::AccountId;

use crate::apdu::decode::{DecodeError, CHAIN_CODE_LEN, ORCHARD_FVK_LEN};
use crate::apdu::{p1, Ins, StatusWord};
use crate::pairing::{
    device_identity_apdu, device_identity_path, parse_device_identity_response,
    parse_firmware_version_response, transparent_external_address_path, DeviceIdentity,
    InvalidDeviceIdentity, PairingError, VkExchange, VkStep, DEVICE_IDENTITY_PERSONALIZATION,
    DEVICE_IDENTITY_PREFIX,
};
use crate::session::Network;
use crate::test_support::{
    testnet_identity_path, wallet_public_key_reply, GENERATOR_UNCOMPRESSED, SAMPLE_ADDRESS,
};

// ---------------------------------------------------------------------------
// Device identity
// ---------------------------------------------------------------------------

/// The generator point, compressed — a fixed key to pin the hash against.
const GENERATOR_COMPRESSED: [u8; 33] = [
    0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
    0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
    0x98,
];

/// The pinned identity vector.
///
/// BLAKE2b-256 with personalization `PcztLedgerDvId_0` over the compressed
/// secp256k1 generator point, cross-checked against an independent
/// implementation (Python's `hashlib.blake2b(pk, digest_size=32,
/// person=b"PcztLedgerDvId_0")`) rather than only against this crate's own
/// output.
///
/// Nothing about this repository may change it: it is the string a paired
/// account is stored under, and a different value here would orphan every
/// account already paired. A deliberate change to the derivation moves the
/// version suffix in the personalization instead, which gives the new
/// scheme a disjoint output space.
const PINNED: &str = "tpk0-b1e9b1e524e494f1714baba8de4dbbd7e106c3ad22e1459ea7b7ef9729bd272c";

#[test]
fn the_personalization_is_sixteen_bytes() {
    // BLAKE2b takes exactly 16; `Params::personal` panics otherwise, and a
    // panic inside a derivation is not where that should be discovered.
    assert_eq!(DEVICE_IDENTITY_PERSONALIZATION.len(), 16);
}

#[test]
fn the_identity_vector_is_pinned() {
    let id = DeviceIdentity::from_compressed_pubkey(&GENERATOR_COMPRESSED);
    assert_eq!(id.to_string(), PINNED);
}

#[test]
fn display_and_parse_round_trip() {
    let id = DeviceIdentity::from_compressed_pubkey(&GENERATOR_COMPRESSED);
    let text = id.to_string();
    assert!(text.starts_with(DEVICE_IDENTITY_PREFIX));
    assert_eq!(text.len(), DEVICE_IDENTITY_PREFIX.len() + 64);
    assert_eq!(DeviceIdentity::parse(&text).expect("its own form"), id);
    assert_eq!(text.parse::<DeviceIdentity>().expect("FromStr"), id);
}

/// A different key is a different identity — the property the whole
/// mechanism rests on.
#[test]
fn a_different_key_is_a_different_identity() {
    let mut other = GENERATOR_COMPRESSED;
    other[0] = 0x03; // the other parity of the same x coordinate.
    assert_ne!(
        DeviceIdentity::from_compressed_pubkey(&GENERATOR_COMPRESSED),
        DeviceIdentity::from_compressed_pubkey(&other),
    );
}

#[test]
fn a_string_without_the_prefix_is_refused() {
    let hex = &PINNED[DEVICE_IDENTITY_PREFIX.len()..];
    assert_eq!(
        DeviceIdentity::parse(hex),
        Err(InvalidDeviceIdentity::MissingPrefix)
    );
    assert_eq!(
        DeviceIdentity::parse("nano-s-plus-01"),
        Err(InvalidDeviceIdentity::MissingPrefix)
    );
    // An empty string is not an identity either.
    assert_eq!(
        DeviceIdentity::parse(""),
        Err(InvalidDeviceIdentity::MissingPrefix)
    );
}

#[test]
fn a_string_of_the_wrong_length_is_refused() {
    assert_eq!(
        DeviceIdentity::parse(&PINNED[..PINNED.len() - 1]),
        Err(InvalidDeviceIdentity::BadLength { got: 63 })
    );
    assert_eq!(
        DeviceIdentity::parse(&format!("{PINNED}0")),
        Err(InvalidDeviceIdentity::BadLength { got: 65 })
    );
}

/// Uppercase hex names the same bytes and is still refused: the string is a
/// directory name, and two spellings of one device would be two caches on a
/// case-sensitive filesystem.
#[test]
fn uppercase_hex_is_refused() {
    let shouted = format!(
        "{DEVICE_IDENTITY_PREFIX}{}",
        PINNED[DEVICE_IDENTITY_PREFIX.len()..].to_uppercase()
    );
    assert_eq!(
        DeviceIdentity::parse(&shouted),
        Err(InvalidDeviceIdentity::NotLowercaseHex)
    );
    assert_eq!(
        DeviceIdentity::parse(&format!("{DEVICE_IDENTITY_PREFIX}{}", "z".repeat(64))),
        Err(InvalidDeviceIdentity::NotLowercaseHex)
    );
}

/// The identity path is account 0's first external address, and its coin
/// type is the network's — which is what makes one device two identities.
#[test]
fn the_identity_path_is_the_networks_first_external_address() {
    let main = device_identity_path(Network::Main);
    let test = device_identity_path(Network::Test);
    assert_eq!(main.0, vec![0x8000_002C, 0x8000_0085, 0x8000_0000, 0, 0]);
    assert_eq!(test.0, vec![0x8000_002C, 0x8000_0001, 0x8000_0000, 0, 0]);
    assert_ne!(main.0, test.0);

    // And it is exactly the account-0 case of the per-account path the
    // sign-time cross-check uses.
    assert_eq!(
        transparent_external_address_path(
            Network::Test,
            zip32::AccountId::ZERO,
            zcash_transparent::keys::NonHardenedChildIndex::ZERO
        )
        .expect("account 0"),
        test
    );
    assert_eq!(
        transparent_external_address_path(
            Network::Test,
            zip32::AccountId::try_from(7).expect("unhardened"),
            zcash_transparent::keys::NonHardenedChildIndex::ZERO
        )
        .expect("account 7")
        .0,
        vec![0x8000_002C, 0x8000_0001, 0x8000_0007, 0, 0]
    );
}

/// The identity probe is the silent `GET_WALLET_PUBLIC_KEY` at that path:
/// no screen, so it can open a signing ceremony without a prompt.
#[test]
fn the_identity_probe_is_the_silent_wallet_public_key_command() {
    let apdu = device_identity_apdu(Network::Test).expect("encodes");
    assert_eq!(apdu[1], Ins::GetWalletPublicKey.code());
    assert_eq!(apdu[2], p1::NO_DISPLAY);
    assert_eq!(apdu[3], 0x00, "P2 is unused and zero");
    assert_eq!(usize::from(apdu[4]), apdu.len() - 5, "Lc counts the path");
    assert_eq!(
        &apdu[5..],
        &testnet_identity_path().to_bytes().expect("encodes")[..]
    );
}

/// The reply parses to the same identity the compressed key hashes to,
/// so the pinned vector holds through the whole probe.
#[test]
fn the_probe_reply_parses_to_the_pinned_identity() {
    let mut rapdu = wallet_public_key_reply(
        &GENERATOR_UNCOMPRESSED,
        SAMPLE_ADDRESS.as_bytes(),
        &[0x3C; CHAIN_CODE_LEN],
    );
    rapdu.extend_from_slice(&StatusWord::Ok.to_u16().to_be_bytes());
    let id = parse_device_identity_response(&rapdu).expect("a well-formed reply");
    assert_eq!(id.to_string(), PINNED);
    assert_eq!(
        id,
        DeviceIdentity::from_compressed_pubkey(&GENERATOR_COMPRESSED)
    );

    // A refusal is a typed error, not an identity.
    assert!(matches!(
        parse_device_identity_response(&StatusWord::IncorrectData.to_u16().to_be_bytes()),
        Err(crate::pairing::PairingError::Device { .. })
    ));
}

// ---------------------------------------------------------------------------
// Status-word classification
// ---------------------------------------------------------------------------

/// A `0x6901` that carries a body is not the SDK's frame refusal.
///
/// The SDK's refusal never carries data, so a body means the reply belongs to
/// another command and the channel is one reply out of step. Retrying — what
/// the refusal asks for — would widen the gap, so it is a decode failure, and
/// a terminal one: a `VkExchange` that retried it would re-raise the
/// export-approval screen up to the retry budget and then report the wrong
/// cause.
#[test]
fn a_frame_refusal_with_a_body_is_not_a_frame_refusal() {
    let empty = StatusWord::CmdNotAccepted.to_u16().to_be_bytes().to_vec();
    let mut bodied = vec![0xAA];
    bodied.extend_from_slice(&empty);

    // The one-shot parsers surface the refusal for the caller to resend, but
    // only when it is one.
    assert_eq!(
        parse_firmware_version_response(&empty),
        Err(PairingError::CmdNotAccepted)
    );
    assert_eq!(
        parse_firmware_version_response(&bodied),
        Err(PairingError::Decode(DecodeError::UnexpectedLength {
            what: "0x6901 refusal",
            expected: 0,
            got: 1,
        }))
    );

    // The viewing-key exchange absorbs the empty one and ends on the other,
    // rather than resending the approval screen until the budget runs out.
    let mut exchange =
        VkExchange::orchard_fvk(Network::Test, AccountId::ZERO).expect("the request encodes");
    let _ = exchange.next_apdu().expect("the request");
    assert_eq!(exchange.process_response(&empty), Ok(VkStep::RetrySameApdu));

    let mut exchange =
        VkExchange::orchard_fvk(Network::Test, AccountId::ZERO).expect("the request encodes");
    let _ = exchange.next_apdu().expect("the request");
    assert_eq!(
        exchange.process_response(&bodied),
        Err(PairingError::Decode(DecodeError::UnexpectedLength {
            what: "0x6901 refusal",
            expected: 0,
            got: 1,
        }))
    );
    assert!(exchange.is_failed());
    assert_eq!(exchange.next_apdu(), None);
}

// ---------------------------------------------------------------------------
// GET_VK exchange
// ---------------------------------------------------------------------------

/// A command already awaiting its reply is not handed out a second time.
///
/// The `GET_VK` request raises the key-export approval screen, so a driver
/// that swallowed a timeout and asked for the next command would otherwise put
/// a second copy on the wire — two commands in flight, and a second screen —
/// where the signing session's pump answers `AwaitingReply`. The SDK's frame
/// refusal is the one thing that makes the identical bytes come out again, and
/// it makes them come out once.
#[test]
fn a_request_awaiting_its_reply_is_not_handed_out_again() {
    let refused = StatusWord::CmdNotAccepted.to_u16().to_be_bytes();

    let mut exchange =
        VkExchange::orchard_fvk(Network::Test, AccountId::ZERO).expect("the request encodes");
    let first = exchange.next_apdu().expect("the request");
    assert!(exchange.is_awaiting_reply());
    assert_eq!(
        exchange.next_apdu(),
        None,
        "the approval screen must not be raised twice"
    );
    assert!(!exchange.is_complete());
    assert!(!exchange.is_failed());

    assert_eq!(
        exchange.process_response(&refused),
        Ok(VkStep::RetrySameApdu)
    );
    assert!(
        !exchange.is_awaiting_reply(),
        "the resend is owed, not sent"
    );
    assert_eq!(exchange.next_apdu().as_ref(), Some(&first));
    assert!(exchange.is_awaiting_reply());
    assert_eq!(exchange.next_apdu(), None);

    // A reply arriving between the refusal and the resend answers no command.
    let mut exchange =
        VkExchange::orchard_fvk(Network::Test, AccountId::ZERO).expect("the request encodes");
    let _ = exchange.next_apdu().expect("the request");
    assert_eq!(
        exchange.process_response(&refused),
        Ok(VkStep::RetrySameApdu)
    );
    let mut reply = vec![0u8; ORCHARD_FVK_LEN];
    reply.extend_from_slice(&StatusWord::Ok.to_u16().to_be_bytes());
    assert_eq!(
        exchange.process_response(&reply),
        Err(PairingError::OutOfOrder)
    );
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

proptest! {
    /// `Display` and `parse` are inverses for every identity, and the three
    /// strictnesses hold: prefix, length and lowercase.
    #[test]
    fn device_identity_display_parses_back(pubkey in prop::collection::vec(any::<u8>(), 33)) {
        let pubkey: [u8; 33] = pubkey.try_into().unwrap();
        let id = DeviceIdentity::from_compressed_pubkey(&pubkey);
        let s = id.to_string();
        prop_assert_eq!(s.len(), DEVICE_IDENTITY_PREFIX.len() + 64);
        prop_assert_eq!(DeviceIdentity::parse(&s).ok(), Some(id));

        let hex = &s[DEVICE_IDENTITY_PREFIX.len()..];
        prop_assert!(matches!(DeviceIdentity::parse(hex), Err(InvalidDeviceIdentity::MissingPrefix)));
        prop_assert_eq!(
            DeviceIdentity::parse(&s[..s.len() - 1]),
            Err(InvalidDeviceIdentity::BadLength { got: 63 })
        );
        prop_assert_eq!(
            DeviceIdentity::parse(&format!("{s}0")),
            Err(InvalidDeviceIdentity::BadLength { got: 65 })
        );
        if hex.bytes().any(|b| b.is_ascii_alphabetic()) {
            let upper = format!("{DEVICE_IDENTITY_PREFIX}{}", hex.to_uppercase());
            prop_assert!(matches!(DeviceIdentity::parse(&upper), Err(InvalidDeviceIdentity::NotLowercaseHex)));
        }
    }

    #[test]
    fn device_identity_parse_never_panics(s in "\\PC{0,80}") {
        let _ = DeviceIdentity::parse(&s);
    }
}
