use std::collections::BTreeSet;

use proptest::prelude::*;

use crate::apdu::decode::*;
use crate::apdu::encode::*;
use crate::apdu::*;
use crate::test_support::{
    arb_bytes, arb_secret_key, wallet_public_key_reply, GENERATOR_UNCOMPRESSED, SAMPLE_ADDRESS,
    VERSION_REPLY,
};

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

#[test]
fn status_word_is_the_last_two_bytes() {
    let (data, sw) = split_status_word(&[0xAA, 0xBB, 0x90, 0x00]).unwrap();
    assert_eq!(data, &[0xAA, 0xBB]);
    assert_eq!(sw, StatusWord::Ok);

    let (data, sw) = split_status_word(&[0x69, 0x85]).unwrap();
    assert!(data.is_empty());
    assert_eq!(sw, StatusWord::Deny);

    assert_eq!(
        split_status_word(&[0x00]),
        Err(DecodeError::TooShortForStatusWord { got: 1 })
    );
}

#[test]
fn expect_ok_surfaces_the_failure_status() {
    assert_eq!(
        expect_ok(&[0xB0, 0x07]),
        Err(DecodeError::Status(StatusWord::BadState))
    );
    assert_eq!(expect_ok(&[0x01, 0x90, 0x00]).unwrap(), &[0x01]);
}

#[test]
fn firmware_version_parse() {
    // 0x38, 0x30, then app 3.9.2, SDK 1.0, API level 3.
    let data = [0x38, 0x30, 3, 9, 2, 1, 0, 3];
    let v = parse_firmware_version(&data).unwrap();
    assert_eq!((v.major, v.minor, v.patch), (3, 9, 2));
    assert_eq!(v.api_level, 3);
    assert_eq!(v.to_string(), "3.9.2");
    // The shared reply vector, less its status word.
    assert_eq!(
        parse_firmware_version(&VERSION_REPLY[..8])
            .unwrap()
            .to_string(),
        "3.9.3"
    );

    let mut bad = data;
    bad[0] = 0x39;
    assert!(matches!(
        parse_firmware_version(&bad),
        Err(DecodeError::BadVersionPrefix { .. })
    ));

    assert!(matches!(
        parse_firmware_version(&data[..7]),
        Err(DecodeError::UnexpectedLength { .. })
    ));
    let mut long = data.to_vec();
    long.push(0x00);
    assert!(matches!(
        parse_firmware_version(&long),
        Err(DecodeError::UnexpectedLength { .. })
    ));
}

/// The DER `SEQUENCE` tag with the `y`-parity bit `append_signature` ORs into
/// it when the `y` coordinate is odd.
const LEDGER_DER_PARITY_TAG: u8 = 0x31;

/// A reply the device wrote: `30 44 02 20 <r> 02 20 <s>`, the shape a 32-byte
/// `r` and `s` take when neither needs the leading zero a high bit forces,
/// then the sighash byte.
fn device_transparent_reply() -> Vec<u8> {
    let mut data = vec![0x30, 0x44, 0x02, 0x20];
    data.extend_from_slice(&[0xAA; 32]);
    data.extend_from_slice(&[0x02, 0x20]);
    data.extend_from_slice(&[0xBB; 32]);
    data.push(SIGHASH_ALL);
    data
}

#[test]
fn transparent_signature_splits_off_the_trailing_sighash_byte() {
    let data = device_transparent_reply();
    let sig = parse_transparent_signature(&data).expect("a reply the device would write");
    assert_eq!(sig.der.as_slice(), &data[..data.len() - 1]);
    assert_eq!(sig.sighash_type, SIGHASH_ALL);

    // The odd-y tag `append_signature` ORs in is kept as it stands; undoing it
    // is `normalize_ledger_der`'s job, not this parser's.
    let mut odd_y = data.clone();
    odd_y[0] = LEDGER_DER_PARITY_TAG;
    assert_eq!(
        parse_transparent_signature(&odd_y)
            .expect("the odd-y form")
            .der[0],
        LEDGER_DER_PARITY_TAG
    );
}

/// The shape checks run at the reply, not at `finish`: every other reply arm
/// is exact about its shape, and a reply absorbed here is one the session
/// counts towards completion.
#[test]
fn a_transparent_signature_of_the_wrong_shape_is_refused_at_the_reply() {
    let data = device_transparent_reply();

    // Shorter than the shortest DER signature plus its sighash byte.
    assert!(matches!(
        parse_transparent_signature(&[0x30, 0x06]),
        Err(DecodeError::Truncated { .. })
    ));

    // Longer than the longest signature the device's SDK emits: two 32-byte
    // scalars, each with the leading zero a high bit forces, plus framing and
    // the sighash byte.
    let longest = 2 + 2 * (2 + 33) + 1;
    let too_long = vec![0x30; longest + 1];
    assert!(matches!(
        parse_transparent_signature(&too_long),
        Err(DecodeError::UnexpectedLength { expected, got, .. })
            if expected == longest && got == too_long.len()
    ));

    // A tag that is neither DER's SEQUENCE nor the device's odd-y form.
    let mut wrong_tag = data.clone();
    wrong_tag[0] = 0x32;
    assert!(matches!(
        parse_transparent_signature(&wrong_tag),
        Err(DecodeError::InvalidTransparentSignature { .. })
    ));

    // A length the reply does not match: one DER byte dropped, so the header
    // declares one more content byte than is there. This is the shape the
    // old floor let through, to be refused only by `normalize_ledger_der`.
    let mut short = data.clone();
    short.remove(short.len() - 2);
    assert!(matches!(
        parse_transparent_signature(&short),
        Err(DecodeError::UnexpectedLength { expected, got, .. })
            if expected == data.len() && got == short.len()
    ));

    // A trailing byte that is not SIGHASH_ALL: `parse_transparent_input_sighash_type`
    // refuses anything else on the way in, so the device echoes nothing else.
    let mut wrong_sighash = data.clone();
    *wrong_sighash.last_mut().expect("non-empty") = SIGHASH_ALL + 1;
    assert!(matches!(
        parse_transparent_signature(&wrong_sighash),
        Err(DecodeError::InvalidTransparentSignature { .. })
    ));
}

/// The case the shape checks exist for: a transport one reply behind hands
/// the previous command's 64-byte shielded signature to
/// `PCZT_SIGN_TRANSPARENT`. It clears the length floor, so it used to be
/// absorbed, leaving the session to report itself complete and fail only in
/// `finish`, after the user had approved.
#[test]
fn a_shielded_signature_is_not_absorbed_as_a_transparent_one() {
    assert!(matches!(
        parse_transparent_signature(&[0x5A; SPEND_AUTH_SIG_LEN]),
        Err(DecodeError::InvalidTransparentSignature { .. })
    ));
}

// ---------------------------------------------------------------------------
// GET_WALLET_PUBLIC_KEY replies
// ---------------------------------------------------------------------------

/// The key and chain code come through; the address is checked and dropped,
/// and nothing the reply carried appears in the parsed value's `Debug` form.
#[test]
fn a_wallet_public_key_reply_keeps_the_key_and_drops_the_address() {
    let data = wallet_public_key_reply(
        &GENERATOR_UNCOMPRESSED,
        SAMPLE_ADDRESS.as_bytes(),
        &[0x3C; CHAIN_CODE_LEN],
    );
    let parsed = parse_wallet_public_key(&data).expect("a well-formed reply");

    assert_eq!(parsed.public_key(), &GENERATOR_UNCOMPRESSED);
    assert_eq!(parsed.chain_code(), &[0x3C; CHAIN_CODE_LEN]);

    let shown = format!("{parsed:?}");
    assert!(!shown.contains(SAMPLE_ADDRESS));
    assert!(
        !shown.contains("121"),
        "0x79, the key's first coordinate byte"
    );
    assert!(!shown.contains("60"), "0x3C, the chain code");
    assert!(shown.contains("[redacted]"));
}

/// `compressed()` is `secp256k1`'s own compression, not a re-implementation of
/// it: the same key through both routes is the same 33 bytes.
#[test]
fn the_compressed_key_is_what_secp256k1_produces() {
    let data = wallet_public_key_reply(
        &GENERATOR_UNCOMPRESSED,
        SAMPLE_ADDRESS.as_bytes(),
        &[0; CHAIN_CODE_LEN],
    );
    let parsed = parse_wallet_public_key(&data).expect("a well-formed reply");

    let expected = secp256k1::PublicKey::from_slice(&GENERATOR_UNCOMPRESSED)
        .expect("the generator is on the curve")
        .serialize();
    assert_eq!(parsed.compressed().expect("a checked key"), expected);
    assert_eq!(expected.len(), COMPRESSED_PUBKEY_SIZE);
}

/// A device announcing a 33-byte key is refused rather than re-cut: every
/// field boundary after it would move, and the app returns 65.
#[test]
fn a_compressed_public_key_in_the_reply_is_refused() {
    let compressed = secp256k1::PublicKey::from_slice(&GENERATOR_UNCOMPRESSED)
        .expect("on the curve")
        .serialize();
    let data =
        wallet_public_key_reply(&compressed, SAMPLE_ADDRESS.as_bytes(), &[0; CHAIN_CODE_LEN]);
    assert!(matches!(
        parse_wallet_public_key(&data),
        Err(DecodeError::UnexpectedLength {
            what: "wallet public key",
            expected: 65,
            got: 33
        })
    ));
}

/// One byte short and one byte long are both failures: the reply's own lengths
/// have to account for every byte it carries.
#[test]
fn a_truncated_or_padded_wallet_public_key_reply_is_refused() {
    let data = wallet_public_key_reply(
        &GENERATOR_UNCOMPRESSED,
        SAMPLE_ADDRESS.as_bytes(),
        &[0; CHAIN_CODE_LEN],
    );

    let short = &data[..data.len() - 1];
    assert!(
        matches!(
            parse_wallet_public_key(short),
            Err(DecodeError::UnexpectedLength { .. })
        ),
        "a missing chain-code byte must be refused"
    );

    let mut long = data.clone();
    long.push(0x00);
    assert!(
        matches!(
            parse_wallet_public_key(&long),
            Err(DecodeError::UnexpectedLength { .. })
        ),
        "a trailing byte must be refused"
    );

    // Shorter than the fixed fields can fit at all.
    assert!(matches!(
        parse_wallet_public_key(&data[..40]),
        Err(DecodeError::Truncated {
            what: "wallet public key",
            ..
        })
    ));
}

#[test]
fn a_non_ascii_address_is_refused() {
    let data = wallet_public_key_reply(
        &GENERATOR_UNCOMPRESSED,
        &[0xE2, 0x82, 0xAC, 0xFF],
        &[0; CHAIN_CODE_LEN],
    );
    assert_eq!(parse_wallet_public_key(&data), Err(DecodeError::NotUtf8));
}

/// Sixty-five bytes that are not a point on the curve are not a public key,
/// and the identity that would be hashed out of them would be meaningless.
#[test]
fn a_key_that_is_not_on_the_curve_is_refused() {
    let mut off_curve = GENERATOR_UNCOMPRESSED;
    off_curve[64] ^= 0x01;
    let data = wallet_public_key_reply(&off_curve, SAMPLE_ADDRESS.as_bytes(), &[0; CHAIN_CODE_LEN]);
    assert!(matches!(
        parse_wallet_public_key(&data),
        Err(DecodeError::InvalidPublicKey { .. })
    ));
}

#[test]
fn shielded_signature_must_be_exactly_64_bytes() {
    let sig = parse_shielded_signature(&[0x5A; 64]).unwrap();
    assert_eq!(sig, [0x5A; 64]);
    assert!(matches!(
        parse_shielded_signature(&[0x5A; 63]),
        Err(DecodeError::UnexpectedLength {
            expected: 64,
            got: 63,
            ..
        })
    ));
    assert!(matches!(
        parse_shielded_signature(&[0x5A; 65]),
        Err(DecodeError::UnexpectedLength {
            expected: 64,
            got: 65,
            ..
        })
    ));
}

#[test]
fn chunked_ufvk_reassembles_across_replies() {
    // A 300-byte UFVK string forces two replies: the device caps each at 255
    // bytes (`VK_RESPONSE_CHUNK_LEN`), and the total transfer is 2 + 300.
    let ufvk: String = "u".repeat(300);
    let mut wire = (ufvk.len() as u16).to_be_bytes().to_vec();
    wire.extend_from_slice(ufvk.as_bytes());
    assert_eq!(wire.len(), 302);

    let mut r = VkReassembler::new(VkKind::Ufvk);
    assert_eq!(r.total_len(), None);
    assert_eq!(r.push(&wire[..255]).unwrap(), None);
    assert_eq!(r.total_len(), Some(302));
    let done = r.push(&wire[255..]).unwrap();
    assert_eq!(done, Some(VkResponse::Ufvk(ufvk)));
}

#[test]
fn orchard_fvk_reassembly_knows_its_length_up_front() {
    let mut r = VkReassembler::new(VkKind::OrchardFvk);
    assert_eq!(r.total_len(), Some(ORCHARD_FVK_LEN));
    assert!(r.is_empty());
    assert_eq!(r.push(&[0x01; 50]).unwrap(), None);
    assert_eq!(r.len(), 50);
    let done = r.push(&[0x02; 46]).unwrap();
    match done {
        Some(VkResponse::OrchardFvk(bytes)) => assert_eq!(bytes.len(), 96),
        other => panic!("expected a completed FVK, got {other:?}"),
    }
}

#[test]
fn vk_reassembly_rejects_an_overrun() {
    let mut r = VkReassembler::new(VkKind::OrchardFvk);
    assert!(matches!(
        r.push(&[0x00; 97]),
        Err(DecodeError::Overrun {
            expected: 96,
            got: 97
        })
    ));
}

#[test]
fn string_response_length_prefix_is_big_endian() {
    let mut wire = 3u16.to_be_bytes().to_vec();
    wire.extend_from_slice(b"u1a");
    assert_eq!(parse_string_response(&wire).unwrap(), "u1a");
    assert!(matches!(
        parse_string_response(&[0x00, 0x05, 0x61]),
        Err(DecodeError::UnexpectedLength { .. })
    ));
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

prop_compose! {
    /// A well-formed `GET_WALLET_PUBLIC_KEY` reply with the key and chain
    /// code it carries.
    fn arb_wallet_public_key_reply()(
        sk in arb_secret_key(),
        addr in prop::collection::vec(0x21u8..0x7f, 0..=60),
        chain_code in any::<[u8; CHAIN_CODE_LEN]>(),
    ) -> (Vec<u8>, [u8; WALLET_PUBLIC_KEY_LEN], [u8; CHAIN_CODE_LEN]) {
        let pk = secp256k1::PublicKey::from_secret_key(&sk).serialize_uncompressed();
        let mut reply = vec![WALLET_PUBLIC_KEY_LEN as u8];
        reply.extend_from_slice(&pk);
        reply.push(addr.len() as u8);
        reply.extend_from_slice(&addr);
        reply.extend_from_slice(&chain_code);
        (reply, pk, chain_code)
    }
}

/// Cuts `bytes` into consecutive non-empty chunks at the given positions,
/// each of which must lie strictly inside `bytes`.
fn chunks_at(bytes: &[u8], cuts: &BTreeSet<usize>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut start = 0;
    for &cut in cuts {
        out.push(bytes[start..cut].to_vec());
        start = cut;
    }
    out.push(bytes[start..].to_vec());
    out
}

/// A `GET_VK` Orchard FVK reply cut into up to seven chunks.
fn arb_orchard_fvk_chunks() -> impl Strategy<Value = (Vec<u8>, Vec<Vec<u8>>)> {
    (
        prop::collection::vec(any::<u8>(), ORCHARD_FVK_LEN),
        prop::collection::btree_set(1..ORCHARD_FVK_LEN, 0..=6),
    )
        .prop_map(|(key, cuts)| {
            let chunks = chunks_at(&key, &cuts);
            (key, chunks)
        })
}

/// A `GET_VK` UFVK reply — length prefix plus arbitrary body bytes, which are
/// UTF-8 or not — cut into up to seven chunks, the first of which carries the
/// whole two-byte prefix.
fn arb_ufvk_chunks() -> impl Strategy<Value = (Vec<u8>, Vec<Vec<u8>>)> {
    arb_bytes(600).prop_flat_map(|body| {
        let mut full = (body.len() as u16).to_be_bytes().to_vec();
        full.extend_from_slice(&body);
        let total = full.len();
        let cuts = if total > 2 {
            prop::collection::btree_set(2..total, 0..=6).boxed()
        } else {
            Just(BTreeSet::new()).boxed()
        };
        cuts.prop_map(move |cuts| (body.clone(), chunks_at(&full, &cuts)))
    })
}

/// Replies around the shape the device writes: a tag that is often one of the
/// two `append_signature` emits, a declared length that is often the body's,
/// and a trailing byte that is often `SIGHASH_ALL`. Every near-miss of a shape
/// check is one field away from a reply the parser accepts, so the accepting
/// branch of the spec is exercised too.
fn arb_transparent_reply() -> impl Strategy<Value = Vec<u8>> {
    (
        prop_oneof![Just(0x30u8), Just(LEDGER_DER_PARITY_TAG), any::<u8>()],
        prop::collection::vec(any::<u8>(), 6..=70),
        prop_oneof![Just(SIGHASH_ALL), any::<u8>()],
        prop_oneof![Just(0usize), Just(1), Just(2)],
    )
        .prop_map(|(tag, body, sighash, shortfall)| {
            let declared = u8::try_from(body.len() - shortfall).expect("at most 70");
            let mut reply = vec![tag, declared];
            reply.extend_from_slice(&body);
            reply.push(sighash);
            reply
        })
}

proptest! {
    /// The status word is the last two bytes and nothing else is touched.
    #[test]
    fn split_status_word_spec(resp in arb_bytes(300)) {
        match split_status_word(&resp) {
            Ok((data, sw)) => {
                prop_assert!(resp.len() >= 2);
                let split = resp.len() - 2;
                prop_assert_eq!(data, &resp[..split]);
                prop_assert_eq!(sw.to_u16(), u16::from_be_bytes([resp[split], resp[split + 1]]));
                prop_assert_eq!(expect_ok(&resp).is_ok(), sw.is_ok());
            }
            Err(e) => {
                prop_assert!(resp.len() < 2);
                prop_assert!(
                    matches!(e, DecodeError::TooShortForStatusWord { got } if got == resp.len()),
                    "{e:?}"
                );
            }
        }
    }

    /// Eight bytes with the legacy prefix, or nothing.
    #[test]
    fn firmware_version_spec(
        data in prop_oneof![arb_bytes(12), prop::collection::vec(any::<u8>(), FIRMWARE_VERSION_LEN)],
        stamp in any::<bool>(),
    ) {
        let mut data = data;
        if stamp && data.len() >= 2 {
            data[0] = LEGACY_VERSION_PREFIX;
            data[1] = ARCH_ID;
        }
        let parsed = parse_firmware_version(&data);
        if data.len() == FIRMWARE_VERSION_LEN && data[0] == LEGACY_VERSION_PREFIX && data[1] == ARCH_ID {
            prop_assert!(parsed.is_ok(), "{:?}", parsed);
            let v = parsed.unwrap();
            prop_assert_eq!(
                [v.major, v.minor, v.patch, v.sdk_major, v.sdk_minor, v.api_level],
                [data[2], data[3], data[4], data[5], data[6], data[7]]
            );
            prop_assert_eq!(v.to_string(), format!("{}.{}.{}", data[2], data[3], data[4]));
        } else {
            prop_assert!(parsed.is_err());
        }
    }

    /// Accepted exactly when the reply has the shape `append_signature`
    /// writes: inside the two length bounds, a `SEQUENCE` tag in one of the
    /// two forms the device emits, a declared length the reply matches, and a
    /// trailing `SIGHASH_ALL`. When accepted, everything but that last byte
    /// is the DER blob, kept as it arrived.
    #[test]
    fn transparent_signature_spec(data in prop_oneof![arb_bytes(80), arb_transparent_reply()]) {
        /// The shortest DER signature plus the sighash byte.
        const MIN: usize = 9;
        /// The longest the device's SDK emits plus the sighash byte.
        const MAX: usize = 2 + 2 * (2 + 33) + 1;
        /// Tag, length byte and the sighash byte.
        const FRAMING: usize = 3;

        let well_formed = data.len() >= MIN
            && data.len() <= MAX
            && matches!(data[0], 0x30 | LEDGER_DER_PARITY_TAG)
            && data.len() == usize::from(data[1]) + FRAMING
            && data[data.len() - 1] == SIGHASH_ALL;

        match parse_transparent_signature(&data) {
            Ok(sig) => {
                prop_assert!(well_formed);
                prop_assert_eq!(sig.der.as_slice(), &data[..data.len() - 1]);
                prop_assert_eq!(sig.sighash_type, SIGHASH_ALL);
            }
            Err(e) => prop_assert!(!well_formed, "{e:?}"),
        }
    }

    /// Exactly 64 bytes, copied through.
    #[test]
    fn shielded_signature_spec(data in prop_oneof![arb_bytes(80), prop::collection::vec(any::<u8>(), SPEND_AUTH_SIG_LEN)]) {
        match parse_shielded_signature(&data) {
            Ok(sig) => prop_assert_eq!(sig.as_slice(), data.as_slice()),
            Err(e) => {
                prop_assert_ne!(data.len(), SPEND_AUTH_SIG_LEN);
                prop_assert!(
                    matches!(e, DecodeError::UnexpectedLength { expected: SPEND_AUTH_SIG_LEN, got, .. } if got == data.len()),
                    "{e:?}"
                );
            }
        }
    }

    /// A string reply is accepted exactly when its declared length is its
    /// body's length and the body is UTF-8.
    #[test]
    fn string_response_spec(body in arb_bytes(600), declared_delta in -2i32..=2) {
        let mut data = (body.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&body);
        match std::str::from_utf8(&body) {
            Ok(s) => {
                let parsed = parse_string_response(&data).ok();
                prop_assert_eq!(parsed.as_deref(), Some(s));
            }
            Err(_) => prop_assert!(matches!(parse_string_response(&data), Err(DecodeError::NotUtf8))),
        }

        let declared = body.len() as i32 + declared_delta;
        if declared_delta != 0 && (0..=0xFFFF).contains(&declared) {
            let mut wrong = (declared as u16).to_be_bytes().to_vec();
            wrong.extend_from_slice(&body);
            prop_assert!(
                matches!(parse_string_response(&wrong), Err(DecodeError::UnexpectedLength { .. })),
                "declared {declared} for a {}-byte body", body.len()
            );
        }
    }

    #[test]
    fn string_response_never_panics(data in arb_bytes(300)) {
        let _ = parse_string_response(&data);
    }

    /// A well-formed `GET_WALLET_PUBLIC_KEY` reply parses to its key and chain
    /// code; every proper prefix, one byte more, a key length other than 65
    /// and a non-ASCII address byte are each refused.
    #[test]
    fn wallet_public_key_reply_spec(
        (reply, pk, chain_code) in arb_wallet_public_key_reply(),
        pick in any::<prop::sample::Index>(),
        other_len in any::<u8>(),
    ) {
        let parsed = parse_wallet_public_key(&reply);
        prop_assert!(parsed.is_ok(), "{:?}", parsed.err());
        let parsed = parsed.unwrap();
        prop_assert_eq!(parsed.public_key(), &pk);
        prop_assert_eq!(parsed.chain_code(), &chain_code);

        for cut in 0..reply.len() {
            prop_assert!(parse_wallet_public_key(&reply[..cut]).is_err(), "a {cut}-byte prefix was accepted");
        }

        let mut longer = reply.clone();
        longer.push(0);
        let res = parse_wallet_public_key(&longer);
        prop_assert!(
            matches!(
                res,
                Err(DecodeError::UnexpectedLength { what: "wallet public key address and chain code", .. })
            ),
            "{:?}",
            res
        );

        if usize::from(other_len) != WALLET_PUBLIC_KEY_LEN {
            let mut wrong_key_len = reply.clone();
            wrong_key_len[0] = other_len;
            let res = parse_wallet_public_key(&wrong_key_len);
            prop_assert!(
                matches!(
                    res,
                    Err(DecodeError::UnexpectedLength { what: "wallet public key", expected: WALLET_PUBLIC_KEY_LEN, got }) if got == usize::from(other_len)
                ),
                "{:?}",
                res
            );
        }

        let addr_len = usize::from(reply[1 + WALLET_PUBLIC_KEY_LEN]);
        if addr_len > 0 {
            let mut non_ascii = reply.clone();
            non_ascii[2 + WALLET_PUBLIC_KEY_LEN + pick.index(addr_len)] |= 0x80;
            prop_assert!(matches!(parse_wallet_public_key(&non_ascii), Err(DecodeError::NotUtf8)));
        }
    }

    #[test]
    fn wallet_public_key_never_panics(data in arb_bytes(200)) {
        let _ = parse_wallet_public_key(&data);
    }
}

proptest! {
    /// However a 96-byte Orchard FVK is cut, reassembly completes on the last
    /// chunk when there are at most `MAX_VK_CONTINUATIONS + 1` of them and
    /// refuses at the budget otherwise; an empty chunk is refused, and the
    /// refusal ends the reassembly.
    #[test]
    fn orchard_fvk_reassembly_spec((key, chunks) in arb_orchard_fvk_chunks()) {
        let budget = MAX_VK_CONTINUATIONS + 1;

        let mut refused = VkReassembler::new(VkKind::OrchardFvk);
        let empty = refused.push(&[]);
        prop_assert!(
            matches!(empty, Err(DecodeError::VkNoProgress { got: 0, expected: ORCHARD_FVK_LEN })),
            "{:?}",
            empty
        );
        // The error ended the transfer: the whole key offered afterwards is
        // not absorbed, so the refusal cannot be pushed past.
        let after = refused.push(&key);
        prop_assert!(matches!(after, Err(DecodeError::VkAbandoned)), "{after:?}");

        let mut r = VkReassembler::new(VkKind::OrchardFvk);
        for (i, chunk) in chunks.iter().enumerate() {
            let last = i + 1 == chunks.len();
            let res = r.push(chunk);
            if last {
                prop_assert!(
                    matches!(&res, Ok(Some(VkResponse::OrchardFvk(got))) if got == &key),
                    "chunk {i} of {}: {res:?}", chunks.len()
                );
                prop_assert!(r.is_empty());
            } else if i + 1 < budget {
                prop_assert!(matches!(res, Ok(None)), "chunk {i}: {res:?}");
            } else {
                prop_assert!(
                    matches!(res, Err(DecodeError::VkTooManyChunks { got, expected: ORCHARD_FVK_LEN, max_continuations: MAX_VK_CONTINUATIONS }) if got < ORCHARD_FVK_LEN),
                    "chunk {i}: {res:?}"
                );
                break;
            }
        }
    }

    /// The same budget for a UFVK, whose total comes from its own first two
    /// bytes; the body is then UTF-8 or it is refused.
    #[test]
    fn ufvk_reassembly_spec((body, chunks) in arb_ufvk_chunks()) {
        let total = 2 + body.len();
        let budget = MAX_VK_CONTINUATIONS + 1;
        let mut r = VkReassembler::new(VkKind::Ufvk);
        prop_assert_eq!(r.total_len(), None);

        for (i, chunk) in chunks.iter().enumerate() {
            let last = i + 1 == chunks.len();
            let res = r.push(chunk);
            if last {
                match std::str::from_utf8(&body) {
                    Ok(s) => prop_assert!(
                        matches!(&res, Ok(Some(VkResponse::Ufvk(got))) if got == s),
                        "chunk {i}: {res:?}"
                    ),
                    Err(_) => prop_assert!(matches!(res, Err(DecodeError::NotUtf8)), "chunk {i}: {res:?}"),
                }
            } else if i + 1 < budget {
                prop_assert!(matches!(res, Ok(None)), "chunk {i}: {res:?}");
                prop_assert_eq!(r.total_len(), Some(total));
            } else {
                prop_assert!(
                    matches!(res, Err(DecodeError::VkTooManyChunks { got, expected, max_continuations: MAX_VK_CONTINUATIONS }) if got < total && expected == total),
                    "chunk {i}: {res:?}"
                );
                break;
            }
        }
    }

    /// Bytes past the announced total are an overrun, not a longer key.
    #[test]
    fn vk_reassembly_refuses_an_overrun((key, chunks) in arb_orchard_fvk_chunks(), extra in 1usize..=3) {
        prop_assume!(chunks.len() <= MAX_VK_CONTINUATIONS + 1);
        let mut chunks = chunks;
        chunks.last_mut().unwrap().extend(std::iter::repeat_n(0, extra));
        let mut r = VkReassembler::new(VkKind::OrchardFvk);
        let mut last = Ok(None);
        for chunk in &chunks {
            last = r.push(chunk);
        }
        prop_assert!(
            matches!(last, Err(DecodeError::Overrun { expected: ORCHARD_FVK_LEN, got }) if got == key.len() + extra),
            "{last:?}"
        );
    }

    /// An announced UFVK length the budget cannot serve is refused on the
    /// first chunk, before any body byte is kept; every smaller one is not.
    #[test]
    fn ufvk_announcement_beyond_the_budget_is_refused(len in any::<u16>()) {
        let announced = 2 + usize::from(len);
        let mut r = VkReassembler::new(VkKind::Ufvk);
        let res = r.push(&len.to_be_bytes());
        if announced > MAX_VK_RESPONSE_LEN {
            prop_assert!(
                matches!(res, Err(DecodeError::VkResponseTooLong { announced: got, max: MAX_VK_RESPONSE_LEN }) if got == announced),
                "{res:?}"
            );
        } else {
            prop_assert!(!matches!(res, Err(DecodeError::VkResponseTooLong { .. })), "{res:?}");
        }
    }

    #[test]
    fn vk_reassembler_never_panics(
        kind in prop_oneof![Just(VkKind::Ufvk), Just(VkKind::OrchardFvk)],
        chunks in prop::collection::vec(arb_bytes(300), 0..=8),
    ) {
        let mut r = VkReassembler::new(kind);
        for chunk in &chunks {
            let _ = r.push(chunk);
        }
    }

    /// Whatever a device sends, and however it is cut, the buffer never grows
    /// past what `VkReassembler::new` reserved. A `Vec` that grows copies its
    /// contents into a fresh allocation and frees the old one, which for this
    /// buffer means leaving viewing-key bytes in a block that nothing wipes —
    /// so the size bound is applied before a chunk is appended, not after.
    /// (It may shrink: a completed raw FVK is moved out to the caller.)
    #[test]
    fn a_vk_reassembly_never_grows_its_buffer(
        kind in prop_oneof![Just(VkKind::Ufvk), Just(VkKind::OrchardFvk)],
        chunks in prop::collection::vec(arb_bytes(MAX_VK_RESPONSE_LEN), 0..=8),
    ) {
        let mut r = VkReassembler::new(kind);
        let reserved = r.buf.capacity();
        for chunk in &chunks {
            let _ = r.push(chunk);
            prop_assert!(
                r.buf.capacity() <= reserved,
                "the buffer grew from {} to {}",
                reserved,
                r.buf.capacity()
            );
        }
    }
}

/// A chunk longer than what the announced total leaves is refused before it is
/// appended.
///
/// Nothing between the deframer and here bounds what one reply carries, so the
/// buffer would otherwise be grown past the size it was given at construction
/// and only then found to overrun.
#[test]
fn an_overlong_vk_chunk_is_refused_without_growing_the_buffer() {
    // A UFVK announcing a short total, with the prefix and one body byte in
    // the first chunk.
    const ANNOUNCED: u16 = 8;
    let mut first = ANNOUNCED.to_be_bytes().to_vec();
    first.push(b'u');

    let mut r = VkReassembler::new(VkKind::Ufvk);
    let reserved = r.buf.capacity();
    assert!(reserved >= MAX_VK_RESPONSE_LEN);
    assert_eq!(r.push(&first), Ok(None));

    // A continuation as long as the whole budget: well past what the
    // announcement leaves, and past the reserved capacity once appended.
    let overlong = vec![b'u'; MAX_VK_RESPONSE_LEN];
    assert_eq!(
        r.push(&overlong),
        Err(DecodeError::Overrun {
            expected: 2 + usize::from(ANNOUNCED),
            got: first.len() + MAX_VK_RESPONSE_LEN,
        }),
    );
    assert_eq!(r.buf.capacity(), reserved, "the buffer was reallocated");
    assert!(r.is_empty(), "the refusal wipes what was collected");
}

/// A reassembly ends on its first error and on the completed response: every
/// later chunk is refused rather than starting a second transfer in a buffer
/// that no longer holds the first one's beginning.
#[test]
fn a_vk_reassembly_ends_on_its_first_error_and_on_completion() {
    let fvk = vec![0x11u8; ORCHARD_FVK_LEN];

    // An error ends it.
    let mut r = VkReassembler::new(VkKind::OrchardFvk);
    assert_eq!(
        r.push(&[0x22; ORCHARD_FVK_LEN + 1]),
        Err(DecodeError::Overrun {
            expected: ORCHARD_FVK_LEN,
            got: ORCHARD_FVK_LEN + 1,
        }),
    );
    assert_eq!(r.push(&fvk), Err(DecodeError::VkAbandoned));

    // So does the completed response.
    let mut r = VkReassembler::new(VkKind::OrchardFvk);
    assert_eq!(r.push(&fvk), Ok(Some(VkResponse::OrchardFvk(fvk.clone()))),);
    assert_eq!(r.push(&fvk), Err(DecodeError::VkAbandoned));

    // And a UFVK's, whose buffer is wiped in place rather than moved out.
    let key = "u".repeat(8);
    let mut reply = u16::try_from(key.len())
        .expect("short")
        .to_be_bytes()
        .to_vec();
    reply.extend_from_slice(key.as_bytes());
    let mut r = VkReassembler::new(VkKind::Ufvk);
    assert_eq!(r.push(&reply), Ok(Some(VkResponse::Ufvk(key))));
    assert_eq!(r.push(&reply), Err(DecodeError::VkAbandoned));
}

/// A parsed transparent signature shows its length and sighash byte in
/// `Debug`, not the DER bytes: the blob appears verbatim in the `scriptSig`
/// once mined, so a logged one would name the transaction.
#[test]
fn a_transparent_signature_redacts_its_der_in_debug() {
    let mut data = vec![0x30, 0x06, 0x02, 0x01, 0x11, 0x02, 0x01, 0x22];
    data.push(0x01);
    let parsed = parse_transparent_signature(&data).expect("a well-formed reply");
    assert_eq!(parsed.der(), &data[..8]);
    assert_eq!(parsed.sighash_type(), 0x01);

    let shown = format!("{parsed:?}");
    assert_eq!(
        shown,
        "TransparentSignature { der: [8 bytes], sighash_type: 0x01 }"
    );
    assert!(!shown.contains("48"), "0x30, the SEQUENCE tag: {shown}");
    assert!(!shown.contains("17"), "0x11, r: {shown}");
}
