use proptest::prelude::*;

use crate::apply::{normalize_ledger_der, ApplyError, DER_LONG_FORM_LENGTH_BIT};
use crate::test_support::{arb_bytes, arb_secret_key};

/// A 131-byte blob whose length byte is the long form (`0x81 0x80`): the
/// sighash checks read the short-form length, so it is refused by name
/// before they would be skipped, rather than parsed by `from_der` — which
/// accepts it — into a signature with no sighash byte at all.
#[test]
fn a_long_form_der_length_is_refused_by_name() {
    let mut blob = vec![0x30, 0x81, 0x80];
    for _ in 0..2 {
        blob.extend_from_slice(&[0x02, 0x3E]);
        blob.extend_from_slice(&[0x01; 0x3E]);
    }
    assert_eq!(blob.len(), 131);
    assert_eq!(
        normalize_ledger_der(&blob),
        Err(ApplyError::DerLengthLongForm { got: 0x81 })
    );
}

/// An INTEGER longer than a scalar parses, in `secp256k1`, to zero: two
/// 35-byte integers in a short-form SEQUENCE plus the sighash byte pass the
/// sighash checks and would come back as the all-zero signature. The round
/// trip refuses it.
#[test]
fn an_oversized_integer_is_not_folded_to_a_zero_signature() {
    let mut blob = vec![0x30, 0x4A];
    for _ in 0..2 {
        blob.extend_from_slice(&[0x02, 0x23]);
        blob.extend_from_slice(&[0x01; 0x23]);
    }
    blob.push(0x01);
    assert_eq!(
        normalize_ledger_der(&blob),
        Err(ApplyError::DerNotCanonical)
    );
}

/// `02 01 00` is canonical DER for zero, so the all-zero signature passes the
/// round trip and `from_der` alike; it is refused by name rather than left to
/// the verifier inside `finish()`. Nine bytes is also the shortest reply
/// `parse_transparent_signature` accepts, so the session path meets it too.
#[test]
fn a_zero_signature_is_refused_by_name() {
    let zero = [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01];
    assert_eq!(
        normalize_ledger_der(&zero),
        Err(ApplyError::ZeroScalar { scalar: "r" })
    );
}

/// A zero `s` beside a nonzero `r` is refused the same way, and named.
#[test]
fn a_zero_s_is_refused_by_name() {
    let blob = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x01];
    assert_eq!(
        normalize_ledger_der(&blob),
        Err(ApplyError::ZeroScalar { scalar: "s" })
    );
}

/// The transparent arm of `apply_device_signatures` names the input a refused
/// reply was filed under: `normalize_ledger_der` sees one reply at a time and
/// cannot, while every other refusal in that function does. The cause is kept
/// whole, as the error's `source`.
#[test]
fn a_refused_transparent_reply_names_its_input() {
    let cause = ApplyError::MissingSighashType {
        expected: 9,
        got: 8,
    };
    let err = ApplyError::TransparentSignature {
        index: 3,
        source: alloc::boxed::Box::new(cause.clone()),
    };

    let shown = err.to_string();
    assert!(shown.contains("transparent input 3"), "{shown}");
    assert!(shown.contains(&cause.to_string()), "{shown}");
    assert_eq!(
        core::error::Error::source(&err).map(alloc::string::ToString::to_string),
        Some(cause.to_string())
    );
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

prop_compose! {
    /// A signature the way the device produces one: deterministic ECDSA over
    /// a digest, low-S.
    fn arb_signature()(sk in arb_secret_key(), digest in any::<[u8; 32]>()) -> secp256k1::ecdsa::Signature {
        secp256k1::ecdsa::sign(secp256k1::Message::from_digest(digest), &sk)
    }
}

/// `N - s` for a secp256k1 scalar `0 < s < N`: the other signature with the
/// same `r`, which is what a signer that does not normalize may emit.
fn negate_scalar(s: &[u8; 32]) -> [u8; 32] {
    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = i16::from(N[i]) - i16::from(s[i]) - borrow;
        if d < 0 {
            out[i] = (d + 256) as u8;
            borrow = 1;
        } else {
            out[i] = d as u8;
            borrow = 0;
        }
    }
    out
}

/// The DER encoding of `sig` with its `s` replaced by `N - s`.
fn high_s_der(sig: &secp256k1::ecdsa::Signature) -> Vec<u8> {
    let mut compact = sig.serialize_compact();
    let s: [u8; 32] = compact[32..].try_into().expect("32 bytes");
    compact[32..].copy_from_slice(&negate_scalar(&s));
    secp256k1::ecdsa::Signature::from_compact(&compact)
        .expect("a high-S signature parses; only verification refuses it")
        .serialize_der()
        .to_vec()
}

proptest! {
    /// Every form the device may hand back — DER with the sighash byte, with
    /// or without the `0x31` parity tag, and with a high-S `s` — normalizes
    /// to the one low-S signature. The same forms without the sighash byte are
    /// refused: the device always appends it. Any other trailing sighash type
    /// is refused by value.
    #[test]
    fn ledger_der_forms_normalize_to_one_signature(sig in arb_signature(), sighash in any::<u8>()) {
        let der = sig.serialize_der().to_vec();
        let mut with_sighash = der.clone();
        with_sighash.push(0x01);
        let mut tagged = der.clone();
        tagged[0] = 0x31;
        let mut tagged_with_sighash = tagged.clone();
        tagged_with_sighash.push(0x01);
        let high_s = high_s_der(&sig);
        prop_assert_ne!(&high_s, &der);
        let mut high_s_with_sighash = high_s.clone();
        high_s_with_sighash.push(0x01);

        for (name, form) in [
            ("der+sighash", &with_sighash),
            ("0x31+sighash", &tagged_with_sighash),
            ("high-S+sighash", &high_s_with_sighash),
        ] {
            let got = normalize_ledger_der(form);
            prop_assert!(got.is_ok(), "{name}: {:?}", got.err());
            prop_assert_eq!(got.unwrap(), sig, "{}", name);
        }

        for (name, form) in [("der", &der), ("0x31", &tagged), ("high-S", &high_s)] {
            let res = normalize_ledger_der(form);
            prop_assert_eq!(
                res,
                Err(ApplyError::MissingSighashType { expected: form.len() + 1, got: form.len() }),
                "{}",
                name
            );
        }

        if sighash != 0x01 {
            let mut other = der.clone();
            other.push(sighash);
            let res = normalize_ledger_der(&other);
            prop_assert!(
                matches!(res, Err(ApplyError::UnexpectedSighashType { got }) if got == sighash),
                "{:?}",
                res
            );
        }
    }

    /// Long enough for a short-form length byte to declare its whole range:
    /// two header bytes, the 127 bytes such a byte can count, and the
    /// trailing sighash byte.
    #[test]
    fn normalize_ledger_der_never_panics(bytes in arb_bytes(140)) {
        let res = normalize_ledger_der(&bytes);
        if bytes.len() < 2 {
            prop_assert!(
                matches!(res, Err(ApplyError::DerTooShort { got }) if got == bytes.len()),
                "{:?}",
                res
            );
        } else if bytes[1] & DER_LONG_FORM_LENGTH_BIT != 0 {
            prop_assert_eq!(res, Err(ApplyError::DerLengthLongForm { got: bytes[1] }));
        } else if let Ok(sig) = res {
            // Whatever is accepted has a nonzero `r` and `s`.
            let compact = sig.serialize_compact();
            prop_assert!(compact[..32].iter().any(|&b| b != 0));
            prop_assert!(compact[32..].iter().any(|&b| b != 0));
        }
    }
}
