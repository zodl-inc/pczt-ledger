//! The return path: device signatures back onto the PCZT.
//!
//! Three things happen here, in this order:
//!
//! 1. **`hash160_preimage` stamping.** A P2PKH `script_pubkey` commits only to
//!    `HASH160(pubkey)`, so the host must supply the pubkey itself before a
//!    transparent signature can be attached. `Builder::build_for_pczt` leaves
//!    `hash160_preimages` empty and the device never returns it, so it is
//!    stamped here from the key of each input's `bip32_derivation` — which is
//!    also the signing-key locator the device used. This is signer metadata: it
//!    changes neither the txid nor the sighash.
//! 2. **Shielded signatures**, through
//!    [`Signer::apply_orchard_spend_auth_signature`], whose
//!    [`SpendAuthSignature`] is tagged with its value pool and action index. The
//!    `orchard` crate verifies each signature against that action's randomized
//!    verification key, so a mis-ordered or wrong signature fails closed.
//! 3. **Transparent signatures**, after [`normalize_ledger_der`] undoes the two
//!    device-specific quirks in the DER encoding.
//!
//! The result is PCZT bytes ready for the downstream Combiner. Proving, spend
//! finalization and extraction all happen downstream.

use pczt::{
    roles::{
        signer::{Signer, SpendAuthSignature},
        updater::Updater,
    },
    Pczt,
};

use crate::apdu::decode::SPEND_AUTH_SIG_LEN;
use crate::apdu::encode::SIGHASH_ALL;

/// Everything the device produced during one ceremony.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceSignatures {
    /// `(action index, RedPallas SpendAuthSig)` for the Orchard bundle.
    pub orchard: Vec<(usize, [u8; SPEND_AUTH_SIG_LEN])>,
    /// The same for the Ironwood bundle.
    pub ironwood: Vec<(usize, [u8; SPEND_AUTH_SIG_LEN])>,
    /// `(input index, raw device reply)` for each transparent input. The bytes
    /// are exactly what `PCZT_SIGN_TRANSPARENT` returned, quirks included;
    /// [`normalize_ledger_der`] handles them.
    pub transparent: Vec<(usize, Vec<u8>)>,
}

/// A device contribution that could not be applied.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApplyError {
    /// A transparent signature was shorter than the smallest possible DER
    /// header.
    DerTooShort {
        /// Length received.
        got: usize,
    },
    /// The trailing byte was a sighash type other than `SIGHASH_ALL`. The
    /// device only ever signs `SIGHASH_ALL`
    /// (`parse_transparent_input_sighash_type` refuses anything else on the way
    /// in), so anything else means the reply is not what it claims to be.
    UnexpectedSighashType {
        /// The byte received.
        got: u8,
    },
    /// `secp256k1` rejected the normalized DER blob.
    DerInvalid(String),
    /// A transparent input carries no `bip32_derivation`, so its controlling
    /// pubkey — and therefore its `hash160_preimage` — is unknown.
    ///
    /// Failing here names the offending input; letting it through would surface
    /// much later, and far less clearly, as a missing-preimage error inside
    /// `SpendFinalizer::finalize_spends`.
    MissingInputDerivation {
        /// Index of the input.
        index: usize,
    },
    /// The `pczt` Updater role rejected the `hash160_preimage` stamping.
    Updater(String),
    /// The `pczt` Signer role rejected a signature or could not be constructed.
    Signer(String),
    /// Serializing the signed PCZT failed.
    Encoding(String),
}

impl core::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ApplyError::DerTooShort { got } => write!(
                f,
                "a transparent signature of {got} byte(s) is shorter than the smallest possible \
                 DER header"
            ),
            ApplyError::UnexpectedSighashType { got } => write!(
                f,
                "a transparent signature's trailing byte declares sighash type {got:#04x}, but \
                 the device only ever signs SIGHASH_ALL (0x01); the reply is not what it claims \
                 to be"
            ),
            ApplyError::DerInvalid(message) => {
                write!(
                    f,
                    "secp256k1 rejected the normalized DER signature: {message}"
                )
            }
            ApplyError::MissingInputDerivation { index } => write!(
                f,
                "transparent input {index} carries no bip32_derivation, so its controlling \
                 pubkey — and therefore its hash160_preimage — is unknown"
            ),
            ApplyError::Updater(message) => write!(
                f,
                "the PCZT Updater role rejected the hash160_preimage stamping: {message}"
            ),
            ApplyError::Signer(message) => {
                write!(f, "the PCZT Signer role rejected a signature: {message}")
            }
            ApplyError::Encoding(message) => {
                write!(f, "serializing the signed PCZT failed: {message}")
            }
        }
    }
}

impl std::error::Error for ApplyError {}

/// Turns a `PCZT_SIGN_TRANSPARENT` reply into a `secp256k1` signature.
///
/// The device signs through `append_signature` in `src/handlers/sign_tx.rs`
/// (`LedgerHQ/app-zcash` @ `22dc385`), which applies two quirks to the DER blob
/// the Ledger SDK produces:
///
/// - it ORs the `y`-parity bit into the DER `SEQUENCE` header byte when the `y`
///   coordinate is odd (`if info != 0 { sig[0] |= 0x01; }`), turning `0x30` into
///   `0x31`; and
/// - it appends a trailing one-byte `sighash_type`.
///
/// So this function, in order:
///
/// 1. resets `0x31` to the canonical `0x30` (an even-`y` signature arrives
///    canonical already, making the reset a no-op);
/// 2. reads the ASN.1 short-form length and, if the buffer is exactly one byte
///    longer than the DER blob declares, checks that trailing byte is
///    [`SIGHASH_ALL`] and strips it. A long-form length byte (`>= 0x80`) is left
///    alone: the SDK's output is bounded at 72 bytes so it cannot occur, and
///    guessing would risk a silent truncation;
/// 3. parses with `Signature::from_der`; and
/// 4. normalizes `s` to the low half of the curve order. `secp256k1`'s verifier
///    — which `Signer::append_transparent_signature` runs before storing the
///    signature — rejects a high-`s` signature outright, and so do Zcash
///    consensus rules.
///
/// # Hardware validation status
///
/// Both quirks are read off the firmware *source*, not confirmed against bytes
/// a physical device returned; `ledger-zcash-utils` flags the same
/// normalizations the same way. They fail closed: a wrong assumption makes
/// `from_der` reject the buffer.
pub fn normalize_ledger_der(bytes: &[u8]) -> Result<secp256k1::ecdsa::Signature, ApplyError> {
    if bytes.len() < 2 {
        return Err(ApplyError::DerTooShort { got: bytes.len() });
    }

    let mut buf = bytes.to_vec();

    // 1. Reset the y-parity bit the device ORs into the SEQUENCE tag.
    if buf[0] == 0x31 {
        buf[0] = 0x30;
    }

    // 2. Strip the trailing sighash type, if the length says there is one.
    if buf[1] < 0x80 {
        let declared_total = 2 + buf[1] as usize; // tag + length byte + content
        if buf.len() == declared_total + 1 {
            let sighash_type = buf[declared_total];
            if sighash_type != SIGHASH_ALL {
                return Err(ApplyError::UnexpectedSighashType { got: sighash_type });
            }
            buf.truncate(declared_total);
        }
    }

    // 3 + 4.
    let mut sig = secp256k1::ecdsa::Signature::from_der(&buf)
        .map_err(|e| ApplyError::DerInvalid(format!("{e}")))?;
    sig.normalize_s();
    Ok(sig)
}

/// Stamps every transparent input's `hash160_preimage` with the pubkeys its
/// `bip32_derivation` names.
///
/// Stamping every candidate is safe: `set_hash160_preimage` keys each entry by
/// `HASH160(value)`, so the lookup in `append_signature` resolves to whichever
/// entry matches the input's `script_pubkey`.
pub fn stamp_hash160_preimages(pczt: Pczt) -> Result<Pczt, ApplyError> {
    if pczt.transparent().inputs().is_empty() {
        return Ok(pczt);
    }

    // The transparent Updater closure can only surface its own `UpdaterError`,
    // which has no variant for this precondition, so a violation is carried out
    // in a slot and converted once the borrow ends.
    let mut precondition: Option<ApplyError> = None;

    let updated = Updater::new(pczt)
        .update_transparent_with(|mut updater| {
            let pubkeys: Vec<Vec<[u8; 33]>> = updater
                .bundle()
                .inputs()
                .iter()
                .map(|input| input.bip32_derivation().keys().copied().collect())
                .collect();

            if let Some(index) = pubkeys.iter().position(Vec::is_empty) {
                precondition = Some(ApplyError::MissingInputDerivation { index });
                return Ok(());
            }

            for (index, keys) in pubkeys.into_iter().enumerate() {
                updater.update_input_with(index, |mut input| {
                    for pubkey in keys {
                        input.set_hash160_preimage(pubkey.to_vec());
                    }
                    Ok(())
                })?;
            }
            Ok(())
        })
        .map_err(|e| ApplyError::Updater(format!("hash160 preimage: {e:?}")))?;

    match precondition {
        Some(e) => Err(e),
        None => Ok(updated.finish()),
    }
}

/// Applies a whole ceremony's signatures and returns the updated PCZT.
///
/// Shielded signatures go through the pool-tagged
/// [`Signer::apply_orchard_spend_auth_signature`], so the Orchard and Ironwood
/// bundles are addressed by the same call with no chance of crossing them.
pub fn apply_device_signatures(
    pczt: Pczt,
    signatures: &DeviceSignatures,
) -> Result<Pczt, ApplyError> {
    let pczt = stamp_hash160_preimages(pczt)?;

    let mut signer = Signer::new(pczt).map_err(|e| ApplyError::Signer(format!("new: {e:?}")))?;

    for (index, sig) in &signatures.orchard {
        signer
            .apply_orchard_spend_auth_signature(&SpendAuthSignature::from_parts(
                orchard::ValuePool::Orchard,
                *index,
                *sig,
            ))
            .map_err(|e| ApplyError::Signer(format!("orchard action {index}: {e:?}")))?;
    }
    for (index, sig) in &signatures.ironwood {
        signer
            .apply_orchard_spend_auth_signature(&SpendAuthSignature::from_parts(
                orchard::ValuePool::Ironwood,
                *index,
                *sig,
            ))
            .map_err(|e| ApplyError::Signer(format!("ironwood action {index}: {e:?}")))?;
    }
    for (index, der) in &signatures.transparent {
        let sig = normalize_ledger_der(der)?;
        signer
            .append_transparent_signature(*index, sig)
            .map_err(|e| ApplyError::Signer(format!("transparent input {index}: {e:?}")))?;
    }

    Ok(signer.finish())
}

/// [`apply_device_signatures`], serialized.
///
/// The encoding is whichever of PCZT v1 / v2 minimally represents the content,
/// exactly as every other producer in the ecosystem emits it.
pub fn apply_device_signatures_to_bytes(
    pczt: Pczt,
    signatures: &DeviceSignatures,
) -> Result<Vec<u8>, ApplyError> {
    apply_device_signatures(pczt, signatures)?
        .serialize()
        .map_err(|e| ApplyError::Encoding(format!("{e:?}")))
}
