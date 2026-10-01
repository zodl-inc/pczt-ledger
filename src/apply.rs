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
//!    `Signer::append_transparent_signature` then verifies each one against
//!    its input's sighash and the pubkey stamped in step 1 before storing it.
//!
//! The result is PCZT bytes ready for the downstream Combiner. Proving, spend
//! finalization and extraction all happen downstream.
//!
//! # Trust boundary
//!
//! The signatures come from a device the session identified, but nothing here
//! trusts them: both halves are verified against the PCZT's own data before
//! they are stored — a shielded signature against its action's randomized
//! verification key, a transparent one against its input's sighash and
//! pubkey. A wrong, swapped or corrupted signature is an [`ApplyError`], never
//! a signed PCZT with a bad signature in it.

use alloc::{boxed::Box, format, string::String, vec::Vec};

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
///
/// `Debug` shows how many signatures of each kind there are, not the
/// signatures: a DER blob appears verbatim in the `scriptSig` once the
/// transaction is mined, so a logged one joins the log line to the chain.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct DeviceSignatures {
    /// `(action index, RedPallas SpendAuthSig)` for the Orchard bundle.
    pub(crate) orchard: Vec<(usize, [u8; SPEND_AUTH_SIG_LEN])>,
    /// The same for the Ironwood bundle.
    pub(crate) ironwood: Vec<(usize, [u8; SPEND_AUTH_SIG_LEN])>,
    /// `(input index, raw device reply)` for each transparent input. The bytes
    /// are exactly what `PCZT_SIGN_TRANSPARENT` returned, quirks included;
    /// [`normalize_ledger_der`] handles them.
    pub(crate) transparent: Vec<(usize, Vec<u8>)>,
}

impl core::fmt::Debug for DeviceSignatures {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceSignatures")
            .field(
                "orchard",
                &format_args!("[{} signatures]", self.orchard.len()),
            )
            .field(
                "ironwood",
                &format_args!("[{} signatures]", self.ironwood.len()),
            )
            .field(
                "transparent",
                &format_args!("[{} signatures]", self.transparent.len()),
            )
            .finish()
    }
}

impl DeviceSignatures {
    /// The signatures of one ceremony, each with the index of the action or
    /// input it belongs to.
    pub fn new(
        orchard: Vec<(usize, [u8; SPEND_AUTH_SIG_LEN])>,
        ironwood: Vec<(usize, [u8; SPEND_AUTH_SIG_LEN])>,
        transparent: Vec<(usize, Vec<u8>)>,
    ) -> Self {
        DeviceSignatures {
            orchard,
            ironwood,
            transparent,
        }
    }

    /// `(action index, RedPallas SpendAuthSig)` for the Orchard bundle.
    ///
    /// The signatures are plain byte arrays, which `Debug` prints in full;
    /// each appears verbatim on chain once the transaction is mined, so a
    /// logged slice joins the log line to the transaction. The count-only
    /// `Debug` on [`DeviceSignatures`] does not cover what this returns.
    pub fn orchard(&self) -> &[(usize, [u8; SPEND_AUTH_SIG_LEN])] {
        &self.orchard
    }

    /// The same for the Ironwood bundle, with the same caution about logging.
    pub fn ironwood(&self) -> &[(usize, [u8; SPEND_AUTH_SIG_LEN])] {
        &self.ironwood
    }

    /// `(input index, raw device reply)` for each transparent input: the DER
    /// blob and the sighash byte exactly as `PCZT_SIGN_TRANSPARENT` returned
    /// them, quirks included.
    ///
    /// The replies are plain byte vectors, which `Debug` prints in full, and
    /// [`normalize_ledger_der`] leaves `r` as it is, so a logged reply is a
    /// fingerprint of the `scriptSig` once the transaction is mined — the
    /// linkage the count-only `Debug` on [`DeviceSignatures`] exists to
    /// prevent, and which that `Debug` does not cover here. The session's
    /// [`crate::session::SignOutcome::transparent_sigs`] hands out a type
    /// whose `Debug` shows the length only.
    pub fn transparent(&self) -> &[(usize, Vec<u8>)] {
        &self.transparent
    }
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
    /// The reply is not a DER blob plus one trailing byte: the device always
    /// appends the sighash type, so a blob without it — or with more than one
    /// byte past what its length field declares — is not a device reply.
    MissingSighashType {
        /// Bytes a DER blob of the declared length plus its trailer would be.
        expected: usize,
        /// Bytes received.
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
    /// The DER length byte has its high bit set: a long-form length.
    ///
    /// The device's DER is at most 72 bytes (the `ledger_device_sdk` ECDSA
    /// output, before the sighash byte), so its length always fits the short
    /// form; a long-form length is not a device reply. It is refused by name
    /// rather than parsed because the sighash checks read the short-form
    /// length, and `secp256k1`'s parser alone would not refuse it.
    DerLengthLongForm {
        /// The length byte received.
        got: u8,
    },
    /// `secp256k1` rejected the normalized DER blob.
    DerInvalid(secp256k1::Error),
    /// The DER blob parsed, but not to a signature that serializes back to
    /// the same bytes.
    ///
    /// `secp256k1`'s parser folds an integer too long for a scalar to zero
    /// rather than refusing it, so a blob whose `r` or `s` is oversized
    /// parses to an all-zero signature that only the verifier would later
    /// refuse. Requiring the parsed signature to serialize back to the bytes
    /// received refuses every such blob at the reply, as the non-canonical
    /// DER it is; the device SDK emits canonical DER.
    DerNotCanonical,
    /// The DER blob parsed to a signature whose `r` or `s` is zero.
    ///
    /// `02 01 00` is canonical DER for zero, so the blob passes the round
    /// trip, and `secp256k1`'s parser accepts it; only the verifier, inside
    /// `finish()`, would refuse the signature, as an opaque
    /// [`ApplyError::Signer`]. No signer produces a zero scalar, so the reply
    /// is refused here by name.
    ZeroScalar {
        /// `"r"` or `"s"`; `"r"` when both are zero.
        scalar: &'static str,
    },
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
    /// A transparent signature reply could not be turned into a signature,
    /// and which input it was filed under.
    ///
    /// [`normalize_ledger_der`] sees one reply at a time and cannot name the
    /// input; every other refusal in [`apply_device_signatures`] does, so a
    /// caller reading the error knows which of several inputs to look at.
    TransparentSignature {
        /// Index of the transparent input the reply was filed under.
        index: usize,
        /// Why the reply is not a signature the device produced.
        source: Box<ApplyError>,
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
            ApplyError::MissingSighashType { expected, got } => write!(
                f,
                "the signature reply is {got} bytes where its DER length plus the trailing \
                 sighash byte make {expected}; the device always appends the byte"
            ),
            ApplyError::DerLengthLongForm { got } => write!(
                f,
                "a transparent signature declares a long-form DER length ({got:#04x}); the \
                 device's DER is at most 72 bytes and always short-form, so the reply is not a \
                 device reply"
            ),
            ApplyError::DerInvalid(source) => {
                write!(
                    f,
                    "secp256k1 rejected the normalized DER signature: {source}"
                )
            }
            ApplyError::DerNotCanonical => write!(
                f,
                "a transparent signature parsed but does not serialize back to the bytes \
                 received: not the canonical DER the device emits"
            ),
            ApplyError::ZeroScalar { scalar } => write!(
                f,
                "a transparent signature has a zero {scalar}, which no signer produces and no \
                 verifier accepts"
            ),
            ApplyError::MissingInputDerivation { index } => write!(
                f,
                "transparent input {index} carries no bip32_derivation, so its controlling \
                 pubkey — and therefore its hash160_preimage — is unknown"
            ),
            ApplyError::TransparentSignature { index, source } => write!(
                f,
                "the signature reply for transparent input {index} is not a device signature: \
                 {source}"
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

impl core::error::Error for ApplyError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            // `secp256k1::Error` implements `Error` only with its `std` feature.
            #[cfg(feature = "std")]
            ApplyError::DerInvalid(source) => Some(source),
            ApplyError::TransparentSignature { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

/// The bit an ASN.1 length byte carries when it is the long form, whose low
/// bits then count the length bytes that follow; clear, the byte is the
/// length itself.
pub(crate) const DER_LONG_FORM_LENGTH_BIT: u8 = 0x80;

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
///    canonical already, making the reset a no-op). The bit is discarded, not
///    read: it is the parity half of a recovery id, which only matters for
///    recovering the public key from the signature, and nothing here needs
///    to. The host already holds the key — the input's `bip32_derivation`
///    pubkey, whose HASH160 is the P2PKH script's and against which the
///    Signer role verifies the signature — and a transparent `scriptSig`
///    carries the DER signature and that pubkey, with no recovery id. The bit
///    would not even survive step 5: negating `s` flips which parity recovers
///    the key;
/// 2. reads the ASN.1 short-form length, requires the buffer to be exactly one
///    byte longer than the DER blob declares — the device always appends the
///    byte, so anything else is not a device reply
///    ([`ApplyError::MissingSighashType`]) — checks that trailing byte is
///    [`SIGHASH_ALL`] and strips it. A long-form length byte (`>= 0x80`) is
///    refused first ([`ApplyError::DerLengthLongForm`]): the SDK's output is
///    bounded at 72 bytes so it cannot occur, and `from_der` would accept it
///    with the sighash checks never run;
/// 3. parses with `Signature::from_der` and requires the result to serialize
///    back to the same bytes ([`ApplyError::DerNotCanonical`]): `from_der`
///    folds an oversized `r` or `s` to zero rather than refusing it, and the
///    round trip is what refuses that;
/// 4. refuses a zero `r` or `s` ([`ApplyError::ZeroScalar`]): `02 01 00` is
///    canonical DER for zero, so the round trip passes it and `from_der`
///    accepts it, and no signer produces one; and
/// 5. normalizes `s` to the low half of the curve order. `secp256k1`'s verifier
///    — which `Signer::append_transparent_signature` runs before storing the
///    signature — rejects a high-`s` signature outright. Low-`s` is a
///    standardness rule ([BIP 62] rule 5), not a consensus rule: a high-`s`
///    transaction is valid but is not relayed. The normalization is required
///    here because of the verifier, and it is the right form because of the
///    rule.
///
/// [BIP 62]: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
///
/// Both quirks fail closed: a wrong assumption about either one makes
/// `from_der` reject the buffer rather than yield a different signature.
///
/// # Errors
///
/// [`ApplyError::DerTooShort`] for fewer than two bytes,
/// [`ApplyError::DerLengthLongForm`] for a long-form length byte,
/// [`ApplyError::MissingSighashType`] when the buffer is not the declared DER
/// length plus one byte, [`ApplyError::UnexpectedSighashType`] when that byte
/// is not `SIGHASH_ALL`, [`ApplyError::DerInvalid`] when `secp256k1` rejects
/// the signature once the quirks are undone, [`ApplyError::DerNotCanonical`]
/// when it accepts one that does not serialize back to the bytes received,
/// and [`ApplyError::ZeroScalar`] when the signature it accepts has a zero
/// `r` or `s`.
pub fn normalize_ledger_der(bytes: &[u8]) -> Result<secp256k1::ecdsa::Signature, ApplyError> {
    if bytes.len() < 2 {
        return Err(ApplyError::DerTooShort { got: bytes.len() });
    }

    let mut buf = bytes.to_vec();

    // 1. Reset the y-parity bit the device ORs into the SEQUENCE tag. It only
    // helps recover the pubkey, which the host already has; see the doc.
    if buf[0] == 0x31 {
        buf[0] = 0x30;
    }

    // 2. Strip the trailing sighash type, which the device always appends.
    // The checks read the short-form length, and the device's DER is short
    // enough that its length byte always is one.
    if buf[1] & DER_LONG_FORM_LENGTH_BIT != 0 {
        return Err(ApplyError::DerLengthLongForm { got: buf[1] });
    }
    let declared_total = 2 + usize::from(buf[1]); // tag + length byte + content
    if buf.len() != declared_total + 1 {
        return Err(ApplyError::MissingSighashType {
            expected: declared_total + 1,
            got: buf.len(),
        });
    }
    let sighash_type = buf[declared_total];
    if sighash_type != SIGHASH_ALL {
        return Err(ApplyError::UnexpectedSighashType { got: sighash_type });
    }
    buf.truncate(declared_total);

    // 3. Parse, and require the canonical form: `from_der` folds an
    // oversized integer to zero instead of refusing it.
    let mut sig = secp256k1::ecdsa::Signature::from_der(&buf).map_err(ApplyError::DerInvalid)?;
    if sig.serialize_der()[..] != buf[..] {
        return Err(ApplyError::DerNotCanonical);
    }

    // 4. Refuse a zero `r` or `s`: `02 01 00` is canonical DER for zero, so
    // the round trip passes it and `from_der` accepts it, and only the
    // verifier would refuse it, inside `finish()`.
    let compact = sig.serialize_compact();
    for (scalar, bytes) in [("r", &compact[..32]), ("s", &compact[32..])] {
        if bytes.iter().all(|&b| b == 0) {
            return Err(ApplyError::ZeroScalar { scalar });
        }
    }

    // 5.
    sig.normalize_s();
    Ok(sig)
}

/// Stamps every transparent input's `hash160_preimage` with the pubkeys its
/// `bip32_derivation` names.
///
/// Stamping every candidate is safe: `set_hash160_preimage` keys each entry by
/// `HASH160(value)`, so the lookup in `append_signature` resolves to whichever
/// entry matches the input's script code. That is its `script_pubkey`: the
/// Signer keys the lookup off `redeem_script.unwrap_or(script_pubkey)`, and
/// the plan refuses an input that carries a `redeem_script`
/// ([`crate::plan::PlanError::RedeemScriptPresent`]).
///
/// # Errors
///
/// [`ApplyError::MissingInputDerivation`] for an input that carries no
/// `bip32_derivation`, and [`ApplyError::Updater`] when the `pczt` Updater role
/// refuses the PCZT.
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
///
/// # Errors
///
/// As [`stamp_hash160_preimages`], plus
/// [`ApplyError::TransparentSignature`] — naming the input — around everything
/// [`normalize_ledger_der`] refuses, and [`ApplyError::Signer`] when the
/// `pczt` Signer role rejects a signature: one that does not verify against
/// the action's `rk` or the input's pubkey, or one for an index the PCZT does
/// not have.
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
        let sig = normalize_ledger_der(der).map_err(|source| ApplyError::TransparentSignature {
            index: *index,
            source: Box::new(source),
        })?;
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
///
/// # Errors
///
/// As [`apply_device_signatures`], plus [`ApplyError::Encoding`] when the
/// signed PCZT cannot be serialized.
pub fn apply_device_signatures_to_bytes(
    pczt: Pczt,
    signatures: &DeviceSignatures,
) -> Result<Vec<u8>, ApplyError> {
    apply_device_signatures(pczt, signatures)?
        .serialize()
        .map_err(|e| ApplyError::Encoding(format!("{e:?}")))
}

#[cfg(test)]
mod tests;
