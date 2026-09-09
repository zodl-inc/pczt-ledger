//! Wire-record encoders, one per `PCZT_*` record in `docs/PCZT_APDU.md`
//! (`LedgerHQ/app-zcash` @ `22dc385`).
//!
//! These take *plain* records of raw fields. Nothing here parses a PCZT: the
//! session layer maps `pczt`-crate types (via the Verifier role) into the
//! structs below, and this module only turns them into bytes.
//!
//! # Byte order
//!
//! Every integer is little-endian, matching `ReadBytesExt` in
//! `src/parser/reader.rs` (`read_u32_le` / `read_u64_le`). The one exception is
//! a derivation path: `Bip32Path::from_dpath` in `src/utils/bip32_path.rs` uses
//! `u32::from_be_bytes`, so path components are **big-endian**.
//!
//! # Packet groups
//!
//! Each builder returns a `Vec<Vec<u8>>` of *groups*. A group must occupy whole
//! APDU packets — see [`super::pack_groups`] for why the device's parser
//! requires this — so the caller hands the groups to [`super::chunk_command`]
//! rather than concatenating them.
//!
//! # Secrets in the records
//!
//! A [`ShieldedActionRecord`] carries `alpha`, which links the action's
//! published `rk` back to the account's `ak`; `rcv`, which opens the value
//! commitment; and both `rseed`s, which open the note commitments. It is
//! wiped when dropped, its `Debug` form redacts those fields along with the
//! two addresses, and the `*_apdus` builders wipe the intermediate group
//! buffers they encode from. The `*_groups` builders hand their buffers to the
//! caller, who owns the wiping from there.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{chunk_command, p1, p2, Apdu, Finish, Ins};

/// The `Debug` form of a field whose value must not appear in a log.
const REDACTED: &str = "[redacted]";

/// Raw Orchard payment address length, `ORCHARD_RAW_ADDRESS_SIZE`.
pub const ORCHARD_RAW_ADDRESS_SIZE: usize = 43;
/// `ORCHARD_ENC_CIPHERTEXT_SIZE`; the device rejects any other length
/// (`"Bad PCZT orchard enc_ciphertext size"`).
pub const ENC_CIPHERTEXT_SIZE: usize = 580;
/// `ORCHARD_OUT_CIPHERTEXT_SIZE`; likewise fixed.
pub const OUT_CIPHERTEXT_SIZE: usize = 80;
/// Compressed secp256k1 public key length in a `bip32_derivation` entry.
pub const COMPRESSED_PUBKEY_SIZE: usize = 33;
/// ZIP 32 seed fingerprint length.
pub const SEED_FINGERPRINT_SIZE: usize = 32;
/// `SIGHASH_ALL`, the only sighash type the device accepts
/// (`src/consts.rs`, and `parse_transparent_input_sighash_type`).
pub const SIGHASH_ALL: u8 = 0x01;
/// PCZT magic bytes (`MAGIC_BYTES` in `src/parser/pczt.rs`).
pub const PCZT_MAGIC: [u8; 4] = *b"PCZT";
/// `PCZT_VERSION_1` — required for a V5 (Orchard) transaction.
pub const PCZT_VERSION_V5: u32 = 1;
/// `PCZT_VERSION_2` — required for a V6 (Ironwood) transaction.
pub const PCZT_VERSION_V6: u32 = 2;
/// `NOTE_VERSION_IRONWOOD` — the only `notePlaintextVersion` the Ironwood pool
/// accepts.
pub const NOTE_VERSION_IRONWOOD: u8 = 0x03;

/// Errors a record can carry that make it unencodable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// A `value_sum` magnitude outside `i64`, which
    /// `finish_orchard_value_sum_sign` rejects with `"value_sum out of range"`.
    ValueSumOutOfRange(i128),
    /// A derivation path longer than `MAX_ZCASH_BIP32_PATH` (10).
    PathTooLong(usize),
    /// `GET_SHIELD_ADDR` was asked to display a raw Orchard receiver.
    ///
    /// `handler_get_shielded_addr` @ `22dc385` answers P1 `0x01` with P2
    /// `0x01` with `WrongP1P2` (`0x6B00`), before any derivation: "A raw
    /// Orchard receiver is thirty-odd bytes with no encoding the user could
    /// read back against their wallet, so this mode has no screen to show."
    ///
    /// Refused here so the APDU is never built.
    OrchardAddressCannotBeDisplayed,
    /// A ciphertext of the wrong fixed length.
    BadCiphertextLength {
        /// Which field.
        field: &'static str,
        /// Length the device requires.
        expected: usize,
        /// Length the record carried.
        got: usize,
    },
}

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EncodeError::ValueSumOutOfRange(v) => {
                write!(f, "value_sum {v} does not fit in i64")
            }
            EncodeError::PathTooLong(n) => {
                write!(
                    f,
                    "derivation path has {n} components, device maximum is 10"
                )
            }
            EncodeError::OrchardAddressCannotBeDisplayed => write!(
                f,
                "a raw Orchard receiver has no screen to show: GET_SHIELD_ADDR P2 0x01 \
                 accepts P1 0x00 only"
            ),
            EncodeError::BadCiphertextLength {
                field,
                expected,
                got,
            } => write!(f, "{field} must be {expected} bytes, got {got}"),
        }
    }
}

impl std::error::Error for EncodeError {}

/// Maximum path components the device stores (`MAX_ZCASH_BIP32_PATH`).
pub const MAX_PATH_COMPONENTS: usize = 10;

// ---------------------------------------------------------------------------
// Primitive writers
// ---------------------------------------------------------------------------

/// Appends a Zcash `CompactSize`.
///
/// Matches `zcash_encoding::CompactSize`, which the device uses for every
/// count and byte length on the PCZT wire (`CompactSize::read_t`).
pub fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=252 => out.push(n as u8),
        253..=0xFFFF => {
            out.push(0xFD);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(0xFE);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xFF);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

/// Appends an `Option<u32>` as the device's 1-byte tag plus optional LE value.
///
/// `read_optional_u32` in `src/parser/pczt/common.rs`: tag `0` is `None`,
/// tag `1` is `Some(u32 LE)`, anything else is
/// `"Bad PCZT Option<u32> tag"`.
pub fn write_optional_u32(out: &mut Vec<u8>, v: Option<u32>) {
    match v {
        None => out.push(0),
        Some(x) => {
            out.push(1);
            out.extend_from_slice(&x.to_le_bytes());
        }
    }
}

/// A BIP 32 / ZIP 32 derivation path, components already hardened by the
/// caller (hardening is the high bit, `0x8000_0000`).
///
/// At most [`MAX_PATH_COMPONENTS`] components, the firmware's
/// `MAX_ZCASH_BIP32_PATH`; [`DerivationPath::new`] enforces the bound.
#[derive(Debug, Clone, PartialEq, Eq, Default, Zeroize)]
pub struct DerivationPath(pub(crate) Vec<u32>);

impl DerivationPath {
    /// Wraps raw path components, refusing more than
    /// [`MAX_PATH_COMPONENTS`] of them.
    pub fn new(components: Vec<u32>) -> Result<Self, EncodeError> {
        if components.len() > MAX_PATH_COMPONENTS {
            return Err(EncodeError::PathTooLong(components.len()));
        }
        Ok(DerivationPath(components))
    }

    /// The raw path components, hardening bits included.
    pub fn components(&self) -> &[u32] {
        &self.0
    }
    /// Wire encoding: `path_len u8` then that many **big-endian** `u32`s.
    ///
    /// `docs/APDU.md`: "`path_len u8`, `path_len` big-endian `u32` path
    /// components". Confirmed by `Bip32Path::from_dpath`.
    pub fn write(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        if self.0.len() > MAX_PATH_COMPONENTS {
            return Err(EncodeError::PathTooLong(self.0.len()));
        }
        out.push(self.0.len() as u8);
        for c in &self.0 {
            out.extend_from_slice(&c.to_be_bytes());
        }
        Ok(())
    }

    /// The encoding as a standalone buffer.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::with_capacity(1 + 4 * self.0.len());
        self.write(&mut out)?;
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// PCZT_HEADER (INS 0x52)
// ---------------------------------------------------------------------------

/// `PCZT_HEADER` payload: the `Pczt` header plus `common::Global`.
///
/// `docs/PCZT_APDU.md#pczt_header`, cross-checked against
/// `parse_pczt_header` + `parse_global` in `src/parser/pczt/common.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderRecord {
    /// PCZT wire-format revision: [`PCZT_VERSION_V5`] (1) for a V5
    /// transaction, [`PCZT_VERSION_V6`] (2) for V6. The device rejects a
    /// mismatch with `tx_version`.
    pub pczt_version: u32,
    /// `tx_version` — 5 or 6.
    pub tx_version: u32,
    /// `version_group_id` — `0x26A7270A` (V5) or `0xD884B698` (V6,
    /// `V6_VERSION_GROUP_ID` in `src/consts.rs`).
    pub version_group_id: u32,
    /// `consensus_branch_id`.
    pub consensus_branch_id: u32,
    /// `fallback_lock_time` — encoded with the 1-byte `Option` tag.
    pub fallback_lock_time: Option<u32>,
    /// `expiry_height`.
    pub expiry_height: u32,
    /// `coin_type` — must equal the app build's `ZCASH_BIP44_COIN_TYPE`
    /// (133 mainnet, 1 testnet) or the device answers
    /// `"Unsupported PCZT coin_type"`.
    pub coin_type: u32,
    /// `tx_modifiable` flags byte.
    pub tx_modifiable: u8,
}

impl HeaderRecord {
    /// Serializes the single-packet `PCZT_HEADER` payload.
    ///
    /// Field order is exactly the read order in `parse_pczt_header` then
    /// `parse_global`: magic, PCZT version, `tx_version`,
    /// `version_group_id`, `consensus_branch_id`, `fallback_lock_time`,
    /// `expiry_height`, `coin_type`, `tx_modifiable`. The device rejects any
    /// trailing byte (`"Unexpected PCZT header data after global fields"`).
    pub fn payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(30);
        out.extend_from_slice(&PCZT_MAGIC);
        out.extend_from_slice(&self.pczt_version.to_le_bytes());
        out.extend_from_slice(&self.tx_version.to_le_bytes());
        out.extend_from_slice(&self.version_group_id.to_le_bytes());
        out.extend_from_slice(&self.consensus_branch_id.to_le_bytes());
        write_optional_u32(&mut out, self.fallback_lock_time);
        out.extend_from_slice(&self.expiry_height.to_le_bytes());
        out.extend_from_slice(&self.coin_type.to_le_bytes());
        out.push(self.tx_modifiable);
        out
    }
}

/// The `PCZT_HEADER` APDU.
///
/// `docs/APDU.md`: INS `0x52`, P1 `0x00`, P2 `0x00`, single packet — and
/// `Instruction::try_from` accepts nothing else for this INS.
pub fn header_apdu(header: &HeaderRecord) -> Apdu {
    Apdu::new(
        Ins::PcztHeader,
        p1::FIRST,
        p2::PCZT_CONTINUE,
        header.payload(),
    )
}

// ---------------------------------------------------------------------------
// PCZT_TRANSPARENT_INPUT (INS 0x53) / PCZT_TRANSPARENT_OUTPUT (INS 0x54)
// ---------------------------------------------------------------------------

/// A transparent `bip32_derivation` entry.
///
/// The device reads a `CompactSize` entry count, then treats the *rest of the
/// packet* as one entry: 33-byte compressed pubkey, 32-byte seed fingerprint,
/// `Bip32Path` (`finish_transparent_input_bip32_derivation`).
///
/// The pubkey names a transparent address, so `Debug` redacts it.
#[derive(Clone, PartialEq, Eq)]
pub struct TransparentDerivation {
    /// Compressed secp256k1 public key.
    pub pubkey: [u8; COMPRESSED_PUBKEY_SIZE],
    /// ZIP 32 seed fingerprint.
    pub seed_fingerprint: [u8; SEED_FINGERPRINT_SIZE],
    /// Derivation path.
    pub path: DerivationPath,
}

impl core::fmt::Debug for TransparentDerivation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TransparentDerivation")
            .field("pubkey", &REDACTED)
            .field("seed_fingerprint", &self.seed_fingerprint)
            .field("path", &self.path)
            .finish()
    }
}

impl TransparentDerivation {
    fn write_entry(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        out.extend_from_slice(&self.pubkey);
        out.extend_from_slice(&self.seed_fingerprint);
        self.path.write(out)
    }
}

/// One `transparent::Input`.
///
/// `docs/PCZT_APDU.md#pczt_transparent_input`. The `script_pubkey` is the
/// spent coin's address, so `Debug` shows only its length.
#[derive(Clone, PartialEq, Eq)]
pub struct TransparentInputRecord {
    /// `prevout_txid [u8; 32]`.
    pub prevout_txid: [u8; 32],
    /// `prevout_index u32`.
    pub prevout_index: u32,
    /// `sequence Option<u32>`; `None` means the device's `DEFAULT_SEQUENCE`
    /// (`0xFFFF_FFFF`).
    pub sequence: Option<u32>,
    /// `value u64`, in zatoshis.
    pub value: u64,
    /// `script_pubkey`, raw (no length prefix — the encoder adds the
    /// `CompactSize`). At most 252 bytes.
    pub script_pubkey: Vec<u8>,
    /// `sighash_type u8`; must be [`SIGHASH_ALL`].
    pub sighash_type: u8,
    /// The single `bip32_derivation` entry; the device requires exactly one.
    pub derivation: TransparentDerivation,
}

impl core::fmt::Debug for TransparentInputRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TransparentInputRecord")
            .field("prevout_txid", &self.prevout_txid)
            .field("prevout_index", &self.prevout_index)
            .field("sequence", &self.sequence)
            .field("value", &self.value)
            .field("script_pubkey", &Redacted(self.script_pubkey.len()))
            .field("sighash_type", &self.sighash_type)
            .field("derivation", &self.derivation)
            .finish()
    }
}

/// One `transparent::Output`.
///
/// `docs/PCZT_APDU.md#pczt_transparent_output`. The `script_pubkey` is the
/// recipient's address, so `Debug` shows only its length.
#[derive(Clone, PartialEq, Eq)]
pub struct TransparentOutputRecord {
    /// `value u64`, in zatoshis.
    pub value: u64,
    /// `script_pubkey`, raw. Must be a standard P2PKH or P2SH script.
    pub script_pubkey: Vec<u8>,
    /// Optional `bip32_derivation`; `Some` marks the output as change, and the
    /// device then verifies the pubkey against its own derivation.
    pub derivation: Option<TransparentDerivation>,
}

impl core::fmt::Debug for TransparentOutputRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TransparentOutputRecord")
            .field("value", &self.value)
            .field("script_pubkey", &Redacted(self.script_pubkey.len()))
            .field("derivation", &self.derivation)
            .finish()
    }
}

/// The `Debug` form of a redacted byte field: its length, never its bytes.
struct Redacted(usize);

impl core::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[redacted; {} bytes]", self.0)
    }
}

/// Encodes a length-prefixed script as its own packet group.
///
/// `docs/PCZT_APDU.md`: "first packet: CompactSize byte length + script bytes;
/// continuation packets: script bytes only" — which is what a single group
/// handed to [`super::pack_groups`] produces.
fn script_group(script: &[u8]) -> Vec<u8> {
    let mut g = Vec::with_capacity(1 + script.len());
    write_compact_size(&mut g, script.len() as u64);
    g.extend_from_slice(script);
    g
}

/// Packet groups for the whole `PCZT_TRANSPARENT_INPUT` command.
///
/// Always sent, including with `inputs = []` — the payload is then the single
/// `CompactSize` `0` count packet.
pub fn transparent_input_groups(
    inputs: &[TransparentInputRecord],
) -> Result<Vec<Vec<u8>>, EncodeError> {
    let mut groups = Vec::new();

    // 1. Count packet.
    let mut count = Vec::new();
    write_compact_size(&mut count, inputs.len() as u64);
    groups.push(count);

    for input in inputs {
        // 2a. Small input packet. `parse_transparent_input` requires the
        //     packet to end here ("scriptPubKey must start in a separate
        //     APDU").
        let mut small = Vec::with_capacity(49);
        small.extend_from_slice(&input.prevout_txid);
        small.extend_from_slice(&input.prevout_index.to_le_bytes());
        write_optional_u32(&mut small, input.sequence);
        small.extend_from_slice(&input.value.to_le_bytes());
        groups.push(small);

        // 2b. script_pubkey packet sequence.
        groups.push(script_group(&input.script_pubkey));

        // 2c. Signing data packet: sighash_type then the complete
        //     bip32_derivation. `parse_transparent_input_sighash_type`
        //     requires bytes to follow in the same packet, and
        //     `parse_transparent_input_bip32_derivation` consumes the rest of
        //     it as one entry — so this is exactly one packet.
        let mut signing = Vec::new();
        signing.push(input.sighash_type);
        write_compact_size(&mut signing, 1);
        input.derivation.write_entry(&mut signing)?;
        groups.push(signing);
    }

    Ok(groups)
}

/// Packet groups for the whole `PCZT_TRANSPARENT_OUTPUT` command.
pub fn transparent_output_groups(
    outputs: &[TransparentOutputRecord],
) -> Result<Vec<Vec<u8>>, EncodeError> {
    let mut groups = Vec::new();

    let mut count = Vec::new();
    write_compact_size(&mut count, outputs.len() as u64);
    groups.push(count);

    for output in outputs {
        // Value packet; `parse_transparent_output` requires it to end here.
        groups.push(output.value.to_le_bytes().to_vec());

        groups.push(script_group(&output.script_pubkey));

        // bip32_derivation packet: CompactSize count 0 or 1, then the entry.
        let mut deriv = Vec::new();
        match &output.derivation {
            None => write_compact_size(&mut deriv, 0),
            Some(d) => {
                write_compact_size(&mut deriv, 1);
                d.write_entry(&mut deriv)?;
            }
        }
        groups.push(deriv);
    }

    Ok(groups)
}

/// The `PCZT_TRANSPARENT_INPUT` APDUs. P2 is always `P2_PCZT_CONTINUE`:
/// `Instruction::try_from` accepts no other P2 on this INS.
pub fn transparent_input_apdus(
    inputs: &[TransparentInputRecord],
) -> Result<Vec<Apdu>, EncodeError> {
    let groups = Zeroizing::new(transparent_input_groups(inputs)?);
    Ok(chunk_command(
        Ins::PcztTransparentInput,
        &groups,
        Finish::Continue,
    ))
}

/// The `PCZT_TRANSPARENT_OUTPUT` APDUs.
pub fn transparent_output_apdus(
    outputs: &[TransparentOutputRecord],
) -> Result<Vec<Apdu>, EncodeError> {
    let groups = Zeroizing::new(transparent_output_groups(outputs)?);
    Ok(chunk_command(
        Ins::PcztTransparentOutput,
        &groups,
        Finish::Continue,
    ))
}

// ---------------------------------------------------------------------------
// PCZT_ORCHARD_ACTION (0x56) / PCZT_IRONWOOD_ACTION (0x58)
// ---------------------------------------------------------------------------

/// A shielded `zip32_derivation`.
///
/// Unlike the transparent one this carries **no** entry count and no pubkey:
/// `parse_orchard_zip32_derivation` takes the whole packet as
/// `seed_fingerprint[32] || Bip32Path`.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct Zip32Derivation {
    /// ZIP 32 seed fingerprint.
    pub seed_fingerprint: [u8; SEED_FINGERPRINT_SIZE],
    /// Derivation path.
    pub path: DerivationPath,
}

/// One shielded action, Orchard or Ironwood.
///
/// `docs/PCZT_APDU.md#pczt_orchard_action`; the Ironwood per-action layout is
/// declared identical ("the same packet types in the same order") apart from
/// the optional trailing `notePlaintextVersion`.
///
/// Wiped on drop, and `Debug` redacts `alpha`, `rcv`, both `rseed`s and both
/// addresses; see the module docs.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ShieldedActionRecord {
    /// `cv_net [u8; 32]`.
    pub cv_net: [u8; 32],
    /// `nullifier [u8; 32]`.
    pub nullifier: [u8; 32],
    /// `rk [u8; 32]`; recomputed on device from the signing key and `alpha`.
    pub rk: [u8; 32],
    /// `spend_recipient [u8; 43]`, raw Orchard payment address.
    pub spend_recipient: [u8; ORCHARD_RAW_ADDRESS_SIZE],
    /// `spend_value u64`. Zero marks a dummy spend, which the device parses
    /// without the `rk`/nullifier checks and refuses to sign.
    pub spend_value: u64,
    /// `spend_rho [u8; 32]`.
    pub spend_rho: [u8; 32],
    /// `spend_rseed [u8; 32]`.
    pub spend_rseed: [u8; 32],
    /// `alpha [u8; 32]`, the spend-auth randomizer.
    pub alpha: [u8; 32],
    /// `zip32_derivation`, its own packet.
    pub zip32_derivation: Zip32Derivation,
    /// `cmx [u8; 32]`.
    pub cmx: [u8; 32],
    /// `ephemeral_key [u8; 32]`.
    pub ephemeral_key: [u8; 32],
    /// `enc_ciphertext`, exactly [`ENC_CIPHERTEXT_SIZE`] bytes.
    pub enc_ciphertext: Vec<u8>,
    /// `out_ciphertext`, exactly [`OUT_CIPHERTEXT_SIZE`] bytes.
    pub out_ciphertext: Vec<u8>,
    /// Output `recipient [u8; 43]`, raw Orchard payment address.
    pub recipient: [u8; ORCHARD_RAW_ADDRESS_SIZE],
    /// Output `value u64`.
    pub value: u64,
    /// Output `rseed [u8; 32]`.
    pub rseed: [u8; 32],
    /// `rcv [u8; 32]`. The device rejects the 83-byte metadata packet that
    /// omits it (`"Missing PCZT orchard rcv"`).
    pub rcv: [u8; 32],
    /// Ironwood only: the optional trailing `notePlaintextVersion` byte, which
    /// makes the output-metadata packet 116 bytes instead of 115. It must be
    /// [`NOTE_VERSION_IRONWOOD`] (`0x03`); the 115-byte form means the same
    /// thing, since the parser's per-action reset leaves the field at `0x03`.
    ///
    /// Must be `None` for an Orchard action: `parse_orchard_output_metadata`
    /// accepts only the 115-byte packet.
    pub note_plaintext_version: Option<u8>,
}

impl core::fmt::Debug for ShieldedActionRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // What is shown is what the chain will publish: commitments,
        // nullifier, `rk`, `cmx`, the ephemeral key, and the values the
        // device displays. Everything that opens or links them is redacted.
        f.debug_struct("ShieldedActionRecord")
            .field("cv_net", &self.cv_net)
            .field("nullifier", &self.nullifier)
            .field("rk", &self.rk)
            .field("spend_recipient", &REDACTED)
            .field("spend_value", &self.spend_value)
            .field("spend_rho", &self.spend_rho)
            .field("spend_rseed", &REDACTED)
            .field("alpha", &REDACTED)
            .field("zip32_derivation", &self.zip32_derivation)
            .field("cmx", &self.cmx)
            .field("ephemeral_key", &self.ephemeral_key)
            .field("enc_ciphertext", &Redacted(self.enc_ciphertext.len()))
            .field("out_ciphertext", &Redacted(self.out_ciphertext.len()))
            .field("recipient", &REDACTED)
            .field("value", &self.value)
            .field("rseed", &REDACTED)
            .field("rcv", &REDACTED)
            .field("note_plaintext_version", &self.note_plaintext_version)
            .finish()
    }
}

/// A bundle trailer, sent only when the action count is greater than zero.
///
/// `docs/PCZT_APDU.md`: `flags u8`, `value_sum` magnitude `u64`, `value_sum`
/// negative-sign flag `u8`, `anchor [u8; 32]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleTrailerRecord {
    /// `flags u8`. The device re-reads this through
    /// `orchard_component::read_flags` for the pool's `BundleVersion`
    /// (`orchard_insecure_v1` for V5 Orchard, `orchard_v3` for V6 Orchard,
    /// `ironwood_v3` for Ironwood), so an out-of-range bit is rejected.
    pub flags: u8,
    /// The signed `value_sum` / `value_balance`, split into magnitude and sign
    /// on the wire. Must fit in `i64`.
    pub value_sum: i64,
    /// `anchor [u8; 32]`. For a V6 transaction this is committed to the
    /// authorizing-data digest rather than the txid sighash, but it is sent
    /// either way.
    pub anchor: [u8; 32],
}

impl BundleTrailerRecord {
    /// The trailer packet.
    ///
    /// Sign encoding from `finish_orchard_value_sum_sign`: byte `0` means
    /// `+magnitude`, byte `1` means `-magnitude`, anything else is
    /// `"Bad PCZT orchard value_sum sign"`.
    pub fn payload(&self) -> Result<Vec<u8>, EncodeError> {
        let magnitude = self.value_sum.unsigned_abs();
        // The device converts the magnitude back with `i64::try_from`, so a
        // magnitude above `i64::MAX` is unrepresentable. `i64::MIN` is the
        // only input that produces one.
        if magnitude > i64::MAX as u64 {
            return Err(EncodeError::ValueSumOutOfRange(self.value_sum as i128));
        }
        let sign = u8::from(self.value_sum < 0);

        let mut out = Vec::with_capacity(42);
        out.push(self.flags);
        out.extend_from_slice(&magnitude.to_le_bytes());
        out.push(sign);
        out.extend_from_slice(&self.anchor);
        Ok(out)
    }
}

/// Which shielded pool a bundle command addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShieldedPool {
    /// `PCZT_ORCHARD_ACTION`, INS `0x56`.
    Orchard,
    /// `PCZT_IRONWOOD_ACTION`, INS `0x58`.
    Ironwood,
}

impl ShieldedPool {
    /// The instruction byte for this pool's bundle command.
    pub const fn bundle_ins(self) -> Ins {
        match self {
            ShieldedPool::Orchard => Ins::PcztOrchardAction,
            ShieldedPool::Ironwood => Ins::PcztIronwoodAction,
        }
    }

    /// The instruction byte for this pool's signing command.
    pub const fn sign_ins(self) -> Ins {
        match self {
            ShieldedPool::Orchard => Ins::PcztSignOrchard,
            ShieldedPool::Ironwood => Ins::PcztSignIronwood,
        }
    }
}

/// Packet groups for a shielded bundle command.
///
/// The trailer is sent only when `actions` is non-empty, per
/// `docs/PCZT_APDU.md`: "Bundle trailer packet, only when Orchard action count
/// is greater than `0`" and, for Ironwood, "An empty bundle has no trailer, so
/// its count packet carries the marker instead."
pub fn shielded_action_groups(
    actions: &[ShieldedActionRecord],
    trailer: Option<&BundleTrailerRecord>,
) -> Result<Vec<Vec<u8>>, EncodeError> {
    let mut groups = Vec::new();

    // 1. Count packet.
    let mut count = Vec::new();
    write_compact_size(&mut count, actions.len() as u64);
    groups.push(count);

    for a in actions {
        if a.enc_ciphertext.len() != ENC_CIPHERTEXT_SIZE {
            return Err(EncodeError::BadCiphertextLength {
                field: "enc_ciphertext",
                expected: ENC_CIPHERTEXT_SIZE,
                got: a.enc_ciphertext.len(),
            });
        }
        if a.out_ciphertext.len() != OUT_CIPHERTEXT_SIZE {
            return Err(EncodeError::BadCiphertextLength {
                field: "out_ciphertext",
                expected: OUT_CIPHERTEXT_SIZE,
                got: a.out_ciphertext.len(),
            });
        }

        // 2a. Spend small fields — 243 bytes, one packet.
        let mut spend = Vec::with_capacity(243);
        spend.extend_from_slice(&a.cv_net);
        spend.extend_from_slice(&a.nullifier);
        spend.extend_from_slice(&a.rk);
        spend.extend_from_slice(&a.spend_recipient);
        spend.extend_from_slice(&a.spend_value.to_le_bytes());
        spend.extend_from_slice(&a.spend_rho);
        spend.extend_from_slice(&a.spend_rseed);
        spend.extend_from_slice(&a.alpha);
        groups.push(spend);

        // 2b. zip32_derivation packet: fingerprint then path, nothing else.
        let mut zip32 = Vec::with_capacity(SEED_FINGERPRINT_SIZE + 1 + 40);
        zip32.extend_from_slice(&a.zip32_derivation.seed_fingerprint);
        a.zip32_derivation.path.write(&mut zip32)?;
        groups.push(zip32);

        // 2c. Output small fields — cmx and ephemeral_key.
        let mut output = Vec::with_capacity(64);
        output.extend_from_slice(&a.cmx);
        output.extend_from_slice(&a.ephemeral_key);
        groups.push(output);

        // 2d/2e. The two ciphertexts, each its own packet sequence.
        let mut enc = Vec::with_capacity(3 + ENC_CIPHERTEXT_SIZE);
        write_compact_size(&mut enc, ENC_CIPHERTEXT_SIZE as u64);
        enc.extend_from_slice(&a.enc_ciphertext);
        groups.push(enc);

        let mut out_ct = Vec::with_capacity(1 + OUT_CIPHERTEXT_SIZE);
        write_compact_size(&mut out_ct, OUT_CIPHERTEXT_SIZE as u64);
        out_ct.extend_from_slice(&a.out_ciphertext);
        groups.push(out_ct);

        // 2f. Output metadata — 115 bytes, or 116 with the Ironwood
        //     notePlaintextVersion byte.
        let mut meta = Vec::with_capacity(116);
        meta.extend_from_slice(&a.recipient);
        meta.extend_from_slice(&a.value.to_le_bytes());
        meta.extend_from_slice(&a.rseed);
        meta.extend_from_slice(&a.rcv);
        if let Some(v) = a.note_plaintext_version {
            meta.push(v);
        }
        groups.push(meta);
    }

    if !actions.is_empty() {
        if let Some(t) = trailer {
            groups.push(t.payload()?);
        }
    }

    Ok(groups)
}

/// The APDUs for a shielded bundle command.
///
/// `finish` places the `P2_PCZT_FINISHED` marker: [`Finish::Finished`] on the
/// Orchard command for a V5 transaction, and on the Ironwood command — never
/// the Orchard one — for a V6 transaction.
pub fn shielded_action_apdus(
    pool: ShieldedPool,
    actions: &[ShieldedActionRecord],
    trailer: Option<&BundleTrailerRecord>,
    finish: Finish,
) -> Result<Vec<Apdu>, EncodeError> {
    let groups = Zeroizing::new(shielded_action_groups(actions, trailer)?);
    Ok(chunk_command(pool.bundle_ins(), &groups, finish))
}

// ---------------------------------------------------------------------------
// Signing commands
// ---------------------------------------------------------------------------

/// `PCZT_SIGN_TRANSPARENT` (`0x55`), P1 `0x00`, P2 = input index, empty data.
///
/// `Instruction::try_from` requires `p2 < MAX_PCZT_TRANSPARENT_INPUTS_NUMBER`
/// (32 at `22dc385`; 10 before v3.9.3 — see
/// [`crate::limits::DeviceBounds`]) and answers `WrongP1P2` otherwise.
pub fn sign_transparent_apdu(input_index: u8) -> Apdu {
    Apdu::new(Ins::PcztSignTransparent, 0x00, input_index, Vec::new())
}

/// `PCZT_SIGN_ORCHARD` (`0x57`) or `PCZT_SIGN_IRONWOOD` (`0x59`), P1 `0x00`,
/// P2 = action index, empty data.
pub fn sign_shielded_apdu(pool: ShieldedPool, action_index: u8) -> Apdu {
    Apdu::new(pool.sign_ins(), 0x00, action_index, Vec::new())
}

// ---------------------------------------------------------------------------
// Key / address / version commands
// ---------------------------------------------------------------------------

/// `INS_GET_FIRMWARE_VERSION` (`0xC4`), P1 = P2 = `0x00`, empty data.
pub fn get_firmware_version_apdu() -> Apdu {
    Apdu::new(Ins::GetFirmwareVersion, 0x00, 0x00, Vec::new())
}

/// `INS_GET_WALLET_PUBLIC_KEY` (`0x40`): derive one transparent public key.
///
/// Data is a single length-prefixed path, written by the same
/// [`DerivationPath::write`] every other command uses — `handler_get_public_key`
/// reads it with one `Bip32Path::try_from` over the whole `data` slice, so a
/// trailing byte is `WrongApduLength`.
///
/// P2 is always [`p2::WALLET_PUBLIC_KEY`] (`0x00`); P1 selects the screen.
/// With `display = false` the device answers silently and leaves no status
/// screen behind, which is what makes this usable as a probe in the middle of
/// another ceremony. With `display = true` it shows the transparent address and
/// answers `Deny` (`0x6985`) if the user refuses.
///
/// See [`Ins::GetWalletPublicKey`] for the path rule (`PrefixOnly`), and
/// [`super::decode::parse_wallet_public_key`] for the reply.
pub fn get_wallet_public_key_apdu(
    path: &DerivationPath,
    display: bool,
) -> Result<Apdu, EncodeError> {
    Ok(Apdu::new(
        Ins::GetWalletPublicKey,
        if display { p1::DISPLAY } else { p1::NO_DISPLAY },
        p2::WALLET_PUBLIC_KEY,
        path.to_bytes()?,
    ))
}

/// `INS_GET_VK` (`0x50`) P2 `0x00`: the unified full viewing key.
///
/// `docs/APDU.md`: "Orchard BIP32 account path followed by transparent BIP32
/// account path" — two length-prefixed paths in one payload, which
/// `parse_vk_paths` reads with two successive
/// `Bip32Path::from_prefixed_bytes` calls and then requires nothing to remain.
///
/// Both must be three-component account paths (`m/32'/coin'/account'` and
/// `m/44'/coin'/account'`) with matching account indices, or the device
/// answers `IncorrectData`.
pub fn get_ufvk_apdu(
    orchard_account_path: &DerivationPath,
    transparent_account_path: &DerivationPath,
) -> Result<Apdu, EncodeError> {
    let mut data = orchard_account_path.to_bytes()?;
    transparent_account_path.write(&mut data)?;
    Ok(Apdu::new(Ins::GetVk, p1::NO_DISPLAY, p2::VK_UFVK, data))
}

/// `INS_GET_VK` P2 `0x01`: raw Orchard FVK bytes, one path only.
pub fn get_orchard_fvk_apdu(orchard_account_path: &DerivationPath) -> Result<Apdu, EncodeError> {
    Ok(Apdu::new(
        Ins::GetVk,
        p1::NO_DISPLAY,
        p2::VK_ORCHARD_FVK,
        orchard_account_path.to_bytes()?,
    ))
}

/// `INS_GET_VK` with P1 `0x80`: request the next response chunk.
///
/// The device requires empty data on a continuation
/// (`handler_get_vk`: `if !data.is_empty() { WrongApduLength }`). `mode` must
/// repeat the P2 of the request that started the response.
pub fn get_vk_continue_apdu(mode: u8) -> Apdu {
    Apdu::new(Ins::GetVk, p1::GET_VK_CONTINUE, mode, Vec::new())
}

/// `INS_GET_SHIELD_ADDR` (`0x51`) P2 `0x00`: the unified address, as a string
/// response.
///
/// Data is the Orchard account path followed by the transparent **address**
/// path (a full BIP 44 path, not an account path — `handler_get_shielded_addr`
/// checks it with `Bip44CheckMode::Full { is_change_path: false }`).
pub fn get_unified_address_apdu(
    orchard_account_path: &DerivationPath,
    transparent_address_path: &DerivationPath,
    display: bool,
) -> Result<Apdu, EncodeError> {
    let mut data = orchard_account_path.to_bytes()?;
    transparent_address_path.write(&mut data)?;
    Ok(Apdu::new(
        Ins::GetShieldAddr,
        if display { p1::DISPLAY } else { p1::NO_DISPLAY },
        p2::ADDR_UNIFIED,
        data,
    ))
}

/// `INS_GET_SHIELD_ADDR` P2 `0x01`: raw Orchard address bytes.
///
/// `display` must be `false`: from `22dc385` the handler refuses the
/// combination with `WrongP1P2` before deriving anything. A `display = true`
/// request fails here with [`EncodeError::OrchardAddressCannotBeDisplayed`]
/// rather than being silently downgraded to a derivation with no review.
pub fn get_orchard_address_apdu(
    orchard_account_path: &DerivationPath,
    display: bool,
) -> Result<Apdu, EncodeError> {
    if display {
        return Err(EncodeError::OrchardAddressCannotBeDisplayed);
    }
    Ok(Apdu::new(
        Ins::GetShieldAddr,
        p1::NO_DISPLAY,
        p2::ADDR_ORCHARD,
        orchard_account_path.to_bytes()?,
    ))
}

// ---------------------------------------------------------------------------
// Whole-transaction plan
// ---------------------------------------------------------------------------

/// Every record needed to stream one transaction, in wire order.
///
/// The session layer fills this from a PCZT; [`crate::limits`] checks it
/// against the device's limits before a byte goes out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamPlan {
    /// The `PCZT_HEADER` record.
    pub header: HeaderRecord,
    /// Transparent inputs, possibly empty.
    pub transparent_inputs: Vec<TransparentInputRecord>,
    /// Transparent outputs, possibly empty.
    pub transparent_outputs: Vec<TransparentOutputRecord>,
    /// Orchard actions, possibly empty.
    pub orchard_actions: Vec<ShieldedActionRecord>,
    /// The Orchard bundle trailer; required when `orchard_actions` is
    /// non-empty and forbidden otherwise.
    pub orchard_trailer: Option<BundleTrailerRecord>,
    /// Ironwood actions. `None` for a V5 transaction (the command is not sent
    /// at all); `Some(vec![])` for a V6 transaction with an empty Ironwood
    /// bundle, which the device accepts and which is what triggers its review.
    pub ironwood_actions: Option<Vec<ShieldedActionRecord>>,
    /// The Ironwood bundle trailer, on the same rule as the Orchard one.
    pub ironwood_trailer: Option<BundleTrailerRecord>,
}

impl StreamPlan {
    /// Whether this plan describes a V6 transaction, i.e. one that sends
    /// `PCZT_IRONWOOD_ACTION` and therefore moves the FINISHED marker there.
    pub fn is_v6(&self) -> bool {
        self.ironwood_actions.is_some()
    }

    /// The full APDU stream for the PCZT payload, header through the packet
    /// carrying `P2_PCZT_FINISHED`.
    ///
    /// Command order is fixed (`docs/PCZT_APDU.md`, "Common rules"):
    /// `PCZT_HEADER`, `PCZT_TRANSPARENT_INPUT`, `PCZT_TRANSPARENT_OUTPUT`,
    /// `PCZT_ORCHARD_ACTION`, and for a V6 transaction
    /// `PCZT_IRONWOOD_ACTION`. The three bundle commands are always sent, even
    /// when their count is zero.
    pub fn to_apdus(&self) -> Result<Vec<Apdu>, EncodeError> {
        let mut apdus = vec![header_apdu(&self.header)];
        apdus.extend(transparent_input_apdus(&self.transparent_inputs)?);
        apdus.extend(transparent_output_apdus(&self.transparent_outputs)?);

        let orchard_finish = if self.is_v6() {
            Finish::Continue
        } else {
            Finish::Finished
        };
        apdus.extend(shielded_action_apdus(
            ShieldedPool::Orchard,
            &self.orchard_actions,
            self.orchard_trailer.as_ref(),
            orchard_finish,
        )?);

        if let Some(ironwood) = &self.ironwood_actions {
            apdus.extend(shielded_action_apdus(
                ShieldedPool::Ironwood,
                ironwood,
                self.ironwood_trailer.as_ref(),
                Finish::Finished,
            )?);
        }

        Ok(apdus)
    }
}
