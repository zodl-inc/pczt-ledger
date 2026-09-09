# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Initial release.

### Added
- `pczt_ledger::Network`, re-exported from `pczt_ledger::limits`.
- `pczt_ledger::apdu::{Apdu, ApduDataTooLong, Ins, StatusWord, StatusClass,
  Deadline, Finish, chunk_command, pack_groups, chunk_bytes, CLA,
  MAX_APDU_DATA, MAX_CMD_NOT_ACCEPTED_RETRIES, STATUS_WORD_LEN}`;
  `Apdu::{try_new, to_bytes, data, cla, ins, p1, p2}`; `ApduDataTooLong::got`;
  `Ins::{code, name}`; `StatusWord::{from_u16, to_u16, is_ok, is_retriable,
  is_transient, class}`.
- `pczt_ledger::apdu::p1::{FIRST, NEXT, LAST, NO_DISPLAY, DISPLAY,
  GET_VK_CONTINUE}` and `pczt_ledger::apdu::p2::{PCZT_CONTINUE, PCZT_FINISHED,
  VK_UFVK, VK_ORCHARD_FVK, WALLET_PUBLIC_KEY, ADDR_UNIFIED, ADDR_ORCHARD}`.
- `pczt_ledger::apdu::encode::{HeaderRecord, TransparentInputRecord,
  TransparentOutputRecord, TransparentDerivation, ShieldedActionRecord,
  Zip32Derivation, BundleTrailerRecord, DerivationPath, StreamPlan,
  ShieldedPool, TxFormat, EncodeError, header_apdu, transparent_input_groups,
  transparent_input_apdus, transparent_output_groups,
  transparent_output_apdus, shielded_action_groups, shielded_action_apdus,
  sign_transparent_apdu, sign_shielded_apdu, get_firmware_version_apdu,
  get_wallet_public_key_apdu, get_ufvk_apdu, get_orchard_fvk_apdu,
  get_vk_continue_apdu, get_unified_address_apdu, get_orchard_address_apdu,
  write_compact_size, write_optional_u32, MAX_PATH_COMPONENTS,
  ORCHARD_RAW_ADDRESS_SIZE, ENC_CIPHERTEXT_SIZE, OUT_CIPHERTEXT_SIZE,
  COMPRESSED_PUBKEY_SIZE, SEED_FINGERPRINT_SIZE, SIGHASH_ALL, PCZT_MAGIC,
  PCZT_VERSION_V5, PCZT_VERSION_V6, NOTE_VERSION_IRONWOOD}`;
  `DerivationPath::{new, components, write, to_bytes}`;
  `HeaderRecord::{new, pczt_version, tx_version, version_group_id,
  consensus_branch_id, fallback_lock_time, expiry_height, coin_type,
  tx_modifiable, payload}`; `TransparentDerivation::{new, pubkey,
  seed_fingerprint, path}`; `TransparentInputRecord::{new, prevout_txid,
  prevout_index, sequence, value, script_pubkey, sighash_type, derivation}`;
  `TransparentOutputRecord::{new, value, script_pubkey, derivation}`;
  `Zip32Derivation::{new, seed_fingerprint, path}`;
  `ShieldedActionRecord::{cv_net, nullifier, rk, spend_value,
  zip32_derivation, cmx, ephemeral_key, enc_ciphertext, out_ciphertext, value,
  note_plaintext_version}`; `BundleTrailerRecord::{new, flags, value_sum,
  anchor, payload}`; `StreamPlan::{new, header, transparent_inputs,
  transparent_outputs, orchard_actions, orchard_trailer, ironwood_actions,
  ironwood_trailer, format, to_apdus}`; `ShieldedPool::{bundle_ins,
  sign_ins}`; `TxFormat::pczt_version`.
- `pczt_ledger::apdu::decode::{DecodeError, FirmwareVersion, WalletPublicKey,
  TransparentSignature, VkKind, VkResponse, VkReassembler, split_status_word,
  expect_ok, parse_firmware_version, parse_wallet_public_key,
  parse_transparent_signature, parse_shielded_signature,
  parse_string_response, SPEND_AUTH_SIG_LEN, ORCHARD_FVK_LEN,
  FIRMWARE_VERSION_LEN, WALLET_PUBLIC_KEY_LEN, CHAIN_CODE_LEN,
  MAX_VK_CONTINUATIONS, MAX_VK_RESPONSE_LEN, LEGACY_VERSION_PREFIX,
  ARCH_ID}`; `FirmwareVersion::{major, minor, patch, sdk_major, sdk_minor,
  api_level}`; `WalletPublicKey::{public_key, chain_code, compressed}`;
  `TransparentSignature::{der, sighash_type}`; `VkReassembler::{new, push,
  len, is_empty, total_len}`.
- `pczt_ledger::framing::{Deframer, FramingError, HidChannel, BleFrameSize,
  hid_frames, ble_frames, ble_mtu_request, parse_ble_mtu_response, HEAD_TAG,
  HID_FRAME_SIZE, MTU_OP}`; `Deframer::{hid, ble, push, reset, is_idle,
  poisoned}`; `HidChannel::{new, get}`; `BleFrameSize::{new, get, MIN}`;
  `STATUS_WORD_LEN` re-exported from `pczt_ledger::apdu`.
- `pczt_ledger::limits::{DeviceBounds, DeviceCaps, Network,
  UnsupportedNetwork, LimitViolation, Section, validate_records,
  validate_against_caps, is_p2pkh_script, is_standard_output_script, hash160,
  p2pkh_hash, MAX_SCRIPT_SIZE, MAX_BIP44_ACCOUNT, MAX_BIP44_ADDRESS_INDEX,
  COIN_TYPE_MAINNET, COIN_TYPE_TESTNET, MIN_VERSION_PCZT,
  MIN_VERSION_IRONWOOD, MIN_VERSION_RAISED_BOUNDS, MAX_TRANSPARENT_OUTPUTS,
  MAX_DISPLAYED_SHIELDED_OUTPUTS, MAX_RETAINED_MEMO_BYTES,
  MEMO_HASH_DISPLAY_LEN}`; `DeviceBounds::{V3_9_2, V3_9_3, MOST_RESTRICTIVE,
  MOST_PERMISSIVE, for_caps, transparent_inputs, transparent_outputs,
  orchard_actions, ironwood_actions, displayed_shielded_outputs,
  retained_memo_bytes}`; `DeviceCaps::{from_version, version, pczt, ironwood,
  bounds}`; `Network::{coin_type, network_type}`;
  `UnsupportedNetwork::network_type`; `V5_TX_VERSION`,
  `V5_VERSION_GROUP_ID`, `V6_TX_VERSION` and `V6_VERSION_GROUP_ID`
  re-exported from `zcash_protocol::constants`.
- `pczt_ledger::plan::{Plan, GlobalFields, PlanError, MemoDisplay, build_plan,
  build_plan_with_keys, validate_plan, read_global, check_branch_id}`;
  `Plan::{stream, global, orchard_real_spends, ironwood_real_spends,
  missing_zip32, displayed_shielded_outputs, shielded_change_outputs,
  displayed_memos, format, displayed_count_is_exact}`;
  `GlobalFields::{tx_version, version_group_id, consensus_branch_id,
  fallback_lock_time, expiry_height, coin_type, tx_modifiable, format}`.
- `pczt_ledger::shape::{Shaped, ShapeParams, ShapeError, ChangeInfo,
  ChangeDeriveError, shape_for_device, derivation_account, ZIP32_PURPOSE,
  BIP44_PURPOSE, HARDENED, TRANSPARENT_EXTERNAL_SCOPE,
  TRANSPARENT_INTERNAL_SCOPE}`; `Shaped::{pczt, into_pczt, encoding_version}`;
  `ShapeParams::{new, with_seed_fingerprint, with_change, coin_type,
  zip32_account, seed_fingerprint, change, shielded_account_path,
  transparent_change_path}`; `ChangeInfo::{derive, output_index, pubkey,
  address_index}`; `hash160` and `p2pkh_hash` re-exported from
  `pczt_ledger::limits`.
- `pczt_ledger::pairing::{DeviceIdentity, InvalidDeviceIdentity, PairingError,
  VkExchange, VkStep, device_identity_path, device_identity_apdu,
  parse_device_identity_response, wallet_public_key_apdu,
  parse_wallet_public_key_response, firmware_version_apdu,
  parse_firmware_version_response, device_caps, shielded_account_path,
  transparent_account_path, transparent_address_path,
  transparent_external_address_path, unified_address_apdu,
  parse_unified_address, orchard_address_apdu, parse_orchard_address,
  DEVICE_IDENTITY_PERSONALIZATION, DEVICE_IDENTITY_PREFIX,
  DEVICE_UNIFIED_REVISION}`; `DeviceIdentity::{from_compressed_pubkey,
  from_wallet_public_key, as_bytes, parse}`; `VkExchange::{ufvk, orchard_fvk,
  next_apdu, process_response, next_deadline, is_complete, is_failed,
  is_awaiting_reply, bytes_received}`; `MAX_BIP44_ACCOUNT` and
  `MAX_BIP44_ADDRESS_INDEX` re-exported from `pczt_ledger::limits`.
- `pczt_ledger::session::{LedgerSignSession, SessionParams, SessionError,
  SessionStatus, PumpStep, Stage, UserAction, Deadline, SignOutcome,
  LedgerViolation, preflight, validate_for_ledger,
  validate_for_ledger_with_keys}`; `LedgerSignSession::{new, new_from_pczt,
  next_step, process_response, next_deadline, pending_user_action,
  is_past_review, stage, caps, device, plan, shaped_pczt, failure,
  is_restartable, finish}`; `SessionParams::{new, with_seed_fingerprint,
  with_change, with_transparent_account_key, with_viewing_keys,
  with_unknown_version_bounds, network, device, zip32_account,
  seed_fingerprint, change, transparent_account_key, viewing_keys,
  unknown_version_bounds}`; `SignOutcome::{pczt_with_sigs, orchard_sigs,
  ironwood_sigs, transparent_sigs}`; `Network`, `UnsupportedNetwork` and
  `MAX_CMD_NOT_ACCEPTED_RETRIES` re-exported from `pczt_ledger::limits` and
  `pczt_ledger::apdu`.
- `pczt_ledger::ceremony::{run_session, sign, query, CeremonyError,
  QueryError, CMD_NOT_ACCEPTED_BACKOFF}`.
- `pczt_ledger::apply::{apply_device_signatures,
  apply_device_signatures_to_bytes, stamp_hash160_preimages,
  normalize_ledger_der, DeviceSignatures, ApplyError}`;
  `DeviceSignatures::{new, orchard, ironwood, transparent}`.
- `pczt_ledger::viewing::{AccountViewingKeys, TransparentAccountKey,
  MEMO_SIZE}`; `AccountViewingKeys::{from_orchard_fvk, opens_as_change,
  recover_output}`; `TransparentAccountKey::{from_account_pubkey,
  account_pubkey, address_pubkey}`.
- `pczt_ledger::transport::{Transport, TransportError, DEFAULT_TIMEOUT}`;
  `pczt_ledger::transport::hid::{HidTransport, ledger_apdu_interfaces,
  LEDGER_USB_VENDOR_ID, LEDGER_HID_USAGE_PAGE}` behind the `transport-hid`
  feature, with `HidTransport::{open_first, open_first_with, from_device,
  with_timeout, set_timeout, timeout, channel, is_poisoned}`; and
  `pczt_ledger::transport::speculos::{SpeculosTransport, addr_from_env,
  addr_or_default, DEFAULT_SPECULOS_ADDR, SPECULOS_ADDR_ENV,
  MAX_RESPONSE_LEN}` behind `transport-speculos`, with
  `SpeculosTransport::{connect, connect_default, connect_from_env,
  with_timeout, set_timeout, timeout, is_poisoned}`.
- `Display` and `core::error::Error` for every error type; `Display` for
  `DeviceIdentity`, `Stage`, `Ins`, `Section`, `HidChannel` and
  `FirmwareVersion`; `FromStr` for `DeviceIdentity`; `TryFrom<NetworkType>`
  for `Network`; `From<PlanError>` for `ShapeError`; `From<DecodeError>` and
  `From<EncodeError>` for `PairingError`; `From<FramingError>` for
  `TransportError`; and `Transport` for `Box<T: Transport + ?Sized>`.
- Cargo features: `std` (default), `transport-hid` and `transport-speculos`,
  the latter two implying `std`. Without `std` the crate is `#![no_std]` with
  `alloc`: everything above but the `transport` and `ceremony` modules.
