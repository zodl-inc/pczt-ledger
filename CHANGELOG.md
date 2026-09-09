# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Initial release. `pczt_ledger` is the Signer step of the PCZT (ZIP 374) role
model for the Ledger embedded Zcash app: it turns a redacted PCZT into the
device's APDU stream, collects the detached signatures, and applies them back
onto the PCZT. Scope is transparent, Orchard and Ironwood (V6); Sapling is
refused. The wire contract is pinned to `LedgerHQ/app-zcash` `22dc385`
(v3.9.3), with v3.9.2 supported through runtime version gating. MSRV 1.88.

### Added
- `pczt_ledger::Network`, re-exported from `pczt_ledger::limits`.
- `pczt_ledger::apdu::{Apdu, ApduDataTooLong, Ins, StatusWord, StatusClass,
  Finish, chunk_command, pack_groups, chunk_bytes, CLA, MAX_APDU_DATA,
  MAX_CMD_NOT_ACCEPTED_RETRIES}` and the `p1` / `p2` constant modules.
- `pczt_ledger::apdu::encode::{HeaderRecord, TransparentInputRecord,
  TransparentOutputRecord, TransparentDerivation, ShieldedActionRecord,
  Zip32Derivation, BundleTrailerRecord, DerivationPath, StreamPlan,
  ShieldedPool, EncodeError}`; `header_apdu`, `transparent_input_groups`,
  `transparent_input_apdus`, `transparent_output_groups`,
  `transparent_output_apdus`, `shielded_action_groups`,
  `shielded_action_apdus`, `sign_transparent_apdu`, `sign_shielded_apdu`,
  `get_firmware_version_apdu`, `get_wallet_public_key_apdu`, `get_ufvk_apdu`,
  `get_orchard_fvk_apdu`, `get_vk_continue_apdu`, `get_unified_address_apdu`,
  `get_orchard_address_apdu`, `write_compact_size`, `write_optional_u32`, and
  the wire-size constants.
- `pczt_ledger::apdu::decode::{DecodeError, FirmwareVersion, WalletPublicKey,
  TransparentSignature, VkKind, VkResponse, VkReassembler}`;
  `split_status_word`, `expect_ok`, `parse_firmware_version`,
  `parse_wallet_public_key`, `parse_transparent_signature`,
  `parse_shielded_signature`, `parse_string_response`, and the reply-length
  constants.
- `pczt_ledger::framing::{Deframer, FramingError, hid_frames, ble_frames,
  ble_mtu_request, parse_ble_mtu_response, HEAD_TAG, HID_FRAME_SIZE, MTU_OP,
  STATUS_WORD_LEN}`.
- `pczt_ledger::limits::{DeviceBounds, DeviceCaps, Network,
  UnsupportedNetwork, LimitViolation, Section, validate_records,
  validate_plan, validate_against_caps, is_p2pkh_script,
  is_standard_output_script, hash160, p2pkh_hash}` and the version, bound and
  coin-type constants.
- `pczt_ledger::plan::{Plan, GlobalFields, PlanError, build_plan,
  build_plan_with_keys, read_global, is_v6_transaction, pczt_version_for}`.
- `pczt_ledger::shape::{shape_for_device, Shaped, ShapeParams, ShapeError,
  ChangeInfo, ChangeDeriveError, derivation_account, ZIP32_PURPOSE,
  BIP44_PURPOSE, TRANSPARENT_INTERNAL_SCOPE}`; `hash160` and `p2pkh_hash`
  re-exported from `pczt_ledger::limits`.
- `pczt_ledger::pairing::{DeviceIdentity, InvalidDeviceIdentity,
  PairingError, VkExchange, device_identity_path, device_identity_apdu,
  parse_device_identity_response, wallet_public_key_apdu,
  parse_wallet_public_key_response, firmware_version_apdu,
  parse_firmware_version_response, device_caps, shielded_account_path,
  transparent_account_path, transparent_address_path,
  transparent_external_address_path, unified_address_apdu,
  parse_unified_address, orchard_address_apdu, parse_orchard_address,
  MAX_BIP44_ADDRESS_INDEX, DEVICE_IDENTITY_PERSONALIZATION,
  DEVICE_IDENTITY_PREFIX}`.
- `pczt_ledger::session::{LedgerSignSession, SessionParams, SessionError,
  SessionStatus, PumpStep, Stage, UserAction, Deadline, SignOutcome,
  LedgerViolation, validate_for_ledger, validate_for_ledger_with_keys}`;
  `Network`, `UnsupportedNetwork` and `MAX_CMD_NOT_ACCEPTED_RETRIES`
  re-exported from `pczt_ledger::limits` and `pczt_ledger::apdu`.
- `pczt_ledger::ceremony::{run_session, sign, query, CeremonyError,
  QueryError}`.
- `pczt_ledger::apply::{apply_device_signatures,
  apply_device_signatures_to_bytes, stamp_hash160_preimages,
  normalize_ledger_der, DeviceSignatures, ApplyError}`.
- `pczt_ledger::viewing::AccountViewingKeys`.
- `pczt_ledger::transport::{Transport, TransportError, DEFAULT_TIMEOUT}`;
  `pczt_ledger::transport::hid::{HidTransport, LEDGER_USB_VENDOR_ID,
  LEDGER_HID_USAGE_PAGE}` behind the `transport-hid` feature, and
  `pczt_ledger::transport::speculos::{SpeculosTransport, addr_from_env,
  addr_or_default, frame_request, frame_reply, DEFAULT_SPECULOS_ADDR,
  SPECULOS_ADDR_ENV, MAX_RESPONSE_LEN}` behind `transport-speculos`.
