use crate::apdu::encode::*;
use crate::apdu::*;

// ---------------------------------------------------------------------------
// Chunker
// ---------------------------------------------------------------------------

#[test]
fn chunk_bytes_empty_yields_one_empty_piece() {
    // A command always occupies at least one packet, even with no payload.
    let chunks = chunk_bytes(&[]);
    assert_eq!(chunks.len(), 1);
    assert!(chunks[0].is_empty());
}

#[test]
fn chunk_bytes_exactly_255_is_one_piece() {
    let data = vec![0xAA; 255];
    let chunks = chunk_bytes(&data);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].len(), 255);
}

#[test]
fn chunk_bytes_256_splits_255_plus_1() {
    let data = vec![0xAA; 256];
    let chunks = chunk_bytes(&data);
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].len(), 255);
    assert_eq!(chunks[1].len(), 1);
}

#[test]
fn chunk_bytes_multi_chunk_lengths() {
    let data = vec![0xAA; 583]; // an `enc_ciphertext` group: 3 + 580.
    let chunks = chunk_bytes(&data);
    assert_eq!(
        chunks.iter().map(|c| c.len()).collect::<Vec<_>>(),
        vec![255, 255, 73]
    );
}

#[test]
fn single_packet_command_uses_p1_first_not_p1_last() {
    // `docs/PCZT_APDU.md`: "A one-packet command uses `P1_FIRST`."
    let apdus = chunk_command(Ins::PcztOrchardAction, &[vec![0x00]], Finish::Continue);
    assert_eq!(apdus.len(), 1);
    assert_eq!(apdus[0].p1(), p1::FIRST);
    assert_eq!(apdus[0].p2(), p2::PCZT_CONTINUE);
}

#[test]
fn two_packet_command_is_first_then_last() {
    let apdus = chunk_command(
        Ins::PcztTransparentInput,
        &[vec![0x11; 256]],
        Finish::Continue,
    );
    assert_eq!(apdus.len(), 2);
    assert_eq!(apdus[0].p1(), p1::FIRST);
    assert_eq!(apdus[1].p1(), p1::LAST);
}

#[test]
fn many_packet_command_is_first_next_last() {
    let apdus = chunk_command(
        Ins::PcztOrchardAction,
        &[vec![0x22; 1000]],
        Finish::Continue,
    );
    // 1000 = 255 * 3 + 235
    assert_eq!(apdus.len(), 4);
    assert_eq!(
        apdus.iter().map(|a| a.p1()).collect::<Vec<_>>(),
        vec![p1::FIRST, p1::NEXT, p1::NEXT, p1::LAST]
    );
}

#[test]
fn finished_marker_lands_only_on_the_last_packet() {
    let apdus = chunk_command(
        Ins::PcztIronwoodAction,
        &[vec![0x33; 600]],
        Finish::Finished,
    );
    assert_eq!(apdus.len(), 3);
    assert_eq!(apdus[0].p2(), p2::PCZT_CONTINUE);
    assert_eq!(apdus[1].p2(), p2::PCZT_CONTINUE);
    assert_eq!(apdus[2].p2(), p2::PCZT_FINISHED);
}

#[test]
fn finished_marker_on_a_single_packet_command() {
    // The empty-Ironwood-bundle case: the count packet is the whole command,
    // so it carries both `P1_FIRST` and `P2_PCZT_FINISHED`.
    let apdus = shielded_action_apdus(ShieldedPool::Ironwood, &[], None, Finish::Finished).unwrap();
    assert_eq!(apdus.len(), 1);
    assert_eq!(apdus[0].data(), [0x00]);
    assert_eq!(apdus[0].p1(), p1::FIRST);
    assert_eq!(apdus[0].p2(), p2::PCZT_FINISHED);
    assert_eq!(apdus[0].ins(), Ins::PcztIronwoodAction.code());
}

#[test]
fn groups_never_share_a_packet() {
    // Two 10-byte groups would fit in one 255-byte packet, but the device's
    // parser asserts the reader is drained at each group boundary.
    let packets = pack_groups(&[vec![0xAA; 10], vec![0xBB; 10]]);
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].len(), 10);
    assert_eq!(packets[1].len(), 10);
}

// ---------------------------------------------------------------------------
// Status words
// ---------------------------------------------------------------------------

#[test]
fn status_word_mapping_round_trips() {
    for sw in [
        StatusWord::Ok,
        StatusWord::Deny,
        StatusWord::ConditionsOfUseNotSatisfied,
        StatusWord::IncorrectData,
        StatusWord::NotEnoughMemorySpace,
        StatusWord::WrongApduLength,
        StatusWord::WrongP1P2,
        StatusWord::InsNotSupported,
        StatusWord::ClaNotSupported,
        StatusWord::SecurityStatusNotSatisfied,
        StatusWord::TechnicalProblem,
        StatusWord::VersionParsingFail,
        StatusWord::TxParsingFail,
        StatusWord::RngFailure,
        StatusWord::MemoryProblem,
        StatusWord::BadState,
        StatusWord::CmdNotAccepted,
        StatusWord::DeviceLocked,
        StatusWord::AppPanicked,
    ] {
        assert_eq!(StatusWord::from_u16(sw.to_u16()), sw);
    }
}

#[test]
fn status_word_numeric_values_match_app_sw() {
    // `enum AppSW` in `src/main.rs`.
    assert_eq!(StatusWord::Ok.to_u16(), 0x9000);
    assert_eq!(StatusWord::Deny.to_u16(), 0x6985);
    assert_eq!(StatusWord::ConditionsOfUseNotSatisfied.to_u16(), 0x6986);
    assert_eq!(StatusWord::IncorrectData.to_u16(), 0x6A80);
    assert_eq!(StatusWord::NotEnoughMemorySpace.to_u16(), 0x6A84);
    assert_eq!(StatusWord::WrongApduLength.to_u16(), 0x6700);
    assert_eq!(StatusWord::WrongP1P2.to_u16(), 0x6B00);
    assert_eq!(StatusWord::InsNotSupported.to_u16(), 0x6D00);
    assert_eq!(StatusWord::ClaNotSupported.to_u16(), 0x6E00);
    assert_eq!(StatusWord::TechnicalProblem.to_u16(), 0x6F00);
    assert_eq!(StatusWord::VersionParsingFail.to_u16(), 0x6F01);
    assert_eq!(StatusWord::TxParsingFail.to_u16(), 0x6F02);
    // New in v3.9.3.
    assert_eq!(StatusWord::RngFailure.to_u16(), 0x6F03);
    assert_eq!(StatusWord::MemoryProblem.to_u16(), 0x9240);
    assert_eq!(StatusWord::BadState.to_u16(), 0xB007);
    // Not from `enum AppSW` at all: the device SDK's legacy I/O layer raises
    // it (`docs/APDU.md` @ `22dc385`).
    assert_eq!(StatusWord::CmdNotAccepted.to_u16(), 0x6901);
    // Nor these two: `StatusWords::DeviceLocked` and `StatusWords::Panic`
    // in `ledger_device_sdk` 1.37.0, `src/io_legacy.rs`.
    assert_eq!(StatusWord::DeviceLocked.to_u16(), 0x5515);
    assert_eq!(StatusWord::AppPanicked.to_u16(), 0xE000);
    // The SDK's `NothingReceived`, which the app aliases and never emits.
    assert_eq!(StatusWord::SecurityStatusNotSatisfied.to_u16(), 0x6982);
}

#[test]
fn status_word_classification() {
    assert_eq!(StatusWord::Ok.class(), StatusClass::Ok);
    // 0x6985 is user denial in this app, not "conditions of use".
    assert_eq!(StatusWord::Deny.class(), StatusClass::UserCancel);
    assert_eq!(StatusWord::ClaNotSupported.class(), StatusClass::WrongApp);
    assert_eq!(StatusWord::InsNotSupported.class(), StatusClass::WrongApp);
    assert_eq!(
        StatusWord::ConditionsOfUseNotSatisfied.class(),
        StatusClass::Fatal
    );
    assert_eq!(StatusWord::BadState.class(), StatusClass::Fatal);
    // A hardware RNG failure is fatal, and no retry on the same device helps.
    assert_eq!(StatusWord::RngFailure.class(), StatusClass::Fatal);
    assert!(!StatusWord::RngFailure.is_retriable());
    assert_eq!(StatusWord::Unknown(0x1234).class(), StatusClass::Fatal);
    // The SDK's own two: a locked device clears on unlocking, a panicked app
    // is gone.
    assert_eq!(StatusWord::DeviceLocked.class(), StatusClass::Fatal);
    assert!(StatusWord::DeviceLocked.is_transient());
    assert_eq!(StatusWord::AppPanicked.class(), StatusClass::Fatal);
    assert!(!StatusWord::AppPanicked.is_transient());
    // Never emitted, and no longer read as "device locked".
    assert!(!StatusWord::SecurityStatusNotSatisfied.is_transient());

    // `0x6901` is the one frame-level refusal: the app never saw the command,
    // so its transaction context is intact and the same APDU can go again.
    assert_eq!(StatusWord::CmdNotAccepted.class(), StatusClass::Retriable);
    assert!(StatusWord::CmdNotAccepted.is_retriable());

    // Everything else stays non-retriable: any non-`0x9000` reply the *app*
    // produces has already reset its tx context.
    for sw in [
        StatusWord::Deny,
        StatusWord::BadState,
        StatusWord::IncorrectData,
        StatusWord::NotEnoughMemorySpace,
        StatusWord::Unknown(0x1234),
    ] {
        assert!(!sw.is_retriable());
    }
}

/// Every status word, and the class each is handled as.
#[test]
fn every_status_word_has_a_class() {
    let table: [(StatusWord, StatusClass); 18] = [
        (StatusWord::Ok, StatusClass::Ok),
        (StatusWord::Deny, StatusClass::UserCancel),
        (StatusWord::ConditionsOfUseNotSatisfied, StatusClass::Fatal),
        (StatusWord::IncorrectData, StatusClass::Fatal),
        (StatusWord::NotEnoughMemorySpace, StatusClass::Fatal),
        (StatusWord::WrongApduLength, StatusClass::Fatal),
        (StatusWord::WrongP1P2, StatusClass::Fatal),
        (StatusWord::InsNotSupported, StatusClass::WrongApp),
        (StatusWord::ClaNotSupported, StatusClass::WrongApp),
        (StatusWord::SecurityStatusNotSatisfied, StatusClass::Fatal),
        (StatusWord::TechnicalProblem, StatusClass::Fatal),
        (StatusWord::VersionParsingFail, StatusClass::Fatal),
        (StatusWord::TxParsingFail, StatusClass::Fatal),
        (StatusWord::RngFailure, StatusClass::Fatal),
        (StatusWord::MemoryProblem, StatusClass::Fatal),
        (StatusWord::BadState, StatusClass::Fatal),
        (StatusWord::CmdNotAccepted, StatusClass::Retriable),
        (StatusWord::Unknown(0x1234), StatusClass::Fatal),
    ];
    for (word, class) in table {
        assert_eq!(word.class(), class, "{word:?}");
        // The numeric mapping round-trips for every named word.
        if !matches!(word, StatusWord::Unknown(_)) {
            assert_eq!(StatusWord::from_u16(word.to_u16()), word);
        }
    }
}

/// Which refusals a *fresh* stream of the same bytes could get past: the
/// device-state words, and none of the deterministic ones. `0x6F00` is on
/// the deterministic side: the derivation drain behind it lasts until a
/// power cycle, and its other emitters are functions of the input.
#[test]
fn status_word_transience() {
    for sw in [
        StatusWord::MemoryProblem,
        StatusWord::BadState,
        StatusWord::DeviceLocked,
        StatusWord::CmdNotAccepted,
    ] {
        assert!(sw.is_transient(), "{sw:?}");
    }
    for sw in [
        StatusWord::Ok,
        StatusWord::Deny,
        StatusWord::ConditionsOfUseNotSatisfied,
        StatusWord::IncorrectData,
        StatusWord::NotEnoughMemorySpace,
        StatusWord::WrongApduLength,
        StatusWord::WrongP1P2,
        StatusWord::InsNotSupported,
        StatusWord::ClaNotSupported,
        StatusWord::SecurityStatusNotSatisfied,
        StatusWord::TechnicalProblem,
        StatusWord::VersionParsingFail,
        StatusWord::TxParsingFail,
        StatusWord::RngFailure,
        StatusWord::AppPanicked,
        StatusWord::Unknown(0x1234),
    ] {
        assert!(!sw.is_transient(), "{sw:?}");
    }
}

// ---------------------------------------------------------------------------
// Constructor bounds
// ---------------------------------------------------------------------------

#[test]
fn an_apdu_with_over_long_data_cannot_be_constructed() {
    assert_eq!(
        Apdu::try_new(Ins::PcztHeader, 0, 0, vec![0; MAX_APDU_DATA + 1]).map_err(|e| e.got()),
        Err(MAX_APDU_DATA + 1),
    );
    let apdu = Apdu::try_new(Ins::PcztHeader, 0, 0, vec![0; MAX_APDU_DATA]).expect("at the bound");
    assert_eq!(apdu.data().len(), MAX_APDU_DATA);
}
