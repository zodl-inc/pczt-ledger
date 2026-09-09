use proptest::prelude::*;

use crate::apdu::decode::*;
use crate::framing::*;
use crate::test_support::arb_bytes;

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

#[test]
fn hid_golden_single_frame() {
    // `DefaultApduSenderService.test.ts`: channel 0x1234, APDU e0 01 00 00 00.
    let frames = hid_frames(HidChannel::new(0x1234), &[0xE0, 0x01, 0x00, 0x00, 0x00]).unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(
        &frames[0][..12],
        &[0x12, 0x34, 0x05, 0x00, 0x00, 0x00, 0x05, 0xE0, 0x01, 0x00, 0x00, 0x00]
    );
    // Padding is zeros, and it fills the whole report even for a lone frame.
    assert!(frames[0][12..].iter().all(|b| *b == 0x00));
    assert_eq!(frames[0].len(), 64);
}

#[test]
fn hid_golden_two_frames() {
    // 69 bytes = 0x45: 57 in frame 0 (64 - 7 header), 12 in frame 1.
    let apdu: Vec<u8> = (0..69).map(|i| i as u8).collect();
    let frames = hid_frames(HidChannel::new(0x1234), &apdu).unwrap();
    assert_eq!(frames.len(), 2);
    assert_eq!(&frames[0][..7], &[0x12, 0x34, 0x05, 0x00, 0x00, 0x00, 0x45]);
    assert_eq!(&frames[0][7..64], &apdu[..57]);
    assert_eq!(&frames[1][..5], &[0x12, 0x34, 0x05, 0x00, 0x01]);
    assert_eq!(&frames[1][5..17], &apdu[57..]);
    assert!(frames[1][17..].iter().all(|b| *b == 0x00));
}

#[test]
fn ble_golden_three_frames() {
    // `DefaultApduSenderService.test.ts`, "[BLE] Without padding nor channel":
    // frameSize 10, a 17-byte payload. Frame 0 holds 5 bytes (10 - 5 header),
    // the rest hold 7 (10 - 3), and the last frame is left short.
    let apdu = [
        0x01, 0x05, 0x4F, 0x4C, 0x4F, 0x53, 0x00, 0x07, 0x2E, 0x32, 0x2E, 0x34, 0x2D, 0x32, 0x00,
        0x90, 0x00,
    ];
    let frames = ble_frames(&apdu, BleFrameSize::new(10).unwrap()).unwrap();
    assert_eq!(
        frames,
        vec![
            vec![0x05, 0x00, 0x00, 0x00, 0x11, 0x01, 0x05, 0x4F, 0x4C, 0x4F],
            vec![0x05, 0x00, 0x01, 0x53, 0x00, 0x07, 0x2E, 0x32, 0x2E, 0x34],
            vec![0x05, 0x00, 0x02, 0x2D, 0x32, 0x00, 0x90, 0x00],
        ]
    );
}

#[test]
fn ble_golden_single_frame() {
    // frameSize 123 with a 5-byte APDU: one 10-byte frame, unpadded.
    let frames = ble_frames(
        &[0xE0, 0x01, 0x00, 0x00, 0x00],
        BleFrameSize::new(123).unwrap(),
    )
    .unwrap();
    assert_eq!(
        frames,
        vec![vec![
            0x05, 0x00, 0x00, 0x00, 0x05, 0xE0, 0x01, 0x00, 0x00, 0x00
        ]]
    );
}

#[test]
fn ble_frame_size_must_exceed_the_frame_zero_header() {
    assert_eq!(
        BleFrameSize::new(5),
        Err(FramingError::FrameSizeTooSmall { got: 5, min: 6 })
    );
    assert_eq!(BleFrameSize::MIN, 6);
    assert!(ble_frames(&[0x00], BleFrameSize::new(6).unwrap()).is_ok());
}

/// The frame-0 header declares the length in a `u16`; a longer APDU is
/// refused rather than declared modulo 65536.
#[test]
fn an_apdu_longer_than_a_frame_zero_can_declare_is_refused() {
    let longest = vec![0u8; 65_535];
    assert_eq!(
        hid_frames(HidChannel::new(0x0001), &longest).unwrap().len(),
        1 + (65_535 - 57usize).div_ceil(59)
    );
    let too_long = vec![0u8; 65_536];
    assert_eq!(
        hid_frames(HidChannel::new(0x0001), &too_long),
        Err(FramingError::ApduTooLong {
            got: 65_536,
            max: 65_535
        })
    );
    assert_eq!(
        ble_frames(&too_long, BleFrameSize::new(20).unwrap()),
        Err(FramingError::ApduTooLong {
            got: 65_536,
            max: 65_535
        })
    );
}

#[test]
fn empty_apdu_yields_no_frames() {
    assert!(hid_frames(HidChannel::new(0x0001), &[]).unwrap().is_empty());
    assert!(ble_frames(&[], BleFrameSize::new(64).unwrap())
        .unwrap()
        .is_empty());
}

#[test]
fn hid_round_trip() {
    // Lengths start at 2: the deframer reassembles *responses*, and a
    // response always carries at least its status word. 56/57/58 straddle the
    // 57-byte frame-0 capacity.
    for len in [2usize, 56, 57, 58, 200, 512, 1174] {
        let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let frames = hid_frames(HidChannel::new(0xBEEF), &payload).unwrap();

        let mut d = Deframer::hid(HidChannel::new(0xBEEF));
        let mut got = None;
        for f in &frames {
            if let Some(p) = d.push(f).unwrap() {
                got = Some(p);
            }
        }
        assert_eq!(got.as_deref(), Some(payload.as_slice()), "len {len}");
        assert!(d.is_idle());
    }
}

#[test]
fn ble_round_trip_at_common_mtus() {
    // 20 is the BLE 4.0 default ATT MTU, 153 the Ledger Nano X value, and 64
    // a common negotiated size.
    for mtu in [20usize, 153, 64] {
        for len in [2usize, 15, 16, 17, 100, 302, 1174] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let frames = ble_frames(&payload, BleFrameSize::new(mtu).unwrap()).unwrap();
            assert!(frames.iter().all(|f| f.len() <= mtu));

            let mut d = Deframer::ble();
            let mut got = None;
            for f in &frames {
                if let Some(p) = d.push(f).unwrap() {
                    got = Some(p);
                }
            }
            assert_eq!(
                got.as_deref(),
                Some(payload.as_slice()),
                "mtu {mtu}, len {len}"
            );
        }
    }
}

/// A HID deframer takes whole 64-byte reports only: a partial read would shift
/// every later frame's data, and a run of minimum-length continuation frames
/// would keep a reassembly alive forever. BLE frames are as long as their
/// data.
#[test]
fn deframer_refuses_a_partial_hid_report() {
    let payload: Vec<u8> = (0..150u32).map(|i| (i % 251) as u8).collect();
    let frames = hid_frames(HidChannel::new(0x0001), &payload).unwrap();

    let mut d = Deframer::hid(HidChannel::new(0x0001));
    assert_eq!(
        d.push(&frames[0][..47]),
        Err(FramingError::BadFrameLength {
            got: 47,
            expected: HID_FRAME_SIZE
        })
    );

    // A well-formed frame 0, then a bare 5-byte continuation header.
    let mut d = Deframer::hid(HidChannel::new(0x0001));
    assert_eq!(d.push(&frames[0]).unwrap(), None);
    assert_eq!(
        d.push(&[0x00, 0x01, 0x05, 0x00, 0x01]),
        Err(FramingError::BadFrameLength {
            got: 5,
            expected: HID_FRAME_SIZE
        })
    );

    // The same short frame is a legitimate BLE frame.
    let mut d = Deframer::ble();
    let ble = ble_frames(&payload, BleFrameSize::new(20).unwrap()).unwrap();
    assert!(
        ble.iter().any(|f| f.len() < 20),
        "the last BLE frame is short"
    );
    let mut got = None;
    for f in &ble {
        if let Some(p) = d.push(f).unwrap() {
            got = Some(p);
        }
    }
    assert_eq!(got.as_deref(), Some(payload.as_slice()));
}

/// The reassembly buffer holds what the device is sending — a viewing key, an
/// address — so the deframer's `Debug` shows its length, not its bytes.
#[test]
fn deframer_redacts_its_buffer_in_debug() {
    let payload: Vec<u8> = (0x41..0x41 + 150u8).collect();
    let frames = hid_frames(HidChannel::new(0x0001), &payload).unwrap();
    let mut d = Deframer::hid(HidChannel::new(0x0001));
    assert_eq!(d.push(&frames[0]).unwrap(), None);
    let shown = format!("{d:?}");
    assert!(shown.contains("buf: [57 bytes]"), "{shown}");
    assert!(!shown.contains("65, 66, 67"), "the buffer leaked: {shown}");
    assert!(shown.contains("channel: Some(\"0x0001\")"), "{shown}");
}

/// A frame on another channel is another host process's reply: it is skipped,
/// and the reassembly of this channel's reply is unaffected by it, whether it
/// arrives before or in the middle of it.
#[test]
fn deframer_skips_a_foreign_channel() {
    let theirs = hid_frames(HidChannel::new(0x0001), &[0x6A, 0x80]).unwrap();
    let payload: Vec<u8> = (0..150u32).map(|i| (i % 251) as u8).collect();
    let ours = hid_frames(HidChannel::new(0x0002), &payload).unwrap();
    assert_eq!(ours.len(), 3);

    let mut d = Deframer::hid(HidChannel::new(0x0002));
    assert_eq!(d.push(&theirs[0]).unwrap(), None, "before ours");
    assert_eq!(d.push(&ours[0]).unwrap(), None);
    assert_eq!(d.push(&theirs[0]).unwrap(), None, "in the middle of ours");
    assert_eq!(d.push(&ours[1]).unwrap(), None);
    assert_eq!(
        d.push(&ours[2]).unwrap().as_deref(),
        Some(payload.as_slice())
    );
}

#[test]
fn deframer_rejects_a_bad_tag() {
    let mut frame = hid_frames(HidChannel::new(0x0001), &[0x90, 0x00]).unwrap()[0];
    frame[2] = 0x06;
    let mut d = Deframer::hid(HidChannel::new(0x0001));
    assert_eq!(d.push(&frame), Err(FramingError::BadTag { got: 0x06 }));
}

#[test]
fn deframer_rejects_a_sequence_gap() {
    let payload: Vec<u8> = (0..200).map(|i| i as u8).collect();
    let frames = hid_frames(HidChannel::new(0x0001), &payload).unwrap();
    assert!(frames.len() >= 3);

    let mut d = Deframer::hid(HidChannel::new(0x0001));
    assert_eq!(d.push(&frames[0]).unwrap(), None);
    // Skipping frame 1 must not silently splice frame 2 in.
    assert_eq!(
        d.push(&frames[2]),
        Err(FramingError::UnexpectedSequence {
            expected: 1,
            got: 2
        })
    );
}

/// A refused frame poisons the deframer: later frames are refused too, so
/// a caller that keeps feeding cannot have a later reply spliced onto this
/// one's frame 0. `reset` lifts it.
#[test]
fn a_refused_frame_poisons_the_deframer_until_reset() {
    let a: Vec<u8> = vec![0xAA; 100];
    let b: Vec<u8> = vec![0xBB; 100];
    let a_frames = hid_frames(HidChannel::new(0x0001), &a).unwrap();
    let b_frames = hid_frames(HidChannel::new(0x0001), &b).unwrap();
    assert_eq!(a_frames.len(), 2);

    let mut d = Deframer::hid(HidChannel::new(0x0001));
    assert_eq!(d.push(&a_frames[0]).unwrap(), None);
    // A new reply's frame 0 mid-reply is refused...
    let refusal = FramingError::UnexpectedSequence {
        expected: 1,
        got: 0,
    };
    assert_eq!(d.push(&b_frames[0]), Err(refusal.clone()));
    assert!(!d.is_idle());
    assert_eq!(d.poisoned(), Some(&refusal));
    // ...and so is everything after it, including what would have completed
    // the splice.
    assert_eq!(
        d.push(&b_frames[1]),
        Err(FramingError::Poisoned {
            source: Box::new(refusal.clone())
        })
    );
    assert_eq!(
        d.push(&a_frames[1]),
        Err(FramingError::Poisoned {
            source: Box::new(refusal)
        })
    );

    d.reset();
    assert!(d.is_idle());
    assert_eq!(d.poisoned(), None);
    assert_eq!(d.push(&b_frames[0]).unwrap(), None);
    assert_eq!(d.push(&b_frames[1]).unwrap().as_deref(), Some(b.as_slice()));
}

/// BLE frames are unpadded, so data past the declared length is not padding
/// and is refused; on HID the same excess is the report's padding.
#[test]
fn a_ble_reply_with_more_data_than_declared_is_refused() {
    // Declares 4 bytes, carries 8.
    let frame = [0x05, 0x00, 0x00, 0x00, 0x04, 1, 2, 3, 4, 5, 6, 7, 8];
    let mut d = Deframer::ble();
    assert_eq!(
        d.push(&frame),
        Err(FramingError::Overrun {
            declared: 4,
            got: 8
        })
    );
    assert_eq!(
        d.poisoned(),
        Some(&FramingError::Overrun {
            declared: 4,
            got: 8
        })
    );

    // Split across frames, the overrun is caught on the frame that crosses.
    let mut d = Deframer::ble();
    assert_eq!(
        d.push(&[0x05, 0x00, 0x00, 0x00, 0x04, 1, 2, 3]).unwrap(),
        None
    );
    assert_eq!(
        d.push(&[0x05, 0x00, 0x01, 4, 5]),
        Err(FramingError::Overrun {
            declared: 4,
            got: 5
        })
    );

    // Exactly the declared length completes.
    let mut d = Deframer::ble();
    assert_eq!(
        d.push(&[0x05, 0x00, 0x00, 0x00, 0x04, 1, 2, 3, 4])
            .unwrap()
            .as_deref(),
        Some(&[1u8, 2, 3, 4][..])
    );

    // HID: the same excess is padding.
    let mut frame = [0u8; HID_FRAME_SIZE];
    frame[..12].copy_from_slice(&[0x00, 0x01, 0x05, 0x00, 0x00, 0x00, 0x04, 1, 2, 3, 4, 5]);
    let mut d = Deframer::hid(HidChannel::new(0x0001));
    assert_eq!(
        d.push(&frame).unwrap().as_deref(),
        Some(&[1u8, 2, 3, 4][..])
    );
}

/// The overrun is refused before the frame's bytes are appended: a BLE
/// frame 0 reserves the declared length and no more, so a buffer grown past
/// it would reallocate and leave the reply bytes already accumulated in a
/// freed block, which is what that reservation exists to prevent.
#[test]
fn an_overrunning_ble_frame_is_refused_before_it_grows_the_buffer() {
    let mut d = Deframer::ble();
    // Declares 4 bytes and carries 3, so the reservation is exactly 4 and
    // three of them are reply bytes in it.
    assert_eq!(
        d.push(&[0x05, 0x00, 0x00, 0x00, 0x04, 1, 2, 3]).unwrap(),
        None
    );
    let reserved = d.buf.capacity();
    assert_eq!(
        d.push(&[0x05, 0x00, 0x01, 4, 5]),
        Err(FramingError::Overrun {
            declared: 4,
            got: 5
        })
    );
    assert!(
        d.buf.len() <= 4,
        "the overrunning frame was not appended: {} bytes",
        d.buf.len()
    );
    assert_eq!(d.buf.capacity(), reserved, "the buffer did not reallocate");
}

/// A BLE continuation frame may carry no data, so a device could keep a
/// reassembly alive for ever; the index is bounded and the reply is refused
/// when it runs out, rather than wrapping to a frame 0 that would replace
/// the declared length.
#[test]
fn a_reply_of_more_frames_than_the_index_can_count_is_refused() {
    let mut d = Deframer::ble();
    // Declares 10 bytes and carries none.
    assert_eq!(d.push(&[0x05, 0x00, 0x00, 0x00, 0x0A]).unwrap(), None);
    for index in 1..u16::MAX {
        let [hi, lo] = index.to_be_bytes();
        assert_eq!(d.push(&[0x05, hi, lo]).unwrap(), None, "frame {index}");
    }
    assert_eq!(
        d.push(&[0x05, 0xFF, 0xFF]),
        Err(FramingError::TooManyFrames { max: u16::MAX })
    );
    assert!(d.poisoned().is_some());
}

/// A BLE frame shorter than its header is refused as such: the tag and the
/// index need three bytes, and a frame 0 the two length bytes as well. On HID
/// the same bytes are a partial report, refused before the header is read.
#[test]
fn a_ble_frame_shorter_than_its_header_is_refused() {
    let mut d = Deframer::ble();
    assert_eq!(
        d.push(&[0x05, 0x00]),
        Err(FramingError::FrameTooShort { got: 2, need: 3 })
    );
    let mut d = Deframer::ble();
    assert_eq!(
        d.push(&[0x05, 0x00, 0x00, 0x00]),
        Err(FramingError::FrameTooShort { got: 4, need: 5 })
    );
    let mut d = Deframer::hid(HidChannel::new(0x0001));
    assert_eq!(
        d.push(&[0x00, 0x01, 0x05, 0x00]),
        Err(FramingError::BadFrameLength {
            got: 4,
            expected: HID_FRAME_SIZE
        })
    );
}

#[test]
fn deframer_rejects_a_continuation_with_nothing_pending() {
    let payload: Vec<u8> = (0..200).map(|i| i as u8).collect();
    let frames = hid_frames(HidChannel::new(0x0001), &payload).unwrap();
    let mut d = Deframer::hid(HidChannel::new(0x0001));
    assert_eq!(d.push(&frames[1]), Err(FramingError::OutOfOrderFrame));
}

#[test]
fn deframer_rejects_a_response_too_short_for_a_status_word() {
    let frames = hid_frames(HidChannel::new(0x0001), &[0x90]).unwrap();
    let mut d = Deframer::hid(HidChannel::new(0x0001));
    assert_eq!(
        d.push(&frames[0]),
        Err(FramingError::DeclaredLengthTooShort { got: 1 })
    );
}

#[test]
fn deframer_reset_clears_a_partial_response() {
    let payload: Vec<u8> = (0..200).map(|i| i as u8).collect();
    let frames = hid_frames(HidChannel::new(0x0001), &payload).unwrap();
    let mut d = Deframer::hid(HidChannel::new(0x0001));
    d.push(&frames[0]).unwrap();
    assert!(!d.is_idle());
    d.reset();
    assert!(d.is_idle());
}

#[test]
fn ble_mtu_handshake() {
    assert_eq!(ble_mtu_request(), [0x08, 0x00, 0x00, 0x00, 0x00]);

    // DMK's own fixture, `08 00 00 00 00 20`.
    assert_eq!(
        parse_ble_mtu_response(&[0x08, 0, 0, 0, 0, 0x20])
            .unwrap()
            .get(),
        32
    );
    // What a real device sends: a declared 1-byte payload.
    assert_eq!(
        parse_ble_mtu_response(&[0x08, 0, 0, 0, 1, 0x99])
            .unwrap()
            .get(),
        153
    );
    // A size the framer could not use is refused here, as that.
    assert_eq!(
        parse_ble_mtu_response(&[0x08, 0, 0, 0, 1, 0x05]),
        Err(FramingError::FrameSizeTooSmall { got: 5, min: 6 })
    );

    assert_eq!(
        parse_ble_mtu_response(&[0x08, 0, 0, 0, 1]),
        Err(FramingError::BadMtuResponse)
    );
    assert_eq!(
        parse_ble_mtu_response(&[0x05, 0, 0, 0, 1, 0x99]),
        Err(FramingError::BadMtuResponse)
    );
    assert_eq!(
        parse_ble_mtu_response(&[0x08, 0, 0, 0, 1, 0x00]),
        Err(FramingError::BadMtuResponse)
    );
}

#[test]
fn a_response_declares_its_status_word_in_its_length() {
    // Framing a response is framing `data || SW`, so the declared length is
    // two more than the data — which is how `DefaultApduReceiverService`
    // reads it back.
    let mut response = vec![0x38, 0x30, 3, 9, 2, 1, 0, 3];
    response.extend_from_slice(&[0x90, 0x00]);

    let frames = hid_frames(HidChannel::new(0x0001), &response).unwrap();
    let mut d = Deframer::hid(HidChannel::new(0x0001));
    let payload = d.push(&frames[0]).unwrap().unwrap();
    assert_eq!(payload.len(), 10);

    let data = expect_ok(&payload).unwrap();
    assert_eq!(parse_firmware_version(data).unwrap().to_string(), "3.9.2");
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

/// A response payload as the deframer sees it: data plus status word, so at
/// least two bytes. 1500 covers the longest reply the crate reassembles
/// ([`MAX_VK_RESPONSE_LEN`]) with room over.
fn arb_payload() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 2..=1500)
}

/// Every BLE frame size the MTU handshake can name and the framer accepts:
/// the handshake carries a byte, and a frame-0 header is five bytes.
fn arb_ble_frame_size() -> impl Strategy<Value = usize> {
    6usize..=255
}

/// A 64-byte report that is structurally plausible more often than random
/// bytes would be: the channel and tag are each right half the time.
fn arb_hid_report(channel: u16) -> impl Strategy<Value = Vec<u8>> {
    (
        any::<bool>(),
        any::<bool>(),
        any::<u16>(),
        prop::collection::vec(any::<u8>(), HID_FRAME_SIZE - 5),
    )
        .prop_map(move |(channel_ok, tag_ok, index, rest)| {
            let mut report = Vec::with_capacity(HID_FRAME_SIZE);
            report.extend_from_slice(&if channel_ok { channel } else { !channel }.to_be_bytes());
            report.push(if tag_ok { HEAD_TAG } else { HEAD_TAG ^ 0x40 });
            report.extend_from_slice(&index.to_be_bytes());
            report.extend_from_slice(&rest);
            report
        })
}

proptest! {
    /// Every payload length and channel frames into whole 64-byte reports and
    /// reassembles to the same bytes, with each frame completing nothing
    /// until the last; the frame count matches the header arithmetic (57
    /// data bytes in frame 0, 59 in each continuation).
    #[test]
    fn hid_frames_round_trip(payload in arb_payload(), channel in any::<u16>()) {
        let channel = HidChannel::new(channel);
        let frames = hid_frames(channel, &payload).unwrap();
        let expected_frames = 1 + payload
            .len()
            .saturating_sub(HID_FRAME_SIZE - 7)
            .div_ceil(HID_FRAME_SIZE - 5);
        prop_assert_eq!(frames.len(), expected_frames);

        let mut d = Deframer::hid(channel);
        for (i, f) in frames.iter().enumerate() {
            let got = d.push(f);
            prop_assert!(got.is_ok(), "frame {i}: {:?}", got);
            let got = got.unwrap();
            if i + 1 < frames.len() {
                prop_assert!(got.is_none(), "frame {i} completed early");
            } else {
                prop_assert_eq!(got.as_deref(), Some(payload.as_slice()));
            }
        }
        prop_assert!(d.is_idle());
    }

    /// The same for BLE at every frame size the handshake can negotiate: no
    /// frame exceeds the size, frame-0 carries `size - 5` bytes and each
    /// continuation `size - 3`.
    #[test]
    fn ble_frames_round_trip(payload in arb_payload(), frame_size in arb_ble_frame_size()) {
        let frames = ble_frames(&payload, BleFrameSize::new(frame_size).unwrap());
        prop_assert!(frames.is_ok(), "{:?}", frames);
        let frames = frames.unwrap();
        prop_assert!(frames.iter().all(|f| f.len() <= frame_size));
        let expected_frames = 1 + payload
            .len()
            .saturating_sub(frame_size - 5)
            .div_ceil(frame_size - 3);
        prop_assert_eq!(frames.len(), expected_frames);

        let mut d = Deframer::ble();
        for (i, f) in frames.iter().enumerate() {
            let got = d.push(f);
            prop_assert!(got.is_ok(), "frame {i}: {:?}", got);
            let got = got.unwrap();
            if i + 1 < frames.len() {
                prop_assert!(got.is_none(), "frame {i} completed early");
            } else {
                prop_assert_eq!(got.as_deref(), Some(payload.as_slice()));
            }
        }
        prop_assert!(d.is_idle());
    }

    /// A frame size that cannot hold a frame-0 header and one byte is refused
    /// where it is made, before any frame is built.
    #[test]
    fn ble_frame_size_below_the_header_is_refused(frame_size in 0usize..=5) {
        prop_assert_eq!(
            BleFrameSize::new(frame_size),
            Err(FramingError::FrameSizeTooSmall { got: frame_size, min: 6 })
        );
    }

    /// Flipping any bit of any header byte — channel, tag, index or declared
    /// length, in any frame — never lets the original payload through: the
    /// reassembly fails, skips the frame, or produces something else.
    #[test]
    fn a_corrupted_hid_header_never_yields_the_original(
        payload in arb_payload(),
        channel in any::<u16>(),
        frame_pick in any::<prop::sample::Index>(),
        byte_pick in 0usize..7,
        mask in 1u8..=255,
    ) {
        let channel = HidChannel::new(channel);
        let mut frames = hid_frames(channel, &payload).unwrap();
        let i = frame_pick.index(frames.len());
        let header = if i == 0 { 7 } else { 5 };
        frames[i][byte_pick % header] ^= mask;

        let mut d = Deframer::hid(channel);
        for f in &frames {
            if let Ok(Some(p)) = d.push(f) {
                prop_assert_ne!(p, payload.clone(), "frame {} corrupted at byte {}", i, byte_pick);
            }
        }
    }

    /// The BLE counterpart: tag, index or declared length.
    #[test]
    fn a_corrupted_ble_header_never_yields_the_original(
        payload in arb_payload(),
        frame_size in arb_ble_frame_size(),
        frame_pick in any::<prop::sample::Index>(),
        byte_pick in 0usize..5,
        mask in 1u8..=255,
    ) {
        let mut frames = ble_frames(&payload, BleFrameSize::new(frame_size).unwrap()).unwrap();
        let i = frame_pick.index(frames.len());
        let header = if i == 0 { 5 } else { 3 };
        frames[i][byte_pick % header] ^= mask;

        let mut d = Deframer::ble();
        for f in &frames {
            if let Ok(Some(p)) = d.push(f) {
                prop_assert_ne!(p, payload.clone(), "frame {} corrupted at byte {}", i, byte_pick);
            }
        }
    }

    /// Any sequence of arbitrary frames is answered, never panicked on, by a
    /// deframer of either kind — including reports of every length but the
    /// one HID accepts.
    #[test]
    fn deframers_never_panic(
        frames in prop::collection::vec(arb_bytes(80), 0..=8),
        channel in any::<u16>(),
    ) {
        let mut hid = Deframer::hid(HidChannel::new(channel));
        let mut ble = Deframer::ble();
        let mut hid_poisoned = false;
        for f in &frames {
            let hid_result = hid.push(f);
            if hid_poisoned {
                prop_assert!(matches!(hid_result, Err(FramingError::Poisoned { .. })), "{:?}", hid_result);
            } else if f.len() != HID_FRAME_SIZE {
                prop_assert_eq!(
                    hid_result,
                    Err(FramingError::BadFrameLength { got: f.len(), expected: HID_FRAME_SIZE })
                );
            }
            hid_poisoned = hid.poisoned().is_some();
            let _ = ble.push(f);
        }
    }

    /// Whole reports with plausible headers, the shape a confused or hostile
    /// device would actually send.
    #[test]
    fn hid_deframer_never_panics_on_plausible_reports(
        channel in any::<u16>(),
        reports in prop::collection::vec(arb_hid_report(0xBEEF), 0..=8),
    ) {
        let mut d = Deframer::hid(HidChannel::new(if channel == 0 { 0xBEEF } else { channel }));
        for r in &reports {
            let _ = d.push(r);
        }
        let mut d = Deframer::hid(HidChannel::new(0xBEEF));
        for r in &reports {
            let _ = d.push(r);
        }
    }

    /// `parse_ble_mtu_response` accepts exactly what `WebBleApduSender.ts`
    /// accepts: six bytes or more, the MTU opcode first, a non-zero size at
    /// index 5, and nothing checked in between.
    #[test]
    fn ble_mtu_response_spec(resp in arb_bytes(12), stamp in any::<bool>()) {
        let mut resp = resp;
        if stamp && !resp.is_empty() {
            resp[0] = MTU_OP;
        }
        let expected = if resp.len() >= 6 && resp[0] == MTU_OP && resp[5] != 0 {
            BleFrameSize::new(usize::from(resp[5]))
        } else {
            Err(FramingError::BadMtuResponse)
        };
        prop_assert_eq!(parse_ble_mtu_response(&resp), expected);
    }
}
