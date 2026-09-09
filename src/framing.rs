//! Ledger transport framing: HID 64-byte reports and BLE frames.
//!
//! Ported from `LedgerHQ/device-sdk-ts`, `packages/device-management-kit`:
//!
//! - `src/api/device-session/data/FramerConst.ts` — `HEAD_TAG = 0x05`,
//!   `HEAD_TAG_LENGTH = 1`, `CHANNEL_LENGTH = 2`, `INDEX_LENGTH = 2`,
//!   `APDU_DATA_LENGTH_LENGTH = 2`.
//! - `src/internal/device-session/model/FrameHeader.ts` (`getRawData`) — the
//!   header field order.
//! - `src/internal/device-session/service/DefaultApduSenderService.ts` — the
//!   per-frame arithmetic and the padding rule.
//! - `src/internal/device-session/service/DefaultApduReceiverService.ts` — the
//!   reassembly rule.
//! - `packages/transport/web-hid/src/api/data/WebHidConfig.ts` —
//!   `FRAME_SIZE = 64`; `WebHidApduSender.ts` — HID uses a random 2-byte
//!   channel and `padding: true`.
//! - `packages/transport/web-ble/src/api/transport/WebBleApduSender.ts` — BLE
//!   passes only `frameSize`, so it has no channel and no padding, and
//!   `MTU_OP = 0x08` with the frame size at byte 5 of the response.
//!
//! # Frame layout
//!
//! ```text
//! [channel u16 BE]?  tag(0x05)  seq u16 BE  [total_len u16 BE]?  data...
//!                                            ^ frame 0 only
//! ```
//!
//! HID carries the channel and pads every frame to 64 bytes with `0x00`; BLE
//! carries no channel and leaves the last frame short.
//!
//! # Deliberate divergence from DMK
//!
//! `DefaultApduReceiverService` does **not** compare the channel, does **not**
//! check the tag, and checks the sequence only for "is it zero". This module
//! validates all three, as the older `@ledgerhq/devices` `hid-framing` does.
//! A frame rejected here is one DMK would have silently spliced into the
//! response, so the stricter behaviour can only prevent a corrupt reassembly —
//! but it *is* a behavioural difference, and callers that need bug-for-bug
//! parity should note it.

/// `HEAD_TAG` — the tag byte on every data frame, HID and BLE alike.
pub const HEAD_TAG: u8 = 0x05;
/// `FRAME_SIZE` for USB HID: one 64-byte report.
///
/// This excludes the leading report-ID byte, which the HID layer adds
/// separately (`NodeHidApduSender.ts` prepends `0x00`; WebHID passes the
/// report ID to `sendReport`).
pub const HID_FRAME_SIZE: usize = 64;
/// `MTU_OP` — the BLE MTU-handshake tag.
pub const MTU_OP: u8 = 0x08;
/// Bytes of status word at the end of a device response.
pub const STATUS_WORD_LEN: usize = 2;

const CHANNEL_LENGTH: usize = 2;
const HEAD_TAG_LENGTH: usize = 1;
const INDEX_LENGTH: usize = 2;
const APDU_DATA_LENGTH_LENGTH: usize = 2;

/// Header size for frame `index`, given whether the transport carries a
/// channel.
///
/// `DefaultApduSenderService.getFrameHeaderSizeFromIndex`:
/// `channel? + INDEX_LENGTH + HEAD_TAG_LENGTH + (index == 0 ? 2 : 0)`.
const fn header_size(with_channel: bool, index: usize) -> usize {
    (if with_channel { CHANNEL_LENGTH } else { 0 })
        + INDEX_LENGTH
        + HEAD_TAG_LENGTH
        + if index == 0 {
            APDU_DATA_LENGTH_LENGTH
        } else {
            0
        }
}

/// Something went wrong reassembling a response.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FramingError {
    /// The frame is shorter than its own header.
    FrameTooShort {
        /// Bytes received.
        got: usize,
        /// Bytes the header alone needs.
        need: usize,
    },
    /// The frame's channel is not the one this session opened.
    ChannelMismatch {
        /// Channel the host is using.
        expected: u16,
        /// Channel on the frame.
        got: u16,
    },
    /// The tag byte is not [`HEAD_TAG`].
    BadTag {
        /// Byte received.
        got: u8,
    },
    /// The frame index is not the one expected next.
    UnexpectedSequence {
        /// Index the deframer wanted.
        expected: u16,
        /// Index on the frame.
        got: u16,
    },
    /// A frame with index 0 arrived mid-response, or a continuation frame
    /// arrived with nothing pending.
    ///
    /// The second half mirrors DMK's only sequencing check
    /// (`DefaultApduReceiverService`: `if (!isFirstIndex && pending.length === 0)`).
    OutOfOrderFrame,
    /// The device declared a response shorter than its status word.
    DeclaredLengthTooShort {
        /// The declared length.
        got: usize,
    },
    /// The requested frame size cannot hold even a frame-0 header.
    FrameSizeTooSmall {
        /// The frame size asked for.
        got: usize,
        /// The smallest usable size (one header plus one data byte).
        min: usize,
    },
    /// The MTU-handshake response was malformed.
    BadMtuResponse,
}

impl core::fmt::Display for FramingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FramingError::FrameTooShort { got, need } => {
                write!(
                    f,
                    "frame of {got} bytes is shorter than its {need}-byte header"
                )
            }
            FramingError::ChannelMismatch { expected, got } => {
                write!(f, "frame channel {got:#06x}, expected {expected:#06x}")
            }
            FramingError::BadTag { got } => write!(f, "frame tag {got:#04x}, expected 0x05"),
            FramingError::UnexpectedSequence { expected, got } => {
                write!(f, "frame index {got}, expected {expected}")
            }
            FramingError::OutOfOrderFrame => write!(f, "frame arrived out of order"),
            FramingError::DeclaredLengthTooShort { got } => {
                write!(
                    f,
                    "device declared a {got}-byte response, too short for a status word"
                )
            }
            FramingError::FrameSizeTooSmall { got, min } => {
                write!(f, "frame size {got} is below the {min}-byte minimum")
            }
            FramingError::BadMtuResponse => write!(f, "malformed BLE MTU response"),
        }
    }
}

impl std::error::Error for FramingError {}

/// Splits an APDU into frames for a transport with the given parameters.
///
/// `pad_to` is `Some(size)` for HID (every frame is zero-filled to the report
/// size) and `None` for BLE (frames end where the data ends).
fn frames(
    apdu: &[u8],
    frame_size: usize,
    channel: Option<u16>,
    pad: bool,
) -> Result<Vec<Vec<u8>>, FramingError> {
    let h0 = header_size(channel.is_some(), 0);
    if frame_size <= h0 {
        // DMK's own guard is `header.getLength() > frameSize`, which lets
        // `frame_size == h0` through and then spins forever on a zero-byte
        // data slice. Rejecting it is the only sane reading.
        return Err(FramingError::FrameSizeTooSmall {
            got: frame_size,
            min: h0 + 1,
        });
    }

    // `getFrames` stops as soon as the offset reaches the APDU length, so an
    // empty APDU produces no frames at all.
    if apdu.is_empty() {
        return Ok(Vec::new());
    }

    let total_len = apdu.len();
    let mut out = Vec::new();
    let mut offset = 0usize;
    let mut index: u16 = 0;

    while offset < total_len {
        let head = header_size(channel.is_some(), index as usize);
        let capacity = frame_size - head;
        let take = capacity.min(total_len - offset);

        let mut frame = Vec::with_capacity(frame_size);
        if let Some(ch) = channel {
            frame.extend_from_slice(&ch.to_be_bytes());
        }
        frame.push(HEAD_TAG);
        frame.extend_from_slice(&index.to_be_bytes());
        if index == 0 {
            frame.extend_from_slice(&(total_len as u16).to_be_bytes());
        }
        frame.extend_from_slice(&apdu[offset..offset + take]);
        if pad {
            frame.resize(frame_size, 0x00);
        }

        out.push(frame);
        offset += take;
        index += 1;
    }

    Ok(out)
}

/// Frames an APDU into 64-byte USB HID reports.
///
/// Every frame is zero-padded to the full 64 bytes, including a lone frame 0 —
/// `DefaultApduSenderService` allocates `new Uint8Array(dataMaxSize).fill(0)`
/// whenever `padding` is set, which HID always sets.
///
/// An empty APDU yields no frames, matching DMK; this crate never produces
/// one, since every command carries at least the 5-byte `CLA INS P1 P2 Lc`.
pub fn hid_frames(channel: u16, apdu: &[u8]) -> Vec<[u8; HID_FRAME_SIZE]> {
    // `HID_FRAME_SIZE` is far above the 7-byte frame-0 header, so the size
    // guard cannot trip here.
    let raw = frames(apdu, HID_FRAME_SIZE, Some(channel), true)
        .expect("64-byte HID frames always exceed the 7-byte header");
    raw.into_iter()
        .map(|f| {
            let mut arr = [0u8; HID_FRAME_SIZE];
            arr.copy_from_slice(&f);
            arr
        })
        .collect()
}

/// Frames an APDU for BLE at the negotiated `frame_size`.
///
/// No channel, no padding: the last frame is as short as its data.
/// `frame_size` is the whole packet length including the 3- or 5-byte header,
/// which is what [`parse_ble_mtu_response`] returns.
pub fn ble_frames(apdu: &[u8], frame_size: usize) -> Result<Vec<Vec<u8>>, FramingError> {
    frames(apdu, frame_size, None, false)
}

/// The BLE MTU-handshake request, written before any APDU.
///
/// `WebBleApduSender.ts`: `new Uint8Array([MTU_OP, 0, 0, 0, 0])` — tag `0x08`,
/// sequence `0x0000`, declared length `0x0000`, no payload.
pub const fn ble_mtu_request() -> [u8; 5] {
    [MTU_OP, 0x00, 0x00, 0x00, 0x00]
}

/// Reads the negotiated frame size out of an MTU-handshake response.
///
/// `WebBleApduSender.ts` accepts a frame of at least 6 bytes whose first byte
/// is `MTU_OP`, and takes `mtuResponseBuffer[5]` as the usable frame size,
/// rejecting zero. Bytes 1–4 are *not* validated: DMK's own fixture sends
/// `08 00 00 00 00 <mtu>` while real devices send `08 00 00 00 01 <mtu>`, so
/// this function does not check them either.
pub fn parse_ble_mtu_response(resp: &[u8]) -> Result<usize, FramingError> {
    if resp.len() < 6 || resp[0] != MTU_OP || resp[5] == 0 {
        return Err(FramingError::BadMtuResponse);
    }
    Ok(resp[5] as usize)
}

/// Streaming reassembly of a framed response.
///
/// Feed frames in arrival order with [`Deframer::push`]; it returns
/// `Ok(Some(payload))` on the frame that completes the response. The payload
/// is the declared-length buffer — response data **plus** the two-byte status
/// word — which [`crate::apdu::decode::split_status_word`] then splits.
///
/// The device's declared length includes the status word
/// (`DefaultApduReceiverService` slices the last two bytes off the
/// declared-length buffer), unlike the outbound direction where it is just the
/// APDU length.
#[derive(Debug, Clone)]
pub struct Deframer {
    channel: Option<u16>,
    next_index: u16,
    declared: Option<usize>,
    buf: Vec<u8>,
}

impl Deframer {
    /// A deframer for the HID channel this session opened.
    pub fn hid(channel: u16) -> Self {
        Deframer {
            channel: Some(channel),
            next_index: 0,
            declared: None,
            buf: Vec::new(),
        }
    }

    /// A deframer for BLE, which carries no channel.
    pub fn ble() -> Self {
        Deframer {
            channel: None,
            next_index: 0,
            declared: None,
            buf: Vec::new(),
        }
    }

    /// Drops any partial response.
    ///
    /// Worth calling after an error: DMK clears its pending frames only on
    /// success, so a failed reassembly there leaves the buffer dirty.
    pub fn reset(&mut self) {
        self.next_index = 0;
        self.declared = None;
        self.buf.clear();
    }

    /// Whether a response is partially assembled.
    pub fn is_idle(&self) -> bool {
        self.declared.is_none() && self.buf.is_empty()
    }

    /// Absorbs one frame.
    ///
    /// Returns the complete payload (data + status word) on the frame that
    /// finishes it, and `None` while more frames are expected.
    pub fn push(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, FramingError> {
        let ch_len = if self.channel.is_some() {
            CHANNEL_LENGTH
        } else {
            0
        };
        let min = ch_len + HEAD_TAG_LENGTH + INDEX_LENGTH;
        if frame.len() < min {
            return Err(FramingError::FrameTooShort {
                got: frame.len(),
                need: min,
            });
        }

        if let Some(expected) = self.channel {
            let got = u16::from_be_bytes([frame[0], frame[1]]);
            if got != expected {
                return Err(FramingError::ChannelMismatch { expected, got });
            }
        }

        let tag = frame[ch_len];
        if tag != HEAD_TAG {
            return Err(FramingError::BadTag { got: tag });
        }

        let index = u16::from_be_bytes([frame[ch_len + 1], frame[ch_len + 2]]);
        if index != self.next_index {
            // With nothing pending the only acceptable index is 0, which is
            // DMK's single sequencing check; mid-response, any gap is fatal.
            return Err(if self.next_index == 0 {
                FramingError::OutOfOrderFrame
            } else {
                FramingError::UnexpectedSequence {
                    expected: self.next_index,
                    got: index,
                }
            });
        }

        let mut cursor = ch_len + HEAD_TAG_LENGTH + INDEX_LENGTH;
        if index == 0 {
            if frame.len() < cursor + APDU_DATA_LENGTH_LENGTH {
                return Err(FramingError::FrameTooShort {
                    got: frame.len(),
                    need: cursor + APDU_DATA_LENGTH_LENGTH,
                });
            }
            let declared = u16::from_be_bytes([frame[cursor], frame[cursor + 1]]) as usize;
            if declared < STATUS_WORD_LEN {
                return Err(FramingError::DeclaredLengthTooShort { got: declared });
            }
            self.declared = Some(declared);
            cursor += APDU_DATA_LENGTH_LENGTH;
        }

        // Every byte after the header counts, HID zero padding included: DMK
        // compares the accumulated length against the declared length and
        // only then truncates, so padding can never shorten a response.
        self.buf.extend_from_slice(&frame[cursor..]);
        self.next_index = self.next_index.wrapping_add(1);

        let declared = self.declared.expect("frame 0 sets the declared length");
        if self.buf.len() >= declared {
            let mut payload = core::mem::take(&mut self.buf);
            payload.truncate(declared);
            self.next_index = 0;
            self.declared = None;
            return Ok(Some(payload));
        }

        Ok(None)
    }
}
