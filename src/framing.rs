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
//! checks all three. The tag and the sequence are validated as the older
//! `@ledgerhq/devices` `hid-framing` does: a frame rejected on either is one
//! DMK would have silently spliced into the response, so the stricter
//! behaviour can only prevent a corrupt reassembly. The channel is handled
//! differently from both: a frame on another channel is *skipped*, not
//! spliced in (DMK) and not an error (`hid-framing`). Such a frame is another
//! host process's reply — on Linux every process with the `hidraw` node open
//! receives every input report — and it says nothing about this session's
//! exchange, whose own reply follows behind it. Failing the exchange on it
//! would poison the link, in the middle of a review, for something the
//! other process did.

use alloc::{boxed::Box, string::ToString, vec::Vec};

use zeroize::{Zeroize, Zeroizing};

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
pub use crate::apdu::STATUS_WORD_LEN;

const CHANNEL_LENGTH: usize = 2;
const HEAD_TAG_LENGTH: usize = 1;
const INDEX_LENGTH: usize = 2;
const APDU_DATA_LENGTH_LENGTH: usize = 2;

/// The MTU-handshake request: the tag, a zero sequence and a zero declared
/// length, no payload.
const MTU_REQUEST_LEN: usize = 5;
/// The shortest MTU-handshake response `WebBleApduSender.ts` accepts.
const MTU_RESPONSE_MIN_LEN: usize = 6;
/// Where the negotiated frame size sits in that response
/// (`mtuResponseBuffer[5]`).
const MTU_RESPONSE_SIZE_OFFSET: usize = 5;

/// The longest APDU the frame-0 header can declare: its length field is a
/// `u16`.
const MAX_FRAMED_LEN: usize = u16::MAX as usize;

/// The 2-byte channel a USB HID connection tags every frame with.
///
/// A demultiplexing tag, not a secret: on Linux every process with the
/// `hidraw` node open receives every input report, and the channel is what
/// tells this connection's reply from another host process's.
/// [`Deframer::hid`] skips frames on any other channel. Each connection
/// picks one at random, the convention every Ledger host library follows.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HidChannel(u16);

impl HidChannel {
    /// A channel from its raw value.
    pub const fn new(channel: u16) -> Self {
        HidChannel(channel)
    }

    /// The raw value, as it goes on the wire.
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl core::fmt::Debug for HidChannel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "HidChannel({:#06x})", self.0)
    }
}

impl core::fmt::Display for HidChannel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#06x}", self.0)
    }
}

/// A BLE frame size the MTU handshake negotiated: the whole packet length,
/// the 3- or 5-byte header included, and large enough that every frame
/// carries data.
///
/// Constructed only through [`BleFrameSize::new`] or
/// [`parse_ble_mtu_response`], so a size [`ble_frames`] cannot use is refused
/// where it is made, not where it is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BleFrameSize(usize);

impl BleFrameSize {
    /// The smallest usable size: a frame-0 header plus one data byte.
    ///
    /// DMK's own guard is `header.getLength() > frameSize`, which lets a size
    /// equal to the header through and then emits an empty frame 0; this
    /// crate refuses it.
    pub const MIN: usize = header_size(false, 0) + 1;

    /// A frame size, refused below [`BleFrameSize::MIN`].
    ///
    /// # Errors
    ///
    /// [`FramingError::FrameSizeTooSmall`] when `size` cannot hold a frame-0
    /// header and one data byte.
    pub const fn new(size: usize) -> Result<Self, FramingError> {
        if size < Self::MIN {
            return Err(FramingError::FrameSizeTooSmall {
                got: size,
                min: Self::MIN,
            });
        }
        Ok(BleFrameSize(size))
    }

    /// The size in bytes.
    pub const fn get(self) -> usize {
        self.0
    }
}

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
    /// A HID frame that is not a whole [`HID_FRAME_SIZE`]-byte report.
    ///
    /// A Ledger sends every report at its full size, zero-padded, so a
    /// shorter one is a partial read by the host's HID stack — and a partial
    /// read is not a shorter frame: the bytes missing from it are data,
    /// and everything after it would be reassembled shifted, with what should
    /// be the status word landing inside the payload. A read the deframer
    /// cannot place is refused, and the transport poisons the link.
    BadFrameLength {
        /// Bytes received.
        got: usize,
        /// The report size.
        expected: usize,
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
    /// A continuation frame arrived with nothing pending.
    ///
    /// Mirrors DMK's only sequencing check (`DefaultApduReceiverService`:
    /// `if (!isFirstIndex && pending.length === 0)`). A frame 0 arriving
    /// mid-response is the other case, and is
    /// [`FramingError::UnexpectedSequence`] with `got: 0`.
    OutOfOrderFrame,
    /// The device declared a response shorter than its status word.
    DeclaredLengthTooShort {
        /// The declared length.
        got: usize,
    },
    /// A BLE reply carried more data than its frame 0 declared.
    ///
    /// BLE frames are never padded, so data past the declared length is not
    /// padding: the frames do not belong to the header they follow. HID
    /// reports are padded to their size, and the excess there is dropped as
    /// the padding it is. `@ledgerhq/devices`' BLE receiver refuses this
    /// (`BLETooMuchData`); DMK truncates.
    Overrun {
        /// The declared length.
        declared: usize,
        /// Bytes received.
        got: usize,
    },
    /// A reply ran to more frames than a `u16` index can count.
    ///
    /// A BLE continuation frame may carry no data, so a device can keep a
    /// reassembly alive with empty frames; the index wrapping to 0 would then
    /// let a frame 0 mid-reply pass the sequence check and replace the
    /// declared length. The reassembly ends here instead.
    TooManyFrames {
        /// The largest index a frame can carry.
        max: u16,
    },
    /// An earlier frame of this reply was refused, and the reassembly is dead
    /// until [`Deframer::reset`].
    ///
    /// Without this a caller that logs an error and keeps feeding would
    /// splice a later reply's continuation frames onto this one's frame 0
    /// and be handed the result as a complete reply.
    Poisoned {
        /// The refusal that killed the reassembly.
        source: Box<FramingError>,
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
    /// An APDU longer than the frame-0 header's `u16` length field can
    /// declare.
    ///
    /// This crate never builds one — a command's data is at most 255 bytes —
    /// so this is for a caller framing bytes of its own.
    ApduTooLong {
        /// Bytes asked for.
        got: usize,
        /// The most a frame 0 can declare.
        max: usize,
    },
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
            FramingError::BadFrameLength { got, expected } => write!(
                f,
                "HID report of {got} bytes where every Ledger report is {expected}; a partial \
                 read cannot be placed in the reply"
            ),
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
            FramingError::Overrun { declared, got } => write!(
                f,
                "BLE reply carried {got} bytes where its frame 0 declared {declared}; unpadded \
                 frames with data past the declared length do not belong to that header"
            ),
            FramingError::TooManyFrames { max } => write!(
                f,
                "the reply ran past frame index {max}, more than a reply can have"
            ),
            FramingError::Poisoned { source } => write!(
                f,
                "an earlier frame of this reply was refused ({source}); the reassembly is dead \
                 until it is reset"
            ),
            FramingError::FrameSizeTooSmall { got, min } => {
                write!(f, "frame size {got} is below the {min}-byte minimum")
            }
            FramingError::BadMtuResponse => write!(f, "malformed BLE MTU response"),
            FramingError::ApduTooLong { got, max } => write!(
                f,
                "an APDU of {got} bytes cannot be framed; the frame-0 header declares at most \
                 {max}"
            ),
        }
    }
}

impl core::error::Error for FramingError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            FramingError::Poisoned { source } => Some(source.as_ref()),
            _ => None,
        }
    }
}

/// Splits an APDU into frames for a transport with the given parameters.
///
/// `frame_size` is above the frame-0 header by construction: [`HID_FRAME_SIZE`]
/// for HID, a [`BleFrameSize`] for BLE. `pad` is `true` for HID (every frame
/// is zero-filled to the frame size) and `false` for BLE (frames end where
/// the data ends).
fn frames(
    apdu: &[u8],
    frame_size: usize,
    channel: Option<HidChannel>,
    pad: bool,
) -> Result<Vec<Vec<u8>>, FramingError> {
    debug_assert!(frame_size > header_size(channel.is_some(), 0));

    let total_len = apdu.len();
    if total_len > MAX_FRAMED_LEN {
        return Err(FramingError::ApduTooLong {
            got: total_len,
            max: MAX_FRAMED_LEN,
        });
    }

    // `getFrames` stops as soon as the offset reaches the APDU length, so an
    // empty APDU produces no frames at all.
    if apdu.is_empty() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    let mut offset = 0usize;
    // Cannot overflow: every frame carries at least one data byte, and there
    // are at most `MAX_FRAMED_LEN` of those.
    let mut index: u16 = 0;

    while offset < total_len {
        let head = header_size(channel.is_some(), usize::from(index));
        let capacity = frame_size - head;
        let take = capacity.min(total_len - offset);

        let mut frame = Vec::with_capacity(frame_size);
        if let Some(ch) = channel {
            frame.extend_from_slice(&ch.get().to_be_bytes());
        }
        frame.push(HEAD_TAG);
        frame.extend_from_slice(&index.to_be_bytes());
        if index == 0 {
            let declared = u16::try_from(total_len).expect("bounded by MAX_FRAMED_LEN above");
            frame.extend_from_slice(&declared.to_be_bytes());
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
///
/// # Errors
///
/// [`FramingError::ApduTooLong`] when `apdu` is longer than the frame-0
/// header can declare; nothing this crate builds is.
pub fn hid_frames(
    channel: HidChannel,
    apdu: &[u8],
) -> Result<Vec<[u8; HID_FRAME_SIZE]>, FramingError> {
    // The frames carry the command's payload — action secrets on a
    // `PCZT_*_ACTION` command — so the intermediate buffers are wiped once
    // copied into the reports the caller takes.
    let raw = Zeroizing::new(frames(apdu, HID_FRAME_SIZE, Some(channel), true)?);
    Ok(raw
        .iter()
        .map(|f| {
            let mut arr = [0u8; HID_FRAME_SIZE];
            arr.copy_from_slice(f);
            arr
        })
        .collect())
}

/// Frames an APDU for BLE at the negotiated `frame_size`.
///
/// No channel, no padding: the last frame is as short as its data.
///
/// # Errors
///
/// [`FramingError::ApduTooLong`], as for [`hid_frames`].
pub fn ble_frames(apdu: &[u8], frame_size: BleFrameSize) -> Result<Vec<Vec<u8>>, FramingError> {
    frames(apdu, frame_size.get(), None, false)
}

/// The BLE MTU-handshake request, written before any APDU.
///
/// `WebBleApduSender.ts`: `new Uint8Array([MTU_OP, 0, 0, 0, 0])` — tag `0x08`,
/// sequence `0x0000`, declared length `0x0000`, no payload.
pub const fn ble_mtu_request() -> [u8; MTU_REQUEST_LEN] {
    [MTU_OP, 0x00, 0x00, 0x00, 0x00]
}

/// Reads the negotiated frame size out of an MTU-handshake response.
///
/// `WebBleApduSender.ts` accepts a frame of at least 6 bytes whose first byte
/// is `MTU_OP`, and takes `mtuResponseBuffer[5]` as the usable frame size,
/// rejecting zero. Bytes 1–4 are *not* validated: DMK's own fixture sends
/// `08 00 00 00 00 <mtu>` while real devices send `08 00 00 00 01 <mtu>`, so
/// this function does not check them either.
///
/// # Errors
///
/// [`FramingError::BadMtuResponse`] for a response shorter than 6 bytes, not
/// tagged `MTU_OP`, or naming a zero size, and
/// [`FramingError::FrameSizeTooSmall`] for a size [`ble_frames`] could not
/// use.
pub fn parse_ble_mtu_response(resp: &[u8]) -> Result<BleFrameSize, FramingError> {
    if resp.len() < MTU_RESPONSE_MIN_LEN || resp[0] != MTU_OP {
        return Err(FramingError::BadMtuResponse);
    }
    let size = resp[MTU_RESPONSE_SIZE_OFFSET];
    if size == 0 {
        return Err(FramingError::BadMtuResponse);
    }
    BleFrameSize::new(usize::from(size))
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
///
/// The reassembly buffer holds whatever the device is sending — a viewing key
/// under `GET_VK`, the account's address under `GET_WALLET_PUBLIC_KEY` — so
/// `Debug` shows its length, not its bytes, and it is wiped when the deframer
/// is dropped. The deframer is not `Clone`: a cloned buffer lacks the
/// capacity frame 0 reserves, so the copy would reallocate as it grew and
/// leave the reply bytes it held behind, unwiped.
///
/// # A refused frame ends the reply
///
/// A `push` that returns an error poisons the deframer: every later `push`
/// answers [`FramingError::Poisoned`] until [`Deframer::reset`]. Without
/// that, a caller that logs the error and keeps feeding would have a later
/// reply's continuation frames spliced onto this reply's frame 0 and handed
/// back as one complete reply (DMK does exactly this). The transports in
/// this crate go further and poison the whole connection; see
/// [`Deframer::reset`] for why a reset is not a recovery.
pub struct Deframer {
    channel: Option<HidChannel>,
    next_index: u16,
    declared: Option<usize>,
    buf: Vec<u8>,
    /// The refusal that poisoned this reassembly, if one has.
    failed: Option<Box<FramingError>>,
}

impl core::fmt::Debug for Deframer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Deframer")
            .field("channel", &self.channel.map(|c| c.to_string()))
            .field("next_index", &self.next_index)
            .field("declared", &self.declared)
            .field("buf", &format_args!("[{} bytes]", self.buf.len()))
            .field("failed", &self.failed)
            .finish()
    }
}

impl Drop for Deframer {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl Deframer {
    /// A deframer for the HID channel this session opened.
    pub fn hid(channel: HidChannel) -> Self {
        Deframer {
            channel: Some(channel),
            next_index: 0,
            declared: None,
            buf: Vec::new(),
            failed: None,
        }
    }

    /// A deframer for BLE, which carries no channel.
    pub fn ble() -> Self {
        Deframer {
            channel: None,
            next_index: 0,
            declared: None,
            buf: Vec::new(),
            failed: None,
        }
    }

    /// Drops any partial response.
    ///
    /// This is not a recovery. After a reassembly fails, the rest of the
    /// device's reply is still arriving, and a deframer reset and reused on
    /// the same channel would take those frames — or the next command's
    /// reply, offset by them — for an answer to whatever is sent next. The
    /// transports in this crate poison the connection instead
    /// (`transport::TransportError::Poisoned`) and start a new one
    /// with a fresh channel; an embedding driving its own channel should do
    /// the same. `reset` is for a deframer that is being reused after a
    /// *successful* reassembly, or for a channel the embedding has itself
    /// re-synchronized. (DMK clears its pending frames only on success, so a
    /// failed reassembly there leaves the buffer dirty; that is the one thing
    /// this clears.) It also lifts the poisoning a refused frame left.
    pub fn reset(&mut self) {
        self.next_index = 0;
        self.declared = None;
        self.buf.zeroize();
        self.buf.clear();
        self.failed = None;
    }

    /// Whether the deframer is ready for a frame 0: nothing partially
    /// assembled, and no refusal poisoning it.
    pub fn is_idle(&self) -> bool {
        self.declared.is_none() && self.buf.is_empty() && self.failed.is_none()
    }

    /// The refusal that poisoned this reassembly, if one has; see the type's
    /// documentation.
    pub fn poisoned(&self) -> Option<&FramingError> {
        self.failed.as_deref()
    }

    /// Absorbs one frame.
    ///
    /// Returns the complete payload (data + status word) on the frame that
    /// finishes it, and `None` while more frames are expected — which is also
    /// the answer for a HID frame on another channel, which belongs to
    /// another host process and is skipped.
    ///
    /// A HID deframer takes whole [`HID_FRAME_SIZE`]-byte reports and nothing
    /// else ([`FramingError::BadFrameLength`]): the device pads every report
    /// to that size, so a shorter one is a partial read whose missing bytes
    /// would shift every later frame's data. That also bounds a reply's
    /// frame count — each continuation frame carries at least one data byte
    /// short of the report, so a device cannot keep a reassembly alive with
    /// empty frames. A BLE frame is as long as its data, and a BLE reply
    /// with data past its declared length is refused
    /// ([`FramingError::Overrun`]) where HID padding is dropped.
    ///
    /// # Errors
    ///
    /// Any [`FramingError`] but [`FramingError::FrameSizeTooSmall`],
    /// [`FramingError::BadMtuResponse`] and [`FramingError::ApduTooLong`],
    /// which belong to the outbound side. Every error poisons the deframer;
    /// see the type's documentation.
    pub fn push(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, FramingError> {
        if let Some(source) = &self.failed {
            return Err(FramingError::Poisoned {
                source: source.clone(),
            });
        }
        let result = self.absorb(frame);
        if let Err(e) = &result {
            self.failed = Some(Box::new(e.clone()));
        }
        result
    }

    /// [`Deframer::push`] without the poisoning.
    fn absorb(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, FramingError> {
        let ch_len = if self.channel.is_some() {
            CHANNEL_LENGTH
        } else {
            0
        };
        if self.channel.is_some() && frame.len() != HID_FRAME_SIZE {
            return Err(FramingError::BadFrameLength {
                got: frame.len(),
                expected: HID_FRAME_SIZE,
            });
        }
        let min = ch_len + HEAD_TAG_LENGTH + INDEX_LENGTH;
        if frame.len() < min {
            return Err(FramingError::FrameTooShort {
                got: frame.len(),
                need: min,
            });
        }

        if let Some(expected) = self.channel {
            let got = u16::from_be_bytes([frame[0], frame[1]]);
            if got != expected.get() {
                // Another host process's reply, sharing the device node; it
                // is not part of this reassembly and not a failure of it.
                // See the module docs.
                return Ok(None);
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
            let declared = usize::from(u16::from_be_bytes([frame[cursor], frame[cursor + 1]]));
            if declared < STATUS_WORD_LEN {
                return Err(FramingError::DeclaredLengthTooShort { got: declared });
            }
            self.declared = Some(declared);
            cursor += APDU_DATA_LENGTH_LENGTH;
            // Sized once: the buffer holds what the device is sending, and a
            // `Vec` that grows leaves its old allocation behind unwiped. HID
            // pads the last report, so up to one report of padding lands in
            // it before the truncation below.
            let padding = if self.channel.is_some() {
                HID_FRAME_SIZE
            } else {
                0
            };
            self.buf.reserve_exact(declared + padding);
        }

        let declared = self.declared.expect("frame 0 sets the declared length");
        let data = &frame[cursor..];
        // Every byte after the header counts, HID zero padding included: DMK
        // compares the accumulated length against the declared length and
        // only then truncates, so padding can never shorten a response.
        let accumulated = self.buf.len().saturating_add(data.len());
        // Refused before the append, not after it: a BLE frame 0 reserves the
        // declared length and no more, so a buffer grown past it would
        // reallocate and leave the reply bytes already accumulated in a freed
        // block — what the reservation exists to prevent.
        if self.channel.is_none() && accumulated > declared {
            return Err(FramingError::Overrun {
                declared,
                got: accumulated,
            });
        }
        // A HID frame 0 reserves one report of padding beyond the declared
        // length, which is more than any one report can add, so the append
        // below never reallocates either.
        debug_assert!(
            accumulated <= self.buf.capacity(),
            "the frame-0 reservation covers every byte appended to it"
        );
        self.buf.extend_from_slice(data);
        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or(FramingError::TooManyFrames { max: u16::MAX })?;
        if self.buf.len() >= declared {
            let mut payload = core::mem::take(&mut self.buf);
            // The padding past the declared length is dropped here; wipe it
            // rather than leave it in the freed tail.
            payload[declared..].zeroize();
            payload.truncate(declared);
            self.next_index = 0;
            self.declared = None;
            return Ok(Some(payload));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests;
