use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::time::{Duration, Instant};

use crate::framing::{hid_frames, Deframer, HidChannel, HID_FRAME_SIZE};
use crate::session::Deadline;
use crate::test_support::{VERSION_APDU, VERSION_REPLY};
use crate::transport::hid::{
    exchange_over, kind_from_message, HidReports, Link, LEDGER_HID_USAGE_PAGE,
    LEDGER_USB_VENDOR_ID, MAX_REPLY_REPORTS, READ_NON_BLOCKING,
};
use crate::transport::TransportError;

// ---------------------------------------------------------------------------
// Transports
// ---------------------------------------------------------------------------
//
// These exercise the two transports' *framing* against the deframers and the
// emulator's own protocol. Neither needs hardware: the HID side is checked by
// running the exact bytes `HidTransport` would write back through
// `Deframer::hid`, and the speculos side against a loopback fake that
// reimplements `speculos/mcu/apdu.py`'s arithmetic independently.

/// The device's echo of one host frame: same channel, same tag, same index,
/// with the declared length re-read as a *response* length (which includes
/// the status word, unlike the outbound one).
fn device_frames(channel: HidChannel, payload: &[u8]) -> Vec<[u8; HID_FRAME_SIZE]> {
    hid_frames(channel, payload).unwrap()
}

const CHANNEL: HidChannel = HidChannel::new(0x4A4A);
const TIMEOUT: Duration = Duration::from_millis(50);

/// A scripted HID device.
///
/// `stale` is what already sits in the OS buffer before the command is
/// written; `reply` is what the device sends *in answer to* the command,
/// so it becomes readable only once the first report has been written.
struct ScriptedHid {
    stale: RefCell<VecDeque<Vec<u8>>>,
    reply: RefCell<Option<Vec<[u8; HID_FRAME_SIZE]>>>,
    /// Like `reply`, but the reports are handed out verbatim, short ones
    /// included — what a partial read by the HID stack looks like.
    reply_reports: RefCell<Option<Vec<Vec<u8>>>>,
    /// Every output report written, and how many reports were still
    /// waiting when the first of each command went out.
    written: RefCell<Vec<Vec<u8>>>,
    waiting_at_write: RefCell<Vec<usize>>,
    /// Fail the next read with an I/O error, once.
    fail_next_read: RefCell<bool>,
    /// Which reads (by count) a signal interrupts, and which writes.
    interrupt_reads: RefCell<Vec<usize>>,
    interrupt_writes: RefCell<Vec<usize>>,
    reads: RefCell<usize>,
    writes: RefCell<usize>,
    /// The timeout every read was asked to wait, in order.
    read_timeouts: RefCell<Vec<i32>>,
}

impl ScriptedHid {
    fn new(stale: Vec<Vec<u8>>, reply: Option<Vec<[u8; HID_FRAME_SIZE]>>) -> Self {
        ScriptedHid {
            stale: RefCell::new(stale.into()),
            reply: RefCell::new(reply),
            reply_reports: RefCell::new(None),
            written: RefCell::new(Vec::new()),
            waiting_at_write: RefCell::new(Vec::new()),
            fail_next_read: RefCell::new(false),
            interrupt_reads: RefCell::new(Vec::new()),
            interrupt_writes: RefCell::new(Vec::new()),
            reads: RefCell::new(0),
            writes: RefCell::new(0),
            read_timeouts: RefCell::new(Vec::new()),
        }
    }
}

/// A device node another host process is streaming on: once the command is
/// out, every read hands back a frame tagged with someone else's channel.
///
/// It has one more of them than [`MAX_REPLY_REPORTS`] allows and nothing
/// behind them, so an exchange that ends on its own is one that bound itself.
struct ForeignStream {
    frame: Vec<u8>,
    reads: RefCell<usize>,
}

impl HidReports for ForeignStream {
    fn write_report(&self, _report: &[u8]) -> Result<(), TransportError> {
        Ok(())
    }

    fn read_report(&self, buf: &mut [u8], timeout_ms: i32) -> Result<usize, TransportError> {
        // Nothing is waiting when the drain looks: the other process starts
        // streaming once this command is out.
        if timeout_ms == READ_NON_BLOCKING {
            return Ok(0);
        }
        *self.reads.borrow_mut() += 1;
        if *self.reads.borrow() > MAX_REPLY_REPORTS {
            return Ok(0);
        }
        buf[..self.frame.len()].copy_from_slice(&self.frame);
        Ok(self.frame.len())
    }
}

/// A device whose writes a signal storm interrupts until `until`, and which
/// has nothing to read: the shape a host running signal handlers on the
/// calling thread presents to the write phase.
struct StormedWrites {
    until: Instant,
    attempts: RefCell<usize>,
}

impl HidReports for StormedWrites {
    fn write_report(&self, _report: &[u8]) -> Result<(), TransportError> {
        *self.attempts.borrow_mut() += 1;
        if Instant::now() < self.until {
            return Err(interrupted());
        }
        Ok(())
    }

    fn read_report(&self, _buf: &mut [u8], _timeout_ms: i32) -> Result<usize, TransportError> {
        Ok(0)
    }
}

fn interrupted() -> TransportError {
    TransportError::Io {
        kind: std::io::ErrorKind::Interrupted,
        message: "EINTR".into(),
    }
}

impl HidReports for ScriptedHid {
    fn write_report(&self, report: &[u8]) -> Result<(), TransportError> {
        let n = *self.writes.borrow();
        *self.writes.borrow_mut() = n + 1;
        if self.interrupt_writes.borrow().contains(&n) {
            return Err(interrupted());
        }
        assert_eq!(report.len(), HID_FRAME_SIZE + 1);
        assert_eq!(report[0], 0x00, "report ID");
        self.waiting_at_write
            .borrow_mut()
            .push(self.stale.borrow().len());
        self.written.borrow_mut().push(report.to_vec());
        if let Some(frames) = self.reply.borrow_mut().take() {
            self.stale
                .borrow_mut()
                .extend(frames.into_iter().map(|f| f.to_vec()));
        }
        if let Some(reports) = self.reply_reports.borrow_mut().take() {
            self.stale.borrow_mut().extend(reports);
        }
        Ok(())
    }

    fn read_report(&self, buf: &mut [u8], timeout_ms: i32) -> Result<usize, TransportError> {
        self.read_timeouts.borrow_mut().push(timeout_ms);
        let n = *self.reads.borrow();
        *self.reads.borrow_mut() = n + 1;
        if self.interrupt_reads.borrow().contains(&n) {
            return Err(interrupted());
        }
        if self.fail_next_read.replace(false) {
            return Err(TransportError::Io {
                kind: std::io::ErrorKind::Other,
                message: "scripted".into(),
            });
        }
        match self.stale.borrow_mut().pop_front() {
            Some(report) => {
                buf[..report.len()].copy_from_slice(&report);
                Ok(report.len())
            }
            None => Ok(0),
        }
    }
}

/// Reports already in the OS buffer — a late reply to a command whose
/// exchange gave up — are discarded before the command goes out, so the
/// real reply is the one returned.
#[test]
fn stale_input_reports_are_drained_before_a_command_is_written() {
    let late_reply: Vec<Vec<u8>> = device_frames(CHANNEL, &[0x90, 0x00])
        .into_iter()
        .map(|f| f.to_vec())
        .collect();
    let device = ScriptedHid::new(late_reply, Some(device_frames(CHANNEL, &VERSION_REPLY)));
    let mut link = Link::new(CHANNEL, TIMEOUT);

    let reply = exchange_over(&device, &mut link, &VERSION_APDU, Deadline::Normal)
        .expect("the real reply reassembles");
    assert_eq!(reply, VERSION_REPLY);
    assert_eq!(
        device.waiting_at_write.borrow().as_slice(),
        &[0],
        "the buffer must be empty when the command goes out"
    );
    assert!(!link.is_poisoned());
}

/// A timeout leaves the device's reply uncollected, so it poisons the
/// link: the next exchange is refused before anything is written.
#[test]
fn a_timeout_poisons_the_link() {
    let device = ScriptedHid::new(Vec::new(), None);
    let mut link = Link::new(CHANNEL, TIMEOUT);

    let err = exchange_over(&device, &mut link, &VERSION_APDU, Deadline::Normal)
        .expect_err("nothing answers");
    assert!(matches!(err, TransportError::Timeout { .. }), "{err}");
    assert!(link.is_poisoned());
    let written = device.written.borrow().len();
    assert_eq!(written, 1);

    // The late reply lands; the next command must not collect it.
    device.stale.borrow_mut().extend(
        device_frames(CHANNEL, &VERSION_REPLY)
            .into_iter()
            .map(|f| f.to_vec()),
    );
    let err = exchange_over(&device, &mut link, &VERSION_APDU, Deadline::Normal)
        .expect_err("a poisoned link refuses every exchange");
    assert!(
        matches!(
            &err,
            TransportError::Poisoned { source } if matches!(**source, TransportError::Timeout { .. })
        ),
        "{err}"
    );
    assert_eq!(
        device.written.borrow().len(),
        written,
        "nothing more is written"
    );
    // The cause is chained as the error's source.
    let cause = std::error::Error::source(&err).expect("a poisoned error names its cause");
    assert!(cause.to_string().starts_with("no reply after"), "{cause}");
}

/// The budget bounds the whole exchange, so a zero timeout is spent before
/// the command goes out: nothing is written and the link stays clean, which
/// is what the transport's own documentation promises and what the speculos
/// transport does with the same setting. A review exchange has no budget to
/// spend and is unaffected.
#[test]
fn a_zero_timeout_fails_before_the_wire_and_leaves_the_link_clean() {
    let device = ScriptedHid::new(Vec::new(), Some(device_frames(CHANNEL, &VERSION_REPLY)));
    let mut link = Link::new(CHANNEL, Duration::ZERO);

    let err = exchange_over(&device, &mut link, &VERSION_APDU, Deadline::Normal)
        .expect_err("a zero budget is spent before the exchange starts");
    assert!(matches!(err, TransportError::Timeout { .. }), "{err}");
    assert!(device.written.borrow().is_empty(), "nothing goes out");
    assert!(!link.is_poisoned(), "the device owes nothing");

    let reply = exchange_over(&device, &mut link, &VERSION_APDU, Deadline::UserReview)
        .expect("a review exchange has no budget to spend");
    assert_eq!(reply, VERSION_REPLY);
}

/// An input report shorter than the frame is a partial read by the HID
/// stack: the bytes missing from it are data, and every later frame would
/// reassemble shifted, with payload bytes where the status word belongs.
/// It ends the exchange as a framing error and poisons the link.
#[test]
fn a_short_input_report_ends_the_exchange_and_poisons_the_link() {
    let mut payload: Vec<u8> = (0..150u32).map(|i| (i % 251) as u8).collect();
    let n = payload.len();
    payload[n - 2] = 0x90;
    payload[n - 1] = 0x00;
    let frames = device_frames(CHANNEL, &payload);
    assert_eq!(frames.len(), 3, "150 bytes is three reports");

    let mut reports: Vec<Vec<u8>> = frames.iter().map(|f| f.to_vec()).collect();
    reports[0].truncate(47);
    let device = ScriptedHid::new(Vec::new(), None);
    *device.reply_reports.borrow_mut() = Some(reports);
    let mut link = Link::new(CHANNEL, TIMEOUT);

    let err = exchange_over(&device, &mut link, &VERSION_APDU, Deadline::Normal)
        .expect_err("a partial report cannot be placed");
    assert!(
        matches!(
            err,
            TransportError::Framing(crate::framing::FramingError::BadFrameLength {
                got: 47,
                expected: HID_FRAME_SIZE
            })
        ),
        "{err}"
    );
    assert!(
        link.is_poisoned(),
        "the rest of the reply is still arriving"
    );
}

/// Another host process sharing the device node gets its reply delivered
/// to this connection too. Its frames are skipped and this connection's
/// reply, arriving behind them, is returned; the link stays clean.
#[test]
fn a_frame_from_another_host_process_is_skipped() {
    let theirs = device_frames(HidChannel::new(CHANNEL.get() ^ 0xFFFF), &[0x6A, 0x80]);
    let ours = device_frames(CHANNEL, &VERSION_REPLY);
    let mut reports: Vec<Vec<u8>> = theirs.iter().map(|f| f.to_vec()).collect();
    reports.extend(ours.iter().map(|f| f.to_vec()));

    let device = ScriptedHid::new(Vec::new(), None);
    *device.reply_reports.borrow_mut() = Some(reports);
    let mut link = Link::new(CHANNEL, TIMEOUT);

    let reply = exchange_over(&device, &mut link, &VERSION_APDU, Deadline::UserReview)
        .expect("our own reply is right behind the foreign frame");
    assert_eq!(reply, VERSION_REPLY);
    assert!(!link.is_poisoned());
}

/// A frame on another channel is skipped and nothing else counts it under a
/// review wait, so another host process streaming on the same device node
/// would park the exchange for ever. It ends once more reports have arrived
/// than any reply could run to, and poisons the link: this connection's own
/// reply was never collected.
#[test]
fn a_flood_of_frames_from_another_host_process_ends_the_exchange() {
    let theirs = device_frames(HidChannel::new(CHANNEL.get() ^ 0xFFFF), &[0x6A, 0x80]);
    let device = ForeignStream {
        frame: theirs[0].to_vec(),
        reads: RefCell::new(0),
    };
    let mut link = Link::new(CHANNEL, TIMEOUT);

    let err = exchange_over(&device, &mut link, &VERSION_APDU, Deadline::UserReview)
        .expect_err("a review wait cannot be parked by another process's traffic");
    assert!(matches!(err, TransportError::Io { .. }), "{err}");
    assert_eq!(*device.reads.borrow(), MAX_REPLY_REPORTS);
    assert!(link.is_poisoned(), "our own reply was never collected");
}

/// A signal interrupting a read or a write (`EINTR`, an I/O error of kind
/// `Interrupted`) is not a failure of the device or the link: the call is
/// made again, in the drain, in the write and mid-reply alike.
#[test]
fn an_interrupted_call_is_made_again() {
    let device = ScriptedHid::new(Vec::new(), Some(device_frames(CHANNEL, &VERSION_REPLY)));
    // Reads: #0 the drain (interrupted), #1 the drain again (empty), then
    // #2 the reply (interrupted) and #3 the reply again. Writes: #0 the
    // command (interrupted) and #1 the command again.
    *device.interrupt_reads.borrow_mut() = vec![0, 2];
    *device.interrupt_writes.borrow_mut() = vec![0];
    let mut link = Link::new(CHANNEL, TIMEOUT);

    let reply = exchange_over(&device, &mut link, &VERSION_APDU, Deadline::Normal)
        .expect("every interrupted call is made again");
    assert_eq!(reply, VERSION_REPLY);
    assert!(!link.is_poisoned());
    assert_eq!(*device.reads.borrow(), 4);
    assert_eq!(*device.writes.borrow(), 2);
    assert_eq!(
        device.written.borrow().len(),
        1,
        "the command went out once"
    );
}

/// A signal storm on the write is bounded by the exchange's budget, as the
/// reply loop's wait is: the exchange gives up while the storm is still
/// running rather than retrying for as long as it lasts.
#[test]
fn a_signal_storm_on_the_write_is_bounded_by_the_exchange_budget() {
    // The storm outlasts the budget by a wide margin, so an exchange that
    // ends before it does is one the budget ended.
    const STORM: Duration = Duration::from_secs(1);
    let device = StormedWrites {
        until: Instant::now() + STORM,
        attempts: RefCell::new(0),
    };
    let mut link = Link::new(CHANNEL, TIMEOUT);

    let started = Instant::now();
    let err = exchange_over(&device, &mut link, &VERSION_APDU, Deadline::Normal)
        .expect_err("every write is interrupted");
    let elapsed = started.elapsed();
    assert!(matches!(err, TransportError::Timeout { .. }), "{err}");
    assert!(elapsed >= TIMEOUT, "it waited the budget out: {elapsed:?}");
    assert!(
        elapsed < STORM,
        "the retries are bounded by the budget, not by the storm: {elapsed:?}"
    );
    assert!(*device.attempts.borrow() > 1, "the write was made again");
    assert!(
        link.is_poisoned(),
        "a write that was attempted has started onto the wire"
    );
}

/// An empty APDU is not a command: it frames to no reports at all, so
/// nothing would go out and the reply loop would take whatever arrived next
/// for its answer. It is refused before even the drain runs.
#[test]
fn an_empty_command_is_refused_before_anything_happens() {
    let device = ScriptedHid::new(Vec::new(), Some(device_frames(CHANNEL, &VERSION_REPLY)));
    let mut link = Link::new(CHANNEL, TIMEOUT);

    assert_eq!(
        exchange_over(&device, &mut link, &[], Deadline::Normal),
        Err(TransportError::EmptyRequest)
    );
    assert!(device.written.borrow().is_empty(), "nothing goes out");
    assert_eq!(*device.reads.borrow(), 0, "not even the drain runs");
    assert!(!link.is_poisoned(), "the device owes nothing");
}

/// A reply that does not reassemble may still be arriving, so a framing
/// error poisons the link too.
#[test]
fn a_bad_frame_poisons_the_link() {
    let mut frames = device_frames(CHANNEL, &VERSION_REPLY);
    frames[0][2] = 0x06; // not HEAD_TAG
    let device = ScriptedHid::new(Vec::new(), Some(frames));
    let mut link = Link::new(CHANNEL, TIMEOUT);

    let err = exchange_over(&device, &mut link, &VERSION_APDU, Deadline::Normal)
        .expect_err("the frame is bad");
    assert!(matches!(err, TransportError::Framing(_)), "{err}");
    assert!(link.is_poisoned());
    assert!(matches!(
        exchange_over(&device, &mut link, &VERSION_APDU, Deadline::Normal),
        Err(TransportError::Poisoned { .. })
    ));
}

/// A failure before anything has gone out — here, in the drain — leaves
/// the link clean: the device owes nothing.
#[test]
fn a_failure_before_the_wire_does_not_poison_the_link() {
    let device = ScriptedHid::new(Vec::new(), Some(device_frames(CHANNEL, &VERSION_REPLY)));
    *device.fail_next_read.borrow_mut() = true;
    let mut link = Link::new(CHANNEL, TIMEOUT);

    let err = exchange_over(&device, &mut link, &VERSION_APDU, Deadline::Normal)
        .expect_err("the drain fails");
    assert!(matches!(err, TransportError::Io { .. }), "{err}");
    assert!(!link.is_poisoned());
    assert!(device.written.borrow().is_empty());

    // And the next exchange proceeds normally.
    let reply = exchange_over(&device, &mut link, &VERSION_APDU, Deadline::Normal)
        .expect("the link is clean");
    assert_eq!(reply, VERSION_REPLY);
}

/// The deadline reaches the device: a `Normal` exchange asks every read
/// of the reply to wait what is left of the budget, and a review read
/// blocks. The drain before the command never waits.
#[test]
fn a_review_read_blocks_and_a_normal_read_is_bounded() {
    let payload: Vec<u8> = (0..150u32).map(|i| (i % 251) as u8).collect();
    let frames = device_frames(CHANNEL, &payload);
    assert_eq!(frames.len(), 3);

    for deadline in [Deadline::Normal, Deadline::UserReview] {
        let device = ScriptedHid::new(Vec::new(), Some(frames.clone()));
        let mut link = Link::new(CHANNEL, TIMEOUT);
        let reply = exchange_over(&device, &mut link, &VERSION_APDU, deadline)
            .expect("the reply reassembles");
        assert_eq!(reply, payload);

        let timeouts = device.read_timeouts.borrow().clone();
        let (drain, reply_reads) = timeouts.split_at(1);
        assert_eq!(drain, &[0], "the drain takes what is already there");
        assert_eq!(reply_reads.len(), 3);
        match deadline {
            Deadline::UserReview => assert!(
                reply_reads.iter().all(|&t| t == -1),
                "a review blocks: {reply_reads:?}"
            ),
            Deadline::Normal => {
                let budget = TIMEOUT.as_millis() as i32;
                assert!(
                    reply_reads.iter().all(|&t| (0..=budget).contains(&t)),
                    "every read waits at most what is left: {reply_reads:?}"
                );
                assert!(
                    reply_reads.windows(2).all(|w| w[1] <= w[0]),
                    "the budget only shrinks: {reply_reads:?}"
                );
            }
        }
    }
}

/// A blocking read that returns with no report is not a timeout — a
/// blocking wait has none — but a device gone away: the exchange ends as
/// a closed connection and poisons the link.
#[test]
fn a_review_read_that_returns_nothing_is_a_closed_connection() {
    let device = ScriptedHid::new(Vec::new(), None);
    let mut link = Link::new(CHANNEL, TIMEOUT);
    let err = exchange_over(&device, &mut link, &VERSION_APDU, Deadline::UserReview)
        .expect_err("nothing answers");
    assert_eq!(err, TransportError::ConnectionClosed);
    assert!(link.is_poisoned());
}

/// The C `hidapi` backend attaches no errno; the kinds a caller branches
/// on are recovered from its `strerror` text, and anything else is
/// `Other`.
#[test]
fn hidapi_error_text_maps_to_the_kinds_callers_branch_on() {
    for (message, kind) in [
        ("Interrupted system call", ErrorKind::Interrupted),
        ("No such device", ErrorKind::NotConnected),
        (
            "hid_read_timeout: unexpected poll error (device disconnected)",
            ErrorKind::NotConnected,
        ),
        ("Permission denied", ErrorKind::PermissionDenied),
        ("Resource temporarily unavailable", ErrorKind::WouldBlock),
        ("Broken pipe", ErrorKind::BrokenPipe),
        ("Failed to write data", ErrorKind::Other),
        ("", ErrorKind::Other),
    ] {
        assert_eq!(kind_from_message(message), kind, "{message:?}");
    }
}

#[test]
fn the_vendor_id_and_usage_page_are_the_documented_ones() {
    assert_eq!(LEDGER_USB_VENDOR_ID, 0x2C97);
    assert_eq!(LEDGER_HID_USAGE_PAGE, 0xFFA0);
}

#[test]
fn a_reply_on_another_channel_is_not_spliced_in() {
    // Two host processes on one device: the frames of the other session
    // are skipped, and this one's response is reassembled from its own.
    let mut deframer = Deframer::hid(HidChannel::new(0x1111));
    let stray = device_frames(HidChannel::new(0x2222), &[0x6A, 0x80]);
    let ours = device_frames(HidChannel::new(0x1111), &VERSION_REPLY);
    assert_eq!(deframer.push(&stray[0]).unwrap(), None);
    assert_eq!(
        deframer.push(&ours[0]).unwrap().as_deref(),
        Some(&VERSION_REPLY[..])
    );
}

#[test]
fn a_short_read_is_not_treated_as_a_frame() {
    // `read_timeout` can return fewer bytes than a full report; the
    // deframer sees the slice it actually read, and refuses it as the
    // partial report it is.
    let mut deframer = Deframer::hid(HidChannel::new(0x0001));
    assert_eq!(
        deframer.push(&[0x00, 0x01, 0x05]),
        Err(crate::framing::FramingError::BadFrameLength {
            got: 3,
            expected: HID_FRAME_SIZE
        })
    );
}
