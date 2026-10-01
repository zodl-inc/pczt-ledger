use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use crate::apdu::encode::header_apdu;
use crate::session::Deadline;
use crate::test_support::{header_vector, VERSION_APDU, VERSION_REPLY};
use crate::transport::speculos::{
    addr_from_env, addr_or_default, frame_reply, frame_request, SpeculosTransport,
    DEFAULT_SPECULOS_ADDR, MAX_RESPONSE_LEN, SPECULOS_ADDR_ENV,
};
use crate::transport::{Transport, TransportError};

// ---------------------------------------------------------------------------
// Transports
// ---------------------------------------------------------------------------
//
// These exercise the two transports' *framing* against the deframers and the
// emulator's own protocol. Neither needs hardware: the HID side is checked by
// running the exact bytes `HidTransport` would write back through
// `Deframer::hid`, and the speculos side against a loopback fake that
// reimplements `speculos/mcu/apdu.py`'s arithmetic independently.

/// Reads one length-prefixed request the way the emulator does.
fn read_request(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut prefix = [0u8; 4];
    stream.read_exact(&mut prefix).ok()?;
    let len = u32::from_be_bytes(prefix) as usize;
    let mut apdu = vec![0u8; len];
    stream.read_exact(&mut apdu).ok()?;
    Some(apdu)
}

/// A fake emulator that answers each request from `replies`, in order.
///
/// `replies` are whole payloads (data ‖ SW); the fake applies the
/// `len(packet) - 2` prefix itself, written out here rather than reusing
/// [`frame_reply`] so the test is not checking the code against itself.
fn fake_speculos(replies: Vec<Vec<u8>>) -> (String, thread::JoinHandle<Vec<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr").to_string();

    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut seen = Vec::new();
        for reply in replies {
            match read_request(&mut stream) {
                Some(apdu) => seen.push(apdu),
                None => break,
            }
            let mut packet = ((reply.len() - 2) as u32).to_be_bytes().to_vec();
            packet.extend_from_slice(&reply);
            stream.write_all(&packet).expect("write reply");
        }
        seen
    });

    (addr, handle)
}

#[test]
fn the_request_prefix_is_the_whole_apdu_length() {
    let apdu = [0xE0, 0xC4, 0x00, 0x00, 0x00];
    assert_eq!(
        frame_request(&apdu).unwrap(),
        vec![0x00, 0x00, 0x00, 0x05, 0xE0, 0xC4, 0x00, 0x00, 0x00]
    );
}

#[test]
fn the_reply_prefix_excludes_the_status_word() {
    // `apdu.py`: `size = (len(packet) - 2) & 0xffffffff`, then the whole
    // packet — status word included — is written after it.
    let reply = [0x03, 0x09, 0x02, 0x00, 0x02, 0x01, 0x00, 0x14, 0x90, 0x00];
    let framed = frame_reply(&reply).expect("long enough for a status word");
    assert_eq!(&framed[..4], &[0x00, 0x00, 0x00, 0x08]);
    assert_eq!(&framed[4..], &reply);
    assert_eq!(framed.len(), 4 + reply.len());
}

#[test]
fn a_reply_with_no_room_for_a_status_word_is_refused() {
    assert_eq!(frame_reply(&[0x90]), None);
    assert_eq!(frame_reply(&[]), None);
}

#[test]
fn an_empty_data_reply_still_carries_its_status_word() {
    // Every `PCZT_*` streaming command answers with `9000` and no data,
    // which is the case a prefix-only reader would swallow entirely.
    let framed = frame_reply(&[0x90, 0x00]).expect("two bytes is a status word");
    assert_eq!(framed, vec![0x00, 0x00, 0x00, 0x00, 0x90, 0x00]);
}

#[test]
fn an_exchange_round_trips_through_a_loopback_emulator() {
    let version = VERSION_REPLY.to_vec();
    let streamed = vec![0x90, 0x00];
    let (addr, server) = fake_speculos(vec![version.clone(), streamed.clone()]);

    let mut transport = SpeculosTransport::connect(addr).expect("connect");
    assert_eq!(
        *transport.exchange(&VERSION_APDU).expect("version reply"),
        version
    );

    // A zero-length data reply must not be mistaken for a closed socket.
    let stream_apdu = header_apdu(&header_vector()).to_bytes();
    assert_eq!(
        *transport
            .exchange_with(&stream_apdu, Deadline::UserReview)
            .expect("streaming reply"),
        streamed
    );

    let seen = server.join().expect("server thread");
    assert_eq!(seen, vec![VERSION_APDU.to_vec(), stream_apdu]);
}

#[test]
fn a_closed_socket_is_reported_as_such() {
    // The fake consumes the request before hanging up, so the client sees
    // an orderly FIN on the read rather than a reset provoked by writing to
    // an already-closed socket.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr").to_string();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let _ = read_request(&mut stream);
    });

    let mut transport = SpeculosTransport::connect(addr).expect("connect");
    let err = transport
        .exchange(&VERSION_APDU)
        .expect_err("the fake answers nothing and hangs up");
    assert!(
        matches!(err, TransportError::ConnectionClosed),
        "unexpected error: {err}"
    );
    assert!(
        transport.is_poisoned(),
        "the request went out and nothing came back"
    );
    server.join().expect("server thread");
}

/// EOF in the middle of a reply's payload is the same closed connection,
/// and poisons: what was read is not a reply to anything.
#[test]
fn an_eof_mid_payload_is_a_closed_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr").to_string();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let _ = read_request(&mut stream);
        // Declares 8 data bytes, sends 4, hangs up.
        let mut packet = 8u32.to_be_bytes().to_vec();
        packet.extend_from_slice(&[1, 2, 3, 4]);
        stream.write_all(&packet).expect("write");
    });

    let mut transport = SpeculosTransport::connect(addr).expect("connect");
    let err = transport
        .exchange(&VERSION_APDU)
        .expect_err("the reply stops short");
    assert!(matches!(err, TransportError::ConnectionClosed), "{err}");
    assert!(transport.is_poisoned());
    server.join().expect("server thread");
}

/// A length prefix past the cap is refused before anything is allocated
/// for it, and poisons: the bytes it announced are still coming.
#[test]
fn an_oversized_prefix_is_refused_and_poisons() {
    // What speculos emits for a one-byte packet: `(1 - 2) & 0xFFFFFFFF`.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr").to_string();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let _ = read_request(&mut stream);
        let mut packet = 0xFFFF_FFFFu32.to_be_bytes().to_vec();
        packet.push(0x90);
        stream.write_all(&packet).expect("write");
        // Hold the socket open until the client is done with it.
        let _ = read_request(&mut stream);
    });

    let mut transport = SpeculosTransport::connect(addr).expect("connect");
    let err = transport
        .exchange(&VERSION_APDU)
        .expect_err("the prefix is absurd");
    assert_eq!(
        err,
        TransportError::ResponseTooLarge {
            declared: 0xFFFF_FFFF,
            max: MAX_RESPONSE_LEN,
        }
    );
    assert!(transport.is_poisoned());
    assert!(matches!(
        transport.exchange(&VERSION_APDU),
        Err(TransportError::Poisoned { .. })
    ));
    drop(transport);
    server.join().expect("server thread");
}

/// `Deadline::UserReview` lifts the per-exchange timeout: a reply that
/// arrives well after it is still collected.
#[test]
fn a_review_exchange_waits_past_the_per_exchange_timeout() {
    let reply = vec![0x90, 0x00];
    let (addr, server) = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr").to_string();
        let reply = reply.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let _ = read_request(&mut stream);
            thread::sleep(Duration::from_millis(300));
            let mut packet = ((reply.len() - 2) as u32).to_be_bytes().to_vec();
            packet.extend_from_slice(&reply);
            stream.write_all(&packet).expect("write");
        });
        (addr, server)
    };

    let mut transport = SpeculosTransport::connect(addr)
        .expect("connect")
        .with_timeout(Duration::from_millis(50));
    let got = transport
        .exchange_with(
            &header_apdu(&header_vector()).to_bytes(),
            Deadline::UserReview,
        )
        .expect("a review has no deadline");
    assert_eq!(*got, reply);
    assert!(!transport.is_poisoned());
    server.join().expect("server thread");
}

/// The timeout bounds the exchange, not each read: a peer that trickles
/// a reply one byte at a time, each inside the timeout, is cut off when
/// the whole exchange has taken that long.
#[test]
fn a_trickling_reply_is_cut_off_at_the_per_exchange_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr").to_string();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let _ = read_request(&mut stream);
        // A 10-byte reply, one byte every 60 ms: 14 bytes on the wire,
        // well over 800 ms in all.
        let reply = [0xAB; 8];
        let mut packet = ((reply.len()) as u32).to_be_bytes().to_vec();
        packet.extend_from_slice(&reply);
        packet.extend_from_slice(&[0x90, 0x00]);
        for byte in packet {
            if stream.write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(60));
        }
    });

    let mut transport = SpeculosTransport::connect(addr)
        .expect("connect")
        .with_timeout(Duration::from_millis(200));
    let started = Instant::now();
    let err = transport
        .exchange(&VERSION_APDU)
        .expect_err("the exchange outlives its budget");
    let elapsed = started.elapsed();
    assert!(matches!(err, TransportError::Timeout { .. }), "{err}");
    assert!(
        elapsed >= Duration::from_millis(190) && elapsed < Duration::from_millis(600),
        "cut off at the budget, not at the end of the trickle: {elapsed:?}"
    );
    assert!(transport.is_poisoned());
    drop(transport);
    server.join().expect("server thread");
}

/// A zero timeout is "do not wait": a `Normal` exchange answers `Timeout`
/// before anything is written, and leaves the link clean, as the HID
/// transport does with the same setting.
#[test]
fn a_zero_timeout_is_a_timeout_before_the_write() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr").to_string();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        read_request(&mut stream)
    });

    let mut transport = SpeculosTransport::connect(addr)
        .expect("connect")
        .with_timeout(Duration::ZERO);
    assert_eq!(
        transport.exchange(&VERSION_APDU),
        Err(TransportError::Timeout {
            waited: Duration::ZERO
        })
    );
    assert!(!transport.is_poisoned());
    drop(transport);
    assert_eq!(
        server.join().expect("server thread"),
        None,
        "nothing was written"
    );
}

/// An empty command is refused before anything is written, as it is on HID:
/// an APDU begins with `CLA INS P1 P2`, and the zero-length packet this would
/// otherwise put on the wire is not one.
#[test]
fn an_empty_command_is_refused_before_the_write() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr").to_string();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        read_request(&mut stream)
    });

    let mut transport = SpeculosTransport::connect(addr).expect("connect");
    assert_eq!(transport.exchange(&[]), Err(TransportError::EmptyRequest));
    assert!(!transport.is_poisoned());
    drop(transport);
    assert_eq!(
        server.join().expect("server thread"),
        None,
        "nothing was written"
    );
}

/// The environment names the emulator, or does not; a value that is not
/// Unicode is an error rather than a silent "does not".
#[test]
fn the_environment_names_the_emulator() {
    let saved = std::env::var_os(SPECULOS_ADDR_ENV);

    std::env::remove_var(SPECULOS_ADDR_ENV);
    assert_eq!(addr_from_env(), Ok(None));
    assert_eq!(addr_or_default(), Ok(DEFAULT_SPECULOS_ADDR.to_string()));
    assert!(SpeculosTransport::connect_from_env().is_none());

    for blank in ["", "   ", "\t"] {
        std::env::set_var(SPECULOS_ADDR_ENV, blank);
        assert_eq!(addr_from_env(), Ok(None), "{blank:?}");
    }

    std::env::set_var(SPECULOS_ADDR_ENV, " 127.0.0.1:1234 ");
    assert_eq!(addr_from_env(), Ok(Some("127.0.0.1:1234".to_string())));
    assert_eq!(addr_or_default(), Ok("127.0.0.1:1234".to_string()));

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        std::env::set_var(
            SPECULOS_ADDR_ENV,
            std::ffi::OsStr::from_bytes(&[0x31, 0xFF, 0x32]),
        );
        assert!(matches!(
            addr_from_env(),
            Err(TransportError::Io {
                kind: std::io::ErrorKind::InvalidData,
                ..
            })
        ));
        assert!(matches!(
            SpeculosTransport::connect_from_env(),
            Some(Err(TransportError::Io { .. }))
        ));
    }

    match saved {
        Some(value) => std::env::set_var(SPECULOS_ADDR_ENV, value),
        None => std::env::remove_var(SPECULOS_ADDR_ENV),
    }
}

/// A reply that arrives after its exchange timed out must not be read as
/// the reply to the next command: the timeout poisons the connection, and
/// the next exchange is refused with the late reply still in the socket.
#[test]
fn a_timed_out_exchange_poisons_the_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr").to_string();
    let late_reply = VERSION_REPLY.to_vec();
    let server = thread::spawn({
        let late_reply = late_reply.clone();
        move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let request = read_request(&mut stream);
            // Answer well after the client has given up.
            thread::sleep(std::time::Duration::from_millis(400));
            let mut packet = ((late_reply.len() - 2) as u32).to_be_bytes().to_vec();
            packet.extend_from_slice(&late_reply);
            let _ = stream.write_all(&packet);
            request
        }
    });

    let mut transport = SpeculosTransport::connect(addr)
        .expect("connect")
        .with_timeout(std::time::Duration::from_millis(100));
    let err = transport
        .exchange(&VERSION_APDU)
        .expect_err("the reply is late");
    assert!(matches!(err, TransportError::Timeout { .. }), "{err}");
    assert!(transport.is_poisoned());

    // Wait until the late reply is certainly sitting in the socket, then
    // ask again: without poisoning this would return the version reply as
    // the answer to a header command.
    server.join().expect("server thread");
    let header = header_apdu(&header_vector()).to_bytes();
    let err = transport
        .exchange(&header)
        .expect_err("a poisoned connection refuses every exchange");
    assert!(
        matches!(
            &err,
            TransportError::Poisoned { source }
                if matches!(**source, TransportError::Timeout { .. })
        ),
        "{err}"
    );
}

#[test]
fn a_normal_deadline_times_out_rather_than_hanging() {
    // A fake that accepts and then never answers: the socket stays open, so
    // only the read timeout can end this.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr").to_string();
    let held = std::thread::spawn(move || listener.accept().map(|(s, _)| s));

    let mut transport = SpeculosTransport::connect(addr)
        .expect("connect")
        .with_timeout(std::time::Duration::from_millis(150));
    let err = transport
        .exchange(&VERSION_APDU)
        .expect_err("nobody answers");
    assert!(
        matches!(err, TransportError::Timeout { .. }),
        "unexpected error: {err}"
    );
    drop(held.join().expect("accept thread"));
}
