//! `common::payload`: nonce verification, which socket is the payload, and the accept-versus-
//! launcher-exit wiring. Every test settles on events it has ordered, none on a wait that a
//! broken helper would leave blocked.

#[path = "common/mod.rs"]
mod common;

use common::payload::{accept_payload, decide, read_peer, Event, ExitWatch, Payload, Sources};
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;

fn listener() -> (TcpListener, String) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("local_addr").to_string();
    (l, addr)
}

/// A launcher watch that returns only when the returned sender is used or dropped.
fn client() -> (mpsc::Sender<()>, ExitWatch) {
    let (tx, rx) = mpsc::channel::<()>();
    let watch = ExitWatch::custom(move || {
        let _ = rx.recv();
        "test client exit".into()
    });
    (tx, watch)
}

fn say(addr: &str, line: &str) -> TcpStream {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.write_all(line.as_bytes()).expect("write");
    s
}

/// Both ends of one loopback connection: `(the peer's end, the accepting side's end)`.
fn pair() -> (TcpStream, TcpStream) {
    let (l, addr) = listener();
    let peer = TcpStream::connect(addr).expect("connect");
    let (accepted, _) = l.accept().expect("accept");
    (peer, accepted)
}

enum Msg {
    Accepted(Payload),
    StrayClosed,
}

/// Runs `accept_payload` on its own thread. The returned sender is for the test's one watcher of
/// a rejected peer; the test holds no other sender, so a panic in `accept_payload` ends the
/// channel instead of leaving `recv` blocked.
fn accept_in_background(l: TcpListener, watch: ExitWatch) -> (mpsc::Sender<Msg>, mpsc::Receiver<Msg>) {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn({
        let tx = tx.clone();
        move || {
            let _ = tx.send(Msg::Accepted(accept_payload(l, "n0nce", watch)));
        }
    });
    (tx, rx)
}

/// Reports `StrayClosed` when `stray` reads EOF or an error: the accept side dropped it.
fn report_when_closed(tx: mpsc::Sender<Msg>, mut stray: TcpStream) {
    std::thread::spawn(move || {
        let mut sink = [0u8; 1];
        let _ = stray.read(&mut sink);
        let _ = tx.send(Msg::StrayClosed);
    });
}

/// Sends a rejected `line` from a stray peer, waits for the accept side to drop it (so it is
/// known to have been judged), and returns the receiver for what comes next.
fn reject_first(addr: &str, line: &str, l: TcpListener, watch: ExitWatch) -> mpsc::Receiver<Msg> {
    let (tx, rx) = accept_in_background(l, watch);
    report_when_closed(tx, say(addr, line));
    match rx.recv().expect("accept_payload ended without a verdict") {
        Msg::StrayClosed => rx,
        Msg::Accepted(p) => panic!(
            "the stray peer's line {line:?} was accepted as the payload (pid {})",
            p.pid
        ),
    }
}

fn accepted(rx: &mpsc::Receiver<Msg>) -> Payload {
    match rx.recv().expect("accept_payload ended without a verdict") {
        Msg::Accepted(p) => p,
        Msg::StrayClosed => panic!("a second peer was dropped while none was expected to be"),
    }
}

// Which peer is accepted =====

#[skuld::test]
fn accepts_the_peer_with_the_nonce_and_reports_its_pid() {
    let (l, addr) = listener();
    let (_keep, exit) = client();
    let _peer = say(&addr, "n0nce 4242\n");
    let p = accept_payload(l, "n0nce", exit);
    assert_eq!(p.pid, 4242);
}

#[skuld::test]
fn rejects_a_wrong_nonce_and_keeps_accepting() {
    let (l, addr) = listener();
    let (_keep, exit) = client();
    let rx = reject_first(&addr, "wrong 1\n", l, exit);
    let _right = say(&addr, "n0nce 7\n");
    assert_eq!(accepted(&rx).pid, 7);
}

#[skuld::test]
fn rejects_a_line_without_a_pid() {
    let (l, addr) = listener();
    let (_keep, exit) = client();
    let rx = reject_first(&addr, "n0nce\n", l, exit);
    let _right = say(&addr, "n0nce 9\n");
    assert_eq!(accepted(&rx).pid, 9);
}

#[skuld::test]
fn the_accepted_socket_is_the_payloads_not_the_first_peers() {
    let (l, addr) = listener();
    let (_keep, exit) = client();
    // Connections are accepted in the order they complete, so the stray is the first one accepted.
    let _stray = say(&addr, "wrong 1\n");
    let mut right = say(&addr, "n0nce 21\n");
    let mut payload = accept_payload(l, "n0nce", exit);
    assert_eq!(payload.pid, 21);
    assert_eq!(
        payload.sock.peer_addr().expect("peer_addr"),
        right.local_addr().expect("local_addr"),
        "the payload's socket is a different connection than the one that sent the nonce"
    );
    // The same connection, from the other side: what the test writes through `sock` arrives here.
    payload.sock.write_all(b"x").expect("write through sock");
    let mut got = [0u8; 1];
    right.read_exact(&mut got).expect("read what the test wrote");
    assert_eq!(&got, b"x");
}

#[skuld::test]
fn a_stray_peer_that_never_writes_does_not_block_the_real_one() {
    let (l, addr) = listener();
    let (_keep, exit) = client();
    let _silent = TcpStream::connect(&addr).expect("connect");
    let _right = say(&addr, "n0nce 11\n");
    assert_eq!(accept_payload(l, "n0nce", exit).pid, 11);
}

#[skuld::test]
fn a_peer_that_hangs_up_without_writing_is_rejected() {
    let (l, addr) = listener();
    let (_keep, exit) = client();
    drop(TcpStream::connect(&addr).expect("connect"));
    let _right = say(&addr, "n0nce 13\n");
    assert_eq!(accept_payload(l, "n0nce", exit).pid, 13);
}

// What a stranger can send =====

#[skuld::test]
fn bytes_after_the_line_are_left_in_the_socket_and_do_not_panic() {
    let (mut peer, accepted) = pair();
    peer.write_all(b"wrong 1\nextra bytes").expect("write");
    match read_peer(accepted) {
        Event::Line(mut sock, Ok(line)) => {
            assert_eq!(line, "wrong 1");
            drop(peer);
            let mut rest = String::new();
            sock.read_to_string(&mut rest).expect("read the rest");
            assert_eq!(rest, "extra bytes");
        }
        other => panic!("expected the line, got {other:?}"),
    }
}

#[skuld::test]
fn a_line_that_is_not_utf8_is_that_peers_rejection() {
    let (mut peer, accepted) = pair();
    peer.write_all(b"\xff\xfe\n").expect("write");
    assert!(matches!(read_peer(accepted), Event::Line(_, Err(_))));
}

#[skuld::test]
fn a_peer_that_hangs_up_mid_line_is_that_peers_rejection() {
    let (mut peer, accepted) = pair();
    peer.write_all(b"n0nce 5").expect("write");
    drop(peer);
    assert!(matches!(read_peer(accepted), Event::Line(_, Err(_))));
}

// The deciding loop =====

#[skuld::test]
fn the_launcher_exiting_first_is_the_verdict() {
    let (_peer, stray) = pair();
    let events = [
        Event::Line(stray, Ok("wrong 1".into())),
        Event::ClientExited("gone".into()),
    ];
    let message = decide("n0nce", events).expect_err("no payload arrived");
    assert!(message.contains("client exited (gone)"), "{message}");
}

#[skuld::test]
fn the_socket_decided_on_is_the_payloads_not_the_first_peers() {
    let (_stray_peer, stray) = pair();
    let (right_peer, right) = pair();
    let events = [
        Event::Line(stray, Ok("wrong 1".into())),
        Event::Line(right, Ok("n0nce 21".into())),
    ];
    let (sock, pid) = decide("n0nce", events).expect("the second peer is the payload");
    assert_eq!(pid, 21);
    assert_eq!(
        sock.peer_addr().expect("peer_addr"),
        right_peer.local_addr().expect("local_addr"),
        "decide returned a socket that is not the payload's"
    );
}

#[skuld::test]
fn a_failed_accept_is_the_verdict() {
    let events = [Event::AcceptFailed(std::io::Error::other("boom"))];
    let message = decide("n0nce", events).expect_err("no payload arrived");
    assert!(
        message.contains("accepting the payload's connection failed: boom"),
        "{message}"
    );
}

#[skuld::test]
fn events_that_run_out_are_a_verdict_not_a_wait() {
    let message = decide("n0nce", []).expect_err("no payload arrived");
    assert!(message.contains("hung up without a verdict"), "{message}");
}

// The launcher watch is wired to the deciding loop =====

#[skuld::test]
fn a_custom_watch_reports_the_launchers_exit_to_the_deciding_loop() {
    let (l, _addr) = listener();
    let events = Sources::start(l, ExitWatch::custom(|| "the fake launcher exited".into())).settle();
    assert!(
        matches!(events.as_slice(), [Event::ClientExited(how)] if how == "the fake launcher exited"),
        "{events:?}"
    );
}

#[skuld::test]
fn an_unobservable_watch_reports_nothing() {
    let (l, _addr) = listener();
    let events = Sources::start(l, ExitWatch::Unobservable).settle();
    assert!(events.is_empty(), "{events:?}");
}

#[skuld::test]
fn a_process_watch_reports_the_process_exit_once_it_is_armed() {
    use std::process::{Command, Stdio};
    let (l, _addr) = listener();
    let mut child = common::spawn_locked(
        Command::new(common::testbin())
            .arg("hold-until-stdin-eof")
            .stdin(Stdio::piped()),
    )
    .expect("spawn a process that outlives the watch's arming");
    // `start` returns only once the watch is armed, so the exit below is one it must report.
    let sources = Sources::start(l, ExitWatch::Process(child.id()));
    assert!(sources.armed(), "start returned before the process watch was armed");
    drop(child.stdin.take());
    let events = sources.settle();
    child.wait().expect("reap");
    assert!(
        matches!(events.as_slice(), [Event::ClientExited(how)] if how.contains("exited")),
        "{events:?}"
    );
}

#[skuld::test]
fn release_joins_the_exit_watch() {
    let (l, addr) = listener();
    let (tx, exit) = client();
    let _peer = say(&addr, "n0nce 5\n");
    let p = accept_payload(l, "n0nce", exit);
    tx.send(()).expect("wake the exit watch");
    // Only a join can hand back what the watch returned.
    assert_eq!(p.release().as_deref(), Some("test client exit"));
}

#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.run()
}
