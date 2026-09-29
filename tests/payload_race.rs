//! `common::payload::accept_payload`: nonce verification and the accept-versus-client-exit race.

#[path = "common/mod.rs"]
mod common;

use common::payload::accept_payload;
use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;

fn listener() -> (TcpListener, String) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = l.local_addr().expect("local_addr").to_string();
    (l, addr)
}

/// A `client_exit` that returns only when the returned sender is used or dropped.
fn client() -> (mpsc::Sender<()>, impl FnOnce() -> String + Send + 'static) {
    let (tx, rx) = mpsc::channel::<()>();
    (tx, move || {
        let _ = rx.recv();
        "test client exit".into()
    })
}

fn say(addr: &str, line: &str) -> TcpStream {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.write_all(line.as_bytes()).expect("write");
    s
}

#[test]
fn accepts_the_peer_with_the_nonce_and_reports_its_pid() {
    let (l, addr) = listener();
    let (_keep, exit) = client();
    let _peer = say(&addr, "n0nce 4242\n");
    let p = accept_payload(l, "n0nce", exit);
    assert_eq!(p.pid, 4242);
}

#[test]
fn rejects_a_wrong_nonce_and_keeps_accepting() {
    let (l, addr) = listener();
    let (_keep, exit) = client();
    let _wrong = say(&addr, "wrong 1\n");
    let _right = say(&addr, "n0nce 7\n");
    assert_eq!(accept_payload(l, "n0nce", exit).pid, 7);
}

#[test]
fn rejects_a_line_without_a_pid() {
    let (l, addr) = listener();
    let (_keep, exit) = client();
    let _bare = say(&addr, "n0nce\n");
    let _right = say(&addr, "n0nce 9\n");
    assert_eq!(accept_payload(l, "n0nce", exit).pid, 9);
}

#[test]
fn a_stray_peer_that_never_writes_does_not_block_the_real_one() {
    let (l, addr) = listener();
    let (_keep, exit) = client();
    let _silent = TcpStream::connect(&addr).expect("connect");
    let _right = say(&addr, "n0nce 11\n");
    assert_eq!(accept_payload(l, "n0nce", exit).pid, 11);
}

#[test]
fn a_peer_that_hangs_up_without_writing_is_rejected() {
    let (l, addr) = listener();
    let (_keep, exit) = client();
    drop(TcpStream::connect(&addr).expect("connect"));
    let _right = say(&addr, "n0nce 13\n");
    assert_eq!(accept_payload(l, "n0nce", exit).pid, 13);
}

#[test]
fn panics_when_the_client_exits_before_any_peer_connects() {
    let (l, _addr) = listener();
    let (tx, exit) = client();
    drop(tx);
    let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| accept_payload(l, "n0nce", exit)))
        .expect_err("must panic");
    let msg = err.downcast_ref::<String>().expect("a formatted panic message");
    assert!(msg.contains("client exited"), "{msg}");
}

#[test]
fn panics_when_the_client_exits_while_a_stray_peer_is_silent() {
    let (l, addr) = listener();
    let (tx, exit) = client();
    let _silent = TcpStream::connect(&addr).expect("connect");
    let _wrong = say(&addr, "wrong 1\n");
    drop(tx);
    let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| accept_payload(l, "n0nce", exit)))
        .expect_err("must panic");
    let msg = err.downcast_ref::<String>().expect("a formatted panic message");
    assert!(msg.contains("client exited"), "{msg}");
}

#[test]
fn release_joins_the_client_exit_closure() {
    let (l, addr) = listener();
    let (tx, exit) = client();
    let _peer = say(&addr, "n0nce 5\n");
    let p = accept_payload(l, "n0nce", exit);
    tx.send(()).expect("wake the client-exit closure");
    p.release();
}
