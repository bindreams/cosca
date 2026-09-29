//! testbin's `block-on-socket` payload, unelevated and on every OS: the elevation tests rely on
//! it and cannot run without privilege, so this is where its contract is checked always.
//!
//! The contract: connect to the address in `argv[2]`, write `<argv[3]> <own pid>\n`, then block
//! until the peer sends anything or hangs up, and exit 0. Death by any other route is EOF (or a
//! reset) on the peer's end.

#[path = "common/mod.rs"]
mod common;

use common::payload::{accept_payload, fresh_nonce, ExitWatch};
use shared_child::SharedChild;
use std::io::{BufRead as _, Read as _};
use std::net::{Shutdown, TcpListener};
use std::process::Command;
use std::time::Duration;

/// How long a payload whose socket was closed may take to exit before the test calls it hung.
/// A failure bound on a child-process exit, not a synchronization delay: the exit is what is
/// under test, and a regression makes it never happen.
const EXIT_BOUND: Duration = Duration::from_secs(30);

fn bind() -> (TcpListener, String) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind readiness listener");
    let addr = l.local_addr().expect("local_addr").to_string();
    (l, addr)
}

/// The payload process, killed when the test ends however it ends: a payload that never exits
/// would otherwise outlive a failed test.
struct Spawned(SharedChild);

impl std::ops::Deref for Spawned {
    type Target = SharedChild;
    fn deref(&self) -> &SharedChild {
        &self.0
    }
}

impl Drop for Spawned {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_payload(addr: &str, nonce: &str) -> Spawned {
    let mut c = Command::new(common::testbin());
    c.args(["block-on-socket", addr, nonce]);
    Spawned(SharedChild::spawn(&mut c).expect("spawn block-on-socket"))
}

#[test]
fn the_payload_writes_its_nonce_and_own_pid() {
    let (l, addr) = bind();
    let nonce = fresh_nonce();
    let child = spawn_payload(&addr, &nonce);
    let (sock, _) = l.accept().expect("accept the payload");
    let mut line = String::new();
    std::io::BufReader::new(&sock)
        .read_line(&mut line)
        .expect("read the payload's line");
    assert_eq!(line, format!("{nonce} {}\n", child.id()));
}

#[test]
fn a_killed_payload_is_eof_on_its_socket() {
    let (l, addr) = bind();
    let nonce = fresh_nonce();
    let child = spawn_payload(&addr, &nonce);
    let mut payload = accept_payload(l, &nonce, ExitWatch::Process(child.id()));
    assert_eq!(payload.pid, child.id());
    child.kill().expect("kill the payload");
    child.wait().expect("reap");
    let mut sink = [0u8; 1];
    match payload.sock.read(&mut sink) {
        Ok(0) => {}
        // A killed process may reset its connections instead of closing them; both are its death.
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("expected EOF or a reset from the killed payload, got {other:?}"),
    }
    payload.release();
}

#[test]
fn the_payload_exits_when_its_peer_hangs_up() {
    let (l, addr) = bind();
    let nonce = fresh_nonce();
    let child = spawn_payload(&addr, &nonce);
    let payload = accept_payload(l, &nonce, ExitWatch::Process(child.id()));
    payload.sock.shutdown(Shutdown::Both).expect("hang up");
    match child.wait_timeout(EXIT_BOUND).expect("wait for the payload") {
        Some(status) => assert!(status.success(), "the payload exited abnormally: {status:?}"),
        None => panic!("the payload was still running {EXIT_BOUND:?} after its peer hung up"),
    }
    payload.release();
}
