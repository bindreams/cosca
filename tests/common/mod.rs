//! Shared control-spawn test harness — the CANONICAL single source (`tests/lifecycle.rs`
//! consumes this too; integration test crates are separate compilation units, so helpers
//! are shared via `#[path = "common/mod.rs"] mod common;`).

// Each test crate compiles the whole module but uses only the subset it needs (e.g.
// `lifecycle` never calls `spawn_blocker`), so per-crate dead-code is expected here.
#![allow(dead_code)]

use std::io::Read;
use std::net::{TcpListener, TcpStream};

pub fn testbin() -> &'static str {
    env!("CARGO_BIN_EXE_subprocess_testbin")
}

/// Spawn `mode <addr> [extra...]` as a control child that connects, writes a 1-byte tag,
/// then blocks; returns the owned `Child` and the accepted socket (the tag read proves it
/// is alive). `contain` applies `.contain()`. This is the canonical form; `tests/lifecycle.rs`
/// now calls this instead of keeping its own copy.
pub fn spawn_control(mode: &str, extra: &[&str], contain: bool) -> (subprocess::Child, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut argv: Vec<String> = vec!["subprocess_testbin".into(), mode.into(), addr];
    argv.extend(extra.iter().map(|s| s.to_string()));
    let mut cmd = subprocess::Command::new();
    cmd.executable(testbin()).args(&argv);
    if contain {
        cmd.contain();
    }
    let child = cmd.spawn().expect("spawn control child");
    let (mut sock, _) = listener.accept().expect("accept");
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read tag");
    (child, sock)
}

/// Convenience alias for the common `control-block` blocker (no `.contain()`). A one-line
/// shortcut over `spawn_control`, NOT a second copy of the body.
pub fn spawn_blocker() -> (subprocess::Child, TcpStream) {
    spawn_control("control-block", &["R"], false)
}
