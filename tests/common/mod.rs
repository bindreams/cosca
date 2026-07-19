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

/// Spawn a 2-level tree via a grandchild-spawning testbin `mode` (root tag "R" + one grandchild
/// tag "G"), optionally contained, and return the owned `Child` plus BOTH accepted sockets (the
/// two tag reads prove the 2-level tree is alive). The tree dies — and both sockets EOF — only
/// when the whole tree is torn down, so callers prove teardown by reading EOF on both, never by
/// a timer.
pub fn spawn_tree(mode: &str, contain: bool) -> (subprocess::Child, Vec<TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = subprocess::Command::new();
    cmd.executable(testbin())
        .args(["subprocess_testbin", mode, addr.as_str()]);
    if contain {
        cmd.contain();
    }
    let child = cmd.spawn().expect("spawn tree");
    // Demux by tag exactly like spawn_tree_async (accept order is not guaranteed, and a
    // duplicate or foreign tag is a harness bug worth failing loudly on).
    let (mut root, mut grand) = (None, None);
    for _ in 0..2 {
        let (mut s, _) = listener.accept().expect("accept");
        let mut tag = [0u8; 1];
        s.read_exact(&mut tag).expect("read tag");
        match &tag {
            b"R" => root = Some(s),
            b"G" => grand = Some(s),
            other => panic!("unexpected tree tag {other:?}"),
        }
    }
    (
        child,
        vec![root.expect("root R connected"), grand.expect("grandchild G connected")],
    )
}

/// Spawn the `spawn-grandchild` helper tree.
pub fn spawn_grandchild(contain: bool) -> (subprocess::Child, Vec<TcpStream>) {
    spawn_tree("spawn-grandchild", contain)
}

/// Async analogue of `spawn_control`: spawn a testbin control child (it connects back and
/// sends its tag before the helper returns), optionally contained.
#[cfg(feature = "tokio")]
pub fn spawn_control_async(mode: &str, extra: &[&str], contain: bool) -> (subprocess::tokio::Child, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut argv: Vec<String> = vec!["subprocess_testbin".into(), mode.into(), addr];
    argv.extend(extra.iter().map(|s| s.to_string()));
    let mut cmd = subprocess::tokio::Command::new();
    if contain {
        // async Windows rejects contained `executable()` until Task 8 wires the raw backend's async
        // containment; load the testbin as argv[0] via the std path instead (mode/addr stay at
        // args[1..], so the testbin behaves identically).
        let mut path_argv = vec![testbin().to_string()];
        path_argv.extend(argv.into_iter().skip(1));
        cmd.args(path_argv);
        cmd.contain();
    } else {
        cmd.executable(testbin()).args(&argv); // uncontained → the async raw backend
    }
    let child = cmd.spawn().expect("spawn async control child");
    let (mut sock, _) = listener.accept().expect("accept");
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read tag");
    (child, sock)
}

/// Spawn a 2-level tree via a grandchild-spawning testbin `mode` (root tag "R", grandchild
/// tag "G"), with builder configuration supplied by `configure` (containment mode, nesting).
/// Returns the root and grandchild control sockets identified by tag (accept order is not
/// guaranteed).
#[cfg(feature = "tokio")]
pub fn spawn_tree_async(
    mode: &str,
    configure: impl FnOnce(&mut subprocess::tokio::Command),
) -> (subprocess::tokio::Child, TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = subprocess::tokio::Command::new();
    // Load the testbin as argv[0] via the std path (mode/addr at args[1..]): these trees are
    // contained (and async Windows rejects contained `executable()` until Task 8's async
    // containment), and the sole uncontained caller is backend-agnostic. `configure` applies the
    // containment/nesting/kill_on_drop.
    cmd.args([testbin(), mode, addr.as_str()]);
    configure(&mut cmd);
    let child = cmd.spawn().expect("spawn async tree");
    let (mut root, mut grandchild) = (None, None);
    for _ in 0..2 {
        let (mut s, _) = listener.accept().expect("accept");
        let mut tag = [0u8; 1];
        s.read_exact(&mut tag).expect("read tag");
        match &tag {
            b"R" => root = Some(s),
            b"G" => grandchild = Some(s),
            other => panic!("unexpected tree tag {other:?}"),
        }
    }
    (
        child,
        root.expect("root R connected"),
        grandchild.expect("grandchild G connected"),
    )
}

/// Async `control-block` blocker (uncontained): a child that connects, tags "R", and blocks on
/// its socket. The accept/tag-read is sync std (the test side); the CHILD is async.
#[cfg(feature = "tokio")]
pub fn spawn_blocker_async() -> (subprocess::tokio::Child, TcpStream) {
    spawn_control_async("control-block", &["R"], false)
}

/// Async analogue of `spawn_grandchild`, returning the root ("R") and grandchild ("G") control
/// sockets identified by tag (accept order is not guaranteed).
#[cfg(feature = "tokio")]
pub fn spawn_grandchild_async(contain: bool) -> (subprocess::tokio::Child, TcpStream, TcpStream) {
    spawn_grandchild_async_with(contain, true)
}

/// `spawn_grandchild_async` with explicit `contain` and `kill_on_drop` flags, so a test can
/// exercise the `kill_on_drop(false)` Drop early-return (attached still armed) without `detach()`.
#[cfg(feature = "tokio")]
pub fn spawn_grandchild_async_with(
    contain: bool,
    kill_on_drop: bool,
) -> (subprocess::tokio::Child, TcpStream, TcpStream) {
    spawn_tree_async("spawn-grandchild", |cmd| {
        if contain {
            cmd.contain();
        }
        cmd.kill_on_drop(kill_on_drop);
    })
}
