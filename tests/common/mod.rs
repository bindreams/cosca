//! Shared control-spawn test harness — the CANONICAL single source (`tests/lifecycle.rs`
//! consumes this too; integration test crates are separate compilation units, so helpers
//! are shared via `#[path = "common/mod.rs"] mod common;`).

// Each test crate compiles the whole module but uses only the subset it needs (e.g.
// `lifecycle` never calls `spawn_blocker`), so per-crate dead code and unused imports (e.g. the
// log-capture re-exports, which only `macos_fdmarker.rs` uses) are expected here.
#![allow(dead_code, unused_imports)]

use std::io::Read;
use std::net::{TcpListener, TcpStream};

pub fn testbin() -> &'static str {
    env!("CARGO_BIN_EXE_cosca_testbin")
}

/// Run `cmd` under `cosca::test_spawn_lock()` and return its captured output — the ONLY way
/// this test surface should fork a RAW `std::process::Command` (one not going through
/// `cosca::Command`, which already takes this same lock internally). Cargo runs `#[test]` fns
/// in one binary concurrently, and every test in `tests/macos_fdmarker.rs` runs a real
/// `FdMarker` sweep; an unguarded raw fork can transiently inherit a live marker pre-`exec`,
/// and a concurrent sweep can then confirm and SIGKILL it before it gets there. A single
/// wrapper, not a `let _guard = ...;` line the caller must remember, closes that gap for
/// every call site at once — including any added later.
pub fn output_locked(cmd: &mut std::process::Command) -> std::io::Result<std::process::Output> {
    let _guard = cosca::test_spawn_lock();
    cmd.output()
}

/// The `.status()` sibling of [`output_locked`] — see there for why raw spawns in this test
/// surface must go through one of these two, not a bare `std::process::Command` call.
pub fn status_locked(cmd: &mut std::process::Command) -> std::io::Result<std::process::ExitStatus> {
    let _guard = cosca::test_spawn_lock();
    cmd.status()
}

/// Block until `pid` — which MUST be an unreaped child of this process — has exited AND become
/// a zombie, leaving it unreaped for the caller to assert on and then reap. The canonical
/// zombie edge for this suite: the ONLY sync point that a liveness assertion about a zombie may
/// be taken at.
///
/// A death-watch is NOT a substitute. `Process::wait` returns on the OS exit edge, and on macOS
/// that edge is `proc_exit`'s `proc_knote(p, NOTE_EXIT)`, which XNU posts well before the same
/// function assigns `p->p_stat = SZOMB` — so a liveness check taken there can still read the
/// process as running. Neither is a pipe or socket EOF on the dying process's own descriptors:
/// `proc_exit` invalidates the fd table earlier still. `waitid` reports `WEXITED` only out of
/// the kernel's `SZOMB` case, so its return IS the zombie transition, and `WNOWAIT` leaves the
/// zombie collectable.
#[cfg(unix)]
pub fn block_until_zombie(pid: cosca::identity::RawPid) {
    loop {
        let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `si` is a valid, correctly-sized out-param; `pid` is our own unreaped child.
        let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut si, libc::WEXITED | libc::WNOWAIT) };
        if rc == 0 {
            return;
        }
        // EINTR is a restart, not a failure — the codebase's convention for every blocking
        // syscall (see `wait/macos.rs`, `identity/macos/kinfo.rs`).
        let e = std::io::Error::last_os_error();
        assert_eq!(
            e.raw_os_error(),
            Some(libc::EINTR),
            "waitid(P_PID, {pid}, WEXITED | WNOWAIT): {e}"
        );
    }
}

/// A capturing `log::Log` for asserting on log output from an integration-test process — a fresh
/// copy of `src/log_capture.rs`'s `pub(crate)`-private original, which a separate compilation unit
/// like this one cannot name.
mod log_capture {
    use std::sync::{Mutex, OnceLock};

    struct CaptureLog;
    static RECORDS: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static INSTALLED: OnceLock<()> = OnceLock::new();

    impl log::Log for CaptureLog {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }
        fn log(&self, record: &log::Record<'_>) {
            RECORDS.lock().unwrap().push(record.args().to_string());
        }
        fn flush(&self) {}
    }

    pub fn install() {
        INSTALLED.get_or_init(|| {
            log::set_logger(&CaptureLog).expect("first logger in this test process");
            log::set_max_level(log::LevelFilter::Trace);
        });
    }

    pub fn mark() -> usize {
        RECORDS.lock().unwrap().len()
    }

    pub fn contains_since(mark: usize, needle: &str) -> bool {
        RECORDS.lock().unwrap()[mark..].iter().any(|m| m.contains(needle))
    }
}
pub use log_capture::{contains_since, install as install_log_capture, mark as log_mark};

/// Spawn `mode <addr> [extra...]` as a control child that connects, writes a 1-byte tag,
/// then blocks; returns the owned `Child` and the accepted socket (the tag read proves it
/// is alive). `contain` applies `.contain()`. This is the canonical form; `tests/lifecycle.rs`
/// now calls this instead of keeping its own copy.
pub fn spawn_control(mode: &str, extra: &[&str], contain: bool) -> (cosca::Child, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut argv: Vec<String> = vec!["cosca_testbin".into(), mode.into(), addr];
    argv.extend(extra.iter().map(|s| s.to_string()));
    let mut cmd = cosca::Command::new();
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
pub fn spawn_blocker() -> (cosca::Child, TcpStream) {
    spawn_control("control-block", &["R"], false)
}

/// Spawn a 2-level tree via a grandchild-spawning testbin `mode` (root tag "R" + one grandchild
/// tag "G"), optionally contained, and return the owned `Child` plus BOTH accepted sockets (the
/// two tag reads prove the 2-level tree is alive). The tree dies — and both sockets EOF — only
/// when the whole tree is torn down, so callers prove teardown by reading EOF on both, never by
/// a timer.
pub fn spawn_tree(mode: &str, contain: bool) -> (cosca::Child, Vec<TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = cosca::Command::new();
    cmd.executable(testbin()).args(["cosca_testbin", mode, addr.as_str()]);
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
pub fn spawn_grandchild(contain: bool) -> (cosca::Child, Vec<TcpStream>) {
    spawn_tree("spawn-grandchild", contain)
}

/// Async analogue of `spawn_control`: spawn a testbin control child (it connects back and
/// sends its tag before the helper returns), optionally contained.
#[cfg(feature = "tokio")]
pub fn spawn_control_async(mode: &str, extra: &[&str], contain: bool) -> (cosca::tokio::Child, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut argv: Vec<String> = vec!["cosca_testbin".into(), mode.into(), addr];
    argv.extend(extra.iter().map(|s| s.to_string()));
    let mut cmd = cosca::tokio::Command::new();
    if contain {
        // Load the testbin as argv[0] via the std path (mode/addr stay at args[1..], so it behaves
        // identically) — keeps this shared helper on one code path across OSes. The async raw
        // backend also serves contained `executable()` (see raw_windows_async.rs).
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
    configure: impl FnOnce(&mut cosca::tokio::Command),
) -> (cosca::tokio::Child, TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = cosca::tokio::Command::new();
    // Load the testbin as argv[0] via the std path (mode/addr at args[1..], so it behaves
    // identically): these trees are usually contained and the sole uncontained caller is
    // backend-agnostic, so argv[0] keeps this helper on one code path across OSes. `configure`
    // applies the containment/nesting/kill_on_drop.
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
pub fn spawn_blocker_async() -> (cosca::tokio::Child, TcpStream) {
    spawn_control_async("control-block", &["R"], false)
}

/// Async analogue of `spawn_grandchild`, returning the root ("R") and grandchild ("G") control
/// sockets identified by tag (accept order is not guaranteed).
#[cfg(feature = "tokio")]
pub fn spawn_grandchild_async(contain: bool) -> (cosca::tokio::Child, TcpStream, TcpStream) {
    spawn_grandchild_async_with(contain, true)
}

/// `spawn_grandchild_async` with explicit `contain` and `kill_on_drop` flags, so a test can
/// exercise the `kill_on_drop(false)` Drop early-return (attached still armed) without `detach()`.
#[cfg(feature = "tokio")]
pub fn spawn_grandchild_async_with(contain: bool, kill_on_drop: bool) -> (cosca::tokio::Child, TcpStream, TcpStream) {
    spawn_tree_async("spawn-grandchild", |cmd| {
        if contain {
            cmd.contain();
        }
        cmd.kill_on_drop(kill_on_drop);
    })
}
