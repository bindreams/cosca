//! Shared control-spawn test harness — the CANONICAL single source (`tests/lifecycle.rs`
//! consumes this too; integration test crates are separate compilation units, so helpers
//! are shared via `#[path = "common/mod.rs"] mod common;`).

// Each test crate compiles the whole module but uses only the subset it needs (e.g.
// `lifecycle` never calls `spawn_blocker`), so per-crate dead code and unused imports (e.g. the
// log-capture re-exports, which only `macos_fdmarker.rs` uses) are expected here.
#![allow(dead_code, unused_imports)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

#[cfg(target_os = "linux")]
pub mod cgroup;

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

/// The ONE `log::Log` this test crate installs. A capturing logger, for asserting on log output
/// from an integration-test process — a fresh copy of `src/log_capture.rs`'s `pub(crate)`-private
/// original, which a separate compilation unit like this one cannot name, extended to also echo
/// every record to stderr (in the same `[LEVEL] text` format `spawn_io.rs`'s `stderr_log` used to
/// print through a logger of its own) so a failing `assert_eq!(…, CgroupV2)`'s degrade reason
/// still reaches CI output — libtest captures a failing test's stderr and prints it with the
/// failure.
///
/// `log::set_logger` is once-per-process, so a second, competing logger in the same test binary
/// would race this one and panic whichever call lost — a real failure under `cargo test`'s
/// default one-binary, many-tests-per-process model (nextest's one-process-per-test does not hit
/// it, but local `cargo test` runs do). [`install_log_capture`] is therefore the only installer
/// left in this crate: `spawn_io.rs`'s `stderr_log::install` is now a thin alias for it.
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
            let text = record.args().to_string();
            eprintln!("[{}] {text}", record.level());
            RECORDS.lock().unwrap().push(text);
        }
        fn flush(&self) {}
    }

    /// `Trace`, the full set: no narrower filter can drop a record before it reaches this
    /// logger (`log!` checks `max_level()` first).
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

/// Is `pid` attached to OUR console? `None` when the probe found no console at all, so a
/// broken or console-less probe can never satisfy an "absent" assertion — the two are
/// different facts and folding them together would make an absence assertion unfailable.
///
/// The answer is only meaningful once the target has executed its own code: console
/// registration is not synchronous with the spawn returning, so a probe taken at the instant
/// `spawn()` returns reads "absent" for a perfectly ordinary console child. Every caller must
/// complete a handshake with the target first.
#[cfg(windows)]
pub fn in_our_console(pid: u32) -> Option<bool> {
    // Grow to whatever count the API reports rather than capping: a too-small buffer makes it
    // return the REQUIRED count without filling, which a fixed cap would silently read as
    // "absent".
    let mut buf = vec![0u32; 16];
    loop {
        // SAFETY: standard Win32; `buf` is a valid writable slice.
        let n = unsafe { windows::Win32::System::Console::GetConsoleProcessList(&mut buf) } as usize;
        if n == 0 {
            return None; // no console at all, or the probe itself failed
        }
        if n <= buf.len() {
            return Some(buf[..n].contains(&pid));
        }
        buf.resize(n, 0);
    }
}

/// Exact-key extraction from a `key=value` report line. Substring matching would be unsafe:
/// `console=0` shares its value alphabet with every other field.
#[cfg(windows)]
pub fn report_field<'a>(report: &'a str, key: &str) -> &'a str {
    report
        .split_ascii_whitespace()
        .find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
        .unwrap_or_else(|| panic!("no field {key} in report: {report}"))
}

/// Build a `CreateProcessW`-style command line from plain args, the way the raw backend's own
/// quoter would join them (`cosca::quote::windows::join_wide`). ONE definition for every test
/// crate that needs a `.commandline(...)`-shaped string from argv-like input: two copies could
/// drift apart and agree on the wrong quoting.
#[cfg(windows)]
pub fn commandline_from(args: &[&str]) -> String {
    let wide_args: Vec<Vec<u16>> = args.iter().map(|a| a.encode_utf16().collect()).collect();
    let refs: Vec<&[u16]> = wide_args.iter().map(Vec::as_slice).collect();
    String::from_utf16(&cosca::quote::windows::join_wide(&refs)).unwrap()
}

/// The escaping `report-console-identity` applies to its `argv0` field, so a test can state its
/// expectation in plain text. ONE definition for every test crate that asserts on that field: two
/// copies could drift apart and agree on the wrong answer.
#[cfg(windows)]
pub fn escape_report_field(value: &str) -> String {
    let mut out = String::new();
    for b in value.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') {
            out.push(*b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Read exactly the one report line a `report-console-identity` child writes before it blocks. A
/// child that panicked after connecting reaches us as EOF (an empty line), which fails the
/// caller's field lookup loudly instead of hanging.
#[cfg(windows)]
pub fn read_report_line(sock: &TcpStream) -> String {
    use std::io::BufRead;
    let mut reader = std::io::BufReader::new(sock.try_clone().expect("clone report socket"));
    let mut line = String::new();
    reader.read_line(&mut line).expect("read report line");
    line
}

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

/// `spawn_control`'s shape against the GUI-subsystem helper: it takes no mode argument (the
/// binary has exactly one behaviour) and tags `b"G"`. A GUI-subsystem image never attaches to
/// its spawner's console, so this is the only way to construct a child whose creation flags say
/// nothing excludes delivery while the OS puts it out of reach.
#[cfg(windows)]
pub fn spawn_gui_control(contain: bool) -> (cosca::Child, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let exe = env!("CARGO_BIN_EXE_cosca_testbin_gui");
    let mut cmd = cosca::Command::new();
    cmd.executable(exe).args([exe, addr.as_str()]);
    if contain {
        cmd.contain();
    }
    let child = cmd.spawn().expect("spawn gui control child");
    let (mut sock, _) = listener.accept().expect("accept");
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read tag");
    assert_eq!(&tag, b"G", "wrong gui tag");
    (child, sock)
}

/// Async sibling of [`spawn_gui_control`] — see there for why the GUI-subsystem image is the
/// only way to construct a child whose flags say nothing excludes delivery while the OS puts it
/// out of reach.
#[cfg(all(windows, feature = "tokio"))]
pub fn spawn_gui_control_async(contain: bool) -> (cosca::tokio::Child, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let exe = env!("CARGO_BIN_EXE_cosca_testbin_gui");
    let mut cmd = cosca::tokio::Command::new();
    cmd.args([exe, addr.as_str()]);
    if contain {
        cmd.contain();
    }
    let child = cmd.spawn().expect("spawn async gui control child");
    let (mut sock, _) = listener.accept().expect("accept");
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read tag");
    assert_eq!(&tag, b"G", "wrong gui tag");
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

/// A contained async `spawn-grandchild-echo` tree: both members round-trip a byte, so a test can
/// prove each POSITIVELY alive (see [`assert_echoes`]).
#[cfg(feature = "tokio")]
pub struct AsyncEchoTree {
    pub child: cosca::tokio::Child,
    pub root: TcpStream,
    pub grand: TcpStream,
    /// The grandchild's own pid, for reading the tree's cgroup back out of `/proc`.
    pub grand_pid: u32,
}

/// Spawn a contained [`AsyncEchoTree`] with the given `kill_on_drop`.
#[cfg(feature = "tokio")]
pub fn spawn_echo_tree_async(kill_on_drop: bool) -> AsyncEchoTree {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = cosca::tokio::Command::new();
    cmd.args([testbin(), "spawn-grandchild-echo", addr.as_str()]);
    cmd.contain();
    cmd.kill_on_drop(kill_on_drop);
    let child = cmd.spawn().expect("spawn async echo tree");
    let (mut root, mut grand) = (None, None);
    for _ in 0..2 {
        let (mut s, _) = listener.accept().expect("accept");
        match read_tag_and_pid(&mut s) {
            (b'R', _) => root = Some(s),
            (b'G', pid) => grand = Some((s, pid)),
            (tag, _) => panic!("unexpected tree tag {:?}", tag as char),
        }
    }
    let (grand, grand_pid) = grand.expect("grandchild G connected");
    AsyncEchoTree {
        child,
        root: root.expect("root R connected"),
        grand,
        grand_pid,
    }
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

/// Read one `<tag><pid>\n` line from a freshly accepted `control-echo-pid` connection.
pub fn read_tag_and_pid(sock: &mut std::net::TcpStream) -> (u8, u32) {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = sock.read(&mut b).expect("read the control line");
        assert_ne!(n, 0, "the control connection closed before sending its tag line");
        if b[0] == b'\n' {
            break;
        }
        line.push(b[0]);
    }
    assert!(line.len() > 1, "a control line is a tag plus a pid, got {line:?}");
    let pid = std::str::from_utf8(&line[1..])
        .expect("the pid is ASCII")
        .parse()
        .expect("the pid is a number");
    (line[0], pid)
}

/// Prove a `control-echo-pid` member is POSITIVELY alive: send a byte and read the echo back.
/// A killed member gives EOF or `ConnectionReset` on the read instead, never the byte.
pub fn assert_echoes(sock: &mut std::net::TcpStream, who: &str) {
    sock.write_all(b"p")
        .unwrap_or_else(|e| panic!("{who} must accept a write while alive: {e}"));
    let mut b = [0u8; 1];
    sock.read_exact(&mut b)
        .unwrap_or_else(|e| panic!("{who} must echo the byte back while alive: {e}"));
    assert_eq!(&b, b"p", "{who} echoed {b:?} instead of the byte it was sent");
}

/// The re-exec args [`alone`] passes after the test name, and the shape [`alone_marker_matches`]
/// demands this process's own argv match before trusting a `COSCA_TEST_ALONE` env var — shared by
/// both so they can never drift apart into two different ideas of "the isolated shape". `pub`:
/// a prover test that needs to invoke a probe with this exact shape directly (skipping `alone`'s
/// own re-exec layer) names it too — see `tests/spawn_io.rs`'s
/// `a_panic_while_fd_2_is_closed_still_reaches_stderr`.
#[cfg(unix)]
pub const ALONE_ARGS: [&str; 4] = ["--exact", "--include-ignored", "--nocapture", "--test-threads=1"];

/// True only if `value` is `Some` AND this process's own argv (skipping argv[0], the binary path)
/// is exactly `[value, ALONE_ARGS...]` — proof that libtest itself was invoked to run exactly one
/// named test, not merely that some env var happens to be set.
///
/// A `COSCA_TEST_ALONE` env var alone is not enough: it is inherited by every child of the
/// process that set it, including — if a caller ever exports it into their own shell, or it
/// leaks from an outer re-exec — the whole, ordinary, many-threads `cargo test` run itself. That
/// run's OWN argv is never this exact one-test-and-no-more shape (`cargo test` does not pass
/// `--exact <one name> --test-threads=1` for the whole suite), so checking argv here is what a
/// forged or leaked env var cannot fake: argv is controlled by whatever actually invoked THIS
/// process, which for the genuine isolated child is [`alone`] itself and nothing else. Measured:
/// without this check, an inherited `COSCA_TEST_ALONE=<a real test's name>` made that one test's
/// guard accept a plain, many-threads `cargo test` run as "isolated" and corrupt others.
///
/// Pure and host-testable (no real env/argv read) — see the unit test just below.
#[cfg(unix)]
fn alone_marker_matches(value: Option<&str>, argv: &[String]) -> bool {
    let Some(value) = value else { return false };
    argv.len() == ALONE_ARGS.len() + 1
        && argv[0] == value
        && argv[1..].iter().map(String::as_str).eq(ALONE_ARGS.iter().copied())
}

/// Run the test `name` (its full path, as libtest reports it — this crate's integration test
/// binaries are flat, so just the fn name) alone, in a fresh copy of this test binary, and assert
/// it passed. `true` in the copy, which must then run the test's real body; `false` in the
/// original caller, which must return immediately — the real work already ran, in isolation, in
/// the copy.
///
/// This is how a test that mutates process-wide state (closes fd 0/1/2, lowers `RLIMIT_NOFILE`,
/// ...) stays safe, and passes, under BOTH plain `cargo test` (many test threads sharing one
/// process) and `cargo nextest run` (one process per test): it puts itself alone in a process no
/// matter which harness launched it, rather than trusting nextest's own isolation (which a caller
/// could reach without going through this function at all). Sets `COSCA_TEST_ALONE` in the copy,
/// so [`require_process_per_test`]'s precondition (guarding the actual mutation) accepts it.
///
/// Checks BOTH that the env var equals `name` AND that this process's own argv matches
/// [`alone_marker_matches`]'s shape — the first alone is not enough (see that function's doc for
/// the inherited/forged-env-var corruption checking only presence, or only the wrong one of these
/// two, would let back in), and belt-and-suspenders costs nothing here.
///
/// Spawns under `cosca::test_spawn_lock()`, waits outside it: on macOS, a fork here that lands
/// while another test's fd-marker write end happens to have its `CLOEXEC` cleared (a real,
/// bounded window `src/child/spawn.rs`'s own `prepare`-to-`drop(std_cmd)` comment names) would
/// transiently inherit it and carry it past this re-exec's own `exec`, becoming an unrelated
/// bystander a concurrent sweep can misidentify. `test_spawn_lock()` is the same lock every
/// cosca-originated spawn in this test binary already takes — see `output_locked`'s doc for the
/// general rule. The lock is a plain, non-reentrant mutex: every caller here calls `alone` FIRST,
/// while holding nothing else, and must keep doing so — nesting a second `spawn_lock()`-taking
/// call inside an already-locked scope deadlocks.
///
/// A copy of `src/containment/cgroup/test_support.rs`'s identical helper — that one is a separate
/// compilation unit (this crate's own lib) and cannot name this `pub` one, or vice versa —
/// deliberately one copy per compilation unit rather than a shared dependency between them.
#[cfg(unix)]
pub fn alone(name: &str) -> bool {
    const ALONE: &str = "COSCA_TEST_ALONE";
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let env_value = std::env::var(ALONE).ok();
    if env_value.as_deref() == Some(name) && alone_marker_matches(env_value.as_deref(), &argv) {
        return true;
    }
    let child = {
        let _guard = cosca::test_spawn_lock();
        std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args(std::iter::once(name).chain(ALONE_ARGS))
            .env(ALONE, name)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn the test alone")
    };
    let out = child.wait_with_output().expect("wait for the test alone");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "{}\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    false
}

/// Require that this test is running alone in its own process, via [`alone`], before any caller
/// touches a process-wide resource (here: closing this process's own low-numbered fds, or
/// lowering its `RLIMIT_NOFILE`). A plain `cargo test` run shares one process across every test
/// thread in the binary, so mutating either there races with, and can corrupt, whatever unrelated
/// test's thread runs concurrently.
///
/// The one accepted proof of isolation is `COSCA_TEST_ALONE=<name>` where this process's own
/// argv is exactly `[<name>, ALONE_ARGS...]` — [`alone_marker_matches`] — set by [`alone`] on the
/// fresh, single-test copy of this binary it re-execs. Checking argv, not just the env var's
/// presence, is load bearing: see `alone_marker_matches`'s doc for the inherited/forged-env-var
/// corruption this closes.
///
/// Deliberately does NOT also accept nextest's own `NEXTEST_EXECUTION_MODE=process-per-test`:
/// every guarded caller goes through `alone` now (which is itself safe under nextest too — its
/// own `alone_marker_matches` check simply never matches there, so it re-execs same as under
/// plain `cargo test`), and `NEXTEST_EXECUTION_MODE` is just as forgeable as `COSCA_TEST_ALONE`
/// ever was — accepting it would reopen a second, unnecessary escape hatch.
///
/// Fails loudly and immediately, before touching anything, rather than silently skipping: see
/// cosca#196 for the long-term structural fix (serializing every process-wide-fd test into one
/// group, so this stops depending on `alone` specifically).
#[cfg(unix)]
fn require_process_per_test(what: &str) {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let alone = alone_marker_matches(std::env::var("COSCA_TEST_ALONE").ok().as_deref(), &argv);
    assert!(alone, "{what}; call this from inside common::alone() — see cosca#196");
}

/// Real fd 2 to `dup2` back before the panic hook's chained write runs, if a [`RestoreStdio`] is
/// currently holding fd 2 closed — `None` when no guard has fd 2 closed. Read only by the ONE
/// process-wide hook [`ensure_stderr_panic_hook`] installs; written only by
/// [`RestoreStdio::close`] (sets) and its `Drop` (clears).
///
/// **`Drop` ONLY EVER clears this slot — it never calls [`std::panic::set_hook`] itself.**
/// Measured: calling `set_hook` from `Drop` panics ("cannot modify the panic hook from a
/// panicking thread") whenever that `Drop` runs during unwinding — which it always might, since
/// unwinding is the ordinary reason a guard drops — and a panic during unwind is not caught: the
/// process aborts (`SIGABRT`, exit 134), turning an ordinary test failure into a hard crash. That
/// is worse than the very bug this file's panic-hook mechanism exists to fix. Installing the hook
/// exactly ONCE, process-wide, and having it read this slot at panic time — rather than being
/// reinstalled and un-installed per guard — is what makes `Drop` never need to touch the hook at
/// all.
#[cfg(unix)]
static SAVED_STDERR: std::sync::Mutex<Option<libc::c_int>> = std::sync::Mutex::new(None);

/// Lock [`SAVED_STDERR`], recovering from poison rather than panicking: this mutex is read from
/// inside a panic hook and written from `Drop` during unwind, both places where panicking AGAIN
/// (on a poisoned lock) is the one outcome that must never happen — see [`SAVED_STDERR`]'s doc.
#[cfg(unix)]
fn saved_stderr() -> std::sync::MutexGuard<'static, Option<libc::c_int>> {
    SAVED_STDERR.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Install the ONE, process-wide panic hook that restores real fd 2 from [`SAVED_STDERR`] (if
/// occupied) before chaining to whatever hook was previously installed — so a panic while a
/// [`RestoreStdio`] holds fd 2 closed still reaches somewhere readable, instead of the default
/// hook's write to a closed fd 2 failing and being silently swallowed. Idempotent via `Once`:
/// safe to call from every [`RestoreStdio::close`].
#[cfg(unix)]
fn ensure_stderr_panic_hook() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if let Some(real_stderr) = *saved_stderr() {
                // SAFETY: `real_stderr` is a live dup of the original fd 2, owned by whichever
                // `RestoreStdio` currently occupies `SAVED_STDERR` — its `Drop` clears the slot
                // before that dup closes, so a `Some` read here is always still valid.
                unsafe { libc::dup2(real_stderr, 2) };
            }
            previous(info);
        }));
    });
}

/// Duplicate each of `fds` aside and close it, restoring all of them (on drop, even if the test
/// panics) so the CURRENT process's own low-numbered descriptors are free for a test to reuse —
/// then land back where they started. Some fd_map regression tests need this THIS process's own
/// fd 1 and/or fd 2 closed to reproduce a bug that only manifests when a mapping's parent-side
/// source, or a `Stdio::from_file` target, gets allocated one of those exact numbers.
///
/// `close` asserts [`require_process_per_test`] before touching anything: see there for why.
///
/// **A panic while fd 2 is among `fds` would otherwise lose its own message** — see
/// [`SAVED_STDERR`]/[`ensure_stderr_panic_hook`] for the mechanism that fixes this and why `Drop`
/// never touches the hook itself.
#[cfg(unix)]
pub struct RestoreStdio {
    saved: Vec<(libc::c_int, std::os::fd::OwnedFd)>,
}

#[cfg(unix)]
impl RestoreStdio {
    pub fn close(fds: &[libc::c_int]) -> RestoreStdio {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let listed = fds.iter().map(|f| f.to_string()).collect::<Vec<_>>().join(", ");
        require_process_per_test(&format!(
            "closes process-wide fd{} {listed}",
            if fds.len() == 1 { "" } else { "s" }
        ));
        let mut saved = Vec::with_capacity(fds.len());
        for &fd in fds {
            // SAFETY: F_DUPFD_CLOEXEC(fd, 3) duplicates fd to a fresh number >= 3, checked below.
            let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            assert!(dup >= 0, "dup fd {fd} aside before closing it");
            // SAFETY: `dup` was just returned by a successful F_DUPFD_CLOEXEC.
            let dup = unsafe { OwnedFd::from_raw_fd(dup) };
            assert_eq!(unsafe { libc::close(fd) }, 0, "close the test process' fd {fd}");
            saved.push((fd, dup));
        }
        // Only relevant when fd 2 (stderr, where the panic hook writes) is actually among the
        // closed fds — see `SAVED_STDERR`'s doc for the mechanism.
        if fds.contains(&2) {
            ensure_stderr_panic_hook();
            let real_stderr = saved
                .iter()
                .find(|(fd, _)| *fd == 2)
                .map(|(_, dup)| dup.as_raw_fd())
                .expect("fd 2 is in `fds`, so its dup is in `saved`");
            let mut slot = saved_stderr();
            debug_assert!(
                slot.is_none(),
                "RestoreStdio: SAVED_STDERR already occupied (by fd {:?}) — a previous guard's fd \
                 2 was never cleared, or two guards overlap. Only reachable if a caller uses \
                 RestoreStdio outside alone()'s single-test isolation.",
                *slot
            );
            *slot = Some(real_stderr);
        }
        RestoreStdio { saved }
    }
}

#[cfg(unix)]
impl Drop for RestoreStdio {
    fn drop(&mut self) {
        // Clear the process-wide slot BEFORE the loop below restores/closes anything — in
        // particular before `self.saved`'s dup of fd 2 is dropped (closed) — so the ONE
        // process-wide panic hook (installed once by `close`, never touched here) can never read
        // a stale fd out of `SAVED_STDERR`. This NEVER calls `std::panic::set_hook`: see
        // `SAVED_STDERR`'s doc for why that would turn an ordinary panic into a process abort.
        if self.saved.iter().any(|(fd, _)| *fd == 2) {
            *saved_stderr() = None;
        }
        use std::os::fd::AsRawFd;
        for (fd, dup) in &self.saved {
            // SAFETY: dup2 back onto `fd`; `dup` stays valid (closed normally by its own Drop,
            // right after) regardless of this call's outcome.
            //
            // Retries EINTR the same way `fd_map::dup2_onto` does, so a signal landing mid-restore
            // cannot leave `fd` unrestored, and asserts the final result: a restore failure here
            // would silently leave this test process' own fd in the wrong state for every test
            // that runs after it, defeating this guard's whole purpose.
            let ret = loop {
                let ret = unsafe { libc::dup2(dup.as_raw_fd(), *fd) };
                if ret != -1 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    break ret;
                }
            };
            assert_eq!(
                ret,
                *fd,
                "dup2({}, {fd}) while restoring a guarded fd failed: {}",
                dup.as_raw_fd(),
                std::io::Error::last_os_error()
            );
        }
    }
}

/// Lower this process' own `RLIMIT_NOFILE` soft limit to `to`, for the life of the guard,
/// restoring the original soft limit on drop (even if the test panics).
///
/// A forked child inherits its parent's rlimits at fork time, before any `pre_exec` hook runs —
/// so lowering the limit HERE, in the process that calls `spawn()`, is what makes an ordinary,
/// valid-looking child fd number deterministically exceed the CHILD's own limit and fail its
/// `dup2` with `EBADF`, regardless of whatever the host's real `ulimit -n` happens to be (on
/// Linux, a soft limit raised past `1_000_000` is entirely ordinary, so a test that assumes a
/// large but fixed child fd is always out of range is otherwise runner-dependent).
///
/// `lower_to` asserts [`require_process_per_test`] before touching anything: see there for why —
/// this is exactly as process-wide, and exactly as unsafe outside a call wrapped in [`alone`], as
/// `RestoreStdio::close`.
#[cfg(unix)]
pub struct RestoreRlimitNofile {
    original: libc::rlimit,
}

#[cfg(unix)]
impl RestoreRlimitNofile {
    pub fn lower_to(to: libc::rlim_t) -> RestoreRlimitNofile {
        require_process_per_test("lowers this process's own RLIMIT_NOFILE, process-wide");
        let mut original: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: `original` is a valid, correctly-sized out-param.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut original) },
            0,
            "getrlimit(RLIMIT_NOFILE): {}",
            std::io::Error::last_os_error()
        );
        let lowered = libc::rlimit {
            rlim_cur: to,
            rlim_max: original.rlim_max,
        };
        // SAFETY: `lowered` only ever lowers `rlim_cur`; `rlim_max` is passed through unchanged,
        // so this cannot raise the process' hard ceiling.
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) },
            0,
            "setrlimit(RLIMIT_NOFILE, {{cur: {to}, max: {}}}): {}",
            original.rlim_max,
            std::io::Error::last_os_error()
        );
        RestoreRlimitNofile { original }
    }
}

#[cfg(unix)]
impl Drop for RestoreRlimitNofile {
    fn drop(&mut self) {
        // SAFETY: restores exactly the limit `getrlimit` reported before this guard lowered it.
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.original) };
        // Raising a soft limit back up to (at most) its own untouched hard limit always succeeds
        // for an unprivileged process — asserted, not just documented in prose, matching
        // `lower_to`'s own checked `getrlimit`/`setrlimit` calls: if that guarantee is ever wrong
        // (a hardened sandbox, a future refactor that also lowers `rlim_max`), this fails loudly
        // here instead of silently leaving a lowered limit in place for every fd-hungry test that
        // runs in this process afterward.
        assert_eq!(
            ret,
            0,
            "setrlimit(RLIMIT_NOFILE, restore to {{cur: {}, max: {}}}) failed: {}",
            self.original.rlim_cur,
            self.original.rlim_max,
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(unix)]
#[cfg(test)]
mod alone_marker_tests {
    use super::{alone_marker_matches, ALONE_ARGS};

    fn genuine_argv(name: &str) -> Vec<String> {
        std::iter::once(name.to_string())
            .chain(ALONE_ARGS.iter().map(|s| s.to_string()))
            .collect()
    }

    #[test]
    fn the_genuine_re_exec_shape_matches() {
        assert!(alone_marker_matches(Some("some_test"), &genuine_argv("some_test")));
    }

    #[test]
    fn no_env_value_never_matches() {
        assert!(!alone_marker_matches(None, &genuine_argv("some_test")));
    }

    #[test]
    fn an_inherited_env_value_with_the_ordinary_suites_own_argv_does_not_match() {
        // The exact corruption measured: `COSCA_TEST_ALONE` set (e.g. leaked from an outer
        // shell or re-exec) to some real test's name, but THIS process's own argv is whatever
        // an ordinary `cargo test` run passes — never the isolated one-test-exact shape.
        assert!(!alone_marker_matches(Some("some_test"), &[]));
        assert!(!alone_marker_matches(Some("some_test"), &["some_test".to_string()]));
    }

    #[test]
    fn a_name_mismatch_does_not_match_even_with_the_right_shape() {
        let mut argv = genuine_argv("some_test");
        argv[0] = "other_test".to_string();
        assert!(!alone_marker_matches(Some("some_test"), &argv));
    }

    #[test]
    fn a_trailing_extra_argument_does_not_match() {
        let mut argv = genuine_argv("some_test");
        argv.push("--extra".to_string());
        assert!(!alone_marker_matches(Some("some_test"), &argv));
    }
}
