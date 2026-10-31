//! Shared control-spawn test harness — the CANONICAL single source (`tests/lifecycle.rs`
//! consumes this too; integration test crates are separate compilation units, so helpers
//! are shared via `#[path = "common/mod.rs"] mod common;`).

// Each test crate compiles the whole module but uses only the subset it needs (e.g.
// `lifecycle` never calls `spawn_blocker`), so per-crate dead code and unused imports (e.g. the
// log-capture re-exports, which only `macos_fdmarker.rs` uses) are expected here.
#![allow(
    dead_code,
    unused_imports,
    reason = "each integration test crate compiles this whole shared module but uses only its own subset"
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

// Shared with `test_groups` (its `StrayLeaves`), which owns the one compilation of the file.
#[cfg(target_os = "linux")]
pub use test_groups::cgroup_leaf as cgroup;
pub mod payload;

#[cfg(target_os = "linux")]
pub mod seccomp;

mod accept;
pub use accept::*;

#[cfg(target_os = "macos")]
pub mod kevent_eintr;

#[cfg(windows)]
pub mod drive_rule;
#[cfg(windows)]
pub mod subst;

#[cfg(windows)]
pub mod windows_env;

#[cfg(windows)]
pub mod null_std;

#[cfg(windows)]
pub mod handle_snapshot;

#[cfg(windows)]
pub mod inheritable;

#[cfg(windows)]
pub mod windows_reparse;

mod locked;
pub use locked::*;

#[cfg(unix)]
mod uid_switch;
#[cfg(unix)]
pub use uid_switch::*;

mod member;
pub use member::*;

mod report;
pub use report::*;

mod marker;
pub use marker::*;

#[cfg(unix)]
mod skuld_db_dir;
#[cfg(unix)]
pub use skuld_db_dir::*;

// Runs a test that changes process-global state in a process of its own; see the module.
#[cfg(unix)]
#[path = "../../src/test_own_process.rs"]
pub mod test_own_process;
#[cfg(unix)]
#[path = "../../src/test_stdio.rs"]
pub mod test_stdio;
// Its Windows twin, under the same name: the token pipe and fd guards above are unix-only.
#[cfg(windows)]
#[path = "../../src/test_own_process_windows.rs"]
pub mod test_own_process;
// Re-exec builder, shared with the library's tests.
#[path = "../../src/test_reexec.rs"]
pub mod test_reexec;
// The role marker, argv, gate and `Completion` that both `test_own_process` modules share.
#[path = "../../src/test_own_process_gate.rs"]
pub mod test_own_process_gate;
// The setuid helper check of the `SETUID` group, shared with the library's tests.
#[cfg(unix)]
#[path = "../../src/test_privilege/setuid.rs"]
pub mod setuid;

/// The `cosca_testbin` path. Prefers nextest's run-time `NEXTEST_BIN_EXE_cosca_testbin`: the
/// build-time path is absent when an archive runs elsewhere.
pub fn testbin() -> &'static str {
    static PATH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PATH.get_or_init(|| match std::env::var_os("NEXTEST_BIN_EXE_cosca_testbin") {
        Some(path) => path.into_string().expect("NEXTEST_BIN_EXE_cosca_testbin is not UTF-8"),
        None => env!("CARGO_BIN_EXE_cosca_testbin").to_owned(),
    })
}

/// An anonymous pipe whose write end is inheritable.
#[cfg(windows)]
pub fn inheritable_pipe() -> (std::io::PipeReader, std::io::PipeWriter) {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::{SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT};
    let (reader, writer) = std::io::pipe().expect("create a pipe");
    // SAFETY: `writer` owns the handle for the call.
    unsafe {
        SetHandleInformation(
            HANDLE(writer.as_raw_handle()),
            HANDLE_FLAG_INHERIT.0,
            HANDLE_FLAG_INHERIT,
        )
    }
    .expect("mark the write end inheritable");
    (reader, writer)
}

/// Blocks reading stdin; ends only by a kill or stdin EOF. `cat` on Unix; `more.com` on Windows
/// (exits 0 on EOF, unlike `findstr x`). Spawn with piped stdin, null stdout.
///
/// This and [`assert_killed`] duplicate `test_child::windows_more` / `test_child::assert_killed`
/// because `tests/` is a separate compilation unit that cannot name the library's `cfg(test)` items.
pub fn stdin_blocker_program() -> std::path::PathBuf {
    #[cfg(unix)]
    {
        "cat".into()
    }
    #[cfg(windows)]
    {
        std::path::Path::new(&std::env::var_os("SystemRoot").expect("SystemRoot is set on Windows"))
            .join("System32")
            .join("more.com")
    }
}

/// The child died to a kill, not by exiting on its own once released (its stdin or control socket
/// closed): `SIGKILL` on Unix, the kill's exit code `1` on Windows. A crash on the release (a
/// panic's `101`, say) fails too.
pub fn assert_killed(who: &str, status: std::process::ExitStatus) {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "{who} must be SIGKILLed, not exit on its own: {status:?}"
        );
    }
    #[cfg(windows)]
    assert_eq!(
        status.code(),
        Some(1),
        "{who} must be killed (exit code 1), not exit on its own: {status:?}"
    );
}

/// `kill` a `control-block` family child, release its control socket, then reap it and assert it
/// died to the kill. The member leaves with 0 when released, so a `kill` that sent nothing fails
/// the assertion where a bare `kill` then `wait` would block forever.
pub fn kill_release_reap(child: &cosca::Child, control: TcpStream) -> std::process::ExitStatus {
    child.kill().expect("kill");
    drop(control);
    let status = child.wait().expect("reap the killed child");
    assert_killed("the killed child", status);
    status
}

/// [`kill_release_reap`] with `kill_tree`, for a contained child: reaping a contained root after a
/// plain `kill` and then dropping it warns, because the group was never swept (#382).
pub fn kill_tree_release_reap(child: &cosca::Child, control: TcpStream) -> std::process::ExitStatus {
    child.kill_tree().expect("kill_tree");
    drop(control);
    let status = child.wait().expect("reap the killed child");
    assert_killed("the killed child", status);
    status
}

/// [`kill_release_reap`] for several children. A `Child` dropped while its member still holds the
/// control socket blocks in the drop's wait, so every socket is released before any `Child` can
/// drop, on every path: `controls` is declared after `children` and so unwinds first, and the
/// reaping starts only once it is gone.
pub fn kill_release_reap_all(pairs: Vec<(cosca::Child, TcpStream)>) {
    let (children, controls): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
    for child in &children {
        // A contained child by its group: a contained root reaped after a plain `kill` and then
        // dropped warns.
        if child.containment().can_teardown() {
            child.kill_tree().expect("kill_tree");
        } else {
            child.kill().expect("kill");
        }
    }
    drop(controls);
    let statuses: Vec<_> = children
        .into_iter()
        .map(|child| child.wait().expect("reap the killed child"))
        .collect();
    for status in statuses {
        assert_killed("the killed child", status);
    }
}

/// [`kill_release_reap`] for the tokio `Child`.
#[cfg(feature = "tokio")]
pub async fn kill_release_reap_async(child: &mut cosca::tokio::Child, control: TcpStream) -> std::process::ExitStatus {
    child.kill().expect("kill");
    drop(control);
    let status = child.wait().await.expect("reap the killed child");
    assert_killed("the killed child", status);
    status
}

/// [`kill_tree_release_reap`] for the tokio `Child`.
#[cfg(feature = "tokio")]
pub async fn kill_tree_release_reap_async(
    child: &mut cosca::tokio::Child,
    control: TcpStream,
) -> std::process::ExitStatus {
    child.kill_tree().expect("kill_tree");
    drop(control);
    let status = child.wait().await.expect("reap the killed child");
    assert_killed("the killed child", status);
    status
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
    zombie_record(pid);
}

/// [`block_until_zombie`], then the zombie's exit status, still without reaping it.
#[cfg(unix)]
pub fn zombie_exit_status(pid: cosca::identity::RawPid) -> std::process::ExitStatus {
    let si = zombie_record(pid);
    #[cfg(target_os = "linux")]
    // SAFETY: `waitid` returned a `SIGCHLD` record, whose status field is set.
    let status = unsafe { si.si_status() };
    #[cfg(target_os = "macos")]
    let status = si.si_status;
    wait_status(si.si_code, status)
}

/// The wait status std would decode for a `SIGCHLD` record's `si_code` and `si_status`, which
/// `waitid(WEXITED)` only reports for an exit.
#[cfg(unix)]
fn wait_status(si_code: libc::c_int, si_status: libc::c_int) -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    match si_code {
        libc::CLD_EXITED => std::process::ExitStatus::from_raw((si_status & 0xff) << 8),
        libc::CLD_DUMPED => std::process::ExitStatus::from_raw((si_status & 0x7f) | 0x80),
        libc::CLD_KILLED => std::process::ExitStatus::from_raw(si_status & 0x7f),
        other => {
            debug_assert!(false, "waitid(WEXITED) reported si_code {other}, which is not an exit");
            std::process::ExitStatus::from_raw(si_status & 0x7f)
        }
    }
}

#[cfg(unix)]
fn zombie_record(pid: cosca::identity::RawPid) -> libc::siginfo_t {
    loop {
        let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `si` is a valid, correctly-sized out-param; `pid` is our own unreaped child.
        let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut si, libc::WEXITED | libc::WNOWAIT) };
        if rc == 0 {
            return si;
        }
        // EINTR is a restart, not a failure — the codebase's convention for every blocking
        // syscall (see `os_process/macos/kqueue.rs`, `identity/macos/kinfo.rs`).
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
/// still reaches CI output — nextest prints a failing test's stderr with the failure.
///
/// `log::set_logger` is once-per-process, so a second, competing logger in the same test binary
/// would race this one and panic whichever call lost — a real failure under `cargo test`'s
/// default one-binary, many-tests-per-process model (nextest's one-process-per-test does not hit
/// it, but local `cargo test` runs do). [`install_log_capture`] is therefore the only installer
/// left in this crate: `spawn_io.rs`'s `stderr_log::install` is now a thin alias for it.
mod log_capture {
    use std::sync::{Mutex, OnceLock};

    struct CaptureLog;
    static RECORDS: Mutex<Vec<(log::Level, String)>> = Mutex::new(Vec::new());
    static INSTALLED: OnceLock<()> = OnceLock::new();

    impl log::Log for CaptureLog {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }
        fn log(&self, record: &log::Record<'_>) {
            let text = record.args().to_string();
            eprintln!("[{}] {text}", record.level());
            RECORDS.lock().unwrap().push((record.level(), text));
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
        RECORDS.lock().unwrap()[mark..].iter().any(|(_, m)| m.contains(needle))
    }

    /// The levels of every record emitted at or after `mark` that contains `needle`: the twin of
    /// the library's own `log_capture::levels_since`. A level is what decides whether an
    /// embedder's sink shows a message by default, which [`contains_since`] cannot see.
    pub fn levels_since(mark: usize, needle: &str) -> Vec<log::Level> {
        RECORDS.lock().unwrap()[mark..]
            .iter()
            .filter(|(_, m)| m.contains(needle))
            .map(|(level, _)| *level)
            .collect()
    }

    /// The text of every record at `Warn` or worse emitted at or after `mark`.
    pub fn warnings_since(mark: usize) -> Vec<String> {
        RECORDS.lock().unwrap()[mark..]
            .iter()
            .filter(|(level, _)| *level <= log::Level::Warn)
            .map(|(_, m)| m.clone())
            .collect()
    }
}
pub use log_capture::{contains_since, install as install_log_capture, levels_since, mark as log_mark, warnings_since};

/// Pins a test's log output: every record at `Warn` or worse emitted while it lives must contain
/// one of the [`expecting`](Self::expecting) needles, and every needle must match at least one
/// such record. Declare it FIRST in a test, so it drops last, after the test's children have been
/// torn down and their teardown has logged. Skipped while the test is already panicking, so it
/// never masks the real failure.
///
/// Reads the process-wide capture from its creation on, so it assumes one test per process (what
/// nextest runs); the binary's `main` must call [`install_log_capture`].
#[must_use = "the watch asserts when dropped; bind it to a named `_watch`, not `_`"]
pub struct WarnWatch {
    mark: usize,
    expected: Vec<&'static str>,
}

pub fn warn_watch() -> WarnWatch {
    WarnWatch {
        mark: log_mark(),
        expected: Vec::new(),
    }
}

impl WarnWatch {
    /// This test legitimately produces a warning containing `needle`.
    pub fn expecting(mut self, needle: &'static str) -> Self {
        self.expected.push(needle);
        self
    }
}

impl Drop for WarnWatch {
    fn drop(&mut self) {
        if std::thread::panicking() {
            return;
        }
        let warnings = warnings_since(self.mark);
        let unexpected: Vec<&String> = warnings
            .iter()
            .filter(|w| !self.expected.iter().any(|n| w.contains(n)))
            .collect();
        assert!(
            unexpected.is_empty(),
            "unexpected warning(s) at Warn or above: {unexpected:#?}"
        );
        for needle in &self.expected {
            assert!(
                warnings.iter().any(|w| w.contains(needle)),
                "expected a warning containing {needle:?}, got {warnings:#?}"
            );
        }
    }
}

/// The lib's group declarations, included once for every root that uses `common` (an integration
/// test cannot name a `#[cfg(test)]` item of the library). See `docs/principles.md`, principles 9
/// and 10.
#[path = "../../src/test_groups.rs"]
pub mod test_groups;

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

/// Point a tree root's stdout/stderr at null. Its descendants inherit them, and a descendant that
/// exits only after the test returns (a released grandchild, a detached tree) would otherwise
/// hold nextest's pipes open past the test's end, which `leak-timeout` reports as a leak.
pub fn silence(cmd: &mut cosca::Command) {
    cmd.stdout(cosca::Stdio::null()).expect("null stdout");
    cmd.stderr(cosca::Stdio::null()).expect("null stderr");
}

/// [`silence`] for the tokio builder.
#[cfg(feature = "tokio")]
pub fn silence_async(cmd: &mut cosca::tokio::Command) {
    cmd.stdout(cosca::Stdio::null()).expect("null stdout");
    cmd.stderr(cosca::Stdio::null()).expect("null stderr");
}

/// `.contain()`, except that on Linux it asks for [`ContainMode::Session`](cosca::ContainMode::Session)
/// (a process group, torn down with `killpg`), which never looks for a cgroup. `.contain()` tries a
/// cgroup leaf first and logs a warning where none is delegated, so the same test would warn on one
/// host and not on another. A test that is about cgroups takes the `cgroup` group instead.
pub fn contain_without_cgroup(cmd: &mut cosca::Command) -> &mut cosca::Command {
    #[cfg(target_os = "linux")]
    return cmd.contain_with(cosca::ContainMode::Session);
    #[cfg(not(target_os = "linux"))]
    cmd.contain()
}

/// [`contain_without_cgroup`] for the async `Command`.
#[cfg(feature = "tokio")]
pub fn contain_without_cgroup_async(cmd: &mut cosca::tokio::Command) -> &mut cosca::tokio::Command {
    #[cfg(target_os = "linux")]
    return cmd.contain_with(cosca::ContainMode::Session);
    #[cfg(not(target_os = "linux"))]
    cmd.contain()
}

/// Spawn `mode <addr> [extra...]` as a control child that connects, writes a 1-byte tag,
/// then blocks; returns the owned `Child` and the accepted socket (the tag read proves it
/// is alive). `contain` applies [`contain_without_cgroup`]. This is the canonical form; `tests/lifecycle.rs`
/// now calls this instead of keeping its own copy.
pub fn spawn_control(mode: &str, extra: &[&str], contain: bool) -> (cosca::Child, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut argv: Vec<String> = vec!["cosca_testbin".into(), mode.into(), addr];
    argv.extend(extra.iter().map(|s| s.to_string()));
    let mut cmd = cosca::Command::new();
    cmd.executable(testbin()).args(&argv).env(ACK_ENV, "1");
    silence(&mut cmd);
    if contain {
        contain_without_cgroup(&mut cmd);
    }
    let mut child = cmd.spawn().expect("spawn control child");
    let mut sock = accept_or_die(&listener, &mut child);
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read tag");
    (child, sock)
}

/// Convenience alias for the common `control-block` blocker (no `.contain()`). A one-line
/// shortcut over `spawn_control`, NOT a second copy of the body.
pub fn spawn_blocker() -> (cosca::Child, TcpStream) {
    spawn_control("control-block", &["R"], false)
}

/// The text of a caught panic payload; fails loudly when the payload is not a string.
pub fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_else(|| panic!("panic payload was not a string: {payload:?}"))
}

/// Spawn a 2-level tree via a grandchild-spawning testbin `mode` (root tag "R" + one grandchild
/// tag "G"), optionally contained, and return the owned `Child` plus BOTH accepted sockets (the
/// two tag reads prove the 2-level tree is alive). Callers prove teardown by an exit code or an
/// echo (see [`Member`] and `assert_members_killed`), never by a timer or an unbounded read.
pub fn spawn_tree(mode: &str, contain: bool) -> (cosca::Child, Vec<TcpStream>) {
    spawn_tree_with(mode, contain, |_| {})
}

/// [`spawn_tree`] with the command further configured by `configure` (an env var, say) before the
/// spawn. The returned sockets are `[root, grandchild]`.
pub fn spawn_tree_with(
    mode: &str,
    contain: bool,
    configure: impl FnOnce(&mut cosca::Command),
) -> (cosca::Child, Vec<TcpStream>) {
    let (mut cmd, listener, report) = tree_command(mode, contain);
    configure(&mut cmd);
    let mut child = cmd.spawn().expect("spawn tree");
    let grand = report_grandchild(report, &mut child);
    let mut socks = Vec::new();
    accept_tree_members(&listener, &mut child, grand, &mut socks);
    (child, member_socks(socks))
}

/// The command of a tree helper, the listener its members connect to and the one its root reports
/// the grandchild's pid to (its address is already in the command's environment).
fn tree_command(mode: &str, contain: bool) -> (cosca::Command, TcpListener, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let mut cmd = cosca::Command::new();
    cmd.executable(testbin())
        .args(["cosca_testbin", mode, addr.as_str()])
        .env(ACK_ENV, "1");
    silence(&mut cmd);
    if contain {
        contain_without_cgroup(&mut cmd);
    }
    let report = TcpListener::bind("127.0.0.1:0").expect("bind the grandchild pid report listener");
    cmd.env(GC_PID_ADDR_ENV, report.local_addr().unwrap().to_string());
    (cmd, listener, report)
}

/// Accepts the root and the grandchild, each pushed to `socks` with its tag as it connects. Demuxed
/// by tag (accept order is not guaranteed, and a duplicate or foreign tag is a harness bug worth
/// failing loudly on). The root is watched throughout, the grandchild until it has connected:
/// either dying first fails the helper.
fn accept_tree_members(
    listener: &TcpListener,
    child: &mut cosca::Child,
    grand: cosca::identity::ProcessId,
    socks: &mut Vec<(u8, TcpStream)>,
) {
    for _ in 0..2 {
        let watch_grand = (!socks.iter().any(|(tag, _)| *tag == b'G')).then_some(grand);
        let mut s = accept_or_die_also(listener, child, watch_grand);
        let mut tag = [0u8; 1];
        s.read_exact(&mut tag).expect("read tag");
        assert!(
            matches!(&tag, b"R" | b"G") && !socks.iter().any(|(t, _)| *t == tag[0]),
            "unexpected or duplicate tree tag {tag:?}"
        );
        socks.push((tag[0], s));
    }
}

/// The tagged sockets of a tree as `[root, grandchild]`.
fn member_socks(mut socks: Vec<(u8, TcpStream)>) -> Vec<TcpStream> {
    let mut take = |wanted: u8| {
        let at = socks
            .iter()
            .position(|(tag, _)| *tag == wanted)
            .expect("both tags connected");
        socks.remove(at).1
    };
    let (root, grandchild) = (take(b'R'), take(b'G'));
    vec![root, grandchild]
}

/// What a tree helper holds while it accepts, so that a failure can end the tree. The fields drop in
/// this order: what a member holds open goes first, the `Child` last.
struct Held<L, C> {
    /// Each accepted connection with its tag.
    socks: Vec<(u8, TcpStream)>,
    listener: L,
    child: C,
}

type Tree = Held<TcpListener, cosca::Child>;

/// [`spawn_tree`] for a test that expects the harness to panic with the tree still running (a
/// death-watch failure), and whose grandchild answers every byte ([`ECHO_HELD_ENV`]).
///
/// On Linux, when the containment names the grandchild (cgroup, process group), the tree is ended by
/// `kill_tree` before the unwind and asserted ended: a grandchild must not echo after it returns
/// (a delivered SIGKILL is pending), and a root that never reported one must have ended. The
/// members' sockets close before the `Child` drops. Other containments unwind as [`spawn_tree`]
/// does. The drop's own kill of an orphaned grandchild is the library's test,
/// `cgroup_drop_of_an_exited_unreaped_root_kills_its_orphaned_descendant`.
pub fn spawn_tree_ending_a_failure(mode: &str, contain: bool) -> (cosca::Child, Vec<TcpStream>) {
    use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};

    let (mut cmd, listener, report) = tree_command(mode, contain);
    cmd.env(ECHO_HELD_ENV, "1");
    let child = cmd.spawn().expect("spawn tree");
    let mut tree = Tree {
        socks: Vec::new(),
        listener,
        child,
    };
    let mut grand = None;
    let accepted = catch_unwind(AssertUnwindSafe(|| {
        let id = report_grandchild(report, &mut tree.child);
        grand = Some(id);
        accept_tree_members(&tree.listener, &mut tree.child, id, &mut tree.socks);
    }));
    if let Err(payload) = accepted {
        #[cfg(target_os = "linux")]
        if names_its_grandchild(tree.child.containment()) {
            end_tree(&mut tree, grand);
        }
        resume_unwind(payload);
    }
    let Tree { socks, child, .. } = tree;
    (child, member_socks(socks))
}

/// Whether `containment` reaches the grandchild of a tree whose root died: a cgroup and a process
/// group both name it without the root.
#[cfg(target_os = "linux")]
fn names_its_grandchild(containment: cosca::Containment) -> bool {
    use cosca::Containment as C;
    matches!(containment, C::CgroupV2 | C::Session | C::ProcessGroup)
}

/// Ends the tree a failed accept left running, and asserts that it ended. `grand` is the grandchild
/// the root reported, if it did. See [`assert_tree_ended`] for what is asserted.
#[cfg(target_os = "linux")]
fn end_tree(tree: &mut Tree, grand: Option<cosca::identity::ProcessId>) {
    if let Some(grand) = grandchild_yet_to_connect(&tree.socks, grand) {
        // The grandchild is alive, so it connects, if it has not yet; one that died instead fails here.
        let socket = accept_or_die_descendant(&tree.listener, grand);
        keep_grandchild(&mut tree.socks, socket);
    }
    let killed = tree.child.kill_tree();
    let root = grand.is_none().then(|| cosca::Process::from_id(tree.child.id()).wait());
    assert_tree_ended(killed, root, &mut tree.socks);
}

/// The grandchild whose connection a failed accept still has to take: the one the root reported,
/// unless it has connected.
#[cfg(target_os = "linux")]
fn grandchild_yet_to_connect(
    socks: &[(u8, TcpStream)],
    grand: Option<cosca::identity::ProcessId>,
) -> Option<cosca::identity::ProcessId> {
    grand.filter(|_| !socks.iter().any(|(tag, _)| *tag == b'G'))
}

/// Keeps the grandchild's accepted connection `socket` with its tag.
#[cfg(target_os = "linux")]
fn keep_grandchild(socks: &mut Vec<(u8, TcpStream)>, mut socket: TcpStream) {
    let mut tag = [0u8; 1];
    socket.read_exact(&mut tag).expect("read the grandchild's tag");
    assert_eq!(&tag, b"G", "only the grandchild connects");
    socks.push((b'G', socket));
}

/// What a tree helper asserts once it has ended the tree a failed accept left running. `killed` is
/// the `kill_tree` it made, which must have succeeded. A grandchild that connected must not echo
/// now, as a `SIGKILL` the kill delivered is pending before it returns, so a kill that sent nothing
/// fails here and never hangs the unwind's drop, which waits for the tree. `root` is the wait for
/// the root's end, made only when no grandchild was reported: the root then reported nothing, so
/// it, and the grandchild it killed or never made, end with the report connection that the unwind
/// closed, whatever the kill did.
#[cfg(target_os = "linux")]
#[track_caller]
fn assert_tree_ended(
    killed: Result<(), cosca::error::Error>,
    root: Option<Result<(), cosca::error::Error>>,
    socks: &mut [(u8, TcpStream)],
) {
    killed.expect("kill_tree of the tree the failed accept left");
    if let Some(root) = root {
        root.expect("wait for the root, which reported no grandchild, to end");
    }
    if let Some((_, grandchild)) = socks.iter_mut().find(|(tag, _)| *tag == b'G') {
        assert_dead(grandchild, "the grandchild after kill_tree");
    }
}

/// Binds the listener a `spawn-grandchild*` root reports its grandchild's pid to, and returns it
/// with the address to pass as [`GC_PID_ADDR_ENV`]. See `report.rs`.
pub fn bind_report() -> (TcpListener, String) {
    let report = TcpListener::bind("127.0.0.1:0").expect("bind the grandchild pid report listener");
    let addr = report.local_addr().unwrap().to_string();
    (report, addr)
}

/// Spawn the `spawn-grandchild` helper tree.
pub fn spawn_grandchild(contain: bool) -> (cosca::Child, Vec<TcpStream>) {
    spawn_tree("spawn-grandchild", contain)
}

/// Binds a fresh `127.0.0.1:0` listener in tokio's async form, for the `*_async` helpers below —
/// one definition so every caller sets non-blocking mode (required for `TcpListener::from_std`)
/// the same way.
#[cfg(feature = "tokio")]
pub fn bind_async_listener() -> (::tokio::net::TcpListener, String) {
    let std_listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = std_listener.local_addr().unwrap().to_string();
    std_listener
        .set_nonblocking(true)
        .expect("set the listener nonblocking for tokio");
    let listener = ::tokio::net::TcpListener::from_std(std_listener).expect("wrap the listener for tokio");
    (listener, addr)
}

/// Async analogue of `spawn_control`: spawn a testbin control child (it connects back and
/// sends its tag before the helper returns), optionally contained.
#[cfg(feature = "tokio")]
pub async fn spawn_control_async(mode: &str, extra: &[&str], contain: bool) -> (cosca::tokio::Child, TcpStream) {
    spawn_control_async_with(mode, extra, contain, |_| {}).await
}

/// [`spawn_control_async`] with the command further configured by `configure` (an env var, say)
/// before the spawn.
#[cfg(feature = "tokio")]
pub async fn spawn_control_async_with(
    mode: &str,
    extra: &[&str],
    contain: bool,
    configure: impl FnOnce(&mut cosca::tokio::Command),
) -> (cosca::tokio::Child, TcpStream) {
    let (listener, addr) = bind_async_listener();
    let mut argv: Vec<String> = vec!["cosca_testbin".into(), mode.into(), addr];
    argv.extend(extra.iter().map(|s| s.to_string()));
    let mut cmd = cosca::tokio::Command::new();
    cmd.env(ACK_ENV, "1");
    silence_async(&mut cmd);
    if contain {
        // Load the testbin as argv[0] via the std path (mode/addr stay at args[1..], so it behaves
        // identically) — keeps this shared helper on one code path across OSes. The async raw
        // backend also serves contained `executable()` (see raw_windows_async.rs).
        let mut path_argv = vec![testbin().to_string()];
        path_argv.extend(argv.into_iter().skip(1));
        cmd.args(path_argv);
        contain_without_cgroup_async(&mut cmd);
    } else {
        cmd.executable(testbin()).args(&argv); // uncontained → the async raw backend
    }
    configure(&mut cmd);
    let mut child = cmd.spawn().expect("spawn async control child");
    let mut sock = accept_or_die_async(&listener, &mut child).await;
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read tag");
    (child, sock)
}

/// Spawn a 2-level tree via a grandchild-spawning testbin `mode` (root tag "R", grandchild
/// tag "G"), with builder configuration supplied by `configure` (containment mode, nesting).
/// Returns the root and grandchild control sockets identified by tag (accept order is not
/// guaranteed).
///
/// The root is watched throughout and the grandchild until it has connected, as in the sync
/// `spawn_tree`: either dying first fails the helper instead of hanging it.
#[cfg(feature = "tokio")]
pub async fn spawn_tree_async(
    mode: &str,
    configure: impl FnOnce(&mut cosca::tokio::Command),
) -> (cosca::tokio::Child, TcpStream, TcpStream) {
    let (listener, addr) = bind_async_listener();
    let mut cmd = cosca::tokio::Command::new();
    // Load the testbin as argv[0] via the std path (mode/addr at args[1..], so it behaves
    // identically): the trees that stay uncontained are backend-agnostic, so
    // argv[0] keeps this helper on one code path across OSes. `configure` applies the
    // containment/nesting/kill_on_drop.
    cmd.args([testbin(), mode, addr.as_str()]).env(ACK_ENV, "1");
    silence_async(&mut cmd);
    configure(&mut cmd);
    let (report, report_addr) = bind_async_listener();
    cmd.env(GC_PID_ADDR_ENV, report_addr);
    let mut child = cmd.spawn().expect("spawn async tree");
    let grand = report_grandchild_async(report, &mut child).await;
    let mut socks = Vec::new();
    accept_tree_members_async(&listener, &mut child, grand, &mut socks).await;
    let mut members = member_socks(socks).into_iter();
    let (root, grandchild) = (
        members.next().expect("root R connected"),
        members.next().expect("grandchild G connected"),
    );
    (child, root, grandchild)
}

/// The async twin of [`accept_tree_members`].
#[cfg(feature = "tokio")]
async fn accept_tree_members_async(
    listener: &::tokio::net::TcpListener,
    child: &mut cosca::tokio::Child,
    grand: cosca::identity::ProcessId,
    socks: &mut Vec<(u8, TcpStream)>,
) {
    for _ in 0..2 {
        let watch_grand = (!socks.iter().any(|(tag, _)| *tag == b'G')).then_some(grand);
        let mut s = accept_or_die_async_also(listener, child, watch_grand).await;
        let mut tag = [0u8; 1];
        s.read_exact(&mut tag).expect("read tag");
        assert!(
            matches!(&tag, b"R" | b"G") && !socks.iter().any(|(t, _)| *t == tag[0]),
            "unexpected or duplicate tree tag {tag:?}"
        );
        socks.push((tag[0], s));
    }
}

/// The async twin of [`Tree`].
#[cfg(feature = "tokio")]
type AsyncTree = Held<::tokio::net::TcpListener, cosca::tokio::Child>;

/// [`spawn_tree_async`] of a contained tree for a test that expects the harness to panic with the
/// tree still running: the async twin of [`spawn_tree_ending_a_failure`], which ends the tree the
/// same way.
#[cfg(feature = "tokio")]
pub async fn spawn_tree_async_ending_a_failure(mode: &str) -> (cosca::tokio::Child, TcpStream, TcpStream) {
    use std::panic::resume_unwind;

    let (listener, addr) = bind_async_listener();
    let mut cmd = cosca::tokio::Command::new();
    cmd.args([testbin(), mode, addr.as_str()])
        .env(ACK_ENV, "1")
        .env(ECHO_HELD_ENV, "1");
    silence_async(&mut cmd);
    cmd.contain();
    let (report, report_addr) = bind_async_listener();
    cmd.env(GC_PID_ADDR_ENV, report_addr);
    let child = cmd.spawn().expect("spawn async tree");
    let mut tree = AsyncTree {
        socks: Vec::new(),
        listener,
        child,
    };
    let mut grand = None;
    let accepted = catching(async {
        let id = report_grandchild_async(report, &mut tree.child).await;
        grand = Some(id);
        accept_tree_members_async(&tree.listener, &mut tree.child, id, &mut tree.socks).await;
    })
    .await;
    if let Err(payload) = accepted {
        #[cfg(target_os = "linux")]
        if names_its_grandchild(tree.child.containment()) {
            end_async_tree(&mut tree, grand).await;
        }
        resume_unwind(payload);
    }
    let AsyncTree { socks, child, .. } = tree;
    let mut members = member_socks(socks).into_iter();
    let (root, grandchild) = (
        members.next().expect("root R connected"),
        members.next().expect("grandchild G connected"),
    );
    (child, root, grandchild)
}

/// Awaits `fut`, returning the payload of a panic it raised instead of unwinding.
#[cfg(feature = "tokio")]
async fn catching<F: std::future::Future>(fut: F) -> Result<F::Output, Box<dyn std::any::Any + Send>> {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::task::Poll;

    let mut fut = std::pin::pin!(fut);
    std::future::poll_fn(|cx| match catch_unwind(AssertUnwindSafe(|| fut.as_mut().poll(cx))) {
        Ok(Poll::Pending) => Poll::Pending,
        Ok(Poll::Ready(out)) => Poll::Ready(Ok(out)),
        Err(payload) => Poll::Ready(Err(payload)),
    })
    .await
}

/// The async twin of [`end_tree`].
#[cfg(all(feature = "tokio", target_os = "linux"))]
async fn end_async_tree(tree: &mut AsyncTree, grand: Option<cosca::identity::ProcessId>) {
    if let Some(grand) = grandchild_yet_to_connect(&tree.socks, grand) {
        let socket = accept_or_die_async_descendant(&tree.listener, grand).await;
        keep_grandchild(&mut tree.socks, socket);
    }
    let killed = tree.child.kill_tree();
    let root = match grand {
        Some(_) => None,
        None => Some(cosca::tokio::Process::from_id(tree.child.id()).wait().await),
    };
    assert_tree_ended(killed, root, &mut tree.socks);
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

/// Spawn a contained [`AsyncEchoTree`] with the given `kill_on_drop`. Root and grandchild are
/// watched as in `spawn_tree_async` above.
#[cfg(feature = "tokio")]
pub async fn spawn_echo_tree_async(kill_on_drop: bool) -> AsyncEchoTree {
    spawn_echo_tree_async_mode("spawn-grandchild-echo", kill_on_drop).await
}

/// [`spawn_echo_tree_async`] over any echo-tree testbin `mode`.
#[cfg(feature = "tokio")]
pub async fn spawn_echo_tree_async_mode(mode: &str, kill_on_drop: bool) -> AsyncEchoTree {
    spawn_echo_tree_async_configured(mode, |cmd| {
        cmd.contain();
        cmd.kill_on_drop(kill_on_drop);
    })
    .await
}

/// [`spawn_echo_tree_async_mode`] with the containment and `kill_on_drop` set by `configure`.
#[cfg(feature = "tokio")]
pub async fn spawn_echo_tree_async_configured(
    mode: &str,
    configure: impl FnOnce(&mut cosca::tokio::Command),
) -> AsyncEchoTree {
    let (listener, addr) = bind_async_listener();
    let mut cmd = cosca::tokio::Command::new();
    cmd.args([testbin(), mode, addr.as_str()]).env(ACK_ENV, "1");
    silence_async(&mut cmd);
    configure(&mut cmd);
    let (report, report_addr) = bind_async_listener();
    cmd.env(GC_PID_ADDR_ENV, report_addr);
    let mut child = cmd.spawn().expect("spawn async echo tree");
    let watched_grand = report_grandchild_async(report, &mut child).await;
    let (mut root, mut grand) = (None, None);
    for _ in 0..2 {
        let watch_grand = grand.is_none().then_some(watched_grand);
        let mut s = accept_or_die_async_also(&listener, &mut child, watch_grand).await;
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
pub async fn spawn_blocker_async() -> (cosca::tokio::Child, TcpStream) {
    spawn_control_async("control-block", &["R"], false).await
}

/// Async analogue of `spawn_grandchild`, returning the root ("R") and grandchild ("G") control
/// sockets identified by tag (accept order is not guaranteed).
#[cfg(feature = "tokio")]
pub async fn spawn_grandchild_async(contain: bool) -> (cosca::tokio::Child, TcpStream, TcpStream) {
    spawn_grandchild_async_with(contain, true).await
}

/// `spawn_grandchild_async` with explicit `contain` and `kill_on_drop` flags, so a test can
/// exercise the `kill_on_drop(false)` Drop early-return (attached still armed) without `detach()`.
#[cfg(feature = "tokio")]
pub async fn spawn_grandchild_async_with(
    contain: bool,
    kill_on_drop: bool,
) -> (cosca::tokio::Child, TcpStream, TcpStream) {
    spawn_tree_async("spawn-grandchild", |cmd| {
        if contain {
            cmd.contain();
        }
        cmd.kill_on_drop(kill_on_drop);
    })
    .await
}

/// A contained async `spawn-grandchild-echo` tree for a test that drops its handle: the root and the
/// grandchild as [`Member`]s, built while both are blocked on their sockets. A member that is
/// released leaves with [`RELEASED_EXIT_CODE`], which no kill produces, so
/// [`assert_members_torn_down`] tells a teardown from a release.
#[cfg(feature = "tokio")]
pub async fn spawn_released_tree_async() -> (cosca::tokio::Child, Member, Member) {
    let AsyncEchoTree {
        child,
        root,
        grand,
        grand_pid,
    } = spawn_echo_tree_async_configured("spawn-grandchild-echo", |cmd| {
        cmd.contain();
        cmd.kill_on_drop(true);
        cmd.env(RELEASED_EXIT_ENV, RELEASED_EXIT_CODE.to_string());
    })
    .await;
    let root = Member::new(root, child.id().pid());
    let grand = Member::new(grand, grand_pid);
    (child, root, grand)
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
/// Process-wide: it takes the `Completion` that `test_own_process::own_process` returns, as
/// `RestoreStdio` does.
#[cfg(unix)]
pub struct RestoreRlimitNofile {
    original: libc::rlimit,
}

#[cfg(unix)]
impl RestoreRlimitNofile {
    pub fn lower_to(_own_process: &test_own_process::Completion, to: libc::rlim_t) -> RestoreRlimitNofile {
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
