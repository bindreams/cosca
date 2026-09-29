//! Test-only child processes shared across the crate's unit tests.

// Blocker fixtures =====

/// The argv of a child that does nothing until its stdin reaches EOF or it is killed: `cat`, or
/// `findstr x` on Windows. Every fixture that needs a child "still alive at some later check"
/// uses this instead of a fixed-duration `sleep`/`ping`, whose own timer would end the child on
/// its own and let a mutant that skips the kill under test pass for the wrong reason. Stdin is
/// what decides the child's fate, so the writer's lifetime is the fixture's lifetime:
///
/// - [`leaked_writer_stdin`]: the write end is never closed, so only a kill by the code under
///   test ends the child (teardown tests that own no handle on it).
/// - [`held_std_blocker`], [`held_contained_blocker`] and [`held_contained_blocker_async`]: the
///   caller holds the write end and must keep it for exactly as long as the child must stay
///   alive. Dropping it (or `std::process::Child::wait()`, which closes the piped stdin before
///   it waits) is a deliberate EOF release.
///
/// A `cat` backgrounded inside an `sh -c` script gets `/dev/null` as stdin (POSIX, for a
/// non-interactive shell) unless it is redirected explicitly, and would exit at once. Write it
/// `exec 3<&0; cat <&3 3<&- &`: `<&3` gives it the real pipe and `3<&-` closes the spare copy.
///
/// Neither `cat` nor `findstr` is proof of life by itself: `Existence::Present` is
/// zombie-inclusive, and `SIGKILL`/`TerminateProcess` land asynchronously. A liveness claim needs
/// an echo round trip through a piped stdout, or (Windows, where `findstr` does not echo) a
/// clean exit after a closed stdin.
pub(crate) const BLOCKER_ARGV: &[&str] = if cfg!(windows) { &["findstr", "x"] } else { &["cat"] };

/// A [`Stdio`](crate::stdio::Stdio) reading from a pipe whose write end is leaked (see
/// [`BLOCKER_ARGV`]).
pub(crate) fn leaked_writer_stdin() -> crate::stdio::Stdio {
    let (reader, writer) = std::io::pipe().expect("pipe");
    #[cfg(unix)]
    let file = std::fs::File::from(std::os::fd::OwnedFd::from(reader));
    #[cfg(windows)]
    let file = std::fs::File::from(std::os::windows::io::OwnedHandle::from(reader));
    std::mem::forget(writer);
    crate::stdio::Stdio::from_file(file)
}

/// A [`BLOCKER_ARGV`] `std::process::Command` with piped stdin (held by the spawned `Child`'s
/// own `stdin` field) and the given stdout. The caller spawns it under `spawn_lock()`.
// Gated with its consumers: `tokio::wait_tests`, and the Unix-only cgroup and kqueue tests.
#[cfg(any(unix, feature = "tokio"))]
pub(crate) fn held_std_blocker(stdout: std::process::Stdio) -> std::process::Command {
    let mut cmd = std::process::Command::new(BLOCKER_ARGV[0]);
    cmd.args(&BLOCKER_ARGV[1..])
        .stdin(std::process::Stdio::piped())
        .stdout(stdout);
    cmd
}

/// A spawned, contained [`BLOCKER_ARGV`] child and the write end of its stdin.
pub(crate) fn held_contained_blocker(stdout: crate::Stdio) -> (crate::Child, std::io::PipeWriter) {
    let mut cmd = crate::Command::new();
    cmd.args(BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(stdout).expect("set stdout");
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    (child, stdin)
}

/// Async twin of [`held_contained_blocker`].
#[cfg(feature = "tokio")]
pub(crate) fn held_contained_blocker_async(stdout: crate::Stdio) -> (crate::tokio::Child, crate::tokio::ChildStdin) {
    let mut cmd = crate::tokio::Command::new();
    cmd.args(BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(stdout).expect("set stdout");
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    (child, stdin)
}

/// A process-group member that announces its own pid on a piped stdout and then blocks on a
/// piped stdin. `pgid` is the group to join (`0` mints a new one of the member's own). The
/// caller must take [`await_member_ready`] before using the member's identity: `spawn()`
/// returning establishes neither that the image is running nor that its `setpgid` is visible.
///
/// `std::process::Child::wait()` closes the piped stdin before it waits, so `wait()` itself ends
/// the member by EOF on its `read` (non-zero exit, no signal). An assertion that a real signal
/// was the cause must check the status's `.signal()` and deliver the signal BEFORE `wait()`.
#[cfg(unix)]
pub(crate) fn member_command(pgid: i32) -> std::process::Command {
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-c")
        .arg("echo $$; read _ignored")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .process_group(pgid);
    cmd
}

/// Blocks until a [`member_command`] child has announced itself, and checks that the
/// announcement came from that child.
#[cfg(unix)]
pub(crate) fn await_member_ready(child: &mut std::process::Child) {
    use std::io::BufRead;
    let mut out = std::io::BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut line = String::new();
    out.read_line(&mut line).expect("read the member's announcement");
    let announced: crate::identity::RawPid = line.trim().parse().expect("the announcement carries a pid");
    assert_eq!(
        announced,
        child.id(),
        "the announcement must come from the member itself"
    );
    // Hand the pipe back rather than dropping it: the member outlives this call, and closing
    // the read end under a live child would make any later write to it a `SIGPIPE`.
    child.stdout = Some(out.into_inner());
}

/// Proves a `cat` blocker is alive and responsive: writes a byte to its stdin and reads it back
/// from its stdout. A killed-but-unreaped `cat` cannot echo.
#[cfg(unix)]
pub(crate) fn assert_echoes(stdin: &mut impl std::io::Write, stdout: &mut impl std::io::Read) {
    stdin.write_all(b"x").expect("write to the blocker");
    let mut echo = [0u8; 1];
    stdout
        .read_exact(&mut echo)
        .expect("the blocker must still be alive to echo");
    assert_eq!(&echo, b"x");
}

/// Writes `bytes` to a held blocker stdin whose reader may already be dead: `Ok` and
/// `BrokenPipe` (the kill under test already landed, so the write goes nowhere) are both
/// expected; any other error is a fixture fault and panics.
pub(crate) fn write_to_possibly_dead_stdin(stdin: &mut impl std::io::Write, bytes: &[u8]) {
    match stdin.write_all(bytes) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
        Err(e) => panic!("writing to the held stdin failed for a reason other than a dead reader: {e}"),
    }
}

#[cfg(test)]
mod write_to_possibly_dead_stdin_tests {
    use super::write_to_possibly_dead_stdin;

    struct FailsWith(std::io::ErrorKind);
    impl std::io::Write for FailsWith {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(self.0.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_dead_reader_is_expected() {
        write_to_possibly_dead_stdin(&mut FailsWith(std::io::ErrorKind::BrokenPipe), b"x");
    }

    #[test]
    fn a_live_reader_is_expected() {
        write_to_possibly_dead_stdin(&mut Vec::new(), b"x");
    }

    #[test]
    #[should_panic(expected = "other than a dead reader")]
    fn any_other_error_panics() {
        write_to_possibly_dead_stdin(&mut FailsWith(std::io::ErrorKind::PermissionDenied), b"x");
    }
}

// Re-exec fixtures =====

#[cfg(unix)]
mod scratch;
#[cfg(unix)]
pub(crate) use scratch::fixture_scratch_tempdir;

/// Runs the libtest fixture at fully-qualified path `fixture` (e.g.
/// `"resolve::resolve_tests::fixture_foo"`) in a FRESH re-exec of this test binary whose OS-level
/// cwd is `cwd`. This proves what the fixture's body proves about a process's real cwd without
/// mutating this shared, multithreaded binary's own cwd. `Command::current_dir` sets the child's
/// cwd before its `exec`/`CreateProcessW`.
///
/// `marker_env` is set to `cwd` in the child only. The fixture uses it to tell a deliberate
/// re-exec from an ordinary suite run, where it must no-op, and to assert its own
/// `current_dir()` against the value, so a dropped `.current_dir(cwd)` is caught (see
/// [`expected_cwd`]).
///
/// Spawns under `spawn_lock()`, like every raw `std::process::Command` re-exec of this binary (see
/// [`spawn_a_process_that_exits`]).
///
/// Panics with the child's captured output on a non-zero exit, or when its libtest banner does not
/// show exactly one test ran and passed: `--exact <fixture>` naming no test matches ZERO tests and
/// still exits 0. Build `fixture` with [`fixture_path!`] so a stale name is a compile error; the
/// banner check backstops the rest.
pub(crate) fn run_fixture_with_cwd(fixture: &str, cwd: &std::path::Path, marker_env: &str) {
    let mut cmd = fixture_command(fixture);
    cmd.env(marker_env, cwd).current_dir(cwd);
    run_fixture_command(fixture, cmd);
}

/// Runs the libtest fixture at `fixture` in a FRESH re-exec of this binary that starts without
/// DAC bypass (see [`fixture_command_without_dac_bypass`]), for a fixture whose `EACCES`
/// precondition must hold for a root driver too. Credentials are per-process state, so the drop
/// cannot happen in this shared suite process.
///
/// The fixture gets a scratch directory built here, under this driver's ambient `TMPDIR`, that
/// its post-drop identity can use; it reaches it with [`fixture_scratch_tempdir`]. Loosening the
/// ambient `TMPDIR` instead would widen a directory this crate does not own.
///
/// See [`run_fixture_with_cwd`] for the re-exec, the panic conditions and [`fixture_path!`].
#[cfg(unix)]
pub(crate) fn run_fixture(fixture: &str) {
    let scratch = tempfile::tempdir().expect("tempdir for fixture scratch root");
    let (mut cmd, _exe_copy) = fixture_command_without_dac_bypass(fixture);

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt as _;
        // `spawn_lock` spans open-to-spawn: `O_CLOEXEC` only acts at `exec`, and a bare `fork`
        // copies the whole fd table, so no other fork that takes the lock may land in between.
        let guard = crate::child::spawn::spawn_lock();
        let fd = scratch::open_scratch_fd(scratch.path());
        let raw = fd.0;
        cmd.env(scratch::FIXTURE_SCRATCH_FD_ENV, raw.to_string());
        // SAFETY: async-signal-safe `fcntl` in the forked child, clearing close-on-exec on the
        // child's own copy only.
        unsafe {
            cmd.pre_exec(move || {
                if libc::fcntl(raw, libc::F_SETFD, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().expect("spawn fixture child");
        drop(fd);
        drop(guard);
        finish_fixture_command(fixture, child);
    }

    #[cfg(not(target_os = "linux"))]
    {
        // The fixture runs as a different uid when this driver is root: hand it the scratch root.
        if unsafe { libc::geteuid() } == 0 {
            use std::os::unix::ffi::OsStrExt as _;
            let path = std::ffi::CString::new(scratch.path().as_os_str().as_bytes())
                .expect("scratch root path has no interior NUL");
            // SAFETY: `path` is a valid C string naming a directory this function just created.
            let rc = unsafe {
                libc::chown(
                    path.as_ptr(),
                    crate::test_privilege::UNPRIVILEGED,
                    crate::test_privilege::UNPRIVILEGED,
                )
            };
            assert!(
                rc == 0,
                "chown scratch root to the fixture's post-drop identity: {}",
                std::io::Error::last_os_error()
            );
        }
        cmd.env(scratch::FIXTURE_SCRATCH_ROOT_ENV, scratch.path());
        let child = {
            let _guard = crate::child::spawn::spawn_lock();
            cmd.spawn().expect("spawn fixture child")
        };
        finish_fixture_command(fixture, child);
    }
}

/// [`fixture_command`] whose child drops DAC bypass in `pre_exec` (see
/// [`crate::test_privilege::drop_dac_bypass_before_exec`]), so the fixture is unprivileged from its
/// first instruction and so is everything it spawns.
///
/// Where a root driver changes uid (non-Linux), the fixture re-execs a copy of this binary in a
/// directory the new uid can enter, and the ambient `TMPDIR` must be one it can enter too. The
/// returned directory holds that copy: keep it until the fixture has exited.
#[cfg(unix)]
pub(crate) fn fixture_command_without_dac_bypass(fixture: &str) -> (std::process::Command, Option<tempfile::TempDir>) {
    #[cfg(target_os = "linux")]
    let (mut cmd, exe_copy) = (fixture_command(fixture), None);
    #[cfg(not(target_os = "linux"))]
    let (mut cmd, exe_copy) = if unsafe { libc::geteuid() } == 0 {
        scratch::assert_dropped_identity_can_traverse_tmpdir();
        let (dir, exe) = scratch::copy_exe_to_traversable_scratch();
        let mut cmd = std::process::Command::new(exe);
        configure_fixture_command(&mut cmd, fixture);
        (cmd, Some(dir))
    } else {
        (fixture_command(fixture), None)
    };
    crate::test_privilege::drop_dac_bypass_before_exec(&mut cmd);
    (cmd, exe_copy)
}

/// Restores a directory's mode on drop, so a test that locked a tempdir down can still remove it,
/// even after a panic. Declare it after the `TempDir` it guards: locals drop in reverse order, so
/// the restore runs first. (`TempDir::drop` swallows its own removal error and would leak the
/// directory.)
#[cfg(unix)]
pub(crate) struct RestoreMode {
    path: std::path::PathBuf,
    mode: u32,
}

#[cfg(unix)]
impl RestoreMode {
    pub(crate) fn new(path: impl Into<std::path::PathBuf>, mode: u32) -> Self {
        Self {
            path: path.into(),
            mode,
        }
    }
}

#[cfg(unix)]
impl Drop for RestoreMode {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;
        if let Err(e) = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(self.mode)) {
            log::warn!("could not restore mode {:o} on {:?}: {e}", self.mode, self.path);
        }
    }
}

/// The `std::process::Command` common to every fixture re-exec: this binary, filtered to exactly
/// one test, single-threaded, stdio captured, [`FIXTURE_PARENT_PID_ENV`] set (see
/// [`is_fixture_reexec`]).
///
/// The ambient `TMPDIR` is inherited untouched; see [`run_fixture`] for writable scratch after a
/// drop.
///
/// No argv-slot-0 placeholder, unlike [`fixture_argv`]: `std::process::Command` supplies argv[0].
///
/// `pub(crate)` so a launcher with its own stdio needs (`exact_posix_tests.rs` pipes stdin) can
/// start here and override only that.
pub(crate) fn fixture_command(fixture: &str) -> std::process::Command {
    // `/proc/self/exe`: the binary's own directory (e.g. nextest's extraction dir under a `0700`
    // TMPDIR) may be unreachable post-drop; the kernel grants a process its own image regardless.
    #[cfg(target_os = "linux")]
    let program = std::path::PathBuf::from("/proc/self/exe");
    #[cfg(not(target_os = "linux"))]
    let program = std::env::current_exe().expect("current_exe");
    let mut cmd = std::process::Command::new(program);
    configure_fixture_command(&mut cmd, fixture);
    cmd
}

/// The argv, env and stdio common to every fixture re-exec, split out for a caller that supplies
/// its own program path.
fn configure_fixture_command(cmd: &mut std::process::Command, fixture: &str) {
    cmd.args(["--test-threads=1", "--exact", fixture])
        .env(FIXTURE_PARENT_PID_ENV, std::process::id().to_string())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
}

/// Set by every fixture re-exec to its parent's pid; see [`is_fixture_reexec`].
const FIXTURE_PARENT_PID_ENV: &str = "COSCA_FIXTURE_PARENT_PID";

/// Whether this process's real parent is the one that re-exec'd it via `run_fixture*`; an
/// inherited marker env var alone does not prove that. On `true`, writes
/// [`FIXTURE_GATE_PASSED_LINE`]; a caller with further checks before its gate is really passed
/// uses [`parent_pid_matches`] and writes the line itself.
#[cfg(unix)]
pub(crate) fn is_fixture_reexec() -> bool {
    let reexec = parent_pid_matches();
    if reexec {
        write_gate_passed();
    }
    reexec
}

/// [`is_fixture_reexec`]'s check, without the write.
#[cfg(unix)]
fn parent_pid_matches() -> bool {
    std::env::var(FIXTURE_PARENT_PID_ENV)
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .is_some_and(|pid| pid == std::os::unix::process::parent_id())
}

/// Written to a fixture's real stderr, bypassing libtest's capture, once its gate passes. A gate
/// that returns early exits 0 like a fixture that ran and passed, so [`finish_fixture_command`]
/// requires the line to tell them apart.
pub(crate) const FIXTURE_GATE_PASSED_LINE: &str = "COSCA_FIXTURE_GATE_PASSED";

fn write_gate_passed() {
    use std::io::Write;
    // A failed write is a broken fixture, not a missing line for the driver to guess at.
    writeln!(std::io::stderr(), "{FIXTURE_GATE_PASSED_LINE}").expect("write the gate line to stderr");
}

/// Spawns `cmd` (from [`fixture_command`]) under `spawn_lock()` and waits for it; panics as
/// [`run_fixture_with_cwd`] documents.
fn run_fixture_command(fixture: &str, mut cmd: std::process::Command) {
    let child = {
        let _guard = crate::child::spawn::spawn_lock();
        cmd.spawn().expect("spawn fixture child")
    };
    finish_fixture_command(fixture, child);
}

/// The post-spawn half of [`run_fixture_command`], for a launcher that spawned under its own lock.
fn finish_fixture_command(fixture: &str, child: std::process::Child) {
    let output = child.wait_with_output().expect("wait for fixture child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "fixture {fixture} failed (status {:?}):\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        output.status,
    );
    assert!(
        stdout.contains("running 1 test") && stdout.contains("test result: ok. 1 passed;"),
        "fixture {fixture} exited 0 but did not run and pass exactly one test; `--exact {fixture}` \
         probably matched none:\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
    assert!(
        stderr.contains(FIXTURE_GATE_PASSED_LINE),
        "fixture {fixture} passed but never wrote {FIXTURE_GATE_PASSED_LINE:?}: its re-exec gate \
         returned early without running its body:\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
}

/// The directory [`run_fixture_with_cwd`]'s caller prepared, read from `marker_env`; `None` when it
/// is unset or (on unix) [`parent_pid_matches`] says this is not a deliberate re-exec. Either way
/// the fixture is also picked up by ordinary suite runs, where it must no-op.
///
/// Also asserts this process's own `current_dir()` IS that directory, so a fixture that reads its
/// cwd through here cannot keep passing after `.current_dir(cwd)` is silently dropped. The gate
/// line is written last, after both checks.
pub(crate) fn expected_cwd(marker_env: &str) -> Option<std::path::PathBuf> {
    #[cfg(unix)]
    if !parent_pid_matches() {
        return None;
    }
    let expected = std::path::PathBuf::from(std::env::var_os(marker_env)?);
    let actual = std::env::current_dir().expect("current_dir");
    assert_eq!(
        actual.canonicalize().expect("canonicalize actual cwd"),
        expected.canonicalize().expect("canonicalize expected cwd"),
        "this fixture's OS-level cwd must be the directory run_fixture_with_cwd's caller prepared",
    );
    write_gate_passed();
    Some(expected)
}

/// Builds the fully-qualified libtest `--exact` path of the `#[test] fn` named `$name`, for
/// [`run_fixture_with_cwd`]'s `fixture` argument. Two things tie the call site to the fixture
/// instead of letting them drift apart as two independently hand-typed strings:
///
/// - `let _: fn() = $name;` forces the compiler to resolve `$name` as an item in scope — a typo
///   or a stale name after a rename is a compile error here, not a filter that silently matches
///   zero tests at runtime (see [`run_fixture_with_cwd`]'s doc for why that is exactly the bug
///   this macro exists to rule out).
/// - `module_path!()` derives the module portion at compile time, so it can never fall out of
///   sync with a file move or a module rename; libtest's `--exact` filter never includes the
///   crate-name component `module_path!()` always carries as its own first segment, hence the
///   [`strip_crate_prefix`] call.
macro_rules! fixture_path {
    ($name:ident) => {{
        let _: fn() = $name;
        crate::test_child::strip_crate_prefix(concat!(module_path!(), "::", stringify!($name)))
    }};
}
pub(crate) use fixture_path;

/// Strips the crate-name segment `module_path!()` always carries as its own first component
/// (e.g. `"cosca::resolve::resolve_tests"`), since libtest's `--exact` filter never includes it
/// (e.g. `"resolve::resolve_tests"`). Panics if `path` does not start with that segment, which
/// would mean `module_path!()`'s documented contract no longer holds.
pub(crate) fn strip_crate_prefix(path: &'static str) -> &'static str {
    let prefix = concat!(env!("CARGO_PKG_NAME"), "::");
    path.strip_prefix(prefix)
        .unwrap_or_else(|| panic!("{path:?} does not start with {prefix:?} — module_path!()'s contract changed"))
}

/// A child that exits promptly and needs no external binary: this same test binary, run
/// with a filter that matches nothing, so libtest runs zero tests and exits 0.
///
/// The libtest filter is mandatory, and is why this lives in exactly one place: re-execing
/// the test binary with NO arguments runs the whole suite — including whichever test called
/// this — which then re-execs again, unboundedly.
///
/// Spawns under `spawn_lock()`: on macOS, a fork here that lands while another test's fd
/// marker write end happens to be open would transiently inherit it, and a concurrently
/// running sweep could then find and signal this bystander child. `spawn_lock()` is the same
/// lock every cosca-originated spawn in this test binary already takes.
pub(crate) fn spawn_a_process_that_exits() -> std::process::Child {
    let _guard = crate::child::spawn::spawn_lock();
    std::process::Command::new(std::env::current_exe().expect("current_exe"))
        .args(["--exact", "__cosca_no_such_test__"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn")
}

/// `more.com` by its `System32` path (no `PATH` lookup): blocks reading stdin and exits 0 on EOF,
/// unlike `findstr x`, whose exit 1 is indistinguishable from a kill.
#[cfg(windows)]
pub(crate) fn windows_more() -> std::path::PathBuf {
    std::path::Path::new(&std::env::var_os("SystemRoot").expect("SystemRoot is set on Windows"))
        .join("System32")
        .join("more.com")
}

/// A contained [`windows_more`] child blocked on a piped stdin the caller holds. It ends only by a
/// real kill or the caller closing the pipe (exit 0). Stdout is nulled because `more` echoes.
#[cfg(windows)]
pub(crate) fn windows_blocker() -> (crate::Child, std::io::PipeWriter) {
    let mut cmd = crate::Command::new();
    cmd.args([windows_more()]);
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::null()).expect("set stdout null");
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    (child, stdin)
}

/// Async twin of [`windows_blocker`]; `configure` selects the containment under test.
#[cfg(all(windows, feature = "tokio"))]
pub(crate) fn windows_blocker_async(
    configure: impl FnOnce(&mut crate::tokio::Command),
) -> (crate::tokio::Child, crate::tokio::ChildStdin) {
    let mut cmd = crate::tokio::Command::new();
    cmd.args([windows_more()]);
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::null()).expect("set stdout null");
    configure(&mut cmd);
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    (child, stdin)
}

/// The argv of a child that ignores `SIGTERM` (an ignored disposition survives the `exec`), tells
/// its stdout it is ready, then blocks on stdin as `cat`. Only `SIGKILL` or stdin EOF ends it.
#[cfg(unix)]
const TERM_IGNORING_BLOCKER_ARGV: &[&str] = &["sh", "-c", "trap '' TERM; echo r; exec cat"];

/// A spawned, contained `SIGTERM`-ignoring [`TERM_IGNORING_BLOCKER_ARGV`] child and the write end of
/// its stdin, returned once its readiness byte proves the trap is installed. A test whose only end
/// for it is a sweep or escalation holds the stdin and releases it after the kill.
#[cfg(unix)]
pub(crate) fn term_ignoring_blocker() -> (crate::Child, std::io::PipeWriter) {
    use std::io::Read as _;

    let mut cmd = crate::Command::new();
    cmd.args(TERM_IGNORING_BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    let mut readiness = [0u8; 1];
    child
        .stdout()
        .expect("piped stdout")
        .read_exact(&mut readiness)
        .expect("readiness byte");
    (child, stdin)
}

/// Async twin of [`term_ignoring_blocker`].
#[cfg(all(unix, feature = "tokio"))]
pub(crate) async fn term_ignoring_blocker_async() -> (crate::tokio::Child, crate::tokio::ChildStdin) {
    use ::tokio::io::AsyncReadExt as _;

    let mut cmd = crate::tokio::Command::new();
    cmd.args(TERM_IGNORING_BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    let mut readiness = [0u8; 1];
    child
        .stdout()
        .expect("piped stdout")
        .read_exact(&mut readiness)
        .await
        .expect("readiness byte");
    (child, stdin)
}

/// A blocker died to a kill, not by exiting on its own once its stdin closed: `SIGKILL` on Unix, a
/// non-zero exit on Windows (`more.com` exits 0 on EOF). Separate compilation units cannot share
/// it: `tests/common` keeps its own copy.
pub(crate) fn assert_killed(who: &str, status: std::process::ExitStatus) {
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
    assert!(
        !status.success(),
        "{who} must be killed, not exit on its own: {status:?}"
    );
}

/// The argv for re-executing this test binary against one fixture through `cosca::Command`,
/// whose `args` is the **full** argv — libtest drops slot 0 as the binary name, so a filter or
/// option placed there is silently eaten and `--exact` degrades to substring matching.
/// `--test-threads=1` keeps a future filter that matches more than one test from running them
/// concurrently inside a process the caller is about to signal.
#[cfg(any(windows, feature = "tokio"))]
pub(crate) fn fixture_argv(test: &str) -> [&str; 4] {
    ["cosca_unit_tests", "--test-threads=1", "--exact", test]
}

/// The fully-qualified libtest path of [`fixture_survives_group_signal`], for callers that
/// re-exec this binary against it directly (`current_exe() --exact <this>`) rather than through
/// [`spawn_a_process_that_exits`]'s own filter.
#[cfg(windows)]
pub(crate) const FIXTURE_SURVIVES_GROUP_SIGNAL_TEST: &str = "test_child::fixture_survives_group_signal";

/// The env var carrying the `127.0.0.1:<port>` address the grandchild (a re-exec'd
/// [`fixture_registers_then_blocks`]) connects back to; [`fixture_survives_group_signal`] only
/// forwards it. Its presence also tells that fixture it was re-exec'd deliberately rather than
/// picked up by an ordinary, unfiltered suite run.
#[cfg(windows)]
pub(crate) const FIXTURE_SURVIVES_GROUP_SIGNAL_ADDR_ENV: &str = "COSCA_FIXTURE_SURVIVES_GROUP_SIGNAL_ADDR";

/// Windows-only fixture for the `root_exited`-on-`MembersRemain` regression (sync and async
/// twins): a no-op when picked up by an ordinary, unfiltered suite run —
/// [`FIXTURE_SURVIVES_GROUP_SIGNAL_ADDR_ENV`] is unset there. Re-executed via `current_exe()
/// --exact` [`FIXTURE_SURVIVES_GROUP_SIGNAL_TEST`] with that var set, it spawns a grandchild a
/// group `CTRL_BREAK` can never reach — `CREATE_NEW_PROCESS_GROUP` puts it in its own process
/// group, the same isolation `graceful_shutdown_tree`'s own doc describes for a nested
/// contained descendant — then returns immediately, letting this intermediate process exit.
///
/// The grandchild is itself a re-exec'd [`fixture_registers_then_blocks`], given THIS fixture's
/// OWN `addr` (forwarded via [`FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV`]) so it connects and
/// blocks DIRECTLY against the caller's listener — never against a socket this short-lived
/// intermediate process would itself own and then close on its own exit, which a
/// caller-chosen `grace` can easily outlive. The grandchild's own connect-and-tag is thus the
/// happens-before edge the caller blocks on: it cannot tag until its own code is running, in
/// its own group. The tag goes out over a real TCP socket, not `print!`/`io::stdout()`: libtest
/// captures the latter per-test and discards it for a passing test, so a stdout-based readiness
/// byte never reaches the caller's piped reader at all — this is the same control-channel shape
/// `tests/common`'s `spawn_tree`/`spawn_tree_async` tag handshake already uses for exactly this
/// reason, not a Windows-specific mechanism. The job object still tracks the grandchild as a
/// tree member despite its own process group (job membership and process group are independent
/// Win32 concepts), so it shows up as a `MembersRemain` survivor even though the signal itself
/// never reaches it, and it stays that way for as long as the caller holds its control socket
/// open. Mirrors [`spawn_a_process_that_exits`]'s
/// filtered-re-exec idiom (see its own doc for why the filter is mandatory) put to a second use.
#[cfg(windows)]
#[test]
fn fixture_survives_group_signal() {
    let Some(addr) = std::env::var_os(FIXTURE_SURVIVES_GROUP_SIGNAL_ADDR_ENV) else {
        return; // picked up by an ordinary suite run — deliberately inert
    };
    use std::os::windows::process::CommandExt;

    // CREATE_NEW_PROCESS_GROUP (winbase.h). A scalar flag, so a raw constant needs no
    // `windows`-crate import: `std::os::windows::process::CommandExt::creation_flags` takes it
    // as a plain `u32`.
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    #[allow(clippy::zombie_processes)] // intentional: the grandchild must outlive us; containment kills it
    let _survivor = std::process::Command::new(std::env::current_exe().expect("current_exe"))
        // `[1..]`: skip `fixture_argv`'s slot-0 placeholder; `std::process::Command` supplies argv[0].
        .args(&fixture_argv(FIXTURE_REGISTERS_THEN_BLOCKS_TEST)[1..])
        .env(FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV, &addr)
        .creation_flags(CREATE_NEW_PROCESS_GROUP)
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("spawn a grandchild the group signal cannot reach");
}

/// The fully-qualified libtest path of [`fixture_registers_then_blocks`], for callers that
/// re-exec this binary against it directly (`current_exe() --exact <this>`).
// Gated with its consumers: the sync caller uses it only under `cfg(windows)`, the other two are
// behind the `tokio` feature, so a default-feature Unix build has none and `-D warnings` rejects it.
#[cfg(any(windows, feature = "tokio"))]
pub(crate) const FIXTURE_REGISTERS_THEN_BLOCKS_TEST: &str = "test_child::fixture_registers_then_blocks";

/// The env var carrying the `127.0.0.1:<port>` address [`fixture_registers_then_blocks`] tags.
/// Its mere presence also tells the fixture it was re-exec'd deliberately rather than picked up
/// by an ordinary, unfiltered suite run.
pub(crate) const FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV: &str = "COSCA_FIXTURE_REGISTERS_THEN_BLOCKS_ADDR";

/// Bind a rendezvous listener for [`fixture_registers_then_blocks`]; returns it and its
/// `127.0.0.1:<port>` address.
#[cfg(any(windows, feature = "tokio"))]
pub(crate) fn registration_rendezvous() -> (std::net::TcpListener, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind rendezvous listener");
    let addr = listener.local_addr().expect("local_addr").to_string();
    (listener, addr)
}

/// Fixture supplying a happens-before edge on a live child: a no-op when picked up by an
/// ordinary, unfiltered suite run ([`FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV`] is unset there).
/// Re-executed via `current_exe() --exact` [`FIXTURE_REGISTERS_THEN_BLOCKS_TEST`] with that var
/// set, it connects to the caller's listener, writes one tag byte, then blocks on a 1-byte read
/// of that same socket. The caller unblocks it by writing a byte back, and it then exits 0 of
/// its own accord — an exit code no forced kill can produce.
///
/// The tag is the edge: the fixture cannot write it until it is executing its own code. On
/// Windows that is also after the console has registered it — a child signalled before that
/// point dies during loader init instead of to the console event, which is a different exit code
/// and a different thing under test.
///
/// It installs no console-control handler, so `CTRL_BREAK`'s default disposition terminates it.
/// Blocking on the socket rather than parking means a panicking or aborted caller closes the
/// socket and the fixture exits on EOF instead of orphaning.
#[test]
fn fixture_registers_then_blocks() {
    let Some(addr) = std::env::var_os(FIXTURE_REGISTERS_THEN_BLOCKS_ADDR_ENV) else {
        return; // picked up by an ordinary suite run — deliberately inert
    };
    use std::io::{Read, Write};

    let mut sock = std::net::TcpStream::connect(addr.to_str().expect("utf8 addr")).expect("connect rendezvous socket");
    sock.write_all(b"R").expect("write registration tag");
    sock.flush().expect("flush registration tag");
    let mut sink = [0u8; 1];
    _ = sock.read(&mut sink);
}

/// The fully-qualified libtest path of [`fixture_control_block`].
#[cfg(feature = "tokio")]
pub(crate) const FIXTURE_CONTROL_BLOCK_TEST: &str = "test_child::fixture_control_block";

/// The env var carrying the `127.0.0.1:<port>` address [`fixture_control_block`] tags. Its mere
/// presence also tells the fixture it was re-exec'd deliberately rather than picked up by an
/// ordinary, unfiltered suite run.
#[cfg(feature = "tokio")]
pub(crate) const FIXTURE_CONTROL_BLOCK_ADDR_ENV: &str = "COSCA_FIXTURE_CONTROL_BLOCK_ADDR";

/// A child that reports readiness and then blocks until the caller releases or kills it: a no-op
/// when picked up by an ordinary, unfiltered suite run ([`FIXTURE_CONTROL_BLOCK_ADDR_ENV`] is
/// unset there). Re-executed via `current_exe() --exact` [`FIXTURE_CONTROL_BLOCK_TEST`] with that
/// var set, it connects to the caller's listener, writes one tag byte, then blocks on a 1-byte
/// read of that same socket and RETURNS as soon as the read returns — so a caller that writes a
/// byte gets a clean voluntary exit, and a caller that kills it gets the socket's EOF.
///
/// Mirrors [`fixture_registers_then_blocks`]'s filtered-re-exec idiom (see
/// [`spawn_a_process_that_exits`] for why the filter is mandatory), and deliberately takes NO
/// `spawn_lock()`: see [`spawn_async_blocker`].
#[cfg(feature = "tokio")]
#[test]
fn fixture_control_block() {
    let Some(addr) = std::env::var_os(FIXTURE_CONTROL_BLOCK_ADDR_ENV) else {
        return; // picked up by an ordinary suite run — deliberately inert
    };
    use std::io::{Read, Write};

    let mut sock = std::net::TcpStream::connect(addr.to_str().expect("utf8 addr")).expect("connect control socket");
    sock.write_all(b"R").expect("write readiness tag");
    sock.flush().expect("flush readiness tag");
    let mut sink = [0u8; 1];
    _ = sock.read(&mut sink);
}

/// Spawn [`fixture_control_block`] through `cosca::tokio` and return its handle plus the control
/// socket, already past the readiness tag — so the child is provably executing its own code.
///
/// **Takes no `spawn_lock()`, deliberately.** That lock is a plain non-reentrant mutex and
/// cosca's own async spawn takes it internally, so a helper holding it across a cosca spawn
/// deadlocks on its own thread. Every existing helper that takes it spawns via
/// `std::process::Command`; the cosca-spawning helpers do not.
///
/// Uncontained (so the tree teardown is a verified no-op) and stdin INHERITED (so closing the
/// parent's stdio cannot make the child exit on its own). Spawned via `executable()`, which puts
/// Windows on the raw `CreateProcessW` backend.
#[cfg(feature = "tokio")]
pub(crate) fn spawn_async_blocker() -> (crate::tokio::Child, std::net::TcpStream) {
    use std::io::Read as _;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind control listener");
    let addr = listener.local_addr().expect("local_addr").to_string();
    let exe = std::env::current_exe().expect("current_exe");
    let mut cmd = crate::tokio::Command::new();
    cmd.executable(&exe)
        .args(fixture_argv(FIXTURE_CONTROL_BLOCK_TEST))
        .env(FIXTURE_CONTROL_BLOCK_ADDR_ENV, &addr);
    // The child runs a full libtest harness, which writes its `running 1 test` / `test result:`
    // banner to fd 1 directly — libtest's capture wraps the Rust print machinery, not the
    // descriptor, so an inherited fd 1 lands that banner raw (and mid-line) in THIS binary's
    // output. Both are nulled; stdin stays inherited, per this helper's contract.
    cmd.stdout(crate::stdio::Stdio::null()).expect("stdout null");
    cmd.stderr(crate::stdio::Stdio::null()).expect("stderr null");
    let child = cmd.spawn().expect("spawn the control-block fixture");
    let (mut sock, _) = listener.accept().expect("accept the control socket");
    let mut tag = [0u8; 1];
    sock.read_exact(&mut tag).expect("read the readiness tag");
    assert_eq!(&tag, b"R", "unexpected control tag");
    (child, sock)
}

/// Exit code of the `tool` in [`cwd_and_path_tools`]'s first directory.
#[cfg(unix)]
pub(crate) const CWD_TOOL_EXIT: i32 = 11;
/// Exit code of the `tool` in [`cwd_and_path_tools`]'s second directory.
#[cfg(unix)]
pub(crate) const PATH_TOOL_EXIT: i32 = 22;

/// Two directories, each holding an executable script named `tool` that exits with its own code
/// ([`CWD_TOOL_EXIT`], [`PATH_TOOL_EXIT`]), so a child's exit status says which one was loaded.
/// Meant as the child's working directory and its `PATH`, respectively.
///
/// Each write is serialized against every other spawn's `fork` and the guard dropped before the
/// caller's spawn: a `fork` while a script's writable descriptor is open leaves the forked child
/// holding it until it execs, and `execve` of that script then fails with `ETXTBSY`. The lock is
/// not reentrant, so holding it across a `spawn()` would deadlock.
#[cfg(unix)]
pub(crate) fn cwd_and_path_tools() -> (tempfile::TempDir, tempfile::TempDir) {
    use std::os::unix::fs::PermissionsExt;
    let dirs = (
        tempfile::tempdir().expect("tempdir"),
        tempfile::tempdir().expect("tempdir"),
    );
    for (dir, code) in [(&dirs.0, CWD_TOOL_EXIT), (&dirs.1, PATH_TOOL_EXIT)] {
        let tool = dir.path().join("tool");
        let _guard = crate::child::spawn::spawn_lock();
        std::fs::write(&tool, format!("#!/bin/sh\nexit {code}\n")).expect("write tool");
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).expect("chmod tool");
    }
    dirs
}

#[cfg(test)]
#[path = "test_child_tests.rs"]
mod test_child_tests;
