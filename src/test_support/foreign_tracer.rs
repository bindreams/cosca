//! A foreign tracer for tests, as `gdb -p` is one: a re-exec of this test binary that seizes one of
//! the test's own children with `ptrace` without being its parent (`TRACER` group; needs
//! `COSCA_TEST_TRACER_CONSENT=1`).
//!
//! A tracee that dies while a foreign tracer holds it is a zombie the tracer alone can see: its
//! pidfd is readable, the parent's `waitid` finds no record, and the parent's own record appears
//! only after the tracer hands the zombie back: by reaping it with `waitpid`, or by exiting
//! (`exit_ptrace` detaches it; a debugger that quits). The tracer is [`foreign_tracer_helper`].
//!
//! A test takes `tracer_group`. A tracee that calls [`allow_any_tracer_now`] itself reports that it
//! returned, and the test reads that report before [`spawn_helper`]. [`Tracer`] calls block; a test
//! whose own thread blocks until the tracer hands the zombie back drives it from another thread.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::process::CommandExt as _;
use std::process::{ChildStdin, ChildStdout};

use crate::test_child::{fixture_command, fixture_path, is_marked_fixture_reexec};

/// Marks the helper re-exec; the value is the driver's pid.
const MARKER: &str = "COSCA_TEST_SHARED_FOREIGN_TRACER";

const PID_ENV: &str = "COSCA_TEST_SHARED_FOREIGN_TRACER_PID";

/// Set (to anything) for a helper that seizes its tracee with `PTRACE_O_TRACEEXIT`.
const HOLD_EXIT_ENV: &str = "COSCA_TEST_SHARED_FOREIGN_TRACER_HOLD_EXIT";

/// The go bytes. `STOP` makes the helper stop the tracee and report it, `RESUME` resumes a tracee it
/// stopped; `LET_EXIT` lets a tracee held at its exit stop on from it; `REAP` and `EXIT` hand the
/// zombie back.
pub(crate) const STOP: u8 = b's';
pub(crate) const RESUME: u8 = b'g';
pub(crate) const LET_EXIT: u8 = b'c';
pub(crate) const REAP: u8 = b'r';
pub(crate) const EXIT: u8 = b'x';

fn say(line: &str) {
    // Not `println!`: it panics on a write error.
    writeln!(std::io::stdout(), "@@{line}@@").expect("write to the driver");
}

/// `waitpid(pid, __WALL)`, past `EINTR`.
fn waitpid_status(pid: libc::pid_t) -> libc::c_int {
    loop {
        let mut status = 0;
        // SAFETY: `status` is a valid out-pointer.
        let r = unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };
        if r != -1 {
            return status;
        }
        let e = std::io::Error::last_os_error();
        assert_eq!(e.raw_os_error(), Some(libc::EINTR), "waitpid: {e}");
    }
}

/// The foreign tracer: seize the pid in [`PID_ENV`] (or, without it, the pid on stdin's first line),
/// report, and act on each go byte from stdin:
/// `STOP` interrupts the tracee and reports the stop, `RESUME` continues it (a tracee a `SIGKILL`
/// already ended is `ESRCH`, and fine), `LET_EXIT` waits for the tracee's exit stop and
/// lets it on from it, `REAP` reaps the zombie with `waitpid` and reports, `EXIT` exits without
/// reaping. A no-op unless it is the re-exec the driver started.
///
/// It seizes with no options (unless [`spawn_helper_holding_exit`] asked for `PTRACE_O_TRACEEXIT`),
/// so the kill is not delayed by an exit stop, and the pidfd turns readable at the zombie. A tracee
/// held at its exit stop is still alive: it is a member of its cgroup, and no pidfd is readable.
#[skuld::test]
fn foreign_tracer_helper() {
    if !is_marked_fixture_reexec(MARKER) {
        return;
    }
    let pid: libc::pid_t = match std::env::var(PID_ENV) {
        Ok(pid) => pid,
        // Started before its tracee existed: see [`spawn_unseized_helper`].
        Err(_) => {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).expect("the tracee's pid");
            line
        }
    }
    .trim()
    .parse()
    .expect("a pid");
    // SAFETY: a ptrace request on a pid; variadic `addr`/`data` are read as pointers: typed nulls.
    let null = std::ptr::null_mut::<libc::c_void>;
    let options = if std::env::var_os(HOLD_EXIT_ENV).is_some() {
        libc::PTRACE_O_TRACEEXIT
    } else {
        0
    };
    let rc = unsafe { libc::ptrace(libc::PTRACE_SEIZE, pid, null(), options as usize as *mut libc::c_void) };
    assert_eq!(rc, 0, "PTRACE_SEIZE: {}", std::io::Error::last_os_error());
    say("seized");
    loop {
        let mut go = [0u8; 1];
        std::io::stdin().read_exact(&mut go).expect("the driver's go byte");
        match go[0] {
            EXIT => return,
            STOP => {
                // SAFETY: as above.
                let rc = unsafe { libc::ptrace(libc::PTRACE_INTERRUPT, pid, null(), null()) };
                assert_eq!(rc, 0, "PTRACE_INTERRUPT: {}", std::io::Error::last_os_error());
                let status = waitpid_status(pid);
                assert!(libc::WIFSTOPPED(status), "waitpid: not a stop: {status:#x}");
                say("stopped");
            }
            RESUME => {
                // SAFETY: as above.
                let rc = unsafe { libc::ptrace(libc::PTRACE_CONT, pid, null(), null()) };
                let e = std::io::Error::last_os_error();
                assert!(rc == 0 || e.raw_os_error() == Some(libc::ESRCH), "PTRACE_CONT: {e}");
            }
            LET_EXIT => {
                let status = waitpid_status(pid);
                assert!(
                    libc::WIFSTOPPED(status) && status >> 16 == libc::PTRACE_EVENT_EXIT,
                    "waitpid: not the exit stop: {status:#x}"
                );
                // SAFETY: as above.
                let rc = unsafe { libc::ptrace(libc::PTRACE_CONT, pid, null(), null()) };
                assert_eq!(rc, 0, "PTRACE_CONT: {}", std::io::Error::last_os_error());
                say("continued");
            }
            REAP => {
                // The driver saw the pidfd readable, so the tracee is a zombie, which `waitpid`
                // reports before any stop.
                let status = waitpid_status(pid);
                assert!(
                    libc::WIFEXITED(status) || libc::WIFSIGNALED(status),
                    "waitpid: not an exit: {status:#x}"
                );
                say("reaped");
                return;
            }
            other => panic!("an unknown go byte {other:#x}"),
        }
    }
}

/// Lets any process trace the child `cmd` spawns: it calls [`allow_any_tracer_now`] before exec.
pub(crate) fn allow_any_tracer(cmd: &mut std::process::Command) {
    // SAFETY: `allow_any_tracer_now` is a raw `prctl` syscall, async-signal-safe, and touches only
    // the forked child.
    unsafe {
        cmd.pre_exec(allow_any_tracer_now);
    }
}

/// Lets any process trace this one (`PR_SET_PTRACER`), which Yama's scope 1 requires of a tracer
/// that is no ancestor. For a tracee that cannot take [`allow_any_tracer`], such as one spawned by
/// `cosca::tokio::Command`, which has no `pre_exec`. Until it returns, [`spawn_helper`]'s seize
/// fails: the tracee reports after it, and the driver reads that report first.
pub(crate) fn allow_any_tracer_now() -> std::io::Result<()> {
    match rustix::process::set_ptracer(rustix::process::PTracer::Any) {
        // `INVAL`: no Yama, so nothing restricts a tracer and nothing needs allowing.
        Ok(()) | Err(rustix::io::Errno::INVAL) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Ends the helper when the driver leaves, whatever the way.
struct Helper(std::process::Child);

impl Drop for Helper {
    fn drop(&mut self) {
        _ = self.0.kill();
        _ = self.0.wait();
    }
}

/// A running foreign tracer.
pub(crate) struct Tracer {
    helper: Helper,
    go: Option<ChildStdin>,
    lines: std::io::Lines<BufReader<ChildStdout>>,
}

/// Starts the helper on `pid`, which was spawned with [`allow_any_tracer`] or has reported that its
/// [`allow_any_tracer_now`] returned, and returns once it has seized the tracee.
pub(crate) fn spawn_helper(pid: u32) -> Tracer {
    let mut tracer = start_helper(Some(pid), false);
    tracer.expect("seized");
    tracer
}

/// [`spawn_helper`] whose tracee stops at its exit (`PTRACE_O_TRACEEXIT`) and stays a live member of
/// its cgroup, whatever kills it, until the tracer sends [`LET_EXIT`].
#[cfg(feature = "tokio")]
pub(crate) fn spawn_helper_holding_exit(pid: u32) -> Tracer {
    let mut tracer = start_helper(Some(pid), true);
    tracer.expect("seized");
    tracer
}

/// Starts the helper before its tracee exists, for a test that cannot start one once it does (its
/// spawning thread holds `spawn_lock` until the tracee dies); [`Tracer::seize`] names the tracee.
#[cfg_attr(
    not(feature = "tokio"),
    allow(dead_code, reason = "only the tokio spawn's tracer test uses it")
)]
pub(crate) fn spawn_unseized_helper() -> Tracer {
    start_helper(None, false)
}

fn start_helper(pid: Option<u32>, hold_exit: bool) -> Tracer {
    let mut cmd = fixture_command(fixture_path!(foreign_tracer_helper));
    if let Some(pid) = pid {
        cmd.env(PID_ENV, pid.to_string());
    }
    cmd.env(MARKER, std::process::id().to_string())
        .env_remove(HOLD_EXIT_ENV)
        .env_remove("RUST_TEST_NOCAPTURE")
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit());
    if hold_exit {
        cmd.env(HOLD_EXIT_ENV, "1");
    }
    let mut helper = Helper(crate::test_spawn::spawn(&mut cmd).expect("spawn the foreign tracer"));
    let go = helper.0.stdin.take().expect("piped stdin");
    let lines = BufReader::new(helper.0.stdout.take().expect("piped stdout")).lines();
    Tracer {
        helper,
        go: Some(go),
        lines,
    }
}

impl Tracer {
    /// Has a helper from [`spawn_unseized_helper`] seize `pid`, which has reported that its
    /// [`allow_any_tracer_now`] returned, and returns once it has.
    #[cfg_attr(
        not(feature = "tokio"),
        allow(dead_code, reason = "only the tokio spawn's tracer test uses it")
    )]
    pub(crate) fn seize(&mut self, pid: u32) {
        writeln!(self.go.as_mut().expect("the tracer is still driven"), "{pid}").expect("send the helper the pid");
        self.expect("seized");
    }

    /// Sends one go byte ([`STOP`], [`REAP`] or [`EXIT`]).
    pub(crate) fn send(&mut self, go_byte: u8) {
        self.go
            .as_mut()
            .expect("the tracer is still driven")
            .write_all(&[go_byte])
            .expect("send the helper a go byte");
    }

    /// Waits for the helper's `@@<expected>@@` line. Matches by suffix: the harness's
    /// `test <name> ... ` prefix may precede it.
    pub(crate) fn expect(&mut self, expected: &str) {
        let want = format!("@@{expected}@@");
        for line in &mut self.lines {
            if line.expect("read the helper's stdout").ends_with(&want) {
                return;
            }
        }
        panic!("the helper ended without reporting {expected:?}");
    }

    /// Closes the helper's stdin and waits for it to exit cleanly.
    pub(crate) fn finish(mut self) {
        drop(self.go.take());
        let status = self.helper.0.wait().expect("the helper exits");
        assert!(status.success(), "{status:?}");
    }
}

/// What [`await_blocked_or_finished`] found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Holder {
    /// Asleep in a `waitid` that waits.
    Blocked,
    Finished,
}

/// Re-reads `/proc/self/task/<tid>/syscall` until the thread sleeps in a `waitid` without
/// `WNOHANG`, or is gone. Both are conditions the thread reaches by itself, so the only exit is
/// the condition; the pauses between reads are a backoff, not a bound. Any other shape of the
/// file than `running` or `<nr> ...` panics with its text.
pub(crate) fn await_blocked_or_finished(tid: libc::pid_t) -> Holder {
    let path = format!("/proc/self/task/{tid}/syscall");
    let mut pause = std::time::Duration::from_micros(50);
    loop {
        match std::fs::read_to_string(&path) {
            Ok(text) if text.trim() == "running" => {}
            // `<nr> <a0> <a1> <a2> <a3> <a4> <a5> <sp> <pc>`, or `-1 <sp> <pc>`.
            Ok(text) => {
                let mut fields = text.split_whitespace();
                let nr: libc::c_long = fields
                    .next()
                    .and_then(|n| n.parse().ok())
                    .unwrap_or_else(|| panic!("{path}: no syscall number in {text:?}"));
                if nr == libc::SYS_waitid {
                    // `waitid(idtype, id, infop, options, rusage)`: `options` is argument 4.
                    let options = fields
                        .nth(3)
                        .and_then(|o| u64::from_str_radix(o.trim_start_matches("0x"), 16).ok())
                        .unwrap_or_else(|| panic!("{path}: no waitid options in {text:?}"));
                    if options & libc::WNOHANG as u64 == 0 {
                        return Holder::Blocked;
                    }
                }
            }
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => return Holder::Finished,
            Err(e) => panic!("read {path}: {e}"),
        }
        std::thread::sleep(pause);
        pause = (pause * 2).min(std::time::Duration::from_millis(5));
    }
}

/// Marks the [`tokio_tracee`] re-exec; the value is the driver's pid.
#[cfg(feature = "tokio")]
const TRACEE_MARKER: &str = "COSCA_TEST_FOREIGN_TRACER_TOKIO_TRACEE";

/// A tracee for a `cosca::tokio::Command`, which has no `pre_exec`: it calls
/// [`allow_any_tracer_now`], reports `allowed`, and reads stdin to EOF. A no-op unless it is the
/// re-exec [`spawn_tokio_tracee`] started.
#[cfg(feature = "tokio")]
#[skuld::test]
fn tokio_tracee() {
    let driver = std::env::var(TRACEE_MARKER).ok();
    if driver != Some(std::os::unix::process::parent_id().to_string()) {
        return;
    }
    allow_any_tracer_now().expect("allow any tracer");
    say("allowed");
    std::io::copy(&mut std::io::stdin(), &mut std::io::sink()).expect("read stdin to EOF");
}

/// A `cosca::tokio::Command` for [`tokio_tracee`], with no stdio set: its `allowed` report goes to
/// its stdout.
#[cfg(feature = "tokio")]
pub(crate) fn tokio_tracee_command() -> crate::tokio::Command {
    let mut cmd = crate::tokio::Command::new();
    cmd.executable(std::env::current_exe().expect("current_exe"))
        .args(crate::test_child::fixture_argv(fixture_path!(tokio_tracee)));
    crate::test_reexec::scrub_env(|var| _ = cmd.env_remove(var));
    cmd.env(TRACEE_MARKER, std::process::id().to_string());
    cmd
}

/// Spawns [`tokio_tracee`] as a kill-on-drop `cosca::tokio::Child` and returns it, with its stdin,
/// once [`spawn_helper`] may seize it.
#[cfg(feature = "tokio")]
pub(crate) async fn spawn_tokio_tracee() -> (crate::tokio::Child, crate::tokio::ChildStdin) {
    use ::tokio::io::AsyncBufReadExt as _;

    let mut cmd = tokio_tracee_command();
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    let mut child = cmd.spawn().expect("spawn the tracee");
    let stdin = child.stdin().expect("piped stdin");
    let mut lines = ::tokio::io::BufReader::new(child.stdout().expect("piped stdout")).lines();
    loop {
        let line = lines.next_line().await.expect("read the tracee's stdout");
        match line {
            Some(line) if line.ends_with("@@allowed@@") => return (child, stdin),
            Some(_) => {}
            None => panic!("the tracee ended without reporting \"allowed\""),
        }
    }
}
