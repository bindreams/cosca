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

/// The go bytes. `STOP` makes the helper stop the tracee and report it; `REAP` and `EXIT` hand the
/// zombie back.
pub(crate) const STOP: u8 = b's';
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
/// `STOP` interrupts the tracee and reports the stop, `REAP` reaps the zombie with `waitpid` and
/// reports, `EXIT` exits without reaping. A no-op unless it is the re-exec the driver started.
///
/// It seizes with no options, so no `PTRACE_O_TRACEEXIT`: the kill is not delayed by an exit stop,
/// and the pidfd turns readable at the zombie.
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
    let rc = unsafe { libc::ptrace(libc::PTRACE_SEIZE, pid, null(), null()) };
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
    let mut tracer = start_helper(Some(pid));
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
    start_helper(None)
}

fn start_helper(pid: Option<u32>) -> Tracer {
    let mut cmd = fixture_command(fixture_path!(foreign_tracer_helper));
    if let Some(pid) = pid {
        cmd.env(PID_ENV, pid.to_string());
    }
    cmd.env(MARKER, std::process::id().to_string())
        .env_remove("RUST_TEST_NOCAPTURE")
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit());
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
