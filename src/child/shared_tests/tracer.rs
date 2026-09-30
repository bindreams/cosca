//! `SharedChild` against a child this process traces (`TRACER` group; needs
//! `COSCA_TEST_TRACER_CONSENT=1`). Every fixture child is spawned under `spawn_lock`.
//!
//! Linux reports a ptrace stop to the tracer whatever the `waitid` options say
//! (`kernel/exit.c`, "Traditionally we see ptrace'd stopped tasks regardless of options"), as
//! `CLD_TRAPPED`, and a consuming `waitid` clears it. So a one-step reap of a child this process
//! traces would take the stop for an exit and steal the tracer's stop event.

#[cfg(target_os = "linux")]
use super::fixtures::Blocker;
#[cfg(target_os = "linux")]
use crate::test_support::require_group;

/// `try_wait` on a child stopped under this process's `PTRACE_SEIZE` returns `None` and leaves the
/// stop for the tracer: the test's own consuming `waitpid` then still gets it.
///
/// Mutants: a one-step consuming `waitid`, which returns `CLD_TRAPPED` and consumes it; and a peek
/// without `WNOWAIT` (`src/wait/exit_only/linux.rs`), which consumes the stop yet still returns
/// `None`. Both fail the final `waitpid` by assertion.
#[cfg(target_os = "linux")]
#[test]
fn try_wait_leaves_a_ptrace_stop_for_the_tracer() {
    if !require_group("TRACER") {
        return;
    }
    let b = Blocker::spawn();
    let pid = b.shared.id() as libc::pid_t;
    // SAFETY: plain ptrace requests on this test's own child, from the thread that waits below.
    unsafe {
        assert_eq!(
            libc::ptrace(libc::PTRACE_SEIZE, pid, 0, 0),
            0,
            "{}",
            std::io::Error::last_os_error()
        );
        assert_eq!(
            libc::ptrace(libc::PTRACE_INTERRUPT, pid, 0, 0),
            0,
            "{}",
            std::io::Error::last_os_error()
        );
    }
    // The stop, seen without consuming it.
    // SAFETY: an all-zero `siginfo_t` is valid and `waitid` writes only into it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WSTOPPED | libc::WNOWAIT | libc::__WALL,
        )
    };
    assert_eq!(r, 0, "waitid: {}", std::io::Error::last_os_error());

    assert_eq!(b.shared.try_wait().expect("try_wait"), None, "a stop is not an exit");

    // The stop is still there for the tracer. `WNOHANG`: the `WNOWAIT` peek above already saw it,
    // so a missing stop is an assertion failure here, never a wait that blocks forever.
    let mut status = 0;
    // SAFETY: `status` is a valid out-pointer.
    let reaped = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::__WALL) };
    assert_eq!(reaped, pid);
    assert!(
        libc::WIFSTOPPED(status),
        "try_wait consumed the tracer's stop: {status:#x}"
    );

    // Clean-up: SIGKILL through the handle (the pidfd), never PTRACE_KILL (which before v5.19 only resumes a
    // PTRACE_EVENT_STOP); `Blocker`'s drop then waits.
    b.shared.kill().expect("kill");
}

// macOS: a child this process traces itself =====
//
// macOS refuses `ptrace` attach with `EPERM` to an ad-hoc signed tracer unless the tracer carries
// `com.apple.security.cs.debugger`. So each case re-execs a copy of this test binary signed with
// it, in a fresh process: the tracer is the whole process, not a thread.

#[cfg(target_os = "macos")]
mod macos {
    use std::io::Write as _;
    use std::sync::mpsc::{channel, RecvTimeoutError};
    use std::sync::Arc;
    use std::time::Duration;

    use super::super::fixtures::{identity_of, Blocker};
    use crate::child::shared::{SharedChild, State};
    use crate::identity::{uniq_fault, ReadPurpose, UniqRead};
    use crate::test_support::tracer::{attach_settled, debugger_signed_copy, settled_stop, AttachError};
    use crate::wait::exit_only::Reaped;

    const MARKER: &str = "COSCA_TEST_SHARED_TRACER";

    /// The failure bound of the driver's wait for its fixture. The fixture aborts from its own
    /// [`BOUND`] watchdog well before, naming the step it hangs in, so this bound only ends a
    /// fixture that never got that far (and is shorter than nextest's own, in `.config`).
    const DRIVER_BOUND: Duration = Duration::from_secs(12);

    /// Run `fixture` in a re-exec of a debugger-entitled copy of this binary.
    pub(super) fn run_signed(fixture: &str) {
        let dir = tempfile::tempdir().expect("tempdir");
        let exe = debugger_signed_copy(dir.path());
        let mut cmd = std::process::Command::new(&exe);
        crate::test_child::configure_fixture_command(&mut cmd, fixture);
        cmd.env(MARKER, std::process::id().to_string());
        // As `run_fixture_output`: an inherited `RUST_TEST_NOCAPTURE` would turn libtest's output
        // capture off.
        cmd.env_remove("RUST_TEST_NOCAPTURE");
        let child = crate::test_spawn::spawn(&mut cmd).expect("spawn the signed fixture");
        match output_within(child, DRIVER_BOUND) {
            Ok(output) => crate::test_child::assert_fixture_passed(fixture, &output),
            Err(output) => panic!(
                "fixture {fixture} was still running after {DRIVER_BOUND:?}, so it was killed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        }
    }

    /// `child`'s output once it exits (`Ok`), or, if it is still running after `bound`, its
    /// output after it is killed and reaped (`Err`). `bound` is a failure bound on an external
    /// event, never a synchronisation: a fixture that passes exits long before it.
    fn output_within(
        mut child: std::process::Child,
        bound: Duration,
    ) -> Result<std::process::Output, std::process::Output> {
        fn drain(mut pipe: impl std::io::Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
            std::thread::spawn(move || {
                let mut bytes = Vec::new();
                _ = pipe.read_to_end(&mut bytes);
                bytes
            })
        }
        let stdout = drain(child.stdout.take().expect("piped stdout"));
        let stderr = drain(child.stderr.take().expect("piped stderr"));
        // Adopted so that the kill below is identity-checked: the waiting thread may reap at any
        // moment, and a bare pid could then name another process.
        let id = identity_of(&child);
        let shared = Arc::new(SharedChild::adopt(child, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}")));
        let (tx, rx) = channel();
        let waiter = {
            let shared = Arc::clone(&shared);
            // The receiver outlives the waiter: a failed send needs no handling.
            std::thread::spawn(move || _ = tx.send(shared.wait()))
        };
        let (status, in_time) = match rx.recv_timeout(bound) {
            Ok(status) => (status, true),
            Err(RecvTimeoutError::Timeout) => {
                shared.kill().expect("kill the hung fixture");
                (rx.recv().expect("the waiter ended without a result"), false)
            }
            Err(RecvTimeoutError::Disconnected) => panic!("the waiter ended without a result"),
        };
        waiter.join().expect("the waiter");
        let output = std::process::Output {
            status: status.expect("wait for the fixture"),
            stdout: stdout.join().expect("stdout reader"),
            stderr: stderr.join().expect("stderr reader"),
        };
        if in_time {
            Ok(output)
        } else {
            Err(output)
        }
    }

    /// The failure bound of a fixture that blocks on a traced child: if it is still running after
    /// `BOUND`, name the step it is in on the real stderr and abort, so the driver's assertion
    /// prints where it hung instead of the job timing out. Never a synchronisation: a passing
    /// fixture drops the guard long before.
    pub(super) struct Watchdog(
        #[allow(dead_code, reason = "dropping the sender ends the watchdog")] std::sync::mpsc::Sender<()>,
    );

    const BOUND: Duration = Duration::from_secs(8);

    pub(super) fn watchdog(name: &'static str) -> Watchdog {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            if rx.recv_timeout(BOUND) == Err(std::sync::mpsc::RecvTimeoutError::Timeout) {
                // Not `eprintln!`: libtest captures that, and the abort would lose it.
                _ = writeln!(
                    std::io::stderr(),
                    "WATCHDOG: {name} still running after {BOUND:?}; last step: {}",
                    step_name()
                );
                std::process::abort();
            }
        });
        Watchdog(tx)
    }

    static STEP: std::sync::Mutex<&'static str> = std::sync::Mutex::new("start");

    pub(super) fn step(name: &'static str) {
        _ = writeln!(std::io::stderr(), "step: {name}");
        *STEP.lock().unwrap_or_else(|e| e.into_inner()) = name;
    }

    fn step_name() -> &'static str {
        *STEP.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Attach to `blocker`'s child and wait, without consuming it, until its stop has settled: a
    /// request before the tracee's threads have parked wakes nothing ([`attach_settled`]).
    ///
    /// Fixtures end the child with [`kill_stopped`], never by resuming it: a `cat` blocked in
    /// `read` when it resumes gets `EINTR`, prints `Interrupted system call` and exits 1. And the
    /// attach is `PT_ATTACH`: under `PT_ATTACHEXC` the same `EINTR` kills a blocked `cat` before it
    /// ever stops, and no stop comes.
    fn attach_and_confirm_stop(blocker: &Blocker) {
        step("attach and settle");
        match attach_settled(blocker.shared.id()) {
            Ok(()) => {}
            Err(AttachError::Errno(e)) => panic!("attach: {}", std::io::Error::from_raw_os_error(e)),
            Err(AttachError::Exited { code, status }) => {
                panic!("the tracee exited before it stopped (si_code {code}, si_status {status})")
            }
        }
    }

    /// End a child stopped by [`attach_and_confirm_stop`]. `PT_KILL` does it: it posts `SIGKILL`
    /// and releases the stopped thread, which then delivers the pending `SIGKILL`
    /// (xnu-12377.121.6 `kern_sig.c:2794-2801`, "Necessary for PT_KILL"; `mach_process.c`
    /// `PT_KILL`, then `resume`).
    ///
    /// The handle's `kill` does not: a `SIGKILL` to a traced child is taken by its tracer as a
    /// stop, and posted only to one that already is stopped (`kern_sig.c:2275-2281`). A debugger
    /// delays a kill and cannot cancel it. So the child is asserted still stopped after `kill`,
    /// until `PT_KILL`.
    fn kill_stopped(blocker: &Blocker) {
        let pid = blocker.shared.id();
        blocker.shared.kill().expect("kill");
        let stopped = settled_stop(pid);
        assert!(
            matches!(stopped, Ok(Some(_))),
            "the handle's SIGKILL ended or released a traced child: {stopped:?}"
        );
        // SAFETY: a plain ptrace request on this test's own child.
        let rc = unsafe { libc::ptrace(libc::PT_KILL, pid as libc::pid_t, std::ptr::null_mut(), 0) };
        assert_eq!(rc, 0, "PT_KILL: {}", std::io::Error::last_os_error());
    }

    fn assert_killed(status: std::process::ExitStatus) {
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGKILL),
            "{status:?}"
        );
    }

    /// `try_wait` on a child stopped under this process's own `PT_ATTACH` returns `None` and
    /// leaves the state `N`.
    ///
    /// Mutant: a `waitpid(WNOHANG)` reap returns the stop as a status and writes `E`.
    #[test]
    fn try_wait_on_a_child_this_process_traces_returns_none_while_it_is_stopped() {
        if !crate::test_support::require_group("TRACER") {
            return;
        }
        if !crate::test_child::is_marked_fixture_reexec(MARKER) {
            return run_signed(crate::test_child::fixture_path!(
                try_wait_on_a_child_this_process_traces_returns_none_while_it_is_stopped
            ));
        }
        let _dog = watchdog("try_wait on a stopped tracee");
        step("spawn");
        let b = Blocker::spawn();
        attach_and_confirm_stop(&b);
        step("try_wait");
        assert_eq!(b.shared.try_wait().expect("try_wait"), None, "a stop is not an exit");
        assert!(matches!(b.shared.lock().state, State::N));
        kill_stopped(&b);
        assert_killed(b.shared.wait().expect("wait"));
    }

    /// A child this process traces is reaped fully: XNU needs two reaps, because the first only
    /// hands the zombie back to this same process (`reap_child_locked`, xnu-12377.121.6
    /// `kern_exit.c:2863-2915`), and the second peek consumes it.
    ///
    /// Mutant: one consuming reap leaves the zombie, which the final peek still finds.
    #[test]
    fn a_child_this_process_traces_is_reaped_fully() {
        if !crate::test_support::require_group("TRACER") {
            return;
        }
        if !crate::test_child::is_marked_fixture_reexec(MARKER) {
            return run_signed(crate::test_child::fixture_path!(
                a_child_this_process_traces_is_reaped_fully
            ));
        }
        let _dog = watchdog("reaped fully");
        step("spawn");
        let b = Blocker::spawn();
        attach_and_confirm_stop(&b);
        kill_stopped(&b);
        step("wait");
        assert_killed(b.shared.wait().expect("wait"));
        // SAFETY: an all-zero `siginfo_t` is valid, and `waitid` writes only into it.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::waitid(
                libc::P_PID,
                b.shared.id() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        assert_eq!(r, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
    }

    /// A refused identity read in the second reap neither panics nor leaves the state `N`: the
    /// first reap's status is kept, and one `warn` names the pid.
    ///
    /// Mutant: a second reap that panics on a refused identity read.
    #[test]
    fn a_failed_start_read_in_the_second_reap_neither_panics_nor_leaves_n() {
        if !crate::test_support::require_group("TRACER") {
            return;
        }
        if !crate::test_child::is_marked_fixture_reexec(MARKER) {
            return run_signed(crate::test_child::fixture_path!(
                a_failed_start_read_in_the_second_reap_neither_panics_nor_leaves_n
            ));
        }
        crate::log_capture::install();
        let _dog = watchdog("failed start read");
        step("spawn");
        let b = Blocker::spawn();
        attach_and_confirm_stop(&b);
        let marker = format!("second reap of pid {}", b.shared.id());
        let mark = crate::log_capture::mark();
        let _forced = uniq_fault::force_uniq_read_once(ReadPurpose::SecondPeek, UniqRead::Refused(libc::EPERM));
        kill_stopped(&b);
        assert_killed(b.shared.wait().expect("wait"));
        assert!(
            matches!(b.shared.lock().state, State::E(Reaped::Status(_))),
            "the first reap's status is cached"
        );
        assert_eq!(crate::log_capture::levels_since(mark, &marker), vec![log::Level::Warn]);
    }
}
