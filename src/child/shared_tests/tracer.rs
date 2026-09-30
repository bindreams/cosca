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
/// Mutant: a one-step consuming `waitid`, which returns `CLD_TRAPPED` and consumes it.
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

    // The stop is still there for the tracer.
    let mut status = 0;
    // SAFETY: `status` is a valid out-pointer.
    let reaped = unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };
    assert_eq!(reaped, pid);
    assert!(
        libc::WIFSTOPPED(status),
        "try_wait consumed the tracer's stop: {status:#x}"
    );

    // Clean-up: SIGKILL by kill(2), never PTRACE_KILL (which before v5.19 only resumes a
    // PTRACE_EVENT_STOP); `Blocker`'s drop then waits.
    b.shared.kill().expect("kill");
}

// macOS: a child this process traces itself =====
//
// macOS refuses `ptrace` attach with `EPERM` to an ad-hoc signed tracer unless the tracer carries
// `com.apple.security.cs.debugger`. So each case re-execs a copy of this test binary signed with
// it, in a fresh process (a tracer is per process, and `--test-threads=1` keeps the tracing
// thread the waiting thread).

#[cfg(target_os = "macos")]
mod macos {
    use std::io::Write as _;
    use std::time::Duration;

    use super::super::fixtures::Blocker;
    use crate::identity::{quiet_fault, ReadPurpose, Resolved};
    use crate::test_support::tracer::{attach_settled, AttachError};

    const MARKER: &str = "COSCA_TEST_SHARED_TRACER";

    /// Run `fixture` in a re-exec of a debugger-entitled copy of this binary.
    pub(super) fn run_signed(fixture: &str) {
        let dir = tempfile::tempdir().expect("tempdir");
        let exe = dir.path().join("cosca_unit_tests");
        std::fs::copy(std::env::current_exe().expect("current_exe"), &exe).expect("copy the test binary");
        let plist = dir.path().join("debugger.plist");
        std::fs::write(
            &plist,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.cs.debugger</key><true/></dict></plist>
"#,
        )
        .expect("write the entitlements");
        let signed = crate::test_spawn::output_captured(
            std::process::Command::new("codesign")
                .args(["--force", "--sign", "-", "--entitlements"])
                .arg(&plist)
                .arg(&exe),
        )
        .expect("run codesign");
        assert!(
            signed.status.success(),
            "codesign: {}",
            String::from_utf8_lossy(&signed.stderr)
        );

        let mut cmd = std::process::Command::new(&exe);
        cmd.args(["--test-threads=1", "--exact", fixture])
            .env(MARKER, std::process::id().to_string())
            .env("COSCA_FIXTURE_PARENT_PID", std::process::id().to_string())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let child = crate::test_spawn::spawn(&mut cmd).expect("spawn the signed fixture");
        let output = child.wait_with_output().expect("wait for the fixture");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("test result: ok. 1 passed;"),
            "fixture {fixture} failed ({:?}):\n{stdout}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
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
    /// The child is `cat`, which a stop can kill: a `cat` already blocked in `read` gets `EINTR`
    /// when it resumes, prints `Interrupted system call` and exits 1. So no fixture resumes it.
    /// They end it with [`kill_stopped`], whose `SIGKILL` cannot lose to that exit.
    fn attach_and_confirm_stop(blocker: &Blocker) {
        step("attach and settle");
        match attach_settled(blocker.shared.id()) {
            Ok(()) => {}
            Err(AttachError::Errno(e)) => panic!("attach: {}", std::io::Error::from_raw_os_error(e)),
            Err(AttachError::Exited) => panic!("the tracee exited before it stopped"),
        }
    }

    /// End a child stopped by [`attach_and_confirm_stop`]: `PT_KILL` sets `SRUN`, then `SIGKILL`
    /// through the handle wakes a thread asleep in `read()` (`PT_KILL`'s own `SIGKILL` is only
    /// posted to an `SSTOP` tracee, `kern_sig.c:2274`).
    fn kill_stopped(blocker: &Blocker) {
        // SAFETY: a plain ptrace request on this test's own child.
        unsafe {
            libc::ptrace(
                libc::PT_KILL,
                blocker.shared.id() as libc::pid_t,
                std::ptr::null_mut(),
                0,
            )
        };
        blocker.shared.kill().expect("kill");
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
        assert!(format!("{:?}", b.shared).contains("N"));
        kill_stopped(&b);
        assert_killed(b.shared.wait().expect("wait"));
    }

    /// A child this process traces is reaped fully: XNU needs two reaps, because the first only
    /// reparents the zombie to this same process (`kern_exit.c:2721-2773`), and the second peek
    /// consumes it.
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

    /// A failed start read in the second reap neither panics nor leaves the state `N`: the first
    /// reap's status is kept, and one `warn` names the pid.
    ///
    /// Mutant: the quiet reader implemented over `read_record`/`bsd_info`, whose
    /// `contract_violation` panics on the injected result.
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
        let _forced = quiet_fault::force_quiet_read_error_once(ReadPurpose::SecondPeek, Resolved::Unknown);
        kill_stopped(&b);
        assert_killed(b.shared.wait().expect("wait"));
        assert!(format!("{:?}", b.shared).contains("E("), "{:?}", b.shared);
        assert_eq!(crate::log_capture::levels_since(mark, &marker), vec![log::Level::Warn]);
    }
}
