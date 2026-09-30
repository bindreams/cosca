//! macOS: `kill` after a foreign reap sends nothing by pid.

use crate::send_log::{Capture, Via};
use crate::tokio::Command;

/// A child reaped by a foreign `waitpid` is no longer ours to signal by number: `kill` peeks first
/// and finds the reap, so it answers `Ok` and sends nothing. The log records an attempt before the
/// syscall, so a mutant's `kill(2)` (which fails with `ESRCH`) still shows.
///
/// Mutant: no pre-send peek.
#[tokio::test(flavor = "current_thread")]
async fn macos_tokio_kill_after_a_foreign_reap_sends_nothing() {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    let mut child = cmd.spawn().expect("spawn");
    let pid = child.id().pid();
    drop(writer);

    // SAFETY: an all-zero `siginfo_t` is valid, and `waitid` writes only into it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: waits for our own child's exit without consuming it.
    let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) };
    assert_eq!(rc, 0, "waitid: {}", std::io::Error::last_os_error());
    let mut status = 0;
    // SAFETY: reaps our own exited child behind tokio's back.
    let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    assert_eq!(
        reaped,
        pid as libc::pid_t,
        "waitpid: {}",
        std::io::Error::last_os_error()
    );

    let log = Capture::start();
    child.kill().expect("a kill of a foreign-reaped child answers Ok");
    let sent_by_pid: Vec<_> = log
        .entries()
        .into_iter()
        .filter(|(_, _, via)| *via == Via::Pid)
        .collect();
    assert!(sent_by_pid.is_empty(), "nothing may be sent by pid: {sent_by_pid:?}");
}

/// The send log records an attempt before the syscall, so a `kill(2)` answering `ESRCH` still
/// shows. A forced `Running` peek stands in for the pre-send peek finding the child alive, so the
/// send goes to a freed pid: that is real system state, so the test runs in the `STALE_PID_SEND`
/// group (CI, with consent) and nowhere else.
///
/// Mutant: macOS records only after a successful `kill(2)`.
#[tokio::test(flavor = "current_thread")]
async fn macos_tokio_kill_records_the_attempt_before_the_syscall() {
    if !crate::test_support::require_group("STALE_PID_SEND") {
        return;
    }
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    let mut child = cmd.spawn().expect("spawn");
    let pid = child.id().pid();
    drop(writer);

    // SAFETY: an all-zero `siginfo_t` is valid, and `waitid` writes only into it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: waits for our own child's exit without consuming it.
    let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) };
    assert_eq!(rc, 0, "waitid: {}", std::io::Error::last_os_error());
    let mut status = 0;
    // SAFETY: reaps our own exited child behind tokio's back.
    let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    assert_eq!(
        reaped,
        pid as libc::pid_t,
        "waitpid: {}",
        std::io::Error::last_os_error()
    );

    let log = Capture::start();
    let _forced = crate::wait::exit_only::seams::force_peek_once(Ok(crate::wait::exit_only::Peek::Running));
    child.kill().expect("a kill answering ESRCH is Ok");
    assert_eq!(log.entries(), vec![(pid, crate::signal::Sig::Kill, Via::Pid)]);
}
