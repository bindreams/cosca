//! macOS: a tokio child's signals go by pid only while the pid still has the unique id read at
//! spawn.

use crate::send_log::{Capture, Via};
use crate::tokio::Command;

/// A blocker that exited and was reaped by a foreign `waitpid`, behind tokio's back.
async fn foreign_reaped_blocker() -> crate::tokio::Child {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    let child = cmd.spawn().expect("spawn");
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
    child
}

/// A child reaped by a foreign `waitpid` has no unique id any more, so `kill` answers `Ok` and
/// sends nothing by pid. The log records an attempt before its syscall, so a mutant's `kill(2)`
/// still shows even though it fails with `ESRCH`.
///
/// Mutants: `kill` via tokio's `start_kill` (answers `Err(ESRCH)`); no identity check before the
/// by-pid send (the log shows `Via::Pid`).
#[tokio::test(flavor = "current_thread")]
async fn macos_tokio_kill_after_a_foreign_reap_sends_nothing() {
    let mut child = foreign_reaped_blocker().await;
    let log = Capture::start();
    child.kill().expect("a kill of a foreign-reaped child answers Ok");
    let sent_by_pid: Vec<_> = log
        .entries()
        .into_iter()
        .filter(|(_, _, via)| *via == Via::Pid)
        .collect();
    assert!(sent_by_pid.is_empty(), "nothing may be sent by pid: {sent_by_pid:?}");
}
