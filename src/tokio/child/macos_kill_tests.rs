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

/// A child of the test that has exited and is not reaped: a stand-in for a pid reused by a child
/// of our own, which a wait by number would take for ours.
fn exited_unreaped_stranger() -> std::process::Child {
    let stranger = crate::test_spawn::spawn(&mut std::process::Command::new("true")).expect("spawn");
    crate::tokio::child::child_reap_tests::wait_exited_unreaped(stranger.id());
    stranger
}

/// A cosca child, reaped behind tokio's back by a foreign `waitpid`.
fn foreign_reaped() -> (crate::tokio::Child, u32) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    let child = cmd.spawn().expect("spawn");
    let pid = child.id().pid();
    drop(writer);
    crate::tokio::child::child_reap_tests::wait_exited_unreaped(pid);
    let mut status = 0;
    // SAFETY: reaps our own exited child behind tokio's back.
    assert_eq!(
        unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) },
        pid as libc::pid_t
    );
    (child, pid)
}

/// A foreign reap seen once stays seen. A forced `Running` peek stands in for the pid being reused
/// by a child of our own: the latch, not the peek, keeps a signal from touching the pid, and the
/// pid of a real, exited stranger keeps `wait_and_reap` from waiting on it.
///
/// Mutant: no latch (the forced `Running` lets `kill(2)` through, and the log records `Via::Pid`;
/// `wait_and_reap` reaches the stranger and answers `Exited`).
#[tokio::test(flavor = "current_thread")]
async fn macos_tokio_foreign_latch_is_sticky() {
    use crate::signal::Sig;
    use crate::wait::exit_only::seams::force_peek_once;
    use crate::wait::exit_only::Peek;

    let (mut child, _pid) = foreign_reaped();
    let mut stranger = exited_unreaped_stranger();

    // Not `Child::kill`, which would forget the child and leave no latch to test.
    child
        .proc_mut()
        .signal(Sig::Kill)
        .expect("the first signal sees the foreign reap and sets the latch");

    let log = Capture::start();
    {
        let _reuse = force_peek_once(Ok(Peek::Running));
        child.proc_mut().signal(Sig::Kill).expect("a latched signal answers Ok");
    }
    {
        let _reuse = force_peek_once(Ok(Peek::Running));
        assert_eq!(child.proc_mut().wait_and_reap(stranger.id()), super::Waited::Foreign);
    }
    {
        let _reuse = force_peek_once(Ok(Peek::Running));
        drop(child);
    }
    let sent_by_pid: Vec<_> = log
        .entries()
        .into_iter()
        .filter(|(_, _, via)| *via == Via::Pid)
        .collect();
    assert!(sent_by_pid.is_empty(), "nothing may be sent by pid: {sent_by_pid:?}");
    stranger.wait().expect("reap the stranger");
}

/// A `kill(2)` that answers `ESRCH` after a peek that found our child means someone reaped it in
/// between: that is a detected foreign reap, and it latches. The send goes to a freed pid, which is
/// real system state, so the test runs in the `STALE_PID_SEND` group.
///
/// Mutant: `ESRCH` does not set the latch.
#[tokio::test(flavor = "current_thread")]
async fn macos_tokio_kill_answering_esrch_sets_the_latch() {
    use crate::signal::Sig;
    use crate::wait::exit_only::seams::force_peek_once;
    use crate::wait::exit_only::Peek;

    if !crate::test_support::require_group("STALE_PID_SEND") {
        return;
    }
    let (mut child, _pid) = foreign_reaped();
    let mut stranger = exited_unreaped_stranger();

    {
        let _reuse = force_peek_once(Ok(Peek::Running));
        child.proc_mut().signal(Sig::Kill).expect("an ESRCH kill answers Ok");
    }

    assert_eq!(child.proc_mut().wait_and_reap(stranger.id()), super::Waited::Foreign);
    stranger.wait().expect("reap the stranger");
}

/// `try_wait` and `wait` on a child whose foreign reap was seen do not reach tokio's wait by pid:
/// the pid may be another child's now. They forget the child and answer `ECHILD`.
///
/// Mutant: `try_wait`/`wait` ignore the latch.
#[tokio::test(flavor = "current_thread")]
async fn macos_tokio_waits_after_a_latched_foreign_reap_answer_echild() {
    use crate::signal::Sig;

    for use_try_wait in [true, false] {
        let (mut child, _pid) = foreign_reaped();
        child.proc_mut().signal(Sig::Kill).expect("latches");
        assert!(
            !child.proc_mut().is_reaped(),
            "the signal alone must not forget the child"
        );

        let answer = if use_try_wait {
            child.try_wait().map(|_| ())
        } else {
            child.wait().await.map(|_| ())
        };

        let echild = matches!(&answer, Err(crate::error::Error::Io(e)) if e.raw_os_error() == Some(libc::ECHILD));
        assert!(echild, "try_wait={use_try_wait}: {answer:?}");
        assert!(child.proc_mut().is_reaped(), "the wait must forget the child");
    }
}
