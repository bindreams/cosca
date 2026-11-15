//! A failed spawn's handshake, under the async policy's threshold, waits for the child it kills and
//! warns once, naming it, when the wait passes it (principle 2). A foreign tracer holds the killed
//! child's zombie, so the wait cannot end before the tracer lets go. The threshold is zero, so no
//! look before the warn blocks or pauses and the warn is out before the wait first does; the
//! tracer lets go only then.
//!
//! The tracee ends only by a kill, or by its stdin closing. The teardown's thread drops the stdin
//! once the kill returned (`release_between_kill_and_wait`), so a kill that sent nothing leaves a
//! tracee that exits `0` into the tracer's hold, and the test fails on the status the teardown
//! reaped it as instead of hanging.

use std::os::fd::OwnedFd;

use super::{conclude, Outcome};
use crate::child::spawn::fault::release_between_kill_and_wait;
use crate::error::Error;
use crate::test_groups::{tracer_group, Group};
use crate::test_support::foreign_tracer::{
    self, assert_no_warn_before_the_threshold, assert_reaped_by_sigkill, assert_warns_once_after_seizing,
    assert_warns_once_before_blocking, Names,
};

/// The pidfd of `child`, which the handshake would have held.
fn pidfd_of(child: &std::process::Child) -> OwnedFd {
    crate::containment::cgroup::test_support::pidfd_of(child.id())
}

/// `conclude` of a spawn that failed (`Err`) with `outcome(pidfd)`, for the tracee `child`, which a
/// foreign tracer holds once killed: as [`assert_warns_once_after_seizing`], the warn naming no pid.
fn assert_failed_spawn_warns_once(outcome: fn(OwnedFd) -> Outcome) {
    let mut child = foreign_tracer::blocker();
    let pid = child.id();
    let pidfd = pidfd_of(&child);
    let stdin = child.stdin.take().expect("piped stdin");
    let reaps = assert_warns_once_after_seizing(Names::Unknown, pid, move || {
        let blocker = release_between_kill_and_wait(stdin);
        let warn_after = crate::tokio::slow_teardown_after();
        let spawned = Err::<std::process::Child, _>(std::io::Error::other("spawn failed"));
        let failed = conclude(
            spawned,
            outcome(pidfd),
            crate::identity::spawn_kernel(crate::identity::HostKernel),
            warn_after,
        );
        assert!(failed.is_err(), "the failed spawn fails");
        blocker.recorded()
    });
    assert_reaped_by_sigkill(&reaps);
    drop(child);
}

/// The child was told to go, and the spawn failed after: it is torn down through its pidfd.
///
/// Mutant: `conclude`'s teardown through the pidfd waits with no warn.
#[skuld::test]
fn a_child_a_failed_spawn_was_told_to_go_is_torn_down_with_a_warn(#[fixture(tracer_group)] _group: &Group) {
    assert_failed_spawn_warns_once(Outcome::Opened);
}

/// Every copy of its end closed before it was told to go: it never ran the program, and the failed
/// spawn tears it down through its pidfd.
///
/// Mutant: this arm tears down with a call of its own that has no warn.
#[skuld::test]
fn a_child_that_died_before_exec_in_a_failed_spawn_is_torn_down_with_a_warn(#[fixture(tracer_group)] _group: &Group) {
    assert_failed_spawn_warns_once(Outcome::Gone);
}

/// The helper failed the spawn but the child sent its pidfd: it is torn down through it.
///
/// Mutant: this arm tears down with a call of its own that has no warn.
#[skuld::test]
fn a_child_whose_spawn_the_helper_failed_is_torn_down_with_a_warn(#[fixture(tracer_group)] _group: &Group) {
    assert_failed_spawn_warns_once(|pidfd| {
        Outcome::Failed(Error::Io(std::io::Error::other("the helper failed")), Some(pidfd))
    });
}

/// What a teardown thread returns: the child's pid and the reaps its teardown recorded.
type Reaped = (u32, Vec<(u32, std::process::ExitStatus)>);

/// The two sides of `conclude` of a spawn that returned a child that never ran the program (it was
/// not told to go), with `outcome(pidfd)`: the teardown thread's, which kills the child and waits
/// for its exit, and the tracer's, which seizes it once the thread has made it.
fn unexecuted_child(
    outcome: fn(OwnedFd) -> Outcome,
) -> (
    impl FnOnce() -> Reaped + Send,
    impl FnOnce() -> (u32, foreign_tracer::Tracer),
) {
    let (pid_tx, pid_rx) = std::sync::mpsc::channel();
    let (seized_tx, seized_rx) = std::sync::mpsc::channel();
    (
        move || {
            let mut child = foreign_tracer::blocker();
            let blocker = release_between_kill_and_wait(child.stdin.take().expect("piped stdin"));
            let pid = child.id();
            let pidfd = pidfd_of(&child);
            pid_tx.send(pid).expect("report the pid");
            seized_rx.recv().expect("the tracer seized the child");
            let warn_after = crate::tokio::slow_teardown_after();
            let failed = conclude(
                Ok(child),
                outcome(pidfd),
                crate::identity::spawn_kernel(crate::identity::HostKernel),
                warn_after,
            );
            assert!(failed.is_err(), "the failed spawn fails");
            (pid, blocker.recorded())
        },
        move || {
            let pid = pid_rx.recv().expect("the tracee's pid");
            let tracer = foreign_tracer::spawn_helper(pid);
            seized_tx.send(()).expect("let the teardown go on");
            (pid, tracer)
        },
    )
}

/// The reap is recorded as the child's, by a `SIGKILL`.
fn assert_reaped_as(pid: u32, reaps: &[(u32, std::process::ExitStatus)]) {
    assert_reaped_by_sigkill(reaps);
    let reaped: Vec<u32> = reaps.iter().map(|(pid, _)| *pid).collect();
    assert_eq!(reaped, [pid], "the reap is recorded as the child's");
}

/// [`unexecuted_child`] under [`assert_warns_once_before_blocking`].
fn assert_unexecuted_child_warns_once(outcome: fn(OwnedFd) -> Outcome) {
    let (teardown, seized) = unexecuted_child(outcome);
    let (pid, reaps) = assert_warns_once_before_blocking(Names::Pid, teardown, seized);
    assert_reaped_as(pid, &reaps);
}

/// A teardown whose wait the tracer's letting go ends before its threshold passes, on a clock no
/// one advances, says no warn: the threshold is honoured, not due at once.
///
/// Mutants: `Due::in_` is due now; `wait_to_exit` warns whatever its bounded wait found.
#[skuld::test]
fn a_child_a_tracer_lets_go_of_before_the_threshold_is_waited_for_without_a_warn(
    #[fixture(tracer_group)] _group: &Group,
) {
    let (teardown, seized) = unexecuted_child(Outcome::Gone);
    let (pid, reaps) = assert_no_warn_before_the_threshold(std::time::Duration::from_secs(1), teardown, seized);
    assert_reaped_as(pid, &reaps);
}

/// Every copy of its end closed before it was told to go.
///
/// Mutant: that wait has no warn.
#[skuld::test]
fn a_child_that_never_ran_is_waited_for_with_a_warn(#[fixture(tracer_group)] _group: &Group) {
    assert_unexecuted_child_warns_once(Outcome::Gone);
}

/// The helper failed the spawn, and the child sent its pidfd.
///
/// Mutant: this arm hands `reap_unexecuted` no threshold.
#[skuld::test]
fn a_child_whose_spawn_the_helper_failed_is_waited_for_with_a_warn(#[fixture(tracer_group)] _group: &Group) {
    assert_unexecuted_child_warns_once(|pidfd| {
        Outcome::Failed(Error::Io(std::io::Error::other("the helper failed")), Some(pidfd))
    });
}
