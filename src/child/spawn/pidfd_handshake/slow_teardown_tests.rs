//! A failed async spawn's handshake waits for the child it kills, and warns once, naming it, when
//! the wait passes 1 s (principle 2). A foreign tracer holds the killed child's zombie, so the wait
//! cannot end before the tracer lets go; it lets go only once the teardown's thread sleeps in a
//! blocking `waitid`, which the teardown reaches only after the warn.
//!
//! The tracee ends only by a kill, or by its stdin closing. The teardown's thread drops the stdin
//! once the kill returned (`release_between_kill_and_wait`), so a kill that sent nothing leaves a
//! tracee that exits `0` into the tracer's hold, and the test fails on the status the teardown
//! reaped it as instead of hanging.

use std::os::fd::OwnedFd;

use super::{conclude, LeftFront, Outcome};
use crate::child::spawn::fault::release_between_kill_and_wait;
use crate::error::Error;
use crate::test_groups::{tracer_group, Group};
use crate::test_support::foreign_tracer::{
    self, assert_reaped_by_sigkill, assert_warns_once_after_seizing, assert_warns_once_before_blocking, Names,
};

/// The pidfd of `child`, which the handshake would have held.
fn pidfd_of(child: &std::process::Child) -> OwnedFd {
    crate::containment::cgroup::test_support::pidfd_of(child.id())
}

/// `conclude` of a spawn that failed (`Err`) with `outcome(pidfd)` and `left` of its front, for the
/// tracee `child`, which a foreign tracer holds once killed: as [`assert_warns_once_after_seizing`],
/// the warn naming no pid.
fn assert_failed_spawn_warns_once_with(
    mut child: std::process::Child,
    outcome: fn(OwnedFd) -> Outcome,
    left: fn() -> LeftFront,
) {
    let pid = child.id();
    let pidfd = pidfd_of(&child);
    let stdin = child.stdin.take().expect("piped stdin");
    let reaps = assert_warns_once_after_seizing(Names::Unknown, pid, move || {
        let blocker = release_between_kill_and_wait(stdin);
        let warn_after = crate::tokio::slow_teardown_after();
        let spawned = Err::<::tokio::process::Child, _>(std::io::Error::other("tokio failed"));
        let failed = conclude(spawned, outcome(pidfd), left(), warn_after);
        assert!(failed.is_err(), "the failed spawn fails");
        blocker.recorded()
    });
    assert_reaped_by_sigkill(&reaps);
    drop(child);
}

/// [`assert_failed_spawn_warns_once_with`] for a child that is not a front.
fn assert_failed_spawn_warns_once(outcome: fn(OwnedFd) -> Outcome) {
    assert_failed_spawn_warns_once_with(foreign_tracer::blocker(), outcome, || LeftFront::NotAFront);
}

/// The child was told to go, and tokio's spawn failed after: it is torn down through its pidfd.
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

/// `conclude` of a spawn whose tokio child never ran the program (it was not told to go), with
/// `outcome(pidfd)`: the handshake kills it and waits for its exit (`await_unexecuted_exit`) before
/// tokio reaps it. As [`assert_warns_once_before_blocking`], and the reap is recorded as the child's.
fn assert_unexecuted_tokio_child_warns_once(outcome: fn(OwnedFd) -> Outcome) {
    let (pid_tx, pid_rx) = std::sync::mpsc::channel();
    let (seized_tx, seized_rx) = std::sync::mpsc::channel();
    let (pid, reaps) = assert_warns_once_before_blocking(
        Names::Pid,
        move || {
            let rt = ::tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let _rt = rt.enter();
            let mut cmd = ::tokio::process::Command::new(crate::test_child::BLOCKER_ARGV[0]);
            cmd.args(&crate::test_child::BLOCKER_ARGV[1..])
                .stdin(std::process::Stdio::piped());
            foreign_tracer::allow_any_tracer(cmd.as_std_mut());
            let mut child = crate::test_spawn::spawn_tokio(&mut cmd).expect("spawn the tracee");
            let blocker = release_between_kill_and_wait(child.stdin.take().expect("piped stdin"));
            let pid = child.id().expect("a pid");
            let pidfd = crate::containment::cgroup::test_support::pidfd_of(pid);
            pid_tx.send(pid).expect("report the pid");
            seized_rx.recv().expect("the tracer seized the child");
            let warn_after = crate::tokio::slow_teardown_after();
            let failed = conclude(Ok(child), outcome(pidfd), LeftFront::NotAFront, warn_after);
            assert!(failed.is_err(), "the failed spawn fails");
            (pid, blocker.recorded())
        },
        move || {
            let pid = pid_rx.recv().expect("the tracee's pid");
            let tracer = foreign_tracer::spawn_helper(pid);
            seized_tx.send(()).expect("let the teardown go on");
            (pid, tracer)
        },
    );
    assert_reaped_by_sigkill(&reaps);
    let reaped: Vec<u32> = reaps.iter().map(|(pid, _)| *pid).collect();
    assert_eq!(reaped, [pid], "the reap is recorded as the tokio child's");
}

/// Every copy of its end closed before it was told to go.
///
/// Mutant: that wait has no warn.
#[skuld::test]
fn a_tokio_child_that_never_ran_is_waited_for_with_a_warn(#[fixture(tracer_group)] _group: &Group) {
    assert_unexecuted_tokio_child_warns_once(Outcome::Gone);
}

/// The helper failed the spawn, and the child sent its pidfd.
///
/// Mutant: this arm hands `reap_unexecuted` no threshold.
#[skuld::test]
fn a_tokio_child_whose_spawn_the_helper_failed_is_waited_for_with_a_warn(#[fixture(tracer_group)] _group: &Group) {
    assert_unexecuted_tokio_child_warns_once(|pidfd| {
        Outcome::Failed(Error::Io(std::io::Error::other("the helper failed")), Some(pidfd))
    });
}

/// The child is the root of a group that is its containment: the group is killed through the pidfd,
/// then the root is torn down through it, and that wait warns.
///
/// Mutant: `conclude`'s `GroupRoot` arm hands its teardown no threshold.
#[skuld::test]
fn a_group_root_a_failed_spawn_was_told_to_go_is_torn_down_with_a_warn(#[fixture(tracer_group)] _group: &Group) {
    assert_failed_spawn_warns_once_with(foreign_tracer::group_leading_blocker(), Outcome::Opened, || {
        LeftFront::GroupRoot
    });
}

/// The child's pidfd is copied for its cgroup leaf's abandonment, and the child is torn down
/// through the original, whose wait warns.
///
/// Mutant: `conclude`'s `LeafHeld` arm tears down with a call that has no threshold.
#[skuld::test]
fn a_child_a_leaf_holds_a_copy_of_is_torn_down_with_a_warn(#[fixture(tracer_group)] _group: &Group) {
    assert_failed_spawn_warns_once_with(foreign_tracer::blocker(), Outcome::Opened, || {
        LeftFront::LeafHeld(std::rc::Rc::default())
    });
}
