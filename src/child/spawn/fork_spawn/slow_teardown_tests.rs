//! A failed spawn, under the async policy's threshold, waits for the child it kills and warns once,
//! naming it, when the wait passes it (principle 2). A foreign tracer holds the killed child's zombie,
//! so the wait cannot end before the tracer lets go. The threshold is zero, so no look before the warn
//! blocks or pauses and the warn is out before the wait first does; the tracer lets go only then.
//!
//! The tracee ends only by a kill, or by its stdin closing. The teardown's thread drops the stdin
//! once the kill returned (`release_between_kill_and_wait`), so a kill that sent nothing leaves a
//! tracee that exits `0` into the tracer's hold, and the test fails on the status the teardown
//! reaped it as instead of hanging.
//!
//! The spawn's clone is a stand-in that hands over the tracee: its status channel is closed with no
//! record, so it died before exec.

use super::fork_spawn_tests::{hand_over, HANDED_OVER};
use super::{start_via, OnFailure, Program};
use crate::child::spawn::fault::release_between_kill_and_wait;
use crate::child::spawn::in_child::InChild;
use crate::child::spawn::policy::SpawnPolicy;
use crate::os_process::linux::fork::{NewChild, Path};
use crate::test_groups::{tracer_group, Group};
use crate::test_support::foreign_tracer::{
    self, assert_no_warn_before_the_threshold, assert_reaped_by_sigkill, assert_warns_once_before_blocking, Names,
};

/// What a teardown thread returns: the child's pid and the reaps its teardown recorded.
type Reaped = (u32, Vec<(u32, std::process::ExitStatus)>);

/// The two sides of the failed spawn of a child that died before exec: the teardown thread's, which
/// spawns (the stand-in hands over the tracee) and so kills the child and waits for its exit, and the
/// tracer's, which seizes the tracee once the thread has made it.
fn dead_child() -> (
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
            HANDED_OVER.with(|handed| {
                *handed.borrow_mut() = Some(NewChild {
                    pid: pid as i32,
                    pidfd: crate::containment::cgroup::test_support::pidfd_of(pid),
                    path: Path::Clone3,
                });
            });
            pid_tx.send(pid).expect("report the pid");
            seized_rx.recv().expect("the tracer seized the child");
            let program = Program::new(
                &[std::ffi::OsStr::new("/bin/true")],
                &[std::ffi::OsStr::new("true")],
                std::iter::empty(),
            )
            .expect("no NUL");
            let lock = crate::child::spawn::spawn_lock();
            let failed = start_via(
                hand_over,
                &program,
                &mut InChild::default(),
                crate::identity::spawn_kernel(crate::identity::HostKernel),
                OnFailure {
                    policy: SpawnPolicy {
                        teardown_warn_after: crate::tokio::slow_teardown_after(),
                        ..SpawnPolicy::SYNC
                    },
                    front: None,
                    placement: None,
                    refusing_placement: false,
                },
                &lock,
            );
            assert!(failed.is_err(), "a child that died before exec fails the spawn");
            drop(child);
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

/// A child that died before exec is torn down with the spawn's policy: its wait warns once, naming it.
///
/// Mutant: the teardown of a child that never ran is handed no threshold.
#[skuld::test]
fn a_child_that_died_before_exec_is_waited_for_with_a_warn(#[fixture(tracer_group)] _group: &Group) {
    let (teardown, seized) = dead_child();
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
    let (teardown, seized) = dead_child();
    let (pid, reaps) = assert_no_warn_before_the_threshold(std::time::Duration::from_secs(1), teardown, seized);
    assert_reaped_as(pid, &reaps);
}
