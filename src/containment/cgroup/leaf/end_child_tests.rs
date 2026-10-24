//! `end_child`'s final reap of an abandoned spawn's child that something else reaped first. The
//! child is a forked process that pauses, and no cgroup is used; the group is the cgroup lane's
//! because `end_child` also signals the child's process group.

use super::super::test_support::fork_running;
use super::{end_child, ChildFate, Received};
use crate::test_groups::{cgroup, Group};

/// The child is killed through its pidfd, then reaped by the test before `end_child`'s final wait,
/// which answers `ECHILD`: a foreign reap, logged at `debug`, and the fate stays `Killed`.
///
/// Mutant: the `debug_assert!` on the failed reap kept (a debug panic), or its `warn`.
#[skuld::test]
fn an_abandoned_childs_foreign_reap_is_debug_not_a_panic(#[fixture(cgroup)] _group: &Group) {
    crate::log_capture::install();
    let child = fork_running(|| loop {
        // SAFETY: async-signal-safe.
        unsafe { libc::pause() };
    });
    let pidfd = rustix::process::pidfd_open(
        rustix::process::Pid::from_raw(child.pid() as i32).expect("a positive pid"),
        rustix::process::PidfdFlags::empty(),
    )
    .expect("pidfd_open the child");
    let pid = child.defuse();
    let received = Received {
        report: None,
        pid: Some(pid),
        pidfd: Some(pidfd),
        proc_dir: None,
    };
    // `end_child` has already sent its `SIGKILL`.
    let _reaped_elsewhere =
        crate::containment::cgroup::fault::set_before_exit_wait(move || super::super::test_support::reap(pid));

    let mark = crate::log_capture::mark();
    let fate = end_child(&received);

    assert_eq!(fate, ChildFate::Killed);
    let records = crate::log_capture::records_since_on_current_thread(mark, "reaped elsewhere");
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].0, log::Level::Debug, "{records:?}");
    assert!(
        records[0].1.contains(&pid.to_string()),
        "it names the child: {records:?}"
    );
    let warns: Vec<_> = crate::log_capture::records_since_on_current_thread(mark, "")
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .collect();
    assert_eq!(warns, [], "a foreign reap is not a warning");
}
