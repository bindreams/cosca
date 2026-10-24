//! `end_child`, called directly on an abandoned spawn's child: a forked process that pauses, with
//! no cgroup. What it sends is read from `fault::take_child_sends`.

use super::super::fault::{self, ChildSend};
use super::super::test_support::{fork_running, KillOnDrop};
use super::{end_child, ChildFate, PlacementReport, Received};
use crate::test_groups::{cgroup, Group};

/// A forked child that pauses until killed, leading its own process group, as a spawned child
/// does. Its group is set from this side too, so it is in place before this returns.
fn paused_group_leader() -> KillOnDrop {
    let child = fork_running(|| {
        // SAFETY: async-signal-safe.
        unsafe { libc::setpgid(0, 0) };
        loop {
            // SAFETY: async-signal-safe.
            unsafe { libc::pause() };
        }
    });
    // SAFETY: plain syscall on this process's own unexec'd child.
    let set = unsafe { libc::setpgid(child.pid() as i32, child.pid() as i32) };
    assert_eq!(set, 0, "setpgid: {}", std::io::Error::last_os_error());
    child
}

/// What `end_child` receives for `child`, named by its pidfd, after `report`. `end_child` reaps
/// it from here on.
fn received(child: KillOnDrop, report: Option<PlacementReport>) -> Received {
    let pidfd = super::super::test_support::pidfd_of(child.pid());
    Received {
        report,
        pid: Some(child.defuse()),
        pidfd: Some(pidfd),
        proc_dir: None,
    }
}

/// The child is killed through its pidfd, then reaped by the test before `end_child`'s final wait,
/// which answers `ECHILD`: a foreign reap, logged at `debug`, and the fate stays `Killed`.
///
/// Mutant: the `debug_assert!` on the failed reap kept (a debug panic), or its `warn`.
#[skuld::test]
fn an_abandoned_childs_foreign_reap_is_debug_not_a_panic() {
    crate::log_capture::install();
    let child = fork_running(|| loop {
        // SAFETY: async-signal-safe.
        unsafe { libc::pause() };
    });
    let received = received(child, None);
    let pid = received.pid.expect("a pid");
    // `end_child` has already sent its `SIGKILL`.
    let _reaped_elsewhere = fault::set_before_exit_wait(move || super::super::test_support::reap(pid));

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

/// A child that reported a failed placement exec'd outside its leaf, so what it forks is reachable
/// only as its process group. That group is killed while the child is still unreaped, before the
/// kill through its handle, which ends it and so frees its number for a foreign reaper.
///
/// Mutant: the group killed after the handle's kill (`[Handle, Group]`).
#[skuld::test]
fn an_abandoned_child_outside_its_leaf_is_killed_as_its_group_before_its_handle(#[fixture(cgroup)] _group: &Group) {
    let child = paused_group_leader();
    let received = received(child, Some(PlacementReport::WriteFailed(libc::EBADF)));

    assert_eq!(end_child(&received), ChildFate::Killed);
    assert_eq!(fault::take_child_sends(), [ChildSend::Group, ChildSend::Handle]);
}

/// A child that entered its leaf is killed with the leaf, and one that never reported never
/// exec'd: neither has anything only its group reaches, so neither is sent a kill by number.
///
/// Mutant: the group kill sent for every child (`[Handle, Group]`).
#[skuld::test]
fn an_abandoned_child_in_its_leaf_or_unreported_is_sent_no_group_kill() {
    for report in [Some(PlacementReport::Placed), None] {
        let child = paused_group_leader();
        let received = received(child, report);

        assert_eq!(end_child(&received), ChildFate::Killed, "{report:?}");
        assert_eq!(fault::take_child_sends(), [ChildSend::Handle], "{report:?}");
    }
}

/// A group kill that finds no group (`ESRCH`, forced here) is logged at `debug`, and the child is
/// still killed through its handle.
///
/// Mutant: the group kill's result discarded (no record).
#[skuld::test]
fn an_abandoned_childs_group_kill_finding_no_group_is_logged_at_debug(#[fixture(cgroup)] _group: &Group) {
    crate::log_capture::install();
    let child = paused_group_leader();
    let received = received(child, Some(PlacementReport::WriteFailed(libc::EBADF)));
    let pid = received.pid.expect("a pid");
    fault::set_force_group_kill_gone(true);

    let mark = crate::log_capture::mark();
    assert_eq!(end_child(&received), ChildFate::Killed);

    let records = crate::log_capture::records_since_on_current_thread(mark, "process group");
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].0, log::Level::Debug, "{records:?}");
    assert!(records[0].1.contains(&pid.to_string()), "{records:?}");
}

/// A kill its handle refuses (`EPERM`, forced here, as from a setuid child) is not retried by the
/// child's bare pid: the child is out of reach, and reaped once it exits.
///
/// Mutant: the by-pid fallback on `EPERM` (`[Handle, Pid]`, fate `Killed`).
#[skuld::test]
fn an_abandoned_child_refusing_its_handles_kill_is_not_killed_by_pid() {
    let child = paused_group_leader();
    let received = received(child, None);
    let pidfd = super::super::test_support::pidfd_of(received.pid.expect("a pid"));
    let (reaped_tx, reaped_rx) = std::sync::mpsc::channel();
    fault::set_force_child_kill_denied(true);
    fault::set_background_reap_notifier(reaped_tx);

    assert_eq!(end_child(&received), ChildFate::Unkillable);
    assert_eq!(fault::take_child_sends(), [ChildSend::Handle]);

    // Unreaped, so its pidfd still names it.
    rustix::process::pidfd_send_signal(&pidfd, rustix::process::Signal::KILL).expect("kill the child");
    reaped_rx.recv().expect("the background reaper must reap it");
}
