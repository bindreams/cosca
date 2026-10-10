//! `end_front`'s arms for a front nothing places or reaps: its reach unreadable, no handle on it, a
//! wait that fails. Unprivileged: the front is a forked process that pauses, and no cgroup is used.

use std::os::fd::OwnedFd;

use super::super::test_support::{fork_running, KillOnDrop};
use super::{end_front, Abandoned, Received};
use crate::child::spawn::FrontFate;
use crate::containment::cgroup::PlacementReport;

/// A running front that did not exec, as the abandoned spawn's child is, and its pidfd.
fn running_front() -> (KillOnDrop, OwnedFd) {
    let front = fork_running(|| loop {
        // SAFETY: async-signal-safe.
        unsafe { libc::pause() };
    });
    let pidfd = rustix::process::pidfd_open(
        rustix::process::Pid::from_raw(front.pid() as i32).expect("a positive pid"),
        rustix::process::PidfdFlags::empty(),
    )
    .expect("pidfd_open the front");
    (front, pidfd)
}

fn received(front: &KillOnDrop, pidfd: OwnedFd) -> Received {
    Received {
        report: Some(PlacementReport::Placed),
        pid: Some(front.pid()),
        pidfd: Some(pidfd),
        proc_dir: None,
    }
}

/// A front whose place cannot be read is left unsignalled and unreaped, and the warning names the
/// cause and does not claim it runs: its leaf's kill may have ended it. Mutant: "an unreadable place
/// answers as a front outside its leaf" (the warning then says nothing of the cause).
#[skuld::test]
fn a_front_whose_place_cannot_be_read_is_left_naming_the_cause() {
    crate::log_capture::install();
    let (front, pidfd) = running_front();
    let received = received(&front, pidfd);
    let mark = crate::log_capture::mark();
    let fate = end_front(&received, |_, _| Err(std::io::Error::other("subtree gone")));
    assert_eq!(fate, Abandoned::Front(FrontFate::LeftUnreaped));
    let warns = crate::log_capture::records_since_on_current_thread(mark, "cannot be placed");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].1.contains("(subtree gone)"), "{warns:?}");
    assert!(!warns[0].1.contains("left running"), "{warns:?}");
}

/// A front that sent no handle on itself is unaccounted for: there is nothing to wait on or read.
/// Mutant: "it answers as a front outside its leaf".
#[skuld::test]
fn a_front_that_sent_no_handle_is_unaccounted_for() {
    crate::log_capture::install();
    let received = Received {
        report: Some(PlacementReport::Placed),
        pid: Some(std::process::id()),
        pidfd: None,
        proc_dir: None,
    };
    let mark = crate::log_capture::mark();
    let fate = end_front(&received, |_, _| panic!("a front with no handle is not placed"));
    assert_eq!(fate, Abandoned::Front(FrontFate::Unaccounted));
    let warns = crate::log_capture::records_since_on_current_thread(mark, "sent no handle on itself");
    assert_eq!(warns.len(), 1, "{warns:?}");
}

/// A front the leaf's kill reached whose final wait fails (something else reaped it between the
/// check and the wait) is unaccounted for, and the warning names the cause. Mutant: "a failed final
/// wait answers `Reaped`".
#[skuld::test]
fn a_front_reaped_by_someone_else_before_the_final_wait_is_unaccounted_for() {
    crate::log_capture::install();
    let (front, pidfd) = running_front();
    let received = received(&front, pidfd);
    let pid = front.defuse();
    let _reaped_elsewhere = crate::containment::cgroup::fault::set_before_exit_wait(move || {
        // SAFETY: `pid` is this process's own unreaped child.
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        crate::containment::cgroup::test_support::reap(pid);
    });
    let mark = crate::log_capture::mark();
    let fate = end_front(&received, |_, _| Ok(true));
    assert_eq!(fate, Abandoned::Front(FrontFate::Unaccounted));
    let warns = crate::log_capture::records_since_on_current_thread(mark, "could not be reaped");
    assert_eq!(warns.len(), 1, "{warns:?}");
}
