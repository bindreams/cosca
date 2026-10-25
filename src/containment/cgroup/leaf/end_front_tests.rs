//! `end_front`'s arms for a front nothing places or reaps: its reach unreadable, no handle on it, a
//! reap by another reaper. Unprivileged: the front is a forked process that pauses, and no cgroup is used.

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
    assert_eq!(fate, Abandoned::Front(FrontFate::Unplaced));
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

/// Kills the forked `pid` and reaps it, as another reaper in the process would.
fn reap_behind(pid: u32) {
    // SAFETY: `pid` is this process's own unreaped child.
    unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    crate::containment::cgroup::test_support::reap(pid);
}

/// The records about the front `pid` since `mark`, on this thread.
fn records_about(mark: usize, pid: u32) -> Vec<(log::Level, String)> {
    crate::log_capture::records_since_on_current_thread(mark, &format!("front (pid {pid})"))
}

/// A front the leaf's kill reached, reaped by another reaper before the final wait, was killed: only
/// its status is lost, so it gets a `debug` record and no warn. Mutant: "`ECHILD` from the final wait
/// stays on the warn arm, `Unaccounted`".
#[skuld::test]
fn a_front_reaped_by_someone_else_before_the_final_wait_is_reaped_at_debug() {
    crate::log_capture::install();
    let (front, pidfd) = running_front();
    let received = received(&front, pidfd);
    let pid = front.defuse();
    let _reaped_elsewhere = crate::containment::cgroup::fault::set_before_exit_wait(move || reap_behind(pid));
    let mark = crate::log_capture::mark();
    let fate = end_front(&received, |_, _| Ok(true));
    assert_eq!(fate, Abandoned::Front(FrontFate::Reaped));
    let records = records_about(mark, pid);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].0, log::Level::Debug, "{records:?}");
    assert!(records[0].1.contains("reaped elsewhere"), "{records:?}");
}

/// A front reaped by another reaper between the look that saw it unreaped and the probe for its
/// exit has ended, as one the look saw reaped, whatever its place read: a `debug` record and no
/// warn. Mutant: "`ECHILD` from the probe stays on the warn arm, `Unaccounted`".
#[skuld::test]
fn a_front_reaped_by_someone_else_before_the_probe_has_ended_at_debug() {
    crate::log_capture::install();
    let (front, pidfd) = running_front();
    let received = received(&front, pidfd);
    let pid = front.defuse();
    let _reaped_elsewhere = crate::containment::cgroup::fault::set_before_front_probe(move || reap_behind(pid));
    let mark = crate::log_capture::mark();
    let fate = end_front(&received, |_, _| Ok(false));
    assert_eq!(fate, Abandoned::Ended);
    let records = records_about(mark, pid);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].0, log::Level::Debug, "{records:?}");
    assert!(records[0].1.contains("reaped elsewhere"), "{records:?}");
}

/// The probe that sees the front running is followed at once by the wait it decides: the front is
/// placed before the probe, not between the two. Mutant: "`reached` runs after the probe" (it then
/// sees the probe's hook fired).
#[skuld::test]
fn a_front_is_placed_before_the_probe_that_decides_its_wait() {
    use std::cell::Cell;
    use std::rc::Rc;

    let (front, pidfd) = running_front();
    let received = received(&front, pidfd);
    let pid = front.defuse();
    let probed = Rc::new(Cell::new(false));
    let _probe = crate::containment::cgroup::fault::set_before_front_probe({
        let probed = Rc::clone(&probed);
        move || probed.set(true)
    });
    // The leaf's kill, landing after the probe saw the front running.
    // SAFETY: `pid` is this process's own unreaped child.
    let _killed = crate::containment::cgroup::fault::set_before_exit_wait(move || unsafe {
        libc::kill(pid as i32, libc::SIGKILL);
    });
    let placed_after_probe = Cell::new(None);
    let fate = end_front(&received, |_, _| {
        placed_after_probe.set(Some(probed.get()));
        Ok(true)
    });
    crate::containment::cgroup::fault::run_before_exit_wait();
    assert_eq!(fate, Abandoned::Front(FrontFate::Reaped));
    assert_eq!(
        placed_after_probe.get(),
        Some(false),
        "the front was placed after the probe"
    );
}

/// A front that sent only its `/proc` directory is waited for by its pid, so the look that finds it
/// unreaped is followed at once by the probe: its place is read before the look. A reap landing while
/// the place is read is then seen by the look (`Ended`, no record), not by the probe. Mutant:
/// "`reached` runs after the look" (the probe then finds the pid gone: a `debug` record).
#[skuld::test]
fn a_front_known_by_its_proc_directory_is_placed_before_the_look_that_precedes_the_probe() {
    crate::log_capture::install();
    let (front, pidfd) = running_front();
    let pid = front.defuse();
    drop(pidfd);
    let proc_dir = std::fs::File::open(format!("/proc/{pid}")).expect("open the front's /proc directory");
    let received = Received {
        report: Some(PlacementReport::Placed),
        pid: Some(pid),
        pidfd: None,
        proc_dir: Some(OwnedFd::from(proc_dir)),
    };
    let mark = crate::log_capture::mark();
    let fate = end_front(&received, |_, _| {
        reap_behind(pid);
        Ok(true)
    });
    assert_eq!(fate, Abandoned::Ended);
    let records = records_about(mark, pid);
    assert_eq!(records, Vec::new(), "{records:?}");
}

/// A front that exits before the probe is reaped whatever its place read, with no warn about its
/// place. Mutant: "an unplaceable front is left before the probe looks" (`Unplaced`, warned).
#[skuld::test]
fn a_front_exited_before_the_probe_is_reaped_whatever_its_place_read() {
    crate::log_capture::install();
    let (front, pidfd) = running_front();
    let received = received(&front, pidfd);
    let pid = front.defuse();
    // SAFETY: `pid` is this process's own unreaped child.
    unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    // Waits for the exit and leaves the zombie, for the probe to see.
    let pidfd = received.pidfd.as_ref().expect("the front's pidfd");
    loop {
        match rustix::process::waitid(
            rustix::process::WaitId::PidFd(std::os::fd::AsFd::as_fd(pidfd)),
            rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOWAIT,
        ) {
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => panic!("wait for the front's exit: {e}"),
            Ok(_) => break,
        }
    }
    let mark = crate::log_capture::mark();
    let fate = end_front(&received, |_, _| Err(std::io::Error::other("subtree gone")));
    assert_eq!(fate, Abandoned::Front(FrontFate::Reaped));
    let records = records_about(mark, pid);
    assert_eq!(records, Vec::new(), "{records:?}");
}
