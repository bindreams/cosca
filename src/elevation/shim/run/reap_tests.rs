use std::os::fd::OwnedFd;

use super::super::child::Spawned;
use super::super::log::Log;

/// A `Spawned` whose handle is not a pidfd: every call on it fails with `EBADF`.
fn not_a_process() -> Spawned {
    let not_a_pidfd: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
    Spawned {
        pid: 0,
        pidfd: not_a_pidfd,
    }
}

/// A `Spawned` for a process that exited and was collected by its parent, here: the test.
fn collected_process() -> Spawned {
    let mut command = std::process::Command::new("true");
    let mut child = crate::test_spawn::spawn(&mut command).expect("true starts");
    let pid = rustix::process::Pid::from_raw(child.id() as i32).unwrap();
    let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).unwrap();
    child.wait().unwrap();
    Spawned {
        pid: pid.as_raw_nonzero().get(),
        pidfd,
    }
}

#[skuld::test]
fn a_kill_of_a_collected_process_is_expected() {
    // `ESRCH`: someone else collected the child, which is a handled case, not a bug.
    collected_process().kill(&Log::new(None));
}

#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "pidfd_send_signal(SIGKILL)")]
fn a_kill_that_fails_otherwise_is_a_bug() {
    not_a_process().kill(&Log::new(None));
}

/// Without `debug_assertions` the failure is logged and the caller goes on.
#[cfg(not(debug_assertions))]
#[skuld::test]
fn a_kill_that_fails_otherwise_is_logged_and_goes_on() {
    not_a_process().kill(&Log::new(None));
}

#[skuld::test]
fn a_status_collected_by_someone_else_is_lost_not_a_bug() {
    // `ECHILD`: the pidfd names a process that is no child of ours any more.
    assert_eq!(collected_process().reap(false, &Log::new(None)), None);
}

#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "waitid on the program's pidfd")]
fn a_wait_that_fails_other_than_echild_is_a_bug() {
    not_a_process().reap(false, &Log::new(None));
}

/// Without `debug_assertions` the failure is logged and the status counts as lost.
#[cfg(not(debug_assertions))]
#[skuld::test]
fn a_wait_that_fails_other_than_echild_is_logged_and_lost() {
    assert_eq!(not_a_process().reap(false, &Log::new(None)), None);
}
