use std::time::Duration;

use crate::identity::ProcessId;
use crate::os_process::drive::{absolute, drive};
use crate::os_process::{kill, open, terminate, terminate_by_id, Exit};
use crate::signal::{Sent, Sig};
use crate::test_child::{held_contained_blocker_without_cgroup, wait_until_zombie};

/// A live blocker, its stdin (held open so it stays alive) and its identity.
fn blocker() -> (crate::Child, std::io::PipeWriter, ProcessId) {
    let (child, stdin) = held_contained_blocker_without_cgroup(crate::Stdio::null());
    let id = child.id();
    (child, stdin, id)
}

#[skuld::test]
fn one_open_serves_look_signal_and_wait() {
    let (child, _stdin, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    assert!(matches!(p.exited().unwrap(), Exit::Running(_)));
    assert!(!drive(&*p, absolute(Some(Duration::ZERO))).unwrap());
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Delivered);
    assert!(drive(&*p, absolute(None)).unwrap());
    child.wait().unwrap();
}

#[skuld::test]
fn open_after_reap_is_none() {
    let (child, _stdin, id) = blocker();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(open(id).unwrap().is_none());
}

#[skuld::test]
fn open_with_wrong_start_token_is_none_and_sends_nothing() {
    let (child, _stdin, id) = blocker();
    let other = ProcessId::from_parts_for_test(id.pid(), id.start_token_raw() + 1);
    assert!(open(other).unwrap().is_none());
    // Still running: the right identity opens and sees no exit.
    let p = open(id).unwrap().expect("the blocker is alive");
    assert!(!drive(&*p, absolute(Some(Duration::ZERO))).unwrap());
    child.kill().unwrap();
    child.wait().unwrap();
}

#[skuld::test]
fn exited_before_first_look_returns_true() {
    let (child, _stdin, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    child.kill().unwrap();
    wait_until_zombie(id.pid());
    assert!(drive(&*p, absolute(Some(Duration::ZERO))).unwrap());
    child.wait().unwrap();
}

/// Mutant: `ESRCH` is an error, or a reaped process is reported `Delivered`.
#[skuld::test]
fn signal_after_exit_is_gone() {
    let (child, _stdin, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Gone);
    // A reaped process reads as exited, too (POLLHUP).
    assert!(drive(&*p, absolute(Some(Duration::ZERO))).unwrap());
}

/// Mutant: a look hands out some other fd to wait on. The kernel names a pidfd's process in its
/// `fdinfo`.
#[skuld::test]
fn the_wait_is_on_the_pidfd_of_the_process() {
    use std::os::fd::AsRawFd;
    let (child, _stdin, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    match p.exited().unwrap() {
        Exit::Running(crate::os_process::WaitFor::Readable(fd)) => {
            let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).unwrap();
            assert!(
                info.lines().any(|line| line == format!("Pid:	{}", id.pid())),
                "not a pidfd of {}: {info}",
                id.pid()
            );
        }
        other => panic!("a live process reads Running(Readable): {other:?}"),
    }
    child.kill().unwrap();
    child.wait().unwrap();
}

/// Mutant: `terminate_by_id` sends `SIGKILL`.
#[skuld::test]
fn terminate_by_id_sends_sigterm_and_the_blocker_exits() {
    use std::os::unix::process::ExitStatusExt;
    let (child, _stdin, id) = blocker();
    terminate_by_id(id).unwrap();
    assert_eq!(
        child.wait().unwrap().signal(),
        Some(rustix::process::Signal::TERM.as_raw())
    );
}

#[skuld::test]
fn kill_sends_sigkill_and_the_blocker_exits() {
    use std::os::unix::process::ExitStatusExt;
    let (child, _stdin, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    kill(&*p).unwrap();
    assert_eq!(
        child.wait().unwrap().signal(),
        Some(rustix::process::Signal::KILL.as_raw())
    );
}

/// A held process that its owner has reaped is gone: both acts are `Ok`. Mutant: `ESRCH` is an
/// error.
#[skuld::test]
fn kill_and_terminate_of_a_held_process_that_is_gone_are_ok() {
    let (child, _stdin, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    child.kill().unwrap();
    child.wait().unwrap();
    kill(&*p).unwrap();
    terminate(&*p).unwrap();
}

#[skuld::test]
fn terminate_by_id_on_a_gone_process_is_ok() {
    let (child, _stdin, id) = blocker();
    let other = ProcessId::from_parts_for_test(id.pid(), id.start_token_raw() + 1);
    terminate_by_id(other).unwrap();
    let p = open(id).unwrap().expect("the blocker is alive");
    assert!(!drive(&*p, absolute(Some(Duration::ZERO))).unwrap());
    child.kill().unwrap();
    child.wait().unwrap();
    terminate_by_id(id).unwrap();
}

/// `Process::kill` promises the raw errno of a refused kill. Mutant: `signal` wraps the errno in
/// an `io_context`, so `raw_os_error()` is `None`.
#[skuld::test]
fn refused_signal_keeps_its_raw_errno() {
    let (child, _stdin, id) = blocker();
    let p = open(id).unwrap().expect("a live process opens");
    let refused = crate::signal::seams::refuse_kills();
    let err = p.signal(Sig::Kill).unwrap_err();
    drop(refused);
    let crate::error::Error::Io(e) = err else {
        panic!("expected Error::Io, got {err:?}");
    };
    assert_eq!(e.raw_os_error(), Some(libc::EPERM), "{e:?}");
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
    child.kill().unwrap();
    child.wait().unwrap();
}
