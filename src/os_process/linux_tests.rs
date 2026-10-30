use std::time::Duration;

use crate::identity::ProcessId;
use crate::os_process::drive::exited_by;
use crate::os_process::{open, Exit, Op};
use crate::signal::{Sent, Sig};
use crate::test_child::{held_contained_blocker_without_cgroup, wait_until_zombie};

/// A live blocker, its stdin (held open so it stays alive) and its identity.
fn blocker() -> (crate::Child, std::io::PipeWriter, ProcessId) {
    let (child, stdin) = held_contained_blocker_without_cgroup(crate::Stdio::null());
    let id = child.id();
    (child, stdin, id)
}

/// Mutant: `exited` calls a live process exited, or `signal` signals nothing.
#[skuld::test]
fn open_live_then_kill_then_exited() {
    let (child, _stdin, id) = blocker();
    let mut p = open(id, Op::Kill).unwrap().expect("a live process opens");
    assert_eq!(p.identity(), id);
    assert!(matches!(p.exited().unwrap(), Exit::Running(_)));
    assert!(!exited_by(&mut *p, Some(Duration::ZERO)).unwrap());
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Delivered);
    assert!(exited_by(&mut *p, None).unwrap());
    child.wait().unwrap();
}

/// Mutant: `open` hands out an object for a reaped process.
#[skuld::test]
fn open_after_reap_is_none() {
    let (child, _stdin, id) = blocker();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(open(id, Op::Wait).unwrap().is_none());
}

/// Review Focus 1. Mutant: `open` trusts the pid and not the start token.
#[skuld::test]
fn open_with_wrong_start_token_is_none_and_sends_nothing() {
    let (child, _stdin, id) = blocker();
    let other = ProcessId::from_parts_for_test(id.pid(), id.start_token_raw() + 1);
    assert!(open(other, Op::Kill).unwrap().is_none());
    // Still running: the right identity opens and sees no exit.
    let mut p = open(id, Op::Wait).unwrap().expect("the blocker is alive");
    assert!(!exited_by(&mut *p, Some(Duration::ZERO)).unwrap());
    child.kill().unwrap();
    child.wait().unwrap();
}

/// Review Focus 2. Mutant: the first look blocks, or misses a zombie.
#[skuld::test]
fn exited_before_first_look_returns_true() {
    let (child, _stdin, id) = blocker();
    let mut p = open(id, Op::Wait).unwrap().expect("a live process opens");
    child.kill().unwrap();
    wait_until_zombie(id.pid());
    assert!(exited_by(&mut *p, Some(Duration::ZERO)).unwrap());
    child.wait().unwrap();
}

/// Mutant: `ESRCH` is an error, or a reaped process is reported `Delivered`.
#[skuld::test]
fn signal_after_exit_is_gone() {
    let (child, _stdin, id) = blocker();
    let mut p = open(id, Op::Kill).unwrap().expect("a live process opens");
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Gone);
    // A reaped process reads as exited, too (POLLHUP).
    assert!(exited_by(&mut *p, Some(Duration::ZERO)).unwrap());
}

/// Mutant: `os_handle` is `None`, or names another fd.
#[skuld::test]
fn os_handle_is_the_pidfd_the_wait_is_on() {
    use std::os::fd::AsRawFd;
    let (child, _stdin, id) = blocker();
    let mut p = open(id, Op::Wait).unwrap().expect("a live process opens");
    let handle = p.os_handle().expect("a Linux process has a pidfd").as_raw_fd();
    match p.exited().unwrap() {
        Exit::Running(crate::os_process::WaitFor::Readable(fd)) => assert_eq!(fd.as_raw_fd(), handle),
        other => panic!("a live process reads Running(Readable): {other:?}"),
    }
    child.kill().unwrap();
    child.wait().unwrap();
}
