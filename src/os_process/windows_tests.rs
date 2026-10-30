use std::time::Duration;

use crate::error::Error;
use crate::identity::ProcessId;
use crate::os_process::drive::exited_by;
use crate::os_process::{kill_by_id, open, terminate_by_id, Exit, Op, WaitFor};
use crate::signal::{Sent, Sig};
use crate::test_child::held_contained_blocker;

/// A live blocker, its stdin (held open so it stays alive) and its identity.
fn blocker() -> (crate::Child, std::io::PipeWriter, ProcessId) {
    let (child, stdin) = held_contained_blocker(crate::Stdio::null());
    let id = child.id();
    (child, stdin, id)
}

/// Mutant: `exited` calls a live process exited, or `signal` signals nothing. The kill handle
/// lacks `SYNCHRONIZE`, so the wait goes through a second, `Op::Wait` object.
#[skuld::test]
fn open_live_then_kill_then_exited() {
    let (child, _stdin, id) = blocker();
    let mut waiter = open(id, Op::Wait).unwrap().expect("a live process opens");
    assert_eq!(waiter.identity(), id);
    assert!(matches!(waiter.exited().unwrap(), Exit::Running(WaitFor::Signalled(_))));
    assert!(!exited_by(&mut *waiter, Some(Duration::ZERO)).unwrap());
    let mut killer = open(id, Op::Kill).unwrap().expect("a live process opens");
    assert_eq!(killer.identity(), id);
    assert_eq!(killer.signal(Sig::Kill).unwrap(), Sent::Delivered);
    assert!(exited_by(&mut *waiter, None).unwrap());
    child.wait().unwrap();
}

/// Review Focus 1. Mutant: `open` trusts the pid and not the start token.
#[skuld::test]
fn open_with_wrong_start_token_is_none_and_sends_nothing() {
    let (child, _stdin, id) = blocker();
    let other = ProcessId::from_parts_for_test(id.pid(), id.start_token_raw() + 1);
    assert!(open(other, Op::Kill).unwrap().is_none());
    assert!(open(other, Op::Wait).unwrap().is_none());
    kill_by_id(other).expect("a stale identity is already gone");
    // Still running: the right identity opens and sees no exit.
    let mut p = open(id, Op::Wait).unwrap().expect("the blocker is alive");
    assert!(!exited_by(&mut *p, Some(Duration::ZERO)).unwrap());
    child.kill().unwrap();
    child.wait().unwrap();
}

/// Review Focus 2. Mutant: the first look blocks, or misses an exit.
#[skuld::test]
fn exited_before_first_look_returns_true() {
    let (child, _stdin, id) = blocker();
    let mut p = open(id, Op::Wait).unwrap().expect("a live process opens");
    child.kill().unwrap();
    // `TerminateProcess` returns before the process object is signalled; the child's own wait is
    // the barrier.
    child.wait().unwrap();
    assert!(exited_by(&mut *p, Some(Duration::ZERO)).unwrap());
}

/// Mutant: a refused `TerminateProcess` on an exited process is an error, or `kill_by_id` of an
/// exited process whose handle is still held by its owner fails.
#[skuld::test]
fn kill_after_exit_is_ok() {
    let (child, _stdin, id) = blocker();
    child.kill().unwrap();
    child.wait().unwrap();
    kill_by_id(id).expect("killing an exited process is success");
}

/// Mutant: `Termination::Exited` is an error, or reads `Delivered`.
#[skuld::test]
fn signal_after_exit_is_gone() {
    let (child, _stdin, id) = blocker();
    let mut p = open(id, Op::Kill).unwrap().expect("a live process opens");
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(p.signal(Sig::Kill).unwrap(), Sent::Gone);
}

/// Mutant: `kill_by_id` opens and drops without signalling.
#[skuld::test]
fn kill_by_id_ends_the_process() {
    let (child, _stdin, id) = blocker();
    kill_by_id(id).unwrap();
    let status = child.wait().unwrap();
    assert!(
        !status.success(),
        "a killed blocker does not exit by itself: {status:?}"
    );
}

/// Windows has no per-process graceful signal: `Unsupported`, and the process is untouched.
#[skuld::test]
fn terminate_by_id_is_unsupported_and_sends_nothing() {
    let (child, _stdin, id) = blocker();
    let err = terminate_by_id(id).expect_err("Windows has no graceful per-process signal");
    let Error::Unsupported { op, platform, detail } = err else {
        panic!("expected Unsupported: {err:?}");
    };
    assert_eq!(op, "graceful terminate (SIGTERM-equivalent)");
    assert_eq!(platform, "windows");
    assert!(detail.contains("graceful_shutdown_tree"), "{detail}");
    let mut p = open(id, Op::Wait).unwrap().expect("the blocker is alive");
    assert!(!exited_by(&mut *p, Some(Duration::ZERO)).unwrap());
    child.kill().unwrap();
    child.wait().unwrap();
}

/// Mutant: `os_handle` is `None`, or names another handle.
#[skuld::test]
fn os_handle_is_the_handle_the_wait_is_on() {
    use std::os::windows::io::AsRawHandle;
    let (child, _stdin, id) = blocker();
    let mut p = open(id, Op::Wait).unwrap().expect("a live process opens");
    let handle = p.os_handle().expect("a Windows process has a handle").as_raw_handle();
    match p.exited().unwrap() {
        Exit::Running(WaitFor::Signalled(h)) => assert_eq!(h.as_raw_handle(), handle),
        other => panic!("a live process reads Running(Signalled): {other:?}"),
    }
    child.kill().unwrap();
    child.wait().unwrap();
}
