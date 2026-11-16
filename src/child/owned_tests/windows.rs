//! Windows-only `OwnedChild` tests over a real process handle.

use std::sync::Arc;

use super::fixtures::{wait_status, Blocker};
use crate::child::owned::OwnedChild;
use crate::elevation::front::TrackedKind;
use crate::identity::refusing_the_next_terminate;
use crate::os_process::child::adopt_std_over;
use crate::os_process::fake::FakeProcess;
use crate::signal::{Sent, Sig};

/// A kill reaches a live child through its process handle, and the wait returns the kill's status:
/// the blocker is released only after the kill, so a kill that sent nothing exits `0`.
///
/// Mutant: `signal` reports `Delivered` and sends nothing.
#[skuld::test]
fn kill_of_a_killable_child_returns_and_reaps() {
    let mut b = Blocker::spawn();
    assert_eq!(b.owned.signal(Sig::Kill).expect("kill a live child"), Sent::Delivered);
    b.end_child();
    assert_eq!(wait_status(&b.owned).code(), Some(1));
    assert!(b.owned.exit_seen());
}

/// An exit seen on the handle is read once and cached: a second wait answers the same status.
///
/// Mutant: no `E` write, so the second wait reads the exit code of the handle again.
#[skuld::test]
fn an_exit_seen_on_the_handle_is_cached() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    assert!(!b.owned.exit_seen(), "an exit nobody waited on is not a reap");
    let first = wait_status(&b.owned);
    assert_eq!(wait_status(&b.owned), first);
    assert!(b.owned.exit_seen());
}

/// A kill the OS refuses because the process is already exiting is `Gone`, and the kill makes no
/// look at the exit, let alone a wait for it. The child is released before the kill, so a kill that
/// waited would fail the count, not hang.
///
/// Mutant: `signal` waits for the exit after a refusal that finds it under way.
#[skuld::test]
fn kill_never_waits() {
    let (blocker, stdin) = crate::test_child::blocker().into_parts();
    let id = super::fixtures::identity_of(&blocker);
    let kernel = Arc::new(refusing_the_next_terminate());
    let fake = FakeProcess::over(adopt_std_over(Arc::clone(&kernel), blocker, id));
    let child = OwnedChild::new(Box::new(fake.clone()), TrackedKind::Own);
    drop(stdin);
    assert_eq!(
        child.signal(Sig::Kill).expect("a refusal under way is no error"),
        Sent::Gone
    );
    assert!(
        kernel.all_rows_taken(),
        "the kill reached TerminateProcess to be refused"
    );
    assert_eq!(fake.looks(), 0, "the kill must not look at the exit");
    wait_status(&child);
}
