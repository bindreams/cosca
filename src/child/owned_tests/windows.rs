//! Windows-only `OwnedChild` tests over a real process handle.

use super::fixtures::{wait_status, Blocker};
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
    assert!(b.owned.is_reaped());
}

/// An exit seen on the handle is read once and cached: a second wait answers the same status.
///
/// Mutant: no `E` write, so the second wait reads the exit code of the handle again.
#[skuld::test]
fn an_exit_seen_on_the_handle_is_cached() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    assert!(!b.owned.is_reaped(), "an exit nobody waited on is not a reap");
    let first = wait_status(&b.owned);
    assert_eq!(wait_status(&b.owned), first);
    assert!(b.owned.is_reaped());
}
