//! The settle rule's classification of a thread's run state.

use super::parked;

/// Mutant: an uninterruptible thread counts as parked. A traced stop's thread blocks
/// uninterruptibly on a kernel lock between setting `SSTOP` and waiting on `sigwait`.
#[test]
fn an_uninterruptible_thread_is_not_parked() {
    assert!(!parked(libc::TH_STATE_UNINTERRUPTIBLE));
}

/// Mutant: a running thread counts as parked.
#[test]
fn a_running_thread_is_not_parked() {
    assert!(!parked(libc::TH_STATE_RUNNING));
}

/// Mutant: the rule rejects every state, so no stop ever settles.
#[test]
fn a_waiting_or_suspended_thread_is_parked() {
    assert!(parked(libc::TH_STATE_WAITING));
    assert!(parked(libc::TH_STATE_STOPPED));
}
