//! The settle rule's classification of a thread's run state and flags.

use super::parked;

const NO_FLAGS: i32 = 0;

/// Mutant: an uninterruptible thread counts as parked. A traced stop's thread blocks
/// uninterruptibly on a kernel lock, keeping its kernel stack, between setting `SSTOP` and
/// waiting on `sigwait`.
#[test]
fn an_uninterruptible_thread_is_not_parked() {
    assert!(!parked(libc::TH_STATE_UNINTERRUPTIBLE, NO_FLAGS));
}

/// Mutant: no exemption, so a stop with a never-started thread never settles.
#[test]
fn an_uninterruptible_thread_without_a_kernel_stack_is_parked() {
    assert!(parked(libc::TH_STATE_UNINTERRUPTIBLE, libc::TH_FLAGS_SWAPPED));
}

/// Mutant: a running thread counts as parked.
#[test]
fn a_running_thread_is_not_parked() {
    assert!(!parked(libc::TH_STATE_RUNNING, NO_FLAGS));
}

/// Mutant: the rule rejects a state no stopping thread is in, so such a stop never settles.
#[test]
fn a_waiting_suspended_or_halted_thread_is_parked() {
    assert!(parked(libc::TH_STATE_WAITING, NO_FLAGS));
    assert!(parked(libc::TH_STATE_STOPPED, NO_FLAGS));
    assert!(parked(libc::TH_STATE_HALTED, NO_FLAGS));
}
