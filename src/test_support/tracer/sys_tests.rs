//! The settle rule's classification of a thread's run state and flags.

use super::{all_parked, parked, vanished_as_none};

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

/// A listed thread in `run_state`, with no flags.
fn thread(run_state: i32) -> Option<libc::proc_threadinfo> {
    // SAFETY: `proc_threadinfo` is plain data; all-zero is a valid value.
    let mut thread: libc::proc_threadinfo = unsafe { std::mem::zeroed() };
    thread.pth_run_state = run_state;
    Some(thread)
}

/// Mutants: the verdict reads only the first thread, or only the last, so a stop whose stopping
/// thread is listed elsewhere settles while that thread still runs.
#[test]
fn a_stop_settles_only_once_every_thread_is_parked() {
    let waiting = thread(libc::TH_STATE_WAITING);
    let running = thread(libc::TH_STATE_RUNNING);
    let uninterruptible = thread(libc::TH_STATE_UNINTERRUPTIBLE);
    assert!(!all_parked(&[waiting, running]));
    assert!(!all_parked(&[waiting, running, waiting]));
    assert!(!all_parked(&[waiting, waiting, uninterruptible]));
    assert!(all_parked(&[waiting, thread(libc::TH_STATE_STOPPED)]));
}

/// A thread that exited between the listing and its read leaves the stop unsettled, so every
/// state peeks again under its backoff. Mutant: it counts as parked.
#[test]
fn a_thread_that_vanished_mid_read_is_not_parked() {
    let waiting = thread(libc::TH_STATE_WAITING);
    assert!(!all_parked(&[waiting, None, waiting]));
}

/// `PROC_PIDTHREADINFO`'s `ESRCH` names that thread, not the process. Mutant: it propagates, and
/// `stop` answers `Running`, after which S3 waits for a `SIGCHLD` it already consumed.
#[test]
fn a_thread_read_meeting_esrch_is_a_vanished_thread() {
    assert_eq!(vanished_as_none::<()>(Err(libc::ESRCH)), Ok(None));
    assert_eq!(vanished_as_none::<()>(Err(libc::EPERM)), Err(libc::EPERM));
    assert_eq!(vanished_as_none(Ok(())), Ok(Some(())));
}

/// Mutant: an unknown run state counts as parked.
#[test]
#[should_panic(expected = "pth_run_state 0 is no TH_STATE_*")]
fn an_unknown_run_state_fails_loudly() {
    parked(0, NO_FLAGS);
}
