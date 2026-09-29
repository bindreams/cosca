//! Windows-only `SharedChild` tests: the process handle's contract and the
//! `WaitForSingleObject` deadline.

use std::time::Duration;

use super::fixtures::Blocker;
use crate::wait::exit_only::seams::{self as exit_seams, ForcedReap};

/// S11m: a signalled handle always has an exit code to read, so a reap that finds nothing after
/// the wait saw the exit is a contract breach: it asserts in a debug build, and in a release
/// build the state goes back to `N` and the caller gets an error, so it never spins.
///
/// Mutant: S11m resumes the wait.
#[test]
#[cfg_attr(debug_assertions, should_panic(expected = "signalled process handle"))]
fn a_reap_that_finds_none_after_signalled_is_a_contract_breach() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let _none = exit_seams::force_reap_once(ForcedReap::None);
    let err = b.shared.wait().expect_err("the forced empty reap");
    assert!(err.to_string().contains("signalled process handle"), "{err}");
    assert!(matches!(b.shared.lock().state, crate::child::shared::State::N));
}

/// Principle 13 for `WaitForSingleObject`: every armed timeout is `ceil_ms(remaining)`, never
/// longer, and the wait re-arms against the frozen clock until the deadline.
///
/// Mutant: a timeout computed once, before the loop.
#[test]
fn a_deadline_wait_for_single_object_arms_the_remaining_time() {
    let b = Blocker::spawn();
    let (_clock, at) = crate::wait::test_clock::FrozenClockGuard::install();
    let limit = Duration::from_millis(50);
    crate::wait::wait_ms_probe::take();
    assert_eq!(
        b.shared
            .wait_deadline(at + limit)
            .expect("a running child is not an error"),
        None
    );
    let arms = crate::wait::wait_ms_probe::take();
    assert!(!arms.is_empty(), "the wait must have blocked at least once");
    for arm in &arms {
        assert!(arm.remaining <= limit, "{arm:?}");
        assert_eq!(
            arm.ms,
            crate::wait::wait_ms_probe::expected_ms(arm.remaining, u32::MAX - 1),
            "{arm:?}"
        );
    }
    for pair in arms.windows(2) {
        assert!(
            pair[1].remaining < pair[0].remaining,
            "remaining must be recomputed each round: {arms:?}"
        );
    }
    assert!(crate::wait::now() >= at + limit);
}
