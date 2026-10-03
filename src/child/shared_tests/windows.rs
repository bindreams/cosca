//! Windows-only `SharedChild` tests: the process handle's contract and the
//! `WaitForSingleObject` deadline.

use std::time::Duration;

use super::fixtures::{identity_of, spawn_std_blocker, Blocker};
use crate::child::shared::SharedChild;
use crate::wait::exit_only::seams::{self as exit_seams, ForcedReap};

/// S11m: a signalled handle always has an exit code to read, so a reap that finds nothing after
/// the wait saw the exit is a contract breach: it asserts in a debug build, and in a release
/// build the state goes back to `N` and the caller gets an error, so it never spins.
///
/// Mutant: S11m resumes the wait.
#[skuld::test]
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
#[skuld::test]
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

/// A `WAIT_TIMEOUT` hours before the deadline is not trusted: the wait re-arms against the real
/// deadline and reports the exit that comes later. The first arm is 1 ms (a forced sub-millisecond
/// remainder) on a child held on its stdin, so it times out; the child is ended as the second arm
/// is recorded, before its wait starts.
///
/// Mutant: the holder's wait trusts the first `WAIT_TIMEOUT` (one `WaitForSingleObject` in place
/// of `wait_until`): `Ok(None)` after 1 ms.
#[skuld::test]
fn a_wait_timeout_before_the_deadline_is_not_trusted() {
    let (child, stdin) = spawn_std_blocker();
    let id = identity_of(&child);
    let shared = SharedChild::adopt(child, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    crate::wait::wait_ms_probe::take();
    let _override = crate::wait::remaining_override_seam::set(Duration::from_micros(500));
    crate::wait::wait_ms_probe::on_second_arm(move || drop(stdin));
    let deadline = std::time::Instant::now() + Duration::from_secs(3600);
    let got = shared.wait_deadline(deadline);
    let arms = crate::wait::wait_ms_probe::take();
    let status = got.expect("a genuinely-exited child is not an error");
    assert!(status.is_some(), "an early WAIT_TIMEOUT was trusted: {arms:?}");
    assert!(arms.len() >= 2, "expected a re-arm, got {arms:?}");
}
