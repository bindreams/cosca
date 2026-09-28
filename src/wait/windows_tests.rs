//! Deadline-contract tests for the two Windows wait sites in this file (`block_until_exit`,
//! `block_until_exit_or_cancel`): never report "still alive" before the caller's real
//! deadline. See docs/principles.md #13 (the deadline contract; PR #233, not yet merged) and
//! the "deadline-windows-never-early" bug this PR fixes.
//!
//! Every test here uses one or more of three seams from `crate::wait` instead of racing the
//! wall clock, each returning an RAII guard that restores the production default on drop (even
//! mid-panic, from a failed assertion) rather than requiring a hand-paired `set`/clear:
//! - `remaining_override_seam` forces a specific `remaining` duration (e.g. a sub-millisecond
//!   one) into the NEXT `win32_timeout_ms` call, so a ceiling-vs-truncation divergence — or an
//!   early, UN-clamped `WAIT_TIMEOUT` — is provable deterministically, not by racing real
//!   OS-clock/scheduler jitter to land on one (real Windows wait-timer coarseness can otherwise
//!   mask a truncation bug entirely; this is how an earlier, unfixed version of
//!   `block_until_exit_or_cancel_arms_the_ceiling_of_the_remaining_duration` passed against
//!   genuinely truncating code — see this PR's description).
//! - `wait_clamp_seam` overrides the `INFINITE - 1` (~49.7 day) clamp with a tiny value, so the
//!   "a capped wait elapsed before the real deadline, so re-arm rather than report" path is
//!   exercised in milliseconds instead of actually waiting 49.7 days.
//! - `wait_ms_probe` records the exact `(ms, remaining)` pair a call site armed a wait with, so
//!   a test can assert `ms == min(ceil_millis(remaining), clamp)` exactly (not merely
//!   `ms >= remaining`, which a slack-adding regression like `ceil_millis(d) + 1` would still
//!   satisfy), that a re-armed wait's successive `remaining` values strictly decrease (proving
//!   `remaining` is recomputed FRESH every loop iteration, never hoisted out and reused stale),
//!   and — via `on_second_arm` — lets a test register a one-shot hook that fires synchronously,
//!   on this thread, the instant a SECOND wait is armed: this ends a wait deterministically via
//!   a real event (closing a fixture's piped stdin so it exits) exactly when the loop has
//!   genuinely re-armed, rather than racing a fixed real-clock window (e.g. "200ms should be
//!   enough for setup plus a few 5ms re-arms") for enough re-arms to happen in time.
//!
//! No test here asserts an UPPER bound on elapsed time — only ever a lower bound
//! (`Instant::now() >= deadline`, or an equivalent real-completion check), per the deadline
//! contract and this repo's global rule against synchronizing on time.

use std::os::windows::io::AsRawHandle;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::HANDLE;

use crate::identity::ProcessId;
use crate::wait::{remaining_override_seam, wait_clamp_seam, wait_ms_probe};

/// A live child that blocks reading its own piped stdin until EOF — it never exits on its
/// own. `cmd /C more` is present on every Windows host (the OS shell itself, no new test
/// dependency); the same fixture shape is already used by
/// `src/containment/windows_tests.rs::wait_drained_raw_tracks_a_real_member_through_exit`.
fn spawn_never_exiting() -> (std::process::Child, ProcessId) {
    let child = std::process::Command::new("cmd")
        .args(["/C", "more"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn cmd /C more");
    let handle = HANDLE(child.as_raw_handle());
    let id = crate::identity::windows_identity_from_handle(handle, child.id())
        .expect("the owned handle always yields an identity");
    (child, id)
}

/// Let the fixture exit on its own terms (EOF on stdin) and reap it, so the test leaves no
/// running process behind.
fn let_child_exit(mut child: std::process::Child) {
    drop(child.stdin.take());
    child.wait().expect("wait for cmd /C more to exit");
}

/// The expected `win32_timeout_ms` output for a `remaining` far below the production clamp:
/// exactly `ceil_millis(remaining)`, no more (a slack-adding regression) and no less (a
/// truncating regression).
fn expected_ms_unclamped(remaining: Duration) -> u32 {
    u32::try_from(remaining.as_nanos().div_ceil(1_000_000)).expect("well under u32::MAX for these tests' durations")
}

// block_until_exit (site 1) ============================================================

/// Ceiling, not truncation, and no added slack: `block_until_exit`'s FIRST armed wait must use
/// EXACTLY `ceil_millis` of a seam-forced sub-millisecond `remaining` — not the OS-clock's
/// naturally-occurring remainder (real Windows wait-timer coarseness can mask a truncation bug
/// measured only by wall-clock elapsed time), and not a looser `ms >= remaining` bound (which a
/// `ceil_millis(d) + K` slack regression would still satisfy).
///
/// Mutant: revert the ceiling conversion at this call site (inside `win32_timeout_ms`) back to
/// the original truncating `d.as_millis()` -> fails: 500µs would floor to `0`, not ceil to `1`.
/// Mutant: add slack (e.g. `ceil_millis(d) + 1`) -> fails: `1` != the forced case's exact `1`.
#[test]
fn block_until_exit_arms_the_ceiling_of_the_remaining_duration() {
    let (child, id) = spawn_never_exiting();
    wait_ms_probe::take(); // clear any residue from a prior test on this thread
    let _override = remaining_override_seam::set(Duration::from_micros(500)); // sub-ms: ceils to 1, floors to 0
    let deadline = Instant::now() + Duration::from_millis(5);
    let result = super::block_until_exit(id, Some(Some(deadline)));
    let probed = wait_ms_probe::take();
    let_child_exit(child);
    result.expect("a live never-exiting child must not report a wait failure");
    let &(first_ms, first_remaining) = probed
        .first()
        .expect("expected at least one recorded (ms, remaining) pair");
    assert_eq!(
        first_remaining,
        Duration::from_micros(500),
        "the seam-forced remaining must be exactly what the call site recorded"
    );
    assert_eq!(
        first_ms, 1,
        "500µs must ceil to 1ms exactly (not truncate to 0, not slack up to >1); got ms={first_ms}"
    );
}

/// Never-early, the deadline contract's core promise: a `WAIT_TIMEOUT` must NEVER be trusted as
/// proof the real deadline passed, whether or not this round's wait happened to be clamped. Per
/// Microsoft's Wait Functions and Time-out Intervals, "the wait may time out in less than the
/// specified length of time" even for an UN-clamped, correctly-ceiled interval — so a recheck
/// conditioned on "was this arm clamped" is exactly as wrong as no recheck at all.
/// `remaining_override_seam` simulates that directly: the FIRST arm is forced to a tiny,
/// UN-clamped 500µs (ceils to 1ms — nowhere near the ~49.7-day production clamp) against a real
/// deadline that is HOURS away, so an early `WAIT_TIMEOUT` here has nothing to do with the
/// clamp. `on_second_arm` fires the instant the loop re-arms a second time, closing the
/// fixture's piped stdin so it exits for real; the wait must resolve via that genuine exit
/// event, never an early "still alive" verdict.
///
/// Mutant: trust an un-clamped `WAIT_TIMEOUT` outright — whether via no recheck loop at all, or
/// a recheck conditioned on "was this arm clamped" — fails: the function returns after just the
/// first (forced, un-clamped) arm, `probed.len() == 1`, and the result wrongly claims "still
/// alive" even though the real deadline is hours off.
#[test]
fn block_until_exit_never_reports_still_alive_before_the_deadline() {
    let (mut child, id) = spawn_never_exiting();
    let stdin = child.stdin.take().expect("piped stdin");
    wait_ms_probe::take();
    let _override = remaining_override_seam::set(Duration::from_micros(500));
    wait_ms_probe::on_second_arm(move || drop(stdin)); // EOF -> `cmd /C more` exits for real
    let deadline = Instant::now() + Duration::from_secs(3600); // hours off: nowhere near expiry
    let result = super::block_until_exit(id, Some(Some(deadline)));
    let probed = wait_ms_probe::take();
    let exited = result.expect("a genuinely-terminated child must not report a wait failure");
    child.wait().expect("reap the child after it exits");
    assert!(
        exited,
        "must report exited once the child genuinely exits, not falsely conclude still-alive \
         from an early, un-clamped WAIT_TIMEOUT"
    );
    assert!(
        probed.len() >= 2,
        "must re-arm past the first (forced-early, un-clamped) WAIT_TIMEOUT rather than \
         trusting it outright, got {} arm(s)",
        probed.len()
    );
}

/// The recheck loop's job under a REAL clamp (distinct from the un-clamped early-timeout path
/// the test above exercises): a wait capped below the real deadline (in production, the
/// `INFINITE - 1` / ~49.7-day clamp) must not be trusted as proof the deadline passed — the
/// loop must re-arm and keep waiting, recomputing `remaining` FRESH every iteration (never
/// hoisting it out of the loop and reusing a stale value). `wait_clamp_seam` substitutes a tiny
/// 5ms clamp for the real one against a real deadline that is hours away, so EVERY round is
/// genuinely clamped. `on_second_arm` ends the wait deterministically via a real exit event —
/// not a race against how much real time a fixed window (e.g. a 200ms real deadline) leaves for
/// setup plus however many re-arms happen to complete in it.
///
/// Mutant: remove the recheck-and-loop -> fails deterministically: `probed.len() == 1`, and the
/// result wrongly claims "still alive" (the hook, gated on a second arm, never fires).
/// Mutant: hoist `crate::wait::remaining(deadline)` above the loop and reuse it every iteration
/// -> fails the strictly-decreasing-`remaining` assertion below (every recorded `remaining`
/// would be identical, not shrinking).
#[test]
fn block_until_exit_re_arms_past_a_clamped_timeout() {
    let (mut child, id) = spawn_never_exiting();
    let stdin = child.stdin.take().expect("piped stdin");
    wait_ms_probe::take();
    let _clamp = wait_clamp_seam::set(5); // every armed wait capped to 5ms
    wait_ms_probe::on_second_arm(move || drop(stdin));
    let deadline = Instant::now() + Duration::from_secs(3600); // hours off: always clamped
    let result = super::block_until_exit(id, Some(Some(deadline)));
    let probed = wait_ms_probe::take();
    let exited = result.expect("a genuinely-terminated child must not report a wait failure");
    child.wait().expect("reap the child after it exits");
    assert!(
        exited,
        "must report exited once the child genuinely exits, not falsely conclude still-alive \
         at the clamp"
    );
    assert!(
        probed.len() >= 2,
        "a 5ms-clamped wait must re-arm (>=2 recorded arms) before the real exit event, got {}",
        probed.len()
    );
    for (ms, remaining) in &probed {
        assert_eq!(
            *ms,
            expected_ms_unclamped(*remaining).min(5),
            "every armed ms must equal exactly min(ceil_millis(remaining), clamp)"
        );
    }
    for pair in probed.windows(2) {
        assert!(
            pair[1].1 < pair[0].1,
            "remaining must strictly decrease across re-arms (recomputed fresh, not hoisted \
             out of the loop and reused): {:?} then {:?}",
            pair[0],
            pair[1]
        );
    }
}

// block_until_exit_or_cancel (site 2) ==================================================

/// Same ceiling-exactness property as `block_until_exit`, for the grace-and-cancel wait.
///
/// Mutant: revert the ceiling conversion (inside `win32_timeout_ms`) back to `d.as_millis()`
/// -> fails: 500µs would floor to `0`. Mutant: add slack -> fails the exact-equality check.
#[test]
fn block_until_exit_or_cancel_arms_the_ceiling_of_the_remaining_duration() {
    let (child, id) = spawn_never_exiting();
    let cancel = super::new_cancel_event().expect("create cancel event");
    wait_ms_probe::take();
    let _override = remaining_override_seam::set(Duration::from_micros(500));
    let result = super::block_until_exit_or_cancel(id, Some(Duration::from_millis(5)), &cancel);
    let probed = wait_ms_probe::take();
    let_child_exit(child);
    result.expect("a live never-exiting child must not report a wait failure");
    let &(first_ms, first_remaining) = probed
        .first()
        .expect("expected at least one recorded (ms, remaining) pair");
    assert_eq!(first_remaining, Duration::from_micros(500));
    assert_eq!(
        first_ms, 1,
        "500µs must ceil to 1ms exactly (not truncate to 0, not slack up to >1); got ms={first_ms}"
    );
}

/// Never-early for the grace-and-cancel wait, the same way
/// `block_until_exit_never_reports_still_alive_before_the_deadline` proves it for
/// `block_until_exit`: an early, UN-clamped `WAIT_TIMEOUT` (forced via `remaining_override_seam`)
/// must never be trusted, regardless of whether this specific arm happened to be clamped. Ending
/// the wait via `cancel` is NOT used here to distinguish "genuinely resolved" from "wrongly
/// trusted the early timeout": both a real cancel and a real timeout collapse to the SAME
/// `Ok(false)` return, so they would not be observably different. Closing the fixture's stdin
/// (an `Ok(true)`, unambiguous) is used instead, exactly as at site 1.
///
/// Mutant: trust an un-clamped `WAIT_TIMEOUT` outright -> fails: returns after the first arm,
/// `probed.len() == 1`, result wrongly claims "still alive" hours before the real deadline.
#[test]
fn block_until_exit_or_cancel_never_reports_still_alive_before_the_deadline() {
    let (mut child, id) = spawn_never_exiting();
    let stdin = child.stdin.take().expect("piped stdin");
    let cancel = super::new_cancel_event().expect("create cancel event");
    wait_ms_probe::take();
    let _override = remaining_override_seam::set(Duration::from_micros(500));
    wait_ms_probe::on_second_arm(move || drop(stdin));
    let grace = Duration::from_secs(3600); // hours off: nowhere near expiry
    let result = super::block_until_exit_or_cancel(id, Some(grace), &cancel);
    let probed = wait_ms_probe::take();
    let exited = result.expect("a genuinely-terminated child must not report a wait failure");
    child.wait().expect("reap the child after it exits");
    assert!(
        exited,
        "must report exited once the child genuinely exits, not falsely conclude still-alive \
         from an early, un-clamped WAIT_TIMEOUT"
    );
    assert!(
        probed.len() >= 2,
        "must re-arm past the first (forced-early, un-clamped) WAIT_TIMEOUT rather than \
         trusting it outright, got {} arm(s)",
        probed.len()
    );
}

/// Re-arm past a REAL clamp for the grace-and-cancel wait, the same way
/// `block_until_exit_re_arms_past_a_clamped_timeout` proves it for `block_until_exit`: a tiny
/// 5ms clamp against an hours-away grace, ended deterministically by a real exit event rather
/// than a fixed real-clock window.
///
/// Mutant: remove the recheck-and-loop -> fails deterministically the same way.
/// Mutant: hoist `remaining` above the loop -> fails the strictly-decreasing check.
#[test]
fn block_until_exit_or_cancel_re_arms_past_a_clamped_timeout() {
    let (mut child, id) = spawn_never_exiting();
    let stdin = child.stdin.take().expect("piped stdin");
    let cancel = super::new_cancel_event().expect("create cancel event");
    wait_ms_probe::take();
    let _clamp = wait_clamp_seam::set(5);
    wait_ms_probe::on_second_arm(move || drop(stdin));
    let grace = Duration::from_secs(3600); // hours off: always clamped
    let result = super::block_until_exit_or_cancel(id, Some(grace), &cancel);
    let probed = wait_ms_probe::take();
    let exited = result.expect("a genuinely-terminated child must not report a wait failure");
    child.wait().expect("reap the child after it exits");
    assert!(
        exited,
        "must report exited once the child genuinely exits, not falsely conclude still-alive \
         at the clamp"
    );
    assert!(
        probed.len() >= 2,
        "a 5ms-clamped wait must re-arm (>=2 recorded arms) before the real exit event, got {}",
        probed.len()
    );
    for (ms, remaining) in &probed {
        assert_eq!(
            *ms,
            expected_ms_unclamped(*remaining).min(5),
            "every armed ms must equal exactly min(ceil_millis(remaining), clamp)"
        );
    }
    for pair in probed.windows(2) {
        assert!(
            pair[1].1 < pair[0].1,
            "remaining must strictly decrease across re-arms (recomputed fresh, not hoisted \
             out of the loop and reused): {:?} then {:?}",
            pair[0],
            pair[1]
        );
    }
}
