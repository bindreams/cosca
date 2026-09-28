//! Deadline-contract tests for the two Windows wait sites in this file (`block_until_exit`,
//! `block_until_exit_or_cancel`): never report "still alive" before the caller's real
//! deadline. See docs/principles.md #13 (the deadline contract; PR #233, not yet merged) and
//! the "deadline-windows-never-early" bug this PR fixes.
//!
//! Every test here uses one or more of three seams from `crate::wait` instead of racing the
//! wall clock:
//! - `remaining_override_seam` forces a specific `remaining` duration (e.g. a sub-millisecond
//!   one) into the NEXT `win32_timeout_ms` call, so a ceiling-vs-truncation divergence is
//!   provable from the recorded `ms` alone — deterministically, not by racing real
//!   OS-clock/scheduler jitter to land on a sub-millisecond remainder (real Windows wait-timer
//!   coarseness can otherwise mask the divergence entirely; this is how an earlier, unfixed
//!   version of `block_until_exit_or_cancel_arms_the_ceiling_of_the_remaining_duration` passed
//!   against genuinely truncating code — see this PR's description).
//! - `wait_ms_probe` records the exact `(ms, remaining)` pair a call site armed a wait with, so
//!   a test can assert `ms == min(ceil_millis(remaining), clamp)` exactly (not merely
//!   `ms >= remaining`, which a slack-adding regression like `ceil_millis(d) + 1` would still
//!   satisfy), and that a clamped-and-re-armed wait's successive `remaining` values strictly
//!   decrease (proving `remaining` is recomputed FRESH every loop iteration, never hoisted out
//!   and reused stale).
//! - `wait_clamp_seam` overrides the `INFINITE - 1` (~49.7 day) clamp with a tiny value, so the
//!   "a capped wait elapsed before the real deadline, so re-arm rather than report" path is
//!   exercised in milliseconds instead of actually waiting 49.7 days.
//!
//! No test here asserts an UPPER bound on elapsed time — only ever a lower bound
//! (`Instant::now() >= deadline`), per the deadline contract and this repo's global rule
//! against synchronizing on time.

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
    remaining_override_seam::set(Duration::from_micros(500)); // sub-ms: ceils to 1, floors to 0
    let deadline = Instant::now() + Duration::from_millis(5);
    let result = super::block_until_exit(id, Some(Some(deadline)));
    let probed = wait_ms_probe::take();
    remaining_override_seam::take(); // defensive: consume any unused override before it leaks
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

/// Never-early, the deadline contract's core promise: once `block_until_exit` reports "still
/// alive" against a deadline, the real clock must already be at or past that deadline. No
/// upper bound on elapsed time is asserted anywhere in this file — only this lower bound.
///
/// This is an end-to-end regression check for the ORIGINAL bug (both the truncating `ms` and
/// the single-shot, no-recheck wait together — see this PR's description for why a ceiling fix
/// or a recheck-loop fix ALONE, with the other already in place, does not make this assertion
/// fail on its own): it does not pin a single-line mutant distinct from
/// `block_until_exit_arms_the_ceiling_of_the_remaining_duration` (the ceiling, provable
/// deterministically via the seam) and `block_until_exit_re_arms_past_a_clamped_timeout` (the
/// recheck loop, provable deterministically via `wait_clamp_seam`) below.
#[test]
fn block_until_exit_never_reports_still_alive_before_the_deadline() {
    let (child, id) = spawn_never_exiting();
    let deadline = Instant::now() + Duration::from_millis(5);
    let result = super::block_until_exit(id, Some(Some(deadline)));
    let_child_exit(child);
    let alive = result.expect("a live never-exiting child must not report a wait failure");
    assert!(!alive, "a never-exiting child must not be reported as exited");
    assert!(
        Instant::now() >= deadline,
        "reported still-alive strictly before the deadline actually passed"
    );
}

/// The recheck loop's job: a wait capped below the real deadline (in production, the
/// `INFINITE - 1` / ~49.7-day clamp) must not be trusted as proof the deadline passed — the
/// loop must re-arm and keep waiting, recomputing `remaining` FRESH every iteration (never
/// hoisting it out of the loop and reusing a stale value). `wait_clamp_seam` substitutes a
/// tiny clamp for the real one so this is provable in milliseconds, not days.
///
/// Mutant: remove the recheck-and-loop (always return/break on the first `WAIT_TIMEOUT`) ->
/// fails deterministically: the wait would report "still alive" after only the clamped
/// interval (a few ms), long before the real (200ms) deadline, AND only one `(ms, remaining)`
/// pair would be recorded.
/// Mutant: hoist `crate::wait::remaining(deadline)` above the loop and reuse it every iteration
/// -> fails the strictly-decreasing-`remaining` assertion below (every recorded `remaining`
/// would be identical, not shrinking).
#[test]
fn block_until_exit_re_arms_past_a_clamped_timeout() {
    let (child, id) = spawn_never_exiting();
    wait_ms_probe::take();
    wait_clamp_seam::set(Some(5)); // every armed wait capped to 5ms, far below the real deadline
    let deadline = Instant::now() + Duration::from_millis(200);
    let result = super::block_until_exit(id, Some(Some(deadline)));
    wait_clamp_seam::set(None); // restore the production default for any later test
    let probed = wait_ms_probe::take();
    let_child_exit(child);
    let alive = result.expect("a live never-exiting child must not report a wait failure");
    assert!(!alive, "a never-exiting child must not be reported as exited");
    assert!(
        Instant::now() >= deadline,
        "a clamped wait must re-arm and keep waiting, not report still-alive at the clamp"
    );
    assert!(
        probed.len() >= 2,
        "a 5ms-clamped wait against a 200ms deadline must re-arm (>=2 recorded arms), got {}",
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
    remaining_override_seam::set(Duration::from_micros(500));
    let result = super::block_until_exit_or_cancel(id, Some(Duration::from_millis(5)), &cancel);
    let probed = wait_ms_probe::take();
    remaining_override_seam::take();
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

/// Never-early for the grace-and-cancel wait: once it reports "still alive" (`Ok(false)`)
/// against a `grace`, the real clock must already be at or past the deadline that `grace`
/// implies (established at function entry, mirroring `block_until_exit`'s convention). Like
/// `block_until_exit_never_reports_still_alive_before_the_deadline` above, this is an
/// end-to-end regression check for the ORIGINAL bug as a whole, not a distinct single-line
/// mutant beyond the ceiling and recheck-loop tests in this file.
#[test]
fn block_until_exit_or_cancel_never_reports_still_alive_before_the_deadline() {
    let (child, id) = spawn_never_exiting();
    let cancel = super::new_cancel_event().expect("create cancel event");
    let before = Instant::now();
    let grace = Duration::from_millis(5);
    let result = super::block_until_exit_or_cancel(id, Some(grace), &cancel);
    let_child_exit(child);
    let alive = result.expect("a live never-exiting child must not report a wait failure");
    assert!(
        !alive,
        "a never-exiting, never-cancelled child must not be reported as exited"
    );
    // The deadline is established at function entry from `grace`; `before` predates that
    // entry, so `before + grace` is an earlier (i.e. safe, conservative) stand-in for it —
    // asserting against it only makes the "never early" check STRICTER, never weaker.
    assert!(
        Instant::now() >= before + grace,
        "reported still-alive strictly before the grace-derived deadline actually passed"
    );
}

/// Re-arm past a clamped timeout for the grace-and-cancel wait, the same way
/// `block_until_exit_re_arms_past_a_clamped_timeout` proves it for `block_until_exit`,
/// including the strictly-decreasing-`remaining` check that catches a hoisted-above-the-loop
/// regression.
///
/// Mutant: remove the recheck-and-loop -> fails deterministically the same way.
/// Mutant: hoist `remaining` above the loop -> fails the strictly-decreasing check.
#[test]
fn block_until_exit_or_cancel_re_arms_past_a_clamped_timeout() {
    let (child, id) = spawn_never_exiting();
    let cancel = super::new_cancel_event().expect("create cancel event");
    wait_ms_probe::take();
    wait_clamp_seam::set(Some(5));
    let before = Instant::now();
    let grace = Duration::from_millis(200);
    let result = super::block_until_exit_or_cancel(id, Some(grace), &cancel);
    wait_clamp_seam::set(None);
    let probed = wait_ms_probe::take();
    let_child_exit(child);
    let alive = result.expect("a live never-exiting child must not report a wait failure");
    assert!(
        !alive,
        "a never-exiting, never-cancelled child must not be reported as exited"
    );
    assert!(
        Instant::now() >= before + grace,
        "a clamped wait must re-arm and keep waiting, not report still-alive at the clamp"
    );
    assert!(
        probed.len() >= 2,
        "a 5ms-clamped wait against a 200ms grace must re-arm (>=2 recorded arms), got {}",
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
