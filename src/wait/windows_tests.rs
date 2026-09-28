//! Deadline-contract tests for the two Windows wait sites in this file (`block_until_exit`,
//! `block_until_exit_or_cancel`): never report "still alive" before the caller's real
//! deadline. See docs/principles.md #13 (the deadline contract, landing separately in #233)
//! and the "deadline-windows-never-early" bug this PR fixes.
//!
//! Every test here uses one of two seams from `crate::wait` instead of racing the wall clock:
//! - `wait_ms_probe` records the exact `(ms, remaining)` pair a call site armed a wait with,
//!   so the ceiling relationship (`ms` in whole milliseconds >= `remaining`) can be checked
//!   structurally — this is immune to OS/syscall jitter, unlike asserting on wall-clock timing
//!   directly.
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
use crate::wait::{wait_clamp_seam, wait_ms_probe};

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

// block_until_exit (site 1) ============================================================

/// Ceiling, not truncation: every `(ms, remaining)` pair `block_until_exit` arms a wait with
/// must satisfy `ms milliseconds >= remaining` — a truncating floor would sometimes arm LESS
/// time than is genuinely left, which is exactly an early report.
///
/// Mutant: revert the ceiling conversion at this call site back to the original truncating
/// `d.as_millis()` -> fails whenever `remaining` has a nonzero sub-millisecond remainder,
/// which any real wall-clock deadline has with overwhelming probability (landing on an exact
/// millisecond boundary is a measure-zero event).
#[test]
fn block_until_exit_arms_the_ceiling_of_the_remaining_duration() {
    let (child, id) = spawn_never_exiting();
    wait_ms_probe::take(); // clear any residue from a prior test on this thread
    let deadline = Instant::now() + Duration::from_millis(5);
    let result = super::block_until_exit(id, Some(Some(deadline)));
    let probed = wait_ms_probe::take();
    let_child_exit(child);
    result.expect("a live never-exiting child must not report a wait failure");
    assert!(
        !probed.is_empty(),
        "expected at least one recorded (ms, remaining) pair"
    );
    for (ms, remaining) in &probed {
        let armed = Duration::from_millis(u64::from(*ms));
        assert!(
            armed >= *remaining,
            "ms={ms} (={armed:?}) must be >= the measured remaining {remaining:?} — a \
             truncating floor would arm less time than is actually left, an early report"
        );
    }
}

/// Never-early, the deadline contract's core promise: once `block_until_exit` reports "still
/// alive" against a deadline, the real clock must already be at or past that deadline. No
/// upper bound on elapsed time is asserted anywhere in this file — only this lower bound.
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

/// The recheck loop's OTHER job: a wait capped below the real deadline (in production, the
/// `INFINITE - 1` / ~49.7-day clamp) must not be trusted as proof the deadline passed — the
/// loop must re-arm and keep waiting. `wait_clamp_seam` substitutes a tiny clamp for the real
/// one so this is provable in milliseconds, not days.
///
/// Mutant: remove the recheck-and-loop (always return on the first `WAIT_TIMEOUT`) -> fails
/// deterministically: the wait would report "still alive" after only the clamped interval (a
/// few ms), long before the real (200ms) deadline.
#[test]
fn block_until_exit_re_arms_past_a_clamped_timeout() {
    let (child, id) = spawn_never_exiting();
    wait_clamp_seam::set(Some(5)); // every armed wait capped to 5ms, far below the real deadline
    let deadline = Instant::now() + Duration::from_millis(200);
    let result = super::block_until_exit(id, Some(Some(deadline)));
    wait_clamp_seam::set(None); // restore the production default for any later test
    let_child_exit(child);
    let alive = result.expect("a live never-exiting child must not report a wait failure");
    assert!(!alive, "a never-exiting child must not be reported as exited");
    assert!(
        Instant::now() >= deadline,
        "a clamped wait must re-arm and keep waiting, not report still-alive at the clamp"
    );
}

// block_until_exit_or_cancel (site 2) ==================================================

/// Same ceiling property as `block_until_exit`, for the grace-and-cancel wait.
///
/// Mutant: revert the ceiling conversion at this call site back to `d.as_millis()` -> fails
/// whenever `remaining` has a nonzero sub-millisecond remainder.
#[test]
fn block_until_exit_or_cancel_arms_the_ceiling_of_the_remaining_duration() {
    let (child, id) = spawn_never_exiting();
    let cancel = super::new_cancel_event().expect("create cancel event");
    wait_ms_probe::take();
    let result = super::block_until_exit_or_cancel(id, Some(Duration::from_millis(5)), &cancel);
    let probed = wait_ms_probe::take();
    let_child_exit(child);
    result.expect("a live never-exiting child must not report a wait failure");
    assert!(
        !probed.is_empty(),
        "expected at least one recorded (ms, remaining) pair"
    );
    for (ms, remaining) in &probed {
        let armed = Duration::from_millis(u64::from(*ms));
        assert!(
            armed >= *remaining,
            "ms={ms} (={armed:?}) must be >= the measured remaining {remaining:?} — a \
             truncating floor would arm less time than is actually left, an early report"
        );
    }
}

/// Never-early for the grace-and-cancel wait: once it reports "still alive" (`Ok(false)`)
/// against a `grace`, the real clock must already be at or past the deadline that `grace`
/// implies (established at function entry, mirroring `block_until_exit`'s convention).
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
/// `block_until_exit_re_arms_past_a_clamped_timeout` proves it for `block_until_exit`.
///
/// Mutant: remove the recheck-and-loop -> fails deterministically the same way.
#[test]
fn block_until_exit_or_cancel_re_arms_past_a_clamped_timeout() {
    let (child, id) = spawn_never_exiting();
    let cancel = super::new_cancel_event().expect("create cancel event");
    wait_clamp_seam::set(Some(5));
    let before = Instant::now();
    let grace = Duration::from_millis(200);
    let result = super::block_until_exit_or_cancel(id, Some(grace), &cancel);
    wait_clamp_seam::set(None);
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
}
