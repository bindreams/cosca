//! Deadline contract for `block_until_exit` and `block_until_exit_or_cancel`: never report
//! "still alive" before the real deadline. Seams are documented in `crate::wait`.

use std::os::windows::io::AsRawHandle;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::HANDLE;

use crate::identity::ProcessId;
use crate::wait::test_clock::FrozenClockGuard;
use crate::wait::wait_ms_probe;
use crate::wait::{remaining_override_seam, wait_clamp_seam};

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

// block_until_exit =====

/// A never-exiting target armed with a sub-millisecond remainder rounds up to 1ms, still reports
/// alive at the deadline, and derives its argument from the site's own deadline.
///
/// Mutant: truncate in `win32_timeout_ms` (`d.as_millis()`) -> `ms` is 0. Mutant: add slack ->
/// `ms` is above 1. Mutant: ignore the site's deadline -> `requested` is not 5ms.
#[test]
fn block_until_exit_arms_the_ceiling_of_the_remaining_duration() {
    let (child, id) = spawn_never_exiting();
    let (_clock, at) = FrozenClockGuard::install();
    wait_ms_probe::take();
    let _override = remaining_override_seam::set(Duration::from_micros(500));
    let deadline = at + Duration::from_millis(5);
    let result = super::block_until_exit(id, Some(Some(deadline)));
    let reached = Instant::now() >= deadline;
    let arms = wait_ms_probe::take();
    let_child_exit(child);
    assert!(
        !result.expect("a live never-exiting child must not report a wait failure"),
        "a never-exiting child is still alive at the deadline"
    );
    assert!(reached, "the call returned before the real deadline");
    let first = arms.first().expect("at least one armed wait");
    assert_eq!(first.remaining, Duration::from_micros(500));
    assert_eq!(first.ms, 1);
    assert_eq!(
        first.requested,
        Duration::from_millis(5),
        "the site must pass the time left to its own deadline (clock frozen at the deadline's origin)"
    );
}

/// An early, unclamped `WAIT_TIMEOUT` hours before the deadline is not trusted: the site re-arms.
///
/// Mutant: return on the first `WAIT_TIMEOUT` (no recheck, or one conditioned on the clamp) ->
/// one arm, wrongly reports alive.
#[test]
fn block_until_exit_never_reports_still_alive_before_the_deadline() {
    let (mut child, id) = spawn_never_exiting();
    let stdin = child.stdin.take().expect("piped stdin");
    wait_ms_probe::take();
    let _override = remaining_override_seam::set(Duration::from_micros(500));
    wait_ms_probe::on_second_arm(move || drop(stdin)); // EOF -> `cmd /C more` exits for real
    let deadline = Instant::now() + Duration::from_secs(3600);
    let result = super::block_until_exit(id, Some(Some(deadline)));
    let arms = wait_ms_probe::take();
    let exited = result.expect("a genuinely-terminated child must not report a wait failure");
    child.wait().expect("reap the child after it exits");
    assert!(exited, "an early WAIT_TIMEOUT was trusted");
    assert!(arms.len() >= 2, "expected a re-arm, got {} arm(s)", arms.len());
}

/// A wait clamped below the deadline re-arms, recomputing `remaining` each round.
///
/// Mutant: drop the re-arm loop -> one arm, wrongly reports alive. Mutant: hoist `remaining`
/// above the loop -> `remaining` does not shrink.
#[test]
fn block_until_exit_re_arms_past_a_clamped_timeout() {
    let (mut child, id) = spawn_never_exiting();
    let stdin = child.stdin.take().expect("piped stdin");
    wait_ms_probe::take();
    let _clamp = wait_clamp_seam::set(5);
    wait_ms_probe::on_second_arm(move || drop(stdin));
    let deadline = Instant::now() + Duration::from_secs(3600);
    let result = super::block_until_exit(id, Some(Some(deadline)));
    let arms = wait_ms_probe::take();
    let exited = result.expect("a genuinely-terminated child must not report a wait failure");
    child.wait().expect("reap the child after it exits");
    assert!(exited, "a clamped WAIT_TIMEOUT was trusted");
    wait_ms_probe::assert_rearmed_with_fresh_remaining(&arms, 5);
}

/// Under a frozen test clock a finite deadline still ends: each real wait advances the clock.
///
/// Mutant: drop `advance_by_elapsed_if_frozen` from `wait_until` -> `remaining` never shrinks
/// and the call re-arms forever.
#[test]
fn block_until_exit_terminates_under_a_frozen_clock() {
    let (child, id) = spawn_never_exiting();
    let (_clock, at) = FrozenClockGuard::install();
    let deadline = at + Duration::from_millis(50);
    let result = super::block_until_exit(id, Some(Some(deadline)));
    let reached = Instant::now() >= deadline;
    let_child_exit(child);
    assert!(!result.expect("a live never-exiting child must not report a wait failure"));
    assert!(reached, "the call returned before the real deadline");
}

// block_until_exit_or_cancel =====

/// Same as `block_until_exit_arms_the_ceiling_of_the_remaining_duration`, for the grace wait.
///
/// Mutant: truncate in `win32_timeout_ms` -> `ms` is 0. Mutant: add slack -> `ms` is above 1.
/// Mutant: ignore the site's grace -> `requested` is not 5ms.
#[test]
fn block_until_exit_or_cancel_arms_the_ceiling_of_the_remaining_duration() {
    let (child, id) = spawn_never_exiting();
    let cancel = super::new_cancel_event().expect("create cancel event");
    let (_clock, at) = FrozenClockGuard::install();
    wait_ms_probe::take();
    let _override = remaining_override_seam::set(Duration::from_micros(500));
    let deadline = at + Duration::from_millis(5);
    let result = super::block_until_exit_or_cancel(id, Some(Some(deadline)), &cancel);
    let reached = Instant::now() >= deadline;
    let arms = wait_ms_probe::take();
    let_child_exit(child);
    assert!(
        !result.expect("a live never-exiting child must not report a wait failure"),
        "a never-exiting child is still alive when the grace elapses"
    );
    assert!(reached, "the call returned before the real deadline");
    let first = arms.first().expect("at least one armed wait");
    assert_eq!(first.remaining, Duration::from_micros(500));
    assert_eq!(first.ms, 1);
    assert_eq!(
        first.requested,
        Duration::from_millis(5),
        "the site must pass the time left to its own grace (clock frozen at the grace's origin)"
    );
}

/// An early, unclamped `WAIT_TIMEOUT` hours before the grace ends is not trusted: the site
/// re-arms. Exit (`Ok(true)`) proves it, since a cancel or a timeout would both read `Ok(false)`.
///
/// Mutant: return on the first `WAIT_TIMEOUT` -> one arm, wrongly reports alive.
#[test]
fn block_until_exit_or_cancel_never_reports_still_alive_before_the_deadline() {
    let (mut child, id) = spawn_never_exiting();
    let stdin = child.stdin.take().expect("piped stdin");
    let cancel = super::new_cancel_event().expect("create cancel event");
    wait_ms_probe::take();
    let _override = remaining_override_seam::set(Duration::from_micros(500));
    wait_ms_probe::on_second_arm(move || drop(stdin));
    let deadline = crate::wait::deadline_from(Duration::from_secs(3600));
    let result = super::block_until_exit_or_cancel(id, deadline, &cancel);
    let arms = wait_ms_probe::take();
    let exited = result.expect("a genuinely-terminated child must not report a wait failure");
    child.wait().expect("reap the child after it exits");
    assert!(exited, "an early WAIT_TIMEOUT was trusted");
    assert!(arms.len() >= 2, "expected a re-arm, got {} arm(s)", arms.len());
}

/// A wait clamped below the grace re-arms, recomputing `remaining` each round.
///
/// Mutant: drop the re-arm loop -> one arm, wrongly reports alive. Mutant: hoist `remaining`
/// above the loop -> `remaining` does not shrink.
#[test]
fn block_until_exit_or_cancel_re_arms_past_a_clamped_timeout() {
    let (mut child, id) = spawn_never_exiting();
    let stdin = child.stdin.take().expect("piped stdin");
    let cancel = super::new_cancel_event().expect("create cancel event");
    wait_ms_probe::take();
    let _clamp = wait_clamp_seam::set(5);
    wait_ms_probe::on_second_arm(move || drop(stdin));
    let deadline = crate::wait::deadline_from(Duration::from_secs(3600));
    let result = super::block_until_exit_or_cancel(id, deadline, &cancel);
    let arms = wait_ms_probe::take();
    let exited = result.expect("a genuinely-terminated child must not report a wait failure");
    child.wait().expect("reap the child after it exits");
    assert!(exited, "a clamped WAIT_TIMEOUT was trusted");
    wait_ms_probe::assert_rearmed_with_fresh_remaining(&arms, 5);
}
