use super::{
    ceil_millis, deadline_from, instant_near_ceiling, remaining, remaining_override_seam, test_clock, wait_clamp_seam,
    win32_timeout_ms,
};
use std::time::{Duration, Instant};

#[test]
fn remaining_unbounded_and_overflow_are_none() {
    assert_eq!(remaining(None), None);
    assert_eq!(remaining(Some(None)), None);
}

#[test]
fn remaining_past_deadline_saturates_to_zero() {
    let past = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
    assert_eq!(remaining(Some(Some(past))), Some(Duration::ZERO));
}

/// A deadline within tokio's own ~1ms round-up margin of `Instant`'s ceiling must saturate to
/// unbounded, not reach a primitive whose own margin arithmetic overflows on it.
#[test]
fn deadline_from_saturates_when_the_result_is_too_close_to_instants_ceiling() {
    let now = Instant::now();
    // 500µs short of the true ceiling (found from `now`): comfortably more than the time this
    // test takes to reach `deadline_from`'s own `Instant::now()` call, so that call's own
    // `checked_add` still succeeds — landing well within the 1ms margin this exercises, not
    // overflowing outright before ever reaching it.
    let duration = instant_near_ceiling(now).saturating_duration_since(now) - Duration::from_micros(500);
    assert_eq!(deadline_from(duration), Some(None));
}

/// Pins `remaining`'s ZERO boundary exactly, via the frozen test clock rather than a real one:
/// 250ms remaining a full 250ms before the deadline, exactly ZERO at the deadline itself (never
/// early), and still (just barely) above zero one nanosecond before it.
#[test]
fn remaining_pins_the_exact_zero_boundary() {
    let (_guard, t0) = test_clock::FrozenClockGuard::install();
    let at = t0 + Duration::from_millis(250);
    let deadline = Some(Some(at));

    assert_eq!(remaining(deadline), Some(Duration::from_millis(250)));
    test_clock::advance(Duration::from_millis(250) - Duration::from_nanos(1));
    assert_eq!(remaining(deadline), Some(Duration::from_nanos(1)));
    test_clock::advance(Duration::from_nanos(1));
    assert_eq!(remaining(deadline), Some(Duration::ZERO));
}

// `ceil_millis` and `win32_timeout_ms` are the fix for the "deadline windows never early" bug
// (owner-confirmed, docs/principles.md #13): four
// Windows wait sites converted a remaining `Duration` to a Win32 millisecond timeout by
// TRUNCATING — `.as_millis()` at `block_until_exit`, `block_until_exit_or_cancel`,
// `wait_drained_raw`; `u32::try_from(remaining.as_millis())` at `RawChild::wait_deadline`,
// which additionally could succeed for a value equal to the `INFINITE` sentinel itself. A
// 500µs remainder truncated to `ms = 0`, arming a non-blocking poll — at the first three sites,
// which (before this PR) trusted ANY `WAIT_TIMEOUT` outright with no recheck at all, that meant
// an early "timed out" report; at the fourth site, whose loop already rechecked the real
// deadline on every `WAIT_TIMEOUT` before this PR, it meant a busy-spin of redundant zero-ms
// polls instead (wasteful, not early — see `RawChild::wait_deadline`'s doc). A remaining-ms
// value of exactly `u32::MAX` truncate-converted (at the fourth site only) to an
// accidentally-unbounded wait. These tests pin the fixed behaviour these sites now rely on,
// independent of any OS call — the math itself is portable.
//
// Mutant: revert `ceil_millis` to `d.as_millis()` (the original truncating expression) →
// `ceil_millis_rounds_up_sub_millisecond_remainders` fails (`500µs` would floor to `0`, not
// ceil to `1`).
#[test]
fn ceil_millis_rounds_up_sub_millisecond_remainders() {
    assert_eq!(ceil_millis(Duration::from_nanos(1)), 1);
    assert_eq!(ceil_millis(Duration::from_micros(500)), 1);
    assert_eq!(ceil_millis(Duration::from_micros(999)), 1);
    assert_eq!(ceil_millis(Duration::from_micros(1500)), 2);
    assert_eq!(ceil_millis(Duration::from_micros(2001)), 3);
}

#[test]
fn ceil_millis_zero_stays_zero() {
    // A zero-remaining deadline ceils to a genuine zero-timeout poll, not a wait — ceiling
    // does not turn "already past" into "wait a bit longer".
    assert_eq!(ceil_millis(Duration::ZERO), 0);
}

#[test]
fn ceil_millis_whole_milliseconds_are_unchanged() {
    assert_eq!(ceil_millis(Duration::from_millis(1)), 1);
    assert_eq!(ceil_millis(Duration::from_millis(7)), 7);
    assert_eq!(ceil_millis(Duration::from_secs(3)), 3_000);
}

#[test]
fn win32_timeout_ms_unbounded_is_the_win32_infinite_sentinel() {
    assert_eq!(win32_timeout_ms(None), u32::MAX);
}

#[test]
fn win32_timeout_ms_ceils_rather_than_truncates() {
    assert_eq!(win32_timeout_ms(Some(Duration::from_micros(500))), 1);
    assert_eq!(win32_timeout_ms(Some(Duration::ZERO)), 0);
    assert_eq!(win32_timeout_ms(Some(Duration::from_millis(7))), 7);
}

/// The bug at the fourth site (`RawChild::wait_deadline`, pre-fix):
/// `u32::try_from(remaining.as_millis()).unwrap_or(INFINITE - 1)` — `try_from` SUCCEEDS for a
/// remaining-ms value of exactly `u32::MAX`, since that value fits in a `u32`. The result is
/// `u32::MAX`, which IS the Win32 `INFINITE` sentinel: a finite, ~49.7-day deadline would
/// silently become an unbounded wait instead of timing out. `win32_timeout_ms` must never
/// produce `u32::MAX` for a `Some` (finite) input, at ANY input value — not just realistic
/// ones — which its own `.min(clamp)` structurally guarantees (clamp is always
/// `u32::MAX - 1` or smaller), backed by a `debug_assert!` in the function itself.
///
/// Mutant: drop the `.min(clamp)` clamp from `win32_timeout_ms` (or otherwise let `ms` pass
/// through un-clamped) -> fails: `win32_timeout_ms(Some(u32::MAX as u64 milliseconds))` would
/// return `u32::MAX` (`INFINITE`) instead of `u32::MAX - 1`.
#[test]
fn win32_timeout_ms_never_returns_the_infinite_sentinel_for_a_finite_remaining() {
    let huge = Duration::from_millis(u64::from(u32::MAX));
    let ms = win32_timeout_ms(Some(huge));
    assert_ne!(
        ms,
        u32::MAX,
        "a finite remaining must never collide with the INFINITE sentinel"
    );
    assert_eq!(
        ms,
        u32::MAX - 1,
        "must clamp to the production cap, not silently truncate"
    );
}

#[test]
fn win32_timeout_ms_honors_the_clamp_seam() {
    let guard = wait_clamp_seam::set(5);
    assert_eq!(win32_timeout_ms(Some(Duration::from_secs(1))), 5);
    drop(guard);
    // Restored: no longer clamped to the tiny test value.
    assert_eq!(win32_timeout_ms(Some(Duration::from_millis(3))), 3);
}

/// `remaining_override_seam` is itself test infrastructure other tests rely on for
/// determinism (see `wait/windows_tests.rs`, `containment/windows_tests.rs`,
/// `child/spawn/windows_raw/proc_tests.rs`) — pin its single-use, take-once contract here,
/// portably, once.
#[test]
fn remaining_override_seam_is_consumed_exactly_once() {
    let guard = remaining_override_seam::set(Duration::from_millis(3));
    assert_eq!(
        win32_timeout_ms(Some(Duration::from_millis(999))),
        3,
        "the forced value must win the first call"
    );
    assert_eq!(
        win32_timeout_ms(Some(Duration::from_millis(999))),
        999,
        "the seam is single-use: the second call must see the real argument, not a stale override"
    );
    drop(guard); // already consumed above; dropping now must not panic or double-clear anything
}

/// The guard's OWN job, independent of consumption: an override that is armed but never
/// consumed (e.g. a test that panics before the call it was meant for) must not leak onto a
/// later test sharing this thread — the guard clears it on drop.
#[test]
fn remaining_override_seam_guard_clears_an_unconsumed_override_on_drop() {
    let guard = remaining_override_seam::set(Duration::from_millis(3));
    drop(guard); // never consumed by a `win32_timeout_ms` call
    assert_eq!(
        win32_timeout_ms(Some(Duration::from_millis(999))),
        999,
        "a dropped, unconsumed guard must have cleared the override"
    );
}
