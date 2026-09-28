use super::{ceil_millis, deadline_from, instant_near_ceiling, remaining};
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

// `ceil_millis` is the fix for the "deadline windows never early" bug (owner-confirmed,
// docs/principles.md #13, not yet merged as of this PR): the three Windows wait sites
// (`block_until_exit`, `block_until_exit_or_cancel`, `wait_drained_raw`) converted a
// remaining `Duration` to a Win32 millisecond timeout with `.as_millis()`, which TRUNCATES.
// A 500µs remainder truncated to `ms = 0`, arming a non-blocking poll that could report
// "timed out" before the real deadline. These tests pin the ceiling behaviour these sites now
// rely on, independent of any OS call — the math itself is portable.
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
