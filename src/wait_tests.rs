use super::{deadline_from, instant_near_ceiling, remaining, test_clock};
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
