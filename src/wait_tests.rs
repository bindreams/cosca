use super::{
    ceil_millis, clears_tokio_timer_margin, deadline_at, deadline_from, instant_near_ceiling, rearm_until, remaining,
    remaining_override_seam, test_clock, wait_clamp_seam, wait_ms_probe, win32_timeout_ms, TOKIO_TIMER_ROUNDING_MARGIN,
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

// `ceil_millis`/`win32_timeout_ms` tests: pure and portable.

/// Mutant: `d.as_millis()` instead of ceiling -> 500us floors to 0.
#[test]
fn ceil_millis_rounds_up_sub_millisecond_remainders() {
    assert_eq!(ceil_millis(Duration::from_nanos(1)), 1);
    assert_eq!(ceil_millis(Duration::from_micros(500)), 1);
    assert_eq!(ceil_millis(Duration::from_micros(999)), 1);
    assert_eq!(ceil_millis(Duration::from_micros(1500)), 2);
    assert_eq!(ceil_millis(Duration::from_micros(2001)), 3);
}

/// A zero remainder stays a poll, not a wait.
///
/// Mutant: round zero up to 1 -> fails.
#[test]
fn ceil_millis_zero_stays_zero() {
    assert_eq!(ceil_millis(Duration::ZERO), 0);
}

/// Mutant: add a millisecond of slack -> whole milliseconds grow.
#[test]
fn ceil_millis_whole_milliseconds_are_unchanged() {
    assert_eq!(ceil_millis(Duration::from_millis(1)), 1);
    assert_eq!(ceil_millis(Duration::from_millis(7)), 7);
    assert_eq!(ceil_millis(Duration::from_secs(3)), 3_000);
}

/// Mutant: map `None` to a finite value -> an unbounded wait gets a deadline.
#[test]
fn win32_timeout_ms_unbounded_is_the_win32_infinite_sentinel() {
    assert_eq!(win32_timeout_ms(None), u32::MAX);
}

/// Mutant: truncate instead of ceiling -> 500us arms 0.
#[test]
fn win32_timeout_ms_ceils_rather_than_truncates() {
    assert_eq!(win32_timeout_ms(Some(Duration::from_micros(500))), 1);
    assert_eq!(win32_timeout_ms(Some(Duration::ZERO)), 0);
    assert_eq!(win32_timeout_ms(Some(Duration::from_millis(7))), 7);
}

/// A finite remainder never arms `INFINITE`, even at exactly `u32::MAX` ms.
///
/// Mutant: drop the clamp -> `u32::MAX` (the sentinel) instead of `u32::MAX - 1`.
#[test]
fn win32_timeout_ms_never_returns_the_infinite_sentinel_for_a_finite_remaining() {
    let ms = win32_timeout_ms(Some(Duration::from_millis(u64::from(u32::MAX))));
    assert_ne!(ms, u32::MAX);
    assert_eq!(ms, u32::MAX - 1);
}

/// Mutant: ignore the clamp seam -> the 1s remainder arms 1000, not 5.
#[test]
fn win32_timeout_ms_honors_the_clamp_seam() {
    let guard = wait_clamp_seam::set(5);
    assert_eq!(win32_timeout_ms(Some(Duration::from_secs(1))), 5);
    drop(guard);
    assert_eq!(win32_timeout_ms(Some(Duration::from_millis(3))), 3);
}

/// The override applies to exactly one call.
///
/// Mutant: leave the override armed after `take` -> the second call sees 3, not 999.
#[test]
fn remaining_override_seam_is_consumed_exactly_once() {
    let guard = remaining_override_seam::set(Duration::from_millis(3));
    assert_eq!(win32_timeout_ms(Some(Duration::from_millis(999))), 3);
    assert_eq!(win32_timeout_ms(Some(Duration::from_millis(999))), 999);
    drop(guard);
}

/// An unconsumed override does not outlive its guard.
///
/// Mutant: make the guard's `Drop` a no-op -> the stale 3 leaks into the next call.
#[test]
fn remaining_override_seam_guard_clears_an_unconsumed_override_on_drop() {
    let guard = remaining_override_seam::set(Duration::from_millis(3));
    drop(guard);
    assert_eq!(win32_timeout_ms(Some(Duration::from_millis(999))), 999);
}

/// The probe pairs what a site asked for with what was armed.
///
/// Mutant: record the overridden duration as `requested` -> `requested` is 3ms, not 999ms.
#[test]
fn wait_ms_probe_records_the_requested_remaining_beside_the_armed_one() {
    wait_ms_probe::take();
    let _override = remaining_override_seam::set(Duration::from_millis(3));
    win32_timeout_ms(Some(Duration::from_millis(999)));
    let arms = wait_ms_probe::take();
    assert_eq!(arms.len(), 1);
    assert_eq!(arms[0].ms, 3);
    assert_eq!(arms[0].remaining, Duration::from_millis(3));
    assert_eq!(arms[0].requested, Duration::from_millis(999));
}

/// `ceiling - MARGIN` clears (adding the margin lands ON
/// the ceiling, representable); one nanosecond later does not.
#[test]
fn deadline_at_passes_through_up_to_the_margin_and_is_unbounded_past_it() {
    let now = Instant::now();
    let ceiling = instant_near_ceiling(now);
    let span = ceiling.saturating_duration_since(now);

    let edge = span - TOKIO_TIMER_ROUNDING_MARGIN;
    assert_eq!(deadline_at(now, edge), Some(now + edge));
    assert_eq!(deadline_at(now, edge + Duration::from_nanos(1)), None);
    assert_eq!(deadline_at(now, span), None);
    assert_eq!(
        deadline_at(now, span + Duration::from_nanos(1)),
        None,
        "overflow itself"
    );
    assert_eq!(deadline_at(now, Duration::MAX), None);
    assert_eq!(deadline_at(now, Duration::ZERO), Some(now));
    assert_eq!(
        deadline_at(now, Duration::from_secs(1)),
        Some(now + Duration::from_secs(1))
    );
}

#[test]
fn clears_tokio_timer_margin_is_true_exactly_up_to_the_margin() {
    let ceiling = instant_near_ceiling(Instant::now());
    assert!(clears_tokio_timer_margin(ceiling - TOKIO_TIMER_ROUNDING_MARGIN));
    assert!(!clears_tokio_timer_margin(
        ceiling - TOKIO_TIMER_ROUNDING_MARGIN + Duration::from_nanos(1)
    ));
}

/// `deadline_from` is `deadline_at` on the frozen clock, wrapped in `Some`.
#[test]
fn deadline_from_applies_deadline_at_on_the_test_clock() {
    let (_guard, t0) = test_clock::FrozenClockGuard::install();
    let span = instant_near_ceiling(t0).saturating_duration_since(t0);
    let edge = span - TOKIO_TIMER_ROUNDING_MARGIN;

    assert_eq!(deadline_from(edge), Some(Some(t0 + edge)));
    assert_eq!(deadline_from(edge + Duration::from_nanos(1)), Some(None));
    assert_eq!(deadline_from(Duration::MAX), Some(None));
}

// rearm_until =====

/// Each round after a real wait sees a frozen clock that has moved on, so a finite deadline ends.
///
/// Mutant: drop the `advance_by_elapsed_if_frozen` call -> the second round sees the same instant.
#[test]
fn rearm_until_advances_the_frozen_clock_by_each_round() {
    let (_clock, at) = test_clock::FrozenClockGuard::install();
    let deadline = Some(Some(at + Duration::from_millis(30)));
    let mut previous: Option<Instant> = None;
    let out = rearm_until(deadline, |remaining| {
        let seen = super::now();
        if let Some(previous) = previous {
            assert!(seen > previous, "the frozen clock did not advance across a real wait");
        }
        previous = Some(seen);
        std::thread::park_timeout(remaining.expect("finite deadline"));
        Ok::<Option<()>, ()>(None)
    });
    assert_eq!(out, Ok(None));
}

/// Every round is armed with the frozen remaining, even when real time is ahead of the frozen
/// clock.
///
/// Mutant: derive the round's remaining from the real clock.
#[test]
fn rearm_until_hands_a_round_the_frozen_remaining() {
    let (_clock, at) = test_clock::FrozenClockGuard::install_lagging(Duration::from_secs(1));
    let deadline = Some(Some(at + Duration::from_millis(50)));
    let mut seen = None;
    let out = rearm_until(deadline, |remaining| {
        seen = Some(remaining);
        Ok::<_, ()>(Some(()))
    });
    assert_eq!(out, Ok(Some(())));
    assert_eq!(seen, Some(Some(Duration::from_millis(50))));
}

/// A deadline already past still runs one round, armed with zero, and reports its `None`.
///
/// Mutant: check `remaining` before the first round.
#[test]
fn rearm_until_polls_once_for_a_past_deadline() {
    let past = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
    let mut rounds = Vec::new();
    let out = rearm_until(Some(Some(past)), |remaining| {
        rounds.push(remaining);
        Ok::<Option<()>, ()>(None)
    });
    assert_eq!(out, Ok(None));
    assert_eq!(rounds, [Some(Duration::ZERO)]);
}

/// A round's error ends the loop at once, wherever in the loop it arrives.
///
/// Mutant: treat `Err` as `None` -> the third round runs and reports `Some`.
#[test]
fn rearm_until_stops_at_a_round_error() {
    let (_clock, at) = test_clock::FrozenClockGuard::install();
    let deadline = Some(Some(at + Duration::from_secs(3600)));
    let mut rounds = 0;
    let out = rearm_until(deadline, |_| {
        rounds += 1;
        match rounds {
            1 => Ok(None),
            2 => Err("boom"),
            _ => Ok(Some(())),
        }
    });
    assert_eq!(out, Err("boom"));
    assert_eq!(rounds, 2);
}

// RoundCheck =====

/// Two rounds with no advance between them, under a frozen clock, are a stalled re-arm.
///
/// Mutant: drop the check in `RoundCheck::round` -> no panic.
#[test]
#[should_panic(expected = "no progress")]
fn round_check_panics_on_two_rounds_without_an_advance() {
    let (_clock, _at) = test_clock::FrozenClockGuard::install();
    let mut check = test_clock::RoundCheck::new("test");
    check.round();
    check.round();
}

/// An advance call between rounds is progress even when it advanced by zero.
///
/// Mutant: bump the generation only for a nonzero elapsed -> panics here.
#[test]
fn round_check_accepts_an_advance_of_zero_between_rounds() {
    let (_clock, _at) = test_clock::FrozenClockGuard::install();
    let mut check = test_clock::RoundCheck::new("test");
    check.round();
    test_clock::advance_by_elapsed_if_frozen(Duration::ZERO);
    check.round();
    test_clock::advance_by_elapsed_if_frozen(Duration::ZERO);
    check.round();
}

/// Only the immediately previous round is compared: an advance before round two does not excuse
/// round three.
///
/// Mutant: compare against the first round's generation -> no panic.
#[test]
#[should_panic(expected = "no progress")]
fn round_check_compares_against_the_previous_round_only() {
    let (_clock, _at) = test_clock::FrozenClockGuard::install();
    let mut check = test_clock::RoundCheck::new("test");
    check.round();
    test_clock::advance_by_elapsed_if_frozen(Duration::ZERO);
    check.round();
    check.round();
}

/// An unfrozen clock advances on its own, so rounds without an advance are fine; and the clock is
/// unfrozen once its guard drops.
///
/// Mutant: ignore `is_frozen` -> panics here.
#[test]
fn round_check_ignores_an_unfrozen_clock() {
    {
        let (_clock, _at) = test_clock::FrozenClockGuard::install();
        assert!(test_clock::is_frozen());
    }
    assert!(!test_clock::is_frozen());
    let mut check = test_clock::RoundCheck::new("test");
    check.round();
    check.round();
}

/// Two waits under one frozen guard that arm the same remaining are independent.
///
/// Mutant: keep the previous round across invocations (a thread-global last round) -> the second
/// wait's first round is compared with the first wait's last.
#[test]
fn two_sequential_waits_with_the_same_remaining_do_not_trip_the_check() {
    let (_clock, at) = test_clock::FrozenClockGuard::install();
    let deadline = Some(Some(at + Duration::from_millis(50)));
    for _ in 0..2 {
        let mut rounds = Vec::new();
        let out = rearm_until(deadline, |remaining| {
            rounds.push(remaining);
            Ok::<_, ()>((rounds.len() == 2).then_some(()))
        });
        assert_eq!(out, Ok(Some(())));
        assert_eq!(rounds.len(), 2);
    }
}

/// The probe holds no progress state: repeated remainings, with or without a `take()` between,
/// are not its concern.
///
/// Mutant: make `wait_ms_probe::record` panic on a repeated remaining -> panics here.
#[test]
fn wait_ms_probe_does_not_judge_progress() {
    let (_clock, _at) = test_clock::FrozenClockGuard::install();
    wait_ms_probe::take();
    let r = Duration::from_millis(7);
    wait_ms_probe::record(7, r, r);
    wait_ms_probe::record(7, r, r);
    wait_ms_probe::take();
    wait_ms_probe::record(7, r, r);
    wait_ms_probe::take();
}

/// A remaining injected by the override seam, and a round that took no clock ticks, are not a
/// stalled loop: the loop advanced.
///
/// Mutant: judge progress by the `remaining` values -> the injected 500us then the real 5ms
/// differ, but a zero-elapsed round repeats the real one and panics.
#[test]
fn the_override_seam_and_a_zero_elapsed_round_do_not_trip_the_check() {
    let (_clock, at) = test_clock::FrozenClockGuard::install();
    let deadline = Some(Some(at + Duration::from_millis(5)));
    let _override = remaining_override_seam::set(Duration::from_micros(500));
    wait_ms_probe::take();
    let mut rounds = 0;
    let out = rearm_until(deadline, |remaining| {
        win32_timeout_ms(remaining);
        rounds += 1;
        Ok::<_, ()>((rounds == 3).then_some(()))
    });
    assert_eq!(out, Ok(Some(())));
    wait_ms_probe::take();
}

/// `rearm_until` with its advance dropped fails at the second round.
///
/// Mutant: drop the `advance_by_elapsed_if_frozen` call in `rearm_until` -> same panic, without
/// the seam.
#[test]
#[should_panic(expected = "no progress")]
fn rearm_until_panics_when_its_advance_is_dropped() {
    let (_clock, at) = test_clock::FrozenClockGuard::install();
    let _skip = test_clock::SkipAdvanceGuard::install();
    let deadline = Some(Some(at + Duration::from_millis(30)));
    rearm_until(deadline, |_| Ok::<Option<()>, ()>(None)).ok();
}

/// A violation found while the thread is already panicking (a Drop path) is recorded, not
/// raised: a second panic would abort the process.
///
/// Mutant: panic regardless of `thread::panicking()` -> the process aborts.
#[test]
fn round_check_defers_its_violation_while_panicking() {
    struct StalledInDrop;
    impl Drop for StalledInDrop {
        fn drop(&mut self) {
            let mut check = test_clock::RoundCheck::new("drop path");
            check.round();
            check.round();
        }
    }
    let (_clock, _at) = test_clock::FrozenClockGuard::install();
    assert!(test_clock::take_deferred_violation().is_none());
    let unwound = std::panic::catch_unwind(|| {
        let _stalled = StalledInDrop;
        panic!("the test body's own failure");
    });
    assert!(unwound.is_err());
    let violation = test_clock::take_deferred_violation().expect("the violation is kept for the test");
    assert!(
        violation.contains("drop path") && violation.contains("no progress"),
        "{violation}"
    );
}
