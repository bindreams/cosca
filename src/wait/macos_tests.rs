//! Unit tests for the shared kqueue arm/drain primitives (macOS CI-only).

use crate::identity::ProcessId;

#[test]
fn drain_reports_none_when_no_event_pending() {
    // Held for the fork itself — see `fdmarker_tests.rs`'s module docs.
    // Alive until this test kills it: the arm-then-drain checks below need that.
    let mut child = crate::test_spawn::spawn(&mut crate::test_child::held_std_blocker(std::process::Stdio::null()))
        .expect("spawn blocker");
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    let kq = super::arm_proc_exit(id).expect("arm").expect("a live child arms");
    assert!(
        super::drain_proc_exit(&kq).expect("drain").is_none(),
        "no exit event yet must drain to None (spurious-readiness input)"
    );
    child.kill().expect("cleanup");
    child.wait().expect("reap");
}

/// `kill(0, sig)` would signal the caller's ENTIRE process group, so pid 0 must never reach
/// `kill(2)`. Two independent layers stop it, and this pins the outer one: the identity
/// re-verify. `ProcessId::of(0)` resolves on macOS (`kernel_task`), but to a token that no
/// caller-held identity matches, so a pid-0 identity is rejected as recycled before the
/// signal is ever formed — and the test process, which is what `kill(0, ..)` would have
/// killed, survives to make the assertion.
///
/// The inner layer, `probe::signal_target`, is defence in depth for a caller holding
/// `kernel_task`'s *genuine* identity. It is not exercised here on purpose: a regression in
/// it would SIGKILL the CI runner's process group rather than fail a test. Its own contract
/// is pinned by `identity::probe::probe_tests::signal_target_is_the_guard_for_real_signals`.
#[test]
fn a_pid_zero_identity_never_reaches_kill() {
    let bogus = crate::identity::ProcessId::from_parts_for_test(0, 1);
    // Already-gone is success: the pid holds a process, but not the one named.
    crate::wait::kill(bogus).expect("a pid-0 identity resolves to a stranger, i.e. already gone");
    crate::wait::terminate(bogus).expect("same for the graceful signal");
    // If either call had reached `kill(2)`, this process would have died with it.
    assert_eq!(
        crate::identity::ProcessId::current().is_alive(),
        crate::identity::Liveness::Alive,
        "the caller must have survived - nothing may signal process group 0"
    );
}

/// `block_on_kqueue` with its frozen-clock advance dropped fails at the second round instead of
/// re-arming forever.
///
/// Mutant: drop the `advance_by_elapsed_if_frozen` call in `block_on_kqueue` -> same panic,
/// without the seam. Mutant: drop `block_on_kqueue`'s `check.round()` -> the round hook fails the
/// test with a different message, instead of the loop spinning forever.
#[test]
#[should_panic(expected = "no progress")]
fn block_on_kqueue_panics_when_its_advance_is_dropped() {
    use crate::wait::test_clock::{FrozenClockGuard, SkipAdvanceGuard};
    use nix::sys::event::Kqueue;
    use std::time::Duration;

    let kq = Kqueue::new().expect("kqueue");
    let (_clock, at) = FrozenClockGuard::install();
    let _skip = SkipAdvanceGuard::install();
    // The frozen clock never advances here, so this deadline can never pass on the test clock,
    // however long a round is preempted; the real `kevent` blocks for it once per round.
    let deadline = Some(Some(at + Duration::from_millis(5)));
    // Ends a loop whose check is gone at its second round, with a panic the test rejects.
    let _hooks = super::test_hooks::HookGuard::install(|round, _| {
        assert!(round < 1, "the check let a second round run");
    });
    super::block_on_kqueue(&kq, deadline, false, |_, _| Ok(None)).ok();
}

/// Under a frozen clock a bounded `block_on_kqueue` ends: each real `kevent` advances the clock.
///
/// Mutant: drop the `advance_by_elapsed_if_frozen` call in `block_on_kqueue` -> the second round
/// panics with "no progress" instead of re-arming forever.
#[test]
fn block_on_kqueue_terminates_under_a_frozen_clock() {
    use crate::wait::test_clock::FrozenClockGuard;
    use nix::sys::event::Kqueue;
    use std::time::Duration;

    let kq = Kqueue::new().expect("kqueue");
    let (_clock, at) = FrozenClockGuard::install();
    let deadline = Some(Some(at + Duration::from_millis(5)));
    let verdict = super::block_on_kqueue(&kq, deadline, true, |_, _| Ok(None)).expect("bounded wait");
    assert!(verdict, "an event-less wait ends by its deadline");
}

/// A deadline beyond XNU's `kevent` `tv_sec` limit still returns the child's exit. The child is
/// ended from the round hook, so the exit is pending or imminent when `kevent` is called.
///
/// Mutant: drop the clamp in `kevent_timeout` -> `Io(EINVAL)` at once.
#[test]
fn a_deadline_beyond_the_kevent_limit_still_returns_the_exit() {
    use std::time::Duration;

    let mut child = crate::test_spawn::spawn(&mut crate::test_child::held_std_blocker(std::process::Stdio::null()))
        .expect("spawn blocker");
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    let mut stdin = child.stdin.take();
    let _hooks = super::test_hooks::HookGuard::install(move |_, _| drop(stdin.take()));
    let deadline = crate::wait::deadline_from(Duration::from_secs(u64::from(u32::MAX)));
    let exited = super::block_until_exit(id, deadline).expect("a far deadline is not an error");
    assert!(exited, "the child was ended, so the wait reports its exit");
    assert_eq!(
        super::test_hooks::requested_timeouts(),
        [Some(Duration::from_secs(i32::MAX as u64))],
        "one kevent, armed with the clamp"
    );
    child.wait().expect("reap");
}

/// A remaining time above the clamp is re-armed from the real deadline: every `kevent` gets at
/// most the clamp, and the wait still ends only at the deadline. The frozen clock advances only
/// from the round hook, so real round durations cannot change the round count.
///
/// Mutants: drop the clamp -> the first call carries the whole 50ms; halve it -> 5ms calls.
#[test]
fn a_remaining_time_above_the_clamp_is_rearmed_in_pieces() {
    use crate::wait::test_clock::{advance, FrozenClockGuard, ZeroElapsedGuard};
    use nix::sys::event::Kqueue;
    use std::time::Duration;

    let kq = Kqueue::new().expect("kqueue");
    let (_clock, at) = FrozenClockGuard::install();
    let _zero = ZeroElapsedGuard::install();
    let deadline = Some(Some(at + Duration::from_millis(50)));
    // Round 0 sees 50ms left, round 1 sees 30ms, round 2 sees none.
    let _hooks = super::test_hooks::HookGuard::install(|round, _| match round {
        1 => advance(Duration::from_millis(20)),
        2 => advance(Duration::from_millis(30)),
        _ => {}
    });
    let clamp = Duration::from_millis(10);
    super::test_hooks::set_clamp_override(clamp);
    let verdict = super::block_on_kqueue(&kq, deadline, true, |_, _| Ok(None)).expect("bounded wait");
    assert!(verdict, "an event-less wait ends by its deadline");
    let requested = super::test_hooks::requested_timeouts();
    assert_eq!(requested, [Some(clamp), Some(clamp), Some(Duration::ZERO)]);
}

/// The clamp override is reset only by a `HookGuard`'s `Drop`, so setting it without one is a
/// contract violation.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "needs a live HookGuard")]
fn the_clamp_override_requires_a_hook_guard() {
    super::test_hooks::set_clamp_override(std::time::Duration::from_millis(10));
}

/// The override may only lower the clamp: zero makes every `kevent` a poll, and anything above
/// `KEVENT_MAX_SECS` brings back the `EINVAL` the clamp exists to prevent.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "may only lower the clamp to a positive value")]
fn the_clamp_override_rejects_zero() {
    let _hooks = super::test_hooks::HookGuard::install(|_, _| {});
    super::test_hooks::set_clamp_override(std::time::Duration::ZERO);
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "may only lower the clamp to a positive value")]
fn the_clamp_override_rejects_a_value_above_the_kevent_limit() {
    let _hooks = super::test_hooks::HookGuard::install(|_, _| {});
    super::test_hooks::set_clamp_override(std::time::Duration::from_secs(super::KEVENT_MAX_SECS + 1));
}

/// A forced timeout is checked like a computed one: above the limit it is a test bug, not an
/// `EINVAL` from the kernel.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "exceeds XNU's INT32_MAX limit")]
fn a_forced_timeout_above_the_kevent_limit_is_rejected() {
    use nix::sys::event::Kqueue;
    use std::time::Duration;

    let kq = Kqueue::new().expect("kqueue");
    let _hooks = super::test_hooks::HookGuard::install(|_, _| {});
    super::test_hooks::set_timeout_override(Duration::from_secs(super::KEVENT_MAX_SECS + 1));
    super::block_on_kqueue(&kq, Some(None), false, |_, _| Ok(Some(true))).ok();
}

/// `kevent_timeout` at the limit's edges, on the real `KEVENT_MAX_SECS`.
///
/// Mutants: always return the cap; drop `subsec_nanos`; cap at `KEVENT_MAX_SECS + 1`.
#[test]
fn kevent_timeout_caps_at_the_limit_and_keeps_the_rest() {
    use std::time::Duration;

    let max = super::KEVENT_MAX_SECS;
    let cases = [
        (Duration::ZERO, (0, 0)),
        (Duration::new(3, 123_456_789), (3, 123_456_789)),
        (Duration::new(max - 1, 999_999_999), (max - 1, 999_999_999)),
        (Duration::new(max, 0), (max, 0)),
        (Duration::new(max, 1), (max, 0)),
        (Duration::new(max + 1, 0), (max, 0)),
        (Duration::from_secs(u64::from(u32::MAX)), (max, 0)),
        (Duration::MAX, (max, 0)),
    ];
    for (input, (secs, nanos)) in cases {
        let ts = super::kevent_timeout(input);
        assert_eq!(
            (ts.tv_sec as u64, ts.tv_nsec as u64),
            (secs, nanos as u64),
            "for {input:?}"
        );
    }
}

/// A positive remaining time never becomes a zero timeout: `kevent` with `{0, 0}` is a poll, so
/// the wait loop would spin on it until the real clock caught up (forever under a frozen one).
///
/// Mutant: drop `subsec_nanos` -> every sub-second remaining time arms a poll.
#[test]
fn a_positive_remaining_time_never_arms_a_poll() {
    use std::time::Duration;

    for d in [
        Duration::from_nanos(1),
        Duration::from_micros(1),
        Duration::from_millis(300),
        Duration::new(0, 999_999_999),
        Duration::new(1, 1),
        Duration::new(1, 500_000_000),
    ] {
        let ts = super::kevent_timeout(d);
        assert!(ts.tv_sec > 0 || ts.tv_nsec > 0, "{d:?} armed a poll: {ts:?}");
    }
}

/// `Ok(0)` with time left is classified: a full-cap timeout is the intended re-arm, anything
/// else is an anomaly. Judged against the cap in force, including a lowered one.
#[test]
fn a_zero_return_is_a_rearm_only_after_a_full_cap_timeout() {
    use super::ZeroReturn::{Anomaly, Rearm};
    use std::time::Duration;

    let max = Duration::from_secs(super::KEVENT_MAX_SECS);
    assert_eq!(super::classify_zero_return(Some(max)), Rearm);
    assert_eq!(
        super::classify_zero_return(Some(max - Duration::from_nanos(1))),
        Anomaly
    );
    assert_eq!(super::classify_zero_return(Some(Duration::ZERO)), Anomaly);
    assert_eq!(super::classify_zero_return(None), Anomaly);
    let _hooks = super::test_hooks::HookGuard::install(|_, _| {});
    let lowered = Duration::from_millis(10);
    super::test_hooks::set_clamp_override(lowered);
    assert_eq!(super::classify_zero_return(Some(lowered)), Rearm);
    assert_eq!(super::classify_zero_return(Some(max)), Anomaly);
}

/// The two `Ok(0)`-with-time-left dispositions reach the log at their own level: the intended
/// re-arm at debug, a short timeout that woke early at warn. Neither retries silently.
///
/// Mutants: swap the arms; drop either log.
#[test]
fn a_zero_return_with_time_left_is_logged_by_kind() {
    use crate::wait::test_clock::{advance, FrozenClockGuard, ZeroElapsedGuard};
    use nix::sys::event::Kqueue;
    use std::time::Duration;

    crate::log_capture::install();
    const REARM: &str = "kevent reached its timeout cap with time left";
    const EARLY: &str = "kevent returned 0 after a timeout below the cap";
    let kq = Kqueue::new().expect("kqueue");
    let (_clock, at) = FrozenClockGuard::install();
    let _zero = ZeroElapsedGuard::install();
    let deadline = Some(Some(at + Duration::from_millis(50)));
    // Round 0: clamp-sized timeout. Round 1: a forced 1ms timeout (below the clamp). Round 2: done.
    let _hooks = super::test_hooks::HookGuard::install(|round, _| match round {
        1 => super::test_hooks::set_timeout_override(Duration::from_millis(1)),
        2 => advance(Duration::from_millis(50)),
        _ => {}
    });
    super::test_hooks::set_clamp_override(Duration::from_millis(10));
    let mark = crate::log_capture::mark();
    super::block_on_kqueue(&kq, deadline, true, |_, _| Ok(None)).expect("bounded wait");
    let levels = |marker| {
        crate::log_capture::records_since_on_current_thread(mark, marker)
            .into_iter()
            .map(|(level, _)| level)
            .collect::<Vec<_>>()
    };
    assert_eq!(levels(REARM), [log::Level::Debug]);
    assert_eq!(levels(EARLY), [log::Level::Warn]);
}
