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

#[path = "macos_tests/await_reapable.rs"]
mod await_reapable;

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
    let requested = super::test_hooks::requested_timeouts();
    assert_eq!(
        requested[0],
        Some(Duration::from_secs(i32::MAX as u64)),
        "the first kevent is armed with the clamp, not the far remaining time"
    );
    child.wait().expect("reap");
}

/// A remaining time above the clamp is re-armed from the real deadline: every `kevent` gets at
/// most the clamp, and the wait still ends only at the deadline.
///
/// Mutant: drop the clamp -> a single call carries the whole remaining time.
#[test]
fn a_remaining_time_above_the_clamp_is_rearmed_in_pieces() {
    use crate::wait::test_clock::FrozenClockGuard;
    use nix::sys::event::Kqueue;
    use std::time::Duration;

    let kq = Kqueue::new().expect("kqueue");
    let (_clock, at) = FrozenClockGuard::install();
    let deadline = Some(Some(at + Duration::from_millis(50)));
    let _hooks = super::test_hooks::HookGuard::install(|_, _| {});
    let clamp = Duration::from_millis(10);
    super::test_hooks::set_clamp_override(clamp);
    let verdict = super::block_on_kqueue(&kq, deadline, true, |_, _| Ok(None)).expect("bounded wait");
    assert!(verdict, "an event-less wait ends by its deadline");
    let requested = super::test_hooks::requested_timeouts();
    assert!(requested.len() >= 2, "one call cannot cover 50ms under a 10ms clamp");
    assert!(
        requested.iter().all(|t| t.is_some_and(|t| t <= clamp)),
        "every call is capped: {requested:?}"
    );
}
