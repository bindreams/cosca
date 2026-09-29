//! Unit tests for the shared kqueue arm/drain primitives (macOS CI-only).

use crate::identity::ProcessId;

#[test]
fn drain_reports_none_when_no_event_pending() {
    // Held for the fork itself — see `fdmarker_tests.rs`'s module docs.
    let _guard = crate::child::spawn::spawn_lock();
    // Alive until this test kills it: the arm-then-drain checks below need that.
    let mut child = crate::test_child::held_std_blocker(std::process::Stdio::null())
        .spawn()
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
/// without the seam.
#[test]
#[should_panic(expected = "no progress")]
fn block_on_kqueue_panics_when_its_advance_is_dropped() {
    use crate::wait::test_clock::{FrozenClockGuard, SkipAdvanceGuard};
    use nix::sys::event::Kqueue;
    use std::time::Duration;

    let kq = Kqueue::new().expect("kqueue");
    let (_clock, at) = FrozenClockGuard::install();
    let _skip = SkipAdvanceGuard::install();
    let deadline = Some(Some(at + Duration::from_millis(5)));
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
