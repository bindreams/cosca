//! Unit tests for the shared kqueue arm/drain primitives (macOS CI-only).

use crate::identity::ProcessId;

#[test]
fn drain_reports_none_when_no_event_pending() {
    // Held for the fork itself — see `fdmarker_tests.rs`'s module docs.
    let _guard = crate::child::spawn::spawn_lock();
    let mut child = std::process::Command::new("sleep")
        .arg("30")
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

/// `Cancel::signal` must wake a `kevent` blocked on the shared kqueue even though the real filter
/// armed alongside it (`EVFILT_PROC` on a child that outlives the test) never fires on its own: if
/// `signal` did nothing, the waiter thread below would block forever and this test would hang
/// rather than fail — a real (non-timing) proof that the wake-up, not the child's exit, is what
/// ends the wait.
#[test]
fn cancel_wakes_a_kevent_blocked_on_the_shared_kqueue() {
    let _guard = crate::child::spawn::spawn_lock();
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn blocker");
    let id = ProcessId::of(child.id()).found().expect("identity of live child");

    let (cancel, kq) = super::Cancel::arm().expect("arm a cancel filter");
    super::arm_note_exit_on(&kq, id.pid())
        .expect("arm the real filter")
        .expect("a live child arms");

    let waiter = std::thread::spawn(move || {
        super::block_on_kqueue(&kq, None, false, |event| {
            if super::Cancel::is_signal(event) {
                return Ok(Some(true)); // cancelled
            }
            Ok(Some(false)) // the child exited — this test's own bug, since it never should
        })
    });

    cancel.signal().expect("signal the cancel filter");
    let cancelled = waiter
        .join()
        .expect("the waiter thread must not panic")
        .expect("block_on_kqueue must not fail");
    assert!(
        cancelled,
        "the wait must end because of the cancel, not the child's (never-happening) exit"
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
