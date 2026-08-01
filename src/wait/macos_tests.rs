//! Unit tests for the shared kqueue arm/drain primitives (macOS CI-only).

use crate::identity::ProcessId;

#[test]
fn drain_reports_none_when_no_event_pending() {
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
