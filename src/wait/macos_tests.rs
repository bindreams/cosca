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

/// The guard that stops `kill(0, sig)` from SIGKILLing the caller-s own process group must be
/// consulted by the real entry points, not merely exist as a pure function. `ProcessId::of(0)`
/// resolves on macOS (`kernel_task`), so nothing upstream rules the value out.
#[test]
fn kill_and_terminate_refuse_a_group_directed_target() {
    let bogus = crate::identity::ProcessId::from_parts_for_test(0, 1);
    assert!(matches!(
        crate::wait::kill(bogus),
        Err(crate::error::Error::Unassessable { .. })
    ));
    assert!(matches!(
        crate::wait::terminate(bogus),
        Err(crate::error::Error::Unassessable { .. })
    ));
}
