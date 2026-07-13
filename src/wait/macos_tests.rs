//! Unit tests for the shared kqueue arm/drain primitives (macOS CI-only).

use crate::identity::ProcessId;

#[test]
fn drain_reports_none_when_no_event_pending() {
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn blocker");
    let id = ProcessId::of(child.id()).expect("identity of live child");
    let kq = super::arm_proc_exit(id).expect("arm").expect("a live child arms");
    assert!(
        super::drain_proc_exit(&kq).expect("drain").is_none(),
        "no exit event yet must drain to None (spurious-readiness input)"
    );
    child.kill().expect("cleanup");
    child.wait().expect("reap");
}
