//! The frozen token's resume-then-release sequence, on real suspended children.

use super::observe;
use crate::containment::dispatch::{attach, Attachment, Prepared};
use crate::containment::ContainMode;
use crate::test_frozen::{child_may_break_away, raw, spawn_suspended_blocker, InitialThread};

/// A suspended `findstr x` blocker, attached the way a frozen
/// spawn attaches it.
fn frozen_uncontained() -> (std::process::Child, Attachment) {
    frozen_with(None, false)
}

fn frozen_with(mode: Option<ContainMode>, is_root: bool) -> (std::process::Child, Attachment) {
    let child = spawn_suspended_blocker();
    let crate::identity::Resolved::Found(id) = crate::identity::ProcessId::of(child.id()) else {
        panic!("the suspended child must be readable");
    };
    let prepared = Prepared {
        mode,
        is_root,
        graceful: crate::graceful::GracefulMechanism::None,
        frozen: true,
        breakaway: false,
    };
    let attachment = attach(id, raw(&child), prepared).expect("attach a frozen child");
    (child, attachment)
}

/// The armed guard of a child of this process, as literal bits: the kill and silent breakaway, plus
/// breakaway when the job the child is in permits it. Not the production flag functions, which
/// cannot vouch for themselves.
fn armed_literal(child: &std::process::Child) -> u32 {
    use windows::Win32::System::JobObjects::{
        JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
    };
    let mut bits = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0 | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK.0;
    if child_may_break_away(child) {
        bits |= JOB_OBJECT_LIMIT_BREAKAWAY_OK.0;
    }
    bits
}

/// The order is the safety argument: releasing the guard first would strand a frozen process if
/// the owner died between the two calls, while resuming first can only kill a running child.
#[skuld::test]
fn release_resumes_before_it_disarms_the_guard() {
    let (mut child, mut attachment) = frozen_uncontained();
    let frozen = attachment.frozen.take().expect("a frozen attach hands back its token");
    let thread = InitialThread::of(child.id());
    assert_eq!(thread.suspend_count(), 1, "frozen until release");

    frozen.release_process(raw(&child)).expect("release");

    let at_resume = observe::take_guard_flags_after_resume().expect("the seam saw the guard after the resume");
    assert_eq!(
        at_resume.0,
        armed_literal(&child),
        "the guard must still be armed when the threads have been resumed"
    );
    assert_eq!(thread.suspend_count(), 0, "the child runs after release");
    drop(attachment);
    child.kill().expect("kill");
    child.wait().expect("reap");
}

/// After release the guard's kill is gone and its breakaway bits stay as armed. (That the child then
/// lives on is `windows_suspended.rs`' `resumed_child_is_alive_after_the_guard_closes`: a blocker
/// that does not echo cannot prove it here.)
#[skuld::test]
fn release_clears_kill_on_close_and_keeps_the_breakaway_bits() {
    let (mut child, mut attachment) = frozen_uncontained();
    let frozen = attachment.frozen.take().expect("token");

    frozen.release_process(raw(&child)).expect("release");

    use windows::Win32::System::JobObjects::{JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK};
    let released = observe::take_guard_flags_after_release().expect("the seam saw the released guard");
    // Literals, not `guard_released_flags()`: the production function cannot vouch for itself.
    // Without `SILENT_BREAKAWAY_OK` every descendant of the resumed child would stay in the guard.
    let mut expected = JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK.0;
    if child_may_break_away(&child) {
        expected |= JOB_OBJECT_LIMIT_BREAKAWAY_OK.0;
    }
    assert_eq!(
        released.0, expected,
        "released: no KILL_ON_JOB_CLOSE, silent breakaway, and breakaway where the enclosing job permits it"
    );
    drop(attachment);
    child.kill().expect("kill");
    child.wait().expect("reap");
}

/// A release that fails after the threads resumed says so, and the guard is still armed when it
/// is dropped, so the OS ends the running child instead of leaving it unguarded.
#[skuld::test]
fn death_watch_a_failed_guard_release_is_reported_after_the_threads_resumed() {
    use crate::containment::windows::fault::{force_next, Step};
    const ERROR_ACCESS_DENIED: u32 = 5;
    let (mut child, mut attachment) = frozen_uncontained();
    let frozen = attachment.frozen.take().expect("token");

    let forced = force_next(Step::SetLimits, ERROR_ACCESS_DENIED);
    let err = frozen
        .release_process(raw(&child))
        .expect_err("the release write was forced to fail");
    drop(forced);

    assert!(!err.to_string().is_empty());
    assert!(
        observe::take_guard_flags_after_resume().is_some(),
        "the guard release is attempted only after the threads were resumed"
    );
    // The guard was dropped armed: the child dies. Reaping blocks until it does.
    child.wait().expect("the dropped, still-armed guard kills the child");
}
