//! A root reaped by another reaper after a tree call's look, where the kernel refuses the group's
//! signal through the root's pidfd (before Linux 6.9, and always on macOS): the check each caller
//! builds for a send by the group's number sees the reap, and nothing goes out by that number.
//! Mutant for each: "the caller's check always passes".

use crate::graceful_hooks::{at, HookPoint};
use crate::send_log::{Capture, GroupStep, Route};

/// A zombie root leading its own group (its fd marker suppressed on macOS): unreaped at the look.
pub(crate) fn zombie_group_root() -> crate::Child {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(crate::ContainMode::Session);
    #[cfg(target_os = "macos")]
    cmd.suppress_fd_marker();
    let child = cmd.spawn().expect("spawn");
    drop(writer);
    crate::test_child::wait_until_zombie(child.id().pid());
    child
}

/// Runs `op` with the root reaped behind its handle's back right after the call's look, and the
/// group's signal through the pidfd refused as by a kernel before 6.9. Returns the group steps
/// and `op`'s answer.
pub(crate) fn reaped_after_the_look<T>(pid: u32, op: impl FnOnce() -> T) -> (Vec<GroupStep>, T) {
    #[cfg(target_os = "linux")]
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    let _hook = at(HookPoint::AfterRootLook, move || {
        crate::test_child::reaped_elsewhere::reap_behind(pid);
    });
    let capture = Capture::start();
    let answer = op();
    (capture.group_steps(), answer)
}

/// The steps end at a failed check: nothing went by the group's number.
#[track_caller]
pub(crate) fn assert_nothing_by_number(steps: &[GroupStep]) {
    assert_eq!(
        steps.last(),
        Some(&GroupStep::Check),
        "the last step is the check: {steps:?}"
    );
    assert!(
        !steps.iter().any(|s| matches!(
            s,
            GroupStep::Group(Route::Number) | GroupStep::Leader(Route::Number) | GroupStep::Member(..)
        )),
        "nothing went by the group's number: {steps:?}"
    );
}

/// The call's error is the check's: the root was reaped elsewhere.
#[track_caller]
pub(crate) fn assert_reaped_elsewhere(err: &crate::error::Error) {
    match err {
        crate::error::Error::Unassessable { detail, .. } => assert!(
            detail.contains(crate::test_child::reaped_elsewhere::REAPED_ELSEWHERE),
            "{detail}"
        ),
        other => panic!("expected Unassessable, got {other:?}"),
    }
}

#[skuld::test]
fn kill_tree_checks_the_root_again_before_a_send_by_number() {
    let child = zombie_group_root();
    let (steps, result) = reaped_after_the_look(child.id().pid(), || child.kill_tree());
    assert_nothing_by_number(&steps);
    assert_reaped_elsewhere(&result.expect_err("a root reaped elsewhere is not assessable"));
}

#[skuld::test]
fn terminate_tree_checks_the_root_again_before_a_send_by_number() {
    let child = zombie_group_root();
    let (steps, result) = reaped_after_the_look(child.id().pid(), || child.terminate_tree());
    assert_nothing_by_number(&steps);
    assert_reaped_elsewhere(&result.expect_err("a root reaped elsewhere is not assessable"));
}

/// The `SIGTERM` is refused by its check; the sweep's own look then sees the reap.
#[skuld::test]
fn graceful_shutdown_tree_checks_the_root_again_before_a_send_by_number() {
    let child = zombie_group_root();
    let (steps, result) = reaped_after_the_look(child.id().pid(), || {
        child.graceful_shutdown_tree(std::time::Duration::ZERO)
    });
    assert_nothing_by_number(&steps);
    assert_reaped_elsewhere(&result.expect_err("a root reaped elsewhere is not assessable"));
}
