//! Async twins of `child/foreign_reap_after_look_tests.rs`: the check each async caller builds for a
//! send by the group's number sees a reap by another reaper after the call's look. Mutant for
//! each: "the caller's check always passes".

use crate::child::foreign_reap_after_look_tests::{
    assert_nothing_by_number, assert_reaped_elsewhere, reaped_after_the_look,
};

/// A zombie root leading its own group (its fd marker suppressed on macOS): unreaped at the look.
fn zombie_group_root() -> crate::tokio::Child {
    // The sync command, which the async spawn takes: only it can suppress the fd marker.
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(crate::ContainMode::Session);
    #[cfg(target_os = "macos")]
    cmd.suppress_fd_marker();
    let child = crate::tokio::spawn::spawn(&mut cmd).expect("spawn");
    drop(writer);
    crate::test_child::wait_until_zombie(child.id().pid());
    child
}

#[skuld::test]
async fn tokio_kill_tree_checks_the_root_again_before_a_send_by_number() {
    crate::tokio::test_runtime::assert_current_thread();
    let mut child = zombie_group_root();
    let pid = child.id().pid();
    let (steps, result) = reaped_after_the_look(pid, || child.kill_tree());
    assert_nothing_by_number(&steps);
    assert_reaped_elsewhere(&result.expect_err("a root reaped elsewhere is not assessable"));
}

#[skuld::test]
async fn tokio_terminate_tree_checks_the_root_again_before_a_send_by_number() {
    crate::tokio::test_runtime::assert_current_thread();
    let child = zombie_group_root();
    let (steps, result) = reaped_after_the_look(child.id().pid(), || child.terminate_tree());
    assert_nothing_by_number(&steps);
    assert_reaped_elsewhere(&result.expect_err("a root reaped elsewhere is not assessable"));
}

/// The `SIGTERM` is refused by its check; the sweep's own look then sees the reap.
#[skuld::test]
async fn tokio_graceful_shutdown_tree_checks_the_root_again_before_a_send_by_number() {
    crate::tokio::test_runtime::assert_current_thread();
    let mut child = zombie_group_root();
    let pid = child.id().pid();
    #[cfg(target_os = "linux")]
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    let _hook = crate::graceful_hooks::at(crate::graceful_hooks::HookPoint::AfterRootLook, move || {
        crate::test_child::reaped_elsewhere::reap_behind(pid);
    });
    let capture = crate::send_log::Capture::start();
    let result = child.graceful_shutdown_tree(std::time::Duration::ZERO).await;
    assert_nothing_by_number(&capture.group_steps());
    assert_reaped_elsewhere(&result.expect_err("a root reaped elsewhere is not assessable"));
}

#[skuld::test]
async fn tokio_drop_checks_the_root_again_before_a_send_by_number() {
    crate::tokio::test_runtime::assert_current_thread();
    let child = zombie_group_root();
    let (steps, ()) = reaped_after_the_look(child.id().pid(), || drop(child));
    assert_nothing_by_number(&steps);
}

#[skuld::test]
async fn tokio_finish_elevated_checks_the_root_again_before_a_send_by_number() {
    crate::tokio::test_runtime::assert_current_thread();
    let child = zombie_group_root();
    let (steps, failed) = reaped_after_the_look(child.id().pid(), || {
        crate::tokio::spawn::finish_elevated(
            child,
            Err(crate::error::Error::Io(std::io::Error::other("no password"))),
        )
    });
    assert_nothing_by_number(&steps);
    assert!(failed.is_err(), "the password write failed");
}
