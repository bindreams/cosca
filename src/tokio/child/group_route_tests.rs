//! Linux 6.9+: each of the async `Child`'s group sends goes through the root's pidfd, so nothing
//! names its process group by number. Mutant for each: "the call gives no pidfd".

use crate::send_log::{assert_group_signalled_first_through_the_pidfd as assert_through_the_pidfd, Capture};
use crate::test_groups::{pidfd_group_signal, Group};

#[skuld::test]
async fn kill_tree_signals_the_group_through_the_root_pidfd(#[fixture(pidfd_group_signal)] _group: &Group) {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, writer) = super::root_state_tests::session_blocker(true);
    let capture = Capture::start();
    child.kill_tree().expect("kill_tree");
    assert_through_the_pidfd(&capture.group_steps(), libc::SIGKILL);
    // The kill's `SIGKILL` is pending: a root nothing killed exits `0` on this release.
    drop(writer);
    crate::test_child::assert_killed("the root", child.wait().await.expect("reap the root"));
}

/// Its `SIGTERM` kills the group's member. Mutant: "the send through the pidfd carries signal 0".
#[skuld::test]
async fn terminate_tree_signals_the_group_through_the_root_pidfd(#[fixture(pidfd_group_signal)] _group: &Group) {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, member, release) = super::group_exact_tests::releasable_root_with_a_member();
    let capture = Capture::start();
    child.terminate_tree().expect("terminate_tree");
    assert_through_the_pidfd(&capture.group_steps(), libc::SIGTERM);
    // The `SIGTERM` is pending: a root nothing signalled exits `0` on this release.
    drop(release);
    let status = child.wait().await.expect("reap the root");
    member.assert_killed();
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&status),
        Some(libc::SIGTERM),
        "the root must die of the SIGTERM: {status:?}"
    );
}

/// Its `SIGTERM` kills the group's member before the sweep could. Mutant: "graceful sends no
/// `SIGTERM`".
#[skuld::test]
async fn graceful_shutdown_tree_signals_the_group_through_the_root_pidfd(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    use crate::child::group_exact_tests::EndedAtTheSigterm;
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, member, release) = super::group_exact_tests::releasable_root_with_a_member();
    let ended = EndedAtTheSigterm::new(member);
    // The root ends with status `0` here if nothing signalled it, instead of the shutdown waiting.
    let _released = crate::graceful_hooks::release_at(crate::graceful_hooks::HookPoint::BeforeReap, release);
    let capture = Capture::start();
    child
        .graceful_shutdown_tree(std::time::Duration::ZERO)
        .await
        .expect("graceful_shutdown_tree");
    assert_through_the_pidfd(&capture.group_steps(), libc::SIGTERM);
    ended.assert_killed_by_the_sigterm();
}

#[skuld::test]
async fn a_drop_kills_the_group_through_the_root_pidfd(#[fixture(pidfd_group_signal)] _group: &Group) {
    crate::tokio::test_runtime::assert_current_thread();
    let (child, writer) = super::root_state_tests::session_blocker(true);
    // Released once the drop's root kill returned, before its reap.
    let teardown = crate::child::spawn::fault::release_between_kill_and_wait(writer);
    let capture = Capture::start();
    drop(child);
    assert_through_the_pidfd(&capture.group_steps(), libc::SIGKILL);
    teardown.assert_killed();
}
