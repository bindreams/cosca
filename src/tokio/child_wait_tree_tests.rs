//! Async twin of `src/child/lifecycle_tests.rs` — unit tests for the public async
//! `Child::wait_tree`/`wait_tree_timeout`. See the sync twin for the full per-test rationale.

use std::time::Duration;

use crate::test_child::{drainable_gives, Console};
#[cfg(target_os = "linux")]
use crate::test_groups::{cgroup, Group};
use crate::Containment;

/// The `TreeDrain` variant a fully-drained tree reports on `containment`'s mechanism:
/// `AllMembersExited` everywhere authoritative (cgroup v2, Windows job object), but
/// `AllMarkersClosed` on macOS's advisory fd marker — see `TreeDrain`'s own doc for why the two
/// are not interchangeable. Centralized here so every test below asserts the SAME real,
/// mechanism-correct verdict rather than assuming the authoritative one everywhere.
fn expected_drained_verdict(containment: crate::containment::Containment) -> crate::containment::TreeDrain {
    match containment {
        crate::containment::Containment::FdMarker => crate::containment::TreeDrain::AllMarkersClosed,
        _ => crate::containment::TreeDrain::AllMembersExited,
    }
}

fn quick_contained_cmd() -> crate::tokio::Command {
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    #[cfg(unix)]
    cmd.args(["true"]);
    #[cfg(windows)]
    cmd.args(["cmd", "/C", "exit 0"]);
    cmd.contain();
    cmd
}

/// Async twin of `child::lifecycle_tests::long_lived_contained_child`.
fn long_lived_contained_child() -> (crate::tokio::Child, crate::tokio::ChildStdin) {
    #[cfg(unix)]
    {
        crate::test_child::held_contained_blocker_async(crate::Stdio::null())
    }
    #[cfg(windows)]
    {
        crate::test_child::windows_blocker_async(|cmd| {
            cmd.contain();
        })
    }
}

/// Async twin of `child::lifecycle_tests::kill_then_release`.
async fn kill_then_release(mut child: crate::tokio::Child, stdin: crate::tokio::ChildStdin) {
    child.kill_tree().expect("kill_tree");
    drop(stdin);
    crate::test_child::assert_killed("the blocker", child.wait().await.expect("reap the blocker"));
}

async fn wait_tree_drained_verdict(expected: Containment) {
    let mut cmd = quick_contained_cmd();
    let mut child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), expected);
    let result = child.wait_tree().await;
    assert_eq!(
        result.expect("a fully-exited tree must report a drained verdict"),
        expected_drained_verdict(expected)
    );
    _ = child.wait().await;
}

#[cfg(not(target_os = "linux"))]
#[skuld::test]
async fn async_wait_tree_reports_the_drained_verdict_when_the_tree_drains() {
    wait_tree_drained_verdict(drainable_gives()).await;
}

#[cfg(target_os = "linux")]
#[skuld::test]
async fn async_wait_tree_reports_the_drained_verdict_when_the_tree_drains(#[fixture(cgroup)] _group: &Group) {
    wait_tree_drained_verdict(drainable_gives()).await;
}

async fn wait_tree_timeout_members_remain(expected: Containment) {
    let (child, stdin) = long_lived_contained_child();
    assert_eq!(child.containment(), expected);
    let result = child.wait_tree_timeout(Duration::from_millis(200)).await;
    assert_eq!(
        result.expect("an unmet deadline on a live tree must not be an error"),
        crate::containment::TreeDrain::MembersRemain
    );
    kill_then_release(child, stdin).await;
}

#[cfg(not(target_os = "linux"))]
#[skuld::test]
async fn async_wait_tree_timeout_reports_members_remain_before_the_deadline() {
    wait_tree_timeout_members_remain(drainable_gives()).await;
}

#[cfg(target_os = "linux")]
#[skuld::test]
async fn async_wait_tree_timeout_reports_members_remain_before_the_deadline(#[fixture(cgroup)] _group: &Group) {
    wait_tree_timeout_members_remain(drainable_gives()).await;
}

/// Async twin of `wait_tree_timeout_zero_reports_members_remain_on_a_live_tree` — see there for
/// the full rationale.
async fn wait_tree_timeout_zero_members_remain(expected: Containment) {
    let (child, stdin) = long_lived_contained_child();
    assert_eq!(child.containment(), expected);
    let result = child.wait_tree_timeout(Duration::ZERO).await;
    assert_eq!(
        result.expect("a ZERO probe against a live tree must not be an error"),
        crate::containment::TreeDrain::MembersRemain
    );
    kill_then_release(child, stdin).await;
}

#[cfg(not(target_os = "linux"))]
#[skuld::test]
async fn async_wait_tree_timeout_zero_reports_members_remain_on_a_live_tree() {
    wait_tree_timeout_zero_members_remain(drainable_gives()).await;
}

#[cfg(target_os = "linux")]
#[skuld::test]
async fn async_wait_tree_timeout_zero_reports_members_remain_on_a_live_tree(#[fixture(cgroup)] _group: &Group) {
    wait_tree_timeout_zero_members_remain(drainable_gives()).await;
}

/// Async twin of `wait_tree_timeout_zero_reports_the_drained_verdict_after_the_tree_has_already_drained`
/// — see there for the full rationale.
async fn wait_tree_timeout_zero_drained_verdict(expected: Containment) {
    let mut cmd = quick_contained_cmd();
    let mut child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), expected);
    child
        .wait_tree()
        .await
        .expect("a fully-exited tree must report a drained verdict");
    assert_eq!(
        child
            .wait_tree_timeout(Duration::ZERO)
            .await
            .expect("a ZERO probe against an already-drained tree must not be an error"),
        expected_drained_verdict(expected),
        "a ZERO probe must observe the SAME drained state an unbounded wait already found, \
         not report MembersRemain just because the deadline is already past"
    );
    _ = child.wait().await;
}

#[cfg(not(target_os = "linux"))]
#[skuld::test]
async fn async_wait_tree_timeout_zero_reports_the_drained_verdict_after_the_tree_has_already_drained() {
    wait_tree_timeout_zero_drained_verdict(drainable_gives()).await;
}

#[cfg(target_os = "linux")]
#[skuld::test]
async fn async_wait_tree_timeout_zero_reports_the_drained_verdict_after_the_tree_has_already_drained(
    #[fixture(cgroup)] _group: &Group,
) {
    wait_tree_timeout_zero_drained_verdict(drainable_gives()).await;
}

/// A quick-exiting child under the containment `contain` asks for.
fn quick_child(contain: impl FnOnce(&mut crate::tokio::Command)) -> crate::tokio::Child {
    let mut cmd = crate::test_child::tokio_command(Console::Hidden);
    #[cfg(unix)]
    cmd.args(["true"]);
    #[cfg(windows)]
    cmd.args(["cmd", "/C", "exit 0"]);
    contain(&mut cmd);
    cmd.spawn().expect("spawn")
}

/// A quick-exiting child of an explicit `ContainMode::TreeWalk` request.
fn quick_treewalk_child() -> crate::tokio::Child {
    quick_child(|cmd| _ = cmd.contain_with(crate::ContainMode::TreeWalk))
}

/// Every wait of `child` is `Unsupported`, and the child is reaped.
async fn assert_wait_tree_unsupported(mut child: crate::tokio::Child) {
    for result in [
        child.wait_tree_timeout(Duration::from_millis(200)).await,
        child.wait_tree_timeout(Duration::ZERO).await,
        child.wait_tree().await,
    ] {
        let err = result.expect_err("this mechanism has no kernel drain edge");
        assert!(matches!(err, crate::error::Error::Unsupported { .. }), "got {err:?}");
    }
    _ = child.wait().await;
}

/// See the sync twin's identical test for the full rationale. macOS does not honor a `TreeWalk`
/// request (see the test below).
#[cfg(not(target_os = "macos"))]
#[skuld::test]
async fn async_wait_tree_is_unsupported_on_a_non_drainable_mechanism() {
    let child = quick_treewalk_child();
    assert_eq!(child.containment(), Containment::TreeWalk);
    assert_wait_tree_unsupported(child).await;
}

/// See the sync twin's identical test.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn async_wait_tree_is_unsupported_on_a_session() {
    let child = quick_child(|cmd| _ = crate::test_child::contain_without_cgroup_async(cmd));
    assert_eq!(child.containment(), crate::test_child::contain_without_cgroup_gives());
    assert_wait_tree_unsupported(child).await;
}

/// See the sync twin's identical test.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn async_wait_tree_is_unsupported_on_an_uncontained_child() {
    let child = quick_child(|_| {});
    assert_eq!(child.containment(), Containment::None);
    assert_wait_tree_unsupported(child).await;
}

/// See the sync twin's identical test: macOS promotes every contained root's mechanism to the
/// drainable fd marker regardless of the requested mode.
#[cfg(target_os = "macos")]
#[skuld::test]
async fn async_a_treewalk_request_is_promoted_to_the_fd_marker_which_drains() {
    let mut child = quick_treewalk_child();
    assert_eq!(child.containment(), Containment::FdMarker);
    assert_eq!(
        child
            .wait_tree()
            .await
            .expect("macOS promotes an explicit TreeWalk request to the drainable fd marker"),
        expected_drained_verdict(Containment::FdMarker),
        "a quick-exiting tree must still be observed as drained through the promoted mechanism"
    );
    _ = child.wait().await;
}
