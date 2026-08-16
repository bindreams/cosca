//! Async twin of `src/child/lifecycle_tests.rs` — unit tests for the public async
//! `Child::wait_tree`/`wait_tree_timeout` (`#62` round-2 review, item 4 — previously zero
//! coverage). See the sync twin for the full per-test rationale.

use std::time::Duration;

fn quick_contained_cmd() -> crate::tokio::Command {
    let mut cmd = crate::tokio::Command::new();
    #[cfg(unix)]
    cmd.args(["true"]);
    #[cfg(windows)]
    cmd.args(["cmd", "/C", "exit 0"]);
    cmd.contain();
    cmd
}

fn long_lived_contained_cmd() -> crate::tokio::Command {
    let mut cmd = crate::tokio::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    cmd
}

#[tokio::test]
async fn async_wait_tree_reports_all_members_exited_when_the_tree_drains() {
    let mut cmd = quick_contained_cmd();
    let mut child = cmd.spawn().expect("spawn");
    let drainable = child.containment().can_observe_drain();
    let result = child.wait_tree().await;
    if drainable {
        assert_eq!(
            result.expect("a fully-exited tree must report AllMembersExited"),
            crate::containment::TreeDrain::AllMembersExited
        );
    } else {
        let err = result.expect_err("a non-drainable mechanism must refuse wait_tree");
        assert!(matches!(err, crate::error::Error::Unsupported { .. }), "got {err:?}");
    }
    let _ = child.wait().await;
}

#[tokio::test]
async fn async_wait_tree_timeout_reports_members_remain_before_the_deadline() {
    let mut cmd = long_lived_contained_cmd();
    let mut child = cmd.spawn().expect("spawn");
    let drainable = child.containment().can_observe_drain();
    let result = child.wait_tree_timeout(Duration::from_millis(200)).await;
    if drainable {
        assert_eq!(
            result.expect("an unmet deadline on a live tree must not be an error"),
            crate::containment::TreeDrain::MembersRemain
        );
    } else {
        let err = result.expect_err("a non-drainable mechanism must refuse wait_tree_timeout");
        assert!(matches!(err, crate::error::Error::Unsupported { .. }), "got {err:?}");
    }
    let _ = child.kill_tree();
    let _ = child.wait().await;
}

/// See the sync twin's identical test for the full rationale, including why this cannot be a
/// single unconditional assertion (macOS promotes every contained root's mechanism to the
/// drainable fd marker regardless of the requested mode).
#[tokio::test]
async fn async_wait_tree_is_unsupported_on_a_non_drainable_mechanism() {
    let mut cmd = crate::tokio::Command::new();
    #[cfg(unix)]
    cmd.args(["true"]);
    #[cfg(windows)]
    cmd.args(["cmd", "/C", "exit 0"]);
    cmd.contain_with(crate::ContainMode::TreeWalk);
    let mut treewalk_child = cmd.spawn().expect("spawn");
    let drainable = treewalk_child.containment().can_observe_drain();
    let result = treewalk_child.wait_tree_timeout(Duration::from_millis(200)).await;
    if drainable {
        assert_eq!(
            result.expect("macOS promotes an explicit TreeWalk request to the drainable fd marker"),
            crate::containment::TreeDrain::AllMembersExited,
            "a quick-exiting tree must still be observed as drained through the promoted mechanism"
        );
    } else {
        let err = result.expect_err("TreeWalk, honored as requested, has no kernel drain edge");
        assert!(matches!(err, crate::error::Error::Unsupported { .. }), "got {err:?}");
        let err2 = treewalk_child
            .wait_tree()
            .await
            .expect_err("TreeWalk, honored as requested, has no kernel drain edge");
        assert!(matches!(err2, crate::error::Error::Unsupported { .. }), "got {err2:?}");
    }
    let _ = treewalk_child.wait().await;
}
