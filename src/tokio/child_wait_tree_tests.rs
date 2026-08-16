//! Async twin of `src/child/lifecycle_tests.rs` — unit tests for the public async
//! `Child::wait_tree`/`wait_tree_timeout`. See the sync twin for the full per-test rationale.

use std::time::Duration;

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
async fn async_wait_tree_reports_the_drained_verdict_when_the_tree_drains() {
    let mut cmd = quick_contained_cmd();
    let mut child = cmd.spawn().expect("spawn");
    let containment = child.containment();
    let drainable = containment.can_observe_drain();
    let result = child.wait_tree().await;
    if drainable {
        assert_eq!(
            result.expect("a fully-exited tree must report a drained verdict"),
            expected_drained_verdict(containment)
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

/// Async twin of `wait_tree_timeout_zero_reports_members_remain_on_a_live_tree` — see there for
/// the full rationale.
#[tokio::test]
async fn async_wait_tree_timeout_zero_reports_members_remain_on_a_live_tree() {
    let mut cmd = long_lived_contained_cmd();
    let mut child = cmd.spawn().expect("spawn");
    let drainable = child.containment().can_observe_drain();
    let result = child.wait_tree_timeout(Duration::ZERO).await;
    if drainable {
        assert_eq!(
            result.expect("a ZERO probe against a live tree must not be an error"),
            crate::containment::TreeDrain::MembersRemain
        );
    } else {
        let err = result.expect_err("a non-drainable mechanism must refuse wait_tree_timeout");
        assert!(matches!(err, crate::error::Error::Unsupported { .. }), "got {err:?}");
    }
    let _ = child.kill_tree();
    let _ = child.wait().await;
}

/// Async twin of `wait_tree_timeout_zero_reports_the_drained_verdict_after_the_tree_has_already_drained`
/// — see there for the full rationale.
#[tokio::test]
async fn async_wait_tree_timeout_zero_reports_the_drained_verdict_after_the_tree_has_already_drained() {
    let mut cmd = quick_contained_cmd();
    let mut child = cmd.spawn().expect("spawn");
    let containment = child.containment();
    let drainable = containment.can_observe_drain();
    let first = child.wait_tree().await;
    if drainable {
        first.expect("a fully-exited tree must report a drained verdict");
        assert_eq!(
            child
                .wait_tree_timeout(Duration::ZERO)
                .await
                .expect("a ZERO probe against an already-drained tree must not be an error"),
            expected_drained_verdict(containment),
            "a ZERO probe must observe the SAME drained state an unbounded wait already found, \
             not report MembersRemain just because the deadline is already past"
        );
    } else {
        first.expect_err("a non-drainable mechanism must refuse wait_tree");
        let err = child.wait_tree_timeout(Duration::ZERO).await;
        assert!(
            matches!(err, Err(crate::error::Error::Unsupported { .. })),
            "got {err:?}"
        );
    }
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
    let containment = treewalk_child.containment();
    let drainable = containment.can_observe_drain();
    let result = treewalk_child.wait_tree_timeout(Duration::from_millis(200)).await;
    if drainable {
        assert_eq!(
            result.expect("macOS promotes an explicit TreeWalk request to the drainable fd marker"),
            expected_drained_verdict(containment),
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
