//! Async twin of `child/graceful_tests.rs` — watch-failure ordering via the shared seam.

use std::time::Duration;

use super::fault as term_fault;
use crate::wait::fault;

#[tokio::test]
async fn async_graceful_tree_watch_error_still_sweeps_and_reaps() {
    let mut cmd = crate::tokio::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let id = child.id();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    fault::set_force_watch_error(true);
    let err = child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .await
        .expect_err("the watch error must surface");
    assert!(
        crate::log_capture::contains_since(mark, &format!("graceful_shutdown_tree({pid})", pid = id.pid())),
        "the subsumption trace must fire on the forced watch error"
    );
    assert!(
        !fault::armed(),
        "seam not consumed — the watch did not run on this thread"
    );
    assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
    // The reap is proven by identity on all Unix (procfs / `sysctl KERN_PROC` are both
    // zombie-inclusive); Windows skips the assert — exists() stays true there while
    // `child` still holds the process handle.
    #[cfg(unix)]
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Gone,
        "root must be swept AND reaped despite the watch error (a zombie would still exist)"
    );
    #[cfg(windows)]
    let _ = id;
    let status = child
        .wait()
        .await
        .expect("cached status — already reaped by the graceful op");
    assert!(!status.success(), "swept root cannot report success, got {status:?}");
}

#[cfg(unix)]
#[tokio::test]
async fn async_graceful_lone_watch_error_still_escalates_and_reaps() {
    let mut cmd = crate::tokio::Command::new();
    cmd.args(["sleep", "30"]);
    let mut child = cmd.spawn().expect("spawn");
    let id = child.id();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    fault::set_force_watch_error(true);
    let err = child
        .graceful_shutdown(Duration::from_secs(30))
        .await
        .expect_err("the watch error must surface");
    assert!(
        crate::log_capture::contains_since(mark, &format!("graceful_shutdown({pid})", pid = id.pid())),
        "the subsumption trace must fire on the forced watch error"
    );
    assert!(
        !fault::armed(),
        "seam not consumed — the watch did not run on this thread"
    );
    assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Gone,
        "child must be killed AND reaped despite the watch error (a zombie would still exist)"
    );
    let status = child
        .wait()
        .await
        .expect("cached status — already reaped by the graceful op");
    assert!(
        !status.success(),
        "escalated child cannot report success, got {status:?}"
    );
}

// Async twin of `graceful_tree_terminate_refusal_still_sweeps_and_reaps` in
// `src/child/graceful_tests.rs` — see there for the full rationale.
#[tokio::test]
async fn async_graceful_tree_terminate_refusal_still_sweeps_and_reaps() {
    let mut cmd = crate::tokio::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let id = child.id();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    term_fault::set_force_terminate(term_fault::Forced::Containment);
    let err = child
        .graceful_shutdown_tree(Duration::ZERO)
        .await
        .expect_err("the forced terminate refusal must surface");
    assert!(matches!(err, crate::error::Error::Containment { .. }), "got {err:?}");
    assert!(
        crate::log_capture::contains_since(
            mark,
            &format!("graceful_shutdown_tree({pid}): terminate_tree refused", pid = id.pid())
        ),
        "the terminate-refusal trace specifically must fire"
    );
    #[cfg(unix)]
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Gone,
        "root must be swept AND reaped despite the forced terminate refusal"
    );
    #[cfg(windows)]
    let _ = id;
    let status = child
        .wait()
        .await
        .expect("cached status — already reaped by the graceful op");
    assert!(!status.success(), "swept root cannot report success, got {status:?}");
}

// Async twin of `graceful_tree_unassessable_per_member_still_sweeps_and_reaps`.
#[tokio::test]
async fn async_graceful_tree_unassessable_per_member_still_sweeps_and_reaps() {
    let mut cmd = crate::tokio::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let id = child.id();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    term_fault::set_force_terminate(term_fault::Forced::UnassessablePerMember);
    let err = child
        .graceful_shutdown_tree(Duration::ZERO)
        .await
        .expect_err("the forced per-member-unassessable state must surface");
    assert!(
        matches!(err, crate::error::Error::Unassessable { source: None, .. }),
        "got {err:?}"
    );
    assert!(
        crate::log_capture::contains_since(
            mark,
            &format!("graceful_shutdown_tree({pid}): terminate_tree refused", pid = id.pid())
        ),
        "the terminate-refusal trace specifically must fire"
    );
    #[cfg(unix)]
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Gone,
        "root must be swept AND reaped despite the forced unassessable state"
    );
    #[cfg(windows)]
    let _ = id;
    let status = child
        .wait()
        .await
        .expect("cached status — already reaped by the graceful op");
    assert!(!status.success(), "swept root cannot report success, got {status:?}");
}

// Async twin of `graceful_tree_unassessable_mechanism_failure_fails_fast`.
#[tokio::test]
async fn async_graceful_tree_unassessable_mechanism_failure_fails_fast() {
    let mut cmd = crate::tokio::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let id = child.id();
    term_fault::set_force_terminate(term_fault::Forced::UnassessableMechanism);
    let err = child
        .graceful_shutdown_tree(Duration::ZERO)
        .await
        .expect_err("the forced listing-mechanism failure must surface immediately");
    assert!(
        matches!(err, crate::error::Error::Unassessable { source: Some(_), .. }),
        "got {err:?}"
    );
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Present,
        "a listing-mechanism failure must return before any grace wait or sweep"
    );
    // Clean up: the child is still running by design (no sweep happened above).
    let _ = child.kill_tree();
    let _ = child.wait().await;
}

// Async twin of `graceful_tree_non_containment_terminate_error_fails_fast`.
#[tokio::test]
async fn async_graceful_tree_non_containment_terminate_error_fails_fast() {
    let mut cmd = crate::tokio::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    let mut child = cmd.spawn().expect("spawn");
    let id = child.id();
    term_fault::set_force_terminate(term_fault::Forced::Unsupported);
    let err = child
        .graceful_shutdown_tree(Duration::ZERO)
        .await
        .expect_err("the forced Unsupported error must surface immediately");
    assert!(matches!(err, crate::error::Error::Unsupported { .. }), "got {err:?}");
    assert_eq!(
        id.exists(),
        crate::identity::Existence::Present,
        "a non-containment terminate error must return before any grace wait or sweep"
    );
    // Clean up: the child is still running by design (no sweep happened above).
    let _ = child.kill_tree();
    let _ = child.wait().await;
}
