//! Async twin of `child/graceful_tests.rs` — watch-failure ordering via the shared seam.

use std::time::Duration;

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
    fault::set_force_watch_error(true);
    let err = child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .await
        .expect_err("the watch error must surface");
    assert!(
        !fault::armed(),
        "seam not consumed — the watch did not run on this thread"
    );
    assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
    #[cfg(target_os = "linux")]
    assert!(
        !id.exists(),
        "root must be swept AND reaped despite the watch error (on Linux a zombie would still exist)"
    );
    #[cfg(not(target_os = "linux"))]
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
    fault::set_force_watch_error(true);
    let err = child
        .graceful_shutdown(Duration::from_secs(30))
        .await
        .expect_err("the watch error must surface");
    assert!(
        !fault::armed(),
        "seam not consumed — the watch did not run on this thread"
    );
    assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
    #[cfg(target_os = "linux")]
    assert!(
        !id.exists(),
        "child must be killed AND reaped despite the watch error (on Linux a zombie would still exist)"
    );
    #[cfg(not(target_os = "linux"))]
    let _ = id;
    let status = child
        .wait()
        .await
        .expect("cached status — already reaped by the graceful op");
    assert!(
        !status.success(),
        "escalated child cannot report success, got {status:?}"
    );
}
