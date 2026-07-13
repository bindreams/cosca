//! Unit tests for the graceful trio's watch-failure ordering (the fault seam is pub(crate),
//! unreachable from tests/).

use std::time::Duration;

use crate::wait::fault;

// A watch failure must not strand the tree between the soft signal and the hard sweep: the
// sweep and reap still run, then the watch error surfaces. The reap is proven by identity on
// LINUX, where /proc keeps a zombie exists()-visible; macOS's proc_pidinfo does not see
// zombies (identity.rs), so the assert is Linux-gated — the ordering under test is the same
// straight-line body everywhere, and Linux pins it.
#[test]
fn graceful_tree_watch_error_still_sweeps_and_reaps() {
    let mut cmd = crate::Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd.contain();
    let child = cmd.spawn().expect("spawn");
    let id = child.id();
    fault::set_force_watch_error(true);
    let err = child
        .graceful_shutdown_tree(Duration::from_secs(30))
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
    let status = child.wait().expect("cached status — already reaped by the graceful op");
    assert!(!status.success(), "swept root cannot report success, got {status:?}");
}

// The LONE-path twin of the same invariant (Unix-gated: graceful_shutdown is Unsupported on
// Windows before the watch runs). With the old `wait_timeout(grace)?` shape the child would
// die by our SIGTERM but stay a zombie — `exists()` catches exactly that on Linux (macOS's
// proc_pidinfo does not see zombies, so the assert is Linux-gated).
#[cfg(unix)]
#[test]
fn graceful_lone_watch_error_still_escalates_and_reaps() {
    let mut cmd = crate::Command::new();
    cmd.args(["sleep", "30"]);
    let child = cmd.spawn().expect("spawn");
    let id = child.id();
    fault::set_force_watch_error(true);
    let err = child
        .graceful_shutdown(Duration::from_secs(30))
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
    let status = child.wait().expect("cached status — already reaped by the graceful op");
    assert!(
        !status.success(),
        "escalated child cannot report success, got {status:?}"
    );
}
