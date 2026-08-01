//! Unit tests for the graceful trio's watch-failure ordering (the fault seam is pub(crate),
//! unreachable from tests/).

use std::time::Duration;

use crate::wait::fault;

// A watch failure must not strand the tree between the soft signal and the hard sweep: the
// sweep and reap still run, then the watch error surfaces. The reap is proven by identity on
// all Unix — procfs and `sysctl KERN_PROC` are both zombie-inclusive, so a swept-but-unreaped
// root would still be exists()-visible. (Windows runs the same body but skips that assert:
// exists() stays true there while `child` still holds the process handle.)
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
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    fault::set_force_watch_error(true);
    let err = child
        .graceful_shutdown_tree(Duration::from_secs(30))
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
    #[cfg(unix)]
    assert_eq!(id.exists(), crate::identity::Existence::Gone,
        "root must be swept AND reaped despite the watch error (a zombie would still exist)"
    );
    #[cfg(windows)]
    let _ = id;
    let status = child.wait().expect("cached status — already reaped by the graceful op");
    assert!(!status.success(), "swept root cannot report success, got {status:?}");
}

// The LONE-path twin of the same invariant (Unix-gated: graceful_shutdown is Unsupported on
// Windows before the watch runs). With the old `wait_timeout(grace)?` shape the child would
// die by our SIGTERM but stay a zombie — `exists()` catches exactly that on all Unix
// (procfs / `sysctl KERN_PROC` are both zombie-inclusive).
#[cfg(unix)]
#[test]
fn graceful_lone_watch_error_still_escalates_and_reaps() {
    let mut cmd = crate::Command::new();
    cmd.args(["sleep", "30"]);
    let child = cmd.spawn().expect("spawn");
    let id = child.id();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    fault::set_force_watch_error(true);
    let err = child
        .graceful_shutdown(Duration::from_secs(30))
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
    assert_eq!(id.exists(), crate::identity::Existence::Gone,
        "child must be killed AND reaped despite the watch error (a zombie would still exist)"
    );
    let status = child.wait().expect("cached status — already reaped by the graceful op");
    assert!(
        !status.success(),
        "escalated child cannot report success, got {status:?}"
    );
}
