//! Async twins of `process/graceful_tests.rs` — watch-failure ordering via the shared seam.
//! Unix-only: both foreign soft ops are `Unsupported` on Windows before any watch runs. The
//! foreign surface is non-reaping, so the Child twins' reap discriminator does not exist
//! here; the child IGNORES `SIGTERM`, making the escalation's `SIGKILL` the only signal that
//! can terminate it — the owned std handle's reaped status proves the escalation ran.
#![cfg(unix)]

use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::time::Duration;

use crate::wait::fault;

/// A std child that ignores `SIGTERM`: `trap '' TERM` before `exec`, and ignored dispositions
/// survive the exec. The readiness byte on stdout proves the trap is installed before any
/// signal is sent (a real pipe event, not a sleep). Byte-identical to the sync twins' helper
/// in `src/process/graceful_tests.rs`.
fn spawn_term_ignoring_sleeper() -> std::process::Child {
    let mut child = std::process::Command::new("sh")
        .args(["-c", "trap '' TERM; echo r; exec sleep 30"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut buf = [0u8; 1];
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_exact(&mut buf)
        .expect("readiness byte");
    child
}

#[tokio::test]
async fn async_foreign_graceful_watch_error_still_escalates() {
    let mut child = spawn_term_ignoring_sleeper();
    let p = crate::tokio::Process::from_pid(child.id()).expect("resolves");
    fault::set_force_watch_error(true);
    let err = p
        .graceful_shutdown(Duration::from_secs(30))
        .await
        .expect_err("the watch error must surface");
    assert!(
        !fault::armed(),
        "seam not consumed — the watch did not run on this thread"
    );
    assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
    // Death proof via the OWNED handle: SIGTERM is ignored, so only the escalation's SIGKILL
    // can have terminated it.
    let status = child.wait().expect("reap");
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "child must be force-killed despite the watch error, got {status:?}"
    );
}

#[tokio::test]
async fn async_foreign_graceful_tree_watch_error_still_sweeps() {
    let mut child = spawn_term_ignoring_sleeper();
    let p = crate::tokio::Process::from_pid(child.id()).expect("resolves");
    fault::set_force_watch_error(true);
    let err = p
        .graceful_shutdown_tree(Duration::from_secs(30))
        .await
        .expect_err("the watch error must surface");
    assert!(
        !fault::armed(),
        "seam not consumed — the watch did not run on this thread"
    );
    assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
    let status = child.wait().expect("reap");
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "root must be swept despite the watch error, got {status:?}"
    );
}
