//! Unit tests for the foreign graceful trio's watch-failure ordering (the fault seam is
//! pub(crate), unreachable from tests/). Unix-only: both foreign soft ops are `Unsupported`
//! on Windows before any watch runs. The foreign surface is non-reaping, so the Child twins'
//! reap discriminator (`!id.exists()`) does not exist here; instead the child IGNORES
//! `SIGTERM`, making the escalation's `SIGKILL` the only signal that can terminate it — the
//! owned std handle's reaped status proves the escalation ran despite the watch error.
#![cfg(unix)]

use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::time::Duration;

use crate::wait::fault;

/// A std child that ignores `SIGTERM`: `trap '' TERM` before `exec`, and ignored dispositions
/// survive the exec. The readiness byte on stdout proves the trap is installed before any
/// signal is sent (a real pipe event, not a sleep).
fn spawn_term_ignoring_sleeper() -> std::process::Child {
    // Held for the fork itself: a fork landing while a `fdmarker_tests.rs` test's marker write
    // end is transiently open would inherit it into this not-yet-`exec`'d process, and a
    // concurrent sweep could then find and SIGKILL it — see that module's docs.
    let _guard = crate::child::spawn::spawn_lock();
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

// A watch failure must not strand the foreign process between the soft signal and the
// escalation: the kill still runs, then the watch error surfaces. With the old
// `block_until_exit(..)?` shape the SIGTERM-ignoring child would survive the op.
#[test]
fn foreign_graceful_lone_watch_error_still_escalates() {
    let mut child = spawn_term_ignoring_sleeper();
    let p = crate::Process::from_pid(child.id()).found().expect("resolves");
    fault::set_force_watch_error(true);
    let err = p
        .graceful_shutdown(Duration::from_secs(30))
        .expect_err("the watch error must surface");
    assert!(
        !fault::armed(),
        "seam not consumed — the watch did not run on this thread"
    );
    assert!(matches!(err, crate::error::Error::Io(_)), "got {err:?}");
    // Death proof via the OWNED handle: SIGTERM is ignored, so only the escalation's SIGKILL
    // can have terminated it (a stranded child exits 0 at the 30s bound and fails the assert).
    let status = child.wait().expect("reap");
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "child must be force-killed despite the watch error, got {status:?}"
    );
}

// The TREE twin of the same invariant: the hard sweep must still run after a watch failure
// (the old shape propagated it before `kill_tree`, stranding the whole tree). A tree of one
// suffices — the ordering, not the walk's reach, is under test (tests/graceful.rs covers reach).
#[test]
fn foreign_graceful_tree_watch_error_still_sweeps() {
    let mut child = spawn_term_ignoring_sleeper();
    let p = crate::Process::from_pid(child.id()).found().expect("resolves");
    fault::set_force_watch_error(true);
    let err = p
        .graceful_shutdown_tree(Duration::from_secs(30))
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
