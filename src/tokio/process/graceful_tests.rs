//! Async twins of `process/graceful_tests.rs` — watch-failure ordering via the shared seam.
//! Unix-only: both foreign soft ops are `Unsupported` on Windows before any watch runs. The
//! foreign surface is non-reaping, so the Child twins' reap discriminator does not exist
//! here; the child IGNORES `SIGTERM`, making the escalation's `SIGKILL` the only signal that
//! can terminate it — the owned std handle's reaped status proves the escalation ran.
#![cfg(unix)]

use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::time::Duration;

use crate::graceful_hooks::{at, release_at, HookPoint};
use crate::send_log::Capture;
use crate::test_child::foreign;
use crate::wait::fault;

/// A std child that ignores `SIGTERM` (`trap '' TERM` before `exec`; an ignored disposition
/// survives the exec) and blocks on the piped stdin the returned `std::process::Child` holds. The
/// readiness byte on stdout proves the trap is installed before any signal is sent.
///
/// A test that never sends `SIGKILL` cannot hang on it: `std::process::Child::wait` closes that
/// stdin before waiting, so the stranded `cat` exits 0 at once and fails the `SIGKILL` assertion.
/// Taking the stdin out of the `Child`, or reaping through another handle, would lose that EOF.
/// Identical to the sync twin's helper in `src/process/graceful_tests.rs`.
fn spawn_term_ignoring_blocker() -> std::process::Child {
    // Held for the fork itself: a fork landing while a `fdmarker_tests.rs` test's marker write
    // end is transiently open would inherit it into this not-yet-`exec`'d process, and a
    // concurrent sweep could then find and SIGKILL it — see that module's docs.
    let mut child = crate::test_spawn::spawn(
        std::process::Command::new("sh")
            .args(["-c", "trap '' TERM; echo r; exec cat"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped()),
    )
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

#[skuld::test]
async fn async_foreign_graceful_watch_error_still_escalates() {
    let mut child = spawn_term_ignoring_blocker();
    let p = crate::tokio::Process::open_pid(child.id())
        .expect("open")
        .expect("running");
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

#[skuld::test]
async fn async_foreign_graceful_tree_watch_error_still_sweeps() {
    let mut child = spawn_term_ignoring_blocker();
    let p = crate::tokio::Process::open_pid(child.id())
        .expect("open")
        .expect("running");
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

#[skuld::test]
async fn async_foreign_terminate_tree_sigterms_the_root_and_its_descendant() {
    crate::tokio::test_runtime::assert_current_thread();
    let tree = foreign::blocked_tree();
    let p = crate::tokio::Process::open_pid(tree.root.id())
        .expect("open")
        .expect("running");
    let sends = Capture::start();
    p.terminate_tree().expect("terminate_tree");
    foreign::assert_tree_sigtermed(&sends, tree.root.id(), tree.grandchild);
    tree.assert_died_of_sigterm();
}

#[skuld::test]
async fn async_foreign_graceful_shutdown_tree_graceful_path() {
    crate::tokio::test_runtime::assert_current_thread();
    let tree = foreign::blocked_tree();
    let (root, grandchild) = (tree.root.id(), tree.grandchild);
    let p = crate::tokio::Process::open_pid(root).expect("open").expect("running");
    let sends = Capture::start();
    let _armed = at(HookPoint::AfterTerminate, move || {
        foreign::assert_tree_sigtermed(&sends, root, grandchild)
    });
    p.graceful_shutdown_tree(Duration::from_secs(30))
        .await
        .expect("graceful_shutdown_tree");
    tree.assert_died_of_sigterm();
}

#[skuld::test]
async fn async_foreign_graceful_shutdown_graceful_path() {
    crate::tokio::test_runtime::assert_current_thread();
    let mut child = foreign::blocker();
    let p = crate::tokio::Process::open_pid(child.id())
        .expect("open")
        .expect("running");
    let stdin = child.stdin.take().expect("piped stdin");
    let _release = release_at(HookPoint::AfterTerminate, stdin);
    p.graceful_shutdown(Duration::from_secs(30))
        .await
        .expect("graceful_shutdown");
    let status = child.wait().expect("reap");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "got {status:?}");
}
