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
    let p = crate::tokio::Process::from_pid(child.id()).found().expect("resolves");
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
    let p = crate::tokio::Process::from_pid(child.id()).found().expect("resolves");
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

/// One `pidfd_open` answer per step of `graceful_shutdown(ZERO)`: the SIGTERM, the grace wait,
/// the SIGKILL escalation. `None` lets the step through; `Some(op)` is the operation a refusal
/// must name, and whether the child was killed anyway.
#[cfg(target_os = "linux")]
const ESCALATION_CASES: [([Option<rustix::io::Errno>; 3], &str, bool); 3] = [
    // The grace wait is refused: the escalation still runs, and the watch error surfaces.
    ([None, Some(rustix::io::Errno::PERM), None], "process wait", true),
    // The escalation is refused after a working wait: nothing kills the child.
    ([None, None, Some(rustix::io::Errno::ACCESS)], "process kill", false),
    // Both are refused: the kill error wins over the watch error.
    (
        [None, Some(rustix::io::Errno::PERM), Some(rustix::io::Errno::NOSYS)],
        "process kill",
        false,
    ),
];

/// A refused `pidfd_open` in the middle of `graceful_shutdown` names the step that hit it: the
/// grace wait is `process wait`, the escalation `process kill`.
///
/// Mutants: the escalation is `wait::terminate`, or names another `PidfdOp`; the grace wait
/// names another `PidfdOp`; a refused wait skips the escalation.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_refused_pidfd_open_during_graceful_shutdown_names_the_step_that_hit_it() {
    for (script, op, killed) in ESCALATION_CASES {
        let mut child = spawn_term_ignoring_blocker();
        let p = crate::tokio::Process::from_pid(child.id()).found().expect("resolves");
        let forced = crate::wait::backend::fault::force_pidfd_open_script(script);
        let result = p.graceful_shutdown(Duration::ZERO).await;
        drop(forced);
        match result {
            Err(e @ crate::error::Error::Unsupported { .. }) => {
                assert!(
                    e.to_string().starts_with(&format!("{op} is not supported")),
                    "{script:?}: {e}"
                )
            }
            other => panic!("{script:?}: expected Unsupported naming {op}, got {other:?}"),
        }
        if !killed {
            child
                .kill()
                .expect("the escalation was refused, so the child is still ours to kill");
        }
        // SIGTERM is ignored: only the escalation's SIGKILL, or ours, ends the child.
        assert_eq!(child.wait().expect("reap").signal(), Some(libc::SIGKILL), "{script:?}");
    }
}

/// The `SIGTERM`s the tree walk sent by number: `root` first, and exactly one more, to the
/// grandchild of a [`foreign::blocked_tree`].
fn assert_tree_sigtermed(sends: &Capture, root: u32) {
    let sent = sends.by_identity();
    assert!(
        sent.len() == 2 && sent.iter().all(|&(_, signo)| signo == libc::SIGTERM) && sent[0].0 == root,
        "the walk must SIGTERM the root {root}, then its one descendant, got {sent:?}"
    );
}

// Async twin of `foreign_terminate_tree_sigterms_the_root_and_its_descendant` in
// `src/process/graceful_tests.rs`.
#[skuld::test]
async fn async_foreign_terminate_tree_sigterms_the_root_and_its_descendant() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, stdout) = foreign::blocked_tree();
    let p = crate::tokio::Process::from_pid(child.id()).found().expect("resolves");
    let sends = Capture::start();
    p.terminate_tree().expect("terminate_tree");
    assert_tree_sigtermed(&sends, child.id());
    let status = child.wait().expect("reap the root");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "got {status:?}");
    foreign::assert_tree_gone(stdout);
}

// Async twin of `foreign_graceful_shutdown_tree_graceful_path` in `src/process/graceful_tests.rs`.
#[skuld::test]
async fn async_foreign_graceful_shutdown_tree_graceful_path() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, stdout) = foreign::blocked_tree();
    let root = child.id();
    let p = crate::tokio::Process::from_pid(root).found().expect("resolves");
    let sends = std::rc::Rc::new(Capture::start());
    let _armed = at(HookPoint::AfterTerminate, {
        let sends = sends.clone();
        move || assert_tree_sigtermed(&sends, root)
    });
    p.graceful_shutdown_tree(Duration::from_secs(30))
        .await
        .expect("graceful_shutdown_tree");
    let status = child.wait().expect("reap the root");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "got {status:?}");
    foreign::assert_tree_gone(stdout);
}

// Async twin of `foreign_graceful_shutdown_graceful_path` in `src/process/graceful_tests.rs`.
#[skuld::test]
async fn async_foreign_graceful_shutdown_graceful_path() {
    crate::tokio::test_runtime::assert_current_thread();
    let mut child = foreign::blocker();
    let p = crate::tokio::Process::from_pid(child.id()).found().expect("resolves");
    let stdin = child.stdin.take().expect("piped stdin");
    let _release = release_at(HookPoint::AfterTerminate, stdin);
    p.graceful_shutdown(Duration::from_secs(30))
        .await
        .expect("graceful_shutdown");
    let status = child.wait().expect("reap");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "got {status:?}");
}
