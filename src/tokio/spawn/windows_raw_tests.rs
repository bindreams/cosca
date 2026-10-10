//! Unit tests for the async raw `CreateProcessW` backend (Plan 12 Task 7). These live in the
//! library (not `tests/`) because the cancellation proof drives the per-instance wait observer — a
//! `#[cfg(test)]` seam unreachable from an integration crate — and needs no `CARGO_BIN_EXE` testbin
//! (a system blocker resolvable via `PATH` suffices). The executable≠argv0 proof is the public
//! integration test `tests/raw_windows_async.rs`.

use std::future::Future;
use std::task::Context;

use crate::child::spawn::windows_raw::WaitOutcome;
use crate::tokio::Command;
use crate::Stdio;

/// Dropping an in-flight `wait()` future cancels its blocking watcher promptly — the `CancelGuard`
/// signals the cancel event — AND the child stays waitable: after the cancelled wait, closing the
/// child's stdin (EOF) lets it exit and a FRESH `wait()` resolves. Fully event-driven: the
/// observer's `started` signal proves the wait parked, its `Cancelled` outcome proves the drop
/// released it; no wall-clock.
///
/// The wait is driven by a manual poll-to-parking then `drop`, rather than `tokio::spawn` +
/// `abort`: that keeps the child accessible (aborting a task that owns the child would drop and
/// reap it) so "stays waitable" is provable on the SAME child, and it isolates the cancel event
/// from the child's own exit (no drop-order race between `signal_cancel` and Drop's kill).
#[skuld::test]
async fn async_wait_drop_cancels_and_child_stays_waitable() {
    // `findstr` with no file argument reads stdin until EOF — a stdin-driven blocker resolvable via
    // PATH (System32), so this unit test needs no CARGO_BIN_EXE testbin.
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (outcome_tx, outcome_rx) = tokio::sync::oneshot::channel();
    let mut c = Command::new();
    c.executable("findstr")
        .args(["findstr", "/c:needle"])
        .stdin(Stdio::pipe())
        .unwrap();
    // The test-only variant injects the observer into THIS child only (no process-global seam).
    let mut child = c.spawn_with_wait_observer(started_tx, outcome_tx).unwrap();

    // Poll the wait future to parking (an unpolled `async fn` runs no code, so this is what brings
    // `spawn_blocking` + `CancelGuard` into existence), await the "parked" signal, then drop the
    // future to fire the cancel event.
    {
        let mut fut = Box::pin(child.wait());
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(
            fut.as_mut().poll(&mut cx).is_pending(),
            "wait must park on a live, wedged child"
        );
        started_rx.await.expect("the blocking watcher parked");
        drop(fut); // CancelGuard signals the cancel event
    }
    // Observed on THIS child, event-driven: the blocking watcher released with Cancelled.
    assert_eq!(outcome_rx.await.unwrap(), WaitOutcome::Cancelled);

    // Child stays waitable: closing its stdin (EOF) lets findstr exit, and a FRESH wait resolves.
    drop(child.stdin().expect("owned stdin writer"));
    child
        .wait()
        .await
        .expect("a fresh wait resolves after the cancelled one");
}

/// The async twin of `a_refused_raw_spawn_does_not_clear_our_handle_inheritance`. Not padding:
/// the async raw backend has its own copy of the ordering, which the sync test cannot see.
///
/// Skuld's default runtime is single-threaded, which matters — the seam is per *thread*, so a
/// multi-thread runtime could move the spawn off this test's thread.
#[cfg(windows)]
#[skuld::test]
async fn an_async_refused_raw_spawn_does_not_clear_our_handle_inheritance() {
    crate::tokio::test_runtime::assert_current_thread();
    use crate::containment::windows::observe;
    use crate::error::Error;

    let mut refused = Command::new();
    refused
        .executable("cmd")
        .args(["cmd", "/C", "exit 0"])
        .contain()
        .creation_flags(windows::Win32::System::Threading::CREATE_SUSPENDED.0);
    observe::take_inheritance_cleared();
    let err =
        crate::child::spawn::failure::expect_not_started(refused.spawn().expect_err("a reserved bit must be refused"));
    assert!(matches!(err, Error::Unsupported { .. }), "got {err:?}");
    assert!(
        !observe::take_inheritance_cleared(),
        "the refusal ran after the mutation it was supposed to precede"
    );

    let mut allowed = Command::new();
    allowed.executable("cmd").args(["cmd", "/C", "exit 0"]).contain();
    let mut child = allowed
        .spawn()
        .expect("the same command without the reserved bit spawns");
    assert!(
        observe::take_inheritance_cleared(),
        "the seam must record a real call, else the negative leg above proves nothing"
    );
    child.wait().await.expect("reap");
}

/// The async twin of `a_raw_spawn_refusing_an_env_nul_does_not_clear_our_handle_inheritance`.
#[cfg(windows)]
#[skuld::test]
async fn an_async_raw_spawn_refusing_an_env_nul_does_not_clear_our_handle_inheritance() {
    crate::tokio::test_runtime::assert_current_thread();
    use crate::containment::windows::observe;
    use crate::error::Error;

    let mut refused = Command::new();
    refused
        .executable("cmd")
        .args(["cmd", "/C", "exit 0"])
        .contain()
        .env("A\0B", "x");
    observe::take_inheritance_cleared();
    let err =
        crate::child::spawn::failure::expect_not_started(refused.spawn().expect_err("an embedded NUL must be refused"));
    assert!(
        matches!(err, Error::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidInput),
        "got {err:?}"
    );
    assert!(
        !observe::take_inheritance_cleared(),
        "the refusal ran after the mutation it was supposed to precede"
    );
}

/// A raw-backend blocker: `findstr` reads its stdin until EOF, and `executable()` routes it to the
/// raw backend.
#[cfg(windows)]
fn raw_blocker() -> Command {
    let mut c = Command::new();
    c.executable("findstr")
        .args(["findstr", "/c:needle"])
        .stdin(Stdio::pipe())
        .unwrap();
    c
}

/// The async twin of `a_raw_spawn_reads_the_identity_before_it_attaches`.
#[cfg(windows)]
#[skuld::test]
async fn an_async_raw_spawn_reads_the_identity_before_it_attaches() {
    crate::tokio::test_runtime::assert_current_thread();
    use crate::child::spawn::fault;
    use crate::error::Error;
    let mut c = raw_blocker();
    fault::set_force_identity_vanished(true);
    fault::set_force_attach_failure(true);
    let result = c.spawn();
    fault::set_force_attach_failure(false);
    fault::set_force_identity_vanished(false);
    let (err, fate) = crate::child::spawn::failure::expect_may_have_started_with(
        result.expect_err("a forced failure fails the spawn"),
    );
    assert!(
        matches!(&err, Error::Io(e) if e.to_string().contains("reaped by another party")),
        "the identity check comes first: {err:?}"
    );
    assert_eq!(
        fate,
        crate::error::ChildFate::Reaped,
        "the raw teardown kills and reaps the child"
    );
    fault::assert_child_reaped(fault::take_captured().expect("the seam captured the child"));
}

/// The async twin of `a_raw_spawn_whose_attach_fails_tears_its_child_down`.
#[cfg(windows)]
#[skuld::test]
async fn an_async_raw_spawn_whose_attach_fails_tears_its_child_down() {
    crate::tokio::test_runtime::assert_current_thread();
    use crate::child::spawn::fault;
    use crate::error::Error;
    let mut c = raw_blocker();
    fault::set_force_attach_failure(true);
    let result = c.spawn();
    fault::set_force_attach_failure(false);
    let (err, fate) = crate::child::spawn::failure::expect_may_have_started_with(
        result.expect_err("the forced attach failure fails the spawn"),
    );
    assert!(matches!(err, Error::Containment { .. }), "{err:?}");
    assert_eq!(fate, crate::error::ChildFate::Reaped, "terminated and waited for");
    fault::assert_child_reaped(fault::take_captured().expect("the seam captured the child"));
}

/// The async twin of `a_raw_spawn_whose_create_process_fails_did_not_start`.
#[cfg(windows)]
#[skuld::test]
async fn an_async_raw_spawn_whose_create_process_fails_did_not_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    let image = dir.path().join("not-a-program.exe");
    std::fs::write(&image, b"not a PE image").expect("write the image");
    let mut c = Command::new();
    c.executable(&image).args(["not-a-program"]);
    let err = crate::child::spawn::failure::expect_not_started(c.spawn().expect_err("a non-PE image fails"));
    assert!(
        matches!(err, crate::error::Error::Io(ref e) if e.raw_os_error().is_some()),
        "{err:?}"
    );
}

/// Every refusal the async raw backend makes before `CreateProcessW` says the program did not start:
/// a batch program, a NUL in the working directory or the command line, an fd table over its limit,
/// and `inherit` on fd 3.
///
/// Mutant: any one of those arms answers that the program may have started.
#[cfg(windows)]
#[skuld::test]
async fn async_raw_refusals_before_create_process_did_not_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bat = dir.path().join("x.bat");
    std::fs::write(&bat, b"@echo off\n").expect("write the batch file");
    let mut batch = Command::new();
    batch.executable(&bat).args(["x.bat"]);
    let mut cwd_nul = Command::new();
    cwd_nul
        .executable("findstr")
        .args(["findstr", "x"])
        .current_dir(std::path::PathBuf::from("a\u{0}b"));
    let mut line_nul = Command::new();
    line_nul.executable("findstr").args(["findstr", "a\u{0}b"]);
    let mut oversized = Command::new();
    oversized.executable("findstr").args(["findstr", "x"]);
    oversized.fd(70_000, Stdio::null()).expect("fd 70000");
    let mut inherit_fd3 = Command::new();
    inherit_fd3.executable("findstr").args(["findstr", "x"]);
    inherit_fd3.fd(3, Stdio::inherit()).expect("fd 3");
    use crate::child::spawn::failure::{invalid_input, unsupported};
    for (what, mut cmd, variant) in [
        ("batch", batch, unsupported as fn(&crate::error::Error) -> bool),
        ("cwd NUL", cwd_nul, invalid_input),
        ("command-line NUL", line_nul, invalid_input),
        ("oversized fd table", oversized, unsupported),
        ("inherit on fd 3", inherit_fd3, unsupported),
    ] {
        let err = crate::child::spawn::failure::expect_not_started(cmd.spawn().expect_err(what));
        assert!(variant(&err), "{what}: not the refusal's own error: {err:?}");
    }
}
