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
#[tokio::test]
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
