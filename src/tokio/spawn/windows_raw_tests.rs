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

/// The async twin of `a_refused_raw_spawn_does_not_clear_our_handle_inheritance`. Not padding:
/// the async raw backend has its own copy of the ordering, which the sync test cannot see.
///
/// `#[tokio::test]` is single-threaded, which matters — the seam is per *thread*, so a
/// multi-thread runtime could move the spawn off this test's thread.
#[cfg(windows)]
#[tokio::test]
async fn an_async_refused_raw_spawn_does_not_clear_our_handle_inheritance() {
    use crate::containment::windows::observe;
    use crate::error::Error;

    let mut refused = Command::new();
    refused
        .executable("cmd")
        .args(["cmd", "/C", "exit 0"])
        .contain()
        .creation_flags(windows::Win32::System::Threading::CREATE_SUSPENDED.0);
    observe::take_inheritance_cleared();
    let err = refused.spawn().expect_err("a reserved bit must be refused");
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

/// `Held::wait`'s `RawAsync` arm calls `RawAsyncChild::wait_blocking`, not `wait_and_reap`: the
/// generic `Unreaped` wait/`Drop` carries no precondition that a kill preceded it (an `Unreaped`
/// exists exactly because a kill failed or was never attempted), so a `WaitForSingleObject`
/// failure there must come back as an `io::Error`, not a `debug_assert` panic. A real failure
/// needs a handle genuinely missing `SYNCHRONIZE` (an unkillable runas child), which a unit test
/// cannot arrange — the forced-failure seam exercises the same code path deterministically.
#[tokio::test]
async fn wait_blocking_returns_the_forced_failure_instead_of_asserting() {
    use std::os::windows::io::OwnedHandle;

    use super::RawAsyncChild;

    // A quickly-exiting child: the forced-failure seam short-circuits before any real OS wait, so
    // this need not stay running.
    let child = std::process::Command::new(std::env::current_exe().expect("current_exe"))
        .args(["--exact", "__cosca_no_such_test__"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn a quickly-exiting child");
    let pid = child.id();
    let mut raw = RawAsyncChild::new(OwnedHandle::from(child), pid);
    raw.set_force_wait_blocking_failure("forced wait_blocking failure");
    let err = raw
        .wait_blocking()
        .expect_err("a forced OS wait failure must be returned, not asserted away");
    assert_eq!(err.to_string(), "forced wait_blocking failure");
    // Real: the forced failure did not memoize an exit, so a real wait afterward still succeeds.
    raw.wait_blocking()
        .expect("a real wait after the forced failure still succeeds");
}

/// The same seam, but driven through `crate::Unreaped::wait` — the actual caller of
/// `Held::wait`'s `RawAsync` arm in production — not `wait_blocking` called directly as above.
/// `wait_blocking_returns_the_forced_failure_instead_of_asserting` proves `wait_blocking` itself
/// returns the forced error rather than asserting; this proves that error actually surfaces
/// through the generic `Unreaped` path a real caller uses, rather than being swallowed or panicked
/// on somewhere between `Held::wait` and `Unreaped::wait`.
#[tokio::test]
async fn unreaped_wait_returns_the_forced_wait_blocking_failure() {
    use std::os::windows::io::OwnedHandle;

    use super::RawAsyncChild;

    let child = std::process::Command::new(std::env::current_exe().expect("current_exe"))
        .args(["--exact", "__cosca_no_such_test__"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn a quickly-exiting child");
    let pid = child.id();
    let mut raw = RawAsyncChild::new(OwnedHandle::from(child), pid);
    raw.set_force_wait_blocking_failure("forced wait_blocking failure");
    let unreaped = crate::Unreaped::new(crate::child::unreaped::Held::RawAsync(raw));
    let err = unreaped
        .wait()
        .expect_err("the forced wait_blocking failure must surface through Unreaped::wait");
    assert_eq!(err.to_string(), "forced wait_blocking failure");
}

/// The async twin of `a_raw_spawn_refusing_an_env_nul_does_not_clear_our_handle_inheritance`.
#[cfg(windows)]
#[tokio::test]
async fn an_async_raw_spawn_refusing_an_env_nul_does_not_clear_our_handle_inheritance() {
    use crate::containment::windows::observe;
    use crate::error::Error;

    let mut refused = Command::new();
    refused
        .executable("cmd")
        .args(["cmd", "/C", "exit 0"])
        .contain()
        .env("A\0B", "x");
    observe::take_inheritance_cleared();
    let err = refused.spawn().expect_err("an embedded NUL must be refused");
    assert!(
        matches!(err, Error::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidInput),
        "got {err:?}"
    );
    assert!(
        !observe::take_inheritance_cleared(),
        "the refusal ran after the mutation it was supposed to precede"
    );
}
