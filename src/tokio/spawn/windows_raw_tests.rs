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

/// A raw-backend blocker only a kill ends: `more.com` on a pipe whose writer the teardown's kill
/// releases (see [`fault::teardown_blocker_stdin`](crate::child::spawn::fault::teardown_blocker_stdin)),
/// so a teardown that sent no kill reaps a child that exited 0, which `assert_killed` rejects,
/// instead of waiting on it for ever. `executable()` routes it to the raw backend.
#[cfg(windows)]
fn raw_blocker() -> (Command, crate::child::spawn::fault::TeardownBlocker) {
    let crate::child::spawn::fault::TeardownBlockerParts {
        argv,
        stdin,
        stdout,
        guard,
    } = crate::child::spawn::fault::teardown_blocker_parts();
    let mut c = Command::new();
    c.executable(&argv[0]).args(argv);
    c.stdin(stdin).unwrap();
    c.stdout(stdout.expect("a Windows blocker nulls its stdout")).unwrap();
    (c, guard)
}

/// The async twin of `a_raw_spawn_reads_the_identity_before_it_attaches`.
#[cfg(windows)]
#[skuld::test]
async fn an_async_raw_spawn_reads_the_identity_before_it_attaches() {
    crate::tokio::test_runtime::assert_current_thread();
    use crate::child::spawn::fault;
    use crate::error::Error;
    let (mut c, teardown) = raw_blocker();
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
    teardown.assert_killed();
    fault::assert_child_reaped(fault::take_captured().expect("the seam captured the child"));
}

/// The async twin of `a_raw_spawn_whose_attach_fails_tears_its_child_down`.
#[cfg(windows)]
#[skuld::test]
async fn an_async_raw_spawn_whose_attach_fails_tears_its_child_down() {
    crate::tokio::test_runtime::assert_current_thread();
    use crate::child::spawn::fault;
    use crate::error::Error;
    let (mut c, teardown) = raw_blocker();
    fault::set_force_attach_failure(true);
    let result = c.spawn();
    fault::set_force_attach_failure(false);
    let (err, fate) = crate::child::spawn::failure::expect_may_have_started_with(
        result.expect_err("the forced attach failure fails the spawn"),
    );
    assert!(matches!(err, Error::Containment { .. }), "{err:?}");
    assert_eq!(fate, crate::error::ChildFate::Reaped, "terminated and waited for");
    teardown.assert_killed();
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

/// A failed `TerminateProcess` reports the plain Win32 code. An event handle is a real handle that
/// is not a process, so the kill fails with `ERROR_INVALID_HANDLE`.
///
/// Mutant: the final arm of `RawAsyncChild::start_kill` converts with `.into()`, so the code is
/// `0x80070006`.
#[skuld::test]
fn a_failed_start_kill_is_reported_as_its_win32_code() {
    use crate::tokio::spawn::windows_raw::RawAsyncChild;
    let event = crate::os_process::windows::new_cancel_event().expect("create an event");
    let child = RawAsyncChild::new(event);
    let err = child.start_kill().expect_err("an event cannot be terminated");
    let crate::error::Error::Io(err) = err else {
        panic!("expected Io, got {err:?}");
    };
    assert_eq!(
        err.raw_os_error(),
        Some(windows::Win32::Foundation::ERROR_INVALID_HANDLE.0 as i32),
        "{err:?}"
    );
}

/// A handle without `PROCESS_TERMINATE` to a child that has exited: its signalled state is the
/// exit, so `start_kill` succeeds.
///
/// Mutant: `start_kill` reads the refusal by the handle's rights alone, so it returns
/// `ERROR_ACCESS_DENIED` for a dead child.
#[skuld::test]
fn start_kill_of_a_handle_without_terminate_to_an_exited_child_succeeds() {
    use crate::tokio::spawn::windows_raw::RawAsyncChild;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Threading::{
        OpenProcess, WaitForSingleObject, INFINITE, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };

    let std_child = crate::test_spawn::spawn(std::process::Command::new("cmd").args(["/C", "exit 0"])).expect("spawn");
    // SAFETY: `std_child` owns the live handle; it is only waited on.
    unsafe { WaitForSingleObject(HANDLE(std_child.as_raw_handle()), INFINITE) };
    // SAFETY: `std_child` pins the pid.
    let limited = unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            std_child.id(),
        )
    }
    .expect("open without PROCESS_TERMINATE");
    // SAFETY: `limited` is a fresh owned handle.
    let child = RawAsyncChild::new(unsafe { OwnedHandle::from_raw_handle(limited.0) });
    child
        .start_kill()
        .expect("a signalled process is the exit, not a denial");
}

/// A handle without `PROCESS_TERMINATE` to a live child (a higher-integrity runas child): the
/// refusal is a denial, not the exit.
///
/// Mutant: every `ERROR_ACCESS_DENIED` reads as the exit, so `start_kill` is `Ok` for a live child.
#[skuld::test]
fn start_kill_of_a_handle_without_terminate_to_a_live_child_is_denied() {
    use crate::tokio::spawn::windows_raw::RawAsyncChild;
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE};

    let mut std_child = crate::test_spawn::spawn(
        std::process::Command::new("cmd")
            .args(["/C", "more"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
    )
    .expect("spawn a child that blocks on stdin");
    // SAFETY: `std_child` pins the pid.
    let limited = unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            std_child.id(),
        )
    }
    .expect("open without PROCESS_TERMINATE");
    // SAFETY: `limited` is a fresh owned handle.
    let child = RawAsyncChild::new(unsafe { OwnedHandle::from_raw_handle(limited.0) });
    let result = child.start_kill();
    std_child.kill().expect("end the fixture");
    std_child.wait().expect("reap the fixture");
    let crate::error::Error::Io(err) = result.expect_err("a live child behind a handle without the right") else {
        panic!("expected Io");
    };
    assert_eq!(err.raw_os_error(), Some(ERROR_ACCESS_DENIED.0 as i32), "{err:?}");
}
