//! Reactor-native, non-reaping async grace-wait. Linux: the identity-verified pidfd is
//! registered with the reactor (`AsyncFd`); macOS: a kqueue `EVFILT_PROC|NOTE_EXIT` filter is
//! armed and its kqueue fd registered; Windows has no pollable process handle, so a
//! `spawn_blocking` watcher waits on the process handle AND a cancel event that a drop-guard
//! signals — a dropped grace-wait releases its watcher promptly on every platform. The grace
//! bound (`tokio::time::timeout` on Unix, the kernel wait's timeout on Windows) is a failure
//! bound on a genuine external event: the child's exit. Unix needs the runtime's IO + time
//! drivers (tokio panics otherwise) — documented on the public graceful methods.

use std::time::Duration;

use crate::error::Error;
use crate::identity::ProcessId;

/// Resolve when the process exits — UNBOUNDED, non-reaping, signal-free, identity-verified
/// (a stale/recycled id reports exited immediately). Cancellable: dropping the future
/// deregisters the watch on Unix; on Windows the drop-guard's cancel event releases the
/// blocking watcher promptly.
#[cfg(unix)]
pub(crate) async fn wait_exit(id: ProcessId) -> Result<(), Error> {
    // Shared watch fault seam (take-semantics; the async fn body runs on the arming thread).
    #[cfg(test)]
    if crate::wait::fault::take_force_watch_error() {
        return Err(crate::wait::fault::forced_watch_error());
    }
    exit_watch(id).await
}

/// `Ok(true)` = the process exited within `grace`; `Ok(false)` = still alive at the deadline.
/// Non-reaping and signal-free; identity-verified (a stale/recycled id reports exited).
/// `Duration::ZERO` performs the sync backend's one-shot non-blocking probe.
#[cfg(unix)]
pub(crate) async fn grace_wait(id: ProcessId, grace: Duration) -> Result<bool, Error> {
    if grace.is_zero() {
        // Delegates to the sync ZERO probe (bounded-instant, safe from async); consumes the
        // fault seam there.
        return crate::wait::block_until_exit(id, Some(Duration::ZERO));
    }
    match ::tokio::time::timeout(grace, wait_exit(id)).await {
        Ok(watch) => watch.map(|()| true),
        Err(_elapsed) => Ok(false),
    }
}

#[cfg(windows)]
async fn blocking_watch(id: ProcessId, grace: Option<Duration>) -> Result<bool, Error> {
    /// Signals the cancel event on drop (harmless after completion) so the blocking watcher
    /// returns promptly instead of parking out the grace, and `Runtime::drop` — which joins
    /// blocking tasks — does not stall.
    struct SignalOnDrop(std::sync::Arc<std::os::windows::io::OwnedHandle>);
    impl Drop for SignalOnDrop {
        fn drop(&mut self) {
            crate::wait::backend::signal_cancel(&self.0);
        }
    }
    let cancel = std::sync::Arc::new(crate::wait::backend::new_cancel_event()?);
    let _guard = SignalOnDrop(cancel.clone());
    let joined = ::tokio::task::spawn_blocking(move || {
        let result = crate::wait::backend::block_until_exit_or_cancel(id, grace, &cancel);
        #[cfg(test)]
        fault_observer::notify_released();
        result
    })
    .await;
    match joined {
        Ok(result) => result,
        // block_until_exit_or_cancel does not panic — a panic here is a bug, not an I/O
        // condition; propagate it instead of masking it as an error.
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        // Keep the shutdown-cancelled discriminator visible instead of folding it into an
        // opaque error indistinguishable from a real wait failure. The final arm is
        // presently unreachable (panic and cancelled are tokio's only variants today) and
        // exists for type-system conservatism: a future variant surfaces as an Err, never a
        // false success — with a debug tripwire, mirroring the unexpected-wait-verdict arm.
        Err(e) if e.is_cancelled() => Err(Error::Io(std::io::Error::other(
            "grace-wait watcher cancelled (runtime shutting down)",
        ))),
        Err(e) => {
            debug_assert!(false, "unknown JoinError variant: {e:?}");
            Err(Error::Io(std::io::Error::other(e)))
        }
    }
}

/// `Ok(true)` = the process exited within `grace`; `Ok(false)` = still alive at the deadline.
/// Non-reaping and signal-free; identity-verified (a stale/recycled id reports exited).
/// `Duration::ZERO` performs the sync backend's one-shot non-blocking probe.
///
/// **Windows:** Graces >= ~49.7 days (`INFINITE - 1` ms) are silently clamped to that cap —
/// a platform limit. A debug_assert surfaces this clamping in tests. On production, the clamp
/// is silent; a use case needing a genuinely unbounded watch composes `wait()` (unbounded,
/// cancellable) with its own escalation instead of a grace.
#[cfg(windows)]
pub(crate) async fn grace_wait(id: ProcessId, grace: Duration) -> Result<bool, Error> {
    // Shared watch fault seam (take-semantics; the async fn body runs on the arming thread).
    #[cfg(test)]
    if crate::wait::fault::take_force_watch_error() {
        return Err(crate::wait::fault::forced_watch_error());
    }
    blocking_watch(id, Some(grace)).await
}

/// Resolve when the process exits — UNBOUNDED, non-reaping, signal-free, identity-verified
/// (a stale/recycled id reports exited immediately). Cancellable: dropping the future
/// deregisters the watch on Unix; on Windows the drop-guard's cancel event releases the
/// blocking watcher promptly.
#[cfg(windows)]
pub(crate) async fn wait_exit(id: ProcessId) -> Result<(), Error> {
    // Shared watch fault seam (take-semantics; the async fn body runs on the arming thread).
    #[cfg(test)]
    if crate::wait::fault::take_force_watch_error() {
        return Err(crate::wait::fault::forced_watch_error());
    }
    // An unbounded watch (`None` => INFINITE) has no timeout path, and cancel-at-drop never
    // RESOLVES the future (it is gone) — so a resolved watch means exit. If that contract
    // ever broke, re-watching — not returning — preserves the postcondition (the Unix
    // exit_watch's false-positive re-await idiom); the debug_assert trips it in tests.
    loop {
        let exited = blocking_watch(id, None).await?;
        debug_assert!(exited, "an unbounded watch resolved without an exit");
        if exited {
            return Ok(());
        }
        log::warn!("unbounded watch for {id:?} resolved without an exit; re-watching");
    }
}

/// Deliberate test scaffolding (the `wait::fault` pattern): signals when the blocking
/// watcher RETURNS, so a test can prove drop-release with a plain `recv()` — the
/// no-time-sync alternative to observing teardown timing. Absent from non-test builds.
#[cfg(all(test, windows))]
pub(crate) mod fault_observer {
    use std::sync::mpsc::Sender;
    use std::sync::Mutex;
    static RELEASE_TX: Mutex<Option<Sender<()>>> = Mutex::new(None);
    pub(crate) fn install_release_observer(tx: Sender<()>) {
        *RELEASE_TX.lock().unwrap() = Some(tx);
    }
    pub(crate) fn notify_released() {
        if let Some(tx) = RELEASE_TX.lock().unwrap().as_ref() {
            let _ = tx.send(());
        }
    }
}

/// Resolve when the process exits (no internal timeout — the caller bounds it).
#[cfg(target_os = "linux")]
async fn exit_watch(id: ProcessId) -> Result<(), Error> {
    use ::tokio::io::unix::AsyncFd;
    use ::tokio::io::Interest;
    let Some(pidfd) = crate::wait::backend::open_verified(id, "its exit cannot be observed")? else {
        return Ok(());
    };
    // The pidfd becomes readable (POLLIN) when the task becomes a zombie; POLLHUP once
    // reaped. Either readiness is terminal. A registration failure here (reactor at
    // capacity, etc.) is a genuine I/O error; a MISSING IO driver panics inside tokio
    // instead (documented on the graceful methods).
    let afd = AsyncFd::with_interest(pidfd, Interest::READABLE | Interest::ERROR).map_err(Error::Io)?;
    // ready() may complete with an empty/unclassified set (tokio's documented false
    // positive) — the same re-await discipline as the macOS watch_readable loop.
    loop {
        let mut guard = afd
            .ready(Interest::READABLE | Interest::ERROR)
            .await
            .map_err(Error::Io)?;
        match classify_pidfd_ready(guard.ready()) {
            Some(verdict) => return verdict,
            None => guard.clear_ready(), // false-positive wake — re-await
        }
    }
}

/// Map a pidfd readiness to the watch verdict; `None` = unclassified readiness (tokio's
/// documented `ready()` false positive) — re-await: never a false "exited" (which would skip
/// escalation on a live child) and never a false watch failure (which would force-kill a
/// gracefully-exiting child). Factored out so the POLLERR branch and the readiness contract
/// are unit-testable with synthetic `Ready` values — a real pidfd cannot be made to surface
/// POLLERR on demand.
#[cfg(target_os = "linux")]
fn classify_pidfd_ready(ready: ::tokio::io::Ready) -> Option<Result<(), Error>> {
    // Mirror the sync backend: POLLERR is an error; POLLIN (zombie) / POLLHUP (reaped) = exited.
    if ready.is_error() {
        return Some(Err(Error::Io(std::io::Error::other("pidfd poll returned POLLERR"))));
    }
    if ready.is_readable() || ready.is_read_closed() {
        return Some(Ok(()));
    }
    None
}

/// Resolve when the process exits (no internal timeout — the caller bounds it).
#[cfg(target_os = "macos")]
async fn exit_watch(id: ProcessId) -> Result<(), Error> {
    use ::tokio::io::unix::AsyncFd;
    use ::tokio::io::Interest;
    let Some(kq) = crate::wait::backend::arm_proc_exit(id)? else {
        return Ok(());
    };
    let afd = AsyncFd::with_interest(KqueueFd(kq), Interest::READABLE).map_err(Error::Io)?;
    watch_readable(&afd, crate::wait::backend::drain_proc_exit).await
}

/// `AsyncFd` requires `AsRawFd`; nix's `Kqueue` exposes only `AsFd` — delegate.
#[cfg(target_os = "macos")]
struct KqueueFd(nix::sys::event::Kqueue);
#[cfg(target_os = "macos")]
impl std::os::fd::AsRawFd for KqueueFd {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsFd;
        self.0.as_fd().as_raw_fd()
    }
}

/// The readiness/drain loop, parameterized over the drain so the re-await cycle is testable
/// against the REAL `AsyncFd` (see `wait_tests`). Exit is concluded only on a drained event;
/// `clear_ready` only after an EMPTY drain — mio's edge-triggered (`EV_CLEAR`) would-block
/// contract.
#[cfg(target_os = "macos")]
async fn watch_readable<F>(afd: &::tokio::io::unix::AsyncFd<KqueueFd>, mut drain: F) -> Result<(), Error>
where
    F: FnMut(&nix::sys::event::Kqueue) -> Result<Option<()>, Error>,
{
    loop {
        let mut guard = afd.readable().await.map_err(Error::Io)?;
        match drain(&afd.get_ref().0)? {
            Some(()) => return Ok(()),
            None => guard.clear_ready(), // no exit drained — re-await
        }
    }
}

/// Resolve when every holder of the containment marker's write end has exited — UNBOUNDED IN
/// BOTH TIME AND CPU, poll-free below `NOTE_LOWAT`'s clamp, reactor-native.
///
/// **Unlike `block_until_drained`, this future has no deadline parameter and no internal
/// bound at all.** Below the clamp it genuinely never wakes except on `EV_EOF` (poll-free,
/// same as the sync form). At or past the clamp (a member sustaining writes ≥ the pipe's
/// buffer capacity), `watch_readable`'s drain-then-re-await loop has no deadline to check
/// against, so it keeps draining and re-awaiting for as long as the writer keeps writing —
/// CPU-proportional to the writer's throughput, for as long as the future is polled, with
/// nothing here to end it. A caller that wants a bound MUST supply one externally (e.g.
/// `tokio::time::timeout`, the same pattern `grace_wait` already uses over `wait_exit` in
/// this file) — that is a caller obligation this doc states explicitly, not a property this
/// function has.
///
/// Exited is not reaped: this says nothing about statuses. A caller wanting a status waits on
/// the root as well.
///
/// The marker's own kqueue is what gets registered with the reactor, not the marker
/// descriptor: a knote is keyed on `(kqueue, fd, filter)`, so a second waiter registering the
/// same descriptor directly would take over the first's registration and park it forever —
/// each call arms its OWN private kqueue (`marker_eof::arm`).
///
/// No production caller exists yet — Task 6 (`Attached::wait_drained`) wires the SYNC form
/// only; wiring this async form into `graceful_shutdown_tree` is #62's job. `#[allow(dead_code)]`
/// reflects that honestly, mirroring `marker_eof::probe`.
#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub(crate) async fn wait_tree_drained(read_end: std::os::fd::BorrowedFd<'_>) -> Result<(), Error> {
    wait_tree_drained_inner(read_end, None).await
}

/// Test-only entry point that reports the instant its kqueue is armed, on a channel the
/// CALLER owns — no shared/global observer state, so concurrently-running tests (this file
/// has four) cannot steal each other's notification.
#[cfg(all(test, target_os = "macos"))]
pub(crate) async fn wait_tree_drained_for_test(
    read_end: std::os::fd::BorrowedFd<'_>,
    armed: std::sync::mpsc::Sender<()>,
) -> Result<(), Error> {
    wait_tree_drained_inner(read_end, Some(armed)).await
}

#[cfg(target_os = "macos")]
async fn wait_tree_drained_inner(
    read_end: std::os::fd::BorrowedFd<'_>,
    armed: Option<std::sync::mpsc::Sender<()>>,
) -> Result<(), Error> {
    use ::tokio::io::unix::AsyncFd;
    use ::tokio::io::Interest;
    // Unbounded: this future has no deadline parameter at all (see the doc comment above).
    let kq = crate::containment::marker_eof::arm(read_end, true)?;
    if let Some(tx) = armed {
        let _ = tx.send(());
    }
    let afd = AsyncFd::with_interest(KqueueFd(kq), Interest::READABLE).map_err(Error::Io)?;
    watch_readable(&afd, move |kq| {
        crate::containment::marker_eof::drain_kqueue(kq, read_end).map(|d| d.map(|_| ()))
    })
    .await
}

#[cfg(test)]
#[path = "wait_tests.rs"]
mod wait_tests;
