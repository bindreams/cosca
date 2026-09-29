//! Reactor-native, non-reaping async grace-wait. Linux: the identity-verified pidfd is
//! registered with the reactor (`AsyncFd`); macOS: a kqueue `EVFILT_PROC|NOTE_EXIT` filter is
//! armed and its kqueue fd registered; Windows has no pollable process handle, so a
//! `spawn_blocking` watcher waits on the process handle AND a cancel event that a drop-guard
//! signals — a dropped grace-wait releases its watcher promptly on every platform. The grace
//! bound (on Unix `tokio::time::timeout_at`, via [`arm_at`], armed with the caller's deadline
//! instant; the kernel wait's timeout on Windows) is a failure bound on a genuine external
//! event: the child's exit. Unix needs the runtime's IO + time drivers (tokio panics otherwise)
//! — documented on the public graceful methods.

use std::time::Duration;

use crate::error::Error;
use crate::identity::ProcessId;

/// The clock every async wait here runs on: tokio's, which is `std`'s unless a test pauses it.
/// Deadlines are `std` instants read off this timeline, so the timer, the "already expired" checks
/// and [`deadline_from`] agree on what "now" is.
pub(crate) fn tokio_now() -> std::time::Instant {
    #[cfg(test)]
    if let Some(now) = now_override::get() {
        return now;
    }
    ::tokio::time::Instant::now().into_std()
}

/// The async twin of [`crate::wait::deadline_from`], on [`tokio_now`]'s clock.
pub(crate) fn deadline_from(duration: Duration) -> Option<Option<std::time::Instant>> {
    Some(crate::wait::deadline_at(tokio_now(), duration))
}

/// The ONLY place a bounded async wait is armed: `tokio::time::timeout_at(at, fut)`, with the
/// caller's deadline instant (never a duration re-derived from it, which would arm later).
/// `None` = the deadline elapsed first. `at` must clear
/// [`crate::wait::TOKIO_TIMER_ROUNDING_MARGIN`], as every [`deadline_from`] result does; a
/// violation `debug_assert`s, and in release waits unbounded with no timer.
#[cfg(unix)]
async fn arm_at<F: std::future::Future>(at: std::time::Instant, fut: F) -> Option<F::Output> {
    let holds = crate::wait::clears_tokio_timer_margin(at);
    debug_assert!(
        holds,
        "deadline_from's contract should prevent a deadline inside tokio's timer margin"
    );
    if !holds {
        #[cfg(test)]
        armed_deadline_seam::notify(armed_deadline_seam::Armed::Unbounded);
        return Some(fut.await);
    }
    #[cfg(test)]
    armed_deadline_seam::notify(armed_deadline_seam::Armed::At(at));
    #[expect(clippy::disallowed_methods, reason = "the one sanctioned timeout_at call")]
    let armed = ::tokio::time::timeout_at(::tokio::time::Instant::from_std(at), fut);
    armed.await.ok()
}

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
    // An overflowing `grace`, or one inside tokio's timer margin, is `Some(None)`: unbounded, no timer.
    match deadline_from(grace) {
        Some(Some(at)) => match arm_at(at, wait_exit(id)).await {
            Some(watch) => watch.map(|()| true),
            // The timer can win the first poll before the reactor reports an exit that was
            // already pending: answer from one final non-blocking probe, as the sync twin does.
            None => crate::wait::block_until_exit(id, Some(Duration::ZERO)),
        },
        _ => wait_exit(id).await.map(|()| true),
    }
}

/// `deadline` (real clock, `None` = unbounded) is fixed by the caller before `spawn_blocking`, so
/// a saturated blocking pool cannot delay it.
#[cfg(windows)]
async fn blocking_watch(id: ProcessId, deadline: Option<std::time::Instant>) -> Result<bool, Error> {
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
    // Test-only: `armed_probe`, `read_probe` and `fault_observer` are thread-local (see their
    // docs for why), and this closure runs on a blocking-pool thread distinct from this one (the
    // "arming" thread) — so read whatever THIS thread has installed now, while still on it
    // (nothing before this point yields), and move the captured values into the closure to
    // re-install on ITS thread.
    #[cfg(test)]
    let armed_tx = crate::wait::backend::armed_probe::current();
    #[cfg(test)]
    let read_tx = crate::wait::read_probe::current();
    #[cfg(test)]
    let released_tx = fault_observer::current();
    let joined = ::tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        let _armed_guard = armed_tx.map(crate::wait::backend::armed_probe::install);
        #[cfg(test)]
        let _read_guard = read_tx.map(crate::wait::read_probe::install);
        #[cfg(test)]
        let _released_guard = released_tx.map(fault_observer::install);
        let result = crate::wait::backend::block_until_exit_or_cancel(id, deadline, &cancel);
        #[cfg(test)]
        if !matches!(result, Ok(true)) {
            fault_observer::notify_released();
        }
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
/// **Windows:** a single `WaitForMultipleObjects` call is capped at ~49.7 days
/// (`INFINITE - 1` ms — `WaitForMultipleObjects` reserves `INFINITE` itself as the "no
/// timeout" sentinel), but a grace longer than that is still honored correctly: the backend
/// re-arms past the cap rather than reporting the process still alive once the cap elapses. A
/// grace that overflows `Instant`, or lands within [`TOKIO_TIMER_ROUNDING_MARGIN`] of its
/// ceiling, is unbounded (see [`deadline_from`]), as on Unix.
///
/// [`TOKIO_TIMER_ROUNDING_MARGIN`]: crate::wait::TOKIO_TIMER_ROUNDING_MARGIN
#[cfg(windows)]
pub(crate) async fn grace_wait(id: ProcessId, grace: Duration) -> Result<bool, Error> {
    // Shared watch fault seam (take-semantics; the async fn body runs on the arming thread).
    #[cfg(test)]
    if crate::wait::fault::take_force_watch_error() {
        return Err(crate::wait::fault::forced_watch_error());
    }
    // Fixed before `spawn_blocking`; the blocking thread only recomputes against it.
    let deadline = to_real_clock(deadline_from(grace)).flatten();
    blocking_watch(id, deadline).await
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
///
/// `thread_local!`, not a process-global slot, for the same reason `crate::wait::backend::
/// armed_probe` is (see its own doc): `notify_released` runs inside `blocking_watch`'s
/// `spawn_blocking` closure, the SAME function EVERY grace-wait/wait-exit call in the binary
/// goes through, so a global slot would let an unrelated watch on another thread notify THIS
/// thread's observer — `wait_exit_drop_releases_the_windows_watcher`'s `rx.recv()` returning on
/// a stranger's release, not its own, would be a vacuous pass under plain `cargo test`'s
/// shared-process, many-threads model. Relayed across the `spawn_blocking` boundary the
/// identical way: `blocking_watch` reads [`current`] on the arming thread (cloned, before
/// calling `spawn_blocking` — nothing before that call yields) and moves the captured value
/// into the closure, re-installing it there via [`install`]'s `Guard`, scoped to that one
/// blocking-pool call.
#[cfg(all(test, windows))]
pub(crate) mod fault_observer {
    use std::cell::RefCell;
    use std::sync::mpsc::Sender;

    thread_local! {
        static RELEASE_TX: RefCell<Option<Sender<()>>> = const { RefCell::new(None) };
    }

    /// `!Send` — see `crate::wait::backend::armed_probe::Guard`'s own doc for why: dropping it
    /// on another thread would clear THAT thread's slot instead of the one it was installed on.
    #[must_use = "dropping this immediately uninstalls the observer; bind it for its duration"]
    pub(crate) struct Guard(std::marker::PhantomData<*const ()>);

    pub(crate) fn install(tx: Sender<()>) -> Guard {
        let prev = RELEASE_TX.with(|cell| cell.replace(Some(tx)));
        debug_assert!(prev.is_none(), "fault_observer::install nested on the same thread");
        Guard(std::marker::PhantomData)
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            RELEASE_TX.with(|cell| *cell.borrow_mut() = None);
        }
    }

    /// The CURRENT thread's installed observer, if any — read on the arming thread, before
    /// `spawn_blocking`, so `blocking_watch` can `move` it into that closure. Cloned, not
    /// taken: the arming thread's own installation must survive for its guard's whole
    /// lifetime, which may span more than one `blocking_watch` call (e.g. `wait_exit`'s retry
    /// loop).
    pub(crate) fn current() -> Option<Sender<()>> {
        RELEASE_TX.with(|cell| cell.borrow().clone())
    }

    pub(crate) fn notify_released() {
        RELEASE_TX.with(|cell| {
            if let Some(tx) = cell.borrow().as_ref() {
                _ = tx.send(());
            }
        });
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
///
/// `drain` returning `Ok(None)` is what `clear_ready` treats as "empty" — this loop has no way
/// to verify that itself, since the closure's return type carries no more than "done" or "not
/// done". The invariant holds for both current callers: `drain_proc_exit`'s only non-`None`
/// outcome is `NOTE_EXIT`, with no draining concept at all, and `marker_eof::drain_kqueue`'s
/// caller here (`wait_tree_drained_inner`) passes through the SAME `unbounded_wait` its own
/// caller computed from the real deadline (`crate::wait::remaining(deadline).is_none()`,
/// matching the sync backend's `block_until_drained` exactly) — when `true`,
/// `interpret_read_event` never drains at all (see `marker_eof`'s module doc — an unbounded wait
/// cannot drain on a sustained writer's behalf without spinning); when `false`, a non-`None`
/// non-terminal event DOES drain bytes, but only inside `interpret_read_event`'s own
/// already-verified `Ok(None)` return, so the invariant this loop relies on — no closure
/// silently drains behind an `Ok(None)` it can't see — still holds. A future `drain` closure
/// that consumed bytes on a DIFFERENT non-`None`-but-non-terminal path would violate that
/// silently; `watch_readable` cannot detect that on its own, so any such closure owns
/// re-verifying this invariant itself.
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

/// Resolve when every holder of the containment marker's write end has exited — genuinely
/// poll-free, reactor-native, and with no internal deadline at all.
///
/// **Unlike `block_until_drained`, this future has no deadline parameter.** Below `NOTE_LOWAT`'s
/// clamp it never wakes except on `EV_EOF`. At or past the clamp (a member sustaining writes ≥
/// the pipe's buffer capacity) this primitive does NOT drain on the writer's behalf, unlike the
/// sync form's bounded case — see `marker_eof`'s module doc for why an unbounded wait cannot
/// honestly offer both zero CPU and forward progress for a sustained writer, and why this
/// primitive, having no deadline to bound the alternative, chooses zero CPU: the writer's own
/// `write()` call blocks against the full pipe (the marker fd's documented misuse contract —
/// `fdmarker`'s module doc), and this future stays genuinely asleep until that descriptor
/// closes. A caller that wants such a writer to make forward progress toward closing the
/// descriptor cannot get that from this primitive; a caller that merely wants a time bound on
/// the wait itself can still bound it with a deadline instant (`grace_wait` bounds `wait_exit`
/// this way in this file: `deadline_from`, then `arm_at`; outside the crate,
/// `tokio::time::timeout_at`) — that bounds the CALLER's patience, not the writer's blocked
/// state.
///
/// Exited is not reaped: this says nothing about statuses. A caller wanting a status waits on
/// the root as well.
///
/// The marker's own kqueue is what gets registered with the reactor, not the marker
/// descriptor: a knote is keyed on `(kqueue, fd, filter)`, so a second waiter registering the
/// same descriptor directly would take over the first's registration and park it forever —
/// each call arms its OWN private kqueue (`marker_eof::arm`).
///
#[cfg(target_os = "macos")]
pub(crate) async fn wait_tree_drained(read_end: std::os::fd::BorrowedFd<'_>) -> Result<(), Error> {
    wait_tree_drained_watched(read_end, None).await
}

/// Deadline-bounded, [`TreeDrain`](crate::containment::TreeDrain)-returning wrapper over
/// [`wait_tree_drained_inner`] — the macOS arm of `tokio::Child::wait_tree`/`wait_tree_timeout`.
/// `Duration::ZERO` delegates to the sync backend's one-shot, non-blocking probe (safe to call
/// directly from async code), matching `grace_wait`'s identical `Duration::ZERO` delegation to
/// `block_until_exit`.
///
/// The bounded arm (`Some(d)`) arms with `unbounded_wait: false` — computed the same way the
/// sync backend's `block_until_drained` does (`crate::wait::remaining(deadline).is_none()`,
/// `false` whenever a real deadline governs this call) — NOT via [`wait_tree_drained`], which is
/// always unbounded by construction (see its own doc). Arming unbounded here would be a real,
/// observable divergence from the sync twin: `refuse_if_write_end_held` would refuse an
/// `Unassessable` write-end scan that a bounded caller should tolerate (its own deadline caps
/// the risk), and `interpret_read_event` would stop draining a sustained writer at the low-water
/// clamp, so a bounded wait could only ever expire into `MembersRemain` where the sync call
/// drains through to the real edge. [`arm_at`] still supplies the actual bound, armed with the
/// caller's deadline instant — the same pattern `grace_wait` uses over `wait_exit` — this only
/// fixes what the ARMED kqueue itself is told.
#[cfg(target_os = "macos")]
pub(crate) async fn wait_tree_deadline(
    read_end: std::os::fd::BorrowedFd<'_>,
    deadline: Option<Option<std::time::Instant>>,
) -> Result<crate::containment::TreeDrain, Error> {
    use crate::containment::TreeDrain;
    match deadline {
        None | Some(None) => {
            wait_tree_drained(read_end).await?;
            Ok(TreeDrain::AllMarkersClosed)
        }
        Some(Some(at)) => {
            if crate::wait::remaining_at(deadline, tokio_now()) == Some(Duration::ZERO) {
                return crate::containment::marker_eof::probe(read_end);
            }
            match arm_at(at, wait_tree_drained_inner(read_end, false, None)).await {
                Some(res) => res.map(|()| TreeDrain::AllMarkersClosed),
                // As in `grace_wait`: one final probe, so an EOF already pending is not missed.
                None => crate::containment::marker_eof::probe(read_end),
            }
        }
    }
}

/// Test seam: fires every time [`wait_tree_drained_inner`]'s watch loop gets
/// `DrainOutcome::Declined` (a genuine non-EOF event, retrieved and interpreted, that did not
/// resolve the wait; its bytes were discarded when `suppress_drain` is false and left buffered
/// when true). Never `Spurious`. A `#[cfg(test)]` thread-local installed by an RAII guard, like
/// `wait::macos::test_hooks::HookGuard`, so no production signature carries it. It relies on a
/// current-thread runtime (`#[tokio::test]`'s default): the future is polled on the installing
/// thread.
#[cfg(all(test, target_os = "macos"))]
pub(crate) mod declined_hook {
    use std::cell::RefCell;

    use ::tokio::sync::mpsc::UnboundedSender;

    thread_local! {
        static DECLINED: RefCell<Option<UnboundedSender<()>>> = const { RefCell::new(None) };
    }

    /// Fire this thread's installed hook, if any. Called only from
    /// [`super::wait_tree_drained_inner`]'s `DrainOutcome::Declined` arm.
    pub(crate) fn notify() {
        DECLINED.with(|d| {
            if let Some(tx) = d.borrow().as_ref() {
                let sent = tx.send(());
                debug_assert!(sent.is_ok(), "declined_hook receiver dropped before the hook fired");
            }
        });
    }

    /// RAII installer: clears the hook on `Drop`, including during unwinding.
    #[must_use]
    pub(crate) struct DeclinedGuard {
        _private: (),
    }

    impl DeclinedGuard {
        pub(crate) fn install(tx: UnboundedSender<()>) -> Self {
            DECLINED.with(|d| {
                let mut slot = d.borrow_mut();
                debug_assert!(slot.is_none(), "a declined_hook is already installed on this thread");
                *slot = Some(tx);
            });
            Self { _private: () }
        }
    }

    impl Drop for DeclinedGuard {
        fn drop(&mut self) {
            DECLINED.with(|d| {
                let prev = d.borrow_mut().take();
                debug_assert!(
                    prev.is_some(),
                    "declined_hook slot was cleared before its guard dropped"
                );
            });
        }
    }
}

/// Test-only entry point that reports the instant its kqueue is armed, on a channel the
/// CALLER owns — no shared/global observer state, so concurrently-running tests (this file
/// has four) cannot steal each other's notification.
#[cfg(all(test, target_os = "macos"))]
pub(crate) async fn wait_tree_drained_for_test(
    read_end: std::os::fd::BorrowedFd<'_>,
    armed: std::sync::mpsc::Sender<std::os::fd::RawFd>,
) -> Result<(), Error> {
    wait_tree_drained_watched(read_end, Some(armed)).await
}

/// The ONE call site for [`wait_tree_drained`]'s own "always unbounded" choice — shared with
/// [`wait_tree_drained_for_test`] so a mutant on that literal breaks both identically. A test
/// that instead called `wait_tree_drained_inner` with its OWN independent `true` would not
/// notice a mutant that changed only the production caller's.
#[cfg(target_os = "macos")]
async fn wait_tree_drained_watched(
    read_end: std::os::fd::BorrowedFd<'_>,
    armed: Option<std::sync::mpsc::Sender<std::os::fd::RawFd>>,
) -> Result<(), Error> {
    wait_tree_drained_inner(read_end, true, armed).await
}

/// `unbounded_wait` must be the SAME expression the sync backend's `block_until_drained` uses
/// (`crate::wait::remaining(deadline).is_none()`) for whichever deadline the caller is honoring
/// — threaded through to both `arm` and `drain_kqueue` (see [`wait_tree_deadline`]'s own doc for
/// why arming this wrong is a real, observable divergence, not a cosmetic one).
///
/// `armed`, if given, receives the raw fd of the kqueue this call just armed (test-only; see
/// [`wait_tree_drained_for_test`]). That fd is valid only while this future is alive.
/// `DrainOutcome::Declined` fires [`declined_hook::notify`] in test builds only.
#[cfg(target_os = "macos")]
async fn wait_tree_drained_inner(
    read_end: std::os::fd::BorrowedFd<'_>,
    unbounded_wait: bool,
    armed: Option<std::sync::mpsc::Sender<std::os::fd::RawFd>>,
) -> Result<(), Error> {
    use std::os::fd::{AsFd, AsRawFd};

    use crate::containment::marker_eof::DrainOutcome;
    use ::tokio::io::unix::AsyncFd;
    use ::tokio::io::Interest;
    let kq = crate::containment::marker_eof::arm(read_end, unbounded_wait)?;
    if let Some(tx) = armed {
        let sent = tx.send(kq.as_fd().as_raw_fd());
        debug_assert!(
            sent.is_ok(),
            "the `armed` receiver was dropped before the kqueue was armed"
        );
    }
    let afd = AsyncFd::with_interest(KqueueFd(kq), Interest::READABLE).map_err(Error::Io)?;
    watch_readable(&afd, move |kq| {
        match crate::containment::marker_eof::drain_kqueue(kq, read_end, unbounded_wait)? {
            DrainOutcome::Drained(_) => Ok(Some(())),
            DrainOutcome::Declined => {
                #[cfg(test)]
                declined_hook::notify();
                Ok(None)
            }
            DrainOutcome::Spurious => Ok(None),
        }
    })
    .await
}

/// Resolve when every process in the cgroup v2 leaf has EXITED (not reaped), or until `deadline`.
/// The async twin of `CgroupLeaf::wait_drained`, taking the same `CgroupLeaf::drain_step`s and
/// awaiting each broadcast where the sync wait blocks on it. It never touches the watch itself, so
/// a future dropped, or never polled again, holds nothing another wait needs. Each round awaits
/// for exactly the caller's own remaining time; no interval anywhere.
#[cfg(target_os = "linux")]
pub(crate) async fn cgroup_wait_tree_drained(
    leaf: &crate::containment::cgroup::CgroupLeaf,
    deadline: Option<Option<std::time::Instant>>,
) -> Result<crate::containment::TreeDrain, Error> {
    use crate::containment::cgroup::DrainStep;

    loop {
        match leaf.drain_step_on(deadline, tokio_now)? {
            DrainStep::Done(drain) => return Ok(drain),
            DrainStep::Block {
                listener,
                deadline: None,
            } => {
                #[cfg(test)]
                armed_deadline_seam::notify(armed_deadline_seam::Armed::Unbounded);
                listener.await
            }
            // The timeout is looked at by the next step, which reads the leaf once more.
            DrainStep::Block {
                listener,
                deadline: Some(at),
            } => {
                let _ = arm_at(at, listener).await;
            }
        }
    }
}

/// Re-express a [`tokio_now`]-clock `deadline` on the real clock, for the Windows job wait, which
/// blocks in the kernel and so is measured in real time. Identical when tokio's clock is unpaused.
#[cfg(any(windows, test))]
pub(crate) fn to_real_clock_at(
    deadline: Option<Option<std::time::Instant>>,
    tokio_now: std::time::Instant,
    real_now: std::time::Instant,
) -> Option<Option<std::time::Instant>> {
    match deadline {
        Some(Some(at)) => Some(crate::wait::deadline_at(
            real_now,
            at.saturating_duration_since(tokio_now),
        )),
        other => other,
    }
}

#[cfg(windows)]
fn to_real_clock(deadline: Option<Option<std::time::Instant>>) -> Option<Option<std::time::Instant>> {
    to_real_clock_at(deadline, tokio_now(), crate::wait::now())
}

/// Resolve when every process in the Windows job has EXITED (not reaped), or until `deadline`.
/// Job objects expose no pollable handle, so — unlike the macOS arm, on the reactor, and the Linux
/// arm, awaiting its leaf's pump — this hands the sync `JobHandle::wait_drained` loop to `spawn_blocking`,
/// releasing the blocking thread promptly on drop via the same cancel-event idiom
/// `blocking_watch` uses for `grace_wait`.
///
/// **Handle ownership across cancellation.** `blocking_watch` gets away with borrowing nothing
/// at all — it re-derives a process handle from a `ProcessId` inside the closure. A job object
/// has no such re-openable identity, so this function instead duplicates the live job `HANDLE`
/// into one the spawned task owns outright (`DuplicateHandle`, closed by the closure itself on
/// every exit path, panic included) before ever spawning. This matters because dropping THIS
/// future only cancels the `.await` — it does not join the blocking task, which keeps running
/// detached. A caller cancelling the `wait_tree`/`wait_tree_timeout` future (via `select!`, an
/// outer `timeout()`, or simply not polling it again) can therefore race `JobHandle::hard_kill`/
/// `Drop` closing the ORIGINAL handle while the detached task is still mid-syscall on it. A
/// borrowed raw `HANDLE` would then alias a handle value the kernel is free to recycle onto an
/// unrelated object the moment it is closed; the duplicate has its own independent lifetime,
/// closed only by the task that owns it, and is never touched by `JobHandle` at all — so no
/// such aliasing is possible regardless of what the caller does with the `Child` after
/// cancelling.
#[cfg(windows)]
async fn job_wait_tree_drained(
    job: &crate::containment::windows::JobHandle,
    deadline: Option<Option<std::time::Instant>>,
) -> Result<crate::containment::TreeDrain, Error> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};

    // The kernel wait runs on the real clock, not tokio's.
    let deadline = to_real_clock(deadline);
    // Duration::ZERO delegates to the sync one-shot probe — no thread-pool hop needed for a
    // call that cannot block (mirrors grace_wait's identical delegation).
    if crate::wait::remaining(deadline) == Some(std::time::Duration::ZERO) {
        return job.wait_drained(deadline, None);
    }
    /// An independently-owned duplicate of the job handle, held only by the spawned blocking
    /// task and closed by it on every exit path, panic included — see this function's own doc
    /// for why a borrowed handle is not safe to hand across the cancellation boundary here.
    /// Closing a job handle only fires `KILL_ON_JOB_CLOSE` if it is the LAST open handle to
    /// that job (Win32 semantics); `JobHandle`'s own, separate handle is unaffected either way.
    struct OwnedJobDup(HANDLE);
    impl Drop for OwnedJobDup {
        fn drop(&mut self) {
            // SAFETY: `self.0` is this struct's own `DuplicateHandle`-created handle, never
            // shared or aliased anywhere else.
            unsafe {
                _ = CloseHandle(self.0);
            }
        }
    }

    // Duplicate INSIDE the closure, so the lock is still held when `DuplicateHandle` reads the
    // handle. Returning the handle out of `with_handle` first would release the guard before
    // the call — leaving the load-then-use gap this is meant to close — and Windows recycles a
    // closed handle's value onto unrelated kernel objects.
    let Some(dup) = job
        .with_handle(crate::containment::windows::duplicate_job)
        .transpose()?
    else {
        // Mirrors `JobHandle::wait_drained`'s own early return exactly (this function only
        // reaches here once that method's Duration::ZERO delegation above has already been
        // ruled out) — see `consumed_job_handle_error`'s own doc for the full justification.
        return Err(crate::containment::windows::consumed_job_handle_error());
    };
    let job_dup = OwnedJobDup(dup);

    /// Signals the cancel event on drop (harmless after completion) so the blocking watcher
    /// releases promptly instead of parking out the deadline, and `Runtime::drop` — which
    /// joins blocking tasks — does not stall. Identical idiom to `blocking_watch`'s guard.
    struct SignalOnDrop(std::sync::Arc<std::os::windows::io::OwnedHandle>);
    impl Drop for SignalOnDrop {
        fn drop(&mut self) {
            crate::wait::backend::signal_cancel(&self.0);
        }
    }
    let cancel = std::sync::Arc::new(crate::wait::backend::new_cancel_event()?);
    let _guard = SignalOnDrop(cancel.clone());
    // SAFETY: `cancel`'s OwnedHandle is kept alive by the Arc clone captured in the
    // spawn_blocking closure below (and by `_guard`/`cancel` here) for the whole wait.
    let cancel_raw = HANDLE(std::os::windows::io::AsRawHandle::as_raw_handle(&*cancel));
    let cancel_for_blocking = cancel.clone();

    /// `HANDLE`'s raw pointer is `!Send` by default; a job or event handle (owned or borrowed
    /// for the task's own full lifetime) is sound to use and close from another thread — the
    /// kernel serialises handle operations — the same justification as `JobHandle`'s own
    /// `unsafe impl Send`.
    struct SendHandles {
        job: OwnedJobDup,
        cancel: HANDLE,
    }
    unsafe impl Send for SendHandles {}
    let handles = SendHandles {
        job: job_dup,
        cancel: cancel_raw,
    };

    let joined = ::tokio::task::spawn_blocking(move || {
        let handles = handles;
        let result = crate::containment::windows::wait_drained_raw(handles.job.0, deadline, Some(handles.cancel));
        drop(cancel_for_blocking); // keep the handle alive for the full blocking call, explicitly
        result
        // `handles.job` (`OwnedJobDup`) drops here on every path, including an early return
        // from `wait_drained_raw` above, closing our duplicate independently of `JobHandle`.
    })
    .await;
    match joined {
        Ok(result) => result,
        // wait_drained_raw does not panic — a panic here is a bug, not an I/O condition;
        // propagate it instead of masking it as an error.
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Err(e) if e.is_cancelled() => Err(Error::Io(std::io::Error::other(
            "tree-drain watcher cancelled (runtime shutting down)",
        ))),
        Err(e) => {
            debug_assert!(false, "unknown JoinError variant: {e:?}");
            Err(Error::Io(std::io::Error::other(e)))
        }
    }
}

/// Async equivalent of `Attached::wait_drained`, dispatched by mechanism. macOS is reactor-native
/// (`AsyncFd`); Linux awaits a broadcast from the pump thread its leaf owns (an
/// `event_listener` future, no reactor registration); Windows hands its sync loop to `spawn_blocking` with a
/// cancel event (job objects have no pollable handle). Every other mechanism delegates to the
/// sync `Attached::wait_drained`, whose non-drainable arm returns `Unsupported` immediately —
/// never blocking — so calling it directly here (no `spawn_blocking`) is safe.
///
/// `deadline` is on [`tokio_now`]'s clock (build it with [`deadline_from`]).
pub(crate) async fn wait_tree_drained_dispatch(
    attached: &crate::containment::Attached,
    deadline: Option<Option<std::time::Instant>>,
) -> Result<crate::containment::TreeDrain, Error> {
    match attached {
        #[cfg(target_os = "linux")]
        crate::containment::Attached::Cgroup(leaf) => cgroup_wait_tree_drained(leaf, deadline).await,
        #[cfg(windows)]
        crate::containment::Attached::JobObject(job) => job_wait_tree_drained(job, deadline).await,
        #[cfg(target_os = "macos")]
        crate::containment::Attached::FdMarker(m) => {
            // Mirrors `Marker::wait_drained`'s own preamble exactly: a reissued read-end fd
            // would falsely deliver `EV_EOF` instantly here just as readily as it would there,
            // so this path must not skip the check just because it reads the raw fd directly
            // instead of going through `Marker::wait_drained`.
            m.check_read_end_still_valid()?;
            debug_assert_ne!(
                crate::containment::marker_eof::write_end_check(m.read_end()),
                crate::containment::marker_eof::WriteEndCheck::HeldByUs,
                "the supervisor still holds a copy of the marker write end - the tree-drain edge can never fire"
            );
            wait_tree_deadline(m.read_end(), deadline).await
        }
        other => other.wait_drained(deadline),
    }
}

/// Test-only seam reporting each bounded arm and each unbounded park of the async waits.
/// Thread-local, so concurrent tests do not see each other; [`install`]'s guard uninstalls on drop.
#[cfg(all(test, unix))]
pub(crate) mod armed_deadline_seam {
    use std::cell::RefCell;
    use std::sync::mpsc::Sender;
    use std::time::Instant;

    /// What a wait did when it went to sleep.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Armed {
        /// `arm_at` armed a timer for this instant.
        At(Instant),
        /// Parked with no timer.
        Unbounded,
    }

    thread_local! {
        static NOTIFY: RefCell<Option<Sender<Armed>>> = const { RefCell::new(None) };
    }

    #[must_use]
    pub(crate) struct Installed(());

    pub(crate) fn install(tx: Sender<Armed>) -> Installed {
        NOTIFY.with(|n| *n.borrow_mut() = Some(tx));
        Installed(())
    }

    impl Drop for Installed {
        fn drop(&mut self) {
            NOTIFY.with(|n| {
                n.borrow_mut().take();
            });
        }
    }

    pub(crate) fn notify(armed: Armed) {
        NOTIFY.with(|n| {
            if let Some(tx) = n.borrow().as_ref() {
                _ = tx.send(armed);
            }
        });
    }
}

/// Test-only override of [`tokio_now`], to make a deadline already past on the timer's first poll.
#[cfg(test)]
pub(crate) mod now_override {
    use std::cell::Cell;
    use std::time::Instant;

    thread_local! {
        static NOW: Cell<Option<Instant>> = const { Cell::new(None) };
    }

    pub(crate) fn get() -> Option<Instant> {
        NOW.with(Cell::get)
    }

    #[must_use]
    pub(crate) struct Installed(());

    pub(crate) fn install(now: Instant) -> Installed {
        NOW.with(|n| {
            debug_assert!(n.get().is_none(), "a now_override is already installed on this thread");
            n.set(Some(now));
        });
        Installed(())
    }

    impl Drop for Installed {
        fn drop(&mut self) {
            NOW.with(|n| n.set(None));
        }
    }
}

#[cfg(test)]
#[path = "wait_tests.rs"]
mod wait_tests;
