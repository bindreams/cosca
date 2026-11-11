//! The reactor and blocking-pool halves of the async waits. Linux: the identity-verified pidfd is
//! registered with the reactor (`AsyncFd`); macOS: a kqueue `EVFILT_PROC|NOTE_EXIT` filter is
//! armed and its kqueue fd registered; Windows has no pollable process handle, so
//! [`cancellable_blocking`] waits on the process handle AND a cancel event that a drop-guard
//! signals — a dropped wait releases its watcher promptly on every platform. The process-exit wait
//! itself, and its deadline, are in [`crate::tokio::drive`]. Unix needs the runtime's IO + time
//! drivers (tokio panics otherwise) — documented on the public graceful methods.

use std::time::Duration;

use crate::error::Error;

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
pub(crate) fn deadline_from(duration: Duration) -> Option<std::time::Instant> {
    crate::wait::deadline_at(tokio_now(), duration)
}

/// The ONLY place a bounded async wait is armed: `tokio::time::timeout_at(at, fut)`, with the
/// caller's deadline instant (never a duration re-derived from it, which would arm later).
/// `None` = the deadline elapsed first. `at` must clear
/// [`crate::wait::TOKIO_TIMER_ROUNDING_MARGIN`], as every [`deadline_from`] result does; a
/// violation `debug_assert`s, and in release waits unbounded with no timer.
#[cfg(unix)]
pub(crate) async fn arm_at<F: std::future::Future>(at: std::time::Instant, fut: F) -> Option<F::Output> {
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

/// Run `work` on the blocking pool, handing it a cancel event that dropping this future signals. The
/// blocking `work` must return once the event is signalled, so a dropped wait releases its thread
/// promptly and `Runtime::drop`, which joins blocking tasks, does not stall. `what` names the work
/// in the error for a task the runtime's shutdown cancelled.
#[cfg(windows)]
pub(crate) async fn cancellable_blocking<T: Send + 'static>(
    what: &'static str,
    work: impl FnOnce(&std::os::windows::io::OwnedHandle) -> Result<T, Error> + Send + 'static,
) -> Result<T, Error> {
    /// Signals the cancel event on drop (harmless after completion) so the blocking watcher
    /// returns promptly instead of parking out the grace.
    struct SignalOnDrop(std::sync::Arc<std::os::windows::io::OwnedHandle>);
    impl Drop for SignalOnDrop {
        fn drop(&mut self) {
            crate::os_process::windows::cancel::signal_cancel(&self.0);
        }
    }
    let cancel = std::sync::Arc::new(crate::os_process::windows::cancel::new_cancel_event()?);
    let _guard = SignalOnDrop(cancel.clone());
    // Test-only: the probes are thread-local and the closure runs on a blocking-pool thread, so
    // capture them here, before any yield, and re-install inside.
    #[cfg(test)]
    let relay = crate::relayed_probe::capture();
    let joined = ::tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        let _relay = relay.reinstall();
        let result = work(&cancel);
        #[cfg(test)]
        fault_observer::notify_released();
        result
    })
    .await;
    match joined {
        Ok(result) => result,
        // `work` does not panic - a panic here is a bug, not an I/O condition; propagate it
        // instead of masking it as an error.
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        // Keep the shutdown-cancelled discriminator visible instead of folding it into an
        // opaque error indistinguishable from a real wait failure. The final arm is
        // presently unreachable (panic and cancelled are tokio's only variants today) and
        // exists for type-system conservatism: a future variant surfaces as an Err, never a
        // false success - with a debug tripwire, mirroring the unexpected-wait-verdict arm.
        Err(e) if e.is_cancelled() => Err(Error::Io(std::io::Error::other(format!(
            "{what} cancelled (runtime shutting down)"
        )))),
        Err(e) => {
            debug_assert!(false, "unknown JoinError variant: {e:?}");
            Err(Error::Io(std::io::Error::other(e)))
        }
    }
}

/// Deliberate test scaffolding (the `wait::fault` pattern): signals when the blocking
/// watcher RETURNS, so a test can prove drop-release with a plain `recv()` — the
/// no-time-sync alternative to observing teardown timing. Absent from non-test builds.
///
/// A [`crate::relayed_probe`]: `cancellable_blocking` relays it across `spawn_blocking`.
#[cfg(all(test, windows))]
pub(crate) mod fault_observer {
    use crate::relayed_probe::{self, Probe};
    use std::sync::mpsc::Sender;

    pub(crate) struct Released;
    impl Probe for Released {
        type Event = ();
    }

    pub(crate) type Guard = relayed_probe::Guard<Released>;

    pub(crate) fn install(tx: Sender<()>) -> Guard {
        relayed_probe::install(tx)
    }

    pub(crate) fn current() -> Option<Sender<()>> {
        relayed_probe::current::<Released>()
    }

    pub(crate) fn notify_released() {
        relayed_probe::notify::<Released>(());
    }
}

/// Resolve when `pidfd`'s process exits or is reaped (no internal timeout). `pidfd` is owned or
/// borrowed; it is deregistered when this returns or is dropped, before a borrow ends.
#[cfg(target_os = "linux")]
pub(crate) async fn watch_pidfd<F: std::os::fd::AsRawFd>(pidfd: F) -> Result<(), Error> {
    use ::tokio::io::unix::AsyncFd;
    use ::tokio::io::Interest;
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
pub(crate) fn classify_pidfd_ready(ready: ::tokio::io::Ready) -> Option<Result<(), Error>> {
    // Mirror the sync backend: POLLERR is an error; POLLIN (zombie) / POLLHUP (reaped) = exited.
    if ready.is_error() {
        return Some(Err(Error::Io(std::io::Error::other("pidfd poll returned POLLERR"))));
    }
    if ready.is_readable() || ready.is_read_closed() {
        return Some(Ok(()));
    }
    None
}

/// The readiness/drain loop, parameterized over the drain so the re-await cycle is testable
/// against the REAL `AsyncFd` (see `wait_tests`). Exit is concluded only on a drained event;
/// `clear_ready` only after an EMPTY drain — mio's edge-triggered (`EV_CLEAR`) would-block
/// contract.
///
/// `drain` returning `Ok(None)` is what `clear_ready` treats as "empty" — this loop has no way
/// to verify that itself, since the closure's return type carries no more than "done" or "not
/// done". The invariant holds for both current callers: the exit look in `tokio::drive` is a
/// `poll` that reads nothing, and `marker_eof::drain_kqueue`'s
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
pub(crate) async fn watch_readable<K, F>(afd: &::tokio::io::unix::AsyncFd<K>, mut drain: F) -> Result<(), Error>
where
    K: std::os::fd::AsRawFd,
    F: FnMut(&K) -> Result<Option<()>, Error>,
{
    loop {
        let mut guard = afd.readable().await.map_err(Error::Io)?;
        match drain(afd.get_ref())? {
            Some(()) => return Ok(()),
            None => guard.clear_ready(), // no exit drained — re-await
        }
    }
}

/// Re-express a [`tokio_now`]-clock `deadline` on the real clock, for the Windows job wait, which
/// blocks in the kernel and so is measured in real time. Identical when tokio's clock is unpaused.
#[cfg(any(windows, test))]
pub(crate) fn to_real_clock_at(
    deadline: Option<std::time::Instant>,
    tokio_now: std::time::Instant,
    real_now: std::time::Instant,
) -> Option<std::time::Instant> {
    deadline.and_then(|at| crate::wait::deadline_at(real_now, at.saturating_duration_since(tokio_now)))
}

#[cfg(windows)]
pub(crate) fn to_real_clock(deadline: Option<std::time::Instant>) -> Option<std::time::Instant> {
    to_real_clock_at(deadline, tokio_now(), crate::wait::now())
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
