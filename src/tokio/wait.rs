//! The reactor half of the async waits, and the one hop onto the blocking pool. Linux: the
//! identity-verified pidfd is registered with the reactor (`AsyncFd`); macOS: a kqueue
//! `EVFILT_PROC|NOTE_EXIT` filter is armed and its kqueue fd registered; Windows has no pollable
//! process handle, so the wait registers the handle with the OS's wait pool
//! ([`crate::os_process::windows::registered_wait`]). No exit wait occupies the blocking pool, which
//! is for bounded work; a dropped wait releases what it registered on every platform. The
//! process-exit wait itself, and its deadline, are in [`crate::tokio::drive`]. Unix async waits need
//! the runtime's time and IO drivers (tokio panics otherwise); what the Windows waits need is in
//! [`registered_wait`](crate::os_process::windows::registered_wait). Documented on the public
//! graceful methods.

use std::time::Duration;

use crate::error::Error;

/// The clock every async wait here runs on: tokio's, which is `std`'s unless a test pauses it.
/// Deadlines are `std` instants read off this timeline, so the timer, the "already expired" checks
/// and [`deadline_from`] agree on what "now" is.
pub(crate) fn tokio_now() -> std::time::Instant {
    #[cfg(all(test, unix))]
    if let Some(now) = now_override::get() {
        return now;
    }
    ::tokio::time::Instant::now().into_std()
}

/// The async twin of [`crate::wait::deadline_from`], on [`tokio_now`]'s clock.
pub(crate) fn deadline_from(duration: Duration) -> Option<std::time::Instant> {
    crate::wait::deadline_at(tokio_now(), duration)
}

/// Re-express a [`tokio_now`]-clock `deadline` on the real clock, for the Windows registered waits,
/// which the OS times in real time. Identical when tokio's clock is unpaused.
#[cfg(any(windows, test))]
pub(crate) fn to_real_clock_at(
    deadline: Option<std::time::Instant>,
    tokio_now: std::time::Instant,
    real_now: std::time::Instant,
) -> Option<std::time::Instant> {
    deadline.and_then(|at| crate::wait::deadline_at(real_now, at.saturating_duration_since(tokio_now)))
}

/// [`to_real_clock_at`] from now, on both clocks.
#[cfg(windows)]
pub(crate) fn to_real_clock(deadline: Option<std::time::Instant>) -> Option<std::time::Instant> {
    to_real_clock_at(deadline, tokio_now(), crate::wait::now())
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

/// Why a task on the blocking pool gave no value.
pub(crate) enum Unjoined {
    /// The task did not run: the runtime's shutdown cancelled it, or there was no runtime to run it.
    /// The closure was dropped with what it held: on the calling thread with no runtime, and for a
    /// `spawn_blocking` call made after the shutdown began; a task that was already queued is dropped
    /// by the pool's shutdown, on a pool or shutdown thread.
    NotRun(Error),
    /// A state of the join tokio does not document today: nothing can be said of what the task did.
    Unknown(Error),
}

/// The place a runtime is looked for, and the one hop onto the blocking pool made from it. A caller
/// that must do something before the hop, but only once a runtime is there (the spawn takes its
/// command), [`enter`](Self::enter)s first and [`run`](Self::run)s after; the others call
/// [`on_blocking_pool`].
pub(crate) struct Hop {
    what: &'static str,
}

impl Hop {
    /// A hop for work called `what` in the errors, or [`Unjoined::NotRun`] with no runtime current:
    /// `spawn_blocking` panics without one, and the answer here is a typed error on every platform.
    pub(crate) fn enter(what: &'static str) -> Result<Hop, Unjoined> {
        if ::tokio::runtime::Handle::try_current().is_err() {
            return Err(Unjoined::NotRun(Error::Io(std::io::Error::other(format!(
                "{what} must be called from within a Tokio runtime"
            )))));
        }
        Ok(Hop { what })
    }

    /// Run `work` on the blocking pool and give back its value: the one way a joined task's result
    /// is read.
    ///
    /// When the runtime's shutdown cancels the task, `work` does not run and is dropped:
    /// [`Unjoined::NotRun`] says on which thread. A caller whose `work` holds a value with a teardown
    /// in its drop (a child) therefore has it run there.
    ///
    /// A panic in `work` is resumed here: it is a bug, not an I/O condition.
    ///
    /// The value reaches this future over a channel, not as the join handle's output, because its
    /// destructor may wait (a child's teardown) and a runtime thread should not run it. Which thread
    /// drops it, once the task ran, is stated once, for every caller of this hop, in
    /// [`Command::spawn`](crate::tokio::Command::spawn)'s "Dropping the future".
    ///
    /// `work` is bounded: the pool is not for a wait on a process or a tree, which are registered with
    /// the OS or the reactor instead.
    pub(crate) async fn run<T: Send + 'static>(self, work: impl FnOnce() -> T + Send + 'static) -> Result<T, Unjoined> {
        let what = self.what;
        // Test probes are thread-local: carry them onto the pool thread.
        #[cfg(test)]
        let relay = crate::relayed_probe::capture();
        let (tx, rx) = ::tokio::sync::oneshot::channel();
        let mut landing = Landing { rx };
        let joined = ::tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            let _relay = relay.reinstall();
            // A closed receiver hands the value back, and this thread drops it.
            _ = tx.send(work());
        })
        .await;
        match joined {
            Ok(()) => {}
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            // Cancelled is its own error, not folded into a wait failure. The last arm covers a join
            // state tokio does not document: an Err, never a false success, with a debug assert.
            Err(e) if e.is_cancelled() => {
                return Err(Unjoined::NotRun(Error::Io(std::io::Error::other(format!(
                    "{what} cancelled (runtime shutting down)"
                )))))
            }
            Err(e) => {
                debug_assert!(false, "unknown JoinError variant: {e:?}");
                return Err(Unjoined::Unknown(Error::Io(std::io::Error::other(format!(
                    "{what}: nothing is known of what the task did: {e}"
                )))));
            }
        }
        // The task ended without panicking, so it sent its value, and this receiver was open.
        Ok(landing
            .rx
            .try_recv()
            .expect("a blocking task that ended without panicking sent its value"))
    }
}

/// [`Hop::enter`] and [`Hop::run`] in one: with no runtime, `work` is dropped unrun on the calling
/// thread, like a task the runtime's shutdown cancels.
pub(crate) async fn on_blocking_pool<T: Send + 'static>(
    what: &'static str,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Unjoined> {
    Hop::enter(what)?.run(work).await
}

/// The receiving end of [`Hop::run`]'s value. Dropped before the value was taken, it closes the
/// channel, so the task's send fails and the task drops the value, and it hands a value already sent
/// to the pool. [`Command::spawn`](crate::tokio::Command::spawn)'s "Dropping the future" says which
/// thread drops the value.
struct Landing<T: Send + 'static> {
    rx: ::tokio::sync::oneshot::Receiver<T>,
}

impl<T: Send + 'static> Drop for Landing<T> {
    fn drop(&mut self) {
        // After `close`, a send that has not happened fails, and one that has is read here. A value
        // already taken leaves nothing to read.
        self.rx.close();
        let Ok(value) = self.rx.try_recv() else { return };
        match ::tokio::runtime::Handle::try_current() {
            // A runtime whose shutdown began cancels the hop at once, and the value drops with its
            // closure on this thread.
            Ok(runtime) => drop(runtime.spawn_blocking(move || drop(value))),
            // Not on a runtime there is no pool to hand it to.
            Err(_) => drop(value),
        }
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
#[cfg(all(test, unix))]
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
