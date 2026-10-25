//! What a reap that must not block wakes on: [`ProcSource::reap_on_events`](super::ProcSource).
//!
//! - **Linux:** the child's own pidfd, registered with the reactor. The kernel wakes a pidfd's
//!   waiters at the exit, and again when a tracer hands the zombie back (`do_notify_parent`, from
//!   the tracer's reap or detach), and the reactor's edge-triggered registration turns each wake
//!   into a new readiness.
//! - **macOS:** a kqueue of its own holding `EVFILT_PROC` (`NOTE_EXIT | NOTE_REAP | NOTE_SIGNAL`)
//!   and `EVFILT_SIGNAL` (`SIGCHLD`), as the sync wait arms it (`wait::macos::await_reapable`). A
//!   tracer's hand-back re-sends `NOTE_EXIT`. A traced child's `NOTE_EXIT` goes to its tracer
//!   alone, so a look that finds the child traced also watches the tracer chain, as the sync wait
//!   does (`wait::backend::TracerWatch`). Under `SIG_IGN` a child past `P_REF_DEAD` at registration
//!   is reaped by the kernel unannounced. So once `NOTE_EXIT` has come, or the registration found
//!   `ESRCH`, a one-shot timer in the same kqueue paces the next look, with the sync wait's
//!   backoff (1 ms doubling to 50 ms, no cap), and so it does while the tracer watch asks for a
//!   re-check. The timer only paces looks; no verdict rests on it.

use crate::error::Error;

// Linux =====

/// `pidfd`'s number, for a registration that must not duplicate it: a duplicate can fail at the fd
/// limit. Deregistered before the pidfd closes: [`PidfdWatch`] borrows it.
#[cfg(target_os = "linux")]
struct RawPidfd(std::os::fd::RawFd);

#[cfg(target_os = "linux")]
impl std::os::fd::AsRawFd for RawPidfd {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0
    }
}

/// The child's pidfd, registered with the reactor.
#[cfg(target_os = "linux")]
pub(super) struct PidfdWatch<'a> {
    afd: ::tokio::io::unix::AsyncFd<RawPidfd>,
    _pidfd: std::marker::PhantomData<std::os::fd::BorrowedFd<'a>>,
}

#[cfg(target_os = "linux")]
impl<'a> PidfdWatch<'a> {
    pub(super) fn arm(pidfd: std::os::fd::BorrowedFd<'a>) -> Result<PidfdWatch<'a>, Error> {
        use std::os::fd::AsRawFd as _;

        use ::tokio::io::Interest;
        #[cfg(test)]
        if crate::tokio::child::fault::take_fail_reap_watch() {
            return Err(Error::Io(std::io::Error::other("forced watch failure (test seam)")));
        }
        let afd = ::tokio::io::unix::AsyncFd::with_interest(
            RawPidfd(pidfd.as_raw_fd()),
            Interest::READABLE | Interest::ERROR,
        )
        .map_err(Error::Io)?;
        Ok(PidfdWatch {
            afd,
            _pidfd: std::marker::PhantomData,
        })
    }

    /// Waits until the pidfd reads ready: at once while the readiness the last [`Ready::seen`] left
    /// stands, else at its next wake.
    pub(super) async fn ready(&self) -> Result<Ready<'_>, Error> {
        use ::tokio::io::Interest;
        loop {
            let mut guard = self
                .afd
                .ready(Interest::READABLE | Interest::ERROR)
                .await
                .map_err(Error::Io)?;
            match crate::tokio::wait::classify_pidfd_ready(guard.ready()) {
                Some(Ok(())) => return Ok(Ready(guard)),
                Some(Err(e)) => return Err(e),
                None => guard.clear_ready(),
            }
        }
    }
}

/// One readiness of a [`PidfdWatch`], taken before the look it prompts.
#[cfg(target_os = "linux")]
pub(super) struct Ready<'a>(::tokio::io::unix::AsyncFdReadyGuard<'a, RawPidfd>);

#[cfg(target_os = "linux")]
impl Ready<'_> {
    /// The look found nothing to reap: the next [`PidfdWatch::ready`] waits for a later wake.
    /// tokio clears only this readiness, so a wake since it was taken still stands.
    pub(super) fn seen(mut self) {
        self.0.clear_ready();
    }
}

// macOS =====

/// `AsyncFd` requires `AsRawFd`; nix's `Kqueue` exposes only `AsFd`.
#[cfg(target_os = "macos")]
struct KqueueFd(nix::sys::event::Kqueue);

#[cfg(target_os = "macos")]
impl std::os::fd::AsRawFd for KqueueFd {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsFd as _;
        self.0.as_fd().as_raw_fd()
    }
}

/// The child's exit events on a kqueue of its own, registered with the reactor.
#[cfg(target_os = "macos")]
pub(super) struct KqueueWatch {
    afd: ::tokio::io::unix::AsyncFd<KqueueFd>,
    pid: u32,
    /// `NOTE_EXIT` has come, or the registration found `ESRCH`: looks are paced by the timer too.
    backoff: bool,
    interval: std::time::Duration,
    /// The tracers that hold the child, and their events.
    tracer: crate::wait::backend::TracerWatch,
    /// The tracer watch's next re-check, if it asked for one.
    recheck: Option<std::time::Duration>,
}

#[cfg(target_os = "macos")]
impl KqueueWatch {
    pub(super) fn arm(pid: u32) -> Result<KqueueWatch, Error> {
        use crate::wait::backend::{register_exit_events, BACKOFF_START};
        #[cfg(test)]
        if crate::tokio::child::fault::take_fail_reap_watch() {
            return Err(Error::Io(std::io::Error::other("forced watch failure (test seam)")));
        }
        let kq = nix::sys::event::Kqueue::new().map_err(|e| Error::Io(e.into()))?;
        let backoff = register_exit_events(&kq, pid).map_err(Error::Io)?;
        let afd = ::tokio::io::unix::AsyncFd::with_interest(KqueueFd(kq), ::tokio::io::Interest::READABLE)
            .map_err(Error::Io)?;
        Ok(KqueueWatch {
            afd,
            pid,
            backoff,
            interval: BACKOFF_START,
            tracer: crate::wait::backend::TracerWatch::default(),
            recheck: None,
        })
    }

    /// Reads every pending event: `true` if one was the child's `NOTE_REAP`, so something else
    /// reaped the child and no look by its pid may follow.
    pub(super) fn reaped(&mut self) -> Result<bool, Error> {
        let (reaped, exited) =
            crate::wait::backend::drain_exit_events(&self.afd.get_ref().0, self.pid, &mut self.tracer)
                .map_err(Error::Io)?;
        self.backoff |= exited;
        Ok(reaped)
    }

    /// A look found the child held by `tracer`: watches the chain from it. `true` when the child
    /// must be looked at again at once, before any wait: the walk registered something new.
    pub(super) fn held_by(&mut self, tracer: u32) -> std::io::Result<bool> {
        use crate::wait::backend::OnTracer;
        match self.tracer.held_by(&self.afd.get_ref().0, tracer)? {
            OnTracer::Block => self.recheck = None,
            OnTracer::Recheck(after) if after.is_zero() => return Ok(true),
            OnTracer::Recheck(after) => self.recheck = Some(after),
        }
        Ok(false)
    }

    /// Waits for the next event, or for the timer once backing off or when the tracer watch asked
    /// for a re-check.
    pub(super) async fn next(&mut self) -> Result<(), Error> {
        use crate::wait::backend::{arm_backoff_timer, BACKOFF_CAP};
        let backoff = self.backoff.then_some(self.interval);
        let timer = match (backoff, self.recheck.take()) {
            (Some(backoff), Some(recheck)) => Some(backoff.min(recheck)),
            (backoff, recheck) => backoff.or(recheck),
        };
        if let Some(timer) = timer {
            arm_backoff_timer(&self.afd.get_ref().0, timer).map_err(Error::Io)?;
        }
        if self.backoff {
            self.interval = (self.interval * 2).min(BACKOFF_CAP);
        }
        // Cleared before the events are read, at the next look: an event queued after this
        // readiness raises a new one.
        let mut guard = self.afd.readable().await.map_err(Error::Io)?;
        guard.clear_ready();
        Ok(())
    }
}
