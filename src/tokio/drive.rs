//! The asynchronous driver of the one wait loop, [`crate::os_process::drive`]'s: [`run`] loops "look;
//! if not done, wait on the [`WaitFor`] the look returned, or pause for a recheck", and a wake is
//! never the answer, the next look is. [`exited_held`] runs it over a process's exit.
//!
//! The deadline differs per platform, and when it passes there is one final look. Unix arms tokio's
//! timer on [`tokio_now`](crate::tokio::wait::tokio_now)'s clock against a descriptor registered with
//! the reactor. Windows has no pollable process handle: the wait is a
//! [`registered_wait`](crate::os_process::windows::registered_wait) on it, which carries the
//! deadline itself. No wait occupies the blocking pool.

use std::time::Duration;

use crate::error::Error;
#[cfg(unix)]
use crate::os_process::drive::pause_end;
use crate::os_process::drive::{exit_wait, wait_ended, Control, Next, RunOutcome, Step, Waitable};
use crate::os_process::{OsProcess, WaitFor};

/// What the entry point does before any open or look: the watch-fault seam.
fn enter() -> Result<(), Error> {
    #[cfg(test)]
    if crate::wait::fault::take_force_watch_error() {
        return Err(crate::wait::fault::forced_watch_error());
    }
    Ok(())
}

/// Wait until the open process `p` has exited or `timeout` has passed, and say which: `Ok(true)` =
/// exited, `Ok(false)` = still running after the deadline's final look. `None` = until exit;
/// `Some(ZERO)` = one look, no wait; a `Duration` too large for the clock is unbounded.
/// Non-reaping. The watch-fault seam and the deadline come before the first look, so the timeout
/// counts from the call.
pub(crate) async fn exited_held(p: &dyn OsProcess, timeout: Option<Duration>) -> Result<bool, Error> {
    exited_until(p, absolute(timeout)).await
}

/// [`exited_held`] against an absolute `deadline` (`None`: unbounded), on the clock [`absolute`]
/// names.
pub(crate) async fn exited_until(p: &dyn OsProcess, deadline: Option<std::time::Instant>) -> Result<bool, Error> {
    enter()?;
    let mut wait = exit_wait(p, remaining(deadline))?;
    Ok(matches!(run(&mut *wait, deadline).await?, RunOutcome::Done(())))
}

/// `timeout` as an absolute deadline, fixed up front so no wake extends the total wait. On Unix it
/// is on tokio's clock, which the timer measures; on Windows on the real clock, which the registered
/// wait measures.
fn absolute(timeout: Option<Duration>) -> Option<std::time::Instant> {
    #[cfg(unix)]
    return timeout.and_then(crate::tokio::wait::deadline_from);
    #[cfg(windows)]
    return timeout.and_then(crate::wait::deadline_from);
}

/// What a look asked the driver to do, once it no longer borrows the `Waitable`'s output type: the
/// future does not hold a `W::Output` across an await, so it is `Send` whenever `W` is.
enum Act<'a> {
    Wait(WaitFor<'a>),
    /// The backoff step, uncut: [`pause`] cuts it where it arms.
    Pause(Duration),
}

/// The one asynchronous wait loop: [`crate::os_process::drive::run`]'s loop, with the same
/// [`Control`], waiting on the runtime. `deadline` is absolute (from [`absolute`]); `None` waits for
/// ever. A failed wait goes to [`Waitable::block_failed`], which ends the loop with the error unless
/// it is survived. Dropping the future releases the wait: the fd is deregistered on Unix, and the
/// registered wait is unregistered on Windows. A Windows `deadline` is on the real clock.
pub(crate) async fn run<W: Waitable + ?Sized>(
    w: &mut W,
    deadline: Option<std::time::Instant>,
) -> Result<RunOutcome<W::Output>, Error> {
    let mut control = Control::new();
    loop {
        control.before_look(remaining(deadline));
        let step = w.look()?;
        let next = control.after_look(step.looked(), remaining(deadline));
        let act = match (next, step) {
            (Next::Done, Step::Done(out)) => return Ok(RunOutcome::Done(out)),
            (Next::DeadlinePassed, _) => return Ok(RunOutcome::DeadlinePassed),
            (Next::Look, _) => continue,
            (Next::Pause(step), _) => Act::Pause(step),
            (Next::Wait, Step::Wait(wait_for)) => Act::Wait(wait_for),
            (next, _) => unreachable!("{next:?} answers a look that found something else"),
        };
        match act {
            Act::Pause(step) => pause(step, deadline).await?,
            Act::Wait(wait_for) => {
                let waited = wait(&wait_for, deadline).await;
                control.waited(wait_ended(w, waited)?);
            }
        }
    }
}

/// [`run`]'s pause for a [`Step::Recheck`]. Nothing wakes it early, so a `Waitable` that others must
/// reach during the pause holds no lock across it.
#[cfg(unix)]
async fn pause(step: Duration, deadline: Option<std::time::Instant>) -> Result<(), Error> {
    let now = crate::tokio::wait::tokio_now();
    let Some(end) = pause_end(now, step, deadline) else {
        return Ok(());
    };
    #[cfg(test)]
    crate::wait::block_probe::record_pause(end.saturating_duration_since(now));
    // An instant, never a duration re-derived from the deadline (`arm_at`'s contract).
    _ = crate::tokio::wait::arm_at(end, std::future::pending::<()>()).await;
    Ok(())
}

/// No Windows `Waitable` asks for a recheck ([`crate::os_process::child::OsChild::try_reap`] answers
/// `Running` or an exit there), so there is nothing to pause on.
#[cfg(windows)]
async fn pause(_step: Duration, _deadline: Option<std::time::Instant>) -> Result<(), Error> {
    debug_assert!(false, "a Windows Waitable asked for a recheck");
    Err(Error::Io(std::io::Error::other(
        "a Windows Waitable asked for a recheck, which no Windows wait has",
    )))
}

/// The time left to `deadline` on the clock this platform's wait runs on.
fn remaining(deadline: Option<std::time::Instant>) -> Option<Duration> {
    #[cfg(unix)]
    return crate::wait::remaining_at(deadline, crate::tokio::wait::tokio_now());
    #[cfg(windows)]
    return crate::wait::remaining(deadline);
}

/// Wait on `wait_for` until it wakes or `deadline` passes. `Ok(false)` = the wait was released
/// without an exit signal: tokio's timer fired. The caller looks again either way, and that look is
/// the final one after `Ok(false)`.
#[cfg(unix)]
async fn wait(wait_for: &WaitFor<'_>, deadline: Option<std::time::Instant>) -> Result<bool, Error> {
    match deadline {
        Some(at) => match crate::tokio::wait::arm_at(at, watch(wait_for)).await {
            Some(woke) => woke.map(|()| true),
            None => Ok(false),
        },
        None => watch(wait_for).await.map(|()| true),
    }
}

/// Resolve when `wait_for` wakes, with no bound of its own.
///
/// The round registers a duplicate of the held descriptor, not the descriptor itself: waits on
/// one open process run at the same time, and the reactor takes one registration per descriptor
/// (epoll refuses a second with `EEXIST`; a kqueue's two registrations would displace each
/// other's wake). A duplicate shares the open file description, so readiness is shared and nothing
/// is consumed; it opens no new process descriptor.
#[cfg(unix)]
async fn watch(wait_for: &WaitFor<'_>) -> Result<(), Error> {
    let WaitFor::Readable(held) = wait_for;
    let fd = held.try_clone_to_owned().map_err(Error::Io)?;
    #[cfg(target_os = "linux")]
    return crate::tokio::wait::watch_pidfd(fd).await;
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsFd;

        use ::tokio::io::unix::AsyncFd;
        use ::tokio::io::Interest;

        use crate::tokio::wait::watch_readable;

        let afd = AsyncFd::with_interest(fd, Interest::READABLE).map_err(Error::Io)?;
        // Readiness is only a hint; the poll look decides, reads nothing, and clears the
        // readiness on a false positive so the next wake waits again.
        watch_readable(&afd, |fd| {
            crate::os_process::poll::is_readable(fd.as_fd())
                .map(|readable| readable.then_some(()))
                .map_err(Error::Io)
        })
        .await
    }
}

/// Wait on the process handle `wait_for` holds until it is signalled or the real-clock `deadline`
/// passes. `Ok(false)` = the deadline passed first: the caller's look after it is the final one. The
/// wait is a [`registered_wait`](crate::os_process::windows::registered_wait).
#[cfg(windows)]
async fn wait(wait_for: &WaitFor<'_>, deadline: Option<std::time::Instant>) -> Result<bool, Error> {
    use crate::os_process::windows::registered_wait::{wait_any, Woke};

    let WaitFor::Signalled(process) = wait_for;
    let woke = wait_any(std::iter::once(*process), deadline).await.map_err(Error::Io)?;
    Ok(woke == Woke::Signalled)
}

#[cfg(test)]
#[path = "drive_tests.rs"]
pub(crate) mod drive_tests;
