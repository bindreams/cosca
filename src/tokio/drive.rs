//! The asynchronous driver of the one wait loop, [`crate::os_process::drive`]'s: [`run`] loops "look;
//! if not done, wait on the [`WaitFor`] the look returned, or pause for a recheck", and a wake is
//! never the answer, the next look is. [`exited_held`] and [`exited_opening`] run it over a
//! process's exit.
//!
//! The deadline differs per platform, as it does for the other async waits. Unix arms tokio's timer
//! on [`tokio_now`]'s clock, and when the timer wins there is one final look. Windows has no
//! pollable process handle: the wait hops to a blocking thread that bounds it with the real
//! clock, so the deadline is moved there before the hop. A wait released without an exit signal
//! (the deadline, or the cancel event) ends in one final look on both.

use std::time::Duration;

use crate::error::Error;
use crate::os_process::drive::{backoff, ProcessExit, RunOutcome, Step, Waitable};
use crate::os_process::{OsProcess, WaitFor};
use crate::tokio::wait::deadline_from;

/// What the entry point does before any open or look: the watch-fault seam.
fn enter() -> Result<(), Error> {
    #[cfg(test)]
    if crate::wait::fault::take_force_watch_error() {
        return Err(crate::wait::fault::forced_watch_error());
    }
    Ok(())
}

/// Wait until the process `open` yields has exited or `timeout` has passed, and say which.
/// `Ok(true)` = exited, `Ok(false)` = still running after the deadline's final look; `open`
/// yielding `None` (a process that is gone) has exited, with no wait. `None` = until exit;
/// `Some(ZERO)` = one look, no wait; a `Duration` too large for the clock is unbounded.
/// Non-reaping. The watch-fault seam and the deadline come before `open` runs, so the timeout
/// counts from the call and the seam holds for a gone process too.
pub(crate) async fn exited_opening(
    open: impl FnOnce() -> Result<Option<Box<dyn OsProcess>>, Error>,
    timeout: Option<Duration>,
) -> Result<bool, Error> {
    enter()?;
    let deadline = absolute(timeout);
    match open()? {
        None => Ok(true),
        Some(process) => exited(&*process, deadline).await,
    }
}

/// [`exited_opening`] for a process already open: `Ok(true)` = exited, `Ok(false)` = still running
/// after the deadline's final look.
pub(crate) async fn exited_held(p: &dyn OsProcess, timeout: Option<Duration>) -> Result<bool, Error> {
    enter()?;
    exited(p, absolute(timeout)).await
}

/// [`run`] over a process's [`OsProcess::exited`] look, against an absolute `deadline`.
async fn exited(p: &dyn OsProcess, deadline: Option<std::time::Instant>) -> Result<bool, Error> {
    Ok(matches!(
        run(&mut ProcessExit(p), deadline).await?,
        RunOutcome::Done(())
    ))
}

/// `timeout` as an absolute deadline, fixed up front so no wake extends the total wait. On Windows
/// it is on the real clock, which the blocking thread measures.
fn absolute(timeout: Option<Duration>) -> Option<std::time::Instant> {
    #[cfg(unix)]
    return timeout.and_then(deadline_from);
    #[cfg(windows)]
    return crate::tokio::wait::to_real_clock(timeout.and_then(deadline_from));
}

/// What a look asked for, once it no longer borrows the `Waitable`'s output type: the future does
/// not hold a `W::Output` across an await, so it is `Send` whenever `W` is.
enum Next<'a> {
    Wait(WaitFor<'a>),
    Recheck,
}

/// The one asynchronous wait loop, with [`crate::os_process::drive::run`]'s contract: look; if not
/// done, wait on what the look returned (or pause, for a recheck) and look again. `deadline` is
/// absolute (from [`absolute`]); `None` waits for ever. A look made at or after the deadline, or
/// after a wait released without an exit signal, is the final one: it starts no wait and no pause, and
/// a look that is not done ends the loop with [`RunOutcome::DeadlinePassed`].
///
/// A pause is the next step of one backoff, cut to the time remaining; the backoff starts over after
/// every wait. A failed wait goes to [`Waitable::block_failed`], which ends the loop with the error
/// unless it is survived. Dropping the future releases the wait: the fd is deregistered on Unix, and
/// the blocking thread is released on Windows.
pub(crate) async fn run<W: Waitable>(
    w: &mut W,
    deadline: Option<std::time::Instant>,
) -> Result<RunOutcome<W::Output>, Error> {
    let mut steps = backoff();
    // Set when the wait was released without an exit signal: the next look is the final one
    // whatever the clock reads.
    let mut released = false;
    loop {
        // Read before the look: a look made at or after the deadline is the final one.
        let final_look = released || remaining(deadline) == Some(Duration::ZERO);
        let next = match w.look()? {
            Step::Done(out) => return Ok(RunOutcome::Done(out)),
            Step::Wait(_) | Step::Recheck if final_look => return Ok(RunOutcome::DeadlinePassed),
            Step::Wait(wait_for) => Next::Wait(wait_for),
            Step::Recheck => Next::Recheck,
        };
        match next {
            Next::Wait(wait_for) => {
                if remaining(deadline) != Some(Duration::ZERO) {
                    let waited = wait(&wait_for, deadline).await;
                    steps = backoff();
                    match waited {
                        Ok(woke) => released = !woke,
                        Err(e) => w.block_failed(e)?,
                    }
                }
            }
            Next::Recheck => {
                if remaining(deadline) != Some(Duration::ZERO) {
                    pause(steps.next().expect("a backoff without a cap never ends"), deadline).await?;
                }
            }
        }
    }
}

/// [`run`]'s pause for a [`Step::Recheck`]: `step`, cut to the time remaining. Nothing wakes it
/// early, so a `Waitable` that others must reach during the pause holds no lock across it.
#[cfg(unix)]
async fn pause(step: Duration, deadline: Option<std::time::Instant>) -> Result<(), Error> {
    let now = crate::tokio::wait::tokio_now();
    let by_step = now + step;
    // An instant, never a duration re-derived from the deadline (`arm_at`'s contract).
    let at = deadline.map_or(by_step, |deadline| deadline.min(by_step));
    #[cfg(test)]
    crate::wait::block_probe::record_pause(at.saturating_duration_since(now));
    // Only the timer ends it.
    _ = crate::tokio::wait::arm_at(at, std::future::pending::<()>()).await;
    Ok(())
}

/// No Windows `Waitable` asks for a recheck ([`crate::os_process::OsChild::try_reap`] answers
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

/// Wait on `wait_for` on the blocking pool until it wakes or the real-clock `deadline` passes.
/// `Ok(false)` = released without an exit signal: the deadline passed, or the cancel event fired.
/// Dropping the future signals the thread's cancel event.
#[cfg(windows)]
async fn wait(wait_for: &WaitFor<'_>, deadline: Option<std::time::Instant>) -> Result<bool, Error> {
    use std::os::windows::io::AsHandle;

    let WaitFor::Signalled(process) = wait_for;
    // The thread outlives a dropped future, so it gets a handle of its own.
    let process = process.try_clone_to_owned().map_err(Error::Io)?;
    crate::tokio::wait::cancellable_blocking("process wait watcher", move |cancel| {
        crate::os_process::windows::cancel::wait_process_or_cancel(process.as_handle(), deadline, cancel)
    })
    .await
}

#[cfg(test)]
#[path = "drive_tests.rs"]
mod drive_tests;
