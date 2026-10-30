//! The asynchronous wait loop over an [`OsProcess`]: the twin of [`crate::os_process::drive`], with
//! the same semantics. It loops "look; if running, wait on the [`WaitFor`] the look returned", and
//! a wake is never the answer, the next look is.
//!
//! The deadline differs per platform, as it does for the other async waits. Unix arms tokio's timer
//! on [`tokio_now`]'s clock, and when the timer wins there is one final look. Windows has no
//! pollable process handle: the wait hops to a blocking thread that bounds it with the real
//! clock, so the deadline is moved there before the hop.

use std::time::Duration;

use crate::error::Error;
use crate::identity::ProcessId;
use crate::os_process::{open, Exit, Op, OsProcess, WaitFor};
use crate::tokio::wait::deadline_from;

/// [`exited_by`] on the process `id` names. A process that is gone, or whose pid now names another
/// process, has exited: `Ok(true)` with no wait. The watch-fault seam comes before the open, so it
/// holds for a gone id too.
pub(crate) async fn exited_by_id(id: ProcessId, timeout: Option<Duration>) -> Result<bool, Error> {
    #[cfg(test)]
    if crate::wait::fault::take_force_watch_error() {
        return Err(crate::wait::fault::forced_watch_error());
    }
    match open(id, Op::Wait)? {
        None => Ok(true),
        Some(mut process) => exited_by(&mut *process, timeout).await,
    }
}

/// Wait until `p` has exited or `timeout` has passed, and say which. `Ok(true)` = exited;
/// `Ok(false)` = still running after the deadline's final look. `None` = until exit;
/// `Some(ZERO)` = one look, no wait; a `Duration` too large for the clock is unbounded.
/// Non-reaping. Dropping the future releases the wait: the fd is deregistered on Unix, and the
/// blocking thread is released on Windows.
pub(crate) async fn exited_by(p: &mut dyn OsProcess, timeout: Option<Duration>) -> Result<bool, Error> {
    #[cfg(test)]
    if crate::wait::fault::take_force_watch_error() {
        return Err(crate::wait::fault::forced_watch_error());
    }
    // Absolute up front, so no wake extends the total wait.
    let deadline = timeout.and_then(deadline_from);
    #[cfg(windows)]
    let deadline = crate::tokio::wait::to_real_clock(deadline);
    // Set when the timer won the wait: the next look is the final one whatever the clock reads.
    let mut timer_won = false;
    loop {
        // Read before the look: a look made at or after the deadline is the final one.
        let final_look = timer_won || remaining(deadline) == Some(Duration::ZERO);
        match p.exited()? {
            Exit::Exited => return Ok(true),
            Exit::Running(_) if final_look => return Ok(false),
            Exit::Running(wait_for) => {
                if remaining(deadline) != Some(Duration::ZERO) {
                    timer_won = !wait(&wait_for, deadline).await?;
                }
            }
        }
    }
}

/// The time left to `deadline` on the clock this platform's wait runs on.
fn remaining(deadline: Option<Option<std::time::Instant>>) -> Option<Duration> {
    #[cfg(unix)]
    return crate::wait::remaining_at(deadline, crate::tokio::wait::tokio_now());
    #[cfg(windows)]
    return crate::wait::remaining(deadline);
}

/// Wait on `wait_for` until it wakes or `deadline` passes. `Ok(false)` = tokio's timer fired
/// first; Windows has no timer, so there it is always `Ok(true)`. The caller looks again either way.
#[cfg(unix)]
async fn wait(wait_for: &WaitFor<'_>, deadline: Option<Option<std::time::Instant>>) -> Result<bool, Error> {
    match deadline {
        Some(Some(at)) => match crate::tokio::wait::arm_at(at, watch(wait_for)).await {
            Some(woke) => woke.map(|()| true),
            None => Ok(false),
        },
        _ => watch(wait_for).await.map(|()| true),
    }
}

/// Resolve when `wait_for` wakes, with no bound of its own.
#[cfg(unix)]
async fn watch(wait_for: &WaitFor<'_>) -> Result<(), Error> {
    match wait_for {
        #[cfg(target_os = "linux")]
        WaitFor::Readable(fd) => crate::tokio::wait::watch_pidfd(fd.try_clone_to_owned().map_err(Error::Io)?).await,
        #[cfg(target_os = "macos")]
        WaitFor::Kqueue(watch) => {
            use ::tokio::io::unix::AsyncFd;
            use ::tokio::io::Interest;

            use crate::tokio::wait::{watch_readable, KqueueFd};

            let afd = AsyncFd::with_interest(KqueueFd(watch.as_fd()), Interest::READABLE).map_err(Error::Io)?;
            // `drain` is `true` once the event has been read, now or earlier; an empty drain clears
            // readiness so a spurious wake waits again.
            watch_readable(&afd, |_| watch.drain().map(|seen| seen.then_some(()))).await
        }
    }
}

/// Wait on `wait_for` on the blocking pool until it wakes or the real-clock `deadline` passes.
/// Dropping the future signals the thread's cancel event.
#[cfg(windows)]
async fn wait(wait_for: &WaitFor<'_>, deadline: Option<Option<std::time::Instant>>) -> Result<bool, Error> {
    use std::os::windows::io::AsHandle;

    let WaitFor::Signalled(process) = wait_for;
    // The thread outlives a dropped future, so it gets a handle of its own.
    let process = process.try_clone_to_owned().map_err(Error::Io)?;
    let deadline = deadline.flatten();
    crate::tokio::wait::cancellable_blocking("process wait watcher", move |cancel| {
        crate::wait::backend::wait_process_or_cancel(process.as_handle(), deadline, cancel)
    })
    .await?;
    Ok(true)
}

#[cfg(test)]
#[path = "drive_tests.rs"]
mod drive_tests;
