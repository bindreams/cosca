//! The synchronous wait loop over an [`OsProcess`].

use std::time::{Duration, Instant};

use backon::{BackoffBuilder as _, ExponentialBackoff, ExponentialBuilder};

#[cfg(test)]
use super::open;
use super::{Exit, OsProcess, WaitFor};
use crate::error::Error;
#[cfg(test)]
use crate::identity::ProcessId;
use crate::wait::remaining;

/// What the entry point does before any open or look: the bounded-section assert, then the
/// watch-fault seam.
fn enter() -> Result<(), Error> {
    #[cfg(feature = "tokio")]
    crate::bounded::assert_may_block("waiting for a process to exit");
    #[cfg(test)]
    if crate::wait::fault::take_force_watch_error() {
        return Err(crate::wait::fault::forced_watch_error());
    }
    Ok(())
}

/// Block until the process `id` names has exited or `timeout` has passed, and say which.
/// `Ok(true)` = exited, `Ok(false)` = still running after the deadline's final look; a process that
/// is gone, or whose pid now names another process, has exited, with no wait. `None` = until exit;
/// `Some(ZERO)` = one look, no blocking call; a `Duration` too large for the clock is unbounded.
/// Non-reaping. The bounded-section assert, the watch-fault seam and the deadline come before the
/// open, so the timeout counts from the call and the first two hold for a gone id too. Every
/// blocking call is armed from the time remaining, read right before it.
///
/// Tests only: an owned child is looked at through its own handle, never opened afresh by its number.
#[cfg(test)]
pub(crate) fn exited_by_id(id: ProcessId, timeout: Option<Duration>) -> Result<bool, Error> {
    enter()?;
    let deadline = absolute(timeout);
    match open(id)? {
        None => Ok(true),
        Some(process) => exited(&*process, deadline),
    }
}

/// [`exited_by_id`] for a process already open: `Ok(true)` = exited, `Ok(false)` = still running
/// after the deadline's final look.
pub(crate) fn exited_held(p: &dyn OsProcess, timeout: Option<Duration>) -> Result<bool, Error> {
    exited_until(p, absolute(timeout))
}

/// [`exited_held`] against an absolute `deadline` (`None`: unbounded).
pub(crate) fn exited_until(p: &dyn OsProcess, deadline: Option<Instant>) -> Result<bool, Error> {
    enter()?;
    exited(p, deadline)
}

/// [`run`] over a process's [`OsProcess::exited`] look.
fn exited(p: &dyn OsProcess, deadline: Option<Instant>) -> Result<bool, Error> {
    Ok(matches!(run(&mut ProcessExit(p), deadline)?, RunOutcome::Done(())))
}

/// `timeout` as an absolute deadline, fixed up front so no wake extends the total wait.
pub(crate) fn absolute(timeout: Option<Duration>) -> Option<Instant> {
    timeout.and_then(crate::wait::deadline_from)
}

/// What a wait loop asks of what it waits on.
pub(crate) trait Waitable {
    type Output;
    /// Done, or what to wait on. The [`WaitFor`] borrows `self` until the loop has waited on it.
    fn look(&mut self) -> Result<Step<'_, Self::Output>, Error>;
    /// Called for [`Step::Recheck`], with the next step of the backoff, already cut to the time
    /// remaining.
    fn pause(&mut self, d: Duration);
    /// Called when the block a [`Step::Wait`] asked for fails with `e`. The default ends the loop
    /// with `e`; a `Waitable` that can still decide by looking again returns `Ok`, and `run` looks.
    fn block_failed(&mut self, e: Error) -> Result<(), Error> {
        Err(e)
    }
}

/// What a [`Waitable::look`] found.
pub(crate) enum Step<'a, T> {
    Done(T),
    Wait(WaitFor<'a>),
    /// Nothing will signal the change (a tracer holds the zombie, or the OS is still finishing the
    /// exit): look again after a [`Waitable::pause`].
    Recheck,
}

/// How [`run`] ended.
#[derive(Debug)]
pub(crate) enum RunOutcome<T> {
    Done(T),
    /// The deadline had passed at the final look, and the look was not done.
    DeadlinePassed,
}

/// The schedule of pauses for [`Step::Recheck`]: 1 ms, doubling, at most 50 ms, never ending, no
/// jitter.
fn backoff() -> ExponentialBackoff {
    ExponentialBuilder::new()
        .with_min_delay(Duration::from_millis(1))
        .with_factor(2.0)
        .with_max_delay(Duration::from_millis(50))
        .without_max_times()
        .build()
}

/// The one synchronous wait loop: look; if not done, block on what the look returned (or pause, for
/// a recheck) and look again. `deadline` is absolute (from [`absolute`]); `None` waits for ever. A
/// look made at or after the deadline is the final one: it starts no block and no pause, and a look
/// that is not done ends the loop with [`RunOutcome::DeadlinePassed`].
///
/// A pause is the next step of one backoff, cut to the time remaining; the backoff starts over after
/// every block. A failed block goes to [`Waitable::block_failed`], which ends the loop with the error
/// unless it is survived.
pub(crate) fn run<W: Waitable>(w: &mut W, deadline: Option<Instant>) -> Result<RunOutcome<W::Output>, Error> {
    let mut steps = backoff();
    loop {
        let final_look = remaining(deadline) == Some(Duration::ZERO);
        match w.look()? {
            Step::Done(out) => return Ok(RunOutcome::Done(out)),
            Step::Wait(_) | Step::Recheck if final_look => return Ok(RunOutcome::DeadlinePassed),
            Step::Wait(wait_for) => {
                if remaining(deadline) != Some(Duration::ZERO) {
                    let blocked = block(&wait_for, deadline);
                    steps = backoff();
                    if let Err(e) = blocked {
                        w.block_failed(e)?;
                    }
                }
            }
            Step::Recheck => {
                let left = remaining(deadline);
                if left != Some(Duration::ZERO) {
                    let step = steps.next().expect("a backoff without a cap never ends");
                    w.pause(left.map_or(step, |left| step.min(left)));
                }
            }
        }
    }
}

/// An open process's exit, as a [`Waitable`]: `look` is [`OsProcess::exited`].
struct ProcessExit<'a>(&'a dyn OsProcess);

impl Waitable for ProcessExit<'_> {
    type Output = ();

    fn look(&mut self) -> Result<Step<'_, ()>, Error> {
        Ok(match self.0.exited()? {
            Exit::Exited => Step::Done(()),
            Exit::Running(wait_for) => Step::Wait(wait_for),
        })
    }

    fn pause(&mut self, _d: Duration) {
        debug_assert!(false, "OsProcess::exited never asks for a recheck");
    }
}

/// Block on `wait_for` until it wakes or `deadline` passes. The caller looks again either way.
fn block(wait_for: &WaitFor<'_>, deadline: Option<Instant>) -> Result<(), Error> {
    match wait_for {
        #[cfg(unix)]
        WaitFor::Readable(fd) => {
            crate::os_process::poll::poll_readable(*fd, deadline).map_err(Error::Io)?;
        }
        #[cfg(windows)]
        WaitFor::Signalled(process) => {
            use std::os::windows::io::AsRawHandle;
            use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
            use windows::Win32::System::Threading::WaitForSingleObject;

            let handle = HANDLE(process.as_raw_handle());
            let waited = crate::wait::wait_until(deadline, |ms| {
                #[cfg(test)]
                crate::wait::block_probe::record_blocking((ms != u32::MAX).then(|| Duration::from_millis(ms.into())));
                // SAFETY: `handle` is borrowed from `wait_for`, which outlives the call.
                unsafe { WaitForSingleObject(handle, ms) }
            });
            if waited != WAIT_OBJECT_0 && waited != WAIT_TIMEOUT {
                let e = std::io::Error::last_os_error();
                // `Signalled` is handed out only for a handle that can be waited on, so the wait
                // does not fail: a failure is a closed or invalid handle, our bug.
                debug_assert!(
                    false,
                    "WaitForSingleObject on a process handle returned {waited:?}: {e}"
                );
                return Err(Error::Io(e));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "drive_tests.rs"]
mod drive_tests;
