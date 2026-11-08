//! The synchronous wait loop over an [`OsProcess`].

use std::time::{Duration, Instant};

use backon::{BackoffBuilder as _, ExponentialBackoff, ExponentialBuilder};

use super::{Exit, OsProcess, WaitFor};
use crate::error::Error;
use crate::wait::remaining;

/// What the entry point does before any look: the watch-fault seam.
fn enter() -> Result<(), Error> {
    #[cfg(test)]
    if crate::wait::fault::take_force_watch_error() {
        return Err(crate::wait::fault::forced_watch_error());
    }
    Ok(())
}

/// Block until the open process `p` has exited or `timeout` has passed, and say which: `Ok(true)` =
/// exited, `Ok(false)` = still running after the deadline's final look. `None` = until exit;
/// `Some(ZERO)` = one look, no blocking call; a `Duration` too large for the clock is unbounded.
/// Non-reaping. Every blocking call is armed from the time remaining at that call.
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
    /// exit): the driver pauses, then looks again. A `Waitable` that holds a lock gives it up before
    /// it returns this, as it does before [`Step::Wait`].
    Recheck,
}

/// How [`run`] ended.
#[derive(Debug)]
pub(crate) enum RunOutcome<T> {
    Done(T),
    /// The deadline had passed at the final look, and the look was not done.
    DeadlinePassed,
}

/// The instant a pause of `step` from `now` ends, cut to `deadline`; `None` once `deadline` has
/// passed at `now`: there is no pause, and the driver looks again, which [`Control`] makes the final
/// look. Both drivers call it with a clock read immediately before they sleep or arm, so the
/// deadline it cuts to is the one the block is armed from (principle 13).
pub(crate) fn pause_end(now: Instant, step: Duration, deadline: Option<Instant>) -> Option<Instant> {
    if crate::wait::remaining_at(deadline, now) == Some(Duration::ZERO) {
        return None;
    }
    Some(deadline.map_or(now + step, |deadline| deadline.min(now + step)))
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

impl<T> Step<'_, T> {
    /// What this look found, without what it borrows.
    pub(crate) fn looked(&self) -> Looked {
        match self {
            Step::Done(_) => Looked::Done,
            Step::Wait(_) => Looked::Wait,
            Step::Recheck => Looked::Recheck,
        }
    }
}

/// What a look found, for [`Control`].
#[derive(Clone, Copy, Debug)]
pub(crate) enum Looked {
    Done,
    Wait,
    Recheck,
}

/// What a driver does after a look.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Next {
    /// Return [`RunOutcome::Done`].
    Done,
    /// Return [`RunOutcome::DeadlinePassed`].
    DeadlinePassed,
    /// Wait on the [`WaitFor`] the look returned, until the deadline.
    Wait,
    /// Pause for this step, which the driver cuts to the deadline with [`pause_end`] at the
    /// instant it arms or sleeps, then look.
    Pause(Duration),
    /// Look again at once: the deadline passed during the look, so there is no time to wait or
    /// pause in, and the next look is the final one.
    Look,
}

/// How a wait ended, as the driver tells [`Control`]: the one thing it reads.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Ended {
    /// The wait ended on a signal from the source, or failed and the [`Waitable`] survived it.
    NotReleased,
    /// Released without an exit signal: the deadline passed (or, in the async Windows wait, the
    /// cancel event fired).
    Released,
}

/// Maps a driver's wait result to [`Ended`]. A failed wait goes to [`Waitable::block_failed`], which
/// ends the loop with the error unless the `Waitable` survives it.
pub(crate) fn wait_ended<W: Waitable>(w: &mut W, waited: Result<bool, Error>) -> Result<Ended, Error> {
    Ok(match waited {
        Ok(true) => Ended::NotReleased,
        Ok(false) => Ended::Released,
        Err(e) => {
            w.block_failed(e)?;
            Ended::NotReleased
        }
    })
}

/// The control of the one wait loop, which the synchronous and the asynchronous driver both run.
/// Reads no clock and waits on nothing. A driver calls [`before_look`],
/// looks, calls [`after_look`] and does what it answers, and after a wait calls [`waited`].
///
/// A look made at or after the deadline, or after a wait released without an exit signal, is the
/// final one: it starts no wait and no pause, and a look that is not done ends the loop with
/// [`Next::DeadlinePassed`]. A pause is the next step of one backoff, uncut: the driver cuts it to
/// the deadline where it arms or sleeps. The backoff starts over after every wait.
///
/// [`before_look`]: Control::before_look
/// [`after_look`]: Control::after_look
/// [`waited`]: Control::waited
pub(crate) struct Control {
    steps: ExponentialBackoff,
    /// The last wait was released without an exit signal.
    released: bool,
    final_look: bool,
}

impl Control {
    pub(crate) fn new() -> Self {
        Self {
            steps: backoff(),
            released: false,
            final_look: false,
        }
    }

    /// Before each look, with the time left to the deadline then (`None`: unbounded).
    pub(crate) fn before_look(&mut self, left: Option<Duration>) {
        self.final_look = self.released || left == Some(Duration::ZERO);
    }

    /// After the look, with the time left now.
    pub(crate) fn after_look(&mut self, looked: Looked, left: Option<Duration>) -> Next {
        match looked {
            Looked::Done => Next::Done,
            Looked::Wait | Looked::Recheck if self.final_look => Next::DeadlinePassed,
            _ if left == Some(Duration::ZERO) => Next::Look,
            Looked::Wait => Next::Wait,
            Looked::Recheck => Next::Pause(self.steps.next().expect("a backoff without a cap never ends")),
        }
    }

    /// After a [`Next::Wait`] has ended.
    pub(crate) fn waited(&mut self, ended: Ended) {
        self.steps = backoff();
        self.released = matches!(ended, Ended::Released);
    }
}

/// The one synchronous wait loop: look; if not done, block on what the look returned (or pause, for
/// a recheck) and look again. `deadline` is absolute (from [`absolute`]); `None` waits for ever. The
/// loop control is [`Control`]'s, which the asynchronous driver runs too. A failed block goes to
/// [`Waitable::block_failed`], which ends the loop with the error unless it is survived.
pub(crate) fn run<W: Waitable>(w: &mut W, deadline: Option<Instant>) -> Result<RunOutcome<W::Output>, Error> {
    run_with(w, deadline, pause)
}

/// [`run`] with the way to pause for a [`Step::Recheck`]: `pause` is given the length of
/// [`pause_end`]'s pause, read immediately before the call, and returns once it has passed. No
/// pause is made, and `pause` is not called, once the deadline has passed.
fn run_with<W: Waitable>(
    w: &mut W,
    deadline: Option<Instant>,
    mut pause: impl FnMut(Duration),
) -> Result<RunOutcome<W::Output>, Error> {
    let mut control = Control::new();
    loop {
        control.before_look(remaining(deadline));
        let step = w.look()?;
        let next = control.after_look(step.looked(), remaining(deadline));
        match (next, step) {
            (Next::Done, Step::Done(out)) => return Ok(RunOutcome::Done(out)),
            (Next::DeadlinePassed, _) => return Ok(RunOutcome::DeadlinePassed),
            (Next::Look, _) => {}
            (Next::Pause(step), _) => {
                let now = crate::wait::now();
                if let Some(end) = pause_end(now, step, deadline) {
                    pause(end - now);
                }
            }
            (Next::Wait, Step::Wait(wait_for)) => {
                let waited = block(&wait_for, deadline);
                control.waited(wait_ended(w, waited)?);
            }
            (next, _) => unreachable!("{next:?} answers a look that found something else"),
        }
    }
}

/// [`run`]'s pause. Nothing wakes it early, so a `Waitable` that others must reach during the pause
/// holds no lock across it.
fn pause(d: Duration) {
    #[cfg(test)]
    crate::wait::block_probe::record_pause(d);
    #[cfg(test)]
    let started = Instant::now();
    std::thread::sleep(d);
    #[cfg(test)]
    crate::wait::test_clock::advance_by_elapsed_if_frozen(started.elapsed());
}

/// An open process's exit, as a [`Waitable`]: `look` is [`OsProcess::exited`].
pub(crate) struct ProcessExit<'a>(pub(crate) &'a dyn OsProcess);

impl Waitable for ProcessExit<'_> {
    type Output = ();

    fn look(&mut self) -> Result<Step<'_, ()>, Error> {
        Ok(match self.0.exited()? {
            Exit::Exited => Step::Done(()),
            Exit::Running(wait_for) => Step::Wait(wait_for),
        })
    }
}

/// Block on `wait_for` until it wakes or `deadline` passes, and say which: `Ok(false)` = the
/// deadline passed without a wake. The caller looks again either way.
fn block(wait_for: &WaitFor<'_>, deadline: Option<Instant>) -> Result<bool, Error> {
    match wait_for {
        #[cfg(unix)]
        WaitFor::Readable(fd) => crate::os_process::poll::poll_readable(*fd, deadline).map_err(Error::Io),
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
            Ok(waited == WAIT_OBJECT_0)
        }
    }
}

#[cfg(test)]
#[path = "drive_tests.rs"]
pub(crate) mod drive_tests;
