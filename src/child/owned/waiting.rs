//! `wait`: the dispatch on the state, and the holder's wait loop.

#[cfg(feature = "tokio")]
use std::sync::PoisonError;
use std::time::{Duration, Instant};

use super::holder::HolderGuard;
use super::{ChildWaitOutcome, Guard, OwnedChild, State};
use crate::error::Error;
use crate::os_process::child::{PeekOutcome, TryReapOutcome};
use crate::os_process::drive::{run, RunOutcome, Step, Waitable};

impl OwnedChild {
    /// Block until the child has exited and this handle has reaped it, or `deadline` passes
    /// ([`ChildWaitOutcome::DeadlinePassed`], after one final look; `None`: for ever). Never reports
    /// `DeadlinePassed` before `crate::wait::now()` reaches `deadline`. A deadline already passed
    /// is one look: reaping when nobody holds the wait, and a peek that reaps nothing when another
    /// thread does.
    pub(crate) fn wait(&self, deadline: Option<Instant>) -> Result<ChildWaitOutcome, Error> {
        let mut lock = self.lock();
        #[cfg(test)]
        let mut check = crate::wait::test_clock::RoundCheck::new("OwnedChild::wait");
        loop {
            match lock.state {
                State::E(record) => return Ok(ChildWaitOutcome::Exited(record)),
                State::N => return self.hold_and_wait(lock, deadline),
                // Another thread is the holder: block on the `Condvar`, re-dispatch on every wake.
                State::W { .. } => {
                    let Some(deadline) = deadline else {
                        lock = self.block(lock, None);
                        continue;
                    };
                    #[cfg(test)]
                    check.round();
                    let now = crate::wait::now();
                    if now >= deadline {
                        // Expired: one look, without reaping and without waiting for the holder.
                        return Ok(match self.peek_locked(&lock)? {
                            PeekOutcome::Exit(record) => ChildWaitOutcome::Exited(record),
                            PeekOutcome::Running => ChildWaitOutcome::DeadlinePassed,
                            PeekOutcome::Foreign(foreign) => ChildWaitOutcome::Foreign(foreign),
                        });
                    }
                    lock = self.block(lock, Some(deadline - now));
                }
            }
        }
    }

    /// One `Condvar` block, under the lock: `remaining` is clamped, and the caller decides expiry
    /// from the clock after the wake.
    fn block<'a>(&'a self, lock: Guard<'a>, remaining: Option<Duration>) -> Guard<'a> {
        let Some(remaining) = remaining else {
            #[cfg(test)]
            crate::wait::block_probe::record_condvar_block(None);
            return self.cv_wait(lock);
        };
        let armed = crate::wait::clamp_block(remaining);
        debug_assert!(armed <= remaining, "a block was armed longer than the time remaining");
        #[cfg(test)]
        crate::wait::block_probe::record_condvar_block(Some(armed));
        #[cfg(test)]
        let started = Instant::now();
        let lock = self.cv_wait_timeout(lock, armed);
        #[cfg(test)]
        crate::wait::test_clock::advance_by_elapsed_if_frozen(started.elapsed());
        lock
    }

    /// Become the holder: write `W`, run the wait loop, and settle under the lock.
    fn hold_and_wait<'a>(&'a self, lock: Guard<'a>, deadline: Option<Instant>) -> Result<ChildWaitOutcome, Error> {
        let mut holder = Holder {
            child: self,
            guard: Some(HolderGuard::arm(self, lock)),
        };
        // An `Err` or a deadline leaves the guard armed: the drop below restores `N` and wakes the
        // waiters, which hands off to a blocked one.
        let outcome = match run(&mut holder, deadline)? {
            RunOutcome::Done(outcome) => outcome,
            RunOutcome::DeadlinePassed => ChildWaitOutcome::DeadlinePassed,
        };
        drop(holder);
        if let ChildWaitOutcome::Exited(record) = outcome {
            #[cfg(test)]
            super::seams::park_after_reap_recorded();
            self.log_unreadable(record);
        }
        Ok(outcome)
    }

    /// [`wait`](OwnedChild::wait) with no deadline, awaited: reaps through [`crate::tokio::drive::run`].
    /// `&mut self` means no other holder or waiter exists, so the state is written through
    /// `Mutex::get_mut`, with no lock and no wake. A dropped future leaves the state `N`: a record
    /// is written only by the look that reaps, and the future ends in the same poll.
    #[cfg(feature = "tokio")]
    pub(crate) async fn wait_async(&mut self) -> Result<ChildWaitOutcome, Error> {
        if let State::E(record) = self.inner.get_mut().unwrap_or_else(PoisonError::into_inner).state {
            return Ok(ChildWaitOutcome::Exited(record));
        }
        let outcome = match crate::tokio::drive::run(&mut AsyncReap(self), None).await? {
            RunOutcome::Done(outcome) => outcome,
            RunOutcome::DeadlinePassed => ChildWaitOutcome::DeadlinePassed,
        };
        if let ChildWaitOutcome::Exited(record) = outcome {
            self.log_unreadable(record);
        }
        Ok(outcome)
    }
}

/// What a [`try_reap`](crate::os_process::child::OsChild::try_reap) answer means for the state, and
/// for the loop: the state to write (`None`: leave it), and the step. Shared by the holder and
/// [`OwnedChild::wait_async`], which differ in how they write the state.
fn reap_step(outcome: TryReapOutcome<'_>) -> (Option<State>, Step<'_, ChildWaitOutcome>) {
    match outcome {
        TryReapOutcome::Reaped(record) => (Some(State::E(record)), Step::Done(ChildWaitOutcome::Exited(record))),
        TryReapOutcome::Foreign(foreign) => (Some(State::N), Step::Done(ChildWaitOutcome::Foreign(foreign))),
        TryReapOutcome::Recheck => (None, Step::Recheck),
        TryReapOutcome::Running(wait_for) => (None, Step::Wait(wait_for)),
    }
}

/// The wait loop of [`OwnedChild::wait_async`], for [`crate::tokio::drive::run`]: each look reaps if
/// there is a record. Nothing is locked.
#[cfg(feature = "tokio")]
struct AsyncReap<'c>(&'c mut OwnedChild);

#[cfg(feature = "tokio")]
impl Waitable for AsyncReap<'_> {
    type Output = ChildWaitOutcome;

    fn look(&mut self) -> Result<Step<'_, ChildWaitOutcome>, Error> {
        let OwnedChild { os, inner, .. } = &mut *self.0;
        let inner = inner.get_mut().unwrap_or_else(PoisonError::into_inner);
        debug_assert!(
            !matches!(inner.state, State::W { .. }),
            "a holder exists though the handle is borrowed mutably: {:?}",
            inner.state
        );
        let (state, step) = reap_step(os.try_reap()?);
        if let Some(state) = state {
            inner.set(state);
        }
        Ok(step)
    }
}

/// The holder's wait loop, for [`run`]: each look reaps if there is a record, and the wait it
/// returns, or the recheck pause, runs with the lock released.
struct Holder<'c> {
    child: &'c OwnedChild,
    /// `None` once the look has finished the holder.
    guard: Option<HolderGuard<'c>>,
}

impl<'c> Holder<'c> {
    fn guard(&mut self) -> &mut HolderGuard<'c> {
        self.guard
            .as_mut()
            .expect("a holder is looked at only until it is done")
    }

    /// Write `state`, wake the waiters and release the lock: the holder is done.
    fn finish(&mut self, state: State) {
        let guard = self.guard.take().expect("a holder is finished once");
        drop(guard.finish(state));
    }
}

impl<'c> Waitable for Holder<'c> {
    type Output = ChildWaitOutcome;

    fn look(&mut self) -> Result<Step<'_, ChildWaitOutcome>, Error> {
        let child: &'c OwnedChild = self.child;
        // Re-read the state before acting on a look.
        self.guard().relock();
        // Nothing between the reap and the state write may panic.
        let (state, step) = reap_step(child.os.try_reap()?);
        match state {
            Some(state) => self.finish(state),
            None => self.guard().unlock(),
        }
        Ok(step)
    }
}
