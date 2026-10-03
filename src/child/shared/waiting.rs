//! `wait` and `wait_deadline`: the dispatch on the state, and the holder's settle of the unlocked
//! wait's result.

use std::io;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use super::holder::HolderGuard;
use super::unlocked::Unlocked;
use super::{echild, status_of, Guard, SharedChild, State};
use crate::wait::exit_only::{self, Reap};

impl SharedChild {
    /// `wait` (no deadline) and `wait_deadline`. `Ok(None)` only at a deadline.
    pub(super) fn wait_inner(&self, deadline: Option<Instant>) -> io::Result<Option<ExitStatus>> {
        let mut lock = self.lock();
        #[cfg(test)]
        let mut check = crate::wait::test_clock::RoundCheck::new("SharedChild::wait_inner");
        loop {
            match lock.state {
                State::E(reaped) => return status_of(reaped).map(Some),
                State::N => {
                    if self.target().is_none() {
                        return Err(echild());
                    }
                    return self.hold(lock, deadline);
                }
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
                        let Some(target) = self.target() else {
                            return Err(echild());
                        };
                        return self.peeked_status(&target);
                    }
                    lock = self.block(lock, Some(deadline - now));
                }
            }
        }
    }

    /// One `Condvar` block, under the lock: `remaining` is clamped, and the caller decides expiry
    /// from the clock after the wake.
    fn block<'a>(&'a self, lock: Guard<'a>, remaining: Option<Duration>) -> Guard<'a> {
        #[cfg(test)]
        super::seams::before_condvar_block(remaining);
        let Some(remaining) = remaining else {
            return self.cv_wait(lock);
        };
        let armed = crate::wait::clamp_block(remaining);
        debug_assert!(armed <= remaining, "a block was armed longer than the time remaining");
        #[cfg(test)]
        crate::wait::block_probe::record(Some(armed));
        #[cfg(test)]
        let started = Instant::now();
        let lock = self.cv_wait_timeout(lock, armed);
        #[cfg(test)]
        crate::wait::test_clock::advance_by_elapsed_if_frozen(started.elapsed());
        lock
    }

    /// Become the holder: write `W`, wait unlocked, then settle the result under the lock.
    fn hold<'a>(&'a self, lock: Guard<'a>, deadline: Option<Instant>) -> io::Result<Option<ExitStatus>> {
        let mut holder = HolderGuard::arm(self, lock);
        holder.unlock();
        let mut waited = self.unlocked_wait(deadline);
        loop {
            // Re-read the state before acting on what the wait saw.
            holder.relock();
            match waited {
                // The wait failed (S14).
                Err(e) => {
                    drop(holder.finish(State::N));
                    return Err(e);
                }
                // The deadline passed, after the wait's final peek (S12): hands off to a blocked
                // waiter.
                Ok(Unlocked::DeadlinePassed) => {
                    drop(holder.finish(State::N));
                    return Ok(None);
                }
                // The child was reaped by someone else (S13).
                Ok(Unlocked::Gone) => {
                    drop(holder.finish(State::N));
                    return Err(echild());
                }
                Ok(Unlocked::ExitSeen) => {}
            }
            let Some(target) = self.target() else {
                drop(holder.finish(State::N));
                return Err(echild());
            };
            #[cfg(test)]
            exit_only::seams::step(exit_only::seams::HolderStep::Reap);
            match exit_only::try_reap(&target) {
                // Nothing between the reap and the `E` write may panic.
                Ok(Reap::Reaped(reaped)) => {
                    drop(holder.finish(State::E(reaped)));
                    #[cfg(test)]
                    super::seams::park_after_reap_recorded();
                    self.log_unreadable(reaped);
                    return status_of(reaped).map(Some);
                }
                Ok(Reap::Foreign(_)) => {
                    drop(holder.finish(State::N));
                    return Err(echild());
                }
                Err(e) => {
                    drop(holder.finish(State::N));
                    return Err(e);
                }
                // An exit was seen but there is nothing to consume: platform-specific.
                Ok(Reap::Running) => waited = self.reap_found_nothing(&mut holder, deadline),
            }
        }
    }
}
