//! The holder's unlocked wait, per OS. It reports one of [`Unlocked`], or an error, and never
//! reaps.

use std::io;
use std::time::Instant;

use super::holder::HolderGuard;
use super::SharedChild;

/// What the unlocked wait saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Unlocked {
    /// The child has exited: reap it.
    ExitSeen,
    /// The deadline passed with the child still running, after one final peek.
    DeadlinePassed,
    /// Someone else reaped the child.
    Gone,
}

impl SharedChild {
    /// The wait the holder runs with no lock held.
    pub(super) fn unlocked_wait(&self, deadline: Option<Instant>) -> io::Result<Unlocked> {
        #[cfg(test)]
        {
            super::seams::park_if_armed();
            if let Some(forced) = super::seams::take_forced_unlocked_wait() {
                return forced.into_result();
            }
        }
        self.platform_wait(deadline)
    }
}

// Linux =====

#[cfg(target_os = "linux")]
impl SharedChild {
    /// `poll` on the pidfd, armed from the time remaining each round.
    fn platform_wait(&self, deadline: Option<Instant>) -> io::Result<Unlocked> {
        use std::os::fd::AsFd;

        use rustix::event::{poll, PollFd, PollFlags, Timespec};

        use crate::wait::exit_only::{self, Peek, Target};

        let Some(pidfd) = &self.pidfd else {
            return Err(super::echild());
        };
        #[cfg(test)]
        exit_only::seams::step(exit_only::seams::HolderStep::Poll);
        let seen = crate::wait::rearm_until(deadline.map(Some), |remaining| {
            #[cfg(test)]
            crate::wait::block_probe::record(remaining);
            let ts = remaining.map(|d| Timespec {
                tv_sec: d.as_secs().min(i64::MAX as u64) as i64,
                tv_nsec: d.subsec_nanos() as _,
            });
            // A deadline wait never arms an unbounded poll.
            debug_assert!(
                deadline.is_none() || ts.is_some(),
                "a deadline wait armed an unbounded poll"
            );
            let mut fds = [PollFd::new(pidfd, PollFlags::IN)];
            match poll(&mut fds, ts.as_ref()) {
                Ok(0) => Ok(None),
                Ok(_) => {
                    let revents = fds[0].revents();
                    // POLLNVAL on an fd we own and hold alive is a contract violation.
                    debug_assert!(
                        !revents.contains(PollFlags::NVAL),
                        "pidfd reported POLLNVAL: owned-fd contract violation"
                    );
                    if revents.contains(PollFlags::ERR) {
                        return Err(io::Error::other("pidfd poll returned POLLERR"));
                    }
                    // POLLIN (zombie), or POLLHUP once reaped.
                    Ok(Some(()))
                }
                // A signal: go round again against the recomputed remaining time.
                Err(rustix::io::Errno::INTR) => Ok(None),
                Err(e) => Err(io::Error::from(e)),
            }
        })?;
        if seen.is_some() {
            return Ok(Unlocked::ExitSeen);
        }
        // Expired: one final peek.
        #[cfg(test)]
        exit_only::seams::step(exit_only::seams::HolderStep::FinalPeek);
        match exit_only::peek(&Target::PidFd(pidfd.as_fd()))? {
            Peek::Exit(_) => Ok(Unlocked::ExitSeen),
            Peek::Running => Ok(Unlocked::DeadlinePassed),
            Peek::Foreign(_) => Ok(Unlocked::Gone),
        }
    }

    /// The exit was seen (the pidfd is readable) but the reap found nothing: the zombie is
    /// traced by another process, and only its tracer sees it until it lets go. Re-polling would
    /// spin, so:
    ///
    /// - an unbounded holder blocks, unlocked, in `waitid(P_PIDFD, WEXITED | WNOWAIT)`;
    /// - a deadline holder re-peeks under the lock with a capped backoff, sleeping on the
    ///   handle's own `Condvar`, so a `notify_all` wakes it at once.
    ///
    /// The backoff re-checks a real condition, the tracer's release; elapsed time decides
    /// nothing. It never re-polls.
    pub(super) fn reap_found_nothing(
        &self,
        holder: &mut HolderGuard<'_>,
        deadline: Option<Instant>,
    ) -> io::Result<Unlocked> {
        use std::os::fd::AsFd;
        use std::time::Duration;

        use crate::wait::exit_only::{self, Peek, Target};

        let Some(pidfd) = &self.pidfd else {
            return Err(super::echild());
        };
        let target = Target::PidFd(pidfd.as_fd());
        let Some(deadline) = deadline else {
            holder.unlock();
            #[cfg(test)]
            exit_only::seams::step(exit_only::seams::HolderStep::BlockingWaitid);
            return match exit_only::wait_visible_exit(&target)? {
                Peek::Foreign(_) => Ok(Unlocked::Gone),
                _ => Ok(Unlocked::ExitSeen),
            };
        };
        let mut interval = Duration::from_millis(1);
        #[cfg(test)]
        let mut check = crate::wait::test_clock::RoundCheck::new("SharedChild::reap_found_nothing");
        loop {
            let now = crate::wait::now();
            if now >= deadline {
                // Expired: one final peek.
                return Ok(match exit_only::peek(&target)? {
                    Peek::Exit(_) => Unlocked::ExitSeen,
                    Peek::Running => Unlocked::DeadlinePassed,
                    Peek::Foreign(_) => Unlocked::Gone,
                });
            }
            #[cfg(test)]
            {
                check.round();
                exit_only::seams::step(exit_only::seams::HolderStep::Backoff);
            }
            let armed = crate::wait::clamp_block(interval.min(deadline - now));
            #[cfg(test)]
            crate::wait::block_probe::record(Some(armed));
            #[cfg(test)]
            let started = Instant::now();
            holder.sleep(armed);
            #[cfg(test)]
            crate::wait::test_clock::advance_by_elapsed_if_frozen(started.elapsed());
            interval = (interval * 2).min(Duration::from_millis(50));
            match exit_only::peek(&target)? {
                Peek::Exit(_) => return Ok(Unlocked::ExitSeen),
                Peek::Foreign(_) => return Ok(Unlocked::Gone),
                Peek::Running => {}
            }
        }
    }
}

// macOS =====

#[cfg(target_os = "macos")]
impl SharedChild {
    /// The kqueue wait: `EVFILT_PROC` plus a peek, by number.
    fn platform_wait(&self, deadline: Option<Instant>) -> io::Result<Unlocked> {
        use crate::wait::backend::{await_reapable, Waited};
        Ok(match await_reapable(self.id.pid(), deadline)? {
            Waited::Reapable => Unlocked::ExitSeen,
            Waited::DeadlinePassed => Unlocked::DeadlinePassed,
            Waited::Gone => Unlocked::Gone,
        })
    }

    /// A reap that finds nothing right after `Reapable` means the pid names another process now:
    /// something else reaped the child. An `ECHILD`, never an assert.
    pub(super) fn reap_found_nothing(
        &self,
        _holder: &mut HolderGuard<'_>,
        _deadline: Option<Instant>,
    ) -> io::Result<Unlocked> {
        Ok(Unlocked::Gone)
    }
}

// Windows =====

#[cfg(windows)]
impl SharedChild {
    /// `WaitForSingleObject` on the process handle, armed from the time remaining each round.
    fn platform_wait(&self, deadline: Option<Instant>) -> io::Result<Unlocked> {
        use std::os::windows::io::{AsHandle, AsRawHandle};

        use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows::Win32::System::Threading::WaitForSingleObject;

        use crate::wait::exit_only::{self, Peek, Target};

        let handle = HANDLE(self.handle.as_raw_handle());
        // SAFETY: `handle` is our owned process handle, alive for the whole call.
        let waited = crate::wait::wait_until(deadline.map(Some), |ms| unsafe { WaitForSingleObject(handle, ms) });
        if waited == WAIT_OBJECT_0 {
            return Ok(Unlocked::ExitSeen);
        }
        if waited != WAIT_TIMEOUT {
            return Err(io::Error::last_os_error());
        }
        // Expired: one final peek.
        match exit_only::peek(&Target::Handle(self.handle.as_handle()))? {
            Peek::Exit(_) => Ok(Unlocked::ExitSeen),
            Peek::Running => Ok(Unlocked::DeadlinePassed),
            Peek::Foreign(_) => Ok(Unlocked::Gone),
        }
    }

    /// A signalled handle always has an exit code to read: finding none is a contract breach.
    /// The state goes back to `N` and the caller gets an error, so it never spins.
    pub(super) fn reap_found_nothing(
        &self,
        _holder: &mut HolderGuard<'_>,
        _deadline: Option<Instant>,
    ) -> io::Result<Unlocked> {
        debug_assert!(false, "a signalled process handle had no exit code to read");
        Err(io::Error::other("a signalled process handle had no exit code to read"))
    }
}
