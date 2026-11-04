//! `Child` bounded waits. A submodule of `child` so it can reach `Child`'s private
//! `proc` handle.

use std::io;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use super::owned::ChildWaitOutcome;
use super::Child;
use crate::error::Error;
use crate::os_process::child::{ExitRecord, Foreign};

/// Whether a wait that finds the child's zombie held by launchd (macOS) says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Orphaned {
    /// The wait reports it: the caller has nobody else to.
    Warn,
    /// The caller reports it itself, with the refusal it goes on to make, or has nothing to report.
    Quiet,
}

/// A wait's `outcome` on the child `pid` as the status `Child` answers: `Some` for an exit
/// (`Unreadable` is `InvalidData`), `None` for a deadline that passed.
pub(super) fn status_of_outcome(
    pid: Option<u32>,
    outcome: ChildWaitOutcome,
    orphaned: Orphaned,
) -> Result<Option<ExitStatus>, Error> {
    match outcome {
        ChildWaitOutcome::Exited(ExitRecord::Status(status)) => Ok(Some(status)),
        ChildWaitOutcome::Exited(ExitRecord::Unreadable { si_code }) => Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the child's exit record was unreadable (si_code {si_code})"),
        ))),
        ChildWaitOutcome::Foreign(foreign) => {
            if foreign == Foreign::Orphaned && orphaned == Orphaned::Warn {
                log::warn!("{}", orphaned_note(pid));
            }
            Err(Error::Io(echild()))
        }
        ChildWaitOutcome::DeadlinePassed => Ok(None),
    }
}

/// What to say of a child whose zombie launchd holds.
pub(super) fn orphaned_note(pid: Option<u32>) -> String {
    format!(
        "{}: not ours to reap (launchd holds its zombie, because its tracer died)",
        child_named(pid)
    )
}

/// How a message names a child: `child 4242`, or what stands for a pid that is not known.
pub(super) fn child_named(pid: Option<u32>) -> String {
    pid.map_or_else(|| "the child (pid unknown)".to_owned(), |pid| format!("child {pid}"))
}

/// The `ECHILD` every wait answers when the child was reaped by someone else.
fn echild() -> io::Error {
    #[cfg(unix)]
    {
        io::Error::from_raw_os_error(libc::ECHILD)
    }
    #[cfg(windows)]
    {
        io::Error::other("the child was already reaped elsewhere")
    }
}

impl Child {
    /// Block up to `timeout` for the root process to exit. `Ok(Some(status))` =
    /// exited; `Ok(None)` = still running at expiry (not an error); `Err` = a wait
    /// failure. `Duration::ZERO` acts like [`try_wait`](Child::try_wait). Event-driven
    /// (no poll loop) and concurrent-safe with `kill` (the handle pins the child: a
    /// pidfd on Linux, the process handle on Windows, an unreaped zombie on macOS). Reaps **only the root**: a contained tree's descendants have
    /// no waitable handle. A `timeout` so large it would overflow `Instant` is treated as
    /// unbounded (blocks until exit) rather than panicking.
    pub fn wait_timeout(&self, timeout: Duration) -> Result<Option<ExitStatus>, Error> {
        self.wait_timeout_by(timeout, Orphaned::Warn)
    }

    /// [`wait_timeout`](Child::wait_timeout) that does not report a zombie launchd holds (macOS):
    /// for a caller that reports it with its own refusal.
    #[cfg(unix)]
    pub(crate) fn wait_timeout_quiet(&self, timeout: Duration) -> Result<Option<ExitStatus>, Error> {
        self.wait_timeout_by(timeout, Orphaned::Quiet)
    }

    fn wait_timeout_by(&self, timeout: Duration, orphaned: Orphaned) -> Result<Option<ExitStatus>, Error> {
        // The sync lone path's watch goes through `OwnedChild::wait`, not
        // `exited_by`, so it needs its own head of the shared watch fault seam.
        #[cfg(test)]
        if crate::wait::fault::take_force_watch_error() {
            return Err(crate::wait::fault::forced_watch_error());
        }
        // `Instant + Duration` panics on overflow (e.g. Duration::MAX). Convert to a deadline
        // with a saturating checked_add: on overflow the timeout is effectively infinite, so
        // block until exit.
        self.wait_root(crate::wait::now().checked_add(timeout), orphaned)
    }

    /// Like [`wait_timeout`](Child::wait_timeout) but against an absolute `deadline`
    /// (at or before now behaves like [`try_wait`](Child::try_wait)).
    ///
    /// Never returns `None` before the clock reaches `deadline`: `OwnedChild` decides expiry
    /// from the clock after every wake, never from a primitive's own "timed out".
    pub fn wait_deadline(&self, deadline: Instant) -> Result<Option<ExitStatus>, Error> {
        self.wait_root(Some(deadline), Orphaned::Warn)
    }

    /// One wait on the root through its handle, until `deadline` (`None`: for ever). `Ok(None)` is
    /// a deadline that passed with the root still running.
    pub(super) fn wait_root(&self, deadline: Option<Instant>, orphaned: Orphaned) -> Result<Option<ExitStatus>, Error> {
        status_of_outcome(Some(self.id.pid()), self.proc.wait(deadline)?, orphaned)
    }

    /// Block until the root is reaped.
    pub(super) fn wait_root_unbounded(&self) -> Result<ExitStatus, Error> {
        match self.wait_root(None, Orphaned::Warn)? {
            Some(status) => Ok(status),
            None => {
                debug_assert!(false, "an unbounded wait ended with no exit");
                Err(Error::Io(io::Error::other("an unbounded wait ended with no exit")))
            }
        }
    }

    /// Block until every member of the contained tree has EXITED — not reaped; a status is
    /// never collected by this call, only the root's own `wait`/`wait_timeout` does that.
    /// Requires a mechanism with a real kernel drain edge (`Unsupported` otherwise — cgroup v2,
    /// a Windows job object, and the macOS fd marker have one; `ProcessGroup`/`Session`/
    /// `TreeWalk` and an uncontained or nested-`Delegated` child do not). Event-driven: no
    /// interval is chosen internally anywhere in this call's path.
    pub fn wait_tree(&self) -> Result<crate::containment::TreeDrain, Error> {
        self.require_drainable()?;
        self.attached.wait_drained(None)
    }

    /// Like [`wait_tree`](Child::wait_tree) but bounded by `timeout`. `TreeDrain::MembersRemain`
    /// at expiry is not an error. A `timeout` so large it would overflow `Instant` is treated as
    /// unbounded, matching [`wait_timeout`](Child::wait_timeout).
    pub fn wait_tree_timeout(&self, timeout: Duration) -> Result<crate::containment::TreeDrain, Error> {
        self.require_drainable()?;
        self.attached.wait_drained(crate::wait::deadline_from(timeout))
    }
}

#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod lifecycle_tests;
