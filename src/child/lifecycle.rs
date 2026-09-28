//! `Child` bounded waits. A submodule of `child` so it can reach `Child`'s private
//! `proc` handle.

use std::process::ExitStatus;
use std::time::{Duration, Instant};

use super::Child;
use crate::error::Error;

impl Child {
    /// Block up to `timeout` for the root process to exit. `Ok(Some(status))` =
    /// exited; `Ok(None)` = still running at expiry (not an error); `Err` = a wait
    /// failure. `Duration::ZERO` acts like [`try_wait`](Child::try_wait). Event-driven
    /// (no poll loop) and concurrent-safe with `kill` (shared_child pins the pid via
    /// `waitid(WNOWAIT)`). Reaps **only the root**: a contained tree's descendants have
    /// no waitable handle. A `timeout` so large it would overflow `Instant` is treated as
    /// unbounded (blocks until exit) rather than panicking.
    pub fn wait_timeout(&self, timeout: Duration) -> Result<Option<ExitStatus>, Error> {
        // The sync lone path's watch goes through shared_child's wait_deadline, not
        // block_until_exit, so it needs its own head of the shared watch fault seam.
        #[cfg(test)]
        if crate::wait::fault::take_force_watch_error() {
            return Err(crate::wait::fault::forced_watch_error());
        }
        // shared_child's wait_timeout computes `Instant::now() + timeout` internally, which
        // panics on overflow (e.g. Duration::MAX). Convert to a deadline with a saturating
        // checked_add: on overflow the timeout is effectively infinite, so block until exit.
        match Instant::now().checked_add(timeout) {
            Some(deadline) => self.wait_deadline(deadline),
            None => self.wait().map(Some),
        }
    }

    /// Like [`wait_timeout`](Child::wait_timeout) but against an absolute `deadline`
    /// (at or before now behaves like [`try_wait`](Child::try_wait)).
    ///
    /// A FIFTH site sharing the "deadline windows never early" bug shape (see
    /// docs/principles.md #13 — PR #233, not yet merged): the Windows-backend (`Raw`) arm of
    /// `self.proc.wait_deadline` is `RawChild::wait_deadline`, cosca's own code (fixed
    /// separately). The std-backend (`Std`) arm forwards to
    /// `shared_child::SharedChild::wait_deadline`, which on Windows
    /// (`shared_child::sys::windows::wait_deadline_noreap`) recheck-loops only while ITS OWN
    /// per-call timeout was capped by the ~49.7-day Win32 clamp — a "recheck only when
    /// clamped" mistake (an un-clamped `WAIT_TIMEOUT` can still fire early on real hardware;
    /// see this crate's own `win32_timeout_ms` doc for the Microsoft citation). `shared_child`
    /// is a third-party dependency (upstream tracking: cosca #237, not filed here) — `test`
    /// builds can simulate its bug's observable effect via `crate::wait::early_none_seam`.
    #[cfg(test)]
    fn wait_deadline_seamed(&self, deadline: Instant) -> Result<Option<ExitStatus>, Error> {
        if crate::wait::early_none_seam::take() {
            return Ok(None);
        }
        self.proc.wait_deadline(deadline).map_err(Error::Io)
    }

    pub fn wait_deadline(&self, deadline: Instant) -> Result<Option<ExitStatus>, Error> {
        #[cfg(test)]
        return self.wait_deadline_seamed(deadline);
        #[cfg(not(test))]
        self.proc.wait_deadline(deadline).map_err(Error::Io)
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
