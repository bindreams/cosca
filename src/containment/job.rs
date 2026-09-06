//! The public Job Object primitive, for a caller that must construct the child process itself
//! and cannot go through [`crate::Command`] — e.g. a ConPTY host, which needs
//! `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` on its own `CreateProcessW` call. See
//! [cosca#131](https://github.com/bindreams/cosca/issues/131).
//!
//! [`Job`] is a thin wrapper over the exact same [`crate::containment::windows::JobHandle`] that
//! backs [`Command::contain()`](crate::Command::contain) — there is exactly one Job Object
//! implementation in this crate, reused by both paths. It exposes only what teardown needs:
//! [`kill_tree`](Job::kill_tree), [`disarm`](Job::disarm), and the drain
//! ([`wait_tree`](Job::wait_tree) / [`wait_tree_timeout`](Job::wait_tree_timeout)).

use std::os::windows::io::{AsRawHandle, BorrowedHandle};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::CloseHandle;

use crate::containment::windows::{
    assign_to_kill_on_close_job, consumed_job_handle_error, wait_drained_raw, JobHandle,
};
use crate::containment::TreeDrain;
use crate::error::Error;

/// An owned Windows Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` set, holding exactly
/// one assigned process tree.
///
/// # The mandatory sequence
///
/// A member must be inside the job before it executes any instruction of its own, or a
/// fast-forking grandchild can spawn and escape before assignment completes. There is exactly
/// one way to close that race, and it is on the caller:
///
/// 1. Create the process **suspended** (`CREATE_SUSPENDED` on `CreateProcessW`).
/// 2. Call [`Job::assign`] with its process handle.
/// 3. Only now resume the process's main thread (e.g. `ResumeThread`).
///
/// Resuming before step 2 completes is a race: any instruction the process executes before it
/// is a job member — including forking a child of its own — can escape containment permanently.
/// This crate cannot enforce the ordering across an FFI boundary it does not own; get it right by
/// literally not calling anything that could resume the thread until [`Job::assign`] has
/// returned `Ok`.
///
/// # Dropping a `Job`
///
/// Dropping a live `Job` closes the underlying job handle, which — because
/// `KILL_ON_JOB_CLOSE` is set — **terminates every process still in it**, exactly like
/// [`kill_tree`](Job::kill_tree). Call [`disarm`](Job::disarm) first to opt out.
#[derive(Debug)]
pub struct Job(JobHandle);

impl Job {
    /// Assign `process` to a freshly created `KILL_ON_JOB_CLOSE` job.
    ///
    /// `process` is **borrowed**, not owned: `Job` does not close it, wait on it, or resume it.
    /// It must have been created suspended and must not yet have been resumed — see the
    /// [type-level sequence](Job#the-mandatory-sequence). The handle must carry the
    /// `PROCESS_SET_QUOTA` and `PROCESS_TERMINATE` access rights (a handle fresh out of
    /// `CreateProcessW` always does).
    ///
    /// # On error
    ///
    /// If this returns `Err`, `process` was never assigned to any job. It is still suspended:
    /// **do not resume it** — an uncontained resume defeats the reason this call exists. Tear it
    /// down instead (e.g. `TerminateProcess`) and propagate the error.
    #[must_use = "dropping the returned `Job` immediately kills the whole tree just assigned to \
                  it, unless `disarm()` is called first"]
    pub fn assign(process: BorrowedHandle<'_>) -> Result<Job, Error> {
        Ok(Job(assign_to_kill_on_close_job(process.as_raw_handle())?))
    }

    /// Terminate every process still in the job, then close the handle.
    ///
    /// Idempotent: calling this (or dropping the `Job`) again is a no-op. A subsequent
    /// [`wait_tree`](Job::wait_tree) call cannot confirm the tree has actually finished exiting —
    /// `TerminateJobObject`/`CloseHandle` are not documented as synchronous with member process
    /// teardown, and once this closes the handle there is nothing left to watch. Call
    /// [`wait_tree`](Job::wait_tree) *before* `kill_tree` if the caller needs the drain outcome.
    pub fn kill_tree(&self) -> Result<(), Error> {
        self.0.hard_kill().map_err(Error::Io)
    }

    /// Clear `KILL_ON_JOB_CLOSE`, so that dropping (or having already dropped) this `Job` leaves
    /// its tree running.
    ///
    /// This is the "session ended normally, leave background processes alone" teardown path —
    /// the opposite of [`kill_tree`](Job::kill_tree)'s "peer disconnected, reap everything".
    /// Best-effort: a failure here is logged (`log::warn!`) rather than returned, since the
    /// backstop for a caller that never sees the log is [`kill_tree`](Job::kill_tree), which
    /// needs no special disarmed state to work.
    pub fn disarm(&self) {
        self.0.disarm();
    }

    /// Block until every member of the tree has exited, or forever if none ever does.
    pub fn wait_tree(&self) -> Result<TreeDrain, Error> {
        self.wait_tree_deadline(None)
    }

    /// Like [`wait_tree`](Job::wait_tree), but give up and report
    /// [`TreeDrain::MembersRemain`](crate::containment::TreeDrain::MembersRemain) once `timeout`
    /// elapses.
    pub fn wait_tree_timeout(&self, timeout: Duration) -> Result<TreeDrain, Error> {
        self.wait_tree_deadline(crate::wait::deadline_from(timeout))
    }

    /// Shared body of `wait_tree`/`wait_tree_timeout`. Waits on a **duplicate** of the job
    /// handle rather than the live one directly: this call can block for the whole `deadline`,
    /// and `kill_tree`/`disarm`/`Drop` running concurrently on `&self` from another thread must
    /// not be able to invalidate the handle value out from under an in-flight wait (a closed
    /// Windows handle's numeric value can be recycled onto an unrelated kernel object).
    /// `DuplicateHandle` pins a second, independent reference to the SAME job for the duration
    /// of this call; closing the original elsewhere cannot touch it.
    fn wait_tree_deadline(&self, deadline: Option<Option<Instant>>) -> Result<TreeDrain, Error> {
        // Duplicated under the lock so a concurrent `kill_tree`/`Drop` cannot close the
        // original between the read and the `DuplicateHandle` call; the wait itself then
        // runs on the duplicate, outside the lock.
        let Some(dup) = self
            .0
            .with_handle(crate::containment::windows::duplicate_job)
            .transpose()?
        else {
            return Err(consumed_job_handle_error());
        };
        let result = wait_drained_raw(dup, deadline, None);
        // SAFETY: `dup` is a handle this function alone created and holds; nothing else
        // references it.
        unsafe {
            let _ = CloseHandle(dup);
        }
        result
    }
}

#[cfg(test)]
#[path = "job_tests.rs"]
mod job_tests;
