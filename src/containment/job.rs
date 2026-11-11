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

use crate::containment::windows::{assign_to_kill_on_close_job, JobHandle};
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
/// Dropping a `Job` closes the underlying job handle, which — because
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

    /// Terminate every process still in the job.
    ///
    /// The kernel documents that termination of every member is initiated before
    /// `TerminateJobObject` returns, not that their teardown has finished: this does not wait.
    /// The job handle stays open, so [`wait_tree`](Job::wait_tree) after it waits for the members
    /// to exit. The kill terminates every member, including a child created while it runs.
    ///
    /// Whether a killed job accepts an explicit `AssignProcessToJobObject` varies by Windows build
    /// (accepted on 10.0.26100, refused with `ACCESS_DENIED` on the CI's Windows arm64 runner);
    /// cosca never makes one.
    pub fn kill_tree(&self) -> Result<(), Error> {
        self.0.hard_kill().map_err(Error::Io)
    }

    /// Clear `KILL_ON_JOB_CLOSE`, so that dropping (or having already dropped) this `Job` leaves
    /// its tree running.
    ///
    /// This is the "session ended normally, leave background processes alone" teardown path —
    /// the opposite of [`kill_tree`](Job::kill_tree)'s "peer disconnected, reap everything". It
    /// also clears the flag after [`kill_tree`](Job::kill_tree).
    ///
    /// # Errors
    ///
    /// [`Error::Io`] with the Win32 code when the OS refuses to clear the flag. The job is then
    /// still armed: dropping this `Job` kills the tree, as it did before the call.
    pub fn disarm(&self) -> Result<(), Error> {
        self.0.disarm().map_err(Error::Io)
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

    /// Shared body of `wait_tree`/`wait_tree_timeout`.
    fn wait_tree_deadline(&self, deadline: Option<Instant>) -> Result<TreeDrain, Error> {
        self.0.wait_drained(deadline, None)
    }
}

#[cfg(test)]
#[path = "job_tests.rs"]
mod job_tests;
