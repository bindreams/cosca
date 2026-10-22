//! The Windows token of a frozen child: its guard job, and the resume that releases it.
//!
//! A child no cosca job holds (uncontained, `TreeWalk` root, nested member) gets a guard job as
//! `attach`'s first act, so a parent that dies while the child is frozen has the child killed by
//! the OS closing the guard handle. A Strongest root needs none: its containment job is armed the
//! same way. **The window between `CreateProcessW` returning and that assignment stays open.**

use std::io;
use std::os::windows::io::RawHandle;

use crate::containment::dispatch::Prepared;
use crate::containment::windows::{self, JobHandle};
use crate::error::Error;

/// A frozen child's guard, if it needs one. Dropped by [`Frozen::release`] once the child runs; a
/// drop before that (the owner gave up) kills the child.
#[derive(Debug)]
pub(crate) struct Frozen {
    guard: Option<JobHandle>,
}

impl Frozen {
    /// The first OS act of `attach` for a frozen spawn: a guard job for a shape no cosca job holds.
    /// `None` for a spawn that is not frozen. A Strongest root's job is assigned by `attach` itself,
    /// without a resume.
    pub(crate) fn establish(prepared: &Prepared, proc_handle: RawHandle) -> Result<Option<Frozen>, Error> {
        if !prepared.frozen {
            return Ok(None);
        }
        if prepared.assigns_job() {
            return Ok(Some(Frozen { guard: None }));
        }
        let guard = windows::assign_guard_job(proc_handle).map_err(|e| Error::Containment {
            detail: format!("could not assign the frozen child to its guard job: {e}"),
        })?;
        Ok(Some(Frozen { guard: Some(guard) }))
    }

    /// Resume the child's threads, then release the guard.
    pub(crate) fn release(self, child: &crate::child::Child) -> io::Result<()> {
        self.release_process(child.process_handle())
    }

    /// [`release`](Self::release) for the process at `proc_handle`, which must stay open for the
    /// call.
    ///
    /// Order is the safety argument: the guard is released only after the threads run. The other
    /// order would strand a frozen process if the owner died between the two calls; this one can
    /// only kill a running child. A guard whose release fails is dropped armed, so the OS ends the
    /// child; the caller tears it down all the same.
    pub(crate) fn release_process(self, proc_handle: RawHandle) -> io::Result<()> {
        windows::resume_initial_threads(proc_handle)?;
        let Some(guard) = self.guard else { return Ok(()) };
        #[cfg(test)]
        observe::record_guard_flags_after_resume(&guard);
        guard.try_set_limit_flags(windows::guard_released_flags())?;
        #[cfg(test)]
        observe::record_guard_flags_after_release(&guard);
        Ok(())
    }

    /// Whether the process `pid` is inside this token's guard job. `false` without a guard.
    pub(crate) fn guard_contains(&self, pid: u32) -> bool {
        self.guard
            .as_ref()
            .is_some_and(|guard| windows::job_handle_contains_pid(guard, pid))
    }

    /// Test-only: whether this token owns a guard job.
    #[cfg(test)]
    pub(crate) fn has_guard(&self) -> bool {
        self.guard.is_some()
    }

    /// Test-only: the guard job.
    #[cfg(test)]
    pub(crate) fn guard_for_test(&self) -> Option<&JobHandle> {
        self.guard.as_ref()
    }
}

/// Test-only: what the guard's limits were at two points of [`Frozen::release_process`], read from
/// the guard itself. Take semantics, per thread.
#[cfg(test)]
pub(crate) mod observe {
    use std::cell::Cell;

    use windows::Win32::System::JobObjects::JOB_OBJECT_LIMIT;

    use crate::containment::windows::JobHandle;

    thread_local! {
        static AFTER_RESUME: Cell<Option<JOB_OBJECT_LIMIT>> = const { Cell::new(None) };
        static AFTER_RELEASE: Cell<Option<JOB_OBJECT_LIMIT>> = const { Cell::new(None) };
    }

    pub(crate) fn record_guard_flags_after_resume(guard: &JobHandle) {
        AFTER_RESUME.with(|c| c.set(Some(crate::test_frozen::limit_flags(guard))));
    }

    pub(crate) fn record_guard_flags_after_release(guard: &JobHandle) {
        AFTER_RELEASE.with(|c| c.set(Some(crate::test_frozen::limit_flags(guard))));
    }

    pub(crate) fn take_guard_flags_after_resume() -> Option<JOB_OBJECT_LIMIT> {
        AFTER_RESUME.with(Cell::take)
    }

    pub(crate) fn take_guard_flags_after_release() -> Option<JOB_OBJECT_LIMIT> {
        AFTER_RELEASE.with(Cell::take)
    }
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
