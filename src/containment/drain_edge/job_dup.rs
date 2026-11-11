//! The duplicated job handle the async drain's blocking thread owns.

use std::os::windows::io::{AsRawHandle, BorrowedHandle};

use windows::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
use windows::Win32::System::Threading::GetCurrentProcess;

use crate::error::Error;

/// A duplicate of a job handle, for the one wait that outlives its borrow of the `JobHandle`: the
/// async drain's blocking thread, which `spawn_blocking` does not join when its future is dropped.
/// Closing it does not fire `KILL_ON_JOB_CLOSE`: that needs the last handle, and `JobHandle`
/// still holds its own.
pub(super) struct OwnedJobDup(HANDLE);

impl OwnedJobDup {
    /// Duplicate `job`, failing with the plain Win32 code.
    pub(super) fn new(job: BorrowedHandle<'_>) -> Result<Self, Error> {
        let mut dup = HANDLE::default();
        // SAFETY: `job` is open for the duration of this call; `dup` is an out-parameter
        // DuplicateHandle initializes.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                HANDLE(job.as_raw_handle()),
                GetCurrentProcess(),
                &mut dup,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )
        }
        .map_err(|e| Error::Io(crate::error::win32_io_error(e)))?;
        Ok(OwnedJobDup(dup))
    }

    pub(super) fn handle(&self) -> BorrowedHandle<'_> {
        // SAFETY: `self.0` is open until `Drop`.
        unsafe { BorrowedHandle::borrow_raw(self.0 .0) }
    }
}

impl Drop for OwnedJobDup {
    fn drop(&mut self) {
        // SAFETY: `self.0` is this struct's own `DuplicateHandle`-created handle, never shared or
        // aliased anywhere else.
        unsafe {
            _ = CloseHandle(self.0);
        }
    }
}

#[cfg(test)]
#[path = "job_dup_tests.rs"]
mod job_dup_tests;
