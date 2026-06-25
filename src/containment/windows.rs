//! Windows Job Object containment: the root spawns suspended into a new console
//! group, is immediately assigned to a `KILL_ON_JOB_CLOSE` job, then resumed.
//! The kernel enforces the invariant: every descendant of the child inherits the
//! job (Windows jobs nest, so inner jobs are not a problem), and closing the job
//! handle terminates the whole tree. Adapted from hole `kill-group`.
//!
//! Kill-group race invariant (why `CREATE_SUSPENDED`):
//! the child must be inside the job before executing any instruction — otherwise
//! a fast-forking grandchild can escape the job before assignment completes.
//! Suspending the initial thread closes the race: assign the job while the child
//! is frozen, then resume so it can run.

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::os::windows::io::AsRawHandle;
use std::sync::atomic::{AtomicPtr, Ordering};

use windows::Win32::Foundation::{CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT};
use windows::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
    TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Threading::{
    GetProcessId, OpenThread, ResumeThread, CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, THREAD_SUSPEND_RESUME,
};

/// Sentinel: a null pointer means the handle has been consumed or is invalid.
fn null_ptr() -> *mut c_void {
    std::ptr::null_mut()
}

/// Owns the Job Object handle. `KILL_ON_JOB_CLOSE` means the whole process tree
/// is terminated when this handle is closed (dropped or explicitly killed).
///
/// Interior mutability via `AtomicPtr` allows `hard_kill` and `disarm` to be
/// called via `&self` (required because `Child::kill_tree` takes `&self`).
pub(crate) struct JobHandle {
    /// The raw HANDLE value stored as an atomic `*mut c_void`.
    /// Null means the handle has been consumed (taken/killed).
    raw: AtomicPtr<c_void>,
}

// A Windows job-object HANDLE is a process-wide kernel handle; using it
// (TerminateJobObject / CloseHandle) from another thread is sound because the
// kernel serialises job operations. The raw pointer inside `HANDLE` is otherwise
// `!Send`, which would prevent this type from crossing thread boundaries.
unsafe impl Send for JobHandle {}

impl std::fmt::Debug for JobHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobHandle")
            .field("raw", &self.raw.load(Ordering::Relaxed))
            .finish()
    }
}

impl JobHandle {
    fn new(handle: HANDLE) -> Self {
        debug_assert!(!handle.0.is_null(), "job handle must not be null");
        JobHandle {
            raw: AtomicPtr::new(handle.0),
        }
    }

    /// Test-only: return the raw job handle so integration tests can call
    /// `IsProcessInJob` against OUR job (not any inherited job). Always compiled
    /// on Windows (not just cfg(test)) because integration tests are a separate
    /// compilation unit that links the library.
    pub(crate) fn as_handle(&self) -> Option<HANDLE> {
        let p = self.raw.load(Ordering::Relaxed);
        if p.is_null() {
            None
        } else {
            Some(HANDLE(p))
        }
    }

    /// Atomically take the raw handle, leaving null. Returns `None` if already consumed.
    fn take(&self) -> Option<HANDLE> {
        let p = self.raw.swap(null_ptr(), Ordering::AcqRel);
        if p.is_null() {
            None
        } else {
            Some(HANDLE(p))
        }
    }

    /// Terminate every process in the job, then close the handle.
    pub(crate) fn hard_kill(&self) {
        if let Some(job) = self.take() {
            // SAFETY: job is a valid handle we own; Win32 calls are safe.
            unsafe {
                let _ = TerminateJobObject(job, 1);
                let _ = CloseHandle(job);
            }
        }
    }

    /// Clear `KILL_ON_JOB_CLOSE` so closing this handle does NOT kill the tree.
    /// Called by `Child::detach()` before the handle is released: otherwise
    /// dropping the job handle terminates the tree the caller intended to keep alive.
    pub(crate) fn disarm(&self) {
        let p = self.raw.load(Ordering::Relaxed);
        if p.is_null() {
            return;
        }
        let job = HANDLE(p);
        // A zeroed JOBOBJECT_EXTENDED_LIMIT_INFORMATION has LimitFlags == 0, which
        // clears KILL_ON_JOB_CLOSE. Best-effort: if this call fails the handle close
        // in Drop will still fire the kill — but that's an unlikely kernel failure.
        let info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // SAFETY: job is a valid handle; info is fully initialised (zeroed by default()).
        unsafe {
            let _ = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of!(info).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
        }
    }
}

#[cfg(all(windows, test))]
impl JobHandle {
    /// Test-only: a real but empty job object (no process assigned). Cheap to create and
    /// cleanly closed on `Drop`; for variant-level assertions like
    /// `Attached::JobObject(_).is_actionable()`.
    pub(crate) fn create_empty_for_test() -> JobHandle {
        // Safety: CreateJobObjectW with null name/attrs returns an owned job handle.
        let handle = unsafe { CreateJobObjectW(None, windows::core::PCWSTR::null()) }
            .expect("CreateJobObjectW for test placeholder");
        JobHandle::new(handle)
    }
}

impl Drop for JobHandle {
    fn drop(&mut self) {
        // If `hard_kill` was not called and `disarm` did not clear the flag,
        // KILL_ON_JOB_CLOSE fires here when we close the handle, tearing down
        // the tree — the drop backstop for `kill_on_drop=true` semantics.
        if let Some(job) = self.take() {
            // SAFETY: job is a valid handle we own.
            unsafe {
                let _ = CloseHandle(job);
            }
        }
    }
}

/// Apply pre-spawn flags to `std_cmd` for a root spawn.
/// `CREATE_SUSPENDED`: child must not execute before it is inside the job.
/// `CREATE_NEW_PROCESS_GROUP`: child leads its own console group so
/// `GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid)` can target it.
pub(crate) fn set_root_flags(std_cmd: &mut std::process::Command) {
    use std::os::windows::process::CommandExt;
    std_cmd.creation_flags(CREATE_SUSPENDED.0 | CREATE_NEW_PROCESS_GROUP.0);
}

/// Apply pre-spawn flags to `std_cmd` for a nested (non-root) spawn.
/// Only `CREATE_NEW_PROCESS_GROUP` — no suspension needed for nested spawns.
pub(crate) fn set_group_flags(std_cmd: &mut std::process::Command) {
    use std::os::windows::process::CommandExt;
    std_cmd.creation_flags(CREATE_NEW_PROCESS_GROUP.0);
}

/// Clear the inherit flag on the parent's std handles before spawning. Prevents
/// the child from inheriting the test runner's console handles. Best-effort.
pub(crate) fn clear_std_handle_inheritance() {
    for std_handle in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: standard Win32 call; handle is not closed.
        unsafe {
            if let Ok(h) = GetStdHandle(std_handle) {
                if !h.is_invalid() {
                    // Clear the INHERIT flag; dwflags=0 means "clear all bits in mask".
                    let _ = SetHandleInformation(h, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0));
                }
            }
        }
    }
}

/// Send `CTRL_BREAK_EVENT` to the process group rooted at `pid`.
/// The child was spawned with `CREATE_NEW_PROCESS_GROUP`, making it the leader;
/// targeting its `pid` reaches the whole group without affecting the parent's console.
/// Note: `CTRL_C` cannot be group-targeted; `CTRL_BREAK` is the only option here.
pub(crate) fn terminate(pid: u32) -> io::Result<()> {
    use windows::Win32::System::Console::{GenerateConsoleCtrlEvent, CTRL_BREAK_EVENT};
    // SAFETY: standard Win32 call targeting the child's own console group.
    unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) }.map_err(io::Error::from)
}

/// Create a `KILL_ON_JOB_CLOSE` job and assign `child` to it.
fn assign_to_kill_on_close_job(child: &std::process::Child) -> io::Result<JobHandle> {
    // `as_raw_handle()` returns a `*mut c_void` on Windows.
    let raw_ptr = child.as_raw_handle();
    let raw_handle = HANDLE(raw_ptr.cast());
    // SAFETY: all calls are standard Win32; owned handles are closed on error.
    unsafe {
        let job = CreateJobObjectW(None, windows::core::PCWSTR::null()).map_err(io::Error::from)?;

        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if let Err(e) = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            std::ptr::addr_of!(info).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        ) {
            let _ = CloseHandle(job);
            return Err(io::Error::from(e));
        }

        if let Err(e) = AssignProcessToJobObject(job, raw_handle) {
            let _ = CloseHandle(job);
            return Err(io::Error::from(e));
        }

        Ok(JobHandle::new(job))
    }
}

/// Resume every suspended thread of `child` after job assignment.
///
/// Why resume REGARDLESS of job-assign result:
/// the kill-group race invariant requires the child to be inside the job before
/// executing. We froze it at spawn (CREATE_SUSPENDED) to close the race window.
/// Whether or not job assignment succeeded, we MUST resume the child — a frozen
/// process is unacceptable. If `ResumeThread` fails we kill the child immediately
/// and return an error.
///
/// PID-reuse safety: we hold the child's process handle (via `std::process::Child`),
/// keeping its PID alive for the duration of the Toolhelp snapshot walk.
fn resume_initial_threads(child: &std::process::Child) -> io::Result<()> {
    use windows::Win32::Foundation::ERROR_NO_MORE_FILES;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };

    let raw_ptr = child.as_raw_handle();
    let raw_handle = HANDLE(raw_ptr.cast());

    // Thread32First/Next signal end-of-enumeration with ERROR_NO_MORE_FILES.
    let end_of_walk = windows::core::HRESULT::from_win32(ERROR_NO_MORE_FILES.0);
    let mut resumed = 0u32;
    let mut last_err: Option<io::Error> = None;

    // SAFETY: snapshot/iterate/open/resume with owned handles, all closed before return.
    unsafe {
        let process_pid = GetProcessId(raw_handle);

        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0).map_err(io::Error::from)?;
        let mut entry = THREADENTRY32 {
            dwSize: size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        let mut step = Thread32First(snap, &mut entry);
        loop {
            match step {
                Ok(()) => {}
                Err(e) if e.code() == end_of_walk => break,
                Err(e) => {
                    // A snapshot-API fault, not normal end-of-iteration.
                    let _ = CloseHandle(snap);
                    return Err(io::Error::from(e));
                }
            }
            if entry.th32OwnerProcessID == process_pid {
                match OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID) {
                    Ok(thread) => {
                        // ResumeThread returns the previous suspend count, or u32::MAX on failure.
                        if ResumeThread(thread) == u32::MAX {
                            last_err = Some(io::Error::last_os_error());
                        } else {
                            resumed += 1;
                        }
                        let _ = CloseHandle(thread);
                    }
                    Err(e) => last_err = Some(io::Error::from(e)),
                }
            }
            step = Thread32Next(snap, &mut entry);
        }
        let _ = CloseHandle(snap);
    }

    if resumed == 0 {
        return Err(last_err.unwrap_or_else(|| io::Error::other("no suspended threads resumed")));
    }
    Ok(())
}

/// Assign `child` to a `KILL_ON_JOB_CLOSE` job and resume its initial threads.
///
/// Returns `Ok(Some(JobHandle))` on full success (job assigned AND resumed).
/// Returns `Ok(None)` when job assignment fails — the caller falls back to the
/// universal `Containment::TreeWalk` mechanism (identity teardown).
/// Returns `Err` when resume fails — a frozen child is unacceptable; we kill
/// the child+job and propagate the error to fail the spawn.
pub(crate) fn attach_job(child: &std::process::Child) -> io::Result<Option<JobHandle>> {
    let job_result = assign_to_kill_on_close_job(child);

    // Resume REGARDLESS of job assignment result. A frozen child cannot be left running.
    if let Err(resume_err) = resume_initial_threads(child) {
        if let Ok(job) = job_result {
            // Kill via the job first (catches any threads the walk may have missed).
            job.hard_kill();
        }
        return Err(resume_err);
    }

    match job_result {
        Ok(job) => Ok(Some(job)),
        Err(_e) => {
            // Job assignment failed. Surfaced to the caller as Ok(None); dispatch
            // falls back to the TreeWalk mechanism. A library must not write to
            // the parent's stderr unconditionally.
            Ok(None)
        }
    }
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
