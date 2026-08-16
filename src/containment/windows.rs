//! Windows Job Object containment: the root spawns suspended into a new console
//! group, is immediately assigned to a `KILL_ON_JOB_CLOSE` job, then resumed.
//! The kernel enforces the invariant: every descendant of the child inherits the
//! job (Windows jobs nest, so inner jobs are not a problem), and closing the job
//! handle terminates the whole tree.
//!
//! Kill-group race invariant (why `CREATE_SUSPENDED`):
//! the child must be inside the job before executing any instruction — otherwise
//! a fast-forking grandchild can escape the job before assignment completes.
//! Suspending the initial thread closes the race: assign the job while the child
//! is frozen, then resume so it can run.

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::sync::atomic::{AtomicPtr, Ordering};

use windows::Win32::Foundation::{
    CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, WAIT_FAILED,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectAssociateCompletionPortInformation,
    JobObjectBasicProcessIdList, JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject, JOBOBJECT_ASSOCIATE_COMPLETION_PORT, JOBOBJECT_BASIC_PROCESS_ID_LIST,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Threading::{
    GetProcessId, OpenProcess, OpenThread, ResumeThread, WaitForMultipleObjects, CREATE_NEW_PROCESS_GROUP,
    CREATE_SUSPENDED, INFINITE, PROCESS_SYNCHRONIZE, THREAD_SUSPEND_RESUME,
};
use windows::Win32::System::IO::CreateIoCompletionPort;

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
    /// The I/O completion port associated with this job at creation time, before
    /// `AssignProcessToJobObject` — always, never opt-in (see `assign_to_kill_on_close_job`).
    ///
    /// `wait_drained` never reads from this port — it is NOT what the drain waits on. The drain
    /// instead re-enumerates the job's live members with `QueryInformationJobObject` and blocks
    /// on real `WaitForMultipleObjects` process-handle waits (see that method's doc for the full
    /// mechanism and why: ordinary job lifecycle messages are documented by Microsoft as not
    /// guaranteed to be delivered, so trusting them here could hang forever on one dropped
    /// packet). The association still matters for a narrower reason: `assign_to_kill_on_close_job`
    /// creates and associates the port *before* assigning the process, so the job never has a
    /// live member without one — a self-imposed ordering invariant, not a functional dependency
    /// of any watch. Kept as an atomic pointer purely so `JobHandle` stays `Sync` (a bare Windows
    /// handle is otherwise `!Sync`, matching `raw`); never null, never taken — it is only ever
    /// read once, in `Drop`, to close it exactly once rather than leak it.
    port: AtomicPtr<c_void>,
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
    fn new(handle: HANDLE, port: HANDLE) -> Self {
        debug_assert!(!handle.0.is_null(), "job handle must not be null");
        debug_assert!(!port.0.is_null(), "job completion port handle must not be null");
        JobHandle {
            raw: AtomicPtr::new(handle.0),
            port: AtomicPtr::new(port.0),
        }
    }

    /// The raw job handle, or `None` once consumed. Backs the test-only
    /// membership probe (`job_contains_pid`).
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
        // SAFETY: creating a fresh, unassociated completion port has no preconditions.
        let port = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, None, 0, 0) }
            .expect("CreateIoCompletionPort for test placeholder");
        JobHandle::new(handle, port)
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
        // SAFETY: `port` was created once in `assign_to_kill_on_close_job` (or the test
        // placeholder) and is owned exclusively by this `JobHandle` — never shared, never
        // closed anywhere else. Closing it here, unconditionally, whether or not the tree was
        // torn down, releases the last resource this type holds.
        unsafe {
            let _ = CloseHandle(HANDLE(self.port.load(Ordering::Relaxed)));
        }
    }
}

/// Pre-spawn creation flags for a root spawn.
/// `CREATE_SUSPENDED`: child must not execute before it is inside the job.
/// `CREATE_NEW_PROCESS_GROUP`: child leads its own console group so
/// `GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid)` can target it.
/// Shared by the std path and the raw `CreateProcessW` backend via `windows_contain_setup`.
pub(crate) fn root_flags() -> u32 {
    CREATE_SUSPENDED.0 | CREATE_NEW_PROCESS_GROUP.0
}

/// Pre-spawn creation flags for a nested (non-root) spawn.
/// Only `CREATE_NEW_PROCESS_GROUP` — no suspension needed for nested spawns.
pub(crate) fn group_flags() -> u32 {
    CREATE_NEW_PROCESS_GROUP.0
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

/// Whether THIS process is attached to a console: `Ok(true)` attached, `Ok(false)` genuinely
/// none, `Err` the probe itself failed.
///
/// `GetConsoleProcessList` returns 0 both for "no console" and for an API-level failure, so
/// the two are told apart by the last OS error: a console-less caller gets 0 with
/// `ERROR_INVALID_HANDLE`. Unlike `GetConsoleWindow` this is correct for a *windowless*
/// console (`CREATE_NO_WINDOW`, ConPTY), which can signal fine.
///
/// Used only to CONFIRM a failure that already happened, never to gate one before it. Both
/// orderings race a concurrent `AttachConsole`/`FreeConsole`; a confirmation at worst
/// withholds the typed error, while a guard decides the outcome from state that may already
/// be gone.
pub(crate) fn caller_has_console() -> io::Result<bool> {
    use windows::Win32::Foundation::{SetLastError, ERROR_INVALID_HANDLE, WIN32_ERROR};
    use windows::Win32::System::Console::GetConsoleProcessList;
    #[cfg(test)]
    if fault::take_force_console_probe_error() {
        return Err(io::Error::from_raw_os_error(
            windows::Win32::Foundation::ERROR_INVALID_PARAMETER.0 as i32,
        ));
    }
    let mut list = [0u32; 1];
    // SAFETY: both calls are standard Win32; `list` is a valid writable slice. A buffer
    // smaller than the attached-process count is fine — the return is then the required
    // count, and only "is it zero" is read here. The last error is cleared first: a zero
    // return is only meaningful together with the code THIS call set, and the live caller
    // reaches here right after a `GenerateConsoleCtrlEvent` that itself failed with
    // `ERROR_INVALID_HANDLE` — reading that stale value would let the probe "confirm" an
    // absence it never measured.
    let n = unsafe {
        SetLastError(WIN32_ERROR(0));
        GetConsoleProcessList(&mut list)
    };
    if n != 0 {
        return Ok(true);
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(ERROR_INVALID_HANDLE.0 as i32) {
        Ok(false)
    } else {
        Err(err)
    }
}

/// Classify a `GenerateConsoleCtrlEvent` failure. Pure — the Win32 result and the console
/// probe are both parameters — so every arm is unit-testable without hooking the OS calls the
/// live path depends on (the same injection idiom as `treewalk::descendants_with`).
///
/// `err` is the `io::Error` converted from `windows::core::Error`, so its `raw_os_error` is
/// the **HRESULT**, not the bare Win32 code.
///
/// `Error::NoConsole` is returned ONLY when the failure code matches AND the probe confirms
/// there is no console. A contradicted probe, a failed probe, or any other failure code keeps
/// the raw `Error::Io`: the typed variant must never assert a cause the process just measured
/// to be false.
pub(crate) fn classify_ctrl_event_failure(pid: u32, err: io::Error, console: io::Result<bool>) -> crate::error::Error {
    use windows::Win32::Foundation::ERROR_INVALID_HANDLE;
    let no_console = windows::core::HRESULT::from_win32(ERROR_INVALID_HANDLE.0).0;
    if err.raw_os_error() == Some(no_console) && matches!(console, Ok(true)) {
        // warn, not debug: the crate's core mapping (this code <=> no console) was just
        // contradicted. Either another thread attached a console in the confirmation gap, or
        // the mapping does not hold on this host — both deserve to be visible, and neither
        // may be reported as an ordinary Io passthrough without a trace.
        log::warn!(
            "CTRL_BREAK to group {pid} failed with ERROR_INVALID_HANDLE, but a console is \
             attached; surfacing the raw error rather than claiming NoConsole"
        );
        return crate::error::Error::Io(err);
    }
    if err.raw_os_error() == Some(no_console) {
        if let Err(probe) = &console {
            log::warn!("CTRL_BREAK to group {pid}: the console probe failed ({probe}); cannot classify");
            return crate::error::Error::Io(err);
        }
        return crate::error::Error::NoConsole {
            detail: format!(
                "cannot send CTRL_BREAK to process group {pid}: this process has no attached \
                 console. A GUI-subsystem binary, a service, or a detached spawn cannot deliver \
                 console control events — Windows delivers them only within the caller's \
                 console. Attach a console before spawning the tree, or use kill_tree() for a \
                 hard teardown."
            ),
        };
    }
    // The probe cannot change this classification, but if it ALSO failed that is a second,
    // independent OS failure and the arms above log theirs — say so here too rather than
    // dropping it silently.
    if let Err(probe) = &console {
        log::warn!("CTRL_BREAK to group {pid} failed, and the console probe also failed ({probe})");
    }
    crate::error::Error::Io(err)
}

/// Send `CTRL_BREAK_EVENT` to the process group rooted at `pid`.
/// The child was spawned with `CREATE_NEW_PROCESS_GROUP`, making it the leader;
/// targeting its `pid` reaches the whole group without affecting the parent's console.
/// `CTRL_C` cannot be group-targeted; `CTRL_BREAK` is the only option here.
///
/// **Requires the CALLER to have a console.** That is the failure this classifies; Windows
/// can also report `ERROR_INVALID_PARAMETER` for a pid that names no process at all, which
/// stays a raw `Error::Io`. A group that merely *drained* is not a failure — measured, a dead
/// group leader still returns success. The failure code is authoritative; the console probe that follows only *confirms* it, so a
/// console state change in the gap degrades the result to a raw `Error::Io` rather than to a
/// false `NoConsole`. Targeting a group that is in a *different* console is NOT reported by
/// Windows at all — it returns success and delivers nothing.
pub(crate) fn terminate(pid: u32) -> Result<(), crate::error::Error> {
    use windows::Win32::System::Console::{GenerateConsoleCtrlEvent, CTRL_BREAK_EVENT};
    // SAFETY: standard Win32 call targeting the child's own console group.
    match unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) } {
        Ok(()) => Ok(()),
        Err(e) => Err(classify_ctrl_event_failure(
            pid,
            io::Error::from(e),
            caller_has_console(),
        )),
    }
}

/// Test-only: force the NEXT `caller_has_console` on THIS thread to report a probe failure,
/// so that arm's production is covered — a live `GetConsoleProcessList` cannot be made to
/// fail. Take semantics, mirroring `treewalk::fault`.
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;
    thread_local! {
        static FORCE_CONSOLE_PROBE_ERROR: Cell<bool> = const { Cell::new(false) };
    }
    pub(crate) fn set_force_console_probe_error(on: bool) {
        FORCE_CONSOLE_PROBE_ERROR.with(|f| f.set(on));
    }
    pub(crate) fn take_force_console_probe_error() -> bool {
        FORCE_CONSOLE_PROBE_ERROR.with(|f| f.replace(false))
    }
    pub(crate) fn armed() -> bool {
        FORCE_CONSOLE_PROBE_ERROR.with(|f| f.get())
    }
}

/// Create a `KILL_ON_JOB_CLOSE` job, associate a fresh I/O completion port with it — ALWAYS,
/// before `AssignProcessToJobObject`, never opt-in — and assign the process at `proc_handle` to
/// it. Associating before assignment (rather than after) means no window exists in which the
/// job could be assigned but unassociated: nothing racing the assignment can observe a job that
/// briefly had a member with no completion port at all.
fn assign_to_kill_on_close_job(proc_handle: std::os::windows::io::RawHandle) -> io::Result<JobHandle> {
    // A Windows `RawHandle` is a `*mut c_void`.
    let raw_handle = HANDLE(proc_handle.cast());
    // SAFETY: all calls are standard Win32; owned handles are closed on every error path.
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

        let port = match CreateIoCompletionPort(INVALID_HANDLE_VALUE, None, 0, 0) {
            Ok(p) => p,
            Err(e) => {
                let _ = CloseHandle(job);
                return Err(io::Error::from(e));
            }
        };
        // The completion key only needs to be unique per port; the job handle's own bit
        // pattern is a convenient, already-unique value with no bookkeeping of its own.
        let assoc = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: job.0,
            CompletionPort: port,
        };
        if let Err(e) = SetInformationJobObject(
            job,
            JobObjectAssociateCompletionPortInformation,
            std::ptr::addr_of!(assoc).cast(),
            size_of::<JOBOBJECT_ASSOCIATE_COMPLETION_PORT>() as u32,
        ) {
            let _ = CloseHandle(port);
            let _ = CloseHandle(job);
            return Err(io::Error::from(e));
        }

        if let Err(e) = AssignProcessToJobObject(job, raw_handle) {
            let _ = CloseHandle(port);
            let _ = CloseHandle(job);
            return Err(io::Error::from(e));
        }

        Ok(JobHandle::new(job, port))
    }
}

/// Read the job's LIVE member pids via `QueryInformationJobObject(JobObjectBasicProcessIdList)`
/// — the authoritative, always-fresh source `wait_drained` re-consults every round, independent
/// of any completion-port message. Grows the buffer and retries (no bound on retries: a job
/// that keeps growing needs an ever-larger buffer, but capping this would silently under-report
/// live membership rather than fail loudly).
fn query_job_pid_list(job: HANDLE) -> io::Result<Vec<u32>> {
    let mut capacity: usize = 64;
    loop {
        let buf_len = size_of::<JOBOBJECT_BASIC_PROCESS_ID_LIST>() + capacity.saturating_sub(1) * size_of::<usize>();
        let mut buf = vec![0u8; buf_len];
        let mut returned = 0u32;
        // SAFETY: `buf` is exactly `buf_len` bytes, zero-initialized, matching the trailing
        // `ProcessIdList` array's declared capacity; the call writes at most that many bytes.
        let result = unsafe {
            QueryInformationJobObject(
                Some(job),
                JobObjectBasicProcessIdList,
                buf.as_mut_ptr().cast(),
                buf_len as u32,
                Some(&mut returned),
            )
        };
        // SAFETY: the fixed header (`NumberOfAssignedProcesses`/`NumberOfProcessIdsInList`) is
        // always written even when the call fails with a too-small buffer.
        let header = unsafe { &*(buf.as_ptr() as *const JOBOBJECT_BASIC_PROCESS_ID_LIST) };
        if result.is_err() {
            let assigned = header.NumberOfAssignedProcesses as usize;
            if assigned > capacity {
                capacity = assigned;
                continue;
            }
            return Err(io::Error::last_os_error());
        }
        let n = header.NumberOfProcessIdsInList as usize;
        debug_assert!(
            n <= capacity,
            "kernel reported more pids than the queried buffer could hold"
        );
        let list_ptr = header.ProcessIdList.as_ptr();
        let mut pids = Vec::with_capacity(n.min(capacity));
        for i in 0..n.min(capacity) {
            // SAFETY: `list_ptr` points at the start of `buf`'s trailing `usize` array, which
            // has room for `capacity` entries; `i < n.min(capacity) <= capacity`.
            let raw = unsafe { *list_ptr.add(i) };
            pids.push(raw as u32);
        }
        return Ok(pids);
    }
}

/// The largest handle count a single `WaitForMultipleObjects` call accepts (`MAXIMUM_WAIT_OBJECTS`).
const MAXIMUM_WAIT_OBJECTS: usize = 64;

impl JobHandle {
    /// Block until every process in this job has EXITED (not reaped), or until `deadline`.
    ///
    /// Deliberately does NOT read the completion port associated at job-creation time: every
    /// ordinary job-lifecycle completion-port message (`JOB_OBJECT_MSG_EXIT_PROCESS`,
    /// `JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO`, ...) is documented by Microsoft as **not guaranteed
    /// to be delivered** — only `JobObjectNotificationLimitInformation`-class resource-limit
    /// messages carry a delivery guarantee, a class unrelated to process lifecycle. Trusting the
    /// port for this call's own correctness would make an unbounded `wait_tree()` capable of a
    /// caller-invisible infinite hang on a single dropped packet.
    ///
    /// Instead, each round: (1) re-enumerate the job's LIVE members via
    /// `QueryInformationJobObject(JobObjectBasicProcessIdList)` — the authoritative, always-fresh
    /// source of truth, independent of any notification; (2) if empty, the tree has drained; (3)
    /// otherwise open real `SYNCHRONIZE` handles to up to `MAXIMUM_WAIT_OBJECTS - 1` of those
    /// pids and block on `WaitForMultipleObjects(bWaitAll = FALSE)`. A process handle becoming
    /// signaled on exit is an unconditional, always-honored OS guarantee — unlike a job message
    /// — so as long as this round's tree is non-empty, at least one tracked handle WILL
    /// eventually signal, forcing a fresh re-enumeration next round. This can never falsely
    /// report `AllMembersExited` (that verdict is only ever reached via a live re-count of
    /// zero); it can only be slow to *notice* full drain when concurrently-live membership
    /// exceeds `MAXIMUM_WAIT_OBJECTS - 1` in a single round (this round's un-tracked excess is
    /// picked up on the NEXT re-enumeration, once a tracked handle signals).
    ///
    /// `deadline` follows the crate's watch convention (see [`crate::wait::remaining`]). No
    /// interval is chosen anywhere in this path: every round blocks in one
    /// `WaitForMultipleObjects` call for exactly the caller's own remaining time.
    ///
    /// `cancel`, when given, is appended to every round's wait set (one fewer live member
    /// tracked per round) so a live `WaitForMultipleObjects` releases the instant it is
    /// signaled rather than only at the next re-enumeration boundary — the async wrapper's
    /// drop-cancellation primitive (mirrors `block_until_exit_or_cancel`'s cancel event). A
    /// cancellation reports `MembersRemain` (the tree's drain state is simply unknown at that
    /// point, same as a timeout), never an error.
    pub(crate) fn wait_drained(
        &self,
        deadline: Option<Option<std::time::Instant>>,
        cancel: Option<HANDLE>,
    ) -> Result<crate::containment::TreeDrain, crate::error::Error> {
        let Some(job) = self.as_handle() else {
            // The job was already consumed (killed/dropped) by the time this call runs — the
            // tree it owned is gone.
            return Ok(crate::containment::TreeDrain::AllMembersExited);
        };
        wait_drained_raw(job, deadline, cancel)
    }
}

/// The loop body of [`JobHandle::wait_drained`], taking the already-resolved raw handle rather
/// than borrowing `&JobHandle` — the async wrapper (`tokio::wait`) copies the handle value out
/// before handing it to `spawn_blocking`, since a `'static` blocking closure cannot capture a
/// borrow. Sound because the async caller holds `&JobHandle` (transitively, `&Child`) across the
/// whole `spawn_blocking` `.await`, so the job handle cannot be closed while this runs.
pub(crate) fn wait_drained_raw(
    job: HANDLE,
    deadline: Option<Option<std::time::Instant>>,
    cancel: Option<HANDLE>,
) -> Result<crate::containment::TreeDrain, crate::error::Error> {
    use crate::containment::TreeDrain;
    use crate::error::Error;

    let budget = MAXIMUM_WAIT_OBJECTS - 1 - if cancel.is_some() { 1 } else { 0 };
    loop {
        let pids = query_job_pid_list(job).map_err(Error::Io)?;
        if pids.is_empty() {
            return Ok(TreeDrain::AllMembersExited);
        }

        let mut handles: Vec<HANDLE> = Vec::new();
        let mut denied: Option<io::Error> = None;
        for pid in pids.iter().take(budget) {
            // SAFETY: standard Win32 call; the handle is closed below on every path.
            match unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, *pid) } {
                Ok(h) => handles.push(h),
                // ERROR_INVALID_PARAMETER: the pid no longer names a process — it exited in
                // the race between the enumeration above and this open. That is real
                // progress (this round's tree is shrinking), not a failure: loop back to
                // re-enumerate rather than treating it as denied.
                Err(e) if e.code() == windows::Win32::Foundation::ERROR_INVALID_PARAMETER.to_hresult() => {}
                Err(e) => denied = Some(io::Error::from(e)),
            }
        }

        if handles.is_empty() {
            if let Some(e) = denied {
                // A persistent, actionable open failure (not a benign exit-race): looping
                // back here without ever holding a real handle to block on would busy-spin.
                log::warn!("wait_tree: could not open any live job member to watch for its exit ({e})");
                return Err(Error::Unassessable {
                    detail: "could not open a handle to any live member of the contained tree \
                                 to observe its exit"
                        .into(),
                    source: Some(e),
                });
            }
            // Every candidate in this round's batch had already exited by the time we tried
            // to open it — real progress. Re-enumerate immediately.
            continue;
        }

        let ms: u32 = match crate::wait::remaining(deadline) {
            None => INFINITE,
            Some(d) => {
                if d.is_zero() {
                    for h in &handles {
                        // SAFETY: each handle was freshly opened above and not yet closed.
                        unsafe {
                            let _ = CloseHandle(*h);
                        }
                    }
                    return Ok(TreeDrain::MembersRemain);
                }
                d.as_millis().min((INFINITE - 1) as u128) as u32
            }
        };

        // The cancel handle (if any) is appended AFTER the real member handles, never
        // closed here (caller-owned) — only `handles` (the freshly opened member handles)
        // are closed below.
        let mut wait_set = handles.clone();
        if let Some(c) = cancel {
            wait_set.push(c);
        }

        // SAFETY: every handle in `handles` was just opened above and stays open for the
        // duration of this call; `cancel`, if present, is kept alive by its caller for the
        // same duration.
        let waited = unsafe { WaitForMultipleObjects(&wait_set, false, ms) };
        let wait_failed = (waited == WAIT_FAILED).then(io::Error::last_os_error);
        for h in &handles {
            // SAFETY: each handle was opened above; closing after the wait releases it
            // regardless of which handle (if any) was signaled.
            unsafe {
                let _ = CloseHandle(*h);
            }
        }

        if waited == WAIT_TIMEOUT {
            return Ok(TreeDrain::MembersRemain);
        }
        if let Some(e) = wait_failed {
            return Err(Error::Io(e));
        }
        let idx = waited.0.wrapping_sub(WAIT_OBJECT_0.0) as usize;
        debug_assert!(
            idx < wait_set.len(),
            "unexpected WaitForMultipleObjects verdict: {waited:?}"
        );
        if cancel.is_some() && idx == handles.len() {
            // The cancel handle was signaled — the caller's future was dropped. The
            // tree's drain state is genuinely unknown at this instant; report it exactly
            // like a timeout rather than inventing a verdict.
            return Ok(TreeDrain::MembersRemain);
        }
        // A tracked member exited — loop back and re-enumerate the authoritative live set.
    }
}

/// Resume every suspended thread of the process at `proc_handle` after job assignment.
///
/// Why resume REGARDLESS of job-assign result: the kill-group race invariant
/// requires the child to be inside the job before executing, so it was spawned
/// frozen (CREATE_SUSPENDED). Whether or not job assignment succeeded, the child
/// MUST be resumed — a frozen process is unacceptable. If `ResumeThread` fails
/// the child is killed immediately and an error returned.
///
/// PID-reuse safety: the caller holds the child's process handle (via the owning
/// `Child`), keeping its PID alive for the duration of the Toolhelp snapshot walk.
fn resume_initial_threads(proc_handle: std::os::windows::io::RawHandle) -> io::Result<()> {
    use windows::Win32::Foundation::ERROR_NO_MORE_FILES;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };

    let raw_handle = HANDLE(proc_handle.cast());

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

/// Assign the process at `proc_handle` to a `KILL_ON_JOB_CLOSE` job and resume its
/// initial threads.
///
/// `proc_handle` must remain open for the whole call (it pins the pid against reuse during the
/// Toolhelp thread walk in `resume_initial_threads`). Both callers hold the owning `Child` —
/// sync `std::process::Child`, async `::tokio::process::Child` — across the call, so it does.
///
/// Returns `Ok(Some(JobHandle))` on full success (job assigned AND resumed).
/// Returns `Ok(None)` when job assignment fails — the caller falls back to the
/// universal `Containment::TreeWalk` mechanism (identity teardown).
/// Returns `Err` when resume fails — a frozen child is unacceptable; the
/// child+job are killed and the error propagates to fail the spawn.
pub(crate) fn attach_job(proc_handle: std::os::windows::io::RawHandle) -> io::Result<Option<JobHandle>> {
    let job_result = assign_to_kill_on_close_job(proc_handle);

    // Resume REGARDLESS of job assignment result. A frozen child cannot be left running.
    if let Err(resume_err) = resume_initial_threads(proc_handle) {
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

/// Test-only membership probe: whether `pid` is inside the Job Object held by `attached`, via
/// `IsProcessInJob` against that job handle (not "any job"). Membership is immutable once assigned,
/// so it is deterministic for a handle-pinned child regardless of run state. Shared by the sync and
/// async `Child::test_job_handle_contains_self` accessors (both compiled outside `cfg(test)` so
/// integration crates can call them).
pub(crate) fn job_contains_pid(attached: &crate::containment::Attached, pid: u32) -> bool {
    use windows::Win32::System::JobObjects::IsProcessInJob;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION};

    let crate::containment::Attached::JobObject(job) = attached else {
        return false;
    };
    let Some(job_handle) = job.as_handle() else {
        return false;
    };

    // Open the child process by PID; the backend doesn't expose its handle.
    // SAFETY: standard Win32 call; the handle is closed below.
    let process_handle = unsafe {
        match OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return false,
        }
    };

    let mut in_job = windows::core::BOOL(0);
    // SAFETY: both handles are valid for the duration of the call.
    let ok = unsafe { IsProcessInJob(process_handle, Some(job_handle), &mut in_job) };
    // SAFETY: `process_handle` was opened above and must be closed.
    unsafe {
        let _ = CloseHandle(process_handle);
    }
    ok.is_ok() && in_job.as_bool()
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
