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
    CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicProcessIdList, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject, JOBOBJECT_BASIC_PROCESS_ID_LIST,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Threading::{
    GetProcessId, OpenProcess, OpenThread, ResumeThread, WaitForMultipleObjects, WaitForSingleObject,
    CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, INFINITE, PROCESS_SYNCHRONIZE, THREAD_SUSPEND_RESUME,
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

/// Pre-spawn creation flags for a root spawn.
/// `CREATE_SUSPENDED`: child must not execute before it is inside the job.
/// `CREATE_NEW_PROCESS_GROUP`: child leads its own console group so
/// `GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid)` can target it.
/// Shared by the std path and the raw `CreateProcessW` backend via `windows_contain_setup`.
/// What this word implies about cooperative shutdown is derived by [`mechanism_from_flags`].
pub(crate) fn root_flags() -> u32 {
    CREATE_SUSPENDED.0 | CREATE_NEW_PROCESS_GROUP.0
}

/// Pre-spawn creation flags for a nested (non-root) spawn.
/// Only `CREATE_NEW_PROCESS_GROUP` — no suspension needed for nested spawns.
/// What this word implies about cooperative shutdown is derived by [`mechanism_from_flags`].
pub(crate) fn group_flags() -> u32 {
    CREATE_NEW_PROCESS_GROUP.0
}

/// Which cooperative signal a child spawned with `creation_flags` can be sent, derived from the
/// flag word the spawn actually passed to `CreateProcessW`.
///
/// Three rows:
///
/// - `CREATE_NEW_PROCESS_GROUP` absent → [`GracefulMechanism::None`]. The child sits in the
///   spawner's group, so no console control event can ever be addressed to it individually by
///   any process, and group leadership cannot be changed after creation. This is the one flat
///   negative the flag word settles absolutely.
/// - the group flag set, and none of `DETACHED_PROCESS` / `CREATE_NEW_CONSOLE` /
///   `CREATE_NO_WINDOW` → [`GracefulMechanism::ConsoleGroup`].
/// - the group flag set together with any of those three → [`GracefulMechanism::OtherConsoleGroup`].
///
/// What the results do **not** mean. `ConsoleGroup` says the flags do not *exclude* in-process
/// delivery — it is not a claim the child is reachable. Console membership is not a function of
/// the flag word at all: a GUI-subsystem image never attaches to the spawner's console whatever
/// the flags say, and any child may `FreeConsole`/`AllocConsole`/`AttachConsole` after it starts.
/// An out-of-console group makes `GenerateConsoleCtrlEvent` report success while delivering
/// nothing, which is why the split exists. And `OtherConsoleGroup` is not "unreachable": a child
/// spawned with window suppression owns a *private* console a helper process can attach to, so
/// the claim is about the route from here, never a verdict on the child.
///
/// Any future creation-flag surface must extend this one function rather than deriving a
/// mechanism of its own.
pub(crate) fn mechanism_from_flags(creation_flags: u32) -> crate::graceful::GracefulMechanism {
    use crate::graceful::GracefulMechanism;
    use windows::Win32::System::Threading::{CREATE_NEW_CONSOLE, CREATE_NO_WINDOW, DETACHED_PROCESS};

    if creation_flags & CREATE_NEW_PROCESS_GROUP.0 == 0 {
        return GracefulMechanism::None;
    }
    let out_of_console = DETACHED_PROCESS.0 | CREATE_NEW_CONSOLE.0 | CREATE_NO_WINDOW.0;
    if creation_flags & out_of_console != 0 {
        return GracefulMechanism::OtherConsoleGroup;
    }
    GracefulMechanism::ConsoleGroup
}

/// Clear the inherit flag on the parent's std handles before spawning. Prevents
/// the child from inheriting the test runner's console handles. Best-effort.
pub(crate) fn clear_std_handle_inheritance() {
    #[cfg(test)]
    observe::record_inheritance_cleared();
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

/// What this process's ambient job object says about a child breaking away from it.
///
/// `Unknown` exists for the same reason `identity::Resolved::Unknown` does: cosca must not assert
/// a cause it could not measure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JobBreakaway {
    NotInJob,
    Permitted,
    /// The job removes new children itself, without them asking — so it does not FORBID
    /// breakaway, and a message saying it does would be wrong about the world.
    SilentBreakaway,
    Forbidden,
    Unknown,
}

/// Read this process's ambient job's breakaway limits.
///
/// Impure, and called only to CLASSIFY a spawn failure that already happened — never to gate one
/// before it. Spawning does not disturb job membership, but membership changes on its own (a
/// process can be assigned to a job at any moment), so a pre-spawn guard would decide the outcome
/// from state that may already be stale, while a post-failure confirmation at worst withholds a
/// typed error. Same impure-probe / pure-classifier split as `caller_has_console` /
/// `classify_ctrl_event_failure`.
///
/// `Permitted` takes precedence over `SilentBreakaway`, because a job setting both does honour
/// the flag.
pub(crate) fn probe_job_breakaway() -> JobBreakaway {
    use windows::Win32::System::JobObjects::{
        IsProcessInJob, JobObjectBasicLimitInformation, QueryInformationJobObject, JOBOBJECT_BASIC_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT, JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
    };
    use windows::Win32::System::Threading::GetCurrentProcess;

    #[cfg(test)]
    if fault::take_force_job_probe_error() {
        return JobBreakaway::Unknown;
    }

    let mut in_job = windows::core::BOOL(0);
    // SAFETY: standard Win32; `in_job` is a valid out-param, and `None` asks "in ANY job".
    if unsafe { IsProcessInJob(GetCurrentProcess(), None, &mut in_job) }.is_err() {
        return JobBreakaway::Unknown;
    }
    if !in_job.as_bool() {
        return JobBreakaway::NotInJob;
    }

    let mut info = JOBOBJECT_BASIC_LIMIT_INFORMATION::default();
    // SAFETY: standard Win32; `info` is a valid, correctly-sized out-param, and `None` asks about
    // the calling process's own job. The query class returns the BASIC structure even though the
    // matching setter needs the extended one — an asymmetry in the API, not a mistake here.
    let queried = unsafe {
        QueryInformationJobObject(
            None,
            JobObjectBasicLimitInformation,
            std::ptr::addr_of_mut!(info).cast(),
            size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as u32,
            None,
        )
    };
    if queried.is_err() {
        return JobBreakaway::Unknown;
    }
    if info.LimitFlags & JOB_OBJECT_LIMIT_BREAKAWAY_OK != JOB_OBJECT_LIMIT(0) {
        return JobBreakaway::Permitted;
    }
    if info.LimitFlags & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK != JOB_OBJECT_LIMIT(0) {
        return JobBreakaway::SilentBreakaway;
    }
    JobBreakaway::Forbidden
}

/// Send `CTRL_BREAK_EVENT` to the process group rooted at `pid`.
/// The child was spawned with `CREATE_NEW_PROCESS_GROUP`, making it the leader;
/// targeting its `pid` reaches the whole group without affecting the parent's console.
/// `CTRL_C` cannot be group-targeted; `CTRL_BREAK` is the only option here.
///
/// **Precondition: the caller holds something that pins `pid`** — the owning `Child`'s process
/// handle, or an identity-verified `ProcessId`. This function takes a raw pid because Win32
/// offers no verify-then-signal primitive, so an unpinned pid could name a recycled process.
///
/// **Requires the CALLER to have a console.** That is the failure this classifies; Windows
/// can also report `ERROR_INVALID_PARAMETER` for a pid that names no process at all, which
/// stays a raw `Error::Io`. The failure code is authoritative; the console probe that follows
/// only *confirms* it, so a console state change in the gap degrades the result to a raw
/// `Error::Io` rather than to a false `NoConsole`.
///
/// **The Win32 return value is evidence in neither direction.** Measured: a target in another
/// console returns success having delivered nothing, and the same class of target returns
/// `ERROR_INVALID_PARAMETER` in another configuration. So the classification above must never
/// be replaced with a return-code check, and success must never be read as delivery.
///
/// **An already-exited target is `Ok`**, because the pinned pid stays allocated and the call
/// succeeds — matching the crate's "already-dead ⇒ `Ok`" contract for the lone signal. A dead
/// group leader is not proof of an empty group either: a signal addressed to one still reaches
/// live members of that group.
///
/// **Two known gaps a caller must plan around.** A target that shares no console with the caller
/// is reported as success and receives nothing; a process attached to the child's *own* console
/// can deliver an event to it, and `kill`/`kill_tree` need no console at all. And every call —
/// including one to an ordinary group that has already drained — leaves a dead entry in the
/// caller's console process list, which persists after the target exits.
///
/// **Absence from the caller's console list is not grounds to refuse.** Membership is readable
/// (`GetConsoleProcessList`), so the first gap's condition is decidable here; the inference is
/// what is missing. Absence is consistent with three states and only one of them is a
/// non-delivery. A contained child is absent at the instant `spawn()` returns — measured 0/10,
/// and 0/10 again for the suspend-then-resume shape a contained root uses — while a signal in
/// that window is delivered and kills it, so refusing would turn a working teardown into an
/// error. An already-exited child is absent too, because a real member's entry is removed on
/// exit, where this function's contract is "already-dead ⇒ `Ok`". The genuinely-elsewhere target
/// is the third, and separating it needs the TARGET's console rather than ours — a broker, not
/// a probe.
pub(crate) fn terminate(pid: u32) -> Result<(), crate::error::Error> {
    use windows::Win32::System::Console::{GenerateConsoleCtrlEvent, CTRL_BREAK_EVENT};
    debug_assert!(
        pid != 0,
        "pid 0 addresses every process attached to the caller's console, including the caller"
    );
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

/// Test-only: record that `clear_std_handle_inheritance` ran on THIS thread, so a test can prove
/// a refused spawn did not mutate this process first. Take semantics, mirroring `fault`.
///
/// The real handle flags cannot serve as the observation: the mutation is process-global and
/// permanent, so any earlier contained spawn in the same test binary would already have made it
/// meaningless.
#[cfg(test)]
pub(crate) mod observe {
    use std::cell::Cell;
    thread_local! {
        static INHERITANCE_CLEARED: Cell<bool> = const { Cell::new(false) };
    }
    pub(crate) fn record_inheritance_cleared() {
        INHERITANCE_CLEARED.with(|f| f.set(true));
    }
    pub(crate) fn take_inheritance_cleared() -> bool {
        INHERITANCE_CLEARED.with(|f| f.replace(false))
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
    thread_local! {
        static FORCE_JOB_PROBE_ERROR: Cell<bool> = const { Cell::new(false) };
    }
    /// Force the NEXT `probe_job_breakaway` on THIS thread to report `Unknown`: neither Win32
    /// call it makes can be made to fail on a live system.
    pub(crate) fn set_force_job_probe_error(on: bool) {
        FORCE_JOB_PROBE_ERROR.with(|f| f.set(on));
    }
    pub(crate) fn take_force_job_probe_error() -> bool {
        FORCE_JOB_PROBE_ERROR.with(|f| f.replace(false))
    }
    pub(crate) fn take_force_console_probe_error() -> bool {
        FORCE_CONSOLE_PROBE_ERROR.with(|f| f.replace(false))
    }
    pub(crate) fn armed() -> bool {
        FORCE_CONSOLE_PROBE_ERROR.with(|f| f.get())
    }
}

/// Create a `KILL_ON_JOB_CLOSE` job and assign the process at `proc_handle` to it.
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

        if let Err(e) = AssignProcessToJobObject(job, raw_handle) {
            let _ = CloseHandle(job);
            return Err(io::Error::from(e));
        }

        Ok(JobHandle::new(job))
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
        // Backed by `Vec<usize>`, not `Vec<u8>`: `JOBOBJECT_BASIC_PROCESS_ID_LIST` is 8-aligned
        // (it holds `usize` fields), but a `Vec<u8>`'s allocation is only ever requested at
        // alignment 1. Forming a `&JOBOBJECT_BASIC_PROCESS_ID_LIST` from a `Vec<u8>` buffer is
        // undefined behaviour regardless of what the allocator happens to return in practice —
        // the compiler is entitled to assume the reference's target is properly aligned. A
        // `Vec<usize>` buffer is naturally aligned for this header, and is read through raw
        // pointers below rather than a reference, so no alignment assumption is ever load-bearing.
        let mut buf: Vec<usize> = vec![0usize; buf_len.div_ceil(size_of::<usize>())];
        let mut returned = 0u32;
        let header_ptr = buf.as_mut_ptr().cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>();
        // SAFETY: `buf` is at least `buf_len` bytes (rounded up to whole `usize`s),
        // zero-initialized, matching the trailing `ProcessIdList` array's declared capacity; the
        // call writes at most `buf_len` bytes.
        let result = unsafe {
            QueryInformationJobObject(
                Some(job),
                JobObjectBasicProcessIdList,
                header_ptr.cast(),
                buf_len as u32,
                Some(&mut returned),
            )
        };
        // The fixed header (`NumberOfAssignedProcesses`/`NumberOfProcessIdsInList`) is always
        // written even when the call fails with a too-small buffer. Read both fields via
        // `addr_of!`/`read_unaligned` on the raw pointer rather than materialising a
        // `&JOBOBJECT_BASIC_PROCESS_ID_LIST` reference, so this call never depends on forming a
        // reference into a buffer the kernel writes out-of-band.
        // SAFETY: `header_ptr` is valid for reads of `size_of::<JOBOBJECT_BASIC_PROCESS_ID_LIST>()`
        // bytes (`buf_len` is at least that size by construction) and initialized (zeroed above,
        // then possibly partially overwritten by the call).
        let assigned = unsafe { std::ptr::addr_of!((*header_ptr).NumberOfAssignedProcesses).read_unaligned() } as usize;
        if result.is_err() {
            if assigned > capacity {
                capacity = assigned;
                continue;
            }
            return Err(io::Error::last_os_error());
        }
        // SAFETY: same as above.
        let n = unsafe { std::ptr::addr_of!((*header_ptr).NumberOfProcessIdsInList).read_unaligned() } as usize;
        debug_assert!(
            n <= capacity,
            "kernel reported more pids than the queried buffer could hold"
        );
        // SAFETY: `ProcessIdList` is the header's trailing flexible-array member; `buf` was sized
        // for `capacity` entries starting right after the two `u32` counters, and
        // `n.min(capacity) <= capacity`, so every read below is in-bounds and initialized.
        let list_ptr = unsafe { std::ptr::addr_of!((*header_ptr).ProcessIdList).cast::<usize>() };
        let mut pids = Vec::with_capacity(n.min(capacity));
        for i in 0..n.min(capacity) {
            // SAFETY: see above.
            let raw = unsafe { list_ptr.add(i).read_unaligned() };
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
    /// Deliberately does not associate an I/O completion port with the job at all: every
    /// ordinary job-lifecycle completion-port message (`JOB_OBJECT_MSG_EXIT_PROCESS`,
    /// `JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO`, ...) is documented by Microsoft as **not guaranteed
    /// to be delivered** — only `JobObjectNotificationLimitInformation`-class resource-limit
    /// messages carry a delivery guarantee, a class unrelated to process lifecycle. Trusting a
    /// port for this call's own correctness would make an unbounded `wait_tree()` capable of a
    /// caller-invisible infinite hang on a single dropped packet — and with the port never read,
    /// associating one anyway would only cost unbounded kernel nonpaged-pool growth (one queued
    /// packet per job lifecycle event, for the job handle's whole lifetime) for nothing.
    ///
    /// Instead, each round: (1) re-enumerate the job's LIVE members via
    /// `QueryInformationJobObject(JobObjectBasicProcessIdList)` — the authoritative, always-fresh
    /// source of truth, independent of any notification; (2) if empty, the tree has drained; (3)
    /// otherwise open real `SYNCHRONIZE` handles to up to `MAXIMUM_WAIT_OBJECTS - 1` of those
    /// pids and block on `WaitForMultipleObjects(bWaitAll = FALSE)`. A process handle becoming
    /// signaled on exit is an unconditional, always-honored OS guarantee — unlike a job message
    /// — so as long as this round's tree is non-empty, at least one tracked handle WILL
    /// eventually signal, forcing a fresh re-enumeration next round. While the job handle is
    /// still open, this can never falsely report `AllMembersExited` (that verdict is only ever
    /// reached via a live re-count of zero); it can only be slow to *notice* full drain when
    /// concurrently-live membership exceeds `MAXIMUM_WAIT_OBJECTS - 1` in a single round (this
    /// round's un-tracked excess is picked up on the NEXT re-enumeration, once a tracked handle
    /// signals). If the job handle has ALREADY been consumed by the time this call runs, there
    /// is nothing left to re-enumerate at all — see the early return below, which reports
    /// [`Error::Unassessable`](crate::error::Error::Unassessable) rather than guess.
    ///
    /// `deadline` follows the crate's watch convention (see [`crate::wait::remaining`]). No
    /// interval is chosen anywhere in this path: every round blocks in one
    /// `WaitForMultipleObjects` call for exactly the caller's own remaining time. An
    /// already-elapsed (or `Duration::ZERO`) deadline still gets one real re-enumeration and, if
    /// any member is still live, one real non-blocking `WaitForMultipleObjects` poll before a
    /// deadline-based verdict is returned — a stale bound only ever forecloses looping back for
    /// ANOTHER round, never the current one's own observation. A drained tree is reported
    /// `AllMembersExited` regardless of how late the caller arrived to look.
    ///
    /// `cancel`, when given, is appended to every round's wait set (one fewer live member
    /// tracked per round) so a live `WaitForMultipleObjects` releases the instant it is
    /// signaled rather than only at the next re-enumeration boundary — the async wrapper's
    /// drop-cancellation primitive (mirrors `block_until_exit_or_cancel`'s cancel event). A
    /// cancellation reports `MembersRemain` (the tree's drain state is simply unknown at that
    /// point, same as a timeout), never an error. Unlike the deadline, cancellation IS checked
    /// before that first re-enumeration too: it is a genuine "stop looking" instruction, not a
    /// stale bound on how long to keep looking, so a caller who cancels before this call ever
    /// enumerates the job once still gets a prompt `MembersRemain` rather than being forced
    /// through one more round first.
    pub(crate) fn wait_drained(
        &self,
        deadline: Option<Option<std::time::Instant>>,
        cancel: Option<HANDLE>,
    ) -> Result<crate::containment::TreeDrain, crate::error::Error> {
        let Some(job) = self.as_handle() else {
            // The job was already consumed — `hard_kill()` or `Drop` already ran, nulling `raw`
            // and closing the underlying handle. See `consumed_job_handle_error`'s own doc for
            // why that is reported as `Unassessable` rather than a guessed `AllMembersExited`.
            return Err(consumed_job_handle_error());
        };
        wait_drained_raw(job, deadline, cancel)
    }
}

/// The [`Error::Unassessable`](crate::error::Error::Unassessable) reported when a drain check
/// finds the job handle already closed (`kill_tree()`/`hard_kill()`, or the `Child` was
/// dropped): `TerminateJobObject`/`CloseHandle` are not documented as synchronous with member
/// process teardown, so once the handle is gone there is no way left to ask whether every member
/// has actually finished exiting — reporting `AllMembersExited` here would be a guess, not a
/// live-checked verdict. Shared verbatim by `JobHandle::wait_drained`'s own early return and its
/// tokio twin, `job_wait_tree_drained`.
pub(crate) fn consumed_job_handle_error() -> crate::error::Error {
    crate::error::Error::Unassessable {
        detail: "the job handle was already closed (kill_tree()/hard_kill(), or the Child was \
                 dropped) before this drain check ran; whether every member has actually \
                 finished exiting can no longer be observed"
            .into(),
        source: None,
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
        // Cancellation is checked BEFORE any work this round, including the very first — a
        // deliberate asymmetry with the deadline check below. Cancellation is a genuine "stop
        // looking" instruction (the caller's future was dropped; the tree's drain state is no
        // longer anyone's to observe), so it is honored even before we have ever enumerated the
        // job once. A deadline, in contrast, is a stale BOUND on how long to keep looking, not
        // an instruction to skip looking — see below.
        if let Some(c) = cancel {
            // SAFETY: `cancel` is a valid handle for the duration of this call (caller-owned).
            let cancel_state = unsafe { WaitForSingleObject(c, 0) };
            if cancel_state == WAIT_OBJECT_0 {
                return Ok(TreeDrain::MembersRemain);
            }
        }

        // Re-enumerate BEFORE consulting the deadline for a return. A `Duration::ZERO` (or
        // already-elapsed) deadline must still observe the tree's ACTUAL current state on the
        // one round it gets, not conclude `MembersRemain` purely because it arrived too late to
        // look — a ZERO probe on an already-drained tree must report `AllMembersExited`, the
        // same verdict an unbounded wait would find. This mirrors `block_on_kqueue`'s
        // `already_elapsed` handling on the macOS side: the real observation always happens
        // first; an elapsed deadline only forecloses looping back for ANOTHER round afterward
        // (see the `handles.is_empty()` branch below, and the `ms` computation for the bounded
        // wait itself).
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

        // Computed once per round and reused below for both the empty-handles decision and the
        // bounded-wait timeout, so the two agree on what "the deadline" means for this round.
        let remaining = crate::wait::remaining(deadline);

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
            // to open it — real progress, but this round's `pids` was non-empty (so
            // `AllMembersExited` isn't supported by what was actually observed) and looping
            // straight back to `query_job_pid_list` is itself another round, which a bounded
            // wait must not be allowed to take once its deadline has already elapsed (the
            // busy-spin/cancellation-starvation hazard this whole restructuring exists to
            // close). An elapsed deadline concludes `MembersRemain` here instead of continuing.
            if remaining == Some(std::time::Duration::ZERO) {
                return Ok(TreeDrain::MembersRemain);
            }
            continue;
        }
        if let Some(e) = &denied {
            // Some sibling in this round was still openable, so the round proceeds — but an
            // actionable `OpenProcess` failure on a live member (as opposed to the benign
            // exit-race above) is otherwise invisible for every round in which that holds,
            // which can be every round for the tree's whole lifetime. Every other known
            // failure in this function gets a visible disposition; this one should too, even
            // though it isn't (yet) fatal to this round's wait.
            log::debug!(
                "wait_tree: could not open one live job member to watch for its exit, but \
                 other members are still trackable this round: {e}"
            );
        }

        // The cancel handle (if any) is appended AFTER the real member handles, never
        // closed here (caller-owned) — only `handles` (the freshly opened member handles)
        // are closed below.
        let mut wait_set = handles.clone();
        if let Some(c) = cancel {
            wait_set.push(c);
        }

        // A ZERO (or already-elapsed) deadline yields `ms == 0` here, which
        // `WaitForMultipleObjects` treats as a genuine non-blocking poll of the handles just
        // opened above — the ZERO-probe semantics fall out of the real API rather than a
        // pre-emptive return, so this round's `handles` (real, live members) still get one
        // real look before `WAIT_TIMEOUT` reports `MembersRemain` below.
        let ms: u32 = match remaining {
            None => INFINITE,
            Some(d) => d.as_millis().min((INFINITE - 1) as u128) as u32,
        };

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
        if idx >= wait_set.len() {
            // Same anomaly the debug_assert above catches in debug builds — surfaced here too
            // so a release build does not silently fall through to "treat as a member exit and
            // re-enumerate" without any trace of the OS having returned an unexpected verdict.
            log::warn!(
                "wait_tree: unexpected WaitForMultipleObjects verdict {waited:?} (index {idx} \
                 outside the {} handles waited on) - re-enumerating regardless",
                wait_set.len()
            );
        }
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

    // That must hold even when SOME threads resumed successfully before another one failed, not
    // only when every one did: a thread left suspended is exactly the "frozen process" this
    // function exists to rule out, regardless of how many of its siblings got moving first.
    if let Some(e) = last_err {
        log::warn!(
            "resume_initial_threads: failed to resume one or more of this child's initial threads \
             ({resumed} resumed successfully before the failure): {e}"
        );
        return Err(e);
    }
    if resumed == 0 {
        return Err(io::Error::other("no suspended threads resumed"));
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
