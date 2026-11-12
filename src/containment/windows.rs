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

use std::io;
use std::mem::size_of;
use std::ops::ControlFlow;
use std::os::windows::io::{AsRawHandle as _, BorrowedHandle};

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
    GetProcessId, GetProcessIdOfThread, OpenProcess, OpenThread, ResumeThread, WaitForMultipleObjects,
    CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
};

use crate::error::{io_context, win32_io_error};
use crate::identity::ProcessId;

/// Owns the Job Object handle. `KILL_ON_JOB_CLOSE` means the whole process tree
/// is terminated when this handle is closed (by `Drop`, unless [`disarm`](JobHandle::disarm)ed).
///
/// The handle stays open from construction until `Drop`, which needs `&mut self`: no `&self`
/// method can run while it closes, so none can see a recycled handle value.
pub(crate) struct JobHandle {
    raw: HANDLE,
}

// A Windows job-object HANDLE is a process-wide kernel handle; using it
// (TerminateJobObject / SetInformationJobObject / ...) from another thread is sound because the
// kernel serialises job operations. The raw pointer inside `HANDLE` is otherwise
// `!Send`, which would prevent this type from crossing thread boundaries.
unsafe impl Send for JobHandle {}

// SAFETY: `raw` is never written after construction, and the job operations are serialised by
// the kernel.
unsafe impl Sync for JobHandle {}

impl std::fmt::Debug for JobHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobHandle").field("raw", &self.raw.0).finish()
    }
}

impl JobHandle {
    fn new(handle: HANDLE) -> Self {
        debug_assert!(!handle.0.is_null(), "job handle must not be null");
        JobHandle { raw: handle }
    }

    /// The job handle, open for as long as `self` is borrowed.
    pub(crate) fn handle(&self) -> BorrowedHandle<'_> {
        // SAFETY: `self.raw` is open until `Drop`, which needs `&mut self`.
        unsafe { BorrowedHandle::borrow_raw(self.raw.0) }
    }

    /// Terminate every process in the job. The handle stays open, so the job can still be
    /// waited on ([`wait_drained`](JobHandle::wait_drained)) and disarmed; it closes in `Drop`.
    ///
    /// Returns the `TerminateJobObject` failure rather than only logging it: a caller that is
    /// told teardown succeeded while the tree is still running has no way to notice, and the
    /// other containment mechanisms already report this.
    pub(crate) fn hard_kill(&self) -> io::Result<()> {
        #[cfg(test)]
        fault::run_before_job_kill();
        // SAFETY: `self.raw` is a valid handle we own for as long as `self` lives.
        unsafe { TerminateJobObject(self.raw, 1) }.map_err(win32_io_error)
    }

    /// Clear `KILL_ON_JOB_CLOSE` so closing this handle does NOT kill the tree.
    /// Called by `Child::detach()` before the handle is released: otherwise
    /// dropping the job handle terminates the tree the caller intended to keep alive.
    ///
    /// Returns the `SetInformationJobObject` failure, with the plain Win32 code: the flag is then
    /// still set, and closing this handle still kills the tree.
    pub(crate) fn disarm(&self) -> io::Result<()> {
        // A zeroed JOBOBJECT_EXTENDED_LIMIT_INFORMATION has LimitFlags == 0, which
        // clears KILL_ON_JOB_CLOSE.
        let info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // SAFETY: `self.raw` is a valid handle; info is fully initialised (zeroed by default()).
        unsafe {
            SetInformationJobObject(
                self.raw,
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of!(info).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        }
        .map_err(win32_io_error)
    }
}

#[cfg(all(windows, test))]
impl JobHandle {
    /// Test-only: a real but empty job object (no process assigned). Cheap to create and
    /// cleanly closed on `Drop`; for variant-level assertions like
    /// `Tree::contained(Mechanism::Job(_))`.
    pub(crate) fn create_empty_for_test() -> JobHandle {
        // Safety: CreateJobObjectW with null name/attrs returns an owned job handle.
        let handle = unsafe { CreateJobObjectW(None, windows::core::PCWSTR::null()) }
            .expect("CreateJobObjectW for test placeholder");
        JobHandle::new(handle)
    }

    /// Test-only: an empty job reached through a handle without `JOB_OBJECT_SET_ATTRIBUTES`, so the
    /// OS refuses `SetInformationJobObject` on it with `ERROR_ACCESS_DENIED`: a real refusal of
    /// `disarm`, which a handle the crate made itself never gives.
    pub(crate) fn create_without_set_access_for_test() -> JobHandle {
        use windows::Win32::System::SystemServices::{JOB_OBJECT_QUERY, JOB_OBJECT_TERMINATE};

        JobHandle::create_empty_for_test().duplicate_with_access_for_test(JOB_OBJECT_QUERY | JOB_OBJECT_TERMINATE)
    }

    /// Test-only: another handle to this job with only `access`: without `JOB_OBJECT_TERMINATE` the
    /// OS refuses `TerminateJobObject` on it with `ERROR_ACCESS_DENIED` while the job and its members
    /// live on, and without `JOB_OBJECT_QUERY` it cannot list them.
    pub(crate) fn duplicate_with_access_for_test(&self, access: u32) -> JobHandle {
        use windows::Win32::Foundation::{DuplicateHandle, DUPLICATE_HANDLE_OPTIONS};
        use windows::Win32::System::Threading::GetCurrentProcess;

        let mut weak = HANDLE::default();
        // SAFETY: `self`'s handle is live; `weak` is an out-parameter.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                self.raw,
                GetCurrentProcess(),
                &mut weak,
                access,
                false,
                DUPLICATE_HANDLE_OPTIONS(0),
            )
        }
        .expect("DuplicateHandle with reduced access");
        JobHandle::new(weak)
    }
}

impl Drop for JobHandle {
    fn drop(&mut self) {
        // If `disarm` did not clear the flag, KILL_ON_JOB_CLOSE fires here when we close the
        // handle, tearing down the tree — the drop backstop for `kill_on_drop=true` semantics.
        // `hard_kill` terminates every member, including a child created during it, so this close
        // only reaps what an explicit post-kill assignment added. Whether a killed job accepts one
        // varies by Windows build (accepted on 10.0.26100, ACCESS_DENIED on the CI's Windows arm64
        // runner); cosca makes none.
        // SAFETY: `self.raw` is a valid handle we own, closed only here.
        unsafe {
            if let Err(e) = CloseHandle(self.raw) {
                // The close IS the teardown here: with KILL_ON_JOB_CLOSE still set, a
                // failed close means the tree was never reaped and the handle leaked.
                // Drop cannot report that, so it must at least be visible.
                log::warn!(
                    "closing the job handle failed ({report}); the tree may still be running",
                    report = crate::error::Report(&e)
                );
            }
        }
    }
}

impl JobHandle {
    /// The processes the job lists now, for the wait over a kill that follows: each is opened and
    /// proved a member through its own handle ([`member_to_watch`]), and its identity is read from
    /// that handle, which is then closed, so no handle is held per member. It is read before
    /// `TerminateJobObject`: the job's list is empty on its first read after the kill, whether or not
    /// the members have exited, so a list read after the kill would miss them. A member that exited
    /// naturally can still show its deleted pid for one listing, so [`wait_drained_raw`] lists again
    /// and a drain is only an empty listing. `root`, the root's pid, is left out: its owner waits for
    /// it. A member that cannot be named, or the listing itself failing, is returned as an error
    /// saying its exit cannot be observed; the kill goes ahead regardless.
    pub(crate) fn list_members(&self, root: Option<u32>) -> (Vec<ProcessId>, Vec<crate::error::Error>) {
        use crate::containment::tree_kill::exit_unobserved;
        use crate::error::Error;

        let pids = match query_job_pid_list(self.raw) {
            Ok(pids) => pids,
            Err(e) => {
                let why = Error::Unassessable {
                    detail: "the members of the job could not be listed before the kill, so their exit cannot be \
                             observed"
                        .to_owned(),
                    source: Some(Error::io_cause(e)),
                };
                return (Vec::new(), vec![why]);
            }
        };
        let (mut members, mut unobserved) = (Vec::new(), Vec::new());
        for pid in pids.into_iter().filter(|pid| Some(*pid) != root) {
            // SAFETY: a standard Win32 call; `member_to_watch` closes the handle unless it returns it.
            let opened = unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };
            match member_to_watch(opened, self.raw) {
                Ok(Some(handle)) => {
                    let id = crate::identity::windows_identity_from_handle_result(handle, pid);
                    // SAFETY: opened above, and kept nowhere else.
                    _ = unsafe { CloseHandle(handle) };
                    match id {
                        Ok(id) => members.push(id),
                        Err(e) => unobserved.push(exit_unobserved(
                            pid,
                            Error::Unassessable {
                                detail: "its start time could not be read".to_owned(),
                                source: Some(Error::io_cause(win32_io_error(e))),
                            },
                        )),
                    }
                }
                Ok(None) => {}
                Err(e) => unobserved.push(exit_unobserved(pid, Error::Io(e))),
            }
        }
        (members, unobserved)
    }
}

impl crate::containment::Contains for JobHandle {
    /// `Ok` says the job was told to terminate every member, however it was spawned (see
    /// [`hard_kill`](JobHandle::hard_kill)). See [`list_members`](JobHandle::list_members) for what
    /// is named and why.
    fn kill(&self, root: Option<&dyn crate::containment::Root>) -> crate::containment::TreeKill<'_> {
        let (members, unobserved) = self.list_members(root.map(crate::containment::Root::pid));
        let sent = crate::containment::Contains::send_kill(self, root);
        crate::containment::TreeKill::listed(
            sent,
            members,
            unobserved,
            crate::containment::drain_edge::DrainEdge::Job(self),
        )
    }

    /// The bare `TerminateJobObject`: no member is listed, for a caller that waits for none.
    fn send_kill(&self, _root: Option<&dyn crate::containment::Root>) -> crate::containment::dispatch::TreeKillOutcome {
        use crate::containment::dispatch::{TreeKillOutcome, Unkilled};
        TreeKillOutcome::Ran(
            self.hard_kill()
                .map_err(|e| crate::error::Error::Containment {
                    detail: "TerminateJobObject could not terminate the job".to_owned(),
                    source: Some(crate::error::Error::io_cause(e)),
                })
                .map_err(Unkilled::from),
        )
    }

    /// `CTRL_BREAK` to the root's console group `pid`: a nested contained descendant leads its own
    /// group and never receives it.
    fn send_terminate(
        &self,
        pid: u32,
        _root: Option<&dyn crate::containment::Root>,
    ) -> crate::containment::TerminateOutcome {
        // One event, so an error is an event that was not sent (`NoConsole` or the OS's refusal).
        crate::containment::TerminateOutcome::of(terminate(pid).map(Ok), Some("the SIGTERM"))
    }

    fn drain_edge(&self) -> Option<crate::containment::drain_edge::DrainEdge<'_>> {
        Some(crate::containment::drain_edge::DrainEdge::Job(self))
    }

    fn kind(&self) -> crate::containment::Containment {
        crate::containment::Containment::JobObject
    }

    /// Clears `KILL_ON_JOB_CLOSE` (see [`disarm`](JobHandle::disarm)).
    fn disarm(&self) -> io::Result<()> {
        JobHandle::disarm(self)
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
    for std_handle in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: standard Win32 call; handle is not closed.
        unsafe {
            if let Ok(h) = GetStdHandle(std_handle) {
                if !h.is_invalid() {
                    // Clear the INHERIT flag; dwflags=0 means "clear all bits in mask".
                    _ = SetHandleInformation(h, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0));
                }
            }
        }
    }
    #[cfg(test)]
    observe::record_inheritance_cleared();
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
/// `err` carries the bare Win32 code (see [`win32_io_error`]).
///
/// `Error::NoConsole` is returned ONLY when the failure code matches AND the probe confirms
/// there is no console. A contradicted probe, a failed probe, or any other failure code keeps
/// the raw `Error::Io`: the typed variant must never assert a cause the process just measured
/// to be false.
pub(crate) fn classify_ctrl_event_failure(pid: u32, err: io::Error, console: io::Result<bool>) -> crate::error::Error {
    use windows::Win32::Foundation::ERROR_INVALID_HANDLE;
    let no_console = ERROR_INVALID_HANDLE.0 as i32;
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
            log::warn!(
                "CTRL_BREAK to group {pid}: the console probe failed ({report}); cannot classify",
                report = crate::error::Report(probe)
            );
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
        log::warn!(
            "CTRL_BREAK to group {pid} failed, and the console probe also failed ({report})",
            report = crate::error::Report(probe)
        );
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
    terminate_with(
        pid,
        // SAFETY: standard Win32 call targeting the child's own console group.
        || unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) },
        caller_has_console,
    )
}

/// [`terminate`] with the OS call `send` and the console probe injected, so a test can make the
/// call fail with the code the OS reports without detaching the test process from its console.
fn terminate_with(
    pid: u32,
    send: impl FnOnce() -> windows::core::Result<()>,
    console: impl FnOnce() -> io::Result<bool>,
) -> Result<(), crate::error::Error> {
    match send() {
        Ok(()) => {
            #[cfg(test)]
            observe::record_ctrl_break(pid);
            Ok(())
        }
        Err(e) => Err(classify_ctrl_event_failure(pid, win32_io_error(e), console())),
    }
}

/// Test-only records of what THIS thread did, with take semantics, mirroring `fault`.
///
/// - `clear_std_handle_inheritance` ran, so a test can prove a refused spawn did not mutate this
///   process first. The real handle flags cannot serve as the observation: the mutation is
///   process-global and permanent, so any earlier contained spawn in the same test binary would
///   already have made it meaningless.
/// - A `CTRL_BREAK` went out: the group `terminate` addressed, once Windows accepted the event.
///   The event lands asynchronously, so a test asserts this before it waits for the target's own
///   evidence, and a call that sent nothing fails that assertion instead of leaving the wait
///   unbounded.
#[cfg(test)]
pub(crate) mod observe {
    use std::cell::{Cell, RefCell};
    thread_local! {
        static INHERITANCE_CLEARED: Cell<bool> = const { Cell::new(false) };
        static CTRL_BREAKS: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
    }
    pub(crate) fn record_inheritance_cleared() {
        INHERITANCE_CLEARED.with(|f| f.set(true));
    }
    pub(crate) fn take_inheritance_cleared() -> bool {
        INHERITANCE_CLEARED.with(|f| f.replace(false))
    }
    pub(crate) fn record_ctrl_break(group: u32) {
        CTRL_BREAKS.with(|b| b.borrow_mut().push(group));
    }
    /// The groups sent a `CTRL_BREAK` on this thread since the last take, in order.
    pub(crate) fn take_ctrl_breaks() -> Vec<u32> {
        CTRL_BREAKS.with(|b| std::mem::take(&mut *b.borrow_mut()))
    }
}

/// Test-only: force the NEXT `caller_has_console` on THIS thread to report a probe failure,
/// so that arm's production is covered — a live `GetConsoleProcessList` cannot be made to
/// fail. Take semantics, mirroring `treewalk::fault`.
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::{Cell, RefCell};
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

    thread_local! {
        static BEFORE_JOB_KILL: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
    }
    /// Run `hook` once, right before the next `TerminateJobObject` on this thread; the guard clears
    /// it.
    pub(crate) fn set_before_job_kill(hook: impl FnOnce() + 'static) -> crate::oneshot_hook::Armed {
        crate::oneshot_hook::arm(&BEFORE_JOB_KILL, hook)
    }
    pub(crate) fn run_before_job_kill() {
        crate::oneshot_hook::fire(&BEFORE_JOB_KILL);
    }
    pub(crate) fn armed() -> bool {
        FORCE_CONSOLE_PROBE_ERROR.with(|f| f.get())
    }

    /// The Win32 call `resume_if_owned` makes at each step, for [`force_next`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Step {
        QueryOpen,
        Owner,
        ResumeOpen,
        Resume,
        /// The read of a thread's creation time, in the search for a frozen child's initial thread.
        CreationTime,
        /// The assignment of a Strongest root's job.
        Assign,
    }

    /// The forced pid lists of this thread.
    enum ForcedPidLists {
        Unarmed,
        /// Answered to the next queries, in order; the real list after them, until the guard drops.
        Armed(std::collections::VecDeque<Vec<u32>>),
    }
    thread_local! {
        static JOB_PID_LIST: RefCell<ForcedPidLists> = const { RefCell::new(ForcedPidLists::Unarmed) };
        static JOB_PID_LIST_QUERIES: Cell<u32> = const { Cell::new(0) };
    }
    /// [`force_job_pid_lists`] for one list.
    pub(crate) fn force_job_pid_list(pids: Vec<u32>) -> ForcedList {
        force_job_pid_lists([pids])
    }
    /// Answer `lists`, one per `query_job_pid_list` on this thread in order; counts the queries made
    /// ([`job_pid_list_queries`]) until dropped.
    pub(crate) fn force_job_pid_lists(lists: impl IntoIterator<Item = Vec<u32>>) -> ForcedList {
        JOB_PID_LIST.with(|f| {
            let mut f = f.borrow_mut();
            debug_assert!(
                matches!(*f, ForcedPidLists::Unarmed),
                "a pid list is forced and its guard is alive"
            );
            *f = ForcedPidLists::Armed(lists.into_iter().collect());
        });
        JOB_PID_LIST_QUERIES.with(|c| c.set(0));
        ForcedList(())
    }
    /// Consume the next forced pid list, if one is armed; counts every call.
    pub(crate) fn take_forced_job_pid_list() -> Option<Vec<u32>> {
        JOB_PID_LIST_QUERIES.with(|c| c.set(c.get() + 1));
        JOB_PID_LIST.with(|f| {
            let mut f = f.borrow_mut();
            let ForcedPidLists::Armed(lists) = &mut *f else {
                return None;
            };
            lists.pop_front()
        })
    }
    /// How many `query_job_pid_list` calls this thread made since [`force_job_pid_list`] or
    /// [`force_job_pid_lists`] last armed it, or since its guard dropped.
    pub(crate) fn job_pid_list_queries() -> u32 {
        JOB_PID_LIST_QUERIES.with(|c| c.get())
    }
    #[must_use = "dropping this immediately disarms the forced pid list"]
    pub(crate) struct ForcedList(());
    impl Drop for ForcedList {
        fn drop(&mut self) {
            JOB_PID_LIST.with(|f| *f.borrow_mut() = ForcedPidLists::Unarmed);
            JOB_PID_LIST_QUERIES.with(|c| c.set(0));
        }
    }

    thread_local! {
        static INJECTED: Cell<Option<(u32, Option<u32>)>> = const { Cell::new(None) };
        static INJECTED_VISIT: Cell<Option<Option<super::Visit>>> = const { Cell::new(None) };
        static FORCED: Cell<Option<(Step, u32, Option<u32>)>> = const { Cell::new(None) };
        static EQUAL_CREATION_TIMES: Cell<bool> = const { Cell::new(false) };
    }
    /// Make `resume_initial_threads` on THIS thread walk one extra snapshot entry for thread
    /// `tid`, owned by `owner` (`None`: the CHILD's pid, which is what a stale id looks like).
    /// Reset on drop, which also clears the recorded visit and any forced failure.
    pub(crate) fn inject_snapshot_tid(tid: u32, owner: Option<u32>) -> Injected {
        INJECTED.with(|f| {
            debug_assert!(f.get().is_none(), "a snapshot tid is already injected");
            f.set(Some((tid, owner)));
        });
        INJECTED_VISIT.with(|f| f.set(None));
        Injected(())
    }
    /// The injected entry's `(tid, owner)`.
    pub(crate) fn injected_entry() -> Option<(u32, Option<u32>)> {
        INJECTED.with(|f| f.get())
    }
    /// Record what the walk did with the injected entry (`None`: the owner filter dropped it).
    pub(crate) fn record_injected_visit(visit: Option<super::Visit>) {
        INJECTED_VISIT.with(|f| f.set(Some(visit)));
    }
    /// What the walk did with the injected entry. The outer `None` means it was never walked.
    pub(crate) fn take_injected_visit() -> Option<Option<super::Visit>> {
        INJECTED_VISIT.with(|f| f.take())
    }
    /// Make the NEXT `step` call on THIS thread fail with Win32 error `code`. Reset on drop of the
    /// guard. Neither an owner of 0 nor a failed `ResumeThread` can be produced on a live system.
    pub(crate) fn force_next(step: Step, code: u32) -> Forced {
        arm(step, code, None)
    }
    /// [`force_next`], but only for the call that handles thread `tid`; a call for another thread
    /// does not consume it.
    pub(crate) fn force_next_for_thread(step: Step, code: u32, tid: u32) -> Forced {
        arm(step, code, Some(tid))
    }
    fn arm(step: Step, code: u32, tid: Option<u32>) -> Forced {
        FORCED.with(|f| {
            debug_assert!(f.get().is_none(), "a failure is already forced");
            f.set(Some((step, code, tid)));
        });
        Forced(())
    }
    /// Whether a forced failure is still armed: the call it was armed for never happened.
    pub(crate) fn forced_is_armed() -> bool {
        FORCED.with(|f| f.get().is_some())
    }
    /// Consume a forced failure for `step` (on thread `tid`, where the call has one), if one is
    /// armed for it.
    pub(crate) fn take_forced(step: Step, tid: Option<u32>) -> Option<u32> {
        FORCED.with(|f| match f.get() {
            Some((armed, code, only)) if armed == step && (only.is_none() || only == tid) => {
                f.set(None);
                Some(code)
            }
            _ => None,
        })
    }
    /// Make every creation time read on THIS thread answer the same value, as a coarse clock would,
    /// until the guard drops. No live system can be made to tie.
    pub(crate) fn equal_creation_times() -> EqualTimes {
        EQUAL_CREATION_TIMES.with(|f| f.set(true));
        EqualTimes(())
    }
    pub(crate) fn creation_times_are_equal() -> bool {
        EQUAL_CREATION_TIMES.with(|f| f.get())
    }
    #[must_use = "dropping this immediately restores the real clock"]
    pub(crate) struct EqualTimes(());
    impl Drop for EqualTimes {
        fn drop(&mut self) {
            EQUAL_CREATION_TIMES.with(|f| f.set(false));
        }
    }
    #[must_use = "dropping this immediately removes the injected entry"]
    pub(crate) struct Injected(());
    impl Drop for Injected {
        fn drop(&mut self) {
            INJECTED.with(|f| f.set(None));
            INJECTED_VISIT.with(|f| f.set(None));
        }
    }
    #[must_use = "dropping this immediately disarms the forced failure"]
    pub(crate) struct Forced(());
    impl Drop for Forced {
        fn drop(&mut self) {
            FORCED.with(|f| f.set(None));
        }
    }
}

/// Create a `KILL_ON_JOB_CLOSE` job and assign the process at `proc_handle` to it.
///
/// `pub(crate)`: also the sole constructor behind the public [`crate::containment::job::Job`]
/// primitive — reused verbatim rather than duplicated, so `Command::contain()` and `Job::assign`
/// share exactly one implementation.
pub(crate) fn assign_to_kill_on_close_job(proc_handle: std::os::windows::io::RawHandle) -> io::Result<JobHandle> {
    // A Windows `RawHandle` is a `*mut c_void`.
    let raw_handle = HANDLE(proc_handle.cast());
    // SAFETY: a standard Win32 call; its handle is closed on every error path below.
    let job = owned_job(unsafe { CreateJobObjectW(None, windows::core::PCWSTR::null()) })?;
    set_kill_on_close_or_close(job)?;
    assign_or_close(job, raw_handle)?;
    Ok(JobHandle::new(job))
}

/// The job `CreateJobObjectW` made, or its failure with the plain Win32 code.
fn owned_job(created: windows::core::Result<HANDLE>) -> io::Result<HANDLE> {
    created.map_err(win32_io_error)
}

/// Set `KILL_ON_JOB_CLOSE` on `job`. On failure `job` is closed and the error has the plain Win32
/// code.
fn set_kill_on_close_or_close(job: HANDLE) -> io::Result<()> {
    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: `info` is a live local of exactly the size passed.
    let set = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            std::ptr::addr_of!(info).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if let Err(e) = set {
        // SAFETY: the caller hands `job` over; nothing else closes it.
        _ = unsafe { CloseHandle(job) };
        return Err(win32_io_error(e));
    }
    Ok(())
}

/// Assign `process` to `job`. On failure `job` is closed and the error has the plain Win32 code.
fn assign_or_close(job: HANDLE, process: HANDLE) -> io::Result<()> {
    // SAFETY: a standard Win32 call on handles the caller keeps open across it.
    if let Err(e) = unsafe { AssignProcessToJobObject(job, process) } {
        // SAFETY: the caller hands `job` over; nothing else closes it.
        _ = unsafe { CloseHandle(job) };
        return Err(win32_io_error(e));
    }
    Ok(())
}

/// [`assign_to_kill_on_close_job`] as `attach` takes it: the job is assigned and the child is NOT
/// resumed.
pub(crate) fn assign_held(proc_handle: std::os::windows::io::RawHandle) -> io::Result<JobHandle> {
    #[cfg(test)]
    forced(fault::Step::Assign, None).map_err(win32_io_error)?;
    assign_to_kill_on_close_job(proc_handle)
}

/// Read the job's LIVE member pids via `QueryInformationJobObject(JobObjectBasicProcessIdList)`
/// — the authoritative, always-fresh source `wait_drained` re-consults every round, independent
/// of any completion-port message. Grows the buffer and retries (no bound on retries: a job
/// that keeps growing needs an ever-larger buffer, but capping this would silently under-report
/// live membership rather than fail loudly).
pub(crate) fn query_job_pid_list(job: HANDLE) -> io::Result<Vec<u32>> {
    #[cfg(test)]
    if let Some(forced) = fault::take_forced_job_pid_list() {
        return Ok(forced);
    }
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
    /// eventually signal, forcing a fresh re-enumeration next round. Never reports
    /// `AllMembersExited` falsely (only a live re-count of zero does); with more than
    /// `MAXIMUM_WAIT_OBJECTS - 1` live members it may notice the drain late. The handle stays
    /// open after [`hard_kill`](JobHandle::hard_kill), so this also waits out a killed tree.
    ///
    /// `deadline`: `None` is no deadline (see [`crate::wait::remaining`]). No interval is chosen
    /// anywhere in this path: every round blocks in one `WaitForMultipleObjects` call for exactly
    /// the caller's own remaining time. What a deadline answers is stated at [`wait_drained_raw`].
    ///
    /// The async drain runs the same rounds ([`drain_round`](JobHandle::drain_round)) and awaits each
    /// round's handles where this blocks on them.
    pub(crate) fn wait_drained(
        &self,
        deadline: Option<std::time::Instant>,
    ) -> Result<crate::containment::TreeDrain, crate::error::Error> {
        wait_drained_raw(self.handle(), deadline)
    }

    /// One round of the drain wait: list the live members, open each (up to the wait-set cap) with
    /// `SYNCHRONIZE`, and say what the round decided. `last_round` is whether the caller's deadline
    /// has already passed, on the caller's clock. What a round answers is stated at
    /// [`wait_drained_raw`].
    #[cfg(feature = "tokio")]
    pub(crate) fn drain_round(&self, last_round: bool) -> Result<Round, crate::error::Error> {
        drain_round(HANDLE(self.handle().as_raw_handle()), last_round)
    }

    /// What follows a round's wait that ended on a member's handle: the answer if the round was the
    /// last, `None` if the next round follows.
    #[cfg(feature = "tokio")]
    pub(crate) fn after_signalled(
        &self,
        watch: &Watch,
    ) -> Result<Option<crate::containment::TreeDrain>, crate::error::Error> {
        after_signalled(HANDLE(self.handle().as_raw_handle()), watch)
    }
}

/// Whether the process `OpenProcess` returned as `opened` is a member of `job`: its handle to wait
/// on if so, `None` if it is not one, and the failure (with the plain Win32 code) if membership
/// could not be established. The handle is closed unless it is returned.
fn member_to_watch(opened: windows::core::Result<HANDLE>, job: HANDLE) -> io::Result<Option<HANDLE>> {
    match opened {
        // A pid enumerated a moment ago can have exited and had its number reused by the time it
        // is opened, so membership is re-confirmed against the job rather than assumed. Waiting
        // on a bystander would either hang the drain (it outlives the tree) or, if it exits
        // first, report the tree drained while members run.
        Ok(h) => {
            use windows::Win32::System::JobObjects::IsProcessInJob;
            let mut in_job = windows::core::BOOL(0);
            // SAFETY: both handles are valid for the duration of the call.
            let confirmed = unsafe { IsProcessInJob(h, Some(job), &mut in_job) };
            match confirmed {
                // A member: wait on it.
                Ok(()) if in_job.as_bool() => Ok(Some(h)),
                // Openable but not in this job: the pid was recycled between the enumeration and
                // the open. Filtering it out is the point.
                Ok(()) => {
                    // SAFETY: opened by the caller and not stored anywhere.
                    _ = unsafe { CloseHandle(h) };
                    Ok(None)
                }
                // The query itself failed, so membership is unknown. Recorded like any other
                // actionable failure rather than silently dropped: if it holds for every member
                // it would otherwise be invisible.
                Err(e) => {
                    // SAFETY: opened by the caller and not stored anywhere.
                    _ = unsafe { CloseHandle(h) };
                    Err(win32_io_error(e))
                }
            }
        }
        // ERROR_INVALID_PARAMETER: the pid no longer names a process: it exited in the race
        // between the enumeration and the open. Not a failure, and not a member either.
        Err(e) if e.code() == windows::Win32::Foundation::ERROR_INVALID_PARAMETER.to_hresult() => Ok(None),
        Err(e) => Err(win32_io_error(e)),
    }
}

/// The Toolhelp thread snapshot `CreateToolhelp32Snapshot` made, or its failure with the plain
/// Win32 code.
fn thread_snapshot(created: windows::core::Result<HANDLE>) -> io::Result<HANDLE> {
    created.map_err(win32_io_error)
}

/// Every entry of the thread snapshot `snap`, which is closed on every path. A failure of the
/// snapshot API has the plain Win32 code; the end of the walk is not one.
fn thread_entries_closing(
    snap: HANDLE,
) -> io::Result<Vec<windows::Win32::System::Diagnostics::ToolHelp::THREADENTRY32>> {
    use windows::Win32::Foundation::ERROR_NO_MORE_FILES;
    use windows::Win32::System::Diagnostics::ToolHelp::{Thread32First, Thread32Next, THREADENTRY32};

    // Thread32First/Next signal end-of-enumeration with ERROR_NO_MORE_FILES.
    let end_of_walk = windows::core::HRESULT::from_win32(ERROR_NO_MORE_FILES.0);
    let mut entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    let mut entries = Vec::new();
    // SAFETY: `snap` is a handle the caller hands over; `entry` has its `dwSize` set.
    let mut step = unsafe { Thread32First(snap, &mut entry) };
    let walked = loop {
        match step {
            Ok(()) => {}
            Err(e) if e.code() == end_of_walk => break Ok(entries),
            // A snapshot-API fault, not normal end-of-iteration.
            Err(e) => break Err(win32_io_error(e)),
        }
        entries.push(entry);
        // SAFETY: as for `Thread32First`.
        step = unsafe { Thread32Next(snap, &mut entry) };
    };
    // SAFETY: handed over by the caller; closed once, here.
    _ = unsafe { CloseHandle(snap) };
    walked
}

/// The blocking driver of the drain wait's rounds ([`drain_round`]), taking a borrowed handle rather
/// than `&JobHandle`.
///
/// A bounded wait answers from the job's list as of its last look, so `MembersRemain` means the tree
/// was not seen drained by the deadline. A round that starts past the deadline (an already-elapsed or
/// `Duration::ZERO` one, or one reached after a wait ended on a member's exit) is the last. It lists:
/// an empty listing is `AllMembersExited` however late the caller arrived. Live members that a
/// zero-ms poll finds none signalled are `MembersRemain`. Otherwise the listing may be stale (a
/// deleted pid shows for one listing after a member's exit, or a polled handle was signalled), and
/// exactly one more listing is final: empty is `AllMembersExited`, anything else `MembersRemain`.
pub(crate) fn wait_drained_raw(
    job: BorrowedHandle<'_>,
    deadline: Option<std::time::Instant>,
) -> Result<crate::containment::TreeDrain, crate::error::Error> {
    use crate::containment::TreeDrain;

    let job = HANDLE(job.as_raw_handle());
    loop {
        // A round that starts past the deadline is the last: it lists and answers, with at most one
        // more listing (`final_listing`).
        let last_round = deadline.is_some_and(|at| crate::wait::now() >= at);
        let watch = match drain_round(job, last_round)? {
            Round::Answer(drain) => return Ok(drain),
            Round::List => continue,
            Round::Watch(watch) => watch,
        };
        match watch.wait(deadline)? {
            // `wait_until` returns a timeout only once the real deadline has passed.
            Ended::Deadline => return Ok(TreeDrain::MembersRemain),
            Ended::Signalled => {
                if let Some(drain) = after_signalled(job, &watch)? {
                    return Ok(drain);
                }
            }
        }
        // A tracked member exited: the next round re-enumerates the authoritative live set.
    }
}

/// What a round of the drain wait decided.
pub(crate) enum Round {
    /// The wait is over, with this answer.
    Answer(crate::containment::TreeDrain),
    /// No listed pid is a live member, which says nothing of one that joined after the listing: list
    /// again.
    List,
    /// Wait for one of these handles, then run the next round.
    Watch(Watch),
}

/// The handles one round waits on: each is open on a listed member, and closed with this.
pub(crate) struct Watch {
    handles: Vec<std::os::windows::io::OwnedHandle>,
    /// The same handles as the array `WaitForMultipleObjects` takes, built once with the round.
    set: HandleSet,
    /// The round started past the deadline: its wait is a poll and its answer final.
    last_round: bool,
}

/// The raw handles of a [`Watch`], which `HANDLE`'s raw pointer would make `!Send` and `!Sync`.
struct HandleSet(Vec<HANDLE>);

// SAFETY: a handle names a kernel object and has no thread affinity. The set is only read, by
// `WaitForMultipleObjects`, while the `OwnedHandle`s it mirrors, owned by the same `Watch`, are open.
unsafe impl Send for HandleSet {}
// SAFETY: as for `Send`; nothing writes the set after it is built.
unsafe impl Sync for HandleSet {}

/// How a round's wait ended, when it did not fail.
pub(crate) enum Ended {
    /// The deadline passed with no handle signalled.
    Deadline,
    /// A member's handle was signalled.
    Signalled,
}

impl Watch {
    /// The handles to wait on: the round ends when any one is signalled.
    #[cfg(feature = "tokio")]
    pub(crate) fn handles(&self) -> impl Iterator<Item = BorrowedHandle<'_>> + Clone {
        use std::os::windows::io::AsHandle as _;
        self.handles.iter().map(|h| h.as_handle())
    }

    /// Block until a handle is signalled or the real `deadline` passes. A `WAIT_TIMEOUT` is never
    /// trusted: the real deadline is rechecked each round (see `win32_timeout_ms`).
    fn wait(&self, deadline: Option<std::time::Instant>) -> Result<Ended, crate::error::Error> {
        self.ended(crate::wait::wait_until(deadline, |ms| self.wait_for(ms)))
    }

    /// Look once, without waiting, for a last round: an elapsed deadline arms `ms == 0` in
    /// [`wait`](Watch::wait), a real poll of the handles.
    #[cfg(feature = "tokio")]
    pub(crate) fn poll(&self) -> Result<Ended, crate::error::Error> {
        self.ended(self.wait_for(0))
    }

    fn wait_for(&self, ms: u32) -> windows::Win32::Foundation::WAIT_EVENT {
        // SAFETY: every handle in `set` is open for the call, owned by `self`.
        unsafe { WaitForMultipleObjects(&self.set.0, false, ms) }
    }

    fn ended(&self, waited: windows::Win32::Foundation::WAIT_EVENT) -> Result<Ended, crate::error::Error> {
        let wait_failed = (waited == WAIT_FAILED).then(io::Error::last_os_error);
        if waited == WAIT_TIMEOUT {
            return Ok(Ended::Deadline);
        }
        if let Some(e) = wait_failed {
            return Err(crate::error::Error::Io(e));
        }
        let idx = waited.0.wrapping_sub(WAIT_OBJECT_0.0) as usize;
        debug_assert!(
            idx < self.handles.len(),
            "unexpected WaitForMultipleObjects verdict: {waited:?}"
        );
        if idx >= self.handles.len() {
            // Same anomaly the debug_assert above catches in debug builds — surfaced here too
            // so a release build does not silently fall through to "treat as a member exit and
            // re-enumerate" without any trace of the OS having returned an unexpected verdict.
            log::warn!(
                "wait_tree: unexpected WaitForMultipleObjects verdict {waited:?} (index {idx} \
                 outside the {} handles waited on) - re-enumerating regardless",
                self.handles.len()
            );
        }
        Ok(Ended::Signalled)
    }
}

/// What follows a round's wait that ended on a member's handle: the answer if it was the last round,
/// whose own listing may have named an exited member, and `None` if the next round follows.
fn after_signalled(job: HANDLE, watch: &Watch) -> Result<Option<crate::containment::TreeDrain>, crate::error::Error> {
    if watch.last_round {
        return final_listing(job).map(Some);
    }
    Ok(None)
}

/// One round of the drain wait, shared by the blocking driver ([`wait_drained_raw`]) and the async
/// one: list the live members, open them, and say what to do next. `last_round` is whether the
/// caller's deadline has passed, on the caller's clock.
fn drain_round(job: HANDLE, last_round: bool) -> Result<Round, crate::error::Error> {
    use crate::error::Error;

    let budget = MAXIMUM_WAIT_OBJECTS - 1;
    // List BEFORE consulting the deadline for a return, so an elapsed deadline (a `Duration::ZERO`
    // probe) still observes the tree's actual state and an empty listing answers
    // `AllMembersExited`, as an unbounded wait would. This mirrors `Kqueue::wait` on the macOS
    // side, which takes one look at an elapsed deadline.
    let pids = match list_members_or_drained(job)? {
        ControlFlow::Break(drained) => return Ok(Round::Answer(drained)),
        ControlFlow::Continue(pids) => pids,
    };

    let mut handles: Vec<std::os::windows::io::OwnedHandle> = Vec::new();
    let mut denied: Option<io::Error> = None;
    // Every listed pid is looked at unless the wait set is already full: a pid that is gone
    // does not use up the budget a live member needs.
    for pid in &pids {
        if handles.len() == budget {
            break;
        }
        // SAFETY: standard Win32 call; the handle is closed by `member_to_watch` unless it is
        // returned. `PROCESS_QUERY_LIMITED_INFORMATION` is what `IsProcessInJob` needs and
        // `PROCESS_SYNCHRONIZE` does not imply it; the least right that works, grantable across
        // integrity levels.
        let opened = unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, *pid) };
        match member_to_watch(opened, job) {
            // SAFETY: `member_to_watch` hands over the handle `OpenProcess` returned.
            Ok(Some(h)) => handles.push(unsafe { std::os::windows::io::FromRawHandle::from_raw_handle(h.0) }),
            Ok(None) => {}
            Err(e) => denied = Some(e),
        }
    }

    if handles.is_empty() {
        if let Some(e) = denied {
            // A persistent, actionable open failure (not a benign exit-race): looping
            // back here without ever holding a real handle to block on would busy-spin.
            log::warn!(
                "wait_tree: could not open any live job member to watch for its exit ({report})",
                report = crate::error::Report(&e)
            );
            return Err(Error::Unassessable {
                detail: "could not open a handle to any live member of the contained tree \
                                 to observe its exit"
                    .into(),
                source: Some(Error::io_cause(e)),
            });
        }
        // Every listed pid is gone (`OpenProcess` found no such process) or no longer a
        // member (its number was reused). That says nothing of a member that joined after the
        // listing, so a drain is only a fresh listing that is empty: list again. Past the
        // deadline this was the last round, so that listing is the final one.
        if last_round {
            return final_listing(job).map(Round::Answer);
        }
        return Ok(Round::List);
    }
    if let Some(e) = &denied {
        // A sibling was openable, so the round proceeds; log the actionable open failure, which
        // would otherwise stay invisible for the tree's lifetime.
        log::debug!(
            "wait_tree: could not open one live job member to watch for its exit, but \
                 other members are still trackable this round: {report}",
            report = crate::error::Report(e)
        );
    }

    let set = HandleSet(handles.iter().map(|h| HANDLE(h.as_raw_handle())).collect());
    Ok(Round::Watch(Watch {
        handles,
        set,
        last_round,
    }))
}

/// The one more listing a last round takes when its own is no proof: an empty listing is the drain,
/// anything else is `MembersRemain`. Nothing follows it.
fn final_listing(job: HANDLE) -> Result<crate::containment::TreeDrain, crate::error::Error> {
    use crate::containment::TreeDrain;

    Ok(match list_members_or_drained(job)? {
        ControlFlow::Break(drained) => drained,
        ControlFlow::Continue(_) => TreeDrain::MembersRemain,
    })
}

/// One listing of the job: an empty one is the drain (`Break`), any other is the listed pids.
fn list_members_or_drained(
    job: HANDLE,
) -> Result<ControlFlow<crate::containment::TreeDrain, Vec<u32>>, crate::error::Error> {
    let pids = query_job_pid_list(job).map_err(crate::error::Error::Io)?;
    Ok(if pids.is_empty() {
        ControlFlow::Break(crate::containment::TreeDrain::AllMembersExited)
    } else {
        ControlFlow::Continue(pids)
    })
}

/// What `resume_if_owned` did with one thread id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Visit {
    Resumed,
    /// The opened thread belongs to `owner`, not to the child: the id was reused.
    Foreign {
        owner: u32,
    },
    /// No thread has this id any more (`ERROR_INVALID_PARAMETER`).
    Gone,
    /// The query-only open was denied. The child's own threads are openable by its creator, so
    /// the id belongs to someone else.
    Denied,
    /// A call failed on a thread that is the child's; recorded in `last_err`.
    Failed,
}

/// What a resume asks of the suspend count it answers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum SuspendCount {
    /// Any count: the ordinary `contain()` spawn resumes whatever the snapshot lists and accepts a
    /// thread something else already ran.
    #[default]
    Any,
    /// A frozen child's release: resumes the child's INITIAL thread only, and only if its previous
    /// count was exactly 1. An initial thread that ran, or that something else suspended again,
    /// means the child is not as its creator left it. Every other thread (one an EDR agent or a
    /// debugger started) is opened query-only, to read its creation time, and never for
    /// suspend/resume: the creator suspended only the initial thread, so a resume of any other would
    /// take away a suspension that is someone else's. Other threads are never resumed and keep
    /// their count. The initial thread is the one created first, so the release fails, resuming
    /// nothing, if the creation time of any thread of the child cannot be read or the earliest two
    /// are equal. A thread that is gone, or that the creator cannot open, is skipped.
    ExactlyOne,
}

/// The state of one walk over the snapshot.
#[derive(Default)]
struct Walk {
    expected: SuspendCount,
    resumed: u32,
    /// The FIRST failure: it is the root cause, and later ones are logged as they happen.
    last_err: Option<io::Error>,
    /// Reason for the latest stale skip, for the none-resumed error.
    last_skip: Option<String>,
}

impl Walk {
    fn skip(&mut self, reason: String) {
        log::debug!("resume_initial_threads: {reason}; skipped");
        self.last_skip = Some(reason);
    }

    /// Record that the initial thread of `process_pid` cannot be told from the threads `first` and
    /// `second`.
    fn fail_unidentified(&mut self, process_pid: u32, first: u32, second: u32) {
        let msg = format!(
            "the initial thread of pid {process_pid} cannot be identified: threads {first} and {second} have the same creation time"
        );
        log::warn!("resume_initial_threads: {msg}");
        self.last_err.get_or_insert_with(|| io::Error::other(msg));
    }

    /// Record a failure that is cosca's own finding about a thread. No OS call failed, so the error
    /// has no OS code.
    fn fail(&mut self, call: &str, tid: u32, process_pid: u32, cause: impl std::fmt::Display) -> Visit {
        let msg = format!("{call} failed for thread {tid} of pid {process_pid}: {cause}");
        log::warn!("resume_initial_threads: {msg}");
        self.last_err.get_or_insert_with(|| io::Error::other(msg));
        Visit::Failed
    }

    /// Record the failure of the Win32 call `call`, keeping its code as the error's source.
    fn fail_win32(&mut self, call: &str, tid: u32, process_pid: u32, cause: windows::core::Error) -> Visit {
        let context = format!("{call} failed for thread {tid} of pid {process_pid}");
        let err = io_context(context, win32_io_error(cause));
        log::warn!("resume_initial_threads: {report}", report = crate::error::Report(&err));
        self.last_err.get_or_insert(err);
        Visit::Failed
    }
}

/// A thread handle, closed on drop.
struct ThreadHandle(HANDLE);

impl Drop for ThreadHandle {
    fn drop(&mut self) {
        // SAFETY: the handle is owned and closed exactly once.
        unsafe { _ = CloseHandle(self.0) };
    }
}

/// Fail with the Win32 error a test armed for `step`, if any.
#[cfg(test)]
fn forced(step: fault::Step, tid: Option<u32>) -> windows::core::Result<()> {
    match fault::take_forced(step, tid) {
        Some(code) => Err(windows::core::Error::from_hresult(windows::core::HRESULT::from_win32(
            code,
        ))),
        None => Ok(()),
    }
}

fn open_query(tid: u32) -> windows::core::Result<ThreadHandle> {
    #[cfg(test)]
    forced(fault::Step::QueryOpen, Some(tid))?;
    // SAFETY: plain Win32 call; the handle is owned by the returned guard.
    unsafe { OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, tid) }.map(ThreadHandle)
}

fn open_for_resume(tid: u32) -> windows::core::Result<ThreadHandle> {
    #[cfg(test)]
    forced(fault::Step::ResumeOpen, Some(tid))?;
    // SAFETY: plain Win32 call; the handle is owned by the returned guard.
    unsafe { OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, false, tid) }.map(ThreadHandle)
}

fn owner_of(thread: &ThreadHandle) -> windows::core::Result<u32> {
    #[cfg(test)]
    forced(fault::Step::Owner, None)?;
    // SAFETY: `thread` is a live handle with THREAD_QUERY_LIMITED_INFORMATION.
    match unsafe { GetProcessIdOfThread(thread.0) } {
        0 => Err(windows::core::Error::from_thread()),
        pid => Ok(pid),
    }
}

/// `ResumeThread`, answering the suspend count the thread had before: a frozen child's initial
/// thread has exactly 1.
fn resume_thread(thread: &ThreadHandle) -> windows::core::Result<u32> {
    #[cfg(test)]
    forced(fault::Step::Resume, None)?;
    // ResumeThread returns the previous suspend count, or u32::MAX on failure.
    // SAFETY: `thread` is a live handle with THREAD_SUSPEND_RESUME.
    match unsafe { ResumeThread(thread.0) } {
        u32::MAX => Err(windows::core::Error::from_thread()),
        previous => Ok(previous),
    }
}

/// Walk one snapshot entry; `None` if the snapshot lists it under another pid. Ownership is then
/// re-checked on the opened handle by [`resume_if_owned`].
fn visit_thread_entry(
    entry: &windows::Win32::System::Diagnostics::ToolHelp::THREADENTRY32,
    process_pid: u32,
    walk: &mut Walk,
) -> Option<Visit> {
    (entry.th32OwnerProcessID == process_pid).then(|| resume_if_owned(entry.th32ThreadID, process_pid, walk))
}

/// Resume thread `tid` only if it provably belongs to `process_pid`.
///
/// The Toolhelp snapshot is stale by the time the thread is opened: an id can be released and
/// reused by another process, or released and not reused. So:
/// 1. Open with query-only rights and KEEP the handle: it pins the thread, so the id cannot be
///    reused while it is held. Read the owner through it. A thread's owner never changes.
/// 2. Only for the child's own thread, open with suspend/resume rights (the pin guarantees it
///    is the same thread), re-check the owner on that handle, and resume.
///
/// A stale id (reused, gone, or not openable by the child's creator) means the child's own thread
/// with that id has exited, so nothing is left to resume: skipped, not an error. A failed call on
/// the child's own thread is recorded in `last_err`.
fn resume_if_owned(tid: u32, process_pid: u32, walk: &mut Walk) -> Visit {
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER};

    let gone = windows::core::HRESULT::from_win32(ERROR_INVALID_PARAMETER.0);
    let denied = windows::core::HRESULT::from_win32(ERROR_ACCESS_DENIED.0);

    let query = match open_query(tid) {
        Ok(h) => h,
        Err(e) if e.code() == gone => {
            walk.skip(format!("thread {tid} no longer exists"));
            return Visit::Gone;
        }
        Err(e) if e.code() == denied => {
            walk.skip(format!(
                "thread {tid} cannot be opened for query (access denied), so it is not the child's"
            ));
            return Visit::Denied;
        }
        Err(e) => return walk.fail_win32("OpenThread(query)", tid, process_pid, e),
    };

    match owner_of(&query) {
        Ok(owner) if owner == process_pid => {}
        Ok(owner) => {
            walk.skip(format!("thread {tid} now belongs to pid {owner}"));
            return Visit::Foreign { owner };
        }
        Err(e) => return walk.fail_win32("GetProcessIdOfThread", tid, process_pid, e),
    }

    let resume = match open_for_resume(tid) {
        Ok(h) => h,
        Err(e) => return walk.fail_win32("OpenThread(suspend/resume)", tid, process_pid, e),
    };
    match owner_of(&resume) {
        Ok(again) if again == process_pid => {}
        Ok(again) => {
            return walk.fail(
                "OpenThread(suspend/resume)",
                tid,
                process_pid,
                format_args!("opened a thread of pid {again}, not the thread just checked"),
            )
        }
        Err(e) => return walk.fail_win32("GetProcessIdOfThread", tid, process_pid, e),
    }

    match resume_thread(&resume) {
        Ok(1) => {
            walk.resumed += 1;
            Visit::Resumed
        }
        Ok(_) if walk.expected == SuspendCount::Any => {
            walk.resumed += 1;
            Visit::Resumed
        }
        // Anything else leaves a process that is not running the way its creator left it. A count
        // above 1 is an initial thread still suspended after this resume (a debugger, an EDR agent
        // or the caller's own tooling suspended it in the window); 0 is an initial thread that was
        // already running, so the child ran before it was released.
        Ok(previous) => walk.fail(
            "ResumeThread",
            tid,
            process_pid,
            format_args!(
                "the previous suspend count was {previous}, not 1: {}",
                if previous > 1 {
                    "the thread is still suspended"
                } else {
                    "the thread was not suspended, so the child had already run"
                }
            ),
        ),
        Err(e) => walk.fail_win32("ResumeThread", tid, process_pid, e),
    }
}

/// The creation time of thread `tid` (100 ns ticks) if it is a thread of `process_pid`; `None` if
/// the id is stale (gone, another process's, not openable by the child's creator). The error names
/// the failed call.
fn creation_time_if_owned(tid: u32, process_pid: u32) -> Result<Option<u64>, (&'static str, windows::core::Error)> {
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, FILETIME};
    use windows::Win32::System::Threading::GetThreadTimes;

    let gone = windows::core::HRESULT::from_win32(ERROR_INVALID_PARAMETER.0);
    let denied = windows::core::HRESULT::from_win32(ERROR_ACCESS_DENIED.0);

    // SAFETY: plain Win32 call; the handle is owned by the returned guard, which pins the thread.
    let thread = match unsafe { OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, tid) } {
        Ok(h) => ThreadHandle(h),
        Err(e) if e.code() == gone || e.code() == denied => return Ok(None),
        Err(e) => return Err(("OpenThread(query)", e)),
    };
    match owner_of(&thread) {
        Ok(owner) if owner == process_pid => {}
        Ok(_) => return Ok(None),
        Err(e) => return Err(("GetProcessIdOfThread", e)),
    }
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    #[cfg(test)]
    forced(fault::Step::CreationTime, Some(tid)).map_err(|e| ("GetThreadTimes", e))?;
    // SAFETY: `thread` is a live handle with THREAD_QUERY_LIMITED_INFORMATION; the out-parameters
    // are valid.
    unsafe { GetThreadTimes(thread.0, &mut created, &mut exited, &mut kernel, &mut user) }
        .map_err(|e| ("GetThreadTimes", e))?;
    #[cfg(test)]
    if fault::creation_times_are_equal() {
        return Ok(Some(1));
    }
    Ok(Some(
        (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime),
    ))
}

/// The id of the child's initial thread among `tids`: the thread of `process_pid` created first.
///
/// A frozen child has one thread, its initial one, until someone else starts another; a thread
/// created later has a later creation time. Thread ids say nothing about order, and the snapshot
/// lists threads in no promised order.
///
/// `None`, with the cause in `walk`, when the initial thread cannot be told: the snapshot lists no
/// thread of the child, every listed thread is stale, the creation time of a thread of the child
/// cannot be read (it might be the earlier), or the earliest two are equal. The
/// clock was measured only on Windows 11 10.0.26100, where 300 threads started back to back in one
/// process were 56 us or more apart; whether an older build's clock can tie is unmeasured, so a tie
/// is a failure, never a guess by thread id.
fn initial_thread_id(process_pid: u32, tids: &[u32], walk: &mut Walk) -> Option<u32> {
    let mut times = Vec::with_capacity(tids.len());
    for &tid in tids {
        match creation_time_if_owned(tid, process_pid) {
            Ok(Some(created)) => times.push((created, tid)),
            Ok(None) => walk.skip(format!(
                "thread {tid} is gone, is not pid {process_pid}'s, or cannot be opened by the child's creator"
            )),
            Err((call, e)) => {
                walk.fail_win32(call, tid, process_pid, e);
                return None;
            }
        }
    }
    match earliest_created(times) {
        Earliest::NoThread => None,
        Earliest::Unique(tid) => Some(tid),
        Earliest::Tie(first, second) => {
            walk.fail_unidentified(process_pid, first, second);
            None
        }
    }
}

/// Which of some `(creation time, thread id)` pairs is the earliest.
#[derive(Debug, PartialEq, Eq)]
enum Earliest {
    NoThread,
    Unique(u32),
    /// Two threads share the earliest time, in the order they were listed: which came first is
    /// unknowable.
    Tie(u32, u32),
}

fn earliest_created(times: impl IntoIterator<Item = (u64, u32)>) -> Earliest {
    let mut best: Option<(u64, u32)> = None;
    let mut tied: Option<u32> = None;
    for (created, tid) in times {
        match best {
            Some((time, _)) if created > time => {}
            Some((time, _)) if created == time => {
                tied.get_or_insert(tid);
            }
            _ => {
                best = Some((created, tid));
                tied = None;
            }
        }
    }
    match (best, tied) {
        (None, _) => Earliest::NoThread,
        (Some((_, tid)), None) => Earliest::Unique(tid),
        (Some((_, first)), Some(second)) => Earliest::Tie(first, second),
    }
}

/// The pid of the process at `raw_handle`, or an error naming `GetProcessId` that keeps its Win32
/// code as its source.
///
/// `GetProcessId` answers 0 on failure, and a walk filtered to owner 0 would match the System
/// Idle process instead of the child.
fn process_pid_of(raw_handle: HANDLE) -> io::Result<u32> {
    // SAFETY: `GetProcessId` only reads the handle; an invalid one is reported as 0.
    let pid = unsafe { GetProcessId(raw_handle) };
    if pid == 0 {
        return Err(io_context(
            "GetProcessId failed on the child's handle",
            io::Error::last_os_error(),
        ));
    }
    Ok(pid)
}

/// The error for a walk that resumed nothing, naming why every listed thread was skipped.
fn none_resumed_error(process_pid: u32, last_skip: Option<&str>) -> io::Error {
    match last_skip {
        Some(reason) => io::Error::other(format!(
            "no suspended threads resumed: every thread the snapshot listed for pid {process_pid} was stale (last: {reason})"
        )),
        None => io::Error::other(format!(
            "no suspended threads resumed: the snapshot listed no threads for pid {process_pid}"
        )),
    }
}

/// The outcome of a finished walk. A failed resume is an error even when siblings resumed: a
/// thread left suspended is exactly the "frozen process" `resume_initial_threads` exists to rule
/// out, however many of its siblings got moving first.
fn walk_verdict(process_pid: u32, walk: Walk) -> io::Result<()> {
    let Walk {
        resumed,
        last_err,
        last_skip,
        ..
    } = walk;
    if let Some(e) = last_err {
        log::warn!(
            "resume_initial_threads: failed to resume one or more of this child's initial threads \
             ({resumed} resumed successfully before the failure): {report}",
            report = crate::error::Report(&e)
        );
        return Err(e);
    }
    if resumed == 0 {
        return Err(none_resumed_error(process_pid, last_skip.as_deref()));
    }
    Ok(())
}

/// Resume every suspended thread of the process at `proc_handle` after job assignment.
///
/// Why resume REGARDLESS of job-assign result: the kill-group race invariant
/// requires the child to be inside the job before executing, so it was spawned
/// frozen (CREATE_SUSPENDED). Whether or not job assignment succeeded, the child
/// MUST be resumed — a frozen process is unacceptable. If `ResumeThread` fails
/// the child is killed immediately and an error returned.
///
/// `expected` is what each resume's previous suspend count must be; see [`SuspendCount`].
///
/// PID-reuse safety: the caller holds the child's process handle (via the owning
/// `Child`), keeping its PID alive for the duration of the Toolhelp snapshot walk.
pub(crate) fn resume_initial_threads(
    proc_handle: std::os::windows::io::RawHandle,
    expected: SuspendCount,
) -> io::Result<()> {
    use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD};

    let raw_handle = HANDLE(proc_handle.cast());

    let mut walk = Walk {
        expected,
        ..Walk::default()
    };

    let process_pid = process_pid_of(raw_handle);
    debug_assert!(
        process_pid.is_ok(),
        "the caller must pass a live process handle: {process_pid:?}"
    );
    let process_pid = process_pid?;

    // SAFETY: snapshot/iterate with an owned handle, closed before return.
    unsafe {
        let snap = thread_snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0))?;
        let entries = thread_entries_closing(snap)?;

        if walk.expected == SuspendCount::ExactlyOne {
            // Only the initial thread is resumed. The others are opened query-only, to read their
            // creation time, and that read failing fails the release.
            let own: Vec<u32> = entries
                .iter()
                .filter(|e| e.th32OwnerProcessID == process_pid)
                .map(|e| e.th32ThreadID)
                .collect();
            if let Some(initial) = initial_thread_id(process_pid, &own, &mut walk) {
                resume_if_owned(initial, process_pid, &mut walk);
            }
        } else {
            for entry in &entries {
                visit_thread_entry(entry, process_pid, &mut walk);
            }
        }
    }

    // Test-only: the injected entry goes through the same owner filter as a real one.
    #[cfg(test)]
    if let Some((tid, owner)) = fault::injected_entry() {
        let entry = windows::Win32::System::Diagnostics::ToolHelp::THREADENTRY32 {
            th32OwnerProcessID: owner.unwrap_or(process_pid),
            th32ThreadID: tid,
            ..Default::default()
        };
        fault::record_injected_visit(visit_thread_entry(&entry, process_pid, &mut walk));
    }

    walk_verdict(process_pid, walk)
}

/// Assign the process at `proc_handle` to a `KILL_ON_JOB_CLOSE` job and resume its
/// initial threads.
///
/// `proc_handle` must remain open for the whole call (it pins the pid against reuse during the
/// Toolhelp thread walk in `resume_initial_threads`). Every caller holds the process it spawned
/// across the call, so it does.
///
/// Returns `Ok(Some(JobHandle))` on full success (job assigned AND resumed).
/// Returns `Ok(None)` when job assignment fails — the caller falls back to the
/// universal `Containment::TreeWalk` mechanism (identity teardown).
/// Returns `Err` when resume fails — a frozen child is unacceptable; the
/// child+job are killed and the error propagates to fail the spawn.
pub(crate) fn attach_job(proc_handle: std::os::windows::io::RawHandle) -> io::Result<Option<JobHandle>> {
    let job_result = assign_held(proc_handle);

    // Resume REGARDLESS of job assignment result. A frozen child cannot be left running.
    if let Err(resume_err) = resume_initial_threads(proc_handle, SuspendCount::Any) {
        if let Ok(job) = job_result {
            // Kill via the job first (catches any threads the walk may have missed). The
            // resume failure is what gets reported; a kill failure on top of it cannot change
            // that outcome, so it is logged here rather than swallowed.
            if let Err(e) = job.hard_kill() {
                log::warn!(
                    "job kill after a failed resume also failed ({report}); the tree may still be running",
                    report = crate::error::Report(&e)
                );
            }
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

/// Test-only membership probe: whether `pid` is inside the Job Object `job`, via
/// `IsProcessInJob` against that job handle (not "any job"). Membership is immutable once assigned,
/// so it is deterministic for a handle-pinned child regardless of run state. Shared by the sync and
/// async `Child::test_job_handle_contains_self` accessors (both compiled outside `cfg(test)` so
/// integration crates can call them). Panics, naming the Win32 error, when `OpenProcess` or
/// `IsProcessInJob` fails, so a failed query is not read as "not a member".
pub(crate) fn job_contains_pid(job: &JobHandle, pid: u32) -> bool {
    use windows::Win32::System::JobObjects::IsProcessInJob;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION};

    // Open the child process by PID; the backend doesn't expose its handle.
    // SAFETY: standard Win32 call; the handle is closed below.
    let process_handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) }
        .unwrap_or_else(|e| panic!("OpenProcess({pid}) failed: {e}"));

    let mut in_job = windows::core::BOOL(0);
    // SAFETY: both handles are valid for the duration of the call.
    let queried = unsafe { IsProcessInJob(process_handle, Some(job.raw), &mut in_job) };
    // SAFETY: `process_handle` was opened above and must be closed.
    unsafe {
        _ = CloseHandle(process_handle);
    }
    queried.unwrap_or_else(|e| panic!("IsProcessInJob({pid}) failed: {e}"));
    in_job.as_bool()
}

/// The limit flags `job` holds now.
pub(crate) fn job_limit_flags(
    job: &JobHandle,
) -> windows::core::Result<windows::Win32::System::JobObjects::JOB_OBJECT_LIMIT> {
    use windows::Win32::System::JobObjects::{JobObjectBasicLimitInformation, JOBOBJECT_BASIC_LIMIT_INFORMATION};

    let mut info = JOBOBJECT_BASIC_LIMIT_INFORMATION::default();
    // SAFETY: the handle is live for the call, and `info` is a correctly sized out-parameter.
    unsafe {
        QueryInformationJobObject(
            Some(job.raw),
            JobObjectBasicLimitInformation,
            std::ptr::addr_of_mut!(info).cast(),
            size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as u32,
            None,
        )
    }?;
    Ok(info.LimitFlags)
}

/// Test-only: whether the Job Object `job` kills its members when its last handle closes. Panics,
/// naming the cause, when the query fails, so a failed query is not read as "no kill-on-close".
pub(crate) fn job_kills_on_close(job: &JobHandle) -> bool {
    let flags = job_limit_flags(job).unwrap_or_else(|e| panic!("querying the job's limits failed: {e}"));
    flags.0 & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0 != 0
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
