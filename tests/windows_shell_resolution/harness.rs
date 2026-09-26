//! Shared harness for the `ShellExecuteExW` `lpFile`-resolution probes in this folder: the
//! `LaunchOutcome` outcome type, the bounded `ShellExecuteExW` call itself, and the self-report
//! readers every probe module uses. See `tests/windows_shell_resolution.rs`'s module doc for what
//! these probes measure and why.

use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use windows::core::{HRESULT, PCWSTR};
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, ERROR_FILE_NOT_FOUND, ERROR_NO_ASSOCIATION, HANDLE,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::System::Threading::{GetCurrentProcess, TerminateProcess, WaitForSingleObject, INFINITE};
use windows::Win32::UI::Shell::{
    ShellExecuteExW, SEE_MASK_CLASSNAME, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS,
    SHELLEXECUTEINFOW,
};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

/// The child is an external process that might never exit, so a bound is the honest failure
/// surface rather than a synchronisation device — if it trips, the probe reports that the launched
/// process did not finish. The process is then terminated and waited out — unboundedly, since that
/// wait confirms a real kernel outcome rather than synchronizing anything this code controls —
/// before its handle closes, so a timed-out probe never abandons a still-running child. If
/// `TerminateProcess` itself fails, this returns an error immediately instead of waiting `INFINITE`
/// on a process nothing here can make exit.
///
/// This bound does not stand alone: every call site that hands `ShellExecuteExW` an existing
/// extensionless target also wraps the WHOLE call this bound lives inside of — `ShellExecuteExW`
/// itself, then this wait, then the terminate-and-reap that follows it — in the outer
/// `SHELL_EXECUTE_BOUND` (60s), via `shell_execute_bounded`. That outer bound tripping does not
/// specifically mean `ShellExecuteExW` itself never returned (measured intermittently, for an
/// existing extensionless target — see `SHELL_EXECUTE_BOUND`'s doc): it can equally mean this wait,
/// or the terminate-and-reap after it, ran long enough to exhaust the remaining 60s. `BoundedCallState`
/// is what lets a caller of `shell_execute_bounded` tell the two apart.
const CHILD_EXIT_BOUND_MS: u32 = 30_000;

fn wide_nul(s: &std::ffi::OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// Write a `.bat` that stamps `marker` with its own path (`%~f0`) — self-reported by the very
/// process that ran, so "did this file run, and was it genuinely this file" are both filesystem
/// questions, not a post-exit OS query (see `shell_execute_with`'s doc for why that query is not
/// used here).
pub(crate) fn plant_batch(path: &Path, marker: &Path) {
    std::fs::write(path, format!("@echo off\r\necho %~f0 > \"{}\"\r\n", marker.display()))
        .unwrap_or_else(|e| panic!("could not plant the probe batch at {}: {e}", path.display()));
}

/// Read a marker a `.bat` planted by [`plant_batch`] wrote with its own path, trimmed of the
/// trailing newline `echo` adds. `None` if the marker was never written — the batch either did not
/// run, or did not get far enough to write it.
pub(crate) fn read_self_report(marker: &Path) -> Option<PathBuf> {
    std::fs::read_to_string(marker).ok().map(|s| PathBuf::from(s.trim()))
}

/// Read a `cosca_testbin_image --report-to` report and extract the `image=` line: the file the OS
/// says the image section was loaded from, queried by the running process itself, on itself, while
/// it was still alive — not by this harness after the fact, which `QueryFullProcessImageNameW`
/// cannot do reliably post-exit (see `shell_execute_with`'s doc). `None` if the report was never
/// written.
pub(crate) fn read_self_report_image(report: &Path) -> Option<PathBuf> {
    std::fs::read_to_string(report)
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("image="))
        .map(PathBuf::from)
}

/// What `shell_execute_with` was actually able to measure, distinct from what it launched.
#[derive(Debug)]
pub(crate) enum LaunchOutcome {
    /// The shell launched something, handed back a process handle, and this function waited for it
    /// to exit. Confirming exactly what ran is deliberately NOT this function's job: querying an
    /// already-exited process's image with `QueryFullProcessImageNameW` is unreliable — measured to
    /// intermittently fail post-exit (`0x8007001F`, "a device attached to the system is not
    /// functioning") even though it is documented as safe to call after the process has exited.
    /// Instead, the launched program self-reports its own identity into a marker or report file
    /// WHILE it is still running: a planted `.bat` writes `%~f0` (see `plant_batch`), and a copy of
    /// `cosca_testbin_image` writes an `image=` line via `--report-to`. Callers below read that
    /// self-report, never an OS query taken after the fact.
    Waited,
    /// The shell launched something but `SEE_MASK_NOCLOSEPROCESS` did not yield a process handle to
    /// wait on. This happens when the verb hands off to another process (e.g. a DDE server), and —
    /// measured directly by `does_an_existing_extensionless_file_ever_launch_directly` — also
    /// whenever `lpFile` names an EXTENSIONLESS file, existing or not: `ShellExecuteEx` never runs
    /// an extensionless file as a program itself, only ever handing it to an association/Open-With
    /// handler. Every call sets `SEE_MASK_NOASYNC` (see `shell_execute_in_apartment`'s doc), so this
    /// outcome is a SYNCHRONOUS handoff, not a race: `ShellExecuteExW` did not return until the shell
    /// finished invoking whatever it handed `lpFile` off to. What is still unmeasured is what that
    /// handler does with the file AFTERWARD — `SHELLEXECUTEINFOW` carries no PID for it either way,
    /// only the `hProcess` that is exactly what's missing, so there is no handle here to terminate or
    /// wait on for any of its own subsequent behaviour. Most probes below treat this outcome as a
    /// failed measurement, but the ones whose own target is specifically extensionless treat it as
    /// the expected, measured negative — say so explicitly at each such arm. Either way, whatever the
    /// shell hands off to this way can never be contained by cosca: there is no process handle here
    /// to assign to a Job Object.
    LaunchedNoHandle,
    /// The shell reported `ERROR_FILE_NOT_FOUND` (it looked for `lpFile` and found nothing to
    /// launch) or `ERROR_NO_ASSOCIATION` (it found `lpFile`, but — with `SEE_MASK_FLAG_NO_UI`
    /// suppressing the picker that would otherwise ask a human — has no program to hand it to).
    /// Both are genuine negative measurements, carried here so a caller can report them; which one
    /// (or both) is the expected answer differs per probe, since `ERROR_NO_ASSOCIATION` only makes
    /// sense where `lpFile` can actually exist. Any OTHER error means the harness itself could not
    /// even ask the question — `shell_execute_with` panics on those instead of returning them
    /// mislabelled as this, and callers must still check which of the two codes they actually got
    /// rather than assume.
    NotLaunched(windows::core::Error),
}

/// Launch `lp_file` through `ShellExecuteExW` with the default verb, wait for whatever it started,
/// and report what could be measured. See `shell_execute_in_apartment`'s doc for why
/// `SEE_MASK_NOASYNC` is always set — never conditionally dropped. `class`, when set, adds
/// `SEE_MASK_CLASSNAME`/`lpClass` — see `does_shellexecute_search_lpdirectory_for_a_pathless_lpfile_as_exefile`
/// for why that matters.
pub(crate) fn shell_execute(
    lp_file: &Path,
    lp_directory: Option<&Path>,
    class: Option<&str>,
) -> Result<LaunchOutcome, String> {
    shell_execute_with(lp_file, lp_directory, None, class, &BoundedCallState::default())
}

/// Initialise a single-threaded COM apartment on this thread, as production
/// (`src/elevation/windows.rs`) and `windows_shell_execute.rs`'s `launch` both already do, before
/// calling `ShellExecuteExW` — Microsoft documents COM initialization as required before that call.
/// Kept for that reason, even though it did NOT by itself stop the intermittent hang described in
/// the module doc: a dispatch run with this already in place still hung, on both architectures at
/// once. The init and the call and the uninit must all run on the SAME thread: a COM apartment is
/// thread-local, so `shell_execute_bounded`'s worker thread calls this function directly rather than
/// initializing COM on the test's own thread and calling `shell_execute_in_apartment` from the
/// worker.
///
/// `state` is a `BoundedCallState` shared with whichever `shell_execute_bounded` call (if any)
/// wraps this one; unbounded callers ([`shell_execute`]) pass a throwaway one that nothing reads
/// back. See `BoundedCallState`'s doc.
pub(crate) fn shell_execute_with(
    lp_file: &Path,
    lp_directory: Option<&Path>,
    lp_parameters: Option<&str>,
    class: Option<&str>,
    state: &BoundedCallState,
) -> Result<LaunchOutcome, String> {
    crate::windows_probe::in_com_apartment(
        |msg| msg,
        || shell_execute_in_apartment(lp_file, lp_directory, lp_parameters, class, state),
    )
}

/// What, if anything, `shell_execute_in_apartment` has for a bound-trip reaper to act on once
/// `ShellExecuteExW` has returned. Never the worker's own `info.hProcess`: the worker keeps waiting
/// on, and eventually terminates/closes, its own handle regardless of what a reaper does with a
/// `Duplicate` here on the caller's thread. Two independent handles to the same process is the
/// documented way to let two parties each wait on, terminate and close a process on their own
/// schedule without ever closing the same handle value twice.
enum ChildHandle {
    /// The shell handed back no process handle at all. Two different cases collapse to this same
    /// variant, and only one of them is actually inert:
    ///   - `NotLaunched`: nothing was launched, so there is genuinely nothing to reap;
    ///   - `LaunchedNoHandle`: the shell DID launch, or hand off to, a process, but gave back no
    ///     handle for it at all — there is no PID here, only `SHELLEXECUTEINFOW`'s missing
    ///     `hProcess`, so nothing in this module can ever terminate or wait on it. That hand-off is
    ///     never reaped in ANY state this enum's caller can reach, and it can outlive this test.
    NoHandle,
    /// A live duplicate, independent of the worker's own `info.hProcess`, that a reaper can
    /// terminate and close directly.
    Duplicate(HANDLE),
}

/// Where a `shell_execute_with` call was, and what (if anything) was available to reap, the moment
/// `shell_execute_bounded`'s outer bound might trip — see that function's doc for why blaming
/// `ShellExecuteExW` unconditionally is wrong. Read by `shell_execute_bounded`'s bound-trip reaper
/// only if the outer bound actually trips; written by `shell_execute_in_apartment` as the call
/// progresses. See `BoundedCallState`'s doc for why this is one `Mutex`-guarded value rather than a
/// separate phase flag and handle slot.
enum CallState {
    /// Before anything has been published here. This does NOT mean nothing has launched — that
    /// would only be true if `ShellExecuteExW` itself had not yet returned, but this state also
    /// covers the moment right after it does, before the code below has finished acting on what it
    /// got back:
    ///   - `ShellExecuteExW` may already have returned a live `info.hProcess`, with this thread not
    ///     yet having published either a duplicate handle or a `DuplicateHandle` failure here — a
    ///     process exists, but nothing has published it here yet. The instant `DuplicateHandle`
    ///     itself returns, this moves on: to [`CallState::Returned`] on success, or
    ///     [`CallState::HeldNoDuplicate`] on failure — never lingering here through any of the
    ///     terminate-and-reap that a `DuplicateHandle` failure goes on to do;
    ///   - the shell may have created, or handed off to, a process entirely inside its own
    ///     synchronous call (`SEE_MASK_NOASYNC` is always set — see that mask's doc), so a process
    ///     can have been created and finished running before `ShellExecuteExW` ever returns.
    ///
    /// If the outer bound trips while this is `Calling`, a bound-trip reaper has nothing published
    /// to act on — not because nothing launched, but because nothing here has been published for it
    /// to find yet. And a process the shell handed off to with NO process handle at all
    /// (`LaunchOutcome::LaunchedNoHandle`) is never reaped in ANY state this enum can reach, whether
    /// or not the outer bound ever trips: there is no PID, only `SHELLEXECUTEINFOW`'s missing
    /// `hProcess`, so nothing here can ever terminate or wait on it, and it can outlive this test.
    Calling,
    /// `ShellExecuteExW` returned a live `info.hProcess`, but `DuplicateHandle` on it failed: there
    /// is no independent handle here for a bound-trip reaper to act on, only `info.hProcess` itself,
    /// which stays owned by the worker thread throughout. Published HERE, before the worker's own
    /// `TerminateProcess` even starts, precisely so a bound-trip reaper that reads this can tell
    /// "nothing exists yet" (`Calling`) apart from "a process exists, and only this worker thread
    /// can reap it, right now." A reaper's answer to THIS state is to join the worker instead of
    /// returning early — see `shell_execute_bounded`'s `Timeout` arm — and that join is bounded by
    /// the worker's own remaining, real work, never by an additional timer of its own: a terminate,
    /// then a wait gated on that terminate having succeeded, a `CloseHandle`, the final state write,
    /// this thread's own `CoUninitialize` (`in_com_apartment` runs the whole call, uninit included,
    /// on this same worker thread — see that function's doc), sending the result back over the
    /// channel, and the thread's own teardown as it exits.
    HeldNoDuplicate,
    /// `ShellExecuteExW` returned; the `ChildHandle` says what (if anything) a bound-trip reaper can
    /// act on.
    Returned(ChildHandle),
    /// The worker's own bounded wait on `info.hProcess` finished without a natural exit, so the
    /// worker is now terminating and reaping `info.hProcess` itself, on this same thread. A
    /// bound-trip reaper has nothing to act on here, same as [`CallState::Done`] — the reclaimed
    /// duplicate (if any) is already closed by the time this is set — but the reap itself is NOT
    /// finished yet, which is exactly what distinguishes this from `Done`: a reader must not treat
    /// this state as "nothing here ever needed reaping."
    Reaping,
    /// The worker's own wait — and, if it ran long, its own terminate-and-reap of `info.hProcess` —
    /// has genuinely, fully finished (either way: a natural exit, or a completed terminate-and-reap
    /// after [`CallState::Reaping`]). There is nothing left here for a reaper to act on.
    Done,
    /// A `TerminateProcess` this thread needed for its own reap — of `info.hProcess`, either after
    /// `CallState::Reaping` or in the `DuplicateHandle`-failure path that never publishes `Reaping`
    /// at all — itself failed. The process was never confirmed dead: it has been abandoned, not
    /// reaped. This must never be conflated with [`CallState::Done`]; a reader must be told the
    /// child may still be alive.
    ReapFailed,
    /// A bound-trip reaper already gave up and took responsibility for whatever was here: either it
    /// reaped a `ChildHandle::Duplicate` itself, or it found `Calling` or `NoHandle` and is telling
    /// the worker "reap your own handle yourself, the moment you get one — this call has already
    /// returned to its caller and will not come back for it." (For `HeldNoDuplicate` specifically,
    /// the reaper instead joins the worker rather than returning early — see
    /// `shell_execute_bounded`'s `Timeout` arm — but it still writes this variant here on its way
    /// there, same as every other case.) The worker checks for this the instant it publishes
    /// `Returned(ChildHandle::Duplicate(_))`, before starting its own bounded wait. See
    /// `BoundedCallState`'s doc for why the worker's later writes here may freely overwrite this
    /// afterward.
    Abandoned,
}

fn call_state_description(state: &CallState) -> String {
    match state {
        CallState::Calling => "nothing has been published here yet — this does NOT mean nothing has launched: \
             ShellExecuteExW may already have returned a live process handle, with this thread not \
             yet having published either a duplicate handle or a DuplicateHandle failure here, or \
             the shell may already have created or handed off to a process inside its own \
             synchronous call. A no-handle hand-off is never reaped in any state and can outlive \
             this test"
            .to_string(),
        CallState::HeldNoDuplicate => "DuplicateHandle failed; info.hProcess is held only by the worker thread, \
             which is terminating and reaping it directly — a bound-trip reaper joins the worker \
             for this state rather than returning early"
            .to_string(),
        CallState::Returned(ChildHandle::NoHandle) => {
            "ShellExecuteExW had already returned with no process handle to reap; if it had handed \
             off to a process this way (a LaunchedNoHandle outcome, as opposed to a genuine \
             NotLaunched), that process is never reaped in any state and can outlive this test"
                .to_string()
        }
        CallState::Returned(ChildHandle::Duplicate(_)) => {
            "waiting for, or reaping, the process ShellExecuteExW launched".to_string()
        }
        CallState::Reaping => "the worker's own bounded wait finished without a natural exit, and it is now \
             terminating and reaping info.hProcess itself; that reap is still in progress"
            .to_string(),
        CallState::Done => "the worker had already finished its own wait, and any terminate-and-reap that \
             followed, by the time this bound tripped; nothing here needed reaping"
            .to_string(),
        CallState::ReapFailed => "a terminate-and-reap of info.hProcess was under way and TerminateProcess \
             itself failed; the process was never confirmed dead and has been abandoned, not reaped"
            .to_string(),
        CallState::Abandoned => "already claimed by an earlier bound-trip reaper".to_string(),
    }
}

/// Shared between `shell_execute_bounded`'s worker thread and its bound-trip reaper: a single
/// `CallState`, behind one `Mutex`, so a reader never observes the phase and the handle as two
/// separately-racing writes. A separate phase flag and handle slot (e.g. an `AtomicU8` phase next to
/// a `Mutex<Option<HANDLE>>`) would let a reader observe a phase transition — "waiting on child" —
/// before the duplicate handle that phase implies even exists: indistinguishable from
/// `DuplicateHandle` failing outright (which also leaves a handle slot empty, silently, for the
/// whole `CHILD_EXIT_BOUND_MS` that follows), and a reader could only give up silently either way,
/// even though a live process might still be running, uncontained. One `Mutex` around one enum makes
/// the phase and the handle publish together, atomically, so that window cannot exist; `Abandoned`
/// is what lets a reaper that finds nothing here tell the worker to reap its own handle itself,
/// later, rather than the reaper silently giving up on a handle that had not been published yet.
///
/// Once a reaper has captured its own snapshot of this state (always via the same `mem::replace`
/// that writes `Abandoned`), nothing reads the shared state again through that reaper's own return
/// path — so the worker's later, unconditional writes here (a `Returned`/`Reaping` transition
/// already mid-flight, or its own final `Done`/`ReapFailed`) may freely overwrite whatever the
/// reaper left behind. That is harmless, not a bug: no variant here needs to stay sticky for
/// correctness, only the snapshot a reaper captures the instant it writes one.
pub(crate) struct BoundedCallState(Mutex<CallState>);

impl Default for BoundedCallState {
    fn default() -> Self {
        Self(Mutex::new(CallState::Calling))
    }
}

impl BoundedCallState {
    fn lock(&self) -> MutexGuard<'_, CallState> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Publish `child` as this call's `Returned` state, unless a bound-trip reaper already marked
    /// this `Abandoned` first — in which case this leaves `Abandoned` in place and returns `true`,
    /// telling the caller (the worker) that it must reap `child` itself instead of handing it to a
    /// reaper that has already given up and returned.
    fn publish_returned(&self, child: ChildHandle) -> bool {
        let mut guard = self.lock();
        let already_abandoned = matches!(*guard, CallState::Abandoned);
        if !already_abandoned {
            *guard = CallState::Returned(child);
        }
        already_abandoned
    }
}

// SAFETY: the only non-`Send`/`Sync` field anywhere in `CallState` is `ChildHandle::Duplicate`'s
// `HANDLE`, and it is never a pseudo-handle (e.g. `GetCurrentProcess()`'s constant, valid only for
// the calling thread's own process) — it is always a real `DuplicateHandle` result, a process-wide
// kernel handle. Waiting on, terminating and closing such a handle from a thread other than the one
// that obtained it is sound; Windows does not tie a real handle's validity to the thread that
// created it. The `Mutex` already makes every read of the state, and any `HANDLE` inside it,
// indivisible from the write that follows — which is what rules out the worker and a bound-trip
// reaper ever touching the same duplicate.
unsafe impl Send for BoundedCallState {}

// SAFETY: every access to the state goes through its `Mutex`, which is what makes concurrent reads
// from `shell_execute_bounded`'s caller thread and writes from the worker thread safe to interleave.
unsafe impl Sync for BoundedCallState {}

/// `SEE_MASK_NOASYNC` is always set, on every call, unconditionally: Microsoft documents it as
/// REQUIRED for a caller that invokes `ShellExecuteExW` from a thread with no message loop, or that
/// may exit soon after the call returns — `shell_execute_bounded`'s worker thread is exactly that.
/// Without it, `ShellExecuteExW` may hand the operation off asynchronously and return before it
/// completes, which would make `LaunchedNoHandle` here an unreliable race instead of a synchronous,
/// complete fact — see `LaunchOutcome::LaunchedNoHandle`'s doc.
fn shell_execute_in_apartment(
    lp_file: &Path,
    lp_directory: Option<&Path>,
    lp_parameters: Option<&str>,
    class: Option<&str>,
    state: &BoundedCallState,
) -> Result<LaunchOutcome, String> {
    let file_w = wide_nul(lp_file.as_os_str());
    let dir_w = lp_directory.map(|d| wide_nul(d.as_os_str()));
    let params_w = lp_parameters.map(|p| wide_nul(std::ffi::OsStr::new(p)));
    let class_w = class.map(|c| wide_nul(std::ffi::OsStr::new(c)));

    let mut mask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: mask,
        lpFile: PCWSTR(file_w.as_ptr()),
        lpDirectory: dir_w.as_ref().map_or(PCWSTR::null(), |d| PCWSTR(d.as_ptr())),
        lpParameters: params_w.as_ref().map_or(PCWSTR::null(), |p| PCWSTR(p.as_ptr())),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    if let Some(class_w) = &class_w {
        mask |= SEE_MASK_CLASSNAME;
        info.fMask = mask;
        info.lpClass = PCWSTR(class_w.as_ptr());
    }

    // SAFETY: every pointer field borrows a buffer that outlives the call, and `cbSize` matches.
    if let Err(e) = unsafe { ShellExecuteExW(&mut info) } {
        // `ERROR_FILE_NOT_FOUND` and `ERROR_NO_ASSOCIATION` are the shell reporting genuine
        // negative measurements — "nothing there" and "something there, but nothing to hand it
        // to" respectively — which are results, not probe-harness failures. Both are handed back
        // as `NotLaunched` for the CALLER to classify: which code (or codes) counts as the
        // expected answer is specific to each probe's target, not to this shared helper. Any other
        // error means the harness could not even ask the question — panic rather than mislabel it
        // as a measured "nothing was launched".
        state.publish_returned(ChildHandle::NoHandle);
        if e.code() == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0)
            || e.code() == HRESULT::from_win32(ERROR_NO_ASSOCIATION.0)
        {
            return Ok(LaunchOutcome::NotLaunched(e));
        }
        panic!(
            "PROBE shell-execute: ShellExecuteExW failed with an unexpected error (not \
             ERROR_FILE_NOT_FOUND or ERROR_NO_ASSOCIATION): {e}"
        );
    }
    if info.hProcess.is_invalid() {
        state.publish_returned(ChildHandle::NoHandle);
        return Ok(LaunchOutcome::LaunchedNoHandle);
    }
    // Duplicate the handle before waiting on it — see `BoundedCallState`'s doc for why a duplicate,
    // not `info.hProcess` itself.
    let mut dup = HANDLE::default();
    // SAFETY: `info.hProcess` is a live process handle owned by this function; the duplicate is an
    // independent handle to the same process, closed exactly once, by exactly one side, below.
    let duplicated = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            info.hProcess,
            GetCurrentProcess(),
            &mut dup,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if duplicated.is_err() {
        // No independent duplicate exists here, so — unlike the `Duplicate` case below — nothing
        // but THIS worker thread, on ITS OWN schedule, can ever recover this process; a bound-trip
        // reaper has no handle of its own to act on for this call. Publish that plainly, before
        // terminating anything: `HeldNoDuplicate` is what lets a reaper that reads this while the
        // outer bound trips JOIN this thread instead of returning early — see that variant's doc and
        // `shell_execute_bounded`'s `Timeout` arm. Returning early here, with the worker still mid
        // terminate-and-reap, is exactly the window that would let `cargo nextest` tear this test's
        // OS process down (if the caller panics on the resulting `Err`) before the worker ever
        // reaches its own reap, leaving the child running — joining closes it, since the join cannot
        // itself hang: the worker's only remaining path is a terminate, then a wait that runs only if
        // that terminate already succeeded, a real kernel outcome, not a race against a second clock.
        *state.lock() = CallState::HeldNoDuplicate;
        eprintln!(
            "PROBE shell-execute: could not duplicate the launched process's handle for the \
             bound-trip reaper; terminating and reaping it directly on this thread instead of \
             waiting on it naturally"
        );
        // SAFETY: `info.hProcess` is still owned by this function, closed exactly once below.
        return unsafe {
            if let Err(term_err) = TerminateProcess(info.hProcess, 1) {
                let _ = CloseHandle(info.hProcess);
                // The process could not be confirmed dead: publish that plainly. `Done` would claim
                // a completed reap that never actually happened. This overwrites `HeldNoDuplicate`
                // (or `Abandoned`, if a reaper already claimed this call) — harmless, see
                // `BoundedCallState`'s doc.
                *state.lock() = CallState::ReapFailed;
                Err(format!(
                    "the launched process's handle could not be duplicated for a bound-trip \
                     reaper, and this worker's own attempt to terminate it directly also failed \
                     ({term_err}); it has been abandoned rather than waited on unboundedly for an \
                     exit that TerminateProcess itself could not obtain"
                ))
            } else {
                let _ = WaitForSingleObject(info.hProcess, INFINITE);
                let _ = CloseHandle(info.hProcess);
                *state.lock() = CallState::Done;
                Err(
                    "the launched process's handle could not be duplicated for a bound-trip \
                     reaper; it has been terminated and reaped directly on this worker thread \
                     instead of waited on naturally"
                        .to_string(),
                )
            }
        };
    }
    let child_handle = ChildHandle::Duplicate(dup);
    // Publish the phase transition and the handle TOGETHER, under one lock — see `BoundedCallState`'s
    // doc for the race this closes. If a bound-trip reaper had already given up before this could be
    // published, it cannot come back for it: reap it ourselves, right now, instead of running the
    // normal `CHILD_EXIT_BOUND_MS` wait below for a caller that has already returned.
    if state.publish_returned(child_handle) {
        // Nobody will ever see this duplicate now (a reaper that found `Abandoned` does not look for
        // it again) — close it here.
        // SAFETY: this function's own duplicate, never published anywhere `publish_returned` found
        // `Abandoned` — the reaper's own read, and this one, are both under `state`'s lock.
        unsafe {
            let _ = CloseHandle(dup);
        }
        // This state is never actually read back — the bound-trip reaper already returned its own
        // `Err` to `shell_execute_bounded`'s caller, and nothing is listening on `tx` any more — but
        // it is published accurately anyway, the same as every other path here: `Done` must not be
        // claimed for a `TerminateProcess` that itself failed.
        // SAFETY: `info.hProcess` is still owned by this function, closed exactly once below.
        unsafe {
            if let Err(term_err) = TerminateProcess(info.hProcess, 1) {
                let _ = CloseHandle(info.hProcess);
                *state.lock() = CallState::ReapFailed;
                eprintln!(
                    "PROBE shell-execute: the outer bound had already given up on this call before \
                     this worker could publish a handle for it to reap; this worker's own attempt to \
                     terminate the process it just launched also failed ({term_err}); it has been \
                     abandoned rather than waited on unboundedly for an exit TerminateProcess itself \
                     could not obtain"
                );
            } else {
                let _ = WaitForSingleObject(info.hProcess, INFINITE);
                let _ = CloseHandle(info.hProcess);
                *state.lock() = CallState::Done;
            }
        }
        return Err("this call was abandoned by the outer bound before it could publish a \
             process handle to reap"
            .to_string());
    }
    // SAFETY: `info.hProcess` is a live process handle the shell just handed us; owned by this
    // function throughout, closed exactly once, on whichever return path below is taken.
    let waited = unsafe { WaitForSingleObject(info.hProcess, CHILD_EXIT_BOUND_MS) };
    // This function is about to either succeed or run its own terminate-and-reap on `info.hProcess`
    // either way, so the duplicate published above is no longer needed from this point. Reclaim and
    // close it now, so a run that never hits the outer bound does not leak it. If
    // `shell_execute_bounded`'s reaper already claimed it (the outer bound tripped while the wait
    // above was still running), this finds `Abandoned` instead and there is nothing left to close
    // here — the reaper already did. `waited` is already known by this point, so the state this
    // reclaim publishes reflects it directly: `Reaping` only when a terminate-and-reap of
    // `info.hProcess` genuinely still lies ahead (`waited != WAIT_OBJECT_0` — see `CallState::Reaping`'s
    // doc for the race that distinction closes); otherwise straight to `Done`, since all that is left
    // on the natural-exit path below is a single `CloseHandle`, which cannot block or fail to
    // complete.
    let post_reclaim = if waited == WAIT_OBJECT_0 {
        CallState::Done
    } else {
        CallState::Reaping
    };
    {
        let mut guard = state.lock();
        match std::mem::replace(&mut *guard, post_reclaim) {
            CallState::Returned(ChildHandle::Duplicate(dup)) => {
                // SAFETY: this function's own duplicate, not yet closed by anyone else — the reaper
                // only ever takes it by replacing this same `Mutex`-guarded state with `Abandoned`,
                // which the arm below would have matched instead.
                unsafe {
                    let _ = CloseHandle(dup);
                }
            }
            CallState::Returned(ChildHandle::NoHandle) => {}
            // The bound-trip reaper already claimed and dealt with whatever was here itself.
            CallState::Abandoned => {}
            CallState::Calling => {
                unreachable!("this function already published Returned before this point")
            }
            CallState::HeldNoDuplicate => {
                unreachable!("the DuplicateHandle-failure branch returns before this point ever runs")
            }
            CallState::Reaping | CallState::Done | CallState::ReapFailed => {
                unreachable!("this reclaim runs exactly once per call")
            }
        }
    }
    if waited != WAIT_OBJECT_0 {
        let reason = if waited == WAIT_TIMEOUT {
            format!("did not exit within {CHILD_EXIT_BOUND_MS}ms")
        } else {
            format!(
                "WaitForSingleObject failed ({waited:?}): {}",
                std::io::Error::last_os_error()
            )
        };
        // Closing the handle here without reaping the child first would abandon a still-running
        // process with nothing left to terminate it or wait it out. Terminate it and confirm the
        // exit with the kernel (a real, unbounded outcome, not a race against a second clock)
        // before closing — but only if the termination request itself succeeded; if it did not,
        // waiting INFINITE on a process this probe cannot make exit would be exactly the unbounded
        // hang this bound exists to prevent.
        // SAFETY: `info.hProcess` is still owned by this function; closed exactly once below.
        return unsafe {
            if let Err(term_err) = TerminateProcess(info.hProcess, 1) {
                let _ = CloseHandle(info.hProcess);
                // The process could not be confirmed dead: publish that plainly, never `Done` —
                // see `CallState::ReapFailed`'s doc.
                *state.lock() = CallState::ReapFailed;
                Err(format!(
                    "the launched process {reason}, and could not even be terminated ({term_err}); \
                     it has been abandoned rather than waited on unboundedly for an exit that \
                     TerminateProcess itself could not obtain"
                ))
            } else {
                let _ = WaitForSingleObject(info.hProcess, INFINITE);
                let _ = CloseHandle(info.hProcess);
                // Only NOW — after this terminate-and-reap has actually, fully completed, not merely
                // been decided upon — is `Done` an accurate description of this call: see
                // `CallState::Reaping`'s doc for why setting this any earlier would let a bound-trip
                // reaper observe "nothing here needed reaping" while it was still in flight.
                *state.lock() = CallState::Done;
                Err(format!(
                    "the launched process {reason}, so this probe could not be measured (it has \
                     now been terminated and reaped)"
                ))
            }
        };
    }
    // The reclaim above already published `Done`: the natural-exit path has nothing left that can
    // block or fail.
    // SAFETY: `info.hProcess` is still owned by this function; closed exactly once.
    unsafe {
        let _ = CloseHandle(info.hProcess);
    }
    Ok(LaunchOutcome::Waited)
}

/// The outer failure bound for the WHOLE `shell_execute_with` call, not `ShellExecuteExW` alone:
/// when a launch does hand back a process handle, this also covers `CHILD_EXIT_BOUND_MS`'s own
/// wait, terminate, and unbounded reap nested inside it — see that constant's doc. See the module
/// doc for what was actually measured about `ShellExecuteExW` itself (an unexplained intermittent
/// hang) and what is not (it is not established to be fixed by the COM-apartment init in
/// `shell_execute_with`). Win32 gives this process no way to cancel a call already inside
/// `ShellExecuteExW`, so its return is a genuinely external event this code cannot synchronize on
/// — bounding the whole call is the sanctioned exception to "don't synchronize via time", not a
/// race against a clock this process controls.
///
/// Hitting this bound is a FAILURE, not a passing answer: nothing about this probe's actual
/// question was measured, whether the block sat inside `ShellExecuteExW` itself or inside the
/// nested child wait and recovery — `shell_execute_bounded`'s error message names which, using
/// `BoundedCallState`'s `CallState`. Chosen well below `.config/nextest.toml`'s 180s
/// `terminate-after` for this binary, so a genuine block is diagnosed here and reported with
/// context, rather than only visible as a bare timeout kill with no diagnosis.
pub(crate) const SHELL_EXECUTE_BOUND: Duration = Duration::from_secs(60);

/// Runs `f` (a `shell_execute_with` call) on its own thread and waits for it, bounded by
/// `SHELL_EXECUTE_BOUND`. See that constant's doc for why a bound is warranted here at all, and why
/// hitting it is always a failure.
///
/// `f` receives its own `BoundedCallState`, shared with this function: on a bound trip, whatever is
/// available to reap is reaped right here — a process handle, if one had already been published (a
/// real kernel outcome, not a race) — before this returns. If nothing was available yet
/// (`ShellExecuteExW` had not returned), this marks the call abandoned instead: the worker itself
/// then reaps its own handle the moment it obtains one, rather than waiting out its full
/// `CHILD_EXIT_BOUND_MS` for a caller that already gave up. A handle that existed but could not be
/// duplicated for this reaper (`CallState::HeldNoDuplicate`) is different again: only the worker
/// thread holds `info.hProcess` at all, so this function JOINS the worker instead of returning early
/// — see that variant's doc and the `Timeout` arm below. That join is bounded by the worker's own
/// remaining, real work — see `CallState::HeldNoDuplicate`'s doc for the full list — never by a
/// timer of its own.
///
/// What is NOT closed: if the outer bound trips while `f`'s state is still `CallState::Calling`,
/// nothing has been published here yet for either side to act on — see that variant's doc for the
/// two ways a live process can already exist at that point even though nothing has been published —
/// and Win32 gives this process no way to cancel a call already in progress. This function's own
/// thread returns an `Err` here regardless, but the launched process (if one exists) is reaped only
/// by the worker thread, on its own schedule, after this function has already returned. Separately,
/// and regardless of whether the outer bound ever trips: a process the shell handed off to with NO
/// process handle at all (`LaunchOutcome::LaunchedNoHandle`) is never reaped in ANY state this module
/// can reach, and can outlive this test. If a caller panics on this function's `Err` and `cargo
/// nextest` tears down this test's OS process before the worker reaches its own reap, the child is
/// left running — a genuine residual risk, not a solved case; there is no Win32 primitive available
/// here to close it. The `Err` message says which of these happened, rather than always blaming
/// `ShellExecuteExW` — see `BoundedCallState`'s doc for how the two sides avoid ever touching the
/// same handle twice.
///
/// If `f` itself panics, the channel disconnects immediately rather than timing out — that is
/// reported here as what it is (a panic inside `f`, which DID return, by unwinding) rather than
/// folded into the timeout case, which would misreport a real panic as an unexplained hang. The
/// worker is joined (it has already finished panicking, so this cannot itself hang) and its panic
/// payload is propagated on this thread via `std::panic::resume_unwind`, so the original panic
/// message and location are what the test actually reports.
///
/// The spawned thread, if still blocked when the bound trips, is deliberately never joined or
/// killed: Rust has no API to force a thread out of a blocking syscall. Leaking the THREAD is safe
/// because `cargo nextest` gives every test its own OS process — the thread ends when that process
/// does — and because a GitHub-hosted Windows runner is an ephemeral VM torn down after the job
/// regardless of what is still running inside it. The launched CHILD PROCESS is not left to that
/// same reasoning, though — see above.
pub(crate) fn shell_execute_bounded<F>(f: F) -> Result<LaunchOutcome, String>
where
    F: FnOnce(&BoundedCallState) -> Result<LaunchOutcome, String> + Send + 'static,
{
    let state = Arc::new(BoundedCallState::default());
    let worker_state = Arc::clone(&state);
    let (tx, rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        // If the receiver already gave up (the bound elapsed), this send fails silently — there is
        // no one left to report the eventual result to.
        let _ = tx.send(f(&worker_state));
    });
    match rx.recv_timeout(SHELL_EXECUTE_BOUND) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // Read and replace the state under ONE lock acquisition: this is what rules out the
            // worker's own reclaim (in `shell_execute_in_apartment`) racing this read — whichever
            // side gets the lock first, the other finds `Abandoned` and acts accordingly, never both
            // touching the same duplicate. See `BoundedCallState`'s doc.
            let prior = std::mem::replace(&mut *state.lock(), CallState::Abandoned);
            debug_assert!(
                !matches!(prior, CallState::Abandoned),
                "shell_execute_bounded's Timeout arm runs at most once per call"
            );
            if matches!(prior, CallState::HeldNoDuplicate) {
                // `DuplicateHandle` failed: there is no independent handle here for THIS thread to
                // act on, only `info.hProcess`, still held by the worker, which is already
                // terminating and reaping it directly — see `CallState::HeldNoDuplicate`'s doc.
                // Returning here without waiting for that to finish would leave exactly the
                // orphaning window this state exists to close: if the caller then panics on this
                // function's `Err`, `cargo nextest` tearing this OS process down could kill the
                // worker mid-`TerminateProcess`. Join it instead — this cannot itself hang, since
                // everything left on the worker's path is real, already-in-flight work, not a wait
                // on anything external: a terminate (which does not block), a wait gated on that
                // terminate having succeeded, a `CloseHandle`, the final state write, this thread's
                // own `CoUninitialize` (`in_com_apartment` runs the whole call, uninit included, on
                // this same worker thread), sending the result back over `tx`, and the thread's own
                // teardown as it exits.
                return match worker.join() {
                    Err(payload) => std::panic::resume_unwind(payload),
                    Ok(()) => match rx.try_recv() {
                        // The `DuplicateHandle`-failure branch this state came from always returns
                        // `Err` (see `shell_execute_in_apartment`) — wrap it so the message says what
                        // actually happened: the OUTER bound tripped, not just that the worker had
                        // its own trouble. `call_state_description` reused here, rather than a second
                        // hand-written description, is what makes `CallState::HeldNoDuplicate`'s own
                        // arm of that function reachable.
                        Ok(result) => result.map_err(|worker_err| {
                            format!(
                                "ShellExecuteExW-based call did not return within \
                                 {SHELL_EXECUTE_BOUND:?} ({}); the worker's own error, after \
                                 joining it to let it finish reaping: {worker_err}",
                                call_state_description(&prior)
                            )
                        }),
                        Err(_) => panic!(
                            "PROBE shell-execute: the worker thread ended without panicking and \
                             without sending a result after a HeldNoDuplicate join — this should be \
                             impossible, since it sends immediately before exiting"
                        ),
                    },
                };
            }
            let outcome = if let CallState::Returned(ChildHandle::Duplicate(child)) = prior {
                // SAFETY: this is the duplicate `shell_execute_in_apartment` published, taken
                // exclusively here (the `Mutex`-guarded replace above is what rules out the worker
                // also touching this same duplicate; its own reclaim will find `Abandoned` instead);
                // terminating, waiting and closing it does not affect the worker's own, separate
                // handle to the same process.
                unsafe {
                    match TerminateProcess(child, 1) {
                        Ok(()) => {
                            let _ = WaitForSingleObject(child, INFINITE);
                            let _ = CloseHandle(child);
                            "the launched process had a handle available here; it has been \
                             terminated and reaped"
                                .to_string()
                        }
                        Err(term_err) => {
                            let _ = CloseHandle(child);
                            format!(
                                "the launched process had a handle available here, but \
                                 terminating it failed ({term_err}); it has been abandoned rather \
                                 than waited on unboundedly for an exit TerminateProcess itself \
                                 could not obtain"
                            )
                        }
                    }
                }
            } else {
                call_state_description(&prior)
            };
            Err(format!(
                "ShellExecuteExW-based call did not return within {SHELL_EXECUTE_BOUND:?} ({outcome})"
            ))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => match worker.join() {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(()) => panic!(
                "PROBE shell-execute: the worker thread ended without panicking and without \
                 sending a result — this should be impossible, since it sends immediately after \
                 the call returns"
            ),
        },
    }
}

pub(crate) fn probe_dir(tag: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("probe needs a temp dir");
    let marker = dir.path().join(format!("{tag}-marker.txt"));
    (dir, marker)
}
