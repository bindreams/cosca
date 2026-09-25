//! Shared harness for the `ShellExecuteExW` `lpFile`-resolution probes in this folder: the
//! `LaunchOutcome` outcome type, the bounded `ShellExecuteExW` call itself, and the self-report
//! readers every probe module uses. See `tests/windows_shell_resolution.rs`'s module doc for what
//! these probes measure and why.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{mpsc, Arc, Mutex, PoisonError};
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

/// Which stage of a `shell_execute_with` call was active when `shell_execute_bounded`'s outer bound
/// tripped — see that function's doc for why blaming `ShellExecuteExW` unconditionally is wrong.
const PHASE_CALLING_SHELL_EXECUTE: u8 = 0;
const PHASE_WAITING_ON_CHILD: u8 = 1;
const PHASE_DONE: u8 = 2;

fn phase_description(phase: u8) -> &'static str {
    match phase {
        PHASE_CALLING_SHELL_EXECUTE => "still inside ShellExecuteExW itself",
        PHASE_WAITING_ON_CHILD => "waiting for, or reaping, the process ShellExecuteExW launched",
        PHASE_DONE => "finishing up just after the child wait completed",
        _ => "at an unrecorded phase",
    }
}

/// Shared between `shell_execute_bounded`'s worker thread and the caller's own thread: which phase
/// the worker is in (see `phase_description`), and — once obtained — the handle to whatever process
/// the shell launched.
///
/// `child` holds a DUPLICATE of the launched process's handle, never the worker's own `hProcess`:
/// the worker keeps waiting on, and eventually terminates/closes, its own handle regardless of
/// what happens here, on its own thread, independently of whatever `shell_execute_bounded` does
/// with this duplicate on the caller's thread if the outer bound trips. Two independent handles to
/// the same process is the documented way to let two parties each wait on, terminate and close a
/// process on their own schedule without ever closing the same handle value twice, or needing the
/// worker and the bound-trip reaper to coordinate who "owns" a single shared one. Guarded by a
/// `Mutex` rather than left to whichever thread gets there first: `take()`ing the `Option` is what
/// makes at most one side ever act on it, deterministically, not a race between two threads reading
/// then writing.
#[derive(Default)]
pub(crate) struct BoundedCallState {
    phase: AtomicU8,
    child: Mutex<Option<HANDLE>>,
}

// SAFETY: the only non-`Send`/`Sync` field is `child`'s `HANDLE`, and it is never a pseudo-handle
// (e.g. `GetCurrentProcess()`'s constant, valid only for the calling thread's own process) — it is
// always a real `DuplicateHandle` result, a process-wide kernel handle. Waiting on, terminating and
// closing such a handle from a thread other than the one that obtained it is sound; Windows does
// not tie a real handle's validity to the thread that created it. `Mutex` already makes every read
// of `child` and the `take()` that follows it indivisible, which is what rules out the worker and a
// bound-trip reaper ever touching the same duplicate.
unsafe impl Send for BoundedCallState {}

// SAFETY: `phase` is an `AtomicU8` (already `Sync`), and every access to `child` goes through its
// `Mutex`, which is what makes concurrent reads from `shell_execute_bounded`'s caller thread and
// writes from the worker thread safe to interleave.
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

    state.phase.store(PHASE_CALLING_SHELL_EXECUTE, Ordering::SeqCst);
    // SAFETY: every pointer field borrows a buffer that outlives the call, and `cbSize` matches.
    if let Err(e) = unsafe { ShellExecuteExW(&mut info) } {
        // `ERROR_FILE_NOT_FOUND` and `ERROR_NO_ASSOCIATION` are the shell reporting genuine
        // negative measurements — "nothing there" and "something there, but nothing to hand it
        // to" respectively — which are results, not probe-harness failures. Both are handed back
        // as `NotLaunched` for the CALLER to classify: which code (or codes) counts as the
        // expected answer is specific to each probe's target, not to this shared helper. Any other
        // error means the harness could not even ask the question — panic rather than mislabel it
        // as a measured "nothing was launched".
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
        return Ok(LaunchOutcome::LaunchedNoHandle);
    }
    state.phase.store(PHASE_WAITING_ON_CHILD, Ordering::SeqCst);
    // Publish a DUPLICATE of the handle before waiting on it — see `BoundedCallState`'s doc for why
    // a duplicate, not `info.hProcess` itself.
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
    if duplicated.is_ok() {
        *state.child.lock().unwrap_or_else(PoisonError::into_inner) = Some(dup);
    } else {
        eprintln!(
            "PROBE shell-execute: could not duplicate the launched process's handle for the bound-trip \
             reaper; a bound trip during this wait will not be able to reap it"
        );
    }
    // SAFETY: `info.hProcess` is a live process handle the shell just handed us; owned by this
    // function throughout, closed exactly once, on whichever return path below is taken.
    let waited = unsafe { WaitForSingleObject(info.hProcess, CHILD_EXIT_BOUND_MS) };
    // This function is about to either succeed or run its own terminate-and-reap on `info.hProcess`
    // either way, so the duplicate handed to `state` for the bound-trip reaper is no longer needed
    // from this point. Reclaim and close it now, so a run that never hits the outer bound does not
    // leak it. If `shell_execute_bounded`'s reaper already claimed it (the outer bound tripped while
    // the wait above was still running), this returns `None` and there is nothing left to close here.
    if let Some(dup) = state.child.lock().unwrap_or_else(PoisonError::into_inner).take() {
        // SAFETY: this function's own duplicate, not yet closed by anyone else.
        unsafe {
            let _ = CloseHandle(dup);
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
        unsafe {
            if let Err(term_err) = TerminateProcess(info.hProcess, 1) {
                let _ = CloseHandle(info.hProcess);
                return Err(format!(
                    "the launched process {reason}, and could not even be terminated ({term_err}); \
                     it has been abandoned rather than waited on unboundedly for an exit that \
                     TerminateProcess itself could not obtain"
                ));
            }
            let _ = WaitForSingleObject(info.hProcess, INFINITE);
            let _ = CloseHandle(info.hProcess);
        }
        return Err(format!(
            "the launched process {reason}, so this probe could not be measured (it has now been \
             terminated and reaped)"
        ));
    }
    // SAFETY: `info.hProcess` is still owned by this function; closed exactly once.
    unsafe {
        let _ = CloseHandle(info.hProcess);
    }
    state.phase.store(PHASE_DONE, Ordering::SeqCst);
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
/// `BoundedCallState`'s phase marker. Chosen well below `.config/nextest.toml`'s 180s
/// `terminate-after` for this binary, so a genuine block is diagnosed here and reported with
/// context, rather than only visible as a bare timeout kill with no diagnosis.
pub(crate) const SHELL_EXECUTE_BOUND: Duration = Duration::from_secs(60);

/// Runs `f` (a `shell_execute_with` call) on its own thread and waits for it, bounded by
/// `SHELL_EXECUTE_BOUND`. See that constant's doc for why a bound is warranted here at all, and why
/// hitting it is always a failure.
///
/// `f` receives its own `BoundedCallState`, shared with this function: on a bound trip, if the
/// worker had already obtained a launched process's handle, that process is terminated and reaped
/// here (a real kernel outcome, not a race) before this returns, rather than left running,
/// uncontained, into the isolation steps that run later in the same workflow job — see the module
/// doc. The `Err` message also names which phase of the call was active, rather than always
/// blaming `ShellExecuteExW` — see `BoundedCallState`'s doc for how the two sides avoid ever
/// touching the same handle twice.
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
            let phase = state.phase.load(Ordering::SeqCst);
            if let Some(child) = state.child.lock().unwrap_or_else(PoisonError::into_inner).take() {
                // SAFETY: this is the duplicate `shell_execute_in_apartment` published, taken
                // exclusively here (the `Mutex` `take()` above is what rules out the worker also
                // touching this same duplicate); terminating, waiting and closing it does not
                // affect the worker's own, separate handle to the same process.
                unsafe {
                    if TerminateProcess(child, 1).is_ok() {
                        let _ = WaitForSingleObject(child, INFINITE);
                    }
                    let _ = CloseHandle(child);
                }
            }
            Err(format!(
                "ShellExecuteExW did not return within {SHELL_EXECUTE_BOUND:?} ({}); this probe \
                 could not be measured",
                phase_description(phase)
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
