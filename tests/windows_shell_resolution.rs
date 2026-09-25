//! Platform probes: what `ShellExecuteEx` actually does with an `lpFile`.
//!
//! cosca's Windows elevated path hands `lpFile` to `ShellExecuteExW`, and the resolution policy
//! around it rests on measured facts rather than documentation — the docs do not say, for
//! instance, whether an ABSOLUTE but extensionless `lpFile` still gets `PATHEXT` applied. Guessing
//! wrong there is the difference between "the search hazard is closed" and "a planted `.bat` runs".
//!
//! These are **probes, not assertions about cosca**. They measure the platform and print what they
//! found, so a maintainer can write a policy against evidence. Every one of them still FAILS if the
//! measurement itself could not be taken: the shell refused to launch anything for a reason other
//! than `ERROR_FILE_NOT_FOUND` (a genuine negative measurement — see `LaunchOutcome::NotLaunched`),
//! a helper could not be written, or a launch this probe waited on left no self-report behind. An
//! earlier version of this rule let a probe that only surveys the platform print `INCONCLUSIVE` and
//! PASS when the shell launched something without handing back a process handle to wait on —
//! `does_a_trailing_dot_still_open_the_extensionless_file` did exactly that, on both architectures
//! — so an inconclusive run is now a hard failure everywhere it is genuinely inconclusive. That handoff (`LaunchOutcome::LaunchedNoHandle`) is NOT
//! inconclusive at all: `SEE_MASK_NOASYNC` is always set on every call (see
//! `shell_execute_in_apartment`'s doc), so `ShellExecuteExW` does not return until the shell has
//! finished invoking whatever it handed `lpFile` off to — a synchronous, measured fact, not a race.
//! For an EXTENSIONLESS `lpFile` it is itself the measured answer — `ShellExecuteEx` never runs an
//! extensionless file as a program, existing or not, so getting no process handle back is exactly
//! what should happen, and every probe that plants an extensionless target says so explicitly at
//! that arm. What is still unmeasured is only what the handler the shell handed off to does
//! AFTERWARD; whatever the shell hands off to this way can never be contained by cosca either, since
//! no process handle is ever returned to assign to a Job Object.
//!
//! Every call sets `SEE_MASK_FLAG_NO_UI` — production (`src/elevation/windows.rs`) does not. These
//! probes measure `lpFile` RESOLUTION, not a human's answer to a picker dialog, and must run
//! unattended on a CI runner where no one is there to click one; the flag is kept here for exactly
//! that reason, even though it makes these probes not a byte-for-byte rehearsal of production's own
//! call. Where the flag suppresses a picker the shell would otherwise show, the shell instead
//! returns `ERROR_NO_ASSOCIATION` synchronously — so that code, exactly like `ERROR_FILE_NOT_FOUND`,
//! is a genuine measured negative for a probe whose target is itself extensionless, not a harness
//! failure; each such probe's `NotLaunched` arm says so explicitly.
//!
//! `ShellExecuteExW` can also fail to return at all rather than ever completing, for an EXISTING
//! extensionless target — measured intermittently, on both `x64` and `arm64` (see the PR
//! description's Verification section for run history; not repeated here to keep it in one place).
//! `OpenWith.exe` has been observed present during a hang. Beyond that, the cause is UNMEASURED: not
//! established to be UI-related, not established to be architecture-specific, not established to
//! depend on `SEE_MASK_NOASYNC` (the hang was first observed with that flag always set, before this
//! file ever dropped it for any call, so setting it unconditionally again is not expected by itself
//! to fix the hang), and — contrary to an earlier hypothesis — NOT explained by a missing COM
//! apartment: initializing one before every `ShellExecuteExW` call (`shell_execute_with`, below) did
//! not stop a later run from hanging on both architectures at once. One candidate was that a
//! leftover `OpenWith.exe` instance from one of the three probes below that hand `ShellExecuteExW`
//! an EXISTING extensionless target blocks a LATER `ShellExecuteExW` call — possibly one belonging
//! to a DIFFERENT probe in a later process, since `cargo nextest` gives each test its own OS process
//! but every process on the same runner still shares the same shell state. Those three probes
//! therefore each run in their own nextest invocation, consecutively, after all other probes, with a
//! read-only diagnostic printing which `OpenWith.exe` instances exist before and after — see
//! `.github/workflows/windows-probes.yaml`'s `executing` job — rather than enumerating or killing
//! anything from inside the test binary itself. That isolation does NOT, on its own evidence,
//! support the leftover-handler theory: a dispatch run against it (see the PR description's
//! Verification section) found one `OpenWith.exe` instance carried across both LATER probes, on
//! BOTH architectures, and neither probe hung — the leftover was present exactly when the theory
//! says it should have blocked the next call, and it did not. Running each probe as its own OS
//! process isolates the TEST PROCESS, not OS-level shell/handler state, so this was never going to
//! rule the theory in or out on its own; this run is evidence against it. Every such call site still
//! bounds the whole call, via `shell_execute_bounded` and `SHELL_EXECUTE_BOUND` — see their docs —
//! as a failure surface, not a synchronisation device: hitting that bound is always a FAILURE to
//! measure, never a passing answer. Whether to keep these three probes at all, if the hang persists
//! under this change too, is the repo owner's call.
//!
//! # Why they are `#[ignore]`d
//!
//! Most of them execute a batch file. That is the exact vector `reject_batch_path` exists to
//! refuse, so it must never happen incidentally during `cargo nextest run`. Opt in explicitly:
//!
//! ```text
//! cargo nextest run --test windows_shell_resolution --run-ignored only --no-capture
//! ```
//!
//! Or, from any host OS and without a local Windows VM, dispatch the `windows-probes` workflow with
//! `run_executing_probes` — see `.github/workflows/windows-probes.yaml`. A GitHub-hosted Windows
//! runner is an ephemeral VM destroyed after the job; these must not run against a development
//! machine.
//!
//! # Why no elevation is involved
//!
//! The open question is how `ShellExecuteEx` RESOLVES `lpFile`, which is the same `PathResolve`
//! step for every verb. Using the default verb instead of `runas` measures the same thing with no
//! UAC prompt and no elevated child — so these run unattended, and a failed probe cannot leave an
//! elevated process behind.
#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use windows::core::{HRESULT, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_NO_ASSOCIATION, WAIT_OBJECT_0};
use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE};
use windows::Win32::System::Threading::{TerminateProcess, WaitForSingleObject, INFINITE};
use windows::Win32::UI::Shell::{
    ShellExecuteExW, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
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
/// or the terminate-and-reap after it, ran long enough to exhaust the remaining 60s. See
/// `SHELL_EXECUTE_BOUND`'s doc for what that means for a child still running at that point.
const CHILD_EXIT_BOUND_MS: u32 = 30_000;

fn wide_nul(s: &std::ffi::OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// Write a `.bat` that stamps `marker` with its own path (`%~f0`) — self-reported by the very
/// process that ran, so "did this file run, and was it genuinely this file" are both filesystem
/// questions, not a post-exit OS query (see `shell_execute_with`'s doc for why that query is not
/// used here).
fn plant_batch(path: &Path, marker: &Path) {
    std::fs::write(path, format!("@echo off\r\necho %~f0 > \"{}\"\r\n", marker.display()))
        .unwrap_or_else(|e| panic!("could not plant the probe batch at {}: {e}", path.display()));
}

/// Read a marker a `.bat` planted by [`plant_batch`] wrote with its own path, trimmed of the
/// trailing newline `echo` adds. `None` if the marker was never written — the batch either did not
/// run, or did not get far enough to write it.
fn read_self_report(marker: &Path) -> Option<PathBuf> {
    std::fs::read_to_string(marker).ok().map(|s| PathBuf::from(s.trim()))
}

/// Read a `cosca_testbin_image --report-to` report and extract the `image=` line: the file the OS
/// says the image section was loaded from, queried by the running process itself, on itself, while
/// it was still alive — not by this harness after the fact, which `QueryFullProcessImageNameW`
/// cannot do reliably post-exit (see `shell_execute_with`'s doc). `None` if the report was never
/// written.
fn read_self_report_image(report: &Path) -> Option<PathBuf> {
    std::fs::read_to_string(report)
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("image="))
        .map(PathBuf::from)
}

/// Record that this probe ran to a real conclusion, as a file named after the test in
/// `$COSCA_PROBE_MARKERS` when that is set. The workflow's final "Require that an executing probe
/// ran" step fails a run that leaves no marker, so a `probe_filter` that matches nothing cannot pass
/// having run nothing — mirrors `tests/windows_path_resolution/harness.rs`'s `mark_canary_passed`
/// and `windows_shell_execute.rs`'s `mark_passed`.
fn mark_probe_passed() {
    let Some(dir) = std::env::var_os("COSCA_PROBE_MARKERS") else {
        return;
    };
    let name = std::thread::current()
        .name()
        .expect("libtest names each test's thread")
        .replace("::", ".");
    std::fs::write(std::path::Path::new(&dir).join(name), b"")
        .unwrap_or_else(|e| panic!("could not write the probe marker: {e}"));
}

/// Whether `reported` names the same file as `want`, by file name only: a self-report's directory
/// component — this probe's own scratch temp dir — may come back short-named (`RUNNER~1`) even
/// though the file name itself never does. Mirrors `windows_shell_execute.rs`'s `same_file`, for
/// the same reason.
fn same_file(reported: &Path, want: &Path) -> bool {
    let want = want
        .file_name()
        .expect("a planted path has a file name")
        .to_string_lossy();
    reported
        .file_name()
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case(&want))
}

/// What `shell_execute_with` was actually able to measure, distinct from what it launched.
#[derive(Debug)]
enum LaunchOutcome {
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
/// `SEE_MASK_NOASYNC` is always set — never conditionally dropped.
fn shell_execute(lp_file: &Path, lp_directory: Option<&Path>) -> Result<LaunchOutcome, String> {
    shell_execute_with(lp_file, lp_directory, None)
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
fn shell_execute_with(
    lp_file: &Path,
    lp_directory: Option<&Path>,
    lp_parameters: Option<&str>,
) -> Result<LaunchOutcome, String> {
    // SAFETY: paired with the `CoUninitialize` below, on this same thread.
    let com = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
    if com.is_err() {
        return Err(format!("CoInitializeEx failed before ShellExecuteExW: {com:?}"));
    }
    let result = shell_execute_in_apartment(lp_file, lp_directory, lp_parameters);
    // SAFETY: balances the successful `CoInitializeEx` above, still on this thread.
    unsafe { CoUninitialize() };
    result
}

/// `SEE_MASK_NOASYNC` is always set, on every call, unconditionally — an earlier version of this
/// commit tried dropping it for the three calls that hand `ShellExecuteExW` an EXISTING
/// extensionless target, on a reviewer's hypothesis that it was implicated in the hang described in
/// the module doc. That was wrong on two counts, not just unconfirmed: Microsoft documents
/// `SEE_MASK_NOASYNC` as REQUIRED for a caller that invokes `ShellExecuteExW` from a thread with no
/// message loop, or that may exit soon after the call returns — `shell_execute_bounded`'s worker
/// thread is exactly that, so dropping the flag violated a documented precondition rather than
/// testing an unrelated one. And without it, `ShellExecuteExW` may hand the operation off
/// asynchronously and return before it completes, which is what actually made two probes report a
/// no-handle result as `NOT MEASURED` in that version — a regression this flag being set is what
/// prevents: with `SEE_MASK_NOASYNC` set, `ShellExecuteExW` does not return until the shell
/// operation itself has completed, so `LaunchedNoHandle` here is a synchronous, complete handoff,
/// not a race — see `LaunchOutcome::LaunchedNoHandle`'s doc.
fn shell_execute_in_apartment(
    lp_file: &Path,
    lp_directory: Option<&Path>,
    lp_parameters: Option<&str>,
) -> Result<LaunchOutcome, String> {
    let file_w = wide_nul(lp_file.as_os_str());
    let dir_w = lp_directory.map(|d| wide_nul(d.as_os_str()));
    let params_w = lp_parameters.map(|p| wide_nul(std::ffi::OsStr::new(p)));

    let mask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: mask,
        lpFile: PCWSTR(file_w.as_ptr()),
        lpDirectory: dir_w.as_ref().map_or(PCWSTR::null(), |d| PCWSTR(d.as_ptr())),
        lpParameters: params_w.as_ref().map_or(PCWSTR::null(), |p| PCWSTR(p.as_ptr())),
        nShow: SW_HIDE.0,
        ..Default::default()
    };

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
    // SAFETY: a process handle the shell just handed us.
    unsafe {
        let waited = WaitForSingleObject(info.hProcess, CHILD_EXIT_BOUND_MS);
        if waited != WAIT_OBJECT_0 {
            // Closing the handle here without reaping the child first — as an earlier version of
            // this probe did — would abandon a still-running process with nothing left to
            // terminate it or wait it out. Terminate it and confirm the exit with the kernel (a
            // real, unbounded outcome, not a race against a second clock) before closing — but
            // only if the termination request itself succeeded; if it did not, waiting INFINITE on
            // a process this probe cannot make exit would be exactly the unbounded hang this bound
            // exists to prevent.
            if let Err(term_err) = TerminateProcess(info.hProcess, 1) {
                let _ = CloseHandle(info.hProcess);
                return Err(format!(
                    "the launched process did not exit within {CHILD_EXIT_BOUND_MS}ms, and could \
                     not even be terminated ({term_err}); it has been abandoned rather than waited \
                     on unboundedly for an exit that TerminateProcess itself could not obtain"
                ));
            }
            let _ = WaitForSingleObject(info.hProcess, INFINITE);
            let _ = CloseHandle(info.hProcess);
            return Err(format!(
                "the launched process did not exit within {CHILD_EXIT_BOUND_MS}ms, so this probe \
                 could not be measured (it has now been terminated and reaped)"
            ));
        }
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
/// nested child wait and recovery. `shell_execute_bounded` deliberately leaks its worker thread
/// when this bound trips (see that function's doc), so a child that WAS launched is not guaranteed
/// to have been terminated by the time a probe reports this failure — it can be left running,
/// uncontained, on the runner when that happens; acceptable only because a GitHub-hosted runner is
/// an ephemeral VM torn down after the job regardless of what is still running inside it. Chosen
/// well below `.config/nextest.toml`'s 180s `terminate-after` for this binary, so a genuine block
/// is diagnosed here and reported with context, rather than only visible as a bare timeout kill
/// with no diagnosis.
const SHELL_EXECUTE_BOUND: Duration = Duration::from_secs(60);

/// Runs `f` (a `shell_execute_with` call) on its own thread and waits for it, bounded by
/// `SHELL_EXECUTE_BOUND`. See that constant's doc for why a bound is warranted here at all, and why
/// hitting it is always a failure.
///
/// Returns `None` if `f` has not returned within the bound. `f` is the WHOLE `shell_execute_with`
/// call, not just its `ShellExecuteExW` invocation — when a launch hands back a process handle, `f`
/// also waits out, terminates, and reaps that child before returning (see `CHILD_EXIT_BOUND_MS`'s
/// doc), so `None` here does not by itself say which part ran long. Every call site below treats
/// `None` as a hard failure — it panics rather than drawing any conclusion about `lpFile`
/// resolution, since nothing about that question was actually measured when the call itself never
/// returned.
///
/// If `f` itself panics, the channel disconnects immediately rather than timing out — that is
/// reported here as what it is (a panic inside `f`, which DID return, by unwinding) rather than
/// folded into the `None`/bound-exceeded case, which would misreport a real panic as an unexplained
/// hang. The worker is joined (it has already finished panicking, so this cannot itself hang) and
/// its panic payload is propagated on this thread via `std::panic::resume_unwind`, so the original
/// panic message and location are what the test actually reports.
///
/// The spawned thread, if still blocked when the bound trips, is deliberately never joined or
/// killed: Rust has no API to force a thread out of a blocking syscall. Leaking it is safe because
/// `cargo nextest` gives every test its own OS process — the thread ends when that process does —
/// and because a GitHub-hosted Windows runner is an ephemeral VM torn down after the job regardless
/// of what is still running inside it.
fn shell_execute_bounded<F>(f: F) -> Option<Result<LaunchOutcome, String>>
where
    F: FnOnce() -> Result<LaunchOutcome, String> + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        // If the receiver already gave up (the bound elapsed), this send fails silently — there is
        // no one left to report the eventual result to.
        let _ = tx.send(f());
    });
    match rx.recv_timeout(SHELL_EXECUTE_BOUND) {
        Ok(result) => Some(result),
        Err(mpsc::RecvTimeoutError::Timeout) => None,
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

fn probe_dir(tag: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("probe needs a temp dir");
    let marker = dir.path().join(format!("{tag}-marker.txt"));
    (dir, marker)
}

/// **THE question.** `raw_executable("tool")` under `.elevate()` produces an `lpFile` that is
/// absolute, extensionless and quite possibly nonexistent — `raw_executable`'s contract forbids an
/// existence check. If `ShellExecuteEx` applies `PATHEXT` to a fully-qualified name, then a
/// `tool.bat` beside it runs through `cmd.exe`, past a batch gate that only ever saw the token
/// `tool`. The "an absolute `lpFile` is taken verbatim" fact this crate relies on was measured on
/// an existing `.exe`, which cannot distinguish the two behaviours.
#[test]
#[ignore = "executes a batch file; opt in with --ignored, on a throwaway runner only"]
fn does_shellexecute_apply_pathext_to_an_absolute_extensionless_lpfile() {
    let (dir, marker) = probe_dir("pathext");
    let bat = dir.path().join("tool.bat");
    plant_batch(&bat, &marker);
    let lp_file = dir.path().join("tool"); // absolute, extensionless, does not exist

    let outcome = shell_execute(&lp_file, None).expect("probe must be measurable");
    match outcome {
        LaunchOutcome::NotLaunched(e) if e.code() == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0) => {
            // A genuine negative: the shell looked for `tool` and found nothing to launch, which
            // is exactly what "PATHEXT is not applied" would look like.
            println!("PROBE absolute-extensionless-lpFile: launched=false ({e})");
            println!(
                "  => ShellExecuteEx does NOT extend an absolute lpFile. Completing the name is \
                 sufficient to close the search half, as cosca currently assumes."
            );
        }
        LaunchOutcome::NotLaunched(e) => panic!(
            "PROBE absolute-extensionless-lpFile: `tool` does not exist here, so ERROR_NO_ASSOCIATION \
             (or anything but ERROR_FILE_NOT_FOUND) is not the negative this probe measures: {e}"
        ),
        LaunchOutcome::LaunchedNoHandle => panic!(
            "PROBE absolute-extensionless-lpFile: INCONCLUSIVE — launched without a process handle, \
             so this probe could not wait for the batch to finish before reading its marker"
        ),
        LaunchOutcome::Waited => {
            let report = read_self_report(&marker);
            println!("PROBE absolute-extensionless-lpFile: launched=true self_report={report:?}");
            match report {
                Some(reported) if same_file(&reported, &bat) => println!(
                    "  => ShellExecuteEx DOES apply PATHEXT to an absolute lpFile. \
                     `raw_executable(\"tool\")` under .elevate() can reach a planted tool.bat; \
                     absolutising alone does NOT close the batch vector, and the gate must also run \
                     on the completed path."
                ),
                Some(reported) => panic!(
                    "PROBE absolute-extensionless-lpFile: INCONCLUSIVE — a marker was written, but \
                     it self-reports {} instead of the planted batch {} — something other than the \
                     planted batch ran",
                    reported.display(),
                    bat.display()
                ),
                None => panic!(
                    "PROBE absolute-extensionless-lpFile: INCONCLUSIVE — the shell waited on a real \
                     process, but no marker was ever written, so what actually ran cannot be \
                     confirmed"
                ),
            }
        }
    }
    mark_probe_passed();
}

/// Control for the probe above: an absolute path to a real `.bat` must launch. If this does not
/// run, the probe harness itself is broken — the shell is not launching anything in this
/// environment — and the negative result above would be meaningless.
#[test]
#[ignore = "executes a batch file; opt in with --ignored, on a throwaway runner only"]
fn control_an_absolute_batch_path_does_launch() {
    let (dir, marker) = probe_dir("control");
    let bat = dir.path().join("tool.bat");
    plant_batch(&bat, &marker);

    let outcome = shell_execute(&bat, None).expect("probe must be measurable");
    match outcome {
        LaunchOutcome::NotLaunched(e) => panic!(
            "PROBE control-absolute-bat: the shell declined to launch anything ({e}), so the harness \
             cannot launch a batch file at all — fix the harness before reading the PATHEXT probe's \
             result"
        ),
        LaunchOutcome::LaunchedNoHandle => panic!(
            "PROBE control-absolute-bat: INCONCLUSIVE — launched without a process handle, so this \
             control could not wait for the batch to finish before checking its marker; fix the \
             harness before reading the PATHEXT probe's result"
        ),
        LaunchOutcome::Waited => {
            let report = read_self_report(&marker);
            println!("PROBE control-absolute-bat: launched=true self_report={report:?}");
            match report {
                Some(reported) if same_file(&reported, &bat) => {}
                Some(reported) => panic!(
                    "the harness launched something, but the marker self-reports {} instead of the \
                     planted batch {} — fix the harness before reading the PATHEXT probe's result",
                    reported.display(),
                    bat.display()
                ),
                None => panic!(
                    "the harness cannot launch a batch file at all, so the PATHEXT probe's result is \
                     not interpretable — fix the harness before reading it"
                ),
            }
        }
    }
    mark_probe_passed();
}

/// The other half of the elevated hazard, re-measured rather than inherited: a PATH-LESS `lpFile`
/// is documented to assume the current directory, and `lpDirectory` is consulted as a search
/// location. This is what makes completing the name necessary in the first place.
#[test]
#[ignore = "executes a batch file; opt in with --ignored, on a throwaway runner only"]
fn does_shellexecute_search_lpdirectory_for_a_pathless_lpfile() {
    let (dir, marker) = probe_dir("lpdir");
    let bat = dir.path().join("tool.bat");
    plant_batch(&bat, &marker);

    // Path-less, extensionless: only a search can find anything.
    let outcome = shell_execute(Path::new("tool"), Some(dir.path())).expect("probe must be measurable");
    match outcome {
        LaunchOutcome::NotLaunched(e) if e.code() == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0) => {
            println!("PROBE pathless-lpFile-with-lpDirectory: launched=false ({e})");
            println!(
                "  => NOT reproduced here. The premise behind resolving before ShellExecuteEx is not \
                 holding in this environment; re-examine it before relying on it."
            );
        }
        LaunchOutcome::NotLaunched(e) => panic!(
            "PROBE pathless-lpFile-with-lpDirectory: `tool` cannot exist as a bare name in this \
             directory (only `tool.bat` was planted), so ERROR_NO_ASSOCIATION (or anything but \
             ERROR_FILE_NOT_FOUND) is not the negative this probe measures: {e}"
        ),
        LaunchOutcome::LaunchedNoHandle => panic!(
            "PROBE pathless-lpFile-with-lpDirectory: INCONCLUSIVE — launched without a process \
             handle, so this probe could not wait for the batch to finish before reading its marker"
        ),
        LaunchOutcome::Waited => {
            let report = read_self_report(&marker);
            println!("PROBE pathless-lpFile-with-lpDirectory: launched=true self_report={report:?}");
            match report {
                Some(reported) if same_file(&reported, &bat) => println!(
                    "  => confirmed: a path-less lpFile is searched, PATHEXT applied and lpDirectory \
                     consulted. This is the hazard the elevated path closes by completing the name."
                ),
                Some(reported) => panic!(
                    "PROBE pathless-lpFile-with-lpDirectory: INCONCLUSIVE — a marker was written, but \
                     it self-reports {} instead of the planted batch {} — something other than the \
                     planted batch ran",
                    reported.display(),
                    bat.display()
                ),
                None => panic!(
                    "PROBE pathless-lpFile-with-lpDirectory: INCONCLUSIVE — the shell waited on a \
                     real process, but no marker was ever written, so what actually ran cannot be \
                     confirmed"
                ),
            }
        }
    }
    mark_probe_passed();
}

// ── the trailing-dot convention ──────────────────────────────────────────────────────
//
// `CreateProcessW` documents, for its command-line mode: "If the file name ends in a period (.)
// with no extension ... .exe is not appended." So Win32 has a spelling for "this name is
// COMPLETE, do not extend it" — and the filesystem strips the trailing dot when opening, so the
// literal file still resolves. If `ShellExecuteEx` honours the same convention, it is exactly the
// marker cosca's `Exact` arm needs: a way to hand over a name that cannot grow a `.bat`.
//
// Both halves have to hold. A dot that suppresses PATHEXT but fails to open the intended file is
// useless, and a dot that opens the file but still extends it closes nothing.

/// Half one: does a trailing dot SUPPRESS the PATHEXT extension that the probe above measured?
#[test]
#[ignore = "executes a batch file; opt in with --ignored, on a throwaway runner only"]
fn does_a_trailing_dot_suppress_pathext_on_an_absolute_lpfile() {
    let (dir, marker) = probe_dir("dot-suppress");
    let bat = dir.path().join("tool.bat");
    plant_batch(&bat, &marker);
    let lp_file = dir.path().join("tool."); // the "complete name" spelling

    let outcome = shell_execute(&lp_file, None).expect("probe must be measurable");
    match outcome {
        LaunchOutcome::NotLaunched(e) if e.code() == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0) => {
            // A genuine negative: the shell found nothing at all for `tool.`, meaning it did not
            // fall through to a PATHEXT-extended `tool.bat`.
            println!("PROBE trailing-dot-suppresses-pathext: launched=false ({e})");
            println!("  => YES. The dot suppressed the PATHEXT search — the .bat did NOT run.");
        }
        LaunchOutcome::NotLaunched(e) => panic!(
            "PROBE trailing-dot-suppresses-pathext: `tool.` does not exist here (only `tool.bat` was \
             planted), so ERROR_NO_ASSOCIATION (or anything but ERROR_FILE_NOT_FOUND) is not the \
             negative this probe measures: {e}"
        ),
        LaunchOutcome::LaunchedNoHandle => panic!(
            "PROBE trailing-dot-suppresses-pathext: INCONCLUSIVE — launched without a process \
             handle, so this probe could not wait for the batch to finish before reading its marker"
        ),
        LaunchOutcome::Waited => {
            let report = read_self_report(&marker);
            println!("PROBE trailing-dot-suppresses-pathext: launched=true self_report={report:?}");
            match report {
                Some(reported) if same_file(&reported, &bat) => {
                    println!("  => NO. The dot does not suppress PATHEXT; the planted .bat still ran.");
                }
                Some(reported) => panic!(
                    "PROBE trailing-dot-suppresses-pathext: INCONCLUSIVE — a marker was written, but \
                     it self-reports {} instead of the planted batch {} — something other than the \
                     planted batch ran",
                    reported.display(),
                    bat.display()
                ),
                None => panic!(
                    "PROBE trailing-dot-suppresses-pathext: INCONCLUSIVE — the shell waited on a \
                     real process, but no marker was ever written, so what actually ran cannot be \
                     confirmed"
                ),
            }
        }
    }
    mark_probe_passed();
}

/// Half two: does a trailing dot still OPEN the extensionless file it names? Uses a copy of
/// `cosca_testbin_image`, renamed to the extensionless `tool`, invoked with `--report-to` — a
/// report means the real image was loaded through the dotted spelling; the image self-reports which
/// file it is, since a post-exit OS query cannot (see `shell_execute_with`'s doc). An extensionless
/// target may also get no process handle at all (`LaunchOutcome::LaunchedNoHandle`) or fail
/// synchronously with `ERROR_NO_ASSOCIATION` — both are the expected, measured negative for this
/// half (see those arms below), not a harness failure; see the module doc for why both can happen
/// for the same underlying fact.
///
/// `ShellExecuteExW` itself can fail to return at all rather than ever completing — see the module
/// doc for what is and is not established about that hang. `CHILD_EXIT_BOUND_MS` cannot cover this —
/// it only bounds the wait AFTER a handle is obtained — so this call is wrapped in
/// `shell_execute_bounded` instead, bounded by `SHELL_EXECUTE_BOUND`. Hitting that bound is a hard
/// failure here, never a conclusion about whether the dotted spelling opens the file: see
/// `SHELL_EXECUTE_BOUND`'s doc.
#[test]
#[ignore = "launches a copied payload binary; opt in with --ignored, on a throwaway runner only"]
fn does_a_trailing_dot_still_open_the_extensionless_file() {
    let (dir, marker) = probe_dir("dot-opens");
    let image_bin = PathBuf::from(env!("CARGO_BIN_EXE_cosca_testbin_image"));
    let extensionless = dir.path().join("tool");
    std::fs::copy(&image_bin, &extensionless).expect("copy cosca_testbin_image to an extensionless name");

    let dotted = dir.path().join("tool.");
    let params = format!("--report-to \"{}\"", marker.display());
    let outcome = {
        let dotted = dotted.clone();
        let params = params.clone();
        shell_execute_bounded(move || shell_execute_with(&dotted, None, Some(&params)))
    };
    let Some(outcome) = outcome else {
        panic!(
            "PROBE trailing-dot-opens-extensionless: ShellExecuteExW did not return within \
             {SHELL_EXECUTE_BOUND:?}; this probe could not be measured"
        );
    };
    let outcome = outcome.expect("probe must be measurable");
    match outcome {
        LaunchOutcome::NotLaunched(e) if e.code() == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0) => {
            println!("PROBE trailing-dot-opens-extensionless: launched=false ({e})");
            println!(
                "  => NO. The dotted spelling did not resolve to anything at all, so it cannot be \
                 used as a complete-path marker even if it suppresses PATHEXT."
            );
        }
        LaunchOutcome::NotLaunched(e) if e.code() == HRESULT::from_win32(ERROR_NO_ASSOCIATION.0) => {
            // Same fact as the LaunchedNoHandle arm below, just returned synchronously instead of as
            // a UI handoff: the dotted spelling DID resolve to the extensionless file — otherwise
            // this would be ERROR_FILE_NOT_FOUND — but there is nothing to hand it to. Checked the
            // same way as its siblings (`marker.exists()`), not by content: this probe's marker path
            // is unique to this run, so existence alone already means the extensionless file ran.
            let exe_ran = marker.exists();
            println!(
                "PROBE trailing-dot-opens-extensionless: launched=false, no association ({e}) \
                 exe_ran={exe_ran}"
            );
            if exe_ran {
                panic!(
                    "PROBE trailing-dot-opens-extensionless: the marker exists despite this call's \
                     synchronous ERROR_NO_ASSOCIATION. That this call itself returned no handle to \
                     hand off to anything is authoritative — a synchronous fact from the API's return \
                     value — but the marker existing anyway means the extensionless file ran through \
                     some path this probe did not account for; failing rather than noting it and \
                     moving on, matching does_an_existing_extensionless_file_ever_launch_directly."
                );
            }
            println!(
                "  => NO, not as a directly-run process. The dotted spelling still resolves to the \
                 extensionless file rather than falling through to ERROR_FILE_NOT_FOUND, but an \
                 extensionless target is never executed directly regardless of spelling — the shell \
                 reported ERROR_NO_ASSOCIATION rather than handing it to a picker. This is the \
                 expected, measured negative for an extensionless target — see \
                 LaunchOutcome::LaunchedNoHandle's doc for the handoff variant of this same fact."
            );
        }
        LaunchOutcome::NotLaunched(e) => panic!(
            "PROBE trailing-dot-opens-extensionless: unexpected error (not ERROR_FILE_NOT_FOUND or \
             ERROR_NO_ASSOCIATION): {e}"
        ),
        LaunchOutcome::LaunchedNoHandle => {
            let exe_ran = marker.exists();
            println!(
                "PROBE trailing-dot-opens-extensionless: launched=true, no process handle \
                 (LaunchedNoHandle) exe_ran={exe_ran} (an instantaneous, racy snapshot taken right \
                 after the call returned — no process handle means nothing here waits for a \
                 handed-off process before reading the marker)"
            );
            if exe_ran {
                panic!(
                    "PROBE trailing-dot-opens-extensionless: the marker exists despite this call \
                     returning no process handle to wait on. That this call itself returned no \
                     handle is authoritative — a synchronous fact from the API's return value, not a \
                     snapshot — but the marker existing anyway means it ran through some path this \
                     probe did not account for; failing rather than noting it and moving on, matching \
                     does_an_existing_extensionless_file_ever_launch_directly."
                );
            }
            println!(
                "  => NO, not as a directly-run process. The dotted spelling still resolves to the \
                 extensionless file rather than falling through to ERROR_FILE_NOT_FOUND, but an \
                 extensionless target is never executed directly regardless of spelling — it is \
                 handed to an association handler with no process handle, so it cannot be waited on, \
                 terminated, or contained. This is the expected, measured negative for an \
                 extensionless target — see LaunchOutcome::LaunchedNoHandle's doc."
            );
        }
        LaunchOutcome::Waited => {
            let report = read_self_report_image(&marker);
            println!("PROBE trailing-dot-opens-extensionless: launched=true self_report={report:?}");
            match report {
                Some(reported) if same_file(&reported, &extensionless) => {
                    println!("  => YES. `<dir>\\tool.` loads the extensionless `<dir>\\tool`.");
                }
                Some(reported) => panic!(
                    "PROBE trailing-dot-opens-extensionless: INCONCLUSIVE — the self-report names {} \
                     instead of the extensionless file {} this probe planted; the dotted spelling \
                     opened something other than the intended file",
                    reported.display(),
                    extensionless.display()
                ),
                None => panic!(
                    "PROBE trailing-dot-opens-extensionless: INCONCLUSIVE — the shell waited on a \
                     real process, but it never wrote a report, so what actually ran cannot be \
                     confirmed"
                ),
            }
        }
    }
    mark_probe_passed();
}

/// **Decides whether this is an `Exact`-only problem or a whole-resolver problem.**
///
/// cosca's resolver can return an absolute EXTENSIONLESS path: a located name like `./myapp`
/// where `myapp` exists with no extension resolves to exactly that, having passed `is_file()`.
/// If PATHEXT outranks an existing extensionless file, then the `Search` arm carries the same
/// hazard as `Exact`, and no amount of resolving fixes it.
///
/// The `.bat` self-reports its own path (`%~f0`) into its marker, and the extensionless copy of
/// `cosca_testbin_image` self-reports the image it loaded via `--report-to` — each into its own
/// marker file, so whichever one ran is the only one that could have written to it. No post-exit OS
/// query is needed to corroborate which image ran, unlike an earlier version of this probe that
/// relied on one (and, separately, was contaminated by a redirect in `lpParameters` that the outer
/// `cmd.exe` would consume — the `--report-to`/`%~f0` scheme has no redirection to contaminate).
///
/// This gives `ShellExecuteExW` the same existing extensionless target as the two probes above, so
/// it is wrapped in `shell_execute_bounded` too, as a precaution — this probe itself was not
/// observed to hang; see the module doc for what actually was. If `ShellExecuteExW` does fail to
/// return here, that is a hard failure (see `SHELL_EXECUTE_BOUND`'s doc): this probe never infers
/// precedence from a call that never returned.
///
/// `SEE_MASK_NOASYNC` is always set on this call too (see `shell_execute_in_apartment`'s doc), so a
/// `LaunchedNoHandle` or `ERROR_NO_ASSOCIATION` return here is a synchronous, complete fact: the
/// shell finished this call without ever handing back a process handle. A real `tool.bat` launch
/// always goes through `cmd.exe`, which always yields one — so no handle from THIS call already
/// rules out `.bat` having won through it, regardless of whether the extensionless file itself can
/// be confirmed to have run. `report_no_handle` below draws exactly that conclusion, and fails
/// instead if either marker suggests otherwise.
#[test]
#[ignore = "executes a batch file; opt in with --ignored, on a throwaway runner only"]
fn does_pathext_outrank_an_existing_extensionless_file() {
    let dir = tempfile::tempdir().expect("probe needs a temp dir");
    let exe_marker = dir.path().join("precedence-exe.txt");
    let bat_marker = dir.path().join("precedence-bat.txt");

    let bat = dir.path().join("tool.bat");
    plant_batch(&bat, &bat_marker);

    let image_bin = PathBuf::from(env!("CARGO_BIN_EXE_cosca_testbin_image"));
    let extensionless = dir.path().join("tool");
    std::fs::copy(&image_bin, &extensionless).expect("copy cosca_testbin_image to an extensionless name");

    // Inert if the shell instead routes to tool.bat: the planted batch ignores its arguments.
    let params = format!("--report-to \"{}\"", exe_marker.display());
    let outcome = {
        let extensionless = extensionless.clone();
        let params = params.clone();
        shell_execute_bounded(move || shell_execute_with(&extensionless, None, Some(&params)))
    };
    let Some(outcome) = outcome else {
        panic!(
            "PROBE pathext-vs-existing-extensionless: ShellExecuteExW did not return within \
             {SHELL_EXECUTE_BOUND:?}; this probe could not be measured — precedence is never inferred \
             from a call that never returned"
        );
    };
    let outcome = outcome.expect("probe must be measurable");
    // Shared by the LaunchedNoHandle and ERROR_NO_ASSOCIATION arms below: both mean this call
    // returned without ever handing this probe a process handle to wait on. With SEE_MASK_NOASYNC
    // always set (see this function's doc), that absence is itself the synchronous, measured
    // conclusion: a real tool.bat launch through cmd.exe always yields a process handle, so no
    // handle here already means PATHEXT did not outrank the existing extensionless file through
    // this call. Either marker existing anyway contradicts that and is treated as a failure, not a
    // note to look into later.
    let report_no_handle = |via: &str| {
        let exe_ran = exe_marker.exists();
        let bat_ran = read_self_report(&bat_marker).is_some_and(|r| same_file(&r, &bat));
        println!(
            "PROBE pathext-vs-existing-extensionless: outcome={via} exe_ran={exe_ran} \
             bat_ran={bat_ran}"
        );
        if exe_ran || bat_ran {
            panic!(
                "PROBE pathext-vs-existing-extensionless: {via} means ShellExecuteExW returned no \
                 process handle for this call. With SEE_MASK_NOASYNC always set (see \
                 shell_execute_in_apartment's doc) that is a synchronous, complete fact, not a \
                 race: neither tool nor tool.bat should have run through it — a real launch of \
                 either always yields a handle (cmd.exe for tool.bat; \
                 does_an_existing_extensionless_file_ever_launch_directly establishes the same \
                 floor for the extensionless target). exe_ran={exe_ran} bat_ran={bat_ran} \
                 contradicts that, so this is treated as a failure here, not a note to look into \
                 later."
            );
        }
        println!(
            "  => {via}: no handle means the shell chose to hand the extensionless file off (or \
             refuse it outright) rather than launch tool.bat, since a real .bat launch through \
             cmd.exe always yields a process handle. PATHEXT did not outrank the existing \
             extensionless file through this call."
        );
    };
    match outcome {
        LaunchOutcome::NotLaunched(e) if e.code() == HRESULT::from_win32(ERROR_NO_ASSOCIATION.0) => {
            report_no_handle(&format!("no association ({e})"));
        }
        LaunchOutcome::NotLaunched(e) => panic!(
            "PROBE pathext-vs-existing-extensionless: the shell declined to launch anything with an \
             unexpected error (not ERROR_NO_ASSOCIATION): {e} — both `tool` and `tool.bat` exist \
             here, so precedence could not be measured"
        ),
        LaunchOutcome::LaunchedNoHandle => {
            report_no_handle("no process handle (LaunchedNoHandle)");
        }
        LaunchOutcome::Waited => {
            let exe_ran = exe_marker.exists();
            let bat_ran = read_self_report(&bat_marker).is_some_and(|r| same_file(&r, &bat));
            println!("PROBE pathext-vs-existing-extensionless: launched=true exe_ran={exe_ran} bat_ran={bat_ran}");
            match (exe_ran, bat_ran) {
                (true, false) => panic!(
                    "PROBE pathext-vs-existing-extensionless: UNREACHABLE per the measured platform \
                     fact that ShellExecuteEx never runs an extensionless lpFile directly (see \
                     LaunchOutcome::LaunchedNoHandle's doc and \
                     does_an_existing_extensionless_file_ever_launch_directly) — yet the extensionless \
                     copy waited on a real process handle here. Either the platform's behaviour has \
                     changed, or the exe marker was written by something other than the extensionless \
                     copy; this probe cannot tell which, so it fails rather than guess."
                ),
                (false, true) => println!(
                    "  => PATHEXT OUTRANKS the existing extensionless file: cmd.exe ran the planted \
                     .bat, not the copy at the extensionless name. The .bat wins even though the exact \
                     named file is present, so resolving to an absolute extensionless path is unsafe \
                     on BOTH arms — `Search` included. Any absolute lpFile without a loadable \
                     extension is plantable."
                ),
                (true, true) => panic!(
                    "PROBE pathext-vs-existing-extensionless: INCONCLUSIVE — both markers set; the \
                     probe is still contaminated and its result cannot be trusted"
                ),
                (false, false) => panic!(
                    "PROBE pathext-vs-existing-extensionless: nothing ran, so precedence could not be \
                     measured — the probe is not interpretable"
                ),
            }
        }
    }
    mark_probe_passed();
}

/// Companion to the precedence probe above, with no `.bat` in the directory to compete: does an
/// EXISTING extensionless file ever get run directly by `ShellExecuteEx`, when nothing else present
/// could satisfy `PATHEXT`? Measured: no, on this call — the shell hands it to an association/
/// Open-With handler (`LaunchOutcome::LaunchedNoHandle`), or fails synchronously with
/// `ERROR_NO_ASSOCIATION` where `SEE_MASK_FLAG_NO_UI` actually suppresses the picker. `ShellExecuteExW`
/// can also fail to return at all — see the module doc for what is and is not established about
/// that. Hitting `SHELL_EXECUTE_BOUND` below is a hard failure, never a conclusion. This probe
/// deliberately plants no competing `.bat`, so it says nothing about what happens when something
/// else COULD satisfy `PATHEXT` beside an existing extensionless file — that is what
/// `does_pathext_outrank_an_existing_extensionless_file` measures instead. This was originally
/// written as a control expected to always launch; it does not, and that failure to launch — a
/// genuine negative, not a harness bug — IS the answer. Both probes hand `ShellExecuteExW` the same
/// existing extensionless target, and both always set `SEE_MASK_NOASYNC` (see
/// `shell_execute_in_apartment`'s doc), so a no-handle outcome from either is itself a synchronous,
/// measured fact from the API's return, not a race. That sibling probe uses the same no-handle
/// outcome from its own call to draw a precedence conclusion (`.bat` never got a tracked process
/// handle through it either); see its doc.
///
/// A no-handle outcome here does not, by itself, prove the file never ran: the marker check right
/// after such an outcome is an instantaneous, racy snapshot — nothing waits for a handed-off process
/// before reading it. If that marker is ever found set anyway, this probe treats it as a failure,
/// not a note: this crate's contract needs a definite answer for whether an existing extensionless
/// target can run without ever handing back a process handle, and "unexplained, not asserted as
/// impossible" is not a definite answer.
#[test]
#[ignore = "launches a copied payload binary; opt in with --ignored, on a throwaway runner only"]
fn does_an_existing_extensionless_file_ever_launch_directly() {
    let dir = tempfile::tempdir().expect("probe needs a temp dir");
    let exe_marker = dir.path().join("no-bat-marker.txt");

    let image_bin = PathBuf::from(env!("CARGO_BIN_EXE_cosca_testbin_image"));
    let extensionless = dir.path().join("tool");
    std::fs::copy(&image_bin, &extensionless).expect("copy cosca_testbin_image to an extensionless name");
    // Deliberately no tool.bat: nothing else in this directory could satisfy PATHEXT.

    let params = format!("--report-to \"{}\"", exe_marker.display());
    let outcome = {
        let extensionless = extensionless.clone();
        let params = params.clone();
        shell_execute_bounded(move || shell_execute_with(&extensionless, None, Some(&params)))
    };
    let Some(outcome) = outcome else {
        panic!(
            "PROBE existing-extensionless-no-bat: ShellExecuteExW did not return within \
             {SHELL_EXECUTE_BOUND:?}; this probe could not be measured"
        );
    };
    let outcome = outcome.expect("probe must be measurable");
    match outcome {
        LaunchOutcome::NotLaunched(e) if e.code() == HRESULT::from_win32(ERROR_NO_ASSOCIATION.0) => {
            let exe_ran = exe_marker.exists();
            println!(
                "PROBE existing-extensionless-no-bat: launched=false, no association ({e}) \
                 exe_ran={exe_ran} (an instantaneous, racy snapshot taken right after the call \
                 returned — no process handle means nothing here waits for a handed-off process \
                 before reading the marker)."
            );
            if exe_ran {
                panic!(
                    "PROBE existing-extensionless-no-bat: the exe marker exists despite this call's \
                     synchronous ERROR_NO_ASSOCIATION. That this call itself returned no process \
                     handle is authoritative — a synchronous fact from the API's return value, not a \
                     snapshot — but the marker existing anyway means the extensionless file ran \
                     through some path this probe did not account for; failing rather than noting it \
                     and moving on."
                );
            }
            println!(
                "  => NO, as far as THIS call is concerned. ShellExecuteEx did not run the existing \
                 extensionless file directly through this call, even when nothing else in the \
                 directory could satisfy PATHEXT: it reported ERROR_NO_ASSOCIATION synchronously \
                 rather than handing off to a picker — the same fact as the LaunchedNoHandle arm \
                 below, just surfaced differently (see the module doc). It also means anything the \
                 shell refuses this way can never be contained by cosca — there is no process handle \
                 to assign to a Job Object."
            );
        }
        LaunchOutcome::NotLaunched(e) => panic!(
            "PROBE existing-extensionless-no-bat: the shell declined to launch anything with an \
             unexpected error (not ERROR_NO_ASSOCIATION): {e} — the file exists here, so \
             ERROR_FILE_NOT_FOUND would also be unexpected — so the harness itself appears to be \
             broken"
        ),
        LaunchOutcome::LaunchedNoHandle => {
            let exe_ran = exe_marker.exists();
            println!(
                "PROBE existing-extensionless-no-bat: launched=true, no process handle \
                 (LaunchedNoHandle) exe_ran={exe_ran} (an instantaneous, racy snapshot taken right \
                 after the call returned — no process handle means nothing here waits for a \
                 handed-off process before reading the marker)."
            );
            if exe_ran {
                panic!(
                    "PROBE existing-extensionless-no-bat: the exe marker exists despite this call \
                     returning no process handle to wait on. That this call itself returned no \
                     handle is authoritative — a synchronous fact from the API's return value, not a \
                     snapshot — but the marker existing anyway means the extensionless file ran \
                     through some path this probe did not account for; failing rather than noting it \
                     and moving on."
                );
            }
            println!(
                "  => NO, as far as THIS call is concerned. ShellExecuteEx did not run the existing \
                 extensionless file directly through this call, even when nothing else in the \
                 directory could satisfy PATHEXT. It hands the file to an association/Open-With \
                 handler instead, which returns no process handle. It also means anything the shell \
                 hands off to this way can never be contained by cosca — there is no process handle \
                 to assign to a Job Object."
            );
        }
        LaunchOutcome::Waited => {
            let report = read_self_report_image(&exe_marker);
            println!("PROBE existing-extensionless-no-bat: launched=true self_report={report:?}");
            match report {
                Some(reported) if same_file(&reported, &extensionless) => panic!(
                    "PROBE existing-extensionless-no-bat: the shell DID run the extensionless file \
                     directly here (confirmed by its self-report, {}), contradicting the measured \
                     platform fact this crate's docs and \
                     does_pathext_outrank_an_existing_extensionless_file's `(true, false)` panic rely \
                     on. Re-examine both before trusting either.",
                    reported.display()
                ),
                Some(reported) => panic!(
                    "PROBE existing-extensionless-no-bat: INCONCLUSIVE — the shell waited on a real \
                     process and a report was written, but it self-reports {} instead of the planted \
                     extensionless file {} — something else ran",
                    reported.display(),
                    extensionless.display()
                ),
                None => panic!(
                    "PROBE existing-extensionless-no-bat: INCONCLUSIVE — the shell waited on a real \
                     process, but no report was ever written, so what actually ran cannot be confirmed"
                ),
            }
        }
    }
    mark_probe_passed();
}
