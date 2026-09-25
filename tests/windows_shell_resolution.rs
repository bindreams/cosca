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
//! `does_a_trailing_dot_still_open_the_extensionless_file` did exactly that, on both architectures,
//! in run 36117246246 — so an inconclusive run is now a hard failure everywhere it is genuinely
//! inconclusive. That handoff (`LaunchOutcome::LaunchedNoHandle`) is NOT always inconclusive,
//! though: for an EXTENSIONLESS `lpFile` it is itself the measured answer — `ShellExecuteEx` never
//! runs an extensionless file as a program, existing or not, so getting no process handle back is
//! exactly what should happen, and every probe that plants an extensionless target says so
//! explicitly at that arm. Whatever the shell hands off to this way can never be contained by
//! cosca either, since no process handle is ever returned to assign to a Job Object.
//!
//! Every call sets `SEE_MASK_FLAG_NO_UI` for exactly this reason: these probes measure `lpFile`
//! RESOLUTION, not a human's answer to a picker dialog, and must run unattended on a CI runner
//! where no one is there to click one. The flag does not guarantee no UI ever appears — measured in
//! run 36125783666: `does_an_existing_extensionless_file_ever_launch_directly` got
//! `LaunchedNoHandle` on `windows-11-arm` (no UI, a clean handoff), but on `windows-latest` (x64) the
//! same extensionless target's "how do you want to open this?" picker still appeared despite the
//! flag, and `ShellExecuteExW` blocked inside the API waiting on it rather than ever returning —
//! there, before this round's fix, the test ran to the full 300s per-test bound and was killed.
//! Where the flag *does* suppress the picker, the shell instead returns `ERROR_NO_ASSOCIATION`
//! synchronously — so that code, exactly like `ERROR_FILE_NOT_FOUND`, is a genuine measured negative
//! for a probe whose target is itself extensionless, not a harness failure; each such probe's
//! `NotLaunched` arm says so explicitly. Every call site that hands `ShellExecuteExW` an EXISTING
//! extensionless target now also bounds the whole call in-process, via `shell_execute_bounded` and
//! `UI_BLOCK_BOUND` — well under `.config/nextest.toml`'s 300s per-test bound — so a block like this
//! one is itself the measured answer, printed and passed, rather than depending on nextest's outer
//! bound to kill the process and report a bare timeout with no diagnosis.
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
/// This bound does not cover `ShellExecuteExW` itself blocking before it ever returns a handle
/// (measured: it can, for an existing extensionless target — see `UI_BLOCK_BOUND`'s doc). Every
/// call site that hands `ShellExecuteExW` an existing extensionless target bounds that separately,
/// via `shell_execute_bounded`.
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
    /// handler. `SHELLEXECUTEINFOW` carries no PID in this case, only the `hProcess` that is
    /// exactly what's missing, so there is no handle here to terminate or wait on — nothing tells
    /// this probe whether the handed-off process has finished, so reading a marker now would be a
    /// race, not a measurement. Most probes below treat this as a failed measurement, but the ones
    /// whose own target is specifically extensionless treat it as the expected, measured negative —
    /// say so explicitly at each such arm. Either way, whatever the shell hands off to this way can
    /// never be contained by cosca: there is no process handle here to assign to a Job Object.
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
/// and report what could be measured.
fn shell_execute(lp_file: &Path, lp_directory: Option<&Path>) -> Result<LaunchOutcome, String> {
    shell_execute_with(lp_file, lp_directory, None)
}

fn shell_execute_with(
    lp_file: &Path,
    lp_directory: Option<&Path>,
    lp_parameters: Option<&str>,
) -> Result<LaunchOutcome, String> {
    let file_w = wide_nul(lp_file.as_os_str());
    let dir_w = lp_directory.map(|d| wide_nul(d.as_os_str()));
    let params_w = lp_parameters.map(|p| wide_nul(std::ffi::OsStr::new(p)));

    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
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

/// The failure bound for `ShellExecuteExW` itself never returning: measured on `windows-latest`
/// (x64) in run 36125783666, an existing extensionless target can make the shell try to show its
/// "how do you want to open this?" picker despite `SEE_MASK_FLAG_NO_UI`, and the call blocks inside
/// the API waiting for a human who is never there on an unattended CI runner. Win32 gives this
/// process no way to cancel a call already inside `ShellExecuteExW`, so the call's return is a
/// genuinely external event this code cannot synchronize on — bounding it is the sanctioned
/// exception to "don't synchronize via time", not a race against a clock this process controls.
/// Chosen well below `.config/nextest.toml`'s 300s `terminate-after` for this binary, so a genuine
/// block is this probe's own clean, measured PASS rather than a bare process kill with no
/// diagnosis.
const UI_BLOCK_BOUND: Duration = Duration::from_secs(60);

/// Runs `f` (a `shell_execute_with` call) on its own thread and waits for it, bounded by
/// `UI_BLOCK_BOUND`. See `UI_BLOCK_BOUND`'s doc for why a bound is warranted here at all.
///
/// Returns `None` if `f` has not returned within the bound. The CALLER treats that itself as the
/// measured answer — "the shell blocked rather than ever resolving this target" — not a harness
/// failure; every call site below prints that conclusion and passes rather than panicking.
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
    std::thread::spawn(move || {
        // If the receiver already gave up (the bound elapsed), this send fails silently — there is
        // no one left to report the eventual result to.
        let _ = tx.send(f());
    });
    rx.recv_timeout(UI_BLOCK_BOUND).ok()
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
/// `ShellExecuteExW` itself can block on this exact input rather than ever returning — measured on
/// `windows-latest`, where it hung with no output past a 30-minute job timeout (run 36120443833).
/// `CHILD_EXIT_BOUND_MS` cannot cover this: it only bounds the wait AFTER a handle is obtained.
/// `shell_execute_bounded` bounds the call itself instead — see its doc and `UI_BLOCK_BOUND`'s.
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
        println!(
            "PROBE trailing-dot-opens-extensionless: BLOCKED — ShellExecuteExW did not return \
             within {UI_BLOCK_BOUND:?}, despite SEE_MASK_FLAG_NO_UI"
        );
        println!(
            "  => the shell itself blocked trying to show UI for this dotted, extensionless target \
             rather than ever resolving it (measured on windows-latest/x64 in run 36125783666, for \
             the same underlying extensionless-target fact — see shell_execute_bounded's doc). This \
             IS the measured answer here too: the dotted spelling does not open the extensionless \
             file as a directly-run process on this architecture either — nothing here was \
             contained, since nothing here ever became a process this probe could observe."
        );
        return;
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
            // this would be ERROR_FILE_NOT_FOUND — but there is nothing to hand it to.
            println!("PROBE trailing-dot-opens-extensionless: launched=false, no association ({e})");
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
            println!(
                "PROBE trailing-dot-opens-extensionless: launched=true, no process handle \
                 (LaunchedNoHandle)"
            );
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
/// it is wrapped in `shell_execute_bounded` too: on the architecture where the shell blocks inside
/// the API instead of resolving it (measured on `windows-latest`/x64 in run 36125783666 — see
/// `UI_BLOCK_BOUND`'s doc), that block is itself the measured answer for precedence, not a harness
/// failure.
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
        println!(
            "PROBE pathext-vs-existing-extensionless: BLOCKED — ShellExecuteExW did not return \
             within {UI_BLOCK_BOUND:?}, despite SEE_MASK_FLAG_NO_UI"
        );
        println!(
            "  => the shell itself blocked trying to show UI for the existing extensionless target \
             rather than ever resolving it — including never searching PATHEXT for the planted \
             `tool.bat` beside it (measured on windows-latest/x64 in run 36125783666, for the same \
             underlying extensionless-target fact — see shell_execute_bounded's doc). This IS the \
             measured answer here too: PATHEXT cannot outrank an existing extensionless file if the \
             shell never gets past trying to resolve the extensionless target's own handoff. Neither \
             image ran as a process here, and nothing was contained, since blocking inside \
             ShellExecuteExW yields no process handle either."
        );
        return;
    };
    let outcome = outcome.expect("probe must be measurable");
    // Shared by the LaunchedNoHandle and ERROR_NO_ASSOCIATION arms below: both mean "the shell
    // resolved `tool`'s own handoff and never even searched PATHEXT for `tool.bat` beside it" — the
    // same fact, reported through two different mechanisms (see the module doc).
    let report_neither_ran = |via: &str| {
        let exe_ran = exe_marker.exists();
        let bat_ran = read_self_report(&bat_marker).is_some_and(|r| same_file(&r, &bat));
        println!("PROBE pathext-vs-existing-extensionless: launched=true, {via} exe_ran={exe_ran} bat_ran={bat_ran}");
        assert!(
            !exe_ran,
            "PROBE pathext-vs-existing-extensionless: UNREACHABLE — the shell reported {via} for an \
             extensionless target, yet the exe marker exists. An extensionless target is never run \
             directly (see LaunchOutcome::LaunchedNoHandle's doc), so nothing should have been able \
             to write this marker."
        );
        assert!(
            !bat_ran,
            "PROBE pathext-vs-existing-extensionless: INCONCLUSIVE — the shell reported {via}, yet \
             the .bat's marker also exists — a real cmd.exe launch of the .bat always yields a \
             process handle, which cannot coexist with that."
        );
        println!(
            "  => the extensionless target's own handoff resolution wins outright: ShellExecuteEx \
             resolved `tool` without ever searching PATHEXT for `tool.bat` beside it. Neither image \
             ran as a process here, so this exact vector is not plantable through a direct launch — \
             but nothing here was contained either, since neither a handoff nor a bare error yields a \
             process handle (see LaunchOutcome::LaunchedNoHandle's doc)."
        );
    };
    match outcome {
        LaunchOutcome::NotLaunched(e) if e.code() == HRESULT::from_win32(ERROR_NO_ASSOCIATION.0) => {
            report_neither_ran(&format!("no association ({e})"));
        }
        LaunchOutcome::NotLaunched(e) => panic!(
            "PROBE pathext-vs-existing-extensionless: the shell declined to launch anything with an \
             unexpected error (not ERROR_NO_ASSOCIATION): {e} — both `tool` and `tool.bat` exist \
             here, so precedence could not be measured"
        ),
        LaunchOutcome::LaunchedNoHandle => {
            // Not automatically a harness failure here: `does_an_existing_extensionless_file_...`
            // establishes that an existing extensionless target can be handed to an association
            // handler outright, independent of whether PATHEXT could have matched something beside
            // it. If neither marker was written, that is what happened here too.
            report_neither_ran("no process handle (LaunchedNoHandle)");
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
}

/// Companion to the precedence probe above, with no `.bat` in the directory to compete: does an
/// EXISTING extensionless file ever get run directly by `ShellExecuteEx`? Measured: no. Depending on
/// the runner, the shell hands it to an association/Open-With handler
/// (`LaunchOutcome::LaunchedNoHandle`), fails synchronously with `ERROR_NO_ASSOCIATION` where
/// `SEE_MASK_FLAG_NO_UI` actually suppresses the picker, or blocks inside `ShellExecuteExW` on the
/// picker itself where the flag does not — measured in run 36125783666: `windows-11-arm` got
/// `LaunchedNoHandle`, `windows-latest` (x64) blocked. `shell_execute_with` is wrapped in
/// `shell_execute_bounded` below for exactly this third case, so a block like that one is now
/// itself a measured, in-process answer — see `UI_BLOCK_BOUND`'s doc — rather than something only
/// `.config/nextest.toml`'s outer per-test bound catches. All three outcomes hold regardless of
/// whether the file exists and regardless of whether anything else in the directory could satisfy
/// `PATHEXT`. This was originally written as a control expected to always launch; it does not, and
/// that failure to launch — a genuine negative, not a harness bug — IS the answer, and is what makes
/// `does_pathext_outrank_an_existing_extensionless_file`'s `(true, false)` outcome unreachable.
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
        println!(
            "PROBE existing-extensionless-no-bat: BLOCKED — ShellExecuteExW did not return within \
             {UI_BLOCK_BOUND:?}, despite SEE_MASK_FLAG_NO_UI"
        );
        println!(
            "  => NO, not measurably as a launch. On this architecture the shell blocked trying to \
             show its \"how do you want to open this?\" picker for the existing extensionless \
             target, rather than ever resolving it (measured on windows-latest/x64 in run \
             36125783666 — windows-11-arm got a clean LaunchedNoHandle in the same run; see \
             shell_execute_bounded's doc). This IS the measured floor for \
             `does_pathext_outrank_an_existing_extensionless_file`'s `(true, false)` branch, exactly \
             like the other two arms below: an extensionless target is never executed directly on \
             this architecture either, it just fails to resolve at all rather than resolving to a \
             handoff or a synchronous error. Nothing here was contained, since blocking inside \
             ShellExecuteExW yields no process handle either."
        );
        return;
    };
    let outcome = outcome.expect("probe must be measurable");
    match outcome {
        LaunchOutcome::NotLaunched(e) if e.code() == HRESULT::from_win32(ERROR_NO_ASSOCIATION.0) => {
            assert!(
                !exe_marker.exists(),
                "PROBE existing-extensionless-no-bat: UNREACHABLE — the shell reported no \
                 association, yet the exe marker exists; something ran despite a synchronous \
                 failure, which should be impossible"
            );
            println!("PROBE existing-extensionless-no-bat: launched=false, no association ({e})");
            println!(
                "  => NO. ShellExecuteEx does NOT run an existing extensionless file directly, even \
                 when nothing else in the directory could satisfy PATHEXT. Here it reported \
                 ERROR_NO_ASSOCIATION synchronously rather than handing off to a picker — the same \
                 fact as the LaunchedNoHandle arm below, just surfaced differently (see the module \
                 doc). This is the measured floor for \
                 `does_pathext_outrank_an_existing_extensionless_file`'s `(true, false)` branch: that \
                 branch is unreachable, because an extensionless target is never executed directly. \
                 It also means anything the shell refuses this way can never be contained by cosca — \
                 there is no process handle to assign to a Job Object."
            );
        }
        LaunchOutcome::NotLaunched(e) => panic!(
            "PROBE existing-extensionless-no-bat: the shell declined to launch anything with an \
             unexpected error (not ERROR_NO_ASSOCIATION): {e} — the file exists here, so \
             ERROR_FILE_NOT_FOUND would also be unexpected — so the harness itself appears to be \
             broken"
        ),
        LaunchOutcome::LaunchedNoHandle => {
            assert!(
                !exe_marker.exists(),
                "PROBE existing-extensionless-no-bat: UNREACHABLE — the shell reported no process \
                 handle, yet the exe marker exists; something ran without a handle this probe could \
                 wait on, which should be impossible"
            );
            println!(
                "PROBE existing-extensionless-no-bat: launched=true, no process handle \
                 (LaunchedNoHandle)"
            );
            println!(
                "  => NO. ShellExecuteEx does NOT run an existing extensionless file directly, even \
                 when nothing else in the directory could satisfy PATHEXT. It hands the file to an \
                 association/Open-With handler instead, which returns no process handle. This is the \
                 measured floor for `does_pathext_outrank_an_existing_extensionless_file`'s `(true, \
                 false)` branch: that branch is unreachable, because an extensionless target is never \
                 executed directly. It also means anything the shell hands off to this way can never \
                 be contained by cosca — there is no process handle to assign to a Job Object."
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
}
