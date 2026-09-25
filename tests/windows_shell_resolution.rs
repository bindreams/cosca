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

use windows::core::{HRESULT, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, ERROR_FILE_NOT_FOUND, WAIT_OBJECT_0};
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
/// (measured: it can, for a trailing-dot extensionless target — see
/// `does_a_trailing_dot_still_open_the_extensionless_file`'s module-level doc). That case is
/// covered externally, by `.config/nextest.toml`'s per-test `slow-timeout` for this binary.
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
    /// The shell reported `ERROR_FILE_NOT_FOUND`: it looked for `lpFile` and found nothing to
    /// launch. This is a genuine negative measurement, carried here so a caller can report it. Any
    /// OTHER error means the harness itself could not even ask the question — `shell_execute_with`
    /// panics on those instead of returning them mislabelled as this.
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
        // `ERROR_FILE_NOT_FOUND` is the shell reporting a genuine negative measurement: it looked
        // for `lpFile` and found nothing to launch, which is a result, not a probe-harness
        // failure. Any other error means the harness could not even ask the question — panic
        // rather than mislabel it as a measured "nothing was launched".
        if e.code() == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0) {
            return Ok(LaunchOutcome::NotLaunched(e));
        }
        panic!(
            "PROBE shell-execute: ShellExecuteExW failed with an unexpected error (not \
             ERROR_FILE_NOT_FOUND): {e}"
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
        LaunchOutcome::NotLaunched(e) => {
            // A genuine negative: the shell looked for `tool` and found nothing to launch, which
            // is exactly what "PATHEXT is not applied" would look like.
            println!("PROBE absolute-extensionless-lpFile: launched=false ({e})");
            println!(
                "  => ShellExecuteEx does NOT extend an absolute lpFile. Completing the name is \
                 sufficient to close the search half, as cosca currently assumes."
            );
        }
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
        LaunchOutcome::NotLaunched(e) => {
            println!("PROBE pathless-lpFile-with-lpDirectory: launched=false ({e})");
            println!(
                "  => NOT reproduced here. The premise behind resolving before ShellExecuteEx is not \
                 holding in this environment; re-examine it before relying on it."
            );
        }
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
        LaunchOutcome::NotLaunched(e) => {
            // A genuine negative: the shell found nothing at all for `tool.`, meaning it did not
            // fall through to a PATHEXT-extended `tool.bat`.
            println!("PROBE trailing-dot-suppresses-pathext: launched=false ({e})");
            println!("  => YES. The dot suppressed the PATHEXT search — the .bat did NOT run.");
        }
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
/// target may also get no process handle at all (`LaunchOutcome::LaunchedNoHandle`) — that is the
/// expected, measured negative for this half (see that arm below), not a harness failure.
///
/// `ShellExecuteExW` itself can block on this exact input rather than ever returning — measured on
/// `windows-latest`, where it hung with no output past a 30-minute job timeout (run 36120443833).
/// `CHILD_EXIT_BOUND_MS` cannot cover this: it only bounds the wait AFTER a handle is obtained.
/// `.config/nextest.toml` bounds this test's whole process instead, via `slow-timeout`.
#[test]
#[ignore = "launches a copied payload binary; opt in with --ignored, on a throwaway runner only"]
fn does_a_trailing_dot_still_open_the_extensionless_file() {
    let (dir, marker) = probe_dir("dot-opens");
    let image_bin = PathBuf::from(env!("CARGO_BIN_EXE_cosca_testbin_image"));
    let extensionless = dir.path().join("tool");
    std::fs::copy(&image_bin, &extensionless).expect("copy cosca_testbin_image to an extensionless name");

    let dotted = dir.path().join("tool.");
    let params = format!("--report-to \"{}\"", marker.display());
    let outcome = shell_execute_with(&dotted, None, Some(&params)).expect("probe must be measurable");
    match outcome {
        LaunchOutcome::NotLaunched(e) => {
            println!("PROBE trailing-dot-opens-extensionless: launched=false ({e})");
            println!(
                "  => NO. The dotted spelling did not resolve to anything at all, so it cannot be \
                 used as a complete-path marker even if it suppresses PATHEXT."
            );
        }
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
    let outcome = shell_execute_with(&extensionless, None, Some(&params)).expect("probe must be measurable");
    match outcome {
        LaunchOutcome::NotLaunched(e) => panic!(
            "PROBE pathext-vs-existing-extensionless: the shell declined to launch anything ({e}), so \
             precedence could not be measured"
        ),
        LaunchOutcome::LaunchedNoHandle => {
            // Not automatically a harness failure here: `does_an_existing_extensionless_file_...`
            // establishes that an existing extensionless target can be handed to an association
            // handler outright, independent of whether PATHEXT could have matched something beside
            // it. If neither marker was written, that is what happened here too.
            let exe_ran = exe_marker.exists();
            let bat_ran = read_self_report(&bat_marker).is_some_and(|r| same_file(&r, &bat));
            println!(
                "PROBE pathext-vs-existing-extensionless: launched=true, no process handle \
                 (LaunchedNoHandle) exe_ran={exe_ran} bat_ran={bat_ran}"
            );
            assert!(
                !exe_ran,
                "PROBE pathext-vs-existing-extensionless: UNREACHABLE — the shell reported no \
                 process handle for an extensionless target, yet the exe marker exists. An \
                 extensionless target is never run directly (see LaunchOutcome::LaunchedNoHandle's \
                 doc), so nothing should have been able to write this marker."
            );
            assert!(
                !bat_ran,
                "PROBE pathext-vs-existing-extensionless: INCONCLUSIVE — the shell reported no \
                 process handle, yet the .bat's marker also exists — a real cmd.exe launch of the \
                 .bat always yields a process handle, so this contradicts LaunchedNoHandle."
            );
            println!(
                "  => the extensionless target's own handoff resolution wins outright: \
                 ShellExecuteEx handed `tool` to an association handler without ever searching \
                 PATHEXT for `tool.bat` beside it. Neither image ran as a process here, so this \
                 exact vector is not plantable through a direct launch — but nothing here was \
                 contained either, since a handoff never yields a process handle (see \
                 LaunchOutcome::LaunchedNoHandle's doc)."
            );
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
/// EXISTING extensionless file ever get run directly by `ShellExecuteEx`? Measured: no. The shell
/// hands it to an association/Open-With handler instead (`LaunchOutcome::LaunchedNoHandle`) —
/// regardless of whether the file exists, and regardless of whether anything else in the directory
/// could satisfy `PATHEXT`. This was originally written as a control expected to always launch; it
/// does not, and that failure to launch — a genuine `LaunchedNoHandle`, not a harness bug — IS the
/// answer, and is what makes `does_pathext_outrank_an_existing_extensionless_file`'s `(true,
/// false)` outcome unreachable.
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
    let outcome = shell_execute_with(&extensionless, None, Some(&params)).expect("probe must be measurable");
    match outcome {
        LaunchOutcome::NotLaunched(e) => panic!(
            "PROBE existing-extensionless-no-bat: the shell declined to launch anything at all ({e}) \
             — not even the association-handler handoff this probe expects — so the harness itself \
             appears to be broken"
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
