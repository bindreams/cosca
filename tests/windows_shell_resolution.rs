//! Platform probes: what `ShellExecuteEx` actually does with an `lpFile`.
//!
//! cosca's Windows elevated path hands `lpFile` to `ShellExecuteExW`, and the resolution policy
//! around it rests on measured facts rather than documentation — the docs do not say, for
//! instance, whether an ABSOLUTE but extensionless `lpFile` still gets `PATHEXT` applied. Guessing
//! wrong there is the difference between "the search hazard is closed" and "a planted `.bat` runs".
//!
//! These are **probes, not assertions about cosca**. They measure the platform and print what they
//! found, so a maintainer can write a policy against evidence. Every one of them still FAILS if the
//! measurement itself could not be taken: the shell refused to launch anything at all, a helper
//! could not be written, or the shell launched something without handing back a process handle to
//! wait on (this happens when the verb hands off to another process, e.g. a DDE server). An earlier
//! version of this rule let a probe that only surveys the platform print `INCONCLUSIVE` and PASS in
//! that last case — `does_a_trailing_dot_still_open_the_extensionless_file` did exactly that, on
//! both architectures, in run 36117246246 — so an inconclusive run is now a hard failure everywhere,
//! never a silent pass.
//!
//! # Why they are `#[ignore]`d
//!
//! They execute a batch file. That is the exact vector `reject_batch_path` exists to refuse, so it
//! must never happen incidentally during `cargo nextest run`. Opt in explicitly:
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

use windows::core::{HRESULT, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, ERROR_FILE_NOT_FOUND, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{
    QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject, INFINITE, PROCESS_NAME_WIN32,
};
use windows::Win32::UI::Shell::{
    ShellExecuteExW, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

/// The child is an external process that might never exit, so a bound is the honest failure
/// surface rather than a synchronisation device — if it trips, the probe reports that the launched
/// process did not finish. The process is then terminated and waited out — unboundedly, since that
/// wait confirms a real kernel outcome rather than synchronizing anything this code controls —
/// before its handle closes, so a timed-out probe never abandons a still-running child.
const CHILD_EXIT_BOUND_MS: u32 = 30_000;

fn wide_nul(s: &std::ffi::OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// Write a `.bat` that stamps `marker`, so "did this file run?" is a filesystem question rather
/// than a timing one.
fn plant_batch(path: &Path, marker: &Path) {
    std::fs::write(path, format!("@echo off\r\necho ran > \"{}\"\r\n", marker.display()))
        .unwrap_or_else(|e| panic!("could not plant the probe batch at {}: {e}", path.display()));
}

/// Loose path comparison for confirming a queried process image against an expected planted file.
/// Windows path comparison is case-insensitive, and `QueryFullProcessImageNameW` can spell a path
/// differently (short names, alternate roots) than the one this probe built by hand, so a plain
/// `==` on `Path` would falsely disagree. This compares canonicalized forms where the filesystem
/// can supply them — both sides name a file that still exists for the life of the calling test —
/// and falls back to a case-insensitive string compare otherwise.
fn paths_match(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a.as_os_str().eq_ignore_ascii_case(b.as_os_str()),
    }
}

/// What `shell_execute_with` was actually able to measure, distinct from what it launched.
#[derive(Debug)]
enum LaunchOutcome {
    /// The shell launched something, handed back a process handle, and this function waited for
    /// it to exit. Carries the image that actually ran, queried with `QueryFullProcessImageNameW`
    /// rather than inferred from a marker file — two different images can leave the same marker
    /// indistinguishably (e.g. a copy of `cmd.exe` run directly, vs. `cmd.exe` run via a planted
    /// `.bat`, can both write the same marker through their own `copy`/`echo`).
    Waited(PathBuf),
    /// The shell launched something but `SEE_MASK_NOCLOSEPROCESS` did not yield a process handle
    /// to wait on (this happens when the verb hands off to another process, e.g. a DDE server).
    /// `SHELLEXECUTEINFOW` carries no PID in this case, only the `hProcess` that is exactly what's
    /// missing, so there is no handle here to terminate or wait on — nothing tells this probe
    /// whether the child has finished, so reading its marker now would be a race, not a
    /// measurement, and every probe below treats this as a failed measurement.
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
            // terminate it or wait it out. Terminate it and wait for the kernel to confirm the
            // exit (a real, unbounded outcome, not a race against a second clock) before closing.
            let _ = TerminateProcess(info.hProcess, 1);
            let _ = WaitForSingleObject(info.hProcess, INFINITE);
            let _ = CloseHandle(info.hProcess);
            return Err(format!(
                "the launched process did not exit within {CHILD_EXIT_BOUND_MS}ms, so this probe \
                 could not be measured (it has now been terminated and reaped)"
            ));
        }
    }
    // What actually launched, independent of any marker file it may have left — see
    // `LaunchOutcome::Waited`'s doc for why the marker alone cannot be trusted. Queried while the
    // handle is still open, before it closes below.
    let mut image_buf = [0u16; 4096];
    let mut image_len = image_buf.len() as u32;
    // SAFETY: `info.hProcess` names a process that has already exited (`WAIT_OBJECT_0` above); the
    // handle itself is still open and valid until the `CloseHandle` below, and querying a
    // just-exited process's image through its still-open handle is documented to work. `image_buf`
    // outlives the call and `image_len` starts at its capacity.
    let queried = unsafe {
        QueryFullProcessImageNameW(
            info.hProcess,
            PROCESS_NAME_WIN32,
            PWSTR(image_buf.as_mut_ptr()),
            &mut image_len,
        )
    };
    let image = queried.map(|()| PathBuf::from(String::from_utf16_lossy(&image_buf[..image_len as usize])));
    // SAFETY: the process signalled `WAIT_OBJECT_0` above; the handle is closed exactly once.
    unsafe {
        let _ = CloseHandle(info.hProcess);
    }
    let image = image.unwrap_or_else(|e| {
        panic!(
            "PROBE shell-execute: INCONCLUSIVE — the launched process exited, but its image could \
             not be queried ({e}), so this probe cannot confirm what actually ran"
        )
    });
    Ok(LaunchOutcome::Waited(image))
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
    plant_batch(&dir.path().join("tool.bat"), &marker);
    let lp_file = dir.path().join("tool"); // absolute, extensionless, does not exist

    let outcome = shell_execute(&lp_file, None).expect("probe must be measurable");
    match outcome {
        LaunchOutcome::NotLaunched(e) => {
            panic!(
                "PROBE absolute-extensionless-lpFile: the shell declined to launch anything ({e}), \
                 so nothing was measured"
            )
        }
        LaunchOutcome::LaunchedNoHandle => panic!(
            "PROBE absolute-extensionless-lpFile: INCONCLUSIVE — launched without a process handle, \
             so this probe could not wait for the batch to finish before reading its marker"
        ),
        LaunchOutcome::Waited(image) => {
            let ran = marker.exists();
            println!(
                "PROBE absolute-extensionless-lpFile: launched=true image={} batch_ran={ran}",
                image.display()
            );
            if ran {
                let system_cmd = PathBuf::from(std::env::var_os("COMSPEC").expect("COMSPEC names cmd.exe"));
                assert!(
                    paths_match(&image, &system_cmd),
                    "PROBE absolute-extensionless-lpFile: INCONCLUSIVE — the marker was written but \
                     the launched image was {}, not {} — something other than the planted batch ran",
                    image.display(),
                    system_cmd.display()
                );
                println!(
                    "  => ShellExecuteEx DOES apply PATHEXT to an absolute lpFile. `raw_executable(\"tool\")` \
                     under .elevate() can reach a planted tool.bat; absolutising alone does NOT close the \
                     batch vector, and the gate must also run on the completed path."
                );
            } else {
                println!(
                    "  => ShellExecuteEx does NOT extend an absolute lpFile. Completing the name is \
                     sufficient to close the search half, as cosca currently assumes."
                );
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
        LaunchOutcome::Waited(image) => {
            println!(
                "PROBE control-absolute-bat: launched=true image={} batch_ran={}",
                image.display(),
                marker.exists()
            );
            let system_cmd = PathBuf::from(std::env::var_os("COMSPEC").expect("COMSPEC names cmd.exe"));
            assert!(
                paths_match(&image, &system_cmd),
                "PROBE control-absolute-bat: INCONCLUSIVE — the launched image was {}, not {} — \
                 something other than cmd.exe running the batch ran",
                image.display(),
                system_cmd.display()
            );
            assert!(
                marker.exists(),
                "the harness cannot launch a batch file at all, so the PATHEXT probe's result is not \
                 interpretable — fix the harness before reading it"
            );
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
    plant_batch(&dir.path().join("tool.bat"), &marker);

    // Path-less, extensionless: only a search can find anything.
    let outcome = shell_execute(Path::new("tool"), Some(dir.path())).expect("probe must be measurable");
    match outcome {
        LaunchOutcome::NotLaunched(e) => {
            panic!(
                "PROBE pathless-lpFile-with-lpDirectory: the shell declined to launch anything ({e}), \
                 so nothing was measured"
            )
        }
        LaunchOutcome::LaunchedNoHandle => panic!(
            "PROBE pathless-lpFile-with-lpDirectory: INCONCLUSIVE — launched without a process \
             handle, so this probe could not wait for the batch to finish before reading its marker"
        ),
        LaunchOutcome::Waited(image) => {
            let ran = marker.exists();
            println!(
                "PROBE pathless-lpFile-with-lpDirectory: launched=true image={} batch_ran={ran}",
                image.display()
            );
            if ran {
                let system_cmd = PathBuf::from(std::env::var_os("COMSPEC").expect("COMSPEC names cmd.exe"));
                assert!(
                    paths_match(&image, &system_cmd),
                    "PROBE pathless-lpFile-with-lpDirectory: INCONCLUSIVE — the marker was written \
                     but the launched image was {}, not {} — something other than the planted batch \
                     ran",
                    image.display(),
                    system_cmd.display()
                );
                println!(
                    "  => confirmed: a path-less lpFile is searched, PATHEXT applied and lpDirectory \
                     consulted. This is the hazard the elevated path closes by completing the name."
                );
            } else {
                println!(
                    "  => NOT reproduced here. The premise behind resolving before ShellExecuteEx is not \
                     holding in this environment; re-examine it before relying on it."
                );
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
    plant_batch(&dir.path().join("tool.bat"), &marker);
    let lp_file = dir.path().join("tool."); // the "complete name" spelling

    let outcome = shell_execute(&lp_file, None).expect("probe must be measurable");
    match outcome {
        LaunchOutcome::NotLaunched(e) => {
            panic!(
                "PROBE trailing-dot-suppresses-pathext: the shell declined to launch anything ({e}), \
                 so nothing was measured"
            )
        }
        LaunchOutcome::LaunchedNoHandle => panic!(
            "PROBE trailing-dot-suppresses-pathext: INCONCLUSIVE — launched without a process \
             handle, so this probe could not wait for the batch to finish before reading its marker"
        ),
        LaunchOutcome::Waited(image) => {
            let ran = marker.exists();
            println!(
                "PROBE trailing-dot-suppresses-pathext: launched=true image={} batch_ran={ran}",
                image.display()
            );
            if ran {
                let system_cmd = PathBuf::from(std::env::var_os("COMSPEC").expect("COMSPEC names cmd.exe"));
                assert!(
                    paths_match(&image, &system_cmd),
                    "PROBE trailing-dot-suppresses-pathext: INCONCLUSIVE — the marker was written \
                     but the launched image was {}, not {} — something other than the planted batch \
                     ran",
                    image.display(),
                    system_cmd.display()
                );
                println!("  => NO. The dot does not suppress PATHEXT; the planted .bat still ran.");
            } else {
                println!("  => YES. The dot suppressed the PATHEXT search — the .bat did NOT run.");
            }
        }
    }
}

/// Half two: does a trailing dot still OPEN the extensionless file it names? Uses a copy of
/// `cmd.exe` renamed to an extensionless `tool`, run with `/c` to stamp the marker — so a marker
/// means the real image was loaded through the dotted spelling.
#[test]
#[ignore = "launches a copied system binary; opt in with --ignored, on a throwaway runner only"]
fn does_a_trailing_dot_still_open_the_extensionless_file() {
    let (dir, marker) = probe_dir("dot-opens");
    let system_cmd = PathBuf::from(std::env::var_os("COMSPEC").expect("COMSPEC names cmd.exe"));
    let extensionless = dir.path().join("tool");
    std::fs::copy(&system_cmd, &extensionless).expect("copy cmd.exe to an extensionless name");

    let dotted = dir.path().join("tool.");
    let params = format!("/c echo ran > \"{}\"", marker.display());
    let outcome = shell_execute_with(&dotted, None, Some(&params)).expect("probe must be measurable");
    match outcome {
        LaunchOutcome::NotLaunched(e) => {
            panic!(
                "PROBE trailing-dot-opens-extensionless: the shell declined to launch anything ({e}), \
                 so nothing was measured"
            )
        }
        LaunchOutcome::LaunchedNoHandle => panic!(
            "PROBE trailing-dot-opens-extensionless: INCONCLUSIVE — launched without a process \
             handle, so this probe could not wait for the image to finish before reading its marker"
        ),
        LaunchOutcome::Waited(image) => {
            let ran = marker.exists();
            println!(
                "PROBE trailing-dot-opens-extensionless: launched=true image={} image_ran={ran}",
                image.display()
            );
            assert!(
                paths_match(&image, &extensionless),
                "PROBE trailing-dot-opens-extensionless: INCONCLUSIVE — the launched image was {}, \
                 not the extensionless file {} this probe planted; the dotted spelling opened \
                 something other than the intended file",
                image.display(),
                extensionless.display()
            );
            if ran {
                println!("  => YES. `<dir>\\tool.` loads the extensionless `<dir>\\tool`.");
            } else {
                println!(
                    "  => NO. The dotted spelling did not load the file, so it cannot be used as a \
                     complete-path marker even if it suppresses PATHEXT."
                );
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
/// The earlier version of this probe was contaminated: its `lpParameters` contained a `>`
/// redirect, which the OUTER `cmd.exe` consumes when the shell routes through a batch file, so
/// both markers appeared regardless of what actually launched. This one uses `copy`, a builtin
/// with no redirection, so each marker can only be written by the image that genuinely ran — and
/// the queried launch image below corroborates the marker evidence directly, rather than trusting
/// the marker alone.
#[test]
#[ignore = "executes a batch file; opt in with --ignored, on a throwaway runner only"]
fn does_pathext_outrank_an_existing_extensionless_file() {
    let dir = tempfile::tempdir().expect("probe needs a temp dir");
    let exe_marker = dir.path().join("precedence-exe.txt");
    let bat_marker = dir.path().join("precedence-bat.txt");

    // The `.bat` writes its marker with a redirect INSIDE its own body, which is safe — nothing
    // in `lpParameters` can trigger it.
    let bat = dir.path().join("tool.bat");
    plant_batch(&bat, &bat_marker);

    // The extensionless image: a copy of cmd.exe, so it can stamp its own marker via `copy`.
    let system_cmd = PathBuf::from(std::env::var_os("COMSPEC").expect("COMSPEC names cmd.exe"));
    let extensionless = dir.path().join("tool");
    std::fs::copy(&system_cmd, &extensionless).expect("copy cmd.exe to an extensionless name");

    // No `>` anywhere: if the shell routes through tool.bat instead, these are inert arguments.
    let params = format!("/c copy /y \"{}\" \"{}\"", bat.display(), exe_marker.display());
    let outcome = shell_execute_with(&extensionless, None, Some(&params)).expect("probe must be measurable");
    let image = match outcome {
        LaunchOutcome::NotLaunched(e) => panic!(
            "PROBE pathext-vs-existing-extensionless: the shell declined to launch anything ({e}), so \
             precedence could not be measured"
        ),
        LaunchOutcome::LaunchedNoHandle => panic!(
            "PROBE pathext-vs-existing-extensionless: INCONCLUSIVE — launched without a process \
             handle, so this probe could not wait for the copy to finish before reading its markers"
        ),
        LaunchOutcome::Waited(image) => image,
    };

    let exe_ran = exe_marker.exists();
    let bat_ran = bat_marker.exists();
    println!(
        "PROBE pathext-vs-existing-extensionless: launched=true image={} exe_ran={exe_ran} bat_ran={bat_ran}",
        image.display()
    );
    match (exe_ran, bat_ran) {
        (true, false) => {
            assert!(
                paths_match(&image, &extensionless),
                "PROBE pathext-vs-existing-extensionless: INCONCLUSIVE — the exe marker was written, \
                 but the launched image was {}, not the extensionless file {} — the marker evidence \
                 and the queried image disagree on what ran",
                image.display(),
                extensionless.display()
            );
            println!(
                "  => the EXISTING extensionless file wins (confirmed by the queried image, {}). \
                 PATHEXT is only consulted when the named file does not exist, so the hazard is \
                 confined to paths that name nothing — i.e. the `Exact` arm, which performs no \
                 existence check. `Search` is safe, because it only ever returns a path that passed \
                 is_file().",
                image.display()
            );
        }
        (false, true) => {
            assert!(
                paths_match(&image, &system_cmd),
                "PROBE pathext-vs-existing-extensionless: INCONCLUSIVE — the bat marker was written, \
                 but the launched image was {}, not {} — the marker evidence and the queried image \
                 disagree on what ran",
                image.display(),
                system_cmd.display()
            );
            println!(
                "  => PATHEXT OUTRANKS the existing file (confirmed by the queried image, {}: cmd.exe \
                 ran the .bat, not the copy at the extensionless name). The .bat wins even though the \
                 exact named file is present, so resolving to an absolute extensionless path is unsafe \
                 on BOTH arms — `Search` included. Any absolute lpFile without a loadable extension is \
                 plantable.",
                image.display()
            );
        }
        (true, true) => panic!(
            "PROBE pathext-vs-existing-extensionless: INCONCLUSIVE — both markers set; the probe is \
             still contaminated and its result cannot be trusted"
        ),
        (false, false) => panic!(
            "PROBE pathext-vs-existing-extensionless: nothing ran, so precedence could not be \
             measured — the probe is not interpretable"
        ),
    }
}

/// Control for the probe above: with no `.bat` in the directory to compete, an existing
/// extensionless file must launch on its own. If this does not run, the harness cannot launch an
/// existing extensionless file at all, and the precedence probe's `(false, false)` result would be
/// meaningless — indistinguishable from "PATHEXT and the existing file both lost" from "the harness
/// never launched anything".
#[test]
#[ignore = "launches a copied system binary; opt in with --ignored, on a throwaway runner only"]
fn control_an_extensionless_file_launches_with_no_bat_present() {
    let dir = tempfile::tempdir().expect("probe needs a temp dir");
    let exe_marker = dir.path().join("no-bat-control-marker.txt");

    let system_cmd = PathBuf::from(std::env::var_os("COMSPEC").expect("COMSPEC names cmd.exe"));
    let extensionless = dir.path().join("tool");
    std::fs::copy(&system_cmd, &extensionless).expect("copy cmd.exe to an extensionless name");
    // Deliberately no tool.bat: nothing else in this directory could satisfy PATHEXT.

    let params = format!("/c echo ran > \"{}\"", exe_marker.display());
    let outcome = shell_execute_with(&extensionless, None, Some(&params)).expect("probe must be measurable");
    match outcome {
        LaunchOutcome::NotLaunched(e) => panic!(
            "PROBE control-extensionless-no-bat: the shell declined to launch anything ({e}), so the \
             harness cannot launch an existing extensionless file at all — fix the harness before \
             reading the PATHEXT-precedence probe's result"
        ),
        LaunchOutcome::LaunchedNoHandle => panic!(
            "PROBE control-extensionless-no-bat: INCONCLUSIVE — launched without a process handle, so \
             this control could not wait for the copy to finish before checking its marker; fix the \
             harness before reading the PATHEXT-precedence probe's result"
        ),
        LaunchOutcome::Waited(image) => {
            println!(
                "PROBE control-extensionless-no-bat: launched=true image={} exe_ran={}",
                image.display(),
                exe_marker.exists()
            );
            assert!(
                paths_match(&image, &extensionless),
                "PROBE control-extensionless-no-bat: INCONCLUSIVE — the launched image was {}, not \
                 the extensionless file {} this probe planted; something other than the intended file \
                 ran",
                image.display(),
                extensionless.display()
            );
            assert!(
                exe_marker.exists(),
                "the harness cannot launch an existing extensionless file at all, so the \
                 PATHEXT-precedence probe's result is not interpretable — fix the harness before \
                 reading it"
            );
        }
    }
}
