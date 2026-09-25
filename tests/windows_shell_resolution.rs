//! Platform probes: what `ShellExecuteEx` actually does with an `lpFile`.
//!
//! cosca's Windows elevated path hands `lpFile` to `ShellExecuteExW`, and the resolution policy
//! around it rests on measured facts rather than documentation — the docs do not say, for
//! instance, whether an ABSOLUTE but extensionless `lpFile` still gets `PATHEXT` applied. Guessing
//! wrong there is the difference between "the search hazard is closed" and "a planted `.bat` runs".
//!
//! These are **probes, not assertions about cosca**. They measure the platform and print what they
//! found, so a maintainer can write a policy against evidence. Each still FAILS if the measurement
//! itself could not be taken (the shell refused to launch anything at all, a helper could not be
//! written), so an inconclusive run is never a silent pass. A probe that only surveys the platform
//! also prints `INCONCLUSIVE` and passes if the shell launched something without handing back a
//! process handle to wait on — it never claimed a specific outcome. A probe that asserts one
//! (`control_an_absolute_batch_path_does_launch`, `does_pathext_outrank_an_existing_extensionless_file`)
//! FAILS on that same case instead, since it cannot wait for what it needs to check.
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

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
use windows::Win32::System::Threading::WaitForSingleObject;
use windows::Win32::UI::Shell::{
    ShellExecuteExW, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

/// The child is an external process that might never exit, so a bound is the honest failure
/// surface rather than a synchronisation device — if it trips, the probe reports that the launched
/// process did not finish, it does not silently continue.
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

/// What `shell_execute_with` was actually able to measure, distinct from what it launched.
#[derive(Debug, PartialEq, Eq)]
enum LaunchOutcome {
    /// The shell launched something, handed back a process handle, and this function waited for
    /// it to exit — a marker written by the child can now be read.
    Waited,
    /// The shell launched something but `SEE_MASK_NOCLOSEPROCESS` did not yield a process handle
    /// to wait on (this happens when the verb hands off to another process, e.g. a DDE server).
    /// Nothing tells this probe whether the child has finished, so reading its marker now would
    /// be a race, not a measurement.
    LaunchedNoHandle,
    /// The shell declined outright; nothing was launched.
    NotLaunched,
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
    let launched = unsafe { ShellExecuteExW(&mut info) }.is_ok();
    if !launched {
        // The shell declined — the measurement is "nothing was launched", which is a result, not
        // an error.
        return Ok(LaunchOutcome::NotLaunched);
    }
    if info.hProcess.is_invalid() {
        return Ok(LaunchOutcome::LaunchedNoHandle);
    }
    // SAFETY: a process handle the shell just handed us, waited on then closed exactly once.
    unsafe {
        let waited = WaitForSingleObject(info.hProcess, CHILD_EXIT_BOUND_MS);
        let _ = CloseHandle(info.hProcess);
        if waited != WAIT_OBJECT_0 {
            return Err(format!(
                "the launched process did not exit within {CHILD_EXIT_BOUND_MS}ms, so this probe \
                 could not be measured"
            ));
        }
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
    plant_batch(&dir.path().join("tool.bat"), &marker);
    let lp_file = dir.path().join("tool"); // absolute, extensionless, does not exist

    let outcome = shell_execute(&lp_file, None).expect("probe must be measurable");
    match outcome {
        LaunchOutcome::NotLaunched => {
            panic!(
                "PROBE absolute-extensionless-lpFile: the shell declined to launch anything, so nothing was measured"
            )
        }
        LaunchOutcome::LaunchedNoHandle => println!(
            "PROBE absolute-extensionless-lpFile: INCONCLUSIVE — launched without a process handle, \
             so this probe could not wait for the batch to finish before reading its marker"
        ),
        LaunchOutcome::Waited => {
            let ran = marker.exists();
            println!("PROBE absolute-extensionless-lpFile: launched=true batch_ran={ran}");
            if ran {
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
        LaunchOutcome::NotLaunched => panic!(
            "PROBE control-absolute-bat: the shell declined to launch anything, so the harness cannot \
             launch a batch file at all — fix the harness before reading the PATHEXT probe's result"
        ),
        LaunchOutcome::LaunchedNoHandle => panic!(
            "PROBE control-absolute-bat: INCONCLUSIVE — launched without a process handle, so this \
             control could not wait for the batch to finish before checking its marker; fix the \
             harness before reading the PATHEXT probe's result"
        ),
        LaunchOutcome::Waited => {
            println!(
                "PROBE control-absolute-bat: launched=true batch_ran={}",
                marker.exists()
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
        LaunchOutcome::NotLaunched => {
            panic!("PROBE pathless-lpFile-with-lpDirectory: the shell declined to launch anything, so nothing was measured")
        }
        LaunchOutcome::LaunchedNoHandle => println!(
            "PROBE pathless-lpFile-with-lpDirectory: INCONCLUSIVE — launched without a process \
             handle, so this probe could not wait for the batch to finish before reading its marker"
        ),
        LaunchOutcome::Waited => {
            let ran = marker.exists();
            println!("PROBE pathless-lpFile-with-lpDirectory: launched=true batch_ran={ran}");
            if ran {
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
        LaunchOutcome::NotLaunched => {
            panic!(
                "PROBE trailing-dot-suppresses-pathext: the shell declined to launch anything, so nothing was measured"
            )
        }
        LaunchOutcome::LaunchedNoHandle => println!(
            "PROBE trailing-dot-suppresses-pathext: INCONCLUSIVE — launched without a process \
             handle, so this probe could not wait for the batch to finish before reading its marker"
        ),
        LaunchOutcome::Waited => {
            let ran = marker.exists();
            println!("PROBE trailing-dot-suppresses-pathext: launched=true batch_ran={ran}");
            if ran {
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
        LaunchOutcome::NotLaunched => {
            panic!("PROBE trailing-dot-opens-extensionless: the shell declined to launch anything, so nothing was measured")
        }
        LaunchOutcome::LaunchedNoHandle => println!(
            "PROBE trailing-dot-opens-extensionless: INCONCLUSIVE — launched without a process \
             handle, so this probe could not wait for the image to finish before reading its marker"
        ),
        LaunchOutcome::Waited => {
            let ran = marker.exists();
            println!("PROBE trailing-dot-opens-extensionless: launched=true image_ran={ran}");
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
/// with no redirection, so each marker can only be written by the image that genuinely ran.
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
    match outcome {
        LaunchOutcome::NotLaunched => panic!(
            "PROBE pathext-vs-existing-extensionless: the shell declined to launch anything, so \
             precedence could not be measured"
        ),
        LaunchOutcome::LaunchedNoHandle => panic!(
            "PROBE pathext-vs-existing-extensionless: INCONCLUSIVE — launched without a process \
             handle, so this probe could not wait for the copy to finish before reading its markers"
        ),
        LaunchOutcome::Waited => {}
    }

    let exe_ran = exe_marker.exists();
    let bat_ran = bat_marker.exists();
    println!("PROBE pathext-vs-existing-extensionless: launched=true exe_ran={exe_ran} bat_ran={bat_ran}");
    match (exe_ran, bat_ran) {
        (true, false) => println!(
            "  => the EXISTING extensionless file wins. PATHEXT is only consulted when the named \
             file does not exist, so the hazard is confined to paths that name nothing — i.e. the \
             `Exact` arm, which performs no existence check. `Search` is safe, because it only \
             ever returns a path that passed is_file()."
        ),
        (false, true) => println!(
            "  => PATHEXT OUTRANKS the existing file. The .bat wins even though the exact named \
             file is present, so resolving to an absolute extensionless path is unsafe on BOTH \
             arms — `Search` included. Any absolute lpFile without a loadable extension is \
             plantable."
        ),
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
