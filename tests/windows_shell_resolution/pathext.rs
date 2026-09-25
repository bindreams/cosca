//! Does `ShellExecuteEx` apply `PATHEXT` to a name that already looks complete, and does it search
//! `lpDirectory` for a bare name? See `tests/windows_shell_resolution.rs`'s module doc for why these
//! are the two questions this whole probe suite exists to answer.

use std::path::{Path, PathBuf};

use windows::core::HRESULT;
use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;

use crate::harness::{
    plant_batch, probe_dir, read_self_report, read_self_report_image, shell_execute, shell_execute_with,
    BoundedCallState, LaunchOutcome,
};
use crate::windows_probe::{mark_test_passed, same_file};

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

    let outcome = shell_execute(&lp_file, None, None).expect("probe must be measurable");
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
    mark_test_passed("COSCA_PROBE_MARKERS");
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

    let outcome = shell_execute(&bat, None, None).expect("probe must be measurable");
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
    mark_test_passed("COSCA_PROBE_MARKERS");
}

/// The other half of the elevated hazard, re-measured rather than inherited: a PATH-LESS `lpFile`
/// is documented to assume the current directory, and `lpDirectory` is consulted as a search
/// location. This is what makes completing the name necessary in the first place.
///
/// No `lpClass` is set on this call. See
/// `does_shellexecute_search_lpdirectory_for_a_pathless_lpfile_as_exefile` below for the same
/// question measured under production's own `SEE_MASK_CLASSNAME`/`lpClass = "exefile"`.
#[test]
#[ignore = "executes a batch file; opt in with --ignored, on a throwaway runner only"]
fn does_shellexecute_search_lpdirectory_for_a_pathless_lpfile() {
    let (dir, marker) = probe_dir("lpdir");
    let bat = dir.path().join("tool.bat");
    plant_batch(&bat, &marker);

    // Path-less, extensionless: only a search can find anything.
    let outcome = shell_execute(Path::new("tool"), Some(dir.path()), None).expect("probe must be measurable");
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
    mark_test_passed("COSCA_PROBE_MARKERS");
}

/// Same question as the probe above, but with `SEE_MASK_CLASSNAME`/`lpClass = "exefile"` set,
/// matching production's actual elevated call (`launch_runas_with_host`,
/// `src/elevation/windows.rs`). Forcing the class tells the shell the file's type is already known
/// and dispatches straight to `HKCR\exefile\shell\<verb>\command`, skipping its own class-detection
/// step — a materially different resolution path than letting the shell infer the class itself,
/// which is what every OTHER probe in this suite does. See the module doc's "The lpClass
/// divergence" section for why this probe exists and what it settles.
///
/// Both a `tool.exe` (a copy of `cosca_testbin_image`, self-reporting via `--report-to`) and a
/// `tool.bat` are planted side by side: PATHEXT's default order resolves a bare `tool` to whichever
/// of these extensions it lists first, and which one that is is itself part of what this probe
/// measures rather than something to assume — see each `Waited` arm below for how the conclusion is
/// scoped to whichever file actually self-reports having run.
#[test]
#[ignore = "executes a batch file; opt in with --ignored, on a throwaway runner only"]
fn does_shellexecute_search_lpdirectory_for_a_pathless_lpfile_as_exefile() {
    let (dir, bat_marker) = probe_dir("lpdir-exefile-bat");
    let bat = dir.path().join("tool.bat");
    plant_batch(&bat, &bat_marker);

    let image_bin = PathBuf::from(env!("CARGO_BIN_EXE_cosca_testbin_image"));
    let exe = dir.path().join("tool.exe");
    std::fs::copy(&image_bin, &exe).expect("copy cosca_testbin_image to tool.exe");
    let exe_report = dir.path().join("lpdir-exefile-exe-report.txt");
    let params = format!("--report-to \"{}\"", exe_report.display());

    let outcome = shell_execute_with(
        Path::new("tool"),
        Some(dir.path()),
        Some(&params),
        Some("exefile"),
        &BoundedCallState::default(),
    )
    .expect("probe must be measurable");
    match outcome {
        LaunchOutcome::NotLaunched(e) if e.code() == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0) => {
            println!("PROBE pathless-lpFile-with-lpDirectory-as-exefile: launched=false ({e})");
            println!(
                "  => under SEE_MASK_CLASSNAME/lpClass=\"exefile\", a path-less lpFile is NOT found \
                 via lpDirectory search — neither the planted tool.exe nor tool.bat ran. This \
                 matches plan_runas's (src/elevation/windows.rs) note of 'no App Paths, no \
                 bare-name search' for an elevated caller under this same class, and means the \
                 no-class probe above does NOT transfer to production's actual call: completing the \
                 name closes a hazard the forced class was never exposed to in the first place."
            );
        }
        LaunchOutcome::NotLaunched(e) => panic!(
            "PROBE pathless-lpFile-with-lpDirectory-as-exefile: `tool` cannot exist as a bare name in \
             this directory (both `tool.exe` and `tool.bat` were planted), so ERROR_NO_ASSOCIATION \
             (or anything but ERROR_FILE_NOT_FOUND) is not the negative this probe measures: {e}"
        ),
        LaunchOutcome::LaunchedNoHandle => panic!(
            "PROBE pathless-lpFile-with-lpDirectory-as-exefile: INCONCLUSIVE — launched without a \
             process handle, so this probe could not wait for the child to finish before reading its \
             report"
        ),
        LaunchOutcome::Waited => {
            let exe_ran = read_self_report_image(&exe_report).filter(|r| same_file(r, &exe));
            let bat_ran = read_self_report(&bat_marker).filter(|r| same_file(r, &bat));
            println!(
                "PROBE pathless-lpFile-with-lpDirectory-as-exefile: launched=true exe_ran={} \
                 bat_ran={}",
                exe_ran.is_some(),
                bat_ran.is_some()
            );
            match (exe_ran, bat_ran) {
                (Some(_), None) => println!(
                    "  => under SEE_MASK_CLASSNAME/lpClass=\"exefile\", a path-less lpFile IS still \
                     searched, PATHEXT applied and lpDirectory consulted, and here it resolved to \
                     the planted tool.exe (tool.bat was also planted, but did not run). The forced \
                     class does NOT close this hazard for an .exe placeholder, contrary to \
                     plan_runas's (src/elevation/windows.rs) note (measured only for an elevated \
                     caller). This conclusion is scoped to tool.exe: it is NOT established that \
                     tool.bat is also reachable this way — see the `tool.bat`-only probe above."
                ),
                (None, Some(_)) => println!(
                    "  => under SEE_MASK_CLASSNAME/lpClass=\"exefile\", a path-less lpFile IS still \
                     searched, PATHEXT applied and lpDirectory consulted, and here it resolved to \
                     the planted tool.bat (tool.exe was also planted, but did not run). The forced \
                     class does NOT close this hazard for a .bat placeholder, contrary to \
                     plan_runas's (src/elevation/windows.rs) note (measured only for an elevated \
                     caller). This conclusion is scoped to tool.bat: it is NOT established that \
                     tool.exe is also reachable this way."
                ),
                (Some(_), Some(_)) => panic!(
                    "PROBE pathless-lpFile-with-lpDirectory-as-exefile: INCONCLUSIVE — both the \
                     planted tool.exe and tool.bat self-reported having run from a single \
                     ShellExecuteExW call, which should be impossible — something is wrong with the \
                     harness, not the measurement"
                ),
                (None, None) => panic!(
                    "PROBE pathless-lpFile-with-lpDirectory-as-exefile: INCONCLUSIVE — the shell \
                     waited on a real process, but neither planted file self-reported having run, so \
                     what actually ran cannot be confirmed"
                ),
            }
        }
    }
    mark_test_passed("COSCA_PROBE_MARKERS");
}
