//! `CreateProcessW` documents, for its command-line mode: "If the file name ends in a period (.)
//! with no extension ... .exe is not appended." So Win32 has a spelling for "this name is
//! COMPLETE, do not extend it" — and the filesystem strips the trailing dot when opening, so the
//! literal file still resolves. If `ShellExecuteEx` honours the same convention, it is exactly the
//! marker cosca's `Exact` arm needs: a way to hand over a name that cannot grow a `.bat`.
//!
//! Both halves have to hold. A dot that suppresses PATHEXT but fails to open the intended file is
//! useless, and a dot that opens the file but still extends it closes nothing.

use std::path::PathBuf;

use windows::core::HRESULT;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_ASSOCIATION};

use crate::harness::{
    plant_batch, probe_dir, read_self_report, read_self_report_image, shell_execute, shell_execute_bounded,
    shell_execute_with, LaunchOutcome,
};
use crate::windows_probe::{mark_test_passed, same_file};

/// Half one: does a trailing dot SUPPRESS the PATHEXT extension that the probe above measured?
#[test]
#[ignore = "executes a batch file; opt in with --ignored, on a throwaway runner only"]
fn does_a_trailing_dot_suppress_pathext_on_an_absolute_lpfile() {
    let (dir, marker) = probe_dir("dot-suppress");
    let bat = dir.path().join("tool.bat");
    plant_batch(&bat, &marker);
    let lp_file = dir.path().join("tool."); // the "complete name" spelling

    let outcome = shell_execute(&lp_file, None, None).expect("probe must be measurable");
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
    mark_test_passed("COSCA_PROBE_MARKERS");
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
/// Neither no-handle arm below reads a marker: a no-handle result — from either
/// `ERROR_NO_ASSOCIATION` or `LaunchedNoHandle` — means only that THIS call returned without a
/// process handle to wait on. It says nothing about whether a handed-off process later runs the
/// file anyway; a marker check taken immediately after the call returns would race that handoff
/// (it might write its marker microseconds after the read), and no wait, sleep or poll here would
/// turn that race into proof either way. So each arm reports only the synchronous, authoritative
/// fact — no process handle came back through this call — and says explicitly that what happens
/// after handoff is unmeasured, rather than drawing a negative conclusion, or passing, on the
/// strength of a racy snapshot.
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
    let outcome = shell_execute_bounded(move |state| shell_execute_with(&dotted, None, Some(&params), None, state))
        .unwrap_or_else(|e| {
            panic!("PROBE trailing-dot-opens-extensionless: {e}");
        });
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
                "  => NO, not as a directly-run process, through THIS call. The dotted spelling still \
                 resolves to the extensionless file rather than falling through to \
                 ERROR_FILE_NOT_FOUND, but an extensionless target is never executed directly \
                 regardless of spelling — the shell reported ERROR_NO_ASSOCIATION rather than handing \
                 it to a picker. This is the expected, measured negative for an extensionless target \
                 — see LaunchOutcome::LaunchedNoHandle's doc for the handoff variant of this same \
                 fact. What happens to the file after this call is not measured here."
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
                "  => NO, not as a directly-run process, through THIS call. The dotted spelling still \
                 resolves to the extensionless file rather than falling through to \
                 ERROR_FILE_NOT_FOUND, but an extensionless target is never executed directly \
                 regardless of spelling — it is handed to an association handler with no process \
                 handle, so it cannot be waited on, terminated, or contained through this call. This \
                 is the expected, measured negative for an extensionless target — see \
                 LaunchOutcome::LaunchedNoHandle's doc. What the handler does with the file \
                 afterward is not measured here."
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
    mark_test_passed("COSCA_PROBE_MARKERS");
}
