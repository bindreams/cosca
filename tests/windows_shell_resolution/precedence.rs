//! **Decides whether this is an `Exact`-only problem or a whole-resolver problem.** cosca's
//! resolver can return an absolute EXTENSIONLESS path: a located name like `./myapp` where `myapp`
//! exists with no extension resolves to exactly that, having passed `is_file()`. If PATHEXT
//! outranks an existing extensionless file, then the `Search` arm carries the same hazard as
//! `Exact`, and no amount of resolving fixes it.

use std::path::PathBuf;

use windows::core::HRESULT;
use windows::Win32::Foundation::ERROR_NO_ASSOCIATION;

use crate::harness::{
    plant_batch, read_self_report, read_self_report_image, shell_execute_bounded, shell_execute_with, LaunchOutcome,
};
use crate::windows_probe::{mark_test_passed, same_file};

/// The `.bat` self-reports its own path (`%~f0`) into its marker, and the extensionless copy of
/// `cosca_testbin_image` self-reports the image it loaded via `--report-to` — each into its own
/// marker file, so whichever one ran is the only one that could have written to it. No post-exit OS
/// query is needed to corroborate which image ran.
///
/// This gives `ShellExecuteExW` the same existing extensionless target as the two probes in
/// `trailing_dot.rs`, so it is wrapped in `shell_execute_bounded` too, as a precaution — this probe
/// itself was not observed to hang; see the module doc for what actually was. If `ShellExecuteExW`
/// does fail to return here, that is a hard failure: this probe never infers precedence from a call
/// that never returned.
///
/// `SEE_MASK_NOASYNC` is always set on this call too (see `shell_execute_in_apartment`'s doc), so a
/// `LaunchedNoHandle` or `ERROR_NO_ASSOCIATION` return here is a synchronous, complete fact: the
/// shell finished this call without ever handing back a process handle. A real `tool.bat` launch
/// always goes through `cmd.exe`, which always yields one — so no handle from THIS call already
/// rules out `.bat` having won through it, regardless of whether the extensionless file itself can
/// be confirmed to have run. `report_no_handle` below draws exactly that conclusion from the
/// no-handle fact alone: it does not additionally read either marker, since a marker read taken
/// immediately after this call returns would only race whatever the shell handed the file off to,
/// and could neither prove nor disprove anything about what runs after this call — nothing observed
/// after a no-handle handoff is measured by this probe.
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
    let outcome =
        shell_execute_bounded(move |state| shell_execute_with(&extensionless, None, Some(&params), None, state))
            .unwrap_or_else(|e| {
                panic!(
                    "PROBE pathext-vs-existing-extensionless: {e} — precedence is never inferred from a call \
             that never returned"
                );
            });
    let report_no_handle = |via: &str| {
        println!("PROBE pathext-vs-existing-extensionless: outcome={via}");
        println!(
            "  => {via}: no handle through THIS call means the shell either refused the \
             extensionless file outright or chose to hand it off rather than run tool.bat through \
             cmd.exe — a real .bat launch through cmd.exe always yields a process handle \
             (does_an_existing_extensionless_file_ever_launch_directly establishes the same floor \
             for the extensionless target), so PATHEXT did not outrank the existing extensionless \
             file through THIS call. What either target does after this call returns is not \
             measured here."
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
    mark_test_passed("COSCA_PROBE_MARKERS");
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
/// `does_pathext_outrank_an_existing_extensionless_file` measures instead. The failure to launch
/// measured below — a genuine negative, not a harness bug — IS the answer. Both probes hand
/// `ShellExecuteExW` the same existing extensionless target, and both always set `SEE_MASK_NOASYNC`
/// (see `shell_execute_in_apartment`'s doc), so a no-handle outcome from either is itself a
/// synchronous, measured fact from the API's return, not a race. That sibling probe uses the same
/// no-handle outcome from its own call to draw a precedence conclusion (`.bat` never got a tracked
/// process handle through it either); see its doc.
///
/// A no-handle outcome here does not, by itself, prove the file never ran, and this probe does not
/// claim it does: the two no-handle arms below report only the synchronous fact that THIS call
/// returned no process handle, and say explicitly that what happens after a handoff is unmeasured.
/// No marker is read on those arms — a read taken immediately after the call returns would only
/// race whatever the shell handed the file off to, and no wait, sleep or poll here would turn that
/// race into proof.
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
    let launched = extensionless.clone();
    let outcome = shell_execute_bounded(move |state| shell_execute_with(&launched, None, Some(&params), None, state))
        .unwrap_or_else(|e| {
            panic!("PROBE existing-extensionless-no-bat: {e}");
        });
    match outcome {
        LaunchOutcome::NotLaunched(e) if e.code() == HRESULT::from_win32(ERROR_NO_ASSOCIATION.0) => {
            println!("PROBE existing-extensionless-no-bat: launched=false, no association ({e})");
            println!(
                "  => NO, as far as THIS call is concerned. ShellExecuteEx did not run the existing \
                 extensionless file directly through this call, even when nothing else in the \
                 directory could satisfy PATHEXT: it reported ERROR_NO_ASSOCIATION synchronously \
                 rather than handing off to a picker — the same fact as the LaunchedNoHandle arm \
                 below, just surfaced differently (see the module doc). It also means anything the \
                 shell refuses this way can never be contained by cosca — there is no process handle \
                 to assign to a Job Object. What happens to the file after this call is not measured \
                 here."
            );
        }
        LaunchOutcome::NotLaunched(e) => panic!(
            "PROBE existing-extensionless-no-bat: the shell declined to launch anything with an \
             unexpected error (not ERROR_NO_ASSOCIATION): {e} — the file exists here, so \
             ERROR_FILE_NOT_FOUND would also be unexpected — so the harness itself appears to be \
             broken"
        ),
        LaunchOutcome::LaunchedNoHandle => {
            println!(
                "PROBE existing-extensionless-no-bat: launched=true, no process handle \
                 (LaunchedNoHandle)"
            );
            println!(
                "  => NO, as far as THIS call is concerned. ShellExecuteEx did not run the existing \
                 extensionless file directly through this call, even when nothing else in the \
                 directory could satisfy PATHEXT. It hands the file to an association/Open-With \
                 handler instead, which returns no process handle. It also means anything the shell \
                 hands off to this way can never be contained by cosca — there is no process handle \
                 to assign to a Job Object. What the handler does with the file afterward is not \
                 measured here."
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
    mark_test_passed("COSCA_PROBE_MARKERS");
}
