//! How a canary records and reports the facts it checks.

use crate::provenance::announce_platform;
use crate::pure::marker_file_name;
use crate::verdict::{conclude, Disagreements};
use crate::winapi::{full_path_name, has_bat_extension};

/// Run a canary: stamp the OS build, run `body` with the facts it checks and the measurement
/// failures it hits, then [`conclude`]. `subject` names what the facts are about.
pub(crate) fn canary(subject: &'static str, body: impl FnOnce(&mut Disagreements, &mut Vec<String>)) {
    let mut failures: Vec<String> = announce_platform().err().into_iter().collect();
    let mut facts = Disagreements::about(subject);
    body(&mut facts, &mut failures);
    conclude(&failures, &facts, mark_canary_passed);
}

/// Record that this canary passed, as a file named after the test in `$COSCA_CANARY_MARKERS`
/// when that is set. The workflow fails a run that leaves no marker, so a test-name filter that
/// selects only surveys, or nothing, cannot pass having asserted nothing.
fn mark_canary_passed() {
    let Some(dir) = std::env::var_os("COSCA_CANARY_MARKERS") else {
        return;
    };
    let name = std::thread::current()
        .name()
        .map(marker_file_name)
        .expect("libtest names each test's thread");
    let path = std::path::Path::new(&dir).join(&name);
    std::fs::write(&path, b"").unwrap_or_else(|e| panic!("could not write the canary marker {path:?}: {e}"));
}

/// One expected `GetFullPathNameW` result: `(input, the result, why)`.
pub(crate) type Resolution = (String, String, &'static str);

/// Check each row's `GetFullPathNameW` result exactly, printing every one.
pub(crate) fn check_resolutions(rows: &[Resolution], facts: &mut Disagreements, failures: &mut Vec<String>) {
    for (input, want, why) in rows {
        match full_path_name(input) {
            Ok(resolved) => {
                println!(
                    "  {input:?} -> {resolved:?}  std_has_bat_extension={}  ({why})",
                    has_bat_extension(&resolved)
                );
                facts.check(
                    &resolved == want,
                    &format!("{input:?} resolves to {want:?} ({why})"),
                    format_args!("{resolved:?}"),
                );
            }
            Err(why) => failures.push(why),
        }
    }
}

/// Rows whose input and result are both literal.
pub(crate) fn literal_rows(rows: &[(&str, &str, &'static str)]) -> Vec<Resolution> {
    rows.iter()
        .map(|&(input, want, why)| (input.to_string(), want.to_string(), why))
        .collect()
}
