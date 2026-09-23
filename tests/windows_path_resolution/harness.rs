//! How a canary records and reports the facts it checks.

use crate::provenance::announce_platform;
use crate::winapi::{full_path_name, has_bat_extension};

/// Run a canary: stamp the OS build, run `body` with the facts it checks and the measurement
/// failures it hits, then fail on a failure, on a broken fact, on no fact checked, or on an unmet
/// coverage requirement, in that order. `subject` names what the facts are about.
pub(crate) fn canary(subject: &'static str, body: impl FnOnce(&mut Disagreements, &mut Vec<String>)) {
    let mut failures: Vec<String> = announce_platform().err().into_iter().collect();
    let mut facts = Disagreements::about(subject);
    body(&mut facts, &mut failures);
    assert!(
        failures.is_empty(),
        "the measurement could not be taken: {}",
        failures.join("; ")
    );
    facts.assert_none();
    facts.assert_covered();
}

/// Platform facts a canary found no longer hold. Distinct from a measurement that could not be
/// taken: that is a broken probe, this is a changed platform.
pub(crate) struct Disagreements {
    /// What the facts are about, named in the failure: `Windows`, or `Windows and Rust's
    /// std::process` when the route under test runs through std.
    subject: &'static str,
    broken: Vec<String>,
    /// Facts checked so far, broken or not.
    checked: usize,
    /// Coverage the canary required and did not get, checked after the facts: a platform change
    /// that explains the shortfall is reported first.
    unmet: Vec<String>,
}

impl Disagreements {
    pub(crate) fn about(subject: &'static str) -> Self {
        Self {
            subject,
            broken: Vec::new(),
            checked: 0,
            unmet: Vec::new(),
        }
    }

    /// Record `fact` as broken unless `holds`, with what was measured instead.
    pub(crate) fn check(&mut self, holds: bool, fact: &str, measured: impl std::fmt::Display) {
        self.checked += 1;
        if !holds {
            self.broken.push(format!("{fact} — measured {measured}"));
        }
    }

    /// Fail the test if any fact disagreed, or if none was checked: a canary whose loops never ran
    /// has measured nothing. Call after the measurement-failure assert, so a broken probe is
    /// reported as one rather than as a platform change.
    /// Require `covered`, or report `shortfall` as a measurement that could not be taken.
    pub(crate) fn require(&mut self, covered: bool, shortfall: String) {
        if !covered {
            self.unmet.push(shortfall);
        }
    }

    fn assert_covered(&self) {
        assert!(
            self.unmet.is_empty(),
            "the measurement could not be taken: {}",
            self.unmet.join("; ")
        );
    }

    fn assert_none(&self) {
        println!("facts checked: {}", self.checked);
        assert!(
            self.checked > 0,
            "the measurement could not be taken: this canary checked no fact"
        );
        assert!(
            self.broken.is_empty(),
            "The measured behaviour of {} has changed. Any code that models these facts (cosca's \
             batch gate among it) must be re-derived from the new behaviour. Facts that changed:\n  {}",
            self.subject,
            self.broken.join("\n  ")
        );
        mark_canary_passed();
    }
}

/// Record that this canary passed, as a file named after the test in `$COSCA_CANARY_MARKERS`
/// when that is set. The workflow fails a run that leaves no marker, so a test-name filter that
/// selects only surveys, or nothing, cannot pass having asserted nothing.
pub(crate) fn mark_canary_passed() {
    let Some(dir) = std::env::var_os("COSCA_CANARY_MARKERS") else {
        return;
    };
    let name = std::thread::current()
        .name()
        .expect("libtest names each test's thread")
        .to_string();
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
