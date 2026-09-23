//! A canary's verdict: the facts it checked, and the order its failures are reported in. Free of
//! Win32, so `windows_path_logic` tests it on every host.

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

    /// Fail the test if any fact disagreed, or if none was checked: a canary whose loops never ran
    /// has measured nothing. Call after the measurement-failure assert, so a broken probe is
    /// reported as one rather than as a platform change.
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
    }
}

/// Fail on a measurement failure, then on no fact checked or a broken fact, then on an unmet
/// coverage requirement, in that order, and only then call `mark_passed`. A platform change that
/// explains a coverage shortfall is therefore reported as the change, and no canary that fails
/// any check is marked as passed.
pub(crate) fn conclude(failures: &[String], facts: &Disagreements, mark_passed: impl FnOnce()) {
    assert!(
        failures.is_empty(),
        "the measurement could not be taken: {}",
        failures.join("; ")
    );
    facts.assert_none();
    facts.assert_covered();
    mark_passed();
}
