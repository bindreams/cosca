//! Unit tests for the group rules, and re-exec tests that drive one real test of the `NAMESPACES` group and one of the `ROOT` group under chosen environments. Its body never runs in these, so they are safe on any host. The re-exec tests, which exercise the macro's expansion, run on Linux only.

use crate::test_groups::{check_group, require_consent, require_enabled, Group};

fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |name| vars.iter().find(|(n, _)| *n == name).map(|(_, v)| v.to_string())
}

/// Mutant: the group variable is required to be set.
#[skuld::test]
fn an_unset_group_variable_with_consent_runs() {
    assert_eq!(
        check_group("COSCA_TEST_TRACER", env(&[("COSCA_TEST_TRACER_CONSENT", "1")])),
        Ok(true)
    );
}

/// Mutant: only `1` enables.
#[skuld::test]
fn any_group_value_but_0_runs() {
    let vars = [("COSCA_TEST_TRACER", "2"), ("COSCA_TEST_TRACER_CONSENT", "1")];
    assert_eq!(check_group("COSCA_TEST_TRACER", env(&vars)), Ok(true));
}

/// Mutant: `0` is ignored.
#[skuld::test]
fn group_0_turns_the_group_off() {
    let vars = [("COSCA_TEST_TRACER", "0"), ("COSCA_TEST_TRACER_CONSENT", "1")];
    assert_eq!(check_group("COSCA_TEST_TRACER", env(&vars)), Ok(false));
}

/// Consent is asked only of an enabled group. Mutant: consent is checked before `=0`.
#[skuld::test]
fn group_0_needs_no_consent() {
    assert_eq!(
        check_group("COSCA_TEST_TRACER", env(&[("COSCA_TEST_TRACER", "0")])),
        Ok(false)
    );
}

/// Mutant: consent defaults to given.
#[skuld::test]
fn unset_consent_fails_and_names_the_variables() {
    let why = check_group("COSCA_TEST_TRACER", env(&[])).unwrap_err();
    assert!(
        why.contains("COSCA_TEST_TRACER_CONSENT=1") && why.contains("COSCA_TEST_TRACER=0"),
        "{why}"
    );
}

/// Mutant: any non-empty consent counts.
#[skuld::test]
fn consent_other_than_1_fails() {
    for value in ["0", "yes", "true", " 1", ""] {
        let vars = [("COSCA_TEST_TRACER_CONSENT", value)];
        assert!(
            check_group("COSCA_TEST_TRACER", env(&vars)).is_err(),
            "consent {value:?} was accepted"
        );
    }
}

/// Mutant: `require_enabled` asks for consent as well, so a group lacking only consent is ignored
/// instead of failing at setup.
#[skuld::test]
fn require_enabled_fails_only_for_0() {
    assert!(require_enabled("COSCA_TEST_X", env(&[])).is_ok());
    assert!(require_enabled("COSCA_TEST_X", env(&[("COSCA_TEST_X", "2")])).is_ok());
    let why = require_enabled("COSCA_TEST_X", env(&[("COSCA_TEST_X", "0")])).unwrap_err();
    assert!(why.contains("COSCA_TEST_X=0"), "{why}");
}

/// Mutant: setup grants without consent.
#[skuld::test]
fn require_consent_grants_only_on_exactly_1() {
    assert!(matches!(
        require_consent("COSCA_TEST_X", "does a thing", env(&[("COSCA_TEST_X_CONSENT", "1")])),
        Ok(Group)
    ));
    let off = [("COSCA_TEST_X", "0"), ("COSCA_TEST_X_CONSENT", "1")];
    let why = require_consent("COSCA_TEST_X", "does a thing", env(&off))
        .err()
        .expect("a group that is off");
    assert!(why.contains("COSCA_TEST_X=0"), "{why}");
    for vars in [&[][..], &[("COSCA_TEST_X_CONSENT", "yes")]] {
        let why = require_consent("COSCA_TEST_X", "does a thing", env(vars))
            .err()
            .expect("no consent");
        assert!(
            why.contains("does a thing") && why.contains("COSCA_TEST_X_CONSENT=1"),
            "{why}"
        );
    }
}

#[cfg(target_os = "linux")]
mod reexec {
    use crate::test_reexec::{command, suite_outcome, with_json_events, SuiteOutcome, NOCAPTURE};

    /// A real `NAMESPACES` test: it unshares namespaces, so only a granted group may run it.
    const NAMESPACES_TEST: &str =
        "wait::backend::linux_namespace_tests::namespaces_a_status_mounted_over_below_proc_keeps_live_foreign_kills_working";

    /// A real `ROOT` test: it needs a DAC bypass, so only a granted group may run it.
    const ROOT_TEST: &str = "resolve::resolve_base_tests::a_denied_candidate_is_denied_by_an_exec_child";

    /// A group under test: its real test, its variable and its label.
    struct Case {
        test: &'static str,
        var: &'static str,
        label: &'static str,
    }

    const NAMESPACES: Case = Case {
        test: NAMESPACES_TEST,
        var: "COSCA_TEST_NAMESPACES",
        label: "namespaces",
    };
    const ROOT: Case = Case {
        test: ROOT_TEST,
        var: "COSCA_TEST_ROOT",
        label: "root",
    };

    /// Re-execs this binary on exactly the case's test with the group's variables set as given (`None` removes them).
    fn run_case(case: &Case, group: Option<&str>, consent: Option<&str>) -> (SuiteOutcome, bool, String) {
        run_case_with(case, &[], group, consent, None)
    }

    /// [`run_case`] with `extra` arguments, such as `--ignored`, and `SKULD_LABELS` set to `labels`.
    fn run_case_with(
        case: &Case,
        extra: &[&str],
        group: Option<&str>,
        consent: Option<&str>,
        labels: Option<&str>,
    ) -> (SuiteOutcome, bool, String) {
        let mut cmd = command(std::env::current_exe().expect("current_exe"));
        cmd.args(["--test-threads=1", "--exact", case.test, NOCAPTURE]);
        cmd.args(extra);
        with_json_events(&mut cmd);
        let consent_var = format!("{}_CONSENT", case.var);
        for (var, value) in [
            (case.var, group),
            (consent_var.as_str(), consent),
            ("SKULD_LABELS", labels),
        ] {
            match value {
                Some(value) => cmd.env(var, value),
                None => cmd.env_remove(var),
            };
        }
        let output = crate::test_spawn::output_captured(&mut cmd).expect("re-exec this test binary");
        let outcome = suite_outcome(&output.stdout).expect("the child reports its suite");
        (
            outcome,
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
        )
    }

    fn assert_group_zero_reports_ignored(case: &Case) {
        let (outcome, success, stdout) = run_case(case, Some("0"), Some("1"));
        assert_eq!(
            outcome,
            SuiteOutcome {
                test_count: 1,
                passed: 0,
                failed: 0,
                ignored: 1
            },
            "{stdout}"
        );
        assert!(success, "{stdout}");
    }

    fn assert_consent_refused(case: &Case, consent: Option<&str>) {
        let (outcome, success, stdout) = run_case(case, None, consent);
        assert_eq!(outcome.failed, 1, "{stdout}");
        assert_eq!(outcome.passed + outcome.ignored, 0, "{stdout}");
        assert!(!success, "{stdout}");
        assert!(stdout.contains(&format!("{}_CONSENT=1", case.var)), "{stdout}");
    }

    fn assert_zero_never_runs_the_body_under_run_ignored(case: &Case) {
        let (outcome, success, stdout) = run_case_with(case, &["--ignored"], Some("0"), Some("1"), None);
        assert_eq!(outcome.test_count, 1, "{stdout}");
        assert_eq!(outcome.passed, 0, "{stdout}");
        assert_eq!((outcome.failed, outcome.ignored), (1, 0), "{stdout}");
        assert!(!success, "{stdout}");
        // A body that ran would fail on `unshare` or the DAC check too (unprivileged), so `failed` alone proves nothing: only the
        // test's own `failed` event carries the fixture's refusal. (The whole output cannot tell: skuld prints the
        // unavailable-test list after every run.)
        let failure = stdout
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|event| event["type"] == "test" && event["event"] == "failed" && event["name"] == case.test)
            .unwrap_or_else(|| panic!("no `failed` event for the test: {stdout}"));
        let message = failure["stdout"].as_str().unwrap_or_default();
        assert!(message.contains(&format!("setup failed: {}=0", case.var)), "{failure}");
    }

    fn assert_label_selects(case: &Case) {
        let (outcome, _, stdout) = run_case_with(case, &[], Some("0"), Some("1"), Some(case.label));
        assert_eq!(outcome.test_count, 1, "{stdout}");
        let (outcome, _, stdout) = run_case_with(case, &[], Some("0"), Some("1"), Some(&format!("!{}", case.label)));
        assert_eq!(outcome.test_count, 0, "{stdout}");
    }

    /// Mutant: the group's `requires` never fails, so `=0` runs the test.
    #[skuld::test]
    fn group_zero_reports_ignored() {
        assert_group_zero_reports_ignored(&NAMESPACES);
    }

    /// Mutant: the group's setup does not check consent (the body then runs where it may).
    #[skuld::test]
    fn unset_consent_fails() {
        assert_consent_refused(&NAMESPACES, None);
    }

    /// Mutant: any non-empty consent counts.
    #[skuld::test]
    fn consent_other_than_1_fails() {
        assert_consent_refused(&NAMESPACES, Some("yes"));
    }

    /// Mutant: the setup grants a group that is off.
    #[skuld::test]
    fn group_zero_never_runs_the_body_under_run_ignored() {
        assert_zero_never_runs_the_body_under_run_ignored(&NAMESPACES);
    }

    /// Mutant: the group's fixture carries no label, so `SKULD_LABELS=namespaces` selects none of its tests.
    #[skuld::test]
    fn the_group_label_selects_its_tests() {
        assert_label_selects(&NAMESPACES);
    }

    /// Mutant: the `ROOT` row's `requires` never fails, so `=0` runs the test.
    #[skuld::test]
    fn root_group_zero_reports_ignored() {
        assert_group_zero_reports_ignored(&ROOT);
    }

    /// Mutant: the `ROOT` setup does not check consent.
    #[skuld::test]
    fn root_unset_consent_fails() {
        assert_consent_refused(&ROOT, None);
    }

    /// Mutant: any non-empty consent counts for `ROOT`.
    #[skuld::test]
    fn root_consent_other_than_1_fails() {
        assert_consent_refused(&ROOT, Some("yes"));
    }

    /// Mutant: the `ROOT` setup grants a group that is off.
    #[skuld::test]
    fn root_group_zero_never_runs_the_body_under_run_ignored() {
        assert_zero_never_runs_the_body_under_run_ignored(&ROOT);
    }

    /// Mutant: the `ROOT` fixture carries no label. The test drops the module default
    /// (`labels = []`), so the fixture's label alone selects it.
    #[skuld::test]
    fn the_root_label_selects_its_tests() {
        assert_label_selects(&ROOT);
    }
}
