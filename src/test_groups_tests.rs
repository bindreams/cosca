//! Unit tests for the group rules, and re-exec tests that drive one real `NAMESPACES` test under chosen environments. Its body never runs in these, so they are safe on any host. The re-exec tests, which exercise the macro's expansion, run on Linux only.

use crate::test_groups::{check_group, require_consent, require_enabled, Group};
use crate::test_harness::{ELEVATION_ROUTES, NAMESPACES, PATH_PROBES, SHELL_EXECUTE, SHELL_PROBES};

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

/// Mutant: a row's fixture carries no label, or another row's, so `SKULD_LABELS=<label>` selects none of its tests (or someone else's).
#[skuld::test]
fn every_group_fixture_carries_exactly_its_label() {
    for (fixture, label) in [
        ("namespaces", NAMESPACES),
        ("path_probes", PATH_PROBES),
        ("shell_execute", SHELL_EXECUTE),
        ("shell_probes", SHELL_PROBES),
        ("elevation_routes", ELEVATION_ROUTES),
    ] {
        assert_eq!(skuld::fixture::collect_fixture_labels(&[fixture]), [label], "{fixture}");
    }
}

#[cfg(target_os = "linux")]
mod reexec {
    use crate::test_reexec::{command, suite_outcome, with_json_events, SuiteOutcome, NOCAPTURE};

    /// A real `NAMESPACES` test: it unshares namespaces, so only a granted group may run it.
    const NAMESPACES_TEST: &str =
        "wait::backend::linux_namespace_tests::namespaces_a_status_mounted_over_below_proc_keeps_live_foreign_kills_working";

    /// Re-execs this binary on exactly [`NAMESPACES_TEST`] with the group's variables set as given (`None` removes them).
    fn run_namespaces_test(group: Option<&str>, consent: Option<&str>) -> (SuiteOutcome, bool, String) {
        run_namespaces_test_with(&[], group, consent, None)
    }

    /// [`run_namespaces_test`] with `extra` arguments, such as `--ignored`, and `SKULD_LABELS` set to `labels`.
    fn run_namespaces_test_with(
        extra: &[&str],
        group: Option<&str>,
        consent: Option<&str>,
        labels: Option<&str>,
    ) -> (SuiteOutcome, bool, String) {
        let mut cmd = command(std::env::current_exe().expect("current_exe"));
        cmd.args(["--test-threads=1", "--exact", NAMESPACES_TEST, NOCAPTURE]);
        cmd.args(extra);
        with_json_events(&mut cmd);
        for (var, value) in [
            ("COSCA_TEST_NAMESPACES", group),
            ("COSCA_TEST_NAMESPACES_CONSENT", consent),
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

    /// Mutant: the group's `requires` never fails, so `=0` runs the test.
    #[skuld::test]
    fn group_zero_reports_ignored() {
        let (outcome, success, stdout) = run_namespaces_test(Some("0"), Some("1"));
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

    /// Mutant: the group's setup does not check consent (the body then runs where it may).
    #[skuld::test]
    fn unset_consent_fails() {
        let (outcome, success, stdout) = run_namespaces_test(None, None);
        assert_eq!(outcome.failed, 1, "{stdout}");
        assert_eq!(outcome.passed + outcome.ignored, 0, "{stdout}");
        assert!(!success, "{stdout}");
        assert!(stdout.contains("COSCA_TEST_NAMESPACES_CONSENT=1"), "{stdout}");
    }

    /// Mutant: any non-empty consent counts.
    #[skuld::test]
    fn consent_other_than_1_fails() {
        let (outcome, success, stdout) = run_namespaces_test(None, Some("yes"));
        assert_eq!(outcome.failed, 1, "{stdout}");
        assert_eq!(outcome.passed + outcome.ignored, 0, "{stdout}");
        assert!(!success, "{stdout}");
        assert!(stdout.contains("COSCA_TEST_NAMESPACES_CONSENT=1"), "{stdout}");
    }

    /// Mutant: the setup grants a group that is off.
    #[skuld::test]
    fn group_zero_never_runs_the_body_under_run_ignored() {
        let (outcome, success, stdout) = run_namespaces_test_with(&["--ignored"], Some("0"), Some("1"), None);
        assert_eq!(outcome.test_count, 1, "{stdout}");
        assert_eq!(outcome.passed, 0, "{stdout}");
        assert_eq!((outcome.failed, outcome.ignored), (1, 0), "{stdout}");
        assert!(!success, "{stdout}");
        // A body that ran would fail on `unshare` too (unprivileged), so `failed` alone proves nothing: only the
        // test's own `failed` event carries the fixture's refusal. (The whole output cannot tell: skuld prints the
        // unavailable-test list after every run.)
        let failure = stdout
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|event| event["type"] == "test" && event["event"] == "failed" && event["name"] == NAMESPACES_TEST)
            .unwrap_or_else(|| panic!("no `failed` event for the test: {stdout}"));
        let message = failure["stdout"].as_str().unwrap_or_default();
        assert!(message.contains("setup failed: COSCA_TEST_NAMESPACES=0"), "{failure}");
    }

    /// Mutant: the group's fixture carries no label, so `SKULD_LABELS=namespaces` selects none of its tests.
    #[skuld::test]
    fn the_group_label_selects_its_tests() {
        let (outcome, _, stdout) = run_namespaces_test_with(&[], Some("0"), Some("1"), Some("namespaces"));
        assert_eq!(outcome.test_count, 1, "{stdout}");
        let (outcome, _, stdout) = run_namespaces_test_with(&[], Some("0"), Some("1"), Some("!namespaces"));
        assert_eq!(outcome.test_count, 0, "{stdout}");
    }
}
