//! Unit tests for the group rules, and re-exec tests that drive one real `NAMESPACES` test, one real `ROOT` test, one real `CGROUP` test and one real `TRACER` test under chosen environments. None of the bodies runs, so they are safe on any host. The re-exec tests, which exercise the macro's expansion, run on Linux only.

use crate::test_groups::{check_group, require_consent, require_enabled, StrayLeaves};
use crate::test_harness::{
    CGROUP, DRIVE_MAPPING, ELEVATION_ROUTES, NAMESPACES, PATH_PROBES, ROOT, SETUID, SHELL_EXECUTE, SHELL_PROBES,
    TRACER, UID_SWITCH,
};

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

/// Mutant: a set group variable counts as consent.
#[skuld::test]
fn group_on_without_consent_fails_and_names_the_consent_variable() {
    for vars in [&[("COSCA_TEST_TRACER", "1")][..], &[("COSCA_TEST_TRACER", "2")]] {
        let why = check_group("COSCA_TEST_TRACER", env(vars)).unwrap_err();
        assert!(why.contains("COSCA_TEST_TRACER_CONSENT=1"), "{why}");
        let why = require_consent("COSCA_TEST_TRACER", "does a thing", env(vars))
            .err()
            .expect("no consent");
        assert!(why.contains("COSCA_TEST_TRACER_CONSENT=1"), "{why}");
    }
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
    assert!(require_consent("COSCA_TEST_X", "does a thing", env(&[("COSCA_TEST_X_CONSENT", "1")])).is_ok());
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
        ("root", ROOT),
        ("namespaces", NAMESPACES),
        ("drive_mapping", DRIVE_MAPPING),
        ("setuid", SETUID),
        ("path_probes", PATH_PROBES),
        ("shell_execute", SHELL_EXECUTE),
        ("shell_probes", SHELL_PROBES),
        ("elevation_routes", ELEVATION_ROUTES),
        ("cgroup", CGROUP),
        ("tracer_group", TRACER),
        ("uid_switch", UID_SWITCH),
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

    /// A real `ROOT` test: it needs a DAC bypass, so only a granted group may run it.
    const ROOT_TEST: &str = "resolve::resolve_base_tests::a_denied_candidate_is_denied_by_an_exec_child";

    /// A real `CGROUP` test, outside `containment::cgroup`, so only its fixture labels it `cgroup`.
    /// It makes cgroup leaves, so only a granted group may run it.
    const CGROUP_TEST: &str =
        "child::spawn::spawn_tests::cgroup_sync_identity_failure_settles_the_leaf_verdict_before_the_kill";

    /// A real `TRACER` test: it attaches a tracer with `ptrace`, so only a granted group may run it.
    const TRACER_TEST: &str = "child::shared::shared_tests::tracer::try_wait_leaves_a_ptrace_stop_for_the_tracer";

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

    const CGROUP: Case = Case {
        test: CGROUP_TEST,
        var: "COSCA_TEST_CGROUP",
        label: "cgroup",
    };

    const TRACER: Case = Case {
        test: TRACER_TEST,
        var: "COSCA_TEST_TRACER",
        label: "tracer",
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
        let (outcome, success, stdout) = run_case(case, Some("0"), None);
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
        assert_consent_refused_with(case, None, consent);
    }

    fn assert_consent_refused_with(case: &Case, group: Option<&str>, consent: Option<&str>) {
        let (outcome, success, stdout) = run_case(case, group, consent);
        assert_eq!(outcome.failed, 1, "{stdout}");
        assert_eq!(outcome.passed + outcome.ignored, 0, "{stdout}");
        assert!(!success, "{stdout}");
        assert!(stdout.contains(&format!("{}_CONSENT=1", case.var)), "{stdout}");
    }

    fn assert_zero_never_runs_the_body_under_run_ignored(case: &Case) {
        let (outcome, success, stdout) = run_case_with(case, &["--ignored"], Some("0"), None, None);
        assert_eq!(outcome.test_count, 1, "{stdout}");
        assert_eq!(outcome.passed, 0, "{stdout}");
        assert_eq!((outcome.failed, outcome.ignored), (1, 0), "{stdout}");
        assert!(!success, "{stdout}");
        // `failed` alone proves nothing (a body that ran would fail unprivileged too): only the test's own `failed`
        // event carries the fixture's refusal. The whole output cannot tell: skuld lists unavailable tests after every run.
        let failure = stdout
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|event| event["type"] == "test" && event["event"] == "failed" && event["name"] == case.test)
            .unwrap_or_else(|| panic!("no `failed` event for the test: {stdout}"));
        let message = failure["stdout"].as_str().unwrap_or_default();
        assert!(message.contains(&format!("setup failed: {}=0", case.var)), "{failure}");
    }

    fn assert_label_selects(case: &Case) {
        let (outcome, _, stdout) = run_case_with(case, &[], Some("0"), None, Some(case.label));
        assert_eq!(outcome.test_count, 1, "{stdout}");
        let (outcome, _, stdout) = run_case_with(case, &[], Some("0"), None, Some(&format!("!{}", case.label)));
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

    /// Mutant: an enabled group needs no consent. `=1` is not consent.
    #[skuld::test]
    fn group_one_without_consent_fails() {
        assert_consent_refused_with(&NAMESPACES, Some("1"), None);
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

    /// Mutant: an enabled `ROOT` group needs no consent. `=1` is not consent.
    #[skuld::test]
    fn root_group_one_without_consent_fails() {
        assert_consent_refused_with(&ROOT, Some("1"), None);
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

    /// Mutant: the `CGROUP` row's `requires` never fails, so `=0` runs the test.
    #[skuld::test]
    fn cgroup_group_zero_reports_ignored() {
        assert_group_zero_reports_ignored(&CGROUP);
    }

    /// Mutant: an enabled `CGROUP` group needs no consent. `=1` is not consent.
    #[skuld::test]
    fn cgroup_group_one_without_consent_fails() {
        assert_consent_refused_with(&CGROUP, Some("1"), None);
    }

    /// Mutant: the `CGROUP` setup does not check consent.
    #[skuld::test]
    fn cgroup_unset_consent_fails() {
        assert_consent_refused(&CGROUP, None);
    }

    /// Mutant: any non-empty consent counts for `CGROUP`.
    #[skuld::test]
    fn cgroup_consent_other_than_1_fails() {
        assert_consent_refused(&CGROUP, Some("yes"));
    }

    /// Mutant: the `CGROUP` setup grants a group that is off.
    #[skuld::test]
    fn cgroup_group_zero_never_runs_the_body_under_run_ignored() {
        assert_zero_never_runs_the_body_under_run_ignored(&CGROUP);
    }

    /// Mutant: the `CGROUP` fixture carries no label. The test sits outside `containment::cgroup`,
    /// so the fixture's label alone selects it.
    #[skuld::test]
    fn the_cgroup_label_selects_its_tests() {
        assert_label_selects(&CGROUP);
    }

    /// Mutant: the `TRACER` row's `requires` never fails, so `=0` runs the test.
    #[skuld::test]
    fn tracer_group_zero_reports_ignored() {
        assert_group_zero_reports_ignored(&TRACER);
    }

    /// Mutant: an enabled `TRACER` group needs no consent. `=1` is not consent.
    #[skuld::test]
    fn tracer_group_one_without_consent_fails() {
        assert_consent_refused_with(&TRACER, Some("1"), None);
    }

    /// Mutant: the `TRACER` setup does not check consent.
    #[skuld::test]
    fn tracer_unset_consent_fails() {
        assert_consent_refused(&TRACER, None);
    }

    /// Mutant: any non-empty consent counts for `TRACER`.
    #[skuld::test]
    fn tracer_consent_other_than_1_fails() {
        assert_consent_refused(&TRACER, Some("yes"));
    }

    /// Mutant: the `TRACER` setup grants a group that is off.
    #[skuld::test]
    fn tracer_group_zero_never_runs_the_body_under_run_ignored() {
        assert_zero_never_runs_the_body_under_run_ignored(&TRACER);
    }

    /// Mutant: the `TRACER` fixture carries no label, so `SKULD_LABELS=tracer` selects none of its tests.
    #[skuld::test]
    fn the_tracer_label_selects_its_tests() {
        assert_label_selects(&TRACER);
    }
}

/// A leaf of this pid left in the cgroup fails the test that ended with it. Mutant: the check is deleted.
#[skuld::test]
fn a_leaf_left_behind_fails_the_test_that_made_it() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(format!("cosca-{}-0-abc", std::process::id()))).unwrap();
    let stray = StrayLeaves {
        own_cgroup: Some(dir.path().to_path_buf()),
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(stray)));
    assert!(outcome.is_err(), "a leaf was left behind and the check passed");
}

/// Another process's leaf, and an empty cgroup, are not this test's.
#[skuld::test]
fn only_this_pids_leaves_are_strays() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(format!("cosca-{}-0-abc", std::process::id() + 1))).unwrap();
    std::fs::create_dir(dir.path().join("unrelated")).unwrap();
    drop(StrayLeaves {
        own_cgroup: Some(dir.path().to_path_buf()),
    });
}
