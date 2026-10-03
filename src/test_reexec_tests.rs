use crate::test_child::fixture_path;
use crate::test_harness::REEXEC_SELFCHECK;
use crate::test_reexec::{command, suite_outcome, suite_passed_exactly_one, SuiteOutcome, JSON_FORMAT, NOCAPTURE};

// Real child runs =====

/// Re-execs this binary on exactly `test` through [`command`], with `SKULD_LABELS` set to `labels`
/// on the child's own `Command` when given.
fn run_json(test: &str, labels: Option<&str>) -> std::process::Output {
    let mut cmd = command(std::env::current_exe().expect("current_exe"));
    cmd.args(["--test-threads=1", "--exact", test, NOCAPTURE])
        .args(JSON_FORMAT);
    if let Some(labels) = labels {
        cmd.env("SKULD_LABELS", labels);
    }
    crate::test_spawn::output_captured(&mut cmd).expect("re-exec this test binary")
}

/// The one test `suite_outcome_reads_a_real_one_test_run` and the others re-exec.
#[skuld::test]
fn fixture_a_trivial_passing_test() {}

fn one_test_run() -> std::process::Output {
    run_json(fixture_path!(fixture_a_trivial_passing_test), None)
}

/// `output` with its stdout replaced.
fn with_stdout(output: &std::process::Output, stdout: &str) -> std::process::Output {
    std::process::Output {
        status: output.status,
        stdout: stdout.as_bytes().to_vec(),
        stderr: Vec::new(),
    }
}

#[skuld::test]
fn suite_outcome_reads_a_real_zero_test_run() {
    let run = run_json("__cosca_no_such_test__", None);
    let outcome = suite_outcome(&run.stdout).expect("a zero-test run still reports its suite");
    assert_eq!(
        outcome,
        SuiteOutcome {
            test_count: 0,
            passed: 0,
            failed: 0,
            ignored: 0
        }
    );
    assert!(suite_passed_exactly_one(&run).is_err());
}

#[skuld::test]
fn suite_outcome_reads_a_real_one_test_run() {
    let run = one_test_run();
    assert_eq!(
        suite_outcome(&run.stdout).expect("a real run"),
        SuiteOutcome {
            test_count: 1,
            passed: 1,
            failed: 0,
            ignored: 0
        }
    );
    suite_passed_exactly_one(&run).expect("exactly one test passed");
}

#[skuld::test]
fn suite_outcome_rejects_missing_or_repeated_terminal_events() {
    let run = one_test_run();
    let real = String::from_utf8(run.stdout.clone()).expect("utf-8 output");
    let (without_terminal, _) = real
        .rsplit_once(r#"{ "type": "suite", "event": "ok""#)
        .expect("the real run ends in a terminal suite event");
    let err = suite_outcome(without_terminal.as_bytes()).expect_err("a truncated capture");
    assert!(err.contains("terminal"), "{err}");
    assert!(suite_passed_exactly_one(&with_stdout(&run, without_terminal)).is_err());

    let doubled = real.repeat(2);
    let err = suite_outcome(doubled.as_bytes()).expect_err("a doubled capture");
    assert!(err.contains("started"), "{err}");
    assert!(suite_passed_exactly_one(&with_stdout(&run, &doubled)).is_err());

    let err = suite_outcome(b"").expect_err("no output at all");
    assert!(err.contains("started"), "{err}");
}

#[skuld::test]
fn suite_outcome_reads_a_failed_run_and_skips_other_lines() {
    let stdout = concat!(
        "not json\n",
        "42\n",
        "{ \"type\": \"suite\", \"event\": \"started\", \"test_count\": 2 }\n",
        "{ \"type\": \"test\", \"event\": \"started\", \"name\": \"a\" }\n",
        "{ \"type\": \"suite\", \"event\": \"failed\", \"passed\": 1, \"failed\": 1, \"ignored\": 0 }\n",
    );
    let outcome = suite_outcome(stdout.as_bytes()).expect("a failed suite is still an outcome");
    assert_eq!(
        outcome,
        SuiteOutcome {
            test_count: 2,
            passed: 1,
            failed: 1,
            ignored: 0
        }
    );
    assert!(suite_passed_exactly_one(&with_stdout(&one_test_run(), stdout)).is_err());
}

/// Skuld can fail the process after printing its `ok` event.
#[skuld::test]
fn a_failing_exit_status_fails_a_run_whose_events_say_ok() {
    // A real failing status, from a child that is not this binary.
    let failing = crate::test_spawn::output_captured(&mut {
        let mut cmd = std::process::Command::new(std::env::current_exe().expect("current_exe"));
        cmd.arg("--no-such-flag");
        cmd
    })
    .expect("run with a bad flag");
    assert!(!failing.status.success());
    let ok_events = with_stdout(&failing, std::str::from_utf8(&one_test_run().stdout).expect("utf-8"));
    let err = suite_passed_exactly_one(&ok_events).expect_err("a failing status");
    assert!(err.contains("exited"), "{err}");
}

// The scrub =====

#[skuld::test]
fn reexec_command_scrubs_skuld_env() {
    let cmd = command("x");
    for var in ["SKULD_LABELS", "SKULD_NEXTEST_METADATA_PATH"] {
        assert!(
            cmd.get_envs().any(|(k, v)| k == var && v.is_none()),
            "{var} is not removed"
        );
    }
}

/// Re-execs a fixture that carries no label, from a driver that does. Run by
/// [`a_labelled_reexec_still_runs_its_fixture`] with `SKULD_LABELS` set; also an ordinary test.
#[skuld::test(labels = [REEXEC_SELFCHECK])]
fn fixture_labelled_driver_reexecs_an_unlabelled_fixture() {
    let out = run_json(fixture_path!(fixture_a_trivial_passing_test), None);
    suite_passed_exactly_one(&out).unwrap_or_else(|e| {
        panic!(
            "the unlabelled fixture did not run: {e}\n--- stdout ---\n{}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
}

#[skuld::test]
fn a_labelled_reexec_still_runs_its_fixture() {
    let out = run_json(
        fixture_path!(fixture_labelled_driver_reexecs_an_unlabelled_fixture),
        Some("reexec_selfcheck"),
    );
    assert!(
        out.status.success(),
        "the labelled driver failed:\n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    suite_passed_exactly_one(&out).expect("the driver itself ran and passed");
}
