//! The one place that decides how a test re-executes its own test binary.
//!
//! Skuld reads `SKULD_LABELS` and `SKULD_NEXTEST_METADATA_PATH` from its environment. A child that
//! inherits `SKULD_LABELS` selects the labelled tests only, so a fixture without the driver's
//! label lists zero tests and exits 0; one that inherits `SKULD_NEXTEST_METADATA_PATH` overwrites
//! the caller's metadata file. Every re-exec removes both ([`command`], or [`scrub_env`] for a
//! command type that is not `std`'s).
//!
//! Skuld's output capture is fd-level and drops a passing test's bytes, so a child whose stdout or
//! stderr the driver reads also runs with [`NOCAPTURE`] ([`fixture_args`] includes it).
//!
//! A driver that checks what its child ran adds [`JSON_FORMAT`] and reads [`suite_outcome`], not
//! the human-readable summary.
//!
//! Also mounted by `#[path]` into `tests/common` (as a sibling of `test_own_process`), so it
//! names nothing of its crate.

/// The skuld variables a re-exec'd child must not inherit.
pub const SCRUBBED_ENV: [&str; 2] = ["SKULD_LABELS", "SKULD_NEXTEST_METADATA_PATH"];

/// Keeps skuld from capturing the child's output.
pub const NOCAPTURE: &str = "--nocapture";

/// `Command::new(program)` for re-executing a test binary, without the [`SCRUBBED_ENV`] variables.
///
/// A raw `tokio::process::Command` takes this value through `From`.
pub fn command(program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
    let mut command = std::process::Command::new(program);
    scrub_env(|var| _ = command.env_remove(var));
    command
}

/// Calls `remove` with each [`SCRUBBED_ENV`] variable, for a `cosca::Command` or
/// `crate::tokio::Command`, which cannot be built by [`command`].
pub fn scrub_env(mut remove: impl FnMut(&str)) {
    for var in SCRUBBED_ENV {
        remove(var);
    }
}

/// The argv (after the program name) that runs exactly one fixture, single-threaded, uncaptured.
pub fn fixture_args(fixture: &str) -> [&str; 4] {
    ["--test-threads=1", "--exact", fixture, NOCAPTURE]
}

/// Makes the child print its test events as JSON lines on stdout, for [`suite_outcome`].
pub const JSON_FORMAT: [&str; 2] = ["--format", "json"];

/// Makes `cmd`'s child print its test events as JSON lines, for [`suite_outcome`]. Every launcher
/// whose child is checked with [`suite_passed_exactly_one`] adds it here.
pub fn with_json_events(cmd: &mut std::process::Command) -> &mut std::process::Command {
    cmd.args(JSON_FORMAT)
}

/// What a skuld run reported about itself.
#[derive(Debug, PartialEq, Eq)]
pub struct SuiteOutcome {
    pub test_count: u64,
    pub passed: u64,
    pub failed: u64,
    pub ignored: u64,
}

/// Reads the suite events of a skuld run started with [`JSON_FORMAT`].
///
/// Lines that are not JSON objects (a test body's own output under [`NOCAPTURE`], say) are logged
/// at debug level and skipped. The run needs exactly one `started` event, which carries the test
/// count, and exactly one terminal (`ok` or `failed`) event, which carries the tallies; a run that
/// died early, or one whose output was concatenated with another's, is an `Err`.
pub fn suite_outcome(stdout: &[u8]) -> Result<SuiteOutcome, String> {
    let mut started = Vec::new();
    let mut terminal = Vec::new();
    for line in String::from_utf8_lossy(stdout).lines() {
        let event = match serde_json::from_str::<serde_json::Value>(line) {
            Ok(event) if event.is_object() => event,
            _ => {
                log::debug!("not a JSON event: {line:?}");
                continue;
            }
        };
        if event["type"] != "suite" {
            continue;
        }
        match event["event"].as_str() {
            Some("started") => started.push(event),
            Some("ok" | "failed") => terminal.push(event),
            other => return Err(format!("a suite event of unknown kind {other:?}: {line}")),
        }
    }
    let [started] = started.as_slice() else {
        return Err(format!(
            "expected exactly one suite `started` event, found {} (the child must run with `--format json`)",
            started.len()
        ));
    };
    let [terminal] = terminal.as_slice() else {
        return Err(format!(
            "expected exactly one terminal suite event (`ok` or `failed`), found {}",
            terminal.len()
        ));
    };
    let count = |event: &serde_json::Value, field: &str| {
        event[field]
            .as_u64()
            .ok_or_else(|| format!("the suite event {event} has no numeric `{field}`"))
    };
    Ok(SuiteOutcome {
        test_count: count(started, "test_count")?,
        passed: count(terminal, "passed")?,
        failed: count(terminal, "failed")?,
        ignored: count(terminal, "ignored")?,
    })
}

/// `Ok` if the child exited successfully and listed exactly one test, which passed.
///
/// The exit status is checked as well as the events: skuld can still fail the process after it
/// printed the `ok` event (its `fail_on_violations`, exit 101).
pub fn suite_passed_exactly_one(output: &std::process::Output) -> Result<(), String> {
    if !output.status.success() {
        return Err(format!("the child exited with {}", output.status));
    }
    let outcome = suite_outcome(&output.stdout)?;
    if outcome.test_count == 1 && outcome.passed == 1 && outcome.failed == 0 {
        Ok(())
    } else {
        Err(format!(
            "expected exactly one test run and passed, got {outcome:?}; `--exact` probably matched none"
        ))
    }
}
