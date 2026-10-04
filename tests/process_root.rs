//! `foreign_kill_surfaces_permission_denied`: a foreign, unprivileged caller's `kill` on a foreign,
//! unprivileged target surfaces `EPERM` as `Err`, never `Ok`. It is the `UID_SWITCH` group
//! (`COSCA_TEST_UID_SWITCH`, principles 9 and 10): it runs as root and switches to real uids.
//! The group's fixture is the gate (`src/test_groups.rs`).

#[path = "common/mod.rs"]
mod common;

#[cfg(unix)]
use common::test_groups::{uid_switch, Group};

/// Set on the re-exec'd reader to `<parent pid>:<target pid>`; `main` then runs
/// [`foreign_kill_helper_main`] instead of skuld. See [`helper_role`].
#[cfg(unix)]
const ENV_TARGET_PID: &str = "COSCA_FOREIGN_KILL_TARGET_PID";

/// The target pid if this process is the re-exec'd reader, `None` if it is an ordinary run. A value
/// whose parent pid is not this process's parent was inherited (a shell export, an outer harness,
/// a descendant) and is an error, never proof of the reader role.
#[cfg(unix)]
fn helper_role(inherited: Option<&str>, parent_pid: u32) -> Result<Option<u32>, String> {
    let Some(v) = inherited else { return Ok(None) };
    let target = v
        .split_once(':')
        .filter(|(parent, _)| *parent == parent_pid.to_string())
        .and_then(|(_, target)| target.parse().ok());
    match target {
        Some(pid) => Ok(Some(pid)),
        None => Err(format!(
            "{ENV_TARGET_PID}={v:?} is set in this process's environment but is not \
             \"{parent_pid}:<target pid>\" (its parent is {parent_pid}), so it was inherited, not set \
             by the caller; unset it"
        )),
    }
}

/// The target crosses to the reader as a bare pid: this process holds the unreaped `Child`, so the
/// pid cannot be recycled before the reader reports.
#[cfg(unix)]
#[skuld::test]
fn foreign_kill_surfaces_permission_denied(#[fixture(uid_switch)] _group: &Group) {
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;

    use common::KillOnDrop;

    common::assert_root_capable();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind control listener");
    let addr = listener.local_addr().unwrap().to_string();

    // execve as another uid needs o+x on every ancestor; $HOME (Linux) and macOS's per-user $TMPDIR
    // lack it, /tmp keeps it.
    let scratch = tempfile::Builder::new()
        .tempdir_in("/tmp")
        .expect("scratch directory for world-executable copies");
    std::fs::set_permissions(scratch.path(), std::fs::Permissions::from_mode(0o755))
        .expect("chmod the scratch directory world-traversable");
    let target_bin = common::world_executable_copy(std::path::Path::new(common::testbin()), scratch.path());

    // `cosca::Command` has no uid()/gid(), so this uses `std::process::Command`. `control-echo-pid`,
    // not `control-block`: the survival check needs a target that stays responsive.
    let target = common::spawn_locked(
        std::process::Command::new(&target_bin)
            .args(["control-echo-pid", &addr, "R"])
            .env(common::ACK_ENV, "1") // the target waits for `accept_or_die`'s ack
            .uid(common::TARGET_UID)
            .gid(common::TARGET_UID),
    )
    .expect("spawn the target under an unprivileged uid");
    let mut target = KillOnDrop::new(target);
    let target_pid = target.id();

    let mut sock = common::accept_or_die(&listener, &mut target);
    let (tag, reported_pid) = common::read_tag_and_pid(&mut sock);
    assert_eq!(tag, b'R', "unexpected control tag from the target");
    assert_eq!(
        reported_pid, target_pid,
        "the target's self-reported pid must match what we spawned"
    );

    // The caller under test: this binary re-exec'd as READER_UID; it reports by exit code.
    let exe = std::env::current_exe().expect("this test binary's own path");
    let reader_bin = common::world_executable_copy(&exe, scratch.path());
    let status = common::status_locked(
        common::test_reexec::command(&reader_bin)
            .uid(common::READER_UID)
            .gid(common::READER_UID)
            .env(ENV_TARGET_PID, format!("{}:{target_pid}", std::process::id())),
    )
    .expect("re-exec this binary as the unprivileged reader");

    assert_eq!(
        status.code(),
        Some(0),
        "the reader did not confirm EPERM (its stderr names the failed check)"
    );

    // The target was alive and answering while the reader was refused, so the EPERM came from a
    // live foreign process. A bare `try_wait() == None` would only show it not yet reaped.
    common::assert_echoes(&mut sock, "the target");
}

#[cfg(unix)]
#[skuld::test]
fn helper_role_is_none_without_the_variable() {
    assert_eq!(helper_role(None, 42), Ok(None));
}

#[cfg(unix)]
#[skuld::test]
fn helper_role_accepts_the_parents_pid_and_returns_the_target() {
    assert_eq!(helper_role(Some("42:7"), 42), Ok(Some(7)));
}

#[cfg(unix)]
#[skuld::test]
fn helper_role_rejects_an_inherited_value_naming_the_variable() {
    for inherited in ["7", "41:7", "42:", "42:x", ":7", "42:7:8"] {
        let err = helper_role(Some(inherited), 42).unwrap_err();
        assert!(
            err.contains(ENV_TARGET_PID) && err.contains("inherited"),
            "{inherited:?}: {err}"
        );
    }
}

/// The re-exec'd reader. Exit code:
/// - `0`: `Process::kill` on the target surfaced `EPERM` as `Err`, as expected.
/// - `10`: `kill` returned `Ok(())`.
/// - `11`: `kill` returned an `Err` other than `Io(EPERM)`.
/// - `12`: the target pid is `Gone` (a test bug, not an OS refusal).
/// - `13`: the target pid's identity is `Unknown` (the OS refused the query).
#[cfg(unix)]
fn foreign_kill_helper_main(pid: u32) -> i32 {
    // A failed uid/gid drop fails the caller's spawn(), so euid is never 0 here.
    // SAFETY: geteuid() takes no arguments and has no preconditions.
    debug_assert_ne!(unsafe { libc::geteuid() }, 0, "the reader is still euid 0");
    let target = match cosca::Process::from_pid(pid) {
        cosca::identity::Resolved::Found(p) => p,
        cosca::identity::Resolved::Gone => {
            eprintln!("foreign_kill_helper: target pid {pid} is gone");
            return 12;
        }
        cosca::identity::Resolved::Unknown => {
            eprintln!("foreign_kill_helper: target pid {pid}'s identity query was refused by the OS");
            return 13;
        }
    };
    match target.kill() {
        Err(cosca::error::Error::Io(e)) if e.raw_os_error() == Some(libc::EPERM) => 0,
        Ok(()) => {
            eprintln!("foreign_kill_helper: kill() unexpectedly succeeded");
            10
        }
        other => {
            eprintln!("foreign_kill_helper: kill() returned an unexpected result: {other:?}");
            11
        }
    }
}

#[cfg(unix)]
mod uid_switch_group {
    //! Re-execs this binary on the `UID_SWITCH` test; every case stops before its body, so it is safe on any host.

    use crate::common::test_reexec::{command, suite_outcome, with_json_events, SuiteOutcome, NOCAPTURE};

    const UID_SWITCH_TEST: &str = "foreign_kill_surfaces_permission_denied";

    fn run_uid_switch_test(
        extra: &[&str],
        group: Option<&str>,
        consent: Option<&str>,
        labels: Option<&str>,
    ) -> (SuiteOutcome, bool, String) {
        let mut cmd = command(std::env::current_exe().expect("current_exe"));
        cmd.args(["--test-threads=1", "--exact", UID_SWITCH_TEST, NOCAPTURE]);
        cmd.args(extra);
        with_json_events(&mut cmd);
        for (var, value) in [
            ("COSCA_TEST_UID_SWITCH", group),
            ("COSCA_TEST_UID_SWITCH_CONSENT", consent),
            ("SKULD_LABELS", labels),
        ] {
            match value {
                Some(value) => cmd.env(var, value),
                None => cmd.env_remove(var),
            };
        }
        let out = crate::common::output_locked(&mut cmd).expect("re-exec this test binary");
        let outcome = suite_outcome(&out.stdout).expect("the child reports its suite");
        (
            outcome,
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    }

    /// The `failed` event of [`UID_SWITCH_TEST`]: its message tells a setup refusal from a body failure.
    fn failure_message(stdout: &str) -> String {
        stdout
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|e| e["type"] == "test" && e["event"] == "failed" && e["name"] == UID_SWITCH_TEST)
            .unwrap_or_else(|| panic!("no `failed` event for the test: {stdout}"))["stdout"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }

    fn assert_consent_refused(group: Option<&str>, consent: Option<&str>) {
        let (outcome, success, stdout) = run_uid_switch_test(&[], group, consent, None);
        assert_eq!((outcome.failed, outcome.passed, outcome.ignored), (1, 0, 0), "{stdout}");
        assert!(!success, "{stdout}");
        // Only the fixture's refusal carries this message; a body that ran cannot.
        assert!(
            failure_message(&stdout).contains("COSCA_TEST_UID_SWITCH_CONSENT=1"),
            "{stdout}"
        );
    }

    /// Mutant: the group's `requires` never fails, so `=0` runs the test.
    #[skuld::test]
    fn uid_switch_group_zero_reports_ignored() {
        let (outcome, success, stdout) = run_uid_switch_test(&[], Some("0"), None, None);
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

    /// Mutant: the group's setup does not check consent (the body then switches uids as root).
    #[skuld::test]
    fn uid_switch_unset_consent_fails() {
        assert_consent_refused(None, None);
    }

    /// Mutant: a set group variable counts as consent.
    #[skuld::test]
    fn uid_switch_group_on_without_consent_fails() {
        assert_consent_refused(Some("1"), None);
    }

    /// Mutant: any non-empty consent counts.
    #[skuld::test]
    fn uid_switch_consent_other_than_1_fails() {
        assert_consent_refused(None, Some("yes"));
    }

    /// Mutant: the setup grants a group that is off, so `--ignored` runs the body.
    #[skuld::test]
    fn uid_switch_group_zero_never_runs_the_body_under_run_ignored() {
        let (outcome, success, stdout) = run_uid_switch_test(&["--ignored"], Some("0"), None, None);
        assert_eq!(
            (outcome.test_count, outcome.passed, outcome.failed, outcome.ignored),
            (1, 0, 1, 0),
            "{stdout}"
        );
        assert!(!success, "{stdout}");
        // Only the fixture's refusal carries this message; a body that ran cannot.
        assert!(
            failure_message(&stdout).contains("setup failed: COSCA_TEST_UID_SWITCH=0"),
            "{stdout}"
        );
    }

    /// Mutant: the fixture carries no `UID_SWITCH` label, so `SKULD_LABELS=uid_switch` selects none of the group.
    #[skuld::test]
    fn the_uid_switch_label_selects_its_test() {
        let (outcome, _, stdout) = run_uid_switch_test(&[], Some("0"), None, Some("uid_switch"));
        assert_eq!(outcome.test_count, 1, "{stdout}");
        let (outcome, _, stdout) = run_uid_switch_test(&[], Some("0"), None, Some("!uid_switch"));
        assert_eq!(outcome.test_count, 0, "{stdout}");
    }
}

#[path = "../src/test_harness.rs"]
mod test_harness;

// The root lanes run this target whole; `UID_SWITCH` (above) is what gates its test.
skuld::default_labels!(test_harness::ROOT);

fn main() {
    #[cfg(unix)]
    {
        let inherited = std::env::var_os(ENV_TARGET_PID).map(|v| v.to_string_lossy().into_owned());
        match helper_role(inherited.as_deref(), std::os::unix::process::parent_id()) {
            Ok(Some(pid)) => std::process::exit(foreign_kill_helper_main(pid)),
            Ok(None) => {}
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2);
            }
        }
    }
    let mut runner = skuld::TestRunner::new();
    runner.require_known_labels();
    runner.run()
}
