//! Unit tests for the async spawn error-path teardown, driven by the shared `fault` seam
//! (`crate::child::spawn::fault`). In the library (not `tests/`) because the seam is
//! `pub(crate)`/`#[cfg(test)]` and only reachable from within the crate.

use crate::child::spawn::fault;
use crate::error::Error;
use crate::tokio::Command;

// A long-lived child, so a teardown leak would show as an alive process at the assert rather than
// self-exiting.
fn blocker() -> Command {
    let mut cmd = Command::new();
    #[cfg(unix)]
    cmd.args(["sleep", "30"]);
    #[cfg(windows)]
    cmd.args(["ping", "-n", "30", "127.0.0.1"]);
    cmd
}

// A failed async spawn must fully reap its child, not leak it. Each error arm is forced via the seam
// (which records the child's real identity); `fault::assert_child_reaped` then proves it was reaped
// (reap_now uses WNOWAIT, leaving the zombie for tokio's field-drop to collect).

#[tokio::test]
async fn identity_failure_reaps_the_spawned_child() {
    fault::set_force_identity_vanished(true);
    let mut cmd = blocker();
    let err = cmd.spawn().err();
    fault::set_force_identity_vanished(false);

    let err = err.expect("forced identity-vanish must make spawn return Err");
    assert!(
        matches!(err, Error::Io(_)),
        "identity-vanish surfaces as an Io error, got {err:?}"
    );
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
}

#[tokio::test]
async fn attach_failure_reaps_the_spawned_child() {
    fault::set_force_attach_failure(true);
    let mut cmd = blocker();
    let err = cmd.spawn().err();
    fault::set_force_attach_failure(false);

    let err = err.expect("forced attach failure must make spawn return Err");
    assert!(
        matches!(err, Error::Containment { .. }),
        "a real attach failure surfaces as Error::Containment, got {err:?}"
    );
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
}

/// The async mirror of `child::spawn::exact_posix_tests`: tokio builds its command through the
/// same `build_std_command`, so a bare `raw_executable()` must load the child-cwd file here too.
#[cfg(unix)]
#[tokio::test]
async fn a_bare_exact_name_loads_the_file_in_the_childs_cwd_not_one_on_path() {
    use crate::test_child::{cwd_and_path_tools, CWD_TOOL_EXIT};
    let (cwd, on_path) = cwd_and_path_tools();
    let mut c = Command::new();
    c.raw_executable("tool")
        .args(["tool"])
        .current_dir(cwd.path())
        .env("PATH", on_path.path());
    let status = c.spawn().expect("spawn").wait().await.expect("wait");
    assert_eq!(status.code(), Some(CWD_TOOL_EXIT));
}

/// tokio can fail a spawn after its fork succeeded (`build_child`: stdio registration, its pidfd
/// reaper, its signal driver), dropping the child neither killed nor reaped. The spawn's cgroup
/// leaf then drops with that child alive and possibly in it: it must be killed through, not left
/// running in a leaked leaf.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
async fn cgroup_a_post_fork_tokio_failure_leaves_no_live_child_in_a_leaked_leaf() {
    use nix::sys::wait::{waitpid, WaitStatus};

    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "requires COSCA_TEST_CGROUP and a delegated cgroup"
    );
    let mut cmd = blocker();
    cmd.contain();
    fault::set_force_post_fork_failure(true);
    assert!(cmd.spawn().is_err(), "the forced failure must fail the spawn");
    let pid = fault::take_forgotten_pid().expect("the seam dropped a child");
    let leaf = fault::take_forgotten_leaf().expect("the dropped spawn was contained in a leaf");

    // Still this process's unreaped child, so waiting on its pid is safe.
    let pid = nix::unistd::Pid::from_raw(pid as i32);
    assert_eq!(
        waitpid(pid, None).expect("reap the dropped child"),
        WaitStatus::Signaled(pid, nix::sys::signal::Signal::SIGKILL, false),
        "the child in the dropped leaf must be killed through it"
    );
    // An empty leaf `Drop` could not remove right after its kill is a known exit-lag gap, not this:
    // no leaf of this spawn may still hold a live process.
    if leaf.exists() {
        let events = std::fs::read_to_string(leaf.join("cgroup.events")).expect("read cgroup.events");
        assert!(
            events.lines().any(|line| line == "populated 0"),
            "{} still holds a process",
            leaf.display()
        );
        std::fs::remove_dir(&leaf).expect("remove the drained leaf");
    }
}

/// A failed kill in the async spawn's error teardown is not waited on, and EPERM — a setuid
/// child refusing SIGKILL — is not asserted, because it is reachable without a bug; any other
/// kind is. The child is left alive, blocked on stdin, and exits when the failed spawn drops the
/// pipe's parent end; tokio's own `Child` drop hands it to the runtime's orphan reaper.
#[test]
fn a_failed_teardown_kill_in_the_async_spawn_asserts_all_but_eperm() {
    use crate::stdio::Stdio;
    use std::io::ErrorKind;
    for (kind, asserted) in [(ErrorKind::PermissionDenied, false), (ErrorKind::Other, true)] {
        let runtime = ::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.block_on(async {
                let mut cmd = crate::tokio::Command::new();
                #[cfg(unix)]
                cmd.args(["cat"]);
                #[cfg(windows)]
                cmd.args(["findstr", "x"]);
                cmd.stdin(Stdio::pipe_in()).unwrap().stdout(Stdio::null()).unwrap();
                fault::set_force_attach_failure(true);
                fault::set_force_kill_failure_leaving_child_alive_as("cosca-async-kill-fail-5d2c", kind);
                let err = cmd.spawn().err();
                fault::set_force_attach_failure(false);
                err
            })
        }));
        assert_eq!(
            fault::take_force_kill_failure(),
            None,
            "{kind:?}: the kill failure must be consumed"
        );
        assert_eq!(
            outcome.is_err(),
            asserted && cfg!(debug_assertions),
            "{kind:?}: the debug_assert fires in exactly the builds that keep it, and never for EPERM"
        );
        if let Ok(err) = outcome {
            err.expect("the forced arm must fail the spawn");
        }
    }
}
