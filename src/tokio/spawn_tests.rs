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

    let pidfd = fault::take_forgotten_pidfd().expect("the seam took a pidfd for the child");

    // Nothing owns the child any more, so the dropped leaf must both kill and reap it.
    let reaped = crate::containment::cgroup::fault::take_reaped_orphans();
    assert!(
        reaped.contains(&(pid, Some(libc::SIGKILL))),
        "the child {pid} in the dropped leaf must be killed, got {reaped:?}"
    );
    assert!(reaped_through(&pidfd), "the child {pid} must be reaped");
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

/// A tokio spawn that fails with no cgroup leaf to kill through says a forked child may have been
/// left running out of reach — tokio can drop a child it forked and return no pid. Here the seam
/// forces that failure under a tree walk, which holds no leaf.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_post_fork_tokio_failure_without_a_leaf_says_the_child_may_be_unreachable() {
    crate::log_capture::install();
    let mut cmd = blocker();
    cmd.contain_with(crate::ContainMode::TreeWalk);
    let mark = crate::log_capture::mark();
    fault::set_force_post_fork_failure(true);
    assert!(cmd.spawn().is_err(), "the forced failure must fail the spawn");
    let pid = fault::take_forgotten_pid().expect("the seam dropped a child");
    assert!(
        crate::log_capture::contains_since(mark, "nothing can reach it"),
        "the failure must say the child may be left running"
    );

    // The seam's child is still this process's unreaped child, so its pid is safe to signal.
    let pid = nix::unistd::Pid::from_raw(pid as i32);
    nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL).expect("kill the dropped child");
    nix::sys::wait::waitpid(pid, None).expect("reap the dropped child");
}

/// The warning is once per errno: the first failure at `warn`, every repeat at `debug`.
#[test]
fn the_unreachable_child_warning_is_once_per_errno() {
    let warned = std::sync::Mutex::default();
    let error = || Error::Io(std::io::Error::from_raw_os_error(libc::EMFILE));
    let levels: Vec<_> = (0..2)
        .map(|_| super::warn_child_may_be_unreachable_into(&warned, &error()))
        .collect();
    assert_eq!(levels, [log::Level::Warn, log::Level::Debug]);
    let other = Error::Io(std::io::Error::from_raw_os_error(libc::ENOMEM));
    assert_eq!(
        super::warn_child_may_be_unreachable_into(&warned, &other),
        log::Level::Warn
    );
}

/// Whether the child `pidfd` names has been reaped — which a pidfd, unlike a pid, can answer after
/// the reap.
#[cfg(target_os = "linux")]
fn reaped_through(pidfd: &std::os::fd::OwnedFd) -> bool {
    use std::os::fd::AsFd;

    use rustix::process::{waitid, WaitId, WaitIdOptions};

    matches!(
        waitid(
            WaitId::PidFd(pidfd.as_fd()),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        ),
        Err(rustix::io::Errno::CHILD)
    )
}

/// A post-fork tokio failure ends its child whether or not the child could send a pidfd — denied
/// here in the child through an inherited seam — and whether or not it entered its leaf: cosca
/// kills and reaps it by its checked pid, and warns about nothing. Only a child that refuses the
/// kill and is outside its leaf is out of reach, and warned about; it is reaped once it exits.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
async fn cgroup_a_post_fork_tokio_failure_warns_only_for_a_child_out_of_reach() {
    use crate::containment::cgroup::fault as cgroup_fault;

    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "requires COSCA_TEST_CGROUP and a delegated cgroup"
    );
    crate::log_capture::install();
    for (placed, refuses) in [(true, false), (false, false), (false, true)] {
        let mut cmd = blocker();
        cmd.contain();
        let mark = crate::log_capture::mark();
        // Armed in this thread, inherited by the child it forks, which takes them.
        cgroup_fault::set_force_child_pidfd_failure(true);
        if !placed {
            cgroup_fault::set_force_placement_write_result(0);
        }
        let (reaped_tx, reaped_rx) = std::sync::mpsc::channel();
        if refuses {
            cgroup_fault::set_force_child_kill_denied(true);
            cgroup_fault::set_background_reap_notifier(reaped_tx);
        }
        fault::set_force_post_fork_failure(true);
        assert!(cmd.spawn().is_err(), "the forced failure must fail the spawn");
        // This thread's own copies of the child's seams were never taken.
        cgroup_fault::set_force_child_pidfd_failure(false);
        let _ = cgroup_fault::take_force_placement_write_result();
        let pid = fault::take_forgotten_pid().expect("the seam dropped a child");
        let pidfd = fault::take_forgotten_pidfd().expect("the seam took a pidfd for the child");
        let _ = fault::take_forgotten_leaf();

        let case = format!("placed: {placed}, refuses the kill: {refuses}");
        assert_eq!(
            crate::log_capture::contains_since(mark, "nothing can reach it"),
            refuses,
            "{case}: the warning must fire exactly when the child is out of reach"
        );
        if refuses {
            assert!(!reaped_through(&pidfd), "{case}: the child is still running");
            rustix::process::pidfd_send_signal(&pidfd, rustix::process::Signal::KILL).expect("kill the child");
            reaped_rx.recv().expect("the background reaper must reap it");
        } else {
            assert!(
                cgroup_fault::take_reaped_orphans().contains(&(pid, Some(libc::SIGKILL))),
                "{case}: the child must be killed by its pid"
            );
        }
        assert!(reaped_through(&pidfd), "{case}: the child must be reaped");
    }
}

/// On the identity-failure path tokio still owns the child, and reaps it: the leaf takes its
/// verdict first, so it never reaps that child as an abandoned spawn's — which would race tokio's
/// own reap for the same pid.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
async fn cgroup_an_identity_failure_leaves_the_child_to_tokio() {
    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "requires COSCA_TEST_CGROUP and a delegated cgroup"
    );
    let _ = crate::containment::cgroup::fault::take_reaped_orphans();
    fault::set_force_identity_vanished(true);
    let mut cmd = blocker();
    cmd.contain();
    let err = cmd.spawn().err();
    fault::set_force_identity_vanished(false);

    err.expect("forced identity-vanish must make spawn return Err");
    assert_eq!(
        crate::containment::cgroup::fault::take_reaped_orphans(),
        Vec::new(),
        "the leaf must not reap a child tokio owns"
    );
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
}

/// On the identity-failure path, a child tokio could not kill (`EPERM`) goes to tokio's orphan
/// queue, which reaps it once it exits. The leaf, having taken its verdict first, answers only for
/// the tree — its kill through the leaf — and never reaps that child as an abandoned spawn's,
/// which would race tokio's reap for the same pid.
///
/// The leaf may be left behind: its `Drop` removes it right after `cgroup.kill`, without waiting
/// for the kill to land — a known exit-lag gap, not this.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
async fn cgroup_an_identity_failure_whose_kill_is_refused_leaves_the_child_to_tokio() {
    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "requires COSCA_TEST_CGROUP and a delegated cgroup"
    );
    let _ = crate::containment::cgroup::fault::take_reaped_orphans();
    fault::set_force_identity_vanished(true);
    fault::set_force_kill_failure_leaving_child_alive_as(
        "cosca-identity-eperm-4c19",
        std::io::ErrorKind::PermissionDenied,
    );
    let mut cmd = blocker();
    cmd.contain();
    let err = cmd.spawn().err();
    fault::set_force_identity_vanished(false);
    err.expect("forced identity-vanish must make spawn return Err");
    assert_eq!(
        fault::take_force_kill_failure(),
        None,
        "the kill failure must be consumed"
    );
    let _ = fault::take_captured();

    assert_eq!(
        crate::containment::cgroup::fault::take_reaped_orphans(),
        Vec::new(),
        "the leaf must not reap a child tokio owns"
    );
}

/// An abandoned spawn's child writes nothing into its own stdio. With fds 1 and 2 closed, `std`'s
/// error channel takes them, the child's stdio `dup2` closes its end, and `spawn` returns before
/// the child's hook runs. The child is held at its hook until the spawn has been abandoned; an
/// error it then returned to `std` would be written to that channel's fd number — by now the
/// child's stderr.
///
/// Each case runs in a copy of this test binary: closing 1 and 2 is process-wide.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn cgroup_an_abandoned_spawn_writes_nothing_into_the_childs_stdio() {
    use std::io::{Read, Seek, Write};
    use std::os::fd::{AsFd, AsRawFd};

    const NAME: &str = "tokio::spawn::spawn_tests::cgroup_an_abandoned_spawn_writes_nothing_into_the_childs_stdio";
    const INNER: &str = "COSCA_TEST_ABANDONED_STDIO_INNER";
    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "requires COSCA_TEST_CGROUP and a delegated cgroup"
    );
    if std::env::var_os(INNER).is_none() {
        let out = std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args([NAME, "--exact", "--include-ignored", "--nocapture", "--test-threads=1"])
            .env(INNER, "1")
            .output()
            .expect("run the case");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "{}\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }

    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut file = tempfile::tempfile().expect("tempfile");
    let (gate_read, mut gate_write) = std::io::pipe().expect("open the gate");
    runtime.block_on(async {
        let mut cmd = blocker();
        for slot in [1, 2] {
            cmd.fd(
                slot,
                crate::stdio::Stdio::from_file(file.try_clone().expect("clone the file")),
            )
            .expect("wire the slot to the file");
        }
        cmd.contain();
        // SAFETY: this process's own std slots, closed only across the spawn and restored from
        // copies above 2 before anything else runs.
        let saved: Vec<(i32, i32)> = [1, 2]
            .into_iter()
            .map(|slot| unsafe { (slot, libc::fcntl(slot, libc::F_DUPFD_CLOEXEC, 3)) })
            .collect();
        for &(slot, _) in &saved {
            // SAFETY: as above.
            unsafe { libc::close(slot) };
        }
        // Inherited by the child, which waits on it at its hook; this thread's copy is cleared.
        crate::containment::cgroup::fault::set_hook_gate(gate_read.as_raw_fd());
        fault::set_force_post_fork_failure(true);
        let spawned = cmd.spawn();
        let _ = crate::containment::cgroup::fault::take_hook_gate();
        for &(slot, saved) in &saved {
            // SAFETY: as above.
            unsafe {
                libc::dup2(saved, slot);
                libc::close(saved);
            }
        }
        assert!(spawned.is_err(), "the forced failure must fail the spawn");
        let pidfd = fault::take_forgotten_pidfd().expect("the seam took a pidfd for the child");
        let _ = fault::take_forgotten_pid();
        let _ = fault::take_forgotten_leaf();
        // The spawn is abandoned: only now does the child's hook run.
        gate_write.write_all(b"x").expect("release the child");
        // Its exit, then its reap: it sent nothing, so nothing else reaps it.
        let _ = rustix::process::waitid(
            rustix::process::WaitId::PidFd(pidfd.as_fd()),
            rustix::process::WaitIdOptions::EXITED,
        );
    });
    let mut written = Vec::new();
    file.rewind().expect("rewind the file");
    file.read_to_end(&mut written).expect("read the file");
    assert!(
        !written.windows(4).any(|w| w == b"NOEX"),
        "std's error record reached the child's stdio: {written:?}"
    );
}
