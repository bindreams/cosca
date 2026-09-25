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
        warned_for(mark, pid, "nothing can reach it"),
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
        .map(|_| super::warn_after_fork_into(&warned, &error(), "it was left running"))
        .collect();
    assert_eq!(levels, [log::Level::Warn, log::Level::Debug]);
    let other = Error::Io(std::io::Error::from_raw_os_error(libc::ENOMEM));
    assert_eq!(
        super::warn_after_fork_into(&warned, &other, "it was left running"),
        log::Level::Warn
    );
}

/// Whether a record since `mark` says `marker` of the seam's failed spawn of `pid` — the seam's
/// error names it — and so of this test's spawn, whatever other tests log meanwhile.
#[cfg(target_os = "linux")]
fn warned_for(mark: usize, pid: u32, marker: &str) -> bool {
    let spawn = format!("for child {pid})");
    crate::log_capture::records_since(mark, marker)
        .iter()
        .any(|record| record.contains(&spawn))
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

/// On the identity-failure path, a child tokio could not kill (`EPERM`) is handed back running in
/// [`Error::Unreaped`] — cosca keeps no background thread to reap it, so the caller must, not
/// tokio's orphan queue. The leaf, having taken its verdict first, answers only for the tree — its
/// kill through the leaf — and never reaps that child as an abandoned spawn's, which would race
/// the caller's own reap of the same pid.
///
/// The leaf may be left behind: its `Drop` removes it right after `cgroup.kill`, without waiting
/// for the kill to land — a known exit-lag gap, not this.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
async fn cgroup_an_identity_failure_whose_kill_is_refused_hands_the_child_back_unreaped() {
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
    assert_eq!(
        fault::take_force_kill_failure(),
        None,
        "the kill failure must be consumed"
    );

    let Some(Error::Unreaped { kill, mut child, .. }) = err else {
        panic!("the unkillable child must be handed back, got {err:?}");
    };
    assert_eq!(
        kill.kind(),
        std::io::ErrorKind::PermissionDenied,
        "the kill's own error"
    );

    assert_eq!(
        crate::containment::cgroup::fault::take_reaped_orphans(),
        Vec::new(),
        "the leaf must not reap a child tokio owns"
    );

    let captured = fault::take_captured().expect("seam captured the child's identity");
    let crate::identity::Resolved::Found(id) = captured else {
        panic!("the seam must capture a resolved identity, got {captured:?}");
    };
    assert_eq!(child.pid(), id.pid(), "the handed-back child is the spawned one");
    // Handled explicitly rather than dropped: `Unreaped`'s `Drop` would block this async test's
    // runtime thread waiting for the child.
    crate::wait::kill(id).expect("end the child");
    child.wait().await.expect("wait for the handed-back child");
    fault::assert_child_reaped(captured);
}

/// An abandoned spawn's child writes nothing into its own stdio. With fds 1 and 2 closed, `std`'s
/// error channel takes them, the child's stdio `dup2` closes its end, and `spawn` returns before
/// the child's hook runs. The child is held at its hook until the spawn has been abandoned; an
/// error it then returned to `std` would be written to that channel's fd number — by now the
/// child's stderr. It exits with `ABANDONED_EXIT` instead.
///
/// It sent nothing before the abandonment, so nothing in cosca holds its pid: the spawn warns that
/// it may be left unreaped, and the test reaps it through the seam's pidfd.
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

    crate::log_capture::install();
    let mark = crate::log_capture::mark();
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
        // The spawn is abandoned: only now does the child's hook run. Released before any assert:
        // the child holds this process's stdout, and a child held forever would hang the outer run.
        gate_write.write_all(b"x").expect("release the child");
        assert!(spawned.is_err(), "the forced failure must fail the spawn");
        let pidfd = fault::take_forgotten_pidfd().expect("the seam took a pidfd for the child");
        let pid = fault::take_forgotten_pid().expect("the seam dropped a child");
        let _ = fault::take_forgotten_leaf();
        let status = loop {
            match rustix::process::waitid(
                rustix::process::WaitId::PidFd(pidfd.as_fd()),
                rustix::process::WaitIdOptions::EXITED,
            ) {
                Err(rustix::io::Errno::INTR) => continue,
                other => break other.expect("reap the child").expect("it exited"),
            }
        };
        assert!(
            warned_for(mark, pid, "left unreaped"),
            "the spawn must say its child may be left unreaped"
        );
        assert_eq!(
            status.exit_status(),
            Some(crate::containment::cgroup::ABANDONED_EXIT),
            "the abandoned child must exit from its hook"
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

// kill_on_drop(false) commits only with the spawn -----
// Async twins of the sync `spawn_tests` of the same name.

/// The sync command `spawn_uncommitted` takes: a long-lived child with `kill_on_drop(false)`.
#[cfg(target_os = "linux")]
fn opted_out_blocker() -> crate::command::Command {
    let mut cmd = crate::command::Command::new();
    cmd.args(["sleep", "30"]);
    cmd.kill_on_drop(false);
    cmd
}

/// An occupied temp leaf whose child entered it, attached to the next spawn on this thread.
#[cfg(target_os = "linux")]
fn attach_entered_leaf(leaf_path: &std::path::Path) {
    std::fs::create_dir(leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("occupant"), "").expect("keep the leaf unremovable");
    std::fs::write(leaf_path.join("cgroup.kill"), b"").expect("create cgroup.kill");
    fault::set_attachment_override(crate::containment::Attachment {
        containment: crate::containment::Containment::CgroupV2,
        attached: crate::containment::Attached::Cgroup(crate::containment::cgroup::test_support::entered_leaf_at(
            leaf_path.to_path_buf(),
        )),
        graceful: crate::graceful::GracefulMechanism::Process,
    });
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn kill_on_drop_false_disarms_the_leaf_only_when_the_spawn_commits() {
    for commit in [false, true] {
        let dir = tempfile::tempdir().expect("tempdir");
        let leaf_path = dir.path().join("cosca-async-commit-leaf");
        attach_entered_leaf(&leaf_path);
        let mut child = super::spawn_uncommitted(&mut opted_out_blocker()).expect("spawn");
        if commit {
            child.commit_kill_on_drop();
        }
        child.kill().expect("end the stand-in root");
        let _ = child.wait().await;
        drop(child);

        let expected: &[u8] = if commit { b"" } else { b"1" };
        assert_eq!(
            std::fs::read(leaf_path.join("cgroup.kill")).expect("read cgroup.kill"),
            expected,
            "committed: {commit}"
        );
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_failed_password_write_kills_the_contained_tree() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-async-password-leaf");
    attach_entered_leaf(&leaf_path);
    let mut child = super::spawn_uncommitted(&mut opted_out_blocker()).expect("spawn");
    // Rule out the leaf's `Drop`: only the failure path itself may kill.
    child.detach();

    let written = Err(Error::Elevation {
        kind: crate::error::ElevationErrorKind::AuthFailed,
        detail: "forced password-write failure".into(),
    });
    let err = super::finish_elevated(child, written).expect_err("a failed write fails the spawn");

    assert!(
        matches!(
            err,
            Error::Elevation {
                kind: crate::error::ElevationErrorKind::AuthFailed,
                ..
            }
        ),
        "got {err:?}"
    );
    assert_eq!(
        std::fs::read(leaf_path.join("cgroup.kill")).expect("read cgroup.kill"),
        b"1",
        "the failed spawn must kill its tree through the leaf"
    );
}

/// The async twin of
/// `child::spawn::spawn_tests::a_failed_password_write_whose_check_is_uncertain_disarms_its_retained_leaf`:
/// a failed password write whose child's one check comes back with ownership uncertain (a genuine
/// `ECHILD`) disarms what it retained, rather than leaving it armed to kill through a tree that may
/// no longer be its own.
///
/// `Containment::Delegated`, not `CgroupV2`: this function's own tree-kill note at its top fires
/// whenever `can_teardown()` is true, which would write `cgroup.kill` before the Uncertain arm is
/// even reached, hiding the one write under test.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_failed_password_write_whose_check_is_uncertain_disarms_its_retained_leaf() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-async-uncertain-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("occupant"), "").expect("keep the leaf unremovable");
    std::fs::write(leaf_path.join("cgroup.kill"), b"").expect("create cgroup.kill");
    fault::set_attachment_override(crate::containment::Attachment {
        containment: crate::containment::Containment::Delegated,
        attached: crate::containment::Attached::Cgroup(crate::containment::cgroup::test_support::entered_leaf_at(
            leaf_path.clone(),
        )),
        graceful: crate::graceful::GracefulMechanism::Process,
    });
    let child = blocker().spawn().expect("spawn the stand-in for the elevated child");
    let pid = child.id().pid();
    fault::set_force_kill_failure_leaving_child_alive_as(
        "cosca-async-elevated-kill-eperm-uncertain-7c4e",
        std::io::ErrorKind::PermissionDenied,
    );
    fault::set_force_teardown_try_wait_echild();

    let err = super::elevated_write_failed(
        child,
        Error::Io(std::io::Error::other("cosca-async-password-write-fail-uncertain-0a5d")),
    );

    assert!(err.to_string().contains("ownership is uncertain"), "got {err}");
    assert_eq!(
        std::fs::read(leaf_path.join("cgroup.kill")).expect("read cgroup.kill"),
        b"",
        "an uncertain-ownership release must disarm its retained leaf, not kill through it"
    );
    // The real child is still alive: the kill above was faked. End it for real and reap it
    // ourselves, since cosca released it as ownership-uncertain without waiting.
    // SAFETY: `pid` is this process's own unreaped child.
    unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    let mut status = 0;
    // SAFETY: as above; a blocking reap of this process's own child.
    unsafe { libc::waitpid(pid as i32, &mut status, 0) };
}

/// Whether `pid`, a child of this process, has been reaped: `waitpid` no longer knows it.
#[cfg(target_os = "linux")]
fn reaped(pid: u32) -> bool {
    let mut status = 0;
    // SAFETY: a non-blocking query on a pid this process spawned; `status` is a valid int.
    let r = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
    r == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
}

/// The error a failed password write returns.
#[cfg(target_os = "linux")]
fn failed_write() -> Result<(), Error> {
    Err(Error::Elevation {
        kind: crate::error::ElevationErrorKind::AuthFailed,
        detail: "forced password-write failure".into(),
    })
}

/// A `Delegated` spawn has no tree teardown of its own, but its root is still this spawn's child:
/// a failed password write kills and reaps it.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_failed_password_write_kills_and_reaps_a_delegated_root() {
    fault::set_attachment_override(crate::containment::Attachment {
        containment: crate::containment::Containment::Delegated,
        attached: crate::containment::Attached::Delegated,
        graceful: crate::graceful::GracefulMechanism::Process,
    });
    let child = super::spawn_uncommitted(&mut opted_out_blocker()).expect("spawn");
    let pid = child.id().pid();

    let err = super::finish_elevated(child, failed_write()).expect_err("a failed write fails the spawn");

    let reaped = reaped(pid);
    if !reaped {
        // SAFETY: `pid` is this process's own unreaped child; do not leak it past the test.
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    }
    assert!(reaped, "the root must be killed and reaped, got {err:?}");
    assert!(err.to_string().contains("was terminated"), "got {err:?}");
}

/// A tree kill that fails does not stop the root's own kill and reap: the two are separate.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_failed_password_write_reaps_the_root_when_the_tree_kill_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-unkillable-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    // A directory: writing `cgroup.kill` fails with EISDIR, as a refused kill would.
    std::fs::create_dir(leaf_path.join("cgroup.kill")).expect("make cgroup.kill unwritable");
    fault::set_attachment_override(crate::containment::Attachment {
        containment: crate::containment::Containment::CgroupV2,
        attached: crate::containment::Attached::Cgroup(crate::containment::cgroup::test_support::entered_leaf_at(
            leaf_path.clone(),
        )),
        graceful: crate::graceful::GracefulMechanism::Process,
    });
    let child = super::spawn_uncommitted(&mut opted_out_blocker()).expect("spawn");
    let pid = child.id().pid();

    let err = super::finish_elevated(child, failed_write()).expect_err("a failed write fails the spawn");

    assert!(reaped(pid), "the root was killed, so it must be reaped, got {err:?}");
    let detail = err.to_string();
    assert!(detail.contains("was terminated"), "the root was killed, got {detail}");
    assert!(
        detail.contains("its contained tree could not be killed"),
        "the tree's failure is reported, got {detail}"
    );
}

/// A post-fork tokio failure ends its child whether or not the child could send a pidfd — denied
/// here in the child through an inherited seam — and whether or not it entered its leaf: cosca
/// kills and reaps it by its checked pid, and warns about nothing. A child that refuses the kill
/// and is outside its leaf is handed back in the error, still running, for the caller to wait for.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
async fn cgroup_a_post_fork_tokio_failure_hands_back_a_child_out_of_reach() {
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
        if refuses {
            cgroup_fault::set_force_child_kill_denied(true);
        }
        fault::set_force_post_fork_failure(true);
        let err = cmd.spawn().expect_err("the forced failure must fail the spawn");
        // This thread's own copies of the child's seams were never taken.
        cgroup_fault::set_force_child_pidfd_failure(false);
        let _ = cgroup_fault::take_force_placement_write_result();
        let pid = fault::take_forgotten_pid().expect("the seam dropped a child");
        let pidfd = fault::take_forgotten_pidfd().expect("the seam took a pidfd for the child");
        let _ = fault::take_forgotten_leaf();

        let case = format!("placed: {placed}, refuses the kill: {refuses}");
        assert!(
            !warned_for(mark, pid, "nothing can reach it"),
            "{case}: a child with a handle is never warned about as out of reach"
        );
        if refuses {
            let crate::error::Error::Unreaped { mut child, .. } = err else {
                panic!("{case}: the child out of reach must be handed back, got {err:?}");
            };
            assert_eq!(child.pid(), pid, "{case}: the handed-back child is the forked one");
            assert!(!reaped_through(&pidfd), "{case}: the child is still running");
            rustix::process::pidfd_send_signal(&pidfd, rustix::process::Signal::KILL).expect("kill the child");
            child.wait().await.expect("wait for the handed-back child");
        } else {
            assert!(
                cgroup_fault::take_reaped_orphans().contains(&(pid, Some(libc::SIGKILL))),
                "{case}: the child must be killed by its pid"
            );
        }
        assert!(reaped_through(&pidfd), "{case}: the child must be reaped");
    }
}

/// A child the async spawn's teardown could not kill is handed back in the error as a
/// `cosca::tokio::Unreaped`, EPERM or not, and not waited on by the spawn. The child is left
/// running, as a refused kill leaves it — one that exited first would be reaped by the teardown's
/// one check, and nothing handed back — and the test ends it; the caller's `wait` then reaps it.
#[test]
fn a_child_the_async_teardown_cannot_kill_is_handed_back_in_the_error() {
    use std::io::ErrorKind;
    for (kind, marker) in [
        (ErrorKind::PermissionDenied, "cosca-async-kill-eperm-5d2c"),
        (ErrorKind::Other, "cosca-async-kill-fail-8a41"),
    ] {
        let runtime = ::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut cmd = blocker();
            fault::set_force_attach_failure(true);
            fault::set_force_kill_failure_leaving_child_alive_as(marker, kind);
            let err = cmd.spawn().err();
            fault::set_force_attach_failure(false);
            assert_eq!(
                fault::take_force_kill_failure(),
                None,
                "{kind:?}: the kill failure must be consumed"
            );
            let Some(Error::Unreaped { error, kill, mut child }) = err else {
                panic!("{kind:?}: the unkillable child must be handed back, got {err:?}");
            };
            assert_eq!(kill.kind(), kind);
            assert!(
                matches!(*error, Error::Containment { .. }),
                "why the spawn failed, got {error:?}"
            );
            let captured = fault::take_captured().expect("seam captured the child's identity");
            let crate::identity::Resolved::Found(id) = captured else {
                panic!("the seam must capture a resolved identity, got {captured:?}");
            };
            assert_eq!(child.pid(), id.pid());
            crate::wait::kill(id).expect("end the child");
            child.wait().await.expect("wait for the handed-back child");
            fault::assert_child_reaped(captured);
        });
    }
}

/// The async twin of
/// `child::spawn::spawn_tests::a_teardown_whose_check_is_uncertain_disarms_its_retained_leaf`:
/// `reap_now`'s teardown whose one check comes back with ownership uncertain (a genuine `ECHILD`)
/// disarms what it retained, rather than leaving it armed to kill through a tree that may no
/// longer be its own.
///
/// Calls `reap_now` directly: it is private, reachable from this submodule, and driving this exact
/// arm through a full spawn would need attach failure, a real placed leaf and the ECHILD seam all
/// armed together for one code path, proving nothing the direct call does not.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_teardown_whose_check_is_uncertain_disarms_its_retained_leaf() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-async-teardown-uncertain-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("occupant"), "").expect("keep the leaf unremovable");
    std::fs::write(leaf_path.join("cgroup.kill"), b"").expect("create cgroup.kill");
    let leaf = crate::containment::cgroup::test_support::entered_leaf_at(leaf_path.clone());
    let child = ::tokio::process::Command::new("sleep")
        .arg("30")
        .kill_on_drop(false)
        .spawn()
        .expect("spawn a real child");
    let pid = child.id().expect("a freshly spawned child has a pid");
    fault::set_force_kill_failure_leaving_child_alive_as(
        "cosca-async-teardown-kill-eperm-uncertain-6b2f",
        std::io::ErrorKind::PermissionDenied,
    );
    fault::set_force_teardown_try_wait_echild();

    let handed_back =
        crate::tokio::child::reap_now(child, pid, false, Some(crate::containment::Attached::Cgroup(leaf)));

    assert!(
        handed_back.is_none(),
        "an uncertain check releases the child, handing nothing back"
    );
    assert_eq!(
        std::fs::read(leaf_path.join("cgroup.kill")).expect("read cgroup.kill"),
        b"",
        "an uncertain-ownership release must disarm its retained leaf, not kill through it"
    );
    // The real child is still alive: the kill above was faked. End it for real and reap it
    // ourselves, since the teardown released it as ownership-uncertain without waiting.
    // SAFETY: `pid` is this process's own unreaped child.
    unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    let mut status = 0;
    // SAFETY: as above; a blocking reap of this process's own child.
    unsafe { libc::waitpid(pid as i32, &mut status, 0) };
}

/// The async counterpart of the sync teardown's suspended-child test. A contained root is created
/// `CREATE_SUSPENDED` and resumed only by a successful attach, so after a failed attach it cannot
/// exit on its own. When `start_kill` fails, `reap_now` terminates it again through the handle it
/// holds, and waits for it.
#[cfg(windows)]
#[test]
fn a_suspended_child_the_async_teardown_could_not_kill_is_terminated_through_its_handle() {
    crate::log_capture::install();
    let marker = "cosca-async-kill-fail-suspended-4f93";
    let mark = crate::log_capture::mark();
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(async {
            let mut cmd = blocker();
            cmd.contain();
            fault::set_force_attach_failure(true);
            fault::set_force_kill_failure_leaving_child_alive(marker);
            cmd.spawn().err()
        })
    }));
    fault::set_force_attach_failure(false);
    assert_eq!(
        fault::take_force_kill_failure(),
        None,
        "the kill failure must be consumed"
    );
    // The retry terminated it, so nothing is handed back and nothing panics.
    let err = outcome.expect("no panic: the kill failure was recovered");
    assert!(
        matches!(err, Some(Error::Containment { .. }) | Some(Error::Io(_))),
        "the spawn's own error, got {err:?}"
    );
    assert!(
        crate::log_capture::contains_since(mark, &format!("{marker}; terminated it through its handle")),
        "the failed kill must be logged as terminated through the handle, not left to a reaper"
    );
    // Dead on return: the teardown waited for the terminated child.
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
}

/// When the retry fails too, the suspended child is leaked, and `reap_now` says so. The test
/// terminates it afterwards.
#[cfg(windows)]
#[test]
fn a_suspended_child_the_async_teardown_cannot_terminate_is_reported_leaked() {
    crate::log_capture::install();
    let marker = "cosca-async-terminate-fail-suspended-a61e";
    let mark = crate::log_capture::mark();
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(async {
            let mut cmd = blocker();
            cmd.contain();
            fault::set_force_attach_failure(true);
            fault::set_force_kill_failure_leaving_child_alive_as(
                "cosca-async-kill-eperm-suspended-d207",
                std::io::ErrorKind::PermissionDenied,
            );
            fault::set_force_suspended_terminate_failure(marker);
            cmd.spawn().err()
        })
    }));
    fault::set_force_attach_failure(false);
    assert_eq!(
        fault::take_force_suspended_terminate_failure(),
        None,
        "the retry must consume its forced failure"
    );
    // The leak is asserted even though EPERM on the kill is not.
    assert_eq!(outcome.is_err(), cfg!(debug_assertions));
    assert!(
        crate::log_capture::contains_since(mark, marker),
        "the leaked suspended child must be reported"
    );
    let captured = fault::take_captured().expect("seam captured the child's identity");
    let crate::identity::Resolved::Found(id) = captured else {
        panic!("the seam must capture a resolved identity, got {captured:?}");
    };
    crate::wait::kill(id).expect("terminate the leaked child");
    crate::wait::block_until_exit(id, None).expect("watch the child's exit");
    fault::assert_child_reaped(captured);
}

/// The async raw backend shares the sync raw teardown, so its suspended root is terminated
/// through its handle the same way when the kill fails.
#[cfg(windows)]
#[test]
fn a_suspended_child_the_async_raw_teardown_could_not_kill_is_terminated_through_its_handle() {
    crate::log_capture::install();
    let marker = "cosca-async-raw-kill-fail-suspended-37ad";
    let mark = crate::log_capture::mark();
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let err = runtime.block_on(async {
        let mut cmd = blocker();
        cmd.executable("ping").contain();
        fault::set_force_attach_failure(true);
        fault::set_force_kill_failure_leaving_child_alive(marker);
        let err = cmd.spawn().err();
        fault::set_force_attach_failure(false);
        err
    });
    err.expect("the forced arm must fail the spawn");
    assert_eq!(
        fault::take_force_kill_failure(),
        None,
        "the kill failure must be consumed"
    );
    assert!(
        crate::log_capture::contains_since(mark, marker),
        "the failed kill must be logged"
    );
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
}

/// When the retry fails too, the async raw teardown reports the leak. The test terminates the
/// child afterwards.
#[cfg(windows)]
#[test]
fn a_suspended_child_the_async_raw_teardown_cannot_terminate_is_reported_leaked() {
    crate::log_capture::install();
    let marker = "cosca-async-raw-terminate-fail-suspended-9b52";
    let mark = crate::log_capture::mark();
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(async {
            let mut cmd = blocker();
            cmd.executable("ping").contain();
            fault::set_force_attach_failure(true);
            fault::set_force_kill_failure_leaving_child_alive("cosca-async-raw-kill-fail-suspended-c410");
            fault::set_force_suspended_terminate_failure(marker);
            cmd.spawn().err()
        })
    }));
    fault::set_force_attach_failure(false);
    assert_eq!(
        fault::take_force_suspended_terminate_failure(),
        None,
        "the retry must consume its forced failure"
    );
    assert_eq!(outcome.is_err(), cfg!(debug_assertions), "the leak is asserted");
    assert!(
        crate::log_capture::contains_since(mark, marker),
        "the leaked suspended child must be reported"
    );
    let captured = fault::take_captured().expect("seam captured the child's identity");
    let crate::identity::Resolved::Found(id) = captured else {
        panic!("the seam must capture a resolved identity, got {captured:?}");
    };
    crate::wait::kill(id).expect("terminate the leaked child");
    crate::wait::block_until_exit(id, None).expect("watch the child's exit");
    fault::assert_child_reaped(captured);
}

/// The async spawn reads identity BEFORE its attach, so a contained root whose identity read fails
/// is still `CREATE_SUSPENDED` on that arm too. When its kill fails, the identity arm retries
/// termination through the handle, as the attach arm does, and waits for it.
#[cfg(windows)]
#[test]
fn a_suspended_child_the_async_identity_arm_could_not_kill_is_terminated_through_its_handle() {
    crate::log_capture::install();
    let marker = "cosca-async-identity-kill-fail-suspended-b61f";
    let mark = crate::log_capture::mark();
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(async {
            let mut cmd = blocker();
            cmd.contain();
            fault::set_force_identity_vanished(true);
            fault::set_force_kill_failure_leaving_child_alive(marker);
            cmd.spawn().err()
        })
    }));
    fault::set_force_identity_vanished(false);
    assert_eq!(
        fault::take_force_kill_failure(),
        None,
        "the kill failure must be consumed"
    );
    // The retry terminated it, so nothing is handed back and nothing panics.
    let err = outcome.expect("no panic: the kill failure was recovered");
    assert!(
        matches!(err, Some(Error::Containment { .. }) | Some(Error::Io(_))),
        "the spawn's own error, got {err:?}"
    );
    assert!(
        crate::log_capture::contains_since(mark, &format!("{marker}; terminated it through its handle")),
        "the identity arm must retry termination through the handle"
    );
    // Dead on return: the teardown waited for the terminated child.
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
}

/// The async twin of the sync elevated hand-back: a failed password write whose child refuses the
/// kill hands it back in `Error::Unreaped`, whose `error` is the elevation's `AuthFailed`.
#[cfg(unix)]
#[tokio::test]
async fn an_elevated_child_a_failed_password_write_cannot_kill_is_handed_back() {
    let child = blocker().spawn().expect("spawn the stand-in for the elevated child");
    let pid = child.id().pid();
    fault::set_force_kill_failure_leaving_child_alive_as(
        "cosca-async-elevated-kill-eperm-91c3",
        std::io::ErrorKind::PermissionDenied,
    );
    let err: crate::tokio::Error = super::elevated_write_failed(
        child,
        Error::Io(std::io::Error::other("cosca-async-password-write-fail-2b6f")),
    )
    .into();
    assert_eq!(
        fault::take_force_kill_failure(),
        None,
        "the kill failure must be consumed"
    );
    let Error::Unreaped { error, kill, mut child } = err else {
        panic!("the unkillable elevated child must be handed back, got {err:?}");
    };
    assert_eq!(kill.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(
        matches!(
            &*error,
            Error::Elevation {
                kind: crate::error::ElevationErrorKind::AuthFailed,
                ..
            }
        ),
        "why the spawn failed, got {error:?}"
    );
    assert_eq!(child.pid(), pid);
    let crate::identity::Resolved::Found(id) = crate::identity::ProcessId::of(pid) else {
        panic!("the handed-back child is unreaped, so its identity resolves");
    };
    crate::wait::kill(id).expect("end the child");
    child.wait().await.expect("wait for the handed-back child");
    fault::assert_child_reaped(crate::identity::Resolved::Found(id));
}

/// The async twin: a suspended child whose kill and check both failed is still terminated through
/// the handle tokio holds, since on Windows a failed check says nothing about ownership.
#[cfg(windows)]
#[test]
fn a_suspended_child_whose_check_fails_in_the_async_teardown_is_still_terminated() {
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let err = runtime.block_on(async {
        let mut cmd = blocker();
        cmd.contain();
        fault::set_force_attach_failure(true);
        fault::set_force_kill_failure_leaving_child_alive("cosca-async-kill-fail-check-fail-6d0a");
        fault::set_force_teardown_try_wait_error("cosca-async-check-fail-suspended-91e2");
        let err = cmd.spawn().err();
        fault::set_force_attach_failure(false);
        err
    });
    assert_eq!(
        fault::take_force_teardown_try_wait_error(),
        None,
        "the check failure must be consumed"
    );
    assert!(
        matches!(err, Some(Error::Containment { .. })),
        "the retry terminated it, so the spawn's own error comes back, got {err:?}"
    );
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
}
