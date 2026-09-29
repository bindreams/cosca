//! Unit tests for the async spawn error-path teardown, driven by the shared `fault` seam
//! (`crate::child::spawn::fault`). In the library (not `tests/`) because the seam is
//! `pub(crate)`/`#[cfg(test)]` and only reachable from within the crate.

use crate::child::spawn::fault;
use crate::error::Error;
use crate::tokio::Command;

/// [`blocker`] for a kill-then-blocking-reap test; see [`fault::teardown_blocker_stdin`].
fn teardown_blocker() -> (Command, fault::TeardownBlocker) {
    let fault::TeardownBlockerParts {
        argv,
        stdin,
        stdout,
        guard,
    } = fault::teardown_blocker_parts();
    let mut cmd = Command::new();
    cmd.args(argv);
    cmd.stdin(stdin).expect("set stdin pipe");
    if let Some(stdout) = stdout {
        cmd.stdout(stdout).expect("set stdout");
    }
    (cmd, guard)
}

// A child only a real kill ends, its stdin writer leaked — see `child::spawn_tests::blocker`.
#[cfg(target_os = "linux")]
fn blocker() -> Command {
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::test_child::leaked_writer_stdin())
        .expect("set stdin pipe");
    cmd
}

// A failed async spawn must fully reap its child, not leak it. Each error arm is forced via the seam
// (which records the child's real identity); `fault::assert_child_reaped` then proves it was reaped
// (reap_now uses WNOWAIT, leaving the zombie for tokio's field-drop to collect).

#[tokio::test]
async fn identity_failure_reaps_the_spawned_child() {
    fault::set_force_identity_vanished(true);
    let (mut cmd, teardown) = teardown_blocker();
    let err = cmd.spawn().err();
    fault::set_force_identity_vanished(false);

    let err = err.expect("forced identity-vanish must make spawn return Err");
    assert!(
        matches!(err, Error::Io(_)),
        "identity-vanish surfaces as an Io error, got {err:?}"
    );
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
    teardown.assert_killed();
}

#[tokio::test]
async fn attach_failure_reaps_the_spawned_child() {
    fault::set_force_attach_failure(true);
    let (mut cmd, teardown) = teardown_blocker();
    let err = cmd.spawn().err();
    fault::set_force_attach_failure(false);

    let err = err.expect("forced attach failure must make spawn return Err");
    assert!(
        matches!(err, Error::Containment { .. }),
        "a real attach failure surfaces as Error::Containment, got {err:?}"
    );
    fault::assert_child_reaped(fault::take_captured().expect("seam captured the child's identity"));
    teardown.assert_killed();
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
/// pipe's parent end; tokio's own `Child` drop hands it to the runtime's orphan reaper, which the
/// test drives until the child is reaped.
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
                cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
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
        let captured = fault::take_captured().expect("seam captured the child's identity");
        drive_until_reaped(&runtime, &captured);
        fault::assert_child_reaped(captured);
    }
}

/// Turn `runtime`'s driver, whose every turn reaps tokio's exited orphans, until the child
/// `captured` names is reaped (Windows: has exited). Ends on the child's own exit, and never
/// before: no interval, no bound.
fn drive_until_reaped(
    runtime: &::tokio::runtime::Runtime,
    captured: &crate::identity::Resolved<crate::identity::ProcessId>,
) {
    let crate::identity::Resolved::Found(id) = captured else {
        panic!("the seam must capture a resolved identity, got {captured:?}");
    };
    #[cfg(unix)]
    let pending = || id.exists() == crate::identity::Existence::Present;
    #[cfg(windows)]
    let pending = || id.is_alive() != crate::identity::Liveness::Dead;
    while pending() {
        runtime.block_on(::tokio::task::yield_now());
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

/// The abandoned-child warning is at `warn` on every call, including a repeat, through the real
/// entry point.
#[test]
fn the_unreachable_child_warning_is_every_time() {
    use crate::containment::AbandonedChild;

    crate::log_capture::install();
    let error = || Error::Io(std::io::Error::other("cosca-abandoned-warn-probe-6f21"));
    let marker = "cosca-abandoned-warn-probe-6f21";

    for child in [AbandonedChild::MaybeUnreachable, AbandonedChild::MaybeUnreaped] {
        let mark = crate::log_capture::mark();
        super::warn_for_abandoned_child(child, &error());
        super::warn_for_abandoned_child(child, &error());

        assert_eq!(
            crate::log_capture::levels_since(mark, marker),
            [log::Level::Warn, log::Level::Warn]
        );
    }
}

/// `AbandonedChild::Ended` means nothing of the child runs and it is reaped or will be — not a
/// degraded guarantee, so it logs nothing at all.
#[test]
fn ended_abandoned_child_logs_nothing() {
    use crate::containment::AbandonedChild;

    crate::log_capture::install();
    let error = Error::Io(std::io::Error::other("cosca-abandoned-ended-probe-3a17"));
    let marker = "cosca-abandoned-ended-probe-3a17";

    let mark = crate::log_capture::mark();
    super::warn_for_abandoned_child(AbandonedChild::Ended, &error);

    assert_eq!(crate::log_capture::levels_since(mark, marker), Vec::<log::Level>::new());
}

/// Whether a record since `mark` says `marker` of the seam's failed spawn of `pid` at `warn` —
/// the seam's error names it — and so of this test's spawn, whatever other tests log meanwhile.
/// Checks the level too: a demoted repeat still carries the same text.
#[cfg(target_os = "linux")]
fn warned_for(mark: usize, pid: u32, marker: &str) -> bool {
    let spawn = format!("for child {pid})");
    crate::log_capture::records_since(mark, marker)
        .iter()
        .zip(crate::log_capture::levels_since(mark, marker))
        .any(|(record, level)| record.contains(&spawn) && level == log::Level::Warn)
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
            warned_for(mark, pid, "nothing can reach it"),
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
    let (mut cmd, teardown) = teardown_blocker();
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
    teardown.assert_killed();
}

/// On the identity-failure path, a child tokio could not kill (`EPERM`) goes to tokio's orphan
/// queue, which reaps it once it exits. The leaf, having taken its verdict first, answers only for
/// the tree — its kill through the leaf — and never reaps that child as an abandoned spawn's,
/// which would race tokio's reap for the same pid.
///
/// The leaf may still be left behind: its `Drop` does wait for the kill to drain before its
/// retried `rmdir` (see `CgroupLeaf`'s `Drop`), so this is not that exit-lag gap — a leftover here
/// would mean the retried `rmdir` itself still failed once the leaf drained.
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
/// child's stderr. It exits with `ABANDONED_EXIT` instead.
///
/// It sent nothing before the abandonment, so nothing in cosca holds its pid: the spawn warns that
/// it may be left unreaped, and the test reaps it through the seam's pidfd.
///
/// Runs in a process of its own: closing 1 and 2 is process-wide.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn cgroup_an_abandoned_spawn_writes_nothing_into_the_childs_stdio() {
    use std::io::{Read, Seek, Write};
    use std::os::fd::{AsFd, AsRawFd};

    use crate::test_own_process::{own_process, test_path};
    use crate::test_stdio::RestoreStdio;

    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "requires COSCA_TEST_CGROUP and a delegated cgroup"
    );
    let Some(done) = own_process(test_path!(
        cgroup_an_abandoned_spawn_writes_nothing_into_the_childs_stdio
    )) else {
        return;
    };

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
        let restore = RestoreStdio::close(&done, &[1, 2]);
        // Inherited by the child, which waits on it at its hook; this thread's copy is cleared.
        crate::containment::cgroup::fault::set_hook_gate(gate_read.as_raw_fd());
        fault::set_force_post_fork_failure(true);
        let spawned = cmd.spawn();
        let _ = crate::containment::cgroup::fault::take_hook_gate();
        drop(restore);
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

/// The sync command `spawn_uncommitted` takes: a [`blocker`] on `stdin` with `kill_on_drop(false)`.
#[cfg(target_os = "linux")]
fn opted_out_blocker(stdin: crate::stdio::Stdio) -> crate::command::Command {
    let mut cmd = crate::command::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin pipe");
    cmd.kill_on_drop(false);
    cmd
}

/// [`teardown_blocker`] with `kill_on_drop(false)`, as a sync command for `spawn_uncommitted`.
#[cfg(target_os = "linux")]
fn opted_out_teardown_blocker() -> (crate::command::Command, fault::TeardownBlocker) {
    let fault::TeardownBlockerParts {
        argv,
        stdin,
        stdout: _,
        guard,
    } = fault::teardown_blocker_parts();
    let mut cmd = crate::command::Command::new();
    cmd.args(argv);
    cmd.stdin(stdin).expect("set stdin pipe");
    cmd.kill_on_drop(false);
    (cmd, guard)
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
        let (stdin, writer) = crate::test_child::held_writer_stdin();
        let mut cmd = opted_out_blocker(stdin);
        let mut child = super::spawn_uncommitted(&mut cmd).expect("spawn");
        if commit {
            child.commit_kill_on_drop();
        }
        child.kill().expect("end the stand-in root");
        // Released only after the kill, so a child that exits 0 was not killed.
        drop(writer);
        let status = child.wait().await.expect("reap the stand-in root");
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGKILL),
            "the stand-in root must die of the kill, got {status:?}"
        );
        drop(child);

        let expected: &[u8] = if commit { b"" } else { b"1" };
        assert_eq!(
            std::fs::read(leaf_path.join("cgroup.kill")).expect("read cgroup.kill"),
            expected,
            "committed: {commit}"
        );
    }
}

/// A `DropProbe` armed for the next `Child::drop` on this thread, gate released at once: the test
/// observes the reaper, it does not pause it (the process-global pool's gate-hold budget is spent
/// elsewhere, see `reaper_tests`).
#[cfg(target_os = "linux")]
struct ReaperFence {
    entered: std::sync::mpsc::Receiver<std::thread::ThreadId>,
    started: std::sync::mpsc::Receiver<std::thread::ThreadId>,
    outcome: std::sync::mpsc::Receiver<crate::tokio::child::reaper::test_probe::ReapOutcome>,
}

#[cfg(target_os = "linux")]
impl ReaperFence {
    fn arm() -> Self {
        use crate::tokio::child::reaper::test_probe::{arm, DropProbe};
        let (entered_tx, entered) = std::sync::mpsc::channel();
        let (started_tx, started) = std::sync::mpsc::channel();
        let (gate_tx, gate_rx) = std::sync::mpsc::channel();
        let (outcome_tx, outcome) = std::sync::mpsc::channel();
        arm(DropProbe {
            entered: entered_tx,
            started: started_tx,
            gate: gate_rx,
            outcome: outcome_tx,
        });
        drop(gate_tx);
        Self {
            entered,
            started,
            outcome,
        }
    }

    /// Block until the reaper pool has fully finished with the dropped child's leaf, so nothing
    /// of it (a re-fired `cgroup.kill` write, the `rmdir`) can race the caller's reads or the
    /// removal of its tempdir. Returns `(dropping thread, executing thread)`; the teardown must
    /// have run on a pool thread, not inline.
    fn wait(self) -> (std::thread::ThreadId, std::thread::ThreadId) {
        use crate::tokio::child::reaper::test_probe::{assert_consumed, ReapOutcome};
        assert_consumed();
        let dropping = self.entered.recv().expect("Drop must reach the reaper handoff");
        let executing = self.started.recv().expect("a reaper worker must take the job");
        let outcome = self
            .outcome
            .recv()
            .expect("the reaper must report an outcome for this job");
        assert!(matches!(outcome, ReapOutcome::Reaped(_)), "got {outcome:?}");
        assert_ne!(
            executing, dropping,
            "the teardown must run on a reaper thread, not inline"
        );
        (dropping, executing)
    }
}

/// A failed password write kills the contained tree through the leaf: checked on the step log and
/// on `cgroup.kill`'s raw bytes.
///
/// `child`'s `Drop` hands the disarmed-but-killed leaf to the reaper pool, which re-fires
/// `hard_kill` on its own thread. Reading `cgroup.kill` or dropping `dir` while that write is in
/// flight races it (`O_TRUNC` can be read as `[]`; the write lands in a removed dir). So the test
/// waits on a [`ReaperFence`] first.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_failed_password_write_kills_the_contained_tree() {
    crate::log_capture::install();
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-async-password-leaf");
    attach_entered_leaf(&leaf_path);
    let (mut cmd, teardown) = opted_out_teardown_blocker();
    let mut child = super::spawn_uncommitted(&mut cmd).expect("spawn");
    // Rule out the leaf's `Drop`: only the failure path itself may kill.
    child.detach();

    let fence = ReaperFence::arm();
    crate::containment::cgroup::fault::record_leaf_steps();
    let mark = crate::log_capture::mark();
    let err = super::finish_elevated(child, failed_write()).expect_err("a failed write fails the spawn");
    teardown.assert_killed();

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
    // The step log is this thread's: the pool thread's re-fired kill is not in it.
    assert_eq!(
        crate::containment::cgroup::fault::take_leaf_steps(),
        vec!["kill".to_string()],
        "the failed spawn must kill its tree through the leaf"
    );

    // Wait for the reaper's teardown of this leaf before reading the file or dropping `dir`.
    fence.wait();
    assert_eq!(
        std::fs::read(leaf_path.join("cgroup.kill")).expect("read cgroup.kill"),
        crate::containment::cgroup::KILL_PAYLOAD,
        "the failed spawn must kill its tree through the leaf"
    );
    // A teardown that worked is not warned about.
    assert_eq!(
        crate::log_capture::levels_since(mark, &crate::child::spawn::teardown_warn_marker(&leaf_path)),
        Vec::<log::Level>::new(),
        "a successful tree kill must not warn"
    );
}

/// Async twin of the sync `a_failed_password_write_warns_when_the_tree_kill_fails`: the teardown
/// failure is logged at `warn`, not only embedded in the error's `detail`.
///
/// No [`ReaperFence`]: a refused `cgroup.kill` never sets the leaf's `killed`, so `Child::drop`
/// does not hand it to the reaper and the leaf drops inline. The test pins that: were the leaf
/// handed off, it would need a fence.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_failed_password_write_warns_when_the_tree_kill_fails() {
    crate::log_capture::install();
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-async-password-kill-fail-leaf");
    attach_entered_leaf(&leaf_path);
    let (mut cmd, teardown) = opted_out_teardown_blocker();
    let mut child = super::spawn_uncommitted(&mut cmd).expect("spawn");
    // Rule out the leaf's `Drop`: only the failure path itself may kill.
    child.detach();

    // Not ENOENT/ENODEV, so `hard_kill` treats it as a real failure: `open(O_WRONLY)` on a
    // directory fails EISDIR.
    std::fs::remove_file(leaf_path.join("cgroup.kill")).expect("remove the fixture's cgroup.kill file");
    std::fs::create_dir(leaf_path.join("cgroup.kill")).expect("make cgroup.kill a directory");
    let _fence = ReaperFence::arm();
    let mark = crate::log_capture::mark();
    let err = super::finish_elevated(child, failed_write()).expect_err("a failed write fails the spawn");
    teardown.assert_killed();
    assert!(
        crate::tokio::child::reaper::test_probe::take().is_some(),
        "a leaf whose kill was refused is not handed to the reaper, so there is nothing to fence"
    );
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
    let marker = crate::child::spawn::teardown_warn_marker(&leaf_path);
    assert_eq!(
        crate::log_capture::levels_since(mark, &marker),
        [log::Level::Warn],
        "a forced tree-kill failure must be logged at warn"
    );
    let errno_text = std::io::Error::from_raw_os_error(libc::EISDIR).to_string();
    let records = crate::log_capture::records_since(mark, &marker);
    assert!(
        records[0].contains(&errno_text),
        "the warning must name the OS reason the write failed, got {records:?}"
    );
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
    let (mut cmd, teardown) = opted_out_teardown_blocker();
    let child = super::spawn_uncommitted(&mut cmd).expect("spawn");
    let pid = child.id().pid();

    let err = super::finish_elevated(child, failed_write()).expect_err("a failed write fails the spawn");
    teardown.assert_killed();

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
    let (mut cmd, teardown) = opted_out_teardown_blocker();
    let child = super::spawn_uncommitted(&mut cmd).expect("spawn");
    let pid = child.id().pid();

    let err = super::finish_elevated(child, failed_write()).expect_err("a failed write fails the spawn");
    teardown.assert_killed();

    assert!(reaped(pid), "the root was killed, so it must be reaped, got {err:?}");
    let detail = err.to_string();
    assert!(detail.contains("was terminated"), "the root was killed, got {detail}");
    assert!(
        detail.contains("its contained tree could not be killed"),
        "the tree's failure is reported, got {detail}"
    );
}
