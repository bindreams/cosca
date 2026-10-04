//! A forced kill of a child behind an elevation front, on an ordinary `cat` this test owns and
//! reports as launched by `sudo` (`set_elevation`). No forced kill may signal a live front.
//!
//! Whether anything signalled the `cat` is read from how it ended: it exits 0 once the test closes
//! its stdin, and dies of `SIGKILL` if it was killed first.

use std::io::{PipeWriter, Read as _};
use std::os::unix::process::ExitStatusExt as _;
use std::time::Duration;

use crate::child::fault::record_root_teardowns;
use crate::command::Command;
use crate::elevation::{Backend, ElevatedStdio, ElevatedVia, ElevationReport};
use crate::error::{ElevationErrorKind, Error};
use crate::{ContainMode, Containment, Stdio};

pub(crate) fn report(via: ElevatedVia) -> Option<ElevationReport> {
    Some(ElevationReport {
        via,
        stripped_env: Vec::new(),
        stdio: ElevatedStdio::Passthrough,
    })
}

/// Spawns `cmd` with a piped stdin, reported as launched by `via`.
fn spawn_as(mut cmd: Command, via: ElevatedVia) -> (crate::Child, PipeWriter) {
    cmd.stdin(Stdio::pipe_in()).expect("stdin pipe");
    let mut child = cmd.spawn().expect("spawn");
    child.set_elevation(report(via));
    let stdin = child.stdin().expect("stdin pipe");
    (child, stdin)
}

fn cat() -> Command {
    let mut cmd = Command::new();
    cmd.args(["cat"]);
    cmd
}

#[track_caller]
pub(crate) fn assert_unkillable_front<T: std::fmt::Debug>(r: Result<T, Error>, pid: u32) {
    match r {
        Err(Error::Elevation {
            kind: ElevationErrorKind::Unkillable,
            detail,
        }) => assert!(detail.contains(&format!("pid {pid} is sudo")), "{detail}"),
        other => panic!("expected Unkillable for the live front {pid}, got {other:?}"),
    }
}

/// Closes the `cat`'s stdin and reaps it: it must exit 0, so nothing signalled it.
#[track_caller]
fn assert_ends_unsignalled(child: &crate::Child, stdin: PipeWriter) {
    drop(stdin);
    let status = child.wait().expect("wait");
    assert!(status.success(), "the front was signalled: {status:?}");
}

/// Mutant: `kill()` signals the front (it answers `Ok`, and the `cat` dies of `SIGKILL`).
#[skuld::test]
fn kill_of_a_live_front_is_unkillable_and_sends_nothing() {
    let (child, stdin) = spawn_as(cat(), ElevatedVia::Wrapped(Backend::Sudo));
    assert_unkillable_front(child.kill(), child.id().pid());
    assert_ends_unsignalled(&child, stdin);
}

/// A front that has exited orphans nothing, so its kill answers as any child's. Mutant: the
/// front's exit is not read, so the kill is `Unkillable`.
#[skuld::test]
fn kill_of_an_exited_front_is_ok() {
    let (child, stdin) = spawn_as(cat(), ElevatedVia::Wrapped(Backend::Sudo));
    drop(stdin);
    crate::test_child::wait_until_zombie(child.id().pid());
    child.kill().expect("an exited front is killed like any child");
    assert!(child.wait().expect("wait").success());
}

/// pkexec execs the program, so the tracked process is the program: it is signalled. Mutant:
/// pkexec counted as a front.
#[skuld::test]
fn kill_of_a_pkexec_child_signals_it() {
    let (child, _stdin) = spawn_as(cat(), ElevatedVia::Wrapped(Backend::Pkexec));
    child.kill().expect("kill");
    assert_eq!(child.wait().expect("wait").signal(), Some(libc::SIGKILL));
}

/// A process group or a walked tree is signalled subject to the target's credentials, so it does
/// not reach the program either. Mutants: `kill_tree` runs the group kill; it signals the front.
#[skuld::test]
fn kill_tree_of_a_live_front_outside_a_cgroup_is_unkillable_and_sends_nothing() {
    let mut cmd = cat();
    cmd.contain_with(ContainMode::Session);
    let (child, stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
    assert_ne!(child.containment(), Containment::CgroupV2);
    assert_unkillable_front(child.kill_tree(), child.id().pid());
    assert_ends_unsignalled(&child, stdin);
}

/// The escalation is the gated kill. A `cat` that ignores `SIGTERM` outlives the grace. Mutant:
/// the escalation signals the front directly.
#[skuld::test]
fn graceful_shutdown_of_a_front_that_outlives_the_grace_is_unkillable() {
    let mut cmd = Command::new();
    // An ignored disposition survives `exec`; `ready` says it is set.
    cmd.args(["sh", "-c", "trap '' TERM; echo ready; exec cat"]);
    cmd.stdout(Stdio::pipe_out()).expect("stdout pipe");
    let (mut child, stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
    let mut ready = [0u8; 6];
    child
        .stdout()
        .expect("stdout pipe")
        .read_exact(&mut ready)
        .expect("read `ready`");
    assert_eq!(&ready, b"ready\n");
    assert_unkillable_front(child.graceful_shutdown(Duration::ZERO), child.id().pid());
    assert_ends_unsignalled(&child, stdin);
}

/// The drop neither kills nor waits for a live front, and says so. Mutants: the drop runs the
/// root's teardown (kill and reap); it warns of nothing.
#[skuld::test]
fn drop_of_a_live_front_leaves_it_running_unreaped_and_warns() {
    crate::log_capture::install();
    let teardowns = record_root_teardowns();
    let mut cmd = cat();
    cmd.contain_with(ContainMode::Session);
    let (child, stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
    let pid = child.id().pid();

    let mark = crate::log_capture::mark();
    drop(child);

    assert_eq!(teardowns.count(), 0, "the drop must not kill or reap a live front");
    let warns = crate::log_capture::records_since_on_current_thread(mark, "Child::drop");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert_eq!(warns[0].0, log::Level::Warn);
    assert!(warns[0].1.contains(&format!("pid {pid} is sudo")), "{warns:?}");

    // Still this process's unreaped child: end it and reap it here.
    drop(stdin);
    assert_reaped_unsignalled(pid);
}

/// In a cgroup the kill goes through `cgroup.kill`, which reaches the program whatever its
/// credentials. Needs a delegated cgroup: the cgroup lane. Mutants: a front in a cgroup is refused;
/// its kill signals the front alone (the tree is not marked killed).
#[cfg(target_os = "linux")]
#[skuld::test]
fn cgroup_kill_of_a_front_goes_through_the_cgroup() {
    if !crate::test_support::require_group("CGROUP") {
        return;
    }
    let mut cmd = cat();
    cmd.contain_with(ContainMode::Strongest);
    let (child, _stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
    assert_eq!(child.containment(), Containment::CgroupV2);
    child.kill().expect("the cgroup kill reaches the program");
    assert!(child.tree_killed.is_set(), "the kill must go through the cgroup");
    assert_eq!(child.wait().expect("wait").signal(), Some(libc::SIGKILL));
}

/// A failed cgroup kill may leave the program running, so the front is not signalled either.
/// Mutant: the front is signalled after a failed cgroup kill.
#[cfg(target_os = "linux")]
#[skuld::test]
fn cgroup_a_failed_kill_of_a_front_leaves_the_front_alone() {
    if !crate::test_support::require_group("CGROUP") {
        return;
    }
    let mut cmd = cat();
    cmd.contain_with(ContainMode::Strongest);
    let (child, stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
    assert_eq!(child.containment(), Containment::CgroupV2);
    {
        let _failing = crate::containment::cgroup::fault::fail_kill_writes();
        assert!(child.kill().is_err(), "the forced cgroup.kill failure surfaces");
        assert!(child.kill_tree().is_err(), "the forced cgroup.kill failure surfaces");
    }
    assert_ends_unsignalled(&child, stdin);
}

/// The drop, too, leaves a front alone when its cgroup kill fails. Mutant: the drop tears the front
/// down after a failed cgroup kill.
#[cfg(target_os = "linux")]
#[skuld::test]
fn cgroup_a_failed_drop_kill_of_a_front_leaves_the_front_alone() {
    if !crate::test_support::require_group("CGROUP") {
        return;
    }
    crate::log_capture::install();
    let teardowns = record_root_teardowns();
    let mut cmd = cat();
    cmd.contain_with(ContainMode::Strongest);
    let (child, stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
    let crate::containment::Attached::Cgroup(leaf) = &child.attached else {
        panic!("expected a cgroup leaf, got {:?}", child.attached);
    };
    let leaf = leaf.path().to_path_buf();
    let pid = child.id().pid();
    {
        let _failing = crate::containment::cgroup::fault::fail_kill_writes();
        drop(child);
    }
    assert_eq!(teardowns.count(), 0, "the drop must not kill or reap the front");
    drop(stdin);
    assert_reaped_unsignalled(pid);
    // The failed kill left the leaf behind; it is empty now.
    std::fs::remove_dir(&leaf).unwrap_or_else(|e| panic!("remove the leaf {}: {e}", leaf.display()));
}

/// Reaps `pid`, an unreaped child of this process that nothing else reaps, and asserts it exited 0.
#[track_caller]
fn assert_reaped_unsignalled(pid: u32) {
    let mut status = 0;
    // SAFETY: `status` is a valid out-parameter.
    let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    assert_eq!(
        reaped,
        pid as libc::pid_t,
        "waitpid: {}",
        std::io::Error::last_os_error()
    );
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "the front was signalled: raw status {status:#x}"
    );
}

/// A failed password write's teardown signals neither a live front nor its group, and says why.
/// The `killpg` recorder stands in for the group kill. Mutants: the teardown runs the group kill;
/// it signals the front.
#[skuld::test]
fn a_failed_password_write_signals_neither_a_live_front_nor_its_group() {
    let groups = crate::containment::unix::fault::record_kill_group();
    let mut cmd = cat();
    cmd.contain_with(ContainMode::Session);
    let (child, stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));
    let pid = child.id().pid();
    let err = crate::child::spawn::finish_elevated(
        child,
        Err(Error::Elevation {
            kind: ElevationErrorKind::AuthFailed,
            detail: "forced password-write failure".into(),
        }),
    )
    .expect_err("a failed write fails the spawn");
    assert_eq!(
        groups.killed(),
        Vec::<i32>::new(),
        "no group kill of a live front: {err}"
    );
    let Error::Elevation { detail, .. } = &err else {
        panic!("expected an Elevation error, got {err:?}");
    };
    assert!(detail.contains("could not be terminated"), "{detail}");
    assert!(detail.contains(&format!("pid {pid} is sudo")), "{detail}");
    // The handle was dropped with the front alive and unreaped.
    drop(stdin);
    assert_reaped_unsignalled(pid);
}
