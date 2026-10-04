//! Async twins of `child/front_cgroup_tests.rs`: forced kills of a front in a cgroup, on the cgroup
//! lane (the `cgroup` group, as root). See there for how a refused signal is made real.
//!
//! tokio owns the reap, so a front's end is read through a pidfd, without reaping it, before this
//! test yields to its runtime.

use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::process::ExitStatusExt as _;

use super::front_kill_tests::{assert_ends_unsignalled, cat, spawn_as};
use crate::child::front_cgroup_tests::{move_out_of_its_leaf, pidfd_of, WithoutKillCap};
use crate::child::front_kill_tests::assert_unkillable_front;
use crate::elevation::{Backend, ElevatedVia};
use crate::test_groups::{cgroup, Group};
use crate::tokio::child::{drop_fault, Child};
use crate::tokio::{ChildStdin, Command};
use crate::{ContainMode, Containment, Stdio};

const SUDO: ElevatedVia = ElevatedVia::Wrapped(Backend::Sudo);

/// A forced kill of a child: `kill` or `kill_tree`.
type Kill = fn(&mut Child) -> Result<(), crate::error::Error>;

fn in_cgroup(mut cmd: Command) -> Command {
    cmd.contain_with(ContainMode::Strongest);
    cmd
}

/// A `cat` that runs as `nobody` in a cgroup, reported as launched by `sudo`; returns once it runs
/// as `nobody`. See the sync `nobody_cat`.
async fn spawn_nobody_front() -> (Child, ChildStdin) {
    use ::tokio::io::AsyncReadExt as _;
    let mut cmd = Command::new();
    cmd.args([
        "setpriv",
        "--reuid=65534",
        "--regid=65534",
        "--clear-groups",
        "sh",
        "-c",
        "echo ready; exec cat",
    ]);
    cmd.stdout(Stdio::pipe()).expect("stdout pipe");
    let (mut child, stdin) = spawn_as(in_cgroup(cmd), SUDO);
    assert_eq!(child.containment(), Containment::CgroupV2);
    let mut ready = [0u8; 6];
    child
        .stdout()
        .expect("stdout pipe")
        .read_exact(&mut ready)
        .await
        .expect("read `ready`");
    assert_eq!(&ready, b"ready\n");
    (child, stdin)
}

/// How the child `pidfd` names ended, read without reaping it: its exit code and signal, or
/// `None` once something reaped it (tokio's in-drop `try_wait` reaps a child that has ended).
fn ended(pidfd: &OwnedFd) -> Option<(Option<i32>, Option<i32>)> {
    loop {
        match rustix::process::waitid(
            rustix::process::WaitId::PidFd(pidfd.as_fd()),
            rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOWAIT,
        ) {
            Ok(Some(status)) => return Some((status.exit_status(), status.terminating_signal())),
            Ok(None) => unreachable!("a blocking waitid returns a status"),
            Err(rustix::io::Errno::INTR) => {}
            Err(rustix::io::Errno::CHILD) => return None,
            Err(e) => panic!("waitid on the front's pidfd: {e}"),
        }
    }
}

/// The front `pidfd` names was killed: it died of `SIGKILL`, or tokio's drop reaped it, which it
/// does only for a child that has ended, and with its stdin still held only a kill ends it.
#[track_caller]
fn assert_killed(pidfd: &OwnedFd) {
    let end = ended(pidfd);
    assert!(
        matches!(end, None | Some((None, Some(libc::SIGKILL)))),
        "the cgroup kill must end the front: {end:?}"
    );
}

/// Mutants: a front in a cgroup is refused; its kill skips the cgroup; it signals the front after
/// it (seen in `cgroup_kill_of_a_front_that_refuses_signals_is_ok`).
#[skuld::test]
async fn cgroup_kill_of_a_front_goes_through_the_cgroup(#[fixture(cgroup)] _group: &Group) {
    let (mut child, _stdin) = spawn_as(in_cgroup(cat()), SUDO);
    assert_eq!(child.containment(), Containment::CgroupV2);
    child.kill().expect("the cgroup kill reaches the program");
    assert!(child.tree_killed.is_set(), "the kill must go through the cgroup");
    assert_eq!(child.wait().await.expect("wait").signal(), Some(libc::SIGKILL));
}

/// Mutant: `kill_tree` skips the cgroup for a front.
#[skuld::test]
async fn cgroup_kill_tree_of_a_front_goes_through_the_cgroup(#[fixture(cgroup)] _group: &Group) {
    let (mut child, _stdin) = spawn_as(in_cgroup(cat()), SUDO);
    child.kill_tree().expect("the cgroup kill reaches the program");
    assert!(child.tree_killed.is_set());
    assert_eq!(child.wait().await.expect("wait").signal(), Some(libc::SIGKILL));
}

/// The drop kills the front through the cgroup, with no kill of its own. Mutants: the drop leaves a
/// front in a cgroup running; it kills the root itself.
#[skuld::test]
async fn cgroup_drop_of_a_front_kills_it_through_the_cgroup(#[fixture(cgroup)] _group: &Group) {
    crate::tokio::test_runtime::assert_current_thread();
    let roots = drop_fault::record();
    let (child, _stdin) = spawn_as(in_cgroup(cat()), SUDO);
    let pidfd = pidfd_of(child.id().pid());
    drop(child);
    assert_eq!(roots.kills(), 0, "the drop sends the front no kill of its own");
    assert_killed(&pidfd);
}

/// Mutant: the front is signalled after a failed cgroup kill.
#[skuld::test]
async fn cgroup_a_failed_kill_of_a_front_leaves_the_front_alone(#[fixture(cgroup)] _group: &Group) {
    let (mut child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
    {
        let _failing = crate::containment::cgroup::fault::fail_kill_writes();
        assert!(child.kill().is_err(), "the forced cgroup.kill failure surfaces");
        assert!(child.kill_tree().is_err(), "the forced cgroup.kill failure surfaces");
    }
    assert_ends_unsignalled(&mut child, stdin).await;
}

/// Mutant: the drop kills the front after a failed cgroup kill.
#[skuld::test]
async fn cgroup_a_failed_drop_kill_of_a_front_leaves_the_front_alone(#[fixture(cgroup)] _group: &Group) {
    crate::tokio::test_runtime::assert_current_thread();
    let roots = drop_fault::record();
    let (child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
    let crate::containment::Attached::Cgroup(leaf) = &child.os.attached else {
        panic!("expected a cgroup leaf, got {:?}", child.os.attached);
    };
    let leaf = leaf.path().to_path_buf();
    let pidfd = pidfd_of(child.id().pid());
    {
        let _failing = crate::containment::cgroup::fault::fail_kill_writes();
        drop(child);
    }
    assert_eq!(roots.kills(), 0, "the drop must not kill the front");
    drop(stdin);
    assert_eq!(ended(&pidfd), Some((Some(0), None)), "the drop signalled the front");
    // The failed kill left the leaf behind; it is empty once the front has exited.
    std::fs::remove_dir(&leaf).unwrap_or_else(|e| panic!("remove the leaf {}: {e}", leaf.display()));
}

/// A front whose signal is refused (direct exec) is still killed, through the cgroup. Mutant: the
/// front is signalled after the cgroup kill, which the refusal turns into a false `Unkillable`.
#[skuld::test]
async fn cgroup_kill_of_a_front_that_refuses_signals_is_ok(#[fixture(cgroup)] _group: &Group) {
    let (mut child, _stdin) = spawn_nobody_front().await;
    {
        let _refusing = WithoutKillCap::refusing(child.id().pid());
        child.kill().expect("the cgroup kill ends the front");
        child.kill_tree().expect("the cgroup kill ends the front");
    }
    assert_eq!(child.wait().await.expect("wait").signal(), Some(libc::SIGKILL));
}

/// Mutant: the drop's own kill is attempted, refused, and warned about.
#[skuld::test]
async fn cgroup_drop_of_a_front_that_refuses_signals_kills_it(#[fixture(cgroup)] _group: &Group) {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let roots = drop_fault::record();
    let (child, _stdin) = spawn_nobody_front().await;
    let pidfd = pidfd_of(child.id().pid());
    let mark = crate::log_capture::mark();
    {
        let _refusing = WithoutKillCap::refusing(child.id().pid());
        drop(child);
    }
    assert_eq!(roots.kills(), 0, "the drop sends the front no kill of its own");
    assert_killed(&pidfd);
    let warns = crate::log_capture::records_since_on_current_thread(mark, "could not be terminated");
    assert_eq!(warns, [], "nothing was refused");
}

/// Mutant: the front is signalled after the cgroup kill, and the note says it could not be.
#[skuld::test]
async fn cgroup_a_failed_password_write_terminates_a_front_that_refuses_signals(#[fixture(cgroup)] _group: &Group) {
    let (child, _stdin) = spawn_nobody_front().await;
    let _refusing = WithoutKillCap::refusing(child.id().pid());
    let err = crate::tokio::spawn::finish_elevated(
        child,
        Err(crate::error::Error::Elevation {
            kind: crate::error::ElevationErrorKind::AuthFailed,
            detail: "forced password-write failure".into(),
        }),
    )
    .expect_err("a failed write fails the spawn");
    let rendered = err.to_string();
    assert!(rendered.contains("the elevated child was terminated"), "{rendered}");
}

/// Mutants: membership is not checked; the drop kills a front that left its leaf.
#[skuld::test]
async fn cgroup_a_front_that_left_its_leaf_is_unkillable_and_sent_nothing(#[fixture(cgroup)] _group: &Group) {
    crate::tokio::test_runtime::assert_current_thread();
    let roots = drop_fault::record();
    let (mut child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
    let pid = child.id().pid();
    let pidfd = pidfd_of(pid);
    move_out_of_its_leaf(pid);
    assert_unkillable_front(child.kill(), pid);
    assert_unkillable_front(child.kill_tree(), pid);
    assert!(!child.tree_killed.is_set(), "no cgroup kill ran");
    drop(child);
    assert_eq!(roots.kills(), 0, "the drop must not kill the front");
    drop(stdin);
    assert_eq!(ended(&pidfd), Some((Some(0), None)), "nothing signalled the front");
}

/// Mutant: an exited front is signalled like any child, and the refusal reads as `Unkillable`.
#[skuld::test]
async fn cgroup_kill_of_an_exited_front_that_refuses_signals_is_ok(#[fixture(cgroup)] _group: &Group) {
    let (mut child, stdin) = spawn_nobody_front().await;
    let pid = child.id().pid();
    drop(stdin);
    crate::test_child::wait_until_zombie(pid);
    {
        let _refusing = WithoutKillCap::refusing(pid);
        child.kill().expect("an exited front is killed like any exited child");
        child
            .kill_tree()
            .expect("an exited front is killed like any exited child");
    }
    assert!(child.wait().await.expect("wait").success());
}

/// Mutant: whether the kill reached the front is not read after the write (`Ok`).
#[skuld::test]
async fn cgroup_a_front_moved_out_during_its_kill_is_unkillable(#[fixture(cgroup)] _group: &Group) {
    use crate::child::front_kill_tests::assert_refused_by;
    let kills: [Kill; 2] = [Child::kill, Child::kill_tree];
    for kill in kills {
        let (mut child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
        let pid = child.id().pid();
        let _moving = crate::containment::cgroup::fault::set_before_kill_write(move || move_out_of_its_leaf(pid));
        assert_refused_by(kill(&mut child), "left the cgroup before its kill");
        assert_ends_unsignalled(&mut child, stdin).await;
    }
}

/// The drop of such a front signals nothing and warns. Mutant: the drop reports the front killed
/// (no warning) because it does not read whether its kill reached it.
#[skuld::test]
async fn cgroup_drop_of_a_front_moved_out_during_its_kill_warns(#[fixture(cgroup)] _group: &Group) {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let roots = drop_fault::record();
    let (child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
    let pid = child.id().pid();
    let pidfd = pidfd_of(pid);
    let _moving = crate::containment::cgroup::fault::set_before_kill_write(move || move_out_of_its_leaf(pid));
    let mark = crate::log_capture::mark();
    drop(child);
    assert_eq!(roots.kills(), 0, "the drop sends the front no kill of its own");
    let warns = crate::log_capture::records_since_on_current_thread(mark, "is left running");
    assert_eq!(warns.len(), 1, "{warns:?}");
    drop(stdin);
    assert_eq!(ended(&pidfd), Some((Some(0), None)), "nothing signalled the front");
}

/// Mutant: the backstop asks the gate again after the cgroup kill.
#[skuld::test]
async fn cgroup_kill_tree_of_a_front_asks_the_gate_once(#[fixture(cgroup)] _group: &Group) {
    let (mut child, _stdin) = spawn_as(in_cgroup(cat()), SUDO);
    let gates = crate::elevation::front::seams::count_kill_gates();
    child.kill_tree().expect("the cgroup kill reaches the front");
    assert_eq!(gates.count(), 1);
}

/// Async twin of the sync `cgroup_a_failed_spawn_kills_a_contained_front_and_reaps_it`.
#[skuld::test]
async fn cgroup_a_failed_spawn_kills_a_contained_front_and_reaps_it(#[fixture(cgroup)] _group: &Group) {
    use crate::child::front_kill_tests::{assert_noted, failed_front_spawns, reap};
    let failures = failed_front_spawns(Some(ContainMode::Strongest), |cmd| {
        crate::tokio::spawn::spawn(cmd).map(drop)
    });
    assert_noted(&failures, "had exited by the teardown");
    for (_, pid) in &failures {
        assert_eq!(reap(*pid), None, "the teardown reaps a front its cgroup's kill ended");
    }
}
