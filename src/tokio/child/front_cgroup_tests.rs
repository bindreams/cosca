//! Async twins of `child/front_cgroup_tests.rs`: forced kills of a front in a cgroup, on the cgroup
//! lane (the `cgroup` group, as root). See there for how a refused signal is made real.
//!
//! tokio owns the reap, so a front's end is read through a pidfd, without reaping it, before this
//! test yields to its runtime.

use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::process::ExitStatusExt as _;

use super::front_kill_tests::{assert_ends_unsignalled, cat, spawn_as};
use crate::child::front_cgroup_tests::{
    assert_left_unsignalled, fail_the_identity_check, front_its_leaf_did_not_take, move_out_of_its_leaf, pidfd_of,
    WithoutKillCap,
};
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

/// Async twin of the sync `spawn_nobody_front`.
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

#[skuld::test]
async fn cgroup_kill_of_a_front_goes_through_the_cgroup(#[fixture(cgroup)] _group: &Group) {
    let (mut child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
    assert_eq!(child.containment(), Containment::CgroupV2);
    child.kill().expect("the cgroup kill reaches the program");
    assert!(child.tree_killed.is_set(), "the kill must go through the cgroup");
    // Closed first: a front nothing killed then exits 0, and the assertion fails.
    drop(stdin);
    assert_eq!(child.wait().await.expect("wait").signal(), Some(libc::SIGKILL));
}

#[skuld::test]
async fn cgroup_kill_tree_of_a_front_goes_through_the_cgroup(#[fixture(cgroup)] _group: &Group) {
    let (mut child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
    child.kill_tree().expect("the cgroup kill reaches the program");
    assert!(child.tree_killed.is_set());
    // Closed first: a front nothing killed then exits 0, and the assertion fails.
    drop(stdin);
    assert_eq!(child.wait().await.expect("wait").signal(), Some(libc::SIGKILL));
}

/// The drop kills the front through the cgroup, with no kill of its own, and warns of nothing. The
/// leaf's own release would kill a busy leaf anyway, so the front's end alone cannot tell the
/// drop's kill from the release's: the warning a front left running gets can.
#[skuld::test]
async fn cgroup_drop_of_a_front_kills_it_through_the_cgroup(#[fixture(cgroup)] _group: &Group) {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let roots = drop_fault::record();
    let (child, _stdin) = spawn_as(in_cgroup(cat()), SUDO);
    let pidfd = pidfd_of(child.id().pid());
    let mark = crate::log_capture::mark();
    drop(child);
    assert_eq!(roots.kills(), 0, "the drop sends the front no kill of its own");
    let warns = crate::log_capture::records_since_on_current_thread(mark, "Child::drop");
    assert_eq!(warns, [], "a front the drop's cgroup kill ended is not left running");
    assert_killed(&pidfd);
}

#[skuld::test]
async fn cgroup_a_failed_kill_of_a_front_leaves_the_front_alone(#[fixture(cgroup)] _group: &Group) {
    let (mut child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
    {
        let _failing = crate::containment::cgroup::fault::fail_kill_writes();
        crate::child::front_kill_tests::assert_refused_by(child.kill(), "its cgroup kill failed");
        crate::child::front_kill_tests::assert_refused_by(child.kill_tree(), "its cgroup kill failed");
    }
    assert_ends_unsignalled(&mut child, stdin).await;
}

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

/// A `cat` front, contained and reported as launched by `sudo`, that has also started a `sleep` in
/// its leaf: another member of the tree. Returns the front, its stdin and a pidfd of the `sleep`.
async fn spawn_front_with_member() -> (Child, ChildStdin, OwnedFd) {
    use ::tokio::io::AsyncReadExt as _;
    let mut cmd = Command::new();
    cmd.args(["sh", "-c", "sleep 1000 & echo $!; exec cat"]);
    cmd.stdout(Stdio::pipe()).expect("stdout pipe");
    let (mut child, stdin) = spawn_as(in_cgroup(cmd), SUDO);
    let mut stdout = child.stdout().expect("stdout pipe");
    let (mut line, mut byte) = (Vec::new(), [0u8; 1]);
    while stdout.read_exact(&mut byte).await.is_ok() && byte[0] != b'\n' {
        line.push(byte[0]);
    }
    let member: u32 = String::from_utf8(line)
        .expect("utf8")
        .trim()
        .parse()
        .expect("the sleep's pid");
    (child, stdin, pidfd_of(member))
}

/// What a tokio drop does with a front in its leaf when it cannot be sure of it: the armed leaf's
/// release writes `cgroup.kill`, which ends the front and every other member, and the one warning
/// says exactly that, never that the front is left running. `fault` arms what made the drop unsure.
async fn assert_tokio_drop_kills_the_leaf(fault: impl FnOnce() -> Box<dyn std::any::Any>) {
    use crate::child::front_cgroup_tests::wait_until_exited;
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (child, _stdin, member) = spawn_front_with_member().await;
    let pid = child.id().pid();
    let pidfd = pidfd_of(pid);
    crate::containment::cgroup::fault::record_leaf_steps();
    let mark = crate::log_capture::mark();
    {
        let _fault = fault();
        drop(child);
    }
    let steps = crate::containment::cgroup::fault::take_leaf_steps();
    let warns = crate::log_capture::records_since_on_current_thread(mark, &format!("elevation front pid {pid}"));
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert_eq!(warns[0].0, log::Level::Warn);
    assert!(
        warns[0]
            .1
            .contains("the front is killed through its cgroup if it is still in it, and is left unreaped"),
        "{warns:?}"
    );
    assert!(!warns[0].1.contains("left running"), "{warns:?}");
    // The write is made before the drop returns; the processes' ends follow it.
    assert!(steps.iter().any(|s| s == "kill"), "the leaf was killed: {steps:?}");
    assert_killed(&pidfd);
    wait_until_exited(&member);
}

/// Async twin of the sync `cgroup_a_drop_whose_placement_read_fails_kills_the_leaf_and_reaps_the_front`.
/// Mutant: "the drop disarms the leaf".
#[skuld::test]
async fn cgroup_a_drop_whose_placement_read_fails_kills_the_leaf(#[fixture(cgroup)] _group: &Group) {
    assert_tokio_drop_kills_the_leaf(|| Box::new(crate::containment::cgroup::fault::fail_pidfd_info())).await;
}

/// Async twin of the sync first-write twin.
#[skuld::test]
async fn cgroup_a_drop_whose_first_cgroup_kill_fails_kills_the_leaf(#[fixture(cgroup)] _group: &Group) {
    assert_tokio_drop_kills_the_leaf(|| Box::new(crate::containment::cgroup::fault::fail_next_kill_write())).await;
}

/// Async twin of the sync post-kill twin.
#[skuld::test]
async fn cgroup_a_drop_whose_post_kill_read_fails_kills_the_leaf(#[fixture(cgroup)] _group: &Group) {
    assert_tokio_drop_kills_the_leaf(|| {
        let unreadable = std::rc::Rc::new(std::cell::RefCell::new(None));
        let arming = crate::containment::cgroup::fault::set_before_kill_write({
            let unreadable = std::rc::Rc::clone(&unreadable);
            move || *unreadable.borrow_mut() = Some(crate::containment::cgroup::fault::fail_pidfd_info())
        });
        let running = crate::elevation::front::seams::read_front_running_at_every_reach_read();
        Box::new((arming, running, unreadable))
    })
    .await;
}

/// A front outside its leaf: the leaf's release kills the rest of the leaf, and the front, which it
/// does not hold, runs on. Mutant: "the drop disarms the leaf" (the member survives, and the leaf
/// is never written).
#[skuld::test]
async fn cgroup_drop_of_a_front_outside_its_leaf_kills_the_rest_of_it(#[fixture(cgroup)] _group: &Group) {
    use crate::child::front_cgroup_tests::wait_until_exited;
    crate::tokio::test_runtime::assert_current_thread();
    let (child, stdin, member) = spawn_front_with_member().await;
    let pid = child.id().pid();
    let pidfd = pidfd_of(pid);
    move_out_of_its_leaf(pid);
    crate::containment::cgroup::fault::record_leaf_steps();
    drop(child);
    let steps = crate::containment::cgroup::fault::take_leaf_steps();
    assert!(steps.iter().any(|s| s == "kill"), "the leaf was killed: {steps:?}");
    wait_until_exited(&member);
    drop(stdin);
    assert_eq!(ended(&pidfd), Some((Some(0), None)), "nothing signalled the front");
}

/// Async twin of the sync `cgroup_kill_of_a_front_that_refuses_signals_is_ok`.
#[skuld::test]
async fn cgroup_kill_of_a_front_that_refuses_signals_is_ok(#[fixture(cgroup)] _group: &Group) {
    let (mut child, stdin) = spawn_nobody_front().await;
    {
        let _refusing = WithoutKillCap::refusing(child.id().pid());
        child.kill().expect("the cgroup kill ends the front");
        child.kill_tree().expect("the cgroup kill ends the front");
    }
    // Closed first: a front nothing killed then exits 0, and the assertion fails.
    drop(stdin);
    assert_eq!(child.wait().await.expect("wait").signal(), Some(libc::SIGKILL));
}

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

#[skuld::test]
async fn cgroup_a_failed_password_write_terminates_a_front_that_refuses_signals(#[fixture(cgroup)] _group: &Group) {
    crate::tokio::test_runtime::assert_current_thread();
    let (child, stdin) = spawn_nobody_front().await;
    let pidfd = pidfd_of(child.id().pid());
    let _refusing = WithoutKillCap::refusing(child.id().pid());
    // The teardown awaits its leaf's drain, which only the cgroup kill brings about: that the kill
    // was written is checked before the wait blocks, so a teardown that skipped it fails here, not
    // by hanging.
    crate::containment::cgroup::fault::record_leaf_steps();
    let _before_drain = crate::containment::cgroup::fault::set_before_drain_block(|| {
        let steps = crate::containment::cgroup::fault::leaf_steps_so_far();
        assert!(
            steps.iter().any(|s| s == "kill"),
            "cgroup.kill was written before the drain wait: {steps:?}"
        );
    });
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
    let steps = crate::containment::cgroup::fault::take_leaf_steps();
    assert!(steps.iter().any(|s| s == "kill"), "{steps:?}");
    // Closed first: a front nothing killed then exits 0, and the assertion fails.
    drop(stdin);
    assert_killed(&pidfd);
}

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

/// The drop of such a front signals nothing and warns.
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
    // The warning of a front whose cgroup kill did not reach it, not that of one never killed.
    let warns = crate::log_capture::records_since_on_current_thread(mark, "if it is still in it");
    assert_eq!(warns.len(), 1, "{warns:?}");
    drop(stdin);
    assert_eq!(ended(&pidfd), Some((Some(0), None)), "nothing signalled the front");
}

/// Async twin of the sync `cgroup_a_failed_password_write_asks_the_gate_once`.
#[skuld::test]
async fn cgroup_a_failed_password_write_asks_the_gate_once(#[fixture(cgroup)] _group: &Group) {
    let mut cmd = in_cgroup(cat());
    cmd.kill_on_drop(false);
    let (child, _stdin) = spawn_as(cmd, SUDO);
    let gates = crate::elevation::front::seams::count_kill_gates();
    let err = crate::tokio::spawn::finish_elevated(
        child,
        Err(crate::error::Error::Elevation {
            kind: crate::error::ElevationErrorKind::AuthFailed,
            detail: "forced password-write failure".into(),
        }),
    )
    .expect_err("a failed write fails the spawn");
    assert!(err.to_string().contains("the elevated child was terminated"), "{err}");
    assert_eq!(gates.count(), 1);
}

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
    use crate::child::front_cgroup_tests::{assert_killed_by_the_leaf, failed_held_front_spawns, LeafKill};
    let _running = crate::child::spawn::fault::see_fronts_running();
    let reaps = crate::child::spawn::fault::record_teardown_reaps();
    let failures = failed_held_front_spawns(LeafKill::Lands, |cmd| crate::tokio::spawn::spawn(cmd).map(drop));
    assert_killed_by_the_leaf(&failures, &reaps);
}

/// Async twin of the sync `cgroup_a_failed_spawn_whose_leaf_kill_fails_leaves_the_front_running`.
#[skuld::test]
async fn cgroup_a_failed_spawn_whose_leaf_kill_fails_leaves_the_front_running(#[fixture(cgroup)] _group: &Group) {
    use crate::child::front_cgroup_tests::{assert_left_running, failed_held_front_spawns, LeafKill};
    let kill = LeafKill::Fails;
    assert_left_running(
        kill,
        failed_held_front_spawns(kill, |cmd| crate::tokio::spawn::spawn(cmd).map(drop)),
    );
}

/// Async twin of the sync `cgroup_a_failed_spawn_leaves_a_front_moved_out_of_its_leaf_running`.
#[skuld::test]
async fn cgroup_a_failed_spawn_leaves_a_front_moved_out_of_its_leaf_running(#[fixture(cgroup)] _group: &Group) {
    use crate::child::front_cgroup_tests::{assert_left_running, failed_held_front_spawns, LeafKill};
    let kill = LeafKill::MissesMovedFront;
    assert_left_running(
        kill,
        failed_held_front_spawns(kill, |cmd| crate::tokio::spawn::spawn(cmd).map(drop)),
    );
}

/// Async twin of the sync `cgroup_a_failed_spawn_kills_a_front_read_through_proc_and_reaps_it`.
#[skuld::test]
async fn cgroup_a_failed_spawn_kills_a_front_read_through_proc_and_reaps_it(#[fixture(cgroup)] _group: &Group) {
    use crate::child::front_cgroup_tests::{assert_killed_by_the_leaf, failed_held_front_spawns, LeafKill};
    let _running = crate::child::spawn::fault::see_fronts_running();
    let reaps = crate::child::spawn::fault::record_teardown_reaps();
    let failures = failed_held_front_spawns(LeafKill::LandsReadThroughProc, |cmd| {
        crate::tokio::spawn::spawn(cmd).map(drop)
    });
    assert_killed_by_the_leaf(&failures, &reaps);
}

/// Async twin of the sync `cgroup_a_failed_spawn_leaves_a_front_in_a_namesake_of_its_leaf_running`.
#[skuld::test]
async fn cgroup_a_failed_spawn_leaves_a_front_in_a_namesake_of_its_leaf_running(#[fixture(cgroup)] _group: &Group) {
    use crate::child::front_cgroup_tests::{assert_left_running, failed_held_front_spawns, LeafKill};
    let kill = LeafKill::MissesIntoNamesake;
    assert_left_running(
        kill,
        failed_held_front_spawns(kill, |cmd| crate::tokio::spawn::spawn(cmd).map(drop)),
    );
}

/// Async twin of the sync `cgroup_a_front_nested_under_its_leaf_is_killed_under_hidepid`.
#[skuld::test]
async fn cgroup_a_front_nested_under_its_leaf_is_killed_under_hidepid(#[fixture(cgroup)] _group: &Group) {
    let (mut child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
    crate::child::front_cgroup_tests::move_under_its_leaf(child.id().pid());
    {
        let _hidden = crate::containment::cgroup::fault::hide_proc();
        child.kill().expect("the leaf's kill reaches a front nested under it");
    }
    // Closed first: a front nothing killed then exits 0, and the assertion fails.
    drop(stdin);
    let status = child.wait().await.expect("wait");
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "the front dies of its leaf's kill"
    );
}

/// Async twin of the sync `cgroup_a_failed_spawn_kills_a_front_nested_under_its_leaf_under_hidepid`.
#[skuld::test]
async fn cgroup_a_failed_spawn_kills_a_front_nested_under_its_leaf_under_hidepid(#[fixture(cgroup)] _group: &Group) {
    use crate::child::front_cgroup_tests::{assert_killed_by_the_leaf, failed_held_front_spawns, LeafKill};
    let _running = crate::child::spawn::fault::see_fronts_running();
    let reaps = crate::child::spawn::fault::record_teardown_reaps();
    let failures = failed_held_front_spawns(LeafKill::LandsNestedHidden, |cmd| {
        crate::tokio::spawn::spawn(cmd).map(drop)
    });
    assert_killed_by_the_leaf(&failures, &reaps);
}

/// Async twin of the sync `cgroup_a_front_whose_leaf_gives_no_id_is_refused_before_its_fork`.
#[skuld::test]
async fn cgroup_a_front_whose_leaf_gives_no_id_is_refused_before_its_fork(#[fixture(cgroup)] _group: &Group) {
    use crate::child::front_cgroup_tests::{assert_refused_unforked_naming, spawn_front_noting_fork};
    let _no_id = crate::containment::cgroup::fault::fail_cgroup_id(libc::ENOSYS);
    let mut cmd = crate::command::Command::new();
    cmd.args(["cat"]).contain_with(ContainMode::Strongest);
    cmd.stdin(Stdio::pipe_in()).expect("stdin pipe");
    let (result, forked) = spawn_front_noting_fork(cmd, |cmd| crate::tokio::spawn::spawn(cmd).map(drop));
    assert_refused_unforked_naming(result, forked, "name_to_handle_at");
}

/// Async twin of the sync `cgroup_a_failed_password_write_whose_cgroup_kill_fails_refuses_as_kill_does`.
#[skuld::test]
async fn cgroup_a_failed_password_write_whose_cgroup_kill_fails_refuses_as_kill_does(
    #[fixture(cgroup)] _group: &Group,
) {
    use crate::child::front_cgroup_tests::assert_front_refused_by_its_cgroup_kill;
    let (child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
    let pid = child.id().pid();
    let pidfd = pidfd_of(pid);
    let crate::containment::Attached::Cgroup(leaf) = &child.os.attached else {
        panic!("expected a cgroup leaf, got {:?}", child.os.attached);
    };
    let leaf = leaf.path().to_path_buf();
    let err = {
        let _failing = crate::containment::cgroup::fault::fail_kill_writes();
        crate::tokio::spawn::finish_elevated(
            child,
            Err(crate::error::Error::Elevation {
                kind: crate::error::ElevationErrorKind::AuthFailed,
                detail: "forced password-write failure".into(),
            }),
        )
        .expect_err("a failed write fails the spawn")
    };
    assert_front_refused_by_its_cgroup_kill(&err, pid);
    drop(stdin);
    assert_eq!(ended(&pidfd), Some((Some(0), None)), "the front was signalled");
    std::fs::remove_dir(&leaf).unwrap_or_else(|e| panic!("remove the leaf {}: {e}", leaf.display()));
}

/// Async twin of the sync `cgroup_an_unplaceable_front_is_refused_before_its_fork`.
#[skuld::test]
async fn cgroup_an_unplaceable_front_is_refused_before_its_fork(#[fixture(cgroup)] _group: &Group) {
    use crate::child::front_cgroup_tests::{assert_refused_unforked, spawn_front_noting_fork};
    let _missing = crate::containment::cgroup::fault::miss_pidfd_info();
    let _hidden = crate::containment::cgroup::fault::hide_proc();
    let _failing = crate::containment::cgroup::fault::fail_kill_writes();
    let mut cmd = crate::command::Command::new();
    cmd.args(["cat"])
        .contain_with(ContainMode::Strongest)
        .kill_on_drop(true);
    cmd.stdin(Stdio::pipe_in()).expect("stdin pipe");
    let (result, forked) = spawn_front_noting_fork(cmd, |cmd| crate::tokio::spawn::spawn(cmd).map(drop));
    assert_refused_unforked(result, forked);
}

/// A tokio spawn failing after its fork (`fail_tokio_spawns_after_fork_then`, running `hook` with
/// the front's pid) of a contained `cat` front whose stdin is a pipe the test holds in `stdin`:
/// tokio's `Child`, whose streams the failure leaks, holds none of it. Returns the error and the
/// front's pid, after checking the leaf's abandonment signalled no child of its own.
fn fail_a_contained_front_spawn(
    stdin: std::io::PipeReader,
    hook: impl FnOnce(u32) + 'static,
) -> (crate::error::Error, u32) {
    use crate::child::spawn::fault;
    let mut cmd = crate::command::Command::new();
    cmd.args(["cat"]).contain_with(ContainMode::Strongest);
    cmd.stdin(Stdio::from_file(std::fs::File::from(OwnedFd::from(stdin))))
        .expect("stdin");
    cmd.set_elevation_front(crate::elevation::front::front(Some(&SUDO)));
    let err = {
        let _failing = fault::fail_tokio_spawns_after_fork_then(hook);
        crate::tokio::spawn::spawn(&mut cmd)
            .map(drop)
            .expect_err("the forced failure fails the spawn")
    };
    let pid = fault::take_forgotten_pid().expect("the seam forked a child");
    assert_eq!(
        crate::containment::cgroup::fault::take_reaped_orphans(),
        [],
        "the abandonment signals no front"
    );
    (err, pid)
}

/// `err` keeps its `Io` variant and notes, once, the front's `fate`.
#[track_caller]
fn assert_front_noted(err: &crate::error::Error, fate: &str) {
    let crate::error::Error::Io(io) = err else {
        panic!("the spawn's error keeps its variant: {err:?}");
    };
    assert_eq!(io.raw_os_error(), None, "noted, with the original as its source: {io}");
    let text = err.to_string();
    assert_eq!(text.matches("the spawned child is what sudo left").count(), 1, "{text}");
    assert!(text.contains(fate), "{text}");
}

/// A contained front tokio drops after its fork is left by the handshake to its leaf, whose kill
/// ends it; the abandonment then waits for it on its pidfd and reaps it, and the error says so. The
/// abandonment is made to see the front still running, as it can once the leaf has drained.
#[skuld::test]
async fn cgroup_a_contained_front_tokio_drops_is_killed_through_its_leaf_and_reaped(#[fixture(cgroup)] _group: &Group) {
    use crate::child::front_kill_tests::reap;
    let _running = crate::child::spawn::fault::see_fronts_running();
    let (reader, writer) = std::io::pipe().expect("pipe");
    let (err, pid) = fail_a_contained_front_spawn(reader, |_| {});
    assert_front_noted(&err, "its cgroup's kill ended it, and it was reaped");
    drop(writer);
    assert_eq!(reap(pid), None, "the abandonment reaps the front");
}

/// A contained front moved out of its leaf before the abandonment is outside the leaf's kill: it is
/// sent nothing, not waited for, and left unreaped, and the error says so. A wait on it would
/// release its `cat` (the hook before the abandonment's wait closes its stdin), so a mutant that
/// waits fails on the note instead of hanging.
#[skuld::test]
async fn cgroup_a_contained_front_moved_out_of_its_leaf_is_left_running(#[fixture(cgroup)] _group: &Group) {
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::child::front_kill_tests::reap;
    let (reader, writer) = std::io::pipe().expect("pipe");
    let writer = Rc::new(RefCell::new(Some(writer)));
    let _released = crate::containment::cgroup::fault::set_before_exit_wait({
        let writer = Rc::clone(&writer);
        move || drop(writer.borrow_mut().take())
    });
    let (err, pid) = fail_a_contained_front_spawn(reader, move_out_of_its_leaf);
    assert_front_noted(&err, "the elevated program may be running; it is left unreaped");
    assert!(
        writer.borrow().is_some(),
        "the abandonment waited on a front outside its leaf"
    );
    drop(writer.borrow_mut().take());
    let status = reap(pid).expect("the front was left unreaped");
    assert!(status.success(), "the front was signalled: {status:?}");
}

/// A contained front that exited outside its leaf before the abandonment is reaped, though no kill
/// reached it.
#[skuld::test]
async fn cgroup_a_contained_front_that_exited_outside_its_leaf_is_reaped(#[fixture(cgroup)] _group: &Group) {
    use crate::child::front_kill_tests::reap;
    let (reader, writer) = std::io::pipe().expect("pipe");
    let (err, pid) = fail_a_contained_front_spawn(reader, move |pid| {
        move_out_of_its_leaf(pid);
        drop(writer);
        crate::test_child::wait_until_zombie(pid);
    });
    assert_front_noted(&err, "it had exited, or its cgroup's kill ended it, and it was reaped");
    assert_eq!(reap(pid), None, "the abandonment reaps the exited front");
}

/// A contained front in a leaf whose kill fails is still in its leaf, but nothing reached it: it is
/// sent nothing, not waited for, and left unreaped, and the error says so. As above, a wait on it
/// would release its `cat`. The leaf, left behind with the front in it, is removed once the front
/// has ended.
#[skuld::test]
async fn cgroup_a_contained_front_its_leaf_could_not_kill_is_left_running(#[fixture(cgroup)] _group: &Group) {
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::child::front_kill_tests::reap;
    let (reader, writer) = std::io::pipe().expect("pipe");
    let writer = Rc::new(RefCell::new(Some(writer)));
    let _released = crate::containment::cgroup::fault::set_before_exit_wait({
        let writer = Rc::clone(&writer);
        move || drop(writer.borrow_mut().take())
    });
    let leaf = Rc::new(RefCell::new(None));
    let (err, pid) = {
        let _failing = crate::containment::cgroup::fault::fail_kill_writes();
        fail_a_contained_front_spawn(reader, {
            let leaf = Rc::clone(&leaf);
            move |pid| {
                let own = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).expect("read the front's cgroup");
                let path = own
                    .lines()
                    .find_map(|line| line.strip_prefix("0::"))
                    .expect("a cgroup v2 `0::` line");
                *leaf.borrow_mut() = Some(format!("/sys/fs/cgroup{path}"));
            }
        })
    };
    assert_front_noted(&err, "the elevated program may be running; it is left unreaped");
    assert!(
        writer.borrow().is_some(),
        "the abandonment waited on a front no kill reached"
    );
    drop(writer.borrow_mut().take());
    let status = reap(pid).expect("the front was left unreaped");
    assert!(status.success(), "the front was signalled: {status:?}");
    let leaf = leaf.borrow_mut().take().expect("the hook read the front's leaf");
    std::fs::remove_dir(&leaf).unwrap_or_else(|e| panic!("remove the leaf left behind, {leaf}: {e}"));
}

/// Async twin of the sync `cgroup_a_front_its_leaf_did_not_take_is_left_by_a_failed_identity_check`.
#[skuld::test]
async fn cgroup_a_front_its_leaf_did_not_take_is_left_by_a_failed_identity_check(#[fixture(cgroup)] _group: &Group) {
    let (mut cmd, stdin) = front_its_leaf_did_not_take();
    let (err, pid) = fail_the_identity_check(&mut cmd, |cmd| crate::tokio::spawn::spawn(cmd).map(drop));
    assert_left_unsignalled(&err, pid, stdin);
}

/// A front whose leaf did not take it, dropped by tokio after its fork, is sent nothing, by the
/// handshake or the leaf, and left unreaped, and the error says so. The failure comes from the
/// `fail_tokio_spawns_after_fork` seam.
#[skuld::test]
async fn cgroup_a_front_its_leaf_did_not_take_is_left_when_tokio_drops_it(#[fixture(cgroup)] _group: &Group) {
    use crate::child::front_kill_tests::assert_reaped_unsignalled;
    use crate::child::spawn::fault;
    let (mut cmd, stdin) = front_its_leaf_did_not_take();
    let err = {
        let _failing = fault::fail_tokio_spawns_after_fork();
        crate::tokio::spawn::spawn(&mut cmd)
            .map(drop)
            .expect_err("the forced failure fails the spawn")
    };
    let pid = fault::take_forgotten_pid().expect("the seam forked a child");
    let crate::error::Error::Io(io) = &err else {
        panic!("the spawn's error keeps its variant: {err:?}");
    };
    assert_eq!(io.raw_os_error(), None, "noted, with the original as its source: {io}");
    let text = err.to_string();
    assert!(text.contains("the spawned child is what sudo left"), "{text}");
    assert!(
        text.contains("the elevated program may be running; it is left unreaped"),
        "{text}"
    );
    drop(stdin);
    assert_reaped_unsignalled(pid);
}

/// Spawns a contained `cat` front whose stdin is a pipe the caller holds in `stdin`, through tokio,
/// with its spawn failing after its fork, and the child killing itself at `at` (if any) and its
/// own handle opens refused when `no_handle`. Returns the error and the child's pid.
fn fail_a_contained_front_spawn_where(
    stdin: std::io::PipeReader,
    at: Option<crate::containment::cgroup::fault::ChildDeath>,
    no_handle: bool,
) -> (crate::error::Error, u32) {
    use crate::child::spawn::fault;
    use crate::containment::cgroup::fault as leaf_fault;
    let mut cmd = crate::command::Command::new();
    cmd.args(["cat"]).contain_with(ContainMode::Strongest);
    cmd.stdin(Stdio::from_file(std::fs::File::from(OwnedFd::from(stdin))))
        .expect("stdin");
    cmd.set_elevation_front(crate::elevation::front::front(Some(&SUDO)));
    let _dies = at.map(leaf_fault::kill_child_at);
    if no_handle {
        leaf_fault::set_force_child_pidfd_failure(true);
        leaf_fault::set_force_child_proc_dir_failure(true);
    }
    let err = {
        let _failing = fault::fail_tokio_spawns_after_fork();
        crate::tokio::spawn::spawn(&mut cmd)
            .map(drop)
            .expect_err("the forced failure fails the spawn")
    };
    // The forked child took the flags; this thread's own copies are cleared here.
    leaf_fault::take_force_child_pidfd_failure();
    leaf_fault::take_force_child_proc_dir_failure();
    let pid = fault::take_forgotten_pid().expect("the seam forked a child");
    (err, pid)
}

/// A contained front whose intent named it by no handle (both its `pidfd_open` and its `/proc` open
/// refused, as `EMFILE` does) is still waited for and reaped once its leaf's kill ends it: through
/// the pidfd its handshake left.
#[skuld::test]
async fn cgroup_a_contained_front_its_intent_named_by_no_handle_is_reaped_through_the_handshake(
    #[fixture(cgroup)] _group: &Group,
) {
    use crate::child::front_kill_tests::reap;
    let (reader, writer) = std::io::pipe().expect("pipe");
    let (err, pid) = fail_a_contained_front_spawn_where(reader, None, true);
    let text = err.to_string();
    assert!(text.contains("its cgroup's kill ended it, and it was reaped"), "{text}");
    drop(writer);
    assert_eq!(reap(pid), None, "the abandonment reaps the front");
}

/// A child that died before naming itself to its leaf never ran the program: it is no front, gets
/// no note, and is reaped through the pidfd its handshake left.
#[skuld::test]
async fn cgroup_a_child_dead_before_its_intent_is_reaped_through_the_handshake(#[fixture(cgroup)] _group: &Group) {
    use crate::child::front_kill_tests::reap;
    use crate::containment::cgroup::fault::ChildDeath;
    let (reader, _writer) = std::io::pipe().expect("pipe");
    let (err, pid) = fail_a_contained_front_spawn_where(reader, Some(ChildDeath::BeforeIntent), false);
    let text = err.to_string();
    assert!(!text.contains("what sudo left"), "no front, no note: {text}");
    assert_eq!(reap(pid), None, "the abandonment reaps the child");
}

/// A child that named itself and died before its report never ran the program: it is no front, gets
/// no note, and is reaped as any child.
#[skuld::test]
async fn cgroup_a_child_dead_before_its_report_is_no_front(#[fixture(cgroup)] _group: &Group) {
    use crate::child::front_kill_tests::reap;
    use crate::containment::cgroup::fault::ChildDeath;
    let (reader, _writer) = std::io::pipe().expect("pipe");
    let (err, pid) = fail_a_contained_front_spawn_where(reader, Some(ChildDeath::BeforeReport), false);
    let text = err.to_string();
    assert!(!text.contains("what sudo left"), "no front, no note: {text}");
    assert_eq!(reap(pid), None, "the abandonment reaps the child");
}

/// A `sh` front that ignores `SIGTERM` and then execs `cat`, contained and reported as launched by
/// `sudo`, once it says `ready`: the escalation of a graceful shutdown runs against it.
async fn spawn_term_ignoring_front() -> (Child, ChildStdin) {
    use ::tokio::io::AsyncReadExt as _;
    let mut cmd = Command::new();
    cmd.args(["sh", "-c", "trap '' TERM; echo ready; exec cat"]);
    cmd.stdout(Stdio::pipe()).expect("stdout pipe");
    let (mut child, stdin) = spawn_as(in_cgroup(cmd), SUDO);
    let mut ready = [0u8; 6];
    child
        .stdout()
        .expect("stdout pipe")
        .read_exact(&mut ready)
        .await
        .expect("read `ready`");
    (child, stdin)
}

/// Async twin of the sync `cgroup_graceful_shutdown_of_a_front_escalates_through_the_cgroup`.
#[skuld::test]
async fn cgroup_graceful_shutdown_of_a_front_escalates_through_the_cgroup(#[fixture(cgroup)] _group: &Group) {
    let (mut child, _stdin) = spawn_term_ignoring_front().await;
    let status = child
        .graceful_shutdown(std::time::Duration::ZERO)
        .await
        .expect("the cgroup kill ends the front");
    assert!(child.tree_killed.is_set(), "the escalation must go through the cgroup");
    assert_eq!(status.signal(), Some(libc::SIGKILL));
}

/// Async twin of the sync `cgroup_a_failed_escalation_of_a_front_is_unkillable`.
#[skuld::test]
async fn cgroup_a_failed_escalation_of_a_front_is_unkillable(#[fixture(cgroup)] _group: &Group) {
    use crate::graceful_hooks::{release_at, HookPoint};
    let (mut child, stdin) = spawn_term_ignoring_front().await;
    // Released at the wait that follows the escalation, which a swallowed failure would reach: the
    // front then ends by itself, and the refusal below fails, instead of the wait hanging.
    let release = release_at(HookPoint::BeforeReap, stdin);
    {
        let _failing = crate::containment::cgroup::fault::fail_kill_writes();
        crate::child::front_kill_tests::assert_refused_by(
            child.graceful_shutdown(std::time::Duration::ZERO).await,
            "its cgroup kill failed",
        );
    }
    // Closes the front's stdin: it ends unsignalled.
    drop(release);
    let status = child.wait().await.expect("wait");
    assert!(status.success(), "the front was signalled: {status:?}");
}

/// Async twin of the sync `cgroup_a_front_spawn_that_cannot_read_its_leaf_subtree_says_why`.
#[skuld::test]
async fn cgroup_a_front_spawn_that_cannot_read_its_leaf_subtree_says_why(#[fixture(cgroup)] _group: &Group) {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (child, stdin) = {
        let _failing = crate::containment::cgroup::fault::fail_subtree(libc::EIO);
        spawn_as(in_cgroup(cat()), SUDO)
    };
    let logs = crate::log_capture::records_since_on_current_thread(mark, "leaf subtree cannot be read");
    assert_eq!(logs.len(), 1, "{logs:?}");
    assert_eq!(logs[0].0, log::Level::Debug);
    assert!(logs[0].1.contains("Input/output error"), "{logs:?}");
    drop(stdin);
    drop(child);
}

/// A contained front tokio drops after its fork, whose leaf's subtree cannot be read once the
/// abandonment needs it, is left unreaped, and the error says it cannot be placed, naming the
/// cause: not that it is outside its leaf's reach. Mutant: "an unreadable subtree answers `Ok(false)`".
#[skuld::test]
async fn cgroup_a_contained_front_whose_leaf_subtree_cannot_be_read_is_left_naming_the_cause(
    #[fixture(cgroup)] _group: &Group,
) {
    use crate::child::front_kill_tests::reap;
    crate::log_capture::install();
    // The abandonment sees the front still running, as it can before the leaf's kill has ended it.
    let _running = crate::child::spawn::fault::see_fronts_running();
    let (reader, writer) = std::io::pipe().expect("pipe");
    let mark = crate::log_capture::mark();
    // The spawn captured its own subtree already: the failure is armed by the hook that runs as
    // the spawn fails, so only the abandonment's read fails.
    let failing = std::rc::Rc::new(std::cell::RefCell::new(None));
    let (err, pid) = fail_a_contained_front_spawn(reader, {
        let failing = std::rc::Rc::clone(&failing);
        move |_| *failing.borrow_mut() = Some(crate::containment::cgroup::fault::fail_subtree(libc::EIO))
    });
    drop(failing.borrow_mut().take());
    let warns = crate::log_capture::records_since_on_current_thread(mark, "cannot be placed");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].1.contains("its leaf's subtree cannot be read: "), "{warns:?}");
    assert_front_noted(&err, "the elevated program may be running; it is left unreaped");
    // Its leaf's kill, which does not need the subtree, ended it; the abandonment left it unreaped.
    drop(writer);
    let status = reap(pid).expect("the front was left unreaped");
    assert_eq!(status.signal(), Some(libc::SIGKILL), "{status:?}");
}
