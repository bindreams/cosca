//! Async twins of `child/front_cgroup_tests.rs`: a front in a Linux cgroup, on the cgroup lane (the
//! `cgroup` group, as root). A front its leaf holds acts as any child does; one its leaf did not take is
//! gated as any uncontained front.

use std::os::unix::process::ExitStatusExt as _;
use std::time::Duration;

use super::front_kill_tests::{cat, spawn_as};
use crate::child::front_cgroup_tests::{
    assert_failed_closed, assert_left_unsignalled, contained_cat, fail_closed_and_refuse_the_identity,
    fail_the_identity_check, front_its_leaf_did_not_take,
};
use crate::elevation::{Backend, ElevatedVia};
use crate::test_groups::{cgroup, Group};
use crate::tokio::child::{drop_fault, Child};
use crate::tokio::{ChildStdin, Command};
use crate::{ContainMode, Containment, Stdio};

const SUDO: ElevatedVia = ElevatedVia::Wrapped(Backend::Sudo);

/// A `sudo` front its cgroup leaf holds, with its stdin.
fn spawn_contained_front(mut cmd: Command) -> (Child, ChildStdin) {
    cmd.contain_with(ContainMode::Strongest);
    let (child, stdin) = spawn_as(cmd, SUDO);
    assert_eq!(child.containment(), Containment::CgroupV2);
    (child, stdin)
}

#[skuld::test]
async fn cgroup_kill_of_a_contained_front_signals_it_as_any_child(#[fixture(cgroup)] _group: &Group) {
    let (mut child, _stdin) = spawn_contained_front(cat());
    child.kill().expect("a contained front is killed as any child");
    assert_eq!(child.wait().await.expect("wait").signal(), Some(libc::SIGKILL));
}

#[skuld::test]
async fn cgroup_kill_tree_of_a_contained_front_signals_it_as_any_child(#[fixture(cgroup)] _group: &Group) {
    let (mut child, _stdin) = spawn_contained_front(cat());
    child
        .kill_tree()
        .expect("a contained front's tree is killed as any child's");
    assert_eq!(child.wait().await.expect("wait").signal(), Some(libc::SIGKILL));
}

/// The drop kills a contained front's root, as any child's is.
#[skuld::test]
async fn cgroup_drop_of_a_contained_front_kills_it_as_any_child(#[fixture(cgroup)] _group: &Group) {
    crate::tokio::test_runtime::assert_current_thread();
    let roots = drop_fault::record();
    let (child, _stdin) = spawn_contained_front(cat());
    drop(child);
    assert_eq!(roots.kills(), 1, "the drop kills a contained front");
}

#[skuld::test]
async fn cgroup_graceful_shutdown_of_a_contained_front_escalates_as_any_child(#[fixture(cgroup)] _group: &Group) {
    use tokio::io::AsyncReadExt as _;
    let mut cmd = Command::new();
    cmd.args(["sh", "-c", "trap '' TERM; echo ready; exec cat"]);
    cmd.stdout(Stdio::pipe()).expect("stdout pipe");
    let (mut child, _stdin) = spawn_contained_front(cmd);
    let mut ready = [0u8; 6];
    child
        .stdout()
        .expect("stdout pipe")
        .read_exact(&mut ready)
        .await
        .expect("read `ready`");
    let status = child
        .graceful_shutdown(Duration::ZERO)
        .await
        .expect("the escalation kills a contained front");
    assert_eq!(status.signal(), Some(libc::SIGKILL));
}

/// Async twin of the sync `cgroup_a_failed_spawn_tears_a_contained_front_down_as_any_child`.
#[skuld::test]
async fn cgroup_a_failed_spawn_tears_a_contained_front_down_as_any_child(#[fixture(cgroup)] _group: &Group) {
    use crate::child::front_kill_tests::{failed_front_spawns, reap};
    for (err, pid) in failed_front_spawns(Some(ContainMode::Strongest), |cmd| {
        crate::tokio::spawn::spawn(cmd).map(drop)
    }) {
        assert!(!err.to_string().contains("what sudo left"), "no note: {err}");
        assert_eq!(reap(pid), None, "the teardown reaps it");
    }
}

/// Async twin of the sync `cgroup_a_front_its_leaf_did_not_take_is_left_by_a_failed_identity_check`.
#[skuld::test]
async fn cgroup_a_front_its_leaf_did_not_take_is_left_by_a_failed_identity_check(#[fixture(cgroup)] _group: &Group) {
    let (mut cmd, stdin) = front_its_leaf_did_not_take();
    let (err, pid) = fail_the_identity_check(&mut cmd, |cmd| crate::tokio::spawn::spawn(cmd).map(drop));
    assert_left_unsignalled(&err, pid, stdin);
}

/// Async twin of the sync `cgroup_a_failed_closed_verdict_is_kept_when_the_identity_check_fails`.
#[skuld::test]
async fn cgroup_a_failed_closed_verdict_is_kept_when_the_identity_check_fails(#[fixture(cgroup)] _group: &Group) {
    for front in [true, false] {
        let (mut cmd, _stdin) = contained_cat(front);
        let (err, pid) = fail_closed_and_refuse_the_identity(&mut cmd, |cmd| crate::tokio::spawn::spawn(cmd).map(drop));
        assert_failed_closed(&err, pid);
    }
}
