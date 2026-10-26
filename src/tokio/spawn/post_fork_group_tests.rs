//! Linux: a tokio spawn that fails after its fork, for a root that left a member in the process
//! group that is its containment. On 6.9+ the cleanup kills the group through the root's pidfd
//! while it has a member, as the identity-failure cleanup does; below 6.9 it kills the root alone.

use crate::child::group_exact_tests::{await_started, Member, ROOT_WITH_A_MEMBER};
use crate::child::spawn::fault;
use crate::child::spawn::identity_group_tests::{Container, ROOT_LEAVING_A_MEMBER};
use crate::error::ChildFate;
use crate::send_log::{assert_group_signalled_first_through_the_pidfd, Capture, GroupStep, Route};
use crate::test_groups::{cgroup, pidfd_group_signal, Group};

/// The root's state when the spawn fails: running with its member, or exited by itself and
/// unreaped, with its member left in the group.
#[derive(Debug, Clone, Copy)]
enum Root {
    Running,
    Exited,
}

impl Root {
    fn argv(self) -> [&'static str; 3] {
        match self {
            Root::Running => ROOT_WITH_A_MEMBER,
            Root::Exited => ROOT_LEAVING_A_MEMBER,
        }
    }
}

/// Spawns `root` contained by `mode`, failing tokio's spawn after its fork once the root's member
/// exists: the failure's fate, the group steps recorded, and the member. `placement` guards a
/// forced placement failure.
fn failed_spawn(root: Root, mode: crate::ContainMode, placement: impl Sized) -> (ChildFate, Vec<GroupStep>, Member) {
    crate::tokio::test_runtime::assert_current_thread();
    let (stdio, started, member) = Member::pipes();
    let capture = Capture::start();
    let spawned = {
        let _failing = fault::fail_tokio_spawns_after_fork_then(move |_| await_started(started));
        let mut cmd = crate::tokio::Command::new();
        cmd.args(root.argv());
        cmd.contain_with(mode);
        cmd.stdin(stdio.stdin).expect("set stdin");
        cmd.stdout(stdio.stdout).expect("set stdout");
        cmd.stderr(stdio.stderr).expect("set stderr");
        cmd.spawn()
    };
    let steps = capture.group_steps();
    drop(placement);
    fault::take_forgotten_pid().expect("the seam forked a child");
    let (_err, fate) = match spawned {
        Ok(child) => panic!("the spawn must fail after its fork: {:?}", child.id()),
        Err(e) => crate::child::spawn::failure::expect_may_have_started_with(e),
    };
    (fate, steps, member)
}

/// 6.9+: the cleanup kills the root's group through its pidfd. Mutant: "a tokio spawn's cleanup
/// after a failed fork kills the root alone".
fn kills_the_group(root: Root, container: Container) {
    let (mode, placement) = container.arm();
    let (fate, steps, member) = failed_spawn(root, mode, placement);
    assert_eq!(fate, ChildFate::Reaped, "killed and reaped through its pidfd");
    assert_group_signalled_first_through_the_pidfd(&steps, libc::SIGKILL);
    member.assert_killed();
}

/// Below 6.9 the old behaviour holds: the kernel refuses the group's send through the pidfd,
/// nothing goes by the group's number, and its member lives on. Mutant: "a refused flag falls back
/// to the group's number".
fn below_6_9_sends_nothing_to_the_group(root: Root, container: Container) {
    let old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    let (mode, placement) = container.arm();
    let (fate, steps, member) = failed_spawn(root, mode, placement);
    drop(old_kernel);
    assert_eq!(fate, ChildFate::Reaped, "killed and reaped through its pidfd");
    assert_eq!(
        steps.first(),
        Some(&GroupStep::Group(Route::Pidfd, libc::SIGKILL)),
        "the group is sent the kill through the pidfd first: {steps:?}"
    );
    assert!(
        !steps.iter().any(|s| matches!(
            s,
            GroupStep::Group(Route::Number, _)
                | GroupStep::Leader(Route::Number, _)
                | GroupStep::Member(Route::Number, ..)
        )),
        "nothing goes by a number: {steps:?}"
    );
    member.assert_survived();
}

#[skuld::test]
async fn a_tokio_spawn_failing_after_its_fork_kills_the_group_its_running_root_left_a_member_in(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group(Root::Running, Container::Session);
}

#[skuld::test]
async fn a_tokio_spawn_failing_after_its_fork_kills_the_group_its_exited_root_left_a_member_in(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group(Root::Exited, Container::Session);
}

#[skuld::test]
async fn a_tokio_spawn_failing_after_its_fork_below_6_9_sends_nothing_to_its_running_roots_group() {
    below_6_9_sends_nothing_to_the_group(Root::Running, Container::Session);
}

#[skuld::test]
async fn a_tokio_spawn_failing_after_its_fork_below_6_9_sends_nothing_to_its_exited_roots_group() {
    below_6_9_sends_nothing_to_the_group(Root::Exited, Container::Session);
}

/// A tree walk's root leads no group of its own: no group is its containment, so none is sent
/// anything, whatever the kernel. Mutant: "the cleanup kills the group of any root".
#[skuld::test]
async fn a_tokio_spawn_failing_after_its_fork_under_a_tree_walk_sends_no_group_anything(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    let (fate, steps, member) = failed_spawn(Root::Running, crate::ContainMode::TreeWalk, ());
    assert_eq!(fate, ChildFate::Reaped, "killed and reaped through its pidfd");
    assert!(steps.is_empty(), "no group is sent anything: {steps:?}");
    member.assert_survived();
}

/// A child std collected, because its `exec` failed, never ran the program and left no group to kill.
/// Mutant: the cleanup sends the group of a collected child the kill.
#[skuld::test]
async fn a_tokio_exec_failure_sends_no_group_anything() {
    crate::tokio::test_runtime::assert_current_thread();
    let capture = Capture::start();
    let mut cmd = crate::tokio::Command::new();
    cmd.args(["cosca-no-such-program-142"]);
    cmd.contain_with(crate::ContainMode::Session);
    let (_err, fate) = crate::child::spawn::failure::expect_may_have_started_with(
        cmd.spawn().expect_err("a missing program fails the spawn"),
    );
    assert_eq!(fate, ChildFate::Gone, "std had collected the child whose exec failed");
    let steps = capture.group_steps();
    assert!(steps.is_empty(), "no group is sent anything: {steps:?}");
}

#[skuld::test]
async fn cgroup_a_tokio_spawn_failing_after_its_fork_kills_the_group_of_a_root_its_leaf_did_not_take(
    #[fixture(cgroup)] _cgroup: &Group,
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group(Root::Running, Container::LeafNotTaken);
}

#[skuld::test]
async fn cgroup_a_tokio_spawn_failing_after_its_fork_below_6_9_sends_nothing_to_the_group_of_a_root_its_leaf_did_not_take(
    #[fixture(cgroup)] _cgroup: &Group,
) {
    below_6_9_sends_nothing_to_the_group(Root::Running, Container::LeafNotTaken);
}
