//! Async twin of `child/spawn/identity_group_tests.rs`: a spawn that fails because its root's
//! identity cannot be read, for a session root that left a member in its process group.

use crate::child::group_exact_tests::Member;
use crate::child::spawn::identity_group_tests::{Container, Failure};
use crate::error::ChildFate;
use crate::send_log::{assert_group_signalled_first_through_the_pidfd, Capture, GroupStep, Route};
use crate::test_groups::{cgroup, pidfd_group_signal, Group};

/// The sync `failed_spawn`'s twin.
fn failed_spawn(failure: Failure, container: Container) -> (ChildFate, Vec<GroupStep>, Member) {
    crate::tokio::test_runtime::assert_current_thread();
    let (stdio, started, member) = Member::pipes();
    let armed = failure.arm(started);
    let (mode, placement) = container.arm();
    let capture = Capture::start();
    let spawned = {
        let mut cmd = crate::tokio::Command::new();
        cmd.args(failure.argv());
        cmd.contain_with(mode);
        cmd.stdin(stdio.stdin).expect("set stdin");
        cmd.stdout(stdio.stdout).expect("set stdout");
        cmd.stderr(stdio.stderr).expect("set stderr");
        cmd.spawn()
    };
    let steps = capture.group_steps();
    drop((armed, placement));
    let (_err, fate) = match spawned {
        Ok(child) => panic!("the spawn must fail at its identity read: {:?}", child.id()),
        Err(e) => crate::child::spawn::failure::expect_may_have_started_with(e),
    };
    (fate, steps, member)
}

/// 6.9+: the cleanup kills the root's group through its pidfd. Mutant: "a failed async spawn's
/// cleanup kills the root alone".
fn kills_the_group(failure: Failure, container: Container) {
    let (fate, steps, member) = failed_spawn(failure, container);
    assert_group_signalled_first_through_the_pidfd(&steps, libc::SIGKILL);
    member.assert_killed();
    if matches!(failure, Failure::ReapedElsewhere) {
        assert_eq!(fate, ChildFate::Gone, "the root was reaped before any kill");
    }
}

/// Below 6.9 the old behaviour holds: the kernel refuses the group's send through the pidfd,
/// nothing goes by the group's number, and its member lives on. Mutant: "a refused flag falls back
/// to the group's number".
fn below_6_9_sends_nothing_to_the_group(failure: Failure, container: Container) {
    let old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    let (_fate, steps, member) = failed_spawn(failure, container);
    drop(old_kernel);
    assert!(
        steps
            .iter()
            .all(|s| *s == GroupStep::Group(Route::Pidfd, libc::SIGKILL)),
        "nothing but the refused send through the pidfd: {steps:?}"
    );
    member.assert_survived();
}

#[skuld::test]
async fn an_async_spawn_whose_root_was_reaped_before_its_identity_read_kills_the_group_left_behind(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group(Failure::ReapedElsewhere, Container::Session);
}

#[skuld::test]
async fn an_async_spawn_whose_identity_read_was_refused_kills_its_roots_group(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group(Failure::Unreadable, Container::Session);
}

#[skuld::test]
async fn an_async_spawn_whose_root_was_reaped_before_its_identity_read_below_6_9_sends_nothing_to_the_group() {
    below_6_9_sends_nothing_to_the_group(Failure::ReapedElsewhere, Container::Session);
}

#[skuld::test]
async fn an_async_spawn_whose_identity_read_was_refused_below_6_9_sends_nothing_to_the_group() {
    below_6_9_sends_nothing_to_the_group(Failure::Unreadable, Container::Session);
}

#[skuld::test]
async fn cgroup_an_async_spawn_whose_leaf_did_not_take_its_root_reaped_before_its_identity_read_kills_the_group_left_behind(
    #[fixture(cgroup)] _cgroup: &Group,
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group(Failure::ReapedElsewhere, Container::LeafNotTaken);
}

#[skuld::test]
async fn cgroup_an_async_spawn_whose_leaf_did_not_take_its_root_and_whose_identity_read_was_refused_kills_its_roots_group(
    #[fixture(cgroup)] _cgroup: &Group,
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group(Failure::Unreadable, Container::LeafNotTaken);
}

#[skuld::test]
async fn cgroup_an_async_spawn_whose_leaf_did_not_take_its_root_reaped_before_its_identity_read_below_6_9_sends_nothing_to_the_group(
    #[fixture(cgroup)] _cgroup: &Group,
) {
    below_6_9_sends_nothing_to_the_group(Failure::ReapedElsewhere, Container::LeafNotTaken);
}

#[skuld::test]
async fn cgroup_an_async_spawn_whose_leaf_did_not_take_its_root_and_whose_identity_read_was_refused_below_6_9_sends_nothing_to_the_group(
    #[fixture(cgroup)] _cgroup: &Group,
) {
    below_6_9_sends_nothing_to_the_group(Failure::Unreadable, Container::LeafNotTaken);
}
