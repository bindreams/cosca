//! Async twin of `child/spawn/identity_group_tests.rs`: a spawn that fails because its root's
//! identity cannot be read, for a session root that left a member in its process group.

use crate::child::spawn::identity_group_tests::{left_running_note, Container, Failed, Failure};
use crate::error::ChildFate;
use crate::send_log::{assert_group_signalled_first_through_the_pidfd, Capture, GroupStep, Route};
use crate::test_child::member::{Member, RELEASE_FD};
use crate::test_groups::{cgroup, pidfd_group_signal, Group};

/// The sync `failed_spawn`'s twin.
fn failed_spawn(failure: Failure, container: Container) -> Failed {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (stdio, started, member) = Member::pipes();
    // Released between the cleanup's kill and wait: a missed kill fails `assert_killed`, not the wait.
    let release = member.release_root_when_a_teardown_waits();
    let reaps = crate::child::spawn::fault::record_teardown_reaps();
    let armed = failure.arm(started);
    let (mode, placement) = container.arm();
    let capture = Capture::start();
    let mark = crate::log_capture::mark();
    let spawned = {
        let mut cmd = crate::tokio::Command::new();
        cmd.args(failure.argv());
        cmd.contain_with(mode);
        cmd.stdin(stdio.stdin).expect("set stdin");
        cmd.stdout(stdio.stdout).expect("set stdout");
        cmd.stderr(stdio.stderr).expect("set stderr");
        cmd.fd(RELEASE_FD, stdio.release).expect("set the release fd");
        cmd.spawn()
    };
    let steps = capture.group_steps();
    let pid = armed.pid();
    drop((armed, placement, release));
    if matches!(failure, Failure::Unreadable) {
        reaps.assert_killed();
    }
    let (_err, fate) = match spawned {
        Ok(child) => panic!("the spawn must fail at its identity read: {:?}", child.id()),
        Err(e) => crate::child::spawn::failure::expect_may_have_started_with(e),
    };
    let left_running = crate::log_capture::levels_since(mark, &left_running_note(pid));
    Failed {
        fate,
        steps,
        member,
        left_running,
    }
}

/// 6.9+: the cleanup kills the root's group through its pidfd. Mutant: "the cleanup says members
/// may be left running although it killed the group".
fn kills_the_group(failure: Failure, container: Container) {
    let failed = failed_spawn(failure, container);
    assert_group_signalled_first_through_the_pidfd(&failed.steps, libc::SIGKILL);
    failed.member.assert_killed();
    assert!(
        failed.left_running.is_empty(),
        "the group was killed, so nothing is left running: {:?}",
        failed.left_running
    );
    if matches!(failure, Failure::ReapedElsewhere) {
        assert_eq!(failed.fate, ChildFate::Gone, "the root was reaped before any kill");
    }
}

/// Below 6.9 the old behaviour holds: the kernel refuses the group's send through the pidfd,
/// nothing goes by the group's number, and its member lives on, which the cleanup says in one
/// `warn` naming the root. Mutants: "a refused flag falls back to the group's number"; "the refusal
/// is only a `debug`".
fn below_6_9_sends_nothing_to_the_group(failure: Failure, container: Container) {
    let old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    let failed = failed_spawn(failure, container);
    drop(old_kernel);
    assert!(
        failed
            .steps
            .iter()
            .all(|s| *s == GroupStep::Group(Route::Pidfd, libc::SIGKILL)),
        "nothing but the refused send through the pidfd: {:?}",
        failed.steps
    );
    failed.member.assert_survived();
    assert_eq!(
        failed.left_running,
        [log::Level::Warn],
        "one warn says members of the root's group may be left running"
    );
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
