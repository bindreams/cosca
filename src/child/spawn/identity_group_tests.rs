//! Linux: a spawn that fails because its root's identity cannot be read, for a root that left a
//! member in the process group that is its containment: a session, or the group a cgroup leaf that
//! did not take the root falls back to. On 6.9+ the cleanup kills the group through the root's pidfd
//! while it has a member, whoever reaped the root; below 6.9 it kills the root alone.

use crate::child::group_exact_tests::{await_started, Member, ROOT_WITH_A_MEMBER};
use crate::child::spawn::failure::expect_may_have_started_with;
use crate::child::spawn::fault;
use crate::error::ChildFate;
use crate::send_log::{assert_group_signalled_first_through_the_pidfd, Capture, GroupStep, Route};
use crate::test_child::reaped_elsewhere::reap_behind;
use crate::test_groups::{cgroup, pidfd_group_signal, Group};

/// A session root `sh` that leaves a member in its group, says `started` and exits, as
/// `sh -c 'sleep 300 & exit'` does. Its member is [`ROOT_WITH_A_MEMBER`]'s.
pub(crate) const ROOT_LEAVING_A_MEMBER: [&str; 3] = [
    "sh",
    "-c",
    "exec 3<&0; (cat <&3 3<&- >/dev/null; echo survived >&2) & echo started",
];

/// Why the spawn's identity read fails.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Failure {
    /// The root exits by itself and another reaper in the process reaps it first: `Gone`.
    ReapedElsewhere,
    /// The read is refused while the root runs: `Unknown`.
    Unreadable,
}

impl Failure {
    /// The root's argv for this failure.
    pub(crate) fn argv(self) -> [&'static str; 3] {
        match self {
            Failure::ReapedElsewhere => ROOT_LEAVING_A_MEMBER,
            Failure::Unreadable => ROOT_WITH_A_MEMBER,
        }
    }

    /// Arms the spawn's `BeforeIdentity` hook: it waits for the member, then brings this failure
    /// about. Dropping the guard disarms both.
    pub(crate) fn arm(self, started: std::io::PipeReader) -> Armed {
        let hook = fault::set_at(fault::SpawnPoint::BeforeIdentity, move || {
            await_started(started);
            if matches!(self, Failure::ReapedElsewhere) {
                reap_behind(fault::spawn_pid());
            }
        });
        fault::set_force_identity_unknown(matches!(self, Failure::Unreadable));
        Armed { _hook: hook }
    }
}

/// [`Failure::arm`]'s guard.
pub(crate) struct Armed {
    _hook: crate::oneshot_hook::Armed,
}

impl Drop for Armed {
    fn drop(&mut self) {
        fault::set_force_identity_unknown(false);
    }
}

/// The root's containment, whose process group the root leads.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Container {
    Session,
    /// A cgroup leaf whose placement write is made to fail, so the process group set before the
    /// spawn is the containment.
    LeafNotTaken,
    /// `Strongest` with no cgroup leaf made (what a host without a delegated cgroup gives), so the
    /// process group set before the spawn is the containment.
    Leafless,
}

impl Container {
    /// The mode to contain the root with, and a guard that ends a forced placement failure.
    pub(crate) fn arm(self) -> (crate::ContainMode, PlacementForced) {
        match self {
            Container::Session => (crate::ContainMode::Session, PlacementForced),
            Container::LeafNotTaken => {
                crate::containment::cgroup::fault::set_force_placement_write_result(0);
                (crate::ContainMode::Strongest, PlacementForced)
            }
            Container::Leafless => {
                crate::containment::cgroup::fault::set_force_leaf_open_failure(true);
                (crate::ContainMode::Strongest, PlacementForced)
            }
        }
    }
}

/// Clears this thread's forced placement result, which only the forked child takes, and a forced
/// leaf failure the spawn did not reach.
pub(crate) struct PlacementForced;

impl Drop for PlacementForced {
    fn drop(&mut self) {
        crate::containment::cgroup::fault::take_force_placement_write_result();
        crate::containment::cgroup::fault::take_force_leaf_open_failure();
    }
}

/// Spawns `failure`'s root in `container`, which fails at the identity read: the failure's fate,
/// the group steps it recorded and the root's member.
fn failed_spawn(failure: Failure, container: Container) -> (ChildFate, Vec<GroupStep>, Member) {
    let (stdio, started, member) = Member::pipes();
    let armed = failure.arm(started);
    let (mode, placement) = container.arm();
    let capture = Capture::start();
    let spawned = {
        let mut cmd = crate::Command::new();
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
        Err(e) => expect_may_have_started_with(e),
    };
    (fate, steps, member)
}

/// 6.9+: the cleanup kills the root's group through its pidfd. Mutant: "a failed spawn's cleanup
/// kills the root alone".
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
fn a_spawn_whose_root_was_reaped_before_its_identity_read_kills_the_group_left_behind(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group(Failure::ReapedElsewhere, Container::Session);
}

#[skuld::test]
fn a_spawn_whose_identity_read_was_refused_kills_its_roots_group(#[fixture(pidfd_group_signal)] _group: &Group) {
    kills_the_group(Failure::Unreadable, Container::Session);
}

#[skuld::test]
fn a_spawn_whose_root_was_reaped_before_its_identity_read_below_6_9_sends_nothing_to_the_group() {
    below_6_9_sends_nothing_to_the_group(Failure::ReapedElsewhere, Container::Session);
}

#[skuld::test]
fn a_spawn_whose_identity_read_was_refused_below_6_9_sends_nothing_to_the_group() {
    below_6_9_sends_nothing_to_the_group(Failure::Unreadable, Container::Session);
}

#[skuld::test]
fn cgroup_a_spawn_whose_leaf_did_not_take_its_root_reaped_before_its_identity_read_kills_the_group_left_behind(
    #[fixture(cgroup)] _cgroup: &Group,
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group(Failure::ReapedElsewhere, Container::LeafNotTaken);
}

#[skuld::test]
fn cgroup_a_spawn_whose_leaf_did_not_take_its_root_and_whose_identity_read_was_refused_kills_its_roots_group(
    #[fixture(cgroup)] _cgroup: &Group,
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group(Failure::Unreadable, Container::LeafNotTaken);
}

#[skuld::test]
fn cgroup_a_spawn_whose_leaf_did_not_take_its_root_reaped_before_its_identity_read_below_6_9_sends_nothing_to_the_group(
    #[fixture(cgroup)] _cgroup: &Group,
) {
    below_6_9_sends_nothing_to_the_group(Failure::ReapedElsewhere, Container::LeafNotTaken);
}

#[skuld::test]
fn cgroup_a_spawn_whose_leaf_did_not_take_its_root_and_whose_identity_read_was_refused_below_6_9_sends_nothing_to_the_group(
    #[fixture(cgroup)] _cgroup: &Group,
) {
    below_6_9_sends_nothing_to_the_group(Failure::Unreadable, Container::LeafNotTaken);
}
