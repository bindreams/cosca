//! Linux: a spawn that fails because its root's identity cannot be read, for a root that left a
//! member in the process group that is its containment: a session, or the group a cgroup leaf that
//! did not take the root falls back to. On 6.9+ the cleanup kills the group through the root's pidfd
//! while it has a member, whoever reaped the root; below 6.9 it kills the root alone and warns once that
//! members of its group may be left running.

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
        let pid = std::rc::Rc::new(std::cell::Cell::new(0));
        let hook = fault::set_at(fault::SpawnPoint::BeforeIdentity, {
            let pid = std::rc::Rc::clone(&pid);
            move || {
                pid.set(fault::spawn_pid());
                await_started(started);
                if matches!(self, Failure::ReapedElsewhere) {
                    reap_behind(fault::spawn_pid());
                }
            }
        });
        fault::set_force_identity_unknown(matches!(self, Failure::Unreadable));
        Armed { _hook: hook, pid }
    }
}

/// [`Failure::arm`]'s guard.
pub(crate) struct Armed {
    _hook: crate::oneshot_hook::Armed,
    pid: std::rc::Rc<std::cell::Cell<u32>>,
}

impl Armed {
    /// The pid of the root the spawn forked; set once the hook has run.
    pub(crate) fn pid(&self) -> u32 {
        let pid = self.pid.get();
        assert_ne!(pid, 0, "the spawn's hook has run");
        pid
    }
}

/// The record the cleanup owes when it cannot kill the group of `pid`: one `warn` that names it.
pub(crate) fn left_running_note(pid: u32) -> String {
    format!("members of the process group of pid {pid} may be left running")
}

/// What a failed spawn did, as the tests below read it.
pub(crate) struct Failed {
    pub(crate) fate: ChildFate,
    pub(crate) steps: Vec<GroupStep>,
    pub(crate) member: Member,
    /// The levels of the records that say members of the root's group may be left running.
    pub(crate) left_running: Vec<log::Level>,
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
        }
    }
}

/// Clears this thread's forced placement result, which only the forked child takes.
pub(crate) struct PlacementForced;

impl Drop for PlacementForced {
    fn drop(&mut self) {
        crate::containment::cgroup::fault::take_force_placement_write_result();
    }
}

/// Spawns `failure`'s root in `container`, which fails at the identity read: the failure's fate,
/// the group steps it recorded and the root's member.
fn failed_spawn(failure: Failure, container: Container) -> Failed {
    crate::log_capture::install();
    let (stdio, started, member) = Member::pipes();
    let armed = failure.arm(started);
    let (mode, placement) = container.arm();
    let capture = Capture::start();
    let mark = crate::log_capture::mark();
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
    let pid = armed.pid();
    drop((armed, placement));
    let (_err, fate) = match spawned {
        Ok(child) => panic!("the spawn must fail at its identity read: {:?}", child.id()),
        Err(e) => expect_may_have_started_with(e),
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
