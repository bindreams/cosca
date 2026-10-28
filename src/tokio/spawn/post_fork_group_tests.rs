//! Linux: a tokio spawn that fails after its fork, for a root that left a member in the process
//! group that is its containment. On 6.9+ the cleanup kills the group through the root's pidfd
//! while it has a member, as the identity-failure cleanup does; below 6.9 it kills the root alone and
//! warns once that members of its group may be left running.

use crate::child::spawn::fault;
use crate::child::spawn::identity_group_tests::{Container, ROOT_LEAVING_A_MEMBER};
use crate::error::ChildFate;
use crate::send_log::{assert_group_signalled_first_through_the_pidfd, Capture, GroupStep, Route};
use crate::test_child::member::{await_started, Member, RELEASE_FD, ROOT_WITH_A_MEMBER};
use crate::test_groups::{cgroup, pidfd_group_signal, Group};

/// The root's state when the spawn fails: running with its member, exited by itself and
/// unreaped, or killed and reaped by another reaper in the process, with its member left in the
/// group.
#[derive(Debug, Clone, Copy)]
enum Root {
    Running,
    Exited,
    ReapedBehind,
}

impl Root {
    fn argv(self) -> [&'static str; 3] {
        match self {
            Root::Running | Root::ReapedBehind => ROOT_WITH_A_MEMBER,
            Root::Exited => ROOT_LEAVING_A_MEMBER,
        }
    }

    /// What the cleanup finds of the root: reaped by itself, or already reaped by someone else.
    fn fate(self) -> ChildFate {
        match self {
            Root::Running | Root::Exited => ChildFate::Reaped,
            Root::ReapedBehind => ChildFate::Gone,
        }
    }
}

/// What a failed spawn did, as the tests below read it.
struct Failed {
    fate: ChildFate,
    steps: Vec<GroupStep>,
    member: Member,
    pid: u32,
    /// The records, at `warn` or above, that say a process group's members are left running.
    group_warns: Vec<String>,
}

/// The start of the record that says the members of the dropped child's group may be left running.
/// The child's pid is unknown to the cleanup, as tokio returns none.
fn left_running_note() -> String {
    format!(
        "members of the process group of {} may be left running",
        crate::child::spawn::named(None)
    )
}

/// Spawns `root` contained by `mode`, failing tokio's spawn after its fork once the root's member
/// exists. `placement` guards a forced placement failure.
fn failed_spawn(root: Root, mode: crate::ContainMode, placement: impl Sized) -> Failed {
    failed_spawn_as(root, mode, placement, None)
}

/// [`failed_spawn`], with the root launched by `front`, if any.
fn failed_spawn_as(
    root: Root,
    mode: crate::ContainMode,
    placement: impl Sized,
    front: Option<crate::elevation::front::Front>,
) -> Failed {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (stdio, started, member) = Member::pipes();
    // Released between the cleanup's kill and wait: a missed kill fails the `SIGKILL` assertion, not
    // the wait.
    let release = member.release_root_when_a_teardown_waits();
    let reaps = fault::record_teardown_reaps();
    let fronted = front.is_some();
    let capture = Capture::start();
    let mark = crate::log_capture::mark();
    let spawned = {
        let _failing = fault::fail_tokio_spawns_after_fork_then(move |pid| {
            await_started(started);
            if matches!(root, Root::ReapedBehind) {
                // SAFETY: `pid` is this process's own unreaped child.
                unsafe { libc::kill(pid as i32, libc::SIGKILL) };
                crate::test_child::reaped_elsewhere::reap_behind(pid);
            }
        });
        let mut cmd = crate::tokio::Command::new();
        cmd.args(root.argv());
        cmd.contain_with(mode);
        cmd.set_elevation_front(front);
        cmd.stdin(stdio.stdin).expect("set stdin");
        cmd.stdout(stdio.stdout).expect("set stdout");
        cmd.stderr(stdio.stderr).expect("set stderr");
        cmd.fd(RELEASE_FD, stdio.release).expect("set the release fd");
        cmd.spawn()
    };
    let steps = capture.group_steps();
    drop(placement);
    drop(release);
    // A front is left running: nothing kills or reaps it.
    if matches!(root, Root::Running) && !fronted {
        reaps.assert_killed();
    }
    let pid = fault::take_forgotten_pid().expect("the seam forked a child");
    let (_err, fate) = match spawned {
        Ok(child) => panic!("the spawn must fail after its fork: {:?}", child.id()),
        Err(e) => crate::child::spawn::failure::expect_may_have_started_with(e),
    };
    let group_warns = crate::log_capture::records_since_on_current_thread(mark, "left running")
        .into_iter()
        .filter(|(level, text)| *level <= log::Level::Warn && text.contains("process group"))
        .map(|(_, text)| text)
        .collect();
    Failed {
        fate,
        steps,
        member,
        pid,
        group_warns,
    }
}

/// 6.9+: the cleanup kills the root's group through its pidfd, whoever reaped the root. Mutants: "a
/// tokio spawn's cleanup after a failed fork kills the root alone", and "the group is killed only
/// of a root nobody else reaped".
fn kills_the_group(root: Root, container: Container) {
    let (mode, placement) = container.arm();
    let failed = failed_spawn(root, mode, placement);
    assert_eq!(failed.fate, root.fate(), "{root:?}");
    assert_group_signalled_first_through_the_pidfd(&failed.steps, libc::SIGKILL);
    failed.member.assert_killed();
    assert_eq!(failed.group_warns, Vec::<String>::new(), "the group was killed");
}

/// Below 6.9 the kernel refuses the group's send through the pidfd, nothing goes by the group's
/// number, and its member lives on, which the cleanup says in one `warn`. Mutants: "a refused flag
/// falls back to the group's number"; "the refusal is only a `debug`".
fn below_6_9_sends_nothing_to_the_group(root: Root, container: Container) {
    let old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    let (mode, placement) = container.arm();
    let failed = failed_spawn(root, mode, placement);
    drop(old_kernel);
    let Failed {
        fate,
        steps,
        member,
        pid,
        group_warns,
    } = failed;
    assert_eq!(fate, root.fate(), "{root:?}");
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
    assert_eq!(
        group_warns.len(),
        1,
        "one warn says the members may be left running: {group_warns:?}"
    );
    // A root its leaf did not take is answered for by the leaf's abandonment, in its own words.
    let note = match container {
        Container::LeafNotTaken => format!("could not kill an abandoned spawn's child's process group {pid}"),
        Container::Session | Container::Leafless => left_running_note(),
    };
    assert!(group_warns[0].contains(&note), "{group_warns:?}");
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
async fn a_tokio_spawn_failing_after_its_fork_kills_the_group_its_foreign_reaped_root_left_a_member_in(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group(Root::ReapedBehind, Container::Session);
}

#[skuld::test]
async fn a_tokio_spawn_failing_after_its_fork_below_6_9_sends_nothing_to_its_running_roots_group() {
    below_6_9_sends_nothing_to_the_group(Root::Running, Container::Session);
}

#[skuld::test]
async fn a_tokio_spawn_failing_after_its_fork_below_6_9_sends_nothing_to_its_exited_roots_group() {
    below_6_9_sends_nothing_to_the_group(Root::Exited, Container::Session);
}

#[skuld::test]
async fn a_tokio_spawn_failing_after_its_fork_below_6_9_sends_nothing_to_its_foreign_reaped_roots_group() {
    below_6_9_sends_nothing_to_the_group(Root::ReapedBehind, Container::Session);
}

/// A tree walk's root leads no group of its own: no group is its containment, so none is sent
/// anything, whatever the kernel. Mutant: "the cleanup kills the group of any root".
#[skuld::test]
async fn a_tokio_spawn_failing_after_its_fork_under_a_tree_walk_sends_no_group_anything(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    let failed = failed_spawn(Root::Running, crate::ContainMode::TreeWalk, ());
    assert_eq!(failed.fate, ChildFate::Reaped, "killed and reaped through its pidfd");
    assert!(failed.steps.is_empty(), "no group is sent anything: {:?}", failed.steps);
    failed.member.assert_survived();
}

/// A child std collected, because its `exec` failed, never ran the program and left no group: the
/// group kill through its pidfd finds no member (`ESRCH`), and nothing goes by a number. Mutant: the
/// cleanup sends the group of a collected child by its number, or kills a group the child did not
/// lead.
#[skuld::test]
async fn a_tokio_exec_failure_kills_a_group_with_no_member_and_sends_nothing_by_number() {
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
    assert_eq!(
        steps,
        [GroupStep::Group(Route::Pidfd, libc::SIGKILL)],
        "one kill through the pidfd, answered with no member, and nothing by a number"
    );
}

/// The route `contain()` takes on a host without a delegated cgroup: `Strongest` with no leaf, whose
/// process group is the containment. Mutant: the leafless route treats only `Session` as a group
/// containment.
#[skuld::test]
async fn a_tokio_spawn_failing_after_its_fork_kills_the_group_its_leafless_strongest_root_left_a_member_in(
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    kills_the_group(Root::Running, Container::Leafless);
}

#[skuld::test]
async fn a_tokio_spawn_failing_after_its_fork_below_6_9_sends_nothing_to_its_leafless_strongest_roots_group() {
    below_6_9_sends_nothing_to_the_group(Root::Running, Container::Leafless);
}

/// A nested spawn (the marker is in the environment) leads no group of its own, so none is sent
/// anything, whatever the kernel. Runs in a process of its own, since the marker is process-wide.
/// Mutant: the cleanup kills the group of a nested root.
#[skuld::test]
async fn a_nested_tokio_spawn_failing_after_its_fork_sends_no_group_anything() {
    use crate::test_own_process::{own_process, test_path};
    use crate::test_spawn::spawn;

    let Some(_done) = own_process(
        test_path!(a_nested_tokio_spawn_failing_after_its_fork_sends_no_group_anything),
        spawn,
    ) else {
        return;
    };
    std::env::set_var(crate::containment::NESTED_ENV, "1");
    let failed = failed_spawn(Root::Running, crate::ContainMode::Session, ());
    assert_eq!(failed.fate, ChildFate::Reaped, "killed and reaped through its pidfd");
    assert!(failed.steps.is_empty(), "no group is sent anything: {:?}", failed.steps);
    failed.member.assert_survived();
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

/// Makes the next intent go with no handle on its child: both its `pidfd_open` and its `/proc/self`
/// open fail. Only the forked child takes the flags; the guard clears this thread's.
struct NoHandle;

impl NoHandle {
    fn arm() -> NoHandle {
        crate::containment::cgroup::fault::set_force_child_pidfd_failure(true);
        crate::containment::cgroup::fault::set_force_child_proc_dir_failure(true);
        NoHandle
    }
}

impl Drop for NoHandle {
    fn drop(&mut self) {
        crate::containment::cgroup::fault::take_force_child_pidfd_failure();
        crate::containment::cgroup::fault::take_force_child_proc_dir_failure();
    }
}

/// A root its leaf did not take, whose intent carried no handle on it, still has its group killed
/// by the leaf's abandonment, through the handshake's pidfd. Mutant: the leaf gets no pidfd for a
/// child that is not a front, so it cannot name the child and kills nothing.
#[skuld::test]
async fn cgroup_a_tokio_spawn_failing_after_its_fork_kills_the_group_of_a_root_its_leaf_did_not_take_and_cannot_name(
    #[fixture(cgroup)] _cgroup: &Group,
    #[fixture(pidfd_group_signal)] _group: &Group,
) {
    let no_handle = NoHandle::arm();
    let (mode, placement) = Container::LeafNotTaken.arm();
    let failed = failed_spawn(Root::Running, mode, (placement, no_handle));
    assert_eq!(failed.fate, ChildFate::Reaped);
    failed.member.assert_killed();
    assert_eq!(failed.group_warns, Vec::<String>::new(), "the group was killed");
}

/// A `sudo`/`doas`-style front is sent nothing: a kill of its group would orphan the elevated
/// program. So a spawn of one that fails after its fork sends the group no signal, though the group
/// is its containment and has a live member. Mutant: `killing_group` drops its front check.
#[skuld::test]
async fn a_tokio_spawn_of_a_front_failing_after_its_fork_sends_its_group_nothing() {
    use crate::elevation::{Backend, ElevatedVia};
    let front = crate::elevation::front::front(Some(&ElevatedVia::Wrapped(Backend::Sudo)));
    assert!(front.is_some(), "sudo launches a front");
    let failed = failed_spawn_as(Root::Running, crate::ContainMode::Session, (), front);
    let Failed {
        fate,
        steps,
        member,
        pid,
        ..
    } = failed;
    // Asserted before anything is sent to `pid`: a front torn down by mistake is reaped, and its
    // number may be reused.
    assert_eq!(fate, ChildFate::Running { id: None }, "the front is left running");
    assert!(steps.is_empty(), "the front's group is sent nothing: {steps:?}");
    // The front is left running and unreaped: what the test made is ended here.
    // SAFETY: `pid` is this process's own unreaped child.
    unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    crate::child::front_kill_tests::reap(pid).expect("the front is left unreaped");
    let said = member.end();
    assert!(said.contains("survived"), "the group's member was killed: {said:?}");
}

/// A group kill the kernel refuses for a reason other than the flag (`EPERM`, forced) is one `warn`
/// that names the refusal and says the members may be left running; the root is still reaped.
/// Mutant: the refusal is not noted, or is a `debug`.
#[skuld::test]
async fn a_tokio_spawn_failing_after_its_fork_whose_group_kill_is_refused_warns_once() {
    let refused = crate::containment::unix::fault::refuse_group_sends();
    let failed = failed_spawn(Root::Running, crate::ContainMode::Session, ());
    drop(refused);
    let Failed {
        fate,
        member,
        group_warns,
        ..
    } = failed;
    assert_eq!(
        fate,
        ChildFate::Reaped,
        "the root is killed and reaped through its pidfd"
    );
    member.assert_survived();
    assert_eq!(group_warns.len(), 1, "{group_warns:?}");
    let named = crate::child::spawn::named(None);
    assert!(
        group_warns[0].contains(&format!("could not kill the process group of {named}"))
            && group_warns[0].contains("may be left running"),
        "{group_warns:?}"
    );
}

/// A group kill the kernel refuses for a reason other than the flag (`EPERM`, forced), sent to a
/// child std collected because its exec failed: the `warn` says the child was reaped, so it may
/// never have run the program. Mutant: the non-`EINVAL` refusal drops that.
#[skuld::test]
async fn a_tokio_exec_failure_whose_group_kill_is_refused_warns_that_the_reaped_child_may_never_have_run() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let refused = crate::containment::unix::fault::refuse_group_sends();
    let mark = crate::log_capture::mark();
    let mut cmd = crate::tokio::Command::new();
    cmd.args(["cosca-no-such-program-142"]);
    cmd.contain_with(crate::ContainMode::Session);
    let (_err, fate) = crate::child::spawn::failure::expect_may_have_started_with(
        cmd.spawn().expect_err("a missing program fails the spawn"),
    );
    drop(refused);
    assert_eq!(fate, ChildFate::Gone, "std had collected the child whose exec failed");
    let warns: Vec<_> = crate::log_capture::records_since_on_current_thread(mark, "the process group of")
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .collect();
    assert_eq!(warns.len(), 1, "{warns:?}");
    let named = crate::child::spawn::named(None);
    assert!(
        warns[0]
            .1
            .contains(&format!("could not kill the process group of {named}")),
        "{warns:?}"
    );
    assert!(
        warns[0]
            .1
            .contains("already reaped, so it may never have run the program"),
        "{warns:?}"
    );
}

/// Below 6.9 the group kill sent to a child std collected, because its exec failed, is refused too.
/// The child never ran the program, which the `warn` says it may not have: the child was reaped, so
/// nothing shows otherwise. Mutants: the refusal is not warned about; the `warn` drops that the
/// child was reaped.
#[skuld::test]
async fn a_tokio_exec_failure_below_6_9_warns_that_the_reaped_child_may_never_have_run() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    let capture = Capture::start();
    let mark = crate::log_capture::mark();
    let mut cmd = crate::tokio::Command::new();
    cmd.args(["cosca-no-such-program-142"]);
    cmd.contain_with(crate::ContainMode::Session);
    let (_err, fate) = crate::child::spawn::failure::expect_may_have_started_with(
        cmd.spawn().expect_err("a missing program fails the spawn"),
    );
    drop(old_kernel);
    assert_eq!(fate, ChildFate::Gone, "std had collected the child whose exec failed");
    assert_eq!(capture.group_steps(), [GroupStep::Group(Route::Pidfd, libc::SIGKILL)]);
    let warns: Vec<_> = crate::log_capture::records_since_on_current_thread(mark, "the process group of")
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .collect();
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(warns[0].1.contains(&left_running_note()), "{warns:?}");
    assert!(
        warns[0]
            .1
            .contains("already reaped, so it may never have run the program"),
        "{warns:?}"
    );
}
