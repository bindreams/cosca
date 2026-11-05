//! `Child::tear_down_or_hand_back`: the teardown of a helper that owns the child, and the child it
//! gives back when the kill is refused. A refused kill is scripted over a real child (`script_over`);
//! the real refusal is `command_tests`' (the setuid group).

use crate::child::owned::teardown::Disposition;
use crate::child::Child;
use crate::error::ChildFate;
use crate::identity::Liveness;
use crate::os_process::fake::FakeProcess;
use crate::test_child::{held_uncontained_blocker, tear_down_holding};

/// Make the next kill of `child` fail with `PermissionDenied`, as an elevated child's does.
fn refuse_the_kill(child: &mut Child) -> FakeProcess {
    child
        .proc
        .script_over(|f| f.signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]))
}

/// Every record at `warn` or above that this thread logged since `mark`.
fn warns_since(mark: usize) -> Vec<String> {
    crate::log_capture::records_since_on_current_thread(mark, "")
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .map(|(_, text)| text)
        .collect()
}

/// A child whose kill is refused and which still runs comes back as an `Unreaped` that names it,
/// and the one warn says so, in the words of a teardown after a failed run, not of a drop.
///
/// Mutants: the child is dropped instead; the fate or the identity is wrong; the warn says the
/// child is left running, or is prefixed with a private name or as a drop's.
#[skuld::test]
fn a_refused_kill_hands_the_child_back_and_says_so() {
    crate::log_capture::install();
    let (mut child, stdin) = held_uncontained_blocker(true);
    let id = child.id();
    refuse_the_kill(&mut child);
    let mark = crate::log_capture::mark();

    let (fate, handed_back) = tear_down_holding(child, stdin, Disposition::HandBack);

    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    assert_eq!(handed_back.unreaped().pid(), Some(id.pid()));
    assert_eq!(handed_back.unreaped().id(), Some(id));
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].starts_with("teardown after a failed run: ")
            && warns[0].contains(&id.pid().to_string())
            && warns[0].contains("handed back to the caller")
            && !warns[0].contains("leaving it running"),
        "{warns:?}"
    );
    handed_back.wait();
}

/// A caller that leaves a child whose kill is refused gets it left, warned, and no `Unreaped`.
///
/// Mutant: the teardown hands the child back whatever the caller said.
#[cfg(unix)]
#[skuld::test]
fn a_refused_kill_is_left_when_the_caller_leaves_it() {
    crate::log_capture::install();
    let (mut child, stdin) = held_uncontained_blocker(true);
    let id = child.id();
    refuse_the_kill(&mut child);
    let mark = crate::log_capture::mark();

    let (fate, handed_back) = tear_down_holding(child, stdin, Disposition::Leave);

    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    assert!(handed_back.is_none(), "the teardown handed the child back");
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].starts_with("teardown after a failed run: ") && warns[0].contains("leaving it running"),
        "{warns:?}"
    );
    drop(handed_back);
    crate::test_child::wait_until_zombie(id.pid());
}

/// A child that opted out of `kill_on_drop` is not torn down and not handed back: its `Unreaped`
/// would block on a child the caller chose to keep.
///
/// Mutant: an opted-out child is handed back.
#[skuld::test]
fn a_child_that_opted_out_is_not_handed_back() {
    let (child, stdin) = held_uncontained_blocker(false);
    let id = child.id();

    let (fate, handed_back) = tear_down_holding(child, stdin, Disposition::HandBack);

    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    assert!(handed_back.is_none(), "the teardown handed the child back");
    assert_eq!(id.is_alive(), Liveness::Alive, "nothing was sent to it");
}

/// A child that has exited was reaped by the look after the refused kill; there is nothing to give
/// back.
///
/// Mutant: a refused kill hands the child back without looking at it.
#[cfg(unix)]
#[skuld::test]
fn a_refused_kill_of_a_child_that_has_exited_hands_nothing_back() {
    let (mut child, stdin) = held_uncontained_blocker(true);
    drop(stdin);
    crate::test_child::wait_until_zombie(child.id().pid());
    refuse_the_kill(&mut child);

    let (fate, handed_back) = tear_down_holding(child, (), Disposition::HandBack);

    assert_eq!(fate, ChildFate::Reaped);
    assert!(handed_back.is_none(), "the teardown handed the child back");
}

/// A refused kill whose look then fails leaves the child's fate unknown, so nothing is handed back:
/// a handed-back child is one shown to run.
///
/// Mutant: any refused kill hands the child back.
#[cfg(unix)]
#[skuld::test]
fn a_refused_kill_with_a_failed_look_hands_nothing_back() {
    use crate::os_process::fake::ReapAnswer;

    let (mut child, stdin) = held_uncontained_blocker(true);
    child.proc.script_over(|f| {
        f.signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))])
            .reaps([ReapAnswer::Err(std::io::ErrorKind::Other)])
    });

    let (fate, handed_back) = tear_down_holding(child, stdin, Disposition::HandBack);

    assert_eq!(fate, ChildFate::Unknown);
    assert!(handed_back.is_none(), "the teardown handed the child back");
}

/// A child whose group is killed before its root kill is refused is handed back after that group
/// kill: handing back skips nothing of the teardown. The group kill is recorded and not sent, so the
/// root still runs for the hand-back.
///
/// Mutant: a child that is to be handed back skips the tree kill.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_handed_back_process_group_child_has_its_group_killed_first() {
    use crate::{ContainMode, Containment};

    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    let recorder = crate::containment::unix::fault::record_kill_group();
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(ContainMode::Session);
    let mut child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), Containment::Session);
    let id = child.id();
    refuse_the_kill(&mut child);

    let (fate, handed_back) = tear_down_holding(child, writer, Disposition::HandBack);

    recorder.assert_killed_only(id.pid() as i32);
    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    handed_back.unreaped();
    handed_back.wait();
}

/// A Job-contained child whose own kill is refused, and whose look then shows it exited, is reaped
/// and nothing is handed back. The look's answer is scripted on the fake: whether a real look
/// catches the child that `TerminateJobObject` is ending is a race, which this test does not pin.
///
/// Mutant: a refused kill hands the child back without looking at it.
#[cfg(windows)]
#[skuld::test]
fn a_job_contained_child_whose_kill_is_refused_and_look_shows_the_exit_is_not_handed_back() {
    use crate::os_process::child::ExitRecord;
    use crate::os_process::fake::ReapAnswer;

    let (mut child, stdin, _id) = crate::test_child::live_blocker();
    child.proc.script_over(|f| {
        f.signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))])
            .reaps([ReapAnswer::Reaped(ExitRecord::Status(Default::default()))])
    });

    let (fate, handed_back) = tear_down_holding(child, stdin, Disposition::HandBack);

    assert_eq!(fate, ChildFate::Reaped);
    assert!(handed_back.is_none());
}

/// An ordinary `cat` the test owns, reported as launched by `sudo`: a front, which is sent no kill,
/// and the write end of its stdin.
#[cfg(unix)]
fn a_running_front() -> (Child, std::io::PipeWriter) {
    use crate::elevation::{Backend, ElevatedVia};

    crate::log_capture::install();
    crate::child::front_kill_tests::spawn_as(
        crate::child::front_kill_tests::cat(),
        ElevatedVia::Wrapped(Backend::Sudo),
    )
}

/// What a teardown that hands a running elevation front back leaves: the front's `Running` fate and
/// identity in the `Unreaped`, nothing sent to it (it is `Alive` and waited for by nobody yet), the
/// one warn saying it is handed back, and then, once released, an exit of 0, which a kill would not
/// give.
#[cfg(unix)]
#[track_caller]
fn assert_front_handed_back(
    id: crate::identity::ProcessId,
    mark: usize,
    fate: ChildFate,
    handed_back: crate::test_child::HandedBack<std::io::PipeWriter>,
) {
    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    assert_eq!(handed_back.unreaped().pid(), Some(id.pid()));
    assert_eq!(handed_back.unreaped().id(), Some(id));
    assert_eq!(id.is_alive(), Liveness::Alive, "a front is sent nothing");
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].starts_with(&format!(
            "teardown after a failed run: elevation front pid {} is running and unreaped",
            id.pid()
        )) && warns[0].contains("handed back to the caller in the error")
            && !warns[0].contains("left running"),
        "{warns:?}"
    );
    assert!(handed_back.wait().success(), "a front is sent nothing");
}

/// An elevation front that is running is handed back, sent nothing.
///
/// Mutants: a front is left whatever the caller says; a front is killed; the warn says it is left.
#[cfg(unix)]
#[skuld::test]
fn an_elevation_front_left_running_is_handed_back() {
    let (child, stdin) = a_running_front();
    let id = child.id();
    let mark = crate::log_capture::mark();

    let (fate, handed_back) = tear_down_holding(child, stdin, Disposition::HandBack);

    assert_front_handed_back(id, mark, fate, handed_back);
}

/// A caller that leaves a front gets it left, warned, and no `Unreaped`.
///
/// Mutant: a front is handed back whatever the caller says.
#[cfg(unix)]
#[skuld::test]
fn an_elevation_front_is_left_when_the_caller_leaves_it() {
    let (child, stdin) = a_running_front();
    let id = child.id();
    let mark = crate::log_capture::mark();

    let (fate, handed_back) = tear_down_holding(child, stdin, Disposition::Leave);

    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    assert!(handed_back.is_none(), "the teardown handed the child back");
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].starts_with("teardown after a failed run: ") && warns[0].contains("is left running and unreaped"),
        "{warns:?}"
    );
    drop(handed_back);
    crate::test_child::wait_until_zombie(id.pid());
}

/// A front that has exited when the teardown runs is reaped by the look; there is nothing to give
/// back.
///
/// Mutant: a front is handed back without a look.
#[cfg(unix)]
#[skuld::test]
fn an_elevation_front_that_has_exited_is_reaped_not_handed_back() {
    let (child, stdin) = a_running_front();
    drop(stdin);
    crate::test_child::wait_until_zombie(child.id().pid());
    let mark = crate::log_capture::mark();

    let (fate, handed_back) = tear_down_holding(child, (), Disposition::HandBack);

    assert_eq!(fate, ChildFate::Reaped);
    assert!(handed_back.is_none(), "the teardown handed the child back");
    assert_eq!(warns_since(mark), Vec::<String>::new());
}

// In a cgroup (the `cgroup` group) =====

#[cfg(target_os = "linux")]
mod in_a_cgroup {
    use std::io::PipeWriter;
    use std::path::Path;

    use super::{refuse_the_kill, warns_since};
    use crate::child::front_cgroup_tests::{cgroup_dir_of, move_out_of_its_leaf};
    use crate::child::owned::teardown::Disposition;
    use crate::child::Child;
    use crate::error::ChildFate;
    use crate::identity::Existence;
    use crate::test_child::tear_down_holding;
    use crate::test_groups::{cgroup, Group};
    use crate::{Command, ContainMode, Containment};

    /// A `cat` in a cgroup leaf, and the write end of its stdin.
    fn blocker_in_a_leaf() -> (Child, PipeWriter) {
        let (stdin, writer) = crate::test_child::held_writer_stdin();
        let mut cmd = Command::new();
        cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
        cmd.stdin(stdin).expect("set stdin");
        cmd.contain_with(ContainMode::Strongest);
        let child = cmd.spawn().expect("spawn");
        assert_eq!(child.containment(), Containment::CgroupV2);
        (child, writer)
    }

    /// A handed-back child does not keep its leaf: the call tears the leaf down before it returns,
    /// and the `Unreaped` is waited for later. The child sits outside the leaf, as a program that
    /// moved itself out does, so the leaf's `cgroup.kill` does not end it.
    ///
    /// Mutants: the leaf is held by the handed-back child; the call blocks on the root.
    #[skuld::test]
    fn a_handed_back_child_does_not_hold_up_its_leaf(#[fixture(cgroup)] _group: &Group) {
        let (mut child, stdin) = blocker_in_a_leaf();
        let pid = child.id().pid();
        let leaf = cgroup_dir_of(pid);
        move_out_of_its_leaf(pid);
        refuse_the_kill(&mut child);

        let (fate, handed_back) = tear_down_holding(child, stdin, Disposition::HandBack);

        assert!(matches!(fate, ChildFate::Running { .. }), "{fate:?}");
        handed_back.unreaped();
        assert!(!Path::new(&leaf).exists(), "the leaf {leaf} was removed by the call");
        handed_back.wait();
    }

    /// A root whose own kill is refused, and which the leaf's `cgroup.kill` ends, is waited for and
    /// reaped: that kill is asynchronous, so a look at the present moment races it. Nothing is
    /// handed back or warned of. The refusal is scripted over the real child in its real leaf.
    ///
    /// The race is not forced here: a child that had already exited before the look passes on the
    /// mutant too. The deterministic pin is `owned_tests/teardown.rs`'s
    /// `a_refused_kill_of_a_child_the_tree_kill_reached_is_waited_for_and_reaped`, on a fake.
    #[skuld::test]
    fn a_refused_kill_of_a_child_the_leaf_killed_is_reaped_not_handed_back(#[fixture(cgroup)] _group: &Group) {
        crate::log_capture::install();
        let (mut child, stdin) = blocker_in_a_leaf();
        let id = child.id();
        refuse_the_kill(&mut child);
        let mark = crate::log_capture::mark();

        let (fate, handed_back) = tear_down_holding(child, stdin, Disposition::HandBack);

        assert_eq!(fate, ChildFate::Reaped);
        assert!(handed_back.is_none(), "the teardown handed the child back");
        assert_eq!(id.exists(), Existence::Gone, "the root was reaped, not left a zombie");
        assert_eq!(warns_since(mark), Vec::<String>::new());
    }

    /// The same child dropped: its refused kill is not "leaving it running", and the root is reaped,
    /// not left a zombie behind the leaf's kill.
    #[skuld::test]
    fn dropping_a_child_whose_kill_is_refused_but_whose_leaf_killed_it_reaps_it(#[fixture(cgroup)] _group: &Group) {
        crate::log_capture::install();
        let (mut child, stdin) = blocker_in_a_leaf();
        let id = child.id();
        refuse_the_kill(&mut child);
        let mark = crate::log_capture::mark();

        drop(child);

        assert_eq!(id.exists(), Existence::Gone, "the root was reaped, not left a zombie");
        assert_eq!(warns_since(mark), Vec::<String>::new());
        drop(stdin);
    }

    /// A leaf whose `cgroup.kill` fails is given up and logged, and the call returns with the child
    /// handed back: the leaf's teardown does not wait for a drain the root may never allow.
    ///
    /// Mutant: the call waits for the leaf to drain.
    #[skuld::test]
    fn a_handed_back_child_whose_leaf_cannot_kill_returns_and_logs_the_leaf(#[fixture(cgroup)] _group: &Group) {
        crate::log_capture::install();
        let (mut child, stdin) = blocker_in_a_leaf();
        let leaf = cgroup_dir_of(child.id().pid());
        refuse_the_kill(&mut child);
        let mark = crate::log_capture::mark();

        let (fate, handed_back) = {
            let _failing = crate::containment::cgroup::fault::fail_kill_writes();
            tear_down_holding(child, stdin, Disposition::HandBack)
        };

        assert!(matches!(fate, ChildFate::Running { .. }), "{fate:?}");
        handed_back.unreaped();
        let warns = warns_since(mark);
        assert!(
            warns.iter().any(|w| w.contains(&leaf) && w.contains("was not removed")),
            "the leaf left behind is named: {warns:?}"
        );
        handed_back.wait();
        std::fs::remove_dir(&leaf).expect("remove the leaf the call gave up");
    }
}
