//! `Child::tear_down_or_hand_back`: the teardown of a helper that owns the child, and the child it
//! gives back when the kill is refused. A refused kill is scripted over a real child (`script_over`);
//! the real refusal is `command_tests`' (the setuid group).

use crate::child::Child;
use crate::error::ChildFate;
use crate::identity::Liveness;
use crate::os_process::fake::FakeProcess;
use crate::test_child::held_uncontained_blocker;

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
/// and the one warn says so, and does not claim a drop.
///
/// Mutants: the child is dropped instead; the fate or the identity is wrong; the warn says the
/// child is left running, or is prefixed as a drop's.
#[skuld::test]
fn a_refused_kill_hands_the_child_back_and_says_so() {
    crate::log_capture::install();
    let (mut child, stdin) = held_uncontained_blocker(true);
    let id = child.id();
    refuse_the_kill(&mut child);
    let mark = crate::log_capture::mark();

    let (fate, unreaped) = child.tear_down_or_hand_back();

    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    let unreaped = unreaped.expect("a child whose kill was refused is handed back");
    assert_eq!(unreaped.pid(), Some(id.pid()));
    assert_eq!(unreaped.id(), Some(id));
    let warns = warns_since(mark);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains(&id.pid().to_string())
            && warns[0].contains("handed back to the caller")
            && !warns[0].contains("leaving it running")
            && !warns[0].contains("Child::drop"),
        "{warns:?}"
    );
    drop(stdin);
    unreaped
        .wait()
        .expect("the handed-back child exits once its stdin closes");
}

/// A child that opted out of `kill_on_drop` is not torn down and not handed back: its `Unreaped`
/// would block on a child the caller chose to keep.
///
/// Mutant: an opted-out child is handed back.
#[skuld::test]
fn a_child_that_opted_out_is_not_handed_back() {
    let (child, stdin) = held_uncontained_blocker(false);
    let id = child.id();

    let (fate, unreaped) = child.tear_down_or_hand_back();

    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    assert!(unreaped.is_none(), "{unreaped:?}");
    assert_eq!(id.is_alive(), Liveness::Alive, "nothing was sent to it");
    drop(stdin);
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

    let (fate, unreaped) = child.tear_down_or_hand_back();

    assert_eq!(fate, ChildFate::Reaped);
    assert!(unreaped.is_none(), "{unreaped:?}");
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

    let (fate, unreaped) = child.tear_down_or_hand_back();

    assert_eq!(fate, ChildFate::Unknown);
    assert!(unreaped.is_none(), "{unreaped:?}");
    drop(stdin);
}

/// An elevation front that is left running is not handed back (fronts are the next change), and is
/// sent nothing.
///
/// Mutant: a front is handed back, or killed.
#[cfg(unix)]
#[skuld::test]
fn an_elevation_front_left_running_is_not_handed_back() {
    use crate::child::front_kill_tests::{cat, spawn_as};
    use crate::elevation::{Backend, ElevatedVia};

    let (child, stdin) = spawn_as(cat(), ElevatedVia::Wrapped(Backend::Sudo));
    let id = child.id();

    let (fate, unreaped) = child.tear_down_or_hand_back();

    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    assert!(unreaped.is_none(), "{unreaped:?}");
    assert_eq!(id.is_alive(), Liveness::Alive, "a front is sent nothing");
    drop(stdin);
    crate::test_child::wait_until_zombie(id.pid());
}

// In a cgroup (the `cgroup` group) =====

#[cfg(target_os = "linux")]
mod in_a_cgroup {
    use std::io::PipeWriter;
    use std::path::Path;

    use super::{refuse_the_kill, warns_since};
    use crate::child::front_cgroup_tests::{cgroup_dir_of, move_out_of_its_leaf};
    use crate::child::Child;
    use crate::error::ChildFate;
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

        let (fate, unreaped) = child.tear_down_or_hand_back();

        assert!(matches!(fate, ChildFate::Running { .. }), "{fate:?}");
        let unreaped = unreaped.expect("handed back");
        assert!(!Path::new(&leaf).exists(), "the leaf {leaf} was removed by the call");
        drop(stdin);
        unreaped
            .wait()
            .expect("the handed-back child exits once its stdin closes");
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

        let (fate, unreaped) = {
            let _failing = crate::containment::cgroup::fault::fail_kill_writes();
            child.tear_down_or_hand_back()
        };

        assert!(matches!(fate, ChildFate::Running { .. }), "{fate:?}");
        let unreaped = unreaped.expect("handed back");
        let warns = warns_since(mark);
        assert!(
            warns.iter().any(|w| w.contains(&leaf) && w.contains("was not removed")),
            "the leaf left behind is named: {warns:?}"
        );
        drop(stdin);
        unreaped
            .wait()
            .expect("the handed-back child exits once its stdin closes");
        std::fs::remove_dir(&leaf).expect("remove the leaf the call gave up");
    }
}
