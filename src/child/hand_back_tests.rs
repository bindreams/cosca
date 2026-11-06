//! `Child::tear_down_or_hand_back`: the teardown of a helper that owns the child, and the child it
//! gives back when the kill is refused. A refused kill is scripted over a real child (`script_over`);
//! the real refusal is `command_tests`' (the setuid group).

use crate::child::owned::teardown::Disposition;
use crate::child::Child;
use crate::error::ChildFate;
use crate::identity::Liveness;
use crate::log_capture::warns_since;
use crate::os_process::fake::FakeProcess;
#[cfg(target_os = "linux")]
use crate::test_child::Console;
use crate::test_child::{held_uncontained_blocker, tear_down_holding};

/// Make the next kill of `child` fail with `PermissionDenied`, as an elevated child's does.
fn refuse_the_kill(child: &mut Child) -> FakeProcess {
    child
        .proc
        .script_over(|f| f.signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))]))
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
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    refuse_the_kill(&mut child);
    let mark = crate::log_capture::mark();

    let (fate, handed_back) = tear_down_holding(child, stdin, Disposition::HandBack);

    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    assert_eq!(handed_back.unreaped().pid(), Some(id.pid()));
    assert_eq!(handed_back.unreaped().id(), Some(id));
    let warns = warns_since(mark, "");
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
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    refuse_the_kill(&mut child);
    let mark = crate::log_capture::mark();

    let (fate, handed_back) = tear_down_holding(child, stdin, Disposition::Leave);

    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    assert!(handed_back.is_none(), "the teardown handed the child back");
    let warns = warns_since(mark, "");
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
    let id = child.id().expect(crate::test_child::IDENTITY_READ);

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
    crate::test_child::wait_until_zombie(child.pid());
    refuse_the_kill(&mut child);

    let (fate, handed_back) = tear_down_holding(child, (), Disposition::HandBack);

    assert_eq!(fate, ChildFate::Reaped);
    assert!(handed_back.is_none(), "the teardown handed the child back");
}

/// A refused kill whose look then fails leaves the child's fate unknown, and the child uncollected
/// and still the caller's: it is handed back, as a child known to run is.
///
/// Mutant: only a `Running` fate hands back.
#[cfg(unix)]
#[skuld::test]
fn a_refused_kill_with_a_failed_look_hands_the_child_back() {
    use crate::os_process::fake::ReapAnswer;

    let (mut child, stdin) = held_uncontained_blocker(true);
    child.proc.script_over(|f| {
        f.signals([Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))])
            .reaps([ReapAnswer::Err(std::io::ErrorKind::Other)])
    });

    let (fate, handed_back) = tear_down_holding(child, stdin, Disposition::HandBack);

    assert_eq!(fate, ChildFate::Unknown);
    handed_back.unreaped();
    handed_back.wait();
}

/// A kill that was delivered, and a wait for the child that then failed, leave the child `Killed`
/// and still a zombie of this process: it is handed back.
///
/// Mutant: only a `Running` fate hands back.
#[cfg(unix)]
#[skuld::test]
fn a_delivered_kill_whose_wait_failed_hands_the_child_back() {
    use crate::os_process::fake::ReapAnswer;
    use crate::signal::Sent;

    let (mut child, stdin) = held_uncontained_blocker(true);
    // The kill is scripted: the child exits when released, below.
    child.proc.script_over(|f| {
        f.signals([Ok(Sent::Delivered)])
            .reaps([ReapAnswer::Err(std::io::ErrorKind::Other)])
    });

    let (fate, handed_back) = tear_down_holding(child, stdin, Disposition::HandBack);

    assert_eq!(fate, ChildFate::Killed);
    handed_back.unreaped();
    handed_back.wait();
}

/// A child someone else reaped is not this process's to hand back, whether the kill was refused
/// (`Gone`) or delivered first (`Killed`).
///
/// Mutants: a `Killed` fate hands back; any fate but `Reaped` hands back.
#[cfg(unix)]
#[skuld::test]
fn a_child_reaped_elsewhere_is_not_handed_back() {
    use crate::os_process::child::Foreign;
    use crate::os_process::fake::ReapAnswer;
    use crate::signal::Sent;

    let refused = || Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    for (kill, fate) in [(refused(), ChildFate::Gone), (Ok(Sent::Delivered), ChildFate::Killed)] {
        let (mut child, stdin) = held_uncontained_blocker(true);
        child
            .proc
            .script_over(|f| f.signals([kill]).reaps([ReapAnswer::Foreign(Foreign::Gone)]));

        let (torn, handed_back) = tear_down_holding(child, stdin, Disposition::HandBack);

        assert_eq!(torn, fate);
        assert!(
            handed_back.is_none(),
            "the teardown handed back a child reaped elsewhere"
        );
    }
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
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(ContainMode::Session);
    let mut child = cmd.spawn().expect("spawn");
    assert_eq!(child.containment(), Containment::Session);
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
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

/// Asserts a running front was handed back unkilled, with one warn saying so.
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
    let warns = warns_since(mark, "");
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

/// Mutants: a front is left whatever the caller says; a front is killed; the warn says it is left.
#[cfg(unix)]
#[skuld::test]
fn a_running_elevation_front_is_handed_back() {
    let (child, stdin) = a_running_front();
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
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
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    let mark = crate::log_capture::mark();

    let (fate, handed_back) = tear_down_holding(child, stdin, Disposition::Leave);

    assert_eq!(fate, ChildFate::Running { id: Some(id) });
    assert!(handed_back.is_none(), "the teardown handed the child back");
    let warns = warns_since(mark, "");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].starts_with("teardown after a failed run: ") && warns[0].contains("is left running and unreaped"),
        "{warns:?}"
    );
    drop(handed_back);
    crate::test_child::wait_until_zombie(id.pid());
}

/// A front whose look fails is uncollected and still ours: it is handed back though its fate is
/// `Unknown`.
///
/// Mutant: only a `Running` fate hands back.
#[cfg(unix)]
#[skuld::test]
fn an_elevation_front_whose_look_failed_is_handed_back() {
    use crate::os_process::fake::ReapAnswer;

    let (mut child, stdin) = a_running_front();
    child
        .proc
        .script_over(|f| f.reaps([ReapAnswer::Err(std::io::ErrorKind::Other)]));

    let (fate, handed_back) = tear_down_holding(child, stdin, Disposition::HandBack);

    assert_eq!(fate, ChildFate::Unknown);
    handed_back.unreaped();
    handed_back.wait();
}

/// A front someone else reaped is not this process's to hand back, though its look found no exit.
///
/// Mutant: a front is handed back whatever its look found.
#[cfg(unix)]
#[skuld::test]
fn an_elevation_front_reaped_elsewhere_is_not_handed_back() {
    use crate::os_process::child::Foreign;
    use crate::os_process::fake::ReapAnswer;

    let (mut child, stdin) = a_running_front();
    child
        .proc
        .script_over(|f| f.reaps([ReapAnswer::Foreign(Foreign::Gone)]));

    let (fate, handed_back) = tear_down_holding(child, stdin, Disposition::HandBack);

    assert_eq!(fate, ChildFate::Gone);
    assert!(
        handed_back.is_none(),
        "the teardown handed back a front reaped elsewhere"
    );
}

/// A front that has exited when the teardown runs reads `Gate::Exited`, so it goes through the
/// `Kill` arm: the kill is a no-op for a zombie, and the wait after it reaps the front. No look
/// runs, and there is nothing to give back.
#[cfg(unix)]
#[skuld::test]
fn an_elevation_front_that_has_exited_is_reaped_not_handed_back() {
    let (child, stdin) = a_running_front();
    drop(stdin);
    crate::test_child::wait_until_zombie(child.pid());
    let mark = crate::log_capture::mark();

    let (fate, handed_back) = tear_down_holding(child, (), Disposition::HandBack);

    assert_eq!(fate, ChildFate::Reaped);
    assert!(handed_back.is_none(), "the teardown handed the child back");
    assert_eq!(warns_since(mark, ""), Vec::<String>::new());
}

// In a cgroup (the `cgroup` group) =====

#[cfg(target_os = "linux")]
mod in_a_cgroup {
    use std::io::PipeWriter;
    use std::path::Path;

    use super::{assert_front_handed_back, refuse_the_kill, warns_since};
    use crate::child::front_cgroup_tests::{cgroup_dir_of, in_cgroup, move_out_of_its_leaf, SUDO};
    use crate::child::front_kill_tests::{cat, spawn_as};
    use crate::child::owned::teardown::Disposition;
    use crate::child::Child;
    use crate::error::ChildFate;
    use crate::identity::Existence;
    use crate::os_process::fake::ReapAnswer;
    use crate::test_child::{tear_down_holding, Console};
    use crate::test_groups::{cgroup, Group};
    use crate::{ContainMode, Containment};

    /// A `cat` in a cgroup leaf, and the write end of its stdin.
    fn blocker_in_a_leaf() -> (Child, PipeWriter) {
        let (stdin, writer) = crate::test_child::held_writer_stdin();
        let mut cmd = crate::test_child::command(Console::Hidden);
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
    /// Mutants: the leaf is held by the handed-back child; the call blocks on the root (that one is
    /// caught by nextest's bound on this module, not by an assertion).
    #[skuld::test]
    fn a_handed_back_child_does_not_hold_up_its_leaf(#[fixture(cgroup)] _group: &Group) {
        let (mut child, stdin) = blocker_in_a_leaf();
        let pid = child.pid();
        let leaf = cgroup_dir_of(pid);
        move_out_of_its_leaf(pid);
        refuse_the_kill(&mut child);

        let (fate, handed_back) = tear_down_holding(child, stdin, Disposition::HandBack);

        assert!(matches!(fate, ChildFate::Running { .. }), "{fate:?}");
        handed_back.unreaped();
        assert!(!Path::new(&leaf).exists(), "the leaf {leaf} was removed by the call");
        handed_back.wait();
    }

    /// A front in a leaf that is outside it when the teardown looks at it was not ended by the leaf's
    /// kill: it is handed back, and the leaf is gone by the time the call returns.
    ///
    /// Mutant: the hand-back holds the leaf.
    #[skuld::test]
    fn a_front_outside_its_leaf_is_handed_back_after_its_leaf_is_gone(#[fixture(cgroup)] _group: &Group) {
        crate::log_capture::install();
        let (child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
        let id = child.id().expect(crate::test_child::IDENTITY_READ);
        let leaf = cgroup_dir_of(id.pid());
        move_out_of_its_leaf(id.pid());
        let mark = crate::log_capture::mark();

        let (fate, handed_back) = tear_down_holding(child, stdin, Disposition::HandBack);

        assert!(!Path::new(&leaf).exists(), "the leaf {leaf} was removed by the call");
        assert_front_handed_back(id, mark, fate, handed_back);
    }

    /// A front that leaves its leaf during the leaf's kill (the gate read `CgroupOnly`, and the kill
    /// did not reach it) is handed back the same way.
    ///
    /// Mutant: the `CgroupOnly` arm of the drop's teardown drops the caller's disposition.
    #[skuld::test]
    fn a_front_that_leaves_its_leaf_during_the_kill_is_handed_back(#[fixture(cgroup)] _group: &Group) {
        crate::log_capture::install();
        let (child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
        let id = child.id().expect(crate::test_child::IDENTITY_READ);
        let leaf = cgroup_dir_of(id.pid());
        let pid = id.pid();
        let _moving = crate::containment::cgroup::fault::set_before_kill_write(move || move_out_of_its_leaf(pid));
        let mark = crate::log_capture::mark();

        let (fate, handed_back) = tear_down_holding(child, stdin, Disposition::HandBack);

        assert!(!Path::new(&leaf).exists(), "the leaf {leaf} was removed by the call");
        assert_front_handed_back(id, mark, fate, handed_back);
    }

    /// A front whose place cannot be read is not known to have been reached by the leaf's kill: the
    /// look saw it running (scripted, as on a kernel before 6.19, where the leaf's kill ends it
    /// first), so it is handed back.
    ///
    /// Mutant: an unreadable place is `Unknown`, which hands nothing back.
    #[skuld::test]
    fn a_front_whose_place_cannot_be_read_is_handed_back(#[fixture(cgroup)] _group: &Group) {
        crate::log_capture::install();
        let (mut child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
        let id = child.id().expect(crate::test_child::IDENTITY_READ);
        child.proc.script_over(|fake| fake.reaps([ReapAnswer::Running]));
        let mark = crate::log_capture::mark();

        let (fate, handed_back) = {
            let _unreadable = crate::containment::cgroup::fault::fail_pidfd_info();
            tear_down_holding(child, stdin, Disposition::HandBack)
        };

        assert_eq!(fate, ChildFate::Running { id: Some(id) });
        assert_eq!(handed_back.unreaped().id(), Some(id));
        let warns = warns_since(mark, "");
        assert_eq!(warns.len(), 1, "{warns:?}");
        assert!(
            warns[0].starts_with(&format!(
                "teardown after a failed run: elevation front pid {} is running and unreaped",
                id.pid()
            )) && warns[0].contains("cannot be read")
                && warns[0].contains("handed back to the caller in the error"),
            "{warns:?}"
        );
        handed_back.wait();
    }

    /// The same for a front whose leaf's subtree cannot be read.
    ///
    /// Mutant: an unreadable subtree is `Unknown`, which hands nothing back.
    #[skuld::test]
    fn a_front_whose_subtree_cannot_be_read_is_handed_back(#[fixture(cgroup)] _group: &Group) {
        crate::log_capture::install();
        let (child, stdin) = spawn_as(in_cgroup(cat()), SUDO);
        let id = child.id().expect(crate::test_child::IDENTITY_READ);
        move_out_of_its_leaf(id.pid());
        let mark = crate::log_capture::mark();

        let (fate, handed_back) = {
            let _unreadable = crate::containment::cgroup::fault::fail_subtree(libc::EIO);
            tear_down_holding(child, stdin, Disposition::HandBack)
        };

        assert_front_handed_back(id, mark, fate, handed_back);
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
        let id = child.id().expect(crate::test_child::IDENTITY_READ);
        refuse_the_kill(&mut child);
        let mark = crate::log_capture::mark();

        let (fate, handed_back) = tear_down_holding(child, stdin, Disposition::HandBack);

        assert_eq!(fate, ChildFate::Reaped);
        assert!(handed_back.is_none(), "the teardown handed the child back");
        assert_eq!(id.exists(), Existence::Gone, "the root was reaped, not left a zombie");
        assert_eq!(warns_since(mark, ""), Vec::<String>::new());
    }

    /// The same child dropped: its refused kill is not "leaving it running", and the root is reaped,
    /// not left a zombie behind the leaf's kill.
    #[skuld::test]
    fn dropping_a_child_whose_kill_is_refused_but_whose_leaf_killed_it_reaps_it(#[fixture(cgroup)] _group: &Group) {
        crate::log_capture::install();
        let (mut child, stdin) = blocker_in_a_leaf();
        let id = child.id().expect(crate::test_child::IDENTITY_READ);
        refuse_the_kill(&mut child);
        let mark = crate::log_capture::mark();

        drop(child);

        assert_eq!(id.exists(), Existence::Gone, "the root was reaped, not left a zombie");
        assert_eq!(warns_since(mark, ""), Vec::<String>::new());
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
        let leaf = cgroup_dir_of(child.pid());
        refuse_the_kill(&mut child);
        let mark = crate::log_capture::mark();

        let (fate, handed_back) = {
            let _failing = crate::containment::cgroup::fault::fail_kill_writes();
            tear_down_holding(child, stdin, Disposition::HandBack)
        };

        assert!(matches!(fate, ChildFate::Running { .. }), "{fate:?}");
        handed_back.unreaped();
        let warns = warns_since(mark, "");
        assert!(
            warns.iter().any(|w| w.contains(&leaf) && w.contains("was not removed")),
            "the leaf left behind is named: {warns:?}"
        );
        handed_back.wait();
        std::fs::remove_dir(&leaf).expect("remove the leaf the call gave up");
    }
}
