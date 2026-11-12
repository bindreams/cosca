//! The wait over a tree kill: its members re-opened by identity, the root through its owner's handle,
//! and nothing waited for by a call that only sends. Every row drives a `Child` over a mechanism and a
//! root of stated answers, with live held children as the members the mechanism states it reached; a
//! member's exit is ended by the wait's own blocking call, so no row depends on timing.

use std::cell::Cell;
use std::rc::Rc;

use crate::containment::dispatch::{SweepFailure, Swept, TreeKillOutcome};
use crate::containment::fake::FakeContains;
use crate::containment::tree_kill::exit_unobserved;
use crate::containment::{Containment, KillWait, Mechanism, Tree, TreeKill};
use crate::error::Error;
use crate::identity::{Liveness, ProcessId};
use crate::os_process::fake::{Answer, FakeProcess};
use crate::signal::Sent;
use crate::test_child::over_fake::child_over;
use crate::test_child::{held_uncontained_blocker, IDENTITY_READ};
use crate::Child;

/// A root of stated answers: its kill is delivered, and its looks answer `exits`.
fn root_looking(exits: impl IntoIterator<Item = Answer>) -> FakeProcess {
    let root = FakeProcess::new(exits).signals([Ok(Sent::Delivered)]);
    #[cfg(target_os = "macos")]
    let root = root.peeks_always(|| Ok(crate::os_process::child::PeekOutcome::Running));
    root
}

/// A child over `root` whose mechanism states that its kill reached `members`.
fn child_reaching(root: &FakeProcess, members: &[ProcessId]) -> Child {
    let (fake, _) = FakeContains::new(Containment::Session, false);
    let mut child = child_over(root);
    child.tree = Tree::contained(Mechanism::Fake(fake.reaching(members.iter().copied())));
    child
}

/// A live held member and the write end of its stdin, which ends it.
fn live_member() -> (Child, crate::PipeWriter, ProcessId) {
    let (member, writer) = held_uncontained_blocker(false);
    let id = member.id().expect(IDENTITY_READ);
    (member, writer, id)
}

/// `kill_tree` returns once every member its kill reached has exited. The member is alive when the
/// wait looks at it, so the wait blocks on it, and the test ends it there: a `kill_tree` that
/// returns without waiting never blocks, and the member is not ended.
///
/// Mutant: `Child::kill_tree` takes the answer and drops the wait.
#[skuld::test]
fn a_kill_tree_waits_for_each_member_its_kill_reached() {
    let (member, writer, id) = live_member();
    let root = root_looking([Answer::Exited]);
    let child = child_reaching(&root, &[id]);

    let writer = Cell::new(Some(writer));
    let ended = Rc::new(Cell::new(false));
    let _blocking = crate::wait::block_probe::on_blocking({
        let ended = ended.clone();
        move || {
            drop(writer.take());
            ended.set(true);
        }
    });
    child.kill_tree().expect("every member exited");

    assert!(
        ended.get(),
        "kill_tree returned without blocking on a member that was running"
    );
    assert_eq!(
        id.is_alive(),
        Liveness::Dead,
        "the member has exited when kill_tree returns"
    );
    _ = member.wait();
}

/// A call that only sends does not look at a member or at the root, and returns while the member it
/// reached runs: the root states no look, so one would panic.
///
/// Mutant: `send_kill_tree` waits.
#[skuld::test]
fn a_send_only_kill_tree_waits_for_nothing() {
    let (member, writer, id) = live_member();
    let root = root_looking([]);
    let child = child_reaching(&root, &[id]);

    // A call that waited would block on the member, and this ends it there, so a mutant fails by
    // assertion instead of hanging.
    let writer = Rc::new(Cell::new(Some(writer)));
    let blocked = Rc::new(Cell::new(false));
    let _blocking = crate::wait::block_probe::on_blocking({
        let (writer, blocked) = (writer.clone(), blocked.clone());
        move || {
            blocked.set(true);
            drop(writer.take());
        }
    });
    child.send_kill_tree().expect("the kill was sent");

    assert!(!blocked.get(), "the call waited for a member");
    assert_eq!(
        id.is_alive(),
        Liveness::Alive,
        "the fake killed nothing, and the member runs"
    );
    assert_eq!(root.looks(), 0, "the call looked at the root");
    drop(writer.take());
    _ = member.wait();
}

/// The root is waited for, through its owner's handle, once its kill landed.
///
/// Mutant: the root is not waited for; it is waited for when its kill was refused.
#[skuld::test]
fn a_kill_tree_waits_for_the_root_once_its_kill_landed() {
    let root = root_looking([Answer::Running, Answer::Exited]);
    let child = child_reaching(&root, &[]);

    let woken = root.clone();
    let _blocking = crate::wait::block_probe::on_blocking(move || woken.wake());
    child.kill_tree().expect("the root exited");

    assert_eq!(root.looks(), 2, "the wait looked at the root until it had exited");
}

/// A root whose kill was refused is not waited for: the call returns the refusal. The root states no
/// look, so one would panic.
///
/// Mutant: the root is waited for whether or not its kill landed.
#[skuld::test]
fn a_kill_tree_does_not_wait_for_a_root_whose_kill_was_refused() {
    let root = FakeProcess::new([]).signals([Err(std::io::Error::other("refused"))]);
    #[cfg(target_os = "macos")]
    let root = root.peeks_always(|| Ok(crate::os_process::child::PeekOutcome::Running));
    let child = child_reaching(&root, &[]);

    child.kill_tree().expect_err("the root's kill was refused");

    assert_eq!(root.looks(), 0, "the call waited for a root it could not kill");
}

/// A member whose exit cannot be observed does not end the wait early: the members after it are waited
/// for, and the error names it.
///
/// Mutant: the wait returns the first member's error without waiting for the rest.
#[skuld::test]
fn a_member_whose_exit_cannot_be_observed_is_named_once_the_rest_are_waited_for() {
    let (member, writer, id) = live_member();
    let why = exit_unobserved(
        4242,
        Error::Unassessable {
            detail: "refused".into(),
            source: None,
        },
    );
    let (_, wait) = TreeKill::of(TreeKillOutcome::Ran(Ok(())))
        .unobserved(why)
        .reaching([id])
        .split();

    let writer = Cell::new(Some(writer));
    let ended = Rc::new(Cell::new(false));
    let _blocking = crate::wait::block_probe::on_blocking({
        let ended = ended.clone();
        move || {
            drop(writer.take());
            ended.set(true);
        }
    });
    let err = wait.wait().expect_err("a member's exit cannot be observed");

    assert!(ended.get(), "the wait returned before it waited for the live member");
    assert!(
        err.to_string()
            .contains("pid 4242 was killed, but its exit cannot be observed"),
        "the error names the member: {err}"
    );
    _ = member.wait();
}

/// A member that is gone has exited: it is neither waited for nor an error.
///
/// Mutant: a member that cannot be opened is an error.
#[skuld::test]
fn a_member_that_is_gone_has_exited() {
    let (member, writer, id) = live_member();
    drop(writer);
    member.wait().expect("the member exits when its stdin closes");
    drop(member);

    let (_, wait) = TreeKill::of(TreeKillOutcome::Ran(Ok(()))).reaching([id]).split();
    wait.wait().expect("a member that is gone has exited");
}

/// A member whose open fails is not an exit: the wait goes on to the rest and names every member it could
/// not observe, and one reached twice is named once.
///
/// Mutant: a failed open counts as an exit; the wait stops at the first failure; a member reached twice
/// is waited for twice.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_failed_open_is_not_an_exit() {
    use crate::identity::{FakeKernel, HostKernel};

    let (first, first_writer, first_id) = live_member();
    let (second, second_writer, second_id) = live_member();
    let kernel = FakeKernel::over(&HostKernel)
        .on_pidfd_open(first_id.pid(), Err(rustix::io::Errno::MFILE))
        .on_pidfd_open(second_id.pid(), Err(rustix::io::Errno::MFILE));

    let (_, wait) = TreeKill::of(TreeKillOutcome::Ran(Ok(())))
        .through(&kernel)
        .reaching([first_id, second_id, first_id])
        .split();
    let err = wait.wait().expect_err("neither member can be opened");

    let said = crate::error::Report(&err).to_string();
    assert!(said.contains(&format!("pid {} was killed", first_id.pid())), "{said}");
    assert!(said.contains(&format!("pid {} was killed", second_id.pid())), "{said}");
    assert!(
        said.contains("the exit of 1 more"),
        "the first member is named once, the second as the one more: {said}"
    );
    drop((first_writer, second_writer));
    _ = (first.wait(), second.wait());
}

/// A wait that finds a member's exit unobservable is still the failure of a sweep whose backstop ended
/// the root: the failure keeps that record, for the caller that reaps the root before it returns the
/// error.
///
/// Mutant: a wait error is a failure that says nothing of the root.
#[skuld::test]
fn a_wait_error_keeps_the_record_that_the_root_was_killed() {
    let root = root_looking([Answer::Exited]);
    let why = exit_unobserved(
        4242,
        Error::Unassessable {
            detail: "refused".into(),
            source: None,
        },
    );
    let (_, wait) = TreeKill::of(TreeKillOutcome::Ran(Ok(()))).unobserved(why).split();

    let failure = Swept::new(Ok(()), wait.with_root(&root, true))
        .wait()
        .expect_err("a member's exit cannot be observed");

    assert!(failure.root_ended, "the root was killed, and its exit was waited for");
}

/// The root's state is the mechanism's record of its own kill, set by `root_killed` to what it is
/// told, either way, and a caller that gives the root's handle for a kill that did not land does not
/// overwrite it. A kill that landed is waited for through the handle.
///
/// Mutant: `with_root(.., false)` resets the state; or `root_killed(false)` leaves an earlier `true`.
#[skuld::test]
fn the_roots_state_is_set_by_root_killed_and_kept_by_with_root() {
    let root = root_looking([Answer::Exited]);
    let killed = |landed| TreeKill::of(TreeKillOutcome::Ran(Ok(()))).root_killed(landed).split().1;

    assert!(killed(true).root_killed(), "a walk that killed the root says so");
    assert!(!killed(false).root_killed(), "a walk that did not says so");
    assert!(
        !TreeKill::of(TreeKillOutcome::Ran(Ok(())))
            .root_killed(true)
            .root_killed(false)
            .split()
            .1
            .root_killed(),
        "the last answer is the state"
    );
    assert!(
        killed(true).with_root(&root, false).root_killed(),
        "a kill that did not land through the handle keeps what the walk recorded"
    );
    assert!(
        killed(true).with_root(&root, true).waits_for_root(),
        "a kill that landed is waited for through the handle"
    );
    assert!(
        !killed(false).with_root(&root, false).waits_for_root(),
        "a root whose kill did not land is not waited for"
    );
}

/// An edge that says members remain, from a wait with no deadline, has not drained the tree: the wait
/// is an error, where an edge that says all members exited is none.
///
/// Mutant: every verdict of the edge is a drain.
#[skuld::test]
fn an_edge_that_says_members_remain_makes_the_wait_an_error() {
    use crate::containment::TreeDrain;

    let (_, drained) = TreeKill::of(TreeKillOutcome::Ran(Ok(())))
        .until(|| Ok(TreeDrain::AllMembersExited))
        .split();
    drained.wait().expect("the edge says every member exited");

    let (_, remaining) = TreeKill::of(TreeKillOutcome::Ran(Ok(())))
        .until(|| Ok(TreeDrain::MembersRemain))
        .split();
    let err = remaining
        .wait()
        .expect_err("a deadline's verdict from a wait with none is no drain");
    assert!(err.to_string().contains("members remaining"), "{err}");
}

/// A root whose look fails is named as the root, not as a member: its exit cannot be observed though its
/// kill landed.
///
/// Mutant: the root's failed look is worded as a member's, or is dropped.
#[skuld::test]
fn a_root_whose_look_fails_is_named_as_the_root() {
    let root = FakeProcess::new([Answer::Err(std::io::ErrorKind::PermissionDenied)]);

    let err = KillWait::none()
        .with_root(&root, true)
        .wait()
        .expect_err("the root's exit cannot be observed");

    let said = crate::error::Report(&err).to_string();
    assert!(
        said.contains("the root was killed, but its exit cannot be observed"),
        "{said}"
    );
    assert!(!said.contains("pid "), "a member is not named: {said}");
}

/// The wait goes to the members first, then the root, then the tree's own edge: when the edge is
/// asked, the member has exited and the root has been looked at, and when the member is waited for, the
/// root has not been.
///
/// Mutant: the root or the edge is waited for before the members.
#[skuld::test]
fn a_wait_goes_to_the_members_then_the_root_then_the_edge() {
    use crate::containment::TreeDrain;

    let (member, writer, id) = live_member();
    let root = root_looking([Answer::Exited]);
    let order = Rc::new(std::cell::RefCell::new(Vec::new()));
    let writer = Cell::new(Some(writer));
    let _blocking = crate::wait::block_probe::on_blocking({
        let (root, order) = (root.clone(), order.clone());
        move || {
            assert_eq!(
                root.looks(),
                0,
                "the root was looked at before the member was waited for"
            );
            order.borrow_mut().push("member");
            drop(writer.take());
        }
    });
    let (_, wait) = TreeKill::of(TreeKillOutcome::Ran(Ok(())))
        .reaching([id])
        .until({
            let (root, order) = (root.clone(), order.clone());
            move || {
                assert_eq!(id.is_alive(), Liveness::Dead, "the edge was asked while the member ran");
                assert_eq!(root.looks(), 1, "the edge was asked before the root was waited for");
                order.borrow_mut().push("edge");
                Ok(TreeDrain::AllMembersExited)
            }
        })
        .split();

    wait.with_root(&root, true).wait().expect("every wait ended");

    assert_eq!(*order.borrow(), ["member", "edge"]);
    _ = member.wait();
}

/// A kill that failed is the call's answer whatever the wait finds, and the members it reached are
/// still waited for: the member is ended where the wait blocks.
///
/// Mutant: a failed kill's wait is not made; a wait error replaces the kill's.
fn a_failed_kill_is_the_answer_and_its_members_are_still_waited_for(wait_fails: bool) {
    let (member, writer, id) = live_member();
    let mut kill = TreeKill::of(TreeKillOutcome::Ran(Ok(()))).reaching([id]);
    if wait_fails {
        kill = kill.unobserved(exit_unobserved(
            4242,
            Error::Unassessable {
                detail: "refused".into(),
                source: None,
            },
        ));
    }
    let (_, wait) = kill.split();
    let writer = Cell::new(Some(writer));
    let blocked = Rc::new(Cell::new(false));
    let _blocking = crate::wait::block_probe::on_blocking({
        let blocked = blocked.clone();
        move || {
            blocked.set(true);
            drop(writer.take());
        }
    });
    let refused = SweepFailure {
        error: Error::Containment {
            detail: "the kill was refused".into(),
            source: None,
        },
        root_ended: false,
    };

    let failure = Swept::new(Err(refused), wait).wait().expect_err("the kill was refused");

    assert!(
        failure.error.to_string().contains("the kill was refused"),
        "the kill's error stands: {}",
        failure.error
    );
    assert!(blocked.get(), "the member the kill reached was not waited for");
    assert_eq!(id.is_alive(), Liveness::Dead);
    _ = member.wait();
}

#[skuld::test]
fn a_failed_kill_whose_wait_is_ok_is_the_answer_and_its_members_are_waited_for() {
    a_failed_kill_is_the_answer_and_its_members_are_still_waited_for(false);
}

#[skuld::test]
fn a_failed_kill_whose_wait_fails_too_is_the_answer_and_its_members_are_waited_for() {
    a_failed_kill_is_the_answer_and_its_members_are_still_waited_for(true);
}

/// A member the settlement killed again (a tree walk's held member, killed once more after the root's
/// death) is in the wait: the member is alive when the wait looks at it, and the wait blocks.
///
/// Mutant: `kill_tree` does not add the settlement's members to its wait.
#[skuld::test]
fn a_member_the_settlement_killed_again_is_waited_for() {
    let (member, writer, id) = live_member();
    let root = root_looking([Answer::Exited]);
    let (fake, _) = FakeContains::new(Containment::Session, false);
    let mut child = child_over(&root);
    child.tree = Tree::contained(Mechanism::Fake(fake.killing_again([id])));
    let writer = Cell::new(Some(writer));
    let ended = Rc::new(Cell::new(false));
    let _blocking = crate::wait::block_probe::on_blocking({
        let ended = ended.clone();
        move || {
            drop(writer.take());
            ended.set(true);
        }
    });

    child.kill_tree().expect("every member exited");

    assert!(
        ended.get(),
        "kill_tree returned without waiting for the re-killed member"
    );
    assert_eq!(id.is_alive(), Liveness::Dead);
    _ = member.wait();
}

/// A call that only sends reads no member list of a Job Object, though the call that waits does: the
/// listing is work for the wait alone.
///
/// Mutant: `send_kill_tree` goes through the kill that lists.
#[cfg(windows)]
#[skuld::test]
fn a_send_only_kill_tree_of_a_job_reads_no_list_of_its_members() {
    let (stdin, _writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::test_child::command(crate::test_child::Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain();
    let child = cmd.spawn().expect("spawn");
    let _counting = crate::containment::windows::fault::force_job_pid_list(Vec::new());

    child.send_kill_tree().expect("the kill was sent");

    assert_eq!(
        crate::containment::windows::fault::job_pid_list_queries(),
        0,
        "a call that only sends read the job's list"
    );
    _ = child.wait();
}
