//! The wait over a tree kill: its members re-opened by identity, the root through its owner's handle,
//! and nothing waited for by a call that only sends. Every row drives a `Child` over a mechanism and a
//! root of stated answers, with live held children as the members the mechanism states it reached; a
//! member's exit is ended by the wait's own blocking call, so no row depends on timing.

use std::cell::Cell;
use std::rc::Rc;

use crate::containment::dispatch::{SweepFailure, Swept, TreeKillOutcome};
use crate::containment::fake::FakeContains;
use crate::containment::tree_kill::refused_unobserved;
use crate::containment::{Containment, KillWait, Mechanism, Tree, TreeKill};
use crate::error::Error;
use crate::identity::Liveness;
use crate::os_process::fake::{Answer, FakeProcess};
#[cfg(feature = "tokio")]
use crate::test_child::over_fake::tokio_child_reaching;
use crate::test_child::over_fake::{child_over, child_reaching, live_member, root_looking};

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
    let why = refused_unobserved(4242);
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

    let said = crate::error::said(&err);
    assert!(said.contains(&format!("pid {} was killed", first_id.pid())), "{said}");
    assert!(said.contains(&format!("pid {} was killed", second_id.pid())), "{said}");
    // The first member's error stands, with the second below it as a peer: each is named once.
    let Error::Unassessable {
        source: Some(source), ..
    } = &err
    else {
        panic!("{err:?}");
    };
    let Error::Several(members) = &**source else {
        panic!("expected Several, got {source:?}");
    };
    assert_eq!(
        members.iter().len(),
        2,
        "its own cause and the second member's error: {members:?}"
    );
    assert_eq!(
        said.matches(&format!("pid {} was killed", first_id.pid())).count(),
        1,
        "{said}"
    );
    assert_eq!(
        said.matches(&format!("pid {} was killed", second_id.pid())).count(),
        1,
        "{said}"
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
    let why = refused_unobserved(4242);
    let (_, wait) = TreeKill::of(TreeKillOutcome::Ran(Ok(()))).unobserved(why).split();

    let failure = Swept::new("kill_tree", Ok(()), wait.with_root(&root, true))
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

/// An edge that says members remain, from a wait with no deadline, has not drained the tree: it is an
/// error, where an edge that says all members exited, or all markers closed, is none.
///
/// Mutant: `drained` takes every verdict of the edge as a drain. The row tests `drained` alone; that
/// `wait` and `wait_async` pass the edge's verdict through it is not shown here.
#[skuld::test]
fn an_edge_that_says_members_remain_is_no_drain() {
    use super::drained;
    use crate::containment::TreeDrain;

    drained(TreeDrain::AllMembersExited).expect("the edge says every member exited");
    drained(TreeDrain::AllMarkersClosed).expect("the edge says every marker closed");
    let err = drained(TreeDrain::MembersRemain).expect_err("a deadline's verdict from a wait with none is no drain");
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

    let said = crate::error::said(&err);
    assert!(
        said.contains("the root was killed, but its exit cannot be observed"),
        "{said}"
    );
    assert!(!said.contains("pid "), "a member is not named: {said}");
}

/// The wait goes to the members first, then the root: when the member is waited for, the root has not
/// been looked at, and when the wait has ended, it has.
///
/// Mutant: the root is waited for before the members.
#[skuld::test]
fn a_wait_goes_to_the_members_then_the_root() {
    let (member, writer, id) = live_member();
    let root = root_looking([Answer::Exited]);
    let writer = Cell::new(Some(writer));
    let _blocking = crate::wait::block_probe::on_blocking({
        let root = root.clone();
        move || {
            assert_eq!(
                root.looks(),
                0,
                "the root was looked at before the member was waited for"
            );
            drop(writer.take());
        }
    });
    let (_, wait) = TreeKill::of(TreeKillOutcome::Ran(Ok(()))).reaching([id]).split();

    wait.with_root(&root, true).wait().expect("every wait ended");

    assert_eq!(id.is_alive(), Liveness::Dead, "the member has exited");
    assert_eq!(root.looks(), 1, "the root was looked at once the member had exited");
    _ = member.wait();
}

/// The tree's own edge is waited for after the root: the root's wait blocks, and the edge has not been
/// asked (a Job's edge lists its processes, once) when it does. The edge is a real Job's.
///
/// Mutant: the edge is waited for before the root.
#[cfg(windows)]
#[skuld::test]
fn the_edge_is_waited_for_after_the_root() {
    use crate::containment::windows::fault::{force_job_pid_list, job_pid_list_queries};

    let (job_child, writer, id) = crate::test_child::live_blocker();
    drop(writer);
    job_child.wait().expect("the job's member exits when its stdin closes");
    let edge = job_child.tree.drain_edge().expect("a Job has a drain edge");
    let root = root_looking([Answer::Running, Answer::Exited]);
    let _forced = force_job_pid_list(Vec::new());
    let _blocking = crate::wait::block_probe::on_blocking({
        let root = root.clone();
        move || {
            assert_eq!(
                job_pid_list_queries(),
                0,
                "the edge was asked before the root was waited for"
            );
            root.wake();
        }
    });
    let (_, wait) = TreeKill::listed(TreeKillOutcome::Ran(Ok(())), vec![id], Vec::new(), edge).split();

    wait.with_root(&root, true).wait().expect("every wait ended");

    assert_eq!(job_pid_list_queries(), 1, "the edge was asked once, after the root");
}

/// A tree's own edge whose wait fails with no deadline, over what it watches: a Job through a handle
/// that may not list its processes (Windows), a leaf whose `cgroup.events` has no `populated` field
/// (Linux). A macOS kill wait has no edge: only [`TreeKill::listed`] (Linux, Windows) sets one, and the
/// fd marker's kill names none. So the rows that use this are not built there.
#[cfg(any(windows, target_os = "linux"))]
struct FailingEdge {
    #[cfg(windows)]
    job: crate::containment::windows::JobHandle,
    // Before the fake: the leaf is closed before the directory it watches is removed.
    #[cfg(target_os = "linux")]
    leaf: crate::containment::cgroup::CgroupLeaf,
    #[cfg(target_os = "linux")]
    _fake: crate::containment::cgroup::test_support::FakeLeaf,
}

#[cfg(any(windows, target_os = "linux"))]
impl FailingEdge {
    fn new() -> FailingEdge {
        #[cfg(windows)]
        {
            use windows::Win32::System::SystemServices::JOB_OBJECT_TERMINATE;

            let job = crate::containment::windows::JobHandle::create_empty_for_test()
                .duplicate_with_access_for_test(JOB_OBJECT_TERMINATE);
            FailingEdge { job }
        }
        #[cfg(target_os = "linux")]
        {
            let fake = crate::containment::cgroup::test_support::FakeLeaf::new("cosca-failing-edge", true);
            crate::containment::cgroup::test_support::FakeLeaf::set_unreadable(&fake.events);
            let leaf = crate::containment::cgroup::test_support::entered_leaf_at(fake.leaf.clone());
            // Keeps the drop from writing the fake's `cgroup.kill` and reporting a left-behind leaf.
            leaf.disarm();
            FailingEdge { leaf, _fake: fake }
        }
    }

    fn edge(&self) -> crate::containment::drain_edge::DrainEdge<'_> {
        #[cfg(windows)]
        return crate::containment::drain_edge::DrainEdge::Job(&self.job);
        #[cfg(target_os = "linux")]
        return crate::containment::drain_edge::DrainEdge::Cgroup(&self.leaf);
    }
}

/// A tree's edge that fails with no deadline is the wait's error: nothing else in the wait failed, so
/// the answer is the edge's.
///
/// Mutant: the wait drops the edge's failure.
#[cfg(any(windows, target_os = "linux"))]
#[skuld::test]
fn an_edge_that_fails_is_the_waits_error() {
    let failing = FailingEdge::new();
    let (_, wait) = TreeKill::listed(TreeKillOutcome::Ran(Ok(())), Vec::new(), Vec::new(), failing.edge()).split();

    let err = wait.wait().expect_err("the edge could not be waited on");

    assert_is_the_edges_error(&err);
}

#[cfg(any(windows, target_os = "linux"))]
fn assert_is_the_edges_error(err: &Error) {
    // An `Io` is a leaf with no slot for peers, so the wait's `Unassessable` holds it.
    assert!(
        matches!(err, Error::Unassessable { source: Some(source), .. } if matches!(&**source, Error::Io(_))),
        "{err:?}"
    );
}

/// `err` is a wait's error when the root's look and the edge both failed: the root's is first, and the
/// edge's is a peer of the root's own cause, in a `Several` below it.
#[cfg(any(windows, target_os = "linux"))]
fn assert_the_root_comes_before_the_edge(err: &Error) {
    let Error::Unassessable {
        detail,
        source: Some(source),
    } = err
    else {
        panic!("the root's error comes first: {err:?}");
    };
    assert!(detail.starts_with("the root was killed"), "{detail}");
    assert!(
        !detail.contains("more could not"),
        "no member's words are in the detail: {detail}"
    );
    let Error::Several(list) = &**source else {
        panic!("expected Several, got {source:?}");
    };
    assert_eq!(list.iter().len(), 2, "{list:?}");
    assert!(
        matches!(&**list.iter().nth(1).expect("the edge's error"), Error::Io(_)),
        "the edge's error is the second: {list:?}"
    );
}

/// The edge is waited for after the root, so when both fail the first error is the root's and the
/// edge's is a peer below it.
///
/// Mutant: the edge is waited for before the root.
#[cfg(any(windows, target_os = "linux"))]
#[skuld::test]
fn the_roots_error_comes_before_the_edges() {
    let failing = FailingEdge::new();
    let root = FakeProcess::new([Answer::Err(std::io::ErrorKind::PermissionDenied)]);
    let (_, wait) = TreeKill::listed(TreeKillOutcome::Ran(Ok(())), Vec::new(), Vec::new(), failing.edge()).split();

    let err = wait
        .with_root(&root, true)
        .wait()
        .expect_err("neither the root's exit nor the edge could be observed");

    assert_the_root_comes_before_the_edge(&err);
}

/// A wait whose first failure is an `Error::Io` (a leaf, with no slot for peers) answers an
/// `Unassessable`, with that `Io` and every other failure below it, in order: none is dropped.
///
/// Mutants: the peers are dropped behind the `Io`; the `Io` is returned bare.
#[skuld::test]
fn a_wait_whose_first_failure_is_an_io_error_keeps_every_failure_below_an_unassessable() {
    let code = |error: &Error| crate::error::first_os_code(error);
    let io = |code: i32| Error::Io(std::io::Error::from_raw_os_error(code));
    let unobserved = vec![
        io(2),
        super::exit_unobserved(4242, io(3)),
        super::root_unobserved(io(5)),
    ];

    let err = super::answer_of(unobserved).expect_err("three exits could not be observed");

    let Error::Unassessable {
        source: Some(source), ..
    } = &err
    else {
        panic!("expected Unassessable, got {err:?}");
    };
    let Error::Several(list) = &**source else {
        panic!("expected Several, got {source:?}");
    };
    let codes: Vec<_> = list.iter().map(|member| code(member)).collect();
    assert_eq!(codes, [Some(2), Some(3), Some(5)]);

    let alone = super::answer_of(vec![io(2)]).expect_err("one exit could not be observed");
    assert!(matches!(&alone, Error::Unassessable { .. }), "{alone:?}");
    assert_eq!(code(&alone), Some(2));
}

/// A kill that failed is the call's answer whatever the wait finds, and the members it reached are
/// still waited for: the member is ended where the wait blocks.
///
/// Mutant: a failed kill's wait is not made; a wait error replaces the kill's.
fn a_failed_kill_is_the_answer_and_its_members_are_still_waited_for(wait_fails: bool) {
    let (member, writer, id) = live_member();
    let mut kill = TreeKill::of(TreeKillOutcome::Ran(Ok(()))).reaching([id]);
    if wait_fails {
        kill = kill.unobserved(refused_unobserved(4242));
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

    let failure = Swept::new("kill_tree", Err(refused), wait)
        .wait()
        .expect_err("the kill was refused");

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

/// A kill that failed stays the answer over a wait that failed too, and the wait's failure is logged
/// once, at warn, through `Report`, naming the call: it is a failure the caller cannot see in the
/// answer.
///
/// Mutant: the failure is logged at debug, not logged, or logged twice.
#[skuld::test]
fn a_failed_waits_failure_behind_a_failed_kill_is_logged_once_at_warn() {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (_, wait) = TreeKill::of(TreeKillOutcome::Ran(Ok(())))
        .unobserved(refused_unobserved(4242))
        .split();
    let refused = SweepFailure {
        error: Error::Containment {
            detail: "the kill was refused".into(),
            source: None,
        },
        root_ended: false,
    };

    let failure = Swept::new("graceful_shutdown_tree", Err(refused), wait)
        .wait()
        .expect_err("the kill was refused");

    assert!(
        failure.error.to_string().contains("the kill was refused"),
        "{}",
        failure.error
    );
    let logged =
        crate::log_capture::records_since_on_current_thread(mark, "the wait after a failed graceful_shutdown_tree");
    assert!(
        matches!(&logged[..], [(log::Level::Warn, line)]
            if line.contains("pid 4242 was killed, but its exit cannot be observed")),
        "{logged:?}"
    );
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

// The awaited wait: the rows above, driven by `KillWait::wait_async` over real held members that the
// test ends from a sibling task. The runtime is the test's current-thread one, so a wait that blocks
// its thread never lets the sibling run, and the test does not finish.

#[cfg(feature = "tokio")]
mod awaited {
    use std::future::Future as _;
    use std::pin::pin;
    use std::task::{Context, Waker};

    use super::*;

    /// `wait_async` returns once the member its kill reached has exited, and not before: its first
    /// poll is pending with the member alive, and the member is gone when it resolves.
    ///
    /// Mutant: `wait_async` returns without waiting for a member.
    #[skuld::test]
    async fn an_awaited_wait_waits_for_each_member_its_kill_reached() {
        let (member, writer, id) = live_member();
        let (_, wait) = TreeKill::of(TreeKillOutcome::Ran(Ok(()))).reaching([id]).split();

        let mut waiting = pin!(wait.wait_async());
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "a running member is waited for"
        );
        assert_eq!(id.is_alive(), Liveness::Alive);
        drop(writer);
        waiting.await.expect("every member exited");

        assert_eq!(
            id.is_alive(),
            Liveness::Dead,
            "the member has exited when the wait resolves"
        );
        _ = member.wait();
    }

    /// While `wait_async` is pending on a live member, another task on the same current-thread runtime
    /// runs, and its progress ends the wait (principle 2). `block_probe` turns a thread-blocking wait
    /// into a failed assertion instead of a hang.
    ///
    /// Mutant: `wait_async` waits through the sync `wait`.
    #[skuld::test]
    async fn an_awaited_wait_blocks_no_runtime_thread() {
        crate::tokio::test_runtime::assert_current_thread();
        let (member, writer, id) = live_member();
        let (_, wait) = TreeKill::of(TreeKillOutcome::Ran(Ok(()))).reaching([id]).split();
        let writer = Rc::new(Cell::new(Some(writer)));
        let blocked = Rc::new(Cell::new(false));
        let _blocking = crate::wait::block_probe::on_blocking({
            let (writer, blocked) = (writer.clone(), blocked.clone());
            move || {
                blocked.set(true);
                drop(writer.take());
            }
        });
        let done = Cell::new(false);

        let (waited, ()) = ::tokio::join!(
            async {
                let waited = wait.wait_async().await;
                done.set(true);
                waited
            },
            async {
                ::tokio::task::yield_now().await;
                assert!(!done.get(), "the other task could not run until the wait was over");
                drop(writer.take());
            }
        );

        waited.expect("every member exited");
        assert!(!blocked.get(), "the wait blocked a runtime thread");
        _ = member.wait();
    }

    /// The awaited wait goes to the members first, then the root: while the member is waited for, a
    /// sibling finds the root not looked at, and once the wait has ended it has been.
    ///
    /// Mutant: the root is waited for before the members.
    #[skuld::test]
    async fn an_awaited_wait_goes_to_the_members_then_the_root() {
        crate::tokio::test_runtime::assert_current_thread();
        let (member, writer, id) = live_member();
        let root = root_looking([Answer::Exited]);
        let (_, wait) = TreeKill::of(TreeKillOutcome::Ran(Ok(()))).reaching([id]).split();

        let (waited, ()) = ::tokio::join!(wait.with_root(&root, true).wait_async(), async {
            ::tokio::task::yield_now().await;
            assert_eq!(
                root.looks(),
                0,
                "the root was looked at before the member was waited for"
            );
            drop(writer);
        });

        waited.expect("every wait ended");
        assert_eq!(id.is_alive(), Liveness::Dead, "the member has exited");
        assert_eq!(root.looks(), 1, "the root was looked at once the member had exited");
        _ = member.wait();
    }

    /// A tree's edge that fails with no deadline is the awaited wait's error.
    ///
    /// Mutant: the awaited wait drops the edge's failure.
    #[cfg(any(windows, target_os = "linux"))]
    #[skuld::test]
    async fn an_awaited_edge_that_fails_is_the_waits_error() {
        let failing = FailingEdge::new();
        let (_, wait) = TreeKill::listed(TreeKillOutcome::Ran(Ok(())), Vec::new(), Vec::new(), failing.edge()).split();

        let err = wait.wait_async().await.expect_err("the edge could not be waited on");

        assert_is_the_edges_error(&err);
    }

    /// The awaited wait waits for the edge after the root, as the sync one does: when both fail the
    /// first error is the root's, with the edge's below it.
    ///
    /// Mutant: the edge is awaited before the root.
    #[cfg(any(windows, target_os = "linux"))]
    #[skuld::test]
    async fn an_awaited_roots_error_comes_before_the_edges() {
        let failing = FailingEdge::new();
        let root = FakeProcess::new([Answer::Err(std::io::ErrorKind::PermissionDenied)]);
        let (_, wait) = TreeKill::listed(TreeKillOutcome::Ran(Ok(())), Vec::new(), Vec::new(), failing.edge()).split();

        let err = wait
            .with_root(&root, true)
            .wait_async()
            .await
            .expect_err("neither the root's exit nor the edge could be observed");

        assert_the_root_comes_before_the_edge(&err);
    }

    /// A member whose exit cannot be observed does not end the awaited wait early: the members after it
    /// are waited for, and the error names it, as for the sync wait.
    ///
    /// Mutant: the awaited wait returns the first member's error without waiting for the rest.
    #[skuld::test]
    async fn an_awaited_wait_names_a_member_it_cannot_observe_once_the_rest_are_waited_for() {
        let (member, writer, id) = live_member();
        let why = refused_unobserved(4242);
        let (_, wait) = TreeKill::of(TreeKillOutcome::Ran(Ok(())))
            .unobserved(why)
            .reaching([id])
            .split();

        let (waited, ()) = ::tokio::join!(wait.wait_async(), async {
            ::tokio::task::yield_now().await;
            drop(writer);
        });

        let err = waited.expect_err("a member's exit cannot be observed");
        assert_eq!(id.is_alive(), Liveness::Dead, "the live member was waited for");
        assert!(
            err.to_string()
                .contains("pid 4242 was killed, but its exit cannot be observed"),
            "the error names the member: {err}"
        );
        _ = member.wait();
    }

    /// `Swept::wait_async` is the answer after the wait, as `Swept::wait` is: a kill that failed is the
    /// answer over a wait that is Ok or fails too, and the member it reached is still waited for.
    ///
    /// Mutant: a failed kill's wait is not made; a wait error replaces the kill's.
    async fn a_failed_kill_is_the_awaited_answer_and_its_members_are_still_waited_for(wait_fails: bool) {
        let (member, writer, id) = live_member();
        let mut kill = TreeKill::of(TreeKillOutcome::Ran(Ok(()))).reaching([id]);
        if wait_fails {
            kill = kill.unobserved(refused_unobserved(4242));
        }
        let (_, wait) = kill.split();
        let refused = SweepFailure {
            error: Error::Containment {
                detail: "the kill was refused".into(),
                source: None,
            },
            root_ended: false,
        };

        let (swept, ()) = ::tokio::join!(Swept::new("kill_tree", Err(refused), wait).wait_async(), async {
            ::tokio::task::yield_now().await;
            drop(writer);
        });

        let failure = swept.expect_err("the kill was refused");
        assert!(
            failure.error.to_string().contains("the kill was refused"),
            "the kill's error stands: {}",
            failure.error
        );
        assert_eq!(
            id.is_alive(),
            Liveness::Dead,
            "the member the kill reached was not waited for"
        );
        _ = member.wait();
    }

    #[skuld::test]
    async fn an_awaited_failed_kill_whose_wait_is_ok_is_the_answer_and_its_members_are_waited_for() {
        a_failed_kill_is_the_awaited_answer_and_its_members_are_still_waited_for(false).await;
    }

    #[skuld::test]
    async fn an_awaited_failed_kill_whose_wait_fails_too_is_the_answer_and_its_members_are_waited_for() {
        a_failed_kill_is_the_awaited_answer_and_its_members_are_still_waited_for(true).await;
    }

    /// `tokio::Child::kill_tree` resolves once every member its kill reached has exited, and not
    /// before: the sibling that ends the member finds the call still pending, and the root, whose kill
    /// landed, has been looked at once the call resolves.
    ///
    /// Mutant: `tokio::Child::kill_tree` takes the answer and drops the wait.
    #[skuld::test]
    async fn a_tokio_kill_tree_awaits_each_member_its_kill_reached() {
        let (member, writer, id) = live_member();
        let root = root_looking([Answer::Exited]);
        let child = tokio_child_reaching(&root, &[id]);
        let done = Cell::new(false);

        let (killed, ()) = ::tokio::join!(
            async {
                let killed = child.kill_tree().await;
                done.set(true);
                killed
            },
            async {
                ::tokio::task::yield_now().await;
                assert!(!done.get(), "kill_tree resolved while a member it killed was running");
                drop(writer);
            }
        );

        killed.expect("every member exited");
        assert_eq!(
            id.is_alive(),
            Liveness::Dead,
            "the member has exited when kill_tree resolves"
        );
        assert_eq!(root.looks(), 1, "the root whose kill landed was looked at");
        _ = member.wait();
    }

    /// `tokio::Child::graceful_shutdown_tree`'s escalation awaits what its sweep reached, as `kill_tree`
    /// does: the sibling that ends the member finds the call still pending. The root outlives the
    /// grace (its one look says running), so the sweep runs.
    ///
    /// Mutant: the escalation takes the sweep's answer and drops its wait.
    #[skuld::test]
    async fn a_tokio_graceful_escalation_awaits_each_member_its_sweep_reached() {
        use crate::os_process::child::ExitRecord;
        use crate::os_process::fake::ReapAnswer;

        crate::tokio::test_runtime::assert_current_thread();
        let (member, writer, id) = live_member();
        let root = root_looking([Answer::Running, Answer::Exited])
            .reaps([ReapAnswer::Reaped(ExitRecord::Status(Default::default()))]);
        let mut child = tokio_child_reaching(&root, &[id]);
        let done = Cell::new(false);

        let (shut_down, ()) = ::tokio::join!(
            async {
                let shut_down = child.graceful_shutdown_tree(std::time::Duration::ZERO).await;
                done.set(true);
                shut_down
            },
            async {
                ::tokio::task::yield_now().await;
                assert!(
                    !done.get(),
                    "graceful_shutdown_tree resolved while a member its sweep killed was running"
                );
                drop(writer);
            }
        );

        shut_down.expect("the tree was shut down");
        assert_eq!(
            id.is_alive(),
            Liveness::Dead,
            "the member has exited when the escalation resolves"
        );
        _ = member.wait();
    }

    /// `tokio::Child::send_kill_tree` sends and returns: it looks at no member and no root, and the
    /// member it reached runs. The root states no look, so one would panic.
    ///
    /// Mutant: `send_kill_tree` waits.
    #[skuld::test]
    fn a_tokio_send_kill_tree_waits_for_nothing() {
        let (member, writer, id) = live_member();
        let root = root_looking([]);
        let child = tokio_child_reaching(&root, &[id]);
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

    /// `Swept::wait_async` keeps the record that the root was killed on a wait error, as the sync wait
    /// does.
    ///
    /// Mutant: a wait error is a failure that says nothing of the root.
    #[skuld::test]
    async fn an_awaited_wait_error_keeps_the_record_that_the_root_was_killed() {
        let root = root_looking([Answer::Exited]);
        let why = refused_unobserved(4242);
        let (_, wait) = TreeKill::of(TreeKillOutcome::Ran(Ok(()))).unobserved(why).split();

        let failure = Swept::new("kill_tree", Ok(()), wait.with_root(&root, true))
            .wait_async()
            .await
            .expect_err("a member's exit cannot be observed");

        assert!(failure.root_ended, "the root was killed, and its exit was waited for");
        assert_eq!(root.looks(), 1);
    }
}
