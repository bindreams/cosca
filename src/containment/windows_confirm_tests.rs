//! Rows of the confirmation of an empty listing ([`super::ConfirmWalk`]) that hold whatever order the
//! system snapshot names the members in.

use crate::containment::TreeDrain;
use crate::error::Error;
use crate::identity::windows_fixture::spawn_query_only_without_console;
use crate::test_child::{let_member_exit, spawn_more_blocker};
use crate::test_own_process::Completion;

// The step core =====

use super::{ConfirmStep, ConfirmWalk, Found, JobHandle};
use crate::containment::tree_kill::Settled;
use crate::identity::{Key, ProcessId};

/// The identity of the process `pid`, started at one fixed time.
fn id(pid: u32) -> ProcessId {
    ProcessId::from_parts_for_test(pid, Key::for_test(1))
}

/// Another process that has the number `pid`.
fn reused(pid: u32) -> ProcessId {
    ProcessId::from_parts_for_test(pid, Key::for_test(2))
}

fn refusal(detail: &str) -> Error {
    Error::Unassessable {
        detail: detail.to_owned(),
        source: None,
    }
}

/// How a wait for a member comes out.
#[derive(Clone, Copy)]
enum Wait {
    Exited,
    Running,
    Refused,
}

/// Run `walk` to its answer, a wait coming to what `outcome` says of the member it is for. Returns the
/// pids the walk asked to wait for, in order, and the answer.
fn run(mut walk: ConfirmWalk<'_>, outcome: impl Fn(u32) -> Wait) -> (Vec<u32>, Result<TreeDrain, Error>) {
    let mut asked = Vec::new();
    loop {
        match walk.next() {
            ConfirmStep::Wait(member) => {
                asked.push(member.pid());
                walk.waited(
                    member,
                    match outcome(member.pid()) {
                        Wait::Exited => Ok(true),
                        Wait::Running => Ok(false),
                        Wait::Refused => Err(refusal("refused")),
                    },
                );
            }
            ConfirmStep::Done(answer) => return (asked, answer),
        }
    }
}

const COUNT: u32 = 7;

fn walk_of<'a>(job: &'a JobHandle, snapshot: Vec<Found>, settled: &Settled) -> ConfirmWalk<'a> {
    ConfirmWalk::new(job, COUNT, Ok(snapshot), settled)
}

fn unreadable(pid: u32) -> Found {
    Err((pid, refusal("its start time could not be read")))
}

/// What a member's wait comes to: member 1 is the one that fails, 2 the one that runs, the rest exit.
fn outcome_by_pid(pid: u32) -> Wait {
    match pid {
        1 => Wait::Refused,
        2 => Wait::Running,
        _ => Wait::Exited,
    }
}

/// A walk asks for every member, whatever an earlier wait came to, and a failure outranks a member still
/// running, whichever comes first in the snapshot.
///
/// Mutant: the walk returns on the first failure, or on the first member still running.
#[skuld::test]
fn the_walk_waits_for_every_member_and_a_failed_wait_outranks_a_running_one_in_either_order() {
    let job = JobHandle::create_empty_for_test();
    for snapshot in [
        vec![Ok(id(1)), Ok(id(2)), Ok(id(3))],
        vec![Ok(id(2)), Ok(id(1)), Ok(id(3))],
    ] {
        let (asked, answer) = run(walk_of(&job, snapshot, &Settled::default()), outcome_by_pid);
        assert_eq!(asked.len(), 3, "{asked:?}");
        let error = answer.expect_err("the failed wait is the answer");
        assert!(
            matches!(&error, Error::Unassessable { detail, .. } if detail.contains("pid 1")),
            "{error:?}"
        );
    }
}

/// A member whose identity the snapshot could not read is the answer over a running one, in either order,
/// and every member is still waited for.
///
/// Mutant: the unreadable member is reported before the walk, or ends it.
#[skuld::test]
fn an_unreadable_member_outranks_a_running_one_in_either_order_and_ends_no_walk() {
    let job = JobHandle::create_empty_for_test();
    for snapshot in [
        vec![Ok(id(2)), unreadable(1), Ok(id(3))],
        vec![unreadable(1), Ok(id(2)), Ok(id(3))],
    ] {
        let (asked, answer) = run(walk_of(&job, snapshot, &Settled::default()), outcome_by_pid);
        assert_eq!(asked.len(), 2, "{asked:?}");
        let error = answer.expect_err("the unreadable member is the answer");
        assert!(
            matches!(&error, Error::Unassessable { detail, .. } if detail.contains("pid 1")),
            "{error:?}"
        );
    }
}

/// Every failure is in the answer, once, in the order found: a member the snapshot could not read comes
/// before the waits.
///
/// Mutant: only the first failure is kept, or a failure is named twice.
#[skuld::test]
fn every_failure_is_in_the_answer_once() {
    let job = JobHandle::create_empty_for_test();
    let snapshot = vec![Ok(id(1)), Ok(id(2)), unreadable(4), Ok(id(5)), unreadable(6)];

    let (asked, answer) = run(walk_of(&job, snapshot, &Settled::default()), |pid| match pid {
        1 | 5 => Wait::Refused,
        _ => Wait::Running,
    });

    assert_eq!(asked, [1, 2, 5]);
    let report = crate::error::Report(&answer.expect_err("failures")).to_string();
    for pid in [1, 4, 5, 6] {
        assert_eq!(report.matches(&format!("pid {pid},")).count(), 1, "pid {pid}: {report}");
    }
    assert_eq!(report.matches("pid 2").count(), 0, "{report}");
}

/// The answer is `MembersRemain` while a member runs and nothing failed, and `AllMembersExited` once
/// every one has exited, when the job's count is stored.
///
/// Mutant: the count is stored whatever the answer.
#[skuld::test]
fn the_count_is_stored_only_for_a_drain_every_member_of_which_exited() {
    let snapshot = || vec![Ok(id(3)), Ok(id(2))];
    for (outcome, expected, stored) in [
        (outcome_by_pid as fn(u32) -> Wait, TreeDrain::MembersRemain, 0),
        (|_| Wait::Exited, TreeDrain::AllMembersExited, COUNT),
    ] {
        let job = JobHandle::create_empty_for_test();
        let (_, answer) = run(walk_of(&job, snapshot(), &Settled::default()), outcome);
        assert_eq!(answer.expect("no failure"), expected);
        assert_eq!(job.confirmed.load(std::sync::atomic::Ordering::Relaxed), stored);
    }
    let job = JobHandle::create_empty_for_test();
    let (_, answer) = run(walk_of(&job, vec![Ok(id(1))], &Settled::default()), outcome_by_pid);
    answer.expect_err("a failed wait");
    assert_eq!(job.confirmed.load(std::sync::atomic::Ordering::Relaxed), 0);
}

/// A snapshot that could not be taken is the answer, with nothing to wait for.
#[skuld::test]
fn a_failed_snapshot_is_the_answer() {
    let job = JobHandle::create_empty_for_test();

    let (asked, answer) = run(
        ConfirmWalk::new(&job, COUNT, Err(refusal("no snapshot")), &Settled::default()),
        |_| Wait::Exited,
    );

    assert!(asked.is_empty());
    assert!(matches!(answer, Err(Error::Unassessable { detail, .. }) if detail == "no snapshot"));
    assert_eq!(job.confirmed.load(std::sync::atomic::Ordering::Relaxed), 0);
}

/// A member with a readable identity is settled by that identity, a member the kill's wait saw exit or
/// reported; it is not waited for, and the count is not stored, for it may still run.
///
/// Mutant: the count is stored whatever was left out.
#[skuld::test]
fn a_member_with_a_settled_identity_is_not_waited_for_and_stands_for_no_count() {
    let job = JobHandle::create_empty_for_test();
    let settled = Settled::new(vec![id(3)], Vec::new());

    let (asked, answer) = run(walk_of(&job, vec![Ok(id(3)), Ok(id(4))], &settled), |_| Wait::Exited);

    assert_eq!(asked, [4]);
    assert_eq!(answer.expect("drained"), TreeDrain::AllMembersExited);
    assert_eq!(job.confirmed.load(std::sync::atomic::Ordering::Relaxed), 0);
}

/// A pid match against a member whose exit was seen is never used.
///
/// Mutant: a readable identity is settled by its pid.
#[skuld::test]
fn a_pid_of_a_settled_member_does_not_settle_another_identity() {
    let job = JobHandle::create_empty_for_test();
    let settled = Settled::new(vec![id(3)], Vec::new());

    let (asked, _) = run(walk_of(&job, vec![Ok(reused(3))], &settled), |_| Wait::Exited);

    assert_eq!(asked, [3]);
}

/// An entry whose identity cannot be read is settled by a pid the kill's wait reported, and by no pid of
/// a member whose exit it saw.
///
/// Mutant: an unreadable entry is settled by any member's pid.
#[skuld::test]
fn an_unreadable_entry_is_settled_by_a_reported_pid_alone() {
    let job = JobHandle::create_empty_for_test();
    let settled = Settled::new(vec![id(3), id(4)], vec![4]);

    let (asked, answer) = run(walk_of(&job, vec![unreadable(4), unreadable(3)], &settled), |_| {
        Wait::Exited
    });

    assert!(asked.is_empty());
    let report = crate::error::Report(&answer.expect_err("pid 3 is not settled")).to_string();
    assert_eq!(report.matches("pid 3,").count(), 1, "{report}");
    assert_eq!(report.matches("pid 4,").count(), 0, "{report}");
}

// The drain with the snapshot's members in a real job =====

/// Why a member's exit cannot be observed.
#[derive(Clone, Copy)]
enum Unobservable {
    /// The wait's open is refused: the member's DACL grants `PROCESS_QUERY_LIMITED_INFORMATION` only.
    Refused,
    /// The member's start time cannot be read from the snapshot (a forced failure).
    Unreadable,
}

/// What a drain answers for a job of one member whose exit cannot be observed and one that runs, with
/// the running one spawned `running_first` (so the snapshot most likely names it first) or after. The
/// drain's listing is empty (forced), as a kill's first one can be. `zero` is an elapsed deadline;
/// otherwise none, and the running member's stdin is released from another thread so the wait ends.
/// Returns the answer, the unobservable member's pid, and whether the running member had exited when
/// the answer came back.
fn drain_over(
    done: &Completion,
    kind: Unobservable,
    running_first: bool,
    zero: bool,
) -> (Result<TreeDrain, Error>, u32, bool) {
    use std::os::windows::io::AsRawHandle as _;
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

    let (mut running, unobservable) = if running_first {
        let running = spawn_more_blocker();
        (running, spawn_query_only_without_console(done))
    } else {
        let unobservable = spawn_query_only_without_console(done);
        (spawn_more_blocker(), unobservable)
    };
    let pid = unobservable.pid();
    let job = super::JobHandle::create_empty_for_test();
    // The OS lets the restricted fixture into a new job only first.
    job.assign_for_test(unobservable.handle().0)
        .expect("assign the unobservable member to the job");
    job.assign_for_test(running.as_raw_handle())
        .expect("assign the running member to the job");
    let _failed = match kind {
        Unobservable::Refused => None,
        Unobservable::Unreadable => Some(super::fault::force_next_for_thread(
            super::fault::Step::Identity,
            ERROR_ACCESS_DENIED.0,
            pid,
        )),
    };
    let forced = super::fault::force_job_pid_list(Vec::new());
    let stdin = running.stdin.take().expect("piped stdin");
    let (verdict, released) = if zero {
        let zero = crate::wait::deadline_from(std::time::Duration::ZERO);
        (super::wait_drained_raw(&job, zero), Some(stdin))
    } else {
        let release = std::thread::spawn(move || drop(stdin));
        let verdict = super::wait_drained_raw(&job, None);
        release.join().expect("the release thread");
        (verdict, None)
    };
    drop(forced);
    let exited = running.try_wait().expect("look at the running member").is_some();
    drop(released);
    job.hard_kill().expect("end the members");
    let_member_exit(running);
    (verdict, pid, exited)
}

fn assert_names(verdict: Result<TreeDrain, Error>, pid: u32, order: &str) {
    let error = verdict.expect_err(&format!("an unobservable member is the answer, {order}"));
    assert!(
        matches!(&error, Error::Unassessable { detail, .. } if detail.contains(&pid.to_string())),
        "{order}: {error:?}"
    );
}

fn the_unobservable_member_is_the_answer(done: &Completion, kind: Unobservable, zero: bool) {
    for running_first in [true, false] {
        let order = if running_first {
            "running member first"
        } else {
            "unobservable member first"
        };
        let (verdict, pid, exited) = drain_over(done, kind, running_first, zero);
        assert_names(verdict, pid, order);
        assert!(
            zero || exited,
            "{order}: the error came before the running member was waited for"
        );
    }
}

/// A member whose wait is refused outranks `MembersRemain` at an elapsed deadline, whichever the
/// snapshot names first: the walk waits for every member, and a running one is a poll.
///
/// Mutant: the walk ends on the first member still running.
#[skuld::test]
fn a_refused_member_is_the_answer_at_an_elapsed_deadline_in_either_order() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(a_refused_member_is_the_answer_at_an_elapsed_deadline_in_either_order),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    the_unobservable_member_is_the_answer(&done, Unobservable::Refused, true);
}

/// With no deadline the error comes once every other member has been waited for, whichever the snapshot
/// names first.
///
/// Mutant: the walk returns the first error.
#[skuld::test]
fn a_refused_member_is_the_answer_once_the_others_exited_with_no_deadline_in_either_order() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(
            a_refused_member_is_the_answer_once_the_others_exited_with_no_deadline_in_either_order
        ),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    the_unobservable_member_is_the_answer(&done, Unobservable::Refused, false);
}

/// [`a_refused_member_is_the_answer_at_an_elapsed_deadline_in_either_order`] for a member whose start
/// time cannot be read.
#[skuld::test]
fn an_unreadable_member_is_the_answer_at_an_elapsed_deadline_in_either_order() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(an_unreadable_member_is_the_answer_at_an_elapsed_deadline_in_either_order),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    the_unobservable_member_is_the_answer(&done, Unobservable::Unreadable, true);
}

/// [`a_refused_member_is_the_answer_once_the_others_exited_with_no_deadline_in_either_order`] for a
/// member whose start time cannot be read.
///
/// Mutant: the error is returned before any member is waited for.
#[skuld::test]
fn an_unreadable_member_is_the_answer_once_the_others_exited_with_no_deadline_in_either_order() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(
            an_unreadable_member_is_the_answer_once_the_others_exited_with_no_deadline_in_either_order
        ),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    the_unobservable_member_is_the_answer(&done, Unobservable::Unreadable, false);
}
