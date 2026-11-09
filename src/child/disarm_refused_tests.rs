//! Windows: a refused disarm of the child's job is returned, not logged. The refusal is real: the
//! job is reached through a handle without `JOB_OBJECT_SET_ATTRIBUTES`, so the OS answers
//! `ERROR_ACCESS_DENIED` to the `SetInformationJobObject` that clears `KILL_ON_JOB_CLOSE`.

use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

use crate::child::Child;
use crate::containment::windows::JobHandle;
use crate::containment::Attached;
use crate::error::{ChildFate, Error};
use crate::identity::{Liveness, ProcessId};
use crate::test_child::{expect_may_have_started_parts, held_uncontained_blocker};

/// A live blocker whose containment is a job that refuses `disarm`; `kill_on_drop` is the command's.
fn refusing_child(kill_on_drop: bool) -> (Child, crate::PipeWriter, ProcessId) {
    let (mut child, stdin) = held_uncontained_blocker(kill_on_drop);
    child.attached = Attached::JobObject(JobHandle::create_without_set_access_for_test());
    let id = child.id().expect(crate::test_child::IDENTITY_READ);
    (child, stdin, id)
}

#[track_caller]
fn assert_access_denied(error: &Error) {
    let Error::Io(io) = error else {
        panic!("expected Io, got {error:?}");
    };
    assert_eq!(io.raw_os_error(), Some(ERROR_ACCESS_DENIED.0 as i32), "{io:?}");
}

/// A `detach` whose disarm is refused gives the child back, with the refusal, and has not touched
/// it.
///
/// Mutants: `detach` drops the child and returns only the error; it logs the refusal and returns
/// `Ok`.
#[skuld::test]
fn a_refused_detach_returns_the_child_and_the_error() {
    let (child, _stdin, id) = refusing_child(true);

    let (child, error) = child.detach().expect_err("the disarm was refused");

    assert_access_denied(&error);
    assert_eq!(child.id(), Some(id));
    assert_eq!(id.is_alive(), Liveness::Alive, "a refused detach kills nothing");
}

/// The child a refused `detach` gave back is still armed: dropping it kills it.
///
/// Mutant: `detach` clears `kill_on_drop` before it knows the disarm worked.
#[skuld::test]
fn the_child_a_refused_detach_gave_back_is_killed_on_drop() {
    let (child, _stdin, id) = refusing_child(true);
    let (child, _error) = child.detach().expect_err("the disarm was refused");

    drop(child);

    assert_eq!(id.is_alive(), Liveness::Dead);
}

/// A `detach` of a child the spawn already disarmed has nothing to clear: `Ok`, and the job is not
/// asked again, so a job that would refuse changes nothing.
///
/// Mutant: `detach` clears the job's flag whatever `kill_on_drop` says.
#[skuld::test]
fn detaching_a_child_that_is_already_disarmed_is_ok_without_asking_the_job() {
    let (child, stdin, id) = refusing_child(false);

    child.detach().expect("the child was already disarmed");

    assert_eq!(id.is_alive(), Liveness::Alive);
    drop(stdin);
}

/// A spawn with `kill_on_drop(false)` whose disarm is refused fails, and its child, still armed, is
/// torn down: the caller is not handed a child that cosca will kill.
///
/// Mutants: the commit logs the refusal and returns the child; it fails the spawn but leaves the
/// child running; it hands the child back.
#[skuld::test]
fn a_refused_disarm_fails_a_kill_on_drop_false_spawn_and_kills_the_child() {
    let (child, stdin, id) = refusing_child(false);

    let failure = child.commit_kill_on_drop().expect_err("the disarm was refused");

    let (cause, fate, handed_back) = expect_may_have_started_parts(failure.into(), stdin);
    assert_access_denied(&cause);
    assert_eq!(fate, ChildFate::Reaped);
    assert!(handed_back.is_none(), "the teardown handed the child back");
    assert_eq!(id.is_alive(), Liveness::Dead);
}

/// The failed commit of a child reported as a launch that leaves no front does not say it is a
/// front's.
///
/// Mutants: `commit_kill_on_drop` sets the flag from `report.is_some()` or from
/// `may_run_as_another_user()`.
#[skuld::test]
fn a_refused_disarm_of_a_child_without_a_front_sets_no_wrapper_flag() {
    use crate::elevation::elevation_tests::{report, VIAS_WITHOUT_A_FRONT};
    for via in VIAS_WITHOUT_A_FRONT {
        let (mut child, stdin, _id) = refusing_child(false);
        child.elevation = Some(report(via.clone()));

        let error = Error::from(child.commit_kill_on_drop().expect_err("the disarm was refused"));

        assert!(
            matches!(
                error,
                Error::MayHaveStarted {
                    wrapper_elevated: false,
                    ..
                }
            ),
            "{via:?}: {error:?}"
        );
        let (_, fate, handed_back) = expect_may_have_started_parts(error, stdin);
        assert_eq!(fate, ChildFate::Reaped, "{via:?}");
        assert!(handed_back.is_none(), "{via:?}: the teardown handed the child back");
    }
}

/// A `kill_on_drop(true)` spawn has nothing to disarm, so a job that refuses it changes nothing.
///
/// Mutant: the commit disarms whatever `kill_on_drop` says.
#[skuld::test]
fn a_kill_on_drop_spawn_is_not_disarmed() {
    let (child, _stdin, id) = refusing_child(true);

    let child = child.commit_kill_on_drop().expect("nothing was asked of the job");

    assert_eq!(id.is_alive(), Liveness::Alive);
    drop(child);
}
