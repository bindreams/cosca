//! Windows: the async twin of `child::disarm_refused_tests`, for what the async `Child` adds to the
//! sync one: `detach` and `commit_kill_on_drop` return the refusal of the sync `Child` they call. The
//! refusal is real (a job handle without `JOB_OBJECT_SET_ATTRIBUTES`).

use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

use super::Child;
use crate::containment::windows::JobHandle;
use crate::containment::Attached;
use crate::error::{ChildFate, Error};
use crate::identity::{Liveness, ProcessId};
use crate::test_child::{expect_may_have_started_parts, held_blocker_async, Console};

/// A live blocker whose containment is a job that refuses `disarm`; `kill_on_drop` is the command's.
fn refusing_child(kill_on_drop: bool) -> (Child, crate::tokio::ChildStdin, ProcessId) {
    let (mut child, stdin) = held_blocker_async(crate::Stdio::null(), Console::Hidden, |cmd| {
        _ = cmd.kill_on_drop(kill_on_drop);
    });
    child.inner.attached = Attached::JobObject(JobHandle::create_without_set_access_for_test());
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

/// A `detach` whose disarm is refused returns the refusal, and the child, which `detach` has not
/// touched, is still armed: dropping it kills it, and the drop waits for the kill.
///
/// Mutants: `detach` logs the refusal and returns `Ok`; it clears `kill_on_drop` before it knows the
/// disarm worked.
#[skuld::test]
async fn a_refused_detach_is_returned_and_leaves_the_child_armed() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, _stdin, id) = refusing_child(true);

    let error = child.detach().expect_err("the disarm was refused");

    assert_access_denied(&error);
    assert_eq!(id.is_alive(), Liveness::Alive, "a refused detach kills nothing");
    drop(child);
    assert_eq!(id.is_alive(), Liveness::Dead);
}

/// A `detach` of a child the spawn already disarmed has nothing to clear: `Ok`, and the job is not
/// asked again, so a job that would refuse changes nothing.
///
/// Mutant: `detach` clears the job's flag whatever `kill_on_drop` says.
#[skuld::test]
async fn detaching_a_child_that_is_already_disarmed_is_ok_without_asking_the_job() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, stdin, id) = refusing_child(false);

    child.detach().expect("the child was already disarmed");

    assert_eq!(id.is_alive(), Liveness::Alive);
    drop(stdin);
    drop(child);
}

/// A spawn with `kill_on_drop(false)` whose disarm is refused fails, and its child, still armed, is
/// torn down.
///
/// Mutants: the commit logs the refusal and returns the child; it fails the spawn but leaves the
/// child running.
#[skuld::test]
async fn a_refused_disarm_fails_a_kill_on_drop_false_spawn_and_kills_the_child() {
    crate::tokio::test_runtime::assert_current_thread();
    let (child, _stdin, id) = refusing_child(false);

    let failure = child.commit_kill_on_drop().expect_err("the disarm was refused");

    let (cause, fate, handed_back) = expect_may_have_started_parts(failure.into(), ());
    assert_access_denied(&cause);
    assert_eq!(fate, ChildFate::Reaped);
    assert!(handed_back.is_none(), "the teardown handed the child back");
    assert_eq!(id.is_alive(), Liveness::Dead);
}

/// A `kill_on_drop(true)` spawn has nothing to disarm, so a job that refuses it changes nothing.
///
/// Mutant: the commit disarms whatever `kill_on_drop` says.
#[skuld::test]
async fn a_kill_on_drop_spawn_is_not_disarmed() {
    crate::tokio::test_runtime::assert_current_thread();
    let (child, _stdin, id) = refusing_child(true);

    let child = child.commit_kill_on_drop().expect("nothing was asked of the job");

    assert_eq!(id.is_alive(), Liveness::Alive);
    drop(child);
}
