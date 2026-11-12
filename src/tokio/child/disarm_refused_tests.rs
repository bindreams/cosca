//! Windows: what the async `Child` adds to `child::disarm_refused_tests`: `detach` returns the
//! refusal of the sync `Child` it calls. The refusal is real (a job handle without
//! `JOB_OBJECT_SET_ATTRIBUTES`). A refused disarm in the async spawn's own path (`resume`) is
//! pinned in `suspended_tests`.

use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

use super::Child;
use crate::containment::windows::JobHandle;
use crate::containment::{Mechanism, Tree};
use crate::error::Error;
use crate::identity::{Liveness, ProcessId};
use crate::test_child::{held_blocker_async, Console};

/// A live blocker whose containment is a job that refuses `disarm`; `kill_on_drop` is the command's.
async fn refusing_child(kill_on_drop: bool) -> (Child, crate::tokio::ChildStdin, ProcessId) {
    let (mut child, stdin) = held_blocker_async(crate::Stdio::null(), Console::Hidden, |cmd| {
        _ = cmd.kill_on_drop(kill_on_drop);
    })
    .await;
    child.inner.tree = Tree::contained(Mechanism::Job(JobHandle::create_without_set_access_for_test()));
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
    let (mut child, _stdin, id) = refusing_child(true).await;

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
    let (mut child, stdin, id) = refusing_child(false).await;

    child.detach().expect("the child was already disarmed");

    assert_eq!(id.is_alive(), Liveness::Alive);
    drop(stdin);
    drop(child);
}
