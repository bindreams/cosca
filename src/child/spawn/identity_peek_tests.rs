//! The sync spawn's identity check on Linux: a peek through the child's pidfd that fails.

use crate::child::spawn::fault::{self, SpawnPoint};
use crate::log_capture::warns_since;
use crate::test_child::Console;
use crate::wait::exit_only::seams::force_peeks;

/// A peek that fails cannot show the read named our child, but the pidfd pins the child whatever
/// the peek said: the spawn keeps the child with no identity, and warns once naming the error. The
/// child is killed and waited for through its pidfd like any other.
///
/// Mutants: the failed check is `Ok` (the child has an identity); the warn drops the error, or is
/// never logged; the spawn fails, or kills the child.
#[skuld::test]
fn a_failed_identity_peek_keeps_the_child_without_an_identity() {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    crate::log_capture::install();
    let (stdin, _teardown) = fault::teardown_blocker_stdin();
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    let pid = Rc::new(Cell::new(0));
    let armed: Rc<RefCell<Option<Box<dyn std::any::Any>>>> = Rc::default();
    let _hook = fault::set_at(SpawnPoint::AfterIdentityRead, {
        let (pid, armed) = (Rc::clone(&pid), Rc::clone(&armed));
        move || {
            pid.set(fault::spawn_pid());
            *armed.borrow_mut() = Some(Box::new(force_peeks([Err(std::io::Error::other(
                "forced identity-check failure 3b7e",
            ))])));
        }
    });
    let mark = crate::log_capture::mark();

    let outcome = cmd.spawn();

    crate::wait::exit_only::seams::assert_peeks_exhausted();
    drop(armed);
    let child = outcome.expect("a failed identity peek keeps the child");
    assert_eq!(
        child.id(),
        None,
        "the read could not be checked, so the child has no identity"
    );
    assert_eq!(child.pid(), pid.get(), "the pid is the spawned child's");
    // The failed check is the event's one warn, logged when the spawn ends.
    let warns = warns_since(mark, "");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains("could not be checked against its handle (forced identity-check failure 3b7e)"),
        "the failed peek is warned, naming its own error: {warns:?}"
    );
    child.kill().expect("a kept child is killed through its pidfd");
    let status = child.wait().expect("a kept child is waited on");
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&status),
        Some(libc::SIGKILL),
        "the kill ended the child"
    );
}

/// A tree walk cannot do without the identity, so a failed peek fails the spawn and the child is
/// torn down. The failed check and that teardown are one event: the diagnosis is folded into the
/// teardown's warn (or logged once on its own), never twice.
///
/// Mutants: the failure arm tears down with a fresh diagnosis, which drops the failed check from the
/// warn; the check warns at the call as well as at the teardown (two warns); the child is not reaped.
#[skuld::test]
fn a_failed_identity_peek_fails_a_tree_walk_spawn_and_warns_once_of_the_check() {
    use std::cell::RefCell;
    use std::rc::Rc;

    crate::log_capture::install();
    let (stdin, teardown) = fault::teardown_blocker_stdin();
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(crate::ContainMode::TreeWalk);
    let armed: Rc<RefCell<Option<Box<dyn std::any::Any>>>> = Rc::default();
    let _hook = fault::set_at(SpawnPoint::AfterIdentityRead, {
        let armed = Rc::clone(&armed);
        move || {
            *armed.borrow_mut() = Some(Box::new(force_peeks([Err(std::io::Error::other(
                "forced identity-check failure 8e2f",
            ))])));
        }
    });
    let mark = crate::log_capture::mark();

    let outcome = cmd.spawn();

    crate::wait::exit_only::seams::assert_peeks_exhausted();
    drop(armed);
    let (err, fate) = crate::child::spawn::failure::expect_may_have_started_with(
        outcome.expect_err("a tree walk without an identity fails the spawn"),
    );
    assert!(
        matches!(err, crate::error::Error::Unassessable { .. }),
        "a failed peek is Unassessable, not a vanish: {err:?}"
    );
    assert_eq!(
        fate,
        crate::error::ChildFate::Reaped,
        "the pidfd pins the child, so it is reaped"
    );
    teardown.assert_killed();
    let warns = warns_since(mark, "");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains("could not be checked against its handle (forced identity-check failure 8e2f)"),
        "the one warn names the failed check: {warns:?}"
    );
}
