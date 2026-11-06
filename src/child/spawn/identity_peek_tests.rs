//! The sync spawn's identity check on Linux: a peek through the child's pidfd that fails.

use crate::child::spawn::fault::{self, SpawnPoint};
use crate::log_capture::warns_since;
use crate::test_child::Console;
use crate::wait::exit_only::seams::force_peeks;

/// A peek that fails cannot show the read named our child, but the pidfd pins the child whatever
/// the peek said: the spawn keeps the child with no identity. The failed check is logged at debug
/// and warns of nothing: a kept child owes no failure. The child is killed and waited for through
/// its pidfd like any other.
///
/// Mutants: the failed check is `Ok` (the child has an identity); the failed check warns though the
/// child is kept, or is never logged; the spawn fails, or kills the child.
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
    assert_eq!(
        warns_since(mark, ""),
        Vec::<String>::new(),
        "a kept child warns of nothing"
    );
    assert_eq!(
        crate::log_capture::levels_since(mark, "forced identity-check failure 3b7e"),
        [log::Level::Debug],
        "the failed check is logged once, at debug, naming its own error"
    );
    assert_eq!(
        crate::log_capture::levels_since(mark, "kept without an identity"),
        [log::Level::Debug],
        "the keep is logged once, at debug"
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
/// teardown's warn (or logged once on its own), never twice. The teardown has a warn of its own to
/// fold the check into: the application reaps the killed child behind the spawn's back, so the
/// teardown's reap finds `ECHILD`.
///
/// Mutants: the failure arm tears down with a fresh diagnosis, which leaves the failed check to be
/// logged apart from the teardown's warn (two warns); the check warns at the call as well as at the
/// teardown (two warns); the child is not reaped; the error is built from the read's cause, which
/// the successful read left empty, and not from the failed peek.
#[skuld::test]
fn a_failed_identity_peek_fails_a_tree_walk_spawn_and_warns_once_of_the_check() {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    crate::log_capture::install();
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(crate::ContainMode::TreeWalk);
    let pid = Rc::new(Cell::new(0));
    let armed: Rc<RefCell<Option<Box<dyn std::any::Any>>>> = Rc::default();
    let _hook = fault::set_at(SpawnPoint::AfterIdentityRead, {
        let (pid, armed) = (Rc::clone(&pid), Rc::clone(&armed));
        move || {
            pid.set(fault::spawn_pid());
            *armed.borrow_mut() = Some(Box::new(force_peeks([Err(std::io::Error::other(
                "forced identity-check failure 8e2f",
            ))])));
        }
    });
    // The hook reaps the zombie the teardown's kill made. The writer is released after the kill, so a
    // kill that sent nothing fails the SIGKILL assertion.
    let _foreign_reap = crate::graceful_hooks::at(crate::graceful_hooks::HookPoint::AfterDropKill, move || {
        let pid = pid.get();
        assert_ne!(pid, 0, "the spawn noted the child's pid");
        drop(writer);
        crate::test_child::assert_zombie_sigkilled("the child", pid);
        let mut status = 0;
        // SAFETY: `pid` is this test's own zombie child; this plays the application that reaps it.
        let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
        assert_eq!(reaped, pid as libc::pid_t, "{}", std::io::Error::last_os_error());
    });
    let mark = crate::log_capture::mark();

    let outcome = cmd.spawn();

    crate::wait::exit_only::seams::assert_peeks_exhausted();
    drop(armed);
    let (err, fate) = crate::child::spawn::failure::expect_may_have_started_with(
        outcome.expect_err("a tree walk without an identity fails the spawn"),
    );
    assert!(
        matches!(
            &err,
            crate::error::Error::Unassessable { source: Some(source), .. }
                if source.to_string().contains("forced identity-check failure 8e2f")
        ),
        "a failed peek is Unassessable with the peek's own error as source, not a vanish: {err:?}"
    );
    assert_eq!(
        fate,
        crate::error::ChildFate::Killed,
        "the kill was delivered and someone else collected the exit"
    );
    let warns = warns_since(mark, "");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains("could not be checked against its handle (forced identity-check failure 8e2f)")
            && warns[0].contains("reaped by someone else"),
        "the one warn names the failed check and the teardown's own: {warns:?}"
    );
}
