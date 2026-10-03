//! The macOS spawn's identity check. macOS has no handle to pin a pid, so the identity read is
//! checked by a peek that re-reads the child's unique id (`peek_verified`), after the read.

use crate::child::spawn::fault::{self, SpawnPoint};
use crate::error::Error;
use crate::wait::exit_only::seams::force_peek_once;

/// Waits for `pid` (a child of this test) to exit, then reaps it by pid, as a foreign reaper would.
fn reap_by_pid(pid: u32) {
    let mut status = 0;
    // SAFETY: `pid` is this test's own child.
    let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    assert_eq!(reaped, pid as libc::pid_t, "{}", std::io::Error::last_os_error());
}

/// Kills and reaps `pid`, a child of this test the spawn under test left running.
fn kill_and_reap(pid: u32) {
    // SAFETY: `pid` is this test's own unreaped child.
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) }, 0);
    reap_by_pid(pid);
}

/// The reap lands after the identity read and before its re-read, so only the re-read can tell.
/// `waitpid` really reaps, so the re-read answers `Gone` from the OS, with no forced peek.
///
/// Mutant: `resolve_identity` does not re-read, so the stale read stands and the spawn is `Ok`.
#[skuld::test]
fn macos_sync_spawn_identity_after_a_real_reap_is_gone() {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    let _hook = fault::set_at(SpawnPoint::AfterIdentityRead, move || {
        drop(writer);
        reap_by_pid(fault::spawn_pid());
    });
    let err = match cmd.spawn() {
        Ok(child) => panic!("a child reaped before its re-read was adopted: {:?}", child.id()),
        Err(e) => e,
    };
    assert!(
        matches!(&err, Error::Io(e) if e.to_string().contains("reaped by another party")),
        "a reaped child is Gone, not Unassessable: {err:?}"
    );
}

/// A re-read the OS refuses (forced: the peek fails) cannot show the child ours: the spawn fails
/// `Unassessable`, and the child is left running, unsignalled and unreaped.
///
/// Mutant: a failed re-read keeps the read (`Refused` -> keep), so the spawn is `Ok`.
#[skuld::test]
fn macos_sync_spawn_identity_with_a_refused_reread_is_unassessable() {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    let (stdin, _writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    let pid = Rc::new(Cell::new(0));
    let armed: Rc<RefCell<Option<Box<dyn std::any::Any>>>> = Rc::default();
    let _hook = fault::set_at(SpawnPoint::AfterIdentityRead, {
        let (pid, armed) = (Rc::clone(&pid), Rc::clone(&armed));
        move || {
            pid.set(fault::spawn_pid());
            *armed.borrow_mut() = Some(Box::new(force_peek_once(Err(std::io::Error::other(
                "forced re-read refusal 5d1b",
            )))));
        }
    });
    let outcome = cmd.spawn();
    drop(armed);
    assert_ne!(pid.get(), 0, "the hook must have run");
    let adopted = outcome.as_ref().ok().map(|child| child.id());
    if adopted.is_none() {
        // Left running, as the spawn documents: this test's own child, killed here.
        kill_and_reap(pid.get());
    }
    let err = outcome.expect_err("a refused re-read fails the spawn");
    assert!(
        matches!(err, Error::Unassessable { .. }),
        "a refusal is Unassessable, not a vanish: {err:?}"
    );
}

#[cfg(feature = "tokio")]
mod tokio_tests {
    use super::*;

    /// As the sync twin: the reap lands between the read and the re-read.
    ///
    /// Mutant: `resolve_identity` does not re-read.
    #[skuld::test]
    async fn macos_tokio_spawn_identity_after_a_real_reap_is_gone() {
        crate::tokio::test_runtime::assert_current_thread();
        let (stdin, writer) = crate::test_child::held_writer_stdin();
        let mut cmd = crate::tokio::Command::new();
        cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
        cmd.stdin(stdin).expect("set stdin");
        let _hook = fault::set_at(SpawnPoint::AfterIdentityRead, move || {
            drop(writer);
            reap_by_pid(fault::spawn_pid());
        });
        let err = match cmd.spawn() {
            Ok(child) => panic!("a child reaped before its re-read was adopted: {:?}", child.id()),
            Err(e) => e,
        };
        assert!(
            matches!(&err, Error::Io(e) if e.to_string().contains("reaped by another party")),
            "a reaped child is Gone, not Unassessable: {err:?}"
        );
    }

    /// As the sync twin: the failed re-read fails the spawn `Unassessable`, and the teardown kills
    /// and reaps the child it can still show ours.
    ///
    /// Mutant: a failed re-read keeps the read.
    #[skuld::test]
    async fn macos_tokio_spawn_identity_with_a_refused_reread_is_unassessable() {
        use std::cell::RefCell;
        use std::rc::Rc;

        crate::tokio::test_runtime::assert_current_thread();
        let mut cmd = crate::tokio::Command::new();
        cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
        cmd.stdin(crate::stdio::Stdio::null()).expect("set stdin");
        let armed: Rc<RefCell<Option<Box<dyn std::any::Any>>>> = Rc::default();
        let _hook = fault::set_at(SpawnPoint::AfterIdentityRead, {
            let armed = Rc::clone(&armed);
            move || {
                *armed.borrow_mut() = Some(Box::new(force_peek_once(Err(std::io::Error::other(
                    "forced re-read refusal 5d1b",
                )))));
            }
        });
        let outcome = cmd.spawn();
        drop(armed);
        let err = outcome.expect_err("a refused re-read fails the spawn");
        assert!(
            matches!(err, Error::Unassessable { .. }),
            "a refusal is Unassessable, not a vanish: {err:?}"
        );
    }
}
