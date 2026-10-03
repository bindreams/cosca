//! The macOS async spawn's identity check, twin of `child::spawn::identity_macos_tests`.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use super::{drop_fault, fault as backend_fault};
use crate::child::spawn::fault::{self, SpawnPoint};
use crate::child::spawn::identity_macos_tests::{
    exists, kill_and_reap, other_unique_id, reap_by_pid, record_pid, vanished,
};
use crate::error::Error;
use crate::identity::{uniq_fault, ReadPurpose, UniqRead};
use crate::wait::exit_only::seams::force_peek_once;

fn tokio_blocker() -> (crate::tokio::Command, std::io::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::tokio::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    (cmd, writer)
}

/// As the sync twin: the reap lands between the read and the re-read.
///
/// Mutant: `resolve_identity` does not re-read.
#[skuld::test]
async fn macos_tokio_spawn_identity_after_a_real_reap_is_gone() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut cmd, writer) = tokio_blocker();
    let _hook = fault::set_at(SpawnPoint::AfterIdentityRead, move || {
        drop(writer);
        reap_by_pid(fault::spawn_pid());
    });
    let err = match cmd.spawn() {
        Ok(child) => panic!("a child reaped before its re-read was adopted: {:?}", child.id()),
        Err(e) => e,
    };
    assert!(vanished(&err), "a reaped child is Gone, not Unassessable: {err:?}");
}

/// As the sync twin: another unique id at the re-read is `Gone`, and the stranger is not
/// signalled. The child cannot be shown ours, so tokio's `Child` is forgotten, not dropped.
///
/// Mutant: the re-read compares nothing.
#[skuld::test]
async fn macos_tokio_spawn_identity_with_a_different_unique_id_is_gone() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut cmd, _writer) = tokio_blocker();
    let pid = Rc::new(Cell::new(0));
    let armed: Rc<RefCell<Option<uniq_fault::Forced>>> = Rc::default();
    let _hook = fault::set_at(SpawnPoint::AfterIdentityRead, {
        let (pid, armed) = (Rc::clone(&pid), Rc::clone(&armed));
        move || {
            pid.set(fault::spawn_pid());
            let other = other_unique_id(pid.get());
            *armed.borrow_mut() = Some(uniq_fault::force_uniq_read_once(ReadPurpose::Running, other));
        }
    });
    let backend_drops = backend_fault::count_backend_drops();
    let outcome = cmd.spawn();
    drop(armed);
    let err = outcome.expect_err("a pid with another unique id is not the child");
    assert!(vanished(&err), "another unique id is Gone, not Unassessable: {err:?}");
    assert!(exists(pid.get()), "nothing may have signalled or reaped the pid");
    assert_eq!(backend_drops.get(), 0, "tokio's Child must not have been dropped");
    kill_and_reap(pid.get());
}

/// As the sync twin: the failed re-read fails the spawn `Unassessable` and warns. Nothing pins
/// the pid, so the child is left running and unsignalled, and tokio's `Child` is forgotten.
///
/// Mutants: a failed re-read keeps the read; the teardown kills or drops the child (it is gone,
/// or `backend_drops` is 1).
#[skuld::test]
async fn macos_tokio_spawn_identity_with_a_refused_reread_is_unassessable_and_leaves_the_child() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut cmd, _writer) = tokio_blocker();
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
    let forgets = drop_fault::record();
    let backend_drops = backend_fault::count_backend_drops();
    let mark = crate::log_capture::mark();
    let outcome = cmd.spawn();
    drop(armed);
    let err = outcome.expect_err("a refused re-read fails the spawn");
    assert!(
        matches!(err, Error::Unassessable { .. }),
        "a refusal is Unassessable, not a vanish: {err:?}"
    );
    assert!(
        crate::log_capture::contains_since(
            mark,
            "could not be checked against its handle (forced re-read refusal 5d1b)"
        ),
        "the failed re-read is warned at the call, naming its own error"
    );
    assert_eq!(forgets.forgets(), 1, "tokio's Child must have been forgotten");
    assert_eq!(backend_drops.get(), 0, "tokio's Child must not have been dropped");
    assert!(
        exists(pid.get()),
        "the child must be left running, unsignalled and unreaped"
    );
    kill_and_reap(pid.get());
}

/// As the sync twin: no process at the first read is `Gone`, the child is left alone.
///
/// Mutant: the `None` target continues to the identity read.
#[skuld::test]
async fn macos_tokio_spawn_first_read_gone_is_gone_and_leaves_the_child() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut cmd, _writer) = tokio_blocker();
    let pid = Rc::new(Cell::new(0));
    let _hook = record_pid(&pid);
    let _forced = uniq_fault::force_uniq_read_once(ReadPurpose::Adopt, UniqRead::Gone);
    let err = cmd
        .spawn()
        .expect_err("a first read that finds nothing fails the spawn");
    assert!(vanished(&err), "no process is Gone, not Unassessable: {err:?}");
    assert!(exists(pid.get()), "nothing may have signalled or reaped the pid");
    kill_and_reap(pid.get());
}

/// As the sync twin: a refused first read is `Unassessable`, the child is left running.
///
/// Mutant: the refusal maps to `Gone`.
#[skuld::test]
async fn macos_tokio_spawn_first_read_refused_is_unassessable_and_leaves_the_child() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut cmd, _writer) = tokio_blocker();
    let _forced = uniq_fault::force_uniq_read_once(ReadPurpose::Adopt, UniqRead::Refused(libc::EPERM));
    let err = cmd.spawn().expect_err("a refused first read fails the spawn");
    assert!(
        matches!(err, Error::Unassessable { .. }),
        "a refusal is Unassessable, not a vanish: {err:?}"
    );
    // The refused arm returns before any hook; the spawn captured the child it left.
    let Some(crate::identity::Resolved::Found(id)) = fault::take_captured() else {
        panic!("the refused arm must have captured the child's identity")
    };
    assert!(exists(id.pid()), "nothing may have signalled or reaped the pid");
    kill_and_reap(id.pid());
}
