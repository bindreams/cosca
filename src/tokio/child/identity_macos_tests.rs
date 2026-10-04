//! The macOS async spawn's identity check, twin of `child::spawn::identity_macos_tests`.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use super::{drop_fault, fault as backend_fault};
use crate::child::spawn::fault::{self, SpawnPoint};
use crate::child::spawn::identity_macos_tests::{
    arm_launchd_hold, assert_program_did_not_run, end_unsignalled_and_reap, has_not_exited, other_unique_id,
    reap_by_pid, vanished,
};
use crate::child::spawn::unique_report;
use crate::error::Error;
use crate::identity::{uniq_fault, uniq_info, ReadPurpose, UniqRead};
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

/// As the sync twin: another unique id at the re-read is `Gone`. Only the re-read is forced, so the
/// teardown's own verified kill still matches the real child and ends it.
///
/// Mutant: the re-read compares nothing, so the spawn is `Ok`.
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
    let outcome = cmd.spawn();
    drop(armed);
    assert_ne!(pid.get(), 0, "the hook must have run");
    let err = outcome.expect_err("a pid with another unique id is not the child");
    assert!(vanished(&err), "another unique id is Gone, not Unassessable: {err:?}");
}

/// As the sync twin: a launchd hold at the re-read is `Unassessable`, not a vanish.
///
/// Mutant: the launchd hold maps to `Gone`.
#[skuld::test]
async fn macos_tokio_spawn_identity_held_by_launchd_is_unassessable() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut cmd, writer) = tokio_blocker();
    let pid = Rc::new(Cell::new(0));
    let armed: Rc<RefCell<Vec<Box<dyn std::any::Any>>>> = Rc::default();
    let _hook = fault::set_at(SpawnPoint::AfterIdentityRead, {
        let (pid, armed) = (Rc::clone(&pid), Rc::clone(&armed));
        move || arm_launchd_hold(&pid, &armed, writer)
    });
    let outcome = cmd.spawn();
    drop(armed);
    let err = outcome.expect_err("a launchd hold cannot be shown to be ours");
    assert!(
        matches!(err, Error::Unassessable { .. }),
        "a hold by launchd is unverifiable, not a vanish: {err:?}"
    );
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
        has_not_exited(pid.get()),
        "the child must be left running, unsignalled and unreaped"
    );
    end_unsignalled_and_reap(pid.get());
}

/// As the sync twin: the unique id is the child's own report, and no by-pid read is made.
///
/// Mutant: the spawn reads the unique id by pid.
#[skuld::test]
async fn macos_tokio_spawn_takes_the_childs_own_unique_id_and_reads_nothing_by_pid() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut cmd, writer) = tokio_blocker();
    let reads = uniq_fault::record();
    let mut child = cmd.spawn().expect("the child's own report needs no by-pid read");
    assert_eq!(
        reads.purposes(),
        [ReadPurpose::Running],
        "the only by-pid read is the identity check's re-read, none to adopt the id"
    );
    drop(writer);
    child.wait().await.expect("wait");
}

/// As the sync twin: a refused own read is `Unassessable` and the program does not run.
///
/// Mutants: the hook execs anyway; a refusal is mapped to `Ended` (no unreaped-child warning).
#[skuld::test]
async fn macos_tokio_spawn_childs_own_read_refused_is_unassessable_and_the_program_does_not_run() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut cmd, _writer) = tokio_blocker();
    let _forced = unique_report::seams::force_child_read_errno(libc::EPERM);
    let mark = crate::log_capture::mark();
    let err = cmd.spawn().expect_err("a refused own read fails the spawn");
    assert!(
        matches!(err, Error::Unassessable { .. }),
        "a refusal is Unassessable, not a vanish: {err:?}"
    );
    assert_program_did_not_run();
    // Who collected the child is open: std may have returned `Ok` for a child killed after its refusal.
    assert!(
        crate::log_capture::contains_since(mark, "was left unreaped"),
        "a refusal under tokio may leave an unreaped child, and the spawn must say so"
    );
}

/// As the sync twin: a child killed before it reports is a child that died before exec, and
/// tokio's `Child` is forgotten, not reaped by pid.
///
/// Mutant: a missing report is read as an errno.
#[skuld::test]
async fn macos_tokio_spawn_of_a_child_killed_before_its_report_says_it_died_before_exec() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut cmd, _writer) = tokio_blocker();
    let _forced = unique_report::seams::force_child_killed_before_report();
    let backend_drops = backend_fault::count_backend_drops();
    let mark = crate::log_capture::mark();
    let err = cmd.spawn().expect_err("a child that never reported cannot be adopted");
    let Error::Io(e) = &err else {
        panic!("a child that died before exec is an io error, not a refusal: {err:?}")
    };
    assert!(e.to_string().contains("died before exec"), "{e}");
    assert_eq!(backend_drops.get(), 0, "tokio's Child must not be dropped");
    assert!(
        crate::log_capture::contains_since(mark, "died before exec; forgetting"),
        "a dead child is forgotten as a corpse"
    );
    assert!(
        !crate::log_capture::contains_since(mark, "may still be running"),
        "a dead child is not reported as possibly running"
    );
}

/// As the sync twin: the adopted id is the live child's own.
///
/// Mutant: the spawn adopts another process's id.
#[skuld::test]
async fn macos_tokio_spawn_adopts_the_live_childs_own_unique_id() {
    use crate::tokio::child::ProcSource;

    crate::tokio::test_runtime::assert_current_thread();
    let (mut cmd, writer) = tokio_blocker();
    let mut child = cmd.spawn().expect("spawn");
    let UniqRead::Found(info) = uniq_info(child.id().pid(), ReadPurpose::Kill) else {
        panic!("the live child has a unique id")
    };
    let ProcSource::Tokio { identity, .. } = child.proc_mut() else {
        panic!("a fresh child is a tokio backend")
    };
    assert_eq!(*identity, Some(info.unique_id));
    drop(writer);
    child.wait().await.expect("wait");
}

/// As the sync twin, and the abandoned-child warning must not claim a child is left running: a
/// missing report on a failed spawn proves the program never ran.
///
/// Mutant: the failed spawn's warning treats a missing report like a child that may be running.
#[skuld::test]
async fn macos_tokio_spawn_failing_before_the_report_keeps_stds_error_and_does_not_warn_running() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (mut cmd, _writer) = tokio_blocker();
    let _forced = unique_report::seams::force_hook_failure_before_report(libc::ENOENT);
    let mark = crate::log_capture::mark();
    let err = cmd.spawn().expect_err("the hook fails the spawn");
    assert!(
        matches!(&err, Error::Io(e) if e.raw_os_error() == Some(libc::ENOENT)),
        "std's error stays: {err:?}"
    );
    assert!(
        !crate::log_capture::contains_since(mark, "left running"),
        "the program never ran, so nothing is left running"
    );
}
