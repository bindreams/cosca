//! The macOS async spawn's identity check, twin of `child::spawn::identity_macos_tests`.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use super::{drop_fault, fault as backend_fault};
use crate::child::spawn::fault::{self, SpawnPoint};
use crate::child::spawn::identity_macos_tests::{
    arm_launchd_hold, assert_program_did_not_run, end_unsignalled_and_reap, has_not_exited, other_unique_id,
    ran_marker, reap_by_pid, vanished, RAN_ARGV,
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
    let (err, fate) = match cmd.spawn() {
        Ok(child) => panic!("a child reaped before its re-read was adopted: {:?}", child.id()),
        Err(e) => crate::child::spawn::failure::expect_may_have_started_with(e),
    };
    assert!(vanished(&err), "a reaped child is Gone, not Unassessable: {err:?}");
    assert_eq!(fate, crate::error::ChildFate::Gone);
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
    crate::wait::exit_only::seams::assert_peeks_exhausted();
    drop(armed);
    assert_ne!(pid.get(), 0, "the hook must have run");
    let (err, fate) = crate::child::spawn::failure::expect_may_have_started_with(
        outcome.expect_err("a pid with another unique id is not the child"),
    );
    assert!(vanished(&err), "another unique id is Gone, not Unassessable: {err:?}");
    // Only the re-read is forced, so the teardown's own verified kill reaches the real child.
    assert_eq!(fate, crate::error::ChildFate::Reaped);
}

/// As the sync twin: a launchd hold at the re-read is `Gone` (it exited, and is not ours to reap),
/// and the fate says so.
///
/// Mutant: the launchd hold maps to `Unknown`, which forgets the child as one that may be running.
#[skuld::test]
async fn macos_tokio_spawn_identity_held_by_launchd_is_gone() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut cmd, writer) = tokio_blocker();
    let pid = Rc::new(Cell::new(0));
    let armed: Rc<RefCell<Vec<Box<dyn std::any::Any>>>> = Rc::default();
    let _hook = fault::set_at(SpawnPoint::AfterIdentityRead, {
        let (pid, armed) = (Rc::clone(&pid), Rc::clone(&armed));
        move || arm_launchd_hold(&pid, &armed, writer)
    });
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let outcome = cmd.spawn();
    drop(armed);
    let (err, fate) = crate::child::spawn::failure::expect_may_have_started_with(
        outcome.expect_err("a launchd hold fails the spawn"),
    );
    assert!(
        matches!(&err, Error::Io(e) if e.to_string().contains("zombie is held")),
        "a hold by launchd has exited, and says its zombie is held: {err:?}"
    );
    assert_eq!(fate, crate::error::ChildFate::Gone, "a launchd-held zombie is gone");
    // The hold and the teardown that forgets the child are one event: one warn.
    let warns: Vec<_> = crate::log_capture::records_since_on_current_thread(mark, "")
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .collect();
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0]
            .1
            .contains(&format!("child {}: launchd holds its zombie", pid.get())),
        "the one warn names the hold and the pid: {warns:?}"
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
    let (err, fate) = crate::child::spawn::failure::expect_may_have_started_with(
        outcome.expect_err("a refused re-read fails the spawn"),
    );
    assert!(
        matches!(err, Error::Unassessable { .. }),
        "a refusal is Unassessable, not a vanish: {err:?}"
    );
    assert_eq!(
        fate,
        crate::error::ChildFate::Running { id: None },
        "the child is left, its identity unread"
    );
    // The failed re-read and the forget that leaves the child are one event: one warn.
    let warns: Vec<_> = crate::log_capture::records_since_on_current_thread(mark, "")
        .into_iter()
        .filter(|(level, _)| *level <= log::Level::Warn)
        .collect();
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0]
            .1
            .contains("could not be checked against its handle (forced re-read refusal 5d1b)")
            && warns[0].1.contains("leaks"),
        "the one warn names the failed re-read and the leak: {warns:?}"
    );
    assert_eq!(forgets.forgets(), 1, "tokio's Child must have been forgotten");
    assert_eq!(backend_drops.get(), 0, "tokio's Child must not have been dropped");
    assert!(
        has_not_exited(pid.get()),
        "the child must be left running, unsignalled and unreaped"
    );
    end_unsignalled_and_reap(pid.get());
}

/// As the sync twin: the unique id is the child's own report, and its only by-pid unique-id read
/// is the running peek's.
///
/// Mutant: the spawn reads the unique id by pid.
#[skuld::test]
async fn macos_tokio_spawn_takes_the_childs_own_unique_id_and_reads_its_unique_id_by_pid_only_in_the_running_peek() {
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
    let (stdout, reader) = ran_marker();
    let mut cmd = crate::tokio::Command::new();
    cmd.args(RAN_ARGV);
    cmd.stdout(stdout).expect("set stdout");
    let _forced = unique_report::seams::force_child_read_errno(libc::EPERM);
    let mark = crate::log_capture::mark();
    let err =
        crate::child::spawn::failure::expect_not_started(cmd.spawn().expect_err("a refused own read fails the spawn"));
    assert!(
        matches!(err, Error::Unassessable { .. }),
        "a refusal is Unassessable, not a vanish: {err:?}"
    );
    assert_program_did_not_run(cmd, reader);
    // Who collected the child is open: std may have returned `Ok` for a child killed after its refusal.
    assert!(
        crate::log_capture::contains_since(mark, "if its spawn did not collect it"),
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
    let err = crate::child::spawn::failure::expect_not_started(
        cmd.spawn().expect_err("a child that never reported cannot be adopted"),
    );
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
    let err = crate::child::spawn::failure::expect_not_started(cmd.spawn().expect_err("the hook fails the spawn"));
    assert!(
        matches!(&err, Error::Io(e) if e.raw_os_error() == Some(libc::ENOENT)),
        "std's error stays: {err:?}"
    );
    assert!(
        !crate::log_capture::contains_since(mark, "left running"),
        "the program never ran, so nothing is left running"
    );
}

/// As the sync twin: the fd marker's root is the verified identity, and the attach reads nothing
/// by pid.
///
/// Mutant: the attach reads the marker's root with `ProcessId::of(pid)`.
#[skuld::test]
async fn macos_tokio_fdmarker_attach_reads_nothing_by_pid() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut cmd, _writer) = tokio_blocker();
    cmd.contain();
    let reads_before_attach = Rc::new(Cell::new(None));
    let _hook = fault::set_at(SpawnPoint::BeforeAttach, {
        let reads = Rc::clone(&reads_before_attach);
        move || reads.set(Some(crate::identity::seams::by_pid_reads()))
    });
    let child = cmd.spawn().expect("spawn");
    assert_eq!(
        Some(crate::identity::seams::by_pid_reads()),
        reads_before_attach.get(),
        "nothing from the attach on may read an identity by pid"
    );
    assert_eq!(
        child.test_marker_root(),
        Some(child.id()),
        "the marker's root is the verified identity"
    );
}

/// As the sync twin: a non-front child whose attach fails is killed and reaped through its verified
/// id, and tokio's `Child` is forgotten, so nothing else reaps it.
///
/// Mutant: the arm leaves the child unreaped.
#[skuld::test]
async fn macos_tokio_a_failed_attach_kills_and_reaps_a_child_that_is_not_a_front() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut cmd, _writer) = tokio_blocker();
    fault::set_force_attach_failure(true);
    let (err, fate) = crate::child::spawn::failure::expect_may_have_started_with(
        cmd.spawn().expect_err("the forced attach failure fails the spawn"),
    );
    fault::set_force_attach_failure(false);
    assert!(matches!(err, Error::Containment { .. }), "{err:?}");
    assert_eq!(
        fate,
        crate::error::ChildFate::Reaped,
        "killed and reaped through its verified id"
    );
    let Some(crate::identity::Resolved::Found(id)) = fault::take_captured() else {
        panic!("the seam captured the child's identity")
    };
    assert!(
        crate::child::spawn::identity_macos_tests::is_reaped(id.pid()),
        "the killed child must have been reaped"
    );
}

/// As the sync twin: a tree-walk root without the fd marker is the verified identity, and the attach
/// reads nothing by pid.
///
/// Mutant: the attach reads the root with `ProcessId::of(pid)`.
#[skuld::test]
async fn macos_tokio_treewalk_attach_reads_nothing_by_pid() {
    crate::tokio::test_runtime::assert_current_thread();
    // The sync command, which the async spawn takes: only it can suppress the fd marker.
    let (stdin, _writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(crate::ContainMode::TreeWalk);
    cmd.suppress_fd_marker();
    let reads_before_attach = Rc::new(Cell::new(None));
    let _hook = fault::set_at(SpawnPoint::BeforeAttach, {
        let reads = Rc::clone(&reads_before_attach);
        move || reads.set(Some(crate::identity::seams::by_pid_reads()))
    });
    let child = crate::tokio::spawn::spawn(&mut cmd).expect("spawn");
    assert_eq!(
        Some(crate::identity::seams::by_pid_reads()),
        reads_before_attach.get(),
        "nothing from the attach on may read an identity by pid"
    );
    assert_eq!(
        child.test_treewalk_root(),
        Some(child.id()),
        "the walk's root is the verified identity"
    );
}

/// Async twin of `macos_sync_spawn_of_an_unreported_child_leaves_it_running_and_says_so`.
#[skuld::test]
async fn macos_tokio_spawn_of_an_unreported_child_leaves_it_running_and_says_so() {
    use crate::child::spawn::identity_macos_tests::{end_unsignalled_and_reap, has_not_exited};
    use crate::elevation::{front::front, ElevatedVia};
    crate::log_capture::install();
    for front in [None, front(Some(&ElevatedVia::MacosOsascript))] {
        let (mut cmd, writer) = tokio_blocker();
        cmd.set_elevation_front(front);
        let mark = crate::log_capture::mark();
        let err = {
            let _unwritten = crate::child::spawn::unique_report::seams::find_the_report_unwritten();
            cmd.spawn().expect_err("an unreported child is not adopted")
        };
        let (err, fate) = crate::child::spawn::failure::expect_may_have_started_with(err);
        // No unique id was read, so no identity names it.
        assert_eq!(
            fate,
            crate::error::ChildFate::Running { id: None },
            "an unreported child is left running"
        );
        let Some(crate::identity::Resolved::Found(id)) = crate::child::spawn::fault::take_captured() else {
            panic!("the spawn captured the child");
        };
        let pid = id.pid();
        assert!(has_not_exited(pid), "the child is left running");
        assert!(
            crate::log_capture::contains_since(mark, &format!("child {pid} had not reported its unique id")),
            "the warning says what happened"
        );
        assert!(
            !crate::log_capture::contains_since(mark, &format!("child {pid} died before exec")),
            "an unreported child is not reported dead"
        );
        assert_eq!(
            err.to_string().contains("it is left unreaped"),
            front.is_some(),
            "only a front is noted: {err}"
        );
        // The writer stays open until the reap: closing it would let the child exit by itself.
        end_unsignalled_and_reap(pid);
        drop(writer);
    }
}
