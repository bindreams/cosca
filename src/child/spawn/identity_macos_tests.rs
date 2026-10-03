//! The macOS spawn's identity check. macOS has no handle to pin a pid, so the identity read is
//! checked by `peek_verified`, which re-reads the child's unique id, after the read.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use crate::child::spawn::fault::{self, SpawnPoint};
use crate::error::Error;
use crate::identity::{uniq_fault, uniq_info, ReadPurpose, UniqInfo, UniqRead};
use crate::wait::exit_only::seams::force_peek_once;

/// Waits for `pid` (a child of this test) to exit, then reaps it by pid, as a foreign reaper would.
pub(crate) fn reap_by_pid(pid: u32) {
    let mut status = 0;
    // SAFETY: `pid` is this test's own child.
    let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    assert_eq!(reaped, pid as libc::pid_t, "{}", std::io::Error::last_os_error());
}

/// Whether `pid`, a child of this test, is still there (running or an unreaped zombie).
pub(crate) fn exists(pid: u32) -> bool {
    // SAFETY: signal 0 only checks that the pid exists; `pid` is this test's own unreaped child.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// Kills and reaps `pid`, a child of this test the spawn under test left running.
pub(crate) fn kill_and_reap(pid: u32) {
    // SAFETY: `pid` is this test's own unreaped child.
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) }, 0);
    reap_by_pid(pid);
}

pub(crate) fn vanished(err: &Error) -> bool {
    matches!(err, Error::Io(e) if e.to_string().contains("reaped by another party"))
}

/// Records the spawned child's pid when the spawn reaches `BeforeIdentity`.
pub(crate) fn record_pid(pid: &Rc<Cell<u32>>) -> crate::oneshot_hook::Armed {
    let pid = Rc::clone(pid);
    fault::set_at(SpawnPoint::BeforeIdentity, move || pid.set(fault::spawn_pid()))
}

/// A child's unique id that differs from `pid`'s own.
pub(crate) fn other_unique_id(pid: u32) -> UniqRead {
    let UniqRead::Found(info) = uniq_info(pid, ReadPurpose::Kill) else {
        panic!("the child's unique id must be readable")
    };
    UniqRead::Found(UniqInfo {
        unique_id: info.unique_id ^ 1,
    })
}

fn sync_blocker() -> (crate::Command, std::io::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    (cmd, writer)
}

// The re-read =====

/// The reap lands after the identity read and before its re-read, so only the re-read can tell.
/// `waitpid` really reaps, so the re-read answers `Gone` from the OS, with no forced peek.
///
/// Mutant: `resolve_identity` does not re-read, so the stale read stands and the spawn is `Ok`.
#[skuld::test]
fn macos_sync_spawn_identity_after_a_real_reap_is_gone() {
    let (mut cmd, writer) = sync_blocker();
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

/// The pid names a different unique id at the re-read (a reap and a reuse): `Foreign`, so `Gone`.
///
/// Mutant: the re-read compares nothing (`IdCheck::Other` is kept), so the spawn is `Ok`.
#[skuld::test]
fn macos_sync_spawn_identity_with_a_different_unique_id_is_gone() {
    let (mut cmd, _writer) = sync_blocker();
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
    // The stranger is not signalled: the child stays, and this test ends it.
    assert!(exists(pid.get()), "nothing may have signalled or reaped the pid");
    kill_and_reap(pid.get());
}

/// A re-read the OS refuses (forced: the peek fails) cannot show the child ours: the spawn fails
/// `Unassessable`, warns at the call naming the error, and leaves the child running, unsignalled
/// and unreaped.
///
/// Mutants: a failed re-read keeps the read, so the spawn is `Ok`; the call-site warn drops the
/// error.
#[skuld::test]
fn macos_sync_spawn_identity_with_a_refused_reread_is_unassessable() {
    crate::log_capture::install();
    let (mut cmd, _writer) = sync_blocker();
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
    let mark = crate::log_capture::mark();
    let outcome = cmd.spawn();
    drop(armed);
    assert_ne!(pid.get(), 0, "the hook must have run");
    let adopted = outcome.as_ref().ok().map(|child| child.id());
    let left = exists(pid.get());
    if adopted.is_none() {
        kill_and_reap(pid.get());
    }
    let err = outcome.expect_err("a refused re-read fails the spawn");
    assert!(
        matches!(err, Error::Unassessable { .. }),
        "a refusal is Unassessable, not a vanish: {err:?}"
    );
    assert!(left, "the child must be left running, unreaped");
    assert!(
        crate::log_capture::contains_since(
            mark,
            "could not be checked against its handle (forced re-read refusal 5d1b)"
        ),
        "the failed re-read is warned at the call, naming its own error"
    );
}

// The first unique-id read =====

/// The first read finds no process: `Gone`, with the pid never read and the child left alone.
///
/// Mutant: the `Ok(None)` arm continues to the identity read (the spawn is `Ok` or reads the pid).
#[skuld::test]
fn macos_sync_spawn_first_read_gone_is_gone_and_leaves_the_child() {
    let (mut cmd, _writer) = sync_blocker();
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

/// The first read is refused: `Unassessable`, and the child is left running.
///
/// Mutant: the `Err` arm maps to `Gone`.
#[skuld::test]
fn macos_sync_spawn_first_read_refused_is_unassessable_and_leaves_the_child() {
    let (mut cmd, _writer) = sync_blocker();
    let pid = Rc::new(Cell::new(0));
    let _hook = record_pid(&pid);
    let _forced = uniq_fault::force_uniq_read_once(ReadPurpose::Adopt, UniqRead::Refused(libc::EPERM));
    let err = cmd.spawn().expect_err("a refused first read fails the spawn");
    assert!(
        matches!(err, Error::Unassessable { .. }),
        "a refusal is Unassessable, not a vanish: {err:?}"
    );
    assert!(exists(pid.get()), "nothing may have signalled or reaped the pid");
    kill_and_reap(pid.get());
}
