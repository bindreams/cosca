//! The macOS spawn's identity check. macOS has no handle to pin a pid, so the identity read is
//! checked by `peek_verified`, which re-reads the child's unique id, after the read.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use crate::child::spawn::fault::{self, SpawnPoint};
use crate::child::spawn::unique_report;
use crate::error::Error;
use crate::identity::{ppid_fault, uniq_fault, uniq_info, ReadPurpose, UniqInfo, UniqRead, LAUNCHD};
use crate::wait::exit_only::seams::force_peek_once;

/// Waits for `pid` (a child of this test) to exit, then reaps it by pid, as a foreign reaper would.
pub(crate) fn reap_by_pid(pid: u32) {
    let mut status = 0;
    // SAFETY: `pid` is this test's own child.
    let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    assert_eq!(reaped, pid as libc::pid_t, "{}", std::io::Error::last_os_error());
}

/// Whether `pid`, a child of this test, has not exited: `waitid` finds no exit record, without
/// consuming one. A zombie still answers `kill(pid, 0)`, so only this tells a signalled child from
/// an unsignalled one: the blocker exits only when killed or when its stdin closes, and the tests
/// hold its writer.
pub(crate) fn has_not_exited(pid: u32) -> bool {
    // SAFETY: an all-zero `siginfo_t` is valid, and `waitid` writes only into it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `pid` is this test's own child; `WNOWAIT` consumes nothing.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    assert_eq!(rc, 0, "waitid: {}", std::io::Error::last_os_error());
    info.si_pid == 0
}

/// Ends and reaps `pid`, a child of this test the spawn under test left running, and asserts that
/// nothing but this test signalled it. The first fatal signal fixes a process's status, and a
/// signal the spawn under test sent would have been delivered before the spawn returned, so a
/// `SIGUSR1` status shows no earlier signal reached the child. (An exit check cannot: a kill is
/// delivered asynchronously, so the child may not have exited yet when it is looked at.)
pub(crate) fn end_unsignalled_and_reap(pid: u32) {
    // SAFETY: `pid` is this test's own unreaped child.
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGUSR1) }, 0);
    let mut status = 0;
    // SAFETY: `pid` is this test's own child.
    let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    assert_eq!(reaped, pid as libc::pid_t, "{}", std::io::Error::last_os_error());
    assert!(
        libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGUSR1,
        "something other than the test signalled the child before it did: status {status:#x}"
    );
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
    assert!(
        has_not_exited(pid.get()),
        "nothing may have signalled or reaped the pid"
    );
    end_unsignalled_and_reap(pid.get());
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
    let left = has_not_exited(pid.get());
    if adopted.is_none() {
        end_unsignalled_and_reap(pid.get());
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

/// At the re-read the child answers `ECHILD` (the test reaped it) yet its pid still names it, held
/// by launchd (forced): a dead tracer's tracee in transit. That is neither a reap nor ours, so it
/// is `Unassessable` with a warn naming the pid, not "reaped by another party".
///
/// Mutant: the launchd hold maps to `Gone` (the spawn fails as reaped by another party).
#[skuld::test]
fn macos_sync_spawn_identity_held_by_launchd_is_unassessable() {
    crate::log_capture::install();
    let (mut cmd, writer) = sync_blocker();
    let pid = Rc::new(Cell::new(0));
    let armed: Rc<RefCell<Vec<Box<dyn std::any::Any>>>> = Rc::default();
    let _hook = fault::set_at(SpawnPoint::AfterIdentityRead, {
        let (pid, armed) = (Rc::clone(&pid), Rc::clone(&armed));
        move || arm_launchd_hold(&pid, &armed, writer)
    });
    let mark = crate::log_capture::mark();
    let outcome = cmd.spawn();
    drop(armed);
    let err = outcome.expect_err("a launchd hold cannot be shown to be ours");
    assert!(
        matches!(err, Error::Unassessable { .. }),
        "a hold by launchd is unverifiable, not a vanish: {err:?}"
    );
    assert!(
        crate::log_capture::contains_since(mark, &format!("child {}: launchd holds it", pid.get())),
        "the hold is warned at the call, naming the pid"
    );
}

/// Reaps the child by pid (so the re-read's `waitid` answers `ECHILD`) and forces the id and parent
/// reads that follow to say launchd holds it.
pub(crate) fn arm_launchd_hold(
    pid: &Rc<Cell<u32>>,
    armed: &Rc<RefCell<Vec<Box<dyn std::any::Any>>>>,
    writer: std::io::PipeWriter,
) {
    pid.set(fault::spawn_pid());
    let UniqRead::Found(info) = uniq_info(pid.get(), ReadPurpose::Kill) else {
        panic!("the child's unique id must be readable")
    };
    drop(writer);
    reap_by_pid(pid.get());
    let mut armed = armed.borrow_mut();
    for _ in 0..2 {
        armed.push(Box::new(uniq_fault::force_uniq_read_once(
            ReadPurpose::Echild,
            UniqRead::Found(info),
        )));
    }
    armed.push(Box::new(ppid_fault::force_ppid_once(Ok(LAUNCHD))));
}

// The child's own unique-id read =====

/// The unique id is the child's own report, not a read by pid: a by-pid read made to fail is never
/// reached, and the spawn still succeeds with an id that the re-read confirms.
///
/// Mutant: the spawn reads the unique id by pid (`ReadPurpose::Adopt`), so the forced refusal is
/// consumed and the spawn fails.
#[skuld::test]
fn macos_sync_spawn_takes_the_childs_own_unique_id_and_reads_nothing_by_pid() {
    let (mut cmd, writer) = sync_blocker();
    let _forced = uniq_fault::force_uniq_read_once(ReadPurpose::Adopt, UniqRead::Refused(libc::EPERM));
    let child = cmd.spawn().expect("the child's own report needs no by-pid read");
    assert_eq!(
        uniq_fault::unconsumed(ReadPurpose::Adopt),
        1,
        "nothing may have read the unique id by pid"
    );
    drop(writer);
    drop(child);
}

/// The child's own read is refused (forced inside the child): `Unassessable`, and the child is left
/// running, unsignalled and unreaped.
///
/// Mutant: the refusal maps to `Gone`, or the report is ignored; the unverified child is killed.
#[skuld::test]
fn macos_sync_spawn_childs_own_read_refused_is_unassessable_and_leaves_the_child() {
    let (mut cmd, _writer) = sync_blocker();
    let pid = Rc::new(Cell::new(0));
    let _hook = record_pid(&pid);
    let _forced = unique_report::seams::force_child_read_errno(libc::EPERM);
    let err = cmd.spawn().expect_err("a refused own read fails the spawn");
    assert!(
        matches!(err, Error::Unassessable { .. }),
        "a refusal is Unassessable, not a vanish: {err:?}"
    );
    assert!(
        has_not_exited(pid.get()),
        "nothing may have signalled or reaped the pid"
    );
    end_unsignalled_and_reap(pid.get());
}
