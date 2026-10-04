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

/// The argv of a program that writes `ran` to its stdout if it runs.
pub(crate) const RAN_ARGV: [&str; 2] = ["/bin/echo", "ran"];

/// A stdout for [`RAN_ARGV`], and the read end of the pipe it writes to.
pub(crate) fn ran_marker() -> (crate::stdio::Stdio, std::io::PipeReader) {
    let (reader, writer) = std::io::pipe().expect("pipe");
    let stdout = crate::stdio::Stdio::from_file(std::fs::File::from(std::os::fd::OwnedFd::from(writer)));
    (stdout, reader)
}

/// Asserts the program of `cmd` did not run: nothing is on `reader` once every copy of the write end
/// has closed. `cmd` is dropped first, since it holds one. A program that ran writes and exits, so
/// the read ends.
pub(crate) fn assert_program_did_not_run(cmd: impl Sized, mut reader: std::io::PipeReader) {
    use std::io::Read;
    drop(cmd);
    let mut out = String::new();
    reader.read_to_string(&mut out).expect("read the marker pipe");
    assert!(out.is_empty(), "the program ran: {out:?}");
}

pub(crate) fn vanished(err: &Error) -> bool {
    matches!(err, Error::Io(e) if e.to_string().contains("reaped by another party"))
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

/// The spawn takes the child's own report and reads the unique id by pid only for the running
/// check.
///
/// Mutant: the spawn reads the unique id by pid (`ReadPurpose::Adopt`), which the recorded read
/// purposes show.
#[skuld::test]
fn macos_sync_spawn_takes_the_childs_own_unique_id_and_reads_its_unique_id_by_pid_only_in_the_running_peek() {
    let (mut cmd, writer) = sync_blocker();
    let reads = uniq_fault::record();
    let child = cmd.spawn().expect("the child's own report needs no by-pid read");
    assert_eq!(
        reads.purposes(),
        [ReadPurpose::Running],
        "the only by-pid read is the identity check's re-read, none to adopt the id"
    );
    drop(writer);
    drop(child);
}

/// The child's own read is refused (forced inside the child): the hook fails before `exec`, so the
/// spawn is `Unassessable` and the program did not run.
///
/// Mutant: the hook execs anyway (the spawn still reports the refusal, but a child is left running).
#[skuld::test]
fn macos_sync_spawn_childs_own_read_refused_is_unassessable_and_the_program_does_not_run() {
    let (stdout, reader) = ran_marker();
    let mut cmd = crate::Command::new();
    cmd.args(RAN_ARGV);
    cmd.stdout(stdout).expect("set stdout");
    let _forced = unique_report::seams::force_child_read_errno(libc::EPERM);
    let err = cmd.spawn().expect_err("a refused own read fails the spawn");
    assert!(
        matches!(err, Error::Unassessable { .. }),
        "a refusal is Unassessable, not a vanish: {err:?}"
    );
    assert_program_did_not_run(cmd, reader);
}

// A child killed before it reports =====

/// A child killed by a signal before it reports makes std return `Ok`; the spawn must say the child
/// died before exec, with no made-up errno, and must not claim it is left running.
///
/// Mutant: a missing report is read as an errno, so the spawn fails `Unassessable` and warns that
/// the child is left running.
#[skuld::test]
fn macos_sync_spawn_of_a_child_killed_before_its_report_says_it_died_before_exec() {
    crate::log_capture::install();
    let (mut cmd, _writer) = sync_blocker();
    let _forced = unique_report::seams::force_child_killed_before_report();
    let mark = crate::log_capture::mark();
    let err = cmd.spawn().expect_err("a child that never reported cannot be adopted");
    let Error::Io(e) = &err else {
        panic!("a child that died before exec is an io error, not a refusal: {err:?}")
    };
    assert!(e.to_string().contains("died before exec"), "{e}");
    assert_eq!(e.raw_os_error(), None, "no errno is made up");
    assert!(
        crate::log_capture::contains_since(mark, "died before exec; nothing is signalled or waited on by pid"),
        "a dead child is abandoned as a corpse"
    );
    assert!(
        !crate::log_capture::contains_since(mark, "may still be running"),
        "a dead child is not reported as possibly running"
    );
}

/// The id the spawn adopts is the unique id of the live child, read from outside.
///
/// Mutant: the spawn adopts another process's id.
#[skuld::test]
fn macos_sync_spawn_adopts_the_live_childs_own_unique_id() {
    let (mut cmd, writer) = sync_blocker();
    let child = cmd.spawn().expect("spawn");
    let UniqRead::Found(info) = uniq_info(child.id().pid(), ReadPurpose::Kill) else {
        panic!("the live child has a unique id")
    };
    assert_eq!(child.adopted_unique(), Some(info.unique_id));
    drop(writer);
    drop(child);
}

/// A spawn that fails before its hook reports (here the hook itself fails) keeps std's own error:
/// the report is missing, and it is not the child's refusal.
///
/// Mutant: a missing report on a failed spawn is mapped to the refusal.
#[skuld::test]
fn macos_sync_spawn_failing_before_the_report_keeps_stds_error() {
    let (mut cmd, _writer) = sync_blocker();
    let _forced = unique_report::seams::force_hook_failure_before_report(libc::ENOENT);
    let err = cmd.spawn().expect_err("the hook fails the spawn");
    assert!(
        matches!(&err, Error::Io(e) if e.raw_os_error() == Some(libc::ENOENT)),
        "std's error stays: {err:?}"
    );
}

/// The spawn consults the child's report before it attaches the containment: a child that died
/// before exec is that, whatever the attach would have said of its pid (with `SIGCHLD` ignored the
/// tree-walk attach finds the zombie gone).
///
/// Mutant: the spawn attaches first, so the forced attach failure is the error.
#[skuld::test]
fn macos_sync_spawn_consults_the_report_before_attaching() {
    let (mut cmd, _writer) = sync_blocker();
    let _killed = unique_report::seams::force_child_killed_before_report();
    fault::set_force_attach_failure(true);
    let err = cmd.spawn().expect_err("a child that never reported cannot be adopted");
    fault::set_force_attach_failure(false);
    assert!(
        matches!(&err, Error::Io(e) if e.to_string().contains("died before exec")),
        "the report decides before the attach does: {err:?}"
    );
}
