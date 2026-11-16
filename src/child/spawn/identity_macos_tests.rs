//! The macOS spawn's identity check. macOS has no handle to pin a pid, so the identity read is
//! checked by `peek_verified`, which re-reads the child's unique id, after the read.

use std::cell::{Cell, RefCell};

use crate::test_child::Console;
use std::rc::Rc;
use std::sync::Arc;

use crate::child::spawn::fault::{self, SpawnPoint};
use crate::child::spawn::unique_report;
use crate::error::Error;
use crate::identity::{short_info, FakeKernel, HostKernel, Kernel, UniqInfo, UniqRead, LAUNCHD};

/// [`Command::spawn`](crate::Command::spawn) over `kernel`, the one the spawn and its box ask: a test
/// that states rows after the child exists keeps a clone of it.
pub(crate) fn spawn_over(
    cmd: &mut crate::Command,
    kernel: impl Kernel + Send + 'static,
) -> Result<crate::Child, Error> {
    Ok(crate::child::spawn::spawn_with(cmd, kernel)?)
}

/// Waits for `pid` (a child of this test) to exit, then reaps it by pid, as a foreign reaper would.
pub(crate) fn reap_by_pid(pid: u32) {
    let mut status = 0;
    // SAFETY: `pid` is this test's own child.
    let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    assert_eq!(reaped, pid as libc::pid_t, "{}", std::io::Error::last_os_error());
}

pub(crate) use crate::test_child::has_not_exited;

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
    let UniqRead::Found(info) = HostKernel.unique_info(pid) else {
        panic!("the child's unique id must be readable")
    };
    UniqRead::Found(UniqInfo {
        unique_id: info.unique_id ^ 1,
        ..info
    })
}

pub(crate) fn sync_blocker() -> (crate::Command, crate::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::test_child::command(Console::Hidden);
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
    let (err, fate) = match cmd.spawn() {
        Ok(child) => panic!("a child reaped before its re-read was adopted: {:?}", child.id()),
        Err(e) => crate::child::spawn::failure::expect_may_have_started_with(e),
    };
    assert!(vanished(&err), "a reaped child is Gone, not Unassessable: {err:?}");
    assert_eq!(fate, crate::error::ChildFate::Gone);
}

/// The pid names a different unique id at the re-read (a reap and a reuse): `Foreign`, so `Gone`, and
/// the teardown that follows sends the pid nothing. The child is really reaped, as the reuse needs:
/// the id the pid then names is a row of the spawn's kernel, the re-read's.
///
/// Mutant: the look at the reaped child's pid takes a different unique id (`Held::Other`) for the
/// child's own, so the spawn is `Ok`.
#[skuld::test]
fn macos_sync_spawn_identity_with_a_different_unique_id_is_gone() {
    let (mut cmd, writer) = sync_blocker();
    let pid = Rc::new(Cell::new(0));
    let kernel = Arc::new(FakeKernel::over(&HostKernel));
    let _hook = fault::set_at(SpawnPoint::AfterIdentityRead, {
        let (pid, kernel) = (Rc::clone(&pid), Arc::clone(&kernel));
        move || {
            pid.set(fault::spawn_pid());
            let other = other_unique_id(pid.get());
            drop(writer);
            reap_by_pid(pid.get());
            kernel.state_unique_info(pid.get(), other);
        }
    });
    let sent = crate::send_log::Capture::start();
    let outcome = spawn_over(&mut cmd, Arc::clone(&kernel));
    assert_ne!(pid.get(), 0, "the hook must have run");
    let (err, fate) = crate::child::spawn::failure::expect_may_have_started_with(
        outcome.expect_err("a pid with another unique id is not the child"),
    );
    assert!(vanished(&err), "another unique id is Gone, not Unassessable: {err:?}");
    assert_eq!(fate, crate::error::ChildFate::Gone);
    assert_eq!(sent.entries(), [], "nothing is sent to a pid that is not the child");
}

/// A re-read the OS refuses (forced: the peek fails) cannot show the child ours, but the spawn does
/// not end it: the uncontained child is kept with no identity, unsignalled and unreaped, and the
/// spawn warns naming the error.
///
/// Mutants: the spawn fails, or leaves the child unadopted; the warn drops the error.
#[skuld::test]
fn macos_sync_spawn_identity_with_a_refused_reread_keeps_the_child_without_an_identity() {
    crate::log_capture::install();
    let (mut cmd, _writer) = sync_blocker();
    let pid = Rc::new(Cell::new(0));
    let kernel = Arc::new(FakeKernel::over(&HostKernel));
    let _hook = fault::set_at(SpawnPoint::AfterIdentityRead, {
        let (pid, kernel) = (Rc::clone(&pid), Arc::clone(&kernel));
        move || {
            pid.set(fault::spawn_pid());
            kernel.state_peek(pid.get(), Err(std::io::Error::other("forced re-read refusal 5d1b")));
        }
    });
    let mark = crate::log_capture::mark();
    let outcome = spawn_over(&mut cmd, Arc::clone(&kernel));
    assert_ne!(pid.get(), 0, "the hook must have run");
    assert!(kernel.all_rows_taken(), "the re-read's peek was the refused one");
    let child = outcome.expect("a refused re-read keeps the child");
    assert_eq!(
        child.id(),
        None,
        "the read could not be checked, so the child has no identity"
    );
    assert_eq!(child.pid(), pid.get(), "the pid is the spawned child's");
    assert!(has_not_exited(pid.get()), "the child must be left running, unreaped");
    // A kept child warns nothing: the failed re-read is logged once, at debug.
    let warns = crate::log_capture::warns_since(mark, "");
    assert!(warns.is_empty(), "{warns:?}");
    let noted = crate::log_capture::records_since_on_current_thread(mark, "forced re-read refusal 5d1b");
    assert!(
        matches!(&noted[..], [(log::Level::Debug, line)]
            if line.contains("could not be checked against its handle (forced re-read refusal 5d1b)")),
        "one debug record names the failed re-read: {noted:?}"
    );
    // A kept child is killed through its handle like any other.
    child.kill().expect("a kept child is killed through its unique id");
    child.wait().expect("a kept child is waited on");
}

/// A contained root names its tree by its identity (the fd marker), so a re-read the OS refuses fails
/// the spawn with the read's own error (`Unassessable`), and the child is killed and reaped through
/// its verified unique id.
///
/// Mutant: the contained spawn is kept without a marker root.
#[skuld::test]
fn macos_sync_spawn_identity_with_a_refused_reread_fails_a_contained_spawn_and_ends_the_child() {
    crate::log_capture::install();
    let (mut cmd, _writer) = sync_blocker();
    cmd.contain_with(crate::ContainMode::Session);
    let pid = Rc::new(Cell::new(0));
    let kernel = Arc::new(FakeKernel::over(&HostKernel));
    let _hook = fault::set_at(SpawnPoint::AfterIdentityRead, {
        let (pid, kernel) = (Rc::clone(&pid), Arc::clone(&kernel));
        move || {
            pid.set(fault::spawn_pid());
            kernel.state_peek(pid.get(), Err(std::io::Error::other("forced re-read refusal 2f9a")));
        }
    });
    let outcome = spawn_over(&mut cmd, Arc::clone(&kernel));
    assert_ne!(pid.get(), 0, "the hook must have run");
    assert!(kernel.all_rows_taken(), "the re-read's peek was the refused one");
    let (err, fate) = crate::child::spawn::failure::expect_may_have_started_with(
        outcome.expect_err("a contained spawn without an identity fails"),
    );
    assert!(
        matches!(err, Error::Unassessable { .. }),
        "a refusal is Unassessable, not a vanish: {err:?}"
    );
    assert_eq!(
        fate,
        crate::error::ChildFate::Reaped,
        "the unique id pins the child, so it is reaped"
    );
}

/// Spawns a blocker contained by `mode`, launched by `front`, whose identity re-read finds the pid
/// holding another unique id (a reap and a reuse), so the child is `Gone`: its pid, and the warns the
/// spawn logged. The child is really reaped, as the reuse needs: the id the pid then names is a row of
/// the spawn's kernel.
fn foreign_reread_warns(
    mode: crate::ContainMode,
    elevation: Option<crate::elevation::ElevationReport>,
) -> (u32, Vec<String>) {
    crate::log_capture::install();
    let (mut cmd, writer) = sync_blocker();
    cmd.contain_with(mode);
    cmd.set_elevation_report(elevation);
    let pid = Rc::new(Cell::new(0));
    let kernel = Arc::new(FakeKernel::over(&HostKernel));
    let _hook = fault::set_at(SpawnPoint::AfterIdentityRead, {
        let (pid, kernel) = (Rc::clone(&pid), Arc::clone(&kernel));
        move || {
            pid.set(fault::spawn_pid());
            let other = other_unique_id(pid.get());
            drop(writer);
            reap_by_pid(pid.get());
            kernel.state_unique_info(pid.get(), other);
        }
    });
    let mark = crate::log_capture::mark();
    let outcome = spawn_over(&mut cmd, kernel);
    assert_ne!(pid.get(), 0, "the hook must have run");
    let _ = outcome.expect_err("a pid with another unique id fails the spawn");
    (pid.get(), crate::log_capture::warns_since(mark, ""))
}

/// A spawn whose identity re-read finds another process leaves a session root unsignalled. macOS has
/// no exact kill of its process group, so the one warn also says the group's members may be left
/// running.
///
/// Mutant: the group's note is dropped.
#[skuld::test]
fn macos_sync_spawn_identity_failure_of_a_group_root_warns_that_its_members_may_be_left_running() {
    let (pid, warns) = foreign_reread_warns(crate::ContainMode::Session, None);
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains(&format!(
            "members of the process group of pid {pid} may be left running"
        )),
        "the one warn says the group's members may be left running: {warns:?}"
    );
}

/// Whether any of `warns` says a process group's members may be left running.
fn notes_a_group(warns: &[String]) -> bool {
    warns.iter().any(|text| text.contains("members of the process group"))
}

/// A tree walk's root leads no group of its own, so the cleanup notes none. Mutant: the note is
/// made for any root.
#[skuld::test]
fn macos_sync_spawn_identity_failure_under_a_tree_walk_notes_no_group() {
    let (_, warns) = foreign_reread_warns(crate::ContainMode::TreeWalk, None);
    assert!(!notes_a_group(&warns), "{warns:?}");
}

/// A nested spawn (the marker is in the environment) leads no group of its own, so the cleanup
/// notes none. Runs in a process of its own, since the marker is process-wide. Mutant: the note is
/// made for a nested root.
#[skuld::test]
fn macos_sync_spawn_identity_failure_of_a_nested_root_notes_no_group() {
    use crate::test_own_process::{own_process, test_path};
    use crate::test_spawn::spawn;

    let Some(_done) = own_process(
        test_path!(macos_sync_spawn_identity_failure_of_a_nested_root_notes_no_group),
        spawn,
    ) else {
        return;
    };
    std::env::set_var(crate::containment::NESTED_ENV, "1");
    let (_, warns) = foreign_reread_warns(crate::ContainMode::Session, None);
    assert!(!notes_a_group(&warns), "{warns:?}");
}

/// An elevation front's group is not its containment, and the front is sent nothing, so the cleanup
/// notes no group. Mutant: the front check before the note is dropped.
#[skuld::test]
fn macos_sync_spawn_identity_failure_of_a_front_notes_no_group() {
    let sudo = crate::child::front_kill_tests::sudo_report();
    assert!(sudo.as_ref().and_then(|r| r.front()).is_some(), "sudo launches a front");
    let (_, warns) = foreign_reread_warns(crate::ContainMode::Session, sudo);
    assert!(!notes_a_group(&warns), "{warns:?}");
}

/// At the re-read the child answers `ECHILD` (the test reaped it) yet its pid still names it, held
/// by launchd (stated): a dead tracer's tracee in transit. That is neither a reap nor ours, so it
/// is `Gone` (it exited, and is not ours to reap) with a warn naming the pid, and the error says its
/// zombie is held.
///
/// Mutant: the launchd hold maps to `Unknown`, so the spawn answers `Unassessable` and a fate that
/// claims the child may be running.
#[skuld::test]
fn macos_sync_spawn_identity_held_by_launchd_is_gone() {
    crate::log_capture::install();
    let (mut cmd, writer) = sync_blocker();
    let pid = Rc::new(Cell::new(0));
    let kernel = Arc::new(FakeKernel::over(&HostKernel));
    let _hook = fault::set_at(SpawnPoint::AfterIdentityRead, {
        let (pid, kernel) = (Rc::clone(&pid), Arc::clone(&kernel));
        move || arm_launchd_hold(&pid, &kernel, writer)
    });
    let mark = crate::log_capture::mark();
    let outcome = spawn_over(&mut cmd, kernel);
    let (err, fate) = crate::child::spawn::failure::expect_may_have_started_with(
        outcome.expect_err("a launchd hold fails the spawn"),
    );
    assert!(
        matches!(&err, Error::Io(e) if e.to_string().contains("zombie is held")),
        "a hold by launchd has exited, and says its zombie is held: {err:?}"
    );
    assert_eq!(fate, crate::error::ChildFate::Gone, "a launchd-held zombie is gone");
    // The hold and the teardown that leaves the child are one event: one warn.
    let warns = crate::log_capture::warns_since(mark, "");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].contains(&format!("child {}: launchd holds its zombie", pid.get()))
            && warns[0].contains("reaped by someone else"),
        "the one warn names the hold and the pid, and what became of the child: {warns:?}"
    );
}

/// Reaps the child by pid (so the re-read's `waitid` answers `ECHILD`) and states the id and parent
/// reads that follow as saying launchd holds it.
pub(crate) fn arm_launchd_hold(pid: &Rc<Cell<u32>>, kernel: &FakeKernel<'_>, writer: crate::PipeWriter) {
    pid.set(fault::spawn_pid());
    let UniqRead::Found(info) = HostKernel.unique_info(pid.get()) else {
        panic!("the child's unique id must be readable")
    };
    drop(writer);
    reap_by_pid(pid.get());
    kernel.state_unique_info(pid.get(), UniqRead::Found(info));
    kernel.state_short_bsd(pid.get(), Ok(short_info(LAUNCHD, libc::SRUN)));
    kernel.state_unique_info(pid.get(), UniqRead::Found(info));
}

// The child's own unique-id read =====

/// The spawn takes the child's own report and reads the unique id by pid only for the running
/// check.
///
/// Mutant: the spawn reads the unique id by pid to adopt it, which the count of the kernel's
/// unique-id reads of the child shows.
#[skuld::test]
fn macos_sync_spawn_takes_the_childs_own_unique_id_and_reads_its_unique_id_by_pid_only_in_the_running_peek() {
    let (mut cmd, writer) = sync_blocker();
    let kernel = Arc::new(FakeKernel::over(&HostKernel));
    let child = spawn_over(&mut cmd, Arc::clone(&kernel)).expect("the child's own report needs no by-pid read");
    assert_eq!(
        kernel.unique_info_reads(child.pid()),
        1,
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
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(RAN_ARGV);
    cmd.stdout(stdout).expect("set stdout");
    let _forced = unique_report::seams::force_child_read_errno(libc::EPERM);
    let err =
        crate::child::spawn::failure::expect_not_started(cmd.spawn().expect_err("a refused own read fails the spawn"));
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
    let err = crate::child::spawn::failure::expect_not_started(
        cmd.spawn().expect_err("a child that never reported cannot be adopted"),
    );
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

/// The id the spawn adopts is the unique id of the live child: a kill passes the id check, and is
/// sent. The blocker is released only after the kill, so a kill that sent nothing exits `0`.
///
/// Mutant: the spawn adopts another process's id, so the kill finds the pid taken and sends nothing.
#[skuld::test]
fn macos_sync_spawn_adopts_the_live_childs_own_unique_id() {
    let (mut cmd, writer) = sync_blocker();
    let child = cmd.spawn().expect("spawn");
    let sent = crate::send_log::Capture::start();
    child.kill().expect("kill");
    assert_eq!(
        sent.entries(),
        [(child.pid(), crate::signal::Sig::Kill, crate::send_log::Via::Identity)]
    );
    drop(sent);
    drop(writer);
    child.wait().expect("reap the killed child");
}

/// A spawn that fails before its hook reports (here the hook itself fails) keeps std's own error:
/// the report is missing, and it is not the child's refusal.
///
/// Mutant: a missing report on a failed spawn is mapped to the refusal.
#[skuld::test]
fn macos_sync_spawn_failing_before_the_report_keeps_stds_error() {
    let (mut cmd, _writer) = sync_blocker();
    let _forced = unique_report::seams::force_hook_failure_before_report(libc::ENOENT);
    let err = crate::child::spawn::failure::expect_not_started(cmd.spawn().expect_err("the hook fails the spawn"));
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
    let err = crate::child::spawn::failure::expect_not_started(
        cmd.spawn().expect_err("a child that never reported cannot be adopted"),
    );
    fault::set_force_attach_failure(false);
    assert!(
        matches!(&err, Error::Io(e) if e.to_string().contains("died before exec")),
        "the report decides before the attach does: {err:?}"
    );
}

// The attach =====

/// The fd marker's root is the identity the spawn verified: the attach reads nothing by pid, so a
/// foreign reap and reuse of the pid cannot make the marker's root a stranger.
///
/// Mutant: the attach reads the marker's root with `ProcessId::of(pid)`.
#[skuld::test]
fn macos_fdmarker_attach_reads_nothing_by_pid() {
    let (mut cmd, _writer) = sync_blocker();
    cmd.contain();
    let kernel = Arc::new(FakeKernel::over(&HostKernel));
    let reads_before_attach = Rc::new(Cell::new(None));
    let _hook = fault::set_at(SpawnPoint::BeforeAttach, {
        let (reads, kernel) = (Rc::clone(&reads_before_attach), Arc::clone(&kernel));
        move || reads.set(Some(kernel.all_record_reads()))
    });
    let child = spawn_over(&mut cmd, Arc::clone(&kernel)).expect("spawn");
    assert_eq!(
        Some(kernel.all_record_reads()),
        reads_before_attach.get(),
        "nothing from the attach on may read an identity by pid"
    );
    assert_eq!(
        child.test_marker_root(),
        child.id(),
        "the marker's root is the verified identity"
    );
}

// The attach-failure teardown =====
//
// A failed spawn's teardown is `OwnedChild::tear_down` over the child's `MacosChild`, which the
// `owned_tests` and `held_teardown_tests` state through their rows; what is left here is what the
// spawn decides.

/// A `std` blocker and its unique id. A test that hands the child to the code under test takes it
/// out of its guard with `StdChild::into_parts`.
pub(crate) fn std_blocker_with_unique() -> (crate::test_child::StdChild, u64) {
    let child = crate::test_child::blocker();
    let Ok(Some(unique)) = crate::signal::read_identity(&HostKernel, child.id()) else {
        panic!("the blocker's unique id must be readable")
    };
    (child, unique)
}

/// Whether `pid` is still an exit record this process can reap (`ECHILD` once something took it).
pub(crate) fn is_reaped(pid: u32) -> bool {
    let mut status = 0;
    // SAFETY: `pid` is this test's own child; `WNOHANG` never blocks.
    let rc = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
    rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
}

/// The answer of the id read a kill makes of a child, refused: the kill sends nothing and leaves the
/// child running.
pub(crate) const REFUSED_KILL_READ: UniqRead = UniqRead::Refused(libc::EPERM);

/// A child whose kill is refused, after its attach failed, is handed back in the error, still running,
/// as a Linux child is; the error is the attach's own.
///
/// Mutants: the child is left running with a warn and no hand-back; it is dropped.
#[skuld::test]
fn macos_a_failed_attach_whose_kill_is_refused_hands_the_child_back() {
    let (mut cmd, writer) = sync_blocker();
    let kernel = Arc::new(FakeKernel::over(&HostKernel));
    let _refused = fault::set_at(SpawnPoint::BeforeAttach, {
        let kernel = Arc::clone(&kernel);
        move || kernel.state_unique_info(fault::spawn_pid(), REFUSED_KILL_READ)
    });
    fault::set_force_attach_failure(true);
    let error = spawn_over(&mut cmd, Arc::clone(&kernel)).expect_err("the forced attach failure fails the spawn");
    fault::set_force_attach_failure(false);
    assert!(kernel.all_rows_taken(), "the kill made its id read");
    let (cause, fate, handed_back) = crate::test_child::expect_handed_back(error, writer);
    assert!(matches!(cause, Error::Containment { .. }), "{cause:?}");
    assert!(
        matches!(fate, crate::error::ChildFate::Running { id: Some(_) }),
        "{fate:?}"
    );
    // The handed-back child exits once released, by itself: the refused kill sent nothing.
    let status = handed_back.wait();
    assert!(status.success(), "the child was signalled: {status:?}");
}

/// A non-front child whose attach fails (which only a seam makes it do) is killed and reaped through
/// its verified unique id, and the error is the attach's own.
///
/// Mutant: the arm leaves the child unreaped, as an unverified one is left.
#[skuld::test]
fn macos_a_failed_attach_kills_and_reaps_a_child_that_is_not_a_front() {
    let (mut cmd, _writer) = sync_blocker();
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
    assert!(is_reaped(id.pid()), "the killed child must have been reaped");
}

/// A tree-walk root without the fd marker is the identity the spawn verified, and the attach reads
/// nothing by pid.
///
/// Mutant: the attach reads the root with `ProcessId::of(pid)`.
#[skuld::test]
fn macos_treewalk_attach_reads_nothing_by_pid() {
    let (mut cmd, _writer) = sync_blocker();
    cmd.contain_with(crate::ContainMode::TreeWalk);
    cmd.suppress_fd_marker();
    let kernel = Arc::new(FakeKernel::over(&HostKernel));
    let reads_before_attach = Rc::new(Cell::new(None));
    let _hook = fault::set_at(SpawnPoint::BeforeAttach, {
        let (reads, kernel) = (Rc::clone(&reads_before_attach), Arc::clone(&kernel));
        move || reads.set(Some(kernel.all_record_reads()))
    });
    let child = spawn_over(&mut cmd, Arc::clone(&kernel)).expect("spawn");
    assert_eq!(
        Some(kernel.all_record_reads()),
        reads_before_attach.get(),
        "nothing from the attach on may read an identity by pid"
    );
    assert_eq!(
        child.test_treewalk_root(),
        child.id(),
        "the walk's root is the verified identity"
    );
}

const REFUSED_KQUEUE_MARKER: &str = "COSCA_TESTCFG_SPAWN_KQUEUE";
// The case a fixture re-exec runs; the tests of one case ignore it.
const REFUSED_KQUEUE_CASE_ENV: &str = "COSCA_TESTCFG_SPAWN_KQUEUE_CASE";

/// The spawn's stated limit: a child whose exit watch cannot be armed (the kqueue is refused,
/// `EMFILE`) has no box. The spawn sends it `SIGKILL` through its unique id, says in a `warn` that it
/// has no handle and is not reaped, and fails with the refusal; the zombie stays until this process
/// reaps it. The descriptor limit is lowered right before the spawn builds its `MacosChild`, once the
/// spawn has closed every descriptor it held for the report, so the first kqueue the box makes is
/// refused; it is process-wide, so the case runs in a fresh re-exec.
///
/// Mutants: the child is left running (it exits cleanly of its stdin's EOF below); the warn is
/// dropped or does not say the tree is not killed; the error is not the refusal.
#[skuld::test]
fn macos_a_spawn_whose_kqueue_is_refused_kills_the_child_by_its_unique_id_and_says_so() {
    if !crate::test_child::is_marked_fixture_reexec(REFUSED_KQUEUE_MARKER) {
        crate::test_child::run_fixture_case(
            crate::test_child::fixture_path!(
                macos_a_spawn_whose_kqueue_is_refused_kills_the_child_by_its_unique_id_and_says_so
            ),
            REFUSED_KQUEUE_MARKER,
            REFUSED_KQUEUE_CASE_ENV,
            "",
        );
        return;
    }
    let (cmd, writer) = sync_blocker();
    let refused = refused_kqueue_spawn(cmd, || (), writer, Refusing::KILLS);
    assert!(refused.warn.contains("its tree was not killed"), "{}", refused.warn);
}

/// The same limit for a contained child with a marker: the spawn also sweeps the marker's holders, by
/// the marker alone, so a descendant that holds it dies, and the warn says that the rest of the tree
/// was not killed.
///
/// Mutants: the marker's holders are not swept (the descendant survives); the warn says nothing of
/// the sweep.
#[skuld::test]
fn macos_a_spawn_whose_kqueue_is_refused_sweeps_the_marker_holders_of_its_tree() {
    if !crate::test_child::is_marked_fixture_reexec(REFUSED_KQUEUE_MARKER) {
        crate::test_child::run_fixture_case(
            crate::test_child::fixture_path!(
                macos_a_spawn_whose_kqueue_is_refused_sweeps_the_marker_holders_of_its_tree
            ),
            REFUSED_KQUEUE_MARKER,
            REFUSED_KQUEUE_CASE_ENV,
            "",
        );
        return;
    }
    let (cmd, tree) = tree_spawn();
    // The grandchild runs, so it holds the marker, before the limit is lowered.
    let refused = refused_kqueue_spawn(cmd, await_grandchild_before(&tree), (), Refusing::KILLS);
    let tree = tree.borrow_mut().take().expect("the tree");
    assert!(!tree.grandchild_survived(), "the marker's holders are swept");
    assert!(
        refused.warn.contains("its marker's holders were killed") && refused.warn.contains("the rest of its tree"),
        "{}",
        refused.warn
    );
}

/// The cases of [`macos_a_spawn_whose_kqueue_is_refused_ends_the_child_as_the_limit_states`], one per
/// fresh re-exec: the descriptor limit is process-wide.
const REFUSED_KQUEUE_CASES: [&str; 5] = [
    "front",
    "late",
    "kill refused",
    "kill finds it gone",
    "holders sweep fails",
];

/// Each way the stated limit's child ends, in fate, cause, `cleanup` and warn: an elevation front is
/// sent nothing and its marker is not swept; a child whose id came late is the late report's error,
/// with the refusal in `cleanup`, and is worded as late; a kill the kernel refuses leaves the child
/// `Running` with the refusal in `cleanup`; a kill that finds the child gone is `Gone` and sent
/// nothing; a holders' sweep that fails leaves its failure in `cleanup` and says so.
///
/// Mutants: a front is killed or its marker swept; the late child is worded as an unlate one, or its
/// refusal is the cause; a refused kill is answered `Killed` or left out of `cleanup`; `Gone` is
/// answered `Killed`; a failed holders' sweep is answered as a clean one.
#[skuld::test]
fn macos_a_spawn_whose_kqueue_is_refused_ends_the_child_as_the_limit_states() {
    if !crate::test_child::is_marked_fixture_reexec(REFUSED_KQUEUE_MARKER) {
        for case in REFUSED_KQUEUE_CASES {
            crate::test_child::run_fixture_case(
                crate::test_child::fixture_path!(
                    macos_a_spawn_whose_kqueue_is_refused_ends_the_child_as_the_limit_states
                ),
                REFUSED_KQUEUE_MARKER,
                REFUSED_KQUEUE_CASE_ENV,
                case,
            );
        }
        return;
    }
    let case = std::env::var(REFUSED_KQUEUE_CASE_ENV).expect("the re-exec names its case");
    match case.as_str() {
        "front" => refused_kqueue_of_a_front(),
        "late" => refused_kqueue_of_a_late_child(),
        "kill refused" => refused_kqueue_whose_kill_is_refused(),
        "kill finds it gone" => refused_kqueue_whose_kill_finds_the_child_gone(),
        "holders sweep fails" => refused_kqueue_whose_holders_sweep_fails(),
        other => panic!("no case {other:?}"),
    }
}

/// The text of each of `errors`, as [`crate::error::said`] has it.
fn said_of(errors: &[&Error]) -> Vec<String> {
    errors.iter().map(|e| crate::error::said(*e)).collect()
}

fn refused_kqueue_of_a_front() {
    let (mut cmd, tree) = tree_spawn();
    cmd.set_elevation_report(crate::child::front_kill_tests::sudo_report());
    let refused = refused_kqueue_spawn(cmd, await_grandchild_before(&tree), (), Refusing::SENDS_NOTHING);
    // The root was sent nothing, and its marker was not swept: the grandchild lives to say so.
    let tree = tree.borrow_mut().take().expect("the tree");
    assert!(tree.grandchild_survived(), "a front's marker is not swept");
    assert_eq!(refused.fate(), crate::error::ChildFate::Running { id: None });
    assert!(
        refused
            .warn
            .contains("it is an elevation front, so nothing was sent to it")
            && refused.warn.contains("its tree was not killed"),
        "{}",
        refused.warn
    );
    assert!(
        refused.detail().is_some_and(|detail| detail.contains("left unreaped")),
        "{:?}",
        refused.detail()
    );
    assert_eq!(said_of(&refused.cleanup()), Vec::<String>::new());
}

fn refused_kqueue_of_a_late_child() {
    let (cmd, tree) = tree_spawn();
    let how = Refusing {
        late: true,
        killed: true,
        kill_read: None,
    };
    let refused = refused_kqueue_spawn(cmd, await_grandchild_before(&tree), (), how);
    let tree = tree.borrow_mut().take().expect("the tree");
    assert!(!tree.grandchild_survived(), "the marker's holders are swept");
    // The cause is the late report's, not the refusal, which is the teardown's one failure.
    assert!(
        crate::error::said(refused.cause()).contains("exec cannot be confirmed"),
        "{:?}",
        refused.cause()
    );
    assert_eq!(refused.cleanup().len(), 1, "{:?}", refused.cleanup());
    assert!(
        refused.warn.contains("descriptors 0 to 2 were closed")
            && refused.warn.contains(", and its exit could not be watched")
            && refused.warn.contains("its marker's holders were killed"),
        "{}",
        refused.warn
    );
}

fn refused_kqueue_whose_kill_is_refused() {
    let (cmd, writer) = sync_blocker();
    let how = Refusing {
        kill_read: Some(REFUSED_KILL_READ),
        ..Refusing::SENDS_NOTHING
    };
    let refused = refused_kqueue_spawn(cmd, || (), writer, how);
    assert_eq!(refused.fate(), crate::error::ChildFate::Running { id: None });
    assert!(refused.warn.contains("it could not be killed"), "{}", refused.warn);
    let cleanup = said_of(&refused.cleanup());
    assert!(
        cleanup.len() == 1 && cleanup[0].contains("killing the child"),
        "the refused kill is the teardown's one failure: {cleanup:?}"
    );
}

fn refused_kqueue_whose_kill_finds_the_child_gone() {
    let (cmd, writer) = sync_blocker();
    let how = Refusing {
        kill_read: Some(UniqRead::Gone),
        ..Refusing::SENDS_NOTHING
    };
    let refused = refused_kqueue_spawn(cmd, || (), writer, how);
    assert_eq!(refused.fate(), crate::error::ChildFate::Gone);
    assert!(
        refused
            .warn
            .contains("it was gone, or its pid names another process, so nothing was sent"),
        "{}",
        refused.warn
    );
    assert_eq!(said_of(&refused.cleanup()), Vec::<String>::new());
}

fn refused_kqueue_whose_holders_sweep_fails() {
    let (cmd, tree) = tree_spawn();
    let awaited = await_grandchild_before(&tree);
    // The marker has no root, so its sweep takes one pass, which is blind.
    let before = move || {
        awaited();
        crate::containment::enumerate::force_blind_snapshots(1);
    };
    let refused = refused_kqueue_spawn(cmd, before, (), Refusing::KILLS);
    crate::containment::enumerate::assert_blind_snapshots_consumed();
    // Released whatever the blind sweep did to it.
    _ = tree.borrow_mut().take().expect("the tree").grandchild_survived();
    assert!(
        refused.warn.contains("its marker's holders were not all killed")
            && refused.warn.contains("and the rest of its tree was not"),
        "{}",
        refused.warn
    );
    let cleanup = said_of(&refused.cleanup());
    assert!(
        cleanup.len() == 1 && cleanup[0].contains("unreadable on at least one pass"),
        "the failed sweep is the teardown's one failure: {cleanup:?}"
    );
}

/// What a refused-kqueue case arranges besides the lowered limit, and expects of the spawn.
#[derive(Clone, Copy)]
struct Refusing {
    /// The child's unique id comes late, as when std's spawn returns before the child's report.
    late: bool,
    /// The spawn kills the child through its unique id; otherwise it sends the child nothing.
    killed: bool,
    /// What the kill's id read of the child answers, a row of the spawn's kernel stated once the
    /// child exists; `None`: the host's.
    kill_read: Option<UniqRead>,
}

impl Refusing {
    const KILLS: Refusing = Refusing {
        late: false,
        killed: true,
        kill_read: None,
    };
    const SENDS_NOTHING: Refusing = Refusing {
        late: false,
        killed: false,
        kill_read: None,
    };
}

/// What a spawn whose first kqueue was refused came to: its error (a [`Error::MayHaveStarted`] that
/// hands no child back), and the one warn the spawn said of the child.
struct Refused {
    error: Error,
    warn: String,
}

impl Refused {
    /// The spawn's cause.
    fn cause(&self) -> &Error {
        let Error::MayHaveStarted { source, .. } = &self.error else {
            panic!("a spawn of a child that may have started: {:?}", self.error);
        };
        source
    }

    fn fate(&self) -> crate::error::ChildFate {
        let Error::MayHaveStarted { fate, .. } = &self.error else {
            panic!("a spawn of a child that may have started: {:?}", self.error);
        };
        *fate
    }

    fn detail(&self) -> Option<&str> {
        let Error::MayHaveStarted { detail, .. } = &self.error else {
            panic!("a spawn of a child that may have started: {:?}", self.error);
        };
        detail.as_deref()
    }

    /// The failures of the spawn's teardown, in the order they happened.
    fn cleanup(&self) -> Vec<&Error> {
        let Error::MayHaveStarted { cleanup, .. } = &self.error else {
            panic!("a spawn of a child that may have started: {:?}", self.error);
        };
        cleanup
            .iter()
            .flat_map(|failures| failures.iter())
            .map(|e| &**e)
            .collect()
    }
}

/// Whether `error` is the refusal of a kqueue: `EMFILE`.
fn is_emfile(error: &Error) -> bool {
    matches!(error, Error::Io(e) if e.raw_os_error() == Some(libc::EMFILE))
}

/// Spawns `cmd` with its first kqueue refused, after `before` ran (in the spawn, before the limit is
/// lowered), and `how` says what else is so. The refusal, the one warn naming the child and the
/// child's death (by `SIGKILL` if the spawn kills it, else not by the spawn) are checked, and the
/// zombie reaped. `end` is dropped to let a child that is not killed exit.
fn refused_kqueue_spawn<E>(mut cmd: crate::Command, before: impl Fn() + 'static, end: E, how: Refusing) -> Refused {
    crate::log_capture::install();
    let _report: Box<dyn std::any::Any> = if how.late {
        Box::new(unique_report::seams::find_the_report_unwritten())
    } else {
        Box::new(unique_report::seams::let_the_report_come_first())
    };
    let pid = Rc::new(Cell::new(None));
    let refused = Rc::new(RefCell::new(None));
    let kernel = Arc::new(FakeKernel::over(&HostKernel));
    let _lower = fault::set_at(SpawnPoint::BeforeAdopt, {
        let (pid, refused, kernel) = (Rc::clone(&pid), Rc::clone(&refused), Arc::clone(&kernel));
        move || {
            before();
            pid.set(Some(fault::spawn_pid()));
            if let Some(read) = how.kill_read {
                kernel.state_unique_info(fault::spawn_pid(), read);
            }
            *refused.borrow_mut() = Some(crate::test_child::refuse_new_descriptors());
        }
    });
    let mark = crate::log_capture::mark();
    let spawned = spawn_over(&mut cmd, Arc::clone(&kernel));
    drop(refused.borrow_mut().take());
    let error = spawned.expect_err("a refused kqueue fails the spawn");
    assert!(
        kernel.all_rows_taken(),
        "the kill made the id read its row answers (a row stated by `kill_read`)"
    );
    let pid = pid.get().expect("the first-read hook ran");
    let warns = crate::log_capture::warns_since(mark, "could not be watched");
    assert_eq!(warns.len(), 1, "{warns:?}");
    let refused = Refused {
        error,
        warn: warns[0].clone(),
    };
    let Error::MayHaveStarted { unreaped, .. } = &refused.error else {
        panic!("a spawn of a child that may have started: {:?}", refused.error);
    };
    assert!(unreaped.is_none(), "the spawn hands no child back");
    // The refusal is the spawn's cause, unless the id came late: the cause is then the late report,
    // and the refusal is the teardown's first failure.
    if how.late {
        assert!(
            refused.cleanup().first().is_some_and(|e| is_emfile(e)),
            "{:?}",
            refused.error
        );
    } else {
        assert!(is_emfile(refused.cause()), "{:?}", refused.error);
    }
    assert!(refused.warn.contains(&format!("child {pid}")), "{}", refused.warn);
    if how.killed {
        assert_eq!(
            refused.fate(),
            crate::error::ChildFate::Killed,
            "killed through its unique id"
        );
        assert!(refused.warn.contains("SIGKILL"), "{}", refused.warn);
        // Not the test's own signal: the child dies of the spawn's `SIGKILL`, not of the EOF that ends
        // it otherwise. The zombie is still ours to reap.
        drop(end);
        let mut status = 0;
        // SAFETY: `pid` is this test's own child, which the spawn left unreaped.
        let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
        assert_eq!(reaped, pid as libc::pid_t, "{}", std::io::Error::last_os_error());
        assert!(
            libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL,
            "the child was not killed by the spawn: status {status:#x}"
        );
    } else {
        end_unsignalled_and_reap(pid);
        drop(end);
    }
    refused
}

/// A contained [`TREE_ARGV`](super::late_report_tests::TREE_ARGV) command, and the ends of its tree the
/// test keeps.
fn tree_spawn() -> (crate::Command, Rc<RefCell<Option<super::late_report_tests::Tree>>>) {
    let (tree, ends) = super::late_report_tests::tree_pipes();
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(super::late_report_tests::TREE_ARGV).contain();
    for (fd, end) in ends {
        cmd.fd(fd, end).expect("set the fd");
    }
    (cmd, Rc::new(RefCell::new(Some(tree))))
}

/// A hook that blocks until the grandchild of `tree` runs, so it holds the marker.
fn await_grandchild_before(tree: &Rc<RefCell<Option<super::late_report_tests::Tree>>>) -> impl Fn() + 'static {
    let tree = Rc::clone(tree);
    move || tree.borrow_mut().as_mut().expect("the tree").await_grandchild()
}
