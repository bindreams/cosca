//! macOS-only `OwnedChild` tests: the kqueue wait under `SIG_IGN`, and the by-pid reaps.
//! The cases that change the process-wide `SIGCHLD` disposition each run in a fresh re-exec of the
//! test binary.

use std::time::{Duration, Instant};

use super::fixtures::{spawn_std_blocker, status, try_wait, wait_status, Blocker};
use crate::child::owned::{ChildWaitOutcome, OwnedChild};
use crate::identity::{ppid_fault, uniq_fault, uniq_info, ReadErr, ReadPurpose, UniqInfo, UniqRead, LAUNCHD};
use crate::os_process::child::{Foreign, PeekOutcome};
use crate::os_process::macos::kqueue::test_hooks::{self, ForcedOnce};
use crate::signal::Sig;
use crate::test_groups::{setuid, Group};
use crate::wait::exit_only::seams::{self as exit_seams, HolderStep};
use crate::wait::exit_only::{self, Target};

fn far() -> Instant {
    Instant::now() + Duration::from_secs(3600)
}

/// Whether `outcome` says the child is not this process's to reap.
fn is_foreign(outcome: &Result<ChildWaitOutcome, crate::error::Error>) -> bool {
    matches!(outcome, Ok(ChildWaitOutcome::Foreign(_)))
}

fn found(unique_id: u64) -> UniqRead {
    UniqRead::Found(UniqInfo {
        unique_id,
        id_version: 0,
    })
}

/// `pid`'s real unique id.
fn unique_of(pid: u32) -> u64 {
    match uniq_info(pid, ReadPurpose::Adopt) {
        UniqRead::Found(info) => info.unique_id,
        other => panic!("the unique id of {pid}: {other:?}"),
    }
}

// S11m: a reap that finds nothing after `Reapable` =====

/// S11m: a consuming reap that finds nothing right after the wait saw a zombie means the pid
/// names something else now. It takes the `ECHILD` path, with no assert in any build, and the
/// state goes back to `N`.
///
/// Mutant: a `debug_assert!` on the by-pid target.
#[skuld::test]
fn a_reap_that_finds_none_after_reapable_takes_the_echild_path() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let none = exit_seams::force_empty_reap_once();
    let outcome = b.owned.wait(None);
    drop(none);
    assert!(is_foreign(&outcome), "{outcome:?}");
    assert!(format!("{:?}", b.owned).contains("N"), "{:?}", b.owned);
    // The zombie was never consumed (the reap was forced empty): a real wait reaps it.
    wait_status(&b.owned);
}

// S2g: an identity read that says the pid is gone =====

/// S2g: an id-checked peek whose identity read says the pid is `Gone` answers `Foreign(Gone)`.
///
/// Mutant: `Gone` treated as a match: the peek returns `Exit`.
#[skuld::test]
fn an_identity_read_gone_takes_the_echild_path() {
    let (child, stdin) = spawn_std_blocker();
    let unique = unique_of(child.id());
    drop(stdin);
    let mut child = child;
    // The child's exit, seen without consuming it.
    let target = Target::pid(child.id(), Some(unique));
    let forced = uniq_fault::force_uniq_read_once(ReadPurpose::Peek, UniqRead::Gone);
    let peeked = loop {
        match exit_only::peek(&target).expect("peek") {
            PeekOutcome::Running => confirm_exit_of(&child),
            other => break other,
        }
    };
    drop(forced);
    assert_eq!(peeked, PeekOutcome::Foreign(Foreign::Gone));
    child.wait().expect("reap");
}

/// Block until `child`'s exit is visible, without consuming it.
fn confirm_exit_of(child: &std::process::Child) {
    // SAFETY: an all-zero `siginfo_t` is a valid value, and `waitid` writes only into it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id() as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOWAIT,
        )
    };
    assert_eq!(r, 0, "waitid(WNOWAIT): {}", std::io::Error::last_os_error());
}

// S10r: the second reap =====

/// The second reap of an exited, unreaped child, whose unique id reads as `read`.
fn second_reap_with_unique(read: UniqRead) -> std::process::Child {
    let (mut child, stdin) = spawn_std_blocker();
    drop(stdin);
    confirm_exit_of(&child);
    let forced = uniq_fault::force_uniq_read_once(ReadPurpose::SecondPeek, read);
    crate::wait::exit_only::second_reap(child.id(), Some(7));
    drop(forced);
    let _ = &mut child;
    child
}

/// S10r: a second reap whose start no longer matches is skipped: nothing is consumed.
///
/// Mutant: a second consume without the start check.
#[skuld::test]
fn a_second_reap_with_an_id_mismatch_is_skipped() {
    let mut child = second_reap_with_unique(found(99));
    let status = child
        .wait()
        .expect("the zombie must still be there: the mismatch skipped the consume");
    assert!(status.success());
}

/// S10r: a second reap whose start matches consumes the leftover zombie.
///
/// Mutant: the start check inverted.
#[skuld::test]
fn a_second_reap_with_a_matching_id_consumes_the_leftover() {
    let child = second_reap_with_unique(found(7));
    let mut status = 0;
    // SAFETY: `status` is a valid out-pointer.
    let r = unsafe { libc::waitpid(child.id() as i32, &mut status, libc::WNOHANG) };
    assert_eq!(r, -1, "the matching second reap must have consumed the zombie");
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
    std::mem::forget(child);
}

/// S10r: a second peek that meets `ECHILD` is skipped quietly, not logged as a foreign reap or a
/// warning.
///
/// Mutant: the `ECHILD` logged at `warn`.
#[skuld::test]
fn a_second_reap_that_meets_echild_is_skipped() {
    crate::log_capture::install();
    let (mut child, stdin) = spawn_std_blocker();
    drop(stdin);
    confirm_exit_of(&child);
    let marker = format!("second reap of pid {}", child.id());
    let mark = crate::log_capture::mark();
    let forced = exit_seams::force_peek_once(Err(std::io::Error::from_raw_os_error(libc::ECHILD)));
    crate::wait::exit_only::second_reap(child.id(), None);
    drop(forced);
    let levels = crate::log_capture::levels_since(mark, &marker);
    assert!(
        !levels.contains(&log::Level::Warn),
        "an ECHILD must not warn: {levels:?}"
    );
    child.wait().expect("the zombie was never consumed");
}

/// S10r: a second reap with no start to check is skipped with a `warn`, and consumes nothing: a
/// consume by a bare pid could take a reusing process's record.
///
/// Mutant: the consume runs when there is no start.
#[skuld::test]
fn a_second_reap_without_an_id_is_skipped_with_a_warning() {
    crate::log_capture::install();
    let (mut child, stdin) = spawn_std_blocker();
    drop(stdin);
    confirm_exit_of(&child);
    let marker = format!("second reap of pid {}", child.id());
    let mark = crate::log_capture::mark();
    crate::wait::exit_only::second_reap(child.id(), None);
    let levels = crate::log_capture::levels_since(mark, &marker);
    assert_eq!(levels, [log::Level::Warn], "{levels:?}");
    child.wait().expect("the zombie was never consumed");
}

/// S10r: a second consume that finds nothing is skipped quietly.
///
/// Mutant: a `debug_assert!` on the by-pid consume.
#[skuld::test]
fn a_second_reap_that_finds_nothing_is_skipped() {
    crate::log_capture::install();
    let (mut child, stdin) = spawn_std_blocker();
    drop(stdin);
    confirm_exit_of(&child);
    let marker = format!("second reap of pid {}", child.id());
    let mark = crate::log_capture::mark();
    let same = uniq_fault::force_uniq_read_once(ReadPurpose::SecondPeek, found(7));
    let none = exit_seams::force_empty_reap_once();
    crate::wait::exit_only::second_reap(child.id(), Some(7));
    drop(none);
    drop(same);
    let levels = crate::log_capture::levels_since(mark, &marker);
    assert!(
        !levels.contains(&log::Level::Warn),
        "finding nothing must not warn: {levels:?}"
    );
    child.wait().expect("the zombie was never consumed");
}

/// S10r: the second peek runs after every first reap, traced or not. For an untraced child it
/// answers `ECHILD` and is skipped quietly.
///
/// Mutant: a second peek gated on `p_oppid`: no `SecondPeek` step for an untraced child.
#[skuld::test]
fn a_second_peek_runs_after_every_first_reap() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    exit_seams::holder_steps();
    wait_status(&b.owned);
    assert_eq!(exit_seams::holder_steps(), [HolderStep::SecondPeek]);
}

/// `uniq_info`'s test seam hits only its purpose: arming one of `Peek`, `PreReap` and `SecondPeek`
/// leaves the other two reads untouched.
///
/// Mutant: a purpose-blind seam.
#[skuld::test]
fn force_uniq_read_once_hits_only_its_purpose() {
    let pid = std::process::id();
    let real = uniq_info(pid, ReadPurpose::Peek);
    assert!(matches!(real, UniqRead::Found(_)), "{real:?}");
    let all = [ReadPurpose::Peek, ReadPurpose::PreReap, ReadPurpose::SecondPeek];
    for armed in all {
        let forced = uniq_fault::force_uniq_read_once(armed, UniqRead::Refused(libc::EPERM));
        for other in all.into_iter().filter(|p| *p != armed) {
            assert_eq!(uniq_info(pid, other), real, "{other:?} read while {armed:?} was armed");
        }
        assert_eq!(uniq_info(pid, armed), UniqRead::Refused(libc::EPERM));
        assert_eq!(uniq_info(pid, armed), real, "the force is taken once");
        drop(forced);
    }
}

// Task 2b: the `SIG_IGN` hang =====

const MARKER: &str = "COSCA_TEST_SHARED_SIGIGN";
const CASE_ENV: &str = "COSCA_TEST_SHARED_SIGIGN_CASE";

fn run_case(path: &str, case: &str) {
    crate::test_child::run_fixture_case(path, MARKER, CASE_ENV, case);
}

/// A root child adopted into an `OwnedChild`, under `SIGCHLD` set to `SIG_IGN` with a live
/// sibling blocked on its stdin, so the kernel reaps the root itself and a blocking `waitid`
/// would sleep until the sibling is gone. The root's stdin closes from inside the holder's first
/// blocking `poll` of the reap kqueue, so the waiter is known to be asleep first.
fn ignoring_sigchld_with_a_sibling() -> (
    OwnedChild,
    std::process::Child,
    std::process::ChildStdin,
    crate::wait::block_probe::Armed,
) {
    crate::test_child::set_signal_ignored(libc::SIGCHLD, true);
    let (sibling, sibling_stdin) = spawn_std_blocker();
    let (root, root_stdin) = spawn_std_blocker();
    let id = super::fixtures::identity_of(&root);
    let owned = OwnedChild::adopt(root, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    let mut root_stdin = Some(root_stdin);
    let end = crate::wait::block_probe::on_blocking(move || drop(root_stdin.take()));
    (owned, sibling, sibling_stdin, end)
}

/// A `wait` on a child the kernel reaped returns `ECHILD` while a sibling lives.
///
/// Mutant: a blocking `waitid` instead of the kqueue form, which sleeps until the child list
/// empties.
#[skuld::test]
fn a_wait_on_a_child_the_kernel_reaped_returns_while_a_sibling_lives() {
    if !crate::test_child::is_marked_fixture_reexec(MARKER) {
        return run_case(
            crate::test_child::fixture_path!(a_wait_on_a_child_the_kernel_reaped_returns_while_a_sibling_lives),
            "",
        );
    }
    let (owned, _sibling, _stdin, _end) = ignoring_sigchld_with_a_sibling();
    let outcome = owned.wait(None);
    assert!(is_foreign(&outcome), "the kernel reaped the root: {outcome:?}");
}

/// A `wait_deadline` far past the bound returns `ECHILD`, not `Ok(None)`.
///
/// Mutant: the same.
#[skuld::test]
fn a_wait_timeout_far_past_the_bound_returns_echild() {
    if !crate::test_child::is_marked_fixture_reexec(MARKER) {
        return run_case(
            crate::test_child::fixture_path!(a_wait_timeout_far_past_the_bound_returns_echild),
            "",
        );
    }
    let (owned, _sibling, _stdin, _end) = ignoring_sigchld_with_a_sibling();
    let outcome = owned.wait(Some(far()));
    assert!(is_foreign(&outcome), "the kernel reaped the root: {outcome:?}");
}

/// A sync drop of a child the kernel reaped returns: its wait after a successful kill answers
/// `ECHILD` instead of sleeping.
///
/// Mutant: the same.
#[skuld::test]
fn a_sync_drop_of_a_child_the_kernel_reaped_returns() {
    if !crate::test_child::is_marked_fixture_reexec(MARKER) {
        return run_case(
            crate::test_child::fixture_path!(a_sync_drop_of_a_child_the_kernel_reaped_returns),
            "",
        );
    }
    crate::test_child::set_signal_ignored(libc::SIGCHLD, true);
    let (_sibling, _sibling_stdin) = spawn_std_blocker();
    use std::io::Read as _;
    let mut cmd = crate::Command::new();
    // Prints `eof` only if `cat` ends of its own accord, as it does on EOF once the writer is
    // released. The kill ends the shell first; `cat` outlives it until the release, and prints nothing.
    cmd.args(["sh", "-c", "cat; echo eof"]);
    // Released once the drop's kill returned. With a kill that sent nothing the shell prints `eof`
    // and exits, the kernel reaps it, and the drop returns all the same (`ECHILD`): the output is
    // what shows the kill.
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let teardown = crate::child::spawn::fault::release_at_drop_kill(writer);
    cmd.stdin(stdin).expect("stdin");
    cmd.stdout(crate::Stdio::pipe()).expect("stdout");
    let mut child = cmd.spawn().expect("spawn");
    let mut stdout = child.stdout().expect("piped stdout");
    drop(child);
    teardown.assert_released();
    let mut printed = Vec::new();
    stdout
        .read_to_end(&mut printed)
        .expect("the pipe ends once `cat` is gone");
    assert!(
        printed.is_empty(),
        "the drop's kill must end the shell first: {printed:?}"
    );
}

// Identity: the unique id is checked on every by-pid surface =====

/// `try_wait` on an exited child whose pid now reads as another process answers `ECHILD` and
/// consumes nothing.
///
/// Mutant: `target()` without the id: the exit is reported.
#[skuld::test]
fn try_wait_on_a_pid_with_another_unique_id_is_echild_and_consumes_nothing() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let other = unique_of(b.pid) ^ 1;
    let forced = uniq_fault::force_uniq_read_once(ReadPurpose::Peek, found(other));
    let outcome = try_wait(&b.owned);
    drop(forced);
    assert!(is_foreign(&outcome), "another process holds the pid: {outcome:?}");
    wait_status(&b.owned);
}

/// The wait itself checks the id: a pid that reads as another process ends the wait as `Gone`,
/// before any reap step.
///
/// Mutant: the wait's peek without the id: it reports `Reapable` and reaches the reap.
#[skuld::test]
fn a_wait_on_a_pid_with_another_unique_id_never_reaches_the_reap() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let other = unique_of(b.pid) ^ 1;
    let forced = uniq_fault::force_uniq_read_once(ReadPurpose::Peek, found(other));
    let outcome = b.owned.wait(None);
    drop(forced);
    assert!(is_foreign(&outcome), "another process holds the pid: {outcome:?}");
    // Our zombie was never consumed: a real wait reaps it.
    wait_status(&b.owned);
}

/// `kill` sends nothing to a pid whose unique id is no longer the child's: the child then ends on its own,
/// by EOF on its stdin, and exits cleanly.
///
/// Mutant: `kill` by the bare pid, as std's `Child::kill` does: the child dies of `SIGKILL`.
#[skuld::test]
fn kill_sends_nothing_to_a_pid_with_another_unique_id() {
    let mut b = Blocker::spawn();
    let log = crate::send_log::Capture::start();
    let other = unique_of(b.pid) ^ 1;
    let forced = uniq_fault::force_uniq_read_once(ReadPurpose::Kill, found(other));
    b.owned
        .signal(Sig::Kill)
        .expect("a pid that is not ours is gone, not an error");
    drop(forced);
    assert_eq!(log.entries(), []);
    b.end_child();
    let status = wait_status(&b.owned);
    assert!(status.success(), "the child was signalled: {status:?}");
}

/// `kill` on a live child sends `SIGKILL` by pid and records it.
///
/// Mutant: nothing sent.
#[skuld::test]
fn kill_signals_a_live_child_by_its_verified_pid() {
    let b = Blocker::spawn();
    let log = crate::send_log::Capture::start();
    b.owned.signal(Sig::Kill).expect("kill");
    assert_eq!(log.entries(), [(b.pid, Sig::Kill, crate::send_log::Via::Pid)]);
    let status = wait_status(&b.owned);
    assert_eq!(super::fixtures::signal_of(status), Some(libc::SIGKILL));
}

// A pid that is not our child, yet still names it (a tracer holds it) =====

/// Our own pid: `waitid` answers `ECHILD` for it, as it does for a child a tracer holds, and it
/// still resolves to its unique id.
fn echild_yet_resolvable() -> (u32, u64) {
    let pid = std::process::id();
    (pid, unique_of(pid))
}

/// The parent read of a live process another process holds, as a tracer holds a child: not
/// launchd.
fn held_by_a_tracer() -> ppid_fault::Forced {
    ppid_fault::force_ppid_once(Ok(4242))
}

/// The parent read of a zombie whose tracer died: XNU reparented it to launchd.
fn orphaned_to_launchd() -> ppid_fault::Forced {
    ppid_fault::force_ppid_once(Ok(LAUNCHD))
}

/// A by-pid `ECHILD` for a pid that still names the child, and that a live process holds, is not a
/// reap.
///
/// Mutant: `ECHILD` mapped to `Foreign(Gone)` without the id and parent check.
#[skuld::test]
fn an_echild_for_a_pid_held_by_a_tracer_is_running() {
    let (pid, unique) = echild_yet_resolvable();
    let target = Target::pid(pid, Some(unique));
    let forced = held_by_a_tracer();
    assert_eq!(exit_only::peek(&target).expect("peek"), PeekOutcome::Running);
    drop(forced);
    let _forced = held_by_a_tracer();
    assert_eq!(
        exit_only::try_reap(&target).expect("try_reap"),
        exit_only::Reap::Running
    );
}

/// A child whose tracer dies while the child is exiting: XNU sends the child's `NOTE_EXIT` and
/// `SIGCHLD` to the tracer alone, then gives the child to launchd. The wait watches the tracer as
/// well, and its `NOTE_EXIT` makes the wait peek again, which finds launchd holding the child:
/// `Orphaned`. This process's own pid stands in for the child (`waitid` answers `ECHILD`, and its id
/// resolves), and a blocker for the tracer; the parent read is forced: the stand-in while it runs,
/// launchd once it has exited. The stand-in is this test's child, so its `SIGCHLD` wakes the wait
/// too, and the assertion is on the tracer's `NOTE_EXIT` among the wait's events.
///
/// Mutant: the wait does not watch the tracer.
#[skuld::test]
fn a_wait_on_a_child_whose_tracer_dies_during_its_exit_is_woken_by_the_tracers_exit() {
    use std::cell::Cell;
    use std::rc::Rc;

    use crate::wait::macos::{await_reapable, Waited};
    let (pid, unique) = echild_yet_resolvable();
    let (mut tracer, tracer_stdin) = spawn_std_blocker();
    let tracer_pid = tracer.id();
    let exited = Rc::new(Cell::new(false));
    let _parent = ppid_fault::force_ppid_with({
        let exited = Rc::clone(&exited);
        move || Ok(if exited.get() { LAUNCHD } else { tracer_pid })
    });
    let _end = test_hooks::on_kevent_round(0, move || {
        drop(tracer_stdin);
        crate::test_child::wait_until_zombie(tracer_pid);
        exited.set(true);
    });
    let _ = test_hooks::take_events();
    let waited = await_reapable(pid, Some(unique), None).expect("wait");
    let events = test_hooks::take_events();
    assert!(
        events
            .iter()
            .any(|&(filter, fflags)| filter == libc::EVFILT_PROC && fflags & libc::NOTE_EXIT != 0),
        "the tracer's exit must wake the wait: {events:?}"
    );
    assert_eq!(waited, Waited::Orphaned);
    tracer.wait().expect("reap the stand-in tracer");
}

/// The rounds of an `await_reapable_on` on `kq`: `hook` runs before each blocking round with the
/// round's index and the kqueue. A round whose hook answers `false` (it found nothing pending that
/// should be) gets a `SIGCHLD` to this process, which the wait also watches, so a wait that missed
/// its event fails its test's assertion instead of hanging.
pub(super) fn on_rounds(
    kq: &std::rc::Rc<crate::os_process::macos::kqueue::Kqueue>,
    mut hook: impl FnMut(u32, &crate::os_process::macos::kqueue::Kqueue) -> bool + 'static,
) -> ForcedOnce {
    let kq = std::rc::Rc::clone(kq);
    test_hooks::on_every_kevent_round(move |round| {
        if !hook(round, &kq) {
            test_hooks::send_signal(std::process::id(), libc::SIGCHLD);
        }
    })
}

/// A tracer that attaches after the wait's check: XNU reparents the child to it and sends the child
/// `SIGSTOP` (see `wait::macos::TracerWatch`). The wait watches the child's signals,
/// so it peeks again, finds the tracer and watches it too; the tracer's exit, with launchd then
/// holding the child, ends the wait: `Orphaned`. This process's own pid stands in for the child, and
/// a blocker for the tracer; the parent read is forced: this process until the attach, then the
/// stand-in, then launchd once that has exited. A `SIGCONT` to this process stands in for the
/// attach's `SIGSTOP`.
///
/// Mutant: the wait registers no `NOTE_SIGNAL` on the child.
#[skuld::test]
fn a_wait_on_a_child_a_tracer_attaches_to_late_is_woken_by_the_attach() {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use crate::wait::macos::{await_reapable_on, Waited};
    let (pid, unique) = echild_yet_resolvable();
    let (mut tracer, tracer_stdin) = spawn_std_blocker();
    let tracer_pid = tracer.id();
    let holder = Rc::new(Cell::new(pid));
    let _parent = ppid_fault::force_ppid_with({
        let holder = Rc::clone(&holder);
        move || Ok(holder.get())
    });
    let kq = Rc::new(crate::os_process::macos::kqueue::Kqueue::new().expect("kqueue"));
    let attach_woke = Rc::new(Cell::new(None));
    let tracer_stdin = RefCell::new(Some(tracer_stdin));
    let _rounds = on_rounds(&kq, {
        let attach_woke = Rc::clone(&attach_woke);
        move |round, kq| match round {
            0 => {
                holder.set(tracer_pid);
                test_hooks::send_signal(pid, libc::SIGCONT);
                attach_woke.set(Some(test_hooks::event_pending(kq)));
                attach_woke.get() == Some(true)
            }
            1 => {
                drop(tracer_stdin.borrow_mut().take());
                crate::test_child::wait_until_zombie(tracer_pid);
                holder.set(LAUNCHD);
                true
            }
            _ => false,
        }
    });
    let waited = await_reapable_on(&kq, pid, Some(unique), None).expect("wait");
    assert_eq!(attach_woke.get(), Some(true), "the attach's signal must wake the wait");
    assert_eq!(waited, Waited::Orphaned);
    tracer.wait().expect("reap the stand-in tracer");
}

/// The parents a `kinfo_proc` read reports for a process this one started, held by `tracer`:
/// `(p_oppid, e_ppid)`.
fn started_by_us_traced_by(tracer: u32) -> (libc::pid_t, libc::pid_t) {
    (std::process::id() as libc::pid_t, tracer as libc::pid_t)
}

/// A tracer that is itself traced: XNU sends its `NOTE_EXIT` only to its own tracer, and its exit
/// sends that tracer `SIGCHLD` (see `wait::macos::TracerWatch`). The wait follows the chain of tracers and watches the signals of each, so
/// that `SIGCHLD` wakes it, and the peek after it finds launchd holding the child: `Orphaned`. This
/// process's own pid stands in for the child, held by one blocker; a second blocker stands in for
/// that one's tracer, by its forced parents. A `SIGCHLD` to the second stands in for the first one's
/// exit, and the child's parent read then answers launchd.
///
/// Mutant: the walk stops at the child's tracer.
#[skuld::test]
fn a_wait_on_a_child_whose_tracer_is_traced_is_woken_by_that_tracers_exit() {
    use std::cell::Cell;
    use std::rc::Rc;

    use crate::wait::macos::{await_reapable_on, Waited};
    let (pid, unique) = echild_yet_resolvable();
    let (tracer, tracer_stdin) = spawn_std_blocker();
    let (outer, outer_stdin) = spawn_std_blocker();
    let (tracer_pid, outer_pid) = (tracer.id(), outer.id());
    let holder = Rc::new(Cell::new(tracer_pid));
    let _parent = ppid_fault::force_ppid_with({
        let holder = Rc::clone(&holder);
        move || Ok(holder.get())
    });
    let _traced = crate::identity::kinfo::fault::force_parents(tracer_pid, move || started_by_us_traced_by(outer_pid));
    let kq = Rc::new(crate::os_process::macos::kqueue::Kqueue::new().expect("kqueue"));
    let exit_woke = Rc::new(Cell::new(None));
    let _rounds = on_rounds(&kq, {
        let exit_woke = Rc::clone(&exit_woke);
        move |round, kq| {
            if round != 0 {
                return false;
            }
            holder.set(LAUNCHD);
            test_hooks::send_signal(outer_pid, libc::SIGCHLD);
            exit_woke.set(Some(test_hooks::event_pending(kq)));
            exit_woke.get() == Some(true)
        }
    });
    let waited = await_reapable_on(&kq, pid, Some(unique), None).expect("wait");
    assert_eq!(
        exit_woke.get(),
        Some(true),
        "the SIGCHLD that the traced tracer's exit sends its tracer must wake the wait"
    );
    assert_eq!(waited, Waited::Orphaned);
    for (mut child, stdin) in [(tracer, tracer_stdin), (outer, outer_stdin)] {
        drop(stdin);
        child.wait().expect("reap a stand-in tracer");
    }
}

/// A tracer that began its exit, then lost its own tracer: XNU gives it to launchd and keeps its
/// `p_oppid`, so its `NOTE_EXIT` and its `SIGCHLD` reach only launchd (see
/// `wait::macos::TracerWatch`). It hands the child over once its exit reaches its children, so the
/// wait peeks again on a backoff instead of blocking for an event that never comes. This process's own pid stands in for the child, held by
/// a blocker whose forced parents say launchd holds it and a tracer attached to it; the child's
/// parent read answers launchd from the first block on.
///
/// Mutant: a tracer launchd holds ends the walk, and the wait blocks with no timeout.
#[skuld::test]
fn a_wait_on_a_child_whose_tracer_is_exiting_at_launchd_peeks_again_on_a_backoff() {
    use std::cell::Cell;
    use std::rc::Rc;

    use crate::wait::macos::{await_reapable_on, Waited};
    let (pid, unique) = echild_yet_resolvable();
    let (mut tracer, tracer_stdin) = spawn_std_blocker();
    let tracer_pid = tracer.id();
    let holder = Rc::new(Cell::new(tracer_pid));
    let _parent = ppid_fault::force_ppid_with({
        let holder = Rc::clone(&holder);
        move || Ok(holder.get())
    });
    let _dying = crate::identity::kinfo::fault::force_parents(tracer_pid, || started_by_us_traced_by(LAUNCHD));
    let kq = Rc::new(crate::os_process::macos::kqueue::Kqueue::new().expect("kqueue"));
    let _rounds = on_rounds(&kq, move |round, _| {
        holder.set(LAUNCHD);
        // The first round's own wake, for a wait that blocked with no timeout.
        round != 0
    });
    let before = test_hooks::await_requested_timeouts().len();
    let waited = await_reapable_on(&kq, pid, Some(unique), None).expect("wait");
    let blocks: Vec<_> = test_hooks::await_requested_timeouts()[before..]
        .iter()
        .copied()
        .filter(|armed| *armed != Some(Duration::ZERO))
        .collect();
    assert!(
        matches!(blocks.first(), Some(Some(_))),
        "the first block must be timed, to peek again: {blocks:?}"
    );
    assert_eq!(waited, Waited::Orphaned);
    drop(tracer_stdin);
    tracer.wait().expect("reap the stand-in tracer");
}

/// launchd answers `ECHILD` to our `waitid` and refuses `PROC_PIDTBSDINFO` to a caller that is not
/// root, yet its unique id and parent read unprivileged: it is held, not reaped. Its parent is the
/// kernel, pid 0, not launchd.
///
/// Mutant: the parent read through a same-user flavor: `Foreign(Gone)`.
#[skuld::test]
fn an_echild_for_another_users_process_that_launchd_does_not_own_is_running() {
    let target = Target::pid(1, Some(unique_of(1)));
    assert_eq!(exit_only::peek(&target).expect("peek"), PeekOutcome::Running);
    assert_eq!(
        exit_only::try_reap(&target).expect("try_reap"),
        exit_only::Reap::Running
    );
}

/// A by-pid `ECHILD` for a pid that still names the child but that launchd owns: a zombie whose
/// tracer died and which XNU reparented to launchd. Only a wait by launchd would hand it back.
///
/// Mutant: the parent ignored: `Running`; the launchd hold mapped to `Gone` (a reap).
#[skuld::test]
fn an_echild_for_a_pid_orphaned_to_launchd_is_orphaned() {
    let (pid, unique) = echild_yet_resolvable();
    let target = Target::pid(pid, Some(unique));
    let forced = orphaned_to_launchd();
    assert_eq!(
        exit_only::peek(&target).expect("peek"),
        PeekOutcome::Foreign(Foreign::Orphaned)
    );
    drop(forced);
    let _forced = orphaned_to_launchd();
    assert_eq!(
        exit_only::try_reap(&target).expect("try_reap"),
        exit_only::Reap::Foreign(Foreign::Orphaned)
    );
}

/// A parent read that fails between two matching id reads is not a hold: a refusal is `Gone`. `ESRCH`
/// there contradicts the matching reads that bracket it (xnu cannot produce it), so it asserts in a
/// debug build and is `Gone` in a release build.
///
/// Mutant: a failed parent read taken for a parent pid, and so for `Running`.
#[skuld::test]
fn an_echild_whose_parent_read_fails_is_foreign() {
    let (pid, unique) = echild_yet_resolvable();
    let target = Target::pid(pid, Some(unique));
    let forced = ppid_fault::force_ppid_once(Err(ReadErr::Refused(libc::EPERM)));
    assert_eq!(
        exit_only::peek(&target).expect("peek"),
        PeekOutcome::Foreign(Foreign::Gone)
    );
    drop(forced);
    let forced = ppid_fault::force_ppid_once(Err(ReadErr::Gone));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| exit_only::peek(&target)));
    drop(forced);
    if cfg!(debug_assertions) {
        assert!(outcome.is_err(), "a debug build asserts the contract");
    } else {
        assert_eq!(
            outcome.expect("release returns").expect("peek"),
            PeekOutcome::Foreign(Foreign::Gone)
        );
    }
}

/// An `ECHILD` for a pid with another unique id is a reuse, whether the first read or the one that
/// closes the parent read says so; a pid that is gone or unreadable is gone.
///
/// Mutant: any `ECHILD` taken for `Running`; the closing read dropped.
#[skuld::test]
fn an_echild_for_a_pid_that_no_longer_names_the_child_is_foreign() {
    let (pid, unique) = echild_yet_resolvable();
    let target = Target::pid(pid, Some(unique));
    let other = found(unique ^ 1);
    for (reads, want) in [
        (vec![other], Foreign::Other),
        // The process changed while its parent was being read.
        (vec![found(unique), other], Foreign::Other),
        (vec![UniqRead::Refused(libc::EPERM)], Foreign::Gone),
        (vec![UniqRead::Gone], Foreign::Gone),
        (vec![found(unique), UniqRead::Gone], Foreign::Gone),
    ] {
        let forced: Vec<_> = reads
            .iter()
            .map(|read| uniq_fault::force_uniq_read_once(ReadPurpose::Echild, *read))
            .collect();
        assert_eq!(
            exit_only::peek(&target).expect("peek"),
            PeekOutcome::Foreign(want),
            "{reads:?}"
        );
        drop(forced);
    }
}

/// A `Running` peek names a child of ours; if the pid now reads as another process, it is a reuse.
///
/// Mutant: `Running` never checks the id.
#[skuld::test]
fn a_running_peek_of_a_pid_with_another_unique_id_is_foreign() {
    let mut b = Blocker::spawn();
    let unique = unique_of(b.pid);
    let forced = uniq_fault::force_uniq_read_once(ReadPurpose::Running, found(unique ^ 1));
    let outcome = try_wait(&b.owned);
    drop(forced);
    assert!(is_foreign(&outcome), "another process holds the pid: {outcome:?}");
    // An id that cannot be read, or that matches, leaves it running.
    for read in [UniqRead::Refused(libc::EPERM), found(unique)] {
        let forced = uniq_fault::force_uniq_read_once(ReadPurpose::Running, read);
        assert_eq!(
            try_wait(&b.owned).expect("try_wait"),
            ChildWaitOutcome::DeadlinePassed,
            "{read:?}"
        );
        drop(forced);
    }
    b.end_child();
    wait_status(&b.owned);
}

/// With no id there is nothing to check an `ECHILD` against: it stays a reap.
///
/// Mutant: `ECHILD` taken for `Running` whatever the id.
#[skuld::test]
fn an_echild_with_no_id_stays_foreign() {
    let (pid, _) = echild_yet_resolvable();
    assert_eq!(
        exit_only::peek(&Target::pid(pid, None)).expect("peek"),
        PeekOutcome::Foreign(Foreign::Gone)
    );
}

/// The kqueue wait does not read a held child as reaped: it is still running at its deadline.
///
/// Mutant: the wait's peek without the id: `Gone`.
#[skuld::test]
fn the_kqueue_wait_keeps_waiting_for_a_child_that_answers_echild_yet_resolves() {
    use crate::wait::macos::{await_reapable, Waited};
    let (pid, unique) = echild_yet_resolvable();
    // The first look, and the final one at expiry.
    let _forced = (held_by_a_tracer(), held_by_a_tracer());
    // An expired deadline: no blocking.
    let waited = await_reapable(pid, Some(unique), Some(Instant::now())).expect("wait");
    assert_eq!(waited, Waited::DeadlinePassed);
}

/// The wait's verdict for a pid that reads as another process is `Gone`.
///
/// Mutant: the wait ignores the id.
#[skuld::test]
fn the_kqueue_wait_reports_gone_for_a_pid_with_another_unique_id() {
    use crate::wait::macos::{await_reapable, Waited};
    let (pid, unique) = echild_yet_resolvable();
    let waited = await_reapable(pid, Some(unique ^ 1), Some(Instant::now())).expect("wait");
    assert_eq!(waited, Waited::Gone);
}

/// A wait whose peek finds the zombie held by launchd (its tracer died) gives up on it with a
/// `warn` that it is not ours to reap, not silently as for a reap.
///
/// Mutant: `Waited::Orphaned` is folded into `Gone` without a log.
#[skuld::test]
fn a_wait_on_a_zombie_launchd_holds_warns_it_is_not_ours_to_reap() {
    crate::log_capture::install();
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let pid = b.pid;
    let mark = crate::log_capture::mark();
    let _orphaned = exit_seams::force_peek_once(Ok(PeekOutcome::Foreign(Foreign::Orphaned)));
    _ = b.owned.wait(None);
    let records = crate::log_capture::records_since_on_current_thread(mark, &format!("pid {pid}"));
    assert!(
        records
            .iter()
            .any(|(level, text)| *level == log::Level::Warn && text.contains("not ours to reap")),
        "{records:?}"
    );
    crate::child::spawn::identity_macos_tests::reap_by_pid(pid);
}

// S11m: the reap finds no exit record after the peek saw one =====

/// A reap whose own peek finds no exit record right after the look's peek saw one is still our
/// child (a foreign reap is `Foreign`): the look is `Recheck`, and the holder looks again after a
/// backoff and gets the exit.
///
/// Mutant: `Gone` at once: the wait answers `ECHILD`.
#[skuld::test]
fn a_reap_that_finds_no_exit_record_after_the_peek_saw_one_looks_again() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    // The look's peek sees the exit; the reap's own peek then finds none.
    let _forced = exit_seams::force_peeks([
        Ok(PeekOutcome::Exit(crate::os_process::child::ExitRecord::Status(
            std::process::ExitStatus::default(),
        ))),
        Ok(PeekOutcome::Running),
    ]);
    crate::wait::block_probe::take();
    let status = wait_status(&b.owned);
    assert!(status.success(), "{status:?}");
    exit_seams::assert_peeks_exhausted();
    assert!(
        !crate::wait::block_probe::take().is_empty(),
        "the second look follows a backoff"
    );
}

// A child whose identity a same-user read refuses (the `setuid` group) =====

/// A setuid-root `setuid-stdin-block root` child that has become root, with its stdin.
fn spawn_root_child() -> (std::process::Child, std::process::ChildStdin) {
    use std::io::Read as _;
    let helper = crate::test_privilege::setuid::setuid_helper();
    let mut cmd = std::process::Command::new(helper);
    cmd.args(["setuid-stdin-block", "root"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let mut child = crate::test_spawn::spawn(&mut cmd).expect("spawn the setuid helper");
    let stdin = child.stdin.take().expect("piped stdin");
    let mut ready = [0u8; 1];
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_exact(&mut ready)
        .expect("the helper reports ready");
    assert_eq!(ready, *b"+");
    (child, stdin)
}

/// `kill` of a child this caller may not signal reads its identity all the same, and surfaces the
/// `EPERM` as `PermissionDenied`, not an untyped error.
///
/// Mutant: the identity read through the same-user `PROC_PIDTBSDINFO`: `ErrorKind::Other`.
#[skuld::test]
fn setuid_kill_of_a_root_child_is_permission_denied(#[fixture(setuid)] _group: &Group) {
    let (child, stdin) = spawn_root_child();
    let id = super::fixtures::identity_of(&child);
    // The identity of another user's process is readable.
    unique_of(id.pid());
    let owned = OwnedChild::adopt(child, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    let err = owned
        .signal(Sig::Kill)
        .expect_err("this caller may not signal a root process")
        .into_io();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    drop(stdin);
    let status = wait_status(&owned);
    assert!(status.success(), "{status:?}");
}

/// The same through the public handle: `Child::kill` is `Io(PermissionDenied)`, which the elevated
/// wrapper's mapping turns into `Unkillable`.
///
/// Mutant: as above.
#[skuld::test]
fn setuid_child_kill_is_permission_denied(#[fixture(setuid)] _group: &Group) {
    let helper = crate::test_privilege::setuid::setuid_helper();
    let mut cmd = crate::Command::new();
    // `args` is the whole argv, program name included.
    cmd.executable(&helper)
        .args(["cosca_testbin", "setuid-stdin-block", "root"]);
    cmd.stdin(crate::Stdio::pipe()).expect("stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("stdout pipe");
    cmd.stderr(crate::Stdio::null()).expect("stderr null");
    let mut child = cmd.spawn().expect("spawn the setuid helper");
    let stdin = child.stdin().expect("piped stdin");
    let mut ready = [0u8; 1];
    std::io::Read::read_exact(&mut child.stdout().expect("piped stdout"), &mut ready).expect("ready");
    assert_eq!(ready, *b"+");
    let err = child.kill().expect_err("this caller may not signal a root process");
    assert!(
        matches!(&err, crate::error::Error::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied),
        "{err:?}"
    );
    drop(stdin);
    let status = child.wait().expect("the helper exits on EOF");
    assert!(status.success(), "{status:?}");
}

/// A refused id read at the exit check, just before a consume, is an error carrying the errno, and
/// nothing is consumed by a bare pid: for `try_wait`, for the holder of a `wait`, and for the
/// `kqueue` wait's own peek.
///
/// Mutant: the refused read handed back the id-less peek, which `try_reap` then consumes.
#[skuld::test]
fn a_refused_id_read_at_the_exit_check_consumes_nothing() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let forced = uniq_fault::force_uniq_read_once(ReadPurpose::Peek, UniqRead::Refused(libc::EPERM));
    let err = try_wait(&b.owned)
        .expect_err("an unverifiable exit is not consumed")
        .into_io();
    drop(forced);
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    let forced = uniq_fault::force_uniq_read_once(ReadPurpose::Peek, UniqRead::Refused(libc::EACCES));
    let err = b.owned.wait(None).expect_err("nor by a wait").into_io();
    drop(forced);
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    // Still ours, unreaped: the next, verifiable, call reaps it.
    let status = wait_status(&b.owned);
    assert!(status.success(), "{status:?}");
}

/// A verified peek (a caller that treats `Running` as "ours") cannot read an `ECHILD` pid's id: a
/// denial is not a reap, so it is an error with the errno, where the plain peek calls it `Gone`.
///
/// Mutant: the verified peek maps `Held::Refused` to `Foreign(Gone)`.
#[skuld::test]
fn a_refused_echild_read_is_an_error_to_a_verified_peek() {
    let (pid, unique) = echild_yet_resolvable();
    let target = Target::pid(pid, Some(unique));
    let _forced = uniq_fault::force_uniq_read_once(ReadPurpose::Echild, UniqRead::Refused(libc::EPERM));
    let err = exit_only::peek_verified(&target).expect_err("a denied read cannot show a reap");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
}

// The reap kqueue is the holder's alone =====

/// A `try_wait` on another thread, during a holder's wait, neither takes the holder's event nor
/// strands it: the one look it makes is a peek by pid, which touches no kqueue, and the child's
/// exit then wakes the holder.
///
/// Mutant: `try_wait` drains the reap kqueue while another thread holds the wait: the holder sleeps
/// through the exit it was woken for.
#[skuld::test]
fn a_try_wait_during_a_holders_wait_does_not_strand_the_holder() {
    let mut b = Blocker::spawn();
    let (reached_tx, reached_rx) = std::sync::mpsc::channel();
    let holder = std::thread::spawn({
        let owned = std::sync::Arc::clone(&b.owned);
        move || {
            let _blocking = crate::wait::block_probe::on_blocking(move || _ = reached_tx.send(()));
            owned.wait(None)
        }
    });
    reached_rx.recv().expect("the holder must reach its wait");
    assert_eq!(
        try_wait(&b.owned).expect("try_wait"),
        ChildWaitOutcome::DeadlinePassed,
        "the child is running"
    );
    b.end_child();
    let status = status(holder.join().expect("holder"));
    assert!(status.success(), "{status:?}");
}

/// A running child whose unique id cannot be read is an error to a `try_wait` made during another
/// thread's wait (named behaviour change: it was `Running`).
///
/// Mutant: the peek is the plain one, which calls an unreadable id on a running child `Running`.
#[skuld::test]
fn try_wait_during_a_wait_errors_when_a_running_childs_unique_id_is_unreadable() {
    let mut b = Blocker::spawn();
    let (reached_tx, reached_rx) = std::sync::mpsc::channel();
    let holder = std::thread::spawn({
        let owned = std::sync::Arc::clone(&b.owned);
        move || {
            let _blocking = crate::wait::block_probe::on_blocking(move || _ = reached_tx.send(()));
            owned.wait(None)
        }
    });
    reached_rx.recv().expect("the holder must reach its wait");
    let forced = uniq_fault::force_uniq_read_once(ReadPurpose::Running, UniqRead::Refused(libc::EPERM));
    let err = try_wait(&b.owned)
        .expect_err("a running child that cannot be shown to be ours")
        .into_io();
    drop(forced);
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    b.end_child();
    let status = status(holder.join().expect("holder"));
    assert!(status.success(), "{status:?}");
}

/// A `try_wait` that drains the child's `NOTE_EXIT` while the record is not yet visible leaves the
/// event behind it gone from the reap kqueue, and a `wait` still returns: "exit seen" is read from
/// the exit kqueue, which nothing drains.
///
/// Mutant: "exit seen" kept as a flag set by the drain, or read from the reap kqueue: the wait
/// blocks on a queue that holds nothing, for ever.
#[skuld::test]
fn a_try_wait_that_drains_note_exit_then_a_wait_still_returns() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    // The look's peek finds no record, as when XNU is still finishing the exit.
    let forced = exit_seams::force_peeks([Ok(PeekOutcome::Running)]);
    assert_eq!(try_wait(&b.owned).expect("try_wait"), ChildWaitOutcome::DeadlinePassed);
    drop(forced);
    let status = wait_status(&b.owned);
    assert!(status.success(), "{status:?}");
}
