//! macOS-only `OwnedChild` tests: the kqueue wait under `SIG_IGN`, the unique-id checks of
//! `wait`, `try_wait` and `kill`, and the tracer-held and launchd-held children. The cases that
//! change the process-wide `SIGCHLD` disposition each run in a fresh re-exec of the test binary.
//! The `exit_only` backend's own tests are in `wait::exit_only::macos_tests`.

use std::time::{Duration, Instant};

use super::fixtures::{spawn_std_blocker, status, try_wait, wait_status, Blocker};
use crate::child::owned::{ChildWaitOutcome, OwnedChild};
use crate::identity::{ppid_fault, uniq_fault, ReadPurpose, UniqRead, LAUNCHD};
use crate::os_process::child::{Foreign, PeekOutcome};
use crate::os_process::macos::kqueue::test_hooks::{self, ForcedOnce};
use crate::signal::Sig;
use crate::test_groups::{setuid, Group};
use crate::wait::exit_only::macos_tests::{echild_yet_resolvable, found, held_by_a_tracer, unique_of};
use crate::wait::exit_only::seams::{self as exit_seams, HolderStep};

fn far() -> Instant {
    Instant::now() + Duration::from_secs(3600)
}

/// Whether `outcome` says the child is not this process's to reap.
fn is_foreign(outcome: &Result<ChildWaitOutcome, crate::error::Error>) -> bool {
    matches!(outcome, Ok(ChildWaitOutcome::Foreign(_)))
}

// A reap that finds nothing after `Reapable` =====

/// A consuming reap that finds nothing right after the wait saw a zombie means the pid
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

// The second peek =====

/// The second peek runs after every first reap, traced or not. For an untraced child it
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

/// `kill` on a live child sends `SIGKILL` through its audit token and records it.
///
/// Mutant: nothing sent.
#[skuld::test]
fn kill_signals_a_live_child_through_its_audit_token() {
    let b = Blocker::spawn();
    let log = crate::send_log::Capture::start();
    b.owned.signal(Sig::Kill).expect("kill");
    assert_eq!(log.entries(), [(b.pid, Sig::Kill, crate::send_log::Via::Identity)]);
    let status = wait_status(&b.owned);
    assert_eq!(super::fixtures::signal_of(status), Some(libc::SIGKILL));
}

/// `kill` on this child's own unreaped zombie is `Delivered`, as on Linux: the kernel answers `ESRCH`
/// for a zombie, but the pid still has the child's unique id and `p_idversion`, so it is ours and
/// not gone. A zombie that reads as `Gone` would send `kill` down the already-reaped path.
///
/// Mutant: an exited-but-unreaped child is mapped to `Gone`.
#[skuld::test]
fn kill_on_an_own_unreaped_zombie_is_delivered() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    assert_eq!(b.owned.signal(Sig::Kill).expect("kill"), crate::signal::Sent::Delivered);
    // The zombie was never consumed: a real wait reaps it, and it ended of its own accord.
    let status = wait_status(&b.owned);
    assert!(status.success(), "{status:?}");
}

// A pid that is not our child, yet still names it (a tracer holds it) =====

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

/// A `Child::wait` whose peek finds the zombie held by launchd (its tracer died) gives up on it with
/// a `warn` that it is not ours to reap, not silently as for a reap.
///
/// Mutant: `Foreign::Orphaned` is folded into `Gone` without a log.
#[skuld::test]
fn a_wait_on_a_zombie_launchd_holds_warns_it_is_not_ours_to_reap() {
    crate::log_capture::install();
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    let child = cmd.spawn().expect("spawn");
    let pid = child.id().pid();
    drop(writer);
    crate::test_child::wait_until_zombie(pid);
    let mark = crate::log_capture::mark();
    let _orphaned = exit_seams::force_peek_once(Ok(PeekOutcome::Foreign(Foreign::Orphaned)));
    _ = child.wait();
    let records = crate::log_capture::records_since_on_current_thread(mark, &format!("pid {pid}"));
    assert!(
        records
            .iter()
            .any(|(level, text)| *level == log::Level::Warn && text.contains("not ours to reap")),
        "{records:?}"
    );
    // The drop reaps what the forced peek left.
    drop(child);
}

// The reap finds no exit record after the peek saw one =====

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

// The reap kqueue is the holder's alone =====

/// A `try_wait` on another thread, during a holder's wait, neither takes the holder's event nor
/// strands it: the one look it makes is a peek by pid, which touches no kqueue. The child exits,
/// and `try_wait` runs, before the holder polls, so the exit's event is already queued when the
/// holder blocks, and wakes it at once.
///
/// Mutant: `try_wait` drains the reap kqueue while another thread holds the wait: the queue is
/// empty when the holder polls, and it sleeps through the exit it was woken for.
#[skuld::test]
fn a_try_wait_during_a_holders_wait_does_not_strand_the_holder() {
    let mut b = Blocker::spawn();
    let (reached_tx, reached_rx) = std::sync::mpsc::channel();
    let (staged_tx, staged_rx) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn({
        let owned = std::sync::Arc::clone(&b.owned);
        move || {
            // Every lock is released here, and the poll is next: the exit and the `try_wait` are
            // staged before it.
            let _blocking = crate::wait::block_probe::on_blocking(move || {
                _ = reached_tx.send(());
                staged_rx.recv().expect("the test stages the exit");
            });
            owned.wait(None)
        }
    });
    reached_rx.recv().expect("the holder must reach its wait");
    b.end_child_and_confirm_exit();
    let peeked = status(try_wait(&b.owned));
    assert!(peeked.success(), "{peeked:?}");
    staged_tx.send(()).expect("the holder is waiting for the stage");
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
/// event gone from the reap kqueue, and a `wait` whose first look still finds no record returns:
/// "exit seen" is read from the exit kqueue, which nothing drains, so that look is a `Recheck`.
///
/// Mutant: "exit seen" taken from the drain's own result, or read from the reap kqueue: the wait
/// blocks on a queue that holds nothing, for ever.
#[skuld::test]
fn a_try_wait_that_drains_note_exit_then_a_wait_still_returns() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    // Each look's peek finds no record, as when XNU is still finishing the exit: the `try_wait`'s,
    // which drains `NOTE_EXIT` from the reap kqueue, and the first of the `wait`'s, which finds
    // that queue empty. The `wait`'s second peek is the real one.
    let forced = exit_seams::force_peeks([Ok(PeekOutcome::Running), Ok(PeekOutcome::Running)]);
    assert_eq!(try_wait(&b.owned).expect("try_wait"), ChildWaitOutcome::DeadlinePassed);
    let status = wait_status(&b.owned);
    drop(forced);
    assert!(status.success(), "{status:?}");
    exit_seams::assert_peeks_exhausted();
}
