//! macOS-only `OwnedChild` tests: the kqueue wait under `SIG_IGN`, the unique-id checks of
//! `wait`, `try_wait` and `kill`, and the tracer-held and launchd-held children. The cases that
//! change the process-wide `SIGCHLD` disposition each run in a fresh re-exec of the test binary.
//! The `exit_only` backend's own tests are in `wait::exit_only::macos_tests`.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use crate::test_child::{blocker, Console};
use std::time::{Duration, Instant};

use super::fixtures::{status, try_wait, wait_status, Blocker};
use crate::child::owned::{ChildWaitOutcome, OwnedChild};
use crate::elevation::front::TrackedKind;
use crate::error::Error;
use crate::identity::kinfo::kinfo_proc;
use crate::identity::{exit_record, short_info_held_by, FakeKernel, HostKernel, Kernel, UniqRead, LAUNCHD};
use crate::os_process::child::Foreign;
use crate::os_process::macos::child::MacosChild;
use crate::os_process::macos::kqueue::test_hooks;
use crate::os_process::macos::ExitWatch;
use crate::signal::Sig;
use crate::test_groups::{setuid, Group};
use crate::wait::exit_only::macos_tests::{assert_zombie_consumed, echild_yet_resolvable, found, unique_of};

fn far() -> Instant {
    Instant::now() + Duration::from_secs(3600)
}

/// Whether `outcome` says the child is not this process's to reap.
fn is_foreign(outcome: &Result<ChildWaitOutcome, crate::error::Error>) -> bool {
    matches!(outcome, Ok(ChildWaitOutcome::Foreign(_)))
}

// A reap that finds nothing after `Reapable` =====

/// The wait only observes the exit; the drop's consume is the one that can find nothing, right
/// after its own peek saw a zombie, which means the pid names something else now. It takes the
/// `ECHILD` path (nothing to consume, a quiet debug line), with no assert in any build.
///
/// Mutant: a `debug_assert!` on the by-pid target.
#[skuld::test]
fn a_drop_whose_consume_finds_none_after_the_wait_saw_the_exit_takes_the_echild_path() {
    let (mut b, kernel) = Blocker::spawn_over(|pid, _| FakeKernel::over(&HostKernel).on_consume(pid, Ok(None)));
    b.end_child_and_confirm_exit();
    let status = wait_status(&b.owned);
    assert!(status.success(), "{status:?}");
    assert!(!kernel.all_rows_taken(), "the wait consumed");
    let pid = b.pid;
    drop(b);
    assert!(kernel.all_rows_taken(), "the drop must consume");
    // The one consume found nothing, so the zombie was never taken: reap it here.
    assert!(
        crate::test_child::is_unreaped_child(pid),
        "the zombie was taken though the consume found nothing"
    );
    crate::test_child::reaped_elsewhere::reap_behind(pid);
}

// The second peek =====

/// The second peek runs after every first reap of the handle's drop, traced or not. For an
/// untraced child it answers `ECHILD` and is skipped quietly. The first consume states an exit
/// record and takes nothing, as the consume of a child its tracer reparented to this process does,
/// so only a second peek and consume can reap the zombie. The wait before it consumes nothing.
///
/// Mutant: a second peek gated on `p_oppid`: the zombie of an untraced child is left.
#[skuld::test]
fn a_second_peek_runs_after_every_first_reap() {
    let (mut b, kernel) =
        Blocker::spawn_over(|pid, _| FakeKernel::over(&HostKernel).on_consume(pid, Ok(Some(exit_record(0)))));
    b.end_child_and_confirm_exit();
    let status = wait_status(&b.owned);
    assert!(status.success(), "{status:?}");
    assert!(!kernel.all_rows_taken(), "the wait consumed");
    let pid = b.pid;
    drop(b);
    assert!(kernel.all_rows_taken(), "the first reap must consume");
    assert_zombie_consumed(pid, "the second reap");
}

// The box's kernel =====

/// The `OwnedChild` lends the kernel its box was built with: the row stated for it answers a read made
/// through the lent kernel.
///
/// Mutant: `kernel()` lends a host kernel.
#[skuld::test]
fn an_owned_child_lends_the_kernel_its_box_was_built_with() {
    let (b, kernel) = Blocker::spawn_over(|pid, _| FakeKernel::over(&HostKernel).on_peek(pid, Ok(None)));
    assert_eq!(b.owned.kernel().peek(b.pid).expect("the stated row"), None);
    assert!(kernel.all_rows_taken(), "the lent kernel answered from the row");
}

// Task 2b: the `SIG_IGN` hang =====

const MARKER: &str = "COSCA_TESTCFG_SHARED_SIGIGN";
const CASE_ENV: &str = "COSCA_TESTCFG_SHARED_SIGIGN_CASE";

fn run_case(path: &str, case: &str) {
    crate::test_child::run_fixture_case(path, MARKER, CASE_ENV, case);
}

/// Fails, by assertion, a wait that blocks after the kernel reaped `pid` with no event left on the
/// wait's kqueue: nothing is left to wake it, so it would sleep until its deadline. The kernel posts a
/// process's `NOTE_EXIT` before it reaps it, so an event is pending at every block that begins after the
/// reap unless the wait already took it; a block there is a wait that took the event and did not act on
/// it. The reap is read before the look, so an event posted before the reap is seen. A block armed for
/// nothing (a deadline already passed) is no block. The hook panics on the waiting thread, which ends
/// the wait: a recorded block ended by a `SIGCHLD` would only send the same wait round again.
fn no_block_after_the_kernel_reaps(pid: u32) -> crate::wait::block_probe::Armed {
    crate::wait::block_probe::on_each_block(move |block| {
        if !block.is_round() || block.armed == Some(Duration::ZERO) {
            return;
        }
        if !crate::test_child::is_unreaped_child(pid) {
            assert_ne!(
                block.ready(),
                Some(false),
                "the wait blocked with nothing left to wake it, after the kernel reaped pid {pid}"
            );
        }
    })
}

/// A root child adopted into an `OwnedChild`, under `SIGCHLD` set to `SIG_IGN` with a live
/// sibling blocked on its stdin, so the kernel reaps the root itself and a blocking `waitid`
/// would sleep until the sibling is gone. The root's stdin closes from inside the holder's first
/// blocking `poll` of the reap kqueue, so the waiter is known to be asleep first. The second guard
/// is [`no_block_after_the_kernel_reaps`] for the root.
fn ignoring_sigchld_with_a_sibling() -> (
    OwnedChild,
    std::process::Child,
    (crate::wait::block_probe::Armed, crate::wait::block_probe::Armed),
) {
    crate::test_child::set_signal_ignored(libc::SIGCHLD, true);
    // Under `SIG_IGN` the kernel reaps the sibling itself when it ends, so a guard's `wait` would
    // fail with `ECHILD`: the child is taken out of its guard, and dropping it closes its stdin.
    let sibling = blocker().into_inner();
    let (root, root_stdin) = blocker().into_parts();
    let root_pid = root.id();
    let id = super::fixtures::identity_of(&root);
    let owned = OwnedChild::adopt(root, id, TrackedKind::Own).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    let mut root_stdin = Some(root_stdin);
    let end = crate::wait::block_probe::on_blocking(move || drop(root_stdin.take()));
    let reaped = no_block_after_the_kernel_reaps(root_pid);
    (owned, sibling, (end, reaped))
}

/// A `wait` on a child the kernel reaped returns `ECHILD` while a sibling lives. (A blocking
/// `waitid` there would sleep until the child list empties: `HostKernel`'s `waitid_record` asserts
/// `WNOHANG` for that.)
///
/// Mutant: the wait reads the kernel's own reap (no zombie, `ECHILD` from the by-pid `waitid`) as
/// anything but `Foreign`: it answers a status or an error. Or it ignores `NOTE_REAP` and blocks
/// again: [`no_block_after_the_kernel_reaps`] fails the assertion at that block.
#[skuld::test]
fn a_wait_on_a_child_the_kernel_reaped_returns_while_a_sibling_lives() {
    if !crate::test_child::is_marked_fixture_reexec(MARKER) {
        return run_case(
            crate::test_child::fixture_path!(a_wait_on_a_child_the_kernel_reaped_returns_while_a_sibling_lives),
            "",
        );
    }
    let (owned, _sibling, _end) = ignoring_sigchld_with_a_sibling();
    let outcome = owned.wait(None);
    assert!(is_foreign(&outcome), "the kernel reaped the root: {outcome:?}");
}

/// A `wait_deadline` far past the bound returns `ECHILD`, not `DeadlinePassed`.
///
/// Mutant: the deadline path of `wait` reads the kernel's reap as a child still running, and answers
/// `DeadlinePassed`: it blocks again, and [`no_block_after_the_kernel_reaps`] fails the assertion at
/// that block instead of waiting out the hour.
#[skuld::test]
fn a_wait_timeout_far_past_the_bound_returns_echild() {
    if !crate::test_child::is_marked_fixture_reexec(MARKER) {
        return run_case(
            crate::test_child::fixture_path!(a_wait_timeout_far_past_the_bound_returns_echild),
            "",
        );
    }
    let (owned, _sibling, _end) = ignoring_sigchld_with_a_sibling();
    let outcome = owned.wait(Some(far()));
    assert!(is_foreign(&outcome), "the kernel reaped the root: {outcome:?}");
}

/// A sync drop of a child the kernel reaped returns: its wait after a successful kill answers
/// `ECHILD` instead of sleeping.
///
/// Mutant: the drop's kill sends nothing before its wait: `cat` ends of its own accord and the shell
/// prints `eof`. Or the drop's wait ignores `NOTE_REAP` and blocks again after the kernel's reap:
/// [`no_block_after_the_kernel_reaps`] fails the assertion at that block.
#[skuld::test]
fn a_sync_drop_of_a_child_the_kernel_reaped_returns() {
    if !crate::test_child::is_marked_fixture_reexec(MARKER) {
        return run_case(
            crate::test_child::fixture_path!(a_sync_drop_of_a_child_the_kernel_reaped_returns),
            "",
        );
    }
    crate::test_child::set_signal_ignored(libc::SIGCHLD, true);
    // Taken out of its guard: the kernel reaps it (see `ignoring_sigchld_with_a_sibling`).
    #[allow(clippy::zombie_processes, reason = "the kernel reaps it: SIGCHLD is ignored")]
    let _sibling = blocker().into_inner();
    use std::io::Read as _;
    let mut cmd = crate::test_child::command(Console::Hidden);
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
    let _no_late_block = no_block_after_the_kernel_reaps(child.pid());
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
    // The peek's id check is the first unique-id read.
    let (mut b, _) =
        Blocker::spawn_over(|pid, unique| FakeKernel::over(&HostKernel).on_unique_info(pid, found(unique ^ 1)));
    b.end_child_and_confirm_exit();
    let outcome = try_wait(&b.owned);
    assert!(is_foreign(&outcome), "another process holds the pid: {outcome:?}");
    wait_status(&b.owned);
}

/// The wait itself checks the id: a pid that reads as another process ends the wait as `Gone`,
/// before any reap step.
///
/// Mutant: the wait's peek without the id: it reports `Reapable` and reaches the reap.
#[skuld::test]
fn a_wait_on_a_pid_with_another_unique_id_never_reaches_the_reap() {
    // The peek's id check is the first unique-id read.
    let (mut b, _) =
        Blocker::spawn_over(|pid, unique| FakeKernel::over(&HostKernel).on_unique_info(pid, found(unique ^ 1)));
    b.end_child_and_confirm_exit();
    let outcome = b.owned.wait(None);
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
    // The kill's version read is the first unique-id read.
    let (mut b, _) =
        Blocker::spawn_over(|pid, unique| FakeKernel::over(&HostKernel).on_unique_info(pid, found(unique ^ 1)));
    let log = crate::send_log::Capture::start();
    b.owned
        .signal(Sig::Kill)
        .expect("a pid that is not ours is gone, not an error");
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

/// `kill` on this child's own unreaped zombie is `Exited`, which a kill reads as delivered: the kernel
/// answers `ESRCH` for a zombie, but the pid still has the child's unique id and `p_idversion`, so it is
/// ours and not gone. A zombie that reads as `Gone` would send `kill` down the already-reaped path; one
/// that reads as `Delivered` would say the kernel took a signal it never did.
///
/// Mutants: an exited-but-unreaped child is mapped to `Gone`, or to `Delivered`.
#[skuld::test]
fn kill_on_an_own_unreaped_zombie_is_exited() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    assert_eq!(b.owned.signal(Sig::Kill).expect("kill"), crate::signal::Sent::Exited);
    // The zombie was never consumed: a real wait reaps it, and it ended of its own accord.
    let status = wait_status(&b.owned);
    assert!(status.success(), "{status:?}");
}

// A pid that is not our child, yet still names it (a tracer holds it) =====

/// The child `pid`, whose unique id is `unique`, watched through a fresh [`MacosChild`] that asks
/// `kernel`: an `OwnedChild` over it, which reaps the child.
pub(super) fn watch(kernel: impl Kernel + Send + 'static, pid: u32, unique: u64) -> OwnedChild {
    let mac = MacosChild::new(kernel, pid, unique).expect("watch the child");
    OwnedChild::new(Box::new(mac), TrackedKind::Own)
}

/// `pid`'s parent reads as `holder` says at each read, and its state as the host's: who holds the
/// child, as a tracer, launchd or this process does, is a value the test changes.
fn held_by_whom(pid: u32, holder: &Arc<AtomicU32>) -> FakeKernel<'static> {
    let holder = Arc::clone(holder);
    FakeKernel::over(&HostKernel)
        .on_every_short_bsd(pid, move || Ok(short_info_held_by(pid, holder.load(Ordering::SeqCst))))
}

/// A child whose tracer dies while the child is exiting: XNU sends the child's `NOTE_EXIT` and
/// `SIGCHLD` to the tracer alone, then gives the child to launchd. The wait watches the tracer as
/// well, and its `NOTE_EXIT` makes the wait look again, which finds launchd holding the child:
/// `Orphaned`. This process's own pid stands in for the child (`waitid` answers `ECHILD`, and its id
/// resolves), and a blocker for the tracer; the parent read is stated: the stand-in while it runs,
/// launchd once it has exited. The stand-in is this test's child, so its `SIGCHLD` wakes the wait
/// too, and the assertion is on the tracer's `NOTE_EXIT` among the wait's events.
///
/// Mutant: the wait does not watch the tracer.
#[skuld::test]
fn a_wait_on_a_child_whose_tracer_dies_during_its_exit_is_woken_by_the_tracers_exit() {
    let (pid, unique) = echild_yet_resolvable();
    let mut tracer = blocker();
    let tracer_stdin = tracer.stdin.take().expect("piped stdin");
    let tracer_pid = tracer.id();
    let holder = Arc::new(AtomicU32::new(tracer_pid));
    let owned = watch(held_by_whom(pid, &holder), pid, unique);
    let _end = crate::wait::block_probe::on_blocking(move || {
        drop(tracer_stdin);
        crate::test_child::wait_until_zombie(tracer_pid);
        holder.store(LAUNCHD, Ordering::SeqCst);
    });
    let _ = test_hooks::take_events();
    let outcome = owned.wait(None).expect("wait");
    let events = test_hooks::take_events();
    assert!(
        events
            .iter()
            .any(|&(filter, fflags)| filter == libc::EVFILT_PROC && fflags & libc::NOTE_EXIT != 0),
        "the tracer's exit must wake the wait: {events:?}"
    );
    assert_eq!(outcome, ChildWaitOutcome::Foreign(Foreign::Orphaned));
}

/// For each round whose hook staged a wake: its index and whether the wait's kqueue held an event at
/// the block (`ready()`).
#[derive(Clone, Default)]
pub(super) struct Looks(std::rc::Rc<std::cell::RefCell<Vec<Look>>>);

type Look = (u32, Option<bool>);

impl Looks {
    pub(super) fn get(&self) -> Vec<Look> {
        self.0.borrow().clone()
    }
}

/// The rounds of a wait: `hook` runs at each blocking round with the round's index (0 for the first)
/// and answers whether it staged a wake for it. The hook must have an ordering edge from staging to the
/// look: an event the kernel has posted by the time the hook returns.
///
/// A round that staged a wake is looked at: `ready()` says whether the wait's kqueue holds an event
/// ([`Looks`]). A round that staged none, or whose look found nothing, gets a `SIGCHLD` to this
/// process, which the wait always watches: it ends the round, so a wake the wait missed fails the
/// test's assertion on [`Looks`] instead of blocking it for ever.
pub(super) fn on_rounds(mut hook: impl FnMut(u32) -> bool + 'static) -> (crate::wait::block_probe::Armed, Looks) {
    let looks = Looks::default();
    let armed = crate::wait::block_probe::on_each_block({
        let looks = looks.clone();
        move |block| {
            // A round is a numbered block: another waiter's `Condvar` block has no number.
            let Some(n) = block.n else { return };
            let round = n - 1;
            if hook(round) {
                let look = block.ready();
                looks.0.borrow_mut().push((round, look));
                if look == Some(true) {
                    return;
                }
            }
            test_hooks::send_signal(std::process::id(), libc::SIGCHLD);
        }
    });
    (armed, looks)
}

/// A tracer that attaches after the wait's check: XNU reparents the child to it and sends the child
/// `SIGSTOP` (see `wait::macos::TracerWatch`). The wait watches the child's signals,
/// so it looks again, finds the tracer and watches it too; the tracer's exit, with launchd then
/// holding the child, ends the wait: `Orphaned`. This process's own pid stands in for the child, and
/// a blocker for the tracer; the parent read is stated: this process until the attach, then the
/// stand-in, then launchd once that has exited. A `SIGCONT` to this process stands in for the
/// attach's `SIGSTOP`. Nothing but that signal wakes the wait's first block.
///
/// Each staged wake is looked at, at its block (`on_rounds`). Round 0's ordering edge is the `kill(2)`:
/// XNU's `psignal_internal` posts `NOTE_SIGNAL` to the target's knotes before it returns, ahead of any
/// disposition check. Round 1's is `wait_until_zombie` on the stand-in: a process's `NOTE_EXIT` is
/// posted before it is a zombie; its `SIGCHLD` lands on the wait's kqueue too, so round 1's look says that
/// the wait has an event to wake on, not which.
///
/// Mutant: the wait registers no `NOTE_SIGNAL` on the child: the look at the first staged wake finds
/// nothing.
#[skuld::test]
fn a_wait_on_a_child_a_tracer_attaches_to_late_is_woken_by_the_attach() {
    use std::cell::RefCell;

    let (pid, unique) = echild_yet_resolvable();
    let mut tracer = blocker();
    let tracer_stdin = tracer.stdin.take().expect("piped stdin");
    let tracer_pid = tracer.id();
    let holder = Arc::new(AtomicU32::new(pid));
    let owned = watch(held_by_whom(pid, &holder), pid, unique);
    let tracer_stdin = RefCell::new(Some(tracer_stdin));
    let (_rounds, looks) = on_rounds(move |round| match round {
        0 => {
            holder.store(tracer_pid, Ordering::SeqCst);
            test_hooks::send_signal(pid, libc::SIGCONT);
            true
        }
        1 => {
            drop(tracer_stdin.borrow_mut().take());
            crate::test_child::wait_until_zombie(tracer_pid);
            holder.store(LAUNCHD, Ordering::SeqCst);
            true
        }
        _ => false,
    });
    let outcome = owned.wait(None);
    assert_eq!(
        looks.get(),
        [(0, Some(true)), (1, Some(true))],
        "the attach's SIGCONT, then the tracer's exit, must each leave the wait an event to wake on"
    );
    assert_eq!(outcome.expect("wait"), ChildWaitOutcome::Foreign(Foreign::Orphaned));
}

/// The `kinfo_proc` of the live process `pid`, which this process started and `tracer` holds.
fn started_by_us_traced_by(pid: u32, tracer: u32) -> kinfo_proc {
    kinfo_proc::of_host_held_by(pid, std::process::id() as libc::pid_t, tracer as libc::pid_t)
}

/// A tracer that is itself traced: XNU sends its `NOTE_EXIT` only to its own tracer, and its exit
/// sends that tracer `SIGCHLD` (see `wait::macos::TracerWatch`). The wait follows the chain of tracers and watches the signals of each, so
/// that `SIGCHLD` wakes it, and the look after it finds launchd holding the child: `Orphaned`. This
/// process's own pid stands in for the child, held by one blocker; a second blocker stands in for
/// that one's tracer, by its stated parents. A `SIGCHLD` to the second stands in for the first one's
/// exit, and the child's parent read then answers launchd. Nothing but that `SIGCHLD` wakes the wait.
///
/// The staged wake is looked at, at its block (`on_rounds`). The ordering edge is the `kill(2)`: XNU's
/// `psignal_internal` posts `NOTE_SIGNAL` to the target's knotes before it returns, ahead of any
/// disposition check. The signal goes to the second blocker, not to this process,
/// so no other event is on the wait's kqueue: a look that finds one is the registration.
///
/// Mutant: the walk stops at the child's tracer: the look at the staged wake finds nothing.
#[skuld::test]
fn a_wait_on_a_child_whose_tracer_is_traced_is_woken_by_that_tracers_exit() {
    let (pid, unique) = echild_yet_resolvable();
    let tracer = blocker();
    let outer = blocker();
    let (tracer_pid, outer_pid) = (tracer.id(), outer.id());
    let holder = Arc::new(AtomicU32::new(tracer_pid));
    let kernel =
        held_by_whom(pid, &holder).on_every_kinfo(tracer_pid, move || started_by_us_traced_by(tracer_pid, outer_pid));
    let owned = watch(kernel, pid, unique);
    let (_rounds, looks) = on_rounds(move |round| {
        if round != 0 {
            return false;
        }
        holder.store(LAUNCHD, Ordering::SeqCst);
        test_hooks::send_signal(outer_pid, libc::SIGCHLD);
        true
    });
    let outcome = owned.wait(None);
    assert_eq!(
        looks.get(),
        [(0, Some(true))],
        "the SIGCHLD to the tracer's tracer must leave the wait an event to wake on"
    );
    assert_eq!(outcome.expect("wait"), ChildWaitOutcome::Foreign(Foreign::Orphaned));
}

/// A tracer that began its exit, then lost its own tracer: XNU gives it to launchd and keeps its
/// `p_oppid`, so its `NOTE_EXIT` and its `SIGCHLD` reach only launchd (see
/// `wait::macos::TracerWatch`). It hands the child over once its exit reaches its children, so the
/// look is `Recheck` and the wait pauses on a backoff instead of blocking for an event that never
/// comes. This process's own pid stands in for the child, held by a blocker whose stated parents say
/// launchd holds it and a tracer attached to it; the child's parent read answers the blocker until
/// the first pause, then launchd.
///
/// Mutant: a tracer launchd holds is `Block` (the look's answer is the reap kqueue, not `Recheck`),
/// so the wait blocks with no timeout: the round hook's wake then ends it, and its first block is
/// not a timed pause.
#[skuld::test]
fn a_wait_on_a_child_whose_tracer_is_exiting_at_launchd_peeks_again_on_a_backoff() {
    let (pid, unique) = echild_yet_resolvable();
    let tracer = blocker();
    let tracer_pid = tracer.id();
    let holder = Arc::new(AtomicU32::new(tracer_pid));
    let kernel =
        held_by_whom(pid, &holder).on_every_kinfo(tracer_pid, move || started_by_us_traced_by(tracer_pid, LAUNCHD));
    let owned = watch(kernel, pid, unique);
    // The first pause is the wait's own backoff: the child's parent read answers launchd after it.
    let _pause = crate::wait::block_probe::on_pause({
        let holder = Arc::clone(&holder);
        move || holder.store(LAUNCHD, Ordering::SeqCst)
    });
    // A wait that blocks instead of pausing gets the wake that lets it end, and fails below.
    let _rounds = on_rounds(move |round| {
        holder.store(LAUNCHD, Ordering::SeqCst);
        round != 0
    });
    crate::wait::block_probe::take();
    let outcome = owned.wait(None).expect("wait");
    let armed = crate::wait::block_probe::take();
    assert!(
        matches!(armed.first(), Some(Some(_))),
        "the first block must be a timed pause, to look again: {armed:?}"
    );
    assert_eq!(outcome, ChildWaitOutcome::Foreign(Foreign::Orphaned));
}

/// A `Running` peek names a child of ours; if the pid now reads as another process, it is a reuse.
///
/// Mutant: `Running` never checks the id.
#[skuld::test]
fn a_running_peek_of_a_pid_with_another_unique_id_is_foreign() {
    // Each `try_wait` makes one unique-id read, the peek's id check, so the rows answer them in order.
    let (mut b, _) = Blocker::spawn_over(|pid, unique| {
        FakeKernel::over(&HostKernel)
            .on_unique_info(pid, found(unique ^ 1))
            .on_unique_info(pid, UniqRead::Refused(libc::EPERM))
            .on_unique_info(pid, found(unique))
    });
    let outcome = try_wait(&b.owned);
    assert!(is_foreign(&outcome), "another process holds the pid: {outcome:?}");
    // An id that cannot be read, or that matches, leaves it running.
    for why in ["a refused id read", "a matching id"] {
        assert_eq!(
            try_wait(&b.owned).expect("try_wait"),
            ChildWaitOutcome::DeadlinePassed,
            "{why}"
        );
    }
    b.end_child();
    wait_status(&b.owned);
}

/// A `Child::wait` whose peek finds the zombie held by launchd (its tracer died) gives up on it with
/// a `warn` that it is not ours to reap, not silently as for a reap.
///
/// Mutant: `Foreign::Orphaned` is folded into `Gone` without a log.
#[skuld::test]
fn a_wait_on_a_zombie_launchd_holds_warns_it_is_not_ours_to_reap() {
    crate::log_capture::install();
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    let mut child = cmd.spawn().expect("spawn");
    let pid = child.pid();
    drop(writer);
    crate::test_child::wait_until_zombie(pid);
    let mark = crate::log_capture::mark();
    // The wait's own look is a reap.
    child
        .proc
        .script_over(|f| f.reaps([crate::os_process::fake::ReapAnswer::Foreign(Foreign::Orphaned)]));
    _ = child.wait();
    let records = crate::log_capture::records_since_on_current_thread(mark, &format!("pid {pid}"));
    assert!(
        records
            .iter()
            .any(|(level, text)| *level == log::Level::Warn && text.contains("not ours to reap")),
        "{records:?}"
    );
    // The drop reaps what the scripted look left.
    drop(child);
}

// The reap finds no exit record after the peek saw one =====

/// A drop whose own peek finds no exit record right after the wait's peek saw one is still the
/// child's handle (a foreign reap is `Foreign`): it consumes nothing, and neither loops nor
/// waits, since the handle is ending.
///
/// Mutant: the drop consumes by the pid without its own peek having found the record.
#[skuld::test]
fn a_drop_that_finds_no_exit_record_after_the_wait_saw_one_consumes_nothing() {
    // The wait's peek sees the exit; the drop's own peek then finds none.
    let (mut b, kernel) = Blocker::spawn_over(|pid, _| {
        FakeKernel::over(&HostKernel)
            .on_peek(pid, Ok(Some(exit_record(0))))
            .on_peek(pid, Ok(None))
    });
    b.end_child_and_confirm_exit();
    let status = wait_status(&b.owned);
    assert!(status.success(), "{status:?}");
    let pid = b.pid;
    drop(b);
    assert!(kernel.all_rows_taken(), "the wait and the drop must each peek");
    assert!(
        crate::test_child::is_unreaped_child(pid),
        "the drop consumed a zombie its own peek did not find"
    );
    crate::test_child::reaped_elsewhere::reap_behind(pid);
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
    let owned = OwnedChild::adopt(child, id, TrackedKind::Own).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
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
    let (child, stdin) = crate::test_privilege::spawn_setuid_blocker();
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
    // Each call's peek makes one unique-id read, its id check, so the rows answer them in order.
    let (mut b, _) = Blocker::spawn_over(|pid, _| {
        FakeKernel::over(&HostKernel)
            .on_unique_info(pid, UniqRead::Refused(libc::EPERM))
            .on_unique_info(pid, UniqRead::Refused(libc::EACCES))
    });
    b.end_child_and_confirm_exit();
    let err = try_wait(&b.owned)
        .expect_err("an unverifiable exit is not consumed")
        .into_io();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    let err = b.owned.wait(None).expect_err("nor by a wait").into_io();
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
    use std::sync::atomic::{AtomicBool, Ordering};

    // The kernel answers every unique-id read by `refused`, which the test raises only while the
    // holder is parked in its blocking hook, making no read: the holder's looks before it blocks
    // find the child's id, whatever their number, and every read the `try_wait` makes is refused.
    let refused = Arc::new(AtomicBool::new(false));
    let (mut b, _) = Blocker::spawn_over({
        let refused = Arc::clone(&refused);
        move |pid, unique| {
            FakeKernel::over(&HostKernel).on_every_unique_info(pid, move || {
                if refused.load(Ordering::SeqCst) {
                    UniqRead::Refused(libc::EPERM)
                } else {
                    found(unique)
                }
            })
        }
    });
    let (reached_tx, reached_rx) = std::sync::mpsc::channel();
    let (staged_tx, staged_rx) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn({
        let owned = Arc::clone(&b.owned);
        move || {
            let _blocking = crate::wait::block_probe::on_blocking(move || {
                _ = reached_tx.send(());
                staged_rx.recv().expect("the test stages the refusal");
            });
            owned.wait(None)
        }
    });
    reached_rx.recv().expect("the holder must reach its wait");
    refused.store(true, Ordering::SeqCst);
    let err = try_wait(&b.owned)
        .expect_err("a running child that cannot be shown to be ours")
        .into_io();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    // The holder's poll is next: its looks after the exit read the child's id again.
    refused.store(false, Ordering::SeqCst);
    staged_tx.send(()).expect("the holder is waiting for the stage");
    b.end_child();
    let status = status(holder.join().expect("holder"));
    assert!(status.success(), "{status:?}");
}

/// A `try_wait` that drains the child's `NOTE_EXIT` while the record is not yet visible leaves the
/// event gone from the reap kqueue, and a `wait` whose first look still finds no record returns:
/// "exit seen" is read from the exit kqueue, which nothing drains, so that look is a `Recheck`.
///
/// The wait's first look is a `Recheck`, which pauses on a backoff (a sleep, not a block), so a correct
/// wait never blocks. A block is the mutant's; the hook there ends it through a `SIGCHLD` to this
/// process, which the wait always watches. That knote stays pending whether the poll has begun or
/// not, so no ordering is needed, and the wait's second look reads the zombie. The assertion that
/// no block was made then fails.
///
/// Mutant: "exit seen" taken from the drain's own result, or read from the reap kqueue: the wait
/// blocks on a queue that holds nothing.
#[skuld::test]
fn a_try_wait_that_drains_note_exit_then_a_wait_still_returns() {
    use std::cell::Cell;
    use std::rc::Rc;

    // Each look's peek finds no record, as when XNU is still finishing the exit: the `try_wait`'s,
    // which drains `NOTE_EXIT` from the reap kqueue, and the first of the `wait`'s, which finds
    // that queue empty. The `wait`'s second peek is the real one.
    let (mut b, kernel) = Blocker::spawn_over(|pid, _| {
        FakeKernel::over(&HostKernel)
            .on_peek(pid, Ok(None))
            .on_peek(pid, Ok(None))
    });
    b.end_child_and_confirm_exit();
    assert_eq!(try_wait(&b.owned).expect("try_wait"), ChildWaitOutcome::DeadlinePassed);
    let blocked = Rc::new(Cell::new(false));
    let _end = crate::wait::block_probe::on_each_block({
        let blocked = Rc::clone(&blocked);
        move |_| {
            blocked.set(true);
            test_hooks::send_signal(std::process::id(), libc::SIGCHLD);
        }
    });
    let status = wait_status(&b.owned);
    assert!(
        !blocked.get(),
        "the wait must pause and look again, not block on an empty queue"
    );
    assert!(status.success(), "{status:?}");
    assert!(kernel.all_rows_taken(), "the try_wait and the wait must each peek");
}

/// A child whose exit watch has fired and whose confirming read is refused is `Dead` when the reap
/// peek shows its exit record: `liveness` does not fail where the record answers, as it did not
/// before the watch was confirmed by a read.
///
/// The confirming read is the first unique-id read, so the row refuses it; the peek's id check
/// after it is the host's.
///
/// Mutant: `OwnedChild::liveness` propagates the refusal of `exited` without asking the peek; or
/// answers `Dead` without the confirming read, leaving the row for the `try_wait`.
#[skuld::test]
fn a_refused_confirmation_is_dead_when_the_peek_shows_the_exit_record() {
    let (mut b, _) =
        Blocker::spawn_over(|pid, _| FakeKernel::over(&HostKernel).on_unique_info(pid, UniqRead::Refused(libc::EPERM)));
    b.end_child_and_confirm_exit();
    assert!(
        matches!(b.owned.liveness(), Ok(crate::identity::Liveness::Dead)),
        "the exit record is visible whatever the confirming read says"
    );
    let reaped = status(try_wait(&b.owned));
    assert!(reaped.success(), "{reaped:?}");
}

/// A child whose exit watch has fired while it runs and whose confirming read is refused is the
/// refusal, not `Alive`, when the peek reads it running: a running peek proves nothing (a tracer can
/// hold the zombie). The registration refusal stands in for the early edge, and the confirming read
/// is the first unique-id read, so the row refuses it.
///
/// Mutant: `OwnedChild::liveness` answers `Alive` for a child the peek reads running.
#[skuld::test]
fn a_refused_confirmation_is_the_refusal_when_the_peek_reads_the_child_running() {
    let (b, kernel) = Blocker::spawn_over(|pid, _| {
        FakeKernel::over(&HostKernel)
            .on_subscribe_refused(ExitWatch::registration(pid), libc::ESRCH)
            .on_unique_info(pid, UniqRead::Refused(libc::EPERM))
    });
    let err = b.owned.liveness().expect_err("a running peek does not answer");
    assert!(matches!(err, Error::Unassessable { .. }), "{err:?}");
    assert_eq!(crate::error::first_os_code(&err), Some(libc::EPERM), "{err:?}");
    assert!(
        kernel.all_rows_taken(),
        "the adoption's registration was refused, and the confirming read was refused"
    );
}
