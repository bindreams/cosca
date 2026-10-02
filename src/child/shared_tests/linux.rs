//! Linux-only `SharedChild` tests: the holder's steps around a zombie only its tracer sees, the
//! `poll` deadline, and adoption (`pidfd_open` by number).

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::fixtures::{park_holder, spawn_std_blocker, Blocker};
use crate::child::shared::seams::{self, ForcedWait};
use crate::child::shared::SharedChild;
use crate::identity::ProcessId;
use crate::wait::backend::fault;
use crate::wait::exit_only::seams::{self as exit_seams, ForcedReap, HolderStep};

fn far() -> Instant {
    Instant::now() + Duration::from_secs(3600)
}

// S11: a zombie only its tracer sees =====

/// A blocking `waitid` that finds no record is a contract breach, not a ptrace stop: it asserts in
/// a debug build and is an error in a release build, never a `Running` the holder loops on.
///
/// Mutant: `Ok(None)` folded into the non-exit arm, which answers `Running`.
#[test]
fn a_blocking_waitid_that_finds_no_record_is_a_contract_breach() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let target = b.shared.target().expect("a pidfd");
    let forced = exit_seams::force_visible_none_once();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::wait::exit_only::wait_visible_exit(&target)
    }));
    drop(forced);
    if cfg!(debug_assertions) {
        assert!(outcome.is_err(), "a debug build asserts the contract");
    } else {
        let err = outcome.expect("release returns").expect_err("a breach is an error");
        assert!(err.to_string().contains("no record"), "{err}");
    }
}

/// S11: an unbounded holder whose reap finds nothing after a real exit blocks in
/// `waitid(WNOWAIT)` rather than re-polling: the pidfd stays readable, so a re-poll would spin at
/// 100% CPU until the tracer lets go.
///
/// Mutant: re-polls, `poll, reap, poll, reap`.
#[test]
fn an_unbounded_holder_whose_reap_finds_none_blocks_in_waitid() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let _none = exit_seams::force_reap_once(ForcedReap::None);
    exit_seams::holder_steps();
    b.shared.wait().expect("wait");
    assert_eq!(
        exit_seams::holder_steps(),
        [
            HolderStep::Poll,
            HolderStep::Reap,
            HolderStep::BlockingWaitid,
            HolderStep::Reap
        ]
    );
}

/// S11: a deadline holder whose reap finds nothing backs off on the handle's `Condvar` instead of
/// re-polling, then re-peeks.
///
/// Mutant: re-polls.
#[test]
fn a_deadline_holder_whose_reap_finds_none_backs_off() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let _none = exit_seams::force_reap_once(ForcedReap::None);
    exit_seams::holder_steps();
    b.shared.wait_deadline(far()).expect("wait_deadline").expect("a status");
    assert_eq!(
        exit_seams::holder_steps(),
        [
            HolderStep::Poll,
            HolderStep::Reap,
            HolderStep::Backoff,
            HolderStep::Reap
        ]
    );
}

/// S11: a holder in its blocking `waitid` holds no lock: `Debug` shows `W`, not `locked`, and
/// `kill` returns.
///
/// Mutant: the `waitid` under the lock, so `Debug`'s `try_lock` fails and prints `locked`.
#[test]
fn a_holder_in_its_blocking_waitid_holds_no_lock() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let (at_waitid_tx, at_waitid_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn({
        let shared = Arc::clone(&b.shared);
        move || {
            let _none = exit_seams::force_reap_once(ForcedReap::None);
            let _hook = exit_seams::on_holder_step(HolderStep::BlockingWaitid, move || {
                _ = at_waitid_tx.send(());
                _ = release_rx.recv();
            });
            shared.wait()
        }
    });
    at_waitid_rx.recv().expect("the holder must reach its blocking waitid");
    // The check comes first, so a RED fails on `locked` rather than hanging in `kill`.
    let printed = format!("{:?}", b.shared);
    assert!(printed.contains("W {"), "the holder is in W: {printed}");
    assert!(
        !printed.contains("locked"),
        "the blocking waitid must hold no lock: {printed}"
    );
    b.shared.kill().expect("kill must not wait for the holder");
    drop(release_tx);
    holder.join().expect("holder").expect("wait");
}

// The poll deadline =====

/// Principle 13 for the `poll` wait: every armed timeout is at most the time remaining, and an
/// expired wait takes one final peek and starts no further round.
///
/// Mutant: an unbounded poll under a deadline (its `debug_assert!` fires); no final peek; every
/// round armed with 1ns.
#[test]
fn a_deadline_poll_arms_the_remaining_time_and_peeks_once_at_expiry() {
    let b = Blocker::spawn();
    let (_clock, at) = crate::wait::test_clock::FrozenClockGuard::install();
    let deadline = at + Duration::from_millis(50);
    crate::wait::block_probe::take();
    exit_seams::holder_steps();
    // The final peek consumes this forced answer: it proves a peek was taken at expiry.
    let peeked = exit_seams::force_peek_once(Ok(crate::wait::exit_only::Peek::Running));
    assert_eq!(
        b.shared
            .wait_deadline(deadline)
            .expect("a running child is not an error"),
        None
    );
    assert!(
        exit_seams::take_forced_peek().is_none(),
        "the wait must take its final peek at expiry"
    );
    drop(peeked);
    let armed = crate::wait::block_probe::take();
    assert!(!armed.is_empty(), "the wait must have blocked at least once");
    let mut previous = Duration::from_millis(50);
    assert_eq!(
        armed[0],
        Some(previous),
        "the first round must be armed with the whole remaining time"
    );
    for a in armed {
        let a = a.expect("a deadline wait arms a bounded timeout");
        assert!(a <= previous, "armed {a:?} with only {previous:?} remaining");
        previous = a;
    }
    assert_eq!(exit_seams::holder_steps(), [HolderStep::Poll, HolderStep::FinalPeek]);
    assert!(crate::wait::now() >= deadline);
}

/// Principle 13 for the `Condvar` wait of a non-holder: each round is armed from the time
/// remaining, recomputed after every wake, so a spurious wake shrinks the next timeout.
///
/// Mutant: the remaining time computed once, before the loop.
#[test]
fn a_deadline_condvar_wait_is_clamped_to_the_remaining_time() {
    let mut b = Blocker::spawn();
    let holder = park_holder(&b.shared, None, || ());
    let (blocked_tx, blocked_rx) = std::sync::mpsc::channel();
    let (again_tx, again_rx) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn({
        let shared = Arc::clone(&b.shared);
        move || {
            let (_clock, at) = crate::wait::test_clock::FrozenClockGuard::install();
            let _first = seams::on_condvar_block(move || {
                _ = blocked_tx.send(());
                // The second round's hook arms from inside the first, under the lock.
                let _second = seams::on_condvar_block(move || {
                    _ = again_tx.send(());
                });
                std::mem::forget(_second);
            });
            let _forced = seams::force_unlocked_wait(ForcedWait::Panic);
            crate::wait::block_probe::take();
            let got = shared.wait_deadline(at + Duration::from_secs(3600));
            (got, crate::wait::block_probe::take())
        }
    });
    blocked_rx.recv().expect("the waiter must block in round one");
    // Taking the lock succeeds only once the waiter is inside its `Condvar` wait, which releases
    // it atomically; notifying under it cannot be lost.
    {
        let _lock = b.shared.lock();
        b.shared.condvar.notify_all();
    }
    again_rx
        .recv()
        .expect("the spurious wake must send the waiter round again");
    // End the child; the holder reaps it, and that wakes the waiter with the cached status.
    b.end_child();
    holder.release_and_join().expect("holder wait").expect("a status");
    let (got, armed) = waiter.join().expect("waiter");
    assert!(matches!(got, Ok(Some(_))), "{got:?}");
    let armed: Vec<Duration> = armed.into_iter().map(|a| a.expect("bounded")).collect();
    assert!(armed.len() >= 2, "a second round must have been armed: {armed:?}");
    assert!(armed[0] <= Duration::from_secs(3600));
    assert!(
        armed[1] < armed[0],
        "the second round must be armed from the recomputed remaining time: {armed:?}"
    );
}

/// A deadline beyond `MAX_BLOCK` is armed in pieces: no `poll` is armed with more than the cap,
/// and the wait still returns the exit. The child is ended from the holder's `Poll` step, so the
/// exit is what wakes the first (capped) poll.
///
/// Mutant: no clamp on the poll's remaining time: the recorded timeout is the whole distance.
#[test]
fn a_deadline_beyond_the_block_limit_is_armed_clamped() {
    let (child, stdin) = spawn_std_blocker();
    let id = super::fixtures::identity_of(&child);
    let shared = SharedChild::adopt(child, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    let mut stdin = Some(stdin);
    let _end = exit_seams::on_holder_step(HolderStep::Poll, move || drop(stdin.take()));
    crate::wait::block_probe::take();
    let deadline = Instant::now() + Duration::from_secs(u64::from(u32::MAX));
    shared
        .wait_deadline(deadline)
        .expect("a far deadline is not an error")
        .expect("the child was ended, so the wait reports its exit");
    let armed = crate::wait::block_probe::take();
    assert!(!armed.is_empty(), "the wait must have polled");
    for a in armed {
        let a = a.expect("a deadline wait arms a bounded poll");
        assert!(a <= crate::wait::MAX_BLOCK, "armed {a:?}");
    }
}

// Adoption =====

/// Adopt with `pidfd_open` forced to `errno`, expecting the gone path.
fn adopt_gone_on(errno: rustix::io::Errno) {
    super::fixtures::assert_adoption_is_gone(|| fault::force_pidfd_open_errno_once(errno));
}

/// `EINVAL` (before 6.16: a reaped leader whose number is held as a PGID, or reused by a
/// non-leader) is the gone path for our own child.
///
/// Mutant: `EINVAL` returned as `Io`, so `adopt` fails and the spawn tears down a child that was
/// never ours.
#[test]
fn adopt_on_einval_takes_the_gone_path() {
    adopt_gone_on(rustix::io::Errno::INVAL);
}

/// `ENOENT` (from 6.16: a number reused by a live non-leader thread) is the gone path too.
///
/// Mutant: `ENOENT` returned as `Io`, so `adopt` fails on a 6.16 kernel.
#[test]
fn adopt_on_enoent_takes_the_gone_path() {
    adopt_gone_on(rustix::io::Errno::NOENT);
}

/// A pidfd whose identity no longer matches is gone, whatever the pid now names.
///
/// Mutant: a by-number pidfd trusted unchecked.
#[test]
fn adopt_treats_a_pidfd_whose_identity_is_gone_as_gone() {
    super::fixtures::assert_adoption_is_gone(|| fault::force_exists_once(crate::identity::Existence::Gone));
}

/// A pid that is not our child answers `ECHILD` to the confirming `waitid`, even when a pidfd for
/// it opens and its identity matches: it is gone for us.
///
/// Mutant: a by-number pidfd trusted unchecked.
#[test]
fn adopt_treats_a_pidfd_that_is_not_our_child_as_gone() {
    // SAFETY: `getppid` takes no arguments and cannot fail.
    let parent = unsafe { libc::getppid() } as u32;
    let id = ProcessId::of(parent).found();
    let opened = crate::wait::backend::open_own_child(parent, id).expect("open");
    assert!(opened.is_none(), "our parent is never our child");
}

/// Adopt a live blocker under a forced `/proc` view whose identity check would say `Gone`, and
/// return the shared handle: the check must be skipped and the confirming `waitid` decide.
fn adopt_under_view_with_exists_gone(view: crate::identity::proc_view_fault::ForcedView) {
    let (child, stdin) = spawn_std_blocker();
    let id = super::fixtures::identity_of(&child);
    let gone = fault::force_exists_once(crate::identity::Existence::Gone);
    let forced_view = crate::identity::proc_view_fault::force_proc_view_once(view);
    let shared = SharedChild::adopt(child, id).expect("adopt");
    drop(forced_view);
    drop(gone);
    shared.kill().expect("the child is kept, with a pidfd, and killable");
    drop(stdin);
    shared.wait().expect("wait");
}

/// On a diverged `/proc` the identity check is skipped: a live child is kept, with its pidfd,
/// relying on the `waitid` confirmation.
///
/// Mutant: trust `exists()` on a diverged `/proc`: `pidfd: None`, and `kill` answers `ECHILD` on
/// a live child.
#[test]
fn adopt_skips_the_identity_check_on_a_diverged_proc() {
    adopt_under_view_with_exists_gone(crate::identity::proc_view_fault::ForcedView::Diverged);
}

/// Likewise when the view cannot be assessed.
///
/// Mutant: the same.
#[test]
fn adopt_on_an_unassessable_proc_view_skips_the_identity_check() {
    adopt_under_view_with_exists_gone(crate::identity::proc_view_fault::ForcedView::Unassessable);
}

// The pidfd's number =====

const SLOT_MARKER: &str = "COSCA_TEST_SHARED_STDIO_SLOT";
const SLOT_CASE_ENV: &str = "COSCA_TEST_SHARED_STDIO_SLOT_CASE";

/// The adopted pidfd never sits in a stdio slot, even when 0, 1 or 2 is closed at adoption: an
/// application that restores its stdio with `dup2` afterwards would otherwise destroy it.
/// Each case runs in a fresh re-exec, since a closed slot is process-wide.
///
/// Mutant: the pidfd kept at the lowest free number.
#[test]
fn an_adopted_pidfd_never_sits_in_a_stdio_slot() {
    if !crate::test_child::is_marked_fixture_reexec(SLOT_MARKER) {
        for case in ["0", "1", "2"] {
            crate::test_child::run_fixture_case(
                crate::test_child::fixture_path!(an_adopted_pidfd_never_sits_in_a_stdio_slot),
                SLOT_MARKER,
                SLOT_CASE_ENV,
                case,
            );
        }
        return;
    }
    let slot: i32 = std::env::var(SLOT_CASE_ENV).expect("case").parse().expect("slot");
    let (child, stdin) = spawn_std_blocker();
    let id = super::fixtures::identity_of(&child);
    // SAFETY: fd juggling on the standard descriptors of this throwaway re-exec; `saved` is above
    // 2, and the slot is restored below, as an application restoring its stdio would.
    let saved = std::os::fd::IntoRawFd::into_raw_fd(
        rustix::io::fcntl_dupfd_cloexec(unsafe { rustix::fd::BorrowedFd::borrow_raw(slot) }, 10)
            .expect("dup the slot aside"),
    );
    assert!(saved >= 10);
    assert_eq!(unsafe { libc::close(slot) }, 0);
    let shared = SharedChild::adopt(child, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    let fd = std::os::fd::AsRawFd::as_raw_fd(shared.pidfd.as_ref().expect("a pidfd"));
    // Restore the slot first: the pidfd is still usable afterwards only if it never sat there.
    assert_eq!(unsafe { libc::dup2(saved, slot) }, slot);
    assert!(fd >= 3, "the pidfd took the closed stdio slot: {fd}");
    drop(stdin);
    shared.wait().expect("wait");
}
