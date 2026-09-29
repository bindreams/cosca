//! One test per row of the `SharedChild` state table. The row is named in each test's doc.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::fixtures::{park_holder, spawn_waiter, Blocker};
use crate::child::shared::seams::{self, ForcedWait};
use crate::child::shared::State;
use crate::wait::exit_only::seams as exit_seams;
use crate::wait::exit_only::seams::ForcedReap;

/// A deadline far enough away that only a forced outcome can end the wait.
fn far() -> Instant {
    Instant::now() + Duration::from_secs(3600)
}

fn is_echild(e: &io::Error) -> bool {
    #[cfg(unix)]
    {
        e.raw_os_error() == Some(libc::ECHILD)
    }
    #[cfg(windows)]
    {
        e.kind() == io::ErrorKind::Other
    }
}

// S1, S20: the lock =====

/// S1, S20: a poisoned mutex neither aborts nor hangs. A holder panics just after its re-lock,
/// with the lock held; then `try_wait`, `kill`, `Debug`, `wait` and `Drop` all return from other
/// threads.
///
/// Mutant: `lock().unwrap()`, which panics on the poison.
#[test]
fn a_poisoned_lock_neither_aborts_nor_hangs() {
    let mut b = Blocker::spawn();
    let poisoner = std::thread::spawn({
        let shared = Arc::clone(&b.shared);
        move || {
            let _panic = seams::panic_after_relock_once();
            let _wait = seams::force_unlocked_wait(ForcedWait::ExitSeen);
            shared.wait()
        }
    });
    assert!(poisoner.join().is_err(), "the holder must have panicked");

    let shared = Arc::clone(&b.shared);
    let shared = &*shared;
    std::thread::scope(|scope| {
        let calls: [Box<dyn FnOnce() + Send + '_>; 3] = [
            Box::new(|| assert!(matches!(shared.try_wait(), Ok(None)))),
            Box::new(|| assert!(!format!("{shared:?}").is_empty())),
            Box::new(|| drop(format!("{shared:#?}"))),
        ];
        let threads: Vec<_> = calls.into_iter().map(|call| scope.spawn(call)).collect();
        for t in threads {
            t.join().expect("a call on a poisoned lock must not panic");
        }
        scope
            .spawn(|| shared.kill().expect("kill on a poisoned lock"))
            .join()
            .expect("kill must not panic");
        scope
            .spawn(|| shared.wait().expect("wait on a poisoned lock"))
            .join()
            .expect("wait must not panic");
    });
    b.end_child();
}

/// S1 (`Debug`): formatting the handle inside a blocked waiter does not block, and shows
/// `locked`. The `on_condvar_block` hook runs under the lock and formats the handle itself.
///
/// Mutant: `Debug` through `lock()`, which deadlocks on its own thread.
#[test]
fn debug_inside_a_blocked_waiter_does_not_block() {
    let mut b = Blocker::spawn();
    let holder = park_holder(&b.shared, None, || ());
    let (printed_tx, printed_rx) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn({
        let shared = Arc::clone(&b.shared);
        move || {
            let printer = Arc::clone(&shared);
            let _hook = seams::on_condvar_block(move || {
                _ = printed_tx.send(format!("{printer:?}"));
            });
            let _forced = seams::force_unlocked_wait(ForcedWait::Panic);
            shared.wait()
        }
    });
    let printed = printed_rx.recv().expect("the waiter must reach its Condvar block");
    assert!(
        printed.contains("locked"),
        "Debug under the lock must say `locked`: {printed}"
    );
    b.end_child();
    let held = holder.release_and_join().expect("holder wait").expect("a status");
    assert_eq!(waiter.join().expect("waiter").expect("waiter wait"), held);
}

// S2, S6: one holder =====

/// S2, S6: a second `wait` blocks behind the holder, on the `Condvar`, and returns the same
/// status.
///
/// Mutant: no `W` check, so the second waiter becomes a second holder; it panics in its (forced)
/// unlocked wait and its hook never fires.
#[test]
fn a_second_wait_blocks_behind_the_holder() {
    let mut b = Blocker::spawn();
    let holder = park_holder(&b.shared, None, || ());
    let (waiter, blocked) = spawn_waiter(&b.shared, true, |s| s.wait());
    blocked
        .recv()
        .expect("the second wait must block on the Condvar behind the holder");
    b.end_child();
    let held = holder.release_and_join().expect("holder wait").expect("a status");
    assert_eq!(waiter.join().expect("waiter").expect("waiter wait"), held);
}

// S3: gone before adoption =====

/// S3: `pidfd_open` answering `ESRCH` is the gone path.
///
/// Mutant: `adopt` fails on `ESRCH`.
#[cfg(target_os = "linux")]
#[test]
fn adopt_on_esrch_takes_the_echild_path() {
    super::fixtures::assert_adoption_is_gone(|| {
        crate::wait::backend::fault::force_pidfd_open_errno_once(rustix::io::Errno::SRCH)
    });
}

// S4: try_wait =====

/// S4: `try_wait` reaps an exited child once and caches it: a second call reaps nothing.
///
/// Mutant: no `E` write, so the second call reaps again and gets the forced `EIO`.
#[test]
fn try_wait_reaps_an_exited_child_once() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let first = b.shared.try_wait().expect("try_wait").expect("the child exited");
    let _eio = exit_seams::force_reap_once(ForcedReap::Errno(5));
    let second = b.shared.try_wait().expect("the cached status").expect("a status");
    assert_eq!(first, second);
}

/// S4: a reap error that is not `ECHILD` is returned as it is, and the state stays `N`.
///
/// Mutant: a non-`ECHILD` errno taken for the `ECHILD` path.
#[test]
fn a_try_wait_reap_error_returns_it_and_stays_n() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let eio = exit_seams::force_reap_once(ForcedReap::Errno(5));
    let err = b.shared.try_wait().expect_err("the forced reap error");
    drop(eio);
    assert!(!is_echild(&err), "EIO must not read as ECHILD: {err}");
    assert!(matches!(b.shared.lock().state, State::N));
    assert!(b.shared.try_wait().expect("the real reap").is_some());
}

// S5: kill =====

/// S5: `kill` during a parked wait signals at once and never blocks on the `Condvar`; the
/// holder then reaps the killed child.
///
/// Mutant: `kill` blocks on the `Condvar` while `W`; the kill thread's hook panics.
#[test]
fn kill_during_a_parked_wait_signals_and_the_holder_reaps() {
    let b = Blocker::spawn();
    let holder = park_holder(&b.shared, None, || ());
    let killer = std::thread::spawn({
        let shared = Arc::clone(&b.shared);
        move || {
            let _hook = seams::on_condvar_block(|| panic!("kill blocked on the Condvar"));
            shared.kill()
        }
    });
    killer.join().expect("kill must not block").expect("kill");
    let status = holder.release_and_join().expect("holder wait").expect("a status");
    #[cfg(unix)]
    assert_eq!(super::fixtures::signal_of(status), Some(libc::SIGKILL));
    #[cfg(windows)]
    assert_eq!(status.code(), Some(1));
}

// S7: wait_deadline behind a holder =====

/// S7: a deadline waiter behind a parked holder returns `None` once its deadline has passed,
/// while the holder is still parked.
///
/// Mutant: the `Condvar::wait` without a timeout, which hangs.
#[test]
fn a_deadline_waiter_behind_a_parked_holder_returns_none_at_its_deadline() {
    let b = Blocker::spawn();
    let holder = park_holder(&b.shared, None, || ());
    let deadline = Instant::now() + Duration::from_millis(50);
    let (waiter, _blocked) = spawn_waiter(&b.shared, true, move |s| s.wait_deadline(deadline));
    let got = waiter.join().expect("waiter").expect("a running child is not an error");
    assert_eq!(got, None);
    assert!(crate::wait::now() >= deadline, "returned before the deadline");
    // Let the holder go, and end the child through the fixture's drop.
    drop(holder);
}

/// S7: a deadline waiter whose deadline has passed, behind a holder, returns the exit status from
/// its peek at once, without reaping and without waiting for the holder.
///
/// Mutant: blocking until the holder writes (shared_child's `wait_deadline` calls `self.wait()`
/// past its deadline): the waiter's hook panics.
#[test]
fn a_deadline_waiter_that_sees_an_exit_at_its_deadline_returns_its_status_without_reaping() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let holder = park_holder(&b.shared, None, || ());
    let deadline = Instant::now();
    let waiter = std::thread::spawn({
        let shared = Arc::clone(&b.shared);
        move || {
            let _hook = seams::on_condvar_block(|| panic!("the waiter blocked past its deadline"));
            shared.wait_deadline(deadline)
        }
    });
    let peeked = waiter.join().expect("waiter must not block").expect("wait_deadline");
    let reaped = holder.release_and_join().expect("holder wait");
    assert!(peeked.is_some(), "the exit was visible at the deadline");
    assert_eq!(peeked, reaped, "the holder's reap carries the same status");
}

// S8: try_wait behind a holder =====

/// S8: `try_wait` during a parked wait on an exited child returns the peeked status without
/// reaping or blocking.
///
/// Mutant: shared_child's `try_wait`, which blocks in `wait()` on an exit under a holder.
#[test]
fn try_wait_during_a_parked_wait_returns_the_peeked_status_without_reaping() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let holder = park_holder(&b.shared, None, || ());
    let waiter = std::thread::spawn({
        let shared = Arc::clone(&b.shared);
        move || {
            let _hook = seams::on_condvar_block(|| panic!("try_wait blocked"));
            shared.try_wait()
        }
    });
    let peeked = waiter.join().expect("try_wait must not block").expect("try_wait");
    let reaped = holder.release_and_join().expect("holder wait");
    assert!(peeked.is_some());
    assert_eq!(peeked, reaped);
}

/// S8: `try_wait` during a parked wait on a running child returns `None`.
///
/// Mutant: the exit-record branch taken for "running".
#[test]
fn try_wait_during_a_parked_wait_on_a_running_child_returns_none() {
    let b = Blocker::spawn();
    let holder = park_holder(&b.shared, None, || ());
    let waiter = std::thread::spawn({
        let shared = Arc::clone(&b.shared);
        move || {
            let _hook = seams::on_condvar_block(|| panic!("try_wait blocked"));
            shared.try_wait()
        }
    });
    assert_eq!(waiter.join().expect("try_wait must not block").expect("try_wait"), None);
    drop(holder);
}

// S9: a non-holder's ECHILD =====

/// S9: a non-holder whose peek answers `ECHILD` returns it and writes nothing: the holder, then
/// released with *deadline passed*, finds its own `W` on the re-read (a `debug_assert!`).
///
/// Mutant: S9 writes `N`, so the holder's re-read finds a foreign state and its assert fires.
#[test]
fn a_non_holder_peek_that_gets_echild_returns_it_and_writes_nothing() {
    let b = Blocker::spawn();
    let holder = park_holder(&b.shared, Some(far()), || {
        seams::force_unlocked_wait(ForcedWait::DeadlinePassed)
    });
    let forced = exit_seams::force_peek_once(Ok(crate::wait::exit_only::Peek::Foreign(
        crate::wait::exit_only::Foreign::Gone,
    )));
    let err = b.shared.try_wait().expect_err("the forced ECHILD");
    drop(forced);
    assert!(is_echild(&err));
    assert!(matches!(b.shared.lock().state, State::W { .. }), "S9 writes nothing");
    assert_eq!(holder.release_and_join().expect("holder"), None);
    assert!(matches!(b.shared.lock().state, State::N));
}

// S10: the holder's reap =====

/// S10: an exit seen is reaped once, under the lock, and cached: a second `wait` never reaches
/// the unlocked wait.
///
/// Mutant: no `E` write, so the second `wait` runs the unlocked wait and panics.
#[test]
fn an_exit_seen_is_reaped_once_under_the_lock() {
    let mut b = Blocker::spawn();
    b.end_child();
    let first = b.shared.wait().expect("wait");
    let _panic = seams::force_unlocked_wait(ForcedWait::Panic);
    assert_eq!(b.shared.wait().expect("the cached status"), first);
}

/// S10, S12, S15: a holder's normal return leaves the next holder alone. A regression test, with
/// no RED claimed: `finish` consumes the guard, so the hazard it guards is unrepresentable.
#[test]
fn a_holders_normal_return_leaves_the_next_holder_alone() {
    let b = Blocker::spawn();
    let holder = park_holder(&b.shared, Some(far()), || {
        seams::force_unlocked_wait(ForcedWait::DeadlinePassed)
    });
    let (gate, second_parked, second_release) = seams::park_gate();
    let (blocked_tx, blocked_rx) = std::sync::mpsc::channel();
    let second = std::thread::spawn({
        let shared = Arc::clone(&b.shared);
        move || {
            let _hook = seams::on_condvar_block(move || {
                _ = blocked_tx.send(());
            });
            let _park = seams::park_in_unlocked_wait(gate);
            let _forced = seams::force_unlocked_wait(ForcedWait::DeadlinePassed);
            shared.wait_deadline(far())
        }
    });
    blocked_rx
        .recv()
        .expect("the second waiter must block behind the first");
    assert_eq!(holder.release_and_join().expect("first holder"), None);
    second_parked.recv().expect("the second waiter must become the holder");
    assert!(
        matches!(b.shared.lock().state, State::W { token: 1 }),
        "the first holder's return must leave the second holder's W alone"
    );
    drop(second_release);
    assert_eq!(second.join().expect("second holder").expect("wait"), None);
}

/// S10: a reap error that is not `ECHILD` returns it, restores `N` and wakes the waiters: the
/// blocked waiter becomes the holder.
///
/// Mutant: a `?` return that leaves `W`: the waiter never wakes.
#[test]
fn a_non_echild_reap_error_restores_n_and_wakes_the_waiters() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let holder = park_holder(&b.shared, None, || {
        (
            seams::force_unlocked_wait(ForcedWait::ExitSeen),
            exit_seams::force_reap_once(ForcedReap::Errno(5)),
        )
    });
    let (waiter, blocked) = spawn_waiter(&b.shared, false, |s| s.wait());
    blocked.recv().expect("the waiter must block behind the holder");
    let err = holder.release_and_join().expect_err("the forced reap error");
    assert!(!is_echild(&err));
    waiter.join().expect("waiter").expect("the waiter becomes the holder");
}

// S12, S13, S14, S15 =====

/// S12: an expired holder hands off to a blocked `wait`, which becomes the holder and returns the
/// real status.
///
/// Mutant: `N` written without `notify_all`: the waiter never wakes.
#[test]
fn an_expired_holder_hands_off_to_a_blocked_wait() {
    let mut b = Blocker::spawn();
    let holder = park_holder(&b.shared, Some(far()), || {
        seams::force_unlocked_wait(ForcedWait::DeadlinePassed)
    });
    let (waiter, blocked) = spawn_waiter(&b.shared, false, |s| s.wait());
    blocked.recv().expect("the waiter must block behind the holder");
    assert_eq!(holder.release_and_join().expect("holder"), None);
    b.end_child();
    waiter.join().expect("waiter").expect("a status");
}

/// S13: a holder that sees *gone* takes the `ECHILD` path and restores `N`.
///
/// Mutant: *gone* taken for *deadline passed*: `Ok(None)`.
#[test]
fn a_holder_that_sees_gone_takes_the_echild_path() {
    let b = Blocker::spawn();
    let _gone = seams::force_unlocked_wait(ForcedWait::Gone);
    let err = b.shared.wait().expect_err("gone");
    assert!(is_echild(&err));
    assert!(matches!(b.shared.lock().state, State::N));
}

/// S14: an error from the unlocked wait restores `N`, wakes the waiters and returns the error.
///
/// Mutant: a `?` return that leaves `W`: the waiter never wakes.
#[test]
fn an_unlocked_wait_error_restores_n_and_wakes_the_waiters() {
    let mut b = Blocker::spawn();
    let holder = park_holder(&b.shared, None, || seams::force_unlocked_wait(ForcedWait::Errno(5)));
    let (waiter, blocked) = spawn_waiter(&b.shared, false, |s| s.wait());
    blocked.recv().expect("the waiter must block behind the holder");
    let err = holder.release_and_join().expect_err("the forced error");
    assert_eq!(err.raw_os_error(), Some(5));
    b.end_child();
    waiter.join().expect("waiter").expect("a status");
}

/// S15: a holder that panics in its wait restores `N` and wakes the waiters.
///
/// Mutant: no guard: the waiter never wakes.
#[test]
fn a_holder_that_panics_in_its_wait_restores_n_and_wakes_the_waiters() {
    let mut b = Blocker::spawn();
    let holder = park_holder(&b.shared, None, || seams::force_unlocked_wait(ForcedWait::Panic));
    let (waiter, blocked) = spawn_waiter(&b.shared, false, |s| s.wait());
    blocked.recv().expect("the waiter must block behind the holder");
    assert!(
        holder.release_and_join_thread().is_err(),
        "the holder must have panicked"
    );
    b.end_child();
    waiter.join().expect("waiter").expect("a status");
}

/// S15: a holder that panics after its re-lock, holding the lock, restores `N` without
/// deadlocking: the blocked waiter wakes, takes the poisoned lock, becomes the holder and returns
/// the real status.
///
/// Mutant: a guard that re-locks instead of using its own `MutexGuard` (self-deadlock), or a
/// `Condvar` result that is `unwrap()`ped (the waiter panics).
#[test]
fn a_holder_that_panics_after_its_relock_restores_n_without_deadlocking() {
    let mut b = Blocker::spawn();
    let holder = park_holder(&b.shared, None, || {
        (
            seams::force_unlocked_wait(ForcedWait::ExitSeen),
            seams::panic_after_relock_once(),
        )
    });
    let (waiter, blocked) = spawn_waiter(&b.shared, false, |s| s.wait());
    blocked.recv().expect("the waiter must block behind the holder");
    assert!(
        holder.release_and_join_thread().is_err(),
        "the holder must have panicked"
    );
    b.end_child();
    waiter.join().expect("waiter").expect("a status");
}

// S16, S17: after the reap =====

/// S16: a cached status never reaches the unlocked wait, for any method.
///
/// Mutant: no `E` check: the unlocked wait panics.
#[test]
fn a_cached_status_never_reaches_the_unlocked_wait() {
    let mut b = Blocker::spawn();
    b.end_child();
    let status = b.shared.wait().expect("wait");
    let _panic = seams::force_unlocked_wait(ForcedWait::Panic);
    assert_eq!(b.shared.wait().expect("cached"), status);
    assert_eq!(b.shared.wait_deadline(far()).expect("cached"), Some(status));
    assert_eq!(b.shared.try_wait().expect("cached"), Some(status));
}

/// S17: `kill` after the reap sends nothing.
///
/// Mutant: a `kill` by pid, or by pidfd, after `E`.
#[test]
fn kill_after_the_reap_sends_nothing() {
    let mut b = Blocker::spawn();
    b.end_child();
    b.shared.wait().expect("wait");
    exit_seams::signals_sent();
    b.shared.kill().expect("an already-reaped child is success");
    assert_eq!(exit_seams::signals_sent(), 0);
}

// L8: an unreadable consuming record =====

/// L8: a consuming reap that hands back a record that is not an exit is cached as
/// `E(Unreadable)` and acts by no pid: every later wait answers `InvalidData` and `kill` sends
/// nothing. In a debug build the contract breach panics, after the `E` write.
///
/// Mutant: a panic before the `E` write: the state stays `W` and the guard restores `N` over a
/// reaped pid.
#[cfg(unix)]
#[test]
fn an_unreadable_consuming_record_is_cached_and_acts_by_no_pid() {
    let mut b = Blocker::spawn();
    b.end_child_and_confirm_exit();
    let bogus = exit_seams::force_consuming_record_once(99);
    let shared = Arc::clone(&b.shared);
    // In a debug build the call panics (after the write); in a release build it returns.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| shared.wait()));
    drop(bogus);
    if cfg!(debug_assertions) {
        assert!(outcome.is_err(), "a debug build asserts the contract");
    } else {
        let err = outcome.expect("release returns").expect_err("unreadable");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
    assert!(
        matches!(
            b.shared.lock().state,
            State::E(crate::wait::exit_only::Reaped::Unreadable { si_code: 99 })
        ),
        "the state must already be E(Unreadable): {:?}",
        b.shared
    );
    for err in [
        b.shared.wait().expect_err("wait"),
        b.shared.try_wait().expect_err("try_wait"),
        b.shared.wait_deadline(far()).expect_err("wait_deadline"),
    ] {
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
    exit_seams::signals_sent();
    b.shared.kill().expect("kill");
    assert_eq!(exit_seams::signals_sent(), 0);
}

// Deadline arithmetic =====

/// `clamp_block` caps every timed block below the value the platforms read as `INFINITE`.
///
/// Mutant: an unclamped `wait_timeout`.
#[test]
fn clamp_block_caps_every_timed_block_below_infinite() {
    let cap = Duration::from_millis(0xFFFF_FFFE);
    for huge in [
        Duration::MAX,
        Duration::from_millis(u64::from(u32::MAX)),
        Duration::from_millis(0xFFFF_FFFE),
    ] {
        assert_eq!(crate::wait::clamp_block(huge), cap);
    }
    assert_eq!(
        crate::wait::clamp_block(Duration::from_millis(5)),
        Duration::from_millis(5)
    );
}

// Adoption =====

/// `adopt` never reaps: an already-exited child is still a zombie afterwards, so a later
/// wait reaps it and returns its status.
///
/// Mutant: shared_child's `SharedChild::new`, which reaps an exited child on adoption.
#[cfg(unix)]
#[test]
fn adopt_never_reaps() {
    let (child, stdin) = super::fixtures::spawn_std_blocker();
    let id = super::fixtures::identity_of(&child);
    drop(stdin);
    // The exit, seen without consuming it.
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
    assert_eq!(r, 0, "waitid(WNOWAIT): {}", io::Error::last_os_error());

    let shared = crate::child::shared::SharedChild::adopt(child, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    // Still a zombie: a non-consuming look finds its exit record.
    // SAFETY: as above.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::waitid(
            libc::P_PID,
            shared.id() as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    assert_eq!(r, 0, "waitid: {}", io::Error::last_os_error());
    #[cfg(target_os = "linux")]
    // SAFETY: `waitid` filled the `siginfo_t` (an exit record), so `si_pid` is initialised.
    let seen = unsafe { info.si_pid() };
    #[cfg(target_os = "macos")]
    let seen = info.si_pid;
    assert_ne!(seen, 0, "adopt must leave the exited child a zombie");
    assert!(shared.wait().expect("wait").success());
}
