//! The policy of `OwnedChild` over a `FakeProcess`, which states what the OS answers: one test per
//! row of the state table, each with the mutant it turns RED against named in its doc. A holder is
//! "parked" when it is blocked on the wait its look returned, which the test fires.

use std::process::ExitStatus;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::fixtures::{assert_handed_off, owned_over, park_holder, spawn_waiter, status, try_wait};
use crate::child::owned::seams;
use crate::child::owned::{ChildWaitOutcome, OwnedChild, State};
use crate::error::Error;
use crate::os_process::child::{ExitRecord, Foreign, PeekOutcome};
use crate::os_process::fake::{FakeProcess, ReapAnswer};
use crate::signal::{Sent, Sig};

fn exit() -> ExitRecord {
    ExitRecord::Status(ExitStatus::default())
}

/// A deadline far enough away that only a scripted answer can end the wait.
fn far() -> Instant {
    Instant::now() + Duration::from_secs(3600)
}

const KIND: std::io::ErrorKind = std::io::ErrorKind::Other;

/// A reap that fails, as the error its caller sees.
fn is_the_scripted_failure(err: &Error) -> bool {
    matches!(err, Error::Io(e) if e.kind() == KIND)
}

// The lock =====

/// A poisoned mutex neither aborts nor hangs. A holder panics just after its re-lock,
/// with the lock held; then `try_wait`, `signal`, `Debug` and `wait` all return from other
/// threads.
///
/// Mutant: `lock().unwrap()`, which panics on the poison.
#[skuld::test]
fn a_poisoned_lock_neither_aborts_nor_hangs() {
    let fake = FakeProcess::new([])
        .reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())])
        .signals([Ok(Sent::Delivered)]);
    let child = owned_over(&fake);
    let poisoner = std::thread::spawn({
        let child = Arc::clone(&child);
        move || {
            let _panic = seams::panic_after_relock_once();
            child.wait(None)
        }
    });
    assert!(poisoner.join().is_err(), "the holder must have panicked");

    let child = &*child;
    std::thread::scope(|scope| {
        let calls: [Box<dyn FnOnce() + Send + '_>; 3] = [
            Box::new(|| assert!(matches!(try_wait(child), Ok(ChildWaitOutcome::DeadlinePassed)))),
            Box::new(|| assert!(!format!("{child:?}").is_empty())),
            Box::new(|| drop(format!("{child:#?}"))),
        ];
        let threads: Vec<_> = calls.into_iter().map(|call| scope.spawn(call)).collect();
        for t in threads {
            t.join().expect("a call on a poisoned lock must not panic");
        }
        let sent = scope
            .spawn(|| child.signal(Sig::Kill))
            .join()
            .expect("signal must not panic");
        assert_eq!(sent.expect("signal on a poisoned lock"), Sent::Delivered);
        let waited = scope.spawn(|| child.wait(None)).join().expect("wait must not panic");
        assert_eq!(status(waited), ExitStatus::default());
    });
}

/// `Debug`: formatting the handle inside a blocked waiter does not block, and shows
/// `locked`. The `on_condvar_block` hook runs under the lock and formats the handle itself.
///
/// Mutant: `Debug` through `OwnedChild::lock()`, which the test build's owner check turns into a
/// panic in the hook, instead of a deadlock on its own thread.
#[skuld::test]
fn debug_inside_a_blocked_waiter_does_not_block() {
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())]);
    let child = owned_over(&fake);
    let holder = park_holder(&child, &fake, |c| c.wait(None));
    let (printed_tx, printed_rx) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn({
        let child = Arc::clone(&child);
        move || {
            let printer = Arc::clone(&child);
            let _hook = seams::on_condvar_block(move || {
                _ = printed_tx.send(format!("{printer:?}"));
            });
            child.wait(None)
        }
    });
    let printed = printed_rx.recv().expect("the waiter must reach its Condvar block");
    assert!(
        printed.contains("locked"),
        "Debug under the lock must say `locked`: {printed}"
    );
    let held = status(holder.release_and_join());
    assert_eq!(status(waiter.join().expect("waiter")), held);
}

// One holder =====

/// A second `wait` blocks behind the holder, on the `Condvar`, and returns the same
/// status.
///
/// Mutant: no `W` check, so the second waiter becomes a second holder; it looks past the holder's
/// scripted answers, and its hook never fires.
#[skuld::test]
fn a_second_wait_blocks_behind_the_holder() {
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())]);
    let child = owned_over(&fake);
    let holder = park_holder(&child, &fake, |c| c.wait(None));
    let (waiter, blocked) = spawn_waiter(&child, |c| c.wait(None));
    blocked
        .recv()
        .expect("the second wait must block on the Condvar behind the holder");
    let held = status(holder.release_and_join());
    assert_eq!(status(waiter.join().expect("waiter")), held);
}

// One look =====

/// A look that finds the exit record reaps it once and caches it: a second call reaps nothing.
///
/// Mutant: no `E` write, so the second call reaps again, past the scripted answers.
#[skuld::test]
fn a_look_reaps_an_exited_child_once() {
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Reaped(exit())]);
    let child = OwnedChild::new(Box::new(fake.clone()));
    let first = status(try_wait(&child));
    let second = status(try_wait(&child));
    assert_eq!(first, second);
    assert_eq!(fake.looks(), 1);
    assert!(child.is_reaped());
}

/// A reap error is returned as it is, and the state stays `N`.
///
/// Mutant: an error taken for the foreign path, or the state left in `W`.
#[skuld::test]
fn a_look_that_fails_returns_the_error_and_stays_n() {
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Err(KIND), ReapAnswer::Reaped(exit())]);
    let child = OwnedChild::new(Box::new(fake));
    let err = try_wait(&child).expect_err("the scripted failure");
    assert!(is_the_scripted_failure(&err), "{err:?}");
    assert!(matches!(child.lock().state, State::N));
    assert!(matches!(try_wait(&child), Ok(ChildWaitOutcome::Exited(_))));
}

// Signal =====

/// `signal` during a parked wait goes to the OS at once and never blocks on the `Condvar`;
/// the holder then reaps.
///
/// Mutant: `signal` blocks on the `Condvar` while `W`; the signalling thread's hook panics.
#[skuld::test]
fn signal_during_a_parked_wait_signals_and_the_holder_reaps() {
    let fake = FakeProcess::new([])
        .reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())])
        .signals([Ok(Sent::Delivered)]);
    let child = owned_over(&fake);
    let holder = park_holder(&child, &fake, |c| c.wait(None));
    let signaller = std::thread::spawn({
        let child = Arc::clone(&child);
        move || {
            let _hook = seams::on_condvar_block(|| panic!("signal blocked on the Condvar"));
            child.signal(Sig::Kill)
        }
    });
    let sent = signaller.join().expect("signal must not block").expect("signal");
    assert_eq!(sent, Sent::Delivered);
    assert_eq!(fake.signal_calls(), [Sig::Kill]);
    status(holder.release_and_join());
}

// A deadline behind a holder =====

/// A deadline waiter behind a parked holder blocks on the `Condvar` for the time remaining,
/// then returns `DeadlinePassed` once its deadline has passed, while the holder is still parked.
/// The clock is frozen, so the armed timeout is exactly the time remaining.
///
/// A block with no timeout is reported by the hook, and the test then lets the holder finish, so
/// the waiter returns and the assertion fails.
///
/// Mutant: the `Condvar::wait` without a timeout; a waiter that returns by peeking, without
/// blocking; a wait armed with anything but the time remaining.
#[skuld::test]
fn a_deadline_waiter_behind_a_parked_holder_returns_at_its_deadline() {
    let fake = FakeProcess::new([])
        .reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())])
        .peeks([Ok(PeekOutcome::Running)]);
    let child = owned_over(&fake);
    let holder = park_holder(&child, &fake, |c| c.wait(None));
    let remaining = Duration::from_millis(50);
    let (armed_tx, armed_rx) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn({
        let child = Arc::clone(&child);
        move || {
            let (_clock, at) = crate::wait::test_clock::FrozenClockGuard::install();
            let _hook = seams::on_condvar_block_with(move |armed| _ = armed_tx.send(armed));
            let got = child.wait(Some(at + remaining));
            let expired = crate::wait::now() >= at + remaining;
            let holder_still_parked = matches!(child.lock().state, State::W { .. });
            (got, expired, holder_still_parked)
        }
    });
    let armed = armed_rx.recv().expect("the waiter must block on the Condvar");
    if armed.is_none() {
        // A wait with no timeout would never return: let the holder reap, which wakes the waiter,
        // and fail on the value.
        holder.release_and_join().expect("holder wait");
        waiter.join().expect("waiter").0.expect("wait");
        panic!("the waiter blocked on the Condvar with no timeout");
    }
    let (got, expired, holder_still_parked) = waiter.join().expect("waiter");
    assert_eq!(armed, Some(remaining), "armed with the time remaining");
    assert_eq!(
        got.expect("a running child is not an error"),
        ChildWaitOutcome::DeadlinePassed
    );
    assert!(expired, "returned before the deadline");
    assert!(
        holder_still_parked,
        "the holder must still be parked when the waiter returns"
    );
    status(holder.release_and_join());
}

/// Principle 13 for a non-holder's `Condvar` block: each round is armed from the time remaining at
/// that moment, so a spurious wake shrinks the next timeout. The clock is frozen, and each block
/// advances it by the real time the block took.
///
/// Mutant: the remaining time computed once, before the loop: both rounds are armed alike.
#[skuld::test]
fn a_spurious_wake_re_arms_a_deadline_waiter_with_less_time() {
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())]);
    let child = owned_over(&fake);
    let holder = park_holder(&child, &fake, |c| c.wait(None));
    let (blocked_tx, blocked_rx) = std::sync::mpsc::channel();
    let (again_tx, again_rx) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn({
        let child = Arc::clone(&child);
        move || {
            let (_clock, at) = crate::wait::test_clock::FrozenClockGuard::install();
            let _first = seams::on_condvar_block(move || {
                _ = blocked_tx.send(());
                // The second round's hook arms from inside the first, under the lock.
                let second = seams::on_condvar_block(move || _ = again_tx.send(()));
                std::mem::forget(second);
            });
            crate::wait::block_probe::take();
            let got = child.wait(Some(at + Duration::from_secs(3600)));
            (got, crate::wait::block_probe::take())
        }
    });
    blocked_rx.recv().expect("the waiter must block in round one");
    // The lock is free only once the waiter is inside its `Condvar` wait, which releases it
    // atomically, so a notify under it cannot be lost.
    {
        let _lock = child.lock();
        child.condvar.notify_all();
    }
    again_rx
        .recv()
        .expect("the spurious wake must send the waiter round again");
    // The holder's reap wakes the waiter with the status.
    status(holder.release_and_join());
    let (got, armed) = waiter.join().expect("waiter");
    status(got);
    let armed: Vec<Duration> = armed
        .into_iter()
        .map(|a| a.expect("a deadline wait arms a bound"))
        .collect();
    assert!(armed.len() >= 2, "a second round must have been armed: {armed:?}");
    assert!(
        armed[1] < armed[0],
        "the second round must be armed from the recomputed remaining time: {armed:?}"
    );
}

/// A waiter whose deadline has passed, behind a holder, returns the exit status from its
/// peek at once, without reaping and without waiting for the holder. `Child::try_wait` is this
/// call with the deadline now.
///
/// Mutant: blocking until the holder writes: the waiter's hook panics; or reaping: the holder's
/// look finds the scripted reap gone.
#[skuld::test]
fn a_waiter_that_sees_an_exit_at_its_deadline_returns_its_status_without_reaping() {
    let fake = FakeProcess::new([])
        .reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())])
        .peeks([Ok(PeekOutcome::Exit(exit()))]);
    let child = owned_over(&fake);
    let holder = park_holder(&child, &fake, |c| c.wait(None));
    let waiter = std::thread::spawn({
        let child = Arc::clone(&child);
        move || {
            let _hook = seams::on_condvar_block(|| panic!("the waiter blocked past its deadline"));
            try_wait(&child)
        }
    });
    let peeked = status(waiter.join().expect("the waiter must not block"));
    let reaped = status(holder.release_and_join());
    assert_eq!(peeked, reaped, "the holder's reap carries the same status");
}

/// A waiter whose deadline has passed, behind a holder, on a running child returns
/// `DeadlinePassed`.
///
/// Mutant: the exit-record branch taken for "running".
#[skuld::test]
fn a_waiter_at_its_deadline_behind_a_holder_on_a_running_child_gets_deadline_passed() {
    let fake = FakeProcess::new([])
        .reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())])
        .peeks([Ok(PeekOutcome::Running)]);
    let child = owned_over(&fake);
    let holder = park_holder(&child, &fake, |c| c.wait(None));
    let waiter = std::thread::spawn({
        let child = Arc::clone(&child);
        move || {
            let _hook = seams::on_condvar_block(|| panic!("the waiter blocked past its deadline"));
            try_wait(&child)
        }
    });
    assert_eq!(
        waiter.join().expect("the waiter must not block").expect("try_wait"),
        ChildWaitOutcome::DeadlinePassed
    );
    status(holder.release_and_join());
}

// A non-holder's foreign verdict =====

/// A non-holder whose peek is foreign returns it and writes nothing: the holder, then released,
/// finds its own `W` on the re-read (a `debug_assert!`) and reaps.
///
/// Mutant: a non-holder's foreign verdict writes `N`, so the holder's re-read finds a foreign state and its assert fires.
#[skuld::test]
fn a_non_holder_peek_that_is_foreign_returns_it_and_writes_nothing() {
    let fake = FakeProcess::new([])
        .reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())])
        .peeks([Ok(PeekOutcome::Foreign(Foreign::Gone))]);
    let child = owned_over(&fake);
    let holder = park_holder(&child, &fake, |c| c.wait(Some(far())));
    let got = try_wait(&child).expect("the scripted peek");
    assert_eq!(got, ChildWaitOutcome::Foreign(Foreign::Gone));
    assert!(
        matches!(child.lock().state, State::W { .. }),
        "a non-holder's foreign verdict writes nothing"
    );
    status(holder.release_and_join());
    assert!(matches!(child.lock().state, State::E(_)));
}

// The holder's reap =====

/// An exit seen is reaped once, under the lock, and cached: a second `wait` never looks.
///
/// Mutant: no `E` write, so the second `wait` looks past the scripted answers.
#[skuld::test]
fn an_exit_seen_is_reaped_once_under_the_lock() {
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Reaped(exit())]);
    let child = OwnedChild::new(Box::new(fake.clone()));
    let first = status(child.wait(None));
    assert_eq!(status(child.wait(None)), first);
    assert_eq!(fake.looks(), 1);
}

/// A holder's normal return leaves the next holder alone. A regression test, with
/// no RED claimed: `finish` consumes the guard, so the hazard it guards is unrepresentable.
#[skuld::test]
fn a_holders_normal_return_leaves_the_next_holder_alone() {
    let fake = FakeProcess::new([]).reaps([
        ReapAnswer::Running,
        ReapAnswer::Foreign(Foreign::Gone),
        ReapAnswer::Running,
        ReapAnswer::Reaped(exit()),
    ]);
    let child = owned_over(&fake);
    let holder = park_holder(&child, &fake, |c| c.wait(None));
    let (blocked_tx, blocked_rx) = std::sync::mpsc::channel();
    let (parked_tx, parked_rx) = std::sync::mpsc::channel();
    let second = std::thread::spawn({
        let child = Arc::clone(&child);
        move || {
            let _hook = seams::on_condvar_block(move || {
                _ = blocked_tx.send(());
            });
            let _blocking = crate::wait::block_probe::on_blocking(move || {
                _ = parked_tx.send(());
            });
            child.wait(None)
        }
    });
    blocked_rx
        .recv()
        .expect("the second waiter must block behind the first");
    assert_eq!(
        holder.release_and_join().expect("first holder"),
        ChildWaitOutcome::Foreign(Foreign::Gone)
    );
    parked_rx.recv().expect("the second waiter must become the holder");
    assert!(
        matches!(child.lock().state, State::W { token: 1 }),
        "the first holder's return must leave the second holder's W alone"
    );
    fake.wake();
    status(second.join().expect("second holder"));
}

/// A reap error returns it, restores `N` and wakes the waiters: the blocked waiter
/// becomes the holder.
///
/// Mutant: a `?` return that leaves `W`: the waiter never wakes.
#[skuld::test]
fn a_reap_error_restores_n_and_wakes_the_waiters() {
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Running, ReapAnswer::Err(KIND), ReapAnswer::Reaped(exit())]);
    let child = owned_over(&fake);
    let holder = park_holder(&child, &fake, |c| c.wait(None));
    let (waiter, blocked) = spawn_waiter(&child, |c| c.wait(None));
    blocked.recv().expect("the waiter must block behind the holder");
    let err = holder.release_and_join().expect_err("the scripted reap error");
    assert_handed_off(&child, 0);
    assert!(is_the_scripted_failure(&err), "{err:?}");
    status(waiter.join().expect("waiter"));
}

// Hand-off and failure of the holder =====

/// A holder whose deadline passes hands off to a blocked `wait`, which becomes the holder and
/// returns the real status. The holder's clock is frozen, and its second look moves it past the
/// deadline, so the final look follows with no block.
///
/// Mutant: `N` written without `notify_all`: the waiter never wakes.
#[skuld::test]
fn an_expired_holder_hands_off_to_a_blocked_wait() {
    let fake = FakeProcess::new([]).reaps([
        ReapAnswer::Running,
        ReapAnswer::Running,
        ReapAnswer::Running,
        ReapAnswer::Reaped(exit()),
    ]);
    fake.on_look(|look| {
        if look == 1 {
            crate::wait::test_clock::advance(Duration::from_secs(7200));
        }
    });
    let child = owned_over(&fake);
    let holder = park_holder(&child, &fake, |c| {
        let (_clock, at) = crate::wait::test_clock::FrozenClockGuard::install();
        c.wait(Some(at + Duration::from_secs(3600)))
    });
    let (waiter, blocked) = spawn_waiter(&child, |c| c.wait(None));
    blocked.recv().expect("the waiter must block behind the holder");
    assert_eq!(
        holder.release_and_join().expect("holder"),
        ChildWaitOutcome::DeadlinePassed
    );
    assert_handed_off(&child, 0);
    status(waiter.join().expect("waiter"));
}

/// A holder that is told the child is foreign takes that path and restores `N`.
///
/// Mutant: *foreign* taken for *deadline passed*.
#[skuld::test]
fn a_holder_that_sees_a_foreign_reap_returns_it_and_restores_n() {
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Foreign(Foreign::Gone)]);
    let child = OwnedChild::new(Box::new(fake));
    assert_eq!(
        child.wait(None).expect("foreign"),
        ChildWaitOutcome::Foreign(Foreign::Gone)
    );
    assert!(matches!(child.lock().state, State::N));
}

/// A holder that panics in its look restores `N` and wakes the waiters.
///
/// Mutant: no guard: the waiter never wakes.
#[skuld::test]
fn a_holder_that_panics_in_its_look_restores_n_and_wakes_the_waiters() {
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())]);
    fake.on_look(|look| {
        if look == 1 {
            panic!("forced panic in the holder's look");
        }
    });
    let child = owned_over(&fake);
    let holder = park_holder(&child, &fake, |c| c.wait(None));
    let (waiter, blocked) = spawn_waiter(&child, |c| c.wait(None));
    blocked.recv().expect("the waiter must block behind the holder");
    assert!(
        holder.release_and_join_thread().is_err(),
        "the holder must have panicked"
    );
    assert_handed_off(&child, 0);
    status(waiter.join().expect("waiter"));
}

/// A holder that panics after its re-lock, holding the lock, restores `N` without
/// deadlocking: the blocked waiter wakes, takes the poisoned lock, becomes the holder and returns
/// the real status.
///
/// Mutant: a guard that re-locks instead of using its own `MutexGuard` (self-deadlock), or a
/// `Condvar` result that is `unwrap()`ped (the waiter panics).
#[skuld::test]
fn a_holder_that_panics_after_its_relock_restores_n_without_deadlocking() {
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())]);
    // Armed in the first look, on the holder's thread: its second look's re-lock panics.
    fake.on_look(|look| {
        if look == 0 {
            // Left armed: the next re-lock on this thread takes it.
            std::mem::forget(seams::panic_after_relock_once());
        }
    });
    let child = owned_over(&fake);
    let holder = park_holder(&child, &fake, |c| c.wait(None));
    let (waiter, blocked) = spawn_waiter(&child, |c| c.wait(None));
    blocked.recv().expect("the waiter must block behind the holder");
    assert!(
        holder.release_and_join_thread().is_err(),
        "the holder must have panicked"
    );
    assert_handed_off(&child, 0);
    status(waiter.join().expect("waiter"));
}

// A recheck =====

/// A look that asks for a recheck (a zombie a tracer holds, or an exit XNU is still finishing)
/// is repeated after a backoff of 1, 2, 4 ... ms, on the handle's `Condvar`, until it shows the
/// record: the looks are the pauses plus one, and none polls.
///
/// Mutant: a recheck that loops with no pause (a spin), or that blocks on the look's wait.
#[skuld::test]
fn a_recheck_backs_off_until_the_zombie_shows() {
    let fake = FakeProcess::new([]).reaps([
        ReapAnswer::Recheck,
        ReapAnswer::Recheck,
        ReapAnswer::Recheck,
        ReapAnswer::Reaped(exit()),
    ]);
    let child = OwnedChild::new(Box::new(fake.clone()));
    crate::wait::block_probe::take();
    status(child.wait(None));
    let pauses = crate::wait::block_probe::take();
    let ms = |n| Some(Duration::from_millis(n));
    assert_eq!(pauses, [ms(1), ms(2), ms(4)]);
    assert_eq!(fake.looks(), pauses.len() + 1);
}

/// A holder blocked on its wait holds no lock: `Debug` shows `W`, not `locked`, and `signal`
/// returns.
///
/// Mutant: the wait under the lock, so `Debug`'s `try_lock` fails and prints `locked`.
#[skuld::test]
fn a_holder_blocked_on_its_wait_holds_no_lock() {
    let fake = FakeProcess::new([])
        .reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())])
        .signals([Ok(Sent::Delivered)]);
    let child = owned_over(&fake);
    let holder = park_holder(&child, &fake, |c| c.wait(None));
    // The check comes first, so a RED fails on `locked` rather than hanging in `signal`.
    let printed = format!("{child:?}");
    assert!(printed.contains("W {"), "the holder is in W: {printed}");
    assert!(!printed.contains("locked"), "the wait must hold no lock: {printed}");
    child.signal(Sig::Kill).expect("signal must not wait for the holder");
    status(holder.release_and_join());
}

/// A holder blocked on its wait looks again only when the wait is fired.
///
/// Mutant: a holder that looks again without waiting (a spin).
#[skuld::test]
fn a_holder_blocked_on_its_wait_wakes_when_signalled() {
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())]);
    let child = owned_over(&fake);
    let holder = park_holder(&child, &fake, |c| c.wait(None));
    assert_eq!(fake.looks(), 1, "the holder has not looked again");
    status(holder.release_and_join());
    assert_eq!(fake.looks(), 2);
}

/// A foreign verdict is cached as nothing: the state stays `N` and nothing is reaped.
///
/// Mutant: the foreign verdict written as `E`, or as a stuck `W`.
#[skuld::test]
fn a_foreign_reap_is_cached_as_nothing_and_wait_stays_n() {
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Foreign(Foreign::Gone), ReapAnswer::Reaped(exit())]);
    let child = OwnedChild::new(Box::new(fake));
    assert_eq!(
        child.wait(None).expect("foreign"),
        ChildWaitOutcome::Foreign(Foreign::Gone)
    );
    assert!(matches!(child.lock().state, State::N));
    assert!(!child.is_reaped());
    status(child.wait(None));
}

/// The deadline of `exited_by` is read through the OS's own look, and reaps nothing.
///
/// Mutant: `exited_by` reaps, or asks the reap's look.
#[cfg(target_os = "linux")]
#[skuld::test]
fn exited_by_looks_through_exited_and_reaps_nothing() {
    let fake = FakeProcess::new([crate::os_process::fake::Answer::Exited]);
    let child = OwnedChild::new(Box::new(fake.clone()));
    assert!(child.exited_by(None).expect("exited_by"));
    assert_eq!(fake.looks(), 1);
    assert!(!child.is_reaped());
}

// After the reap =====

/// A cached status never reaches the OS, for any deadline.
///
/// Mutant: no `E` check: the look runs past the scripted answers.
#[skuld::test]
fn a_cached_status_never_reaches_the_os() {
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Reaped(exit())]);
    let child = OwnedChild::new(Box::new(fake.clone()));
    let first = status(child.wait(None));
    assert_eq!(status(child.wait(None)), first);
    assert_eq!(status(child.wait(Some(far()))), first);
    assert_eq!(status(try_wait(&child)), first);
    assert_eq!(fake.looks(), 1);
}

/// `signal` after the reap sends nothing.
///
/// Mutant: a `signal` to the OS after `E`: the empty signal table panics.
#[skuld::test]
fn signal_after_the_reap_sends_nothing() {
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Reaped(exit())]);
    let child = OwnedChild::new(Box::new(fake.clone()));
    status(child.wait(None));
    assert_eq!(
        child.signal(Sig::Kill).expect("an already-reaped child is success"),
        Sent::Gone
    );
    assert_eq!(fake.signal_calls(), []);
}

/// `ReapHold::signal` after our own reap (`State::E`) reports `Gone` and sends nothing.
///
/// Mutant: it reports `Delivered`, or signals, after `E`.
#[cfg(unix)]
#[skuld::test]
fn a_held_signal_after_our_own_reap_is_gone() {
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Reaped(exit())]);
    let child = OwnedChild::new(Box::new(fake.clone()));
    status(child.wait(None));
    assert_eq!(
        child
            .hold()
            .signal(Sig::Kill)
            .expect("an already-reaped child is success"),
        Sent::Gone
    );
    assert_eq!(fake.signal_calls(), []);
}

// L8: an unreadable consuming record =====

/// L8: a consuming reap that hands back a record that is not an exit is cached as
/// `E(Unreadable)` and acts by no pid: every later wait answers it and `signal` sends nothing. In
/// a debug build the contract breach panics, after the `E` write.
///
/// Mutant: a panic before the `E` write: the state stays `W` and the guard restores `N` over a
/// reaped pid.
#[skuld::test]
fn an_unreadable_consuming_record_is_cached_and_acts_by_no_pid() {
    let unreadable = ExitRecord::Unreadable { si_code: 99 };
    let fake = FakeProcess::new([]).reaps([ReapAnswer::Reaped(unreadable)]);
    let child = OwnedChild::new(Box::new(fake.clone()));
    // In a debug build the call panics (after the write); in a release build it returns.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| child.wait(None)));
    if cfg!(debug_assertions) {
        assert!(outcome.is_err(), "a debug build asserts the contract");
    } else {
        assert_eq!(
            outcome.expect("release returns").expect("a record"),
            ChildWaitOutcome::Exited(unreadable)
        );
    }
    assert!(
        matches!(child.lock().state, State::E(ExitRecord::Unreadable { si_code: 99 })),
        "the state must already be E(Unreadable): {child:?}"
    );
    for outcome in [child.wait(None), child.wait(Some(far())), try_wait(&child)] {
        assert_eq!(outcome.expect("cached"), ChildWaitOutcome::Exited(unreadable));
    }
    assert_eq!(child.signal(Sig::Kill).expect("signal"), Sent::Gone);
    assert_eq!(fake.signal_calls(), []);
}

// Adoption =====

/// Taking over a child makes no call to it: nothing is reaped or looked at.
///
/// Mutant: `OwnedChild::new` reaps or looks at an already-exited child on adoption.
#[skuld::test]
fn adopt_never_reaps() {
    let fake = FakeProcess::new([]);
    let child = OwnedChild::new(Box::new(fake.clone()));
    assert_eq!(fake.looks(), 0);
    assert!(!child.is_reaped());
}

/// `adopt` never reaps: an already-exited child is still a zombie afterwards, so a later
/// wait reaps it and returns its status.
///
/// Mutant: `OwnedChild::new` reaps or looks at an already-exited child on adoption.
#[cfg(unix)]
#[skuld::test]
fn adopt_never_reaps_a_zombie() {
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
    assert_eq!(r, 0, "waitid(WNOWAIT): {}", std::io::Error::last_os_error());

    let owned = OwnedChild::adopt(child, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    // Still a zombie: a non-consuming look finds its exit record.
    // SAFETY: as above.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::waitid(
            libc::P_PID,
            id.pid() as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    assert_eq!(r, 0, "waitid: {}", std::io::Error::last_os_error());
    #[cfg(target_os = "linux")]
    // SAFETY: `waitid` filled the `siginfo_t` (an exit record), so `si_pid` is initialised.
    let seen = unsafe { info.si_pid() };
    #[cfg(target_os = "macos")]
    let seen = info.si_pid;
    assert_ne!(seen, 0, "adopt must leave the exited child a zombie");
    assert!(super::fixtures::wait_status(&owned).success());
}

// Deadline arithmetic =====

/// `clamp_block` caps every timed block below the value the platforms read as `INFINITE`.
///
/// Mutant: an unclamped `wait_timeout`.
#[skuld::test]
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

// The state of the root =====

/// The state is `Reaped` once the reap is recorded, before the waiter returns, for every shape of
/// deadline; and it reads the record, not the OS.
///
/// Mutant: `state` answers `Unreaped` once the reap is recorded.
#[skuld::test]
fn the_state_is_reaped_as_soon_as_the_reap_is_recorded() {
    for deadline in [None, Some(far()), Some(Instant::now())] {
        // No peek is scripted: a `state` that asks the OS panics.
        let fake = FakeProcess::new([]).reaps([ReapAnswer::Reaped(exit())]);
        let child = OwnedChild::new(Box::new(fake));
        let (gate, reached, release) = seams::park_gate();
        std::thread::scope(|scope| {
            let a = scope.spawn(|| {
                let _armed = seams::park_after_reap_recorded_on(gate);
                child.wait(deadline)
            });
            reached.recv().expect("the reap was recorded");
            #[cfg(unix)]
            let seen = matches!(child.hold().state(), crate::signal::RootState::Reaped { own: true });
            #[cfg(not(unix))]
            let seen = true;
            let seen_own = child.is_reaped();
            release.send(()).expect("release");
            assert!(matches!(a.join().expect("join"), Ok(ChildWaitOutcome::Exited(_))));
            assert!(seen, "the reap was recorded, but the state was not Reaped");
            assert!(seen_own, "the reap was recorded, but is_reaped answered false");
        });
    }
}

/// The state is `Unreaped` until a look returns the record, and `Reaped { own }` from then on,
/// asked of the record and not of the OS.
///
/// Mutant: `state` answers `Reaped` for a state that is not `E`, or asks the OS after `E`.
#[cfg(unix)]
#[skuld::test]
fn the_state_is_an_own_reap_only_once_a_look_returns_the_record() {
    use crate::signal::RootState;
    let fake = FakeProcess::new([])
        .reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())])
        .peeks([Ok(PeekOutcome::Running)]);
    let child = OwnedChild::new(Box::new(fake));
    assert_eq!(try_wait(&child).expect("try_wait"), ChildWaitOutcome::DeadlinePassed);
    assert!(matches!(child.hold().state(), RootState::Unreaped));
    assert!(!child.is_reaped());
    status(try_wait(&child));
    // The one scripted peek is spent: a `state` that asks the OS now panics.
    assert!(matches!(child.hold().state(), RootState::Reaped { own: true }));
    assert!(child.is_reaped());
}

/// A waiter parked on its wait is a holder (`W`), not a reap.
///
/// Mutant: `state` answers `Reaped` for a state that is not `E`.
#[cfg(unix)]
#[skuld::test]
fn the_state_is_unreaped_while_a_holder_waits() {
    use crate::signal::RootState;
    let fake = FakeProcess::new([])
        .reaps([ReapAnswer::Running, ReapAnswer::Reaped(exit())])
        .peeks([Ok(PeekOutcome::Running)]);
    let child = owned_over(&fake);
    let holder = park_holder(&child, &fake, |c| c.wait(None));
    let seen = child.hold().state();
    let seen_own = child.is_reaped();
    status(holder.release_and_join());
    assert!(matches!(seen, RootState::Unreaped), "{seen:?}");
    assert!(!seen_own, "a holder is waiting, but is_reaped answered true");
    assert!(child.is_reaped());
}
