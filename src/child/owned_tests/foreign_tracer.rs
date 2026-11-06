//! `OwnedChild` against a child traced by a process that is not its parent, as `gdb -p` does
//! (`TRACER` group; needs `COSCA_TEST_TRACER_CONSENT=1`).
//!
//! A tracee that dies while a foreign tracer holds it is a zombie the tracer alone can see: its
//! pidfd is readable, the parent's `waitid` finds no record, and the parent's own record appears
//! only after the tracer hands the zombie back: by reaping it with `waitpid`, or by exiting
//! (`exit_ptrace` detaches it; a debugger that quits). Both are tested, for the unbounded `wait`
//! and, for the reap, for a bounded one. The look finds the pidfd readable and no record, so it asks
//! for a recheck and the holder backs off until the tracer lets go. A tracee the tracer merely
//! stops is no exit either. The tracer is [`crate::test_support::foreign_tracer`].

use std::os::unix::process::ExitStatusExt as _;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use super::fixtures::{status, try_wait, Blocker};
use crate::child::owned::{seams, ChildWaitOutcome};
use crate::error::Error;
use crate::identity::Liveness;
use crate::test_child::reaped_elsewhere::kill_own_child;
use crate::test_groups::{tracer_group, Group};
use crate::test_support::foreign_tracer::{self, EXIT, REAP, STOP};

/// What the waiting thread reports.
enum Msg {
    /// The holder is about to back off: its first look found the zombie held.
    AtBackoff,
    /// `wait` returned, with the pauses the holder took.
    Done(Result<ChildWaitOutcome, Error>, Vec<Option<Duration>>),
}

/// How the driver waits on the held zombie.
#[derive(Clone, Copy)]
enum Wait {
    /// `wait` with no deadline.
    Unbounded,
    /// `wait` against a deadline far in the future.
    Deadline,
}

/// A zombie held by a foreign tracer is running to `try_wait`; `wait` backs off (no polling, no
/// blocking `waitid`) until the tracer reaps it, then returns the kill.
#[skuld::test]
fn a_zombie_held_by_a_foreign_tracer_is_handed_back_to_a_blocked_wait(#[fixture(tracer_group)] _group: &Group) {
    hand_back(REAP, Wait::Unbounded, false);
}

/// As [`a_zombie_held_by_a_foreign_tracer_is_handed_back_to_a_blocked_wait`], but the tracer lets
/// go by exiting without reaping, as a debugger that quits does.
#[skuld::test]
fn a_zombie_held_by_a_foreign_tracer_that_exits_is_handed_back_to_a_blocked_wait(
    #[fixture(tracer_group)] _group: &Group,
) {
    hand_back(EXIT, Wait::Unbounded, false);
}

/// A tracee the foreign tracer has stopped is no exit: `try_wait` and a short bounded `wait` find
/// it running. The kill and the hand-back then go as above.
///
/// Mutant: a peek that finds no record reads as an exit (the holder goes on to reap).
#[skuld::test]
fn a_tracee_stopped_by_a_foreign_tracer_is_not_an_exit(#[fixture(tracer_group)] _group: &Group) {
    hand_back(REAP, Wait::Unbounded, true);
}

/// A bounded `wait` over the held zombie backs off and looks again, and returns the kill once the
/// tracer reaps it. The tracer lets go only after the backoff began, so a first look that found no
/// record has to have been read as "still running".
///
/// Mutants: a bounded holder that re-polls, or reads the missing record as the child gone.
#[skuld::test]
fn a_deadline_wait_on_a_zombie_held_by_a_foreign_tracer_is_handed_back(#[fixture(tracer_group)] _group: &Group) {
    hand_back(REAP, Wait::Deadline, false);
}

/// A zombie a foreign tracer holds has exited, so the child reads `Dead` from the pidfd's edge,
/// though the parent's peek finds no record to show for it.
///
/// Mutant: liveness answered from the peek, which reads the held zombie as `Running`.
#[skuld::test]
fn a_zombie_held_by_a_foreign_tracer_is_dead(#[fixture(tracer_group)] _group: &Group) {
    let b = Blocker::spawn_with(foreign_tracer::allow_any_tracer);
    let mut tracer = foreign_tracer::spawn_helper(b.pid);
    assert_eq!(
        b.owned.liveness().expect("liveness"),
        Liveness::Alive,
        "a running child"
    );

    kill_own_child(b.pid);
    let pidfd = b.owned.os_handle();
    let mut fds = [rustix::event::PollFd::new(&pidfd, rustix::event::PollFlags::IN)];
    crate::wait::poll_ready(&mut fds).expect("poll the pidfd");
    assert!(
        matches!(try_wait(&b.owned), Ok(ChildWaitOutcome::DeadlinePassed)),
        "the tracer still holds it"
    );
    assert_eq!(b.owned.liveness().expect("liveness"), Liveness::Dead);

    tracer.send(REAP);
    tracer.expect("reaped");
    assert_eq!(
        b.owned.liveness().expect("liveness"),
        Liveness::Dead,
        "and once handed back"
    );
    tracer.finish();
}

fn hand_back(go_byte: u8, wait: Wait, stop_first: bool) {
    let b = Blocker::spawn_with(foreign_tracer::allow_any_tracer);
    let mut tracer = foreign_tracer::spawn_helper(b.pid);

    if stop_first {
        tracer.send(STOP);
        tracer.expect("stopped");
        assert!(
            matches!(try_wait(&b.owned), Ok(ChildWaitOutcome::DeadlinePassed)),
            "a stop is no exit"
        );
        // The wait ends at its deadline with one final look; a look that read the stop as an exit
        // would reap.
        let soon = std::time::Instant::now() + Duration::from_millis(20);
        assert_eq!(
            b.owned.wait(Some(soon)).expect("wait"),
            ChildWaitOutcome::DeadlinePassed,
            "a stop is no exit"
        );
    }

    // Setup: the test ends the tracee itself, so a signal route that sends nothing cannot leave it
    // alive for the unbounded `poll` and `wait` below.
    kill_own_child(b.pid);
    // The exit, which the tracer alone can see: the pidfd turns readable.
    let pidfd = b.owned.os_handle();
    let mut fds = [rustix::event::PollFd::new(&pidfd, rustix::event::PollFlags::IN)];
    crate::wait::poll_ready(&mut fds).expect("poll the pidfd");
    assert!(
        matches!(try_wait(&b.owned), Ok(ChildWaitOutcome::DeadlinePassed)),
        "the tracer still holds it"
    );

    let (tx, rx) = mpsc::channel();
    let waiter = std::thread::spawn({
        let owned = Arc::clone(&b.owned);
        move || {
            crate::wait::block_probe::take();
            // Fires just before the holder's first backoff sleep: the look found the zombie held.
            let at = tx.clone();
            let _hook = seams::on_condvar_block_with(move |_| _ = at.send(Msg::AtBackoff));
            let result = match wait {
                Wait::Unbounded => owned.wait(None),
                Wait::Deadline => owned.wait(Some(std::time::Instant::now() + Duration::from_secs(3600))),
            };
            _ = tx.send(Msg::Done(result, crate::wait::block_probe::take()));
        }
    });
    match rx.recv().expect("the waiter reports") {
        Msg::AtBackoff => {}
        Msg::Done(result, pauses) => {
            panic!("wait returned {result:?} ({pauses:?}) while the tracer still held the zombie")
        }
    }
    tracer.send(go_byte);
    if go_byte == REAP {
        tracer.expect("reaped");
    }
    let Msg::Done(result, pauses) = rx.recv().expect("the waiter reports") else {
        panic!("the waiter reported a backoff twice");
    };
    waiter.join().expect("the waiter");
    assert_eq!(status(result).signal(), Some(libc::SIGKILL));
    // The holder backed off between its looks, each pause at most 50 ms and none shorter than the one before.
    assert!(!pauses.is_empty(), "the holder spun: it looked again with no pause");
    let pauses: Vec<Duration> = pauses.into_iter().map(|p| p.expect("a pause is bounded")).collect();
    assert!(pauses.windows(2).all(|w| w[0] <= w[1]), "{pauses:?}");
    assert!(pauses.iter().all(|p| *p <= Duration::from_millis(50)), "{pauses:?}");
    assert_eq!(status(try_wait(&b.owned)).signal(), Some(libc::SIGKILL));
    tracer.finish();
}
