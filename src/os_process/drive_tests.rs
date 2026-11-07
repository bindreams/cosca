use std::time::{Duration, Instant};

use super::{absolute, exited_held, run, run_with, ProcessExit, RunOutcome, Step, Waitable};
use crate::error::Error;
use crate::identity::ProcessId;
use crate::os_process::fake::{Answer, FakeProcess};
use crate::os_process::{Exit, OsProcess};
use crate::wait::{block_probe, fault, test_clock};

fn fake(exits: impl IntoIterator<Item = Answer>) -> FakeProcess {
    FakeProcess::new(exits)
}

#[skuld::test]
fn zero_timeout_looks_once_and_never_blocks() {
    block_probe::take();
    let p = fake([Answer::Running]);
    assert!(!exited_held(&p, Some(Duration::ZERO)).unwrap());
    assert_eq!(p.looks(), 1);
    assert!(block_probe::take().is_empty(), "a zero timeout must not block");
}

/// Mutant: swallow a failed look as a wake, or block before returning it.
#[skuld::test]
fn a_failed_look_is_returned_without_blocking() {
    block_probe::take();
    let p = fake([Answer::Err(std::io::ErrorKind::PermissionDenied)]);
    let err = exited_held(&p, None).unwrap_err();
    assert!(
        matches!(&err, Error::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied),
        "{err:?}"
    );
    assert_eq!(p.looks(), 1);
    assert!(block_probe::take().is_empty());
}

#[skuld::test]
fn exited_before_first_look_returns_true_without_blocking() {
    block_probe::take();
    let p = fake([Answer::Exited]);
    assert!(exited_held(&p, None).unwrap());
    assert_eq!(p.looks(), 1);
    assert!(block_probe::take().is_empty());
}

#[skuld::test]
fn wakes_and_looks_again() {
    block_probe::take();
    let p = fake([Answer::Running, Answer::Exited]);
    p.wake();
    assert!(exited_held(&p, Some(Duration::from_secs(60))).unwrap());
    assert_eq!(p.looks(), 2);
    assert_eq!(block_probe::take().len(), 1, "one wait, between the two looks");
}

#[skuld::test]
fn expiry_ends_in_one_final_look() {
    block_probe::take();
    let (_clock, start) = test_clock::FrozenClockGuard::install();
    let timeout = Duration::from_secs(10);
    let p = fake([Answer::Running, Answer::Running]);
    // The deadline passes while the first look is being made.
    p.on_look(|n| {
        if n == 0 {
            test_clock::advance(Duration::from_secs(11));
        }
    });
    assert!(!exited_held(&p, Some(timeout)).unwrap());
    assert_eq!(p.looks(), 2);
    let last = *p.look_times().last().unwrap();
    assert!(last > start + timeout, "the final look must come after the deadline");
    assert!(
        block_probe::take().is_empty(),
        "nothing is armed at or after the deadline"
    );
}

/// Mutant: let `Duration::MAX` overflow the deadline sum.
#[skuld::test]
fn duration_max_is_unbounded() {
    block_probe::take();
    let p = fake([Answer::Running, Answer::Exited]);
    p.wake();
    assert!(exited_held(&p, Some(Duration::MAX)).unwrap());
    assert_eq!(
        block_probe::take(),
        [None],
        "an overflowing timeout arms an unbounded wait"
    );
}

/// What a [`Scripted`] look does.
#[derive(Clone, Copy)]
pub(crate) enum Move {
    Done,
    Recheck,
    /// Wait on a source that is already fired: the block returns at once.
    Wait,
    /// Wait on a descriptor whose poll fails (`POLLERR`: the write end of a pipe nobody reads).
    #[cfg(target_os = "linux")]
    WaitFails,
}

/// A [`Waitable`] that plays `moves`. A row drives it with [`run_with`] and its own pause, which
/// records what it is asked for (and moves the frozen clock, where the row needs it) and returns at
/// once. The async driver's rows play it too.
pub(crate) struct Scripted {
    moves: std::collections::VecDeque<Move>,
    source: FakeProcess,
    pub(crate) looks: usize,
    pub(crate) on_look: Box<dyn FnMut(usize)>,
    /// Whether [`Waitable::block_failed`] lets the loop go on.
    pub(crate) survive_block_errors: bool,
    pub(crate) block_errors: usize,
    #[cfg(target_os = "linux")]
    broken: Option<std::io::PipeWriter>,
}

impl Scripted {
    pub(crate) fn new(moves: impl IntoIterator<Item = Move>) -> Self {
        let moves: std::collections::VecDeque<Move> = moves.into_iter().collect();
        let waits = moves.iter().filter(|m| matches!(m, Move::Wait)).count();
        let source = fake(vec![Answer::Running; waits]);
        source.wake();
        Self {
            moves,
            source,
            looks: 0,
            on_look: Box::new(|_| {}),
            survive_block_errors: false,
            block_errors: 0,
            #[cfg(target_os = "linux")]
            broken: None,
        }
    }
}

impl Waitable for Scripted {
    type Output = ();

    fn look(&mut self) -> Result<Step<'_, ()>, Error> {
        (self.on_look)(self.looks);
        self.looks += 1;
        Ok(match self.moves.pop_front().expect("a look past the scripted moves") {
            Move::Done => Step::Done(()),
            Move::Recheck => Step::Recheck,
            Move::Wait => match self.source.exited()? {
                Exit::Running(wait_for) => Step::Wait(wait_for),
                Exit::Exited => unreachable!("the source answers Running"),
            },
            #[cfg(target_os = "linux")]
            Move::WaitFails => {
                use std::os::fd::AsFd as _;
                let (rx, tx) = std::io::pipe().expect("pipe");
                drop(rx);
                let tx: &std::io::PipeWriter = self.broken.insert(tx);
                Step::Wait(crate::os_process::WaitFor::Readable(tx.as_fd()))
            }
        })
    }

    fn block_failed(&mut self, e: Error) -> Result<(), Error> {
        self.block_errors += 1;
        if self.survive_block_errors {
            Ok(())
        } else {
            Err(e)
        }
    }
}

pub(crate) fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// `pauses` in whole milliseconds: `backon` multiplies through `f32` seconds, so a step can come out
/// a microsecond over (16.000001 ms).
pub(crate) fn whole_ms(pauses: &[Duration]) -> Vec<u64> {
    pauses
        .iter()
        .map(|d| (d.as_secs_f64() * 1000.0).round() as u64)
        .collect()
}

/// Mutant: pause a constant, or restart the schedule at every pause, or cap it at another value.
#[skuld::test]
fn run_pauses_the_backoff_steps_on_recheck() {
    block_probe::take();
    let mut w = Scripted::new([Move::Recheck; 8].into_iter().chain([Move::Done]));
    let mut pauses = Vec::new();
    assert!(matches!(
        run_with(&mut w, None, |d| pauses.push(d)).unwrap(),
        RunOutcome::Done(())
    ));
    assert_eq!(whole_ms(&pauses), [1, 2, 4, 8, 16, 32, 50, 50]);
    assert_eq!(w.looks, 9, "one look per pause, and one more");
    assert!(block_probe::take().is_empty(), "a Recheck blocks on nothing");
}

/// Mutant: keep the schedule across a wait.
#[skuld::test]
fn run_restarts_the_backoff_after_a_wait() {
    block_probe::take();
    let mut w = Scripted::new([Move::Recheck, Move::Recheck, Move::Wait, Move::Recheck, Move::Done]);
    let mut pauses = Vec::new();
    assert!(matches!(
        run_with(&mut w, None, |d| pauses.push(d)).unwrap(),
        RunOutcome::Done(())
    ));
    assert_eq!(whole_ms(&pauses), [1, 2, 1]);
    assert_eq!(block_probe::take().len(), 1, "the one Wait blocked once");
}

/// A pause never outlasts the deadline: the last one is cut to the time remaining, and the look
/// after it is the final one.
///
/// Mutant: pause the whole step; or make no final look after the last pause.
#[skuld::test]
fn run_clamps_a_pause_to_the_time_remaining() {
    let (_clock, _start) = test_clock::FrozenClockGuard::install();
    let mut w = Scripted::new([Move::Recheck; 4]);
    let mut pauses = Vec::new();
    let outcome = run_with(&mut w, absolute(Some(ms(4))), |d| {
        pauses.push(d);
        test_clock::advance(d);
    })
    .unwrap();
    assert!(matches!(outcome, RunOutcome::DeadlinePassed), "{outcome:?}");
    assert_eq!(whole_ms(&pauses), [1, 2, 1]);
    assert_eq!(w.looks, 4, "the last look is made at the deadline");
}

/// Mutant: pause at or after the deadline, or give up at the deadline without a final look.
#[skuld::test]
fn run_never_pauses_after_the_deadline() {
    let (_clock, _start) = test_clock::FrozenClockGuard::install();
    // The deadline is already past.
    let mut w = Scripted::new([Move::Recheck]);
    let mut pauses = Vec::new();
    let outcome = run_with(&mut w, absolute(Some(Duration::ZERO)), |d| pauses.push(d)).unwrap();
    assert!(matches!(outcome, RunOutcome::DeadlinePassed), "{outcome:?}");
    assert!(pauses.is_empty());
    assert_eq!(w.looks, 1);
    // The deadline passes during a look that asks for a recheck: no pause, one final look, whose
    // answer is the outcome.
    let mut w = Scripted::new([Move::Recheck, Move::Done]);
    w.on_look = Box::new(|n| {
        if n == 0 {
            test_clock::advance(ms(5));
        }
    });
    let outcome = run_with(&mut w, absolute(Some(ms(5))), |d| pauses.push(d)).unwrap();
    assert!(matches!(outcome, RunOutcome::Done(())), "{outcome:?}");
    assert!(pauses.is_empty());
    assert_eq!(w.looks, 2);
}

/// A failed block is the `Waitable`'s to answer: by default it ends the loop with the error.
///
/// Mutant: swallow the error in `run`; or never hand it to the `Waitable`.
#[cfg(target_os = "linux")]
#[skuld::test]
fn run_returns_a_block_error_the_waitable_does_not_survive() {
    let mut w = Scripted::new([Move::WaitFails, Move::Done]);
    assert!(matches!(run(&mut w, None), Err(Error::Io(_))));
    assert_eq!(w.block_errors, 1);
    assert_eq!(w.looks, 1);
}

/// A `Waitable` that survives a failed block is looked at again, and the loop goes on.
///
/// Mutant: end the loop on a block error the `Waitable` survived; or skip the look after it.
#[cfg(target_os = "linux")]
#[skuld::test]
fn run_looks_again_after_a_block_error_the_waitable_survives() {
    let mut w = Scripted::new([Move::WaitFails, Move::Recheck, Move::Done]);
    w.survive_block_errors = true;
    assert!(matches!(run_with(&mut w, None, |_| {}).unwrap(), RunOutcome::Done(())));
    assert_eq!(w.block_errors, 1);
    assert_eq!(w.looks, 3);
}

/// One open serves a signal and a wait from different threads: `Sync`, `&self`. The wait ends
/// only when the killed process exits, so the two threads need no other sync.
#[skuld::test]
fn looks_and_a_signal_on_one_process_run_from_two_threads() {
    use crate::os_process::{open, OsProcess};
    use crate::signal::{Sent, Sig};

    let mut child = crate::test_spawn::spawn(&mut crate::test_child::held_std_blocker(std::process::Stdio::null()))
        .expect("spawn blocker");
    let id = ProcessId::of(child.id()).found().expect("identity of a live child");
    let process = open(id).unwrap().expect("a live process opens");
    let p: &dyn OsProcess = &*process;
    std::thread::scope(|scope| {
        let waiter = scope.spawn(|| exited_held(p, None));
        let killer = scope.spawn(|| p.signal(Sig::Kill));
        assert!(waiter.join().unwrap().unwrap(), "the wait ends when the process exits");
        let sent = killer.join().unwrap().unwrap();
        assert!(matches!(sent, Sent::Delivered | Sent::Gone), "{sent:?}");
    });
    child.wait().expect("reap the blocker");
}

#[cfg(windows)]
mod windows {
    //! The Windows arm of the blocking wait: it never reports "still alive" before the real
    //! deadline. Seams are documented in `crate::wait`.

    use std::time::{Duration, Instant};

    use super::exited_held;
    use crate::os_process::open;
    use crate::test_child::live_blocker as blocker;
    use crate::wait::test_clock::FrozenClockGuard;
    use crate::wait::{block_probe, wait_ms_probe};
    use crate::wait::{remaining_override_seam, wait_clamp_seam};

    /// A never-exiting target armed with a sub-millisecond remainder rounds up to 1ms, still reports
    /// alive at the deadline, and derives its argument from the site's own deadline.
    ///
    /// Mutant: truncate in `win32_timeout_ms` (`d.as_millis()`) -> `ms` is 0. Mutant: add slack ->
    /// `ms` is above 1. Mutant: ignore the site's deadline -> `requested` is not 5ms.
    #[skuld::test]
    fn exited_by_arms_the_ceiling_of_the_remaining_duration() {
        let (child, stdin, id) = blocker();
        let process = open(id).unwrap().expect("a live process opens");
        let (_clock, at) = FrozenClockGuard::install();
        wait_ms_probe::take();
        let _override = remaining_override_seam::set(Duration::from_micros(500));
        let deadline = at + Duration::from_millis(5);
        let result = exited_held(&*process, Some(Duration::from_millis(5)));
        let reached = Instant::now() >= deadline;
        let arms = wait_ms_probe::take();
        drop(stdin);
        child.wait().expect("reap the blocker");
        assert!(
            !result.expect("a live never-exiting child must not report a wait failure"),
            "a never-exiting child is still alive at the deadline"
        );
        assert!(reached, "the call returned before the real deadline");
        let first = arms.first().expect("at least one armed wait");
        assert_eq!(first.remaining, Duration::from_micros(500));
        assert_eq!(first.ms, 1);
        assert_eq!(
            first.requested,
            Duration::from_millis(5),
            "the site must pass the time left to its own deadline (clock frozen at the deadline's origin)"
        );
    }

    /// `exited_held` arms its first wait with the whole timeout it was given, on a live process.
    ///
    /// Mutant: the timeout is dropped on the way to the loop (the wait is unbounded, or zero).
    #[skuld::test]
    fn exited_held_arms_the_wait_from_its_timeout() {
        let (child, stdin, id) = blocker();
        let process = open(id).unwrap().expect("a live process opens");
        let (_clock, _at) = FrozenClockGuard::install();
        block_probe::take();
        let result = exited_held(&*process, Some(Duration::from_millis(50)));
        let armed = block_probe::take();
        drop(stdin);
        child.wait().expect("reap the blocker");
        assert!(!result.expect("a live never-exiting child must not report a wait failure"));
        assert_eq!(armed.first(), Some(&Some(Duration::from_millis(50))), "{armed:?}");
    }

    /// An early, unclamped `WAIT_TIMEOUT` hours before the deadline is not trusted: the site re-arms.
    ///
    /// Mutant: return on the first `WAIT_TIMEOUT` (no recheck, or one conditioned on the clamp) ->
    /// one arm, wrongly reports alive.
    #[skuld::test]
    fn exited_by_never_reports_still_alive_before_the_deadline() {
        let (child, stdin, id) = blocker();
        let process = open(id).unwrap().expect("a live process opens");
        wait_ms_probe::take();
        let _override = remaining_override_seam::set(Duration::from_micros(500));
        wait_ms_probe::on_second_arm(move || drop(stdin)); // EOF -> the blocker exits for real
        let result = exited_held(&*process, Some(Duration::from_secs(3600)));
        let arms = wait_ms_probe::take();
        let exited = result.expect("a genuinely-terminated child must not report a wait failure");
        child.wait().expect("reap the child after it exits");
        assert!(exited, "an early WAIT_TIMEOUT was trusted");
        assert!(arms.len() >= 2, "expected a re-arm, got {} arm(s)", arms.len());
    }

    /// A wait clamped below the deadline re-arms, recomputing `remaining` each round.
    ///
    /// Mutant: drop the re-arm loop -> one arm, wrongly reports alive. Mutant: hoist `remaining`
    /// above the loop -> `remaining` does not shrink.
    #[skuld::test]
    fn exited_by_re_arms_past_a_clamped_timeout() {
        let (child, stdin, id) = blocker();
        let process = open(id).unwrap().expect("a live process opens");
        wait_ms_probe::take();
        let _clamp = wait_clamp_seam::set(5);
        wait_ms_probe::on_second_arm(move || drop(stdin));
        let result = exited_held(&*process, Some(Duration::from_secs(3600)));
        let arms = wait_ms_probe::take();
        let exited = result.expect("a genuinely-terminated child must not report a wait failure");
        child.wait().expect("reap the child after it exits");
        assert!(exited, "a clamped WAIT_TIMEOUT was trusted");
        wait_ms_probe::assert_rearmed_with_fresh_remaining(&arms, 5);
    }

    /// Under a frozen test clock a finite deadline still ends: each real wait advances the clock.
    ///
    /// Mutant: drop `advance_by_elapsed_if_frozen` from `wait_until` -> `remaining` never shrinks
    /// and the call re-arms forever.
    #[skuld::test]
    fn exited_by_terminates_under_a_frozen_clock() {
        let (child, stdin, id) = blocker();
        let process = open(id).unwrap().expect("a live process opens");
        let (_clock, at) = FrozenClockGuard::install();
        let deadline = at + Duration::from_millis(50);
        let result = exited_held(&*process, Some(Duration::from_millis(50)));
        let reached = Instant::now() >= deadline;
        drop(stdin);
        child.wait().expect("reap the blocker");
        assert!(!result.expect("a live never-exiting child must not report a wait failure"));
        assert!(reached, "the call returned before the real deadline");
    }
}

/// Mutant: `exited_held` skips the seam, or takes it after the look.
#[skuld::test]
fn exited_held_takes_the_watch_fault_seam() {
    let p = fake([Answer::Exited]);
    fault::set_force_watch_error(true);
    assert!(super::exited_held(&p, None).is_err());
    assert!(!fault::armed(), "the seam is consumed");
    assert_eq!(p.looks(), 0, "the seam comes before any look");
}

/// Mutant: `exited_held` skips the bounded-section assert.
#[cfg(feature = "tokio")]
#[skuld::test]
#[should_panic(expected = "would block inside an async Drop")]
fn exited_held_refuses_inside_a_bounded_section() {
    let _section = crate::bounded::Section::enter();
    _ = super::exited_held(&fake([Answer::Exited]), Some(Duration::ZERO));
}

/// Mutant: `exited_held` drops the timeout, or looks twice at zero.
#[skuld::test]
fn exited_held_zero_is_one_look() {
    let running = fake([Answer::Running]);
    assert!(!super::exited_held(&running, Some(Duration::ZERO)).unwrap());
    assert_eq!(running.looks(), 1);
    let exited = fake([Answer::Exited]);
    assert!(super::exited_held(&exited, Some(Duration::ZERO)).unwrap());
    assert_eq!(exited.looks(), 1);
}

// `run` =====

/// `run` over a fake's looks, against `deadline`.
fn run_fake(p: &FakeProcess, deadline: Option<Instant>) -> Result<RunOutcome<()>, Error> {
    run(&mut ProcessExit(p), deadline)
}

/// Mutant: block before the first look.
#[skuld::test]
fn run_returns_done_without_blocking() {
    block_probe::take();
    let p = fake([Answer::Exited]);
    assert!(matches!(run_fake(&p, absolute(None)).unwrap(), RunOutcome::Done(())));
    assert_eq!(p.looks(), 1);
    assert!(block_probe::take().is_empty());
}

/// Mutant: return after the wake without looking again, or look twice per wake.
#[skuld::test]
fn run_blocks_on_the_wait_the_look_returned_then_looks_again() {
    block_probe::take();
    let p = fake([Answer::Running, Answer::Exited]);
    p.wake();
    assert!(matches!(
        run_fake(&p, absolute(Some(Duration::from_secs(60)))).unwrap(),
        RunOutcome::Done(())
    ));
    assert_eq!(p.looks(), 2);
    assert_eq!(block_probe::take().len(), 1, "one block, between the two looks");
}

/// Mutant: block once before honouring a deadline that has already passed.
#[skuld::test]
fn run_with_an_expired_deadline_looks_once() {
    block_probe::take();
    let (_clock, start) = test_clock::FrozenClockGuard::install();
    let p = fake([Answer::Running]);
    assert!(matches!(run_fake(&p, Some(start)).unwrap(), RunOutcome::DeadlinePassed));
    assert_eq!(p.looks(), 1);
    assert!(block_probe::take().is_empty(), "a passed deadline arms nothing");
}

/// The clock passes the deadline at the start of the second look, after one block. That look has
/// no time left to block in, so the next is the last: it returns, and nothing is armed after it.
///
/// Mutant: block (or loop) again after the deadline; mutant: return at the look that saw the clock
/// pass, without the final look.
#[skuld::test]
fn run_takes_one_final_look_at_the_deadline_and_starts_no_round() {
    block_probe::take();
    let (_clock, start) = test_clock::FrozenClockGuard::install();
    let timeout = Duration::from_secs(10);
    let p = fake([Answer::Running, Answer::Running, Answer::Running]);
    p.wake();
    p.on_look(|n| {
        if n == 1 {
            test_clock::advance(Duration::from_secs(11));
        }
    });
    assert!(matches!(
        run_fake(&p, absolute(Some(timeout))).unwrap(),
        RunOutcome::DeadlinePassed
    ));
    assert_eq!(p.looks(), 3);
    assert!(*p.look_times().last().unwrap() > start + timeout);
    assert_eq!(
        block_probe::take().len(),
        1,
        "only the block before the deadline passed"
    );
}

/// Mutant: arm the whole timeout each round, not what is left of it.
#[skuld::test]
fn run_arms_each_block_with_at_most_the_time_remaining() {
    block_probe::take();
    let (_clock, _start) = test_clock::FrozenClockGuard::install();
    let p = fake([Answer::Running, Answer::Running, Answer::Exited]);
    p.wake();
    // 3 s of the 10 s pass at the start of each of the first two looks.
    p.on_look(|n| {
        if n < 2 {
            test_clock::advance(Duration::from_secs(3));
        }
    });
    assert!(matches!(
        run_fake(&p, absolute(Some(Duration::from_secs(10)))).unwrap(),
        RunOutcome::Done(())
    ));
    let armed: Vec<Duration> = block_probe::take().into_iter().map(|a| a.expect("bounded")).collect();
    assert_eq!(armed.len(), 2, "{armed:?}");
    assert!(armed[0] <= Duration::from_secs(7), "{armed:?}");
    assert!(armed[1] <= Duration::from_secs(4), "{armed:?}");
    assert!(armed[1] < armed[0], "{armed:?}");
}

/// Mutant: no clamp on the armed time, so a far deadline arms its whole distance.
#[skuld::test]
fn run_arms_a_deadline_beyond_the_block_limit_in_pieces() {
    block_probe::take();
    let p = fake([Answer::Running, Answer::Exited]);
    p.wake();
    let far = absolute(Some(Duration::from_secs(u64::from(u32::MAX)))).expect("the clock reaches 136 years");
    assert!(matches!(run_fake(&p, Some(far)).unwrap(), RunOutcome::Done(())));
    let armed = block_probe::take();
    assert!(!armed.is_empty(), "the wait must have blocked");
    for a in armed {
        let a = a.expect("a deadline wait arms a bounded block");
        assert!(a <= crate::wait::MAX_BLOCK, "armed {a:?}");
    }
}

/// A wait on a process handle that fails is a contract breach, not a wake: debug builds assert,
/// release builds return the OS error.
///
/// Mutant: the `debug_assert!` removed from the failed arm of `block`.
#[cfg(windows)]
#[skuld::test]
fn a_failed_block_on_a_process_handle_is_a_contract_breach() {
    use std::os::windows::io::AsHandle as _;

    use crate::os_process::WaitFor;

    let unwaitable = crate::test_child::unwaitable::unwaitable_handle();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        super::block(&WaitFor::Signalled(unwaitable.as_handle()), None)
    }));
    if cfg!(debug_assertions) {
        assert!(outcome.is_err(), "a debug build asserts the contract");
    } else {
        assert!(matches!(outcome.expect("release returns"), Err(Error::Io(_))));
    }
}
