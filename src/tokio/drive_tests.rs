use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use super::exited_by;
use crate::identity::ProcessId;
use crate::os_process::fake::{Answer, FakeProcess};
use crate::wait::fault;

fn fake(exits: impl IntoIterator<Item = Answer>) -> FakeProcess {
    FakeProcess::new(ProcessId::current(), exits, [])
}

/// Poll `fut` once, with a waker that wakes nothing.
fn poll_once<F: Future>(fut: F) -> Poll<F::Output> {
    pin!(fut).as_mut().poll(&mut Context::from_waker(Waker::noop()))
}

/// Mutant: await at a zero timeout, or look a second time.
#[skuld::test]
async fn zero_timeout_looks_once_and_never_waits() {
    let mut p = fake([Answer::Running]);
    let Poll::Ready(answer) = poll_once(exited_by(&mut p, Some(Duration::ZERO))) else {
        panic!("a zero timeout must not wait");
    };
    assert!(!answer.unwrap());
    assert_eq!(p.looks(), 1);
}

/// Mutant: wait before looking, or after an `Exited` look.
#[skuld::test]
async fn exited_before_first_look_returns_true_without_waiting() {
    let mut p = fake([Answer::Exited]);
    let Poll::Ready(answer) = poll_once(exited_by(&mut p, None)) else {
        panic!("an exited process must not wait");
    };
    assert!(answer.unwrap());
    assert_eq!(p.looks(), 1);
}

/// Mutant: trust the wake as the answer instead of looking again.
#[skuld::test]
async fn wakes_and_looks_again() {
    let mut p = fake([Answer::Running, Answer::Exited]);
    p.wake();
    assert!(exited_by(&mut p, Some(Duration::from_secs(60))).await.unwrap());
    assert_eq!(p.looks(), 2);
}

/// Mutant: answer `false` on the expiry itself, without a look after the deadline. The fake is never
/// woken, so only the deadline ends the wait.
#[skuld::test]
async fn expiry_ends_in_one_final_look() {
    let timeout = Duration::from_millis(50);
    let mut p = fake([Answer::Running, Answer::Running]);
    let start = crate::wait::now();
    assert!(!exited_by(&mut p, Some(timeout)).await.unwrap());
    assert_eq!(p.looks(), 2);
    let last = *p.look_times().last().unwrap();
    assert!(
        last >= start + timeout,
        "the final look must come at or after the deadline"
    );
}

/// Mutant: answer `false` on the expiry without trusting the final look, which finds an exit that
/// was pending when the deadline passed.
#[skuld::test]
async fn the_final_look_can_find_an_exit() {
    let mut p = fake([Answer::Running, Answer::Exited]);
    assert!(exited_by(&mut p, Some(Duration::from_millis(50))).await.unwrap());
    assert_eq!(p.looks(), 2);
}

/// Mutant: let `Duration::MAX` overflow the deadline sum.
#[skuld::test]
async fn duration_max_is_unbounded() {
    #[cfg(unix)]
    let (tx, armed) = std::sync::mpsc::channel();
    #[cfg(unix)]
    let _seam = {
        crate::tokio::test_runtime::assert_current_thread();
        crate::tokio::wait::armed_deadline_seam::install(tx)
    };
    let mut p = fake([Answer::Running, Answer::Exited]);
    p.wake();
    assert!(exited_by(&mut p, Some(Duration::MAX)).await.unwrap());
    #[cfg(unix)]
    assert_eq!(armed.try_iter().count(), 0, "an overflowing timeout arms no timer");
}

/// Mutant: arm the timer for a duration re-derived later, or not at all.
#[cfg(unix)]
#[skuld::test]
async fn a_bounded_wait_arms_the_timer_at_the_deadline() {
    use crate::tokio::wait::armed_deadline_seam::{install, Armed};

    crate::tokio::test_runtime::assert_current_thread();
    let (tx, armed) = std::sync::mpsc::channel();
    let _seam = install(tx);
    let timeout = Duration::from_secs(60);
    let before = crate::tokio::wait::tokio_now();
    let mut p = fake([Answer::Running, Answer::Exited]);
    p.wake();
    assert!(exited_by(&mut p, Some(timeout)).await.unwrap());
    let after = crate::tokio::wait::tokio_now();
    let [Armed::At(at)] = armed.try_iter().collect::<Vec<_>>()[..] else {
        panic!("one wait arms one timer");
    };
    assert!(at >= before + timeout && at <= after + timeout, "{at:?}");
}

/// Mutant: look before taking the seam.
#[skuld::test]
async fn forced_watch_error_is_returned_before_looking() {
    crate::tokio::test_runtime::assert_current_thread();
    let mut p = fake([Answer::Exited]);
    fault::set_force_watch_error(true);
    assert!(exited_by(&mut p, None).await.is_err());
    assert_eq!(p.looks(), 0);
    assert!(!fault::armed(), "the seam is consumed");
}

/// Review Focus 5. A `Running` fake whose wait is dropped, and then the runtime. Mutant: the Windows
/// watcher is not released by the drop, so the runtime's drop joins a thread parked on the fake
/// forever; the observer then never hears a release.
#[skuld::test]
fn dropped_wait_releases_the_watch() {
    #[cfg(windows)]
    let (tx, released) = std::sync::mpsc::channel();
    #[cfg(windows)]
    let observer = crate::tokio::wait::fault_observer::install(tx);
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build a runtime");
    let mut p = fake([Answer::Running]);
    runtime.block_on(async {
        let mut wait = pin!(exited_by(&mut p, None));
        assert!(
            wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending(),
            "a running process with nothing fired waits"
        );
    }); // the wait is dropped here
    #[cfg(windows)]
    {
        // The watcher holds its own copy of the observer; ours must go so a missing release ends
        // the `recv` instead of hanging it.
        drop(observer);
        released
            .recv()
            .expect("the blocking watcher must return after the drop released it");
    }
    drop(runtime);
}

/// The futures cross threads on every platform: `spawn` needs it.
#[skuld::test]
fn async_waits_are_send() {
    fn assert_send<T: Send>(_: &T) {}

    let mut p = fake([]);
    assert_send(&exited_by(&mut p, None));
    let process = crate::tokio::Process::current();
    assert_send(&process.wait());
}

#[cfg(windows)]
mod windows {
    //! The blocking half of the Windows arm, `wait_handle_or_cancel`: the cancel-race tests that
    //! covered the old cancellable wait, with the same assertions, now run on the handle an
    //! `OsProcess` hands out.

    use std::time::{Duration, Instant};

    use crate::os_process::{open, Op};
    use crate::wait::backend::{new_cancel_event, signal_cancel, wait_handle_or_cancel};
    use crate::wait::test_clock::FrozenClockGuard;
    use crate::wait::wait_ms_probe;
    use crate::wait::{remaining_override_seam, wait_clamp_seam};

    use crate::test_child::live_blocker as blocker;

    /// Mutant: truncate in `win32_timeout_ms` -> `ms` is 0. Mutant: add slack -> `ms` is above 1.
    /// Mutant: ignore the site's grace -> `requested` is not 5ms.
    #[skuld::test]
    fn the_blocking_half_arms_the_ceiling_of_the_remaining_duration() {
        let (child, stdin, id) = blocker();
        let process = open(id, Op::Wait).unwrap().expect("a live process opens");
        let cancel = new_cancel_event().expect("create cancel event");
        let (_clock, at) = FrozenClockGuard::install();
        wait_ms_probe::take();
        let _override = remaining_override_seam::set(Duration::from_micros(500));
        let deadline = at + Duration::from_millis(5);
        let result = wait_handle_or_cancel(process.os_handle().unwrap(), Some(deadline), &cancel);
        let reached = Instant::now() >= deadline;
        let arms = wait_ms_probe::take();
        drop(stdin);
        child.wait().expect("reap the blocker");
        assert!(
            !result.expect("a live never-exiting child must not report a wait failure"),
            "a never-exiting child is still alive when the grace elapses"
        );
        assert!(reached, "the call returned before the real deadline");
        let first = arms.first().expect("at least one armed wait");
        assert_eq!(first.remaining, Duration::from_micros(500));
        assert_eq!(first.ms, 1);
        assert_eq!(
            first.requested,
            Duration::from_millis(5),
            "the site must pass the time left to its own grace (clock frozen at the grace's origin)"
        );
    }

    /// An early, unclamped `WAIT_TIMEOUT` hours before the grace ends is not trusted: the site
    /// re-arms. Exit (`Ok(true)`) proves it, since a cancel or a timeout would both read `Ok(false)`.
    ///
    /// Mutant: return on the first `WAIT_TIMEOUT` -> one arm, wrongly reports alive.
    #[skuld::test]
    fn the_blocking_half_never_reports_still_alive_before_the_deadline() {
        let (child, stdin, id) = blocker();
        let process = open(id, Op::Wait).unwrap().expect("a live process opens");
        let cancel = new_cancel_event().expect("create cancel event");
        wait_ms_probe::take();
        let _override = remaining_override_seam::set(Duration::from_micros(500));
        wait_ms_probe::on_second_arm(move || drop(stdin));
        let result = wait_handle_or_cancel(
            process.os_handle().unwrap(),
            Some(Instant::now() + Duration::from_secs(3600)),
            &cancel,
        );
        let arms = wait_ms_probe::take();
        let exited = result.expect("a genuinely-terminated child must not report a wait failure");
        child.wait().expect("reap the child after it exits");
        assert!(exited, "an early WAIT_TIMEOUT was trusted");
        assert!(arms.len() >= 2, "expected a re-arm, got {} arm(s)", arms.len());
    }

    /// A wait clamped below the grace re-arms, recomputing `remaining` each round.
    ///
    /// Mutant: drop the re-arm loop -> one arm, wrongly reports alive. Mutant: hoist `remaining`
    /// above the loop -> `remaining` does not shrink.
    #[skuld::test]
    fn the_blocking_half_re_arms_past_a_clamped_timeout() {
        let (child, stdin, id) = blocker();
        let process = open(id, Op::Wait).unwrap().expect("a live process opens");
        let cancel = new_cancel_event().expect("create cancel event");
        wait_ms_probe::take();
        let _clamp = wait_clamp_seam::set(5);
        wait_ms_probe::on_second_arm(move || drop(stdin));
        let result = wait_handle_or_cancel(
            process.os_handle().unwrap(),
            Some(Instant::now() + Duration::from_secs(3600)),
            &cancel,
        );
        let arms = wait_ms_probe::take();
        let exited = result.expect("a genuinely-terminated child must not report a wait failure");
        child.wait().expect("reap the child after it exits");
        assert!(exited, "a clamped WAIT_TIMEOUT was trusted");
        wait_ms_probe::assert_rearmed_with_fresh_remaining(&arms, 5);
    }

    /// A PRE-signaled cancel event must release the wait on a LIVE child: no race, nothing to time.
    /// If the cancel plumbing were broken, the wait would sit at the unbounded `None` (=> INFINITE)
    /// and a nextest override ends it as a failure.
    #[skuld::test]
    fn cancel_event_releases_the_blocking_wait() {
        let (child, _stdin, id) = blocker();
        let process = open(id, Op::Wait).unwrap().expect("a live process opens");
        let cancel = new_cancel_event().expect("event");
        signal_cancel(&cancel);
        let exited = wait_handle_or_cancel(process.os_handle().unwrap(), None, &cancel).expect("cancellable wait");
        assert!(!exited, "a live child with a signaled cancel must report still-alive");
        child.kill().expect("cleanup");
        child.wait().expect("reap");
    }

    /// The concurrent case: signal the cancel while the wait is (or is about to be) in flight. The
    /// manual-reset event is set-once/released-forever, so EVERY interleaving must release the
    /// watcher; this is race-INSENSITIVITY being proven, not an outcome bet on a race. If the
    /// release were broken, the join would hang until a nextest override ends it as a failure.
    #[skuld::test]
    fn cancel_event_signaled_mid_wait_releases_the_blocking_wait() {
        let (child, _stdin, id) = blocker();
        let process = open(id, Op::Wait).unwrap().expect("a live process opens");
        let cancel = std::sync::Arc::new(new_cancel_event().expect("event"));
        let handle = process.os_handle().unwrap();
        let exited = std::thread::scope(|scope| {
            let watcher = scope.spawn(|| wait_handle_or_cancel(handle, None, &cancel));
            signal_cancel(&cancel);
            watcher.join().expect("watcher thread").expect("cancellable wait")
        });
        assert!(!exited, "a live child with a signaled cancel must report still-alive");
        child.kill().expect("cleanup");
        child.wait().expect("reap");
    }

    /// `armed_probe` reaches the blocking half through the driver's hop: the armed poll finds the
    /// fake's event unsignalled, reports it, and force-releases the wait.
    ///
    /// Mutant: the hop does not relay the probe -> nothing is reported.
    #[skuld::test]
    async fn the_armed_probe_reaches_the_blocking_half() {
        use super::{fake, Answer};

        crate::tokio::test_runtime::assert_current_thread();
        let (tx, armed) = std::sync::mpsc::channel();
        let _guard = crate::wait::backend::armed_probe::install(tx);
        let mut p = fake([Answer::Running, Answer::Exited]);
        assert!(super::exited_by(&mut p, None).await.unwrap());
        assert_eq!(
            armed.try_iter().count(),
            1,
            "the wait armed on an unsignalled target once"
        );
    }
}
