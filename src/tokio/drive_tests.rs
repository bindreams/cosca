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

/// Open descriptors of this process (each count includes the directory handle that reads it).
#[cfg(target_os = "linux")]
fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").expect("read /proc/self/fd").count()
}

/// A wait round registers the pidfd the process already holds: it opens no descriptor of its own,
/// so a wait does not fail with `EMFILE` where the held pidfd alone would not.
///
/// Mutant: register a duplicate of the pidfd, which is one more open descriptor for the round.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_wait_round_opens_no_descriptor() {
    use crate::os_process::{open, Op};
    use crate::test_child::held_contained_blocker_without_cgroup;

    let (child, stdin) = held_contained_blocker_without_cgroup(crate::Stdio::null());
    let mut process = open(child.id(), Op::Wait).unwrap().expect("a live process opens");
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build a runtime");
    let before = open_fds();
    let during = runtime.block_on(async {
        let mut wait = pin!(exited_by(&mut *process, None));
        assert!(
            wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending(),
            "a running process waits"
        );
        open_fds()
    });
    assert_eq!(during, before, "the round registered a descriptor of its own");
    drop(stdin);
    child.wait().expect("reap the blocker");
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
    //! The blocking half of the Windows arm, `wait_process_or_cancel`: the cancel-race tests that
    //! covered the old cancellable wait, with the same assertions, now run on the handle an
    //! `OsProcess` hands out.

    use std::time::{Duration, Instant};

    use std::os::windows::io::BorrowedHandle;

    use crate::os_process::{open, Exit, Op, OsProcess, WaitFor};
    use crate::wait::backend::{new_cancel_event, signal_cancel, wait_process_or_cancel};
    use crate::wait::test_clock::FrozenClockGuard;
    use crate::wait::wait_ms_probe;
    use crate::wait::{remaining_override_seam, wait_clamp_seam};

    use crate::test_child::live_blocker as blocker;

    /// The handle a look at a live process hands out to wait on.
    fn wait_handle(p: &mut dyn OsProcess) -> BorrowedHandle<'_> {
        match p.exited().unwrap() {
            Exit::Running(WaitFor::Signalled(handle)) => handle,
            other => panic!("a live process reads Running(Signalled): {other:?}"),
        }
    }

    /// Mutant: truncate in `win32_timeout_ms` -> `ms` is 0. Mutant: add slack -> `ms` is above 1.
    /// Mutant: ignore the site's grace -> `requested` is not 5ms.
    #[skuld::test]
    fn the_blocking_half_arms_the_ceiling_of_the_remaining_duration() {
        let (child, stdin, id) = blocker();
        let mut process = open(id, Op::Wait).unwrap().expect("a live process opens");
        let cancel = new_cancel_event().expect("create cancel event");
        let (_clock, at) = FrozenClockGuard::install();
        wait_ms_probe::take();
        let _override = remaining_override_seam::set(Duration::from_micros(500));
        let deadline = at + Duration::from_millis(5);
        let result = wait_process_or_cancel(wait_handle(&mut *process), Some(deadline), &cancel);
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
        let mut process = open(id, Op::Wait).unwrap().expect("a live process opens");
        let cancel = new_cancel_event().expect("create cancel event");
        wait_ms_probe::take();
        let _override = remaining_override_seam::set(Duration::from_micros(500));
        wait_ms_probe::on_second_arm(move || drop(stdin));
        let result = wait_process_or_cancel(
            wait_handle(&mut *process),
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
        let mut process = open(id, Op::Wait).unwrap().expect("a live process opens");
        let cancel = new_cancel_event().expect("create cancel event");
        wait_ms_probe::take();
        let _clamp = wait_clamp_seam::set(5);
        wait_ms_probe::on_second_arm(move || drop(stdin));
        let result = wait_process_or_cancel(
            wait_handle(&mut *process),
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
        let mut process = open(id, Op::Wait).unwrap().expect("a live process opens");
        let cancel = new_cancel_event().expect("event");
        signal_cancel(&cancel);
        let exited = wait_process_or_cancel(wait_handle(&mut *process), None, &cancel).expect("cancellable wait");
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
        let mut process = open(id, Op::Wait).unwrap().expect("a live process opens");
        let cancel = std::sync::Arc::new(new_cancel_event().expect("event"));
        let handle = wait_handle(&mut *process);
        let exited = std::thread::scope(|scope| {
            let watcher = scope.spawn(|| wait_process_or_cancel(handle, None, &cancel));
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

    /// A release that is neither an exit nor the deadline ends the wait after one final look, which
    /// answers.
    ///
    /// Mutant: the arm discards the blocking half's verdict, so the loop re-arms and looks again
    /// past the script.
    #[skuld::test]
    async fn a_forced_release_ends_the_wait_after_one_final_look() {
        use super::{fake, Answer};

        crate::tokio::test_runtime::assert_current_thread();
        let (tx, armed) = std::sync::mpsc::channel();
        let _guard = crate::wait::backend::armed_probe::install(tx);
        let mut p = fake([Answer::Running, Answer::Running]);
        assert!(!super::exited_by(&mut p, None).await.unwrap());
        assert_eq!(p.looks(), 2, "one look, one wait, one final look");
        assert_eq!(armed.try_iter().count(), 1, "the wait armed once");
    }
}

/// Mutant: `exited_by_id` takes the seam only after `open`, so a gone id never reaches it.
#[skuld::test]
async fn exited_by_id_returns_a_forced_watch_error_for_a_gone_id() {
    crate::tokio::test_runtime::assert_current_thread();
    let current = ProcessId::current();
    let gone = ProcessId::from_parts_for_test(current.pid(), current.start_token_raw() ^ 1);
    fault::set_force_watch_error(true);
    assert!(super::exited_by_id(gone, None).await.is_err());
    assert!(!fault::armed(), "the seam is consumed");
}
