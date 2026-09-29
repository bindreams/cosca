//! Unit tests for the reactor-native grace-wait. In the library because `grace_wait` is
//! `pub(crate)`. Death-proof discipline: a generous grace on an already-dead child is a
//! failure bound (the exit event precedes the call); `Duration::ZERO` on a live child makes
//! the timeout branch deterministic.

use std::time::Duration;

// This module is declared INSIDE src/tokio/wait.rs, so `super` is `tokio::wait` itself.
#[cfg(unix)]
use super::armed_deadline_seam::Armed;
use super::{grace_wait, wait_exit};
use crate::identity::ProcessId;

// A long-lived std child (leak-proof: killed + reaped by each test) that only a kill or a closed
// stdin ends; see `test_child::BLOCKER_ARGV`. Each test calls `wait()` (which closes the piped
// stdin) only as its last step, after an explicit `kill()`.
fn std_blocker() -> std::process::Child {
    // Held for the fork itself — see `fdmarker_tests.rs`'s module docs.
    let _guard = crate::child::spawn::spawn_lock();
    crate::test_child::held_std_blocker(std::process::Stdio::null())
        .spawn()
        .expect("spawn std blocker")
}

/// Like `std_blocker`, with stdout piped for the echo round trip in [`assert_child_still_alive`].
/// Local to the tests that call `assert_child_still_alive`.
fn std_blocker_with_stdout() -> std::process::Child {
    let _guard = crate::child::spawn::spawn_lock();
    crate::test_child::held_std_blocker(std::process::Stdio::piped())
        .spawn()
        .expect("spawn std blocker")
}

/// Proves `child` (a [`std_blocker_with_stdout`]) is genuinely still alive: `is_alive()` alone
/// races the asynchronous `SIGKILL`/`TerminateProcess`. On Unix, round-trips a byte through the
/// piped stdout. On Windows, `findstr` does not echo: closes stdin and requires a clean exit and
/// the echoed match, as `child::graceful_tests::assert_still_running` does, which reaps `child`.
fn assert_child_still_alive(child: &mut std::process::Child) {
    #[cfg(unix)]
    crate::test_child::assert_echoes(
        child.stdin.as_mut().expect("piped stdin"),
        child.stdout.as_mut().expect("piped stdout"),
    );
    #[cfg(windows)]
    {
        use std::io::{Read as _, Write as _};
        child
            .stdin
            .as_mut()
            .expect("piped stdin")
            .write_all(b"x\r\n")
            .expect("write to the blocker");
        child.stdin = None; // close stdin: EOF, findstr can now finish and exit
        let mut output = Vec::new();
        child
            .stdout
            .as_mut()
            .expect("piped stdout")
            .read_to_end(&mut output)
            .expect("read stdout to EOF");
        let status = child.wait().expect("the blocker must exit after stdin closes");
        assert!(
            status.success(),
            "the blocker must exit 0 (findstr's own 'a match was found' code), got {status:?}"
        );
        assert!(
            output.windows(1).any(|w| w == b"x"),
            "the blocker's stdout must contain the echoed match, got {output:?}"
        );
    }
}

/// Kills and reaps `child`. Windows discards errors: `assert_child_still_alive` already reaped it
/// there, so a second kill or wait has nothing to act on.
fn kill_and_reap(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        child.kill().expect("kill");
        child.wait().expect("reap");
    }
    #[cfg(windows)]
    {
        _ = child.kill();
        _ = child.wait();
    }
}

/// Polls `fut` once: all code up to the first suspension (including the seam) runs inside that poll.
#[cfg(unix)]
fn poll_once<F: std::future::Future>(fut: std::pin::Pin<&mut F>) -> std::task::Poll<F::Output> {
    fut.poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
}

#[tokio::test]
async fn grace_wait_true_for_exited_unreaped_child() {
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    child.kill().expect("kill");
    // NOT reaped yet (no wait): on Unix the child is a zombie — the watch must still see the
    // exit.
    let exited = grace_wait(id, Duration::from_secs(30)).await.expect("grace_wait");
    assert!(exited, "an exited (unreaped) child must report exited");
    child.wait().expect("reap");
}

#[tokio::test]
async fn grace_wait_false_for_live_child_at_zero_grace() {
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    let exited = grace_wait(id, Duration::ZERO).await.expect("grace_wait");
    assert!(!exited, "a live child at ZERO grace must report still-alive");
    child.kill().expect("cleanup");
    child.wait().expect("reap");
}

#[tokio::test]
async fn grace_wait_true_for_stale_identity() {
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    child.kill().expect("kill");
    child.wait().expect("reap"); // fully gone; the pid may even be recycled
    let exited = grace_wait(id, Duration::from_secs(30)).await.expect("grace_wait");
    assert!(exited, "a stale identity (reaped child) must report exited, never hang");
}

#[tokio::test]
async fn grace_wait_true_when_child_dies_mid_wait() {
    // The live-then-exits path: the watch arms on a LIVE child and must resolve on the real
    // exit event (our own kill). Whether the kill lands before or after arming, the result
    // must be `true`.
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    let watch = ::tokio::spawn(grace_wait(id, Duration::from_secs(30)));
    child.kill().expect("kill mid-wait");
    let exited = watch.await.expect("join").expect("grace_wait");
    assert!(exited, "the watch must resolve on the child's exit");
    child.wait().expect("reap");
}

// The Windows release mechanism itself, deterministically: a PRE-signaled cancel event must
// release the wait on a LIVE child — no race, nothing to time. If the cancel plumbing were
// broken, the wait would sit at the unbounded `None` (=> INFINITE) watch and the test
// harness's own bound would surface the hang loudly.
#[cfg(windows)]
#[test]
fn cancel_event_releases_the_blocking_wait() {
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    let cancel = crate::wait::backend::new_cancel_event().expect("event");
    crate::wait::backend::signal_cancel(&cancel);
    let exited = crate::wait::backend::block_until_exit_or_cancel(id, None, &cancel).expect("cancellable wait");
    assert!(!exited, "a live child with a signaled cancel must report still-alive");
    child.kill().expect("cleanup");
    child.wait().expect("reap");
}

// The concurrent case: signal the cancel while the wait is (or is about to be) in flight.
// The manual-reset event is set-once/released-forever, so EVERY interleaving must release
// the watcher — this is race-INSENSITIVITY being proven, not an outcome bet on a race. If
// the release were broken, the join would hang at the harness's own failure bound.
#[cfg(windows)]
#[test]
fn cancel_event_signaled_mid_wait_releases_the_blocking_wait() {
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    let cancel = std::sync::Arc::new(crate::wait::backend::new_cancel_event().expect("event"));
    let watcher = std::thread::spawn({
        let cancel = cancel.clone();
        move || crate::wait::backend::block_until_exit_or_cancel(id, None, &cancel)
    });
    crate::wait::backend::signal_cancel(&cancel);
    let exited = watcher.join().expect("watcher thread").expect("cancellable wait");
    assert!(!exited, "a live child with a signaled cancel must report still-alive");
    child.kill().expect("cleanup");
    child.wait().expect("reap");
}

/// What one `grace_wait` on a Windows child logged on its blocking thread.
#[cfg(windows)]
struct Observed {
    /// The real clock as `grace_wait` saw it: frozen a second behind the actual now.
    real_start: std::time::Instant,
    exited: bool,
    log: Vec<crate::wait::read_probe::Event>,
}

/// Runs `grace_wait(id, grace)` with tokio's clock pinned at `pin` and the real clock frozen behind the
/// blocking thread's, so a deadline `grace_wait` fixes on this thread differs from any a
/// blocking thread would derive itself. Logs every `remaining` read and the identity step.
/// With `release`, closes the child's stdin after the first read, so the wait ends by exit.
#[cfg(windows)]
async fn observed_grace_wait(
    child: &mut std::process::Child,
    pin: std::time::Instant,
    grace: Duration,
    release: bool,
) -> Observed {
    use crate::wait::read_probe::{install, Event};
    use crate::wait::test_clock::FrozenClockGuard;

    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    let (tx, rx) = std::sync::mpsc::channel();
    let _log = install(tx);
    let _tokio_now = super::now_override::install(pin);
    let (_clock, real_start) = FrozenClockGuard::install_lagging(Duration::from_secs(1));
    let mut log = Vec::new();
    let exited = if release {
        // A live child's watch always logs a read before it can end, so the `recv` returns.
        let (exited, ()) = ::tokio::join!(grace_wait(id, grace), async {
            loop {
                let event = rx.recv().expect("the blocking watch logs a read");
                log.push(event);
                if matches!(event, Event::Read { .. }) {
                    break;
                }
            }
            drop(child.stdin.take());
        });
        exited
    } else {
        grace_wait(id, grace).await
    };
    // The join has returned, so every send happened before this.
    log.extend(rx.try_iter());
    Observed {
        real_start,
        exited: exited.expect("grace_wait"),
        log,
    }
}

/// Asserts the blocking thread verified identity before its first `remaining` read, and that
/// every read was made against `deadline`. Returns the reads' results.
#[cfg(windows)]
#[track_caller]
fn assert_reads_of(
    log: &[crate::wait::read_probe::Event],
    deadline: Option<Option<std::time::Instant>>,
) -> Vec<Option<Duration>> {
    use crate::wait::read_probe::Event;

    let mark = log
        .iter()
        .position(|e| *e == Event::Mark("identity verified"))
        .expect("the blocking thread verified identity");
    let mut results = Vec::new();
    for (i, event) in log.iter().enumerate() {
        if let Event::Read {
            deadline: used,
            remaining,
        } = event
        {
            assert!(i > mark, "a remaining read preceded identity verification: {log:?}");
            assert_eq!(
                *used, deadline,
                "a read was made against a re-derived deadline: {log:?}"
            );
            results.push(*remaining);
        }
    }
    assert!(!results.is_empty(), "the blocking thread never read remaining: {log:?}");
    results
}

// `grace_wait` must arm the blocking wait from the deadline it fixed before `spawn_blocking`.
// Tokio's clock is pinned and the real clock frozen a second behind the blocking thread's, so a
// blocking thread deriving its own deadline reads a later instant and fails the equality.
// The deadline is already past: the wait is one non-blocking probe.
#[cfg(windows)]
#[tokio::test]
async fn grace_wait_windows_arms_from_a_past_deadline_fixed_before_spawn_blocking() {
    let mut child = std_blocker();
    let seen = observed_grace_wait(&mut child, std::time::Instant::now(), Duration::ZERO, false).await;
    kill_and_reap(&mut child);
    assert!(!seen.exited, "a live child at ZERO grace must report still-alive");
    let reads = assert_reads_of(&seen.log, Some(Some(seen.real_start)));
    assert!(reads.iter().all(|r| *r == Some(Duration::ZERO)), "{reads:?}");
}

// A genuinely future deadline crossing `spawn_blocking`: the blocking thread's remaining time is
// what is left of the caller's deadline, not a fresh grace.
#[cfg(windows)]
#[tokio::test]
async fn grace_wait_windows_arms_from_a_future_deadline_fixed_before_spawn_blocking() {
    let grace = Duration::from_secs(3600);
    let mut child = std_blocker();
    let seen = observed_grace_wait(&mut child, std::time::Instant::now(), grace, true).await;
    child.wait().expect("reap");
    assert!(seen.exited, "the child exited after its stdin closed");
    let reads = assert_reads_of(&seen.log, Some(Some(seen.real_start + grace)));
    for r in reads {
        let r = r.expect("a bounded deadline has a remaining time");
        assert!(r > Duration::ZERO && r <= grace, "{r:?}");
    }
}

// A grace that overflows `Instant` is unbounded: not expired, not a panic, not a fixed fallback.
#[cfg(windows)]
#[tokio::test]
async fn grace_wait_windows_treats_an_overflowing_grace_as_unbounded() {
    let mut child = std_blocker();
    let seen = observed_grace_wait(&mut child, std::time::Instant::now(), Duration::MAX, true).await;
    child.wait().expect("reap");
    assert!(seen.exited, "an unbounded watch ends only by the exit");
    assert!(assert_reads_of(&seen.log, None).iter().all(Option::is_none));
}

// As above for a grace landing inside tokio's timer margin of `Instant`'s ceiling, which
// `deadline_at` also makes unbounded.
#[cfg(windows)]
#[tokio::test]
async fn grace_wait_windows_treats_a_grace_inside_the_timer_margin_of_the_ceiling_as_unbounded() {
    let mut child = std_blocker();
    let pin = std::time::Instant::now();
    // 500us short of the ceiling: inside the 1ms margin, but not overflowing outright.
    let grace = crate::wait::instant_near_ceiling(pin).saturating_duration_since(pin) - Duration::from_micros(500);
    let seen = observed_grace_wait(&mut child, pin, grace, true).await;
    child.wait().expect("reap");
    assert!(seen.exited, "an unbounded watch ends only by the exit");
    assert!(assert_reads_of(&seen.log, None).iter().all(Option::is_none));
}

// Drive the REAL macOS watch loop through its clear_ready + re-await cycle with genuine
// kernel events: a DECOY second NOTE_EXIT filter on the same kqueue supplies the first wake;
// the scripted drain consumes it (keeping the kqueue level low, so clear_ready cannot miss a
// wake) but reports "no exit" — the loop must re-await, and the target's real exit must still
// resolve it. Every wake is a real kernel event.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn watch_loop_survives_a_non_exit_drain_cycle() {
    let mut decoy = std_blocker();
    let target = std_blocker();
    let target_id = ProcessId::of(target.id()).found().expect("identity of live target");
    let kq = crate::wait::backend::arm_proc_exit(target_id)
        .expect("arm target")
        .expect("a live target arms");
    // Arm the decoy on the SAME kqueue, through the production receipt dance.
    assert!(
        crate::wait::backend::arm_note_exit_on(&kq, decoy.id())
            .expect("arm decoy")
            .is_some(),
        "a live decoy arms"
    );
    decoy.kill().expect("kill decoy"); // the first, non-target wake

    let afd = ::tokio::io::unix::AsyncFd::with_interest(super::KqueueFd(kq), ::tokio::io::Interest::READABLE)
        .expect("register");
    let target_cell = std::cell::RefCell::new(None);
    let mut pending = Some(target);
    let watch = super::watch_readable(&afd, |kq| {
        let drained = crate::wait::backend::drain_proc_exit(kq)?;
        if let Some(mut t) = pending.take() {
            // First cycle (the decoy's event, consumed above): report "no exit" so the loop
            // clear_readys and re-awaits; only NOW create the target's exit event.
            t.kill().expect("kill target mid-cycle");
            *target_cell.borrow_mut() = Some(t);
            return Ok(None);
        }
        Ok(drained)
    });
    watch.await.expect("watch");
    let mut target = target_cell
        .borrow_mut()
        .take()
        .expect("target stored by the first cycle");
    target.wait().expect("reap target");
    decoy.wait().expect("reap decoy");
}

// The POLLERR branch and the readiness contract, via synthetic Ready values — these pin the
// BRANCH LOGIC only. The real OS→Ready mapping (pidfd → epoll → mio → AsyncFd) is validated
// by the live-path tests above: grace_wait_true_for_exited_unreaped_child and
// grace_wait_true_when_child_dies_mid_wait run the whole stack on a real pidfd.
#[cfg(target_os = "linux")]
mod classify {
    use ::tokio::io::Ready;

    use super::super::classify_pidfd_ready;

    #[test]
    fn readable_and_read_closed_mean_exited() {
        assert!(matches!(classify_pidfd_ready(Ready::READABLE), Some(Ok(()))));
        assert!(matches!(classify_pidfd_ready(Ready::READ_CLOSED), Some(Ok(()))));
    }

    #[test]
    fn error_readiness_is_surfaced_not_swallowed() {
        assert!(matches!(
            classify_pidfd_ready(Ready::ERROR | Ready::READABLE),
            Some(Err(_))
        ));
        assert!(matches!(classify_pidfd_ready(Ready::ERROR), Some(Err(_))));
    }

    #[test]
    fn unclassified_readiness_retries_never_a_false_verdict() {
        // tokio's documented false-positive wake: not an exit (would skip escalation on a
        // live child), not an error (would force-kill a graceful exit) — re-await.
        assert!(classify_pidfd_ready(Ready::EMPTY).is_none());
    }
}

#[tokio::test]
async fn wait_exit_resolves_for_exited_unreaped_child() {
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    child.kill().expect("kill");
    // NOT reaped: the exit event precedes the call, so the unbounded watch must resolve.
    wait_exit(id).await.expect("wait_exit");
    child.wait().expect("reap");
}

#[tokio::test]
async fn wait_exit_resolves_when_child_dies_mid_wait() {
    // Arm on a LIVE child; our own kill is the real exit event. Race-tolerant either side.
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    let watch = ::tokio::spawn(wait_exit(id));
    child.kill().expect("kill mid-wait");
    watch.await.expect("join").expect("wait_exit");
    child.wait().expect("reap");
}

#[tokio::test]
async fn grace_wait_zero_reports_an_observed_exit() {
    // The ZERO one-shot probe must see an already-exited (zombie) child — the sync/async
    // parity case a plain timeout(ZERO, ..) gets wrong (the AsyncFd readiness of a zombie
    // needs a reactor round-trip the zero timer would win against).
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    child.kill().expect("kill");
    // Observe the exit as a real event WITHOUT reaping: wait for it via the unbounded watch
    // (30 s-class bound is the harness), then probe at ZERO.
    wait_exit(id).await.expect("exit observed");
    assert!(
        grace_wait(id, Duration::ZERO).await.expect("zero probe"),
        "an observed-exited child must report exited at ZERO grace"
    );
    child.wait().expect("reap");
}

#[tokio::test]
async fn wait_exit_cancel_leaves_child_untouched() {
    use std::future::Future;
    // Poll the unbounded watch exactly once (arms it), then drop — the watch is signal-free,
    // so the child must still be alive; it dies only by the test's own kill.
    let mut child = std_blocker_with_stdout();
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    {
        let mut fut = std::pin::pin!(wait_exit(id));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        if let std::task::Poll::Ready(r) = fut.as_mut().poll(&mut cx) {
            panic!("unbounded watch resolved at first poll on a live child: {r:?}");
        }
    } // <- future dropped here; on Windows the drop-guard releases the blocking watcher
    assert_child_still_alive(&mut child); // a cancelled watch must not affect the child
    kill_and_reap(&mut child);
}

// Proves release without a timeout: the watcher signals a channel when it returns; recv()
// blocks until that happens.
#[cfg(windows)]
#[tokio::test]
async fn wait_exit_drop_releases_the_windows_watcher() {
    use std::future::Future;
    let (tx, rx) = std::sync::mpsc::channel();
    let guard = super::fault_observer::install(tx);
    let mut child = std_blocker_with_stdout();
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    {
        let mut fut = std::pin::pin!(wait_exit(id));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        if let std::task::Poll::Ready(r) = fut.as_mut().poll(&mut cx) {
            panic!("unbounded watch resolved at first poll on a live child: {r:?}");
        }
        // Release our sender so `recv()` returns Ok only from the blocking closure's notification.
        drop(guard);
    } // <- drop signals the cancel event
    rx.recv()
        .expect("the blocking watcher must return after the drop released it");
    assert_child_still_alive(&mut child); // release must be signal-free
    kill_and_reap(&mut child);
}

// Mutant: make `fault_observer::Guard::drop` a no-op -> the slot stays installed after the scope.
#[cfg(windows)]
#[test]
fn fault_observer_guard_uninstalls_on_drop() {
    let (tx, rx) = std::sync::mpsc::channel();
    {
        let _guard = super::fault_observer::install(tx);
    }
    super::fault_observer::notify_released();
    assert_eq!(rx.try_iter().count(), 0);
    assert!(super::fault_observer::current().is_none());
}

// Mutant: delete the `debug_assert!` in `fault_observer::install` -> no panic.
#[cfg(all(windows, debug_assertions))]
#[test]
#[should_panic(expected = "nested on the same thread")]
fn fault_observer_install_panics_when_nested() {
    let (tx, _rx) = std::sync::mpsc::channel();
    let _outer = super::fault_observer::install(tx.clone());
    let _inner = super::fault_observer::install(tx);
}

// The relay's pool-thread guard must not outlive the closure: on a pool pinned to ONE thread, a
// watch without an observer that runs after one with an observer must not reach the first's
// channel, and the pool thread's slot must be empty afterwards.
//
// Mutant: `mem::forget` the `_released_guard` in `blocking_watch`'s closure -> the second
// watch's release reaches the first's channel.
#[cfg(windows)]
#[test]
fn the_relayed_observer_does_not_outlive_its_blocking_call() {
    let rt = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        // The same pool thread must serve every call below; asserted via its id.
        .thread_keep_alive(Duration::from_secs(3600))
        .build()
        .expect("build a runtime with a one-thread blocking pool");
    rt.block_on(async {
        let pool_thread = ::tokio::task::spawn_blocking(|| std::thread::current().id())
            .await
            .expect("probe the pool thread");
        let (tx, rx) = std::sync::mpsc::channel();

        let mut first = std_blocker();
        let first_id = ProcessId::of(first.id()).found().expect("identity of live child");
        first.kill().expect("kill");
        let guard = super::fault_observer::install(tx);
        wait_exit(first_id).await.expect("first watch");
        drop(guard);
        first.wait().expect("reap");
        assert_eq!(rx.try_iter().count(), 1, "the first watch releases exactly once");

        let mut second = std_blocker();
        let second_id = ProcessId::of(second.id()).found().expect("identity of live child");
        second.kill().expect("kill");
        wait_exit(second_id).await.expect("second watch");
        second.wait().expect("reap");
        assert_eq!(
            rx.try_iter().count(),
            0,
            "a watch with no observer must not notify the previous watch's"
        );

        let (thread, empty) =
            ::tokio::task::spawn_blocking(|| (std::thread::current().id(), super::fault_observer::current().is_none()))
                .await
                .expect("probe the pool thread");
        assert_eq!(thread, pool_thread, "the pool must have reused its one thread");
        assert!(empty, "the pool thread's slot must be empty after the call");
    });
}

// `HandleIdentity::Different` is one of three outcomes `block_until_exit_or_cancel` can land on
// when watching an already-reaped root — see
// `windows_async_treewalk_grants_no_grace_window_once_the_backend_has_reaped`'s own doc for why
// that test alone cannot pin this ONE down: `Opened::Gone` returns before any handle exists, and
// a live-but-already-signalled `Same` never reaches `armed_probe`'s poll either, so `Different`
// is possible there only if the OS happens to recycle the pid in the window between the test
// killing its root and this watch opening it. This test pins `Different` down directly and
// deterministically instead: a genuinely LIVE child, watched under an identity naming the SAME
// pid but a WRONG start token, is `Opened::Found` + `HandleIdentity::Different` on every run —
// no dependence on OS pid-recycling timing.
#[cfg(windows)]
#[tokio::test]
async fn grace_wait_resolves_immediately_on_an_identity_mismatch() {
    let mut child = std_blocker_with_stdout();
    let real = ProcessId::of(child.id()).found().expect("identity of live child");
    let stale = ProcessId::from_parts_for_test(real.pid(), real.start_token_raw() ^ 1);

    let (armed_tx, armed_rx) = std::sync::mpsc::channel();
    let _armed_guard = crate::wait::backend::armed_probe::install(armed_tx);

    let exited = grace_wait(stale, Duration::from_secs(30))
        .await
        .expect("an identity mismatch must resolve, not error");
    assert!(
        exited,
        "HandleIdentity::Different must report exited — the original identity is gone"
    );
    assert!(
        armed_rx.try_recv().is_err(),
        "the identity-mismatch fast path must never reach the real wait — armed_probe must not fire"
    );

    // The watch resolved on the STALE identity, so it must not have touched this live child.
    assert_child_still_alive(&mut child);
    // A `std` `Child` neither kills nor reaps on drop.
    kill_and_reap(&mut child);
}

// `fault_observer` is thread-local: a watch on another thread must not notify this thread's
// observer. Deterministic: the other watch is joined on its own OS thread and runtime before the
// channel is checked.
//
// Mutant: make the slot process-global -> this thread's channel receives the other's release.
// Mutant: skip `notify_released` in `blocking_watch` -> the other thread's channel is empty.
#[cfg(windows)]
#[tokio::test]
async fn a_watch_on_another_thread_does_not_notify_this_threads_observer() {
    let (own_tx, own_rx) = std::sync::mpsc::channel();
    let _guard = super::fault_observer::install(own_tx);

    let mut other = std_blocker();
    let other_id = ProcessId::of(other.id()).found().expect("identity of live child");
    other.kill().expect("kill");
    // A separate OS thread with its own runtime; a task on this runtime would poll on this thread.
    let handle = std::thread::spawn(move || {
        let (other_tx, other_rx) = std::sync::mpsc::channel();
        let _guard = super::fault_observer::install(other_tx);
        let rt = ::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build a current-thread runtime for the other thread");
        rt.block_on(wait_exit(other_id)).expect("other thread's watch");
        other_rx
    });
    let other_rx = handle.join().expect("other thread panicked");
    other.wait().expect("reap");

    assert_eq!(
        other_rx.try_iter().count(),
        1,
        "the other thread's own observer receives exactly its own release"
    );
    assert!(
        own_rx.try_recv().is_err(),
        "an unrelated watch's release on another thread must never notify this thread's observer"
    );
}

/// The async cgroup drain wait wakes when the leaf is removed, even with no event on
/// `cgroup.events` — the removal can cancel the one notification a drain sends.
#[cfg(target_os = "linux")]
#[::tokio::test]
async fn cgroup_wait_tree_drained_wakes_when_the_leaf_is_removed_without_a_populated_event() {
    use crate::containment::cgroup::test_support::FakeLeaf;
    use crate::containment::TreeDrain;

    let fake = FakeLeaf::new("cosca-async-removed-while-waited", true);
    let removed = fake.leaf.clone();
    let (blocking_tx, blocking_rx) = std::sync::mpsc::channel::<()>();
    // Loops on `recv` rather than returning after the first, so its receiver stays alive for as
    // long as the notifier is installed: `drain_step` can legally re-block (a spurious wake, or
    // the removal notification racing a stale re-read) before this wait ever completes, and a
    // send with no live receiver by then is a contract violation `notify_drain_blocking`
    // debug-asserts against.
    let remover = std::thread::spawn(move || {
        let mut removed_once = false;
        while blocking_rx.recv().is_ok() {
            if !removed_once {
                FakeLeaf::remove(&removed);
                removed_once = true;
            }
        }
    });
    crate::containment::cgroup::fault::set_drain_blocking_notifier(blocking_tx);
    let leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(fake.leaf.clone());
    let drained = super::cgroup_wait_tree_drained(&leaf, None).await;
    crate::containment::cgroup::fault::take_drain_blocking_notifier();
    remover.join().expect("remover");

    assert_eq!(drained.expect("wait"), TreeDrain::AllMembersExited);
}

/// A deadline within tokio's own ~1ms round-up margin of `Instant`'s ceiling must not panic:
/// `crate::wait::deadline_from` saturates it to unbounded before `drain_step` ever sees it, so
/// this call takes the `listener.await` arm, never the bounded one.
#[cfg(target_os = "linux")]
#[::tokio::test]
async fn cgroup_wait_tree_drained_does_not_panic_on_a_near_maximum_deadline() {
    use crate::containment::cgroup::test_support::FakeLeaf;

    let fake = FakeLeaf::new("cosca-async-near-max-deadline", true);
    let leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(fake.leaf.clone());

    let now = std::time::Instant::now();
    // 500µs short of the true ceiling: comfortably more than the time this takes to reach
    // `deadline_from`'s own `Instant::now()` call, landing within the 1ms margin this exercises.
    let duration =
        crate::wait::instant_near_ceiling(now).saturating_duration_since(now) - std::time::Duration::from_micros(500);
    let deadline = super::deadline_from(duration);

    let fut = super::cgroup_wait_tree_drained(&leaf, deadline);
    ::tokio::pin!(fut);
    // A single poll is enough: reaching here without panicking is the proof. The fake leaf never
    // drains, so a correct call is Pending either way — nothing here needs it to resolve.
    ::tokio::select! {
        biased;
        _ = &mut fut => {}
        _ = std::future::ready(()) => {}
    }
}

/// `cgroup_wait_tree_drained`'s bounded arm, driven end to end on a `FakeLeaf` (no cgroup
/// needed): a populated leaf that never drains must answer `MembersRemain` no earlier than the
/// caller's own deadline. No upper bound is asserted — only that it never answers early.
#[cfg(target_os = "linux")]
#[::tokio::test]
async fn cgroup_wait_tree_drained_through_arm_at_never_answers_early() {
    use crate::containment::cgroup::test_support::FakeLeaf;
    use crate::containment::TreeDrain;
    use std::time::{Duration, Instant};

    let fake = FakeLeaf::new("cosca-async-wait-tree-fakeleaf-bounded", true);
    let leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(fake.leaf.clone());

    const BOUND: Duration = Duration::from_millis(50);
    let start = Instant::now();
    let result = super::cgroup_wait_tree_drained(&leaf, Some(Some(start + BOUND)))
        .await
        .expect("wait");
    let elapsed = start.elapsed();

    assert_eq!(
        result,
        TreeDrain::MembersRemain,
        "a populated leaf that never drains must report MembersRemain once its deadline passes"
    );
    assert!(
        elapsed >= BOUND,
        "cgroup_wait_tree_drained returned after {elapsed:?}, before its own {BOUND:?} deadline"
    );
}

/// The Linux wait site is armed, through `arm_at`, with the caller's deadline instant exactly.
/// Populated `FakeLeaf` (no real cgroup), so `drain_step` reaches its `Block` arm.
#[cfg(target_os = "linux")]
#[::tokio::test]
async fn cgroup_wait_tree_drained_arms_the_callers_deadline_instant() {
    use crate::containment::cgroup::test_support::FakeLeaf;

    let (tx, rx) = std::sync::mpsc::channel();
    let _seam = super::armed_deadline_seam::install(tx);
    let fake = FakeLeaf::new("cosca-async-arm-at-deadline", true);
    let leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(fake.leaf.clone());
    let at = super::tokio_now() + Duration::from_secs(3600);

    {
        let mut fut = std::pin::pin!(super::cgroup_wait_tree_drained(&leaf, Some(Some(at))));
        assert!(poll_once(fut.as_mut()).is_pending(), "the fake leaf never drains");
    }
    assert_eq!(rx.try_recv().expect("the wait site must arm via arm_at"), Armed::At(at));
    assert!(rx.try_recv().is_err(), "armed exactly once");
}

/// The async wait site's unbounded arm reports an unbounded park, and arms no timer.
#[cfg(target_os = "linux")]
#[::tokio::test]
async fn cgroup_wait_tree_drained_parks_unbounded_with_no_timer() {
    use crate::containment::cgroup::test_support::FakeLeaf;

    let (tx, rx) = std::sync::mpsc::channel();
    let _seam = super::armed_deadline_seam::install(tx);
    let fake = FakeLeaf::new("cosca-async-wait-site-unbounded", true);
    let leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(fake.leaf.clone());

    {
        let mut fut = std::pin::pin!(super::cgroup_wait_tree_drained(&leaf, None));
        assert!(poll_once(fut.as_mut()).is_pending(), "the fake leaf never drains");
    }
    assert_eq!(rx.try_recv().expect("an unbounded park is reported"), Armed::Unbounded);
    assert!(rx.try_recv().is_err(), "reported exactly once");
}

// Bounded waits arm the caller's deadline via `arm_at`, never earlier or later -----

/// grace_wait (site 1) arms `deadline_from`'s instant: `t0 + grace` on the paused clock.
#[cfg(unix)]
#[::tokio::test(start_paused = true)]
async fn grace_wait_arms_deadline_froms_instant() {
    let (tx, rx) = std::sync::mpsc::channel();
    let _seam = super::armed_deadline_seam::install(tx);
    let t0 = super::tokio_now();
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    let grace = Duration::from_secs(3600);

    {
        let mut fut = std::pin::pin!(grace_wait(id, grace));
        assert!(
            poll_once(fut.as_mut()).is_pending(),
            "a live child with an hour of grace"
        );
    }
    assert_eq!(
        rx.try_recv().expect("grace_wait must arm via arm_at"),
        Armed::At(t0 + grace)
    );
    assert!(rx.try_recv().is_err(), "armed exactly once");

    child.kill().expect("cleanup");
    child.wait().expect("reap");
}

/// Polls `grace_wait(id, grace)` once on a live child and returns what the seam saw.
#[cfg(unix)]
async fn armed_by_one_poll_of_grace_wait(grace: Duration) -> Vec<Armed> {
    let (tx, rx) = std::sync::mpsc::channel();
    let _seam = super::armed_deadline_seam::install(tx);
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    {
        let mut fut = std::pin::pin!(grace_wait(id, grace));
        assert!(
            poll_once(fut.as_mut()).is_pending(),
            "a live child must not resolve grace_wait on its first poll (grace {grace:?})"
        );
    }
    child.kill().expect("cleanup");
    child.wait().expect("reap");
    rx.try_iter().collect()
}

/// An overflowing grace is UNBOUNDED, not a far-future deadline: no timer is armed at all (a
/// fallback deadline, at any distance, would report to the seam), and no early `Ok(false)`.
#[cfg(unix)]
#[::tokio::test(start_paused = true)]
async fn grace_wait_arms_no_timer_for_an_overflowing_grace() {
    assert_eq!(armed_by_one_poll_of_grace_wait(Duration::MAX).await, vec![]);
}

/// The 1 ms margin's edge at site 1, on the paused clock: a grace landing exactly `MARGIN` short
/// of `Instant`'s ceiling is armed as is, and one nanosecond further is unbounded.
#[cfg(unix)]
#[::tokio::test(start_paused = true)]
async fn grace_wait_at_the_timer_margin_edge_is_armed_and_one_nanosecond_past_it_is_unbounded() {
    let t0 = super::tokio_now();
    let span = crate::wait::instant_near_ceiling(t0).saturating_duration_since(t0);
    let edge = span - crate::wait::TOKIO_TIMER_ROUNDING_MARGIN;

    assert_eq!(armed_by_one_poll_of_grace_wait(edge).await, vec![Armed::At(t0 + edge)]);
    assert_eq!(
        armed_by_one_poll_of_grace_wait(edge + Duration::from_nanos(1)).await,
        vec![]
    );
}

/// tokio's own boundary, on real tokio: the extreme instant `arm_at` accepts, `ceiling - MARGIN`,
/// arms without a panic, so a larger tokio round-up breaks this test rather than the margin.
#[cfg(unix)]
#[::tokio::test]
async fn tokio_arms_the_extreme_instant_arm_at_accepts_without_panicking() {
    let ceiling = crate::wait::instant_near_ceiling(super::tokio_now());
    let at = ceiling - crate::wait::TOKIO_TIMER_ROUNDING_MARGIN;
    let mut fut = std::pin::pin!(super::arm_at(at, std::future::pending::<()>()));
    assert!(poll_once(fut.as_mut()).is_pending());
}

/// "Never early" on tokio's virtual clock (`start_paused`): with the child alive throughout, the
/// only way `grace_wait` resolves is its timer, and virtual time is auto-advanced to exactly the
/// armed deadline. It must answer `Ok(false)` only once the clock has reached `t0 + grace`.
#[cfg(unix)]
#[::tokio::test(start_paused = true)]
async fn grace_wait_never_answers_before_its_deadline_on_a_paused_clock() {
    let (tx, rx) = std::sync::mpsc::channel();
    let _seam = super::armed_deadline_seam::install(tx);
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    let grace = Duration::from_secs(600);
    let t0 = ::tokio::time::Instant::now();

    let mut fut = std::pin::pin!(grace_wait(id, grace));
    // The first poll arms the deadline at t0 + grace; the advance then stops one second short.
    assert!(poll_once(fut.as_mut()).is_pending());
    ::tokio::time::advance(grace - Duration::from_secs(1)).await;
    if let std::task::Poll::Ready(r) = poll_once(fut.as_mut()) {
        panic!("grace_wait answered {r:?} before its deadline");
    }
    let exited = fut.await.expect("grace_wait");
    assert!(!exited, "a live child is still alive when the deadline passes");
    assert_eq!(
        rx.try_recv().expect("armed"),
        Armed::At((t0 + grace).into_std()),
        "armed at t0 + grace"
    );
    let now = ::tokio::time::Instant::now();
    assert!(
        now >= t0 + grace,
        "grace_wait answered before t0 + grace on the virtual clock"
    );
    assert!(
        now <= t0 + grace + crate::wait::TOKIO_TIMER_ROUNDING_MARGIN,
        "grace_wait answered later than the timer's own round-up after t0 + grace"
    );

    child.kill().expect("cleanup");
    child.wait().expect("reap");
}

/// An unbounded grace on the paused clock: virtual time can pass a year and `grace_wait` is still
/// pending, and nothing was armed (no fallback deadline of any length).
#[cfg(unix)]
#[::tokio::test(start_paused = true)]
async fn grace_wait_with_an_overflowing_grace_stays_pending_across_a_virtual_year() {
    let (tx, rx) = std::sync::mpsc::channel();
    let _seam = super::armed_deadline_seam::install(tx);
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).found().expect("identity of live child");

    let mut fut = std::pin::pin!(grace_wait(id, Duration::MAX));
    assert!(poll_once(fut.as_mut()).is_pending());
    ::tokio::time::advance(Duration::from_secs(86_400 * 365)).await;
    if let std::task::Poll::Ready(r) = poll_once(fut.as_mut()) {
        panic!("an unbounded grace_wait answered {r:?}");
    }
    assert!(rx.try_recv().is_err(), "no timer may be armed for an unbounded grace");

    child.kill().expect("cleanup");
    child.wait().expect("reap");
}

// A timer that wins the first poll still answers from a final probe -----
// `Timeout` polls the inner future first, but a fresh reactor registration reports nothing until a
// driver turn; a deadline already past then fires the timer with the event still unreported. The
// `now_override` makes the deadline past on that first poll, with no timing involved.

/// Site 1: the child exited (unreaped) before the call. Linux only: the pidfd of a zombie
/// registers with the reactor, which reports nothing until a driver turn, whereas macOS detects an
/// already-exited process while arming and never reaches the timer.
#[cfg(target_os = "linux")]
#[::tokio::test]
async fn grace_wait_reports_an_exit_pending_when_the_timer_wins_the_first_poll() {
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    child.kill().expect("kill");
    // `kill` only signals: block (non-reaping) until the exit has really happened.
    assert!(crate::wait::block_until_exit(id, None).expect("exit wait"));
    let past = super::tokio_now()
        .checked_sub(Duration::from_secs(3600))
        .expect("an hour before now");
    let _now = super::now_override::install(past);

    let exited = grace_wait(id, Duration::from_secs(60)).await.expect("grace_wait");
    assert!(exited, "an exit that preceded the call must be reported, not Ok(false)");
    child.wait().expect("reap");
}

/// Site 2: every holder of the marker's write end exited before the call.
#[cfg(target_os = "macos")]
#[::tokio::test]
async fn wait_tree_deadline_reports_an_eof_pending_when_the_timer_wins_the_first_poll() {
    use std::os::fd::AsFd;

    let mut cmd = crate::Command::new();
    cmd.executable("/bin/sh").args(["sh", "-c", "cat"]);
    cmd.fd(0, crate::Stdio::pipe_in()).expect("stdin pipe");
    cmd.fd(3, crate::Stdio::pipe_out()).expect("marker pipe");
    let mut child = cmd.spawn().expect("spawn /bin/sh holding the marker");
    let marker = child.fd_read_end(3.into()).expect("marker read end");
    drop(child.fd_write_end(crate::Fd::STDIN).expect("stdin write end")); // `cat` sees EOF
    child.wait().expect("reap /bin/sh");

    let past = super::tokio_now()
        .checked_sub(Duration::from_secs(3600))
        .expect("an hour before now");
    let _now = super::now_override::install(past);
    let deadline = super::deadline_from(Duration::from_secs(60));

    let drain = super::wait_tree_deadline(marker.as_fd(), deadline)
        .await
        .expect("wait_tree_deadline");
    assert_eq!(drain, crate::containment::TreeDrain::AllMarkersClosed);
}

/// `wait_tree_deadline` (site 2) arms the caller's own instant. The marker's write end must be
/// held by something other than this process (`arm`'s `refuse_if_write_end_held` refuses
/// otherwise), so a real `/bin/sh` holds it on fd 3 until this test closes its stdin. No
/// `test_spawn_lock()`: `Command::spawn` takes it itself.
#[cfg(target_os = "macos")]
#[::tokio::test]
async fn wait_tree_deadline_arms_the_callers_deadline_instant() {
    use std::os::fd::AsFd;

    let mut cmd = crate::Command::new();
    cmd.executable("/bin/sh").args(["sh", "-c", "cat"]);
    cmd.fd(0, crate::Stdio::pipe_in()).expect("stdin pipe");
    cmd.fd(3, crate::Stdio::pipe_out()).expect("marker pipe");
    let mut child = cmd.spawn().expect("spawn /bin/sh holding the marker");
    let marker = child.fd_read_end(3.into()).expect("marker read end");
    let stdin = child.fd_write_end(crate::Fd::STDIN).expect("stdin write end");

    let (tx, rx) = std::sync::mpsc::channel();
    let _seam = super::armed_deadline_seam::install(tx);
    let at = super::tokio_now() + Duration::from_secs(3600);
    {
        let mut fut = std::pin::pin!(super::wait_tree_deadline(marker.as_fd(), Some(Some(at))));
        assert!(poll_once(fut.as_mut()).is_pending(), "an hour-out deadline");
    }
    assert_eq!(rx.try_recv().expect("the wait site must arm via arm_at"), Armed::At(at));
    assert!(rx.try_recv().is_err(), "armed exactly once");

    drop(stdin); // `cat` sees EOF and exits
    child.wait().expect("reap /bin/sh");
}

// `arm_at` owns the timer-margin contract, on every unix platform -----
// A deadline inside tokio's timer margin reaches `arm_at` only by bypassing `deadline_from`, which
// no real caller does. Debug builds assert; release builds wait unbounded.

#[cfg(all(unix, debug_assertions))]
#[::tokio::test]
#[should_panic(expected = "deadline_from's contract should prevent")]
async fn arm_at_debug_asserts_a_deadline_inside_the_timer_margin() {
    let violating = crate::wait::instant_near_ceiling(super::tokio_now());
    let mut fut = std::pin::pin!(super::arm_at(violating, std::future::pending::<()>()));
    _ = poll_once(fut.as_mut());
}

/// Release counterpart of the debug-assert test: the wait resolves with the future's own output,
/// reports an unbounded park, and no timer of any length bounds it.
#[cfg(all(unix, not(debug_assertions)))]
#[::tokio::test(start_paused = true)]
async fn arm_at_waits_unbounded_for_a_deadline_inside_the_timer_margin_in_release() {
    let (tx, rx) = std::sync::mpsc::channel();
    let _seam = super::armed_deadline_seam::install(tx);
    let violating = crate::wait::instant_near_ceiling(super::tokio_now());

    assert_eq!(super::arm_at(violating, std::future::ready(7)).await, Some(7));

    let mut fut = std::pin::pin!(super::arm_at(violating, std::future::pending::<()>()));
    assert!(poll_once(fut.as_mut()).is_pending());
    ::tokio::time::advance(Duration::from_secs(86_400 * 365)).await;
    if let std::task::Poll::Ready(r) = poll_once(fut.as_mut()) {
        panic!("an unbounded wait answered {r:?}");
    }
    assert_eq!(rx.try_iter().collect::<Vec<_>>(), vec![Armed::Unbounded; 2]);
}

/// The Windows job wait is measured on the real clock: a tokio-clock deadline keeps its remaining
/// time, an expired one keeps none, and unbounded stays unbounded.
#[test]
fn to_real_clock_preserves_the_remaining_time_across_clocks() {
    let real = std::time::Instant::now();
    let tokio = real + Duration::from_secs(3600); // virtual time ran ahead
    let s = Duration::from_secs(60);
    assert_eq!(
        super::to_real_clock_at(Some(Some(tokio + s)), tokio, real),
        Some(Some(real + s))
    );
    assert_eq!(
        super::to_real_clock_at(Some(Some(tokio)), tokio, real),
        Some(Some(real))
    );
    assert_eq!(super::to_real_clock_at(Some(Some(real)), tokio, real), Some(Some(real)));
    assert_eq!(super::to_real_clock_at(Some(None), tokio, real), Some(None));
    assert_eq!(super::to_real_clock_at(None, tokio, real), None);
}

/// The wait runs on tokio's clock: virtual time advanced BEFORE the call must not eat the grace.
#[cfg(unix)]
#[::tokio::test(start_paused = true)]
async fn grace_wait_serves_its_full_grace_on_tokios_clock_after_an_advance() {
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    ::tokio::time::advance(Duration::from_secs(3600)).await;
    let t0 = ::tokio::time::Instant::now();
    let grace = Duration::from_secs(60);

    let exited = grace_wait(id, grace).await.expect("grace_wait");
    assert!(!exited, "a live child is still alive at the deadline");
    assert!(
        ::tokio::time::Instant::now() >= t0 + grace,
        "grace_wait answered before t0 + grace on tokio's clock"
    );

    child.kill().expect("cleanup");
    child.wait().expect("reap");
}

/// Site 3 reads tokio's clock for "already expired": with virtual time far ahead of the real
/// clock, a deadline past on tokio's clock answers `MembersRemain` at once, without arming.
#[cfg(target_os = "linux")]
#[::tokio::test(start_paused = true)]
async fn cgroup_wait_tree_drained_judges_expiry_on_tokios_clock() {
    use crate::containment::cgroup::test_support::FakeLeaf;
    use crate::containment::TreeDrain;

    let fake = FakeLeaf::new("cosca-async-expiry-on-tokio-clock", true);
    let leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(fake.leaf.clone());
    ::tokio::time::advance(Duration::from_secs(3600)).await;
    let expired = super::tokio_now() - Duration::from_secs(1);

    let mut fut = std::pin::pin!(super::cgroup_wait_tree_drained(&leaf, Some(Some(expired))));
    match poll_once(fut.as_mut()) {
        std::task::Poll::Ready(r) => assert_eq!(r.expect("wait"), TreeDrain::MembersRemain),
        std::task::Poll::Pending => panic!("a deadline past on tokio's clock must answer at once"),
    }
}

/// Site 2 reads tokio's clock for "already expired": a deadline past on tokio's clock probes at
/// once, arming nothing, even though the real clock still shows it in the future.
#[cfg(target_os = "macos")]
#[::tokio::test(start_paused = true)]
async fn wait_tree_deadline_judges_expiry_on_tokios_clock() {
    use std::os::fd::AsFd;

    let mut cmd = crate::Command::new();
    cmd.executable("/bin/sh").args(["sh", "-c", "cat"]);
    cmd.fd(0, crate::Stdio::pipe_in()).expect("stdin pipe");
    cmd.fd(3, crate::Stdio::pipe_out()).expect("marker pipe");
    let mut child = cmd.spawn().expect("spawn /bin/sh holding the marker");
    let marker = child.fd_read_end(3.into()).expect("marker read end");
    let stdin = child.fd_write_end(crate::Fd::STDIN).expect("stdin write end");

    let (tx, rx) = std::sync::mpsc::channel();
    let _seam = super::armed_deadline_seam::install(tx);
    ::tokio::time::advance(Duration::from_secs(3600)).await;
    let expired = super::tokio_now() - Duration::from_secs(1);

    let drain = super::wait_tree_deadline(marker.as_fd(), Some(Some(expired)))
        .await
        .expect("wait_tree_deadline");
    assert_eq!(drain, crate::containment::TreeDrain::MembersRemain);
    assert!(rx.try_recv().is_err(), "an expired deadline arms nothing");

    drop(stdin);
    child.wait().expect("reap /bin/sh");
}
