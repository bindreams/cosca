//! Unit tests for the reactor-native grace-wait. In the library because `grace_wait` is
//! `pub(crate)`. Death-proof discipline: a generous grace on an already-dead child is a
//! failure bound (the exit event precedes the call); `Duration::ZERO` on a live child makes
//! the timeout branch deterministic.

use std::time::Duration;

// This module is declared INSIDE src/tokio/wait.rs, so `super` is `tokio::wait` itself.
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
/// Local to `wait_exit_cancel_leaves_child_untouched` and (on Windows)
/// `wait_exit_drop_releases_the_windows_watcher`.
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
        let _ = child.kill();
        let _ = child.wait();
    }
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
    let child = IndefiniteBlocker::spawn();
    let exited = grace_wait(child.id(), Duration::ZERO).await.expect("grace_wait");
    assert!(!exited, "a live child at ZERO grace must report still-alive");
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
    let child = IndefiniteBlocker::spawn();
    let id = child.id();
    let cancel = crate::wait::backend::new_cancel_event().expect("event");
    crate::wait::backend::signal_cancel(&cancel);
    let exited = crate::wait::backend::block_until_exit_or_cancel(id, None, &cancel).expect("cancellable wait");
    assert!(!exited, "a live child with a signaled cancel must report still-alive");
}

// The concurrent case: signal the cancel while the wait is (or is about to be) in flight.
// The manual-reset event is set-once/released-forever, so EVERY interleaving must release
// the watcher — this is race-INSENSITIVITY being proven, not an outcome bet on a race. If
// the release were broken, the join would hang at the harness's own failure bound.
#[cfg(windows)]
#[test]
fn cancel_event_signaled_mid_wait_releases_the_blocking_wait() {
    let child = IndefiniteBlocker::spawn();
    let id = child.id();
    let cancel = std::sync::Arc::new(crate::wait::backend::new_cancel_event().expect("event"));
    let watcher = std::thread::spawn({
        let cancel = cancel.clone();
        move || crate::wait::backend::block_until_exit_or_cancel(id, None, &cancel)
    });
    crate::wait::backend::signal_cancel(&cancel);
    let exited = watcher.join().expect("watcher thread").expect("cancellable wait");
    assert!(!exited, "a live child with a signaled cancel must report still-alive");
}

/// A child that blocks INDEFINITELY — no internal timeout at all, unlike `std_blocker`'s
/// `ping -n 30` / `sleep 30`, whose liveness during a probe is only "generous enough," a real
/// subprocess's own timer a slow/loaded test run could in principle outrun. `cat` (Unix) /
/// `cmd /C more` (Windows) block reading stdin forever with nothing writing to it; neither
/// exits on its own. Kill-FREE cleanup (RAII, in `Drop`): closing stdin is the program's own
/// graceful-exit signal (and on Windows `cmd.exe` exits once `more.com`, its child, has) — no
/// kill, no timing bet, no orphaned grandchild, and no risk of `Drop` itself hanging behind a
/// kill that failed while stdin was still held open.
struct IndefiniteBlocker(std::process::Child);

impl IndefiniteBlocker {
    fn spawn() -> Self {
        // Held for the fork itself — see `fdmarker_tests.rs`'s module docs.
        let _guard = crate::child::spawn::spawn_lock();
        #[cfg(unix)]
        let mut cmd = std::process::Command::new("cat");
        #[cfg(windows)]
        let mut cmd = {
            let mut cmd = std::process::Command::new("cmd");
            cmd.args(["/C", "more"]);
            cmd
        };
        let child = cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn indefinite blocker");
        Self(child)
    }

    fn id(&self) -> ProcessId {
        ProcessId::of(self.0.id()).found().expect("identity of live child")
    }
}

impl Drop for IndefiniteBlocker {
    fn drop(&mut self) {
        // Close stdin FIRST: EOF is the program's own exit signal, so the `wait()` below is
        // bounded by a real, imminent exit already in motion.
        drop(self.0.stdin.take());
        let _ = self.0.wait();
    }
}

// Deadline-armed-once proof (principle 13, "never late by its own choice"): `grace_wait`'s
// Windows arm must arm the blocking wait from the Instant it computed BEFORE crossing the
// spawn_blocking boundary, never re-derive a fresh one once inside the blocking closure, and
// `block_until_exit_or_cancel` must recompute the real Win32 timeout from THAT deadline only
// after the identity-verification work, never before. Two proofs, both made deterministic —
// neither depends on two independent clock reads happening to differ:
//
// 1. `armed == used.deadline == Some(Some(fake))`: `crate::wait::deadline_from_override_seam`
//    forces `grace_wait`'s `deadline_from(grace)` call to return a made-up PAST instant
//    (`fake`) instead of a real one. A callee that only THREADS that value through (correct)
//    reports the exact same `fake` back; one that RE-DERIVES its own deadline instead (e.g. by
//    calling `deadline_from`/`Instant::now()` again — on the blocking-pool thread, where the
//    override does not apply) reports a real, current instant instead, always later than
//    `fake` and so always unequal to it.
// 2. `used.used_seq > used.before_identity_seq`: a sequence counter, not an `Instant`,
//    fetched right after the real `OpenProcess` syscall (`before_identity_seq`) and again
//    where the loop's `remaining` is actually read (`used_seq`). A mutant that hoists that
//    read above `windows_open_classified` fetches `used_seq` first, making the comparison
//    fail deterministically — not "probably, unless two `Instant::now()` reads happen to tie."
//
// `try_recv()`, not `recv()`: `blocking_watch` awaits the `spawn_blocking` join before
// returning, so both channel sends happen-before `grace_wait(..).await` resolves here — a
// missing notification is then a fast, immediate test failure instead of a hang out to the CI
// job's own 15-minute timeout. The install guards remove their registry entries on drop, so a
// finished run of this test cannot leave a sender behind for a later test to trip over.
//
// Uses a child that blocks with no internal timeout of its own (`IndefiniteBlocker`, not
// `std_blocker`'s `ping -n 30`): `assert!(!exited, ..)` below must hold because the child
// cannot exit on its own, never because 30 real seconds "should be" enough.
#[cfg(windows)]
#[tokio::test]
async fn grace_wait_windows_arms_the_wait_from_a_single_deadline_not_a_re_derived_one() {
    let (armed_tx, armed_rx) = std::sync::mpsc::channel();
    let (used_tx, used_rx) = std::sync::mpsc::channel();

    let child = IndefiniteBlocker::spawn();
    let id = child.id();
    let _armed_guard = super::grace_wait_armed_observer::install(id, armed_tx);
    let _used_guard = crate::wait::backend::deadline_observer::install(id, used_tx);

    let start = std::time::Instant::now();
    let fake = start - Duration::from_secs(1);
    let _seam = crate::wait::deadline_from_override_seam::set(fake);

    let exited = grace_wait(id, Duration::ZERO).await.expect("grace_wait");
    assert!(
        !exited,
        "a live child (blocked indefinitely on stdin) at ZERO grace must report still-alive"
    );

    let armed = armed_rx
        .try_recv()
        .expect("armed observer must have fired synchronously by the time grace_wait returned");
    let used = used_rx
        .try_recv()
        .expect("used observer must have fired synchronously by the time grace_wait returned");

    assert_eq!(
        armed,
        Some(Some(fake)),
        "grace_wait must arm from the exact deadline it computed (the seam-forced instant), \
         not a real Instant::now()"
    );
    assert_eq!(
        armed, used.deadline,
        "the blocking wait must be armed from the SAME deadline grace_wait computed before \
         spawn_blocking, not one re-derived after crossing into the blocking closure"
    );
    assert!(
        used.used_at >= start,
        "the 'used_at' instant notify() recorded must not predate this test's own start read"
    );
    assert!(
        used.used_seq > used.before_identity_seq,
        "remaining() must be computed AFTER windows_open_classified/identity verification \
         (used_seq = {}, before_identity_seq = {})",
        used.used_seq,
        used.before_identity_seq
    );
}

// Drive the REAL macOS watch loop through its clear_ready + re-await cycle with genuine
// kernel events: a DECOY second NOTE_EXIT filter on the same kqueue supplies the first wake;
// the scripted drain consumes it (keeping the kqueue level low, so clear_ready cannot miss a
// wake) but reports "no exit" — the loop must re-await, and the target's real exit must still
// resolve it. Every wake is a real kernel event; the 30 s timeout is the failure bound.
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
    ::tokio::time::timeout(Duration::from_secs(30), watch)
        .await
        .expect("the re-awaited loop must resolve on the target's exit")
        .expect("watch");
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
    super::fault_observer::install_release_observer(tx);
    let mut child = std_blocker_with_stdout();
    let id = ProcessId::of(child.id()).found().expect("identity of live child");
    {
        let mut fut = std::pin::pin!(wait_exit(id));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        if let std::task::Poll::Ready(r) = fut.as_mut().poll(&mut cx) {
            panic!("unbounded watch resolved at first poll on a live child: {r:?}");
        }
    } // <- drop signals the cancel event
    rx.recv()
        .expect("the blocking watcher must return after the drop released it");
    assert_child_still_alive(&mut child); // release must be signal-free
    kill_and_reap(&mut child);
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
    let mut child = std_blocker();
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

    // The child itself is still live throughout (the watch above resolved on the STALE
    // identity, never touching this one) — kill-on-drop would also cover this, but clean up
    // explicitly rather than leaving a live `ping` to the runtime's teardown.
    child.kill().expect("cleanup");
    child.wait().expect("reap");
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
    let deadline = crate::wait::deadline_from(duration);

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
async fn cgroup_wait_tree_drained_through_sleep_until_never_answers_early() {
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

/// The async wait site (`cgroup_wait_tree_drained`'s own `Block` arm) is armed with the caller's
/// deadline instant exactly — structural, no timing.
#[cfg(target_os = "linux")]
#[::tokio::test]
async fn cgroup_wait_tree_drained_arms_the_wait_site_with_the_callers_deadline_instant() {
    use crate::containment::cgroup::test_support::{FakeLeaf, TokioWaitSiteParkGuard};
    use std::time::{Duration, Instant};

    let fake = FakeLeaf::new("cosca-async-wait-site-deadline", true);
    let leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(fake.leaf.clone());

    let (_guard, park_rx) = TokioWaitSiteParkGuard::install();

    // Far enough out that a populated fake leaf never takes the zero-remaining shortcut; how far
    // is irrelevant, since the future below is polled only once.
    let at = Instant::now() + Duration::from_secs(3600);
    let fut = super::cgroup_wait_tree_drained(&leaf, Some(Some(at)));
    ::tokio::pin!(fut);
    // Poll once, `biased` so `&mut fut` is polled first: a mutant resolving on this poll panics
    // instead of being masked by `ready(())`.
    ::tokio::select! {
        biased;
        _ = &mut fut => panic!(
            "the fake leaf never drains and the deadline is an hour out; a single poll must not \
             resolve this"
        ),
        _ = std::future::ready(()) => {}
    }

    let park = park_rx
        .try_recv()
        .expect("the wait site must arm a park on its first poll");
    assert_eq!(
        park.deadline,
        Some(at),
        "the tokio wait site must arm its wait with the caller's own deadline instant exactly, \
         got {park:?}"
    );
}

/// The async wait site's unbounded arm fires the same seam, with no deadline armed.
#[cfg(target_os = "linux")]
#[::tokio::test]
async fn cgroup_wait_tree_drained_arms_the_wait_site_unbounded_with_no_deadline() {
    use crate::containment::cgroup::test_support::{FakeLeaf, TokioWaitSiteParkGuard};

    let fake = FakeLeaf::new("cosca-async-wait-site-unbounded", true);
    let leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(fake.leaf.clone());

    let (_guard, park_rx) = TokioWaitSiteParkGuard::install();

    let fut = super::cgroup_wait_tree_drained(&leaf, None);
    ::tokio::pin!(fut);
    ::tokio::select! {
        biased;
        _ = &mut fut => panic!("the fake leaf never drains; a single poll must not resolve this"),
        _ = std::future::ready(()) => {}
    }

    let park = park_rx
        .try_recv()
        .expect("the wait site must arm a park on its first poll");
    assert_eq!(
        park.deadline, None,
        "the unbounded wait site must arm with no deadline, got {park:?}"
    );
}
