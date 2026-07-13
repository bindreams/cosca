//! Unit tests for the reactor-native grace-wait. In the library because `grace_wait` is
//! `pub(crate)`. Death-proof discipline: a generous grace on an already-dead child is a
//! failure bound (the exit event precedes the call); `Duration::ZERO` on a live child makes
//! the timeout branch deterministic.

use std::time::Duration;

// This module is declared INSIDE src/tokio/wait.rs, so `super` is `tokio::wait` itself.
use super::grace_wait;
use crate::identity::ProcessId;

// A long-lived std child (leak-proof: killed + reaped by each test).
fn std_blocker() -> std::process::Child {
    let mut cmd = std::process::Command::new(if cfg!(windows) { "ping" } else { "sleep" });
    #[cfg(windows)]
    cmd.args(["-n", "30", "127.0.0.1"]).stdout(std::process::Stdio::null());
    #[cfg(unix)]
    cmd.arg("30");
    cmd.spawn().expect("spawn std blocker")
}

#[tokio::test]
async fn grace_wait_true_for_exited_unreaped_child() {
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).expect("identity of live child");
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
    let id = ProcessId::of(child.id()).expect("identity of live child");
    let exited = grace_wait(id, Duration::ZERO).await.expect("grace_wait");
    assert!(!exited, "a live child at ZERO grace must report still-alive");
    child.kill().expect("cleanup");
    child.wait().expect("reap");
}

#[tokio::test]
async fn grace_wait_true_for_stale_identity() {
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).expect("identity of live child");
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
    let id = ProcessId::of(child.id()).expect("identity of live child");
    let watch = ::tokio::spawn(grace_wait(id, Duration::from_secs(30)));
    child.kill().expect("kill mid-wait");
    let exited = watch.await.expect("join").expect("grace_wait");
    assert!(exited, "the watch must resolve on the child's exit");
    child.wait().expect("reap");
}

// The Windows release mechanism itself, deterministically: a PRE-signaled cancel event must
// release the wait on a LIVE child — no race, nothing to time. If the cancel plumbing were
// broken, the wait would sit at the (effectively infinite) Duration::MAX cap and the test
// harness's own bound would surface the hang loudly.
#[cfg(windows)]
#[test]
fn cancel_event_releases_the_blocking_wait() {
    let mut child = std_blocker();
    let id = ProcessId::of(child.id()).expect("identity of live child");
    let cancel = crate::wait::backend::new_cancel_event().expect("event");
    crate::wait::backend::signal_cancel(&cancel);
    let exited =
        crate::wait::backend::block_until_exit_or_cancel(id, Duration::MAX, &cancel).expect("cancellable wait");
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
    let id = ProcessId::of(child.id()).expect("identity of live child");
    let cancel = std::sync::Arc::new(crate::wait::backend::new_cancel_event().expect("event"));
    let watcher = std::thread::spawn({
        let cancel = cancel.clone();
        move || crate::wait::backend::block_until_exit_or_cancel(id, Duration::MAX, &cancel)
    });
    crate::wait::backend::signal_cancel(&cancel);
    let exited = watcher.join().expect("watcher thread").expect("cancellable wait");
    assert!(!exited, "a live child with a signaled cancel must report still-alive");
    child.kill().expect("cleanup");
    child.wait().expect("reap");
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
    let target_id = ProcessId::of(target.id()).expect("identity of live target");
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
