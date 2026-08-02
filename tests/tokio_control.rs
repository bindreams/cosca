//! Async control-op integration tests (kill / kill_tree / terminate_tree + builder mirror).
//! Same death-proof discipline as tests/graceful.rs: control-socket EOF or an inspected
//! ExitStatus signal — never sleep/poll/wall-clock.
#![cfg(feature = "tokio")]

#[path = "common/mod.rs"]
mod common;

use std::io::Read;

fn expect_eof(who: &str, s: &mut std::net::TcpStream) {
    let mut buf = [0u8; 1];
    match s.read(&mut buf) {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("{who} not torn down: {other:?}"),
    }
}

#[tokio::test]
async fn async_kill_terminates_the_child() {
    let (mut child, mut sock) = common::spawn_blocker_async();
    child.kill().expect("kill");
    expect_eof("blocker", &mut sock);
    let status = child.wait().await.expect("reap");
    assert!(!status.success(), "killed child cannot report success, got {status:?}");
}

#[tokio::test]
async fn async_kill_after_wait_is_ok() {
    use std::io::Write;
    let (mut child, mut sock) = common::spawn_blocker_async();
    sock.write_all(b"x").expect("release the blocker");
    child.wait().await.expect("reap");
    child.kill().expect("kill after wait is Ok");
}

#[tokio::test]
async fn async_kill_on_exited_unreaped_child_is_ok() {
    use std::io::Write;
    let (mut child, mut sock) = common::spawn_blocker_async();
    sock.write_all(b"x").expect("release the blocker");
    expect_eof("blocker", &mut sock); // real exit event; the child is NOT yet reaped
    child.kill().expect("kill on an exited-unreaped child is Ok");
    child.wait().await.expect("reap");
}

#[tokio::test]
async fn async_tree_ops_unsupported_when_uncontained() {
    let (mut child, mut sock) = common::spawn_blocker_async();
    let err = child.kill_tree().expect_err("uncontained kill_tree");
    assert!(matches!(err, cosca::error::Error::Unsupported { .. }), "got {err:?}");
    let err = child.terminate_tree().expect_err("uncontained terminate_tree");
    assert!(matches!(err, cosca::error::Error::Unsupported { .. }), "got {err:?}");
    child.kill().expect("cleanup");
    expect_eof("blocker", &mut sock);
    let _ = child.wait().await;
}

#[tokio::test]
async fn async_kill_tree_tears_down_tree() {
    let (mut child, mut root, mut grand) = common::spawn_grandchild_async(true);
    child.kill_tree().expect("kill_tree");
    expect_eof("root", &mut root);
    expect_eof("grandchild", &mut grand);
    let status = child.wait().await.expect("reap root");
    assert!(
        !status.success(),
        "hard-killed root cannot report success, got {status:?}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn async_terminate_tree_soft_kills_the_group() {
    use std::os::unix::process::ExitStatusExt;
    // control-block honors SIGTERM: the group signal alone (signal-only op) tears it down.
    let (mut child, mut sock) = common::spawn_control_async("control-block", &["R"], true);
    child.terminate_tree().expect("terminate_tree");
    expect_eof("root", &mut sock);
    let status = child.wait().await.expect("reap");
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "soft group signal must be SIGTERM, got {status:?}"
    );
}

#[tokio::test]
async fn async_contain_with_treewalk_tears_down_tree() {
    // kill_tree on a TreeWalk-contained tree tears down BOTH members via the identity walk
    // (no kernel group needed). The builder mirror's value-sensitivity is the unit test's job
    // (src/tokio/command_tests.rs).
    let (mut child, mut root, mut grand) = common::spawn_tree_async("spawn-grandchild", |cmd| {
        cmd.contain_with(cosca::ContainMode::TreeWalk)
            .nesting(cosca::containment::Nesting::Opaque);
    });
    assert_eq!(child.containment(), cosca::Containment::TreeWalk);
    child.kill_tree().expect("treewalk kill_tree");
    expect_eof("root", &mut root);
    expect_eof("grandchild", &mut grand);
    let _ = child.wait().await.expect("reap");
}

// Graceful-escalation trio (mirrors tests/graceful.rs child_* cases, async) =====

#[cfg(unix)]
#[tokio::test]
async fn async_terminate_sends_sigterm() {
    use std::os::unix::process::ExitStatusExt;
    let (mut child, mut sock) = common::spawn_blocker_async();
    child.terminate().expect("terminate sends SIGTERM");
    expect_eof("blocker", &mut sock);
    let status = child.wait().await.expect("reap");
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "control-block must die by SIGTERM, got {status:?}"
    );
}

#[cfg(windows)]
#[tokio::test]
async fn async_terminate_unsupported_on_windows() {
    let (mut child, mut sock) = common::spawn_blocker_async();
    let err = child
        .terminate()
        .expect_err("lone graceful terminate has no Windows primitive");
    assert!(matches!(err, cosca::error::Error::Unsupported { .. }), "got {err:?}");
    child.kill().expect("cleanup");
    expect_eof("blocker", &mut sock);
    let _ = child.wait().await;
}

#[cfg(unix)]
#[tokio::test]
async fn async_graceful_shutdown_graceful_path() {
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    // control-block dies on default-disposition SIGTERM. The long grace is the safety bound on
    // a child that exits promptly — never the synchronization; correctness is the exit signal.
    let (mut child, mut sock) = common::spawn_blocker_async();
    let status = child
        .graceful_shutdown(Duration::from_secs(30))
        .await
        .expect("graceful_shutdown");
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "graceful path must exit via SIGTERM, got {status:?}"
    );
    expect_eof("blocker", &mut sock);
}

#[cfg(unix)]
#[tokio::test]
async fn async_graceful_shutdown_escalates() {
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    // SIG_IGN child + Duration::ZERO: provably alive at the single poll → deterministic
    // escalation; SIGKILL is the only terminating signal it can receive.
    let (mut child, mut sock) = common::spawn_control_async("control-block-ignore-term", &["R"], false);
    let status = child
        .graceful_shutdown(Duration::ZERO)
        .await
        .expect("graceful_shutdown escalates");
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "SIGTERM-ignoring child must be force-killed, got {status:?}"
    );
    expect_eof("blocker", &mut sock);
}

#[cfg(unix)]
#[tokio::test]
async fn async_graceful_cancel_mid_grace_leaves_child_owned() {
    use std::future::Future;
    use std::time::Duration;
    // The documented cancellation contract: dropping the graceful future mid-grace cancels
    // the watch and performs no further signalling. Deterministic, no timers: poll the future
    // exactly ONCE (that sends SIGTERM and arms the watch), then drop it. The acking child's
    // handler returns without exiting, so nothing escalated => it must still be alive.
    let (mut child, mut sock) = common::spawn_control_async("control-block-ack-term", &["R"], false);
    {
        // Duration::MAX: the watch cannot time out, the SIGTERM-acking (never-exiting) child
        // cannot exit on the soft signal, and nothing escalates before the drop — so the
        // single poll (which sends SIGTERM and parks in the grace-wait) can resolve Ready
        // only through a genuine watch failure. Not asserted away as a race: a Ready is
        // surfaced loudly with its value.
        let mut fut = std::pin::pin!(child.graceful_shutdown(Duration::MAX));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        if let std::task::Poll::Ready(r) = fut.as_mut().poll(&mut cx) {
            panic!("graceful future resolved at first poll instead of parking: {r:?}");
        }
        // The ack byte proves the single poll actually DELIVERED the SIGTERM (a real event,
        // not an assumption about await points) while the future is still parked.
        let mut ack = [0u8; 1];
        sock.read_exact(&mut ack).expect("SIGTERM ack");
        assert_eq!(&ack, b"T", "child must ack the SIGTERM sent by the first poll");
    } // <- future dropped mid-grace here

    // is_alive is THE non-escalation discriminator: this child can only die by SIGKILL (its
    // SIGTERM handler acks and returns), so its terminating signal cannot distinguish our
    // kill from an escalation — being alive here proves the cancelled graceful sent nothing
    // further.
    assert_eq!(
        child.is_alive(),
        cosca::identity::Liveness::Alive,
        "cancelled graceful must not have escalated"
    );
    child.kill().expect("explicit teardown after cancel");
    expect_eof("blocker", &mut sock);
    let _ = child.wait().await.expect("reap");
}

#[cfg(windows)]
#[tokio::test]
async fn async_graceful_tree_cancel_does_not_escalate_on_windows() {
    use std::future::Future;
    use std::time::Duration;
    // The Windows non-escalation discriminator (this is the only Windows grace_wait entry):
    // BOTH members ignore CTRL_BREAK, so after poll-once + drop the root can only be dead if
    // something escalated — being alive proves the cancelled graceful sent nothing further.
    let (mut child, mut root, mut grand) = common::spawn_tree_async("spawn-grandchild-ignore-break", |cmd| {
        cmd.contain();
    });
    {
        // Duration::MAX: the blocking watch cannot time out, the ignore-break members cannot
        // exit on the soft signal, and the cancel event is unsignaled until the drop — so a
        // first-poll Ready can only be a genuine watch failure, surfaced loudly with its
        // value. The drop's guarantee is observable, not timing-based: SignalOnDrop fires,
        // and the runtime-shutdown join (see the note at the end) would hang loudly if the
        // release failed.
        let mut fut = std::pin::pin!(child.graceful_shutdown_tree(Duration::MAX));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        if let std::task::Poll::Ready(r) = fut.as_mut().poll(&mut cx) {
            panic!("graceful future resolved at first poll instead of parking: {r:?}");
        }
    } // <- future dropped mid-grace here
    assert_eq!(
        child.is_alive(),
        cosca::identity::Liveness::Alive,
        "cancelled tree graceful must not have escalated"
    );
    child.kill_tree().expect("explicit sweep after cancel");
    expect_eof("root", &mut root);
    expect_eof("grandchild", &mut grand);
    let _ = child.wait().await.expect("reap after cancelled graceful");
    // End-to-end release proof rides on test teardown: the #[tokio::test] runtime's drop
    // JOINS blocking tasks, so if the dropped guard's cancel event failed to release the
    // Duration::MAX watcher, this test would hang at shutdown — loudly, at the harness bound.
}

#[cfg(unix)]
#[tokio::test]
async fn async_graceful_tree_cancel_does_not_escalate() {
    use std::future::Future;
    use std::time::Duration;
    // The tree-path non-escalation discriminator: BOTH members ignore SIGTERM, so after
    // poll-once + drop the root can only be dead if something escalated — being alive proves
    // the cancelled graceful sent nothing further.
    let (mut child, mut root, mut grand) = common::spawn_tree_async("spawn-grandchild-ignore-term", |cmd| {
        cmd.contain();
    });
    {
        // Duration::MAX + SIGTERM-ignoring members: the single poll (group signal + park in
        // the grace-wait) can resolve Ready only through a genuine watch failure — surfaced
        // loudly with its value.
        let mut fut = std::pin::pin!(child.graceful_shutdown_tree(Duration::MAX));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        if let std::task::Poll::Ready(r) = fut.as_mut().poll(&mut cx) {
            panic!("graceful future resolved at first poll instead of parking: {r:?}");
        }
    }
    assert_eq!(
        child.is_alive(),
        cosca::identity::Liveness::Alive,
        "cancelled tree graceful must not have escalated"
    );
    child.kill_tree().expect("explicit sweep after cancel");
    expect_eof("root", &mut root);
    expect_eof("grandchild", &mut grand);
    let _ = child.wait().await.expect("reap");
}

#[cfg(windows)]
#[tokio::test]
async fn async_graceful_shutdown_tree_sweep_is_load_bearing_on_windows() {
    use std::time::Duration;
    // BOTH members ignore CTRL_BREAK, so whether or not the soft signal reaches this console
    // group, only the ZERO-grace hard sweep can tear the tree down.
    let (mut child, mut root, mut grand) = common::spawn_tree_async("spawn-grandchild-ignore-break", |cmd| {
        cmd.contain();
    });
    let status = child
        .graceful_shutdown_tree(Duration::ZERO)
        .await
        .expect("tree escalates");
    assert!(!status.success(), "swept root cannot report success, got {status:?}");
    expect_eof("root", &mut root);
    expect_eof("grandchild", &mut grand);
}

#[cfg(windows)]
#[tokio::test]
async fn async_graceful_shutdown_unsupported_on_windows() {
    use std::time::Duration;
    let (mut child, mut sock) = common::spawn_blocker_async();
    let err = child
        .graceful_shutdown(Duration::from_secs(1))
        .await
        .expect_err("no Windows lone graceful");
    assert!(matches!(err, cosca::error::Error::Unsupported { .. }), "got {err:?}");
    child.kill().expect("cleanup");
    expect_eof("blocker", &mut sock);
    let _ = child.wait().await;
}

#[tokio::test]
async fn async_graceful_shutdown_tree_tears_down_tree() {
    use std::time::Duration;
    // A contained 2-level tree: the group's graceful signal (SIGTERM / CTRL_BREAK) plus the
    // hard sweep tear down BOTH members; both sockets EOF. All OSes.
    let (mut child, mut root, mut grand) = common::spawn_grandchild_async(true);
    child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .await
        .expect("tree graceful");
    expect_eof("root", &mut root);
    expect_eof("grandchild", &mut grand);
}

#[cfg(unix)]
#[tokio::test]
async fn async_graceful_shutdown_tree_graceful_root_sigterm() {
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    // A contained root that honors SIGTERM: the group signal makes it exit; the reaped status
    // is SIGTERM (15), not escalated.
    let (mut child, mut sock) = common::spawn_control_async("control-block", &["R"], true);
    let status = child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .await
        .expect("tree graceful");
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "root must exit via SIGTERM, got {status:?}"
    );
    expect_eof("root", &mut sock);
}

#[cfg(unix)]
#[tokio::test]
async fn async_graceful_shutdown_tree_escalates_with_surviving_grandchild() {
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    // BOTH tree members ignore SIGTERM (spawn-grandchild-ignore-term), so with ZERO grace both
    // are provably alive when the grace elapses — the hard sweep, not the soft signal, must
    // tear down the root AND the surviving grandchild.
    let (mut child, mut root, mut grand) = common::spawn_tree_async("spawn-grandchild-ignore-term", |cmd| {
        cmd.contain();
    });
    let status = child
        .graceful_shutdown_tree(Duration::ZERO)
        .await
        .expect("tree escalates");
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "ignored SIGTERM must escalate to SIGKILL, got {status:?}"
    );
    expect_eof("root", &mut root);
    expect_eof("grandchild", &mut grand);
}

#[cfg(unix)]
#[tokio::test]
async fn async_graceful_shutdown_tree_sweeps_survivor_after_graceful_root_exit() {
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    // The exact case the sweep-before-reap invariant protects: the root honors the group
    // SIGTERM and exits within the grace, but the grandchild ignores it and survives — only
    // the post-grace hard sweep (running while the unreaped root still pins the group id)
    // can tear it down. The root's status stays SIGTERM: the sweep no-ops on the dead root.
    let (mut child, mut root, mut grand) = common::spawn_tree_async("spawn-grandchild-stubborn-child", |cmd| {
        cmd.contain();
    });
    let status = child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .await
        .expect("tree graceful with survivor");
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "root must exit via SIGTERM (graceful), got {status:?}"
    );
    expect_eof("root", &mut root);
    expect_eof("grandchild", &mut grand);
}

#[tokio::test]
async fn async_graceful_tree_unsupported_when_uncontained() {
    use std::time::Duration;
    let (mut child, mut sock) = common::spawn_blocker_async();
    let err = child
        .graceful_shutdown_tree(Duration::from_secs(1))
        .await
        .expect_err("uncontained tree graceful");
    assert!(matches!(err, cosca::error::Error::Unsupported { .. }), "got {err:?}");
    child.kill().expect("cleanup");
    expect_eof("blocker", &mut sock);
    let _ = child.wait().await;
}
