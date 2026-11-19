//! Async control-op integration tests (kill / kill_tree / terminate_tree + builder mirror).
//! Same death-proof discipline as tests/graceful.rs: control-socket EOF or an inspected
//! ExitStatus signal — never sleep/poll/wall-clock.

#[cfg(feature = "tokio")]
#[path = "common/mod.rs"]
mod common;

#[cfg(all(feature = "tokio", target_os = "linux"))]
use common::test_groups::{pidfd_group_signal, Group};
#[cfg(feature = "tokio")]
use std::io::Read;

#[cfg(feature = "tokio")]
fn expect_eof(who: &str, s: &mut std::net::TcpStream) {
    let mut buf = [0u8; 1];
    match s.read(&mut buf) {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("{who} not torn down: {other:?}"),
    }
}

#[cfg(feature = "tokio")]
#[skuld::test]
async fn async_kill_terminates_the_child() {
    let (mut child, sock) = common::spawn_blocker_async().await;
    // Released after the kill: a kill that sent nothing exits 0.
    common::kill_release_reap_async(&mut child, sock).await;
}

#[cfg(feature = "tokio")]
#[skuld::test]
async fn async_kill_after_wait_is_ok() {
    use std::io::Write;
    let (mut child, mut sock) = common::spawn_blocker_async().await;
    sock.write_all(b"x").expect("release the blocker");
    child.wait().await.expect("reap");
    child.kill().expect("kill after wait is Ok");
}

#[cfg(feature = "tokio")]
#[skuld::test]
async fn async_kill_on_exited_unreaped_child_is_ok() {
    use std::io::Write;
    let (mut child, mut sock) = common::spawn_blocker_async().await;
    sock.write_all(b"x").expect("release the blocker");
    expect_eof("blocker", &mut sock); // real exit event; the child is NOT yet reaped
    child.kill().expect("kill on an exited-unreaped child is Ok");
    child.wait().await.expect("reap");
}

#[cfg(feature = "tokio")]
#[skuld::test]
async fn async_tree_ops_unsupported_when_uncontained() {
    let (mut child, sock) = common::spawn_blocker_async().await;
    let err = child.kill_tree().await.expect_err("uncontained kill_tree");
    assert!(matches!(err, cosca::error::Error::Unsupported { .. }), "got {err:?}");
    let err = child.terminate_tree().await.expect_err("uncontained terminate_tree");
    assert!(matches!(err, cosca::error::Error::Unsupported { .. }), "got {err:?}");
    common::kill_release_reap_async(&mut child, sock).await;
}

#[cfg(feature = "tokio")]
#[skuld::test]
async fn async_kill_tree_tears_down_tree() {
    let _warns = common::warn_watch();
    let (mut child, root, grand) = common::spawn_tree_async("spawn-grandchild", |cmd| {
        common::contain_without_cgroup_async(cmd);
        cmd.kill_on_drop(true);
        cmd.env(common::ECHO_HELD_ENV, "1");
    })
    .await;
    let (root, grand) = (
        common::Member::new(root, child.pid()),
        common::Member::new(grand, common::last_reported_grandchild().expect("the grandchild's pid")),
    );
    let grand_id = common::last_reported_grandchild_id().expect("the grandchild's identity");
    child.kill_tree().await.expect("kill_tree");
    common::assert_exited(grand_id, "the grandchild");
    // A kill that did not come fails here by assertion.
    common::assert_members_killed(vec![(root, "the root"), (grand, "the grandchild")]);
    let status = child.wait().await.expect("reap root");
    assert!(
        !status.success(),
        "hard-killed root cannot report success, got {status:?}"
    );
}

/// The soft signal alone is the subject, so the root is reaped before the drop: a `kill_tree()`
/// first would race the SIGTERM for the exit status. What the drop then says depends on the host
/// (#382, #782), so each host's test passes the `WarnWatch` that states it.
#[cfg(feature = "tokio")]
#[cfg(unix)]
async fn terminate_tree_soft_kills_the_group(_warns: common::WarnWatch) {
    use std::os::unix::process::ExitStatusExt;
    // control-block honors SIGTERM: the group signal alone (signal-only op) tears it down. It also
    // exits at the test's byte, so a root the SIGTERM missed exits by itself: the wait cannot hang,
    // and its status shows no signal.
    let (mut child, mut sock) = common::spawn_control_async("control-block", &["R"], true).await;
    child.terminate_tree().await.expect("terminate_tree");
    _ = std::io::Write::write_all(&mut sock, b"x");
    let status = child.wait().await.expect("reap");
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "soft group signal must be SIGTERM, got {status:?}"
    );
}

/// Linux 6.9+: the drop reads the reaped root's group through its pidfd, finds it empty and says
/// nothing at warn. The library's own tests cover this, since they can refuse the flag and `tests/`
/// cannot.
#[cfg(feature = "tokio")]
#[cfg(target_os = "linux")]
#[skuld::test]
async fn async_terminate_tree_soft_kills_the_group(#[fixture(pidfd_group_signal)] _group: &Group) {
    terminate_tree_soft_kills_the_group(common::warn_watch()).await;
}

/// macOS has no pidfd, but `wait` leaves the root a zombie that pins its group's number: the drop
/// kills the group by it, as for a running root, and says nothing at warn.
#[cfg(feature = "tokio")]
#[cfg(target_os = "macos")]
#[skuld::test]
async fn async_terminate_tree_soft_kills_the_group() {
    terminate_tree_soft_kills_the_group(common::warn_watch()).await;
}

#[cfg(feature = "tokio")]
#[skuld::test]
async fn async_contain_with_treewalk_tears_down_tree() {
    let _warns = common::warn_watch();
    // kill_tree on a TreeWalk-contained tree tears down BOTH members via the identity walk
    // (no kernel group needed). The builder mirror's value-sensitivity is the unit test's job
    // (src/tokio/command_tests.rs).
    let (mut child, root, grand) = common::spawn_tree_async("spawn-grandchild", |cmd| {
        cmd.contain_with(cosca::ContainMode::TreeWalk)
            .nesting(cosca::containment::Nesting::Opaque);
        cmd.env(common::ECHO_HELD_ENV, "1");
    })
    .await;
    assert_eq!(child.containment(), common::tree_walk_gives());
    let (root, grand) = (
        common::Member::new(root, child.pid()),
        common::Member::new(grand, common::last_reported_grandchild().expect("the grandchild's pid")),
    );
    let grand_id = common::last_reported_grandchild_id().expect("the grandchild's identity");
    child.kill_tree().await.expect("treewalk kill_tree");
    common::assert_exited(grand_id, "the grandchild");
    common::assert_members_killed(vec![(root, "the root"), (grand, "the grandchild")]);
    let _ = child.wait().await.expect("reap");
}

// Graceful-escalation trio (mirrors tests/graceful.rs child_* cases, async) =====

#[cfg(feature = "tokio")]
#[cfg(unix)]
#[skuld::test]
async fn async_terminate_sends_sigterm() {
    use std::os::unix::process::ExitStatusExt;
    let (mut child, sock) = common::spawn_blocker_async().await;
    child.terminate().await.expect("terminate sends SIGTERM");
    // Released after the signal: a terminate that sent nothing exits 0.
    drop(sock);
    let status = child.wait().await.expect("reap");
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "control-block must die by SIGTERM, got {status:?}"
    );
}

#[cfg(feature = "tokio")]
#[cfg(windows)]
#[skuld::test]
async fn async_terminate_unsupported_for_an_uncontained_child_on_windows() {
    let (mut child, sock) = common::spawn_control_async_on_console("control-block", &["R"], false).await;
    let err = child
        .terminate()
        .await
        .expect_err("a child that leads no group cannot be addressed");
    common::assert_refused_for_no_group(&err);
    common::kill_release_reap_async(&mut child, sock).await;
}

#[cfg(feature = "tokio")]
#[cfg(unix)]
#[skuld::test]
async fn async_graceful_cancel_mid_grace_leaves_child_owned() {
    use std::future::Future;
    use std::time::Duration;
    // The documented cancellation contract: dropping the graceful future mid-grace cancels
    // the watch and performs no further signalling. Deterministic, no timers: poll the future
    // exactly ONCE (that sends SIGTERM and arms the watch), then drop it. The acking child's
    // handler returns without exiting, so nothing escalated => it must still be alive.
    // The child echoes a probe byte: see the `probe` below.
    let (mut child, mut sock) = common::spawn_control_async_with("control-block-ack-term", &["R"], false, |cmd| {
        cmd.env(common::ECHO_HELD_ENV, "1");
    })
    .await;
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
        // not an assumption about await points) while the future is still parked. The probe is
        // written after the poll, so a SIGTERM that poll sent is acked before the echo. Read one
        // byte at a time: a missing ack makes the first byte the echo and fails the assertion.
        std::io::Write::write_all(&mut sock, b"p").expect("write the probe");
        let mut ack = [0u8; 1];
        sock.read_exact(&mut ack).expect("SIGTERM ack");
        assert_eq!(&ack, b"T", "child must ack the SIGTERM sent by the first poll");
        let mut echo = [0u8; 1];
        sock.read_exact(&mut echo).expect("the probe's echo");
        assert_eq!(&echo, b"p", "the probe's echo must follow the ack");
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
    common::kill_release_reap_async(&mut child, sock).await;
}

#[cfg(feature = "tokio")]
#[cfg(windows)]
#[skuld::test]
async fn async_graceful_tree_cancel_does_not_escalate_on_windows() {
    let _warns = common::warn_watch();
    use std::future::Future;
    use std::time::Duration;
    // The Windows non-escalation discriminator (this is the only Windows entry into the async process wait):
    // BOTH members ignore CTRL_BREAK, so after poll-once + drop the root can only be dead if
    // something escalated — being alive proves the cancelled graceful sent nothing further.
    let (mut child, root, grand) = common::spawn_tree_async_on_console("spawn-grandchild-ignore-break", |cmd| {
        common::contain_without_cgroup_async(cmd);
        cmd.env(common::ECHO_HELD_ENV, "1");
    })
    .await;
    let (root, grand) = (
        common::Member::new(root, child.pid()),
        common::Member::new(grand, common::last_reported_grandchild().expect("the grandchild's pid")),
    );
    {
        // Duration::MAX: the watch cannot time out and the ignore-break members cannot exit on
        // the soft signal, so a first-poll Ready can only be a genuine watch failure, surfaced
        // loudly with its value.
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
    child.kill_tree().await.expect("explicit sweep after cancel");
    common::assert_members_killed(vec![(root, "the root"), (grand, "the grandchild")]);
    let _ = child.wait().await.expect("reap after cancelled graceful");
}

#[cfg(feature = "tokio")]
#[cfg(unix)]
#[skuld::test]
async fn async_graceful_tree_cancel_does_not_escalate() {
    let _warns = common::warn_watch();
    use std::future::Future;
    use std::time::Duration;
    // The tree-path non-escalation discriminator: BOTH members ignore SIGTERM, so after
    // poll-once + drop the root can only be dead if something escalated — being alive proves
    // the cancelled graceful sent nothing further.
    let (mut child, mut root, mut grand) = common::spawn_tree_async("spawn-grandchild-ignore-term", |cmd| {
        common::contain_without_cgroup_async(cmd);
        cmd.env(common::ECHO_HELD_ENV, "1");
    })
    .await;
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
    child.kill_tree().await.expect("explicit sweep after cancel");
    common::assert_dead(&mut root, "the root after the sweep");
    common::assert_dead(&mut grand, "the grandchild after the sweep");
    let _ = child.wait().await.expect("reap");
}

#[cfg(feature = "tokio")]
#[cfg(windows)]
#[skuld::test]
async fn async_graceful_shutdown_unsupported_for_an_uncontained_child_on_windows() {
    use std::time::Duration;
    let (mut child, sock) = common::spawn_control_async_on_console("control-block", &["R"], false).await;
    let err = child
        .graceful_shutdown(Duration::from_secs(1))
        .await
        .expect_err("a child that leads no group cannot be addressed");
    common::assert_refused_for_no_group(&err);
    common::kill_release_reap_async(&mut child, sock).await;
}

#[cfg(feature = "tokio")]
#[skuld::test]
async fn async_graceful_tree_unsupported_when_uncontained() {
    use std::time::Duration;
    let (mut child, sock) = common::spawn_blocker_async().await;
    let err = child
        .graceful_shutdown_tree(Duration::from_secs(1))
        .await
        .expect_err("uncontained tree graceful");
    assert!(matches!(err, cosca::error::Error::Unsupported { .. }), "got {err:?}");
    common::kill_release_reap_async(&mut child, sock).await;
}

// The lone graceful ops on a console-group child — async twins of tests/graceful.rs's =====

#[cfg(feature = "tokio")]
/// Async twin of `child_terminate_reports_ok_for_an_already_exited_child`. The async `Child` pins
/// its pid for its whole life, as the sync one does, so the already-exited answer is `Ok` on
/// Windows too, except for a child created on our console that leads no group, which the direct send
/// refuses before and after its exit, which the last block pins.
#[skuld::test]
async fn async_child_terminate_reports_ok_for_an_already_exited_child() {
    let _warns = common::warn_watch();
    let (mut child, sock) = common::spawn_control_async_on_console("control-block", &["R"], true).await;
    // `kill_tree`, not `kill`: reaping a contained root first and then dropping it warns (#382).
    common::kill_tree_release_reap_async(&mut child, sock).await;
    child.terminate().await.expect("already-dead must be Ok");

    // Off our console too: on Windows the default asks the proxy for these (this host's `main` calls the
    // hook, so the proxy route is open), and an exited child is answered `Ok`.
    let (mut child, sock) = common::spawn_control_async_with("control-block", &["R"], true, |_| {}).await;
    common::kill_tree_release_reap_async(&mut child, sock).await;
    child
        .terminate()
        .await
        .expect("already-dead, on a console of its own, must be Ok");

    let (mut child, sock) = common::spawn_control_async_with("control-block", &["R"], false, |_| {}).await;
    common::kill_release_reap_async(&mut child, sock).await;
    child
        .terminate()
        .await
        .expect("already-dead, uncontained, on a console of its own, must be Ok");

    // The exception: the direct send's refusal of a child that leads no group does not look at the exit.
    #[cfg(windows)]
    {
        let (mut child, sock) = common::spawn_control_async_on_console("control-block", &["R"], false).await;
        common::kill_release_reap_async(&mut child, sock).await;
        let err = child
            .terminate()
            .await
            .expect_err("a child on our console that leads no group is refused, exited or not");
        common::assert_refused_for_no_group(&err);
    }
}

#[cfg(feature = "tokio")]
/// The one assertion that catches a future divergence between the two hand-mirrored surfaces:
/// the async child must refuse an uncontained child exactly as the sync side does, alive and after a
/// reap. (A contained child is not compared here: its soft stop ends it, and a contained root reaped
/// before its drop warns, per host. On Windows the default's answers for a child on our console
/// are compared by `async_default_answers_match_the_sync_surface_on_our_console`.)
#[skuld::test]
async fn async_refusals_match_the_sync_surface() {
    let _warns = common::warn_watch();
    let (mut uncontained, s1) = common::spawn_blocker_async().await;
    let (sync_uncontained, s3) = common::spawn_blocker();
    assert_eq!(
        refusal_shape(&uncontained.terminate_tree().await),
        refusal_shape(&sync_uncontained.terminate_tree()),
        "uncontained terminate_tree: the two mirrors answer with different error shapes"
    );
    // The mirrors must also refuse for the same REASON after a reap.
    // Reaped first: that is where a pid-scoped refusal that also swallowed the pid-INDEPENDENT
    // ones would start answering something the sync side never answers. Uncontained on purpose.
    //
    // Each child blocks on a piped stdin this test holds and releases right after the `kill()`: a
    // `kill()` that did nothing exits 0 and fails `assert_killed`.
    let argv = [common::stdin_blocker_program()];
    let (mut async_reaped, async_stdin) = {
        let mut cmd = common::tokio_command(common::Console::Hidden);
        cmd.args(&argv);
        cmd.stdin(cosca::Stdio::pipe()).expect("set stdin pipe");
        cmd.stdout(cosca::Stdio::null()).expect("set stdout null");
        let mut child = cmd.spawn().await.expect("spawn async uncontained");
        let stdin = child.stdin().expect("piped stdin");
        (child, stdin)
    };
    let (sync_reaped, sync_stdin) = {
        let mut cmd = common::command(common::Console::Hidden);
        cmd.args(&argv);
        cmd.stdin(cosca::Stdio::pipe()).expect("set stdin pipe");
        cmd.stdout(cosca::Stdio::null()).expect("set stdout null");
        let mut child = cmd.spawn().expect("spawn sync uncontained");
        let stdin = child.stdin().expect("piped stdin");
        (child, stdin)
    };
    async_reaped.kill().expect("kill");
    drop(async_stdin);
    common::assert_killed("the async child", async_reaped.wait().await.expect("reap"));
    sync_reaped.kill().expect("kill");
    drop(sync_stdin);
    common::assert_killed("the sync child", sync_reaped.wait().expect("reap"));
    assert_eq!(
        refusal_shape(&async_reaped.terminate().await),
        refusal_shape(&sync_reaped.terminate()),
        "uncontained, after a reap: the two mirrors answer with different error shapes"
    );

    common::kill_release_reap_async(&mut uncontained, s1).await;
    common::kill_release_reap_all(vec![(sync_uncontained, s3)]);
}

/// Windows: the default stop's answers for a child on our console that needs no proxy (a contained child that
/// leads a group, which gets the direct send, and a contained and an uncontained child that lead none, which
/// get the direct send's refusal) are the same from the sync and the async `Child`, alive and after the
/// reap. This host calls the hook, so a proxy the default took for a no-group child would run and refuse it
/// in words of its own (`ConsoleIsCallers`); [`refusal_shape`] tells the direct send's refusal from that
/// by its text. Mutant: the default routes a no-group child on our console through the proxy.
#[cfg(feature = "tokio")]
#[cfg(windows)]
#[skuld::test]
async fn async_default_answers_match_the_sync_surface_on_our_console() {
    let _warns = common::warn_watch();
    // (name, contained, leads no group)
    for (name, contain, no_group) in [
        ("uncontained", false, false),
        ("contained, no group", true, true),
        ("contained, leads a group", true, false),
    ] {
        let configure = |cmd: &mut cosca::Command| _ = cmd.new_process_group(!no_group && contain);
        let configure_async = |cmd: &mut cosca::tokio::Command| _ = cmd.new_process_group(!no_group && contain);
        let (sync_child, sync_sock) =
            common::spawn_control_on_console_with("control-block-ignore-break", &["R"], contain, configure);
        let (mut async_child, async_sock) =
            common::spawn_control_async_on_console_with("control-block-ignore-break", &["R"], contain, configure_async)
                .await;
        let alive = (
            refusal_shape(&async_child.terminate().await),
            refusal_shape(&sync_child.terminate()),
        );
        assert_eq!(alive.0, alive.1, "{name}, alive: the mirrors' terminate");
        if !contain {
            assert_eq!(alive.1, "unsupported (no group)", "{name}: the direct send's refusal");
        } else if no_group {
            assert_eq!(alive.1, "unsupported (no group)", "{name}: the direct send's refusal");
            assert_eq!(
                refusal_shape(&async_child.terminate_tree().await),
                refusal_shape(&sync_child.terminate_tree()),
                "{name}, alive: the mirrors' terminate_tree"
            );
        } else {
            assert_eq!(alive.1, "ok", "{name}: the direct send");
        }
        if contain {
            common::kill_tree_release_reap(&sync_child, sync_sock);
            common::kill_tree_release_reap_async(&mut async_child, async_sock).await;
        } else {
            common::kill_release_reap(&sync_child, sync_sock);
            common::kill_release_reap_async(&mut async_child, async_sock).await;
        }
        assert_eq!(
            refusal_shape(&async_child.terminate().await),
            refusal_shape(&sync_child.terminate()),
            "{name}, after the reap: the mirrors' terminate"
        );
        if contain {
            assert_eq!(
                refusal_shape(&async_child.terminate_tree().await),
                refusal_shape(&sync_child.terminate_tree()),
                "{name}, after the reap: the mirrors' terminate_tree"
            );
        }
    }
}

#[cfg(feature = "tokio")]
/// The comparable shape of a cooperative-signal outcome: `Error` is `#[non_exhaustive]` and not
/// `PartialEq`, and the detail strings legitimately differ between the two surfaces. An `Unsupported` that
/// says the child "leads no console process group" is the direct send's refusal of a child that leads no
/// group; the proxy's own refusal (`ConsoleIsCallers`) names `Command::new_process_group` too, and is told
/// from it by that phrase.
fn refusal_shape(result: &Result<(), cosca::error::Error>) -> &'static str {
    match result {
        Ok(()) => "ok",
        Err(cosca::error::Error::Unsupported { detail, .. })
            if detail.contains("leads no console process group") && detail.contains("Command::new_process_group") =>
        {
            "unsupported (no group)"
        }
        Err(cosca::error::Error::Unsupported { .. }) => "unsupported",
        Err(cosca::error::Error::Unassessable { .. }) => "unassessable",
        Err(_) => "other",
    }
}

#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    #[cfg(windows)]
    cosca::init_helpers();
    #[cfg(feature = "tokio")]
    common::install_log_capture();
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
