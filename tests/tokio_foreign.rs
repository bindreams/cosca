//! Async foreign `Process` integration tests — mirrors tests/process.rs and the process_*
//! cases of tests/graceful.rs. Same death-proof discipline: control-socket EOF or an
//! inspected ExitStatus on an OWNED handle — never sleep/poll/wall-clock.

#[cfg(feature = "tokio")]
#[path = "common/mod.rs"]
mod common;

#[cfg(feature = "tokio")]
use cosca::tokio::Process;

#[cfg(feature = "tokio")]
#[skuld::test]
async fn async_foreign_wait_resolves_on_exit() {
    let (child, sock) = common::spawn_blocker();
    let p = Process::open_pid(child.id().pid()).expect("open").expect("running");
    let watch = ::tokio::spawn(async move { p.wait().await });
    child.kill().expect("kill");
    // Released after the kill: a kill that sent nothing exits 0.
    drop(sock);
    watch
        .await
        .expect("join")
        .expect("foreign wait resolves on the real exit");
    common::assert_killed("the killed child", child.wait().expect("reap"));
}

#[cfg(feature = "tokio")]
#[skuld::test]
async fn async_foreign_wait_timeout_zero_is_deterministic() {
    let (child, sock) = common::spawn_blocker();
    let p = Process::open_pid(child.id().pid()).expect("open").expect("running");
    assert!(
        !p.wait_timeout(std::time::Duration::ZERO).await.expect("poll"),
        "live child at ZERO"
    );
    common::kill_release_reap(&child, sock);
}

#[cfg(feature = "tokio")]
#[skuld::test]
async fn async_foreign_wait_timeout_observes_an_exit() {
    let (child, sock) = common::spawn_blocker();
    let p = Process::open_pid(child.id().pid()).expect("open").expect("running");
    child.kill().expect("kill");
    // Released after the kill: a kill that sent nothing exits 0. The exit is waited for first, so
    // `wait_timeout` observes an exit that already happened.
    drop(sock);
    common::assert_killed("the killed child", common::exit_status_once_exited(child.id().pid()));
    assert!(
        p.wait_timeout(std::time::Duration::from_secs(30)).await.expect("wait"),
        "exited child must report exited (30 s is the failure bound)"
    );
    common::assert_killed("the killed child", child.wait().expect("reap"));
}

/// Two waits pending at once on one handle (`&self`, so `select!`, `join!` and shared `Arc`s all
/// reach it) both resolve on the exit. Mutant: each wait registers the one held descriptor itself,
/// so the second registration fails (Linux) or displaces the first's wake (macOS).
#[cfg(feature = "tokio")]
#[skuld::test]
async fn async_foreign_concurrent_waits_both_resolve_on_exit() {
    use std::future::{poll_fn, Future};
    use std::pin::pin;
    use std::task::Poll;
    use std::time::Duration;

    let (child, sock) = common::spawn_blocker();
    let p = Process::open_pid(child.id().pid()).expect("open").expect("running");
    // 30 s is the failure bound of the exit this test causes, not a synchronisation delay.
    let mut first = pin!(p.wait());
    let mut second = pin!(p.wait_timeout(Duration::from_secs(30)));
    // Both are registered and pending before the kill.
    poll_fn(|cx| {
        assert!(first.as_mut().poll(cx).is_pending(), "a live process waits");
        assert!(second.as_mut().poll(cx).is_pending(), "a live process waits");
        Poll::Ready(())
    })
    .await;
    child.kill().expect("kill");
    // Released after the kill: a kill that sent nothing exits 0.
    drop(sock);
    let (first, second) = ::tokio::join!(first, second);
    first.expect("the first wait resolves on the real exit");
    assert!(second.expect("the second wait"), "the second wait sees the exit");
    common::assert_killed("the killed child", child.wait().expect("reap"));
}

#[cfg(feature = "tokio")]
#[skuld::test]
async fn async_foreign_introspection_delegates() {
    let (child, sock) = common::spawn_blocker();
    let p = Process::open_pid(child.id().pid()).expect("open").expect("running");
    assert_eq!(p.id(), child.id());
    assert_eq!(p.is_alive(), cosca::identity::Liveness::Alive);
    assert_eq!(Process::open(p.id()).expect("open").expect("running").id(), p.id());
    assert_eq!(p.id().exists(), cosca::identity::Existence::Present);
    common::kill_release_reap(&child, sock);
}

#[cfg(feature = "tokio")]
#[skuld::test]
async fn async_foreign_kill_terminates_the_process() {
    let (child, sock) = common::spawn_blocker();
    let p = Process::open_pid(child.id().pid()).expect("open").expect("running");
    p.kill().expect("foreign kill");
    // Release after the kill: a kill that sent nothing lets it exit 0, failing the status assertion.
    drop(sock);
    common::assert_killed("the killed child", child.wait().expect("reap"));
}

#[cfg(feature = "tokio")]
#[cfg(unix)]
#[skuld::test]
async fn async_foreign_terminate_sends_sigterm() {
    use std::os::unix::process::ExitStatusExt;
    let (child, sock) = common::spawn_blocker();
    let p = Process::open_pid(child.id().pid()).expect("open").expect("running");
    p.terminate().expect("foreign terminate");
    // Release after the kill: a kill that sent nothing lets it exit 0, failing the status assertion.
    drop(sock);
    let status = child.wait().expect("reap");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "got {status:?}");
}

#[cfg(feature = "tokio")]
#[cfg(unix)]
#[skuld::test]
async fn async_foreign_graceful_shutdown_escalates() {
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    // SIG_IGN child + ZERO grace: provably alive at the single poll => deterministic
    // escalation; SIGKILL is the only terminating signal it can receive.
    let (child, sock) = common::spawn_control("control-block-ignore-term", &["R"], false);
    let p = Process::open_pid(child.id().pid()).expect("open").expect("running");
    p.graceful_shutdown(Duration::ZERO).await.expect("foreign escalates");
    // Release after the kill: a kill that sent nothing lets it exit 0, failing the status assertion.
    drop(sock);
    let status = child.wait().expect("reap");
    assert_eq!(status.signal(), Some(libc::SIGKILL), "got {status:?}");
}

#[cfg(feature = "tokio")]
#[skuld::test]
async fn async_foreign_kill_tree_tears_down_tree() {
    let (child, socks) = common::spawn_tree_with("spawn-grandchild", false, |cmd| {
        cmd.env(common::ECHO_HELD_ENV, "1");
    });
    let [root, grand]: [_; 2] = socks.try_into().expect("a root and a grandchild socket");
    let (root, grand) = (
        common::Member::new(root, child.id().pid()),
        common::Member::new(grand, common::last_reported_grandchild().expect("the grandchild's pid")),
    );
    let p = Process::open_pid(child.id().pid()).expect("open").expect("running");
    p.kill_tree().expect("kill_tree");
    // A kill that sent nothing fails here by assertion.
    common::assert_members_killed(vec![(root, "the root"), (grand, "the grandchild")]);
    let _ = child.wait();
}

#[cfg(feature = "tokio")]
#[cfg(windows)]
#[skuld::test]
async fn async_foreign_unix_only_ops_are_unsupported_on_windows() {
    use std::time::Duration;
    let (child, sock) = common::spawn_blocker();
    let p = Process::open_pid(child.id().pid()).expect("open").expect("running");
    assert!(matches!(p.terminate(), Err(cosca::error::Error::Unsupported { .. })));
    assert!(matches!(
        p.graceful_shutdown(Duration::from_secs(1)).await,
        Err(cosca::error::Error::Unsupported { .. })
    ));
    assert!(matches!(
        p.terminate_tree(),
        Err(cosca::error::Error::Unsupported { .. })
    ));
    assert!(matches!(
        p.graceful_shutdown_tree(Duration::from_secs(1)).await,
        Err(cosca::error::Error::Unsupported { .. })
    ));
    common::kill_release_reap(&child, sock);
}

#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    #[cfg(feature = "tokio")]
    common::install_log_capture();
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
