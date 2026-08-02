//! Async foreign `Process` integration tests — mirrors tests/process.rs and the process_*
//! cases of tests/graceful.rs. Same death-proof discipline: control-socket EOF or an
//! inspected ExitStatus on an OWNED handle — never sleep/poll/wall-clock.
#![cfg(feature = "tokio")]

#[path = "common/mod.rs"]
mod common;

use std::io::Read;

use cosca::tokio::Process;

fn expect_eof(who: &str, s: &mut std::net::TcpStream) {
    let mut buf = [0u8; 1];
    match s.read(&mut buf) {
        Ok(0) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("{who} not torn down: {other:?}"),
    }
}

#[tokio::test]
async fn async_foreign_wait_resolves_on_exit() {
    let (child, mut sock) = common::spawn_blocker();
    let p = Process::from_pid(child.id().pid()).found().expect("resolves");
    let watch = ::tokio::spawn(async move { p.wait().await });
    child.kill().expect("kill");
    expect_eof("blocker", &mut sock);
    watch
        .await
        .expect("join")
        .expect("foreign wait resolves on the real exit");
    let _ = child.wait();
}

#[tokio::test]
async fn async_foreign_wait_timeout_zero_is_deterministic() {
    let (child, _sock) = common::spawn_blocker();
    let p = Process::from_pid(child.id().pid()).found().expect("resolves");
    assert!(
        !p.wait_timeout(std::time::Duration::ZERO).await.expect("poll"),
        "live child at ZERO"
    );
    child.kill().expect("cleanup");
    child.wait().expect("reap");
}

#[tokio::test]
async fn async_foreign_wait_timeout_observes_an_exit() {
    let (child, mut sock) = common::spawn_blocker();
    let p = Process::from_pid(child.id().pid()).found().expect("resolves");
    child.kill().expect("kill");
    expect_eof("blocker", &mut sock); // real exit event precedes the wait
    assert!(
        p.wait_timeout(std::time::Duration::from_secs(30)).await.expect("wait"),
        "exited child must report exited (30 s is the failure bound)"
    );
    child.wait().expect("reap");
}

#[tokio::test]
async fn async_foreign_introspection_delegates() {
    let (child, _sock) = common::spawn_blocker();
    let p = Process::from_pid(child.id().pid()).found().expect("resolves");
    assert_eq!(p.id(), child.id());
    assert_eq!(p.is_alive(), cosca::identity::Liveness::Alive);
    assert_eq!(Process::from_id(p.id()).id(), p.id());
    assert_eq!(Process::from_id(p.id()).exists(), cosca::identity::Existence::Present);
    child.kill().expect("cleanup");
    child.wait().expect("reap");
}

#[tokio::test]
async fn async_foreign_kill_terminates_the_process() {
    let (child, mut sock) = common::spawn_blocker();
    let p = Process::from_pid(child.id().pid()).found().expect("resolves");
    p.kill().expect("foreign kill");
    expect_eof("blocker", &mut sock);
    let status = child.wait().expect("reap");
    assert!(!status.success(), "killed child cannot report success, got {status:?}");
}

#[cfg(unix)]
#[tokio::test]
async fn async_foreign_terminate_sends_sigterm() {
    use std::os::unix::process::ExitStatusExt;
    let (child, mut sock) = common::spawn_blocker();
    let p = Process::from_pid(child.id().pid()).found().expect("resolves");
    p.terminate().expect("foreign terminate");
    expect_eof("blocker", &mut sock);
    let status = child.wait().expect("reap");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "got {status:?}");
}

#[cfg(unix)]
#[tokio::test]
async fn async_foreign_graceful_shutdown_graceful_path() {
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    let (child, mut sock) = common::spawn_blocker();
    let p = Process::from_pid(child.id().pid()).found().expect("resolves");
    p.graceful_shutdown(Duration::from_secs(30))
        .await
        .expect("foreign graceful");
    expect_eof("blocker", &mut sock);
    let status = child.wait().expect("reap"); // owned handle reaps; SIGTERM = graceful
    assert_eq!(status.signal(), Some(libc::SIGTERM), "got {status:?}");
}

#[cfg(unix)]
#[tokio::test]
async fn async_foreign_graceful_shutdown_escalates() {
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;
    // SIG_IGN child + ZERO grace: provably alive at the single poll => deterministic
    // escalation; SIGKILL is the only terminating signal it can receive.
    let (child, mut sock) = common::spawn_control("control-block-ignore-term", &["R"], false);
    let p = Process::from_pid(child.id().pid()).found().expect("resolves");
    p.graceful_shutdown(Duration::ZERO).await.expect("foreign escalates");
    expect_eof("blocker", &mut sock);
    let status = child.wait().expect("reap");
    assert_eq!(status.signal(), Some(libc::SIGKILL), "got {status:?}");
}

#[tokio::test]
async fn async_foreign_kill_tree_tears_down_tree() {
    let (child, mut socks) = common::spawn_grandchild(false);
    let p = Process::from_pid(child.id().pid()).found().expect("resolves");
    p.kill_tree().expect("kill_tree");
    for (i, s) in socks.iter_mut().enumerate() {
        let mut buf = [0u8; 1];
        match s.read(&mut buf) {
            Ok(0) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("tree member {i} not torn down: {other:?}"),
        }
    }
    let _ = child.wait();
}

#[cfg(unix)]
#[tokio::test]
async fn async_foreign_graceful_shutdown_tree_tears_down_tree() {
    use std::time::Duration;
    let (child, mut socks) = common::spawn_grandchild(false);
    let p = Process::from_pid(child.id().pid()).found().expect("resolves");
    p.graceful_shutdown_tree(Duration::from_secs(30))
        .await
        .expect("foreign tree graceful");
    for (i, s) in socks.iter_mut().enumerate() {
        let mut buf = [0u8; 1];
        match s.read(&mut buf) {
            Ok(0) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("tree member {i} not torn down: {other:?}"),
        }
    }
    let _ = child.wait();
}

#[cfg(windows)]
#[tokio::test]
async fn async_foreign_unix_only_ops_are_unsupported_on_windows() {
    use std::time::Duration;
    let (child, _sock) = common::spawn_blocker();
    let p = Process::from_pid(child.id().pid()).found().expect("resolves");
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
    child.kill().expect("cleanup");
    let _ = child.wait();
}
