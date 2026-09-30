//! Async twins of `child::setuid_tests`: a signal refused for privilege, on a real setuid-root
//! child (`COSCA_TEST_SETUID` group).

use ::tokio::io::AsyncReadExt as _;

use crate::error::{ElevationErrorKind, Error};
use crate::test_privilege::setuid_helper;

fn report(via: crate::elevation::ElevatedVia) -> Option<crate::elevation::ElevationReport> {
    Some(crate::elevation::ElevationReport {
        via,
        stripped_env: Vec::new(),
        stdio: crate::elevation::ElevatedStdio::Passthrough,
    })
}

fn wrapped() -> Option<crate::elevation::ElevationReport> {
    report(crate::elevation::ElevatedVia::Wrapped(
        crate::elevation::Backend::Pkexec,
    ))
}

async fn root_child(helper: &std::path::Path) -> (crate::tokio::Child, crate::tokio::ChildStdin) {
    let mut cmd = crate::tokio::Command::new();
    cmd.executable(helper).args(["cosca_testbin", "setuid-stdin-block"]);
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    let mut child = cmd.spawn().expect("spawn the setuid helper");
    let stdin = child.stdin().expect("piped stdin");
    let mut ready = [0u8; 6];
    child
        .stdout()
        .expect("piped stdout")
        .read_exact(&mut ready)
        .await
        .expect("the helper is root and says ready (else its stderr says why)");
    assert_eq!(&ready, b"ready\n");
    (child, stdin)
}

fn assert_unkillable_still_running(err: &Error) {
    match err {
        Error::Elevation {
            kind: ElevationErrorKind::Unkillable,
            detail,
        } => assert!(detail.contains("still running"), "{detail}"),
        other => panic!("expected Unkillable, got {other:?}"),
    }
}

fn assert_plain_permission_denied(err: &Error) {
    assert!(
        matches!(err, Error::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied),
        "got {err:?}"
    );
}

#[tokio::test]
async fn async_kill_of_a_live_root_child_is_unkillable_and_says_still_running() {
    let Some(helper) = setuid_helper() else { return };
    let (mut child, stdin) = root_child(&helper).await;
    child.set_elevation(wrapped());
    assert_unkillable_still_running(&child.kill().expect_err("root ignores the caller"));
    drop(stdin);
    child.wait().await.expect("reap");
}

#[tokio::test]
async fn async_terminate_of_a_live_root_child_is_unkillable_and_says_still_running() {
    let Some(helper) = setuid_helper() else { return };
    let (mut child, stdin) = root_child(&helper).await;
    child.set_elevation(wrapped());
    assert_unkillable_still_running(&child.terminate().expect_err("root ignores the caller"));
    drop(stdin);
    child.wait().await.expect("reap");
}

#[tokio::test]
async fn async_graceful_shutdown_of_a_live_root_child_is_unkillable() {
    let Some(helper) = setuid_helper() else { return };
    let (mut child, stdin) = root_child(&helper).await;
    child.set_elevation(wrapped());
    let err = child
        .graceful_shutdown(std::time::Duration::ZERO)
        .await
        .expect_err("root ignores the caller");
    assert_unkillable_still_running(&err);
    drop(stdin);
    child.wait().await.expect("reap");
}

#[tokio::test]
async fn async_a_live_root_child_that_no_wrapper_elevated_stays_io() {
    let Some(helper) = setuid_helper() else { return };
    for via in [
        None,
        report(crate::elevation::ElevatedVia::AlreadyElevated),
        report(crate::elevation::ElevatedVia::MacosOsascript),
    ] {
        let (mut child, stdin) = root_child(&helper).await;
        child.set_elevation(via);
        assert_plain_permission_denied(&child.kill().expect_err("root ignores the caller"));
        assert_plain_permission_denied(&child.terminate().expect_err("root ignores the caller"));
        drop(stdin);
        child.wait().await.expect("reap");
    }
}

#[tokio::test]
async fn async_an_exited_unreaped_root_child_is_ok_for_kill_and_terminate() {
    let Some(helper) = setuid_helper() else { return };
    for via in [wrapped(), None] {
        let (mut child, stdin) = root_child(&helper).await;
        child.set_elevation(via);
        drop(stdin);
        assert!(
            crate::wait::block_until_exit(child.id(), None).expect("watch the exit"),
            "exited"
        );
        child.kill().expect("kill of an exited child");
        child.terminate().expect("terminate of an exited child");
        child.wait().await.expect("reap");
    }
}
