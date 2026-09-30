//! A signal refused for privilege, on a real setuid-root child (`COSCA_TEST_SETUID` group; see
//! [`crate::test_privilege::setuid_helper`]). The child has real uid 0, so the unprivileged test
//! process genuinely cannot signal it: the kernel answers `EPERM` from its own permission rule.

use std::io::Read as _;

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

/// A root-uid child that has announced `ready`, and the stdin whose EOF ends it.
fn root_child(helper: &std::path::Path) -> (crate::Child, std::io::PipeWriter) {
    child_with(helper, "root")
}

/// A `setuid-stdin-block` child with the credentials `mode` names (see the testbin), ready.
fn child_with(helper: &std::path::Path, mode: &str) -> (crate::Child, std::io::PipeWriter) {
    let mut cmd = crate::Command::new();
    cmd.executable(helper)
        .args(["cosca_testbin", "setuid-stdin-block", mode]);
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::pipe()).expect("set stdout pipe");
    let mut child = cmd.spawn().expect("spawn the setuid helper");
    let stdin = child.stdin().expect("piped stdin");
    let mut ready = [0u8; 6];
    child
        .stdout()
        .expect("piped stdout")
        .read_exact(&mut ready)
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

// A live root child =====

#[test]
fn kill_of_a_live_root_child_is_unkillable_and_says_still_running() {
    let Some(helper) = setuid_helper() else { return };
    let (mut child, stdin) = root_child(&helper);
    child.set_elevation(wrapped());
    assert_unkillable_still_running(&child.kill().expect_err("root ignores the caller"));
    drop(stdin);
    child.wait().expect("reap");
}

#[test]
fn terminate_of_a_live_root_child_is_unkillable_and_says_still_running() {
    let Some(helper) = setuid_helper() else { return };
    let (mut child, stdin) = root_child(&helper);
    child.set_elevation(wrapped());
    assert_unkillable_still_running(&child.terminate().expect_err("root ignores the caller"));
    drop(stdin);
    child.wait().expect("reap");
}

// The cooperative half fails first and nothing is waited for or killed.
#[test]
fn graceful_shutdown_of_a_live_root_child_is_unkillable() {
    let Some(helper) = setuid_helper() else { return };
    let (mut child, stdin) = root_child(&helper);
    child.set_elevation(wrapped());
    let err = child
        .graceful_shutdown(std::time::Duration::ZERO)
        .expect_err("root ignores the caller");
    assert_unkillable_still_running(&err);
    drop(stdin);
    child.wait().expect("reap");
}

// Not a wrapper-elevated child: the refusal stays a plain `Io`.
#[test]
fn a_live_root_child_that_no_wrapper_elevated_stays_io() {
    let Some(helper) = setuid_helper() else { return };
    for via in [
        None,
        report(crate::elevation::ElevatedVia::AlreadyElevated),
        report(crate::elevation::ElevatedVia::MacosOsascript),
    ] {
        let (mut child, stdin) = root_child(&helper);
        child.set_elevation(via);
        assert_plain_permission_denied(&child.kill().expect_err("root ignores the caller"));
        assert_plain_permission_denied(&child.terminate().expect_err("root ignores the caller"));
        drop(stdin);
        child.wait().expect("reap");
    }
}

// An exited root child =====

// Linux answers `EPERM` for a root-owned zombie too, so this is the case where the refusal is not
// about privilege at all. `kill`'s doc: `Ok` if already dead.
#[test]
fn an_exited_unreaped_root_child_is_ok_for_kill_and_terminate() {
    let Some(helper) = setuid_helper() else { return };
    for via in [wrapped(), None] {
        let (mut child, stdin) = root_child(&helper);
        child.set_elevation(via);
        drop(stdin);
        assert!(
            crate::wait::block_until_exit(child.id(), None).expect("watch the exit"),
            "exited"
        );
        child.kill().expect("kill of an exited child");
        child.terminate().expect("terminate of an exited child");
        child.wait().expect("reap");
    }
}

// A filter's `EPERM`, not a privilege refusal =====

// The kernel's rule compares the sender's uids with the target's REAL and SAVED uids, never its
// effective one. These children are root by effective uid, yet the rule permits the signal, so an
// `EPERM` there is a filter's: `Unsupported`. Mutants: the rule reading the target's euid, only
// its ruid, or only its suid.
#[test]
fn a_filtered_signal_to_a_child_the_kernel_would_allow_is_unsupported_whatever_its_euid() {
    let Some(helper) = setuid_helper() else { return };
    for mode in ["euid-only", "suid-only"] {
        let (child, stdin) = child_with(&helper, mode);
        let err = crate::test_seccomp::with_denied(&[libc::SYS_kill], || child.kill().expect_err("the filter refuses"));
        assert!(matches!(err, Error::Unsupported { .. }), "{mode}: got {err:?}");
        let killed = child.kill();
        killed.expect("the caller may signal a child whose real or saved uid is its own");
        drop(stdin);
        child.wait().expect("reap");
    }
}
