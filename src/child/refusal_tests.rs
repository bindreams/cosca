//! A signal the OS refuses, on a real Linux child: a seccomp filter's `EPERM` (the kernel's own
//! permission rule would allow it) is `Unsupported` naming the syscall, never `Unkillable`; an
//! already-exited child is `Ok` whatever refuses the signal.

use crate::error::Error;
use crate::refusal::linux::SignalCall;
use crate::test_seccomp::with_denied;

fn wrapped() -> Option<crate::elevation::ElevationReport> {
    Some(crate::elevation::ElevationReport {
        via: crate::elevation::ElevatedVia::Wrapped(crate::elevation::Backend::Pkexec),
        stripped_env: Vec::new(),
        stdio: crate::elevation::ElevatedStdio::Passthrough,
    })
}

/// Every elevation report the refusal must not depend on.
fn reports() -> [Option<crate::elevation::ElevationReport>; 2] {
    [None, wrapped()]
}

fn blocker() -> (crate::Child, std::io::PipeWriter) {
    crate::test_child::held_contained_blocker(crate::Stdio::pipe())
}

/// Ends a blocker the test still holds and reaps it. Runs OUTSIDE the filtered thread.
fn cleanup(child: crate::Child, stdin: std::io::PipeWriter) {
    drop(stdin);
    child.wait().expect("reap");
}

fn assert_unsupported_naming(err: &Error, call: SignalCall) {
    let (name, op) = match call {
        SignalCall::Kill => ("kill", "kill a child process"),
        SignalCall::PidfdKill => ("pidfd_send_signal", "kill a process"),
        SignalCall::PidfdTerminate => ("pidfd_send_signal", "terminate a process"),
    };
    match err {
        Error::Unsupported {
            op: got_op,
            platform,
            detail,
        } => {
            assert_eq!(*platform, "linux");
            assert_eq!(got_op, op);
            assert!(
                detail.contains(&format!("refused here: {name} answered EPERM")),
                "{detail}"
            );
        }
        other => panic!("expected Unsupported naming {name}, got {other:?}"),
    }
}

// A filter refusing `pidfd_send_signal` on an own-uid child =====

#[test]
fn terminate_refused_by_a_filter_is_unsupported_naming_pidfd_send_signal() {
    for report in reports() {
        let (err, child, stdin) = with_denied(&[libc::SYS_pidfd_send_signal], move || {
            let (mut child, stdin) = blocker();
            child.set_elevation(report);
            let err = child.terminate().expect_err("the filter refuses the signal");
            (err, child, stdin)
        });
        assert_unsupported_naming(&err, SignalCall::PidfdTerminate);
        cleanup(child, stdin);
    }
}

#[test]
fn kill_refused_by_a_filter_is_unsupported_naming_kill() {
    for report in reports() {
        let (err, child, stdin) = with_denied(&[libc::SYS_kill], move || {
            let (mut child, stdin) = blocker();
            child.set_elevation(report);
            let err = child.kill().expect_err("the filter refuses the signal");
            (err, child, stdin)
        });
        assert_unsupported_naming(&err, SignalCall::Kill);
        cleanup(child, stdin);
    }
}

// The escalation kill is `kill`, so it reports the same.
#[test]
fn graceful_shutdown_escalation_refused_by_a_filter_is_unsupported_naming_kill() {
    let (err, child, stdin) = with_denied(&[libc::SYS_kill], || {
        let (mut child, stdin) = crate::test_child::term_ignoring_blocker();
        child.set_elevation(wrapped());
        let err = child
            .graceful_shutdown(std::time::Duration::ZERO)
            .expect_err("the escalation is refused");
        (err, child, stdin)
    });
    assert_unsupported_naming(&err, SignalCall::Kill);
    cleanup(child, stdin);
}

// A refused pidfd_open is a refused pidfd_open, whoever the child is =====

// `terminate` reaches `pidfd_open` first. Its `EPERM` is not the signal's, so it is never
// `Unkillable`, even on a wrapper-elevated child.
#[test]
fn a_refused_pidfd_open_is_unsupported_naming_pidfd_open_not_unkillable() {
    use crate::wait::backend::fault::force_pidfd_open_errno_once;
    for (errno, name) in [
        (rustix::io::Errno::PERM, "EPERM"),
        (rustix::io::Errno::ACCESS, "EACCES"),
        (rustix::io::Errno::NODEV, "ENODEV"),
    ] {
        let (mut child, stdin) = blocker();
        child.set_elevation(wrapped());
        let forced = force_pidfd_open_errno_once(errno);
        let err = child.terminate().expect_err("pidfd_open is refused");
        drop(forced);
        match &err {
            Error::Unsupported { platform, detail, .. } => {
                assert_eq!(*platform, "linux");
                assert!(
                    detail.contains(&format!("refused here: pidfd_open answered {name}")),
                    "{detail}"
                );
            }
            other => panic!("expected Unsupported for {name}, got {other:?}"),
        }
        cleanup(child, stdin);
    }
}

// An exited child is Ok whatever refuses the signal =====

// A filter refuses both signal syscalls, yet an unreaped zombie is `Ok`: the kernel would have
// answered success for it, so the refusal is not about the child.
#[test]
fn an_exited_unreaped_child_is_ok_even_when_a_filter_refuses_the_signal() {
    for report in reports() {
        let (results, child) = with_denied(&[libc::SYS_pidfd_send_signal, libc::SYS_kill], move || {
            let (mut child, stdin) = blocker();
            child.set_elevation(report);
            drop(stdin);
            assert!(
                crate::wait::block_until_exit(child.id(), None).expect("watch the exit"),
                "exited"
            );
            let results = (child.terminate(), child.kill());
            (results, child)
        });
        results.0.expect("terminate of an exited child");
        results.1.expect("kill of an exited child");
        child.wait().expect("reap");
    }
}
