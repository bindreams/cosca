//! Async twins of `child::refusal_tests`. The whole test runs on the filtered thread's own runtime:
//! a tokio child is bound to the reactor that spawned it.

use std::future::Future;

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

fn reports() -> [Option<crate::elevation::ElevationReport>; 2] {
    [None, wrapped()]
}

/// Run the future `make` builds on a current-thread runtime of a thread whose filter fails
/// `syscalls` with `EPERM`.
fn run<F: Future>(syscalls: &[i64], make: impl FnOnce() -> F + Send) -> F::Output
where
    F::Output: Send,
{
    with_denied(syscalls, || {
        ::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(make())
    })
}

/// Ends the blocker by EOF and reaps it.
async fn finish(mut child: crate::tokio::Child, stdin: crate::tokio::ChildStdin) {
    drop(stdin);
    child.wait().await.expect("reap");
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

#[test]
fn async_terminate_refused_by_a_filter_is_unsupported_naming_pidfd_send_signal() {
    for report in reports() {
        let err = run(&[libc::SYS_pidfd_send_signal], move || async move {
            let (mut child, stdin) = crate::test_child::held_contained_blocker_async(crate::Stdio::pipe());
            child.set_elevation(report);
            let err = child.terminate().expect_err("the filter refuses the signal");
            finish(child, stdin).await;
            err
        });
        assert_unsupported_naming(&err, SignalCall::PidfdTerminate);
    }
}

#[test]
fn async_kill_refused_by_a_filter_is_unsupported_naming_kill() {
    for report in reports() {
        let err = run(&[libc::SYS_kill], move || async move {
            let (mut child, stdin) = crate::test_child::held_contained_blocker_async(crate::Stdio::pipe());
            child.set_elevation(report);
            let err = child.kill().expect_err("the filter refuses the signal");
            finish(child, stdin).await;
            err
        });
        assert_unsupported_naming(&err, SignalCall::Kill);
    }
}

#[test]
fn async_graceful_shutdown_escalation_refused_by_a_filter_is_unsupported_naming_kill() {
    let err = run(&[libc::SYS_kill], || async {
        let (mut child, stdin) = crate::test_child::term_ignoring_blocker_async().await;
        child.set_elevation(wrapped());
        let err = child
            .graceful_shutdown(std::time::Duration::ZERO)
            .await
            .expect_err("the escalation is refused");
        finish(child, stdin).await;
        err
    });
    assert_unsupported_naming(&err, SignalCall::Kill);
}

#[test]
fn async_an_exited_unreaped_child_is_ok_even_when_a_filter_refuses_the_signal() {
    for report in reports() {
        let (terminated, killed) = run(&[libc::SYS_pidfd_send_signal, libc::SYS_kill], move || async move {
            let (mut child, stdin) = crate::test_child::held_contained_blocker_async(crate::Stdio::pipe());
            child.set_elevation(report);
            drop(stdin);
            assert!(
                crate::wait::block_until_exit(child.id(), None).expect("watch the exit"),
                "exited"
            );
            let results = (child.terminate(), child.kill());
            child.wait().await.expect("reap");
            results
        });
        terminated.expect("terminate of an exited child");
        killed.expect("kill of an exited child");
    }
}
