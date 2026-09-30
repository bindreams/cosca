//! Async twins of `child::refusal_tests`. The whole test runs on the filtered thread's own runtime:
//! a tokio child is bound to the reactor that spawned it.

use std::future::Future;

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
