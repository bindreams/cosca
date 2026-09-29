//! `pidfd_open` refused by a real seccomp filter is `Unsupported` in the policy's message shape.
//! The unit tests force the errno through a seam; these tests make the kernel answer it.
#![cfg(target_os = "linux")]

use std::time::Duration;

use cosca::error::Error;

#[path = "common/mod.rs"]
mod common;

const REFUSALS: [(i32, &str); 4] = [
    (libc::EPERM, "EPERM"),
    (libc::EACCES, "EACCES"),
    (libc::ENODEV, "ENODEV"),
    (libc::ENOSYS, "ENOSYS"),
];

fn assert_refused(result: Result<impl std::fmt::Debug, Error>, op: &str, errno: &str) {
    match result {
        Err(e @ Error::Unsupported { .. }) => assert_eq!(
            e.to_string(),
            format!(
                "{op} is not supported on linux: cosca requires pidfd_open (Linux \u{2265} 5.3), \
                 refused here: pidfd_open answered {errno}"
            )
        ),
        other => panic!("{op} under a pidfd_open answering {errno} must be Unsupported, got {other:?}"),
    }
}

/// Mutants: an errno missing from the refusals; an op named as another; the message shape;
/// `Child::kill` routed through `pidfd_open`.
#[test]
fn a_seccomp_refused_pidfd_open_is_unsupported_for_every_operation() {
    for (code, name) in REFUSALS {
        let (child, _control) = common::spawn_blocker();
        let process = cosca::Process::from_pid(child.id().pid())
            .found()
            .expect("resolve the child");
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    common::seccomp::deny_pidfd_open_on_this_thread(code);
                    assert_refused(process.wait(), "process wait", name);
                    assert_refused(process.wait_timeout(Duration::ZERO), "process wait", name);
                    assert_refused(process.kill(), "process kill", name);
                    assert_refused(process.terminate(), "process terminate", name);
                    assert_refused(process.graceful_shutdown(Duration::ZERO), "process terminate", name);
                    assert_refused(child.terminate(), "process terminate", name);
                    assert_refused(child.graceful_shutdown(Duration::ZERO), "process terminate", name);
                    // An owned child is killed through its own handle: no pidfd, so no refusal.
                    child.kill().expect("Child::kill needs no pidfd_open");
                })
                .join()
                .expect("the filtered thread");
        });
        child.kill().expect("kill the child");
        child.wait().expect("reap the child");
    }
}

#[cfg(feature = "tokio")]
#[test]
fn a_seccomp_refused_pidfd_open_is_unsupported_for_every_async_operation() {
    for (code, name) in REFUSALS {
        let (child, _control) = common::spawn_blocker();
        let process = cosca::tokio::Process::from_pid(child.id().pid())
            .found()
            .expect("resolve the child");
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    common::seccomp::deny_pidfd_open_on_this_thread(code);
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("runtime");
                    runtime.block_on(async {
                        assert_refused(process.wait().await, "process wait", name);
                        assert_refused(
                            process.wait_timeout(Duration::from_secs(60)).await,
                            "process wait",
                            name,
                        );
                        assert_refused(process.kill(), "process kill", name);
                        assert_refused(process.terminate(), "process terminate", name);
                        assert_refused(
                            process.graceful_shutdown(Duration::ZERO).await,
                            "process terminate",
                            name,
                        );
                    });
                })
                .join()
                .expect("the filtered thread");
        });
        child.kill().expect("kill the child");
        child.wait().expect("reap the child");
    }
}
