//! Unit tests for the async builder mirror — assert the wrapped sync request records the
//! configured values (the integration suite only proves the spawn path).

use crate::containment::Nesting;
use crate::ContainMode;

#[test]
fn contain_with_and_nesting_recorded() {
    let mut cmd = super::Command::new();
    cmd.contain_with(ContainMode::TreeWalk).nesting(Nesting::Opaque);
    let req = cmd.inner.contain_request();
    assert_eq!(req.mode, Some(ContainMode::TreeWalk));
    assert_eq!(req.nesting, Nesting::Opaque);
}

#[test]
fn tokio_elevate_forwards_to_inner_request() {
    let mut c = super::Command::new();
    c.args(["id", "-u"]).elevation_backend(crate::elevation::Backend::Sudo);
    // command_tests is a child module of tokio::command, so it can read the private inner.
    let req = c.inner.elevation_request();
    assert!(req.enabled);
    assert_eq!(req.backend, crate::elevation::Backend::Sudo);
}

#[cfg(unix)]
#[tokio::test]
async fn tokio_child_elevation_is_none_without_elevate() {
    let mut c = super::Command::new();
    c.args(["true"]);
    let child = c.spawn().expect("spawn");
    assert!(child.elevation().is_none());
}

/// The async builder hand-mirrors the sync one and parity is not compiler-enforced (see this
/// module's own doc), so a delegate can silently go missing. This test pins that `raw_executable`
/// exists and forwards correctly.
///
/// Asserted over the RECORDED spec rather than "a method was called", so it also pins that the
/// delegate forwards to `raw_executable` and not to `executable`.
#[test]
fn tokio_raw_executable_records_an_exact_spec() {
    use crate::command::ExecutableSpec;
    use std::path::Path;

    let mut c = super::Command::new();
    c.raw_executable("helper");
    assert!(
        matches!(c.inner.executable_spec(), Some(ExecutableSpec::Exact(p)) if p == Path::new("helper")),
        "raw_executable must record Exact, got {:?}",
        c.inner.executable_spec()
    );

    // And the sibling setter still records Search through the same wrapper, so the two are not
    // accidentally wired to the same inner method.
    let mut s = super::Command::new();
    s.executable("helper");
    assert!(matches!(s.inner.executable_spec(), Some(ExecutableSpec::Search(_))));
}

/// Poll `future` once, and return what that poll gave.
async fn poll_once<F: std::future::Future>(future: F) -> std::task::Poll<F::Output> {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|cx| std::task::Poll::Ready(future.as_mut().poll(cx))).await
}

/// A spawn that `status`, `output` or `read` could not complete, and whose child refused the kill,
/// returns the child in `Error::Unreaped` from the first poll, as `spawn` does: nothing is awaited
/// while the error holds it. So a caller that drops the future after one poll never blocks, and no
/// task is left behind. The child stays running until the test ends it.
#[test]
fn a_run_to_completion_hands_back_an_unkillable_child_from_its_first_poll() {
    use crate::child::spawn::fault;
    use crate::error::Error;
    for method in ["status", "output", "read"] {
        let runtime = ::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut cmd = super::Command::new();
            #[cfg(unix)]
            cmd.args(["sleep", "300"]);
            #[cfg(windows)]
            cmd.args(["ping", "-n", "300", "127.0.0.1"]);
            fault::set_force_attach_failure(true);
            fault::set_force_kill_failure_leaving_child_alive("cosca-first-poll-handed-back-5b20");
            let polled = match method {
                "status" => poll_once(cmd.status()).await.map(|r| r.err()),
                "output" => poll_once(cmd.output()).await.map(|r| r.err()),
                _ => poll_once(cmd.read()).await.map(|r| r.err()),
            };
            fault::set_force_attach_failure(false);
            assert_eq!(
                fault::take_force_kill_failure(),
                None,
                "{method}: the kill failure was consumed"
            );
            let std::task::Poll::Ready(Some(Error::Unreaped { mut child, .. })) = polled else {
                panic!("{method}: the first poll must hand the child back, got {polled:?}");
            };
            assert_eq!(
                ::tokio::runtime::Handle::current().metrics().num_alive_tasks(),
                0,
                "{method}: no task was left behind"
            );
            let crate::identity::Resolved::Found(id) = crate::identity::ProcessId::of(child.pid()) else {
                panic!("{method}: the handed-back child is unreaped, so its identity resolves");
            };
            crate::wait::kill(id).expect("end the handed-back child");
            child.wait().await.expect("reap the handed-back child");
        });
    }
}
