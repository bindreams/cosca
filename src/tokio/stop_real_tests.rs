//! The async stop through the real console-event proxy: the async twins of `stop/proxy_real_tests.rs`, in the
//! same `CTRL_PROXY` group. A wrong proxy sends Ctrl+C or Ctrl+Break to every process on the console it
//! attached to, so these run on CI, and a host runs them only after consenting
//! (`COSCA_TEST_CTRL_PROXY_CONSENT=1`) or turns them off (`COSCA_TEST_CTRL_PROXY=0`).
//!
//! Each asserts the recorded answer of the proxy before it reads a member's ack, so a stop that sent nothing
//! fails by assertion.

use std::time::Duration;

use crate::stop::proxy::protocol::{CtrlEvent, ProxyAnswer};
use crate::test_child::ctrl_break::{
    assert_acked_event, assert_proxy_answered, kill_release_reap_async, spawn_member_async, Handler,
    STATUS_CONTROL_C_EXIT,
};
use crate::test_groups::{ctrl_proxy, Group};
use crate::tokio::stop::{self, StopFuture};
use crate::tokio::test_runtime::{assert_current_thread, never_blocking};
use crate::{ContainMode, StopTarget};

/// An action that sends `event` through the proxy.
fn through_the_proxy(
    event: CtrlEvent,
) -> impl for<'t, 'c> Fn(&'t StopTarget<'c>) -> StopFuture<'t> + Send + Sync + 'static {
    move |target| Box::pin(stop::send_console_event_via_proxy(target, event))
}

/// Makes `cmd`'s child stop by sending `event` through the proxy, and gives it a console of its own.
fn stops_through_the_proxy(cmd: &mut crate::tokio::Command, event: CtrlEvent) {
    cmd.no_window();
    cmd.graceful_stop(through_the_proxy(event));
}

/// Ctrl+Break to a contained child with a console of its own, which no group of the caller's reaches.
/// Mutant: the stop sends Ctrl+C for Ctrl+Break (the ack is `C`), sends nothing, or waits for the proxy
/// with a blocking wait.
#[skuld::test]
async fn async_the_proxy_delivers_ctrl_break_to_a_no_window_child(#[fixture(ctrl_proxy)] _group: &Group) {
    assert_current_thread();
    let (mut child, mut sock, _) = spawn_member_async(Handler::AckEvent, None, Some(ContainMode::Strongest), |cmd| {
        stops_through_the_proxy(cmd, CtrlEvent::CtrlBreak)
    })
    .await;
    never_blocking(child.terminate())
        .await
        .expect("terminate through the proxy");
    assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::Sent);
    assert_acked_event(&mut sock, "the member", CtrlEvent::CtrlBreak);
    kill_release_reap_async(&mut child, sock, false).await;
}

/// The tree calls take the proxy's answer as the direct send's: `terminate_tree` ends a root and a
/// grandchild on its console that have no handler, and `graceful_shutdown_tree` does the same within its
/// grace. Mutants: a tree target does not take the route (nothing reaches the grandchild); the answer is
/// not recorded.
#[skuld::test]
async fn async_the_tree_calls_use_the_proxy_too(#[fixture(ctrl_proxy)] _group: &Group) {
    assert_current_thread();
    let (mut child, _sock, grand) = spawn_member_async(
        Handler::Default,
        Some(Handler::Default),
        Some(ContainMode::Strongest),
        |cmd| stops_through_the_proxy(cmd, CtrlEvent::CtrlBreak),
    )
    .await;
    let grand = grand.expect("a grandchild was asked for");
    never_blocking(child.terminate_tree())
        .await
        .expect("terminate_tree through the proxy");
    assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::Sent);
    assert_eq!(grand.exit.wait_for_exit_code(), STATUS_CONTROL_C_EXIT, "the grandchild");
    assert_eq!(
        child.wait().await.expect("reap the root").code(),
        Some(STATUS_CONTROL_C_EXIT),
        "the root"
    );

    let (mut child, _sock, grand) = spawn_member_async(
        Handler::Default,
        Some(Handler::Default),
        Some(ContainMode::Strongest),
        |cmd| stops_through_the_proxy(cmd, CtrlEvent::CtrlBreak),
    )
    .await;
    let grand = grand.expect("a grandchild was asked for");
    let pid = child.pid();
    let check = crate::graceful_hooks::at_checked(crate::graceful_hooks::HookPoint::AfterTerminate, move || {
        assert_proxy_answered(pid, CtrlEvent::CtrlBreak, ProxyAnswer::Sent)
    });
    let status = never_blocking(child.graceful_shutdown_tree(Duration::from_secs(30)))
        .await
        .expect("graceful_shutdown_tree through the proxy");
    check.assert_fired();
    assert_eq!(status.code(), Some(STATUS_CONTROL_C_EXIT), "the root, got {status:?}");
    assert_eq!(grand.exit.wait_for_exit_code(), STATUS_CONTROL_C_EXIT, "the grandchild");
}
