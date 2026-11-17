//! Async twin of `child/ctrl_break_proxy_tests.rs`: the async default stop through the real console-event
//! proxy, in the same `CTRL_PROXY` group. A wrong proxy sends Ctrl+C or Ctrl+Break to every process on
//! the console it attached to, so these run on CI, and a host runs them only after consenting
//! (`COSCA_TEST_CTRL_PROXY_CONSENT=1`) or turns them off (`COSCA_TEST_CTRL_PROXY=0`).
//!
//! Each asserts the recorded answer of the proxy before it reads a member's evidence, so a stop that sent
//! nothing fails by assertion.

use std::time::Duration;

use super::ctrl_break_tests::{Call, CALLS};
use crate::stop::proxy::protocol::{CtrlEvent, ProxyAnswer};
use crate::test_child::ctrl_break::{
    assert_acked_event, assert_proxy_answered, kill_release_reap_async, spawn_member_async, Handler,
    STATUS_CONTROL_C_EXIT,
};
use crate::test_groups::{ctrl_proxy, Group};
use crate::tokio::test_runtime::assert_current_thread;
use crate::ContainMode;

/// The call on `child`, which only the break ends: the root's status once the call has ended it, with
/// the proxy's answer asserted as soon as the call sent (a graceful call, in the hook after its stop).
/// The graceful calls' 30 s grace is a failure bound, not the condition under test: the break ends the
/// root within milliseconds, and a root that outlives the grace is killed, so a status other than
/// [`STATUS_CONTROL_C_EXIT`] fails the caller's assertion.
async fn ending(call: Call, child: &mut crate::tokio::Child) -> std::process::ExitStatus {
    let pid = child.pid();
    let answered = move || assert_proxy_answered(pid, CtrlEvent::CtrlBreak, ProxyAnswer::Sent);
    if call.escalates() {
        let check = crate::graceful_hooks::at_checked(crate::graceful_hooks::HookPoint::AfterTerminate, answered);
        let status = call.run(child, Duration::from_secs(30)).await;
        check.assert_fired();
        status
            .unwrap_or_else(|e| panic!("{call:?}: {e:?}"))
            .expect("a graceful call answers a status")
    } else {
        call.run(child, Duration::ZERO)
            .await
            .unwrap_or_else(|e| panic!("{call:?}: {e:?}"));
        answered();
        child.wait().await.expect("reap the root")
    }
}

/// Every call, on a fresh contained root that has a console of its own and no handler, ends the root
/// with the break the proxy sent.
async fn assert_default_stops_through_the_proxy(mode: ContainMode) {
    assert_current_thread();
    for call in CALLS {
        let (mut child, _sock, _) =
            spawn_member_async(Handler::Default, None, Some(mode), |cmd| _ = cmd.no_window()).await;
        let status = ending(call, &mut child).await;
        assert_eq!(
            status.code(),
            Some(STATUS_CONTROL_C_EXIT),
            "{mode:?} {call:?}: the root must die to the break, got {status:?}"
        );
    }
}

/// Async twin of the sync `a_no_window_contained_root_is_stopped_through_the_proxy`: no runtime thread
/// blocks on the proxy. Mutants: the async default calls the blocking send; it sends the direct break.
#[skuld::test]
async fn an_async_no_window_contained_root_is_stopped_through_the_proxy(#[fixture(ctrl_proxy)] _group: &Group) {
    assert_default_stops_through_the_proxy(ContainMode::Strongest).await;
}

/// As [`an_async_no_window_contained_root_is_stopped_through_the_proxy`], under the tree walk.
#[skuld::test]
async fn an_async_treewalk_contained_root_is_stopped_through_the_proxy(#[fixture(ctrl_proxy)] _group: &Group) {
    assert_default_stops_through_the_proxy(ContainMode::TreeWalk).await;
}

/// Async twin of the sync `an_uncontained_no_window_child_is_stopped_through_the_proxy`.
#[skuld::test]
async fn an_async_uncontained_no_window_child_is_stopped_through_the_proxy(#[fixture(ctrl_proxy)] _group: &Group) {
    assert_current_thread();
    let (mut child, mut sock, _) = spawn_member_async(Handler::AckEvent, None, None, |cmd| _ = cmd.no_window()).await;
    Call::Terminate
        .run(&mut child, Duration::ZERO)
        .await
        .expect("terminate through the proxy");
    assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::Sent);
    assert_acked_event(&mut sock, "the member", CtrlEvent::CtrlBreak);
    kill_release_reap_async(&mut child, sock, false).await;
}
