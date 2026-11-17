//! Async twin of `child/ctrl_break_tests.rs`: the async cooperative ops' `CTRL_BREAK` reaches its
//! target, asserted sent before any wait for the member's evidence.

use std::net::TcpStream;
use std::time::Duration;

use crate::child::graceful::fault as term_fault;
use crate::containment::Containment;
use crate::error::Error;
use crate::stop::proxy::protocol::{CtrlEvent, ProxyAnswer};
use crate::stop::proxy::proxy_tests::Fixture;
use crate::test_child::ctrl_break::{
    self, assert_acked, assert_in_our_console, assert_proxy_answered, console_less, kill_release_reap_async,
    Grandchild, Handler, STATUS_CONTROL_C_EXIT,
};
use crate::tokio::test_runtime::never_blocking;
use crate::StopTarget;

async fn spawn_root(handler: Handler) -> (crate::tokio::Child, TcpStream) {
    spawn_root_configured(handler, crate::ContainMode::Strongest, |_| {}).await
}

/// [`spawn_root`] under `mode`, with `configure` applied to the root's command before the spawn.
async fn spawn_root_configured(
    handler: Handler,
    mode: crate::ContainMode,
    configure: impl FnOnce(&mut crate::tokio::Command),
) -> (crate::tokio::Child, TcpStream) {
    let (child, sock, _) = spawn(handler, None, mode, configure).await;
    (child, sock)
}

/// The root's socket keeps the root running while held.
async fn spawn_tree(root: Handler, grandchild: Handler) -> (crate::tokio::Child, TcpStream, Grandchild) {
    let (child, sock, grand) = spawn(root, Some(grandchild), crate::ContainMode::Strongest, |_| {}).await;
    (child, sock, grand.expect("a grandchild was asked for"))
}

async fn spawn(
    handler: Handler,
    grandchild: Option<Handler>,
    mode: crate::ContainMode,
    configure: impl FnOnce(&mut crate::tokio::Command),
) -> (crate::tokio::Child, TcpStream, Option<Grandchild>) {
    ctrl_break::spawn_member_async(handler, grandchild, Some(mode), configure).await
}

#[skuld::test]
async fn async_child_terminate_delivers_ctrl_break_to_a_contained_root() {
    let _warns = crate::log_capture::warn_watch();
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, mut sock) = spawn_root(Handler::Ack).await;
    assert!(StopTarget::from(&child.inner).leads_group_on_our_console());
    assert_in_our_console(child.pid(), "the root");
    child.terminate().await.expect("terminate a console-group child");
    ctrl_break::assert_break_sent_to(child.pid());
    assert_acked(&mut sock, "the root");
    assert_eq!(
        child.is_alive(),
        crate::identity::Liveness::Alive,
        "the root handles the break and keeps running"
    );
    kill_release_reap_async(&mut child, sock, false).await;
}

/// Async twin of the sync `an_uncontained_child_given_a_group_is_stopped_directly`: the setter on the
/// tokio `Command` reaches the child. Mutants: the tokio setter dropping the request (the call is
/// refused, not sent); the break sent to another group.
#[skuld::test]
async fn an_async_uncontained_child_given_a_group_is_stopped_directly() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, mut sock, _) =
        ctrl_break::spawn_member_async(Handler::Ack, None, None, |cmd| _ = cmd.new_process_group(true)).await;
    assert_eq!(child.containment(), Containment::None);
    assert!(StopTarget::from(&child.inner).leads_group_on_our_console());
    assert_in_our_console(child.pid(), "the child");
    child.terminate().await.expect("terminate a child created in a group");
    ctrl_break::assert_break_sent_to(child.pid());
    assert_acked(&mut sock, "the child");
    kill_release_reap_async(&mut child, sock, false).await;
}

#[skuld::test]
async fn an_async_plain_contained_root_really_receives_the_break() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, mut sock) = spawn_root(Handler::Ack).await;
    assert_eq!(child.containment(), Containment::JobObject);
    assert!(StopTarget::from(&child.inner).leads_group_on_our_console());
    assert_in_our_console(child.pid(), "the root");
    child
        .terminate_tree()
        .await
        .expect("terminate_tree on a contained root");
    ctrl_break::assert_break_sent_to(child.pid());
    assert_acked(&mut sock, "the root");
    kill_release_reap_async(&mut child, sock, true).await;
}

#[skuld::test]
async fn async_child_graceful_shutdown_tree_tears_down_tree_on_windows() {
    let _warns = crate::log_capture::warn_watch();
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, _root_sock, grand) = spawn_tree(Handler::Default, Handler::Default).await;
    let pid = child.pid();
    assert_in_our_console(pid, "the root");
    let check = term_fault::at_checked(term_fault::HookPoint::AfterTerminate, move || {
        ctrl_break::assert_break_sent_to(pid)
    });
    let status = child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .await
        .expect("graceful_shutdown_tree on a console-group root");
    check.assert_fired();
    assert_eq!(
        status.code(),
        Some(STATUS_CONTROL_C_EXIT),
        "the root must die to the break, got {status:?}"
    );
    assert_eq!(
        grand.exit.wait_for_exit_code(),
        STATUS_CONTROL_C_EXIT,
        "the grandchild must die to the break"
    );
}

/// Both members ignore the break, so only the ZERO-grace hard sweep can end the tree. The root's
/// socket is closed once the sweep returned, and the grandchild's after the root is reaped: a sweep
/// that sent nothing, or only to the root, yields code 0 for the member it missed.
#[skuld::test]
async fn async_graceful_shutdown_tree_sweep_is_load_bearing_on_windows() {
    let _warns = crate::log_capture::warn_watch();
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, root_sock, grand) = spawn_tree(Handler::Ignore, Handler::Ignore).await;
    assert_in_our_console(child.pid(), "the root");
    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, root_sock);
    let status = child
        .graceful_shutdown_tree(Duration::ZERO)
        .await
        .expect("tree escalates");
    assert_eq!(status.code(), Some(1), "the sweep ends the root, got {status:?}");
    assert_eq!(
        child.is_alive(),
        crate::identity::Liveness::Dead,
        "the sweep really ended the root"
    );
    let Grandchild { sock, exit } = grand;
    drop(sock);
    assert_eq!(exit.wait_for_exit_code(), 1, "the sweep must kill the grandchild");
}

// A child outside our group or console: the default asks the proxy =====
//
// The proxy here is the fixture of `stop::proxy::proxy_tests`: it answers what its name says and sends
// nothing, so none of these tests is in the `CTRL_PROXY` group. What a real proxy delivers is in
// `ctrl_break_proxy_tests.rs`. Each awaited call runs under `never_blocking`.

/// The four calls that run the child's stop action.
#[derive(Clone, Copy, Debug)]
pub(super) enum Call {
    Terminate,
    TerminateTree,
    GracefulShutdown,
    GracefulShutdownTree,
}

pub(super) const CALLS: [Call; 4] = [
    Call::Terminate,
    Call::TerminateTree,
    Call::GracefulShutdown,
    Call::GracefulShutdownTree,
];

impl Call {
    /// The call on `child`, with `grace` for a graceful one, which answers the root's status.
    pub(super) async fn run(
        self,
        child: &mut crate::tokio::Child,
        grace: Duration,
    ) -> Result<Option<std::process::ExitStatus>, Error> {
        never_blocking(async {
            match self {
                Call::Terminate => child.terminate().await.map(|()| None),
                Call::TerminateTree => child.terminate_tree().await.map(|()| None),
                Call::GracefulShutdown => child.graceful_shutdown(grace).await.map(Some),
                Call::GracefulShutdownTree => child.graceful_shutdown_tree(grace).await.map(Some),
            }
        })
        .await
    }

    /// Whether the call goes on to a kill when its stop did not end the root.
    pub(super) fn escalates(self) -> bool {
        matches!(self, Call::GracefulShutdown | Call::GracefulShutdownTree)
    }
}

/// A contained root that stops by the default, whose proxy is `fixture`, with `configure` applied to
/// its command last.
async fn root_stopping_through(
    fixture: &Fixture,
    mode: crate::ContainMode,
    configure: impl FnOnce(&mut crate::tokio::Command),
) -> (crate::tokio::Child, TcpStream) {
    spawn_root_configured(Handler::Ignore, mode, |cmd| {
        cmd.ctrl_proxy(fixture.setting());
        configure(cmd);
    })
    .await
}

/// The detail of an `Unsupported`; any other error is a panic.
fn unsupported_detail(err: &Error) -> &str {
    match err {
        Error::Unsupported { detail, .. } => detail,
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

/// Async twin of the sync `the_default_asks_the_proxy_for_a_no_window_contained_root`; see there.
#[skuld::test]
async fn the_async_default_asks_the_proxy_for_a_no_window_contained_root() {
    crate::tokio::test_runtime::assert_current_thread();
    for (mode, expected) in [
        (crate::ContainMode::Strongest, Containment::JobObject),
        (crate::ContainMode::TreeWalk, Containment::TreeWalk),
    ] {
        for call in CALLS {
            let fixture = Fixture::answering(ProxyAnswer::Sent.code());
            let (mut child, sock) = root_stopping_through(&fixture, mode, |cmd| _ = cmd.no_window()).await;
            assert_own_console_route(&child, expected);
            if call.escalates() {
                let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, sock);
                let status = call
                    .run(&mut child, Duration::ZERO)
                    .await
                    .unwrap_or_else(|e| panic!("{mode:?} {call:?}: {e:?}"))
                    .expect("a graceful call answers a status");
                assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::Sent);
                // The release comes after the kill, so a root the call did not kill leaves with 0.
                assert_eq!(
                    status.code(),
                    Some(1),
                    "{mode:?} {call:?}: the escalation's kill: {status:?}"
                );
            } else {
                call.run(&mut child, Duration::ZERO)
                    .await
                    .unwrap_or_else(|e| panic!("{mode:?} {call:?}: {e:?}"));
                assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::Sent);
                kill_release_reap_async(&mut child, sock, false).await;
            }
        }
    }
}

/// Async twin of the sync `a_detached_contained_root_is_refused_for_having_no_console`; see there.
#[skuld::test]
async fn an_async_detached_contained_root_is_refused_for_having_no_console() {
    crate::tokio::test_runtime::assert_current_thread();
    for call in CALLS {
        let fixture = Fixture::answering(ProxyAnswer::TargetHasNoConsole.code());
        let (mut child, sock) =
            root_stopping_through(&fixture, crate::ContainMode::Strongest, |cmd| _ = cmd.detached()).await;
        let err = call
            .run(&mut child, Duration::ZERO)
            .await
            .expect_err("the call is refused");
        let detail = unsupported_detail(&err);
        assert!(detail.contains("answer TargetHasNoConsole"), "{call:?}: {detail}");
        let (kill, graceful_stop) = (detail.find("Child::kill"), detail.find("Command::graceful_stop"));
        assert!(
            matches!((kill, graceful_stop), (Some(k), Some(g)) if k < g),
            "{call:?}: the remedies, in order: {detail}"
        );
        assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::TargetHasNoConsole);
        assert_eq!(
            child.is_alive(),
            crate::identity::Liveness::Alive,
            "{call:?}: the call ended with the root running"
        );
        kill_release_reap_async(&mut child, sock, false).await;
    }
}

/// Async twin of the sync `a_child_on_our_console_without_a_group_is_refused_by_the_direct_send_without_the_proxy`;
/// see there.
#[skuld::test]
async fn an_async_child_on_our_console_without_a_group_is_refused_by_the_direct_send_without_the_proxy() {
    crate::tokio::test_runtime::assert_current_thread();
    for call in CALLS {
        let fixture = Fixture::answering(ProxyAnswer::Sent.code());
        let (mut child, sock) = root_stopping_through(&fixture, crate::ContainMode::Strongest, |cmd| {
            _ = cmd.new_process_group(false)
        })
        .await;
        assert_in_our_console(child.pid(), "the contained member");
        assert!(!StopTarget::from(&child.inner).leads_group_on_our_console());
        let err = call
            .run(&mut child, Duration::ZERO)
            .await
            .expect_err("the call is refused");
        ctrl_break::assert_refused_by_the_direct_send_for_no_group(&err);
        assert!(fixture.ran().is_none(), "{call:?}: the proxy was started");
        assert_eq!(
            child.is_alive(),
            crate::identity::Liveness::Alive,
            "{call:?}: the call ended with the root running"
        );
        kill_release_reap_async(&mut child, sock, false).await;
    }
}

/// Async twin of the sync `an_uncontained_child_on_our_console_is_refused_by_the_direct_send_without_the_proxy`.
#[skuld::test]
async fn an_async_uncontained_child_on_our_console_is_refused_by_the_direct_send_without_the_proxy() {
    crate::tokio::test_runtime::assert_current_thread();
    for call in [Call::Terminate, Call::GracefulShutdown] {
        let fixture = Fixture::answering(ProxyAnswer::Sent.code());
        let (mut child, sock, _) =
            ctrl_break::spawn_member_async(Handler::Ignore, None, None, |cmd| _ = cmd.ctrl_proxy(fixture.setting()))
                .await;
        assert_eq!(child.containment(), Containment::None);
        assert_in_our_console(child.pid(), "the uncontained member");
        assert!(!StopTarget::from(&child.inner).leads_group_on_our_console());
        let err = call
            .run(&mut child, Duration::ZERO)
            .await
            .expect_err("the call is refused");
        ctrl_break::assert_refused_by_the_direct_send_for_no_group(&err);
        assert!(fixture.ran().is_none(), "{call:?}: the proxy was started");
        assert_eq!(
            child.is_alive(),
            crate::identity::Liveness::Alive,
            "{call:?}: the call ended with the root running"
        );
        kill_release_reap_async(&mut child, sock, false).await;
    }
}

/// Async twin of `child::ctrl_break_tests::assert_own_console_route`: the async derivation must
/// read the composed creation-flag word too.
fn assert_own_console_route(child: &crate::tokio::Child, expected_containment: Containment) {
    assert_eq!(
        child.containment(),
        expected_containment,
        "this test is about the wrong thing if containment did not take"
    );
    let console = child.inner.console;
    assert!(
        console.group && console.own_console_flags && !StopTarget::from(&child.inner).leads_group_on_our_console(),
        "cosca's honest report of the route: a group in a console of its own, {console:?}"
    );
}

/// The fully-qualified libtest path of [`fixture_async_console_less_reporter`].
const CONSOLE_LESS_TEST: &str = "tokio::child::graceful::ctrl_break_tests::fixture_async_console_less_reporter";

/// Async twin of the sync `a_console_less_callers_default_asks_the_proxy_and_its_direct_send_has_no_console`:
/// from a caller with no console, the async default asks the proxy for every call, whose answers are the
/// proxy's. The checks run in a re-exec of this binary spawned detached. Mutant: `tokio::stop::default`
/// sends the direct break (`NoConsole`, and no proxy asked).
#[skuld::test]
fn an_async_console_less_callers_default_asks_the_proxy() {
    ctrl_break::drive_reporter(CONSOLE_LESS_TEST, console_less::ADDR_ENV, |cmd| _ = cmd.detached());
}

/// The reporter of [`an_async_console_less_callers_default_asks_the_proxy`], inert unless that test
/// spawned it.
#[skuld::test]
async fn fixture_async_console_less_reporter() {
    let Some(mut report) = ctrl_break::connect_reporter(console_less::ADDR_ENV) else {
        return;
    };
    console_less::assert_no_console();
    for call in CALLS {
        let fixture = Fixture::answering(ProxyAnswer::Sent.code());
        let (mut child, sock) = ctrl_break::spawn_gui_root_async(|cmd| _ = cmd.ctrl_proxy(fixture.setting())).await;
        assert!(
            !StopTarget::from(&child.inner).leads_group_on_our_console(),
            "the caller had no console at the spawn, so there is no route from it"
        );
        if call.escalates() {
            let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, sock);
            let status = call
                .run(&mut child, Duration::ZERO)
                .await
                .unwrap_or_else(|e| panic!("{call:?}: {e:?}"));
            console_less::assert_the_proxy_was_asked(call, true, child.pid(), status);
        } else {
            let status = call
                .run(&mut child, Duration::ZERO)
                .await
                .unwrap_or_else(|e| panic!("{call:?}: {e:?}"));
            console_less::assert_the_proxy_was_asked(call, false, child.pid(), status);
            kill_release_reap_async(&mut child, sock, false).await;
        }
    }
    ctrl_break::report_done(&mut report);
}
