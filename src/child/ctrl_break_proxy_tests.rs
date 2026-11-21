//! Windows: the default stop through the real console-event proxy. A wrong proxy sends Ctrl+C or
//! Ctrl+Break to every process on the console it attached to, so these tests are the `CTRL_PROXY` group:
//! they run on CI, and a host runs them only after consenting (`COSCA_TEST_CTRL_PROXY_CONSENT=1`) or
//! turns them off (`COSCA_TEST_CTRL_PROXY=0`).
//!
//! The members set no `graceful_stop`, so each call runs `stop::default`. Each test asserts the recorded
//! answer of the proxy before it reads a member's evidence, so a stop that sent nothing fails by
//! assertion. The rows of the default that need no real proxy are in `ctrl_break_tests.rs`.

use std::time::Duration;

use super::ctrl_break_tests::{Call, CALLS};
use crate::error::Error;
use crate::stop::proxy::protocol::{CtrlEvent, ProxyAnswer};
use crate::test_child::ctrl_break::{
    self, assert_acked_event, assert_in_our_console, assert_proxy_answered, connect_reporter, kill_release_reap,
    report_done, spawn_member, spawn_uncontained_member, Handler, STATUS_CONTROL_C_EXIT,
};
use crate::test_groups::{ctrl_proxy, Group};
use crate::ContainMode;

/// The call on `child`, which only the break ends: the root's status once the call has ended it, with
/// the proxy's answer asserted as soon as the call sent (a graceful call, in the hook after its stop).
/// The graceful calls' 30 s grace is a failure bound, not the condition under test: the break ends
/// the root within milliseconds, and a root that outlives the grace is killed, so a status other
/// than [`STATUS_CONTROL_C_EXIT`] fails the caller's assertion.
fn ending(call: Call, child: &crate::Child) -> std::process::ExitStatus {
    let pid = child.pid();
    let answered = move || assert_proxy_answered(pid, CtrlEvent::CtrlBreak, ProxyAnswer::Sent);
    if call.escalates() {
        let check = crate::graceful_hooks::at_checked(crate::graceful_hooks::HookPoint::AfterTerminate, answered);
        let status = call.run(child, Duration::from_secs(30));
        check.assert_fired();
        status
            .unwrap_or_else(|e| panic!("{call:?}: {e:?}"))
            .expect("a graceful call answers a status")
    } else {
        call.run(child, Duration::ZERO)
            .unwrap_or_else(|e| panic!("{call:?}: {e:?}"));
        answered();
        child.wait().expect("reap the root")
    }
}

/// Every call, on a fresh contained root that has a console of its own and no handler, ends the root
/// with the break the proxy sent.
fn assert_default_stops_through_the_proxy(mode: ContainMode) {
    for call in CALLS {
        let (child, _sock, _) = spawn_member(Handler::Default, None, mode, |cmd| _ = cmd.no_window());
        let status = ending(call, &child);
        assert_eq!(
            status.code(),
            Some(STATUS_CONTROL_C_EXIT),
            "{mode:?} {call:?}: the root must die to the break, got {status:?}"
        );
    }
}

/// A contained root with a console of its own is stopped by the default through the proxy, in every
/// call. Mutants: the default sends the direct break (the record is a direct send, and the root,
/// which no group of ours reaches, is not ended); the proxy is asked for Ctrl+C.
#[skuld::test]
fn a_no_window_contained_root_is_stopped_through_the_proxy(#[fixture(ctrl_proxy)] _group: &Group) {
    assert_default_stops_through_the_proxy(ContainMode::Strongest);
}

/// As [`a_no_window_contained_root_is_stopped_through_the_proxy`], under the tree walk, which reaches the
/// send through its own route.
#[skuld::test]
fn a_treewalk_contained_root_is_stopped_through_the_proxy(#[fixture(ctrl_proxy)] _group: &Group) {
    assert_default_stops_through_the_proxy(ContainMode::TreeWalk);
}

/// An uncontained child with a console of its own, which the default refused before the proxy: it is sent
/// Ctrl+Break, and its handler acks the break. Mutant: the default refuses a child that leads no group.
#[skuld::test]
fn an_uncontained_no_window_child_is_stopped_through_the_proxy(#[fixture(ctrl_proxy)] _group: &Group) {
    let (child, mut sock) = spawn_uncontained_member(Handler::AckEvent, |cmd| _ = cmd.no_window());
    child.terminate().expect("terminate through the proxy");
    assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::Sent);
    assert_acked_event(&mut sock, "the member", CtrlEvent::CtrlBreak);
    kill_release_reap(&child, sock, false);
}

/// A contained child created with `new_process_group(false)` on our console, stopped by an explicit proxy
/// action (the default does not take the proxy for it): the real proxy refuses a child on its caller's
/// console, and the stop says so by naming the setter. Nothing was sent, so the child is running. Mutant: the
/// proxy does not check the console list (the answer is `Sent`).
#[skuld::test]
fn a_child_without_a_group_is_refused_by_the_real_proxy_when_asked(#[fixture(ctrl_proxy)] _group: &Group) {
    let (child, sock, _) = spawn_member(Handler::Ignore, None, ContainMode::Strongest, |cmd| {
        _ = cmd.new_process_group(false);
        cmd.graceful_stop(|target| crate::stop::send_console_event_via_proxy(target, CtrlEvent::CtrlBreak));
    });
    assert_in_our_console(child.pid(), "the member");
    let err = child.terminate().expect_err("the child is on our console");
    let Error::Unsupported { detail, .. } = err.error() else {
        panic!("{err:?}")
    };
    assert!(detail.contains("Command::new_process_group"), "{detail}");
    assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::ConsoleIsCallers);
    kill_release_reap(&child, sock, false);
}

/// A detached contained root has no console for the real proxy to attach to: every call is refused with
/// the proxy's answer, the root keeps running, and the graceful calls do not go on to their kill.
/// Mutant: `TargetHasNoConsole` is mapped to `Ok`.
#[skuld::test]
fn a_detached_contained_root_is_refused_for_having_no_console(#[fixture(ctrl_proxy)] _group: &Group) {
    for call in CALLS {
        let (child, sock, _) = spawn_member(Handler::Default, None, ContainMode::Strongest, |cmd| _ = cmd.detached());
        let err = call
            .run(&child, Duration::ZERO)
            .expect_err("a detached root has no console");
        assert!(matches!(err, Error::Unsupported { .. }), "{call:?}: {err:?}");
        assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::TargetHasNoConsole);
        assert_eq!(
            child.is_alive(),
            crate::identity::Liveness::Alive,
            "{call:?}: the call ended with the root running"
        );
        kill_release_reap(&child, sock, false);
    }
}

/// The fully-qualified libtest path of [`fixture_console_less_default_reporter`].
const CONSOLE_LESS_TEST: &str = "child::graceful::ctrl_break_proxy_tests::fixture_console_less_default_reporter";

/// The environment variable carrying the address the console-less reporter reports to.
const CONSOLE_LESS_ADDR_ENV: &str = "COSCA_FIXTURE_CONSOLE_LESS_DEFAULT_ADDR";

/// A caller with no console, which the direct send cannot reach a child from (`NoConsole`), stops its
/// contained child by the default: through the proxy. The checks run in the reporter, a re-exec of this
/// binary spawned detached. Mutant: the default sends the direct break (`NoConsole`).
#[skuld::test]
fn a_console_less_callers_default_reaches_its_contained_child(#[fixture(ctrl_proxy)] _group: &Group) {
    ctrl_break::drive_reporter(CONSOLE_LESS_TEST, CONSOLE_LESS_ADDR_ENV, |cmd| _ = cmd.detached());
}

/// The reporter of [`a_console_less_callers_default_reaches_its_contained_child`].
#[skuld::test]
fn fixture_console_less_default_reporter() {
    let Some(mut report) = connect_reporter(CONSOLE_LESS_ADDR_ENV) else {
        return;
    };
    ctrl_break::console_less::assert_no_console();
    assert_default_stops_through_the_proxy(ContainMode::Strongest);
    report_done(&mut report);
}
