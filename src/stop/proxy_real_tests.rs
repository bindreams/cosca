//! The caller's side of the console-event proxy against the real proxy: this test binary re-executed
//! with the proxy's arguments (its `main` calls `init` first), started by a stop action of
//! `stop::send_console_event_via_proxy`. A wrong proxy sends Ctrl+C or Ctrl+Break to every process on the
//! console it attached to, so these tests are the `CTRL_PROXY` group: they run on CI, and a host runs them
//! only after consenting (`COSCA_TEST_CTRL_PROXY_CONSENT=1`) or turns them off
//! (`COSCA_TEST_CTRL_PROXY=0`).
//!
//! Each asserts the recorded answer of the proxy ([`assert_proxy_answered`]) before it reads a member's
//! ack, so a stop that sent nothing fails by assertion, and the tests of a refusal read nothing. Targets
//! are the `test_child::ctrl_break` members: a member's ack says which event reached its handler.

use std::time::Duration;

use super::protocol::{CtrlEvent, ProxyAnswer};
use crate::error::Error;
use crate::stop;
use crate::test_child::ctrl_break::{
    self, assert_acked_event, assert_in_our_console, assert_proxy_answered, connect_reporter, kill_release_reap,
    report_done, spawn_gui_root, spawn_member, spawn_uncontained_member, Handler, STATUS_CONTROL_C_EXIT,
};
use crate::test_groups::{ctrl_proxy, Group};
use crate::{Command, ContainMode};

/// Makes `cmd`'s child stop by sending `event` through the proxy, and gives it a console of its own.
fn stops_through_the_proxy(cmd: &mut Command, event: CtrlEvent) {
    cmd.no_window();
    stops_by_sending(cmd, event);
}

/// Makes `cmd`'s child stop by sending `event` through the proxy.
fn stops_by_sending(cmd: &mut Command, event: CtrlEvent) {
    cmd.graceful_stop(move |target| stop::send_console_event_via_proxy(target, event));
}

/// Ctrl+Break to a contained child with a console of its own, which no group of the caller's reaches.
/// Mutant: the stop sends Ctrl+C for Ctrl+Break (the ack is `C`), or sends nothing.
#[skuld::test]
fn the_proxy_delivers_ctrl_break_to_a_no_window_child(#[fixture(ctrl_proxy)] _group: &Group) {
    let (child, mut sock, _) = spawn_member(Handler::AckEvent, None, ContainMode::Strongest, |cmd| {
        stops_through_the_proxy(cmd, CtrlEvent::CtrlBreak)
    });
    child.terminate().expect("terminate through the proxy");
    assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::Sent);
    assert_acked_event(&mut sock, "the member", CtrlEvent::CtrlBreak);
    kill_release_reap(&child, sock, false);
}

/// Ctrl+C to a child that leads no group, with a console of its own: the event no group address reaches.
/// Mutant: the stop sends Ctrl+Break for Ctrl+C (the ack is `B`), or sends nothing.
#[skuld::test]
fn the_proxy_delivers_ctrl_c_to_a_child_without_a_group(#[fixture(ctrl_proxy)] _group: &Group) {
    let (child, mut sock) =
        spawn_uncontained_member(Handler::AckEvent, |cmd| stops_through_the_proxy(cmd, CtrlEvent::CtrlC));
    child.terminate().expect("terminate through the proxy");
    assert_proxy_answered(child.pid(), CtrlEvent::CtrlC, ProxyAnswer::Sent);
    assert_acked_event(&mut sock, "the member", CtrlEvent::CtrlC);
    kill_release_reap(&child, sock, false);
}

/// The fully-qualified libtest path of [`fixture_console_less_proxy_reporter`].
const CONSOLE_LESS_TEST: &str = "stop::proxy::proxy_real_tests::fixture_console_less_proxy_reporter";

/// The environment variable carrying the address the console-less reporter reports to.
const CONSOLE_LESS_ADDR_ENV: &str = "COSCA_FIXTURE_CONSOLE_LESS_PROXY_ADDR";

/// A caller with no console, which the direct send cannot reach a child from (`NoConsole`), stops its
/// child through the proxy. The checks run in the reporter, a re-exec of this binary spawned detached.
/// Mutant: the stop sends nothing, or needs the caller's console.
#[skuld::test]
fn a_console_less_caller_reaches_its_child_through_the_proxy(#[fixture(ctrl_proxy)] _group: &Group) {
    ctrl_break::drive_reporter(CONSOLE_LESS_TEST, CONSOLE_LESS_ADDR_ENV, |cmd| _ = cmd.detached());
}

/// The reporter of [`a_console_less_caller_reaches_its_child_through_the_proxy`].
#[skuld::test]
fn fixture_console_less_proxy_reporter() {
    let Some(mut report) = connect_reporter(CONSOLE_LESS_ADDR_ENV) else {
        return;
    };
    ctrl_break::console_less::assert_no_console();
    let (child, mut sock, _) = spawn_member(Handler::AckEvent, None, ContainMode::Strongest, |cmd| {
        stops_through_the_proxy(cmd, CtrlEvent::CtrlBreak)
    });
    child
        .terminate()
        .expect("a console-less caller stops its child through the proxy");
    assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::Sent);
    assert_acked_event(&mut sock, "the member", CtrlEvent::CtrlBreak);
    kill_release_reap(&child, sock, false);
    report_done(&mut report);
}

/// A child on the caller's own console is refused, with nothing sent: an event there would reach this
/// process too. The error names the direct send, and nothing is read from the member. Mutant: the proxy
/// does not check the console list, so the event is sent (the answer is `Sent`).
#[skuld::test]
fn the_proxy_refuses_a_child_on_the_callers_console(#[fixture(ctrl_proxy)] _group: &Group) {
    let (child, sock, _) = spawn_member(Handler::Ignore, None, ContainMode::Strongest, |cmd| {
        stops_by_sending(cmd, CtrlEvent::CtrlBreak)
    });
    assert_in_our_console(child.pid(), "the member");
    let err = child.terminate().expect_err("the child is on our console");
    let Error::Unsupported { detail, .. } = &err else {
        panic!("{err:?}")
    };
    assert!(detail.contains("stop::send_ctrl_break_to_group"), "{detail}");
    assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::ConsoleIsCallers);
    kill_release_reap(&child, sock, false);
}

/// A GUI-subsystem child never has a console to attach to: the proxy answers `TargetHasNoConsole`, and
/// the stop is `Unsupported`. Mutant: `TargetHasNoConsole` is mapped to `Ok`.
#[skuld::test]
fn a_gui_child_has_no_console_to_attach(#[fixture(ctrl_proxy)] _group: &Group) {
    let (child, sock) = spawn_gui_root(|cmd| stops_through_the_proxy(cmd, CtrlEvent::CtrlBreak));
    let err = child.terminate().expect_err("a GUI child has no console");
    assert!(matches!(err, Error::Unsupported { .. }), "{err:?}");
    assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::TargetHasNoConsole);
    kill_release_reap(&child, sock, false);
}

/// The tree calls take the proxy's answer as the direct send's, over a job object and over a tree walk:
/// `terminate_tree` ends a root and a grandchild on its console that have no handler, and
/// `graceful_shutdown_tree` does the same within its grace. The 30 s grace is a failure bound, not the
/// condition under test: the event reaches the root within milliseconds, and a root that outlives the
/// grace is killed by the sweep, so a status other than `STATUS_CONTROL_C_EXIT` means the event did not
/// end it in time, and fails the assertion on the status. Mutants: a tree target does not take the route
/// (nothing reaches the grandchild); the answer is not recorded.
#[skuld::test]
fn the_tree_calls_use_the_proxy_too(#[fixture(ctrl_proxy)] _group: &Group) {
    for mode in [ContainMode::Strongest, ContainMode::TreeWalk] {
        let (child, _sock, grand) = spawn_member(Handler::Default, Some(Handler::Default), mode, |cmd| {
            stops_through_the_proxy(cmd, CtrlEvent::CtrlBreak)
        });
        let grand = grand.expect("a grandchild was asked for");
        child.terminate_tree().expect("terminate_tree through the proxy");
        assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::Sent);
        assert_eq!(
            grand.exit.wait_for_exit_code(),
            STATUS_CONTROL_C_EXIT,
            "{mode:?}: the grandchild"
        );
        assert_eq!(
            child.wait().expect("reap the root").code(),
            Some(STATUS_CONTROL_C_EXIT),
            "{mode:?}: the root"
        );

        let (child, _sock, grand) = spawn_member(Handler::Default, Some(Handler::Default), mode, |cmd| {
            stops_through_the_proxy(cmd, CtrlEvent::CtrlBreak)
        });
        let grand = grand.expect("a grandchild was asked for");
        let pid = child.pid();
        let check = crate::graceful_hooks::at_checked(crate::graceful_hooks::HookPoint::AfterTerminate, move || {
            assert_proxy_answered(pid, CtrlEvent::CtrlBreak, ProxyAnswer::Sent)
        });
        let status = child
            .graceful_shutdown_tree(Duration::from_secs(30))
            .expect("graceful_shutdown_tree through the proxy");
        check.assert_fired();
        assert_eq!(
            status.code(),
            Some(STATUS_CONTROL_C_EXIT),
            "{mode:?}: the root, got {status:?}: another status means the grace ran out and the sweep killed it, so the event did not end it in time"
        );
        assert_eq!(
            grand.exit.wait_for_exit_code(),
            STATUS_CONTROL_C_EXIT,
            "{mode:?}: the grandchild"
        );
    }
}
