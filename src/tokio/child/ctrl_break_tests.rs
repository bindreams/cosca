//! Async twin of `child/ctrl_break_tests.rs`: the async cooperative ops' `CTRL_BREAK` reaches its
//! target, asserted sent before any wait for the member's evidence.

use std::net::TcpStream;
use std::time::Duration;

use super::fault as term_fault;
use crate::containment::Containment;
use crate::test_child::ctrl_break::{
    self, assert_acked, assert_in_our_console, kill_release_reap_async, Grandchild, Handler, STATUS_CONTROL_C_EXIT,
};
use crate::GracefulMechanism;

fn spawn_root(handler: Handler) -> (crate::tokio::Child, TcpStream) {
    let (child, sock, _) = spawn(handler, None);
    (child, sock)
}

/// The root's socket keeps the root running while held.
fn spawn_tree(root: Handler, grandchild: Handler) -> (crate::tokio::Child, TcpStream, Grandchild) {
    let (child, sock, grand) = spawn(root, Some(grandchild));
    (child, sock, grand.expect("a grandchild was asked for"))
}

fn spawn(handler: Handler, grandchild: Option<Handler>) -> (crate::tokio::Child, TcpStream, Option<Grandchild>) {
    ctrl_break::spawn_member_async(handler, grandchild, crate::ContainMode::Strongest, |_| {})
}

#[skuld::test]
async fn async_child_terminate_delivers_ctrl_break_to_a_contained_root() {
    let _warns = crate::log_capture::warn_watch();
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, mut sock) = spawn_root(Handler::Ack);
    assert_eq!(child.graceful_mechanism(), GracefulMechanism::ConsoleGroup);
    assert_in_our_console(child.id().pid(), "the root");
    child.terminate().expect("terminate a console-group child");
    ctrl_break::assert_break_sent_to(child.id().pid());
    assert_acked(&mut sock, "the root");
    assert_eq!(
        child.is_alive(),
        crate::identity::Liveness::Alive,
        "the root handles the break and keeps running"
    );
    kill_release_reap_async(&mut child, sock, false).await;
}

#[skuld::test]
async fn an_async_plain_contained_root_really_receives_the_break() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, mut sock) = spawn_root(Handler::Ack);
    assert_eq!(child.containment(), Containment::JobObject);
    assert_eq!(child.graceful_mechanism(), GracefulMechanism::ConsoleGroup);
    assert_in_our_console(child.id().pid(), "the root");
    child.terminate_tree().expect("terminate_tree on a contained root");
    ctrl_break::assert_break_sent_to(child.id().pid());
    assert_acked(&mut sock, "the root");
    kill_release_reap_async(&mut child, sock, true).await;
}

/// The hook runs on this thread, inside the future's poll, so it reads the record `terminate` wrote
/// there.
#[skuld::test]
async fn async_child_graceful_shutdown_exits_via_ctrl_break_on_windows() {
    let _warns = crate::log_capture::warn_watch();
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, _sock) = spawn_root(Handler::Default);
    let pid = child.id().pid();
    assert_in_our_console(pid, "the root");
    let check = term_fault::at_checked(term_fault::HookPoint::AfterTerminate, move || {
        ctrl_break::assert_break_sent_to(pid)
    });
    let status = child
        .graceful_shutdown(Duration::from_secs(30))
        .await
        .expect("graceful_shutdown on a console-group child");
    check.assert_fired();
    assert_eq!(
        status.code(),
        Some(STATUS_CONTROL_C_EXIT),
        "the child must die to the console event, got {status:?}"
    );
}

#[skuld::test]
async fn async_child_graceful_shutdown_tree_tears_down_tree_on_windows() {
    let _warns = crate::log_capture::warn_watch();
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, _root_sock, grand) = spawn_tree(Handler::Default, Handler::Default);
    let pid = child.id().pid();
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

#[skuld::test]
async fn async_child_graceful_shutdown_signals_the_group_but_only_kills_the_child() {
    let _warns = crate::log_capture::warn_watch();
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, root_sock, mut grand) = spawn_tree(Handler::Ignore, Handler::Ack);
    assert_in_our_console(child.id().pid(), "the root");
    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, root_sock);
    let status = child
        .graceful_shutdown(Duration::ZERO)
        .await
        .expect("graceful_shutdown on a console-group root");
    assert_eq!(
        status.code(),
        Some(1),
        "the root ignores the break, so only the escalation can have ended it, got {status:?}"
    );
    assert_eq!(
        child.is_alive(),
        crate::identity::Liveness::Dead,
        "the escalation really ended the root"
    );
    ctrl_break::assert_break_sent_to(child.id().pid());
    // The break reached a descendant the escalation does not touch.
    assert_acked(&mut grand.sock, "the grandchild");
    assert_eq!(
        child.wait_tree_timeout(Duration::ZERO).await.expect("drain verdict"),
        crate::containment::TreeDrain::MembersRemain,
        "the escalation must not have reached the group"
    );
    // Released after the kill: code 1 is the kill's.
    child.kill_tree().expect("kill_tree");
    let Grandchild { sock, exit } = grand;
    drop(sock);
    assert_eq!(exit.wait_for_exit_code(), 1, "kill_tree must kill the grandchild");
}

/// Async twin of `child_graceful_ops_report_success_for_a_child_that_shares_no_console`: the same
/// known limitation (#832), pinned on the async surface too.
#[skuld::test]
async fn async_child_graceful_ops_report_success_for_a_child_that_shares_no_console() {
    let _warns = crate::log_capture::warn_watch();
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, sock) = spawn_root(Handler::Detached);
    let pid = child.id().pid();
    assert_eq!(
        child.graceful_mechanism(),
        GracefulMechanism::ConsoleGroup,
        "the flags do not exclude delivery, which is what makes this a gap"
    );
    assert_eq!(
        ctrl_break::in_our_console(pid),
        Some(false),
        "a child that freed its console is not in ours"
    );
    child.terminate().expect("the documented false success");
    ctrl_break::assert_break_sent_to(pid);
    assert_eq!(
        child.is_alive(),
        crate::identity::Liveness::Alive,
        "nothing was delivered, so the child must still be running"
    );
    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, sock);
    let status = child
        .graceful_shutdown(Duration::ZERO)
        .await
        .expect("the forced half needs no console");
    assert_eq!(status.code(), Some(1), "the escalation's kill, got {status:?}");
}

/// Both members ignore the break, so only the ZERO-grace hard sweep can end the tree. The root's
/// socket is closed once the sweep returned, and the grandchild's after the root is reaped: a sweep
/// that sent nothing, or only to the root, yields code 0 for the member it missed.
#[skuld::test]
async fn async_graceful_shutdown_tree_sweep_is_load_bearing_on_windows() {
    let _warns = crate::log_capture::warn_watch();
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, root_sock, grand) = spawn_tree(Handler::Ignore, Handler::Ignore);
    assert_in_our_console(child.id().pid(), "the root");
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

/// Async twin of `graceful_shutdown_tree_ends_a_root_that_has_a_console_of_its_own`.
#[skuld::test]
async fn async_graceful_shutdown_tree_ends_a_root_that_has_a_console_of_its_own() {
    crate::tokio::test_runtime::assert_current_thread();
    let legs = [
        (
            "no_window, job",
            crate::ContainMode::Strongest,
            Containment::JobObject,
            false,
        ),
        (
            "detached, job",
            crate::ContainMode::Strongest,
            Containment::JobObject,
            true,
        ),
        (
            "no_window, treewalk",
            crate::ContainMode::TreeWalk,
            Containment::TreeWalk,
            false,
        ),
    ];
    for (what, mode, containment, detached) in legs {
        let (mut child, sock, _) = ctrl_break::spawn_member_async(Handler::Ignore, None, mode, |c| {
            _ = if detached { c.detached() } else { c.no_window() }
        });
        assert_eq!(
            child.containment(),
            containment,
            "{what}: this test is about the wrong thing if containment did not take"
        );
        assert_eq!(
            child.graceful_mechanism(),
            GracefulMechanism::OtherConsoleGroup,
            "{what}: the honest route; a derivation reading only the containment half says ConsoleGroup"
        );
        let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, sock);
        let status = child
            .graceful_shutdown_tree(Duration::ZERO)
            .await
            .unwrap_or_else(|e| panic!("{what}: the forced half tears the tree down: {e:?}"));
        assert_eq!(
            status.code(),
            Some(1),
            "{what}: the forced half must kill the root, got {status:?}"
        );
        assert_eq!(
            child.is_alive(),
            crate::identity::Liveness::Dead,
            "{what}: the forced half really ended it"
        );
    }
}
