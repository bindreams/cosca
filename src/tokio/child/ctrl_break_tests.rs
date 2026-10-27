//! Async twin of `child/ctrl_break_tests.rs`: the async cooperative ops' `CTRL_BREAK` reaches its
//! target, asserted sent before any wait for the member's evidence.

use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

use super::fault as term_fault;
use crate::containment::Containment;
use crate::test_child::ctrl_break::{self, Grandchild, Handler, STATUS_CONTROL_C_EXIT};
use crate::GracefulMechanism;

fn spawn_root(handler: Handler) -> (crate::tokio::Child, TcpStream) {
    spawn_root_configured(handler, crate::ContainMode::Strongest, |_| {})
}

/// [`spawn_root`] under `mode`, with `configure` applied to the root's command before the spawn.
fn spawn_root_configured(
    handler: Handler,
    mode: crate::ContainMode,
    configure: impl FnOnce(&mut crate::tokio::Command),
) -> (crate::tokio::Child, TcpStream) {
    let (child, sock, _) = spawn(handler, None, mode, configure);
    (child, sock)
}

/// The root's socket keeps the root running while held.
fn spawn_tree(root: Handler, grandchild: Handler) -> (crate::tokio::Child, TcpStream, Grandchild) {
    let (child, sock, grand) = spawn(root, Some(grandchild), crate::ContainMode::Strongest, |_| {});
    (child, sock, grand.expect("a grandchild was asked for"))
}

fn spawn(
    handler: Handler,
    grandchild: Option<Handler>,
    mode: crate::ContainMode,
    configure: impl FnOnce(&mut crate::tokio::Command),
) -> (crate::tokio::Child, TcpStream, Option<Grandchild>) {
    let (listener, addr) = crate::test_child::registration_rendezvous();
    let mut cmd = crate::tokio::Command::new();
    cmd.executable(std::env::current_exe().expect("current_exe"))
        .args(ctrl_break::member_argv());
    crate::test_reexec::scrub_env(|var| _ = cmd.env_remove(var));
    for (key, value) in ctrl_break::member_env(&addr, handler, grandchild) {
        cmd.env(key, value);
    }
    cmd.contain_with(mode);
    configure(&mut cmd);
    let child = cmd.spawn().expect("spawn the root");
    let mut sock = ctrl_break::accept_root(&listener, child.id());
    let grand = grandchild.map(|_| ctrl_break::accept_grandchild(&listener, &mut sock));
    (child, sock, grand)
}

/// Same contract as `child::ctrl_break_tests::assert_in_our_console`.
fn assert_in_our_console(pid: u32) {
    assert_eq!(
        ctrl_break::in_our_console(pid),
        Some(true),
        "the root must share our console for the break to be deliverable"
    );
}

/// Same contract as `child::ctrl_break_tests::assert_acked`.
fn assert_acked(sock: &mut TcpStream) {
    let mut ack = [0u8; 1];
    sock.read_exact(&mut ack).expect("the root must acknowledge the break");
    assert_eq!(&ack, b"B", "the root acked something other than CTRL_BREAK");
}

/// Same contract as `child::ctrl_break_tests::kill_tree_release_reap`.
async fn kill_tree_release_reap(child: &mut crate::tokio::Child, sock: TcpStream) {
    child.kill_tree().expect("kill_tree");
    drop(sock);
    let status = child.wait().await.expect("reap");
    assert_eq!(status.code(), Some(1), "kill_tree must kill the root, got {status:?}");
}

#[skuld::test]
async fn async_child_terminate_delivers_ctrl_break_to_a_contained_root() {
    let _warns = crate::log_capture::warn_watch();
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, mut sock) = spawn_root(Handler::Ack);
    assert_eq!(child.graceful_mechanism(), GracefulMechanism::ConsoleGroup);
    assert_in_our_console(child.id().pid());
    child.terminate().expect("terminate a console-group child");
    ctrl_break::assert_break_sent_to(child.id().pid());
    assert_acked(&mut sock);
    kill_tree_release_reap(&mut child, sock).await;
}

#[skuld::test]
async fn an_async_plain_contained_root_really_receives_the_break() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, mut sock) = spawn_root(Handler::Ack);
    assert_eq!(child.graceful_mechanism(), GracefulMechanism::ConsoleGroup);
    assert_in_our_console(child.id().pid());
    child.terminate_tree().expect("terminate_tree on a contained root");
    ctrl_break::assert_break_sent_to(child.id().pid());
    assert_acked(&mut sock);
    kill_tree_release_reap(&mut child, sock).await;
}

/// The hook runs on this thread, inside the future's poll, so it reads the record `terminate` wrote
/// there.
#[skuld::test]
async fn async_child_graceful_shutdown_exits_via_ctrl_break_on_windows() {
    let _warns = crate::log_capture::warn_watch();
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, _sock) = spawn_root(Handler::Default);
    let pid = child.id().pid();
    assert_in_our_console(pid);
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
    assert_in_our_console(pid);
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
    assert_in_our_console(child.id().pid());
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
    assert_acked(&mut grand.sock);
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

/// Both members ignore the break, so only the ZERO-grace hard sweep can end the tree. The root's
/// socket is closed once the sweep returned, and the grandchild's after the root is reaped: a sweep
/// that sent nothing, or only to the root, yields code 0 for the member it missed.
#[skuld::test]
async fn async_graceful_shutdown_tree_sweep_is_load_bearing_on_windows() {
    let _warns = crate::log_capture::warn_watch();
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, root_sock, grand) = spawn_tree(Handler::Ignore, Handler::Ignore);
    assert_in_our_console(child.id().pid());
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

// A root outside our console =====

/// Async twin of the sync `assert_false_success`; see there.
async fn assert_false_success(
    expected_containment: Containment,
    mode: crate::ContainMode,
    configure: impl Fn(&mut crate::tokio::Command),
) {
    use std::io::Write as _;

    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, mut sock) = spawn_root_configured(Handler::Default, mode, &configure);
    assert_eq!(child.containment(), expected_containment);
    assert_eq!(
        child.graceful_mechanism(),
        GracefulMechanism::OtherConsoleGroup,
        "the async derivation must read the composed word too"
    );
    child.terminate_tree().expect("the cooperative op reports success");
    ctrl_break::assert_break_sent_to(child.id().pid());
    assert_eq!(
        child.is_alive(),
        crate::identity::Liveness::Alive,
        "nothing was delivered, so the root must still be running"
    );
    sock.write_all(b"x").expect("release the root through its own socket");
    let status = child.wait().await.expect("reap");
    assert_eq!(
        status.code(),
        Some(0),
        "the root exited on OUR release byte, so the cooperative op delivered nothing, got {status:?}"
    );
    drop(sock);

    let (mut child, sock) = spawn_root_configured(Handler::Default, mode, &configure);
    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, sock);
    let status = child
        .graceful_shutdown_tree(Duration::ZERO)
        .await
        .expect("the forced half tears the tree down");
    assert_eq!(
        status.code(),
        Some(1),
        "the forced half must kill the root, got {status:?}"
    );
    assert_eq!(child.is_alive(), crate::identity::Liveness::Dead);
}

#[skuld::test]
async fn an_async_no_window_contained_root_gets_a_false_success() {
    assert_false_success(Containment::JobObject, crate::ContainMode::Strongest, |c| {
        c.no_window();
    })
    .await;
}

#[skuld::test]
async fn an_async_detached_contained_root_gets_a_false_success() {
    assert_false_success(Containment::JobObject, crate::ContainMode::Strongest, |c| {
        c.detached();
    })
    .await;
}

#[skuld::test]
async fn an_async_treewalk_contained_root_gets_a_false_success_too() {
    assert_false_success(Containment::TreeWalk, crate::ContainMode::TreeWalk, |c| {
        c.no_window();
    })
    .await;
}

/// Async twin of `child_graceful_ops_report_success_for_a_child_that_shares_no_console`: the same
/// behaviour (#832), on the async surface.
#[skuld::test]
async fn async_child_graceful_ops_report_success_for_a_child_that_shares_no_console() {
    let _warns = crate::log_capture::warn_watch();
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, mut sock) = spawn_root(Handler::Detached);
    ctrl_break::assert_left_console(&mut sock);
    let pid = child.id().pid();
    assert_eq!(
        child.graceful_mechanism(),
        GracefulMechanism::ConsoleGroup,
        "the flags do not exclude delivery: that is exactly what makes this a gap"
    );
    child.terminate().expect("the documented false success");
    ctrl_break::assert_break_sent_to(pid);
    assert_eq!(
        child.is_alive(),
        crate::identity::Liveness::Alive,
        "nothing was delivered, so the child must still be running"
    );
    let check = term_fault::at_checked(term_fault::HookPoint::AfterTerminate, move || {
        ctrl_break::assert_break_sent_to(pid)
    });
    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, sock);
    let status = child
        .graceful_shutdown(Duration::ZERO)
        .await
        .expect("the forced half needs no console");
    check.assert_fired();
    assert_eq!(status.code(), Some(1), "escalation's kill, got {status:?}");
}
