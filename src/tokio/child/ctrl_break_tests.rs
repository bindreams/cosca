//! Async twin of `child/ctrl_break_tests.rs`: the async cooperative ops' `CTRL_BREAK` reaches its
//! target, asserted sent before any wait for the member's evidence.

use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

use super::fault as term_fault;
use crate::test_child::ctrl_break::{self, Grandchild, Handler, STATUS_CONTROL_C_EXIT};
use crate::GracefulMechanism;

/// A contained [`ctrl_break`] root answering with `handler`, after its handshake.
fn spawn_root(handler: Handler) -> (crate::tokio::Child, TcpStream) {
    let (child, sock, _) = spawn(handler, None);
    (child, sock)
}

/// A contained root and the grandchild it starts in its console process group, after both
/// handshakes. The root's socket keeps the root running while held.
fn spawn_tree(root: Handler, grandchild: Handler) -> (crate::tokio::Child, TcpStream, Grandchild) {
    let (child, sock, grand) = spawn(root, Some(grandchild));
    (child, sock, grand.expect("a grandchild was asked for"))
}

fn spawn(handler: Handler, grandchild: Option<Handler>) -> (crate::tokio::Child, TcpStream, Option<Grandchild>) {
    spawn_configured(handler, grandchild, crate::ContainMode::Strongest, |_| {})
}

/// [`spawn`] contained as `mode`, with `configure` applied to the command last.
fn spawn_configured(
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

/// As the sync twin's.
fn assert_in_our_console(pid: u32) {
    assert_eq!(
        ctrl_break::in_our_console(pid),
        Some(true),
        "the root must share our console for the break to be deliverable"
    );
}

/// As the sync twin's.
fn assert_acked(sock: &mut TcpStream) {
    let mut ack = [0u8; 1];
    sock.read_exact(&mut ack).expect("the root must acknowledge the break");
    assert_eq!(&ack, b"B", "the root acked something other than CTRL_BREAK");
}

/// As the sync twin's.
async fn kill_tree_release_reap(child: &mut crate::tokio::Child, sock: TcpStream) {
    child.kill_tree().expect("kill_tree");
    drop(sock);
    let status = child.wait().await.expect("reap");
    assert_eq!(status.code(), Some(1), "kill_tree must kill the root, got {status:?}");
}

/// Async twin of `child_terminate_delivers_ctrl_break_to_a_contained_root`.
#[skuld::test]
async fn async_child_terminate_delivers_ctrl_break_to_a_contained_root() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, mut sock) = spawn_root(Handler::Ack);
    assert_eq!(child.graceful_mechanism(), GracefulMechanism::ConsoleGroup);
    assert_in_our_console(child.id().pid());
    child.terminate().expect("terminate a console-group child");
    ctrl_break::assert_break_sent_to(child.id().pid());
    assert_acked(&mut sock);
    kill_tree_release_reap(&mut child, sock).await;
}

/// Async twin of `a_plain_contained_root_really_receives_the_break`.
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

/// Async twin of `child_graceful_shutdown_exits_via_ctrl_break_on_windows`. The hook runs on this
/// thread, inside the future's poll, so it reads the record `terminate` wrote there.
#[skuld::test]
async fn async_child_graceful_shutdown_exits_via_ctrl_break_on_windows() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, _sock) = spawn_root(Handler::Default);
    let pid = child.id().pid();
    assert_in_our_console(pid);
    let _check = term_fault::at(term_fault::HookPoint::AfterTerminate, move || {
        ctrl_break::assert_break_sent_to(pid)
    });
    let status = child
        .graceful_shutdown(Duration::from_secs(30))
        .await
        .expect("graceful_shutdown on a console-group child");
    assert_eq!(
        status.code(),
        Some(STATUS_CONTROL_C_EXIT),
        "the child must die to the console event, got {status:?}"
    );
}

/// Async twin of `child_graceful_shutdown_tree_tears_down_tree_on_windows`.
#[skuld::test]
async fn async_child_graceful_shutdown_tree_tears_down_tree_on_windows() {
    crate::tokio::test_runtime::assert_current_thread();
    let (mut child, _root_sock, grand) = spawn_tree(Handler::Default, Handler::Default);
    let pid = child.id().pid();
    assert_in_our_console(pid);
    let _check = term_fault::at(term_fault::HookPoint::AfterTerminate, move || {
        ctrl_break::assert_break_sent_to(pid)
    });
    let status = child
        .graceful_shutdown_tree(Duration::from_secs(30))
        .await
        .expect("graceful_shutdown_tree on a console-group root");
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

/// Async twin of `child_graceful_shutdown_signals_the_group_but_only_kills_the_child`. The root
/// ignores the break, so only the escalation can end it; its socket is closed once the escalation
/// returned, so an escalation that sent nothing yields code 0, not a hang.
#[skuld::test]
async fn async_child_graceful_shutdown_signals_the_group_but_only_kills_the_child() {
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
    // Released after the kill, so code 1 is the kill's, not a release.
    child.kill_tree().expect("kill_tree");
    let Grandchild { sock, exit } = grand;
    drop(sock);
    assert_eq!(exit.wait_for_exit_code(), 1, "kill_tree must kill the grandchild");
}

/// Async twin of `child_graceful_ops_report_success_for_a_child_that_shares_no_console`: the same
/// known limitation, pinned on the async surface too.
#[skuld::test]
async fn async_child_graceful_ops_report_success_for_a_child_that_shares_no_console() {
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
/// that sent nothing, or only to the root, yields code 0 for the member it missed, not a hang.
#[skuld::test]
async fn async_graceful_shutdown_tree_sweep_is_load_bearing_on_windows() {
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

/// Async twin of `graceful_shutdown_tree_ends_a_root_that_has_a_console_of_its_own`.
#[skuld::test]
async fn async_graceful_shutdown_tree_ends_a_root_that_has_a_console_of_its_own() {
    crate::tokio::test_runtime::assert_current_thread();
    // The last field: `detached()` rather than `no_window()`.
    let legs = [
        ("no_window, job", crate::ContainMode::Strongest, false),
        ("detached, job", crate::ContainMode::Strongest, true),
        ("no_window, treewalk", crate::ContainMode::TreeWalk, false),
    ];
    for (what, mode, detached) in legs {
        let (mut child, sock, _) = spawn_configured(Handler::Ignore, None, mode, |c| {
            _ = if detached { c.detached() } else { c.no_window() }
        });
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
