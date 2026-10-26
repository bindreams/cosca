//! Windows: the cooperative ops' `CTRL_BREAK` reaches its target. Each test asserts that the call
//! sent the break to the expected group before it waits for the member's own evidence (see
//! `test_child::ctrl_break`), so a call that sends nothing fails by assertion, and nothing is
//! released that could race the break.

use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

use super::fault as term_fault;
use crate::containment::Containment;
use crate::test_child::ctrl_break::{self, Grandchild, Handler, STATUS_CONTROL_C_EXIT};
use crate::GracefulMechanism;

/// A contained [`ctrl_break`] root answering with `handler`, after its handshake.
fn spawn_root(handler: Handler, mode: crate::ContainMode) -> (crate::Child, TcpStream) {
    let (child, sock, _) = spawn(handler, None, mode);
    (child, sock)
}

/// A contained root and the grandchild it starts in its console process group, after both
/// handshakes. The root's socket keeps the root running while held.
fn spawn_tree(root: Handler, grandchild: Handler, mode: crate::ContainMode) -> (crate::Child, TcpStream, Grandchild) {
    let (child, sock, grand) = spawn(root, Some(grandchild), mode);
    (child, sock, grand.expect("a grandchild was asked for"))
}

fn spawn(
    handler: Handler,
    grandchild: Option<Handler>,
    mode: crate::ContainMode,
) -> (crate::Child, TcpStream, Option<Grandchild>) {
    let (listener, addr) = crate::test_child::registration_rendezvous();
    let mut cmd = crate::Command::new();
    cmd.executable(std::env::current_exe().expect("current_exe"))
        .args(ctrl_break::member_argv());
    crate::test_reexec::scrub_env(|var| _ = cmd.env_remove(var));
    for (key, value) in ctrl_break::member_env(&addr, handler, grandchild) {
        cmd.env(key, value);
    }
    cmd.contain_with(mode);
    let child = cmd.spawn().expect("spawn the root");
    let mut sock = ctrl_break::accept_root(&listener, child.id());
    let grand = grandchild.map(|_| ctrl_break::accept_grandchild(&listener, &mut sock));
    (child, sock, grand)
}

/// Require that `pid` shares our console, after its handshake: a break to a group outside it is
/// accepted and lost.
fn assert_in_our_console(pid: u32, who: &str) {
    assert_eq!(
        ctrl_break::in_our_console(pid),
        Some(true),
        "{who} must share our console for the break to be deliverable"
    );
}

/// Read the `B` an acking member writes when its handler receives the break.
fn assert_acked(sock: &mut TcpStream, who: &str) {
    let mut ack = [0u8; 1];
    sock.read_exact(&mut ack)
        .unwrap_or_else(|e| panic!("{who} must acknowledge the break: {e}"));
    assert_eq!(&ack, b"B", "{who} acked something other than CTRL_BREAK");
}

/// Kill the tree, then release the root: it leaves with 0 when released, so code 1 is the kill's.
fn kill_tree_release_reap(child: &crate::Child, sock: TcpStream) {
    child.kill_tree().expect("kill_tree");
    drop(sock);
    let status = child.wait().expect("reap");
    assert_eq!(status.code(), Some(1), "kill_tree must kill the root, got {status:?}");
}

/// `terminate` delivers to the root's console group: proved by a byte the root's own handler
/// writes, never by the Win32 return value, which reports success for an event that reached
/// nobody. The root survives its break by design, so the read cannot race a teardown.
#[skuld::test]
fn child_terminate_delivers_ctrl_break_to_a_contained_root() {
    let (child, mut sock) = spawn_root(Handler::Ack, crate::ContainMode::Strongest);
    assert_eq!(child.graceful_mechanism(), GracefulMechanism::ConsoleGroup);
    assert_in_our_console(child.id().pid(), "the root");
    child.terminate().expect("terminate a console-group child");
    ctrl_break::assert_break_sent_to(child.id().pid());
    assert_acked(&mut sock, "the root");
    kill_tree_release_reap(&child, sock);
}

/// The control leg of `tests/windows_false_success.rs`: a contained root with no flag methods
/// really receives the tree op's break. Without it the false-success legs there pass against any
/// build that never signals anything.
#[skuld::test]
fn a_plain_contained_root_really_receives_the_break() {
    let (child, mut sock) = spawn_root(Handler::Ack, crate::ContainMode::Strongest);
    assert_eq!(child.graceful_mechanism(), GracefulMechanism::ConsoleGroup);
    assert_in_our_console(child.id().pid(), "the root");
    child.terminate_tree().expect("terminate_tree on a contained root");
    ctrl_break::assert_break_sent_to(child.id().pid());
    assert_acked(&mut sock, "the root");
    kill_tree_release_reap(&child, sock);
}

/// The graceful path end to end: no handler, so the default disposition applies and the child dies
/// to the console event. [`STATUS_CONTROL_C_EXIT`] tells it from `1` (the escalation). The break is
/// asserted sent as soon as `terminate` returns, so a missing one fails there, not when the grace
/// runs out.
#[skuld::test]
fn child_graceful_shutdown_exits_via_ctrl_break_on_windows() {
    let (child, _sock) = spawn_root(Handler::Default, crate::ContainMode::Strongest);
    let pid = child.id().pid();
    assert_in_our_console(pid, "the child");
    let _check = term_fault::at(term_fault::HookPoint::AfterTerminate, move || {
        ctrl_break::assert_break_sent_to(pid)
    });
    let status = child
        .graceful_shutdown(Duration::from_secs(30))
        .expect("graceful_shutdown on a console-group child");
    assert_eq!(
        status.code(),
        Some(STATUS_CONTROL_C_EXIT),
        "the child must die to the console event, got {status:?}"
    );
}

/// The lone graceful shutdown's two halves have different radii: the break reaches the child's
/// whole console group, the escalation only the child. The root ignores the break, so only the
/// escalation can end it, while its grandchild acks the break and survives.
#[skuld::test]
fn child_graceful_shutdown_signals_the_group_but_only_kills_the_child() {
    let (child, root_sock, mut grand) = spawn_tree(Handler::Ignore, Handler::Ack, crate::ContainMode::Strongest);
    assert_in_our_console(child.id().pid(), "the root");
    // The root leaves with 0 when its socket closes. Closed once the escalation returned, so an
    // escalation that sent nothing fails the code assertion below instead of hanging the reap.
    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, root_sock);
    let status = child
        .graceful_shutdown(Duration::ZERO)
        .expect("graceful_shutdown on a console-group root");
    assert_eq!(
        status.code(),
        Some(1),
        "the root ignores the break, so only the escalation can have ended it, got {status:?}"
    );
    ctrl_break::assert_break_sent_to(child.id().pid());
    // The break reached a descendant the escalation does not touch. Its handler reports "handled",
    // so this read cannot race its death.
    assert_acked(&mut grand.sock, "the grandchild");
    // The job object's own live-member count: the grandchild still runs.
    assert_eq!(
        child.wait_tree_timeout(Duration::ZERO).expect("drain verdict"),
        crate::containment::TreeDrain::MembersRemain,
        "the escalation must not have reached the group"
    );
    // Released after the kill, so code 1 is the kill's, not a release.
    child.kill_tree().expect("kill_tree");
    let Grandchild { sock, exit } = grand;
    drop(sock);
    assert_eq!(exit.wait_for_exit_code(), 1, "kill_tree must kill the grandchild");
}

/// `terminate_tree` under Job Object containment: the break to the root's group reaches the
/// grandchild, an ordinary spawn of the root, which dies to it. Neither member is released, so its
/// exit code is the break's.
#[skuld::test]
fn windows_terminate_tree_reaps_the_grandchild() {
    let (child, _root_sock, grand) = spawn_tree(Handler::Default, Handler::Default, crate::ContainMode::Strongest);
    assert_eq!(child.containment(), Containment::JobObject);
    assert_in_our_console(child.id().pid(), "the root");
    child.terminate_tree().expect("terminate_tree");
    ctrl_break::assert_break_sent_to(child.id().pid());
    assert_eq!(
        grand.exit.wait_for_exit_code(),
        STATUS_CONTROL_C_EXIT,
        "the grandchild must die to the break"
    );
    let status = child.wait().expect("reap the root");
    assert_eq!(
        status.code(),
        Some(STATUS_CONTROL_C_EXIT),
        "the root must die to the break"
    );
}

/// The graceful tree path end to end: no handlers, so the break ends the root and its grandchild
/// within the grace, and the job object drains without the sweep. The break is asserted sent as
/// soon as `terminate_tree` returns, so a missing one fails there, not when the grace runs out.
#[skuld::test]
fn child_graceful_shutdown_tree_tears_down_tree_on_windows() {
    let (child, _root_sock, grand) = spawn_tree(Handler::Default, Handler::Default, crate::ContainMode::Strongest);
    assert_eq!(child.containment(), Containment::JobObject);
    let pid = child.id().pid();
    assert_in_our_console(pid, "the root");
    let _check = term_fault::at(term_fault::HookPoint::AfterTerminate, move || {
        ctrl_break::assert_break_sent_to(pid)
    });
    let status = child
        .graceful_shutdown_tree(Duration::from_secs(30))
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

/// `terminate_tree` under `TreeWalk`, which on Windows reaches `containment::windows::terminate`
/// by its own route: the break to the root's group ends the root and its grandchild. The root's
/// socket keeps it alive until the break, so the walk has a live root to start from.
#[skuld::test]
fn treewalk_terminate_tree_reaps_the_grandchild() {
    let (child, _root_sock, grand) = spawn_tree(Handler::Default, Handler::Default, crate::ContainMode::TreeWalk);
    assert_eq!(child.containment(), Containment::TreeWalk);
    assert_in_our_console(child.id().pid(), "the root");
    child.terminate_tree().expect("terminate_tree");
    ctrl_break::assert_break_sent_to(child.id().pid());
    assert_eq!(
        grand.exit.wait_for_exit_code(),
        STATUS_CONTROL_C_EXIT,
        "the grandchild must die to the break"
    );
    let status = child.wait().expect("reap the root");
    assert_eq!(
        status.code(),
        Some(STATUS_CONTROL_C_EXIT),
        "the root must die to the break"
    );
}

/// Both members ignore the break, so only the ZERO-grace hard sweep can end the tree. The root's
/// socket is closed once the sweep returned, and the grandchild's after the root is reaped: a sweep
/// that sent nothing, or only to the root, yields code 0 for the member it missed, not a hang.
#[skuld::test]
fn graceful_shutdown_tree_sweep_is_load_bearing_on_windows() {
    let (child, root_sock, grand) = spawn_tree(Handler::Ignore, Handler::Ignore, crate::ContainMode::Strongest);
    assert_in_our_console(child.id().pid(), "the root");
    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, root_sock);
    let status = child.graceful_shutdown_tree(Duration::ZERO).expect("tree escalates");
    assert_eq!(status.code(), Some(1), "the sweep ends the root, got {status:?}");
    let Grandchild { sock, exit } = grand;
    drop(sock);
    assert_eq!(exit.wait_for_exit_code(), 1, "the sweep must kill the grandchild");
}
