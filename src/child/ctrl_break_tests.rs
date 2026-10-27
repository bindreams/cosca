//! Windows: the cooperative ops' `CTRL_BREAK` reaches its target. Each test asserts that the call
//! sent the break to the expected group before it waits for the member's own evidence (see
//! `test_child::ctrl_break`), so a call that sends nothing fails by assertion, and nothing is
//! released that could race the break.
//!
//! Each break sent to a group outside our console leaves a dead entry in the console's process
//! list. Run these locally from a fresh terminal; no test asserts the absence of a pid it did not
//! spawn.

use std::net::TcpStream;
use std::time::Duration;

use super::fault as term_fault;
use crate::containment::Containment;
use crate::test_child::ctrl_break::{
    self, assert_acked, assert_in_our_console, kill_release_reap, Grandchild, Handler, STATUS_CONTROL_C_EXIT,
};
use crate::GracefulMechanism;

/// A contained [`ctrl_break`] root answering with `handler`, after its handshake.
fn spawn_root(handler: Handler, mode: crate::ContainMode) -> (crate::Child, TcpStream) {
    spawn_root_configured(handler, mode, |_| {})
}

/// [`spawn_root`] with `configure` applied to the root's command before the spawn.
fn spawn_root_configured(
    handler: Handler,
    mode: crate::ContainMode,
    configure: impl FnOnce(&mut crate::Command),
) -> (crate::Child, TcpStream) {
    let (child, sock, _) = spawn(handler, None, mode, configure);
    (child, sock)
}

/// A contained root and the grandchild it starts in its console process group, after both
/// handshakes. The root's socket keeps the root running while held.
fn spawn_tree(root: Handler, grandchild: Handler, mode: crate::ContainMode) -> (crate::Child, TcpStream, Grandchild) {
    let (child, sock, grand) = spawn(root, Some(grandchild), mode, |_| {});
    (child, sock, grand.expect("a grandchild was asked for"))
}

fn spawn(
    handler: Handler,
    grandchild: Option<Handler>,
    mode: crate::ContainMode,
    configure: impl FnOnce(&mut crate::Command),
) -> (crate::Child, TcpStream, Option<Grandchild>) {
    ctrl_break::spawn_member(handler, grandchild, mode, configure)
}

/// `terminate` delivers to the root's console group: proved by a byte the root's own handler
/// writes, never by the Win32 return value, which reports success for an event that reached
/// nobody. The root survives its break by design, so the read cannot race a teardown.
#[skuld::test]
fn child_terminate_delivers_ctrl_break_to_a_contained_root() {
    let _warns = crate::log_capture::warn_watch();
    let (child, mut sock) = spawn_root(Handler::Ack, crate::ContainMode::Strongest);
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
    kill_release_reap(&child, sock, false);
}

/// The control leg of the false-success tests below: a contained root with no flag methods
/// really receives the tree op's break. Without it their "nothing was delivered" legs pass against
/// any build that never signals anything.
#[skuld::test]
fn a_plain_contained_root_really_receives_the_break() {
    let (child, mut sock) = spawn_root(Handler::Ack, crate::ContainMode::Strongest);
    assert_eq!(child.containment(), Containment::JobObject);
    assert_eq!(child.graceful_mechanism(), GracefulMechanism::ConsoleGroup);
    assert_in_our_console(child.id().pid(), "the root");
    child.terminate_tree().expect("terminate_tree on a contained root");
    ctrl_break::assert_break_sent_to(child.id().pid());
    assert_acked(&mut sock, "the root");
    kill_release_reap(&child, sock, true);
}

/// The graceful path end to end: no handler, so the default disposition applies and the child dies
/// to the console event. [`STATUS_CONTROL_C_EXIT`] tells it from `1` (the escalation). The break is
/// asserted sent as soon as `terminate` returns, so a missing one fails there, not when the grace
/// runs out.
#[skuld::test]
fn child_graceful_shutdown_exits_via_ctrl_break_on_windows() {
    let _warns = crate::log_capture::warn_watch();
    let (child, _sock) = spawn_root(Handler::Default, crate::ContainMode::Strongest);
    let pid = child.id().pid();
    assert_in_our_console(pid, "the child");
    let check = term_fault::at_checked(term_fault::HookPoint::AfterTerminate, move || {
        ctrl_break::assert_break_sent_to(pid)
    });
    let status = child
        .graceful_shutdown(Duration::from_secs(30))
        .expect("graceful_shutdown on a console-group child");
    check.assert_fired();
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
    let _warns = crate::log_capture::warn_watch();
    let (child, root_sock, mut grand) = spawn_tree(Handler::Ignore, Handler::Ack, crate::ContainMode::Strongest);
    assert_in_our_console(child.id().pid(), "the root");
    // The root leaves with 0 when its socket closes; closed once the escalation returned.
    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, root_sock);
    let status = child
        .graceful_shutdown(Duration::ZERO)
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
    // The break reached a descendant the escalation does not touch. Its handler reports "handled",
    // so this read cannot race its death.
    assert_acked(&mut grand.sock, "the grandchild");
    // The job object's own live-member count: the grandchild still runs.
    assert_eq!(
        child.wait_tree_timeout(Duration::ZERO).expect("drain verdict"),
        crate::containment::TreeDrain::MembersRemain,
        "the escalation must not have reached the group"
    );
    // Released after the kill: code 1 is the kill's.
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
    let _warns = crate::log_capture::warn_watch();
    let (child, _root_sock, grand) = spawn_tree(Handler::Default, Handler::Default, crate::ContainMode::Strongest);
    assert_eq!(child.containment(), Containment::JobObject);
    let pid = child.id().pid();
    assert_in_our_console(pid, "the root");
    let check = term_fault::at_checked(term_fault::HookPoint::AfterTerminate, move || {
        ctrl_break::assert_break_sent_to(pid)
    });
    let status = child
        .graceful_shutdown_tree(Duration::from_secs(30))
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

/// `graceful_shutdown_tree` with no grace sends its own break (asserted through the
/// `AfterTerminate` hook) and escalates, because the root survives its break, and nothing is left
/// alive. The root is released before the reap, so a no-op escalation fails the status assertion
/// instead of hanging.
#[skuld::test]
fn graceful_shutdown_tree_with_no_grace_sends_its_break_and_escalates() {
    let (child, sock) = spawn_root(Handler::Ack, crate::ContainMode::Strongest);
    let pid = child.id().pid();
    let check = term_fault::at_checked(term_fault::HookPoint::AfterTerminate, move || {
        ctrl_break::assert_break_sent_to(pid)
    });
    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, sock);
    let status = child
        .graceful_shutdown_tree(Duration::ZERO)
        .expect("graceful_shutdown_tree");
    check.assert_fired();
    assert_eq!(
        status.code(),
        Some(1),
        "the escalation's kill ends the root, got {status:?}"
    );
    assert_eq!(
        child.is_alive(),
        crate::identity::Liveness::Dead,
        "a successful graceful_shutdown_tree must leave nothing alive"
    );
}

/// As [`graceful_shutdown_tree_with_no_grace_sends_its_break_and_escalates`], for the lone
/// `graceful_shutdown`: exit code 1 is the escalation's kill, and a later `kill` of the dead child
/// is `Ok`.
#[skuld::test]
fn graceful_shutdown_with_no_grace_sends_its_break_and_escalates() {
    let (child, sock) = spawn_root(Handler::Ack, crate::ContainMode::Strongest);
    let pid = child.id().pid();
    let check = term_fault::at_checked(term_fault::HookPoint::AfterTerminate, move || {
        ctrl_break::assert_break_sent_to(pid)
    });
    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, sock);
    let status = child.graceful_shutdown(Duration::ZERO).expect("graceful_shutdown");
    check.assert_fired();
    assert_eq!(status.code(), Some(1), "the escalation's kill, got {status:?}");
    assert_eq!(child.is_alive(), crate::identity::Liveness::Dead);
    child.kill().expect("killing a dead child is Ok");
}

/// Both members ignore the break, so only the ZERO-grace hard sweep can end the tree. The root's
/// socket is closed once the sweep returned, and the grandchild's after the root is reaped: a sweep
/// that sent nothing, or only to the root, yields code 0 for the member it missed.
#[skuld::test]
fn graceful_shutdown_tree_sweep_is_load_bearing_on_windows() {
    let _warns = crate::log_capture::warn_watch();
    let (child, root_sock, grand) = spawn_tree(Handler::Ignore, Handler::Ignore, crate::ContainMode::Strongest);
    assert_in_our_console(child.id().pid(), "the root");
    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, root_sock);
    let status = child.graceful_shutdown_tree(Duration::ZERO).expect("tree escalates");
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

/// Require of a root spawned for [`assert_false_success`] the containment the leg is about, and the
/// route that reads its creation flags whole: a derivation reading only the containment half of the
/// word says `ConsoleGroup` here.
fn assert_own_console_route(child: &crate::Child, expected_containment: Containment) {
    assert_eq!(
        child.containment(),
        expected_containment,
        "this test is about the wrong thing if containment did not take"
    );
    assert_eq!(
        child.graceful_mechanism(),
        GracefulMechanism::OtherConsoleGroup,
        "cosca's honest report of the route"
    );
}

/// A root whose creation flags put it in a console of its own gets a false success from the
/// cooperative ops: they return `Ok` having sent a break that reached nobody. The subject is HOW
/// the root ended, so the assertions are on its exit code.
///
/// The root has no handler, so a delivered break would end it with [`STATUS_CONTROL_C_EXIT`]. It is
/// released through its own socket after the cooperative op, and must then leave with `0`: it ended
/// on the release, having received nothing. The exit code alone cannot rule out a break that lands
/// after the release (no ordering exists for a negative claim). The send record is read before the
/// release, so it does not depend on that timing; the liveness read cannot fail on a build that
/// delivers the break, and is not what carries the claim. A second root checks the
/// other half: the forced `graceful_shutdown_tree` still ends such a tree, and its release comes
/// after the sweep, so a sweep that sent nothing yields `0` instead of a hang on the held root.
///
/// Mutants caught deterministically: `terminate_tree` sends nothing (the break assertion); the sweep
/// sends nothing (the code of the second root). A break delivered outside the console is not among
/// them, for the ordering reason above.
fn assert_false_success(
    expected_containment: Containment,
    mode: crate::ContainMode,
    configure: impl Fn(&mut crate::Command),
) {
    use std::io::Write as _;

    let (child, mut sock) = spawn_root_configured(Handler::Default, mode, &configure);
    assert_own_console_route(&child, expected_containment);
    child
        .terminate_tree()
        .expect("the cooperative op reports success: that is the gap this pins");
    ctrl_break::assert_break_sent_to(child.id().pid());
    assert_eq!(
        child.is_alive(),
        crate::identity::Liveness::Alive,
        "nothing was delivered, so the root must still be running"
    );
    sock.write_all(b"x").expect("release the root through its own socket");
    let status = child.wait().expect("reap");
    assert_eq!(
        status.code(),
        Some(0),
        "the root exited on OUR release byte, so the cooperative op delivered nothing; a delivered break would have ended it with STATUS_CONTROL_C_EXIT ({STATUS_CONTROL_C_EXIT:#x}), got {status:?}"
    );
    drop(sock);

    // A second root, because the first is already gone.
    let (child, sock) = spawn_root_configured(Handler::Default, mode, &configure);
    assert_own_console_route(&child, expected_containment);
    let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, sock);
    let status = child
        .graceful_shutdown_tree(Duration::ZERO)
        .expect("the forced half tears the tree down");
    assert_eq!(
        status.code(),
        Some(1),
        "the forced half must kill the root, got {status:?}"
    );
    assert_eq!(
        child.is_alive(),
        crate::identity::Liveness::Dead,
        "the forced half really ended it"
    );
}

#[skuld::test]
fn a_no_window_contained_root_gets_a_false_success() {
    assert_false_success(Containment::JobObject, crate::ContainMode::Strongest, |c| {
        c.no_window();
    });
}

/// As [`a_no_window_contained_root_gets_a_false_success`], for `detached`.
#[skuld::test]
fn a_detached_contained_root_gets_a_false_success() {
    assert_false_success(Containment::JobObject, crate::ContainMode::Strongest, |c| {
        c.detached();
    });
}

/// A distinct route into the same call site: on Windows `Attached::TreeWalk` reaches
/// `containment::windows::terminate` through `treewalk::terminate`, so a change made in one arm
/// only would miss it.
#[skuld::test]
fn a_treewalk_contained_root_gets_a_false_success_too() {
    assert_false_success(Containment::TreeWalk, crate::ContainMode::TreeWalk, |c| {
        c.no_window();
    });
}

/// A child that shares no console with us is signalled with a success Windows reports for an event
/// that reached nobody, and nothing inside this process can tell that case apart from a healthy
/// one (#832). This test must flip when #832 lands, not the behaviour change silently.
///
/// The child is a contained GUI-subsystem root, which never attaches to our console, so its
/// creation flags exclude nothing and a break reaches nobody. `terminate` is asserted sent, and the
/// child is still running afterwards. The forced half still ends it: its release comes after the
/// escalation, so an escalation that sent nothing yields `0` instead of a hang.
///
/// Mutants: `terminate` sends nothing (the break record); `graceful_shutdown` skips the kill (the
/// exit code).
#[skuld::test]
fn child_graceful_ops_report_success_for_a_child_that_shares_no_console() {
    let _warns = crate::log_capture::warn_watch();
    let (child, sock) = ctrl_break::spawn_consoleless_root();
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
        .expect("the forced half needs no console");
    check.assert_fired();
    assert_eq!(status.code(), Some(1), "escalation's kill, got {status:?}");
}

/// Dropping a `Child` with a Job Object tree kills the grandchild as well as the root. Both
/// sockets are released once the drop's root kill returned, so a drop that sent nothing lets each
/// member leave on its own with 0, which the code assertions reject, instead of hanging the drop's
/// reap of the root. A drop whose job kill ended the root first never reaches that release.
#[skuld::test]
fn drop_kills_a_job_object_tree() {
    let (child, root_sock, grand) = spawn_tree(Handler::Default, Handler::Default, crate::ContainMode::Strongest);
    assert_eq!(child.containment(), Containment::JobObject);
    let Grandchild { sock, exit } = grand;
    let teardown = crate::child::spawn::fault::release_at_drop_kill((root_sock, sock));

    drop(child);

    teardown.assert_reaps_killed();
    assert_eq!(exit.wait_for_exit_code(), 1, "the drop must kill the grandchild");
}

/// The case the capability exists for, end to end: a nested contained child owns no tree, leads a
/// console process group of its own, and had no cooperative shutdown at all. The checks run in
/// `test_child::ctrl_break::nested`.
#[skuld::test]
fn nested_delegated_child_can_be_gracefully_terminated() {
    ctrl_break::drive_reporter(ctrl_break::nested::REPORTER_TEST, ctrl_break::nested::ADDR_ENV, |cmd| {
        _ = cmd.contain()
    });
}

/// From a caller with no console, the cooperative ops fail with `NoConsole` and send no break. The
/// checks, including the sender's empty break record, run in `test_child::ctrl_break::console_less`
/// in a re-exec of this binary spawned detached.
#[skuld::test]
fn console_less_caller_sends_no_break() {
    ctrl_break::drive_reporter(
        ctrl_break::console_less::REPORTER_TEST,
        ctrl_break::console_less::ADDR_ENV,
        |cmd| _ = cmd.detached(),
    );
}
