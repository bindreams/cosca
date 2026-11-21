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
use crate::error::Error;
use crate::stop::proxy::protocol::{CtrlEvent, ProxyAnswer};
use crate::stop::proxy::proxy_tests::Fixture;
use crate::test_child::ctrl_break::{
    self, assert_acked, assert_in_our_console, assert_proxy_answered, kill_release_reap, Grandchild, Handler,
    STATUS_CONTROL_C_EXIT,
};
use crate::StopTarget;

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
    assert!(StopTarget::from(&child).leads_group_on_our_console());
    assert_in_our_console(child.pid(), "the root");
    child.terminate().expect("terminate a console-group child");
    ctrl_break::assert_break_sent_to(child.pid());
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
    assert!(StopTarget::from(&child).leads_group_on_our_console());
    assert_in_our_console(child.pid(), "the root");
    child.terminate_tree().expect("terminate_tree on a contained root");
    ctrl_break::assert_break_sent_to(child.pid());
    assert_acked(&mut sock, "the root");
    kill_release_reap(&child, sock, true);
}

/// An uncontained child created with `new_process_group(true)` leads a group on our console, so
/// `terminate` sends the break to it directly and its handler answers. Mutants: the setter ignored
/// for an uncontained spawn (the call is refused, not sent); the break sent to another group.
#[skuld::test]
fn an_uncontained_child_given_a_group_is_stopped_directly() {
    let (child, mut sock) = ctrl_break::spawn_uncontained_member(Handler::Ack, |cmd| _ = cmd.new_process_group(true));
    assert_eq!(child.containment(), Containment::None);
    assert!(StopTarget::from(&child).leads_group_on_our_console());
    assert_in_our_console(child.pid(), "the child");
    child.terminate().expect("terminate a child created in a group");
    ctrl_break::assert_break_sent_to(child.pid());
    assert_acked(&mut sock, "the child");
    kill_release_reap(&child, sock, false);
}

/// The graceful path end to end: no handler, so the default disposition applies and the child dies
/// to the console event. [`STATUS_CONTROL_C_EXIT`] tells it from `1` (the escalation). The break is
/// asserted sent as soon as `terminate` returns, so a missing one fails there, not when the grace
/// runs out.
#[skuld::test]
fn child_graceful_shutdown_exits_via_ctrl_break_on_windows() {
    let _warns = crate::log_capture::warn_watch();
    let (child, _sock) = spawn_root(Handler::Default, crate::ContainMode::Strongest);
    let pid = child.pid();
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
    assert_in_our_console(child.pid(), "the root");
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
    ctrl_break::assert_break_sent_to(child.pid());
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
    assert_in_our_console(child.pid(), "the root");
    child.terminate_tree().expect("terminate_tree");
    ctrl_break::assert_break_sent_to(child.pid());
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
    let pid = child.pid();
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
    assert_in_our_console(child.pid(), "the root");
    child.terminate_tree().expect("terminate_tree");
    ctrl_break::assert_break_sent_to(child.pid());
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
    let pid = child.pid();
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
    let pid = child.pid();
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
    assert_in_our_console(child.pid(), "the root");
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

// A child outside our group or console: the default asks the proxy =====
//
// The proxy here is the fixture of `stop::proxy::proxy_tests`: it answers what its name says and sends
// nothing, so none of these tests is in the `CTRL_PROXY` group. What a real proxy delivers is in
// `ctrl_break_proxy_tests.rs`.

/// The four calls that run the child's stop action.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Call {
    Terminate,
    TerminateTree,
    GracefulShutdown,
    GracefulShutdownTree,
}

pub(crate) const CALLS: [Call; 4] = [
    Call::Terminate,
    Call::TerminateTree,
    Call::GracefulShutdown,
    Call::GracefulShutdownTree,
];

impl Call {
    /// The call on `child`, with `grace` for a graceful one, which answers the root's status.
    pub(crate) fn run(self, child: &crate::Child, grace: Duration) -> Result<Option<std::process::ExitStatus>, Error> {
        match self {
            Call::Terminate => child.terminate().map(|()| None).map_err(Error::from),
            Call::TerminateTree => child.terminate_tree().map(|()| None).map_err(Error::from),
            Call::GracefulShutdown => child.graceful_shutdown(grace).map(Some),
            Call::GracefulShutdownTree => child.graceful_shutdown_tree(grace).map(Some),
        }
    }

    /// Whether the call goes on to a kill when its stop did not end the root.
    pub(crate) fn escalates(self) -> bool {
        matches!(self, Call::GracefulShutdown | Call::GracefulShutdownTree)
    }
}

/// A contained root that stops by the default, whose proxy is `fixture`, with `configure` applied to
/// its command last.
fn root_stopping_through(
    fixture: &Fixture,
    mode: crate::ContainMode,
    configure: impl FnOnce(&mut crate::Command),
) -> (crate::Child, TcpStream) {
    spawn_root_configured(Handler::Ignore, mode, |cmd| {
        cmd.ctrl_proxy(fixture.setting());
        configure(cmd);
    })
}

/// The detail of an `Unsupported`; any other error is a panic.
fn unsupported_detail(err: &Error) -> &str {
    match err {
        Error::Unsupported { detail, .. } => detail,
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

/// A root that has a console of its own leads no group of the caller's console, so the default asks the
/// proxy, in every call and under both mechanisms that contain a root. The fixture answers `Sent`: the
/// stops answer `Ok` and leave the root running, and the graceful calls go on to escalate (the kill
/// ends the root, which the exit status shows). Mutants: the default sends the direct break (the record is a
/// direct send, and the proxy is not asked); a call does not run the default; a graceful call skips its kill
/// after the stop (the status is the release's, 0).
#[skuld::test]
fn the_default_asks_the_proxy_for_a_no_window_contained_root() {
    for (mode, expected) in [
        (crate::ContainMode::Strongest, Containment::JobObject),
        (crate::ContainMode::TreeWalk, Containment::TreeWalk),
    ] {
        for call in CALLS {
            let fixture = Fixture::answering(ProxyAnswer::Sent.code());
            let (child, sock) = root_stopping_through(&fixture, mode, |cmd| _ = cmd.no_window());
            assert_own_console_route(&child, expected);
            if call.escalates() {
                let _release = term_fault::release_at(term_fault::HookPoint::BeforeReap, sock);
                let status = call
                    .run(&child, Duration::ZERO)
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
                call.run(&child, Duration::ZERO)
                    .unwrap_or_else(|e| panic!("{mode:?} {call:?}: {e:?}"));
                assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::Sent);
                kill_release_reap(&child, sock, false);
            }
        }
    }
}

/// An uncontained child with a console of its own, which `terminate` refused before the proxy: the
/// default asks the proxy for it too. Mutant: the default refuses a child that leads no group before
/// asking.
#[skuld::test]
fn the_default_asks_the_proxy_for_an_uncontained_no_window_child() {
    let fixture = Fixture::answering(ProxyAnswer::Sent.code());
    let (child, sock) = ctrl_break::spawn_uncontained_member(Handler::Ignore, |cmd| {
        cmd.ctrl_proxy(fixture.setting());
        cmd.no_window();
    });
    assert_eq!(child.containment(), Containment::None);
    assert!(!StopTarget::from(&child).leads_group_on_our_console());
    child.terminate().expect("the proxy answered Sent");
    assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::Sent);
    kill_release_reap(&child, sock, false);
}

/// A root created with `detached()` is not refused up front: the proxy is asked, and its answer for a
/// child with no console is the stop's `Unsupported`, naming `Child::kill` before `Command::graceful_stop`.
/// Every call ends there with the root running, `graceful_shutdown` and `graceful_shutdown_tree` before
/// their grace and their kill. Mutants: the default sends the direct break (`Ok` for a root it
/// reached nobody with); a graceful call goes on to its kill after the refusal.
#[skuld::test]
fn a_detached_contained_root_is_refused_for_having_no_console() {
    for call in CALLS {
        let fixture = Fixture::answering(ProxyAnswer::TargetHasNoConsole.code());
        let (child, sock) = root_stopping_through(&fixture, crate::ContainMode::Strongest, |cmd| _ = cmd.detached());
        let err = call.run(&child, Duration::ZERO).expect_err("the call is refused");
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
        kill_release_reap(&child, sock, false);
    }
}

/// A child created on our console without a group (a contained one given `new_process_group(false)`, an
/// uncontained one by default) is refused by the direct send's own refusal, in every call: `Unsupported`
/// naming `Command::new_process_group`, with nothing sent, no proxy started (the fixture, which answers
/// `Sent`, never ran, and no answer is recorded) and the root running. The default does not need the
/// proxy for it. Mutants: the default takes the proxy (the fixture runs and answers `Sent`); `contain()`
/// forces the group on (the default sends directly); a graceful call goes on to its kill.
#[skuld::test]
fn a_child_on_our_console_without_a_group_is_refused_by_the_direct_send_without_the_proxy() {
    for call in CALLS {
        let fixture = Fixture::answering(ProxyAnswer::Sent.code());
        let (child, sock) = root_stopping_through(&fixture, crate::ContainMode::Strongest, |cmd| {
            _ = cmd.new_process_group(false)
        });
        assert_eq!(
            child.containment(),
            Containment::JobObject,
            "the job does not depend on the group"
        );
        assert_in_our_console(child.pid(), "the contained member");
        assert!(!StopTarget::from(&child).leads_group_on_our_console());
        let err = call.run(&child, Duration::ZERO).expect_err("the call is refused");
        ctrl_break::assert_refused_by_the_direct_send_for_no_group(&err);
        assert!(fixture.ran().is_none(), "{call:?}: the proxy was started");
        assert_eq!(
            child.is_alive(),
            crate::identity::Liveness::Alive,
            "{call:?}: the call ended with the root running"
        );
        kill_release_reap(&child, sock, false);
    }
}

/// The uncontained child of a console program, which `contain()` does not give a group: the same refusal
/// for the calls that run its action (an uncontained child has no tree), with no proxy started. Mutant: the
/// default takes the proxy for it.
#[skuld::test]
fn an_uncontained_child_on_our_console_is_refused_by_the_direct_send_without_the_proxy() {
    for call in [Call::Terminate, Call::GracefulShutdown] {
        let fixture = Fixture::answering(ProxyAnswer::Sent.code());
        let (child, sock) = ctrl_break::spawn_uncontained_member(Handler::Ignore, |cmd| {
            cmd.ctrl_proxy(fixture.setting());
        });
        assert_eq!(child.containment(), Containment::None);
        assert_in_our_console(child.pid(), "the uncontained member");
        assert!(!StopTarget::from(&child).leads_group_on_our_console());
        let err = call.run(&child, Duration::ZERO).expect_err("the call is refused");
        ctrl_break::assert_refused_by_the_direct_send_for_no_group(&err);
        assert!(fixture.ran().is_none(), "{call:?}: the proxy was started");
        assert_eq!(
            child.is_alive(),
            crate::identity::Liveness::Alive,
            "{call:?}: the call ended with the root running"
        );
        kill_release_reap(&child, sock, false);
    }
}

/// `send_ctrl_break_to_group`, called as an explicit action for a child that has a console of its own
/// (`no_window`) or none (`detached`), answers `Ok` and reaches nobody, as its doc says: Windows reports
/// success for an event aimed at a group in another console, and this process cannot rule the case out.
/// The default never takes this route for such a child; this is the one test of what a caller who chose
/// the direct send gets.
///
/// The root has no handler, so a delivered break would end it with [`STATUS_CONTROL_C_EXIT`]. It is
/// released through its own socket after the call, and must then leave with `0`: it ended on the release,
/// having received nothing. The break is asserted sent before the release, so that does not depend on
/// timing; the exit code alone cannot rule out a break that lands after the release.
///
/// Mutants: the send refuses a child whose flags put it outside our console (`Err`); it sends nothing
/// (the record is empty); it delivers the break to the child (the exit code).
#[skuld::test]
fn an_explicit_direct_send_answers_ok_for_a_child_outside_our_console_and_reaches_nobody() {
    use std::io::Write as _;

    for detached in [false, true] {
        let (child, mut sock) = spawn_root_configured(Handler::Default, crate::ContainMode::Strongest, |cmd| {
            if detached {
                cmd.detached();
            } else {
                cmd.no_window();
            }
            cmd.graceful_stop(crate::stop::send_ctrl_break_to_group);
        });
        child
            .terminate()
            .unwrap_or_else(|e| panic!("detached {detached}: the documented false success: {e:?}"));
        ctrl_break::assert_break_sent_to(child.pid());
        assert_eq!(
            child.is_alive(),
            crate::identity::Liveness::Alive,
            "detached {detached}: nothing was delivered, so the root must still be running"
        );
        sock.write_all(b"x").expect("release the root through its own socket");
        let status = child.wait().expect("reap");
        assert_eq!(
            status.code(),
            Some(0),
            "detached {detached}: the root exited on OUR release byte, so the direct send delivered nothing; \
             a delivered break would have ended it with STATUS_CONTROL_C_EXIT ({STATUS_CONTROL_C_EXIT:#x}), \
             got {status:?}"
        );
    }
}

/// Require of a root spawned for the tests below the containment the leg is about, and the
/// route that reads its creation flags whole: a derivation reading only the containment half of the
/// word says `ConsoleGroup` here.
fn assert_own_console_route(child: &crate::Child, expected_containment: Containment) {
    assert_eq!(
        child.containment(),
        expected_containment,
        "this test is about the wrong thing if containment did not take"
    );
    let console = child.console;
    assert!(
        console.group && console.own_console_flags && !StopTarget::from(child).leads_group_on_our_console(),
        "cosca's honest report of the route: a group in a console of its own, {console:?}"
    );
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
    let pid = child.pid();
    assert!(
        StopTarget::from(&child).leads_group_on_our_console(),
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

/// The setter reaches a nested contained child too: given `new_process_group(false)` it leads no
/// group, so the default is the direct send's refusal naming the setter, with no proxy started and no break
/// sent. Mutants: a nested spawn that ignores the setter and leads a group anyway (`terminate` sends
/// directly and succeeds); the default takes the proxy; the refusal not naming the setter. The checks run
/// in `test_child::ctrl_break::nested`.
#[skuld::test]
fn a_nested_contained_child_without_a_group_is_refused_by_the_direct_send() {
    ctrl_break::drive_reporter(
        ctrl_break::nested::NO_GROUP_REPORTER_TEST,
        ctrl_break::nested::NO_GROUP_ADDR_ENV,
        |cmd| _ = cmd.contain(),
    );
}

/// From a caller with no console, the direct send fails with `NoConsole` and sends no break, and the
/// default asks the proxy instead: its stops answer what the proxy answered. The checks, including the
/// sender's record, run in `test_child::ctrl_break::console_less` in a re-exec of this binary spawned
/// detached. Mutant: the default sends the direct break (`NoConsole`, and no proxy asked).
#[skuld::test]
fn a_console_less_callers_default_asks_the_proxy_and_its_direct_send_has_no_console() {
    ctrl_break::drive_reporter(
        ctrl_break::console_less::REPORTER_TEST,
        ctrl_break::console_less::ADDR_ENV,
        |cmd| _ = cmd.detached(),
    );
}
