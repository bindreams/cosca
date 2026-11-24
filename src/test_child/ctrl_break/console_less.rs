//! The graceful ops from a caller with no console, with the proxy a fixture that sends nothing. The
//! checks run in a re-exec of this binary spawned `DETACHED_PROCESS`; the driver in
//! `child::ctrl_break_tests` reads only whether the checks finished.
//!
//! A target's reply cannot show that no break was sent: its handler thread may not have run yet.
//! The proof is the sender's own record, empty after each op ([`assert_no_break_sent`]): with no
//! console `GenerateConsoleCtrlEvent` fails at the syscall, so each op of the direct send reports
//! `NoConsole`. The members are GUI-subsystem images ([`spawn_gui_root`]), which no break reaches, so
//! nothing else would reveal a break sent anyway. A console-subsystem member would open a visible
//! console window (its parent has none).

use std::time::Duration;

use super::{
    assert_no_break_sent, assert_proxy_answered, connect_reporter, kill_release_reap, report_done, spawn_gui_root,
};
use crate::child::graceful::ctrl_break_tests::CALLS;
use crate::error::Error;
use crate::graceful_hooks::{release_at, HookPoint};
use crate::identity::Liveness;
use crate::stop::proxy::protocol::{CtrlEvent, ProxyAnswer};
use crate::stop::proxy::proxy_tests::Fixture;
use crate::{Containment, StopTarget};

/// The fully-qualified libtest path of [`fixture_console_less_reporter`].
pub(crate) const REPORTER_TEST: &str = "test_child::ctrl_break::console_less::fixture_console_less_reporter";

/// The environment variable carrying the address the reporter reports to.
pub(crate) const ADDR_ENV: &str = "COSCA_FIXTURE_CONSOLE_LESS_ADDR";

/// Require that this process has no console, measured: a zero from `GetConsoleProcessList` is also
/// how it reports failure, so the error code must say "no console" for the checks not to be
/// vacuous.
pub(crate) fn assert_no_console() {
    use windows::Win32::Foundation::{SetLastError, ERROR_INVALID_HANDLE, WIN32_ERROR};
    use windows::Win32::System::Console::GetConsoleProcessList;

    let mut list = [0u32; 1];
    // SAFETY: `SetLastError` only writes this thread's last-error slot, which is cleared so the
    // code read below is this call's; `list` is a valid writable slice.
    let n = unsafe {
        SetLastError(WIN32_ERROR(0));
        GetConsoleProcessList(&mut list)
    };
    assert_eq!(n, 0, "the reporter must have no console, else the checks are vacuous");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(ERROR_INVALID_HANDLE.0 as i32),
        "GetConsoleProcessList must fail for want of a console, not for another reason"
    );
}

/// A blocker that leads a console process group of its own, which the test made and so may signal.
/// It is `CREATE_NO_WINDOW` through the test spawn helpers.
fn spawn_group_leader() -> crate::test_child::StdChild {
    use windows::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP;

    crate::test_child::blocker_with_flags(CREATE_NEW_PROCESS_GROUP.0, crate::test_child::Console::Hidden, |_| {})
}

/// The routes beneath the ops, given the refused send of a group this process made and leads: with no
/// console the OS refuses the `CTRL_BREAK`, so each is `NotSent` with nothing sent. A job's route and
/// the walker's are both checked.
///
/// Mutant: a route folds the refusal into `Sent { result: Err(..) }`.
fn assert_refused_sends_are_not_sent() {
    use crate::containment::{Contains as _, TerminateOutcome, TreeStop};

    let leader = spawn_group_leader();
    let job = crate::containment::windows::assign_to_kill_on_close_job(
        std::os::windows::io::AsRawHandle::as_raw_handle(&*leader),
        crate::identity::spawn_kernel(crate::identity::HostKernel),
    )
    .expect("assign the group leader to a job");
    let broken = TreeStop::named(
        crate::stop::proxy::protocol::CtrlEvent::CtrlBreak.name(),
        crate::containment::SendAnswer::direct(crate::containment::windows::terminate(leader.id())),
    );
    let (outcome, _) = job.send_terminate(leader.id(), None, broken);
    assert!(
        matches!(outcome, TerminateOutcome::NotSent(_, _)),
        "a job's refused break must be NotSent, got {outcome:?}"
    );
    assert_no_break_sent();
    job.hard_kill().expect("end the group leader");

    let leader = spawn_group_leader();
    let id = crate::identity::ProcessId::of(leader.id())
        .found()
        .expect("the live group leader resolves");
    let broken = TreeStop::named(
        crate::stop::proxy::protocol::CtrlEvent::CtrlBreak.name(),
        crate::containment::SendAnswer::direct(crate::containment::windows::terminate(leader.id())),
    );
    let (outcome, _) = crate::containment::treewalk::terminate_tree(&crate::identity::HostKernel, id, None, broken);
    assert!(
        matches!(outcome, TerminateOutcome::NotSent(_, _)),
        "a walker's refused break must be NotSent, got {outcome:?}"
    );
    assert_no_break_sent();
}

/// A stop action that sends the direct break, as a caller who chose it would write it.
fn direct(target: &StopTarget<'_>) -> Result<(), Error> {
    crate::stop::send_ctrl_break_to_group(target)
}

/// The direct send, which every cooperative op of a child that chose it makes, from a caller with no
/// console: each op fails with `NoConsole` and leaves the member running, and the forced ops still end
/// it. No op sends a break, and the sends beneath them, to a group the reporter leads, are refused.
fn assert_the_direct_send_has_no_console() {
    // The tree ops.
    let (child, sock) = spawn_gui_root(|cmd| _ = cmd.graceful_stop(direct));
    assert_eq!(child.containment(), Containment::JobObject);
    let err = child
        .terminate_tree()
        .expect_err("terminate_tree must report NoConsole");
    assert!(matches!(err.error(), Error::NoConsole { .. }), "{err:?}");
    assert_eq!(err.outcome(), crate::stop::SendOutcome::NotSent, "no event was sent");
    assert_no_break_sent();
    assert_eq!(
        child.is_alive(),
        Liveness::Alive,
        "a fail-fast terminate leaves the tree alone"
    );
    assert!(
        matches!(
            child.graceful_shutdown_tree(Duration::ZERO),
            Err(Error::NoConsole { .. })
        ),
        "graceful_shutdown_tree must report NoConsole"
    );
    assert_no_break_sent();
    assert_eq!(
        child.is_alive(),
        Liveness::Alive,
        "graceful_shutdown_tree must fail before signalling, not after hard-killing"
    );
    kill_release_reap(&child, sock, true);

    // The lone ops.
    let (child, sock) = spawn_gui_root(|cmd| _ = cmd.graceful_stop(direct));
    let err = child.terminate().expect_err("terminate must report NoConsole");
    assert!(matches!(err.error(), Error::NoConsole { .. }), "{err:?}");
    assert_eq!(err.outcome(), crate::stop::SendOutcome::NotSent, "no event was sent");
    assert_no_break_sent();
    assert_eq!(
        child.is_alive(),
        Liveness::Alive,
        "a fail-fast terminate leaves the child alone"
    );
    assert!(
        matches!(child.graceful_shutdown(Duration::ZERO), Err(Error::NoConsole { .. })),
        "graceful_shutdown must report NoConsole"
    );
    assert_no_break_sent();
    assert_eq!(
        child.is_alive(),
        Liveness::Alive,
        "graceful_shutdown must fail before signalling, not after hard-killing"
    );
    kill_release_reap(&child, sock, false);
}

/// The default of a caller with no console asks the proxy for every call, as no group of a console
/// the caller does not have can be sent an event: the fixture proxy answers `Sent`, the stops are `Ok`
/// and leave the member running, and the graceful calls go on to their kill, whose exit status (1) shows
/// it was made: the release that follows it would give a member the kill missed the status 0.
fn assert_the_default_asks_the_proxy() {
    for call in CALLS {
        let fixture = Fixture::answering(ProxyAnswer::Sent.code());
        let (child, sock) = spawn_gui_root(|cmd| _ = cmd.ctrl_proxy(fixture.setting()));
        assert!(
            !StopTarget::from(&child).leads_group_on_our_console(),
            "the caller had no console at the spawn, so there is no route from it"
        );
        if call.escalates() {
            let _release = release_at(HookPoint::BeforeReap, sock);
            let status = call
                .run(&child, Duration::ZERO)
                .unwrap_or_else(|e| panic!("{call:?}: {e:?}"));
            assert_the_proxy_was_asked(call, call.escalates(), child.pid(), status);
        } else {
            let status = call
                .run(&child, Duration::ZERO)
                .unwrap_or_else(|e| panic!("{call:?}: {e:?}"));
            assert_the_proxy_was_asked(call, call.escalates(), child.pid(), status);
            kill_release_reap(&child, sock, false);
        }
    }
}

/// What a call of the default left, from a caller with no console and a proxy that answers `Sent`: the
/// proxy was asked for `pid`, and a graceful call (`escalates`), whose `status` is the root's, went on to
/// the kill (the release that follows it would give a root the kill missed the status 0). Shared by the
/// sync and the async checks.
pub(crate) fn assert_the_proxy_was_asked(
    call: impl std::fmt::Debug,
    escalates: bool,
    pid: u32,
    status: Option<std::process::ExitStatus>,
) {
    assert_proxy_answered(pid, CtrlEvent::CtrlBreak, ProxyAnswer::Sent);
    if escalates {
        let status = status.expect("a graceful call answers a status");
        assert_eq!(status.code(), Some(1), "{call:?}: the escalation's kill: {status:?}");
    }
}

/// From a caller with no console, the direct send fails with `NoConsole` and sends no break, and the
/// default asks the proxy instead of failing: its stops answer what the proxy answers.
#[skuld::test]
fn fixture_console_less_reporter() {
    let Some(mut report) = connect_reporter(ADDR_ENV) else {
        return;
    };
    assert_no_console();
    assert_refused_sends_are_not_sent();
    assert_the_direct_send_has_no_console();
    assert_the_default_asks_the_proxy();

    report_done(&mut report);
}
