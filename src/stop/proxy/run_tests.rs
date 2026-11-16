//! The proxy's sequence, against real consoles.
//!
//! Every test but the first starts the proxy for real: this test binary re-executed with the proxy's
//! arguments (its `main` calls `init` first), as cosca starts it, `detached()` with null stdio. A
//! wrong proxy sends Ctrl+C or Ctrl+Break to every process on the console it attached to, so those
//! tests are the `CTRL_PROXY` group: they run on CI, and a host runs them only after consenting
//! (`COSCA_TEST_CTRL_PROXY_CONSENT=1`) or turns them off (`COSCA_TEST_CTRL_PROXY=0`).
//!
//! Each asserts the proxy's answer before it reads anything from its target, so a proxy that ANSWERS
//! wrongly fails by assertion; the `Mutant:` line of a test names only mutants its assertions catch.
//! No test reaches the handler routine's close and shutdown branch, the closing check before the
//! generate, `Unconfirmed`, or the `NothingSent` answers of the failed Win32 calls, and the runner's
//! timeout is the only bound of a proxy that never generates, because the crate sets no timeout on
//! its own waits. Targets are the `test_child::ctrl_break` members: a member's ack says which event
//! reached its handler.

use windows::core::HRESULT;
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER};
use windows::Win32::System::Console::SetConsoleCtrlHandler;

use super::answer_for_failed_attach;
use crate::identity::windows_fixture::{deny_every_open_by_pid, drop_se_debug_privilege};
use crate::identity::{HostKernel, ProcessId, Resolved};
use crate::stop::proxy::protocol::{CtrlEvent, ProxyAnswer, ProxyArgs};
use crate::test_child::ctrl_break::{
    self, assert_acked_event, assert_in_our_console, connect_reporter, kill_release_reap, report_done, spawn_gui_root,
    spawn_member, spawn_uncontained_member, Handler,
};
use crate::test_child::IDENTITY_READ;
use crate::test_groups::{ctrl_proxy, Group};
use crate::ContainMode;

/// The arguments that name `target` by its identity.
fn args_for(target: ProcessId, event: CtrlEvent, caller: u32) -> ProxyArgs {
    let record = target.to_record().expect("a Windows identity has a record");
    ProxyArgs {
        target: record.pid,
        target_key: record.token,
        event,
        caller,
    }
}

/// Starts the proxy as a copy of this test binary with `args`, and returns the answer it exits with.
fn ask_proxy_with(args: ProxyArgs) -> ProxyAnswer {
    let exe = std::env::current_exe().expect("current_exe");
    let argv = args.to_argv(exe.as_os_str());
    let mut cmd = crate::test_child::command(crate::test_child::Console::Asked);
    cmd.executable(exe).args(argv);
    // As cosca starts it: no console of its own, so that it can attach to one.
    cmd.detached();
    cmd.stdin(crate::Stdio::null()).expect("null stdin");
    cmd.stdout(crate::Stdio::null()).expect("null stdout");
    cmd.stderr(crate::Stdio::null()).expect("null stderr");
    crate::test_reexec::scrub_env(|var| _ = cmd.env_remove(var));
    let child = cmd.spawn().expect("start the proxy");
    let status = child.wait().expect("wait for the proxy");
    let code = status
        .code()
        .unwrap_or_else(|| panic!("the proxy ended without a code: {status:?}"));
    ProxyAnswer::from_code(code).unwrap_or_else(|| panic!("the proxy's exit code {code:#x} is not an answer"))
}

/// Asks the proxy to send `event` to `child`'s console, on behalf of this process.
fn ask_proxy(child: &crate::Child, event: CtrlEvent) -> ProxyAnswer {
    ask_proxy_with(args_for(child.id().expect(IDENTITY_READ), event, std::process::id()))
}

/// Mutant: an error code is mapped to another row, or the rows are collapsed. Not in the group: it
/// sends nothing.
#[skuld::test]
fn a_failed_attach_is_answered_by_its_error() {
    let win32 = |code: u32| HRESULT::from_win32(code);
    assert_eq!(
        answer_for_failed_attach(win32(ERROR_INVALID_HANDLE.0)),
        ProxyAnswer::TargetHasNoConsole
    );
    assert_eq!(
        answer_for_failed_attach(win32(ERROR_ACCESS_DENIED.0)),
        ProxyAnswer::AttachDenied
    );
    assert_eq!(
        answer_for_failed_attach(win32(ERROR_INVALID_PARAMETER.0)),
        ProxyAnswer::TargetGone
    );
    // Any other refusal sent nothing: not ERROR_NOT_ENOUGH_MEMORY (8), and not an HRESULT of another
    // facility.
    for code in [HRESULT::from_win32(8), HRESULT(0x8000_4005_u32 as i32)] {
        assert_eq!(answer_for_failed_attach(code), ProxyAnswer::NothingSent, "{code:?}");
    }
}

/// Ctrl+Break to a contained child with a console of its own, which no group of the caller's
/// reaches. Mutant: the proxy sends Ctrl+C for Ctrl+Break (the ack is `C`), or answers other than
/// `Sent`.
#[skuld::test]
fn the_proxy_delivers_ctrl_break_to_a_contained_no_window_child(#[fixture(ctrl_proxy)] _group: &Group) {
    let (child, mut sock, _) = spawn_member(Handler::AckEvent, None, ContainMode::Strongest, |cmd| {
        _ = cmd.no_window()
    });
    assert_eq!(ask_proxy(&child, CtrlEvent::CtrlBreak), ProxyAnswer::Sent);
    assert_acked_event(&mut sock, "the member", CtrlEvent::CtrlBreak);
    kill_release_reap(&child, sock, false);
}

/// Ctrl+C to a child that was not created in a process group, with a console of its own. Mutant: the
/// proxy sends Ctrl+Break for Ctrl+C (the ack is `B`), or answers other than `Sent`.
#[skuld::test]
fn the_proxy_delivers_ctrl_c_to_an_uncontained_no_window_child(#[fixture(ctrl_proxy)] _group: &Group) {
    let (child, mut sock) = spawn_uncontained_member(Handler::AckEvent, |cmd| _ = cmd.no_window());
    assert_eq!(ask_proxy(&child, CtrlEvent::CtrlC), ProxyAnswer::Sent);
    assert_acked_event(&mut sock, "the member", CtrlEvent::CtrlC);
    kill_release_reap(&child, sock, false);
}

/// A proxy that inherits "Ctrl+C is ignored" still sees its own Ctrl+C, because it re-enables it, and
/// so sends it and answers `Sent`. The launcher is a reporter that ignores Ctrl+C itself (a process
/// inherits that from its parent), as a supervisor run under such a shell is. Mutant: the proxy
/// answers other than `Sent`, or sends the wrong event (the ack is not `C`). The mutant "the
/// re-enable is dropped" is not caught by an assertion: the proxy then waits for a copy that never
/// comes, with no cap, and this test ends only by the runner's timeout.
#[skuld::test]
fn the_proxy_delivers_ctrl_c_when_it_inherits_ctrl_c_ignored(#[fixture(ctrl_proxy)] _group: &Group) {
    ctrl_break::drive_reporter(IGNORING_LAUNCHER_TEST, IGNORING_LAUNCHER_ADDR_ENV, |cmd| {
        _ = cmd.no_window()
    });
}

/// The fully-qualified libtest path of [`fixture_ignoring_launcher_reporter`].
const IGNORING_LAUNCHER_TEST: &str = "stop::proxy::run::run_tests::fixture_ignoring_launcher_reporter";

/// The environment variable carrying the address the launcher reports to.
const IGNORING_LAUNCHER_ADDR_ENV: &str = "COSCA_FIXTURE_IGNORING_LAUNCHER_ADDR";

/// A launcher that ignores Ctrl+C, so the proxy it starts inherits that, and a target with a console
/// of its own that does not ignore it.
#[skuld::test]
fn fixture_ignoring_launcher_reporter() {
    let Some(mut report) = connect_reporter(IGNORING_LAUNCHER_ADDR_ENV) else {
        return;
    };
    // SAFETY: a null routine with `true` makes this process ignore Ctrl+C; no preconditions.
    unsafe { SetConsoleCtrlHandler(None, true) }.expect("ignore Ctrl+C");
    let (child, mut sock) = spawn_uncontained_member(Handler::AckEvent, |cmd| _ = cmd.no_window());
    assert_eq!(ask_proxy(&child, CtrlEvent::CtrlC), ProxyAnswer::Sent);
    assert_acked_event(&mut sock, "the member", CtrlEvent::CtrlC);
    kill_release_reap(&child, sock, false);
    report_done(&mut report);
}

/// The fully-qualified libtest path of [`fixture_callers_console_reporter`].
pub(crate) const REPORTER_TEST: &str = "stop::proxy::run::run_tests::fixture_callers_console_reporter";

/// The environment variable carrying the address the reporter reports to.
pub(crate) const ADDR_ENV: &str = "COSCA_FIXTURE_CALLERS_CONSOLE_ADDR";

/// A caller with a console of its own (it is started `no_window()`) and a child on that console, the
/// proxy being started on the caller's behalf: nothing is sent, so the member's ack is not read.
#[skuld::test]
fn fixture_callers_console_reporter() {
    let Some(mut report) = connect_reporter(ADDR_ENV) else {
        return;
    };
    let (child, sock) = spawn_uncontained_member(Handler::AckEvent, |_| {});
    // The member has no flags: it is on this process's console, which is what makes the answer below
    // about the caller and not about a console that merely looks alike.
    assert_in_our_console(child.pid(), "the member");
    assert_eq!(ask_proxy(&child, CtrlEvent::CtrlBreak), ProxyAnswer::ConsoleIsCallers);
    kill_release_reap(&child, sock, false);
    report_done(&mut report);
}

/// Mutant: the caller-console check is missing, so the proxy answers `Sent` and the event goes to the
/// caller's own console and every process on it, the caller included (the reporter's answer
/// assertion fails, or the event ends it before it reports and the driver reads no report). The
/// caller is a re-exec of this binary with a console of its own, never this test process.
#[skuld::test]
fn the_proxy_refuses_a_child_on_the_callers_console(#[fixture(ctrl_proxy)] _group: &Group) {
    ctrl_break::drive_reporter(REPORTER_TEST, ADDR_ENV, |cmd| _ = cmd.no_window());
}

/// A GUI-subsystem image has no console, whatever its creation flags. Mutant: a failed attach is
/// answered with another row.
#[skuld::test]
fn a_gui_child_has_no_console_to_attach(#[fixture(ctrl_proxy)] _group: &Group) {
    let (child, sock) = spawn_gui_root(|cmd| _ = cmd.no_window());
    assert_eq!(ask_proxy(&child, CtrlEvent::CtrlBreak), ProxyAnswer::TargetHasNoConsole);
    kill_release_reap(&child, sock, false);
}

/// A console image started `detached()` has no console. Mutant: as for the GUI image.
#[skuld::test]
fn a_detached_child_has_no_console_to_attach(#[fixture(ctrl_proxy)] _group: &Group) {
    let (child, sock, _) = spawn_member(Handler::Ack, None, ContainMode::Strongest, |cmd| _ = cmd.detached());
    assert_eq!(ask_proxy(&child, CtrlEvent::CtrlBreak), ProxyAnswer::TargetHasNoConsole);
    kill_release_reap(&child, sock, false);
}

/// An exited process whose handle is still held refuses the attach, differently from a process with
/// no console. Mutant: the refusal is answered `TargetHasNoConsole`, or the proxy takes the exited
/// process for gone.
#[skuld::test]
fn an_exited_child_whose_handle_is_held_is_refused_the_attach(#[fixture(ctrl_proxy)] _group: &Group) {
    let (child, sock, _) = spawn_member(Handler::Default, None, ContainMode::Strongest, |cmd| {
        _ = cmd.no_window()
    });
    child.kill().expect("kill");
    drop(sock);
    // The handle `child` holds keeps the pid from being reused while the proxy runs.
    child.wait().expect("the member's exit");
    assert_eq!(ask_proxy(&child, CtrlEvent::CtrlBreak), ProxyAnswer::AttachDenied);
}

/// A pid that another process holds now is not the target the caller named: the proxy answers
/// before it attaches. The member is live with a console of its own, and a break sent to it would end
/// it. Mutant: the proxy attaches by the bare pid (the answer is `Sent`).
#[skuld::test]
fn a_pid_held_by_another_process_is_gone(#[fixture(ctrl_proxy)] _group: &Group) {
    let (child, sock, _) = spawn_member(Handler::Default, None, ContainMode::Strongest, |cmd| {
        _ = cmd.no_window()
    });
    let other_holder = child.id().expect(IDENTITY_READ).with_other_value();
    assert_eq!(
        ask_proxy_with(args_for(other_holder, CtrlEvent::CtrlBreak, std::process::id())),
        ProxyAnswer::TargetGone
    );
    kill_release_reap(&child, sock, false);
}

/// `AttachConsole` takes `u32::MAX` for "the parent's console", not for a pid: no process has it, so
/// the proxy answers before it attaches. Mutant: the proxy answers a bad pid with another row.
#[skuld::test]
fn a_pid_no_process_has_is_gone(#[fixture(ctrl_proxy)] _group: &Group) {
    let args = ProxyArgs {
        target: u32::MAX,
        target_key: 0,
        event: CtrlEvent::CtrlBreak,
        caller: std::process::id(),
    };
    assert_eq!(ask_proxy_with(args), ProxyAnswer::TargetGone);
}

/// A target that refuses every open by pid exists but cannot be checked, so the proxy answers before
/// it attaches, and nothing is read from it. The target is live with a console of its own, and a break
/// sent to it would be acked. Mutant: the refusal is answered as another row (`TargetGone`), or the
/// proxy goes on without the check (the answer is `Sent`).
#[skuld::test]
fn a_target_that_refuses_every_open_by_pid_is_unreadable(#[fixture(ctrl_proxy)] _group: &Group) {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(a_target_that_refuses_every_open_by_pid_is_unreadable),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    // The proxy this process starts inherits its token: without `SeDebugPrivilege` it is refused too.
    drop_se_debug_privilege(&done);
    let (child, sock) = spawn_uncontained_member(Handler::Ack, |cmd| _ = cmd.no_window());
    let target = child.id().expect(IDENTITY_READ);
    deny_every_open_by_pid(child.pid());
    let (by_pid, _) = ProcessId::of_with(&HostKernel, child.pid());
    assert!(
        matches!(by_pid, Resolved::Unknown),
        "precondition: no open of the member by pid is granted: {by_pid:?}"
    );
    assert_eq!(
        ask_proxy_with(args_for(target, CtrlEvent::CtrlBreak, std::process::id())),
        ProxyAnswer::TargetUnreadable
    );
    kill_release_reap(&child, sock, false);
}
