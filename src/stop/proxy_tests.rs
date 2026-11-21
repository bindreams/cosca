//! The caller's side of the console-event proxy, against a fixture that stands in for it: a copy of the
//! testbin that answers the code its name says ([`crate::proxy_fixture`]). No console event is sent, so
//! none of these tests is in the `CTRL_PROXY` group. Each asserts the send's record
//! ([`assert_proxy_answered`], [`assert_no_break_sent`]) with the call's answer, and the refusals before
//! anything starts assert that the fixture never ran.
//!
//! The proxy started through the real program, and an event that arrives, are in
//! `proxy_real_tests.rs`.

use std::net::TcpStream;
use std::path::PathBuf;

use super::protocol::{exit_text, Cause, CtrlEvent, ProxyAnswer, ProxyArgs, ProxyExit, Step, VERSION};
use super::{exe_unreadable, failed_step, start_failed, wait_failed, CtrlProxy};
use crate::containment::SendOutcome;
use crate::error::Error;
use crate::stop::{self, StopTarget};
use crate::test_child::ctrl_break::{
    assert_no_break_sent, assert_proxy_answered, kill_release_reap, spawn_member, Handler,
};
use crate::test_child::IDENTITY_READ;
use crate::{Child, Command, ContainMode};

/// A fixture proxy that answers `code`: a copy of the testbin in a directory of its own.
pub(crate) struct Fixture {
    _dir: tempfile::TempDir,
    exe: PathBuf,
}

impl Fixture {
    pub(crate) fn answering(code: i32) -> Fixture {
        let dir = tempfile::tempdir().expect("a directory for the fixture proxy");
        let exe = dir.path().join(crate::proxy_fixture::exe_name(code));
        std::fs::copy(crate::test_child::testbin("cosca_testbin"), &exe).expect("copy the testbin");
        Fixture { _dir: dir, exe }
    }

    /// A fixture that reports its pid on the returned listener and answers `code` only once the test
    /// writes a byte to that connection.
    pub(crate) fn answering_when_told(code: i32) -> (Fixture, std::net::TcpListener) {
        let fixture = Fixture::answering(code);
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("listen for the fixture proxy");
        std::fs::write(
            crate::proxy_fixture::port_path(&fixture.exe),
            listener
                .local_addr()
                .expect("the listener's address")
                .port()
                .to_string(),
        )
        .expect("tell the fixture proxy where to report");
        (fixture, listener)
    }

    pub(crate) fn setting(&self) -> CtrlProxy {
        CtrlProxy::Executable(self.exe.clone())
    }

    /// What the fixture recorded; `None` when it never ran.
    pub(crate) fn ran(&self) -> Option<crate::proxy_fixture::Ran> {
        crate::proxy_fixture::read_record(&self.exe)
    }
}

/// The proxy's own program, held: the fixture proxy reports its pid and answers `Sent` only once told.
/// Both ends are real conditions with no time in them.
pub(crate) mod held_proxy {
    use std::io::{BufRead as _, Write as _};
    use std::sync::mpsc;

    use ::tokio::sync::oneshot;

    use super::Fixture;
    use crate::stop::proxy::protocol::ProxyAnswer;

    /// A fixture proxy that answers `Sent` once [`release`](Self::release) is called (or the test
    /// ends), and the pid it reports when it starts.
    pub(crate) struct Held {
        pub(crate) fixture: Fixture,
        pid: Option<oneshot::Receiver<u32>>,
        go: mpsc::Sender<()>,
    }

    impl Held {
        pub(crate) fn new() -> Held {
            let (fixture, listener) = Fixture::answering_when_told(ProxyAnswer::Sent.code());
            let (pid_tx, pid) = oneshot::channel();
            let (go, go_rx) = mpsc::channel::<()>();
            // A thread of the test, not a task: it blocks in `accept` and in `recv`, which must not be the
            // runtime's, and ends when the fixture has been told or the test is over.
            std::thread::spawn(move || {
                let (stream, _) = listener.accept().expect("the fixture proxy connects");
                let mut line = String::new();
                std::io::BufReader::new(&stream)
                    .read_line(&mut line)
                    .expect("the fixture proxy reports its pid");
                _ = pid_tx.send(line.trim().parse().expect("a pid"));
                // A release, or the test's end: either way the fixture is told to answer.
                _ = go_rx.recv();
                _ = (&stream).write_all(b"x");
            });
            Held {
                fixture,
                pid: Some(pid),
                go,
            }
        }

        /// The pid the proxy reported when it started.
        #[cfg(feature = "tokio")]
        pub(crate) async fn started(&mut self) -> u32 {
            self.pid
                .take()
                .expect("asked once")
                .await
                .expect("the proxy reports its pid")
        }

        /// The pid the proxy reported when it started, for a caller that is no task.
        pub(crate) fn started_blocking(&mut self) -> u32 {
            self.pid
                .take()
                .expect("asked once")
                .blocking_recv()
                .expect("the proxy reports its pid")
        }

        /// A handle that tells the proxy to answer, which a hook that runs at a block can hold.
        pub(crate) fn releaser(&self) -> mpsc::Sender<()> {
            self.go.clone()
        }

        /// Tells the proxy to answer. A proxy already told (by a hook that ran at a block) is not an error:
        /// the assertion about that block is the test's.
        #[cfg(feature = "tokio")]
        pub(crate) fn release(&self) {
            _ = self.go.send(());
        }
    }
}

/// A contained member that stops through `fixture`, as [`spawn_member`] makes it, with `configure`
/// applied to its command last.
fn member(fixture: &Fixture, configure: impl FnOnce(&mut Command)) -> (Child, TcpStream) {
    let (child, sock, _) = spawn_member(Handler::Ignore, None, ContainMode::Strongest, |cmd| {
        cmd.ctrl_proxy(fixture.setting());
        configure(cmd);
    });
    (child, sock)
}

/// A hidden-console member, so a test opens no window.
fn hidden_member(fixture: &Fixture) -> (Child, TcpStream) {
    member(fixture, |cmd| _ = cmd.no_window())
}

/// A hidden-console member contained by `mode`, whose stop sends Ctrl+C through `fixture`.
fn stopping_member(fixture: &Fixture, mode: ContainMode) -> (Child, TcpStream) {
    let (child, sock, _) = spawn_member(Handler::Ignore, None, mode, |cmd| {
        cmd.no_window();
        cmd.ctrl_proxy(fixture.setting());
        cmd.graceful_stop(|target| stop::send_console_event_via_proxy(target, CtrlEvent::CtrlC));
    });
    (child, sock)
}

/// The error `send_console_event_via_proxy` answers to `child`.
fn send_err(child: &Child, event: CtrlEvent) -> Error {
    stop::send_console_event_via_proxy(&StopTarget::from(child), event).expect_err("the send is refused")
}

/// The exit of a proxy that sent nothing because a step failed.
fn nothing_sent() -> ProxyExit {
    Cause::new(Step::Generate, Some(5)).into()
}

fn unsupported_detail(err: &Error) -> &str {
    match err {
        Error::Unsupported { detail, .. } => detail,
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

/// `first` is in `text` before `second`.
fn names_in_order(text: &str, first: &str, second: &str) {
    let (a, b) = (text.find(first), text.find(second));
    assert!(
        matches!((a, b), (Some(a), Some(b)) if a < b),
        "{text:?} must name {first} first and {second} second"
    );
}

// What the proxy is asked =====

/// `Sent` is `Ok`, and the proxy is started with the child's identity, the event and this process as the
/// caller, with no console of its own, told it is the proxy by the environment. Mutants: the other event,
/// the pid with another key, another caller, the proxy started attached to a console, the variable not
/// set or set to another role, `Sent` not `Ok`.
#[skuld::test]
fn a_sent_answer_is_ok_and_the_proxy_is_asked_for_this_child_and_event() {
    for event in [CtrlEvent::CtrlBreak, CtrlEvent::CtrlC] {
        let fixture = Fixture::answering(ProxyAnswer::Sent.code());
        let (child, sock) = hidden_member(&fixture);
        stop::send_console_event_via_proxy(&StopTarget::from(&child), event).expect("Sent is Ok");
        assert_proxy_answered(child.pid(), event, ProxyAnswer::Sent);
        let ran = fixture.ran().expect("the fixture proxy ran");
        let record = child.id().expect(IDENTITY_READ).to_record().expect("a record");
        assert_eq!(
            ProxyArgs::parse(&ran.argv),
            Ok(ProxyArgs {
                target: record.pid,
                target_key: record.token,
                event,
                caller: std::process::id(),
            }),
            "{ran:?}"
        );
        assert_eq!(
            ran.helper.as_deref(),
            Some(std::ffi::OsStr::new(crate::role::CTRL_PROXY)),
            "the proxy is started as a helper in the proxy role: {ran:?}"
        );
        assert_eq!(std::path::Path::new(&ran.argv[0]), fixture.exe, "{ran:?}");
        assert!(!ran.had_console, "the proxy has no console of its own: {ran:?}");
        kill_release_reap(&child, sock, false);
    }
}

/// The hook has run in this test binary (its `main` calls it), so the default setting,
/// `HostExecutable`, panics nowhere: the default stop and the proxy send answer an exited child `Ok`, and
/// the exit is looked at before a proxy is started (a started proxy is this test binary playing the proxy,
/// and its answer is recorded: [`assert_no_break_sent`] sees it). The panic is the other side of the same
/// check, in `tests/ctrl_proxy_host.rs`. Mutants: the check panics whatever the hook says; the look at the
/// exit is skipped, so the proxy is started and answers.
#[skuld::test]
fn nothing_panics_once_the_hook_has_run_and_an_exited_child_starts_no_proxy() {
    assert!(crate::helpers_initialized(), "the test binary's `main` calls the hook");
    let (child, sock, _) = spawn_member(Handler::Ignore, None, ContainMode::Strongest, |cmd| {
        cmd.no_window().ctrl_proxy(CtrlProxy::HostExecutable);
    });
    assert_eq!(StopTarget::from(&child).ctrl_proxy(), &CtrlProxy::HostExecutable);
    child.kill().expect("kill the member");
    child.wait().expect("see its exit, reaping nothing");
    drop(sock);

    child
        .terminate()
        .unwrap_or_else(|e| panic!("an exited child is Ok: {e:?}"));
    stop::send_console_event_via_proxy(&StopTarget::from(&child), CtrlEvent::CtrlBreak)
        .unwrap_or_else(|e| panic!("an exited child is Ok: {e:?}"));
    assert_no_break_sent();
}

// What each answer means =====

/// Connects to a listener when dropped, which releases a thread blocked in its `accept`.
struct AcceptRelease(std::net::SocketAddr);

impl Drop for AcceptRelease {
    fn drop(&mut self) {
        drop(TcpStream::connect(self.0));
    }
}

/// The proxy's own program, held, while `ask` runs on this thread: a fixture that answers `answer` once told.
/// The child is ended and its exit seen after the proxy has started and before it answers, which is the one
/// thing cosca's look at the start of the call could not have seen. Fails by assertion if `ask` ends without
/// having started the proxy.
fn asking_while_the_child_exits<T>(
    child: &Child,
    held: &(Fixture, std::net::TcpListener),
    ask: impl FnOnce() -> T,
) -> T {
    use std::io::{BufRead as _, Write as _};

    let listener = &held.1;
    std::thread::scope(|scope| {
        let ender = scope.spawn(|| {
            let (stream, _) = listener.accept().expect("a connection to the fixture's listener");
            let mut line = String::new();
            std::io::BufReader::new(&stream)
                .read_line(&mut line)
                .expect("the fixture proxy reports its pid");
            assert!(!line.is_empty(), "the call ended without having started the proxy");
            child.kill().expect("kill the member");
            child.wait().expect("see its exit, reaping nothing");
            (&stream).write_all(b"x").expect("tell the fixture proxy to answer");
        });
        // A call that never started the proxy, or panicked, has left the thread above in `accept`: a
        // connection ends it, made on unwind too, which the scope's join would otherwise wait on for ever.
        let release = AcceptRelease(listener.local_addr().expect("the listener's address"));
        let asked = ask();
        drop(release);
        ender.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        asked
    })
}

/// A child that exits while the proxy is being asked is answered as `send_ctrl_break_to_group` answers one:
/// `Ok`. The proxy cannot attach to an exited process whose handle is held (`AttachDenied`), finds no such
/// identity (`TargetGone`), or finds the process has no console (`TargetHasNoConsole`), and cosca's look
/// after the answer finds the exit. Mutants: the answer is always an error; the exit is not looked at, for
/// one of the three.
#[skuld::test]
fn a_refused_attach_by_a_child_that_exits_during_the_ask_is_ok() {
    for answer in [
        ProxyAnswer::AttachDenied,
        ProxyAnswer::TargetGone,
        ProxyAnswer::TargetHasNoConsole,
    ] {
        let held = Fixture::answering_when_told(answer.code());
        let (child, sock) = hidden_member(&held.0);
        asking_while_the_child_exits(&child, &held, || {
            stop::send_console_event_via_proxy(&StopTarget::from(&child), CtrlEvent::CtrlBreak)
        })
        .unwrap_or_else(|e| panic!("{answer:?} for a child that exited is Ok: {e:?}"));
        assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, answer);
        drop(sock);
    }
}

/// A child that has exited before the call is answered at the first look, and the proxy is not started: a
/// root target answers `Ok` as every platform does for an exited child, `terminate_tree` the "root
/// exited" error that claims no event went out, and `graceful_shutdown_tree` goes on to its grace and
/// sweep with the debug line that it sent no event. The fixture answers `Sent`, so a call that asked it
/// would record an answer. Mutants: the look comes after the gates or the start (the fixture ran, an answer
/// is recorded); a root target answers the tree's error.
#[skuld::test]
fn a_child_that_has_exited_is_answered_before_the_proxy_is_started() {
    crate::log_capture::install();
    for (tree, mode) in [
        (false, ContainMode::Strongest),
        (true, ContainMode::Strongest),
        (true, ContainMode::TreeWalk),
    ] {
        let exited = |fixture: &Fixture| {
            let (child, sock) = stopping_member(fixture, mode);
            child.kill().expect("kill the member");
            child.wait().expect("see its exit, reaping nothing");
            drop(sock);
            child
        };

        let fixture = Fixture::answering(ProxyAnswer::Sent.code());
        let child = exited(&fixture);
        if tree {
            let err = child
                .terminate_tree()
                .expect_err("nothing was sent to a tree whose root had exited");
            let Error::Unassessable { detail, .. } = &err else {
                panic!("{mode:?}: {err:?}")
            };
            assert!(detail.contains("nothing was sent"), "{mode:?}: {detail}");
            assert!(!detail.contains("CTRL_C"), "{mode:?}: no event went out: {detail}");
        } else {
            child
                .terminate()
                .unwrap_or_else(|e| panic!("an exited child is Ok: {e:?}"));
            stop::send_console_event_via_proxy(&StopTarget::from(&child), CtrlEvent::CtrlBreak)
                .unwrap_or_else(|e| panic!("an exited child is Ok: {e:?}"));
        }
        assert_no_break_sent();
        assert!(fixture.ran().is_none(), "{mode:?}, tree {tree}: the proxy was started");

        if tree {
            let fixture = Fixture::answering(ProxyAnswer::Sent.code());
            let child = exited(&fixture);
            let mark = crate::log_capture::mark();
            child
                .graceful_shutdown_tree(std::time::Duration::ZERO)
                .unwrap_or_else(|e| panic!("{mode:?}: the call goes on and ends the tree: {e:?}"));
            assert_no_break_sent();
            assert!(fixture.ran().is_none(), "{mode:?}: the proxy was started");
            let logged = crate::log_capture::records_since_on_current_thread(
                mark,
                &format!("graceful_shutdown_tree({})", child.pid()),
            );
            assert!(
                logged
                    .iter()
                    .any(|(level, text)| *level == log::Level::Debug && text.contains("sent no CTRL_C")),
                "{mode:?}: the call says it sent no event: {logged:?}"
            );
        }
    }
}

/// The same answers for a child that has not exited: the error says what was observed, the answer with
/// its code and that the child had not exited when cosca looked, and lists the causes it cannot tell
/// apart. A child that has a console is not offered `stop::send_wm_close`. Mutants: the exit is assumed; the
/// code is dropped; the look is not mentioned; `Ok`; the shared remedies name `send_wm_close`.
#[skuld::test]
fn a_refused_attach_to_a_running_child_is_unsupported() {
    for answer in [ProxyAnswer::AttachDenied, ProxyAnswer::TargetGone] {
        let fixture = Fixture::answering(answer.code());
        let (child, sock) = hidden_member(&fixture);
        let err = send_err(&child, CtrlEvent::CtrlBreak);
        let detail = unsupported_detail(&err);
        assert!(detail.contains("did not succeed"), "{detail}");
        assert!(detail.contains(&format!("answer {answer:?}")), "the answer: {detail}");
        assert!(detail.contains("had not exited when cosca looked"), "{detail}");
        assert!(detail.contains("may still be running"), "{detail}");
        assert!(
            detail.contains(&format!("exit {}", answer.code())),
            "the code: {detail}"
        );
        names_in_order(detail, "Child::kill", "Command::graceful_stop");
        assert!(!detail.contains("send_wm_close"), "{detail}");
        assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, answer);
        kill_release_reap(&child, sock, false);
    }
}

/// A child the proxy found no console for, that had not exited: the error says what was observed and
/// lists as possible causes that the child has none or has not set it up yet, and names `Child::kill`
/// first, `stop::send_wm_close` (the action that fits a GUI child) second and `Command::graceful_stop` last.
/// Mutants: the text of `AttachDenied` is used (the missing console is not listed as a cause); the remedies
/// swapped or dropped, or `send_wm_close` not named; a cause stated as the conclusion.
#[skuld::test]
fn a_target_with_no_console_is_unsupported_and_names_the_remedies() {
    let fixture = Fixture::answering(ProxyAnswer::TargetHasNoConsole.code());
    let (child, sock) = hidden_member(&fixture);
    let err = send_err(&child, CtrlEvent::CtrlC);
    let detail = unsupported_detail(&err);
    assert!(detail.contains("did not succeed"), "{detail}");
    assert!(detail.contains("answer TargetHasNoConsole"), "{detail}");
    assert!(detail.contains("had not exited when cosca looked"), "{detail}");
    assert!(detail.contains("may have no console"), "{detail}");
    assert!(detail.contains("may not have started running yet"), "{detail}");
    names_in_order(detail, "Child::kill", "stop::send_wm_close");
    names_in_order(detail, "stop::send_wm_close", "Command::graceful_stop");
    assert_proxy_answered(child.pid(), CtrlEvent::CtrlC, ProxyAnswer::TargetHasNoConsole);
    kill_release_reap(&child, sock, false);
}

/// The child's console is the caller's. A child created with the group flag is named the direct send;
/// one without is named the setter that gives it a group. Mutants: the two texts are one; the setter is
/// named for a child that has the flag.
#[skuld::test]
fn the_callers_console_names_the_direct_send_or_the_setter_by_the_childs_group() {
    let fixture = Fixture::answering(ProxyAnswer::ConsoleIsCallers.code());
    let (child, sock) = hidden_member(&fixture);
    let err = send_err(&child, CtrlEvent::CtrlBreak);
    let detail = unsupported_detail(&err);
    assert!(detail.contains("stop::send_ctrl_break_to_group"), "{detail}");
    assert!(
        !detail.contains("new_process_group"),
        "the child has the flag: {detail}"
    );
    assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::ConsoleIsCallers);
    kill_release_reap(&child, sock, false);

    let (child, sock) = member(&fixture, |cmd| _ = cmd.no_window().new_process_group(false));
    let err = send_err(&child, CtrlEvent::CtrlBreak);
    let detail = unsupported_detail(&err);
    assert!(detail.contains("Command::new_process_group"), "{detail}");
    assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::ConsoleIsCallers);
    kill_release_reap(&child, sock, false);
}

/// A proxy of another version, or one that did not understand the arguments, is `Unsupported` naming
/// the version this cosca speaks. Mutant: `Usage` is mapped as a failed step.
#[skuld::test]
fn a_version_the_proxy_does_not_speak_names_ours() {
    for answer in [ProxyAnswer::VersionMismatch, ProxyAnswer::Usage] {
        let fixture = Fixture::answering(answer.code());
        let (child, sock) = hidden_member(&fixture);
        let err = send_err(&child, CtrlEvent::CtrlBreak);
        let detail = unsupported_detail(&err);
        assert!(detail.contains(&format!("protocol version {VERSION}")), "{detail}");
        assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, answer);
        kill_release_reap(&child, sock, false);
    }
}

/// A helper that refuses the role cosca named (its exit is `role::UNKNOWN_HELPER_ROLE`: it never played
/// one) is `Unsupported`, nothing sent, naming the program and the same-cosca remedy, as for a version the
/// proxy does not speak. Mutant: the code is read as "no answer, the event may have been sent".
#[skuld::test]
fn a_helper_that_refuses_the_role_sent_nothing_and_names_the_remedy() {
    let fixture = Fixture::answering(crate::role::UNKNOWN_HELPER_ROLE);
    let (child, sock) = hidden_member(&fixture);
    let err = send_err(&child, CtrlEvent::CtrlBreak);
    let detail = unsupported_detail(&err);
    assert!(detail.contains(&fixture.exe.display().to_string()), "{detail}");
    assert!(detail.contains("nothing was sent"), "{detail}");
    assert!(detail.contains("built from the same cosca"), "{detail}");
    assert_no_break_sent();
    kill_release_reap(&child, sock, false);
}

/// A program that says it has no proxy is `Unsupported` naming the program that was started. Mutants:
/// the executable is not named.
#[skuld::test]
fn a_program_with_no_proxy_is_named() {
    let fixture = Fixture::answering(ProxyAnswer::NoProxyHere.code());
    let (child, sock) = hidden_member(&fixture);
    let err = send_err(&child, CtrlEvent::CtrlBreak);
    let detail = unsupported_detail(&err);
    assert!(detail.contains(&fixture.exe.display().to_string()), "{detail}");
    assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::NoProxyHere);
    kill_release_reap(&child, sock, false);
}

/// A proxy that failed a step says which, and the Win32 error it met: through a real send, the error is
/// `Io` with the text naming the step, the code's `io::ErrorKind`, and an `io::Error` with that code as its
/// source, and the proxy's exit is what the send records. Mutant: the code is dropped, truncated or folded
/// into the text only.
#[skuld::test]
fn a_failed_step_is_an_error_that_names_the_step_and_holds_its_code() {
    // ERROR_TIMEOUT: above 0xFF, and a kind other than `Other`.
    const ERROR_TIMEOUT: i32 = 1460;
    let kind = std::io::Error::from_raw_os_error(ERROR_TIMEOUT).kind();
    assert_ne!(kind, std::io::ErrorKind::Other, "the code has a kind of its own");
    let cause = Cause::new(Step::AttachConsole, Some(ERROR_TIMEOUT));
    let fixture = Fixture::answering(cause.code());
    let (child, sock) = hidden_member(&fixture);
    let err = send_err(&child, CtrlEvent::CtrlBreak);
    let Error::Io(io) = &err else { panic!("{err:?}") };
    let text = io.to_string();
    assert!(text.contains("nothing was sent"), "{text}");
    assert!(text.contains(Step::AttachConsole.name()), "{text}");
    assert_eq!(crate::error::first_os_code(&err), Some(ERROR_TIMEOUT), "{err:?}");
    assert_eq!(io.kind(), kind, "{err:?}");
    assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, cause);
    kill_release_reap(&child, sock, false);
}

/// A step that failed with no Win32 code the exit code can carry is named, and the error says so: no code is
/// invented, and the kind is `Other`. Mutant: a missing code reads as 0.
#[skuld::test]
fn a_failed_step_with_no_os_code_is_named_and_has_none() {
    let cause = Cause::new(Step::ConsoleClosing, None);
    let fixture = Fixture::answering(cause.code());
    let (child, sock) = hidden_member(&fixture);
    let err = send_err(&child, CtrlEvent::CtrlBreak);
    let Error::Io(io) = &err else { panic!("{err:?}") };
    let text = io.to_string();
    assert!(text.contains(cause.step.name()), "{text}");
    assert!(text.contains("no Win32 code the exit code can carry"), "{text}");
    assert_eq!(io.kind(), std::io::ErrorKind::Other, "{err:?}");
    assert_eq!(crate::error::first_os_code(&err), None, "{err:?}");
    assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, cause);
    kill_release_reap(&child, sock, false);
}

/// The error of every step, with codes below and above a byte and the widest: the text names the step and
/// the exit as `exit_text` shows it, and the source holds the code. Mutant: the exit is dropped from the
/// text, printed in decimal, or another cause's.
#[skuld::test]
fn every_failed_step_names_itself_and_holds_its_code() {
    for step in Step::ALL {
        for code in [5, 1168, 0xFFFF] {
            let cause = Cause::new(step, Some(code));
            let io = failed_step(cause, "CTRL_BREAK");
            let text = io.to_string();
            assert!(text.contains(step.name()), "{step:?}: {text}");
            assert!(!text.contains("no Win32 code"), "{step:?}: {text}");
            assert!(
                text.contains(&format!("(exit {})", exit_text(cause.code()))),
                "the exit: {step:?}: {text}"
            );
            assert_eq!(crate::error::first_os_code(&io), Some(code), "{step:?}: {io:?}");
            assert_eq!(io.kind(), std::io::Error::from_raw_os_error(code).kind(), "{step:?}");
        }
        let cause = Cause::new(step, None);
        let io = failed_step(cause, "CTRL_BREAK");
        let text = io.to_string();
        assert!(text.contains(step.name()), "{step:?}: {text}");
        assert!(
            text.contains(&format!("(exit {})", exit_text(cause.code()))),
            "the exit: {step:?}: {text}"
        );
        assert_eq!(crate::error::first_os_code(&io), None, "{step:?}: {io:?}");
    }
}

/// Whether the event was sent is unknown: `Unassessable`, for an exit that is no answer (0, a code outside
/// the protocol's, the codes 156 and 160 that no proxy of it gives, a value of the cause range with no step,
/// an NTSTATUS), with the code shown as `exit_text` shows it. Mutant: an unknown code is an error that says
/// nothing was sent.
#[skuld::test]
fn an_exit_that_is_no_answer_is_unassessable() {
    for (code, shown) in [
        (0, "0"),
        (3, "3"),
        (156, "156"),
        (160, "160"),
        (0x2000_0000, "0x20000000"),
        (0xC000_013A_u32 as i32, "0xc000013a"),
    ] {
        let fixture = Fixture::answering(code);
        let (child, sock) = hidden_member(&fixture);
        let err = send_err(&child, CtrlEvent::CtrlBreak);
        let Error::Unassessable { detail, .. } = &err else {
            panic!("{err:?}")
        };
        assert!(detail.contains("unknown"), "{detail}");
        assert!(
            detail.contains(&format!("exited with code {shown},")),
            "the code: {detail}"
        );
        assert_no_break_sent();
        kill_release_reap(&child, sock, false);
    }
}

/// `Unconfirmed` is `Unassessable` with the event possibly sent, and the answer is recorded. Mutants: `Ok`;
/// an error that says nothing was sent.
#[skuld::test]
fn an_unconfirmed_answer_is_unassessable() {
    let fixture = Fixture::answering(ProxyAnswer::Unconfirmed.code());
    let (child, sock) = hidden_member(&fixture);
    let err = send_err(&child, CtrlEvent::CtrlBreak);
    let Error::Unassessable { detail, .. } = &err else {
        panic!("{err:?}")
    };
    assert!(detail.contains("unknown"), "{detail}");
    assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::Unconfirmed);
    kill_release_reap(&child, sock, false);
}

/// A child created with `detached()` is asked through the proxy like any other, as it may allocate or
/// attach a console later: the proxy's own answer for the common case, no console, is `Unsupported`,
/// naming `Child::kill` first and `Command::graceful_stop` second. Mutants: a gate that refuses a
/// detached child before the proxy starts (the fixture never ran); the remedies are swapped.
#[skuld::test]
fn a_detached_child_is_asked_and_gets_the_proxys_no_console_answer() {
    let fixture = Fixture::answering(ProxyAnswer::TargetHasNoConsole.code());
    let (child, sock) = member(&fixture, |cmd| _ = cmd.detached());
    let err = send_err(&child, CtrlEvent::CtrlBreak);
    let detail = unsupported_detail(&err);
    assert!(detail.contains("answer TargetHasNoConsole"), "{detail}");
    names_in_order(detail, "Child::kill", "Command::graceful_stop");
    assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::TargetHasNoConsole);
    assert!(
        fixture.ran().is_some(),
        "the proxy was not asked about a detached child"
    );
    kill_release_reap(&child, sock, false);
}

// Refusals before anything starts =====

/// A child with no identity cannot be named exactly, so the proxy, which names its target by
/// identity, is not started. Mutants: the proxy is started with a bare pid.
#[skuld::test]
fn a_child_with_no_identity_is_refused_before_the_proxy_starts() {
    let fixture = Fixture::answering(ProxyAnswer::Sent.code());
    let mut child = crate::test_child::over_fake::child_over(&crate::os_process::fake::FakeProcess::new([
        crate::os_process::fake::Answer::Running,
    ]));
    child.id = None;
    child.ctrl_proxy = std::sync::Arc::new(fixture.setting());
    let err = send_err(&child, CtrlEvent::CtrlBreak);
    let detail = unsupported_detail(&err);
    assert!(detail.contains("no identity"), "{detail}");
    names_in_order(detail, "Child::kill", "Command::graceful_stop");
    assert!(!detail.contains("  "), "a run of spaces: {detail:?}");
    assert_no_break_sent();
    assert!(
        fixture.ran().is_none(),
        "the proxy was started for a child with no identity"
    );
}

/// A child a system service created on a UAC consent is refused, as the direct send refuses it, with
/// nothing started. Mutants: the gate is left to the proxy.
#[skuld::test]
fn an_elevated_child_is_refused_before_anything_starts() {
    use crate::containment::windows::ConsoleFacts;

    let fixture = Fixture::answering(ProxyAnswer::Sent.code());
    let mut child = crate::test_child::over_fake::child_over(&crate::os_process::fake::FakeProcess::new([
        crate::os_process::fake::Answer::Running,
    ]));
    child.console = ConsoleFacts {
        group: true,
        ..ConsoleFacts::uac_elevated()
    };
    child.ctrl_proxy = std::sync::Arc::new(fixture.setting());
    let err = send_err(&child, CtrlEvent::CtrlBreak);
    let detail = unsupported_detail(&err);
    assert!(detail.contains("did not create this child"), "{detail}");
    assert!(detail.contains("kill()"), "{detail}");
    assert!(!detail.contains("  "), "a run of spaces: {detail:?}");
    assert_no_break_sent();
    assert!(fixture.ran().is_none(), "the proxy was started for an elevated child");
}

/// `plan` maps the facts fixed at the spawn to the plan `send` acts on (and decides the missing-hook panic
/// by): with the default proxy an elevated child is `RefuseElevated`, one with no identity is
/// `RefuseNoIdentity`, a plain child is `StartHost`; with an `Executable` setting a plain child is
/// `StartExecutable`. Built on the existing `child_over` fakes. Mutant: `plan` looks at the setting before the
/// elevated fact (an elevated child under `HostExecutable` is `StartHost`), or before the identity.
#[skuld::test]
fn the_plan_of_a_send_follows_the_facts_fixed_at_the_spawn() {
    use super::{plan, Plan};
    use crate::containment::windows::ConsoleFacts;

    let child_with = |configure: &dyn Fn(&mut Child)| {
        let mut child = crate::test_child::over_fake::child_over(&crate::os_process::fake::FakeProcess::new([
            crate::os_process::fake::Answer::Running,
        ]));
        child.ctrl_proxy = std::sync::Arc::new(CtrlProxy::HostExecutable);
        configure(&mut child);
        child
    };

    let plain = child_with(&|_| {});
    assert!(matches!(plan(&StopTarget::from(&plain)), Plan::StartHost(_)));
    let elevated = child_with(&|child| {
        child.console = ConsoleFacts {
            group: true,
            ..ConsoleFacts::uac_elevated()
        }
    });
    assert!(matches!(plan(&StopTarget::from(&elevated)), Plan::RefuseElevated));
    let no_identity = child_with(&|child| child.id = None);
    assert!(matches!(plan(&StopTarget::from(&no_identity)), Plan::RefuseNoIdentity));
    let named = child_with(&|child| child.ctrl_proxy = std::sync::Arc::new(CtrlProxy::Executable("proxy.exe".into())));
    assert!(matches!(
        plan(&StopTarget::from(&named)),
        Plan::StartExecutable(_, exe) if exe == std::path::Path::new("proxy.exe")
    ));
}

/// Decided here because the hook-less binary cannot build an elevated or identity-less child. With the
/// hook not called: panics only for the plan that starts this program; with it called, none. Mutants: every
/// plan panics; a refusal plan panics. Which facts give which plan is pinned by
/// `the_plan_of_a_send_follows_the_facts_fixed_at_the_spawn`.
#[skuld::test]
fn only_a_plan_that_starts_this_program_panics_without_the_hook() {
    use super::{require_helpers_initialized, Plan};
    use crate::identity::ProcessId;

    let panics = |plan: Plan, hook_called: bool| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            require_helpers_initialized(&plan, hook_called)
        }))
        .is_err()
    };
    let id = ProcessId::current();

    assert!(panics(Plan::StartHost(id), false), "this program would be the proxy");
    assert!(
        !panics(Plan::StartExecutable(id, std::path::Path::new("proxy.exe")), false),
        "a named executable is no copy of this program"
    );
    assert!(!panics(Plan::RefuseElevated, false), "an elevated child is refused");
    assert!(
        !panics(Plan::RefuseNoIdentity, false),
        "a child with no identity is refused"
    );
    for plan in [
        Plan::StartHost(id),
        Plan::StartExecutable(id, std::path::Path::new("proxy.exe")),
        Plan::RefuseElevated,
        Plan::RefuseNoIdentity,
    ] {
        assert!(!panics(plan, true), "the hook was called");
    }
}

// What a call does with the answer =====

/// The calls run the action on a root target and on a tree target (over a job object and over a tree
/// walk), and each answers what the prepared send did: `Sent` is `Ok` for all, and an error that sent
/// nothing is the call's error. Mutants: a tree target does not take the mechanism's route (its answer
/// is a root's); the action's error is dropped; one mechanism's route does not carry a `Sent`.
#[skuld::test]
fn the_calls_answer_what_the_proxy_answered() {
    for (answer, ok) in [(ProxyExit::from(ProxyAnswer::Sent), true), (nothing_sent(), false)] {
        for (tree, mode) in [
            (false, ContainMode::Strongest),
            (true, ContainMode::Strongest),
            (true, ContainMode::TreeWalk),
        ] {
            let fixture = Fixture::answering(answer.code());
            let (child, sock) = stopping_member(&fixture, mode);
            let called = if tree {
                child.terminate_tree()
            } else {
                child.terminate()
            };
            assert_eq!(called.is_ok(), ok, "{answer:?}, tree: {tree}, {mode:?}: {called:?}");
            assert_proxy_answered(child.pid(), CtrlEvent::CtrlC, answer);
            kill_release_reap(&child, sock, tree);
        }
    }
}

/// A proxy answer that may have sent the event (`Unconfirmed`) is a send that went out: a tree call
/// goes on to its grace and sweep, which end the member, and keeps the answer as its cooperative error
/// (a sweep that proves the tree clear discards it, saying so). One that sent nothing (a failed step)
/// is a refused send: the call ends with it, and the tree runs. Both mechanisms a Windows tree is
/// signalled by are asked: a job object, and a tree walk.
///
/// Mutants: an `Unassessable` answer is read as a send that was not made (the call ends at it, the
/// member runs on); a refused send is read as one that went out (the grace and sweep run).
#[skuld::test]
fn a_tree_call_goes_on_after_a_send_that_may_have_gone_out_and_ends_after_one_that_did_not() {
    crate::log_capture::install();
    for mode in [ContainMode::Strongest, ContainMode::TreeWalk] {
        for answer in [ProxyExit::from(ProxyAnswer::Unconfirmed), nothing_sent()] {
            let fixture = Fixture::answering(answer.code());
            let (child, sock) = stopping_member(&fixture, mode);
            let mark = crate::log_capture::mark();
            let called = child.graceful_shutdown_tree(std::time::Duration::ZERO);
            assert_proxy_answered(child.pid(), CtrlEvent::CtrlC, answer);
            let logged = crate::log_capture::records_since_on_current_thread(
                mark,
                &format!("graceful_shutdown_tree({})", child.pid()),
            );
            if answer == ProxyAnswer::Unconfirmed.into() {
                called.unwrap_or_else(|e| panic!("{mode:?}: the sweep ends the member: {e:?}"));
                assert!(
                    logged.iter().any(|(level, text)| *level == log::Level::Debug
                        && text.contains("discarding the superseded")
                        && text.contains("whether the child received it is unknown")),
                    "{mode:?}: the call kept the answer through its sweep: {logged:?}"
                );
                drop(sock);
            } else {
                let err = called.expect_err("a refused send ends the call");
                assert!(
                    matches!(&err, Error::Io(e) if e.to_string().contains("nothing was sent")),
                    "{mode:?}: {err:?}"
                );
                assert_eq!(
                    child.is_alive(),
                    crate::identity::Liveness::Alive,
                    "{mode:?}: no grace, no sweep"
                );
                kill_release_reap(&child, sock, true);
            }
        }
    }
}

/// On a root target, an answer that may have sent the event is recorded as a send that was made: a
/// shutdown that goes on after an action that ignored the call's error words its kill's `earlier` as the
/// event; a refused send leaves "the stop action". Mutants: either answer is recorded as the other.
#[skuld::test]
fn a_root_records_a_send_that_may_have_gone_out_as_made() {
    for (answer, earlier) in [
        (ProxyExit::from(ProxyAnswer::Unconfirmed), "the CTRL_C"),
        (nothing_sent(), "the stop action"),
    ] {
        let fixture = Fixture::answering(answer.code());
        let (child, sock, _) = spawn_member(Handler::Ignore, None, ContainMode::Strongest, |cmd| {
            cmd.no_window();
            cmd.ctrl_proxy(fixture.setting());
            cmd.graceful_stop(|target| {
                // An action that goes on whatever the send answered.
                _ = stop::send_console_event_via_proxy(target, CtrlEvent::CtrlC);
                Ok(())
            });
        });
        let (acted, said) = crate::child::graceful::shutdown::run_ready(crate::child::graceful::shutdown::stop_root(
            &crate::child::graceful::shutdown::BlockingDriver(&child),
        ));
        acted.expect("the action ignored the send's answer");
        assert_eq!(said, earlier, "{answer:?}");
        assert_proxy_answered(child.pid(), CtrlEvent::CtrlC, answer);
        kill_release_reap(&child, sock, false);
    }
}

/// A proxy that cannot be started is an I/O error that says a console-event proxy was being started,
/// names its path, and says nothing was sent, over the OS's own error as its source, and records no
/// send. Mutants: the bare spawn error; the path or the reason is left out.
#[skuld::test]
fn a_proxy_that_cannot_be_started_says_so_and_names_its_path() {
    let missing = std::env::temp_dir().join("cosca-no-such-proxy-for-this-test.exe");
    assert!(!missing.exists(), "the path must name no file");
    let (child, sock, _) = spawn_member(Handler::Ignore, None, ContainMode::Strongest, |cmd| {
        cmd.no_window();
        cmd.ctrl_proxy(CtrlProxy::Executable(missing.clone()));
    });
    let err = send_err(&child, CtrlEvent::CtrlBreak);
    let Error::Io(io) = &err else { panic!("{err:?}") };
    assert_eq!(
        io.kind(),
        std::io::ErrorKind::NotFound,
        "the OS's kind is kept: {err:?}"
    );
    let text = io.to_string();
    assert!(text.contains("nothing was sent"), "{text}");
    assert!(text.contains("console-event proxy"), "{text}");
    assert!(text.contains(&missing.display().to_string()), "{text}");
    assert!(
        std::error::Error::source(io).is_some(),
        "the OS's error is the source: {err:?}"
    );
    assert_no_break_sent();
    kill_release_reap(&child, sock, false);
}

// A tree whose root has exited =====

/// The proxy cannot attach, and cosca's look after its answer finds the tree's root exited (it exited
/// while the proxy was being asked): nothing was sent, for either tree call and both mechanisms, whichever
/// of the three answers the proxy gave. `terminate_tree` ends with an error that says so and claims no event
/// went out; `graceful_shutdown_tree` goes on, with the debug line that it sent no event, and answers `Ok`.
///
/// Mutants: the exit is answered `Ok` as for a root target (`terminate_tree` is `Ok`, the debug line is
/// missing); the error says the event was sent.
#[skuld::test]
fn a_tree_call_whose_root_exited_during_the_ask_sends_nothing_and_says_so() {
    crate::log_capture::install();
    for mode in [ContainMode::Strongest, ContainMode::TreeWalk] {
        for answer in [
            ProxyAnswer::AttachDenied,
            ProxyAnswer::TargetGone,
            ProxyAnswer::TargetHasNoConsole,
        ] {
            let held = Fixture::answering_when_told(answer.code());
            let (child, sock) = stopping_member(&held.0, mode);
            let err = asking_while_the_child_exits(&child, &held, || child.terminate_tree())
                .expect_err("nothing was sent to a tree whose root had exited");
            drop(sock);
            let Error::Unassessable { detail, .. } = &err else {
                panic!("{mode:?}, {answer:?}: {err:?}")
            };
            assert!(detail.contains("nothing was sent"), "{mode:?}, {answer:?}: {detail}");
            assert!(
                !detail.contains("CTRL_C"),
                "{mode:?}, {answer:?}: no event went out: {detail}"
            );
            assert_proxy_answered(child.pid(), CtrlEvent::CtrlC, answer);

            let held = Fixture::answering_when_told(answer.code());
            let (child, sock) = stopping_member(&held.0, mode);
            let mark = crate::log_capture::mark();
            asking_while_the_child_exits(&child, &held, || {
                child.graceful_shutdown_tree(std::time::Duration::ZERO)
            })
            .unwrap_or_else(|e| panic!("{mode:?}, {answer:?}: the call goes on and ends the tree: {e:?}"));
            drop(sock);
            assert_proxy_answered(child.pid(), CtrlEvent::CtrlC, answer);
            let logged = crate::log_capture::records_since_on_current_thread(
                mark,
                &format!("graceful_shutdown_tree({})", child.pid()),
            );
            assert!(
                logged
                    .iter()
                    .any(|(level, text)| *level == log::Level::Debug && text.contains("sent no CTRL_C")),
                "{mode:?}, {answer:?}: the call says it sent no event: {logged:?}"
            );
        }
    }
}

// What an executable path is =====

/// `CtrlProxy::Executable` is loaded exactly as written, with no `.exe` appended: the path of a fixture
/// proxy without its extension is not started, though the file with it exists beside, and the error says
/// nothing was sent and names the path as written. Mutant: an extension is appended (the fixture runs
/// and the send is `Ok`).
#[skuld::test]
fn an_executable_is_loaded_exactly_as_written() {
    let fixture = Fixture::answering(ProxyAnswer::Sent.code());
    let bare = fixture.exe.with_extension("");
    assert!(
        fixture.exe.exists() && !bare.exists(),
        "the file is beside its bare name"
    );
    let (child, sock, _) = spawn_member(Handler::Ignore, None, ContainMode::Strongest, |cmd| {
        cmd.no_window();
        cmd.ctrl_proxy(CtrlProxy::Executable(bare.clone()));
    });
    let err = send_err(&child, CtrlEvent::CtrlBreak);
    let Error::Io(io) = &err else { panic!("{err:?}") };
    let text = io.to_string();
    assert!(text.contains("nothing was sent"), "{text}");
    assert!(text.contains(&bare.display().to_string()), "{text}");
    assert!(fixture.ran().is_none(), "the fixture beside the bare name was started");
    assert_no_break_sent();
    kill_release_reap(&child, sock, false);
}

// What a failure to ask comes to =====

/// A start of the proxy that may have started it may have sent the event, and keeps that error; one that
/// did not start it sent nothing, and says a console-event proxy was being started, names its path and
/// keeps the OS's error. Tested on the mapping: the OS failure itself cannot be made to happen without
/// a seam. Mutants: a start that may have started is a send that was not made; the path is dropped.
#[skuld::test]
fn a_start_that_may_have_started_the_proxy_may_have_sent() {
    let exe = std::path::Path::new("C:/no/such/cosca-proxy.exe");
    let may_have_started = Error::MayHaveStarted {
        fate: crate::error::ChildFate::Reaped,
        wrapper_elevated: false,
        detail: None,
        source: std::sync::Arc::new(Error::Io(std::io::Error::other("the attach failed"))),
        unreaped: None,
        cleanup: None,
    };
    assert!(matches!(
        start_failed(exe, may_have_started),
        SendOutcome::Sent(Err(Error::MayHaveStarted { .. }))
    ));

    let SendOutcome::NotSent(Error::Io(io)) = start_failed(
        exe,
        Error::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
    ) else {
        panic!("a start that did not start sent nothing")
    };
    assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied);
    let text = io.to_string();
    assert!(
        text.contains("nothing was sent") && text.contains(&exe.display().to_string()),
        "{text}"
    );
}

/// A failed wait for the proxy leaves unknown whether the event was sent, keeps the wait's error as the
/// source, and says cosca ended the proxy. Tested on the mapping, which no OS failure of the wait can
/// be made to reach. Mutants: the failed wait is a send that was not made; the source is dropped.
#[skuld::test]
fn a_failed_wait_for_the_proxy_is_unknown_and_says_the_proxy_was_ended() {
    let SendOutcome::Sent(Err(Error::Unassessable { detail, source })) = wait_failed(
        77,
        CtrlEvent::CtrlC,
        Error::Io(std::io::Error::other("the wait was refused")),
    ) else {
        panic!("a failed wait leaves it unknown")
    };
    assert!(detail.contains("pid 77") && detail.contains("CTRL_C"), "{detail}");
    assert!(detail.contains("unknown"), "{detail}");
    assert!(detail.contains("cosca ended the proxy"), "{detail}");
    assert!(matches!(source.as_deref(), Some(Error::Io(_))), "{source:?}");
}

/// A host program whose own path cannot be read cannot be started as the proxy: nothing was sent, and the
/// OS's kind and error are kept. Tested on the mapping: `current_exe` cannot be made to fail without a
/// seam. Mutants: the kind is lost; the failure is a send that may have gone out.
#[skuld::test]
fn an_unreadable_host_path_sends_nothing_and_keeps_the_os_error() {
    let SendOutcome::NotSent(Error::Io(io)) =
        exe_unreadable(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
    else {
        panic!("nothing was sent")
    };
    assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(io.to_string().contains("nothing was sent"), "{io}");
    assert!(std::error::Error::source(&io).is_some(), "the OS's error is the source");
}

// A proxy that has not answered =====

/// The warning for a proxy that has not answered by the threshold: logged once, naming the proxy's pid and
/// the child, and the call goes on waiting for the answer. The proxy is held until the wait is at its
/// unbounded block, which only comes after the threshold passed, and is released from that block: a call
/// that never warned still returns there, and fails on the record, not on a hang.
///
/// Mutants: the warning is never made; it is made twice.
#[skuld::test]
fn a_proxy_that_has_not_answered_is_warned_of_once_and_waited_for() {
    use crate::wait::block_probe::{on_each_block, WaitObject};

    crate::log_capture::install();
    let mut held = held_proxy::Held::new();
    let (child, sock) = hidden_member(&held.fixture);
    let marker = format!("for child {} has not answered", child.pid());
    let mark = crate::log_capture::mark();
    let releaser = held.releaser();
    let release_at_the_unbounded_block = on_each_block(move |block| {
        if matches!(block.on, WaitObject::Handles) && block.armed.is_none() {
            _ = releaser.send(());
        }
    });
    let sent = stop::send_console_event_via_proxy(&StopTarget::from(&child), CtrlEvent::CtrlBreak);
    drop(release_at_the_unbounded_block);
    sent.expect("the proxy answered Sent, once told");
    assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::Sent);
    let proxy = held.started_blocking();
    let warned = crate::log_capture::records_since(mark, &marker);
    assert_eq!(
        warned.len(),
        1,
        "one warning for the proxy that had not answered: {warned:?}"
    );
    assert!(
        warned[0].contains(&format!("(pid {proxy})")),
        "the warning names the proxy: {warned:?}"
    );
    kill_release_reap(&child, sock, false);
}
