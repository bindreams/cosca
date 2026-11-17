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

use super::protocol::{CtrlEvent, ProxyAnswer, ProxyArgs, VERSION};
use super::{exe_unreadable, start_failed, wait_failed, CtrlProxy};
use crate::containment::SendOutcome;
use crate::error::Error;
use crate::stop::{self, StopTarget};
use crate::test_child::ctrl_break::{
    assert_no_break_sent, assert_proxy_answered, kill_release_reap, spawn_member, Handler,
};
use crate::test_child::IDENTITY_READ;
use crate::{Child, Command, ContainMode};

/// A fixture proxy that answers `code`: a copy of the testbin in a directory of its own.
struct Fixture {
    _dir: tempfile::TempDir,
    exe: PathBuf,
}

impl Fixture {
    fn answering(code: i32) -> Fixture {
        let dir = tempfile::tempdir().expect("a directory for the fixture proxy");
        let exe = dir.path().join(crate::proxy_fixture::exe_name(code));
        std::fs::copy(crate::test_child::testbin("cosca_testbin"), &exe).expect("copy the testbin");
        Fixture { _dir: dir, exe }
    }

    fn setting(&self) -> CtrlProxy {
        CtrlProxy::Executable(self.exe.clone())
    }

    /// What the fixture recorded; `None` when it never ran.
    fn ran(&self) -> Option<crate::proxy_fixture::Ran> {
        crate::proxy_fixture::read_record(&self.exe)
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
/// caller, with no console of its own. Mutants: the other event, the pid with another key, another
/// caller, the proxy started attached to a console, `Sent` not `Ok`.
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
            Ok(Some(ProxyArgs {
                target: record.pid,
                target_key: record.token,
                event,
                caller: std::process::id(),
            })),
            "{ran:?}"
        );
        assert_eq!(std::path::Path::new(&ran.argv[0]), fixture.exe, "{ran:?}");
        assert!(!ran.had_console, "the proxy has no console of its own: {ran:?}");
        kill_release_reap(&child, sock, false);
    }
}

// What each answer means =====

/// A child that exited is answered as `send_ctrl_break_to_group` answers one: `Ok`. The proxy cannot
/// attach to an exited process whose handle is held (`AttachDenied`), finds no such identity
/// (`TargetGone`), or finds the process has no console (`TargetHasNoConsole`). Mutants: the answer is
/// always an error; the exit is not looked at, for one of the three.
#[skuld::test]
fn a_refused_attach_to_an_exited_child_is_ok() {
    for answer in [
        ProxyAnswer::AttachDenied,
        ProxyAnswer::TargetGone,
        ProxyAnswer::TargetHasNoConsole,
    ] {
        let fixture = Fixture::answering(answer.code());
        let (child, sock) = hidden_member(&fixture);
        child.kill().expect("kill the member");
        child.wait().expect("see its exit, reaping nothing");
        drop(sock);
        stop::send_console_event_via_proxy(&StopTarget::from(&child), CtrlEvent::CtrlBreak)
            .unwrap_or_else(|e| panic!("{answer:?} for an exited child is Ok: {e:?}"));
        assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, answer);
        assert!(
            fixture.ran().is_some(),
            "the proxy was asked, as the child's exit was not assumed"
        );
    }
}

/// The same answers for a child that has not exited: the error says what was observed, the answer with
/// its code and that the child had not exited when cosca looked, and lists the causes it cannot tell
/// apart. Mutants: the exit is assumed; the code is dropped; the look is not mentioned; `Ok`.
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
        assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, answer);
        kill_release_reap(&child, sock, false);
    }
}

/// A child the proxy found no console for, that had not exited: the error says what was observed and
/// lists as possible causes that the child has none or has not set it up yet, and names `Child::kill`
/// first and `Command::graceful_stop` second. Mutants: the text of `AttachDenied` is used (the missing
/// console is not listed as a cause); the remedies swapped or dropped; a cause stated as the conclusion.
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
    names_in_order(detail, "Child::kill", "Command::graceful_stop");
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
/// the version this cosca speaks. Mutants: the version is not named; `Usage` is mapped as `NothingSent`
/// (an I/O error).
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

/// A proxy that failed before it generated the event, or could not read its target: an I/O error of kind
/// `Other` that says nothing was sent and gives the answer. Mutants: `Unassessable` (the event may have
/// been sent); the answer not named.
#[skuld::test]
fn an_answer_that_sent_nothing_is_an_error_that_says_so() {
    for answer in [ProxyAnswer::NothingSent, ProxyAnswer::TargetUnreadable] {
        let fixture = Fixture::answering(answer.code());
        let (child, sock) = hidden_member(&fixture);
        let err = send_err(&child, CtrlEvent::CtrlBreak);
        let Error::Io(io) = &err else { panic!("{err:?}") };
        assert_eq!(io.kind(), std::io::ErrorKind::Other, "{err:?}");
        let text = io.to_string();
        assert!(text.contains("nothing was sent"), "{text}");
        assert!(text.contains("the proxy's own reason is not available"), "{text}");
        assert!(!text.contains("standard error"), "{text}");
        assert!(
            text.contains(&format!("{answer:?}")) && text.contains(&format!("exit {}", answer.code())),
            "{text}"
        );
        assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, answer);
        kill_release_reap(&child, sock, false);
    }
}

/// Whether the event was sent is unknown: `Unassessable`, for the answer that says the event was
/// generated and not confirmed, and for an exit that is no answer (0, and a code outside the
/// protocol's) with the code. Mutants: `Ok`; an unknown code is an error that says nothing was sent.
#[skuld::test]
fn an_unconfirmed_send_and_an_exit_that_is_no_answer_are_unassessable() {
    for code in [ProxyAnswer::Unconfirmed.code(), 0, 3] {
        let fixture = Fixture::answering(code);
        let (child, sock) = hidden_member(&fixture);
        let err = send_err(&child, CtrlEvent::CtrlBreak);
        let Error::Unassessable { detail, .. } = &err else {
            panic!("{err:?}")
        };
        assert!(detail.contains("unknown"), "{detail}");
        assert!(detail.contains(&code.to_string()), "the code: {detail}");
        match ProxyAnswer::from_code(code) {
            Some(answer) => assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, answer),
            None => assert_no_break_sent(),
        }
        kill_release_reap(&child, sock, false);
    }
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
    let mut child = crate::test_child::over_fake::child_over(&crate::os_process::fake::FakeProcess::new([]));
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
    let mut child = crate::test_child::over_fake::child_over(&crate::os_process::fake::FakeProcess::new([]));
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

// What a call does with the answer =====

/// The calls run the action on a root target and on a tree target (over a job object and over a tree
/// walk), and each answers what the prepared send did: `Sent` is `Ok` for all, and an error that sent
/// nothing is the call's error. Mutants: a tree target does not take the mechanism's route (its answer
/// is a root's); the action's error is dropped; one mechanism's route does not carry a `Sent`.
#[skuld::test]
fn the_calls_answer_what_the_proxy_answered() {
    for (answer, ok) in [(ProxyAnswer::Sent, true), (ProxyAnswer::NothingSent, false)] {
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
/// (a sweep that proves the tree clear discards it, saying so). One that sent nothing (`NothingSent`)
/// is a refused send: the call ends with it, and the tree runs. Both mechanisms a Windows tree is
/// signalled by are asked: a job object, and a tree walk.
///
/// Mutants: an `Unassessable` answer is read as a send that was not made (the call ends at it, the
/// member runs on); a refused send is read as one that went out (the grace and sweep run).
#[skuld::test]
fn a_tree_call_goes_on_after_a_send_that_may_have_gone_out_and_ends_after_one_that_did_not() {
    crate::log_capture::install();
    for mode in [ContainMode::Strongest, ContainMode::TreeWalk] {
        for answer in [ProxyAnswer::Unconfirmed, ProxyAnswer::NothingSent] {
            let fixture = Fixture::answering(answer.code());
            let (child, sock) = stopping_member(&fixture, mode);
            let mark = crate::log_capture::mark();
            let called = child.graceful_shutdown_tree(std::time::Duration::ZERO);
            assert_proxy_answered(child.pid(), CtrlEvent::CtrlC, answer);
            let logged = crate::log_capture::records_since_on_current_thread(
                mark,
                &format!("graceful_shutdown_tree({})", child.pid()),
            );
            if answer == ProxyAnswer::Unconfirmed {
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
        (ProxyAnswer::Unconfirmed, "the CTRL_C"),
        (ProxyAnswer::NothingSent, "the stop action"),
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
        let (acted, said) = child.stop_root();
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

/// The proxy cannot attach, and cosca's look finds the tree's root exited: nothing was sent, for either
/// tree call and both mechanisms, whichever of the three answers the proxy gave. `terminate_tree` ends
/// with an error that says so and claims no event went out; `graceful_shutdown_tree` goes on, with the
/// debug line that it sent no event, and answers `Ok`. The proxy is asked in each case.
///
/// Mutants: the exit is answered `Ok` as for a root target (`terminate_tree` is `Ok`, the debug line is
/// missing); the error says the event was sent.
#[skuld::test]
fn a_tree_call_whose_root_has_exited_sends_nothing_and_says_so() {
    crate::log_capture::install();
    for mode in [ContainMode::Strongest, ContainMode::TreeWalk] {
        for answer in [
            ProxyAnswer::AttachDenied,
            ProxyAnswer::TargetGone,
            ProxyAnswer::TargetHasNoConsole,
        ] {
            let exited = |fixture: &Fixture| {
                let (child, sock) = stopping_member(fixture, mode);
                child.kill().expect("kill the member");
                child.wait().expect("see its exit, reaping nothing");
                drop(sock);
                child
            };

            let fixture = Fixture::answering(answer.code());
            let child = exited(&fixture);
            let err = child
                .terminate_tree()
                .expect_err("nothing was sent to a tree whose root had exited");
            let Error::Unassessable { detail, .. } = &err else {
                panic!("{mode:?}, {answer:?}: {err:?}")
            };
            assert!(detail.contains("nothing was sent"), "{mode:?}, {answer:?}: {detail}");
            assert!(
                !detail.contains("CTRL_C"),
                "{mode:?}, {answer:?}: no event went out: {detail}"
            );
            assert_proxy_answered(child.pid(), CtrlEvent::CtrlC, answer);

            let fixture = Fixture::answering(answer.code());
            let child = exited(&fixture);
            let mark = crate::log_capture::mark();
            child
                .graceful_shutdown_tree(std::time::Duration::ZERO)
                .unwrap_or_else(|e| panic!("{mode:?}, {answer:?}: the call goes on and ends the tree: {e:?}"));
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
