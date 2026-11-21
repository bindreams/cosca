//! The stop action and the prepared functions (see `crate::stop`), on real children. Where a test reads a
//! member's own evidence, it first asserts the call's answer and, on Windows, the send's record, so a
//! call that sent nothing fails there and not in a wait.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::Error;
use crate::stop::{self, StopTarget};
use crate::test_child::{self, Console};
#[cfg(target_os = "linux")]
use crate::test_groups::{stray_signal, Group};

/// What an action saw of its target: its pid, and whether it covers the tree.
type Seen = Arc<Mutex<Vec<(u32, bool)>>>;

/// An error an action returns, which no prepared function can: `Unsupported` naming the test.
fn refused() -> Error {
    Error::Unsupported {
        op: "the test action".into(),
        platform: "test",
        detail: "refused by the test action".into(),
        source: None,
    }
}

/// An action that records what it saw of its target and sends nothing.
fn recording(seen: &Seen) -> impl Fn(&StopTarget<'_>) -> Result<(), Error> + Send + Sync + 'static {
    let seen = Arc::clone(seen);
    move |target| {
        seen.lock().unwrap().push((target.pid(), target.covers_tree()));
        Ok(())
    }
}

/// A live [`BLOCKER_ARGV`](test_child::BLOCKER_ARGV) child, contained when `contain` says so, that stops
/// by `action`, and the write end of its stdin, which keeps it running.
fn blocker_stopping_by(
    action: impl Fn(&StopTarget<'_>) -> Result<(), Error> + Send + Sync + 'static,
    contain: bool,
) -> (crate::Child, crate::PipeWriter) {
    let mut cmd = test_child::command(Console::Hidden);
    cmd.args(test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::null()).expect("set stdout null");
    if contain {
        #[cfg(unix)]
        test_child::contain_without_cgroup(&mut cmd);
        #[cfg(windows)]
        cmd.contain();
    }
    cmd.graceful_stop(action);
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    (child, stdin)
}

/// The prepared send the rows below use, whichever platform: `SIGUSR1` on Unix, the `CTRL_BREAK` to the
/// child's group on Windows.
fn prepared_send(target: &StopTarget<'_>) -> Result<(), Error> {
    #[cfg(unix)]
    return stop::send_signal(target, crate::Signal::Usr1);
    #[cfg(windows)]
    return stop::send_ctrl_break_to_group(target);
}

/// What a call that went on to a kill says [`prepared_send`] sent before it.
#[cfg(unix)]
const PREPARED_SENT: &str = "the SIGUSR1";
#[cfg(windows)]
const PREPARED_SENT: &str = "the CTRL_BREAK";

/// The child ended by a kill, so nothing before it sent a stop: on Unix a `SIGTERM` would end the
/// blocker by itself; on Windows the send's own record says no break went out.
fn assert_nothing_was_sent(child: &crate::Child, stdin: crate::PipeWriter) {
    #[cfg(windows)]
    crate::test_child::ctrl_break::assert_no_break_sent();
    child.kill().expect("kill");
    drop(stdin);
    test_child::assert_killed("the blocker", child.wait().expect("reap"));
}

// What a child does when no action was set =====

/// A child with no action set stops as `terminate` always did: `SIGTERM` to the root alone.
#[cfg(unix)]
#[skuld::test]
fn the_default_action_is_what_terminate_sent_before() {
    let (child, stdin, stdout) = test_child::ready_tree(test_child::signal_reporting_tree_argv(), |_| {});
    child.terminate().expect("the default stop");
    drop(stdin);
    assert_eq!(
        test_child::signal_reports_to_end(stdout),
        ["leaf eof", "root SIGTERM"],
        "only the root was sent the signal"
    );
    child.wait().expect("the root reported the signal and exited");
}

/// Windows: the default is the `CTRL_BREAK` to the child's group, called on its own as a caller would.
#[cfg(windows)]
#[skuld::test]
fn the_default_action_is_what_terminate_sent_before() {
    use crate::test_child::ctrl_break::{self, assert_acked, kill_release_reap, Handler};

    let (child, mut sock, _) = ctrl_break::spawn_member(Handler::Ack, None, crate::ContainMode::Strongest, |_| {});
    stop::default(&StopTarget::from(&child)).expect("the default stop");
    ctrl_break::assert_break_sent_to(child.pid());
    assert_acked(&mut sock, "the root");
    kill_release_reap(&child, sock, false);
}

// The caller's action =====

/// `terminate` gives the action a root target and sends nothing else.
#[skuld::test]
fn terminate_runs_the_callers_action_on_a_root_target() {
    let seen = Seen::default();
    let (child, stdin) = blocker_stopping_by(recording(&seen), false);
    child.terminate().expect("the action's Ok is the answer");
    assert_eq!(*seen.lock().unwrap(), [(child.pid(), false)]);
    assert_nothing_was_sent(&child, stdin);
}

/// `terminate_tree` gives the action a tree target and sends nothing else.
#[skuld::test]
fn terminate_tree_runs_the_action_on_a_tree_target() {
    let seen = Seen::default();
    let (child, stdin) = blocker_stopping_by(recording(&seen), true);
    child.terminate_tree().expect("the action's Ok is the answer");
    assert_eq!(*seen.lock().unwrap(), [(child.pid(), true)]);
    assert_nothing_was_sent(&child, stdin);
}

/// The action's error is the call's, and the shutdown calls end there: nothing waited for, nothing
/// killed, the child left running.
#[skuld::test]
fn an_actions_error_is_terminates_error() {
    let (child, stdin) = blocker_stopping_by(|_| Err(refused()), false);
    let err = child.terminate().expect_err("the action refused");
    assert!(
        matches!(err.error(), Error::Unsupported { detail, .. } if detail == "refused by the test action"),
        "{err:?}"
    );
    let err = child
        .graceful_shutdown(Duration::ZERO)
        .expect_err("the shutdown ends at the action's error");
    assert!(
        matches!(&err, Error::Unsupported { detail, .. } if detail == "refused by the test action"),
        "{err:?}"
    );
    assert_eq!(
        child.is_alive(),
        crate::identity::Liveness::Alive,
        "nothing was killed, so the child runs"
    );
    assert_nothing_was_sent(&child, stdin);
}

// A chosen signal (Unix) =====

/// A [`signal_then_term_tree_argv`](test_child::signal_then_term_tree_argv) tree's stdout, read as its
/// members report: each wait is for the members' own lines, or the end of the stream once the tree's stdin
/// has ended, a real condition with no time in it.
#[cfg(unix)]
struct Reports {
    stdout: std::io::BufReader<crate::PipeReader>,
    lines: Vec<String>,
}

#[cfg(unix)]
impl Reports {
    fn new(stdout: crate::PipeReader) -> Reports {
        Reports {
            stdout: std::io::BufReader::new(stdout),
            lines: Vec::new(),
        }
    }

    /// Reads until each of `wanted` has been reported since the last wait. A line that is not among them
    /// is a signal the members were not meant to get yet (or ever), and fails here by assertion.
    fn until(&mut self, wanted: &[&str]) {
        use std::io::BufRead as _;

        let mut seen: Vec<String> = Vec::new();
        while !wanted.iter().all(|line| seen.iter().any(|got| got == line)) {
            let mut line = String::new();
            let read = self.stdout.read_line(&mut line).expect("a report line");
            assert_ne!(read, 0, "the tree's stdout ended before {wanted:?}; read {seen:?}");
            let line = line.trim_end().to_owned();
            assert!(wanted.contains(&line.as_str()), "{line:?} is no report of {wanted:?}");
            self.lines.push(line.clone());
            seen.push(line);
        }
    }

    /// Reads the rest of the stream: every member has reported, and ended, once the tree's stdin has.
    fn read_rest(&mut self) {
        use std::io::BufRead as _;

        for line in (&mut self.stdout).lines() {
            self.lines.push(line.expect("a report line"));
        }
    }

    /// Every line `member` reported, in the order it reported them.
    fn of(&self, member: &str) -> Vec<&str> {
        self.lines
            .iter()
            .map(String::as_str)
            .filter(|line| line.starts_with(member))
            .collect()
    }
}

/// A prepared send to a root target reaches the root alone, with the signal it is given: once the stdin
/// ends, the descendant's report is its end of input, not a signal.
///
/// Mutants: the send is `SIGTERM` whatever it is given; it goes to the root's whole group.
#[cfg(unix)]
#[skuld::test]
fn a_chosen_signal_reaches_the_root() {
    let (child, stdin, stdout) = test_child::ready_tree(test_child::signal_reporting_tree_argv(), |cmd| {
        cmd.graceful_stop(|target| stop::send_signal(target, crate::Signal::Usr1));
    });
    child.terminate().expect("the chosen signal was sent");
    drop(stdin);
    assert_eq!(
        test_child::signal_reports_to_end(stdout),
        ["leaf eof", "root SIGUSR1"],
        "only the root was sent the signal"
    );
    child.wait().expect("the root reported the signal and exited");
}

/// A prepared send to a tree target reaches every member the mechanism names, with the signal it is
/// given, in `terminate_tree` and in `graceful_shutdown_tree` alike.
///
/// Mutant: the tree route sends `SIGTERM` whatever it is given.
#[cfg(unix)]
#[skuld::test]
fn a_chosen_signal_reaches_every_member_of_the_tree() {
    for shutdown in [false, true] {
        let held = test_child::HeldStdin::default();
        let ending = held.clone();
        let (child, stdin, stdout) = test_child::ready_tree(test_child::signal_reporting_tree_argv(), |cmd| {
            test_child::contain_without_cgroup(cmd);
            cmd.graceful_stop(move |target| {
                stop::send_signal(target, crate::Signal::Usr1)?;
                ending.end();
                Ok(())
            });
        });
        held.hold(stdin);
        let status = if shutdown {
            Some(
                child
                    .graceful_shutdown_tree(Duration::from_secs(3600))
                    .expect("the chosen signal ended the tree"),
            )
        } else {
            child.terminate_tree().expect("the chosen signal was sent to the tree");
            None
        };
        // Two processes write these lines, so their order is not fixed: the reports are sorted.
        let reports = test_child::signal_reports_to_end(stdout);
        if let Some(status) = status {
            // The root reports the signal and exits, within the grace; a mechanism whose sweep then ends what is
            // left may kill a member before it reports: the root's own report is what is required.
            assert!(status.success(), "the root reported the signal and exited: {status:?}");
            assert!(reports.iter().any(|line| line == "root SIGUSR1"), "{reports:?}");
            assert!(
                reports.iter().all(|line| line.ends_with("SIGUSR1")),
                "only the chosen signal was sent: {reports:?}"
            );
        } else {
            assert_eq!(
                reports,
                ["leaf SIGUSR1", "root SIGUSR1"],
                "both members got the chosen signal"
            );
            child.wait().expect("the root reported the signal and exited");
        }
    }
}

/// A prepared send keeps the rules `terminate` applies, whoever calls it: a signal an elevation front
/// does not relay is refused with nothing sent, and one it relays goes through.
///
/// Mutant: the front's table lets a signal it does not relay through.
#[cfg(unix)]
#[skuld::test]
fn a_prepared_send_called_directly_keeps_the_gates() {
    use crate::child::front_kill_tests::{cat, spawn_as};
    use crate::elevation::{Backend, ElevatedVia};
    use std::os::unix::process::ExitStatusExt as _;

    let (child, stdin) = spawn_as(cat(), ElevatedVia::Wrapped(Backend::Sudo));
    let target = StopTarget::from(&child);

    let err = stop::send_signal(&target, crate::Signal::Alrm).expect_err("sudo does not relay SIGALRM");
    let Error::Unsupported { detail, .. } = &err else {
        panic!("{err:?}");
    };
    assert!(detail.contains("SIGALRM") && detail.contains("sudo"), "{detail}");
    assert_eq!(
        child.is_alive(),
        crate::identity::Liveness::Alive,
        "the refused signal was not sent"
    );

    stop::send_signal(&target, crate::Signal::Usr1).expect("sudo relays SIGUSR1");
    drop(stdin);
    let status = child.wait().expect("reap");
    assert_eq!(
        status.signal(),
        Some(libc::SIGUSR1),
        "the relayed signal was sent: {status:?}"
    );
}

/// A prepared send to a tree target meets the front's gate as one to a root target does, in
/// `terminate_tree` and in `graceful_shutdown_tree` alike: a signal the front does not relay is refused
/// with nothing sent to the tree, the front included, and the shutdown ends there with no grace and no
/// sweep.
///
/// Mutant: the tree arm of `send_signal` goes to the mechanism without the front's gate.
#[cfg(unix)]
#[skuld::test]
fn a_prepared_tree_send_keeps_the_front_gate() {
    use crate::child::front_kill_tests::{cat, spawn_as};
    use crate::elevation::{Backend, ElevatedVia};

    for shutdown in [false, true] {
        let mut cmd = cat();
        test_child::contain_without_cgroup(&mut cmd);
        cmd.graceful_stop(|target| stop::send_signal(target, crate::Signal::Alrm));
        let (child, stdin) = spawn_as(cmd, ElevatedVia::Wrapped(Backend::Sudo));

        let err = if shutdown {
            child.graceful_shutdown_tree(Duration::ZERO).expect_err("refused")
        } else {
            let stopped = child.terminate_tree().expect_err("refused");
            assert_eq!(
                stopped.outcome(),
                stop::SendOutcome::NotSent,
                "the front's gate sent nothing to the tree"
            );
            stopped.into()
        };
        let Error::Unsupported { detail, .. } = &err else {
            panic!("shutdown: {shutdown}: {err:?}");
        };
        assert!(
            detail.contains("SIGALRM") && detail.contains("sudo"),
            "shutdown: {shutdown}: {detail}"
        );
        assert_eq!(
            child.is_alive(),
            crate::identity::Liveness::Alive,
            "shutdown: {shutdown}: nothing was sent, and no sweep ran"
        );
        drop(stdin);
        let status = child.wait().expect("reap");
        assert!(
            status.success(),
            "shutdown: {shutdown}: it ended on its stdin: {status:?}"
        );
    }
}

// Composing sends with a wait =====

/// An action sends, waits for the members' own report of that signal, waits for the root through the
/// target, and sends again: each member reports both signals in order, and the wait answers what the root
/// did meanwhile (kept running, then exited). The same for a root target and a tree target.
///
/// The second signal waits for every member's first report, so the test is of the composed action, not of
/// how a member orders signals seen together.
///
/// Mutants: `wait_exit` answers `true` whatever the root did; the chosen signal is replaced by `SIGTERM`;
/// the first send sends nothing (an assertion on the send log, not a wait for a report that never comes).
///
/// The tree's stdin ends after the second send, and the members' lines are read to the end of the stream: a member
/// the second signal missed reports the end of its input, and a signal reported three times, which no route
/// sends, is a line too, so each fails by assertion. A member the first signal misses is failed by
/// `a_chosen_signal_reaches_every_member_of_the_tree`, not here. The macOS fd marker's route, which may send
/// a member a signal twice, is allowed one or two reports of each.
#[cfg(unix)]
#[skuld::test]
fn an_action_may_compose_sends_with_a_wait() {
    for tree in [false, true] {
        let waited = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&waited);
        let reports = Arc::new(Mutex::new(None::<Reports>));
        let held = test_child::HeldStdin::default();
        let first: &[&str] = if tree {
            &["root SIGUSR1", "leaf SIGUSR1"]
        } else {
            &["root SIGUSR1"]
        };
        let (child, stdin, stdout) = test_child::ready_tree(test_child::signal_then_term_tree_argv(), |cmd| {
            if tree {
                test_child::contain_without_cgroup(cmd);
            }
            let (reports, held) = (Arc::clone(&reports), held.clone());
            cmd.graceful_stop(move |target| {
                let sent = crate::send_log::Capture::start();
                stop::send_signal(target, crate::Signal::Usr1)?;
                // Fails here, not in the wait below, if nothing was sent.
                sent.require_a_send(libc::SIGUSR1)?;
                // The members keep running: the root is looked at once, and every member reports the signal
                // before the second goes out.
                record.lock().unwrap().push(target.wait_exit(Duration::ZERO)?);
                reports.lock().unwrap().as_mut().expect("the reports").until(first);
                stop::send_signal(target, crate::Signal::Term)?;
                held.end();
                // The root exits on the second signal: the wait ends on its exit.
                record
                    .lock()
                    .unwrap()
                    .push(target.wait_exit(Duration::from_secs(3600))?);
                Ok(())
            });
        });
        held.hold(stdin);
        *reports.lock().unwrap() = Some(Reports::new(stdout));
        if tree {
            child.terminate_tree().expect("the composed stop");
        } else {
            child.terminate().expect("the composed stop");
        }
        assert_eq!(*waited.lock().unwrap(), [false, true], "tree: {tree}");
        let mut reports = reports.lock().unwrap().take().expect("the reports");
        reports.read_rest();
        let repeat = child.containment() == crate::Containment::FdMarker;
        test_child::assert_reported_usr1_then_term("root", &reports.of("root"), repeat);
        if tree {
            test_child::assert_reported_usr1_then_term("leaf", &reports.of("leaf"), repeat);
        }
        child.wait().expect("the root had exited, and is reaped once");
    }
}

// What a failed `terminate` and `terminate_tree` say of the send =====

/// Ends a blocker that an action's send may already have ended.
fn end_blocker(child: &crate::Child, stdin: crate::PipeWriter) {
    child.kill_tree().expect("kill_tree");
    drop(stdin);
    child.wait().expect("reap");
}

/// The outcome of a call's error, or `None` for `Ok`.
fn outcome_of(result: Result<(), stop::StopError>) -> Option<stop::SendOutcome> {
    result.err().map(|stopped| stopped.outcome())
}

/// A failed call answers how the action's LAST prepared send went, whatever the action did after it, for a
/// root target and a tree target alike: an error after a send that went out is `Sent`; one after a refused
/// send is `NotSent`; one from an action that made no prepared send is `Unknown`; the last of several sends
/// decides; and an action that returns `Ok` is `Ok` whatever its sends did.
///
/// Mutants: the outcome is taken from the action's error and not from the record; the first send decides
/// and not the last; an action with no send reads as `NotSent` or `Sent`; the tree call writes no record
/// for a send that went out (it reads as `Unknown`).
#[skuld::test]
fn a_failed_call_answers_how_the_actions_last_prepared_send_went() {
    use stop::SendOutcome::{NotSent, Sent, Unknown};

    type Action = Box<dyn Fn(&StopTarget<'_>) -> Result<(), Error> + Send + Sync>;
    // Built per use: an action is moved into the command.
    let rows = || -> [(&str, Action, Option<stop::SendOutcome>); 6] {
        [
            (
                "no prepared send, then an error",
                Box::new(|_| Err(refused())),
                Some(Unknown),
            ),
            (
                "a send that went out, then an error",
                Box::new(|target| {
                    prepared_send(target)?;
                    Err(refused())
                }),
                Some(Sent),
            ),
            (
                "a send that went out, a refused send, then an error",
                Box::new(|target| {
                    prepared_send(target)?;
                    target.note_not_sent(&refused());
                    Err(refused())
                }),
                Some(NotSent),
            ),
            (
                "a refused send, a send that went out, then an error",
                Box::new(|target| {
                    target.note_not_sent(&refused());
                    prepared_send(target)?;
                    Err(refused())
                }),
                Some(Sent),
            ),
            (
                "a refused send, then Ok",
                Box::new(|target| {
                    target.note_not_sent(&refused());
                    Ok(())
                }),
                None,
            ),
            ("a send that went out, then Ok", Box::new(prepared_send), None),
        ]
    };
    for tree in [false, true] {
        for (what, action, expected) in rows() {
            // Contained, so that on Windows the direct send has a group to address.
            let (child, stdin) = blocker_stopping_by(action, true);
            let result = if tree {
                child.terminate_tree()
            } else {
                child.terminate()
            };
            assert_eq!(outcome_of(result), expected, "tree: {tree}, {what}");
            end_blocker(&child, stdin);
        }
    }
}

/// `terminate_tree` on a child that owns no tree fails before the action runs, so nothing was sent: the error
/// is `Unsupported` and the outcome `NotSent`. Mutant: the refusal reads as `Unknown`.
#[skuld::test]
fn terminate_tree_on_an_uncontained_child_sent_nothing() {
    let (child, stdin) = blocker_stopping_by(|_| panic!("the action must not run"), false);
    let err = child.terminate_tree().expect_err("no tree to stop");
    assert!(matches!(err.error(), Error::Unsupported { .. }), "{err:?}");
    assert_eq!(err.outcome(), stop::SendOutcome::NotSent);
    child.kill().expect("kill");
    drop(stdin);
    child.wait().expect("reap");
}

// What `graceful_shutdown_tree` goes on from =====

/// Row: the caller's own action, which sent no prepared send. The call waits the grace and sweeps with
/// nothing assumed sent: the tree is ended by the sweep's kill, and no stop went out before it.
///
/// Mutant: a stop that sent nothing is taken for one that sent the default stop.
#[skuld::test]
fn graceful_shutdown_tree_goes_on_after_a_callers_own_action() {
    let (child, stdin) = blocker_stopping_by(|_| Ok(()), true);
    let status = child
        .graceful_shutdown_tree(Duration::ZERO)
        .expect("the sweep ended the tree");
    #[cfg(windows)]
    crate::test_child::ctrl_break::assert_no_break_sent();
    test_child::assert_killed("the blocker, which only the sweep ended", status);
    drop(stdin);
}

/// Row: the action's last prepared send went out and the action then failed. The grace is waited and the
/// sweep runs, and the action's error is the call's cooperative error: with a sweep that fails and
/// cannot prove the tree clear, it is reported beside the sweep's.
///
/// Mutant: the action's error is dropped.
#[cfg(unix)]
#[skuld::test]
fn graceful_shutdown_tree_keeps_an_error_after_a_send_that_went_out() {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let held = test_child::HeldStdin::default();
    let ending = held.clone();
    let (child, stdin, stdout) = test_child::ready_tree(test_child::signal_reporting_tree_argv(), |cmd| {
        test_child::contain_without_cgroup(cmd);
        cmd.graceful_stop(move |target| {
            prepared_send(target)?;
            ending.end();
            Err(refused())
        });
    });
    held.hold(stdin);
    let _armed = crate::child::graceful::fault::ArmedKillTreeError::arm();
    let err = child
        .graceful_shutdown_tree(Duration::from_secs(3600))
        .expect_err("the sweep failed");
    assert!(
        matches!(&err, Error::Io(e) if e.to_string().contains("forced kill_tree failure")),
        "{err:?}"
    );
    let logged =
        crate::log_capture::records_since_on_current_thread(mark, &format!("graceful_shutdown_tree({})", child.pid()));
    assert!(
        matches!(&logged[..], [(log::Level::Warn, refusal)] if refusal.contains("refused by the test action")),
        "the action's error is the call's cooperative error: {logged:?}"
    );
    assert_eq!(
        test_child::signal_reports_to_end(stdout),
        ["leaf SIGUSR1", "root SIGUSR1"],
        "the send that went out reached the tree"
    );
}

/// [`graceful_shutdown_tree_keeps_an_error_after_a_send_that_went_out`] on Windows: the `CTRL_BREAK` ends a
/// member that handles it by default, within the grace, and a job object's drain proves the tree clear, so
/// the sweep is skipped and the action's error, which the call kept through the grace, is superseded: the
/// call answers the root's status.
///
/// Mutant: the call ends at the action's error, with the grace unwaited.
#[cfg(windows)]
#[skuld::test]
fn graceful_shutdown_tree_keeps_an_error_after_a_send_that_went_out() {
    use crate::test_child::ctrl_break::{self, Handler, STATUS_CONTROL_C_EXIT};

    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (child, sock, _) = ctrl_break::spawn_member(Handler::Default, None, crate::ContainMode::Strongest, |cmd| {
        cmd.graceful_stop(|target| {
            prepared_send(target)?;
            Err(refused())
        });
    });
    ctrl_break::assert_in_our_console(child.pid(), "the root");
    let status = child
        .graceful_shutdown_tree(Duration::from_secs(3600))
        .expect("the tree drained, which supersedes the action's error");
    ctrl_break::assert_break_sent_to(child.pid());
    assert_eq!(
        status.code(),
        Some(STATUS_CONTROL_C_EXIT),
        "the break reached the root: {status:?}"
    );
    let logged =
        crate::log_capture::records_since_on_current_thread(mark, &format!("graceful_shutdown_tree({})", child.pid()));
    assert!(
        logged.iter().any(|(level, text)| *level == log::Level::Debug
            && text.contains("superseded")
            && text.contains("refused by the test action")),
        "the action's error was kept through the grace and then discarded: {logged:?}"
    );
    drop(sock);
}

/// Row: the action failed with nothing sent. The call ends with that error: no grace, no sweep, the
/// tree left running.
///
/// Mutant: the call goes on to the grace and the sweep.
#[skuld::test]
fn graceful_shutdown_tree_ends_on_an_error_with_nothing_sent() {
    let (child, stdin) = blocker_stopping_by(|_| Err(refused()), true);
    let err = child
        .graceful_shutdown_tree(Duration::ZERO)
        .expect_err("the action refused");
    assert!(
        matches!(&err, Error::Unsupported { detail, .. } if detail == "refused by the test action"),
        "{err:?}"
    );
    assert_eq!(
        child.is_alive(),
        crate::identity::Liveness::Alive,
        "no sweep ran, so the tree runs"
    );
    assert_nothing_was_sent(&child, stdin);
}

/// What a call that goes on after the action's last send says was sent before its kill is that send's stop,
/// by name, or "the stop action" when the last send was refused or the action made none: for the lone
/// shutdown's escalation (`stop_root`) and for the tree shutdown's sweep
/// (the `earlier` its cooperative signal hands it). An action that goes on after a refused send leaves a
/// trace of the refusal at `debug`.
///
/// Mutants: either wording is hard-coded; the two are swapped; the refusal is not logged.
#[skuld::test]
fn a_call_words_what_the_action_sent_before_its_kill() {
    type Action = Box<dyn Fn(&StopTarget<'_>) -> Result<(), Error> + Send + Sync>;
    let rows: [(&str, Action, &str, bool); 3] = [
        (
            "an action that sends nothing",
            Box::new(|_| Ok(())),
            "the stop action",
            false,
        ),
        ("a prepared send", Box::new(prepared_send), PREPARED_SENT, false),
        (
            "a prepared send, then one that was refused",
            Box::new(|target| {
                prepared_send(target)?;
                target.note_not_sent(&refused());
                Ok(())
            }),
            "the stop action",
            true,
        ),
    ];
    crate::log_capture::install();
    let refusal_logged = |mark: usize, marker: &str| {
        crate::log_capture::records_since_on_current_thread(mark, marker)
            .iter()
            .any(|(level, text)| {
                *level == log::Level::Debug
                    && text.contains("the action went on after a refused send")
                    && text.contains("refused by the test action")
            })
    };
    for (what, action, says, logs_a_refusal) in rows {
        let (child, stdin) = blocker_stopping_by(action, true);
        let mark = crate::log_capture::mark();
        let (answer, earlier) = crate::child::graceful::shutdown::run_ready(
            crate::child::graceful::shutdown::stop_root(&crate::child::graceful::shutdown::BlockingDriver(&child)),
        );
        answer.unwrap_or_else(|e| panic!("{what}: {e:?}"));
        assert_eq!(earlier.as_deref(), Some(says), "the lone shutdown's kill, after {what}");
        assert_eq!(
            refusal_logged(mark, &format!("graceful_shutdown({})", child.pid())),
            logs_a_refusal,
            "{what}"
        );
        // A stop this blocker handles by default may have ended it: the kill answers either way.
        child.kill().expect("kill");
        drop(stdin);
        child.wait().expect("reap");
    }
}

/// [`a_call_words_what_the_action_sent_before_its_kill`] for the tree shutdown's cooperative signal: what
/// its sweep's error will say was sent before it.
#[skuld::test]
fn a_tree_call_words_what_the_action_sent_before_its_sweep() {
    use crate::child::graceful::SignalTreeCooperativelyOutcome;

    type Action = Box<dyn Fn(&StopTarget<'_>) -> Result<(), Error> + Send + Sync>;
    let rows: [(&str, Action, &str, bool); 3] = [
        (
            "an action that sends nothing",
            Box::new(|_| Ok(())),
            "the stop action",
            false,
        ),
        ("a prepared send", Box::new(prepared_send), PREPARED_SENT, false),
        (
            "a prepared send, then one that was refused",
            Box::new(|target| {
                prepared_send(target)?;
                target.note_not_sent(&refused());
                Ok(())
            }),
            "the stop action",
            true,
        ),
    ];
    crate::log_capture::install();
    for (what, action, says, logs_a_refusal) in rows {
        let (child, stdin) = blocker_stopping_by(action, true);
        let mark = crate::log_capture::mark();
        match crate::child::graceful::shutdown::run_ready(crate::child::graceful::shutdown::signal_tree_cooperatively(
            &crate::child::graceful::shutdown::BlockingDriver(&child),
        )) {
            SignalTreeCooperativelyOutcome::Sent {
                result: Ok(()),
                earlier: Some(earlier),
                ..
            } => assert_eq!(earlier, says, "the sweep's error, after {what}"),
            other => panic!("{what}: the cooperative signal did not go on to the sweep: {other:?}"),
        }
        let logged = crate::log_capture::records_since_on_current_thread(
            mark,
            &format!("graceful_shutdown_tree({})", child.pid()),
        );
        assert_eq!(
            logged.iter().any(|(level, text)| {
                *level == log::Level::Debug
                    && text.contains("the action went on after a refused send")
                    && text.contains("refused by the test action")
            }),
            logs_a_refusal,
            "{what}: {logged:?}"
        );
        // A stop this blocker handles by default may have ended it: the kill answers either way.
        child.kill_tree().expect("kill_tree");
        drop(stdin);
        child.wait().expect("reap");
    }
}

/// Row: nothing names the tree (Linux: a root reaped elsewhere, on a kernel with no pidfd group signal).
/// The prepared send answers what the call answers for it, the error: an action composed of sends stops
/// at its first `?`, with nothing sent, and the call ends with that error.
///
/// Mutant: the send answers `Ok` for the outcome, and leaves the error to the call.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_composed_action_stops_at_a_send_that_found_nothing_to_name(#[fixture(stray_signal)] _stray: &Group) {
    use crate::containment::unix::fault::{record_kill_group, record_term_group};
    use crate::test_child::reaped_elsewhere::{kill_own_child, reap_behind, session_cat};

    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    crate::log_capture::install();
    let killed = record_kill_group();
    let termed = record_term_group();
    let steps = Arc::new(Mutex::new(Vec::new()));
    let mut cmd = session_cat();
    cmd.graceful_stop({
        let steps = Arc::clone(&steps);
        move |target| {
            steps.lock().unwrap().push("first send");
            stop::send_signal(target, crate::Signal::Int)?;
            steps.lock().unwrap().push("wait");
            target.wait_exit(Duration::ZERO)?;
            steps.lock().unwrap().push("second send");
            stop::send_signal(target, crate::Signal::Term)?;
            Ok(())
        }
    });
    let child = cmd.spawn().expect("spawn");
    let pid = child.pid();
    kill_own_child(pid);
    reap_behind(pid);

    let err = child
        .graceful_shutdown_tree(Duration::ZERO)
        .expect_err("a group whose root was reaped elsewhere is not assessable");

    assert!(matches!(err, Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        *steps.lock().unwrap(),
        ["first send"],
        "the action stopped at its first `?`"
    );
    assert_eq!(
        killed.killed(),
        Vec::<i32>::new(),
        "no killpg by a reaped root's number"
    );
    assert_eq!(
        termed.termed(),
        Vec::<i32>::new(),
        "no signal by a reaped root's number"
    );
}

/// Row: a root reachable only through its pidfd. The send goes through the pidfd with the action's
/// signal, exactly once, and nothing goes out by the root's number.
///
/// Mutants: the send is `SIGTERM`; it is sent twice.
#[cfg(target_os = "linux")]
#[skuld::test]
fn graceful_shutdown_tree_sends_the_actions_signal_once_to_a_root_reachable_only_through_its_pidfd() {
    use crate::graceful_hooks::{at, HookPoint};
    use crate::signal::Sig::Graceful;
    use crate::signal::Signal::Usr1;
    use crate::test_child::reaped_elsewhere::session_cat;
    use std::os::unix::process::ExitStatusExt as _;

    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    crate::log_capture::install();
    let mut cmd = session_cat();
    cmd.graceful_stop(|target| stop::send_signal(target, crate::Signal::Usr1));
    let mut child = cmd.spawn().expect("spawn");
    let stdin = child.stdin().expect("stdin pipe");
    let pid = child.pid();

    let sends = std::rc::Rc::new(crate::send_log::Capture::start());
    let fake = child
        .proc
        .script_over(|f| f.peeks([Err(std::io::Error::other("forced peek failure"))]));
    // After the signal: it went out, then the root's end is awaited, so the grace's one look finds it.
    let exited_first = at(HookPoint::AfterTerminate, {
        let sends = std::rc::Rc::clone(&sends);
        move || {
            assert_eq!(
                sends.entries(),
                [(pid, Graceful(Usr1), crate::send_log::Via::Pidfd)],
                "the action's signal went out, once, before the grace"
            );
            drop(stdin);
            crate::test_child::wait_until_zombie(pid);
        }
    });
    let err = child
        .graceful_shutdown_tree(Duration::ZERO)
        .expect_err("a group whose root nothing can answer for is not assessable");
    drop(exited_first);
    fake.assert_peeks_exhausted();

    assert!(matches!(err, Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        sends.entries(),
        [(pid, Graceful(Usr1), crate::send_log::Via::Pidfd)],
        "only the action's signal, through the pidfd"
    );
    let status = child.wait().expect("reap the root");
    assert_eq!(
        status.signal(),
        Some(libc::SIGUSR1),
        "the action's signal ended the root"
    );
}

// Windows: what the prepared send refuses =====

/// A child that leads no group of its own is refused, with the remedy named and nothing sent.
#[cfg(windows)]
#[skuld::test]
fn a_prepared_send_on_a_child_without_the_group_flag_is_unsupported() {
    let (child, stdin) = blocker_stopping_by(|_| Ok(()), false);
    for target in [
        StopTarget::from(&child),
        StopTarget::tree(&child, stop::TreeCall::SignalOnly),
    ] {
        let err = stop::send_ctrl_break_to_group(&target).expect_err("no group to address");
        let Error::Unsupported { detail, .. } = &err else {
            panic!("{err:?}");
        };
        assert!(detail.contains("contain"), "the refusal names the remedy: {detail}");
        assert!(
            detail.contains("kill()"),
            "the refusal names the other remedy: {detail}"
        );
        // A lost line continuation in the source leaves a run of spaces.
        assert!(!detail.contains("  "), "a run of spaces: {detail:?}");
    }
    assert_nothing_was_sent(&child, stdin);
}

/// A child a system service created is refused, whatever its facts say of a group.
#[cfg(windows)]
#[skuld::test]
fn a_prepared_send_refuses_a_child_cosca_did_not_create() {
    use crate::containment::windows::ConsoleFacts;

    let mut child = test_child::over_fake::child_over(&crate::os_process::fake::FakeProcess::new([]));
    child.console = ConsoleFacts {
        group: true,
        ..ConsoleFacts::uac_elevated()
    };
    let err = stop::send_ctrl_break_to_group(&StopTarget::from(&child)).expect_err("not created by cosca");
    let Error::Unsupported { detail, .. } = &err else {
        panic!("{err:?}");
    };
    assert!(detail.contains("did not create this child"), "{detail}");
    assert!(detail.contains("kill()"), "the refusal names the remedy: {detail}");
    // A lost line continuation in the source leaves a run of spaces.
    assert!(!detail.contains("  "), "a run of spaces: {detail:?}");
    crate::test_child::ctrl_break::assert_no_break_sent();
}

/// The default refuses a child a system service created whichever send it would have made: the direct
/// one (the caller had a console and the facts lead a group) or the proxy's (they do not). Nothing is
/// sent and no proxy is asked; the refusal is the prepared sends' own.
#[cfg(windows)]
#[skuld::test]
fn the_default_refuses_a_child_cosca_did_not_create() {
    use crate::containment::windows::ConsoleFacts;

    for caller_had_console in [true, false] {
        let mut child = test_child::over_fake::child_over(&crate::os_process::fake::FakeProcess::new([
            crate::os_process::fake::Answer::Running,
        ]));
        child.console = ConsoleFacts {
            group: true,
            caller_had_console,
            ..ConsoleFacts::uac_elevated()
        };
        let err = stop::default(&StopTarget::from(&child)).expect_err("not created by cosca");
        let Error::Unsupported { detail, .. } = &err else {
            panic!("{err:?}");
        };
        assert!(
            detail.contains("did not create this child"),
            "caller_had_console {caller_had_console}: {detail}"
        );
        crate::test_child::ctrl_break::assert_no_break_sent();
    }
}

// Windows: one handle, a waiter, and the tree calls =====
//
// One handle, a thread blocked in `wait()`, and the main thread calling the tree calls. A main-thread call
// that blocks behind the waiter on the handle's `Condvar` fails by assertion (`not_behind_the_waiter`). No
// assertion covers a tree wait that never sees the tree drained: it waits out `TREE_DRAINS_WITHIN`.

/// How long a tree whose root was told to exit has to drain: a failure bound for a human, never a proof.
#[cfg(windows)]
const TREE_DRAINS_WITHIN: Duration = Duration::from_secs(3600);

/// A hook that fails the test, naming `call`, if this thread's next call blocks on the handle's `Condvar`
/// (behind another thread's wait). Disarmed when dropped.
#[cfg(windows)]
fn not_behind_the_waiter(call: &'static str) -> crate::wait::block_probe::Armed {
    crate::wait::block_probe::on_condvar_block(move || panic!("{call} waited behind the waiter's wait"))
}

/// A Job-contained [`ctrl_break`](test_child::ctrl_break) member that stops by `action`, with a thread
/// blocked in its `wait()`. The member runs while `control` is open, and exits with 0 once it is shut. Dropped
/// before the test ends (a failed assertion), it ends the member and joins the waiter.
#[cfg(windows)]
struct Waited {
    child: Arc<crate::Child>,
    control: std::net::TcpStream,
    waiter: Option<std::thread::JoinHandle<Result<std::process::ExitStatus, Error>>>,
}

#[cfg(windows)]
impl Waited {
    fn start(
        handler: test_child::ctrl_break::Handler,
        action: impl Fn(&StopTarget<'_>) -> Result<(), Error> + Send + Sync + 'static,
    ) -> Waited {
        let (child, control, _) =
            test_child::ctrl_break::spawn_member(handler, None, crate::ContainMode::Strongest, |cmd| {
                cmd.graceful_stop(action);
            });
        assert_eq!(child.containment(), crate::Containment::JobObject);
        test_child::ctrl_break::assert_in_our_console(child.pid(), "the root");
        let child = Arc::new(child);
        let waiter = crate::wait::block_probe::spawn_until_blocked({
            let child = Arc::clone(&child);
            move || child.wait()
        });
        Waited {
            child,
            control,
            waiter: Some(waiter),
        }
    }

    /// Ends the member when this thread's next wait blocks (the tree wait's), so the waiter is provably
    /// already waiting.
    fn end_at_the_next_block(&self) -> crate::wait::block_probe::Armed {
        let control = self.control.try_clone().expect("clone the control socket");
        crate::wait::block_probe::on_blocking(move || control.shutdown(std::net::Shutdown::Both).expect("end the root"))
    }

    /// Joins the waiter and returns what its `wait()` returned.
    fn status(mut self) -> std::process::ExitStatus {
        self.waiter
            .take()
            .expect("joined once")
            .join()
            .expect("the waiter thread")
            .expect("the waiter's wait returned the root's status")
    }
}

#[cfg(windows)]
impl Drop for Waited {
    fn drop(&mut self) {
        _ = self.control.shutdown(std::net::Shutdown::Both);
        if let Some(waiter) = self.waiter.take() {
            _ = waiter.join();
        }
    }
}

/// After `AllMembersExited` the root's process object is signalled: every wait on the handle gives exit code
/// `code`.
#[cfg(windows)]
#[track_caller]
fn assert_every_wait_gives(waited: Waited, code: i32) {
    let child = Arc::clone(&waited.child);
    let status = {
        let _no_wait = not_behind_the_waiter("try_wait");
        child
            .try_wait()
            .expect("a look at the root")
            .expect("a drained tree's root has exited")
    };
    assert_eq!(status.code(), Some(code), "the status of the end: {status:?}");
    assert_eq!(waited.status(), status, "the waiter's wait");
    assert_eq!(child.wait().expect("a later wait on the same handle"), status);
}

/// The action sends the direct `CTRL_BREAK` (no proxy; only the root's group gets it) and the root handles
/// it and runs on. The tree wait's own block ends the root, so the order is provable: the waiter holds the
/// root's wait before the root can exit. Every wait then gives code 0, which only that end gives; a kill
/// gives 1.
///
/// Mutants: `terminate_tree` kills the root or ends the waiter's wait (`try_wait` is `Some`, with code 1);
/// `wait_tree_timeout` answers drained at once (`try_wait` is `None`); a later `wait()` answers another
/// status; `terminate_tree`, `try_wait` or `wait_tree_timeout` waits behind the waiter (the hook).
#[cfg(windows)]
#[skuld::test]
fn a_waiter_gets_the_roots_status_when_terminate_tree_sends_and_the_tree_drains() {
    use test_child::ctrl_break::{self, Handler};

    let mut waited = Waited::start(Handler::Ack, prepared_send);
    let child = Arc::clone(&waited.child);

    {
        let _no_wait = not_behind_the_waiter("terminate_tree");
        child.terminate_tree().expect("the send went out");
    }
    ctrl_break::assert_break_sent_to(child.pid());
    ctrl_break::assert_acked(&mut waited.control, "the root");
    {
        let _no_wait = not_behind_the_waiter("try_wait");
        assert_eq!(child.try_wait().expect("one look at the root"), None, "the root runs");
    }

    let drained = {
        let _no_wait = not_behind_the_waiter("wait_tree_timeout");
        let _end = waited.end_at_the_next_block();
        child.wait_tree_timeout(TREE_DRAINS_WITHIN).expect("the tree wait")
    };
    assert_eq!(drained, crate::containment::TreeDrain::AllMembersExited);
    assert_every_wait_gives(waited, 0);
}

/// [`a_waiter_gets_the_roots_status_when_terminate_tree_sends_and_the_tree_drains`] for a root with no
/// handler, which the `CTRL_BREAK` ends itself: the waiter gets the break's exit code,
/// `STATUS_CONTROL_C_EXIT`, which a kill (1) does not give. Whether the break ends the root before the tree
/// wait blocks is not provable, so the answers are those of every order.
///
/// Caught for certain: a `terminate_tree` that kills with no send (`assert_break_sent_to`), a status other
/// than the break's, and a call that waits behind the waiter (the hook). A `terminate_tree` that sends the break and then kills is caught
/// only if the kill lands first; that mutant belongs to the Ack-handler test above, where only a kill can
/// give 1.
#[cfg(windows)]
#[skuld::test]
fn a_waiter_gets_the_breaks_status_when_the_send_ends_the_root() {
    use test_child::ctrl_break::{self, Handler, STATUS_CONTROL_C_EXIT};

    let waited = Waited::start(Handler::Default, prepared_send);
    let child = Arc::clone(&waited.child);

    {
        let _no_wait = not_behind_the_waiter("terminate_tree");
        child.terminate_tree().expect("the send went out");
    }
    ctrl_break::assert_break_sent_to(child.pid());
    let drained = {
        let _no_wait = not_behind_the_waiter("wait_tree_timeout");
        child.wait_tree_timeout(TREE_DRAINS_WITHIN).expect("the tree wait")
    };
    assert_eq!(drained, crate::containment::TreeDrain::AllMembersExited);
    assert_every_wait_gives(waited, STATUS_CONTROL_C_EXIT);
}

/// `terminate_tree` whose action refuses and sends nothing, with a waiter blocked on the same handle: the
/// waiter stays blocked, and once the root is ended during the tree wait every wait gives its exit code 0 (a
/// kill gives 1).
///
/// Mutants: `terminate_tree` kills the root, or ends the waiter's wait, when the action refuses
/// (`try_wait` is `Some`); `wait_tree_timeout` answers drained while the member runs (the zero look);
/// a call waits behind the waiter (the hook); a later `wait()` answers another status.
#[cfg(windows)]
#[skuld::test]
fn a_waiter_stays_blocked_when_terminate_tree_is_refused_and_gets_the_status_of_the_end() {
    use test_child::ctrl_break::{self, Handler};

    let waited = Waited::start(Handler::Ack, |_| Err(refused()));
    let child = Arc::clone(&waited.child);

    let err = {
        let _no_wait = not_behind_the_waiter("terminate_tree");
        child.terminate_tree().expect_err("the action refused")
    };
    assert!(
        matches!(err.error(), Error::Unsupported { detail, .. } if detail == "refused by the test action"),
        "{err:?}"
    );
    ctrl_break::assert_no_break_sent();
    {
        let _no_wait = not_behind_the_waiter("try_wait");
        assert_eq!(child.try_wait().expect("one look at the root"), None, "the root runs");
    }
    {
        let _no_wait = not_behind_the_waiter("wait_tree_timeout(ZERO)");
        assert_eq!(
            child.wait_tree_timeout(Duration::ZERO).expect("one look at the tree"),
            crate::containment::TreeDrain::MembersRemain
        );
    }

    let drained = {
        let _no_wait = not_behind_the_waiter("wait_tree_timeout");
        let _end = waited.end_at_the_next_block();
        child.wait_tree_timeout(TREE_DRAINS_WITHIN).expect("the tree wait")
    };
    assert_eq!(drained, crate::containment::TreeDrain::AllMembersExited);
    assert_every_wait_gives(waited, 0);
}
