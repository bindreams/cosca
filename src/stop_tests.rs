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
    let (child, stdin, mut stdout) = test_child::ready_tree(test_child::SIGNAL_REPORTING_TREE_ARGV, |_| {});
    child.terminate().expect("the default stop");
    drop(stdin);
    let mut said = String::new();
    std::io::Read::read_to_string(&mut stdout, &mut said).expect("the tree's stdout, to its end");
    // Two processes write these lines, so their order is not fixed.
    let mut reports: Vec<&str> = said.lines().collect();
    reports.sort_unstable();
    assert_eq!(
        reports,
        ["leaf eof", "root SIGTERM"],
        "only the root was sent the signal"
    );
    child.wait().expect("the root exited on its handler");
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
        matches!(&err, Error::Unsupported { detail, .. } if detail == "refused by the test action"),
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

/// A [`SIGNAL_THEN_TERM_TREE_ARGV`](test_child::SIGNAL_THEN_TERM_TREE_ARGV) tree's stdout, read as its
/// members report: each wait is for the members' own lines, a real condition with no time in it.
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
    let (child, stdin, mut stdout) = test_child::ready_tree(test_child::SIGNAL_REPORTING_TREE_ARGV, |cmd| {
        cmd.graceful_stop(|target| stop::send_signal(target, crate::Signal::Usr1));
    });
    child.terminate().expect("the chosen signal was sent");
    drop(stdin);
    let mut said = String::new();
    std::io::Read::read_to_string(&mut stdout, &mut said).expect("the tree's stdout, to its end");
    // Two processes write these lines, so their order is not fixed.
    let mut reports: Vec<&str> = said.lines().collect();
    reports.sort_unstable();
    assert_eq!(
        reports,
        ["leaf eof", "root SIGUSR1"],
        "only the root was sent the signal"
    );
    child.wait().expect("the root exited on its handler");
}

/// A prepared send to a tree target reaches every member the mechanism names, with the signal it is
/// given, in `terminate_tree` and in `graceful_shutdown_tree` alike.
///
/// Mutant: the tree route sends `SIGTERM` whatever it is given.
#[cfg(unix)]
#[skuld::test]
fn a_chosen_signal_reaches_every_member_of_the_tree() {
    for shutdown in [false, true] {
        let (child, stdin, mut stdout) = test_child::ready_tree(test_child::SIGNAL_REPORTING_TREE_ARGV, |cmd| {
            test_child::contain_without_cgroup(cmd);
            cmd.graceful_stop(|target| stop::send_signal(target, crate::Signal::Usr1));
        });
        if shutdown {
            // The root exits on its handler, within the grace; the sweep then ends what is left, so a
            // member may be killed before it reports: the root's own report is what is asserted.
            let status = child
                .graceful_shutdown_tree(Duration::from_secs(3600))
                .expect("the chosen signal ended the tree");
            assert!(status.success(), "the root exited on its handler: {status:?}");
            let mut said = String::new();
            std::io::Read::read_to_string(&mut stdout, &mut said).expect("the tree's stdout, to its end");
            let mut reports: Vec<&str> = said.lines().collect();
            reports.sort_unstable();
            assert!(reports.contains(&"root SIGUSR1"), "{reports:?}");
            assert!(
                reports.iter().all(|line| line.ends_with("SIGUSR1")),
                "only the chosen signal was sent: {reports:?}"
            );
        } else {
            child.terminate_tree().expect("the chosen signal was sent to the tree");
            assert_eq!(
                test_child::two_signal_reports(stdout),
                ["leaf SIGUSR1", "root SIGUSR1"],
                "both members got the chosen signal"
            );
            child.wait().expect("the root exited on its handler");
        }
        drop(stdin);
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
            child.terminate_tree().expect_err("refused")
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
/// The second signal is not sent before every member has reported the first: a shell runs the traps of
/// signals that are pending together in signal-number order, not in the order they arrived (`SIGTERM`
/// is 15 and `SIGUSR1` 30 on macOS), so two sends with nothing between them can lose the first report.
///
/// Mutants: `wait_exit` answers `true` whatever the root did; the chosen signal is replaced by `SIGTERM`.
#[cfg(unix)]
#[skuld::test]
fn an_action_may_compose_sends_with_a_wait() {
    for tree in [false, true] {
        let waited = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&waited);
        let reports = Arc::new(Mutex::new(None::<Reports>));
        let (first, last): (&[&str], &[&str]) = if tree {
            (&["root SIGUSR1", "leaf SIGUSR1"], &["root SIGTERM", "leaf SIGTERM"])
        } else {
            (&["root SIGUSR1"], &["root SIGTERM"])
        };
        let (child, stdin, stdout) = test_child::ready_tree(test_child::SIGNAL_THEN_TERM_TREE_ARGV, |cmd| {
            if tree {
                test_child::contain_without_cgroup(cmd);
            }
            let reports = Arc::clone(&reports);
            cmd.graceful_stop(move |target| {
                stop::send_signal(target, crate::Signal::Usr1)?;
                // The members keep running: the root is looked at once, and every member reports the signal
                // before the second goes out.
                record.lock().unwrap().push(target.wait_exit(Duration::ZERO)?);
                reports.lock().unwrap().as_mut().expect("the reports").until(first);
                stop::send_signal(target, crate::Signal::Term)?;
                // The root exits on the second signal: the wait ends on its exit.
                record
                    .lock()
                    .unwrap()
                    .push(target.wait_exit(Duration::from_secs(3600))?);
                Ok(())
            });
        });
        *reports.lock().unwrap() = Some(Reports::new(stdout));
        if tree {
            child.terminate_tree().expect("the composed stop");
        } else {
            child.terminate().expect("the composed stop");
        }
        assert_eq!(*waited.lock().unwrap(), [false, true], "tree: {tree}");
        let mut reports = reports.lock().unwrap().take().expect("the reports");
        reports.until(last);
        assert_eq!(reports.of("root"), ["root SIGUSR1", "root SIGTERM"], "tree: {tree}");
        if tree {
            assert_eq!(reports.of("leaf"), ["leaf SIGUSR1", "leaf SIGTERM"], "tree: {tree}");
        }
        drop(stdin);
        child.wait().expect("the root had exited, and is reaped once");
    }
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
    let (child, stdin, stdout) = test_child::ready_tree(test_child::SIGNAL_REPORTING_TREE_ARGV, |cmd| {
        test_child::contain_without_cgroup(cmd);
        cmd.graceful_stop(|target| {
            prepared_send(target)?;
            Err(refused())
        });
    });
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
        test_child::two_signal_reports(stdout),
        ["leaf SIGUSR1", "root SIGUSR1"],
        "the send that went out reached the tree"
    );
    drop(stdin);
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
                target.note_refused(&refused());
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
        assert_eq!(earlier, says, "the lone shutdown's kill, after {what}");
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
                target.note_refused(&refused());
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
            _ => panic!("{what}: the cooperative signal did not go on to the sweep"),
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
