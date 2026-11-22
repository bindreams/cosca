//! The async stop action and the prepared functions of `crate::tokio::stop`, on real children: the async
//! twins of `stop_tests.rs`, each awaited call under `never_blocking`, on a current-thread runtime. Where a
//! test reads a member's own evidence it first asserts the call's answer, so a call that sent nothing fails
//! there. No test here waits out a grace to see a signal that never came: the member's input ends, so a
//! member that was not signalled reports the end of its input instead, which fails by assertion.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::Error;
use crate::test_child::{self, Console};
use crate::tokio::stop::{self, StopFuture};
use crate::tokio::test_runtime::{assert_current_thread, never_blocking};
use crate::StopTarget;

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
fn recording(seen: &Seen) -> impl for<'t, 'c> Fn(&'t StopTarget<'c>) -> StopFuture<'t> + Send + Sync + 'static {
    let seen = Arc::clone(seen);
    move |target| {
        seen.lock().unwrap().push((target.pid(), target.covers_tree()));
        Box::pin(async { Ok(()) })
    }
}

/// A live [`BLOCKER_ARGV`](test_child::BLOCKER_ARGV) child, contained when `contain` says so, that stops
/// by `action`, and the write end of its stdin, which keeps it running.
async fn blocker_stopping_by(
    action: impl for<'t, 'c> Fn(&'t StopTarget<'c>) -> StopFuture<'t> + Send + Sync + 'static,
    contain: bool,
) -> (crate::tokio::Child, crate::tokio::ChildStdin) {
    let mut cmd = test_child::tokio_command(Console::Hidden);
    cmd.args(test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::null()).expect("set stdout null");
    if contain {
        #[cfg(unix)]
        test_child::contain_without_cgroup_async(&mut cmd);
        #[cfg(windows)]
        cmd.contain();
    }
    cmd.graceful_stop(action);
    let mut child = cmd.spawn().await.expect("spawn");
    let stdin = child.stdin().expect("piped stdin");
    (child, stdin)
}

/// The prepared send the rows below use, whichever platform: `SIGUSR1` on Unix, the `CTRL_BREAK` to the
/// child's group on Windows.
async fn prepared_send(target: &StopTarget<'_>) -> Result<(), Error> {
    #[cfg(unix)]
    return stop::send_signal(target, crate::Signal::Usr1).await;
    #[cfg(windows)]
    return stop::send_ctrl_break_to_group(target).await;
}

/// The child ended by a kill, so nothing before it sent a stop: on Unix a `SIGTERM` would end the
/// blocker by itself; on Windows the send's own record says no break went out.
async fn assert_nothing_was_sent(child: &mut crate::tokio::Child, stdin: crate::tokio::ChildStdin) {
    #[cfg(windows)]
    crate::test_child::ctrl_break::assert_no_break_sent();
    child.kill().expect("kill");
    drop(stdin);
    test_child::assert_killed("the blocker", child.wait().await.expect("reap"));
}

// The caller's action =====

/// `terminate` awaits the action on a root target and sends nothing else.
///
/// Mutants: `terminate` runs the default stop in place of the async action (a `SIGTERM`, or a break,
/// ends or is recorded for the blocker); it gives the action a tree target.
#[skuld::test]
async fn async_terminate_runs_the_callers_action_on_a_root_target() {
    assert_current_thread();
    let seen = Seen::default();
    let (mut child, stdin) = blocker_stopping_by(recording(&seen), false).await;
    never_blocking(child.terminate())
        .await
        .expect("the action's Ok is the answer");
    assert_eq!(*seen.lock().unwrap(), [(child.pid(), false)]);
    assert_nothing_was_sent(&mut child, stdin).await;
}

/// `terminate_tree` awaits the action on a tree target and sends nothing else.
///
/// Mutant: `terminate_tree` gives the action a root target.
#[skuld::test]
async fn async_terminate_tree_runs_the_action_on_a_tree_target() {
    assert_current_thread();
    let seen = Seen::default();
    let (mut child, stdin) = blocker_stopping_by(recording(&seen), true).await;
    never_blocking(child.terminate_tree())
        .await
        .expect("the action's Ok is the answer");
    assert_eq!(*seen.lock().unwrap(), [(child.pid(), true)]);
    assert_nothing_was_sent(&mut child, stdin).await;
}

/// A failed async call answers how the action's last prepared send went, as the sync call does
/// (`a_failed_call_answers_how_the_actions_last_prepared_send_went`), for a root target and a tree target:
/// an error after a send that went out is `Sent`, and one from an action that made no prepared send is
/// `Unknown`.
///
/// Mutants: the outcome is taken from the action's error and not from the record; the async send writes no
/// record, or the tree call reads none.
#[skuld::test]
async fn async_a_failed_call_answers_how_the_actions_last_prepared_send_went() {
    use crate::stop::SendOutcome::{Sent, Unknown};

    assert_current_thread();
    for tree in [false, true] {
        for sends in [false, true] {
            let (mut child, stdin) = if sends {
                blocker_stopping_by(
                    |target| {
                        Box::pin(async move {
                            prepared_send(target).await?;
                            Err(refused())
                        })
                    },
                    true,
                )
                .await
            } else {
                blocker_stopping_by(|_| Box::pin(async { Err(refused()) }), true).await
            };
            let err = if tree {
                never_blocking(child.terminate_tree()).await
            } else {
                never_blocking(child.terminate()).await
            }
            .expect_err("the action failed");
            let expected = if sends { Sent } else { Unknown };
            assert_eq!(err.outcome(), expected, "tree: {tree}, a send: {sends}");
            child.kill_tree().await.expect("kill_tree");
            drop(stdin);
            child.wait().await.expect("reap");
        }
    }
}

/// The action's error is the call's, and `graceful_shutdown` ends there: nothing waited for, nothing
/// killed, the child left running.
///
/// Mutants: the error is dropped; the shutdown goes on to its grace and kill.
#[skuld::test]
async fn async_an_actions_error_is_terminates_error() {
    assert_current_thread();
    let (mut child, stdin) = blocker_stopping_by(|_| Box::pin(async { Err(refused()) }), false).await;
    let err = never_blocking(child.terminate()).await.expect_err("the action refused");
    assert!(
        matches!(err.error(), Error::Unsupported { detail, .. } if detail == "refused by the test action"),
        "{err:?}"
    );
    let err = never_blocking(child.graceful_shutdown(Duration::ZERO))
        .await
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
    assert_nothing_was_sent(&mut child, stdin).await;
}

// A chosen signal (Unix) =====

/// An action's `SIGUSR1` to a tree, then the end of the members' input: a member that got the signal reports
/// it, and one that did not reports the end of its input. The input is ended after the send, so no member
/// can report the end of its input first.
#[cfg(unix)]
fn signalling_then_ending_the_input(
    held: &test_child::HeldStdin<crate::tokio::ChildStdin>,
) -> impl for<'t, 'c> Fn(&'t StopTarget<'c>) -> StopFuture<'t> + Send + Sync + 'static {
    let held = held.clone();
    move |target| {
        let held = held.clone();
        Box::pin(async move {
            stop::send_signal(target, crate::Signal::Usr1).await?;
            held.end();
            Ok(())
        })
    }
}

/// A prepared send to a tree target reaches every member the mechanism names, with the signal it is
/// given, in `terminate_tree` and in `graceful_shutdown_tree` alike.
///
/// The action ends the members' input after its send, so neither call can wait on a signal that never
/// came: the members then report the end of their input, and the assertion on the reports fails. The grace
/// of the shutdown is unbounded for that reason: the root ends at once, signalled or not.
///
/// Mutants: the tree route sends `SIGTERM` whatever it is given; the async send reaches no member.
#[cfg(unix)]
#[skuld::test]
async fn async_a_chosen_signal_reaches_every_member_of_the_tree() {
    use ::tokio::io::AsyncReadExt as _;

    assert_current_thread();
    for shutdown in [false, true] {
        let held = test_child::HeldStdin::default();
        let (mut child, stdin, mut stdout) =
            test_child::ready_tree_async(test_child::signal_reporting_tree_argv(), |cmd| {
                test_child::contain_without_cgroup_async(cmd);
                cmd.graceful_stop(signalling_then_ending_the_input(&held));
            })
            .await;
        held.hold(stdin);
        if shutdown {
            never_blocking(child.graceful_shutdown_tree(Duration::MAX))
                .await
                .expect("the chosen signal ended the tree");
        } else {
            never_blocking(child.terminate_tree())
                .await
                .expect("the chosen signal was sent to the tree");
        }
        let mut said = String::new();
        stdout
            .read_to_string(&mut said)
            .await
            .expect("the tree's stdout, to its end");
        let mut reports: Vec<&str> = said.lines().collect();
        reports.sort_unstable();
        if shutdown {
            // The sweep may end the leaf before it reports: the root's own report is what is asserted.
            assert!(reports.contains(&"root SIGUSR1"), "shutdown: {reports:?}");
            assert!(
                reports.iter().all(|line| line.ends_with("SIGUSR1")),
                "shutdown: only the chosen signal was sent: {reports:?}"
            );
        } else {
            assert_eq!(
                reports,
                ["leaf SIGUSR1", "root SIGUSR1"],
                "both members got the chosen signal"
            );
            child.wait().await.expect("the root reported the signal and exited");
        }
    }
}

// Composing sends with a wait =====

/// A [`signal_then_term_tree_argv`](test_child::signal_then_term_tree_argv) tree's stdout, read as its
/// members report: each wait is for the members' own lines, or the end of the stream once the tree's stdin
/// has ended, a real condition with no time in it.
#[cfg(unix)]
struct Reports {
    stdout: ::tokio::io::BufReader<crate::tokio::ChildStdout>,
    lines: Vec<String>,
}

#[cfg(unix)]
impl Reports {
    fn new(stdout: crate::tokio::ChildStdout) -> Reports {
        Reports {
            stdout: ::tokio::io::BufReader::new(stdout),
            lines: Vec::new(),
        }
    }

    /// Reads until each of `wanted` has been reported since the last wait. A line that is not among them
    /// is a signal the members were not meant to get (or the end of their input), and fails here by
    /// assertion.
    async fn until(&mut self, wanted: &[&str]) {
        use ::tokio::io::AsyncBufReadExt as _;

        let mut seen: Vec<String> = Vec::new();
        while !wanted.iter().all(|line| seen.iter().any(|got| got == line)) {
            let mut line = String::new();
            let read = self.stdout.read_line(&mut line).await.expect("a report line");
            assert_ne!(read, 0, "the tree's stdout ended before {wanted:?}; read {seen:?}");
            let line = line.trim_end().to_owned();
            assert!(wanted.contains(&line.as_str()), "{line:?} is no report of {wanted:?}");
            self.lines.push(line.clone());
            seen.push(line);
        }
    }

    /// Reads the rest of the stream: every member has reported, and ended, once the tree's stdin has.
    async fn read_rest(&mut self) {
        use ::tokio::io::AsyncBufReadExt as _;

        let mut lines = (&mut self.stdout).lines();
        while let Some(line) = lines.next_line().await.expect("a report line") {
            self.lines.push(line);
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

/// An action sends, waits for the members' own report of that signal, waits for the root through the
/// target, and sends again: each member reports both signals in order, and the wait answers what the root
/// did meanwhile (kept running, then exited). The same for a root target and a tree target.
///
/// The second signal is not sent before every member has reported the first (see the sync twin), and the
/// members' input ends after the second, so a member that was not signalled reports the end of its input,
/// and the lines are read to the end of the stream: a miss, or a signal reported three times, fails by
/// assertion, and the wait for the root's exit is for an exit that comes. The check is the sync twin's: a
/// member of an fd-marker tree (chosen by the child's reported containment) may report each signal twice.
///
/// Mutants: `wait_exit` answers `true` whatever the root did; the chosen signal is replaced by `SIGTERM`;
/// the first send sends nothing (an assertion on the send log).
#[cfg(unix)]
#[skuld::test]
async fn async_an_action_may_compose_sends_with_a_wait() {
    assert_current_thread();
    for tree in [false, true] {
        let waited = Arc::new(Mutex::new(Vec::new()));
        let reports = Arc::new(::tokio::sync::Mutex::new(None::<Reports>));
        let held = test_child::HeldStdin::default();
        let first: &'static [&'static str] = if tree {
            &["root SIGUSR1", "leaf SIGUSR1"]
        } else {
            &["root SIGUSR1"]
        };
        let (mut child, stdin, stdout) =
            test_child::ready_tree_async(test_child::signal_then_term_tree_argv(), |cmd| {
                if tree {
                    test_child::contain_without_cgroup_async(cmd);
                }
                let (waited, reports, held) = (Arc::clone(&waited), Arc::clone(&reports), held.clone());
                cmd.graceful_stop(move |target| {
                    let (waited, reports, held) = (Arc::clone(&waited), Arc::clone(&reports), held.clone());
                    Box::pin(async move {
                        let sent = crate::send_log::Capture::start();
                        stop::send_signal(target, crate::Signal::Usr1).await?;
                        // Fails here, not in the wait below, if nothing was sent.
                        sent.require_a_send(libc::SIGUSR1)?;
                        // The members keep running: the root is looked at once, and every member reports
                        // the signal before the second goes out.
                        let running = stop::wait_exit(target, Duration::ZERO).await?;
                        waited.lock().unwrap().push(running);
                        reports.lock().await.as_mut().expect("the reports").until(first).await;
                        stop::send_signal(target, crate::Signal::Term).await?;
                        held.end();
                        // The root exits on the second signal: the wait ends on its exit.
                        let exited = stop::wait_exit(target, Duration::MAX).await?;
                        waited.lock().unwrap().push(exited);
                        Ok(())
                    })
                });
            })
            .await;
        held.hold(stdin);
        *reports.lock().await = Some(Reports::new(stdout));
        if tree {
            never_blocking(child.terminate_tree()).await.expect("the composed stop");
        } else {
            never_blocking(child.terminate()).await.expect("the composed stop");
        }
        assert_eq!(*waited.lock().unwrap(), [false, true], "tree: {tree}");
        let mut reports = reports.lock().await.take().expect("the reports");
        reports.read_rest().await;
        let repeat = child.containment() == crate::Containment::FdMarker;
        test_child::assert_reported_usr1_then_term("root", &reports.of("root"), repeat);
        if tree {
            test_child::assert_reported_usr1_then_term("leaf", &reports.of("leaf"), repeat);
        }
        child.wait().await.expect("the root had exited, and is reaped once");
    }
}

// What `graceful_shutdown_tree` goes on from =====

/// A caller's own action that made no prepared send: the call waits the grace and sweeps with
/// nothing assumed sent: the tree is ended by the sweep's kill, and no stop went out before it.
///
/// Mutant: a stop that sent nothing is taken for one that sent the default stop.
#[skuld::test]
async fn async_graceful_shutdown_tree_goes_on_after_a_callers_own_action() {
    assert_current_thread();
    let (mut child, stdin) = blocker_stopping_by(|_| Box::pin(async { Ok(()) }), true).await;
    let status = never_blocking(child.graceful_shutdown_tree(Duration::ZERO))
        .await
        .expect("the sweep ended the tree");
    #[cfg(windows)]
    crate::test_child::ctrl_break::assert_no_break_sent();
    test_child::assert_killed("the blocker, which only the sweep ended", status);
    drop(stdin);
}

/// An action whose last prepared send went out and which then failed: the grace is waited and the
/// sweep runs, and the action's error is the call's cooperative error: with a sweep that fails and
/// cannot prove the tree clear, it is reported beside the sweep's.
///
/// The action ends the members' input after its send, so a send that never came ends the members by the end
/// of their input within the unbounded grace, and the reports say so.
///
/// Mutant: the action's error is dropped.
#[cfg(unix)]
#[skuld::test]
async fn async_graceful_shutdown_tree_keeps_an_error_after_a_send_that_went_out() {
    use ::tokio::io::AsyncReadExt as _;

    assert_current_thread();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let held = test_child::HeldStdin::default();
    let (mut child, stdin, mut stdout) =
        test_child::ready_tree_async(test_child::signal_reporting_tree_argv(), |cmd| {
            test_child::contain_without_cgroup_async(cmd);
            let held = held.clone();
            cmd.graceful_stop(move |target| {
                let held = held.clone();
                Box::pin(async move {
                    prepared_send(target).await?;
                    held.end();
                    Err(refused())
                })
            });
        })
        .await;
    held.hold(stdin);
    let _armed = crate::child::graceful::fault::ArmedKillTreeError::arm();
    let err = never_blocking(child.graceful_shutdown_tree(Duration::MAX))
        .await
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
    let mut said = String::new();
    stdout
        .read_to_string(&mut said)
        .await
        .expect("the tree's stdout, to its end");
    let mut reports: Vec<&str> = said.lines().collect();
    reports.sort_unstable();
    assert_eq!(
        reports,
        ["leaf SIGUSR1", "root SIGUSR1"],
        "the send that went out reached the tree"
    );
}

/// [`async_graceful_shutdown_tree_keeps_an_error_after_a_send_that_went_out`] on Windows: the `CTRL_BREAK` ends a
/// member that handles it by default, within the grace, and a job object's drain proves the tree clear, so
/// the sweep is skipped and the action's error, which the call kept through the grace, is superseded: the
/// call answers the root's status. The break's record is asserted at the call's own point after the stop, so a
/// send that never went out fails there and not in the grace.
///
/// Mutant: the call ends at the action's error, with the grace unwaited.
#[cfg(windows)]
#[skuld::test]
async fn async_graceful_shutdown_tree_keeps_an_error_after_a_send_that_went_out() {
    use crate::test_child::ctrl_break::{self, Handler, STATUS_CONTROL_C_EXIT};

    assert_current_thread();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (mut child, sock, _) =
        ctrl_break::spawn_member_async(Handler::Default, None, Some(crate::ContainMode::Strongest), |cmd| {
            cmd.graceful_stop(|target| {
                Box::pin(async move {
                    prepared_send(target).await?;
                    Err(refused())
                })
            });
        })
        .await;
    ctrl_break::assert_in_our_console(child.pid(), "the root");
    let pid = child.pid();
    let check = crate::graceful_hooks::at_checked(crate::graceful_hooks::HookPoint::AfterTerminate, move || {
        ctrl_break::assert_break_sent_to(pid)
    });
    let status = never_blocking(child.graceful_shutdown_tree(Duration::from_secs(30)))
        .await
        .expect("the tree drained, which supersedes the action's error");
    check.assert_fired();
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

/// An action that failed with nothing sent: the call ends with that error: no grace, no sweep, the
/// tree left running.
///
/// Mutant: the call goes on to the grace and the sweep.
#[skuld::test]
async fn async_graceful_shutdown_tree_ends_on_an_error_with_nothing_sent() {
    assert_current_thread();
    let (mut child, stdin) = blocker_stopping_by(|_| Box::pin(async { Err(refused()) }), true).await;
    let err = never_blocking(child.graceful_shutdown_tree(Duration::ZERO))
        .await
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
    assert_nothing_was_sent(&mut child, stdin).await;
}

/// A root reachable only through its pidfd: the send goes through the pidfd with the action's
/// signal, exactly once, and nothing goes out by the root's number.
///
/// Mutants: the send is `SIGTERM`; it is sent twice.
#[cfg(target_os = "linux")]
#[skuld::test]
async fn async_graceful_shutdown_tree_sends_the_actions_signal_once_to_a_root_reachable_only_through_its_pidfd() {
    use crate::graceful_hooks::{at, HookPoint};
    use crate::signal::Sig::Graceful;
    use crate::signal::Signal::Usr1;
    use std::os::unix::process::ExitStatusExt as _;

    assert_current_thread();
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    crate::log_capture::install();
    let mut cmd = test_child::tokio_command(Console::Hidden);
    cmd.args(["cat"]);
    cmd.contain_with(crate::ContainMode::Session);
    cmd.stdin(crate::Stdio::pipe_in()).expect("stdin pipe");
    cmd.graceful_stop(|target| Box::pin(stop::send_signal(target, crate::Signal::Usr1)));
    let mut child = cmd.spawn().await.expect("spawn");
    let stdin = child.stdin().expect("stdin pipe");
    let pid = child.pid();

    let sends = std::rc::Rc::new(crate::send_log::Capture::start());
    let fake = child
        .inner
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
    let err = never_blocking(child.graceful_shutdown_tree(Duration::ZERO))
        .await
        .expect_err("a group whose root nothing can answer for is not assessable");
    drop(exited_first);
    fake.assert_peeks_exhausted();

    assert!(matches!(err, Error::Unassessable { .. }), "{err:?}");
    assert_eq!(
        sends.entries(),
        [(pid, Graceful(Usr1), crate::send_log::Via::Pidfd)],
        "only the action's signal, through the pidfd"
    );
    let status = child.wait().await.expect("reap the root");
    assert_eq!(
        status.signal(),
        Some(libc::SIGUSR1),
        "the action's signal ended the root"
    );
}

// `wait_exit` =====

/// A bounded grace that runs out with the root still running answers `false`, and the wait blocks no
/// runtime thread. The root runs until the test ends its input, so the answer is the same for any grace,
/// and the grace is short.
///
/// Mutants: a grace that ran out is read as an exit; the wait blocks its thread.
#[skuld::test]
async fn async_wait_exit_answers_false_when_the_grace_runs_out_with_the_root_running() {
    assert_current_thread();
    let (member, writer, _) = test_child::over_fake::live_member();
    let mut child = crate::tokio::Child { inner: member };
    let exited = never_blocking(stop::wait_exit(&StopTarget::from(&child), Duration::from_millis(10))).await;
    drop(writer);
    assert!(
        !exited.expect("a look at the root"),
        "the grace ran out with the root running"
    );
    child.wait().await.expect("the root ended once its input did");
}

/// Unix: the async wait runs on tokio's clock, so on a paused runtime the test moves it: a running root's
/// `wait_exit` under a tokio-clock deadline answers `TimedOut` once the clock is past the deadline, and
/// `Ok(false)` once it is past a grace that is the shorter of the two. The sibling advances the clock after the
/// wait's first poll, and a wait that did not end by the bound it was given is still pending when the sibling is
/// done: it then ends the root's input and takes a second answer, which is `Ok(true)` and fails the assertion, with
/// no hang. (The Windows wait is the OS's, on the real clock, which a paused runtime does not move.)
///
/// Mutants: the async wait ignores the deadline (the first row) or arms it in place of the grace (the second).
#[cfg(unix)]
#[skuld::test(runtime = crate::tokio::test_runtime::paused)]
async fn async_wait_exit_ends_by_the_nearer_of_a_tokio_deadline_and_the_grace_on_a_paused_clock() {
    use std::cell::RefCell;

    use crate::stop::Deadline;

    let thirty = Duration::from_secs(30);
    let hour = Duration::from_secs(3600);
    for (deadline, grace, timed_out) in [(thirty, Duration::MAX, true), (hour, thirty, false)] {
        let case = format!("deadline {deadline:?}, grace {grace:?}");
        let (member, writer, _) = test_child::over_fake::live_member();
        let mut child = crate::tokio::Child { inner: member };
        let writer = RefCell::new(Some(writer));
        let target = StopTarget::from(&child).with_deadline(Deadline::tokio(deadline));
        let waited = ::tokio::select! {
            biased;
            waited = stop::wait_exit(&target, grace) => waited,
            () = ::tokio::time::advance(thirty + Duration::from_secs(1)) => {
                drop(writer.borrow_mut().take());
                stop::wait_exit(&target, grace).await
            }
        };
        match (timed_out, waited) {
            (true, Err(Error::TimedOut { members, .. })) => {
                assert_eq!(members, [child.id().expect(test_child::IDENTITY_READ)], "{case}");
            }
            (false, Ok(false)) => {}
            (_, other) => panic!("{case}: the wait did not end by the nearer bound: {other:?}"),
        }
        drop(writer.borrow_mut().take());
        child.wait().await.expect("the root ended once its input did");
    }
}

/// On Windows the wait for the root is a registered OS wait: it needs neither the IO nor the time driver, so
/// it runs on a runtime built with neither, for a grace that runs out and for one that ends at the exit.
///
/// Mutants: the bounded wait is armed on tokio's timer (it panics on this runtime); the wait blocks.
#[cfg(windows)]
#[skuld::test]
fn async_wait_exit_on_windows_needs_neither_the_io_nor_the_time_driver() {
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime with no driver");
    runtime.block_on(async {
        let (member, writer, _) = test_child::over_fake::live_member();
        let mut child = crate::tokio::Child { inner: member };
        let exited = never_blocking(stop::wait_exit(&StopTarget::from(&child), Duration::from_millis(10))).await;
        assert!(
            !exited.expect("a look at the root"),
            "the grace ran out with the root running"
        );
        drop(writer);
        let exited = never_blocking(stop::wait_exit(&StopTarget::from(&child), Duration::MAX)).await;
        assert!(exited.expect("the wait for the root"), "the root exited");
        child.wait().await.expect("the exited root is reaped");
    });
}

/// The async twins of the sync timeout calls carry their timeout to the action's target as well: a timeout
/// already past makes the action's `wait_exit` one look, which answers `TimedOut` naming the root for a root
/// that runs, and the action's `?` makes it the call's answer (`Unknown`: the action sent nothing); a plain
/// call makes the same wait for the whole grace and is `Ok`. The sibling ends the root's input, and runs only
/// when the call is pending: a timeout call that has made its look is done before the sibling runs.
///
/// Mutants: a timeout call passes no deadline to its target (root or tree); the plain call passes one; the
/// deadline's end answers `Ok(false)` instead of `TimedOut`.
#[skuld::test]
async fn async_a_timeout_call_bounds_the_wait_its_action_makes_and_a_plain_call_does_not() {
    use crate::stop::SendOutcome;

    assert_current_thread();
    for (tree, timed) in [(false, true), (true, true), (false, false), (true, false)] {
        let waited = Arc::new(Mutex::new(Vec::new()));
        let (mut child, stdin) = blocker_stopping_by(
            {
                let waited = Arc::clone(&waited);
                move |target| {
                    let waited = Arc::clone(&waited);
                    Box::pin(async move {
                        let exited = stop::wait_exit(target, Duration::MAX).await?;
                        waited.lock().unwrap().push(exited);
                        Ok(())
                    })
                }
            },
            tree,
        )
        .await;
        let release = async { drop(stdin) };
        let (answer, ()) = match (tree, timed) {
            (false, true) => ::tokio::join!(never_blocking(child.terminate_timeout(Duration::ZERO)), release),
            (true, true) => ::tokio::join!(never_blocking(child.terminate_tree_timeout(Duration::ZERO)), release),
            (false, false) => ::tokio::join!(never_blocking(child.terminate()), release),
            (true, false) => ::tokio::join!(never_blocking(child.terminate_tree()), release),
        };
        let case = format!("tree: {tree}, timed: {timed}");
        if timed {
            let err = answer.expect_err("a past deadline is one look at a root that runs, and `?` ended the action");
            assert_eq!(err.outcome(), SendOutcome::Unknown, "{case}: the action sent nothing");
            let Error::TimedOut {
                detail,
                members,
                source,
            } = err.error()
            else {
                panic!("{case}: {err:?}")
            };
            assert_eq!(members, &[child.id().expect(test_child::IDENTITY_READ)], "{case}");
            assert!(detail.contains(&format!("pid {}", child.pid())), "{case}: {detail}");
            assert!(source.is_none(), "{case}: {source:?}");
            assert!(
                waited.lock().unwrap().is_empty(),
                "{case}: the action ended at its wait"
            );
        } else {
            answer.expect("the action ended with its wait");
            assert_eq!(
                *waited.lock().unwrap(),
                [true],
                "{case}: no deadline waits for the exit"
            );
        }
        let status = child.wait().await.expect("the root is reaped once its input ended");
        assert!(
            status.success(),
            "{case}: the blocker ended at its input's end: {status:?}"
        );
    }
}

/// A timeout too large for the clock is no bound on the async calls either: the call makes the wait the plain
/// call makes and answers `Ok`, with no panic. The sibling ends the root's input once the call is pending, so a
/// call that read the timeout as passed has answered `TimedOut` at its first look and fails the assertion.
///
/// Mutant: a timeout that overflows tokio's clock is read as already passed.
#[skuld::test]
async fn async_a_timeout_too_large_for_the_clock_is_no_bound() {
    assert_current_thread();
    for tree in [false, true] {
        let waited = Arc::new(Mutex::new(Vec::new()));
        let (mut child, stdin) = blocker_stopping_by(
            {
                let waited = Arc::clone(&waited);
                move |target| {
                    let waited = Arc::clone(&waited);
                    Box::pin(async move {
                        let exited = stop::wait_exit(target, Duration::MAX).await?;
                        waited.lock().unwrap().push(exited);
                        Ok(())
                    })
                }
            },
            tree,
        )
        .await;
        let release = async { drop(stdin) };
        let (answered, ()) = if tree {
            ::tokio::join!(never_blocking(child.terminate_tree_timeout(Duration::MAX)), release)
        } else {
            ::tokio::join!(never_blocking(child.terminate_timeout(Duration::MAX)), release)
        };
        answered.unwrap_or_else(|e| panic!("tree: {tree}: no bound, so the wait is for the exit: {e:?}"));
        assert_eq!(*waited.lock().unwrap(), [true], "tree: {tree}");
        let status = child.wait().await.expect("the exited root is reaped");
        assert!(
            status.success(),
            "tree: {tree}: the blocker ended at its input's end: {status:?}"
        );
    }
}

// Windows: the wait for the proxy =====

#[cfg(windows)]
use crate::stop::proxy::proxy_tests::held_proxy::Held;

/// A member that stops through the proxy, which is `held`'s fixture, and the member's control socket.
#[cfg(windows)]
async fn member_stopping_through(held: &Held) -> (crate::tokio::Child, std::net::TcpStream) {
    use crate::test_child::ctrl_break::{spawn_member_async, Handler};

    let (child, sock, _) = spawn_member_async(Handler::Ignore, None, Some(crate::ContainMode::Strongest), |cmd| {
        cmd.no_window();
        cmd.ctrl_proxy(held.fixture.setting());
        cmd.graceful_stop(|target| Box::pin(stop::send_console_event_via_proxy(target, crate::CtrlEvent::CtrlBreak)));
    })
    .await;
    (child, sock)
}

/// Polls `call` by hand to its wait for the proxy and returns the proxy's pid. The start of the proxy is on
/// the blocking pool, and the future is woken when it is done: the next poll is the wait for the proxy.
#[cfg(windows)]
async fn polled_to_the_proxy_wait<F: std::future::Future>(call: &mut std::pin::Pin<Box<F>>, held: &mut Held) -> u32 {
    use std::task::Context;

    let (waker, wakes) = crate::tokio::test_runtime::counting_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(call.as_mut().poll(&mut cx).is_pending(), "the proxy is not started yet");
    wakes.recv().expect("the start of the proxy woke the call");
    assert!(
        call.as_mut().poll(&mut cx).is_pending(),
        "the proxy has not answered, so the call waits for it"
    );
    held.started().await
}

/// The wait for the proxy's exit is an await: while the proxy runs, a second task on the same runtime runs,
/// and releases it. A wait that blocked the runtime thread would starve that task, so the release comes from
/// the block itself, which also records that the thread blocked: the call returns and fails here by
/// assertion.
///
/// Mutant: the async driver waits for the proxy with the blocking `Child::wait_saying`.
#[cfg(windows)]
#[skuld::test]
async fn the_wait_for_the_proxy_blocks_no_runtime_thread() {
    use std::cell::Cell;
    use std::rc::Rc;

    use crate::stop::proxy::protocol::{CtrlEvent, ProxyAnswer};
    use crate::test_child::ctrl_break::{assert_proxy_answered, kill_release_reap_async};

    assert_current_thread();
    let mut held = Held::new();
    let (mut child, sock) = member_stopping_through(&held).await;
    let blocked = Rc::new(Cell::new(false));
    let releaser = held.releaser();
    let _release_at_a_block = crate::wait::block_probe::on_blocking({
        let blocked = blocked.clone();
        move || {
            blocked.set(true);
            _ = releaser.send(());
        }
    });
    let (stopped, ()) = ::tokio::join!(child.terminate(), async {
        held.started().await;
        held.release();
    });
    assert!(!blocked.get(), "the call blocked a runtime thread");
    stopped.expect("the proxy answered Sent");
    assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::Sent);
    kill_release_reap_async(&mut child, sock, false).await;
}

/// The async driver's wait for the proxy ends by the deadline it is given, with the proxy still running: a
/// deadline already past (on the real clock, which the target hands every driver) is one look, and the wait
/// answers `None`, which `ask` takes as a proxy that did not answer in time. The proxy is up and held before
/// the wait starts, and it is still running when the wait answers; dropping its handle, as `ask` does, ends
/// it, which a look at the process by identity sees (the drop kills and reaps before it returns). The wait is
/// raced, in order, against a future that tells the proxy to answer: a wait that made its look is ready first
/// and the proxy is never told, and one that ignored the deadline is pending, so the second arm runs and fails
/// the assertion, with no hang. The warn threshold is not due before the deadline, so `late` is never called.
///
/// Mutants: the deadline is not read by the async wait; the threshold's wait ignores the deadline; the proxy
/// is not ended by its handle's drop.
#[cfg(windows)]
#[skuld::test]
async fn async_wait_proxy_ends_by_its_deadline_with_the_proxy_running() {
    use crate::identity::ProcessId;
    use crate::stop::proxy::CtrlProxy;
    use crate::stop::StopWaits as _;
    use crate::test_child::ctrl_break::kill_release_reap_async;
    use crate::test_child::exited_through_open;

    assert_current_thread();
    let mut held = Held::new();
    let (mut child, sock) = member_stopping_through(&held).await;
    let CtrlProxy::Executable(exe) = held.fixture.setting() else {
        unreachable!("a fixture is an executable proxy")
    };
    let mut command = crate::tokio::Command::new();
    let sync = command.as_sync_mut();
    sync.raw_executable(&exe).detached();
    sync.stdin(crate::Stdio::null()).expect("null stdin");
    sync.stdout(crate::Stdio::null()).expect("null stdout");
    sync.stderr(crate::Stdio::null()).expect("null stderr");
    let mut proxy = command.spawn().await.expect("start the held proxy");
    let id = ProcessId::of(held.started().await)
        .found()
        .expect("the held proxy runs");

    let driver = stop::AsyncDriver(&child.inner);
    let waited = ::tokio::select! {
        biased;
        waited = driver.wait_proxy(
            &mut proxy,
            crate::wait::teardown_warn::LATE,
            |_| panic!("the threshold is past the deadline: nothing is waited for to warn of"),
            crate::wait::deadline_from(Duration::ZERO),
        ) => waited,
        () = async { held.release() } => panic!("the wait was pending: it ignored the deadline"),
    };
    assert!(
        matches!(waited, Ok(None)),
        "the deadline ended the wait with the proxy running: {waited:?}"
    );
    assert!(
        !exited_through_open(id, Some(Duration::ZERO)).expect("a look at the proxy"),
        "the proxy is still running when the wait answers"
    );
    drop(proxy);
    assert!(
        exited_through_open(id, Some(Duration::ZERO)).expect("a look at the proxy"),
        "the proxy is gone once its handle is dropped"
    );
    kill_release_reap_async(&mut child, sock, false).await;
}

/// A call whose timeout is already past is refused before the proxy is started, as the sync call is: the
/// answer is `NotSent` with `TimedOut` and no members, and the fixture never ran. The call never reaches a wait,
/// so it answers at its first poll.
///
/// Mutants: the proxy is started and ended; the answer is `Unknown`.
#[cfg(windows)]
#[skuld::test]
async fn async_a_timeout_already_past_refuses_the_call_before_the_proxy_is_started() {
    use crate::stop::proxy::protocol::ProxyAnswer;
    use crate::stop::proxy::proxy_tests::Fixture;
    use crate::stop::SendOutcome;
    use crate::test_child::ctrl_break::{assert_no_break_sent, kill_release_reap_async, spawn_member_async, Handler};

    assert_current_thread();
    for tree in [false, true] {
        let fixture = Fixture::answering(ProxyAnswer::Sent.code());
        let (mut child, sock, _) =
            spawn_member_async(Handler::Ignore, None, Some(crate::ContainMode::Strongest), |cmd| {
                cmd.no_window();
                cmd.ctrl_proxy(fixture.setting());
                cmd.graceful_stop(|target| {
                    Box::pin(stop::send_console_event_via_proxy(target, crate::CtrlEvent::CtrlBreak))
                });
            })
            .await;
        let answer = if tree {
            child.terminate_tree_timeout(Duration::ZERO).await
        } else {
            child.terminate_timeout(Duration::ZERO).await
        };
        let err = answer.expect_err("the timeout was past before the proxy would start");
        assert_eq!(err.outcome(), SendOutcome::NotSent, "tree: {tree}");
        let Error::TimedOut {
            detail,
            members,
            source,
        } = err.error()
        else {
            panic!("tree: {tree}: {err:?}")
        };
        assert_eq!(
            detail, "the call's timeout had run out before the console-event proxy was started; nothing was sent",
            "tree: {tree}"
        );
        assert!(members.is_empty() && source.is_none(), "tree: {tree}: {err:?}");
        assert!(fixture.ran().is_none(), "tree: {tree}: no proxy was started");
        assert_no_break_sent();
        kill_release_reap_async(&mut child, sock, false).await;
    }
}

/// A call with a generous timeout whose proxy answers is answered as the call without one: the deadline the
/// target hands the async driver for its wait is not read as past. The proxy is told to answer once it runs.
///
/// Mutant: the deadline the target converts for the wait is already past (the call answers that the proxy did
/// not answer in time).
#[cfg(windows)]
#[skuld::test]
async fn async_a_proxy_that_answers_within_the_timeout_is_answered_as_without_one() {
    use crate::stop::proxy::protocol::{CtrlEvent, ProxyAnswer};
    use crate::test_child::ctrl_break::{assert_proxy_answered, kill_release_reap_async};

    assert_current_thread();
    for tree in [false, true] {
        let mut held = Held::new();
        let (mut child, sock) = member_stopping_through(&held).await;
        let timeout = Duration::from_secs(3600);
        let (stopped, ()) = if tree {
            ::tokio::join!(never_blocking(child.terminate_tree_timeout(timeout)), async {
                held.started().await;
                held.release();
            })
        } else {
            ::tokio::join!(never_blocking(child.terminate_timeout(timeout)), async {
                held.started().await;
                held.release();
            })
        };
        stopped.unwrap_or_else(|e| panic!("tree: {tree}: the proxy answered Sent, once told: {e:?}"));
        assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::Sent);
        kill_release_reap_async(&mut child, sock, false).await;
    }
}

/// The async call's deadline reaches the wait for the proxy: once the proxy is up, the wait's clock reads
/// include one against a bound longer than the warn threshold (the threshold's own wait is the one before)
/// and no longer than the call's generous timeout. The reads before the proxy is up are the call's own and
/// are dropped from the log; the proxy answers once told, at its start, so a wait that ignored the deadline
/// still ends, and fails the assertion on the log.
///
/// Mutant: the target hands the async driver no deadline for a call on tokio's clock (the log then holds
/// only the threshold's reads, or unbounded ones).
#[cfg(windows)]
#[skuld::test]
async fn async_a_calls_deadline_bounds_the_wait_for_the_proxy() {
    use crate::stop::proxy::protocol::{CtrlEvent, ProxyAnswer};
    use crate::test_child::ctrl_break::{assert_proxy_answered, kill_release_reap_async};
    use crate::wait::read_probe::{self, Event};
    use crate::wait::teardown_warn::LATE;

    assert_current_thread();
    let timeout = Duration::from_secs(3600);
    for tree in [false, true] {
        let case = format!("tree: {tree}");
        let mut held = Held::new();
        let (mut child, sock) = member_stopping_through(&held).await;
        let (log_tx, log) = std::sync::mpsc::channel();
        let _log = read_probe::install(log_tx);
        let sibling = async {
            held.started().await;
            while log.try_recv().is_ok() {}
            held.release();
        };
        let (stopped, ()) = if tree {
            ::tokio::join!(never_blocking(child.terminate_tree_timeout(timeout)), sibling)
        } else {
            ::tokio::join!(never_blocking(child.terminate_timeout(timeout)), sibling)
        };
        stopped.unwrap_or_else(|e| panic!("{case}: the proxy answered Sent, once told: {e:?}"));
        assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::Sent);
        let reads: Vec<Event> = log.try_iter().collect();
        assert!(
            reads.iter().any(
                |event| matches!(event, Event::Read { remaining: Some(left), .. } if *left > LATE && *left <= timeout)
            ),
            "{case}: the wait for the proxy was armed against the call's deadline: {reads:?}"
        );
        kill_release_reap_async(&mut child, sock, false).await;
    }
}

/// A `terminate` dropped while its proxy runs has ended the proxy by the time the drop returns: the proxy's
/// handle is dropped with the future, which kills and reaps it. The future is polled by hand, to its wait for
/// the proxy: the start of the proxy is on the blocking pool, and the future is woken when it is done. A drop
/// during the start is not this case: the start ends the proxy when it completes, not the drop.
///
/// Mutant: the proxy's handle outlives the future (it is detached or leaked).
#[cfg(windows)]
#[skuld::test]
async fn a_dropped_terminate_has_ended_its_proxy() {
    use crate::test_child::ctrl_break::{assert_no_break_sent, kill_release_reap_async};

    assert_current_thread();
    let mut held = Held::new();
    let (mut child, sock) = member_stopping_through(&held).await;
    {
        let mut terminate = Box::pin(child.terminate());
        let proxy = polled_to_the_proxy_wait(&mut terminate, &mut held).await;
        let id = crate::identity::ProcessId::of(proxy)
            .found()
            .expect("the proxy runs, and has an identity");
        assert!(
            !crate::test_child::exited_through_open(id, Some(Duration::ZERO)).expect("a look at the proxy"),
            "the proxy runs while the call waits for it"
        );
        drop(terminate);
        assert!(
            crate::test_child::exited_through_open(id, Some(Duration::ZERO)).expect("a look at the proxy"),
            "the drop of the call ended the proxy"
        );
    }
    assert_no_break_sent();
    held.release();
    kill_release_reap_async(&mut child, sock, false).await;
}

/// A proxy send dropped while its proxy runs leaves the record of a send that may have gone out, whatever
/// an earlier send of the same target recorded: the proxy was started, and may have sent before it was ended.
/// The target holds a refused send, then the send's future is polled to its wait for the proxy and dropped;
/// the record is `Unknown` and names the `CTRL_BREAK` as sent, for a root and for a tree target.
///
/// Mutants: the record is written only when the answer is in (`conclude`), so the dropped send leaves the
/// earlier refusal, `NotSent`; the record of a tree target does not name the stop.
#[cfg(windows)]
#[skuld::test]
async fn a_dropped_proxy_send_records_a_send_that_may_have_gone_out() {
    use crate::containment::earlier_of;
    use crate::stop::{RootRecord, SendOutcome, TreeCall, TreeRecord};
    use crate::test_child::ctrl_break::kill_release_reap_async;

    assert_current_thread();
    for tree in [false, true] {
        let mut held = Held::new();
        let (mut child, sock) = member_stopping_through(&held).await;
        let target = if tree {
            StopTarget::tree(&child.inner, TreeCall::SignalOnly)
        } else {
            StopTarget::from(&child)
        };
        target.note_not_sent(&refused(), crate::containment::UnsentKind::NotSent);
        {
            let mut send = Box::pin(stop::send_console_event_via_proxy(&target, crate::CtrlEvent::CtrlBreak));
            polled_to_the_proxy_wait(&mut send, &mut held).await;
        }
        // The outcome, and the stop the record names as sent.
        let (recorded, named) = if tree {
            let Some(TreeRecord::Sent { earlier, outcome, .. }) = target.into_tree_record() else {
                panic!("the tree target holds no record of a send that was made")
            };
            (outcome, earlier)
        } else {
            let record = target.into_root_record().expect("the root target holds a record");
            let outcome = record.outcome();
            let RootRecord::Unknown(name) = record else {
                panic!("the root's record names no send that may have gone out")
            };
            (outcome, Some(earlier_of(name)))
        };
        assert_eq!(recorded, SendOutcome::Unknown, "tree: {tree}");
        assert_eq!(named.as_deref(), Some("the CTRL_BREAK"), "tree: {tree}");
        held.release();
        kill_release_reap_async(&mut child, sock, false).await;
    }
}

/// The warning for a proxy that has not answered by the threshold, as the sync driver gives it (see its
/// twin `a_proxy_that_has_not_answered_is_warned_of_once_and_waited_for`): logged once, naming the proxy's
/// pid and the child, and the call goes on waiting. A thread of the test waits for the warning record itself
/// and then tells the proxy to answer. The wait takes about the threshold of real time.
///
/// Mutants: the warning is never made (the thread then waits for a record that does not come, and the
/// test hangs: it is no assertion); it is made twice.
#[cfg(windows)]
#[skuld::test]
async fn async_a_proxy_that_has_not_answered_is_warned_of_once_and_waited_for() {
    use crate::stop::proxy::protocol::{CtrlEvent, ProxyAnswer};
    use crate::test_child::ctrl_break::{assert_proxy_answered, kill_release_reap_async};

    crate::log_capture::install();
    assert_current_thread();
    let mut held = Held::new();
    let (mut child, sock) = member_stopping_through(&held).await;
    let marker = format!("for child {} has not answered", child.pid());
    let mark = crate::log_capture::mark();
    let releaser = held.releaser();
    let release_at_the_warning = std::thread::spawn({
        let marker = marker.clone();
        move || {
            crate::log_capture::wait_for_since(mark, &marker);
            _ = releaser.send(());
        }
    });
    never_blocking(child.terminate())
        .await
        .expect("the proxy answered Sent, once told");
    release_at_the_warning.join().expect("the thread saw the warning");
    assert_proxy_answered(child.pid(), CtrlEvent::CtrlBreak, ProxyAnswer::Sent);
    let proxy = held.started().await;
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
    kill_release_reap_async(&mut child, sock, false).await;
}

/// The async driver's own part of that warning: its wait calls `late` once, and before it goes on to the
/// unbounded wait, for a root that is still running at the look (a threshold of zero makes the look one
/// look, so no time passes), and never for a root that has exited. The sibling that ends the root runs after
/// the wait's first poll, so a `late` that was not called by then fails here by assertion, not by a hang.
///
/// Mutants: the wait never calls `late`; it calls it for a root that has exited.
#[cfg(windows)]
#[skuld::test]
async fn async_wait_saying_calls_late_once_for_a_running_root_only() {
    use std::cell::Cell;

    assert_current_thread();
    let (member, writer, _) = crate::test_child::over_fake::live_member();
    let mut child = crate::tokio::Child { inner: member };
    let writer = Cell::new(Some(writer));
    let late = Cell::new(0u32);
    let late_at_release = Cell::new(None);
    let (waited, ()) = ::tokio::join!(
        child.wait_saying(Duration::ZERO, |_| late.set(late.get() + 1), None),
        async {
            late_at_release.set(Some(late.get()));
            drop(writer.take());
        }
    );
    waited
        .expect("the root ended once its input did")
        .expect("with no deadline, the wait is for the exit");
    assert_eq!(
        late_at_release.get(),
        Some(1),
        "late was called before the wait went on"
    );
    assert_eq!(late.get(), 1, "late was called once");

    // A root that has exited is not late: the wait that finds it so calls nothing.
    let (member, writer, _) = crate::test_child::over_fake::live_member();
    let mut child = crate::tokio::Child { inner: member };
    drop(writer);
    assert!(
        stop::wait_exit(&StopTarget::from(&child), Duration::MAX)
            .await
            .expect("the root's exit"),
        "the root exited"
    );
    child
        .wait_saying(
            Duration::ZERO,
            |_| panic!("late was called for a root that had exited"),
            None,
        )
        .await
        .expect("the exited root is reaped")
        .expect("with no deadline, the wait is for the exit");
}

/// The async `wait_saying` calls `late` for a threshold its deadline is after, and not for one at or before
/// the deadline, as the sync wait does (`a_warn_threshold_is_warned_of_only_when_the_deadline_is_after_it`). The
/// clock is frozen, so a tie is exact. A running root with the threshold due and the deadline an hour away is
/// warned of, and then waited for: the sibling, which runs after the wait's first poll, ends it. The other
/// rows end at their deadline, one look, and call `late` for nothing.
///
/// Mutants: the threshold is not filtered by the deadline (the rows with the deadline at or before it call
/// `late`); every threshold is filtered (the first row does not); the filter's `<` is `<=` (the tie calls it).
#[cfg(windows)]
#[skuld::test]
async fn async_wait_saying_calls_late_only_for_a_threshold_before_the_deadline() {
    use std::cell::Cell;

    use crate::wait::test_clock::FrozenClockGuard;

    assert_current_thread();
    let (_clock, now) = FrozenClockGuard::install();
    let (member, writer, _) = crate::test_child::over_fake::live_member();
    let mut child = crate::tokio::Child { inner: member };
    let hour = Duration::from_secs(3600);
    let late = Cell::new(0u32);
    let writer = Cell::new(Some(writer));
    let (waited, ()) = ::tokio::join!(
        child.wait_saying(Duration::ZERO, |_| late.set(late.get() + 1), Some(now + hour)),
        async {
            assert_eq!(late.get(), 1, "late was called before the wait went on");
            drop(writer.take());
        }
    );
    assert!(
        waited.expect("the root ended once its input did").is_some(),
        "the wait to a deadline an hour away saw the exit"
    );
    late.set(0);

    // The deadline is the threshold's instant, or before it: one look at a root that has exited by then.
    let (member, writer, _) = crate::test_child::over_fake::live_member();
    let mut child = crate::tokio::Child { inner: member };
    for (after, case) in [(Duration::ZERO, "a tie"), (Duration::from_secs(1), "a deadline before")] {
        let waited = child
            .wait_saying(after, |_| late.set(late.get() + 1), Some(now))
            .await
            .expect("a look at the root");
        assert!(waited.is_none(), "{case}: the root runs, and the deadline is past");
        assert_eq!(late.get(), 0, "{case}: nothing is waited for to warn of");
    }
    drop(writer);
    child.wait().await.expect("the root ended once its input did");
}

/// With no deadline the async `wait_saying` is `wait` after its warn stage: an untaken stdin is closed at once
/// (a child that exits only at the end of its input needs that), and the wait for the exit has no cap. The
/// future is polled once, with a threshold that is never due, and dropped: the stdin is closed by then, whatever
/// the child has done, which a wait that first waited for the exit (and would hang here) has not done.
///
/// Mutant: with no deadline, the wait for the exit comes before `wait` closes the stdin.
#[cfg(windows)]
#[skuld::test]
async fn async_wait_saying_with_no_deadline_closes_an_untaken_stdin_before_it_waits() {
    use crate::stdio::Fd;
    use crate::tokio::drive::drive_tests::poll_once;

    assert_current_thread();
    let mut cmd = test_child::tokio_command(Console::Hidden);
    cmd.args(test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::null()).expect("set stdout null");
    let mut child = cmd.spawn().await.expect("spawn");
    assert!(child.inner.pipes.contains_key(&Fd::STDIN), "the stdin is not taken");
    drop(poll_once(child.wait_saying(
        Duration::MAX,
        |_| panic!("the threshold is never due"),
        None,
    )));
    assert!(
        !child.inner.pipes.contains_key(&Fd::STDIN),
        "the untaken stdin was closed before the wait for the exit"
    );
    let status = child.wait().await.expect("the blocker ended at its input's end");
    assert!(status.success(), "{status:?}");
}

/// Async twin of the sync `a_child_that_has_exited_is_answered_before_the_proxy_is_started`: a child that has
/// exited is answered at the first look, `Ok` for a root target and the "root exited" error for
/// `terminate_tree`, and the proxy (the fixture, which answers `Sent`) is not started.
///
/// Mutants: the look comes after the gates or the start (the fixture ran, an answer is recorded); a root
/// target answers the tree's error.
#[cfg(windows)]
#[skuld::test]
async fn async_a_child_that_has_exited_is_answered_before_the_proxy_is_started() {
    use crate::stop::proxy::protocol::ProxyAnswer;
    use crate::stop::proxy::proxy_tests::Fixture;
    use crate::test_child::ctrl_break::{assert_no_break_sent, spawn_member_async, Handler};

    assert_current_thread();
    for tree in [false, true] {
        let fixture = Fixture::answering(ProxyAnswer::Sent.code());
        let (mut child, sock, _) =
            spawn_member_async(Handler::Ignore, None, Some(crate::ContainMode::Strongest), |cmd| {
                cmd.no_window();
                cmd.ctrl_proxy(fixture.setting());
            })
            .await;
        child.kill().expect("kill the member");
        child.wait().await.expect("see its exit");
        drop(sock);
        if tree {
            let err = never_blocking(child.terminate_tree())
                .await
                .expect_err("nothing was sent to a tree whose root had exited");
            assert!(
                matches!(err.error(), Error::Unassessable { detail, .. } if detail.contains("nothing was sent") && !detail.contains("CTRL_BREAK")),
                "{err:?}"
            );
            never_blocking(child.graceful_shutdown_tree(Duration::ZERO))
                .await
                .expect("the call goes on and ends the tree");
        } else {
            never_blocking(child.terminate()).await.expect("an exited child is Ok");
        }
        assert_no_break_sent();
        assert!(fixture.ran().is_none(), "tree {tree}: the proxy was started");
    }
}

/// Async twin of the sync `the_default_refuses_a_child_cosca_did_not_create`: `tokio::stop::default` refuses a
/// child a system service created whichever send it would have made, the direct one (the caller had a console
/// and the facts lead a group) or the proxy's (they do not). Nothing is sent and no proxy is asked.
///
/// Mutant: the async default does not refuse such a child (it answers `Ok`, or sends or asks past the refusal,
/// which the record of sends shows).
#[cfg(windows)]
#[skuld::test]
async fn async_the_default_refuses_a_child_cosca_did_not_create() {
    use crate::containment::windows::ConsoleFacts;

    assert_current_thread();
    for caller_had_console in [true, false] {
        let mut child = test_child::over_fake::child_over(&crate::os_process::fake::FakeProcess::new([
            crate::os_process::fake::Answer::Running,
        ]));
        child.console = ConsoleFacts {
            group: true,
            caller_had_console,
            ..ConsoleFacts::uac_elevated()
        };
        let err = never_blocking(stop::default(&StopTarget::from(&child)))
            .await
            .expect_err("not created by cosca");
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
