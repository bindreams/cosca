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
        matches!(&err, Error::Unsupported { detail, .. } if detail == "refused by the test action"),
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
    held: &Arc<Mutex<Option<crate::tokio::ChildStdin>>>,
) -> impl for<'t, 'c> Fn(&'t StopTarget<'c>) -> StopFuture<'t> + Send + Sync + 'static {
    let held = Arc::clone(held);
    move |target| {
        let held = Arc::clone(&held);
        Box::pin(async move {
            stop::send_signal(target, crate::Signal::Usr1).await?;
            drop(held.lock().unwrap().take());
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
        let held = Arc::new(Mutex::new(None));
        let (mut child, stdin, mut stdout) =
            test_child::ready_tree_async(test_child::SIGNAL_REPORTING_TREE_ARGV, |cmd| {
                test_child::contain_without_cgroup_async(cmd);
                cmd.graceful_stop(signalling_then_ending_the_input(&held));
            })
            .await;
        *held.lock().unwrap() = Some(stdin);
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
            child.wait().await.expect("the root exited on its handler");
        }
    }
}

// Composing sends with a wait =====

/// A [`SIGNAL_THEN_TERM_TREE_ARGV`](test_child::SIGNAL_THEN_TERM_TREE_ARGV) tree's stdout, read as its
/// members report: each wait is for the members' own lines, a real condition with no time in it.
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
/// which fails by assertion, and the wait for the root's exit is for an exit that comes.
///
/// Mutants: `wait_exit` answers `true` whatever the root did; the chosen signal is replaced by `SIGTERM`.
#[cfg(unix)]
#[skuld::test]
async fn async_an_action_may_compose_sends_with_a_wait() {
    assert_current_thread();
    for tree in [false, true] {
        let waited = Arc::new(Mutex::new(Vec::new()));
        let reports = Arc::new(::tokio::sync::Mutex::new(None::<Reports>));
        let held = Arc::new(Mutex::new(None::<crate::tokio::ChildStdin>));
        let (first, last): (&'static [&'static str], &'static [&'static str]) = if tree {
            (&["root SIGUSR1", "leaf SIGUSR1"], &["root SIGTERM", "leaf SIGTERM"])
        } else {
            (&["root SIGUSR1"], &["root SIGTERM"])
        };
        let (mut child, stdin, stdout) = test_child::ready_tree_async(test_child::SIGNAL_THEN_TERM_TREE_ARGV, |cmd| {
            if tree {
                test_child::contain_without_cgroup_async(cmd);
            }
            let (waited, reports, held) = (Arc::clone(&waited), Arc::clone(&reports), Arc::clone(&held));
            cmd.graceful_stop(move |target| {
                let (waited, reports, held) = (Arc::clone(&waited), Arc::clone(&reports), Arc::clone(&held));
                Box::pin(async move {
                    stop::send_signal(target, crate::Signal::Usr1).await?;
                    // The members keep running: the root is looked at once, and every member reports
                    // the signal before the second goes out.
                    let running = stop::wait_exit(target, Duration::ZERO).await?;
                    waited.lock().unwrap().push(running);
                    reports.lock().await.as_mut().expect("the reports").until(first).await;
                    stop::send_signal(target, crate::Signal::Term).await?;
                    drop(held.lock().unwrap().take());
                    reports.lock().await.as_mut().expect("the reports").until(last).await;
                    // The root exits on the second signal: the wait ends on its exit.
                    let exited = stop::wait_exit(target, Duration::MAX).await?;
                    waited.lock().unwrap().push(exited);
                    Ok(())
                })
            });
        })
        .await;
        *held.lock().unwrap() = Some(stdin);
        *reports.lock().await = Some(Reports::new(stdout));
        if tree {
            never_blocking(child.terminate_tree()).await.expect("the composed stop");
        } else {
            never_blocking(child.terminate()).await.expect("the composed stop");
        }
        assert_eq!(*waited.lock().unwrap(), [false, true], "tree: {tree}");
        let reports = reports.lock().await.take().expect("the reports");
        assert_eq!(reports.of("root"), ["root SIGUSR1", "root SIGTERM"], "tree: {tree}");
        if tree {
            assert_eq!(reports.of("leaf"), ["leaf SIGUSR1", "leaf SIGTERM"], "tree: {tree}");
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
    let held = Arc::new(Mutex::new(None));
    let (mut child, stdin, mut stdout) = test_child::ready_tree_async(test_child::SIGNAL_REPORTING_TREE_ARGV, |cmd| {
        test_child::contain_without_cgroup_async(cmd);
        let held = Arc::clone(&held);
        cmd.graceful_stop(move |target| {
            let held = Arc::clone(&held);
            Box::pin(async move {
                prepared_send(target).await?;
                drop(held.lock().unwrap().take());
                Err(refused())
            })
        });
    })
    .await;
    *held.lock().unwrap() = Some(stdin);
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

/// A `terminate` dropped while its proxy runs has ended the proxy by the time the drop returns: the proxy's
/// handle is dropped with the future, which kills and reaps it. The future is polled by hand, to its wait for
/// the proxy: the start of the proxy is on the blocking pool, and the future is woken when it is done. A drop
/// during the start is not this case: the start ends the proxy when it completes, not the drop.
///
/// Mutant: the proxy's handle outlives the future (it is detached or leaked).
#[cfg(windows)]
#[skuld::test]
async fn a_dropped_terminate_has_ended_its_proxy() {
    use std::future::Future as _;
    use std::task::Context;

    use crate::test_child::ctrl_break::{assert_no_break_sent, kill_release_reap_async};

    assert_current_thread();
    let mut held = Held::new();
    let (mut child, sock) = member_stopping_through(&held).await;
    {
        let (waker, wakes) = crate::tokio::test_runtime::counting_waker();
        let mut cx = Context::from_waker(&waker);
        let mut terminate = Box::pin(child.terminate());
        assert!(
            terminate.as_mut().poll(&mut cx).is_pending(),
            "the proxy is not started yet"
        );
        // The start of the proxy finished: the next poll is the wait for it.
        wakes.recv().expect("the start of the proxy woke the call");
        assert!(
            terminate.as_mut().poll(&mut cx).is_pending(),
            "the proxy has not answered, so the call waits for it"
        );
        let proxy = held.started().await;
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
    let (waited, ()) = ::tokio::join!(child.wait_saying(Duration::ZERO, |_| late.set(late.get() + 1)), async {
        late_at_release.set(Some(late.get()));
        drop(writer.take());
    });
    waited.expect("the root ended once its input did");
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
        .wait_saying(Duration::ZERO, |_| panic!("late was called for a root that had exited"))
        .await
        .expect("the exited root is reaped");
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
                matches!(&err, Error::Unassessable { detail, .. } if detail.contains("nothing was sent") && !detail.contains("CTRL_BREAK")),
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
