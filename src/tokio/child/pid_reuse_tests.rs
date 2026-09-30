//! A tokio child is reaped behind its back and its pid reused: what it sends must not reach the
//! new owner. Each test runs as pid 1 of a fresh pid namespace (see `test_child::pid_reuse`), on a
//! `current_thread` runtime.

use std::os::fd::AsFd;
use std::sync::mpsc;

use rustix::process::{pidfd_open, Pid, PidfdFlags, WaitId, WaitIdOptions};

use crate::identity::fault::alias_token;
use crate::identity::StartToken;
use crate::send_log::{Capture, Via};
use crate::signal::Sig;
use crate::test_child::pid_reuse::{
    in_fresh_pid_ns, reap_behind_and_reuse, sigusr1_and_peek, sigusr1_and_wait, wait_pollin,
};
use crate::tokio::Command;

use super::reaper::test_probe::{arm, assert_consumed, DropProbe, ReapOutcome};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current_thread runtime")
}

/// A blocker whose stdin the caller can close, so it exits when told to.
fn spawn_blocker() -> (crate::tokio::Child, std::io::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    (cmd.spawn().expect("spawn"), writer)
}

// The child keeps its handshake pidfd -----

/// Mutant: `held.map(|held| held.child)` drops the pidfd.
#[test]
fn tokio_child_holds_its_handshake_pidfd() {
    let rt = runtime();
    rt.block_on(async {
        let (mut child, writer) = spawn_blocker();
        let pid = child.id().pid();
        let proc = child.proc_mut();
        let pidfd = proc.pidfd().expect("the child must hold its pidfd");
        let dir = crate::identity::ProcDir::open().expect("/proc opens");
        let target = crate::identity::pidfd_pid_in_view(&dir, pidfd);
        assert!(
            matches!(target, Ok(crate::identity::PidfdTarget::Pid(p)) if p == pid),
            "the held pidfd must name the child: {target:?}"
        );
        drop(writer);
        child.wait().await.expect("wait");
    });
}

// Kill after a foreign reap and a reuse -----

/// Ends the child, reaps it behind tokio's back, reuses its pid and arms the token alias.
fn foreign_reaped_and_reused(
    child: &mut crate::tokio::Child,
    writer: std::io::PipeWriter,
) -> (std::process::Child, impl Sized) {
    let token = StartToken::from_raw(child.id().start_token_raw());
    drop(writer);
    let reuser = reap_behind_and_reuse(child.id().pid());
    let alias = alias_token(reuser.id(), token);
    (reuser, alias)
}

/// Mutant: Linux `kill` via `start_kill`.
fn kill_after_foreign_reap_and_reuse_body() {
    runtime().block_on(async {
        let (mut child, writer) = spawn_blocker();
        let (reuser, _alias) = foreign_reaped_and_reused(&mut child, writer);
        child.kill().expect("a kill of a foreign-reaped child answers Ok");
        assert_eq!(
            sigusr1_and_wait(reuser),
            Some(libc::SIGUSR1),
            "the reuser must have been signalled by the test alone"
        );
    });
}
in_fresh_pid_ns!(
    namespaces_tokio_kill_after_foreign_reap_and_reuse_signals_nothing,
    fixture_tokio_kill_reuse_driver,
    fixture_tokio_kill_reuse_init,
    kill_after_foreign_reap_and_reuse_body
);

/// A `Drop` of a foreign-reaped child whose pid a live stranger now holds signals nothing and
/// hands nothing to the reaper pool: a worker parked on the stranger would never come back, and
/// tokio's reap by pid would take it. The probe's `started` sender is dropped unused, so the
/// receiver's `Err` is the negative edge.
///
/// Mutants: the `Drop` kill via `start_kill` (the reuser dies of `SIGKILL`); `Drop` submitting
/// after a send that reached nobody (`started` arrives).
fn drop_after_foreign_reap_and_reuse_signals_and_submits_nothing_body() {
    runtime().block_on(async {
        let (mut child, writer) = spawn_blocker();
        let (reuser, _alias) = foreign_reaped_and_reused(&mut child, writer);

        let (entered, _entered_rx) = mpsc::channel();
        let (started, started_rx) = mpsc::channel();
        let (_gate_tx, gate) = mpsc::channel::<()>();
        let (outcome_tx, _outcome) = mpsc::channel();
        arm(DropProbe {
            entered,
            started,
            gate,
            outcome: outcome_tx,
        });

        drop(child);
        assert_consumed();
        assert!(
            started_rx.recv().is_err(),
            "no reaper worker may take a job for a child that was reaped by someone else"
        );
        assert_eq!(
            sigusr1_and_peek(&reuser),
            Some(libc::SIGUSR1),
            "the reuser must have been signalled by the test alone"
        );
        // tokio reaps its orphans at every spawn. A dropped `Child` that was queued as one would
        // take the dead reuser's exit record here.
        let mut tick = crate::test_spawn::spawn_tokio(&mut ::tokio::process::Command::new("true")).expect("spawn");
        tick.wait().await.expect("wait");
        let mut reuser = reuser;
        let status = reuser.wait().expect("the reuser must still be waitable by its owner");
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGUSR1)
        );
    });
}
in_fresh_pid_ns!(
    namespaces_tokio_drop_kill_after_foreign_reap_and_reuse_signals_nothing,
    fixture_tokio_drop_kill_reuse_driver,
    fixture_tokio_drop_kill_reuse_init,
    drop_after_foreign_reap_and_reuse_signals_and_submits_nothing_body
);

/// A backend with no pidfd has nothing to send through, so it sends nothing: it must not fall back
/// to a by-pid kill.
///
/// Mutant: `pidfd: None` falls back to `child.start_kill()`.
fn signal_without_a_pidfd_body() {
    runtime().block_on(async {
        let mut cmd = ::tokio::process::Command::new(crate::test_child::BLOCKER_ARGV[0]);
        cmd.stdin(std::process::Stdio::piped());
        let mut child = crate::test_spawn::spawn_tokio(&mut cmd).expect("spawn");
        let stdin = child.stdin.take().expect("piped stdin");
        let pid = child.id().expect("a fresh child has a pid");
        let proc = super::ProcSource::tokio(child);
        assert!(proc.pidfd().is_none(), "a hand-built backend has no pidfd");

        drop(stdin);
        let reuser = reap_behind_and_reuse(pid);
        proc.signal(Sig::Kill)
            .expect("a send with nothing to send through is Ok");
        assert_eq!(
            sigusr1_and_wait(reuser),
            Some(libc::SIGUSR1),
            "the reuser must have been signalled by the test alone"
        );
    });
}
in_fresh_pid_ns!(
    namespaces_tokio_signal_without_a_pidfd_sends_nothing,
    fixture_tokio_nopidfd_driver,
    fixture_tokio_nopidfd_init,
    signal_without_a_pidfd_body
);

// The send log -----

/// A `pidfd_send_signal` answering `ESRCH` is still an attempt. Mutant: record after a successful
/// syscall only.
fn send_log_failed_attempt_body() {
    runtime().block_on(async {
        let (mut child, writer) = spawn_blocker();
        let pid = child.id().pid();
        drop(writer);
        let pidfd = pidfd_open(Pid::from_raw(pid as i32).expect("pid"), PidfdFlags::empty()).expect("pidfd_open");
        wait_pollin(pidfd.as_fd());
        let reaped = rustix::process::waitid(
            rustix::process::WaitId::Pid(Pid::from_raw(pid as i32).expect("pid")),
            rustix::process::WaitIdOptions::EXITED,
        )
        .expect("raw reap");
        assert!(reaped.is_some());

        let log = Capture::start();
        child.kill().expect("Ok");
        assert_eq!(log.entries(), vec![(pid, Sig::Kill, Via::Pidfd)]);
    });
}
in_fresh_pid_ns!(
    namespaces_send_log_records_a_failed_attempt,
    fixture_send_log_failed_driver,
    fixture_send_log_failed_init,
    send_log_failed_attempt_body
);

// A dropped child whose pid was reused reaps nothing -----

/// `Drop` on a foreign-reaped child whose pid a stranger now holds: the stranger has already died
/// of the test's `SIGUSR1` and is a zombie when the child drops, so a reap by pid would take its
/// exit record. The drop must leave it for the test to consume.
///
/// Mutants: no forget (tokio's field-drop reaps the zombie by pid, and the test's own `waitid`
/// gets `ECHILD`).
fn drop_after_foreign_reap_and_reuse_reaps_nothing_body() {
    runtime().block_on(async {
        let (mut child, writer) = spawn_blocker();
        let (reuser, _alias) = foreign_reaped_and_reused(&mut child, writer);
        let reuser_pid = reuser.id();
        assert_eq!(
            sigusr1_and_peek(&reuser),
            Some(libc::SIGUSR1),
            "the reuser must have been signalled by the test alone"
        );

        drop(child);

        let pid = Pid::from_raw(reuser_pid as i32).expect("pid");
        let record = rustix::process::waitid(WaitId::Pid(pid), WaitIdOptions::EXITED)
            .expect("the reuser's exit record must still be unconsumed")
            .expect("an exit record");
        assert_eq!(record.terminating_signal(), Some(libc::SIGUSR1));
        drop(reuser);
    });
}
in_fresh_pid_ns!(
    namespaces_tokio_drop_after_foreign_reap_and_reuse_signals_and_reaps_nothing,
    fixture_tokio_drop_reaps_nothing_driver,
    fixture_tokio_drop_reaps_nothing_init,
    drop_after_foreign_reap_and_reuse_reaps_nothing_body
);

// The spawn's identity-failure teardown -----

/// A spawn whose child is reaped behind its back, and its pid reused, between the fork and the
/// identity read: the failure teardown signals nothing, and a debug build does not panic.
///
/// Mutants: `reap_now` via `start_kill`; `signal` answers `Err(ESRCH)` (the debug build panics).
fn spawn_identity_failure_teardown_signals_nothing_body() {
    identity_failure_teardown(false);
}

/// The same, with the stranger already dead of the test's `SIGUSR1` and unreaped when the teardown
/// runs, so a wait or reap by pid finishes at once instead of parking, and takes its exit record.
///
/// Mutant: `wait_and_reap` keeps `P_PID` (the record is gone, so the test's `waitid` gets `ECHILD`;
/// with the stranger alive the same mutant parks forever, which the nextest bound ends).
fn spawn_identity_failure_teardown_reaps_nothing_body() {
    identity_failure_teardown(true);
}

fn identity_failure_teardown(stranger_dies_first: bool) {
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::child::spawn::fault;
    use crate::identity::{ProcessId, Resolved};

    runtime().block_on(async {
        let (stdin, writer) = crate::test_child::held_writer_stdin();
        let mut cmd = Command::new();
        cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
        cmd.stdin(stdin).expect("set stdin");

        let stranger = Rc::new(RefCell::new(None));
        let alias = Rc::new(RefCell::new(None));
        let _hook = fault::set_at(fault::SpawnPoint::BeforeIdentity, {
            let (stranger, alias) = (Rc::clone(&stranger), Rc::clone(&alias));
            move || {
                let pid = fault::spawn_pid();
                let Resolved::Found(id) = ProcessId::of(pid) else {
                    panic!("the child must be readable before it is reaped")
                };
                let token = StartToken::from_raw(id.start_token_raw());
                drop(writer);
                let reuser = reap_behind_and_reuse(pid);
                *alias.borrow_mut() = Some(alias_token(reuser.id(), token));
                if stranger_dies_first {
                    assert_eq!(sigusr1_and_peek(&reuser), Some(libc::SIGUSR1));
                }
                *stranger.borrow_mut() = Some(reuser);
            }
        });
        fault::set_force_identity_vanished(true);
        let err = cmd.spawn().err();
        fault::set_force_identity_vanished(false);
        err.expect("the forced identity failure must fail the spawn");

        let mut reuser = stranger.borrow_mut().take().expect("the hook must have run");
        if stranger_dies_first {
            let status = reuser
                .wait()
                .expect("the stranger's exit record must still be unconsumed");
            assert_eq!(
                std::os::unix::process::ExitStatusExt::signal(&status),
                Some(libc::SIGUSR1)
            );
        } else {
            assert_eq!(
                sigusr1_and_wait(reuser),
                Some(libc::SIGUSR1),
                "the reuser must have been signalled by the test alone"
            );
        }
        drop(alias);
    });
}
in_fresh_pid_ns!(
    namespaces_tokio_spawn_identity_failure_teardown_signals_nothing,
    fixture_tokio_spawn_identity_driver,
    fixture_tokio_spawn_identity_init,
    spawn_identity_failure_teardown_signals_nothing_body
);
in_fresh_pid_ns!(
    namespaces_tokio_spawn_identity_failure_teardown_reaps_nothing,
    fixture_tokio_spawn_identity_reaps_driver,
    fixture_tokio_spawn_identity_reaps_init,
    spawn_identity_failure_teardown_reaps_nothing_body
);

// The reaper's forget -----

/// A live child is dropped: the kill is delivered and the reap job parks at the probe's gate. While
/// it waits, the child is reaped behind the job's back and its pid reused. The job then finds the
/// pidfd foreign and must forget the child, not drop it (which would reap the stranger by pid).
///
/// Mutant: `run_teardown` does not forget on `Foreign`.
fn teardown_forgets_a_child_reaped_while_it_waited_body() {
    runtime().block_on(async {
        let (child, writer) = spawn_blocker();
        let pid = child.id().pid();

        let (entered, _entered_rx) = mpsc::channel();
        let (started, started_rx) = mpsc::channel();
        let (gate_tx, gate) = mpsc::channel::<()>();
        let (outcome_tx, outcome) = mpsc::channel();
        arm(DropProbe {
            entered,
            started,
            gate,
            outcome: outcome_tx,
        });
        drop(child);
        assert_consumed();
        started_rx.recv().expect("a worker must take the job");

        let reuser = reap_behind_and_reuse(pid);
        assert_eq!(
            sigusr1_and_peek(&reuser),
            Some(libc::SIGUSR1),
            "the reuser must have been signalled by the test alone"
        );
        drop(gate_tx);
        assert!(
            matches!(outcome.recv(), Ok(ReapOutcome::Reaped(_))),
            "the job must complete"
        );

        let record = rustix::process::waitid(
            WaitId::Pid(Pid::from_raw(reuser.id() as i32).expect("pid")),
            WaitIdOptions::EXITED,
        )
        .expect("the reuser's exit record must still be unconsumed")
        .expect("an exit record");
        assert_eq!(record.terminating_signal(), Some(libc::SIGUSR1));
        drop((reuser, writer));
    });
}
in_fresh_pid_ns!(
    namespaces_tokio_teardown_forgets_a_child_reaped_while_it_waited,
    fixture_tokio_teardown_forgets_driver,
    fixture_tokio_teardown_forgets_init,
    teardown_forgets_a_child_reaped_while_it_waited_body
);
