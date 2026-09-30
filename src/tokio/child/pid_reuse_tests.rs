//! A tokio child is reaped behind its back and its pid reused: what it sends must not reach the
//! new owner. Each test runs as pid 1 of a fresh pid namespace (see `test_child::pid_reuse`), on a
//! `current_thread` runtime.

use std::os::fd::AsFd;
use std::sync::mpsc;

use rustix::process::{pidfd_open, Pid, PidfdFlags};

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

/// Mutant: the `Drop` kill via `start_kill`. The reap half of `Drop` is held at the probe's gate.
fn drop_kill_after_foreign_reap_and_reuse_body() {
    runtime().block_on(async {
        let (mut child, writer) = spawn_blocker();
        let (reuser, _alias) = foreign_reaped_and_reused(&mut child, writer);

        let (entered, _entered_rx) = mpsc::channel();
        let (started, _started_rx) = mpsc::channel();
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
        drop(reuser);
    });
}
in_fresh_pid_ns!(
    namespaces_tokio_drop_kill_after_foreign_reap_and_reuse_signals_nothing,
    fixture_tokio_drop_kill_reuse_driver,
    fixture_tokio_drop_kill_reuse_init,
    drop_kill_after_foreign_reap_and_reuse_body
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
