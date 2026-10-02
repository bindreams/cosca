//! A tokio child is reaped behind its back and its pid reused: what it sends must not reach the
//! new owner. Each test runs as pid 1 of a fresh pid namespace (see `test_child::pid_reuse`), on a
//! `current_thread` runtime.

use std::os::fd::AsFd;

use rustix::process::{pidfd_open, Pid, PidfdFlags};

use crate::identity::fault::alias_token;
use crate::identity::StartToken;
use crate::send_log::{Capture, Via};
use crate::signal::Sig;
use crate::test_child::pid_reuse::{in_fresh_pid_ns, reap_behind_and_reuse, sigusr1_and_wait, wait_pollin};
use crate::tokio::Command;

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

// The child keeps its handshake pidfd =====

/// Mutant: the spawn drops the pidfd the handshake opened (`held.map(|held| held.child)`), so the
/// backend holds one that names nothing, or none.
#[test]
fn tokio_child_holds_its_handshake_pidfd() {
    runtime().block_on(async {
        let (mut child, writer) = spawn_blocker();
        let pid = child.id().pid();
        let crate::tokio::child::ProcSource::Tokio { pidfd, .. } = child.proc_mut();
        let dir = crate::identity::ProcDir::open().expect("/proc opens");
        let target = crate::identity::pidfd_pid_in_view(&dir, pidfd.as_fd());
        assert!(
            matches!(target, Ok(crate::identity::PidfdTarget::Pid(p)) if p == pid),
            "the held pidfd must name the child: {target:?}"
        );
        drop(writer);
        child.wait().await.expect("wait");
    });
}

// Kill after a foreign reap and a reuse =====

/// Ends the child, reaps it behind tokio's back, reuses its pid and arms the token alias, so a
/// check of the pid's start token would take the reuser for the child.
fn foreign_reaped_and_reused(
    child: &crate::tokio::Child,
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
        let (reuser, _alias) = foreign_reaped_and_reused(&child, writer);
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

/// A `Drop` kill of a foreign-reaped child whose pid a live stranger now holds reaches the
/// stranger by neither pid nor token: the send goes through the pidfd, and is the only one.
///
/// Mutant: the `Drop` kill via `start_kill` (the reuser dies of `SIGKILL`).
fn drop_kill_after_foreign_reap_and_reuse_body() {
    runtime().block_on(async {
        let (child, writer) = spawn_blocker();
        let pid = child.id().pid();
        let (reuser, _alias) = foreign_reaped_and_reused(&child, writer);
        let log = Capture::start();
        drop(child);
        assert_eq!(log.entries(), vec![(pid, Sig::Kill, Via::Pidfd)]);
        assert_eq!(
            sigusr1_and_wait(reuser),
            Some(libc::SIGUSR1),
            "the reuser must have been signalled by the test alone"
        );
    });
}
in_fresh_pid_ns!(
    namespaces_tokio_drop_kill_after_foreign_reap_and_reuse_signals_nothing,
    fixture_tokio_drop_kill_reuse_driver,
    fixture_tokio_drop_kill_reuse_init,
    drop_kill_after_foreign_reap_and_reuse_body
);

// The send log =====

/// A `pidfd_send_signal` answering `ESRCH` is still an attempt, and `kill` through it is `Ok`.
///
/// Mutant: `kill` does not go through [`crate::signal::via_pidfd`], so nothing is recorded.
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
    namespaces_tokio_kill_records_a_gone_attempt_through_the_pidfd,
    fixture_tokio_kill_gone_driver,
    fixture_tokio_kill_gone_init,
    send_log_failed_attempt_body
);

// A dropped child reaped behind its back =====

/// How many open descriptors of this process are pidfds.
fn open_pidfds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("read /proc/self/fd")
        .filter_map(Result::ok)
        .filter(|entry| {
            std::fs::read_link(entry.path()).is_ok_and(|target| target.to_string_lossy() == "anon_inode:[pidfd]")
        })
        .count()
}

/// Dropping a handle whose child someone else reaped closes cosca's own pidfd (the one the spawn
/// handshake opened) and forgets tokio's `Child`, which leaks tokio's pidfd and its reactor
/// registration: exactly one pidfd stays open. A reap by pid there could take a process that reused
/// the number, and tokio offers no exact reap or release (see `forget_reaped_elsewhere`), so the one
/// leak is the cost. It goes away with a backend that is not tokio's `Child`.
///
/// Mutant: the forget takes cosca's pidfd with it (two stay open).
#[test]
fn tokio_drop_after_a_foreign_reap_leaks_no_pidfd() {
    runtime().block_on(async {
        let before = open_pidfds();
        let (child, writer) = spawn_blocker();
        let pid = child.id().pid();
        drop(writer);
        crate::test_child::wait_until_zombie(pid);
        let mut status = 0;
        // SAFETY: `pid` is this test's own zombie child; this plays the application that reaps it.
        let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
        assert_eq!(reaped, pid as libc::pid_t, "{}", std::io::Error::last_os_error());

        drop(child);

        assert_eq!(
            open_pidfds(),
            before + 1,
            "only tokio's forgotten pidfd may stay open, not cosca's own"
        );
    });
}
