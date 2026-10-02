//! A tokio child is reaped behind its back and its pid reused: what it sends must not reach the
//! new owner. Each test runs as pid 1 of a fresh pid namespace (see `test_child::pid_reuse`), on a
//! `current_thread` runtime.

use std::os::fd::AsFd;

use rustix::process::{pidfd_open, Pid, PidfdFlags, WaitId, WaitIdOptions};

use crate::identity::fault::alias_token;
use crate::identity::StartToken;
use crate::send_log::{Capture, Via};
use crate::signal::Sig;
use crate::test_child::pid_reuse::{
    in_fresh_pid_ns, reap_behind_and_reuse, sigusr1_and_peek, sigusr1_and_wait, wait_pollin,
};
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
        let crate::tokio::child::ProcSource::Tokio { pidfd, .. } = child.proc_mut() else {
            panic!("a fresh child is a tokio backend");
        };
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

/// Whether `fd` is an open descriptor of this process.
fn is_open(fd: std::os::fd::RawFd) -> bool {
    // SAFETY: `F_GETFD` reads a flag and changes nothing.
    unsafe { libc::fcntl(fd, libc::F_GETFD) != -1 }
}

/// Dropping a handle whose child someone else reaped closes cosca's own pidfd, the one the spawn
/// handshake opened. (tokio's `Child` is forgotten, which leaks tokio's own pidfd where tokio has
/// one, on Linux 5.10+, so the test checks cosca's descriptor and counts nothing.) Runs in its own
/// process, so no other test can reuse the descriptor number between the drop and the check.
///
/// Mutant: the forget leaks cosca's pidfd with tokio's `Child`.
fn drop_after_a_foreign_reap_closes_cosca_pidfd_body() {
    runtime().block_on(async {
        let (mut child, writer) = spawn_blocker();
        let pid = child.id().pid();
        let crate::tokio::child::ProcSource::Tokio { pidfd, .. } = child.proc_mut() else {
            panic!("a fresh child is a tokio backend");
        };
        let cosca_pidfd = std::os::fd::AsRawFd::as_raw_fd(pidfd);
        assert!(is_open(cosca_pidfd), "cosca holds its pidfd while the child lives");
        drop(writer);
        crate::test_child::wait_until_zombie(pid);
        let mut status = 0;
        // SAFETY: `pid` is this test's own zombie child; this plays the application that reaps it.
        let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
        assert_eq!(reaped, pid as libc::pid_t, "{}", std::io::Error::last_os_error());

        drop(child);

        assert!(!is_open(cosca_pidfd), "the drop must close cosca's own pidfd");
    });
}
in_fresh_pid_ns!(
    namespaces_tokio_drop_after_a_foreign_reap_closes_cosca_pidfd,
    fixture_tokio_drop_pidfd_driver,
    fixture_tokio_drop_pidfd_init,
    drop_after_a_foreign_reap_closes_cosca_pidfd_body
);

// The elevated spawn's failure teardown =====

fn failed_write() -> Result<(), crate::error::Error> {
    Err(crate::error::Error::Elevation {
        kind: crate::error::ElevationErrorKind::AuthFailed,
        detail: "forced password-write failure".into(),
    })
}

fn elevation_detail(err: crate::error::Error) -> String {
    match err {
        crate::error::Error::Elevation { detail, .. } => detail,
        other => panic!("expected an Elevation error, got {other:?}"),
    }
}

/// A child someone else reaped was not terminated by the failure teardown: it says so, and waits
/// for nothing (a wait by its number would answer `ECHILD`).
///
/// Mutant: `kill`'s `Ok` for a gone child is read as "terminated" (the detail says so, and a wait
/// is recorded or attempted).
#[test]
fn finish_elevated_after_a_foreign_reap_does_not_claim_a_termination() {
    runtime().block_on(async {
        let (child, writer) = spawn_blocker();
        let pid = child.id().pid();
        drop(writer);
        crate::test_child::wait_until_zombie(pid);
        let mut status = 0;
        // SAFETY: `pid` is this test's own zombie child; this plays the application that reaps it.
        let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
        assert_eq!(reaped, pid as libc::pid_t, "{}", std::io::Error::last_os_error());

        let reaps = crate::child::spawn::fault::record_teardown_reaps();
        let err = crate::tokio::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");

        let detail = elevation_detail(err);
        assert!(detail.contains("could not be terminated"), "{detail}");
        assert!(!detail.contains("was terminated"), "{detail}");
        assert_eq!(reaps.recorded(), vec![], "nothing was waited on");
    });
}

/// The same, with the pid reused by a live child of this process: the teardown neither waits for
/// the stranger nor takes its exit record.
///
/// Mutant: as above (the wait by number parks on the stranger, which the nextest bound ends).
fn finish_elevated_after_a_foreign_reap_and_reuse_waits_for_nothing_body() {
    runtime().block_on(async {
        let (child, writer) = spawn_blocker();
        let (reuser, _alias) = foreign_reaped_and_reused(&child, writer);

        let reaps = crate::child::spawn::fault::record_teardown_reaps();
        let err = crate::tokio::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");

        let detail = elevation_detail(err);
        assert!(detail.contains("could not be terminated"), "{detail}");
        assert_eq!(reaps.recorded(), vec![], "nothing was waited on");
        assert_eq!(
            sigusr1_and_wait(reuser),
            Some(libc::SIGUSR1),
            "the reuser must be signalled and reaped by the test alone"
        );
    });
}
in_fresh_pid_ns!(
    namespaces_tokio_finish_elevated_after_a_foreign_reap_and_reuse_waits_for_nothing,
    fixture_tokio_finish_elevated_driver,
    fixture_tokio_finish_elevated_init,
    finish_elevated_after_a_foreign_reap_and_reuse_waits_for_nothing_body
);

// A dropped child whose pid was reused reaps nothing =====

/// `Drop` on a foreign-reaped child whose pid a stranger now holds: the stranger has already died
/// of the test's `SIGUSR1` and is a zombie when the child drops, so a reap by pid would take its
/// exit record. The drop must leave it for the test to consume.
///
/// Mutant: no forget (tokio's field-drop reaps the zombie by pid, and the test's own `waitid`
/// gets `ECHILD`).
fn drop_after_foreign_reap_and_reuse_reaps_nothing_body() {
    runtime().block_on(async {
        let (child, writer) = spawn_blocker();
        let (reuser, _alias) = foreign_reaped_and_reused(&child, writer);
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

// The spawn's identity-failure teardown =====

/// A spawn whose child is reaped behind its back, and its pid reused, between the fork and the
/// identity read: the failure teardown signals nothing, and a debug build does not panic.
///
/// Mutants: `reap_now` via `start_kill`; `signal` answers `Err(ESRCH)` (the debug build panics).
fn spawn_identity_failure_teardown_signals_nothing_body() {
    identity_failure_teardown(false, false);
}

/// The same, with the stranger already dead of the test's `SIGUSR1` and unreaped when the teardown
/// runs, so a wait or reap by pid finishes at once instead of parking, and takes its exit record.
///
/// Mutant: `wait_and_reap` keeps `P_PID` (the record is gone, so the test's `waitid` gets `ECHILD`;
/// with the stranger alive the same mutant parks forever, which the nextest bound ends).
fn spawn_identity_failure_teardown_reaps_nothing_body() {
    identity_failure_teardown(true, false);
}

/// The attach-failure arm of the same teardown: the identity read still succeeds (the alias makes
/// the stranger look like the child), and the forced attach failure tears the child down.
fn spawn_attach_failure_teardown_signals_nothing_body() {
    identity_failure_teardown(false, true);
}

fn spawn_attach_failure_teardown_reaps_nothing_body() {
    identity_failure_teardown(true, true);
}

fn identity_failure_teardown(stranger_dies_first: bool, attach_arm: bool) {
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
        if attach_arm {
            fault::set_force_attach_failure(true);
        } else {
            fault::set_force_identity_vanished(true);
        }
        let err = cmd.spawn().err();
        fault::set_force_attach_failure(false);
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
in_fresh_pid_ns!(
    namespaces_tokio_spawn_attach_failure_teardown_signals_nothing,
    fixture_tokio_spawn_attach_driver,
    fixture_tokio_spawn_attach_init,
    spawn_attach_failure_teardown_signals_nothing_body
);
in_fresh_pid_ns!(
    namespaces_tokio_spawn_attach_failure_teardown_reaps_nothing,
    fixture_tokio_spawn_attach_reaps_driver,
    fixture_tokio_spawn_attach_reaps_init,
    spawn_attach_failure_teardown_reaps_nothing_body
);
