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
        let crate::tokio::child::ProcSource::Tokio { pidfd, .. } = child.proc_mut();
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

/// The same, with the pid reused by a child of this process: the teardown does not wait for the
/// stranger. (The stranger is alive when the handle drops, so tokio's own drop would find nothing
/// to take either way. A stranger that is already a zombie at the drop is
/// `namespaces_tokio_drop_after_foreign_reap_and_reuse_signals_and_reaps_nothing`.)
///
/// A regressed teardown would wait by the number. So that it returns at once instead of parking on
/// a live stranger, the stranger is made a zombie in the gap between the kill and the wait (the
/// teardown's own hook), where a by-pid wait takes its record. The test then reaps it itself and
/// asserts it got `SIGUSR1`: `ECHILD` means the record was stolen.
///
/// Mutant: `kill`'s `Ok` for a gone child is read as "terminated", and the wait by number runs.
fn finish_elevated_after_a_foreign_reap_and_reuse_waits_for_nothing_body() {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    runtime().block_on(async {
        let (child, writer) = spawn_blocker();
        let (reuser, _alias) = foreign_reaped_and_reused(&child, writer);
        let reuser = Rc::new(RefCell::new(Some(reuser)));
        let died = Rc::new(Cell::new(false));
        let _hook = crate::child::spawn::fault::set_between_kill_and_wait({
            let (reuser, died) = (Rc::clone(&reuser), Rc::clone(&died));
            move || {
                let reuser = reuser.borrow();
                assert_eq!(
                    sigusr1_and_peek(reuser.as_ref().expect("the reuser")),
                    Some(libc::SIGUSR1)
                );
                died.set(true);
            }
        });

        let reaps = crate::child::spawn::fault::record_teardown_reaps();
        let err = crate::tokio::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");

        let detail = elevation_detail(err);
        assert!(detail.contains("could not be terminated"), "{detail}");
        assert_eq!(reaps.recorded(), vec![], "nothing was waited on");
        let mut reuser = reuser.borrow_mut().take().expect("the reuser");
        if !died.get() {
            crate::test_child::pid_reuse::signal_usr1(&reuser);
        }
        let status = reuser
            .wait()
            .expect("the reuser's exit record must not have been taken by the teardown");
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGUSR1),
            "the reuser must have been signalled by the test alone"
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
/// The alias makes the stranger's start token equal the child's, as a reuse in the same tick does,
/// so only the pidfd's `ESRCH` (the kill's `Gone`) can tell the drop the child is gone.
///
/// Mutant: the drop does not forget on `Gone` (tokio's field-drop reaps the zombie by pid, and the
/// test's own `waitid` gets `ECHILD`).
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
