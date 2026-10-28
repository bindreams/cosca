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
use crate::test_child::reaped_elsewhere::{assert_one_reaped_elsewhere_warn, REAPED_ELSEWHERE};
use crate::test_groups::{namespaces, tracer_group};
use crate::tokio::Command;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current_thread runtime")
}

/// A blocker whose stdin the caller can close, so it exits when told to.
fn spawn_blocker() -> (crate::tokio::Child, std::io::PipeWriter) {
    spawn_blocker_with(true)
}

/// [`spawn_blocker`] with `kill_on_drop` as given.
fn spawn_blocker_with(kill_on_drop: bool) -> (crate::tokio::Child, std::io::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.kill_on_drop(kill_on_drop);
    (cmd.spawn().expect("spawn"), writer)
}

// The child keeps its handshake pidfd =====

/// Mutant: the spawn drops the pidfd the handshake opened (`held.map(|held| held.child)`), so the
/// backend holds one that names nothing, or none.
#[skuld::test]
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

/// A `Drop` of a foreign-reaped child whose pid a live stranger now holds sends it nothing by pid or
/// token. The drop sees from the child's own pidfd that the root is reaped, so it sends nothing at
/// all.
///
/// Mutant: the drop has no first look, so it sends the pidfd kill (the log then shows a send).
fn drop_kill_after_foreign_reap_and_reuse_body() {
    runtime().block_on(async {
        let (child, writer) = spawn_blocker();
        let (reuser, _alias) = foreign_reaped_and_reused(&child, writer);
        let log = Capture::start();
        drop(child);
        assert_eq!(log.entries(), vec![], "the drop sees the reap and sends nothing");
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
/// handshake opened. (tokio's `Child` is forgotten, so the test checks cosca's descriptor and counts
/// nothing.) Runs in its own process, so no other test can reuse the descriptor number between the drop and the check.
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
#[skuld::test]
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
        let (err, fate) = crate::tokio::spawn::finish_elevated(child, failed_write())
            .expect_err("the spawn fails")
            .expect_may_have_started_with();
        assert_eq!(fate, crate::error::ChildFate::Gone);

        let detail = elevation_detail(err);
        assert!(detail.contains("could not be terminated"), "{detail}");
        assert!(!detail.contains("was terminated"), "{detail}");
        assert_eq!(reaps.recorded(), vec![], "nothing was waited on");
    });
}

/// The same, with the pid reused by a child of this process: the teardown does not wait for the
/// stranger.
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
        let (err, fate) = crate::tokio::spawn::finish_elevated(child, failed_write())
            .expect_err("the spawn fails")
            .expect_may_have_started_with();
        assert_eq!(fate, crate::error::ChildFate::Gone);

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

/// The teardown's kill is delivered, and in the gap before its wait the child is reaped behind its
/// back and a stranger takes its pid, then dies. The wait goes through the pidfd, so it takes
/// nothing: the stranger's record is still there for the test, with `SIGUSR1`.
///
/// Detected by `reaps.recorded()` (the test-only recorder of teardown reaps), which a by-number
/// wait fills with the stranger's status. The stranger's record itself survives such a wait, since
/// `Drop`'s forget masks tokio's later by-pid reap, so `ECHILD` is not what catches it.
///
/// Mutant: the wait is by the number (the recorder shows the stranger's status).
fn finish_elevated_after_a_delivered_kill_and_a_foreign_reap_and_reuse_waits_for_nothing_body() {
    use std::cell::RefCell;
    use std::rc::Rc;

    runtime().block_on(async {
        let (child, writer) = spawn_blocker();
        let pid = child.id().pid();
        let stranger = Rc::new(RefCell::new(None));
        let _hook = crate::child::spawn::fault::set_between_kill_and_wait({
            let stranger = Rc::clone(&stranger);
            move || {
                drop(writer);
                let reuser = reap_behind_and_reuse(pid);
                assert_eq!(sigusr1_and_peek(&reuser), Some(libc::SIGUSR1));
                *stranger.borrow_mut() = Some(reuser);
            }
        });

        let reaps = crate::child::spawn::fault::record_teardown_reaps();
        let (err, fate) = crate::tokio::spawn::finish_elevated(child, failed_write())
            .expect_err("the spawn fails")
            .expect_may_have_started_with();
        assert_eq!(fate, crate::error::ChildFate::Killed);

        let detail = elevation_detail(err);
        assert!(detail.contains("was terminated"), "{detail}");
        assert_eq!(
            reaps.recorded(),
            vec![],
            "the stranger's exit was not recorded as a reap"
        );
        let mut stranger = stranger.borrow_mut().take().expect("the hook must have run");
        let status = stranger
            .wait()
            .expect("the stranger's exit record must not have been taken by the teardown");
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGUSR1)
        );
    });
}
in_fresh_pid_ns!(
    namespaces_tokio_finish_elevated_after_a_delivered_kill_and_a_foreign_reap_and_reuse_waits_for_nothing,
    fixture_tokio_finish_elevated_delivered_driver,
    fixture_tokio_finish_elevated_delivered_init,
    finish_elevated_after_a_delivered_kill_and_a_foreign_reap_and_reuse_waits_for_nothing_body
);

// A dropped child whose pid was reused reaps nothing =====

/// `Drop` on a foreign-reaped child whose pid a stranger now holds: the stranger has already died
/// of the test's `SIGUSR1` and is a zombie when the child drops, so a reap by pid would take its
/// exit record. The drop must leave it for the test to consume.
///
/// The alias makes the stranger's start token equal the child's, as a reuse in the same tick does,
/// so only the child's own handle (its pidfd) can tell the drop the child is gone.
///
/// Mutant: the drop does not forget (tokio's field-drop reaps the zombie by pid, and the test's own
/// `waitid` gets `ECHILD`).
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
    namespaces_tokio_drop_after_foreign_reap_and_reuse_reaps_nothing,
    fixture_tokio_drop_reaps_nothing_driver,
    fixture_tokio_drop_reaps_nothing_init,
    drop_after_foreign_reap_and_reuse_reaps_nothing_body
);

/// An armed drop whose kill was delivered, and whose root is then reaped behind its back and its pid
/// taken by a stranger, before the drop's wait: the wait goes through the child's pidfd, finds it
/// gone, and neither signals nor reaps the stranger. The stranger is already a zombie of the test's
/// `SIGUSR1` when the wait runs, so a by-pid reap would take its record.
///
/// The hook releases the child's stdin once the drop's kill returned, then checks it died of
/// `SIGKILL`: a kill that sent nothing leaves a child that exits `0` on the release, and fails there
/// instead of leaving the hook to wait for an exit nothing causes.
///
/// Mutants: the drop's root kill by pid (the send log shows no pidfd kill); the wait reaps by pid
/// (the test's own `waitid` on the stranger answers `ECHILD`); the drop's root kill sends nothing
/// (the child is not `SIGKILL`ed).
fn armed_drop_after_foreign_reap_and_reuse_signals_nothing_body() {
    use std::cell::RefCell;
    use std::rc::Rc;

    runtime().block_on(async {
        let (child, writer) = spawn_blocker();
        let pid = child.id().pid();
        let token = StartToken::from_raw(child.id().start_token_raw());
        // The reuser, and the token alias that keeps it the child's look-alike.
        type Reused = Option<(std::process::Child, Box<dyn std::any::Any>)>;
        let reused: Rc<RefCell<Reused>> = Rc::default();
        let hand = Rc::clone(&reused);
        let _between = crate::child::spawn::fault::set_between_kill_and_wait(move || {
            drop(writer);
            crate::test_child::assert_zombie_sigkilled("the child", pid);
            let reuser = reap_behind_and_reuse(pid);
            let alias = alias_token(reuser.id(), token);
            assert_eq!(sigusr1_and_peek(&reuser), Some(libc::SIGUSR1));
            *hand.borrow_mut() = Some((reuser, Box::new(alias)));
        });
        let log = Capture::start();

        drop(child);

        assert_eq!(
            log.entries(),
            vec![(pid, Sig::Kill, Via::Pidfd)],
            "one kill, through the pidfd"
        );
        let (reuser, alias) = reused.borrow_mut().take().expect("the drop reached its wait");
        let record = rustix::process::waitid(
            WaitId::Pid(Pid::from_raw(pid as i32).expect("pid")),
            WaitIdOptions::EXITED,
        )
        .expect("the reuser's exit record must still be unconsumed")
        .expect("an exit record");
        assert_eq!(record.terminating_signal(), Some(libc::SIGUSR1));
        drop((reuser, alias));
    });
}
in_fresh_pid_ns!(
    namespaces_tokio_armed_drop_after_foreign_reap_and_reuse_signals_nothing,
    fixture_tokio_armed_drop_reuse_driver,
    fixture_tokio_armed_drop_reuse_init,
    armed_drop_after_foreign_reap_and_reuse_signals_nothing_body
);

/// The same for a failed run-to-completion helper's awaited teardown: the root is reaped behind
/// its back and its pid taken by a stranger that is already a zombie, before the awaited reap
/// looks. The reap finds the root gone through its pidfd and takes nothing.
///
/// The hook releases the child's stdin once the teardown's kill returned, then checks it died of
/// `SIGKILL`, as in the armed drop's test above.
fn awaited_teardown_after_foreign_reap_and_reuse_takes_nothing_body() {
    use std::cell::RefCell;
    use std::rc::Rc;

    runtime().block_on(async {
        let (mut child, writer) = spawn_blocker();
        let pid = child.id().pid();
        type Reused = Option<std::process::Child>;
        let reused: Rc<RefCell<Reused>> = Rc::default();
        let hand = Rc::clone(&reused);
        let _between = crate::child::spawn::fault::set_between_kill_and_wait(move || {
            drop(writer);
            crate::test_child::assert_zombie_sigkilled("the child", pid);
            let reuser = reap_behind_and_reuse(pid);
            assert_eq!(sigusr1_and_peek(&reuser), Some(libc::SIGUSR1));
            *hand.borrow_mut() = Some(reuser);
        });
        let log = Capture::start();

        let fate = child.tear_down_awaiting().await;

        assert_eq!(
            log.entries(),
            vec![(pid, Sig::Kill, Via::Pidfd)],
            "one kill, through the pidfd"
        );
        let mut reuser = reused.borrow_mut().take().expect("the teardown reached its reap");
        let status = reuser
            .wait()
            .expect("the reuser's exit record must still be unconsumed");
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGUSR1)
        );
        assert_ne!(
            fate,
            crate::error::ChildFate::Reaped,
            "the root's exit was not collected"
        );
    });
}
in_fresh_pid_ns!(
    namespaces_tokio_awaited_teardown_after_foreign_reap_and_reuse_takes_nothing,
    fixture_tokio_awaited_teardown_reuse_driver,
    fixture_tokio_awaited_teardown_reuse_init,
    awaited_teardown_after_foreign_reap_and_reuse_takes_nothing_body
);

// A traced zombie reaped elsewhere while a reap waits on events =====

/// Spawns a tokio tracee, has a foreign tracer seize it, and arms the reap-parked seam: once a reap
/// that waits on events has looked and found the zombie held by the tracer, the tracer hands it
/// back, the test reaps it behind its owner's back, and a stranger that is already a zombie of ours
/// takes its pid. Answers the child, its stdin and the slot the seam leaves the stranger in.
async fn traced_then_reaped_elsewhere_on_park() -> (
    crate::tokio::Child,
    crate::tokio::ChildStdin,
    std::rc::Rc<std::cell::RefCell<Option<std::process::Child>>>,
    crate::oneshot_hook::Armed,
) {
    use crate::test_support::foreign_tracer::{self, REAP};

    let (child, stdin) = foreign_tracer::spawn_tokio_tracee().await;
    let pid = child.id().pid();
    let mut tracer = foreign_tracer::spawn_helper(pid);
    let reused: std::rc::Rc<std::cell::RefCell<Option<std::process::Child>>> = std::rc::Rc::default();
    let hand = std::rc::Rc::clone(&reused);
    let parked = crate::tokio::child::fault::set_reap_parked(move || {
        tracer.send(REAP);
        tracer.expect("reaped");
        let reuser = reap_behind_and_reuse(pid);
        assert_eq!(sigusr1_and_peek(&reuser), Some(libc::SIGUSR1));
        *hand.borrow_mut() = Some(reuser);
    });
    (child, stdin, reused, parked)
}

/// Asserts the stranger the seam left in `reused` still has its exit record, of `SIGUSR1`.
fn assert_stranger_untouched(reused: &std::cell::RefCell<Option<std::process::Child>>) {
    let mut reuser = reused
        .borrow_mut()
        .take()
        .expect("the reap parked on the traced zombie");
    let status = reuser
        .wait()
        .expect("the stranger's exit record must still be unconsumed");
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&status),
        Some(libc::SIGUSR1)
    );
}

/// An awaited teardown whose root a foreign tracer holds as a zombie looks at the root again
/// before every reap it tries. Here the tracer lets go after the teardown found the zombie held,
/// the application reaps the root, and its pid goes to a stranger that is already a zombie of ours:
/// the teardown takes nothing.
///
/// Mutant: tokio's own `wait` after one look (its repeated `waitpid(pid)` takes the stranger's
/// record).
fn awaited_teardown_of_a_traced_zombie_reaped_elsewhere_body() {
    runtime().block_on(async {
        let (mut child, stdin, reused, _parked) = traced_then_reaped_elsewhere_on_park().await;
        let fate = child.tear_down_awaiting().await;
        assert_stranger_untouched(&reused);
        assert_ne!(
            fate,
            crate::error::ChildFate::Reaped,
            "the root's exit was not collected"
        );
        drop(stdin);
    });
}
in_fresh_pid_ns!(
    namespaces_tokio_awaited_teardown_of_a_traced_zombie_reaped_elsewhere_takes_nothing,
    fixture_tokio_awaited_traced_driver,
    fixture_tokio_awaited_traced_init,
    awaited_teardown_of_a_traced_zombie_reaped_elsewhere_body,
    tracer
);

/// The same for `wait` after `kill`: `wait` answers `ECHILD` and takes nothing. (Killed, not left to
/// exit on its own: any other signal, even an ignored `SIGPIPE`, stops a tracee until its tracer
/// resumes it.)
///
/// Mutant: tokio's own `wait` after one look.
fn wait_of_a_traced_zombie_reaped_elsewhere_body() {
    runtime().block_on(async {
        let (mut child, stdin, reused, _parked) = traced_then_reaped_elsewhere_on_park().await;
        child.kill().expect("kill the tracee");
        let answer = child.wait().await;
        assert_stranger_untouched(&reused);
        assert!(
            matches!(&answer, Err(crate::error::Error::Io(e)) if e.raw_os_error() == Some(libc::ECHILD)),
            "wait answered {answer:?}"
        );
        drop(stdin);
    });
}
in_fresh_pid_ns!(
    namespaces_tokio_wait_of_a_traced_zombie_reaped_elsewhere_takes_nothing,
    fixture_tokio_wait_traced_driver,
    fixture_tokio_wait_traced_init,
    wait_of_a_traced_zombie_reaped_elsewhere_body,
    tracer
);

/// The same with `kill_on_drop(false)`, which the derived elevated command reaches: the drop sends
/// no kill, so nothing but the held pidfd can tell it the child is gone, and the start token (equal
/// here, as for a reuse in the same tick) cannot.
///
/// Mutant: the drop asks the pidfd only when an armed kill ran (so a disarmed drop trusts the token).
fn disarmed_drop_after_foreign_reap_and_reuse_reaps_nothing_body() {
    runtime().block_on(async {
        let (child, writer) = spawn_blocker_with(false);
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
    namespaces_tokio_disarmed_drop_after_foreign_reap_and_reuse_reaps_nothing,
    fixture_tokio_disarmed_drop_driver,
    fixture_tokio_disarmed_drop_init,
    disarmed_drop_after_foreign_reap_and_reuse_reaps_nothing_body
);

// A reap that lands after the drop's first look =====

/// Makes the drop's FIRST look at the child's pidfd answer `Running`, as if the reap had not
/// happened yet, while the alias hides it from the start token: only the look after the signals
/// can see it. (The seam answers one peek, and the first look consumes it.)
fn first_look_sees_it_running() -> impl Sized {
    use crate::wait::exit_only::seams::force_peek_once;
    use crate::wait::exit_only::Peek;
    force_peek_once(Ok(Peek::Running))
}

/// An armed drop whose first look misses the reap. Its root kill goes through the pidfd (`ESRCH`,
/// so it reaches nothing), the second look forgets tokio's `Child`, and the live stranger is killed
/// by the test alone.
///
/// Mutants: the armed drop's root kill is by `libc::kill(pid)` (the stranger dies of `SIGKILL`);
/// the drop has no second look (nothing is forgotten, `forgets` is 0).
fn armed_drop_whose_first_look_missed_the_reap_body() {
    runtime().block_on(async {
        let (child, writer) = spawn_blocker();
        let pid = child.id().pid();
        let (reuser, _alias) = foreign_reaped_and_reused(&child, writer);
        let root = super::drop_fault::record();
        let log = Capture::start();
        let _look = first_look_sees_it_running();

        drop(child);

        assert_eq!(root.kills(), 1, "the armed drop reached its root kill");
        assert_eq!(root.forgets(), 1, "the second look forgot tokio's Child");
        assert_eq!(log.entries(), vec![(pid, Sig::Kill, Via::Pidfd)]);
        assert_eq!(
            sigusr1_and_wait(reuser),
            Some(libc::SIGUSR1),
            "the reuser must have been signalled by the test alone"
        );
    });
}
in_fresh_pid_ns!(
    namespaces_tokio_armed_drop_whose_first_look_missed_the_reap_leaves_the_stranger_alone,
    fixture_tokio_first_look_armed_live_driver,
    fixture_tokio_first_look_armed_live_init,
    armed_drop_whose_first_look_missed_the_reap_body
);

/// The same, armed and disarmed, with a stranger that is already a zombie, so a by-pid
/// reap would take its record.
///
/// Mutant: the drop has no second look (tokio's field-drop reaps by pid: `ECHILD`).
fn drop_whose_first_look_missed_the_reap_reaps_nothing(kill_on_drop: bool) {
    runtime().block_on(async {
        let (child, writer) = spawn_blocker_with(kill_on_drop);
        let (reuser, _alias) = foreign_reaped_and_reused(&child, writer);
        let reuser_pid = reuser.id();
        assert_eq!(sigusr1_and_peek(&reuser), Some(libc::SIGUSR1));
        let _look = first_look_sees_it_running();

        drop(child);

        let pid = Pid::from_raw(reuser_pid as i32).expect("pid");
        let record = rustix::process::waitid(WaitId::Pid(pid), WaitIdOptions::EXITED)
            .expect("the reuser's exit record must still be unconsumed")
            .expect("an exit record");
        assert_eq!(record.terminating_signal(), Some(libc::SIGUSR1));
        drop(reuser);
    });
}
fn armed_zombie_drop_whose_first_look_missed_the_reap_body() {
    drop_whose_first_look_missed_the_reap_reaps_nothing(true);
}
fn disarmed_zombie_drop_whose_first_look_missed_the_reap_body() {
    drop_whose_first_look_missed_the_reap_reaps_nothing(false);
}
in_fresh_pid_ns!(
    namespaces_tokio_armed_zombie_drop_whose_first_look_missed_the_reap_reaps_nothing,
    fixture_tokio_first_look_armed_zombie_driver,
    fixture_tokio_first_look_armed_zombie_init,
    armed_zombie_drop_whose_first_look_missed_the_reap_body
);
in_fresh_pid_ns!(
    namespaces_tokio_disarmed_zombie_drop_whose_first_look_missed_the_reap_reaps_nothing,
    fixture_tokio_first_look_disarmed_zombie_driver,
    fixture_tokio_first_look_disarmed_zombie_init,
    disarmed_zombie_drop_whose_first_look_missed_the_reap_body
);

/// A process-group child reaped behind its back, its pid reused and the start token aliased: the
/// failure teardown and the drop inside it must send no `killpg` by the group's number. Only the
/// pidfd look (not the start token) can see the reap, in `finish_elevated` and again in its drop.
///
/// Mutants: `kill_tree_members_unless_reaped` has no pidfd term (`finish_elevated` runs `killpg`);
/// the drop has no first look (its tree kill runs `killpg`).
fn finish_elevated_of_an_aliased_process_group_sends_no_killpg_body() {
    runtime().block_on(async {
        let recorder = crate::containment::unix::fault::record_kill_group();
        let (stdin, writer) = crate::test_child::held_writer_stdin();
        let mut cmd = Command::new();
        cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
        cmd.stdin(stdin).expect("set stdin");
        cmd.contain_with(crate::ContainMode::Session);
        let child = cmd.spawn().expect("spawn");
        assert!(
            child.signals_a_group(),
            "the test needs a group named by the root's pid, which ContainMode::Session makes"
        );
        let (_reuser, _alias) = foreign_reaped_and_reused(&child, writer);

        let (err, fate) = crate::tokio::spawn::finish_elevated(child, failed_write())
            .expect_err("the spawn fails")
            .expect_may_have_started_with();
        assert_eq!(fate, crate::error::ChildFate::Gone);

        let detail = elevation_detail(err);
        assert_eq!(
            recorder.killed(),
            Vec::<i32>::new(),
            "no killpg by a reaped root's number ({detail})"
        );
    });
}
in_fresh_pid_ns!(
    namespaces_tokio_finish_elevated_of_an_aliased_process_group_sends_no_killpg,
    fixture_tokio_first_look_process_group_driver,
    fixture_tokio_first_look_process_group_init,
    finish_elevated_of_an_aliased_process_group_sends_no_killpg_body
);

// A failed peek through the child's own pidfd =====

/// A peek that fails on the child's own pidfd cannot show the child is ours, so its state is
/// unknown: the child is forgotten, never released to tokio's by-pid reap.
///
/// Mutant: a failed peek counts as ours.
#[skuld::test]
fn a_failed_pidfd_peek_is_unknown_so_the_child_is_forgotten() {
    use crate::wait::exit_only::seams::force_peeks;
    runtime().block_on(async {
        let (mut child, _writer) = spawn_blocker();
        // One failed peek for the state read, one for the forget's own look.
        let _failed = force_peeks((0..2).map(|_| Err(std::io::Error::other("forced peek failure"))));
        assert!(
            matches!(child.proc_mut().state(), crate::signal::RootState::Unknown(_)),
            "a child nothing can answer for is not shown to be ours"
        );
        let forgot = child.proc_mut().forget_if_foreign();
        assert!(
            forgot.is_some(),
            "a child nothing can answer for is not tokio's to reap by pid"
        );
        assert!(
            child.proc_mut().is_reaped(),
            "the forgotten child is not tokio's any more"
        );
    });
}

// Wait and try_wait after a foreign reap and a reuse =====

/// A `try_wait` or `wait` of a child reaped behind tokio's back, whose pid a stranger that is
/// already a zombie of ours now holds, answers `ECHILD` and takes nothing: tokio's own wait is a
/// `waitpid` by pid, and would take the stranger's record. The test reaps the stranger itself and
/// asserts it got `SIGUSR1`.
///
/// Mutants: `ProcSource::try_wait` or `wait` go to tokio without looking at the pidfd.
fn after_foreign_reap_and_reuse(use_wait: bool) {
    runtime().block_on(async {
        let (mut child, writer) = spawn_blocker();
        let (mut reuser, _alias) = foreign_reaped_and_reused(&child, writer);
        assert_eq!(
            sigusr1_and_peek(&reuser),
            Some(libc::SIGUSR1),
            "the stranger is a zombie"
        );
        let answer = if use_wait {
            child.wait().await.map(Some)
        } else {
            child.try_wait()
        };
        let err = answer.expect_err("a foreign-reaped child has no status to give");
        assert!(
            matches!(&err, crate::error::Error::Io(e) if e.raw_os_error() == Some(libc::ECHILD)),
            "{err:?}"
        );
        let status = reuser.wait().expect("the stranger's record must not have been taken");
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGUSR1)
        );
    });
}
fn try_wait_after_foreign_reap_and_reuse_body() {
    after_foreign_reap_and_reuse(false);
}
fn wait_after_foreign_reap_and_reuse_body() {
    after_foreign_reap_and_reuse(true);
}
in_fresh_pid_ns!(
    namespaces_tokio_try_wait_after_foreign_reap_and_reuse_takes_nothing,
    fixture_tokio_try_wait_reuse_driver,
    fixture_tokio_try_wait_reuse_init,
    try_wait_after_foreign_reap_and_reuse_body
);
in_fresh_pid_ns!(
    namespaces_tokio_wait_after_foreign_reap_and_reuse_takes_nothing,
    fixture_tokio_wait_reuse_driver,
    fixture_tokio_wait_reuse_init,
    wait_after_foreign_reap_and_reuse_body
);

/// A `wait` already parked in its exit watch when the child is reaped behind tokio's back and its
/// pid is reused by a stranger that is a zombie of ours answers `ECHILD` and takes nothing. The
/// check after the watch is what stops tokio's by-pid `waitpid` from taking the stranger's record.
///
/// Mutants: no check after the watch; no watch (tokio waits for the child's whole life).
fn wait_parked_then_foreign_reap_and_reuse_body() {
    runtime().block_on(async {
        let (mut child, writer) = spawn_blocker();
        let id = child.id();
        let mut waiting = std::pin::pin!(child.wait());
        let parked = std::future::poll_fn(|cx| {
            std::task::Poll::Ready(std::future::Future::poll(waiting.as_mut(), cx).is_pending())
        })
        .await;
        assert!(parked, "wait must be parked on a live child");
        let token = StartToken::from_raw(id.start_token_raw());
        drop(writer);
        let mut reuser = reap_behind_and_reuse(id.pid());
        let _alias = alias_token(reuser.id(), token);
        assert_eq!(
            sigusr1_and_peek(&reuser),
            Some(libc::SIGUSR1),
            "the stranger is a zombie"
        );
        let answer = waiting.await;
        let status = reuser.wait();
        assert!(
            matches!(&answer, Err(crate::error::Error::Io(e)) if e.raw_os_error() == Some(libc::ECHILD)),
            "wait answered {answer:?}; the stranger's own wait: {status:?}"
        );
        let status = status.expect("the stranger's record must not have been taken");
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGUSR1)
        );
    });
}
in_fresh_pid_ns!(
    namespaces_tokio_wait_parked_then_foreign_reap_and_reuse_takes_nothing,
    fixture_tokio_wait_parked_driver,
    fixture_tokio_wait_parked_init,
    wait_parked_then_foreign_reap_and_reuse_body
);

// The spawn's failure teardown =====

/// A spawn whose child is reaped behind its back, and its pid reused, then fails: between the fork
/// and the identity read, which then answers `Gone`; or, once the identity is verified, between
/// the check and the attach, which is forced to fail.
/// The failure teardown signals nothing, waits for nothing and takes no exit record, and a debug
/// build does not panic.
///
/// A regressed teardown would wait by the number. So that it returns at once instead of parking on
/// a live stranger, the stranger is made a zombie in the gap between the teardown's kill and its
/// wait (the teardown's own hook), where a by-pid wait takes its record. The test then reaps the
/// stranger itself and asserts it got `SIGUSR1`: `SIGKILL` means the teardown signalled it, and
/// `ECHILD` means it took the record.
///
/// Mutants: `reap_now` via `start_kill`; `wait_and_reap` keeps `P_PID`; `signal` answers
/// `Err(ESRCH)` (the debug build panics).
fn spawn_failure_teardown_leaves_the_stranger_alone(attach_arm: bool) {
    use std::cell::{Cell, RefCell};
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
        let died = Rc::new(Cell::new(false));
        let point = if attach_arm {
            fault::SpawnPoint::BeforeAttach
        } else {
            fault::SpawnPoint::BeforeIdentity
        };
        let _spawn_hook = fault::set_at(point, {
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
                *stranger.borrow_mut() = Some(reuser);
            }
        });
        let _wait_hook = fault::set_between_kill_and_wait({
            let (stranger, died) = (Rc::clone(&stranger), Rc::clone(&died));
            move || {
                let stranger = stranger.borrow();
                assert_eq!(
                    sigusr1_and_peek(stranger.as_ref().expect("the stranger")),
                    Some(libc::SIGUSR1),
                    "the stranger must have been signalled by the test alone"
                );
                died.set(true);
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
        let (err, fate) = crate::child::spawn::failure::expect_may_have_started_with(
            err.expect("the forced failure must fail the spawn"),
        );
        assert_eq!(fate, crate::error::ChildFate::Gone, "the child was reaped elsewhere");
        // The arm under test ran: only the forced attach failure is a `Containment` error.
        assert_eq!(
            matches!(err, crate::error::Error::Containment { .. }),
            attach_arm,
            "the spawn must fail in the arm under test: {err:?}"
        );

        let mut stranger = stranger.borrow_mut().take().expect("the hook must have run");
        if !died.get() {
            crate::test_child::pid_reuse::signal_usr1(&stranger);
        }
        let status = stranger
            .wait()
            .expect("the stranger's exit record must not have been taken by the teardown");
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGUSR1),
            "the stranger must have been signalled by the test alone"
        );
        drop(alias);
    });
}
fn spawn_identity_failure_teardown_body() {
    spawn_failure_teardown_leaves_the_stranger_alone(false);
}
fn spawn_attach_failure_teardown_body() {
    spawn_failure_teardown_leaves_the_stranger_alone(true);
}
in_fresh_pid_ns!(
    namespaces_tokio_spawn_identity_failure_teardown_leaves_the_stranger_alone,
    fixture_tokio_spawn_identity_driver,
    fixture_tokio_spawn_identity_init,
    spawn_identity_failure_teardown_body
);
in_fresh_pid_ns!(
    namespaces_tokio_spawn_attach_failure_teardown_leaves_the_stranger_alone,
    fixture_tokio_spawn_attach_driver,
    fixture_tokio_spawn_attach_init,
    spawn_attach_failure_teardown_body
);

/// A spawn whose child is reaped behind its back, and its pid reused by a stranger whose start
/// token aliases the child's, between the fork and the identity read. The read finds the stranger,
/// so only the check against the backend's own pidfd shows it is not the child: the spawn fails as
/// vanished, and the stranger is signalled by the test alone.
///
/// Mutant: `resolve_identity` skips the peek through the handle.
fn spawn_identity_gone_after_a_reap_at(point: crate::child::spawn::fault::SpawnPoint) {
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
        let alias: Rc<RefCell<Option<Box<dyn std::any::Any>>>> = Rc::default();
        let _hook = fault::set_at(point, {
            let (stranger, alias) = (Rc::clone(&stranger), Rc::clone(&alias));
            move || {
                let pid = fault::spawn_pid();
                let Resolved::Found(id) = ProcessId::of(pid) else {
                    panic!("the child must be readable before it is reaped")
                };
                let token = StartToken::from_raw(id.start_token_raw());
                drop(writer);
                let reuser = reap_behind_and_reuse(pid);
                *alias.borrow_mut() = Some(Box::new(alias_token(reuser.id(), token)));
                *stranger.borrow_mut() = Some(reuser);
            }
        });
        let (err, fate) = match cmd.spawn() {
            Ok(child) => panic!("the spawn took the stranger for its child: {:?}", child.id()),
            Err(e) => crate::child::spawn::failure::expect_may_have_started_with(e),
        };
        assert_eq!(fate, crate::error::ChildFate::Gone, "the child was reaped elsewhere");
        let stranger = stranger.borrow_mut().take().expect("the hook must have run");
        assert!(
            matches!(&err, crate::error::Error::Io(e) if e.to_string().contains("reaped by another party")),
            "a child reaped before its identity was read is Gone, not Unassessable: {err:?}"
        );
        assert_eq!(
            sigusr1_and_wait(stranger),
            Some(libc::SIGUSR1),
            "the stranger must have been signalled by the test alone"
        );
        drop(alias);
    });
}
fn spawn_identity_after_foreign_reap_and_reuse_is_gone_body() {
    spawn_identity_gone_after_a_reap_at(crate::child::spawn::fault::SpawnPoint::BeforeIdentity);
}
in_fresh_pid_ns!(
    namespaces_tokio_spawn_identity_after_foreign_reap_and_reuse_is_gone,
    fixture_tokio_spawn_identity_gone_driver,
    fixture_tokio_spawn_identity_gone_init,
    spawn_identity_after_foreign_reap_and_reuse_is_gone_body
);

/// The reap lands right before the attach, after the identity was verified. The attach takes the
/// verified identity and reads nothing by pid, so the tree-walk root is the child itself and
/// `kill_tree` reaches no one: the stranger's start token is its own (aliased to differ from the child's, as a reuse in a
/// later clock tick has it, since the tick it really started in may match).
///
/// Mutant: the attach re-reads the root by pid.
fn treewalk_root_is_the_verified_identity_body() {
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::child::spawn::fault;
    use crate::identity::fault::alias_token;
    use crate::identity::{ProcessId, Resolved, StartToken};

    runtime().block_on(async {
        let (stdin, writer) = crate::test_child::held_writer_stdin();
        let mut cmd = Command::new();
        cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
        cmd.stdin(stdin).expect("set stdin");
        cmd.contain_with(crate::ContainMode::TreeWalk);

        let stranger = Rc::new(RefCell::new(None));
        let alias: Rc<RefCell<Option<Box<dyn std::any::Any>>>> = Rc::default();
        let _hook = fault::set_at(fault::SpawnPoint::BeforeAttach, {
            let (stranger, alias) = (Rc::clone(&stranger), Rc::clone(&alias));
            move || {
                let pid = fault::spawn_pid();
                let Resolved::Found(id) = ProcessId::of(pid) else {
                    panic!("the child must be readable before it is reaped")
                };
                drop(writer);
                let reuser = reap_behind_and_reuse(pid);
                // A reuse in a later clock tick, whichever tick the reuser really started in.
                let token = StartToken::from_raw(id.start_token_raw() + 1);
                *alias.borrow_mut() = Some(Box::new(alias_token(reuser.id(), token)));
                *stranger.borrow_mut() = Some(reuser);
            }
        });
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => panic!("a reap after the verified identity read must not fail the spawn: {e:?}"),
        };
        let stranger = stranger.borrow_mut().take().expect("the hook must have run");
        assert_eq!(
            stranger.id(),
            child.id().pid(),
            "the stranger must hold the child's pid"
        );
        assert_eq!(
            child.test_treewalk_root(),
            Some(child.id()),
            "the walk's root must be the verified identity, not whoever holds the pid now"
        );
        child.kill_tree().expect("a tree whose root was reaped answers Ok");
        assert_eq!(
            sigusr1_and_wait(stranger),
            Some(libc::SIGUSR1),
            "the stranger must have been signalled by the test alone"
        );
    });
}
in_fresh_pid_ns!(
    namespaces_tokio_treewalk_root_is_the_verified_identity,
    fixture_tokio_treewalk_root_driver,
    fixture_tokio_treewalk_root_init,
    treewalk_root_is_the_verified_identity_body
);

// Panicking loggers =====

/// The spawn's identity-failure teardown, child reaped behind its back and its pid reused by a
/// stranger that is already a zombie. `reap_now`'s kill gets ESRCH through the pidfd, and
/// `via_pidfd` logs "already gone". A logger that panics there unwinds out of the spawn with the
/// backend in hand, and the unwind must leak tokio's `Child`, not reap the stranger by pid.
fn a_panicking_logger_in_reap_nows_via_pidfd_log_body() {
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::child::spawn::fault;

    crate::log_capture::install();
    runtime().block_on(async {
        let (stdin, writer) = crate::test_child::held_writer_stdin();
        let mut cmd = Command::new();
        cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
        cmd.stdin(stdin).expect("set stdin");
        let stranger = Rc::new(RefCell::new(None));
        let _spawn_hook = fault::set_at(fault::SpawnPoint::BeforeIdentity, {
            let stranger = Rc::clone(&stranger);
            move || {
                let pid = fault::spawn_pid();
                drop(writer);
                let reuser = reap_behind_and_reuse(pid);
                assert_eq!(sigusr1_and_peek(&reuser), Some(libc::SIGUSR1));
                *stranger.borrow_mut() = Some(reuser);
            }
        });
        fault::set_force_identity_vanished(true);
        let unwound = {
            let _panics = crate::log_capture::panic_on("it is already gone");
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cmd.spawn().map(drop)))
        };
        fault::set_force_identity_vanished(false);
        assert!(unwound.is_err(), "the logger must have panicked out of the spawn");
        let mut stranger = stranger.borrow_mut().take().expect("the hook must have run");
        let status = stranger
            .wait()
            .expect("the stranger's exit record must not have been taken by the teardown");
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGUSR1)
        );
    });
}
in_fresh_pid_ns!(
    namespaces_a_panicking_logger_in_reap_nows_via_pidfd_log_leaves_the_stranger_alone,
    fixture_panicking_logger_reap_now_driver,
    fixture_panicking_logger_reap_now_init,
    a_panicking_logger_in_reap_nows_via_pidfd_log_body
);

/// `Drop`'s first look misses the reap (forced `Running`, standing in for a reap that lands after
/// it) and its armed kill gets ESRCH through the pidfd, so `via_pidfd` logs. A logger that panics
/// there unwinds with tokio's `Child` in `os`, and the unwind must leak it, not reap the stranger
/// by pid.
fn a_panicking_logger_in_drops_via_pidfd_log_body() {
    use crate::wait::exit_only::seams::force_peek_once;
    use crate::wait::exit_only::Peek;

    crate::log_capture::install();
    runtime().block_on(async {
        let (child, writer) = spawn_blocker();
        let (reuser, _alias) = foreign_reaped_and_reused(&child, writer);
        let reuser_pid = reuser.id();
        assert_eq!(sigusr1_and_peek(&reuser), Some(libc::SIGUSR1));
        let _first_look = force_peek_once(Ok(Peek::Running));
        let unwound = {
            let _panics = crate::log_capture::panic_on("it is already gone");
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(child)))
        };
        assert!(unwound.is_err(), "the logger must have panicked out of the drop");
        let pid = Pid::from_raw(reuser_pid as i32).expect("pid");
        let record = rustix::process::waitid(WaitId::Pid(pid), WaitIdOptions::EXITED)
            .expect("the reuser's exit record must still be unconsumed")
            .expect("an exit record");
        assert_eq!(record.terminating_signal(), Some(libc::SIGUSR1));
        drop(reuser);
    });
}
in_fresh_pid_ns!(
    namespaces_a_panicking_logger_in_drops_via_pidfd_log_leaves_the_stranger_alone,
    fixture_panicking_logger_drop_driver,
    fixture_panicking_logger_drop_init,
    a_panicking_logger_in_drops_via_pidfd_log_body
);

// Tree signals after a reap and a reuse =====

/// A blocker in its own session (`Attached::ProcessGroup`), which exits once `writer` is dropped.
fn spawn_group_blocker() -> (crate::tokio::Child, std::io::PipeWriter) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(crate::ContainMode::Session);
    let child = cmd.spawn().expect("spawn");
    assert!(
        child.signals_a_group(),
        "the test needs a group named by the root's pid, which ContainMode::Session makes"
    );
    (child, writer)
}

/// The token a reuser of `child`'s pid is made to read with: `child`'s own (a reuse in the same
/// clock tick, which only the handle can tell apart) or the next one (a later tick, which the
/// number shows).
fn reuser_token(child: &crate::tokio::Child, same_tick: bool) -> StartToken {
    let raw = child.id().start_token_raw();
    StartToken::from_raw(if same_tick { raw } else { raw + 1 })
}

/// The sync `kill_tree_after_a_foreign_reap_and_reuse`'s twin. Mutants: the precondition assert
/// kept (a debug panic on the later-tick reuse); `killpg` sent; the decision taken on the number
/// alone (the same-tick reuse reads as the root).
fn kill_tree_after_a_foreign_reap_and_reuse(same_tick: bool) {
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    runtime().block_on(async {
        crate::log_capture::install();
        let recorder = crate::containment::unix::fault::record_kill_group();
        let (mut child, writer) = spawn_group_blocker();
        let pid = child.id().pid();
        let token = reuser_token(&child, same_tick);
        drop(writer);
        let reuser = reap_behind_and_reuse(pid);
        let _alias = alias_token(reuser.id(), token);

        let mark = crate::log_capture::mark();
        let err = child
            .kill_tree()
            .expect_err("a group whose root was reaped elsewhere is not assessable");

        assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
        assert_eq!(
            recorder.killed(),
            Vec::<i32>::new(),
            "no killpg by a reaped root's number"
        );
        assert_one_reaped_elsewhere_warn(mark, pid);
        assert_eq!(
            sigusr1_and_wait(reuser),
            Some(libc::SIGUSR1),
            "the reuser must have been signalled by the test alone"
        );
    });
}
fn kill_tree_after_a_foreign_reap_and_reuse_body() {
    kill_tree_after_a_foreign_reap_and_reuse(false);
}
fn kill_tree_after_a_foreign_reap_and_same_tick_reuse_body() {
    kill_tree_after_a_foreign_reap_and_reuse(true);
}
in_fresh_pid_ns!(
    namespaces_tokio_kill_tree_after_a_foreign_reap_and_reuse_sends_no_killpg,
    fixture_tokio_kill_tree_reuse_driver,
    fixture_tokio_kill_tree_reuse_init,
    kill_tree_after_a_foreign_reap_and_reuse_body
);
in_fresh_pid_ns!(
    namespaces_tokio_kill_tree_after_a_foreign_reap_and_same_tick_reuse_sends_no_killpg,
    fixture_tokio_kill_tree_same_tick_driver,
    fixture_tokio_kill_tree_same_tick_init,
    kill_tree_after_a_foreign_reap_and_same_tick_reuse_body
);

/// `terminate_tree`'s twin. Same mutants.
fn terminate_tree_after_a_foreign_reap_and_reuse_body() {
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    runtime().block_on(async {
        crate::log_capture::install();
        let recorder = crate::containment::unix::fault::record_term_group();
        let (child, writer) = spawn_group_blocker();
        let pid = child.id().pid();
        let token = reuser_token(&child, false);
        drop(writer);
        let reuser = reap_behind_and_reuse(pid);
        let _alias = alias_token(reuser.id(), token);

        let mark = crate::log_capture::mark();
        let err = child
            .terminate_tree()
            .expect_err("a group whose root was reaped elsewhere is not assessable");

        assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
        assert_eq!(
            recorder.termed(),
            Vec::<i32>::new(),
            "no SIGTERM by a reaped root's number"
        );
        assert_one_reaped_elsewhere_warn(mark, pid);
        assert_eq!(
            sigusr1_and_wait(reuser),
            Some(libc::SIGUSR1),
            "the reuser must have been signalled by the test alone"
        );
    });
}
in_fresh_pid_ns!(
    namespaces_tokio_terminate_tree_after_a_foreign_reap_and_reuse_sends_no_signal,
    fixture_tokio_terminate_tree_reuse_driver,
    fixture_tokio_terminate_tree_reuse_init,
    terminate_tree_after_a_foreign_reap_and_reuse_body
);

/// A root this handle reaped itself, whose pid now names another process: `kill_tree` sends
/// nothing and is `Ok`, whether the reuser reads as another process or as the root. Mutants: the
/// precondition assert kept (a debug panic); our own reap answered as foreign (`Unassessable`);
/// `killpg` sent; the number trusted when it reads as the root (same tick); the tree not marked
/// killed, so the drop warns.
fn kill_tree_after_own_wait_and_reuse(same_tick: bool) {
    runtime().block_on(async {
        crate::log_capture::install();
        let recorder = crate::containment::unix::fault::record_kill_group();
        let (mut child, writer) = spawn_group_blocker();
        let pid = child.id().pid();
        let token = reuser_token(&child, same_tick);
        drop(writer);
        child.wait().await.expect("this handle reaps the root");
        let reuser = crate::test_child::pid_reuse::reuse(pid);
        let _alias = alias_token(reuser.id(), token);

        let mark = crate::log_capture::mark();
        child
            .kill_tree()
            .expect("a tree whose root this handle reaped answers Ok");

        assert_eq!(
            recorder.killed(),
            Vec::<i32>::new(),
            "no killpg by a reaped root's number"
        );
        assert_eq!(
            crate::log_capture::records_since_on_current_thread(mark, REAPED_ELSEWHERE),
            [],
            "our own reap is not a foreign one"
        );
        let dropped = crate::log_capture::mark();
        drop(child);
        assert_eq!(
            crate::test_child::reaped_elsewhere::warns_since(dropped),
            Vec::<String>::new(),
            "the group is empty, so the tree counts as killed: the drop does not warn"
        );
        assert_eq!(
            sigusr1_and_wait(reuser),
            Some(libc::SIGUSR1),
            "the reuser must have been signalled by the test alone"
        );
    });
}
fn kill_tree_after_own_wait_and_reuse_body() {
    kill_tree_after_own_wait_and_reuse(false);
}
fn kill_tree_after_own_wait_and_same_tick_reuse_body() {
    kill_tree_after_own_wait_and_reuse(true);
}
in_fresh_pid_ns!(
    namespaces_tokio_kill_tree_after_own_wait_and_reuse_is_ok_and_sends_nothing,
    fixture_tokio_kill_tree_own_wait_driver,
    fixture_tokio_kill_tree_own_wait_init,
    kill_tree_after_own_wait_and_reuse_body
);
in_fresh_pid_ns!(
    namespaces_tokio_kill_tree_after_own_wait_and_same_tick_reuse_is_ok_and_sends_nothing,
    fixture_tokio_kill_tree_own_wait_same_tick_driver,
    fixture_tokio_kill_tree_own_wait_same_tick_init,
    kill_tree_after_own_wait_and_same_tick_reuse_body
);

/// The sync `graceful_shutdown_tree_after_own_wait_and_reuse_body`'s twin. Same mutant.
fn graceful_shutdown_tree_after_own_wait_and_reuse_body() {
    runtime().block_on(async {
        crate::log_capture::install();
        let killed = crate::containment::unix::fault::record_kill_group();
        let termed = crate::containment::unix::fault::record_term_group();
        let (mut child, writer) = spawn_group_blocker();
        let pid = child.id().pid();
        let token = reuser_token(&child, false);
        drop(writer);
        let status = child.wait().await.expect("this handle reaps the root");
        let reuser = crate::test_child::pid_reuse::reuse(pid);
        let _alias = alias_token(reuser.id(), token);

        let mark = crate::log_capture::mark();
        let shut_down = child
            .graceful_shutdown_tree(std::time::Duration::ZERO)
            .await
            .expect("a tree whose root this handle reaped answers its status");

        assert_eq!(shut_down, status, "the root's own status");
        assert_eq!(
            termed.termed(),
            Vec::<i32>::new(),
            "no SIGTERM by a reaped root's number"
        );
        assert_eq!(
            killed.killed(),
            Vec::<i32>::new(),
            "no killpg by a reaped root's number"
        );
        assert_eq!(
            crate::test_child::reaped_elsewhere::warns_since(mark),
            Vec::<String>::new(),
            "the group is empty: nothing to warn about"
        );
        assert_eq!(
            sigusr1_and_wait(reuser),
            Some(libc::SIGUSR1),
            "the reuser must have been signalled by the test alone"
        );
    });
}
in_fresh_pid_ns!(
    namespaces_tokio_graceful_shutdown_tree_after_own_wait_and_reuse_sends_nothing,
    fixture_tokio_graceful_own_wait_driver,
    fixture_tokio_graceful_own_wait_init,
    graceful_shutdown_tree_after_own_wait_and_reuse_body
);

/// The sync `terminate_tree_after_own_wait_and_reuse_body`'s twin. Same mutant.
fn terminate_tree_after_own_wait_and_reuse_body() {
    runtime().block_on(async {
        crate::log_capture::install();
        let termed = crate::containment::unix::fault::record_term_group();
        let (mut child, writer) = spawn_group_blocker();
        let pid = child.id().pid();
        let token = reuser_token(&child, false);
        drop(writer);
        child.wait().await.expect("this handle reaps the root");
        let reuser = crate::test_child::pid_reuse::reuse(pid);
        let _alias = alias_token(reuser.id(), token);

        let mark = crate::log_capture::mark();
        child
            .terminate_tree()
            .expect("a tree whose root this handle reaped answers Ok");

        assert_eq!(
            termed.termed(),
            Vec::<i32>::new(),
            "no SIGTERM by a reaped root's number"
        );
        assert_eq!(
            crate::test_child::reaped_elsewhere::warns_since(mark),
            Vec::<String>::new(),
            "the group is empty: nothing to warn about"
        );
        assert_eq!(
            sigusr1_and_wait(reuser),
            Some(libc::SIGUSR1),
            "the reuser must have been signalled by the test alone"
        );
    });
}
in_fresh_pid_ns!(
    namespaces_tokio_terminate_tree_after_own_wait_and_reuse_sends_nothing,
    fixture_tokio_terminate_own_wait_driver,
    fixture_tokio_terminate_own_wait_init,
    terminate_tree_after_own_wait_and_reuse_body
);

/// The sync `graceful_shutdown_tree_after_a_foreign_reap_and_reuse_body`'s twin. Same mutant.
fn graceful_shutdown_tree_after_a_foreign_reap_and_reuse_body() {
    let _old_kernel = crate::containment::unix::fault::refuse_pidfd_group_flag();
    runtime().block_on(async {
        crate::log_capture::install();
        let killed = crate::containment::unix::fault::record_kill_group();
        let termed = crate::containment::unix::fault::record_term_group();
        let (mut child, writer) = spawn_group_blocker();
        let pid = child.id().pid();
        let token = reuser_token(&child, false);
        drop(writer);
        let reuser = reap_behind_and_reuse(pid);
        let _alias = alias_token(reuser.id(), token);

        let mark = crate::log_capture::mark();
        let err = child
            .graceful_shutdown_tree(std::time::Duration::ZERO)
            .await
            .expect_err("a group whose root was reaped elsewhere is not assessable");

        assert!(matches!(err, crate::error::Error::Unassessable { .. }), "{err:?}");
        assert_eq!(
            termed.termed(),
            Vec::<i32>::new(),
            "no SIGTERM by a reaped root's number"
        );
        assert_eq!(
            killed.killed(),
            Vec::<i32>::new(),
            "no killpg by a reaped root's number"
        );
        assert_one_reaped_elsewhere_warn(mark, pid);
        assert_eq!(
            sigusr1_and_wait(reuser),
            Some(libc::SIGUSR1),
            "the reuser must have been signalled by the test alone"
        );
    });
}
in_fresh_pid_ns!(
    namespaces_tokio_graceful_shutdown_tree_after_a_foreign_reap_and_reuse_sends_nothing,
    fixture_tokio_graceful_foreign_reuse_driver,
    fixture_tokio_graceful_foreign_reuse_init,
    graceful_shutdown_tree_after_a_foreign_reap_and_reuse_body
);
