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
use crate::test_groups::namespaces;
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
        let err = crate::tokio::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");

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
        let err = crate::tokio::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");

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
            child.carries_recyclable_pgid(),
            "the test needs a number-named group kill"
        );
        let (_reuser, _alias) = foreign_reaped_and_reused(&child, writer);

        let err = crate::tokio::spawn::finish_elevated(child, failed_write()).expect_err("the spawn fails");

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

/// A peek that fails on the child's own pidfd cannot show the child is ours, so it counts as reaped
/// elsewhere: the child is forgotten, never released to tokio's by-pid reap.
///
/// Mutant: a failed peek counts as ours.
#[skuld::test]
fn a_failed_pidfd_peek_is_unknown_so_the_child_is_forgotten() {
    use crate::wait::exit_only::seams::force_peek_once;
    runtime().block_on(async {
        let (mut child, _writer) = spawn_blocker();
        let _failed = force_peek_once(Err(std::io::Error::other("forced peek failure")));
        let reaped = child.proc_mut().reaped_elsewhere();
        assert!(reaped, "a child nothing can answer for is not tokio's to reap by pid");
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

/// A spawn whose child is reaped behind its back, and its pid reused, between the fork and the
/// identity read, then fails (the identity read answers `Gone`, or the attach is forced to fail).
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
        let _spawn_hook = fault::set_at(fault::SpawnPoint::BeforeIdentity, {
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
        err.expect("the forced failure must fail the spawn");

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
        let err = match cmd.spawn() {
            Ok(child) => panic!("the spawn took the stranger for its child: {:?}", child.id()),
            Err(e) => e,
        };
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

/// The reap lands right before the attach. The attach reads the tree-walk root by pid, so it must
/// come before the checked identity read: attached after, the stranger would be the attachment's
/// root under an identity that passed, and the spawn would be `Ok`.
///
/// Mutant: the async spawn attaches after the identity check.
fn spawn_reap_before_the_attach_is_gone_body() {
    spawn_identity_gone_after_a_reap_at(crate::child::spawn::fault::SpawnPoint::BeforeAttach);
}
in_fresh_pid_ns!(
    namespaces_tokio_spawn_reap_before_the_attach_is_gone,
    fixture_tokio_spawn_attach_gone_driver,
    fixture_tokio_spawn_attach_gone_init,
    spawn_reap_before_the_attach_is_gone_body
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
