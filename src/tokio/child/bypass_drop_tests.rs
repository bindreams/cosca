//! `Drop`'s two branches that release the backend in place, without the reaper pool: a detached
//! handle, and an armed one whose kill was refused. Evidence of a foreign reap must stop tokio's
//! field-drop from reaping the child by pid, or it would reap whichever process took the pid.
//!
//! The evidence is forced: the peek through the child's handle answers `Foreign`. The child really
//! is an unreaped zombie, so a reap by pid that should not have run consumes the record the test
//! then finds gone.

use crate::tokio::Command;
use crate::wait::exit_only::seams::{force_peek_once, force_peeks};
use crate::wait::exit_only::{Foreign, Peek};

/// Watches one child from outside cosca and reaps it on the test's behalf.
struct Witness {
    #[cfg(target_os = "macos")]
    pid: u32,
    #[cfg(target_os = "linux")]
    pidfd: std::os::fd::OwnedFd,
}

impl Witness {
    /// `SIGKILL` through the pidfd (Linux), or by the pid of a child nothing else reaps (macOS).
    fn kill(&self) {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsFd;
            rustix::process::pidfd_send_signal(self.pidfd.as_fd(), rustix::process::Signal::KILL).expect("kill");
        }
        #[cfg(target_os = "macos")]
        // SAFETY: `pid` is this test's own child, which nothing reaps while the test runs.
        assert_eq!(unsafe { libc::kill(self.pid as libc::pid_t, libc::SIGKILL) }, 0);
    }

    fn new(pid: u32) -> Witness {
        Witness {
            #[cfg(target_os = "macos")]
            pid,
            #[cfg(target_os = "linux")]
            pidfd: rustix::process::pidfd_open(
                rustix::process::Pid::from_raw(pid as i32).expect("pid"),
                rustix::process::PidfdFlags::empty(),
            )
            .expect("pidfd_open"),
        }
    }

    /// Blocks until the child has exited, without consuming it.
    fn wait_exited(&self) {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsFd;
            let fd = self.pidfd.as_fd();
            let mut fds = [rustix::event::PollFd::new(&fd, rustix::event::PollFlags::IN)];
            loop {
                match rustix::event::poll(&mut fds, None) {
                    Ok(n) if n > 0 => return,
                    Ok(_) | Err(rustix::io::Errno::INTR) => {}
                    Err(e) => panic!("poll(pidfd): {e}"),
                }
            }
        }
        #[cfg(target_os = "macos")]
        {
            // SAFETY: an all-zero `siginfo_t` is valid, and `waitid` writes only into it.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: waits for our own child's exit without consuming it.
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT,
                )
            };
            assert_eq!(rc, 0, "waitid: {}", std::io::Error::last_os_error());
        }
    }

    /// Consumes the child's exit record. `Err` if something else already did.
    fn reap(&self) -> Result<(), std::io::Error> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsFd;
            let record = rustix::process::waitid(
                rustix::process::WaitId::PidFd(self.pidfd.as_fd()),
                rustix::process::WaitIdOptions::EXITED,
            )?;
            assert!(record.is_some(), "an exited child has a record");
            Ok(())
        }
        #[cfg(target_os = "macos")]
        {
            let mut status = 0;
            // SAFETY: reaps this process's own exited child.
            let reaped = unsafe { libc::waitpid(self.pid as libc::pid_t, &mut status, 0) };
            if reaped == self.pid as libc::pid_t {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        }
    }
}

/// A child that has exited and is not reaped, and the witness of it.
fn exited_unreaped(kill_on_drop: bool) -> (crate::tokio::Child, Witness) {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.kill_on_drop(kill_on_drop);
    let child = cmd.spawn().expect("spawn");
    let witness = Witness::new(child.id().pid());
    drop(writer);
    witness.wait_exited();
    (child, witness)
}

/// Makes the next peek through the child's handle see a foreign reap.
fn force_evidence() -> impl Sized {
    force_peek_once(Ok(Peek::Foreign(Foreign::Gone)))
}

/// Mutant: no forget in the bypass branches. tokio's in-drop `try_wait` then reaps the zombie, and
/// the test's own reap gets `ECHILD`.
#[skuld::test]
async fn tokio_bypass_drop_of_a_detached_child_after_a_foreign_reap_reaps_nothing() {
    let (mut child, witness) = exited_unreaped(true);
    child.detach();
    let _evidence = force_evidence();
    drop(child);
    witness.reap().expect("the drop must not have reaped the child by pid");
}

/// The failed-kill early return: the drop's first look misses the reap, its kill is refused, and
/// the look inside that branch sees it, so the drop forgets tokio's `Child` instead of `try_wait`ing
/// it by pid. The looks are forced in sequence: `Running`, then `Foreign`.
///
/// Mutants: no forget in the refused-kill branch (the zombie is reaped by pid: `ECHILD`); the
/// `is_reaped` check dropped there (a false "left running" warning).
#[skuld::test]
async fn tokio_bypass_drop_after_a_refused_kill_and_a_foreign_reap_reaps_nothing() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (child, witness) = exited_unreaped(true);
    let _looks = force_peeks([Ok(Peek::Running), Ok(Peek::Foreign(Foreign::Gone))]);
    let _refused = super::fault::force_kill_failure();
    let kills = super::drop_fault::record();

    drop(child);

    assert_eq!(kills.kills(), 1, "the drop reached its refused root kill");
    assert!(
        !crate::log_capture::contains_since(mark, "could not be terminated on drop"),
        "a forgotten child must not be reported as left running"
    );
    witness.reap().expect("the drop must not have reaped the child by pid");
}

/// `reap_now`'s refused-kill arm must not hand tokio's drop a child that is not shown ours: it
/// forgets it instead. A forced attach failure, a refused kill and forced evidence, for a child
/// that exited before the identity read. `evidence` arms the evidence inside the hook, where the
/// handshake's own peeks are done.
fn reap_now_after_a_refused_kill(evidence: fn() -> Box<dyn std::any::Any>) {
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::child::spawn::fault;

    let slot: Rc<RefCell<Option<Witness>>> = Rc::default();
    let armed: Rc<RefCell<Option<Box<dyn std::any::Any>>>> = Rc::default();
    let _hook = fault::set_at(fault::SpawnPoint::BeforeIdentity, {
        let slot = Rc::clone(&slot);
        let armed = Rc::clone(&armed);
        move || {
            let witness = Witness::new(fault::spawn_pid());
            witness.wait_exited();
            // Armed here, not before `spawn()`: the handshake's own watch peek runs first and
            // would consume it. The evidence follows the identity check's own peek, which the
            // test answers `Running`: the child is ours until the forced attach failure.
            *armed.borrow_mut() = Some(evidence());
            *slot.borrow_mut() = Some(witness);
        }
    });
    fault::set_force_attach_failure(true);
    fault::set_force_kill_failure_leaving_child_alive_as("reap_now refused", std::io::ErrorKind::PermissionDenied);
    let backend_drops = super::fault::count_backend_drops();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::stdio::Stdio::null()).expect("stdin");

    let err = cmd.spawn().err();

    fault::set_force_attach_failure(false);
    drop(armed);
    assert!(err.is_some(), "the forced attach failure fails the spawn");
    assert_eq!(backend_drops.get(), 0, "tokio's Child must have been forgotten");
    let witness = slot.borrow_mut().take().expect("the hook ran");
    witness
        .reap()
        .expect("reap_now's refused-kill arm must not reap the child by pid");
}

/// Evidence that the child was reaped elsewhere.
///
/// Mutant: no forget in `reap_now`'s refused-kill arm (tokio's drop reaps the zombie by pid).
#[skuld::test]
async fn reap_now_after_a_refused_kill_and_a_foreign_reap_reaps_nothing() {
    reap_now_after_a_refused_kill(|| Box::new(force_peeks([Ok(Peek::Running), Ok(Peek::Foreign(Foreign::Gone))])));
}

/// A failed look cannot show the child is ours, so the arm forgets it too.
///
/// Mutant: a failed look counts as ours.
#[skuld::test]
async fn reap_now_after_a_refused_kill_and_a_failed_look_reaps_nothing() {
    reap_now_after_a_refused_kill(|| {
        Box::new(force_peeks([
            Ok(Peek::Running),
            Err(std::io::Error::other("forced peek failure 6e2a")),
        ]))
    });
}

/// `try_wait` and `wait` on a child shown reaped elsewhere answer `ECHILD` and take nothing: tokio's
/// own are `waitpid`s by pid.
///
/// Mutants: `ProcSource::try_wait` or `wait` go to tokio without looking at the handle.
#[skuld::test]
async fn try_wait_after_a_foreign_reap_takes_nothing() {
    let (mut child, witness) = exited_unreaped(false);
    let _evidence = force_evidence();
    let err = child.try_wait().expect_err("a foreign-reaped child has no status");
    assert!(
        matches!(&err, crate::error::Error::Io(e) if e.raw_os_error() == Some(libc::ECHILD)),
        "{err:?}"
    );
    witness.reap().expect("try_wait must not have reaped the child by pid");
}

#[skuld::test]
async fn wait_after_a_foreign_reap_takes_nothing() {
    let (mut child, witness) = exited_unreaped(false);
    let _evidence = force_evidence();
    let err = child.wait().await.expect_err("a foreign-reaped child has no status");
    assert!(
        matches!(&err, crate::error::Error::Io(e) if e.raw_os_error() == Some(libc::ECHILD)),
        "{err:?}"
    );
    witness.reap().expect("wait must not have reaped the child by pid");
}

/// `try_wait` and `wait` on a child the handle cannot answer for (a failed look) say so with
/// `Unassessable`, not `ECHILD`: the child may be running. Nothing is reaped, and the child is not
/// forgotten, so a later call can still answer.
///
/// Mutants: the answer is `ECHILD`; the child is forgotten.
#[skuld::test]
async fn try_wait_and_wait_on_a_child_that_cannot_be_verified_say_so() {
    let (mut child, witness) = exited_unreaped(false);
    let backend_drops = super::fault::count_backend_drops();
    for use_wait in [false, true] {
        let _failed = force_peek_once(Err(std::io::Error::other("forced peek failure 8c4f")));
        let err = if use_wait {
            child.wait().await.map(Some)
        } else {
            child.try_wait()
        }
        .expect_err("an unverifiable child has no status to give");
        assert!(
            matches!(&err, crate::error::Error::Unassessable { detail, .. } if detail.contains("cannot be shown to be ours")),
            "{use_wait}: {err:?}"
        );
        assert!(
            !child.os.proc.as_ref().expect("backend").is_reaped(),
            "{use_wait}: not forgotten"
        );
    }
    witness.reap().expect("neither call may reap the child by pid");
    drop(backend_drops);
}

/// `finish_elevated`'s refused-kill arm forgets a child shown reaped elsewhere (`forget_if_foreign`,
/// as `Drop`'s and `reap_now`'s refused-kill arms do) before its `try_wait`, a `waitpid` by pid.
#[skuld::test]
async fn finish_elevated_after_a_refused_kill_and_a_foreign_reap_reaps_nothing() {
    let (child, witness) = exited_unreaped(true);
    let _evidence = force_evidence();
    let _refused = super::fault::force_kill_failure();
    let err = crate::tokio::spawn::finish_elevated(
        child,
        Err(crate::error::Error::Io(std::io::Error::other("no password"))),
    )
    .expect_err("the password write failed");
    assert!(matches!(err, crate::error::Error::Elevation { .. }), "{err:?}");
    witness
        .reap()
        .expect("finish_elevated's refused-kill arm must not reap the child by pid");
}

/// A contained root reaped elsewhere: `Drop`'s tree teardown warns that it skips the group kill. A
/// logger that panics there unwinds out of the drop with tokio's `Child` held; the backend's own
/// drop must forget it, since its handle shows the root reaped, rather than hand it to tokio's
/// by-pid reap.
#[skuld::test]
async fn a_panicking_logger_in_the_tree_teardown_warn_does_not_reap_the_child_by_pid() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.contain_with(crate::ContainMode::Session);
    let child = cmd.spawn().expect("spawn");
    let witness = Witness::new(child.id().pid());
    drop(writer);
    witness.wait_exited();
    witness
        .reap()
        .expect("the child is ours to reap: this is the foreign reap");
    let backend_drops = super::fault::count_backend_drops();
    let unwound = {
        let _panics = crate::log_capture::panic_on("the root is already reaped, so this drop does not");
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(child)))
    };
    assert!(unwound.is_err(), "the logger must have panicked out of the drop");
    assert_eq!(
        backend_drops.get(),
        0,
        "tokio's Child must have been forgotten, not dropped into a by-pid reap"
    );
}

/// A live child of ours, armed drop, kill refused (EPERM-like). `signal_on_drop` peeks (`Running`:
/// ours), `try_wait`s, then warns "could not be terminated on drop". A logger that panics there
/// unwinds out of `Drop` before it releases the backend, and the backend's own drop must still hand
/// a child its handle shows ours to tokio's drop and its orphan queue.
#[skuld::test]
async fn a_panicking_refused_kill_warn_in_drop_does_not_strand_or_reap_by_pid() {
    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    cmd.kill_on_drop(true);
    let child = cmd.spawn().expect("spawn");
    let witness = Witness::new(child.id().pid());
    let _refused = super::fault::force_kill_failure();
    let drops = super::fault::count_backend_drops();
    let unwound = {
        let _panics = crate::log_capture::panic_on("could not be terminated on drop");
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(child)))
    };
    assert!(unwound.is_err(), "the logger must have panicked out of the drop");
    let released = drops.get();
    // Clean up regardless: end the child and reap it ourselves.
    drop(writer);
    witness.wait_exited();
    let reaped_by_us = witness.reap().is_ok();
    assert_eq!(
        released, 1,
        "a child shown ours must reach tokio's drop (reaped_by_us={reaped_by_us})"
    );
}

/// As above, but stdin is tokio's own pipe and was never taken. The unwind must close this
/// process's end of it, or a child reading stdin to EOF never exits. The end is recorded by its
/// descriptor, which stays closed in this single-threaded test.
#[skuld::test]
async fn an_unwind_out_of_drop_closes_the_untaken_stdin_pipe() {
    crate::tokio::test_runtime::assert_current_thread();
    use std::os::fd::AsRawFd;
    crate::log_capture::install();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::stdio::Stdio::pipe_in()).expect("set stdin");
    cmd.kill_on_drop(true);
    let child = cmd.spawn().expect("spawn");
    let witness = Witness::new(child.id().pid());
    let crate::tokio::child::ProcSource::Tokio { stdin, .. } = child.os.proc.as_ref().expect("backend") else {
        panic!("a fresh child is a tokio backend");
    };
    let fd = stdin.as_ref().expect("tokio's piped stdin").as_raw_fd();
    let is_open = || {
        // SAFETY: `fcntl(F_GETFD)` reads a flag and changes nothing.
        unsafe { libc::fcntl(fd, libc::F_GETFD) != -1 }
    };
    assert!(is_open(), "before: this process holds the write end");
    let _refused = super::fault::force_kill_failure();
    let unwound = {
        let _panics = crate::log_capture::panic_on("could not be terminated on drop");
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(child)))
    };
    assert!(unwound.is_err(), "the logger must have panicked out of the drop");
    let still_open = is_open();
    // The child is ours and, on macOS, was forgotten: end it and reap it.
    witness.kill();
    witness.wait_exited();
    drop(witness.reap()); // tokio's orphan queue may have reaped it first
    assert!(
        !still_open,
        "after the unwind this process still holds the stdin write end"
    );
}

/// The spawn's identity check peeks through the child's pidfd. A peek that fails cannot show the
/// child ours, so the spawn fails `Unassessable`, warns at the call, and forgets tokio's `Child`:
/// its drop would reap by pid. The second failed peek is the forget decision's own look.
///
/// Mutants: the identity read moves before `ProcSource::new` (tokio's `Child` is then dropped by
/// value on the error path, so `forgets()` is 0); the failed check goes to `reap_now` without the
/// forget decision (`backend_drops` is 1).
#[cfg(target_os = "linux")]
#[skuld::test]
async fn a_failed_identity_peek_is_unknown_and_forgets_the_tokio_child() {
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::child::spawn::fault;
    use crate::error::Error;

    crate::tokio::test_runtime::assert_current_thread();
    crate::log_capture::install();
    let slot: Rc<RefCell<Option<Witness>>> = Rc::default();
    let armed: Rc<RefCell<Option<Box<dyn std::any::Any>>>> = Rc::default();
    let _hook = fault::set_at(fault::SpawnPoint::BeforeIdentity, {
        let (slot, armed) = (Rc::clone(&slot), Rc::clone(&armed));
        move || {
            *slot.borrow_mut() = Some(Witness::new(fault::spawn_pid()));
            // Armed here, not before `spawn()`: the handshake's own peeks run first.
            *armed.borrow_mut() = Some(Box::new(force_peeks([
                Err(std::io::Error::other("forced peek failure 91c4")),
                Err(std::io::Error::other("forced peek failure 91c4")),
            ])));
        }
    });
    let forgets = super::drop_fault::record();
    let backend_drops = super::fault::count_backend_drops();
    let mark = crate::log_capture::mark();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::stdio::Stdio::null()).expect("stdin");

    let err = cmd.spawn().err();

    drop(armed);
    let err = err.expect("a failed identity peek fails the spawn");
    assert!(
        matches!(err, Error::Unassessable { .. }),
        "a failed peek is Unassessable, not a vanish: {err:?}"
    );
    assert!(
        crate::log_capture::contains_since(mark, "forced peek failure 91c4"),
        "the failed peek is warned at the call"
    );
    assert_eq!(forgets.forgets(), 1, "tokio's Child must have been forgotten");
    assert_eq!(backend_drops.get(), 0, "tokio's Child must not have been dropped");
    let witness = slot.borrow_mut().take().expect("the hook ran");
    witness.kill();
    witness.wait_exited();
    witness
        .reap()
        .expect("the failed spawn must not have reaped the child by pid");
}
