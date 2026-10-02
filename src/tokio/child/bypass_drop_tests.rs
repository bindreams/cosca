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
#[tokio::test(flavor = "current_thread")]
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
#[tokio::test(flavor = "current_thread")]
async fn tokio_bypass_drop_after_a_refused_kill_and_a_foreign_reap_reaps_nothing() {
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

/// `reap_now`'s refused-kill arm must not hand tokio's drop a child shown reaped elsewhere: it
/// forgets it instead. A forced attach failure, a refused kill
/// and forced `Foreign` evidence, for a child that exited before the identity read.
///
/// Mutant: no forget in `reap_now`'s refused-kill arm (tokio's drop reaps the zombie by pid).
#[tokio::test(flavor = "current_thread")]
async fn reap_now_after_a_refused_kill_and_a_foreign_reap_reaps_nothing() {
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::child::spawn::fault;

    let slot: Rc<RefCell<Option<Witness>>> = Rc::default();
    let evidence: Rc<RefCell<Option<Box<dyn std::any::Any>>>> = Rc::default();
    let _hook = fault::set_at(fault::SpawnPoint::BeforeIdentity, {
        let slot = Rc::clone(&slot);
        let evidence = Rc::clone(&evidence);
        move || {
            let witness = Witness::new(fault::spawn_pid());
            witness.wait_exited();
            // Armed here, not before `spawn()`: the handshake's own watch peek runs first and
            // would consume it.
            *evidence.borrow_mut() = Some(Box::new(force_evidence()));
            *slot.borrow_mut() = Some(witness);
        }
    });
    fault::set_force_attach_failure(true);
    fault::set_force_kill_failure_leaving_child_alive_as("reap_now refused", std::io::ErrorKind::PermissionDenied);
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::stdio::Stdio::null()).expect("stdin");

    let err = cmd.spawn().err();

    fault::set_force_attach_failure(false);
    drop(evidence);
    assert!(err.is_some(), "the forced attach failure fails the spawn");
    let witness = slot.borrow_mut().take().expect("the hook ran");
    witness
        .reap()
        .expect("reap_now's refused-kill arm must not reap the child by pid");
}

/// `finish_elevated`'s refused-kill arm forgets a child shown reaped elsewhere (`forget_if_foreign`,
/// as `Drop`'s and `reap_now`'s refused-kill arms do) before its `try_wait`, a `waitpid` by pid.
#[tokio::test(flavor = "current_thread")]
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
/// logger that panics there unwinds out of the drop with tokio's `Child` held; the unwind must
/// leak it, not reap the child by pid. Holds wherever the log sits, because tokio's `Child` is
/// never dropped implicitly.
#[tokio::test(flavor = "current_thread")]
async fn a_panicking_logger_in_the_tree_teardown_warn_does_not_reap_the_child_by_pid() {
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
    let _evidence = force_evidence();
    let unwound = {
        let _panics = crate::log_capture::panic_on("the root is already reaped, so this drop does not");
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(child)))
    };
    assert!(unwound.is_err(), "the logger must have panicked out of the drop");
    witness.reap().expect("the drop must not have reaped the child by pid");
}

/// A live child of ours, armed drop, kill refused (EPERM-like). `signal_on_drop` peeks
/// (Running: ours), `try_wait`s, then warns "could not be terminated on drop" BEFORE `Drop`
/// reaches `release`. A logger that panics there unwinds with tokio's `Child` in `ManuallyDrop`,
/// so a verified-ours child never reaches tokio's drop or orphan queue.
/// The unwind must still hand a child verified ours (peek: `Running`) to tokio, as it did before
/// tokio's `Child` was held out of the implicit drop.
#[tokio::test(flavor = "current_thread")]
async fn a_panicking_refused_kill_warn_in_drop_still_releases_a_child_of_ours() {
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
        "a child verified ours (peek: Running) was leaked instead of released to tokio (reaped_by_us={reaped_by_us})"
    );
}

/// As above, but stdin is tokio's own pipe and was never taken. `forget` closes the untaken
/// streams; an implicit drop of the backend (an unwind) does not, since they sit inside the
/// `ManuallyDrop`'d tokio `Child`. After the unwind this process still holds the write end of the
/// child's stdin, so `cat` never sees EOF. `forget`'s doc says "This is also what dropping a
/// backend does".
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn an_unwind_out_of_drop_closes_the_untaken_stdin_pipe() {
    crate::log_capture::install();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(crate::stdio::Stdio::pipe_in()).expect("set stdin");
    cmd.kill_on_drop(true);
    let child = cmd.spawn().expect("spawn");
    let pid = child.id().pid();
    let witness = Witness::new(pid);
    let child_stdin = std::fs::read_link(format!("/proc/{pid}/fd/0")).expect("child's fd 0");
    let held = || {
        std::fs::read_dir("/proc/self/fd")
            .expect("own fds")
            .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
            .any(|l| l == child_stdin)
    };
    assert!(held(), "before: tokio holds the write end of {child_stdin:?}");
    let _refused = super::fault::force_kill_failure();
    let unwound = {
        let _panics = crate::log_capture::panic_on("could not be terminated on drop");
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(child)))
    };
    assert!(unwound.is_err(), "the logger must have panicked out of the drop");
    let still_held = held();
    // Clean up: kill through the pidfd and reap.
    {
        use std::os::fd::AsFd;
        rustix::process::pidfd_send_signal(witness.pidfd.as_fd(), rustix::process::Signal::KILL).expect("kill");
    }
    witness.wait_exited();
    let _ = witness.reap();
    assert!(!still_held, "after the unwind this process still holds {child_stdin:?}'s write end: cat never sees EOF");
}
