//! `Drop`'s two branches that release the backend in place, without the reaper pool: a detached
//! handle, and an armed one whose kill was refused. Evidence of a foreign reap must stop tokio's
//! field-drop from reaping the child by pid, or it would reap whichever process took the pid.
//!
//! The evidence is forced: on Linux the pidfd peek answers `Foreign`; on macOS the latch is set by
//! a `kill` whose peek answers `Foreign`. The child really is an unreaped zombie, so a reap by pid
//! that should not have run consumes the record the test then finds gone.

use crate::tokio::Command;
use crate::wait::exit_only::seams::force_peek_once;
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

/// Makes the next `Drop` see evidence of a foreign reap.
fn force_evidence(child: &mut crate::tokio::Child) -> impl Sized {
    #[cfg(target_os = "linux")]
    {
        let _ = child;
        force_peek_once(Ok(Peek::Foreign(Foreign::Gone)))
    }
    #[cfg(target_os = "macos")]
    {
        // The `kill`'s peek sees the "foreign reap" and sets the latch; nothing is sent.
        let forced = force_peek_once(Ok(Peek::Foreign(Foreign::Gone)));
        child.kill().expect("a kill of a foreign-reaped child answers Ok");
        forced
    }
}

/// Mutant: no forget in the bypass branches. tokio's in-drop `try_wait` then reaps the zombie, and
/// the test's own reap gets `ECHILD`.
#[tokio::test(flavor = "current_thread")]
async fn tokio_bypass_drop_of_a_detached_child_after_a_foreign_reap_reaps_nothing() {
    let (mut child, witness) = exited_unreaped(true);
    child.detach();
    let _evidence = force_evidence(&mut child);
    drop(child);
    witness.reap().expect("the drop must not have reaped the child by pid");
}

/// The failed-kill early return: the kill is refused, so the drop falls back to a `try_wait`,
/// which reaps by pid.
#[tokio::test(flavor = "current_thread")]
async fn tokio_bypass_drop_after_a_refused_kill_and_a_foreign_reap_reaps_nothing() {
    let (mut child, witness) = exited_unreaped(true);
    let _evidence = force_evidence(&mut child);
    super::reaper::fault::set_force_kill_failure(true);
    drop(child);
    assert!(
        !super::reaper::fault::take_force_kill_failure(),
        "the drop must have consumed the forced kill failure"
    );
    witness.reap().expect("the drop must not have reaped the child by pid");
}
