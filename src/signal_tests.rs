//! The signal helpers: what each answers for a live, gone and unverifiable child, and that a
//! send is recorded only when the OS was asked.

use std::process::{Child, ChildStdin};

use crate::send_log::{Capture, Via};
use crate::signal::{Sent, Sig};

fn spawn() -> (Child, ChildStdin) {
    let mut child = crate::test_spawn::spawn(&mut crate::test_child::held_std_blocker(std::process::Stdio::null()))
        .expect("spawn the blocker");
    let stdin = child.stdin.take().expect("piped stdin");
    (child, stdin)
}

// Linux =====

#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::{AsFd, OwnedFd};

    use super::*;
    use crate::signal::via_pidfd;

    fn pidfd_of(child: &Child) -> OwnedFd {
        let pid = rustix::process::Pid::from_raw(child.id() as i32).expect("a child's pid");
        rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).expect("pidfd_open")
    }

    /// Mutant: a missing pidfd is an error, or a signal sent by pid.
    #[test]
    fn no_pidfd_is_gone_and_sends_nothing() {
        let log = Capture::start();
        assert_eq!(via_pidfd(None, 4242, Sig::Kill).expect("gone is Ok"), Sent::Gone);
        assert_eq!(log.entries(), []);
    }

    /// Mutant: the send is not recorded, or recorded under another address.
    #[test]
    fn a_live_child_is_signalled_through_its_pidfd_and_recorded() {
        let (mut child, _stdin) = spawn();
        let pidfd = pidfd_of(&child);
        let log = Capture::start();
        assert_eq!(
            via_pidfd(Some(pidfd.as_fd()), child.id(), Sig::Kill).expect("send"),
            Sent::Delivered
        );
        assert_eq!(log.entries(), [(child.id(), Sig::Kill, Via::Pidfd)]);
        let status = child.wait().expect("reap");
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGKILL)
        );
    }

    /// Mutant: `ESRCH` returned as an error.
    #[test]
    fn a_reaped_child_is_gone_but_the_attempt_is_recorded() {
        let (mut child, stdin) = spawn();
        let pidfd = pidfd_of(&child);
        drop(stdin);
        child.wait().expect("reap");
        let log = Capture::start();
        assert_eq!(
            via_pidfd(Some(pidfd.as_fd()), child.id(), Sig::Kill).expect("gone is Ok"),
            Sent::Gone
        );
        assert_eq!(log.entries(), [(child.id(), Sig::Kill, Via::Pidfd)]);
    }
}

// macOS =====

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use crate::identity::{quiet_fault, ReadPurpose, Resolved, StartToken};
    use crate::signal::via_verified_pid;

    fn start_of(child: &Child) -> StartToken {
        match crate::identity::pbi_start_quiet(child.id(), ReadPurpose::Kill) {
            Resolved::Found(start) => start,
            other => panic!("the live child's start: {other:?}"),
        }
    }

    /// Mutant: the start is not compared, so a reused pid is signalled.
    #[test]
    fn a_pid_that_names_another_start_is_gone_and_sends_nothing() {
        let (mut child, stdin) = spawn();
        let other = StartToken::from_raw(1);
        let log = Capture::start();
        assert_eq!(
            via_verified_pid(child.id(), other, Sig::Kill).expect("gone is Ok"),
            Sent::Gone
        );
        assert_eq!(log.entries(), []);
        assert!(child.try_wait().expect("try_wait").is_none(), "the child was signalled");
        drop(stdin);
        child.wait().expect("reap");
    }

    /// Mutant: an unreadable identity is taken for a match.
    #[test]
    fn an_unreadable_identity_is_an_error_and_sends_nothing() {
        let (mut child, stdin) = spawn();
        let start = start_of(&child);
        let log = Capture::start();
        let _forced = quiet_fault::force_quiet_read_error_once(ReadPurpose::Kill, Resolved::Unknown);
        let err = via_verified_pid(child.id(), start, Sig::Kill).expect_err("unverifiable");
        assert!(err.to_string().contains("identity could not be confirmed"), "{err}");
        assert_eq!(log.entries(), []);
        drop(stdin);
        child.wait().expect("reap");
    }

    /// Mutant: `ESRCH` returned as an error. `PID_MAX` is 99999, so this pid names nothing, ever.
    #[test]
    fn a_pid_that_vanishes_after_the_check_is_gone_and_the_attempt_is_recorded() {
        const NEVER_A_PID: u32 = 4_000_000;
        let start = StartToken::from_raw(7);
        let log = Capture::start();
        let _forced = quiet_fault::force_quiet_read_error_once(ReadPurpose::Kill, Resolved::Found(start));
        assert_eq!(
            via_verified_pid(NEVER_A_PID, start, Sig::Kill).expect("gone is Ok"),
            Sent::Gone
        );
        assert_eq!(log.entries(), [(NEVER_A_PID, Sig::Kill, Via::Pid)]);
    }

    /// Mutant: the send is not recorded, or nothing is sent.
    #[test]
    fn a_verified_live_child_is_signalled_and_recorded() {
        let (mut child, _stdin) = spawn();
        let start = start_of(&child);
        let log = Capture::start();
        assert_eq!(
            via_verified_pid(child.id(), start, Sig::Kill).expect("send"),
            Sent::Delivered
        );
        assert_eq!(log.entries(), [(child.id(), Sig::Kill, Via::Pid)]);
        let status = child.wait().expect("reap");
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGKILL)
        );
    }
}
