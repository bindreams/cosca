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
    use std::io;

    use super::*;
    use crate::identity::{uniq_fault, uniq_info, ReadPurpose, UniqInfo, UniqRead};
    use crate::signal::{read_identity, via_verified_pid};

    /// `PID_MAX` is 99999, so this pid names nothing, ever.
    const NEVER_A_PID: u32 = 4_000_000;

    fn unique_id_of(pid: u32) -> u64 {
        match uniq_info(pid, ReadPurpose::Adopt) {
            UniqRead::Found(info) => info.unique_id,
            other => panic!("the unique id of {pid}: {other:?}"),
        }
    }

    // `uniq_info` -----

    /// Mutant: `PROC_PIDTBSDINFO`, whose start read is refused for another user's process.
    #[test]
    fn uniq_info_reads_another_users_process() {
        // launchd runs as root. On a runner that is not root this is another user's process.
        let a = unique_id_of(1);
        assert_eq!(a, unique_id_of(1), "the id is stable");
    }

    /// Mutant: `arg = 0`, which does not look for zombies.
    #[test]
    fn uniq_info_reads_a_zombie() {
        let (mut child, stdin) = spawn();
        let live = unique_id_of(child.id());
        drop(stdin);
        // The exit, seen without consuming it: the child is a zombie.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::waitid(
                libc::P_PID,
                child.id() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        assert_eq!(r, 0, "waitid(WNOWAIT): {}", io::Error::last_os_error());
        assert_eq!(unique_id_of(child.id()), live);
        child.wait().expect("reap");
    }

    /// Mutant: `ESRCH` classified as refused.
    #[test]
    fn uniq_info_says_gone_for_a_pid_that_names_nothing() {
        assert_eq!(uniq_info(NEVER_A_PID, ReadPurpose::Adopt), UniqRead::Gone);
    }

    // `identity_unreadable` -----

    /// The adoption error names the pid and keeps the errno's kind.
    ///
    /// Mutant: the errno is dropped from the source, or the error is not `Unassessable`.
    #[test]
    fn identity_unreadable_names_the_pid_and_keeps_the_errno() {
        let err = crate::signal::identity_unreadable(77, libc::EPERM);
        match err {
            crate::error::Error::Unassessable { detail, source } => {
                assert!(
                    detail.contains("pid 77") && detail.contains("EPERM") || detail.contains("errno 1"),
                    "{detail}"
                );
                assert_eq!(source.map(|e| e.raw_os_error()), Some(Some(libc::EPERM)));
            }
            other => panic!("expected Unassessable, got {other:?}"),
        }
    }

    // `via_verified_pid` -----

    /// Mutant: the id is not compared, so a reused pid is signalled.
    #[test]
    fn a_pid_with_another_unique_id_is_gone_and_sends_nothing() {
        let (mut child, stdin) = spawn();
        let other = Some(unique_id_of(child.id()) ^ 1);
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

    /// Mutant: a process that was gone at adoption is signalled anyway.
    #[test]
    fn a_child_gone_at_adoption_is_gone_and_sends_nothing() {
        let log = Capture::start();
        assert_eq!(
            via_verified_pid(NEVER_A_PID, None, Sig::Kill).expect("gone is Ok"),
            Sent::Gone
        );
        assert_eq!(log.entries(), []);
    }

    /// A re-read that is refused is an error that keeps its errno's kind, so `EPERM` reaches
    /// `Unkillable`; nothing is sent.
    ///
    /// Mutant: `Refused` taken for a match, or turned into `ErrorKind::Other`.
    #[test]
    fn a_refused_identity_reread_keeps_its_errno_and_sends_nothing() {
        let (mut child, stdin) = spawn();
        let known = Some(unique_id_of(child.id()));
        let log = Capture::start();
        let _forced = uniq_fault::force_uniq_read_once(ReadPurpose::Kill, UniqRead::Refused(libc::EPERM));
        let err = via_verified_pid(child.id(), known, Sig::Kill).expect_err("unverifiable");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
        assert_eq!(err.raw_os_error(), None);
        assert!(err.to_string().contains("identity could not be read"), "{err}");
        assert_eq!(log.entries(), []);
        drop(stdin);
        child.wait().expect("reap");
    }

    /// Mutant: `ESRCH` returned as an error.
    #[test]
    fn a_pid_that_vanishes_after_the_check_is_gone_and_the_attempt_is_recorded() {
        let log = Capture::start();
        let _forced = uniq_fault::force_uniq_read_once(ReadPurpose::Kill, UniqRead::Found(UniqInfo { unique_id: 7 }));
        assert_eq!(
            via_verified_pid(NEVER_A_PID, Some(7), Sig::Kill).expect("gone is Ok"),
            Sent::Gone
        );
        assert_eq!(log.entries(), [(NEVER_A_PID, Sig::Kill, Via::Pid)]);
    }

    /// Mutant: the send is not recorded, or nothing is sent.
    #[test]
    fn a_verified_live_child_is_signalled_and_recorded() {
        let (mut child, _stdin) = spawn();
        let identity = read_identity(child.id()).expect("readable");
        let log = Capture::start();
        assert_eq!(
            via_verified_pid(child.id(), identity, Sig::Kill).expect("send"),
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
