//! Fixtures for tests where a child is reaped behind its owner's back and a stranger takes its pid.
//!
//! Every such test runs as pid 1 of a fresh pid namespace with its own procfs, in the shape of
//! `identity::linux::proc_view_tests`: a driver fixture enters the namespace, the init fixture
//! mounts `/proc` and runs the body. Nothing may create a thread or a process between
//! [`reap_behind_and_reuse`]'s `set_last_pid` and the reuser's spawn, so a test must not touch
//! the reaper pool or tokio's blocking pool before it. The reuser is a plain `std` child with
//! default signal dispositions, not a cosca one.

use std::os::fd::{AsFd, BorrowedFd};
use std::process::Child;

use rustix::event::{poll, PollFd, PollFlags};
use rustix::process::{pidfd_open, waitid, Pid, PidfdFlags, WaitId, WaitIdOptions};

use super::namespaces as ns;

/// Runs `$body` as pid 1 of a fresh pid namespace with its own procfs. Defines the `#[test]`
/// `$test` (the entry, in the `NAMESPACES` group) and its two fixtures. The caller imports
/// `crate::test_groups::namespaces`.
macro_rules! in_fresh_pid_ns {
    ($test:ident, $driver:ident, $init:ident, $body:path) => {
        $crate::test_child::pid_reuse::in_fresh_pid_ns!(@define $test, $driver, $init, $body, [#[fixture(namespaces)] _group: &crate::test_groups::Group]);
    };
    // For a body that also needs a delegated cgroup: the entry test holds the `cgroup` group too.
    ($test:ident, $driver:ident, $init:ident, $body:path, cgroup) => {
        $crate::test_child::pid_reuse::in_fresh_pid_ns!(@define $test, $driver, $init, $body, [
            #[fixture(namespaces)] _group: &crate::test_groups::Group,
            #[fixture(cgroup)] _cgroup: &crate::test_groups::Group
        ]);
    };
    (@define $test:ident, $driver:ident, $init:ident, $body:path, [$($params:tt)*]) => {
        #[skuld::test]
        fn $test($($params)*) {
            crate::test_child::namespaces::run(crate::test_child::fixture_path!($driver));
        }

        #[skuld::test]
        fn $driver() {
            if !crate::test_child::namespaces::is_child() {
                return;
            }
            crate::test_child::namespaces::enter_new_pid_ns_for_children();
            crate::test_child::namespaces::run(crate::test_child::fixture_path!($init));
        }

        #[skuld::test]
        fn $init() {
            if !crate::test_child::namespaces::is_child_in_new_pid_ns() {
                return;
            }
            crate::test_child::namespaces::enter_private_mount_ns();
            crate::test_child::namespaces::mount_proc(std::path::Path::new("/proc"));
            $body();
        }
    };
}
pub(crate) use in_fresh_pid_ns;

fn pid_of(pid: u32) -> Pid {
    Pid::from_raw(pid as i32).expect("a child's pid is nonzero")
}

/// Blocks until `pidfd` reports the process has exited.
pub(crate) fn wait_pollin(pidfd: BorrowedFd<'_>) {
    let mut fds = [PollFd::new(&pidfd, PollFlags::IN)];
    loop {
        match poll(&mut fds, None) {
            Ok(n) if n > 0 => return,
            Ok(_) | Err(rustix::io::Errno::INTR) => {}
            Err(e) => panic!("poll(pidfd): {e}"),
        }
    }
}

/// Waits for `pid`'s exit on a pidfd of the test's own, then reaps it with a raw `waitid(P_PID)`
/// behind its owner's back, and starts a `std` child that takes the same pid.
///
/// `pid` must be an unreaped child of this process that has been told to exit.
pub(crate) fn reap_behind_and_reuse(pid: u32) -> Child {
    let pidfd = pidfd_open(pid_of(pid), PidfdFlags::empty()).expect("pidfd_open the child");
    wait_pollin(pidfd.as_fd());
    let reaped = waitid(WaitId::Pid(pid_of(pid)), WaitIdOptions::EXITED).expect("raw reap");
    assert!(reaped.is_some(), "the raw reap must consume an exit record");
    drop(pidfd);

    ns::set_last_pid(pid - 1);
    let mut cmd = std::process::Command::new("sleep");
    cmd.arg("3600");
    let reuser = crate::test_spawn::spawn(&mut cmd).expect("spawn the reuser");
    assert_eq!(
        reuser.id(),
        pid,
        "precondition: the reuser must take the reaped child's pid"
    );
    reuser
}

/// [`sigusr1_and_wait`] without consuming the exit: sends `SIGUSR1`, then waits on a pidfd until the
/// reuser is a zombie, and peeks with `WNOWAIT`. Returns the signal it died of.
#[cfg(feature = "tokio")]
pub(crate) fn sigusr1_and_peek(reuser: &Child) -> Option<i32> {
    let pidfd = pidfd_open(pid_of(reuser.id()), PidfdFlags::empty()).expect("pidfd_open the reuser");
    signal_usr1(reuser);
    wait_pollin(pidfd.as_fd());
    let record = waitid(
        WaitId::PidFd(pidfd.as_fd()),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    )
    .expect("peek the reuser's exit")
    .expect("the reuser has exited");
    record.terminating_signal()
}

/// Sends `SIGUSR1` to `reuser` and returns the signal it died of. The first fatal signal fixes the
/// status, so anything that signalled it earlier shows here.
pub(crate) fn sigusr1_and_wait(mut reuser: Child) -> Option<i32> {
    signal_usr1(&reuser);
    std::os::unix::process::ExitStatusExt::signal(&reuser.wait().expect("wait for the reuser"))
}

pub(crate) fn signal_usr1(reuser: &Child) {
    // SAFETY: `reuser` is an unreaped child of ours, so its pid names it.
    let rc = unsafe { libc::kill(reuser.id() as i32, libc::SIGUSR1) };
    assert_eq!(rc, 0, "kill(SIGUSR1): {}", std::io::Error::last_os_error());
}
