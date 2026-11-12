use std::os::fd::AsRawFd as _;

use super::{clone_with_pidfd, fails_with, fallback, fork_with_pidfd, Fork, ForkFn, NewChild, Path};
use crate::child::spawn::spawn_lock;
use crate::test_groups::{clone3, Group};

/// Forks a child that exits with `code` at once, through `fork`.
fn fork_exiting(fork: ForkFn, code: i32) -> Result<NewChild, i32> {
    let _lock = spawn_lock();
    // SAFETY: the child calls only `_exit`, and this thread holds `spawn_lock`.
    match unsafe { fork() }? {
        // SAFETY: a plain system call.
        Fork::Child => unsafe { libc::_exit(code) },
        Fork::Parent(child) => Ok(child),
    }
}

/// The pid and exit code `waitid` on `child`'s pidfd reports, reaping the child through it.
fn reaped_through_pidfd(child: &NewChild) -> (libc::pid_t, i32) {
    // SAFETY: an all-zero `siginfo_t` is a valid out-parameter.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: the pidfd is open, and `info` is a valid, writable `siginfo_t`.
    let waited = unsafe {
        libc::waitid(
            libc::P_PIDFD,
            child.pidfd.as_raw_fd() as libc::id_t,
            &mut info,
            libc::WEXITED,
        )
    };
    assert_eq!(waited, 0, "waitid on the pidfd: {}", std::io::Error::last_os_error());
    // SAFETY: a `SIGCHLD` info, which a successful `waitid` fills in.
    unsafe { (info.si_pid(), info.si_status()) }
}

/// The child `fork` (the entry named `entry`) makes is the one the parent's pidfd names: `waitid` on
/// the pidfd reports the pid the parent was given and the exit code the child chose, and the pidfd is
/// close-on-exec. The child was made by `path`. `hint` ends the failure messages of the fork and the
/// path.
///
/// Mutants: the pidfd is the wrong descriptor; the pid is not the child's; the pidfd is inheritable.
fn assert_names_the_child_that_ran(entry: &str, hint: &str, fork: ForkFn, path: Path, code: i32) {
    let child = fork_exiting(fork, code).unwrap_or_else(|errno| panic!("{entry} failed, errno {errno}{hint}"));
    assert_eq!(
        child.path, path,
        "{entry} made the child by {:?}, not {path:?}{hint}",
        child.path
    );
    // SAFETY: a plain system call on an open descriptor.
    let flags = unsafe { libc::fcntl(child.pidfd.as_raw_fd(), libc::F_GETFD) };
    assert!(
        flags >= 0 && flags & libc::FD_CLOEXEC != 0,
        "the pidfd of {entry} is close-on-exec: {flags:#x}"
    );
    assert_eq!(reaped_through_pidfd(&child), (child.pid, code), "{entry}");
}

/// The default entry makes its child by `clone3`, as every unprivileged lane must see. Needs a host that
/// allows `clone3`: a sandbox that refuses it fails the row. Current Docker's default seccomp profile
/// answers `clone3` with `ENOSYS` (without `CAP_SYS_ADMIN`), so set `COSCA_TEST_CLONE3=0` under any
/// default Docker profile.
///
/// Mutant: the default entry skips `clone3`.
#[skuld::test]
fn the_pidfd_names_the_child_that_ran(#[fixture(clone3)] _group: &Group) {
    assert_names_the_child_that_ran(
        "fork_with_pidfd",
        "; this row needs a host that allows clone3: set COSCA_TEST_CLONE3=0 to turn it off",
        fork_with_pidfd,
        Path::Clone3,
        7,
    );
}

/// `clone(CLONE_PIDFD)` alone makes a child its pidfd names: the fallback where `clone3` is refused.
///
/// Mutant: the fallback makes no pidfd.
#[skuld::test]
fn clone_makes_a_child_its_pidfd_names() {
    assert_names_the_child_that_ran("clone_with_pidfd", "", clone_with_pidfd, Path::Clone, 9);
}

// The three `unsafe fn`s below call `fallback` with the real `clone`, so the caller's contract is
// `fork_exiting`'s.
unsafe fn enosys_then_clone() -> Result<Fork, i32> {
    // SAFETY: the caller's contract.
    unsafe { fallback(|| fails_with(libc::ENOSYS), clone_with_pidfd) }
}

unsafe fn eperm_then_clone() -> Result<Fork, i32> {
    // SAFETY: the caller's contract.
    unsafe { fallback(|| fails_with(libc::EPERM), clone_with_pidfd) }
}

unsafe fn eagain_then_clone() -> Result<Fork, i32> {
    // SAFETY: the caller's contract.
    unsafe { fallback(|| fails_with(libc::EAGAIN), clone_with_pidfd) }
}

/// A first clone refused with `ENOSYS` or `EPERM` falls back to `clone`, whose child its pidfd names.
///
/// Mutant: the fallback arm is deleted, or takes only one of the two errnos.
#[skuld::test]
fn a_refused_first_clone_falls_back_to_clone() {
    assert_names_the_child_that_ran("enosys then clone", "", enosys_then_clone, Path::Clone, 10);
    assert_names_the_child_that_ran("eperm then clone", "", eperm_then_clone, Path::Clone, 11);
}

/// Any other errno of the first clone is the fork's own: the second clone does not run, and the errno
/// is the answer.
///
/// Mutant: every errno falls back (the second clone would make a child).
#[skuld::test]
fn another_errno_of_the_first_clone_does_not_fall_back() {
    let answer = fork_exiting(eagain_then_clone, 12);
    assert_eq!(answer.err(), Some(libc::EAGAIN));
}
