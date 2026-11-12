//! Forking a child whose pidfd comes from the fork itself.
//!
//! The child is made by `clone3(CLONE_PIDFD)`, or `clone(CLONE_PIDFD)` where `clone3` is refused
//! (Docker's default seccomp profile answers `ENOSYS`). The kernel stores the pidfd as the child is
//! created, so the handle exists from the child's first instant: no other thread can reap the child
//! and let a stranger take its pid before the parent has a handle on it, and a pidfd opened later by
//! number could name that stranger.

// The raw `clone`'s return convention (0 in the child) is the one these architectures share; sparc64,
// for one, returns the parent's pid in the child and flags it in a register.
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64",
    target_arch = "s390x",
    target_arch = "powerpc64",
    target_arch = "loongarch64"
)))]
compile_error!("os_process::linux::fork: the raw clone's return convention is checked only on x86_64, aarch64, riscv64, s390x, powerpc64 and loongarch64");

use std::os::fd::{FromRawFd, OwnedFd};

/// The clone that made the child: `clone3`, or `clone(CLONE_PIDFD)` after `clone3` was refused.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Path {
    Clone3,
    Clone,
}

/// The new child, as its parent sees it.
#[derive(Debug)]
pub(crate) struct NewChild {
    pub(crate) pid: libc::pid_t,
    /// Names the child for good, from its first instant. Close-on-exec.
    pub(crate) pidfd: OwnedFd,
    pub(crate) path: Path,
}

/// Which side of the fork a caller is on.
#[derive(Debug)]
pub(crate) enum Fork {
    /// In the child.
    Child,
    /// In the parent.
    Parent(NewChild),
}

/// A fork: [`fork_with_pidfd`], or a stand-in for it.
pub(crate) type ForkFn = unsafe fn() -> Result<Fork, i32>;

/// A fork the kernel refused with `errno`: no child was made. The stand-in a test or an injected fault
/// puts in a [`ForkFn`]'s place, as `|| fails_with(libc::EAGAIN)`.
pub(crate) fn fails_with(errno: i32) -> Result<Fork, i32> {
    Err(errno)
}

/// The arguments of `clone3`, version 0 (kernel 5.3).
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
}

const CLONE_PIDFD: u64 = 0x1000;

/// Forks this process, as `fork` does, and hands the parent a pidfd for the child. `Err` is the
/// errno, and no child was made. Allocates and logs nothing, in either process: [`NewChild::path`]
/// says which clone ran, for the parent to log.
///
/// `clone3` is tried first, and `clone(CLONE_PIDFD)` replaces it where its errno is a refusal: `ENOSYS`
/// (the kernel lacks `clone3`, or Docker's default seccomp profile refuses it) or `EPERM` (a seccomp
/// profile whose default action is `EPERM`, as Docker's before 20.10). `EPERM` is a refusal here and not
/// the kernel's own: with only `CLONE_PIDFD` asked, `clone3` checks no capability, so the kernel never
/// answers it.
///
/// # Safety
///
/// As for `fork` in a multithreaded process, and the caller holds [`spawn_lock`]. On
/// [`Fork::Child`] the child comes from a raw clone that runs none of glibc's fork bookkeeping: no
/// atfork handler runs, and the locks of `malloc` and stdio are not reset, though another thread of the
/// parent may have held one at the instant of the clone. The caller's body makes raw system calls and
/// async-signal-safe libc wrappers only: no allocation, no logging, no formatted panic (a failing
/// `assert!` or `unwrap` formats). It never returns into Rust: it ends in `execve` or `_exit`.
///
/// The child must not call glibc's `fork`, `vfork`, `posix_spawn` or `system`: glibc still counts the
/// parent's threads, so these take the atfork, stdio-list and malloc-arena locks that a thread which
/// does not exist in the child may have held, and block for ever. A grandchild is made by this
/// function, which logs and allocates nothing, so it is itself safe to call in such a child.
///
/// [`spawn_lock`]: crate::child::spawn::spawn_lock
pub(crate) unsafe fn fork_with_pidfd() -> Result<Fork, i32> {
    // SAFETY: the caller's contract.
    unsafe { fallback(clone3_with_pidfd, clone_with_pidfd) }
}

/// `first`, and `second` where `first`'s errno is `ENOSYS` or `EPERM`, a refusal that made no child.
///
/// # Safety
///
/// As [`fork_with_pidfd`].
pub(crate) unsafe fn fallback(first: ForkFn, second: ForkFn) -> Result<Fork, i32> {
    // SAFETY: the caller's contract.
    match unsafe { first() } {
        // SAFETY: the caller's contract; `first` made no child.
        Err(libc::ENOSYS | libc::EPERM) => unsafe { second() },
        forked => forked,
    }
}

/// [`fork_with_pidfd`] by `clone3` alone: `Err` is its errno, a refusal included.
///
/// # Safety
///
/// As [`fork_with_pidfd`].
unsafe fn clone3_with_pidfd() -> Result<Fork, i32> {
    debug_assert_locked();
    let mut pidfd: libc::c_int = -1;
    let args = CloneArgs {
        flags: CLONE_PIDFD,
        pidfd: (&mut pidfd as *mut libc::c_int) as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..CloneArgs::default()
    };
    // SAFETY: `args` is a valid `clone_args` of the size passed; no stack is given, so the child
    // continues on a copy of this one, as after `fork`.
    let pid = unsafe { libc::syscall(libc::SYS_clone3, &args, std::mem::size_of::<CloneArgs>()) };
    after_clone(pid, pidfd, Path::Clone3)
}

/// [`fork_with_pidfd`] by `clone(CLONE_PIDFD)` alone: `Err` is its errno.
///
/// # Safety
///
/// As [`fork_with_pidfd`].
pub(crate) unsafe fn clone_with_pidfd() -> Result<Fork, i32> {
    debug_assert_locked();
    let mut pidfd: libc::c_int = -1;
    let flags = CLONE_PIDFD | libc::SIGCHLD as u64;
    // SAFETY: the legacy `clone` with no stack, as `fork`; the pidfd is stored through the
    // `parent_tid` argument. The argument order is the architecture's.
    let pid = unsafe { raw_clone(flags, &mut pidfd) };
    after_clone(pid, pidfd, Path::Clone)
}

fn debug_assert_locked() {
    #[cfg(any(test, debug_assertions))]
    debug_assert!(
        crate::child::spawn::spawn_lock_held_by_this_thread(),
        "a fork runs under spawn_lock"
    );
}

/// The result of a clone that returned `pid`: right after the call, so that `errno` is its own.
fn after_clone(pid: libc::c_long, pidfd: libc::c_int, path: Path) -> Result<Fork, i32> {
    if pid == 0 {
        return Ok(Fork::Child);
    }
    if pid < 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO));
    }
    debug_assert!(pidfd >= 0, "CLONE_PIDFD stores the descriptor");
    // SAFETY: the kernel made `pidfd` for this call and nothing else owns it.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
    Ok(Fork::Parent(NewChild {
        pid: pid as libc::pid_t,
        pidfd,
        path,
    }))
}

#[cfg(not(target_arch = "s390x"))]
unsafe fn raw_clone(flags: u64, pidfd: &mut libc::c_int) -> libc::c_long {
    // SAFETY: the caller's contract.
    unsafe {
        libc::syscall(
            libc::SYS_clone,
            flags,
            0usize,
            pidfd as *mut libc::c_int,
            0usize,
            0usize,
        )
    }
}

/// s390x puts the stack pointer first (`CONFIG_CLONE_BACKWARDS2`).
#[cfg(target_arch = "s390x")]
unsafe fn raw_clone(flags: u64, pidfd: &mut libc::c_int) -> libc::c_long {
    // SAFETY: the caller's contract.
    unsafe {
        libc::syscall(
            libc::SYS_clone,
            0usize,
            flags,
            pidfd as *mut libc::c_int,
            0usize,
            0usize,
        )
    }
}

#[cfg(test)]
#[path = "fork_tests.rs"]
mod fork_tests;
