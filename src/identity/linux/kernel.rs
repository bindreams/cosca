//! What cosca asks the Linux kernel about processes, and nothing else. [`HostKernel`] makes the
//! system calls; the test `FakeKernel` answers from a table of stated facts and models no kernel.
//!
//! The logic lives once, in functions that take `&dyn Kernel`; every production caller passes
//! `&HostKernel`. Reads no test answers for stay raw until a test needs them.

use std::os::fd::{BorrowedFd, OwnedFd};

use rustix::fs::{fstat, fstatfs};
use rustix::io::Errno;
use rustix::process::{pidfd_open, test_kill_process, waitid, Pid, PidfdFlags, WaitId, WaitIdOptions};

use super::proc_read::{ProcDir, ProcOpenFailure, ReadFailure};
use crate::identity::Record;

/// `PIDFD_THREAD`: open a pidfd for a thread that is not a thread-group leader. rustix has no
/// name for it.
pub(crate) const PIDFD_THREAD: PidfdFlags = PidfdFlags::from_bits_retain(libc::PIDFD_THREAD);

/// The `f_type` of pidfs (`PID_FS_MAGIC`); rustix and libc do not name it.
const PID_FS_MAGIC: i64 = 0x5049_4446;

pub(crate) trait Kernel: Sync {
    /// `pidfd_open(target, flags)`. The caller decides what is a pidfd target; the kernel is asked
    /// only about one.
    fn pidfd_open(&self, target: Pid, flags: PidfdFlags) -> Result<OwnedFd, Errno>;

    /// The inode of the pidfd `fd` on pidfs (Linux 6.9+), where it is one per process: `Some`.
    /// `None` for a pidfd with no inode of its own, which an older kernel hands out. `fstatfs`
    /// names the filesystem, then `fstat` the inode.
    fn pidfs_ino(&self, fd: BorrowedFd<'_>) -> Result<Option<u64>, Errno>;

    /// `ProcDir::open`: `openat2` of `/proc`, proven procfs's root.
    fn open_proc(&self) -> Result<ProcDir, ProcOpenFailure>;

    /// The file at `path` under `dir`: `<pid>/stat`, `<pid>/cgroup`, `self/stat`, `self/status`
    /// or `thread-self/fdinfo/<fd>`. A failure says whether the `openat2` or `read(2)` failed.
    fn read(&self, dir: &ProcDir, path: &str) -> Result<Vec<u8>, ReadFailure>;

    /// The target of the symlink at `path` under `dir`: `thread-self/ns/pid` or `<pid>/ns/pid`. A
    /// failure says whether the `openat2` or the `readlinkat` failed.
    fn read_link(&self, dir: &ProcDir, path: &str) -> Result<Vec<u8>, ReadFailure>;

    /// The numeric entries of `dir` (`ProcDir::pids`). A failure says whether the `openat2` of `dir`
    /// or its listing failed.
    fn pids(&self, dir: &ProcDir) -> Result<Vec<u32>, ReadFailure>;

    /// The thread ids of `pid`, the numeric entries of `<pid>/task` under `dir`: each call lists the
    /// directory afresh. A failure says whether the `openat2` of the directory or its listing failed.
    fn tids(&self, dir: &ProcDir, pid: u32) -> Result<Vec<u32>, ReadFailure>;

    /// `kill(target, 0)`. The caller decides what is a kill target (`probe::signal_target`); the
    /// kernel is asked only about one.
    fn signal_probe(&self, target: Pid) -> Result<(), Errno>;

    /// `waitid(P_PIDFD, pidfd, WEXITED | WNOHANG | WNOWAIT)`: the record a peek of our own child
    /// sees, without consuming it. `Ok(None)`: no record (the child has not exited). Answers only
    /// `ECHILD` (a foreign reap), or `EBADF`/`EINVAL` for a non-pidfd; a sandbox policy may answer
    /// more, which is what a test states a row for.
    fn peek(&self, pidfd: BorrowedFd<'_>) -> Result<Option<Record>, Errno>;

    /// `waitid(P_PIDFD, pidfd, WEXITED | WNOHANG)`: the record this call consumes. `Ok(None)`: nothing
    /// to consume (not exited, or a zombie only its tracer can reap).
    fn consume(&self, pidfd: BorrowedFd<'_>) -> Result<Option<Record>, Errno>;
}

/// The real kernel.
pub(crate) struct HostKernel;

impl Kernel for HostKernel {
    fn pidfd_open(&self, target: Pid, flags: PidfdFlags) -> Result<OwnedFd, Errno> {
        pidfd_open(target, flags)
    }

    fn pidfs_ino(&self, fd: BorrowedFd<'_>) -> Result<Option<u64>, Errno> {
        if fstatfs(fd)?.f_type as i64 != PID_FS_MAGIC {
            return Ok(None);
        }
        Ok(Some(fstat(fd)?.st_ino as u64))
    }

    fn open_proc(&self) -> Result<ProcDir, ProcOpenFailure> {
        ProcDir::open()
    }

    fn read(&self, dir: &ProcDir, path: &str) -> Result<Vec<u8>, ReadFailure> {
        dir.read(path)
    }

    fn read_link(&self, dir: &ProcDir, path: &str) -> Result<Vec<u8>, ReadFailure> {
        dir.read_link(path)
    }

    fn pids(&self, dir: &ProcDir) -> Result<Vec<u32>, ReadFailure> {
        dir.pids()
    }

    fn tids(&self, dir: &ProcDir, pid: u32) -> Result<Vec<u32>, ReadFailure> {
        dir.tids(pid)
    }

    fn signal_probe(&self, target: Pid) -> Result<(), Errno> {
        test_kill_process(target)
    }

    fn peek(&self, pidfd: BorrowedFd<'_>) -> Result<Option<Record>, Errno> {
        waitid_record(
            pidfd,
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        )
    }

    fn consume(&self, pidfd: BorrowedFd<'_>) -> Result<Option<Record>, Errno> {
        waitid_record(pidfd, WaitIdOptions::EXITED | WaitIdOptions::NOHANG)
    }
}

/// One `waitid(P_PIDFD, options)`: `Ok(None)` when nothing matched (`si_signo == 0`, rustix
/// zeroes the `siginfo_t` first). `EINTR` retries.
///
/// `options` must carry `NOHANG`: a blocking `waitid` on a zombie its tracer holds sleeps until the
/// tracer lets go.
fn waitid_record(fd: BorrowedFd<'_>, options: WaitIdOptions) -> Result<Option<Record>, Errno> {
    debug_assert!(
        options.contains(WaitIdOptions::NOHANG),
        "a blocking waitid on a zombie a tracer holds sleeps until the tracer lets go"
    );
    loop {
        match waitid(WaitId::PidFd(fd), options) {
            Ok(status) => {
                return Ok(status.map(|st| Record {
                    si_code: st.raw_code(),
                    si_status: st.exit_status().or_else(|| st.terminating_signal()).unwrap_or(0),
                }))
            }
            Err(Errno::INTR) => continue,
            Err(e) => return Err(e),
        }
    }
}

forward_kernel! {
    fn pidfd_open(&self, target: Pid, flags: PidfdFlags) -> Result<OwnedFd, Errno>;
    fn pidfs_ino(&self, fd: BorrowedFd<'_>) -> Result<Option<u64>, Errno>;
    fn open_proc(&self) -> Result<ProcDir, ProcOpenFailure>;
    fn read(&self, dir: &ProcDir, path: &str) -> Result<Vec<u8>, ReadFailure>;
    fn read_link(&self, dir: &ProcDir, path: &str) -> Result<Vec<u8>, ReadFailure>;
    fn pids(&self, dir: &ProcDir) -> Result<Vec<u32>, ReadFailure>;
    fn tids(&self, dir: &ProcDir, pid: u32) -> Result<Vec<u32>, ReadFailure>;
    fn signal_probe(&self, target: Pid) -> Result<(), Errno>;
    fn peek(&self, pidfd: BorrowedFd<'_>) -> Result<Option<Record>, Errno>;
    fn consume(&self, pidfd: BorrowedFd<'_>) -> Result<Option<Record>, Errno>;
}

#[cfg(test)]
#[path = "kernel/fake.rs"]
pub(crate) mod fake;

#[cfg(test)]
#[path = "kernel_tests.rs"]
mod kernel_tests;
