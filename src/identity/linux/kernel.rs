//! What cosca asks the Linux kernel about processes, and nothing else. [`HostKernel`] makes the
//! system calls; the test `FakeKernel` answers from a table of stated facts and models no kernel.
//!
//! The logic lives once, in functions that take `&dyn Kernel`; every production caller passes
//! `&HostKernel`. Reads no test answers for stay raw until a test needs them.

use std::io;
use std::os::fd::{BorrowedFd, OwnedFd};

use rustix::fs::{fstat, fstatfs};
use rustix::io::Errno;
use rustix::process::{pidfd_open, test_kill_process, Pid, PidfdFlags};

use super::proc_view::{ProcDir, ViewUnreadable};

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
    fn open_proc(&self) -> Result<ProcDir, ViewUnreadable>;

    /// The file at `path` under `dir`: `<pid>/stat`, `<pid>/cgroup`, `self/stat`, `self/status`
    /// or `thread-self/fdinfo/<fd>`.
    fn read(&self, dir: &ProcDir, path: &str) -> io::Result<Vec<u8>>;

    /// The numeric entries of `dir` (`ProcDir::pids`).
    fn pids(&self, dir: &ProcDir) -> io::Result<Vec<u32>>;

    /// `kill(target, 0)`. The caller decides what is a kill target (`probe::signal_target`); the
    /// kernel is asked only about one.
    fn signal_probe(&self, target: Pid) -> Result<(), Errno>;
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

    fn open_proc(&self) -> Result<ProcDir, ViewUnreadable> {
        ProcDir::open()
    }

    fn read(&self, dir: &ProcDir, path: &str) -> io::Result<Vec<u8>> {
        dir.read(path)
    }

    fn pids(&self, dir: &ProcDir) -> io::Result<Vec<u32>> {
        dir.pids()
    }

    fn signal_probe(&self, target: Pid) -> Result<(), Errno> {
        test_kill_process(target)
    }
}

#[cfg(test)]
#[path = "kernel/fake.rs"]
pub(crate) mod fake;

#[cfg(test)]
#[path = "kernel_tests.rs"]
mod kernel_tests;
