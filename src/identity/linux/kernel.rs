//! What cosca asks the Linux kernel about processes, and nothing else. [`HostKernel`] makes the
//! system calls; the test `FakeKernel` answers from a table of stated facts and models no kernel.
//!
//! The logic lives once, in functions that take `&dyn Kernel`; every production caller passes
//! `&HostKernel`. Reads that no test answers for (`btime`, `sysconf`, `boot_id`, the namespace
//! link inodes, `/proc/self/cgroup`) stay raw.

use std::io;

use rustix::io::Errno;
use rustix::process::{test_kill_process, Pid};

use super::proc_view::{ProcDir, ViewUnreadable};
use crate::identity::probe::signal_target;

pub(crate) trait Kernel: Sync {
    /// `ProcDir::open`: `openat2` of `/proc`, proven procfs's root.
    fn open_proc(&self) -> Result<ProcDir, ViewUnreadable>;

    /// The file at `path` under `dir`: `<pid>/stat`, `self/stat`, `self/status` or
    /// `thread-self/fdinfo/<fd>`.
    fn read(&self, dir: &ProcDir, path: &str) -> io::Result<Vec<u8>>;

    /// `kill(pid, 0)`. `pid` is a [`signal_target`]; a number that is no pid answers `ESRCH`.
    fn signal_probe(&self, pid: u32) -> Result<(), Errno>;
}

/// The real kernel.
pub(crate) struct HostKernel;

impl Kernel for HostKernel {
    fn open_proc(&self) -> Result<ProcDir, ViewUnreadable> {
        ProcDir::open()
    }

    fn read(&self, dir: &ProcDir, path: &str) -> io::Result<Vec<u8>> {
        dir.read(path)
    }

    fn signal_probe(&self, pid: u32) -> Result<(), Errno> {
        let target = signal_target(pid);
        debug_assert!(target.is_some(), "{pid} is no kill target; the caller checks first");
        // Never issued for 0 or a wrapped value: `kill(0, ..)` and `kill(-n, ..)` signal groups
        // and would answer for a process that is not there.
        match target.and_then(Pid::from_raw) {
            Some(pid) => test_kill_process(pid),
            None => Err(Errno::SRCH),
        }
    }
}

#[cfg(test)]
#[path = "kernel/fake.rs"]
pub(crate) mod fake;

#[cfg(test)]
#[path = "kernel_tests.rs"]
mod kernel_tests;
