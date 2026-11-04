//! What cosca asks the Linux kernel about processes, and nothing else. [`HostKernel`] makes the
//! system calls; the test `FakeKernel` answers from a table of stated facts and models no kernel.
//!
//! The logic lives once, in functions that take `&dyn Kernel`; every production caller passes
//! `&HostKernel`. Reads that no test answers for (`btime`, `sysconf`, `boot_id`, the namespace
//! link inodes, `/proc/self/cgroup`) stay raw.

use std::io;

use super::proc_view::{ProcDir, ViewUnreadable};

pub(crate) trait Kernel: Sync {
    /// `ProcDir::open`: `openat2` of `/proc`, proven procfs's root.
    fn open_proc(&self) -> Result<ProcDir, ViewUnreadable>;

    /// The file at `path` under `dir`: `<pid>/stat`, `self/stat`, `self/status` or
    /// `thread-self/fdinfo/<fd>`.
    fn read(&self, dir: &ProcDir, path: &str) -> io::Result<Vec<u8>>;
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
}

#[cfg(test)]
#[path = "kernel/fake.rs"]
pub(crate) mod fake;

#[cfg(test)]
#[path = "kernel_tests.rs"]
mod kernel_tests;
