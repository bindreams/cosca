//! A stated-facts [`Kernel`]: the answers its tables hold, and nothing the kernel would do. A call
//! with no row panics, except under [`FakeKernel::over`], which passes it to the real kernel.
//!
//! Rows are plain data: a path or pid is looked up by `==`, and a later row replaces an earlier one.

use std::io;

use rustix::io::Errno;

use super::Kernel;
use crate::identity::{ProcDir, ViewUnreadable};

pub(crate) struct FakeKernel<'a> {
    /// What answers a call the tables have nothing for. `None`: such a call panics.
    real: Option<&'a dyn Kernel>,
    open_proc: Option<Errno>,
    /// `Err` is a raw errno.
    reads: Vec<(String, Result<Vec<u8>, i32>)>,
    signal_probes: Vec<(u32, Result<(), Errno>)>,
}

impl<'a> FakeKernel<'a> {
    /// A kernel with no rows.
    pub(crate) fn new() -> Self {
        FakeKernel {
            real: None,
            open_proc: None,
            reads: Vec::new(),
            signal_probes: Vec::new(),
        }
    }

    /// A kernel that answers its rows and passes every other call to `real`.
    pub(crate) fn over(real: &'a dyn Kernel) -> Self {
        FakeKernel {
            real: Some(real),
            ..Self::new()
        }
    }

    /// Reading `path` under any `/proc` answers `answer`: the bytes, or a raw errno.
    pub(crate) fn on_read(mut self, path: &str, answer: Result<&[u8], i32>) -> Self {
        self.reads.push((path.to_owned(), answer.map(<[u8]>::to_vec)));
        self
    }

    /// `kill(pid, 0)` answers `answer`.
    pub(crate) fn on_signal_probe(mut self, pid: u32, answer: Result<(), Errno>) -> Self {
        self.signal_probes.push((pid, answer));
        self
    }

    /// Opening `/proc` fails as its `openat2` answering `errno`.
    pub(crate) fn open_proc_fails(mut self, errno: Errno) -> Self {
        self.open_proc = Some(errno);
        self
    }

    fn real(&self, call: &str) -> &'a dyn Kernel {
        self.real.unwrap_or_else(|| panic!("FakeKernel has no row for {call}"))
    }
}

impl Kernel for FakeKernel<'_> {
    fn open_proc(&self) -> Result<ProcDir, ViewUnreadable> {
        match self.open_proc {
            Some(errno) => Err(ViewUnreadable::from_open_errno(errno)),
            None => self.real("open_proc").open_proc(),
        }
    }

    fn read(&self, dir: &ProcDir, path: &str) -> io::Result<Vec<u8>> {
        match self.reads.iter().rev().find(|(p, _)| p == path) {
            Some((_, Ok(bytes))) => Ok(bytes.clone()),
            Some((_, Err(errno))) => Err(io::Error::from_raw_os_error(*errno)),
            None => self.real(&format!("read of {path}")).read(dir, path),
        }
    }

    fn signal_probe(&self, pid: u32) -> Result<(), Errno> {
        match self.signal_probes.iter().rev().find(|(p, _)| *p == pid) {
            Some((_, answer)) => *answer,
            None => self.real(&format!("signal_probe of {pid}")).signal_probe(pid),
        }
    }
}
