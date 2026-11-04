//! A stated-facts [`Kernel`]: the answers its tables hold, and nothing the kernel would do. A call
//! with no row panics, except under [`FakeKernel::over`], which passes it to the real kernel.
//!
//! Rows are plain data: a path or pid is looked up by `==`, and a later row replaces an earlier one.

use std::io;
use std::os::fd::OwnedFd;
use std::sync::Mutex;

use rustix::io::Errno;
use rustix::process::Pid;

use super::Kernel;
use crate::identity::{ProcDir, ViewUnreadable};

pub(crate) struct FakeKernel<'a> {
    /// What answers a call the tables have nothing for. `None`: such a call panics.
    real: Option<&'a dyn Kernel>,
    open_proc: Option<Errno>,
    /// `Err` is a raw errno.
    reads: Vec<(String, Result<Vec<u8>, i32>)>,
    signal_probes: Vec<(Pid, Result<(), Errno>)>,
    pidfd_opens: Vec<(Pid, PidfdRow)>,
}

/// What a `pidfd_open` row answers.
enum PidfdRow {
    /// Every call.
    Errno(Errno),
    /// The first call hands the fd out; a second panics.
    Fd(Mutex<Option<OwnedFd>>),
}

impl<'a> FakeKernel<'a> {
    /// A kernel with no rows.
    pub(crate) fn new() -> Self {
        FakeKernel {
            real: None,
            open_proc: None,
            reads: Vec::new(),
            signal_probes: Vec::new(),
            pidfd_opens: Vec::new(),
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

    /// `kill(target, 0)` answers `answer`.
    pub(crate) fn on_signal_probe(mut self, target: Pid, answer: Result<(), Errno>) -> Self {
        self.signal_probes.push((target, answer));
        self
    }

    /// `pidfd_open` of `pid` answers `answer`. An errno answers every call. An fd the test opened
    /// itself is handed out once, because an `OwnedFd` has no copy with the same number.
    pub(crate) fn on_pidfd_open(mut self, pid: u32, answer: Result<OwnedFd, Errno>) -> Self {
        let target = Pid::from_raw(pid as i32).expect("a pidfd_open row names a positive pid");
        let row = match answer {
            Ok(fd) => PidfdRow::Fd(Mutex::new(Some(fd))),
            Err(errno) => PidfdRow::Errno(errno),
        };
        self.pidfd_opens.push((target, row));
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
    fn pidfd_open(&self, target: Pid) -> Result<OwnedFd, Errno> {
        match self.pidfd_opens.iter().rev().find(|(p, _)| *p == target) {
            Some((_, PidfdRow::Errno(errno))) => Err(*errno),
            Some((_, PidfdRow::Fd(slot))) => Ok(slot
                .lock()
                .expect("no panic holds the row")
                .take()
                .unwrap_or_else(|| panic!("FakeKernel hands the pidfd of {target:?} out once"))),
            None => self.real(&format!("pidfd_open of {target:?}")).pidfd_open(target),
        }
    }

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

    fn signal_probe(&self, target: Pid) -> Result<(), Errno> {
        match self.signal_probes.iter().rev().find(|(p, _)| *p == target) {
            Some((_, answer)) => *answer,
            None => self.real(&format!("signal_probe of {target:?}")).signal_probe(target),
        }
    }
}
