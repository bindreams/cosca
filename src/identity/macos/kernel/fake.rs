//! A stated-facts [`Kernel`]: the answers its tables hold, and nothing the kernel would do. A call
//! with no row left panics, except under [`FakeKernel::over`], which passes it to the real kernel.
//!
//! A row answers one call for one pid, or for one [`Subscription`]. The rows of a call kind are
//! taken in the order they were stated, the first one for what is asked about, and each answers
//! once. A peek row never answers a consume.

use std::fmt::Arguments;
use std::io;
use std::sync::Mutex;

use super::Kernel;
use crate::identity::kinfo::kinfo_proc;
use crate::identity::{RawPid, ReadErr, Record, Resolved, UniqRead};
use crate::os_process::macos::kqueue::{Kqueue, Subscription};

/// The rows of one call kind: what each answers for, and the answer.
struct Rows<A, T>(Mutex<Vec<(A, T)>>);

impl<A: PartialEq, T> Rows<A, T> {
    fn new() -> Self {
        Rows(Mutex::new(Vec::new()))
    }

    fn push(&mut self, asked: A, answer: T) {
        self.0
            .get_mut()
            .expect("no thread holds the rows")
            .push((asked, answer));
    }

    /// The first row for `asked`, which it removes.
    fn take(&self, asked: &A) -> Option<T> {
        let mut rows = self.0.lock().expect("no thread panics holding the rows");
        let at = rows.iter().position(|(row, _)| row == asked)?;
        Some(rows.remove(at).1)
    }
}

/// What `sysctl(KERN_PROC_PID)` answers: the read, and the failure that left it `Unknown`.
type KinfoAnswer = (Resolved<kinfo_proc>, Option<io::Error>);

pub(crate) struct FakeKernel<'a> {
    /// What answers a call the rows have nothing for. `None`: such a call panics.
    real: Option<&'a dyn Kernel>,
    peeks: Rows<u32, io::Result<Option<Record>>>,
    consumes: Rows<u32, io::Result<Option<Record>>>,
    unique_infos: Rows<RawPid, UniqRead>,
    short_bsds: Rows<RawPid, Result<libc::proc_bsdshortinfo, ReadErr>>,
    bsd_infos: Rows<RawPid, Result<libc::proc_bsdinfo, ReadErr>>,
    kinfos: Rows<RawPid, KinfoAnswer>,
    /// `Err`: the registration is refused with this errno. `Ok`: it is made and never fires.
    subscribes: Rows<Subscription, Result<(), i32>>,
}

/// A row builder enters with the first test that states that call's answer.
impl<'a> FakeKernel<'a> {
    /// A kernel with no rows.
    pub(crate) fn new() -> Self {
        FakeKernel {
            real: None,
            peeks: Rows::new(),
            consumes: Rows::new(),
            unique_infos: Rows::new(),
            short_bsds: Rows::new(),
            bsd_infos: Rows::new(),
            kinfos: Rows::new(),
            subscribes: Rows::new(),
        }
    }

    /// A kernel that answers its rows and passes every other call to `real`.
    pub(crate) fn over(real: &'a dyn Kernel) -> Self {
        FakeKernel {
            real: Some(real),
            ..Self::new()
        }
    }

    /// The next unique-id read of `pid` without a row before it answers `answer`.
    pub(crate) fn on_unique_info(mut self, pid: RawPid, answer: UniqRead) -> Self {
        self.unique_infos.push(pid, answer);
        self
    }

    /// The next short BSD-info read of `pid` without a row before it answers `answer`.
    pub(crate) fn on_short_bsd(mut self, pid: RawPid, answer: Result<libc::proc_bsdshortinfo, ReadErr>) -> Self {
        self.short_bsds.push(pid, answer);
        self
    }

    /// The next BSD-info read of `pid` without a row before it answers `answer`.
    pub(crate) fn on_bsd_info(mut self, pid: RawPid, answer: Result<libc::proc_bsdinfo, ReadErr>) -> Self {
        self.bsd_infos.push(pid, answer);
        self
    }

    /// The next `kinfo_proc` read of `pid` without a row before finds `record`.
    pub(crate) fn on_kinfo(mut self, pid: RawPid, record: kinfo_proc) -> Self {
        self.kinfos.push(pid, (Resolved::Found(record), None));
        self
    }

    /// The next `kinfo_proc` read of `pid` without a row before is refused with `errno`.
    pub(crate) fn on_kinfo_refused(mut self, pid: RawPid, errno: i32) -> Self {
        self.kinfos
            .push(pid, (Resolved::Unknown, Some(io::Error::from_raw_os_error(errno))));
        self
    }

    /// The next registration `what` without a row before is made and never fires.
    pub(crate) fn on_subscribe(mut self, what: Subscription) -> Self {
        self.subscribes.push(what, Ok(()));
        self
    }

    /// The kernel that answers a call no row answers; `asked` says what the call was.
    fn real(&self, asked: Arguments<'_>) -> &'a dyn Kernel {
        self.real
            .unwrap_or_else(|| panic!("the fake kernel has no row left for {asked}"))
    }
}

impl Kernel for FakeKernel<'_> {
    fn peek(&self, pid: u32) -> io::Result<Option<Record>> {
        self.peeks
            .take(&pid)
            .unwrap_or_else(|| self.real(format_args!("a peek of pid {pid}")).peek(pid))
    }

    fn consume(&self, pid: u32) -> io::Result<Option<Record>> {
        self.consumes
            .take(&pid)
            .unwrap_or_else(|| self.real(format_args!("a consume of pid {pid}")).consume(pid))
    }

    fn unique_info(&self, pid: RawPid) -> UniqRead {
        self.unique_infos.take(&pid).unwrap_or_else(|| {
            self.real(format_args!("a unique-id read of pid {pid}"))
                .unique_info(pid)
        })
    }

    fn short_bsd(&self, pid: RawPid) -> Result<libc::proc_bsdshortinfo, ReadErr> {
        self.short_bsds.take(&pid).unwrap_or_else(|| {
            self.real(format_args!("a short BSD-info read of pid {pid}"))
                .short_bsd(pid)
        })
    }

    fn bsd_info(&self, pid: RawPid) -> Result<libc::proc_bsdinfo, ReadErr> {
        self.bsd_infos
            .take(&pid)
            .unwrap_or_else(|| self.real(format_args!("a BSD-info read of pid {pid}")).bsd_info(pid))
    }

    fn kinfo(&self, pid: RawPid) -> KinfoAnswer {
        self.kinfos
            .take(&pid)
            .unwrap_or_else(|| self.real(format_args!("a kinfo_proc read of pid {pid}")).kinfo(pid))
    }

    fn subscribe(&self, kq: &Kqueue, what: Subscription) -> io::Result<()> {
        match self.subscribes.take(&what) {
            Some(Ok(())) => Ok(()),
            Some(Err(errno)) => Err(io::Error::from_raw_os_error(errno)),
            None => self.real(format_args!("the registration {what:?}")).subscribe(kq, what),
        }
    }
}

/// A short BSD-info record that states a parent and a state, and nothing else.
pub(crate) fn short_info(ppid: u32, status: u32) -> libc::proc_bsdshortinfo {
    // SAFETY: all-zero is a valid `proc_bsdshortinfo`.
    let mut info: libc::proc_bsdshortinfo = unsafe { std::mem::zeroed() };
    info.pbsi_ppid = ppid;
    info.pbsi_status = status;
    info
}
