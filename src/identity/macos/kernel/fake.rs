//! A stated-facts [`Kernel`]: the answers its tables hold, and nothing the kernel would do. A call
//! with no row left panics, except under [`FakeKernel::over`], which passes it to the real kernel.
//!
//! A row answers one call for one pid. The rows of a call kind are taken in the order they were
//! stated, the first one for the pid asked about, and each answers once. A peek row never answers a
//! consume.

use std::io;
use std::sync::Mutex;

use super::Kernel;
use crate::identity::kinfo::kinfo_proc;
use crate::identity::{RawPid, ReadErr, Record, Resolved, UniqRead};
use crate::os_process::macos::kqueue::{Kqueue, Subscription};

/// The rows of one call kind: the pid each answers for, and the answer.
struct Rows<T>(Mutex<Vec<(u32, T)>>);

impl<T> Rows<T> {
    fn new() -> Self {
        Rows(Mutex::new(Vec::new()))
    }

    fn push(&mut self, pid: u32, answer: T) {
        self.0.get_mut().expect("no thread holds the rows").push((pid, answer));
    }

    /// The first row for `pid`, which it removes.
    fn take(&self, pid: u32) -> Option<T> {
        let mut rows = self.0.lock().expect("no thread panics holding the rows");
        let at = rows.iter().position(|(row, _)| *row == pid)?;
        Some(rows.remove(at).1)
    }
}

pub(crate) struct FakeKernel<'a> {
    /// What answers a call the rows have nothing for. `None`: such a call panics.
    real: Option<&'a dyn Kernel>,
    peeks: Rows<io::Result<Option<Record>>>,
    consumes: Rows<io::Result<Option<Record>>>,
    unique_infos: Rows<UniqRead>,
    short_bsds: Rows<Result<libc::proc_bsdshortinfo, ReadErr>>,
    bsd_infos: Rows<Result<libc::proc_bsdinfo, ReadErr>>,
    kinfos: Rows<Resolved<kinfo_proc>>,
    /// `Err`: the registration is refused with this errno. `Ok`: it is made and never fires.
    subscribes: Rows<Result<(), i32>>,
}

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

    /// The next peek of `pid` without a row before it answers `answer`.
    pub(crate) fn on_peek(mut self, pid: u32, answer: io::Result<Option<Record>>) -> Self {
        self.peeks.push(pid, answer);
        self
    }

    /// The next consume of `pid` without a row before it answers `answer`.
    pub(crate) fn on_consume(mut self, pid: u32, answer: io::Result<Option<Record>>) -> Self {
        self.consumes.push(pid, answer);
        self
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

    /// The next `kinfo_proc` read of `pid` without a row before it answers `answer`.
    pub(crate) fn on_kinfo(mut self, pid: RawPid, answer: Resolved<kinfo_proc>) -> Self {
        self.kinfos.push(pid, answer);
        self
    }

    /// The next registration for process `pid` without a row before it is refused with `errno`, as
    /// `ESRCH` refuses one past `P_REF_DEAD`.
    pub(crate) fn on_subscribe_refused(mut self, pid: u32, errno: i32) -> Self {
        self.subscribes.push(pid, Err(errno));
        self
    }

    /// The next registration for process `pid` without a row before it is accepted and never
    /// fires: nothing is registered on the queue.
    pub(crate) fn on_subscribe_silent(mut self, pid: u32) -> Self {
        self.subscribes.push(pid, Ok(()));
        self
    }

    /// The kernel that answers a call no row answers.
    fn real(&self, call: &str, pid: u32) -> &'a dyn Kernel {
        self.real
            .unwrap_or_else(|| panic!("the fake kernel has no row left for {call} of pid {pid}"))
    }
}

impl Kernel for FakeKernel<'_> {
    fn peek(&self, pid: u32) -> io::Result<Option<Record>> {
        self.peeks.take(pid).unwrap_or_else(|| self.real("peek", pid).peek(pid))
    }

    fn consume(&self, pid: u32) -> io::Result<Option<Record>> {
        self.consumes
            .take(pid)
            .unwrap_or_else(|| self.real("consume", pid).consume(pid))
    }

    fn unique_info(&self, pid: RawPid) -> UniqRead {
        self.unique_infos
            .take(pid)
            .unwrap_or_else(|| self.real("unique_info", pid).unique_info(pid))
    }

    fn short_bsd(&self, pid: RawPid) -> Result<libc::proc_bsdshortinfo, ReadErr> {
        self.short_bsds
            .take(pid)
            .unwrap_or_else(|| self.real("short_bsd", pid).short_bsd(pid))
    }

    fn bsd_info(&self, pid: RawPid) -> Result<libc::proc_bsdinfo, ReadErr> {
        self.bsd_infos
            .take(pid)
            .unwrap_or_else(|| self.real("bsd_info", pid).bsd_info(pid))
    }

    fn kinfo(&self, pid: RawPid) -> Resolved<kinfo_proc> {
        self.kinfos
            .take(pid)
            .unwrap_or_else(|| self.real("kinfo", pid).kinfo(pid))
    }

    fn subscribe(&self, kq: &Kqueue, what: Subscription) -> io::Result<()> {
        let Subscription::Process { pid, .. } = what else {
            return self.real("subscribe", 0).subscribe(kq, what);
        };
        match self.subscribes.take(pid) {
            Some(Ok(())) => Ok(()),
            Some(Err(errno)) => Err(io::Error::from_raw_os_error(errno)),
            None => self.real("subscribe", pid).subscribe(kq, what),
        }
    }
}
