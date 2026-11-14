//! A stated-facts [`Kernel`]: the answers its tables hold, and nothing the kernel would do. A call
//! with no row left panics, except under [`FakeKernel::over`], which passes it to the real kernel.
//!
//! A row answers one call for one pid, or for one [`Subscription`]. The rows of a call kind are
//! taken in the order they were stated, the first one for what is asked about, and each answers
//! once. A peek row never answers a consume. An `on_every_*` row answers every call of its kind
//! for its pid that no other row answers.

use std::fmt::Arguments;
use std::io;
use std::sync::Mutex;

use super::Kernel;
use crate::identity::kinfo::kinfo_proc;
use crate::identity::{RawPid, ReadErr, Record, Resolved, UniqRead};
use crate::os_process::macos::kqueue::{Kqueue, Subscription};

/// The rows of one call kind: what each answers for, and the answer. A row answers once; an
/// `every` row answers each call no row of the kind answers.
struct Rows<A, T> {
    once: Mutex<Vec<(A, T)>>,
    every: Vec<(A, Box<dyn Fn() -> T + Send + Sync>)>,
}

impl<A: PartialEq, T> Rows<A, T> {
    fn new() -> Self {
        Rows {
            once: Mutex::new(Vec::new()),
            every: Vec::new(),
        }
    }

    fn push(&mut self, asked: A, answer: T) {
        self.once
            .get_mut()
            .expect("no thread holds the rows")
            .push((asked, answer));
    }

    fn push_every(&mut self, asked: A, answer: impl Fn() -> T + Send + Sync + 'static) {
        self.every.push((asked, Box::new(answer)));
    }

    /// The first row for `asked`, which it removes; else the first `every` row for it.
    fn take(&self, asked: &A) -> Option<T> {
        let mut rows = self.once.lock().expect("no thread panics holding the rows");
        if let Some(at) = rows.iter().position(|(row, _)| row == asked) {
            return Some(rows.remove(at).1);
        }
        self.every
            .iter()
            .find(|(row, _)| row == asked)
            .map(|(_, answer)| answer())
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
    /// How many `kinfo_proc` reads each pid has had, whoever answered them.
    kinfo_reads: Mutex<Vec<(RawPid, usize)>>,
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
            kinfo_reads: Mutex::new(Vec::new()),
        }
    }

    /// A kernel that answers its rows and passes every other call to `real`.
    pub(crate) fn over(real: &'a dyn Kernel) -> Self {
        FakeKernel {
            real: Some(real),
            ..Self::new()
        }
    }

    /// The next peek of `pid` answers `answer`: `Ok(None)` is a child that has not exited.
    pub(crate) fn on_peek(mut self, pid: u32, answer: io::Result<Option<Record>>) -> Self {
        self.peeks.push(pid, answer);
        self
    }

    /// The next consume of `pid` answers `answer`, and takes nothing from the real process.
    pub(crate) fn on_consume(mut self, pid: u32, answer: io::Result<Option<Record>>) -> Self {
        self.consumes.push(pid, answer);
        self
    }

    /// Every peek of `pid` that no row answers answers what `answer` says at that peek.
    pub(crate) fn on_every_peek(
        mut self,
        pid: u32,
        answer: impl Fn() -> io::Result<Option<Record>> + Send + Sync + 'static,
    ) -> Self {
        self.peeks.push_every(pid, answer);
        self
    }

    /// The next unique-id read of `pid` answers `answer`.
    pub(crate) fn on_unique_info(mut self, pid: RawPid, answer: UniqRead) -> Self {
        self.unique_infos.push(pid, answer);
        self
    }

    /// The next short BSD-info read of `pid` answers `answer`.
    pub(crate) fn on_short_bsd(mut self, pid: RawPid, answer: Result<libc::proc_bsdshortinfo, ReadErr>) -> Self {
        self.short_bsds.push(pid, answer);
        self
    }

    /// The next BSD-info read of `pid` answers `answer`.
    pub(crate) fn on_bsd_info(mut self, pid: RawPid, answer: Result<libc::proc_bsdinfo, ReadErr>) -> Self {
        self.bsd_infos.push(pid, answer);
        self
    }

    /// The next `kinfo_proc` read of `pid` finds `record`.
    pub(crate) fn on_kinfo(mut self, pid: RawPid, record: kinfo_proc) -> Self {
        self.kinfos.push(pid, (Resolved::Found(record), None));
        self
    }

    /// The next `kinfo_proc` read of `pid` is refused with `errno`.
    pub(crate) fn on_kinfo_refused(mut self, pid: RawPid, errno: i32) -> Self {
        self.kinfos
            .push(pid, (Resolved::Unknown, Some(io::Error::from_raw_os_error(errno))));
        self
    }

    /// Every unique-id read of `pid` that no row answers answers what `answer` says at that read, so
    /// a test that reads from two threads states what each sees, not an order of reads.
    pub(crate) fn on_every_unique_info(
        mut self,
        pid: RawPid,
        answer: impl Fn() -> UniqRead + Send + Sync + 'static,
    ) -> Self {
        self.unique_infos.push_every(pid, answer);
        self
    }

    /// Every BSD-info read of `pid` that no row answers fails with `error`.
    pub(crate) fn on_every_bsd_info_failing(mut self, pid: RawPid, error: ReadErr) -> Self {
        self.bsd_infos.push_every(pid, move || Err(error));
        self
    }

    /// Every `kinfo_proc` read of `pid` that no row answers is refused with `errno`.
    pub(crate) fn on_every_kinfo_refused(mut self, pid: RawPid, errno: i32) -> Self {
        self.kinfos.push_every(pid, move || {
            (Resolved::Unknown, Some(io::Error::from_raw_os_error(errno)))
        });
        self
    }

    /// The next registration `what` is made and never fires.
    pub(crate) fn on_subscribe(mut self, what: Subscription) -> Self {
        self.subscribes.push(what, Ok(()));
        self
    }

    /// How many `kinfo_proc` reads of `pid` the kernel has been asked for.
    pub(crate) fn kinfo_reads(&self, pid: RawPid) -> usize {
        let counts = self.kinfo_reads.lock().expect("no panic holds the counts");
        counts.iter().find(|(p, _)| *p == pid).map_or(0, |(_, n)| *n)
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
        {
            let mut counts = self.kinfo_reads.lock().expect("no panic holds the counts");
            match counts.iter_mut().find(|(p, _)| *p == pid) {
                Some((_, n)) => *n += 1,
                None => counts.push((pid, 1)),
            }
        }
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
