//! A stated-facts [`Kernel`]: the answers its tables hold, and nothing the kernel would do. A call
//! with no row left panics, except under [`FakeKernel::over`], which passes it to the real kernel.
//!
//! A row answers one call for one pid, or for one [`Subscription`]. The rows of a call kind are
//! taken in the order they were stated, the first one for what is asked about, and each answers
//! once. A peek row never answers a consume. An `on_every_*` row answers every call of its kind
//! for its pid that no other row answers.

use std::fmt::Arguments;
use std::io;
use std::sync::{Arc, Mutex};

use super::Kernel;
use crate::identity::kinfo::kinfo_proc;
use crate::identity::{RawPid, ReadErr, Record, Resolved, UniqRead};
use crate::os_process::macos::kqueue::{Kqueue, Subscription};

/// The rows of one call kind: what each answers for, and the answer. A row answers once; an
/// `every` row answers each call no row of the kind answers.
struct Rows<A, T> {
    once: Mutex<Vec<(A, T)>>,
    every: Mutex<Vec<(A, EveryAnswer<T>)>>,
}

/// What an `every` row makes at each call it answers.
type EveryAnswer<T> = Arc<dyn Fn() -> T + Send + Sync>;

impl<A: PartialEq, T> Rows<A, T> {
    fn new() -> Self {
        Rows {
            once: Mutex::new(Vec::new()),
            every: Mutex::new(Vec::new()),
        }
    }

    /// Adds a row. Through a shared reference, so a row can be stated after the kernel is shared.
    fn push(&self, asked: A, answer: T) {
        self.once
            .lock()
            .expect("no thread panics holding the rows")
            .push((asked, answer));
    }

    /// Adds an `every` row for `asked`, in place of the one it had.
    fn push_every(&self, asked: A, answer: impl Fn() -> T + Send + Sync + 'static) {
        let mut rows = self.every.lock().expect("no thread panics holding the rows");
        rows.retain(|(row, _)| *row != asked);
        rows.push((asked, Arc::new(answer)));
    }

    /// Whether every once row has answered. An `every` row is never left over.
    fn spent(&self) -> bool {
        self.once.lock().expect("no thread panics holding the rows").is_empty()
    }

    /// The first row for `asked`, which it removes; else the first `every` row for it. An `every`
    /// answer runs with no lock held, so one that panics or takes rows itself leaves the rows usable.
    fn take(&self, asked: &A) -> Option<T> {
        {
            let mut rows = self.once.lock().expect("no thread panics holding the rows");
            if let Some(at) = rows.iter().position(|(row, _)| row == asked) {
                return Some(rows.remove(at).1);
            }
        }
        let answer = self
            .every
            .lock()
            .expect("no thread panics holding the rows")
            .iter()
            .find(|(row, _)| row == asked)
            .map(|(_, answer)| Arc::clone(answer))?;
        Some(answer())
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
    /// `Err`: the listing fails with this errno. `Ok`: the pids it lists.
    pids: Rows<(), Result<Vec<libc::c_int>, i32>>,
    peek_reads: Mutex<Vec<(RawPid, usize)>>,
    /// How many `kinfo_proc` reads each pid has had, whoever answered them.
    kinfo_reads: Mutex<Vec<(RawPid, usize)>>,
    /// How many unique-id reads each pid has had, whoever answered them.
    unique_info_reads: Mutex<Vec<(RawPid, usize)>>,
    /// How many BSD-info reads each pid has had, whoever answered them.
    bsd_info_reads: Mutex<Vec<(RawPid, usize)>>,
}

/// Counts one more read of `pid` in `counts`.
fn count_read(counts: &Mutex<Vec<(RawPid, usize)>>, pid: RawPid) {
    let mut counts = counts.lock().expect("no panic holds the counts");
    match counts.iter_mut().find(|(p, _)| *p == pid) {
        Some((_, n)) => *n += 1,
        None => counts.push((pid, 1)),
    }
}

/// How many reads of `pid` `counts` holds.
fn reads_of(counts: &Mutex<Vec<(RawPid, usize)>>, pid: RawPid) -> usize {
    let counts = counts.lock().expect("no panic holds the counts");
    counts.iter().find(|(p, _)| *p == pid).map_or(0, |(_, n)| *n)
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
            pids: Rows::new(),
            peek_reads: Mutex::new(Vec::new()),
            kinfo_reads: Mutex::new(Vec::new()),
            unique_info_reads: Mutex::new(Vec::new()),
            bsd_info_reads: Mutex::new(Vec::new()),
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
    pub(crate) fn on_peek(self, pid: u32, answer: io::Result<Option<Record>>) -> Self {
        self.state_peek(pid, answer);
        self
    }

    /// [`on_peek`](Self::on_peek) after the kernel is shared: for a child whose pid the test learns
    /// only once the spawn under test has made it.
    pub(crate) fn state_peek(&self, pid: u32, answer: io::Result<Option<Record>>) {
        self.peeks.push(pid, answer);
    }

    /// Every peek of `pid` that no row answers answers what `answer` makes. A second such row for
    /// `pid` replaces the first.
    pub(crate) fn on_every_peek(
        self,
        pid: u32,
        answer: impl Fn() -> io::Result<Option<Record>> + Send + Sync + 'static,
    ) -> Self {
        self.state_every_peek(pid, answer);
        self
    }

    /// [`on_every_peek`](Self::on_every_peek) after the kernel is shared.
    pub(crate) fn state_every_peek(
        &self,
        pid: u32,
        answer: impl Fn() -> io::Result<Option<Record>> + Send + Sync + 'static,
    ) {
        self.peeks.push_every(pid, answer);
    }

    /// The next consume of `pid` answers `answer`, and takes nothing from the real process.
    pub(crate) fn on_consume(self, pid: u32, answer: io::Result<Option<Record>>) -> Self {
        self.consumes.push(pid, answer);
        self
    }

    /// The next unique-id read of `pid` answers `answer`.
    pub(crate) fn on_unique_info(self, pid: RawPid, answer: UniqRead) -> Self {
        self.state_unique_info(pid, answer);
        self
    }

    /// [`on_unique_info`](Self::on_unique_info) after the kernel is shared. A test that cannot name
    /// a pid beforehand (a spawned child's) states the row from the spawn hook that knows it.
    pub(crate) fn state_unique_info(&self, pid: RawPid, answer: UniqRead) {
        self.unique_infos.push(pid, answer);
    }

    /// The next short BSD-info read of `pid` answers `answer`.
    pub(crate) fn on_short_bsd(self, pid: RawPid, answer: Result<libc::proc_bsdshortinfo, ReadErr>) -> Self {
        self.state_short_bsd(pid, answer);
        self
    }

    /// [`on_short_bsd`](Self::on_short_bsd) after the kernel is shared; see
    /// [`state_unique_info`](Self::state_unique_info).
    pub(crate) fn state_short_bsd(&self, pid: RawPid, answer: Result<libc::proc_bsdshortinfo, ReadErr>) {
        self.short_bsds.push(pid, answer);
    }

    /// Every short BSD-info read of `pid` that no row answers answers what `answer` says at that
    /// read: a parent that changes while the test runs is a value the test changes, not an order of
    /// reads. A second such row for `pid` replaces the first.
    pub(crate) fn on_every_short_bsd(
        self,
        pid: RawPid,
        answer: impl Fn() -> Result<libc::proc_bsdshortinfo, ReadErr> + Send + Sync + 'static,
    ) -> Self {
        self.state_every_short_bsd(pid, answer);
        self
    }

    /// [`on_every_short_bsd`](Self::on_every_short_bsd) after the kernel is shared; see
    /// [`state_unique_info`](Self::state_unique_info).
    pub(crate) fn state_every_short_bsd(
        &self,
        pid: RawPid,
        answer: impl Fn() -> Result<libc::proc_bsdshortinfo, ReadErr> + Send + Sync + 'static,
    ) {
        self.short_bsds.push_every(pid, answer);
    }

    /// The next BSD-info read of `pid` answers `answer`.
    pub(crate) fn on_bsd_info(self, pid: RawPid, answer: Result<libc::proc_bsdinfo, ReadErr>) -> Self {
        self.bsd_infos.push(pid, answer);
        self
    }

    /// The next `kinfo_proc` read of `pid` finds `record`.
    pub(crate) fn on_kinfo(self, pid: RawPid, record: kinfo_proc) -> Self {
        self.kinfos.push(pid, (Resolved::Found(record), None));
        self
    }

    /// Every `kinfo_proc` read of `pid` that no row answers finds what `record` makes at that read:
    /// the parents a tracer's attach and its exit change are values the test changes.
    pub(crate) fn on_every_kinfo(self, pid: RawPid, record: impl Fn() -> kinfo_proc + Send + Sync + 'static) -> Self {
        self.kinfos.push_every(pid, move || (Resolved::Found(record()), None));
        self
    }

    /// The next `kinfo_proc` read of `pid` is refused with `errno`.
    pub(crate) fn on_kinfo_refused(self, pid: RawPid, errno: i32) -> Self {
        self.kinfos
            .push(pid, (Resolved::Unknown, Some(io::Error::from_raw_os_error(errno))));
        self
    }

    /// Every unique-id read of `pid` that no row answers answers what `answer` says at that read, so
    /// a test that reads from two threads states what each sees, not an order of reads.
    pub(crate) fn on_every_unique_info(
        self,
        pid: RawPid,
        answer: impl Fn() -> UniqRead + Send + Sync + 'static,
    ) -> Self {
        self.unique_infos.push_every(pid, answer);
        self
    }

    /// Every BSD-info read of `pid` that no row answers fails with `error`.
    pub(crate) fn on_every_bsd_info_failing(self, pid: RawPid, error: ReadErr) -> Self {
        self.bsd_infos.push_every(pid, move || Err(error));
        self
    }

    /// Every `kinfo_proc` read of `pid` that no row answers is refused with `errno`.
    pub(crate) fn on_every_kinfo_refused(self, pid: RawPid, errno: i32) -> Self {
        self.kinfos.push_every(pid, move || {
            (Resolved::Unknown, Some(io::Error::from_raw_os_error(errno)))
        });
        self
    }

    /// The next record read of `pid` is refused on both paths, as for a cross-user process in a
    /// sandbox: its `proc_pidinfo` is refused (`EPERM`) and so is the sysctl it falls back to, which
    /// leaves the record `Unknown`. The record is the one behind a pid's parent and its identity. Every
    /// such read, not the next only, is [`unreadable`](crate::identity::unreadable)'s.
    pub(crate) fn on_record_refused(self, pid: RawPid) -> Self {
        self.on_bsd_info(pid, Err(ReadErr::Refused(libc::EPERM)))
            .on_kinfo_refused(pid, libc::EPERM)
    }

    /// The next registration `what` is made and never fires.
    pub(crate) fn on_subscribe(self, what: Subscription) -> Self {
        self.subscribes.push(what, Ok(()));
        self
    }

    /// The next registration `what` is refused with `errno` (a pid past `P_REF_DEAD` answers `ESRCH`).
    pub(crate) fn on_subscribe_refused(self, what: Subscription, errno: i32) -> Self {
        self.subscribes.push(what, Err(errno));
        self
    }

    /// The next pid listing answers `answer`: the pids, or the errno it fails with. One row answers one
    /// listing; a sweep that lists twice is stated twice.
    pub(crate) fn on_pids(self, answer: Result<&[libc::c_int], i32>) -> Self {
        self.state_pids(answer);
        self
    }

    /// [`on_pids`](Self::on_pids) after the kernel is shared; see
    /// [`state_unique_info`](Self::state_unique_info).
    pub(crate) fn state_pids(&self, answer: Result<&[libc::c_int], i32>) {
        self.pids.push((), answer.map(<[libc::c_int]>::to_vec));
    }

    /// How many peeks of `pid` the kernel has been asked for, whoever answered them.
    pub(crate) fn peek_reads(&self, pid: u32) -> usize {
        reads_of(&self.peek_reads, pid)
    }

    /// How many `kinfo_proc` reads of `pid` the kernel has been asked for.
    pub(crate) fn kinfo_reads(&self, pid: RawPid) -> usize {
        reads_of(&self.kinfo_reads, pid)
    }

    /// How many unique-id reads of `pid` the kernel has been asked for.
    pub(crate) fn unique_info_reads(&self, pid: RawPid) -> usize {
        reads_of(&self.unique_info_reads, pid)
    }

    /// How many BSD-info reads of `pid` the kernel has been asked for.
    pub(crate) fn bsd_info_reads(&self, pid: RawPid) -> usize {
        reads_of(&self.bsd_info_reads, pid)
    }

    /// How many times the kernel has been asked for the record of `pid`: by pid, whichever way an
    /// identity is read (BSD info, else `kinfo_proc`).
    pub(crate) fn record_reads(&self, pid: RawPid) -> usize {
        self.bsd_info_reads(pid) + self.kinfo_reads(pid)
    }

    /// [`record_reads`](Self::record_reads) of every pid together.
    pub(crate) fn all_record_reads(&self) -> usize {
        let total = |counts: &Mutex<Vec<(RawPid, usize)>>| {
            let counts = counts.lock().expect("no panic holds the counts");
            counts.iter().map(|(_, n)| n).sum::<usize>()
        };
        total(&self.bsd_info_reads) + total(&self.kinfo_reads)
    }

    /// Whether every row stated for one call has answered it, `on_every_*` rows aside. A row left
    /// over is a call the test expected and the code never made, or made in another order.
    pub(crate) fn all_rows_taken(&self) -> bool {
        self.peeks.spent()
            && self.consumes.spent()
            && self.unique_infos.spent()
            && self.short_bsds.spent()
            && self.bsd_infos.spent()
            && self.kinfos.spent()
            && self.subscribes.spent()
            && self.pids.spent()
    }

    /// The kernel that answers a call no row answers; `asked` says what the call was.
    fn real(&self, asked: Arguments<'_>) -> &'a dyn Kernel {
        self.real
            .unwrap_or_else(|| panic!("the fake kernel has no row left for {asked}"))
    }
}

impl Kernel for FakeKernel<'_> {
    fn peek(&self, pid: u32) -> io::Result<Option<Record>> {
        count_read(&self.peek_reads, pid);
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
        count_read(&self.unique_info_reads, pid);
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
        count_read(&self.bsd_info_reads, pid);
        self.bsd_infos
            .take(&pid)
            .unwrap_or_else(|| self.real(format_args!("a BSD-info read of pid {pid}")).bsd_info(pid))
    }

    fn kinfo(&self, pid: RawPid) -> KinfoAnswer {
        count_read(&self.kinfo_reads, pid);
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

    fn pids(&self) -> io::Result<Vec<libc::c_int>> {
        match self.pids.take(&()) {
            Some(answer) => answer.map_err(io::Error::from_raw_os_error),
            None => self.real(format_args!("a pid listing")).pids(),
        }
    }
}

/// The `waitid` record of a child that exited with `status`.
pub(crate) fn exit_record(status: i32) -> Record {
    Record {
        si_code: libc::CLD_EXITED,
        si_status: status,
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

/// The host's short BSD info of the live process `pid`, stating only that `ppid` holds it: its state
/// stays the host's, so a read of the state is not answered by the test.
pub(crate) fn short_info_held_by(pid: RawPid, ppid: u32) -> libc::proc_bsdshortinfo {
    let mut info = super::HostKernel
        .short_bsd(pid)
        .unwrap_or_else(|e| panic!("pid {pid} is live and has a short BSD info: {e:?}"));
    info.pbsi_ppid = ppid;
    info
}
