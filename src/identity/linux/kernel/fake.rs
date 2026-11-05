//! A stated-facts [`Kernel`]: the answers its tables hold, and nothing the kernel would do. A call
//! with no row panics, except under [`FakeKernel::over`], which passes it to the real kernel.
//!
//! Rows are plain data: a path or pid is looked up by `==`, and a later row replaces an earlier one.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::sync::Mutex;

use rustix::io::Errno;
use rustix::process::{Pid, PidfdFlags};

use super::Kernel;
use crate::identity::{ProcDir, ViewUnreadable};

pub(crate) struct FakeKernel<'a> {
    /// What answers a call the tables have nothing for. `None`: such a call panics.
    real: Option<&'a dyn Kernel>,
    open_proc: Option<Errno>,
    /// A path, the number of earlier reads of it before the row answers, and the answer. `Err` is a
    /// raw errno.
    reads: Vec<(String, usize, Result<Vec<u8>, i32>)>,
    /// How many times each path has been read.
    read_counts: Mutex<Vec<(String, usize)>>,
    /// The listing of any `/proc`: the pids, or a raw errno.
    pids: Option<Result<Vec<u32>, i32>>,
    signal_probes: Vec<(Pid, Result<(), Errno>)>,
    /// A pid, the flags the row answers (`None`: any), and the answer.
    pidfd_opens: Vec<(Pid, Option<PidfdFlags>, PidfdRow)>,
    /// A pid, the path whose earlier read the row waits for (`None`: no wait), and the answer.
    pidfs_inos: Vec<PidfsRow>,
    /// The descriptors this kernel has handed out, so that `pidfs_ino` can tell whose they are.
    opened: Mutex<Vec<Opened>>,
}

/// A `pidfs_ino` row: the pid, the path whose earlier read it waits for, and the answer.
type PidfsRow = (Pid, Option<String>, Result<Option<u64>, Errno>);

/// A pidfd this kernel opened: its number, the pid, and how many times each path had been read then.
struct Opened {
    fd: RawFd,
    pid: Pid,
    reads: Vec<(String, usize)>,
}

/// What a `pidfd_open` row answers, on every call.
enum PidfdRow {
    Errno(Errno),
    /// The first call hands out the test's own fd, whose number the test may have stated rows
    /// about; each later one a duplicate of it.
    Fd {
        first: Mutex<Option<OwnedFd>>,
        spare: OwnedFd,
    },
}

impl<'a> FakeKernel<'a> {
    /// A kernel with no rows.
    pub(crate) fn new() -> Self {
        FakeKernel {
            real: None,
            open_proc: None,
            reads: Vec::new(),
            read_counts: Mutex::new(Vec::new()),
            pids: None,
            signal_probes: Vec::new(),
            pidfd_opens: Vec::new(),
            pidfs_inos: Vec::new(),
            opened: Mutex::new(Vec::new()),
        }
    }

    /// A kernel that answers its rows and passes every other call to `real`.
    pub(crate) fn over(real: &'a dyn Kernel) -> Self {
        FakeKernel {
            real: Some(real),
            ..Self::new()
        }
    }

    /// A kernel over `real` whose `/proc` is this namespace's own and lists `pid` alone, and whose
    /// `stat` read of it fails with the raw `errno`: what a whole-table scan meets in one pid.
    pub(crate) fn listing_unreadable_pid(real: &'a dyn Kernel, pid: u32, errno: i32) -> Self {
        Self::over(real)
            .same_view()
            .on_pids(Ok(&[pid]))
            .on_read(&format!("{pid}/stat"), Err(errno))
    }

    /// Reading `path` under any `/proc` answers `answer`: the bytes, or a raw errno.
    pub(crate) fn on_read(self, path: &str, answer: Result<&[u8], i32>) -> Self {
        self.on_read_after(path, 0, answer)
    }

    /// From the read of `path` that follows `earlier_reads` reads of it, answers `answer`. Of the
    /// rows whose count has been reached, the one with the highest count wins.
    pub(crate) fn on_read_after(mut self, path: &str, earlier_reads: usize, answer: Result<&[u8], i32>) -> Self {
        self.reads
            .push((path.to_owned(), earlier_reads, answer.map(<[u8]>::to_vec)));
        self
    }

    /// Listing any `/proc` answers `answer`: the pids, or a raw errno.
    pub(crate) fn on_pids(mut self, answer: Result<&[u32], i32>) -> Self {
        self.pids = Some(answer.map(<[u32]>::to_vec));
        self
    }

    /// `self/status` shows the pid in one namespace: `/proc` is this namespace's own.
    pub(crate) fn same_view(self) -> Self {
        self.on_read("self/status", Ok(b"NSpid:\t4242\n"))
    }

    /// `self/status` shows the pid in two namespaces: `/proc` is an outer namespace's.
    pub(crate) fn diverged_view(self) -> Self {
        self.diverged_view_after(0)
    }

    /// [`diverged_view`](Self::diverged_view) from the read of `self/status` that follows
    /// `earlier_reads` reads of it.
    pub(crate) fn diverged_view_after(self, earlier_reads: usize) -> Self {
        self.on_read_after("self/status", earlier_reads, Ok(b"NSpid:\t4242\t1\n"))
    }

    /// `self/status` cannot be read (`EIO`).
    pub(crate) fn unreadable_view(self) -> Self {
        self.unreadable_view_after(0)
    }

    /// [`unreadable_view`](Self::unreadable_view) from the read of `self/status` that follows
    /// `earlier_reads` reads of it.
    pub(crate) fn unreadable_view_after(self, earlier_reads: usize) -> Self {
        self.on_read_after("self/status", earlier_reads, Err(libc::EIO))
    }

    /// `kill(target, 0)` answers `answer`.
    pub(crate) fn on_signal_probe(mut self, target: Pid, answer: Result<(), Errno>) -> Self {
        self.signal_probes.push((target, answer));
        self
    }

    /// `pidfd_open` of `pid`, with any flags, answers `answer` on every call. An fd the test opened
    /// itself is handed out as it is on the first call, and as a duplicate of it on each later one.
    pub(crate) fn on_pidfd_open(self, pid: u32, answer: Result<OwnedFd, Errno>) -> Self {
        self.pidfd_open_row(pid, None, answer)
    }

    /// [`on_pidfd_open`](Self::on_pidfd_open) for opens with exactly `flags`.
    pub(crate) fn on_pidfd_open_flags(self, pid: u32, flags: PidfdFlags, answer: Result<OwnedFd, Errno>) -> Self {
        self.pidfd_open_row(pid, Some(flags), answer)
    }

    fn pidfd_open_row(mut self, pid: u32, flags: Option<PidfdFlags>, answer: Result<OwnedFd, Errno>) -> Self {
        let target = Self::target(pid);
        let row = match answer {
            Ok(fd) => PidfdRow::Fd {
                spare: fd.try_clone().expect("the row's fd duplicates"),
                first: Mutex::new(Some(fd)),
            },
            Err(errno) => PidfdRow::Errno(errno),
        };
        self.pidfd_opens.push((target, flags, row));
        self
    }

    /// A pidfd this kernel opened for `pid` has `pidfs_ino` `answer`: `Some(inode)` on pidfs, `None`
    /// on a kernel whose pidfds have none, or an errno.
    pub(crate) fn on_pidfs_ino(mut self, pid: u32, answer: Result<Option<u64>, Errno>) -> Self {
        self.pidfs_inos.push((Self::target(pid), None, answer));
        self
    }

    /// [`on_pidfs_ino`](Self::on_pidfs_ino) for the pidfds of `pid` opened after `path` was read
    /// once: from then on this row answers in place of the plain one.
    pub(crate) fn on_pidfs_ino_after_read(mut self, pid: u32, path: &str, answer: Result<Option<u64>, Errno>) -> Self {
        self.pidfs_inos.push((Self::target(pid), Some(path.to_owned()), answer));
        self
    }

    /// Live `pid` on a host before Linux 6.9: its pidfd opens (as a stand-in descriptor) and has no
    /// inode of its own, so the process is told by its `/proc` `starttime`. Rows of its own that
    /// follow replace these.
    pub(crate) fn live_without_pidfs(self, pid: u32) -> Self {
        let stand_in = OwnedFd::from(std::fs::File::open("/dev/null").expect("/dev/null opens"));
        self.on_pidfd_open(pid, Ok(stand_in)).on_pidfs_ino(pid, Ok(None))
    }

    fn target(pid: u32) -> Pid {
        Pid::from_raw(pid as i32).expect("a row names a positive pid")
    }

    /// Opening `/proc` fails as its `openat2` answering `errno`.
    pub(crate) fn open_proc_fails(mut self, errno: Errno) -> Self {
        self.open_proc = Some(errno);
        self
    }

    /// Notes a read of `path` and returns how many reads of it came before.
    fn count_read(&self, path: &str) -> usize {
        let mut counts = self.read_counts.lock().expect("no panic holds the counts");
        match counts.iter_mut().find(|(p, _)| p == path) {
            Some((_, n)) => {
                *n += 1;
                *n - 1
            }
            None => {
                counts.push((path.to_owned(), 1));
                0
            }
        }
    }

    fn real(&self, call: &str) -> &'a dyn Kernel {
        self.real.unwrap_or_else(|| panic!("FakeKernel has no row for {call}"))
    }
}

impl Kernel for FakeKernel<'_> {
    fn pidfd_open(&self, target: Pid, flags: PidfdFlags) -> Result<OwnedFd, Errno> {
        let row = self
            .pidfd_opens
            .iter()
            .rev()
            .find(|(p, row_flags, _)| *p == target && row_flags.is_none_or(|f| f == flags));
        let opened = match row {
            Some((_, _, PidfdRow::Errno(errno))) => return Err(*errno),
            Some((_, _, PidfdRow::Fd { first, spare })) => {
                let first = first.lock().expect("no panic holds the row").take();
                first.unwrap_or_else(|| spare.try_clone().expect("the row's fd duplicates"))
            }
            None => self
                .real(&format!("pidfd_open of {target:?}"))
                .pidfd_open(target, flags)?,
        };
        let reads = self.read_counts.lock().expect("no panic holds the counts").clone();
        self.opened.lock().expect("no panic holds the opens").push(Opened {
            fd: opened.as_raw_fd(),
            pid: target,
            reads,
        });
        Ok(opened)
    }

    fn pidfs_ino(&self, fd: BorrowedFd<'_>) -> Result<Option<u64>, Errno> {
        let raw = fd.as_raw_fd();
        let opened = self.opened.lock().expect("no panic holds the opens");
        let Some(open) = opened.iter().rev().find(|o| o.fd == raw) else {
            return self.real("pidfs_ino of a descriptor it did not open").pidfs_ino(fd);
        };
        let read_before_open = |path: &str| open.reads.iter().any(|(p, n)| p == path && *n > 0);
        let rows = || self.pidfs_inos.iter().rev().filter(|(p, _, _)| *p == open.pid);
        let row = rows()
            .find(|(_, after, _)| after.as_deref().is_some_and(read_before_open))
            .or_else(|| rows().find(|(_, after, _)| after.is_none()));
        match row {
            Some((_, _, answer)) => *answer,
            None => self.real(&format!("pidfs_ino of {:?}", open.pid)).pidfs_ino(fd),
        }
    }

    fn open_proc(&self) -> Result<ProcDir, ViewUnreadable> {
        match self.open_proc {
            Some(errno) => Err(ViewUnreadable::from_open_errno(errno)),
            None => self.real("open_proc").open_proc(),
        }
    }

    fn read(&self, dir: &ProcDir, path: &str) -> io::Result<Vec<u8>> {
        let earlier = self.count_read(path);
        let row = self
            .reads
            .iter()
            .filter(|(p, from, _)| p == path && *from <= earlier)
            .max_by_key(|(_, from, _)| *from);
        match row {
            Some((_, _, Ok(bytes))) => Ok(bytes.clone()),
            Some((_, _, Err(errno))) => Err(io::Error::from_raw_os_error(*errno)),
            None => self.real(&format!("read of {path}")).read(dir, path),
        }
    }

    fn pids(&self, dir: &ProcDir) -> io::Result<Vec<u32>> {
        match &self.pids {
            Some(Ok(pids)) => Ok(pids.clone()),
            Some(Err(errno)) => Err(io::Error::from_raw_os_error(*errno)),
            None => self.real("pids").pids(dir),
        }
    }

    fn signal_probe(&self, target: Pid) -> Result<(), Errno> {
        match self.signal_probes.iter().rev().find(|(p, _)| *p == target) {
            Some((_, answer)) => *answer,
            None => self.real(&format!("signal_probe of {target:?}")).signal_probe(target),
        }
    }
}
