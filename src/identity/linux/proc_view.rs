//! Whether this process's `/proc` is the pid namespace its own pids live in — the divergence
//! [`ProcessId::current`](super::super::ProcessId::current)'s doc explains for `/proc/self` vs
//! `getpid()`, generalised to any bare-pid lookup through `/proc`.
//!
//! A pid namespace without `--mount-proc`, an `nsenter --mount` into another mount namespace's
//! `/proc`, or no `/proc` at all: this task's `/proc` then describes a DIFFERENT pid namespace
//! than its own `getpid()` and every pid a caller hands it. A `/proc/<pid>` lookup can resolve an
//! unrelated process, so what it says about `<pid>` must not be read as an answer about the
//! caller's `<pid>`, `Gone` included.
//!
//! Two ways to establish that the mounted `/proc` describes a given target, each through ONE
//! [`ProcDir`] so nothing re-resolves `/proc` by path between the check and the read:
//!
//! - **With a pidfd** ([`pidfd_pid_in_view`]): a pidfd's fdinfo `Pid:` line is printed
//!   unconditionally, relative to the pid namespace of the procfs that printed it (`0` when the
//!   target is not visible there, `-1` when it was reaped). Equal to the pid the caller holds
//!   means this procfs names the target under that number.
//! - **Without one** ([`proc_view`]): the `NSpid` line of `self/status`, which has one entry per
//!   pid namespace from the procfs's down to the reader's. One entry means the same namespace.
//!   Where `NSpid` is absent but pid namespaces exist (gVisor), `thread-self/stat`'s id must
//!   equal `gettid()`.
//!
//! [`ProcDir`] is proven procfs's root and reads only with `openat2` (Linux 5.6), so a mount
//! placed over `/proc`, or over a file below it, after the check is refused, not read.

use std::io::{self, Read};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};

use rustix::fs::{openat2, Mode, OFlags, ResolveFlags, CWD, PROC_SUPER_MAGIC};

/// What this process's `/proc` says about its own pid namespace.
#[derive(Debug)]
pub(crate) enum ProcView {
    /// The `/proc` is this task's own pid namespace's. The dirfd is that `/proc`: read through
    /// it (`openat`), never through a fresh `/proc/...` path.
    Same(ProcDir),
    /// The `/proc` belongs to an outer pid namespace.
    Diverged,
    /// The view could not be established; [`ViewUnreadable`] says why. Never treated as
    /// [`Same`](Self::Same).
    Unassessable(ViewUnreadable),
}

/// Why a `/proc` view or pidfd cross-check could not be established.
#[derive(Debug)]
pub(crate) struct ViewUnreadable {
    pub(crate) reason: String,
    /// The OS error behind `reason`, when there was one.
    pub(crate) source: Option<io::Error>,
}

impl ViewUnreadable {
    fn new(reason: impl Into<String>, source: Option<io::Error>) -> Self {
        ViewUnreadable {
            reason: reason.into(),
            source,
        }
    }
}

impl std::fmt::Display for ViewUnreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.source {
            Some(e) => write!(f, "{}: {e}", self.reason),
            None => f.write_str(&self.reason),
        }
    }
}

/// A `/proc` directory fd proven to be procfs's root, and the only way to read `/proc`: every
/// read is an `openat2` beneath it that cannot cross a mount, so nothing mounted over `/proc`
/// or below it after the check is ever read. Needs Linux 5.6 (`openat2`); on an older kernel
/// every read fails naming that.
#[derive(Debug)]
pub(crate) struct ProcDir(OwnedFd);

impl ProcDir {
    /// Open `/proc` and prove it is procfs's root: `PROC_SUPER_MAGIC`, and inode 1.
    pub(crate) fn open() -> Result<ProcDir, ViewUnreadable> {
        let fd = openat2(
            CWD,
            "/proc",
            OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|e| ViewUnreadable::new("/proc could not be opened", Some(openat2_error(e))))?;
        let fs =
            rustix::fs::fstatfs(&fd).map_err(|e| ViewUnreadable::new("/proc could not be checked", Some(e.into())))?;
        if fs.f_type != PROC_SUPER_MAGIC {
            return Err(ViewUnreadable::new(
                format!("/proc is not procfs (filesystem type {:#x})", fs.f_type),
                None,
            ));
        }
        let ino = rustix::fs::fstat(&fd)
            .map_err(|e| ViewUnreadable::new("/proc could not be checked", Some(e.into())))?
            .st_ino;
        if ino != PROC_ROOT_INO {
            return Err(ViewUnreadable::new(
                format!("/proc is not the root of procfs (inode {ino})"),
                None,
            ));
        }
        Ok(ProcDir(fd))
    }

    /// Open `path` under this `/proc`, refusing to leave it, cross a mount, or follow a magic link.
    fn open_beneath(&self, path: &str, oflags: OFlags) -> io::Result<OwnedFd> {
        openat2(
            &self.0,
            path,
            oflags | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(openat2_error)
    }

    /// Read the file at `path` under this `/proc`.
    pub(crate) fn read(&self, path: &str) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        std::fs::File::from(self.open_beneath(path, OFlags::RDONLY)?).read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    /// [`read`](Self::read) as UTF-8 text.
    pub(crate) fn read_to_string(&self, path: &str) -> io::Result<String> {
        String::from_utf8(self.read(path)?).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Whether the symlink at `path` under this `/proc` exists, without following it.
    fn link_exists(&self, path: &str) -> io::Result<bool> {
        match self.open_beneath(path, OFlags::PATH | OFlags::NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// The inode of procfs's root directory (`PROC_ROOT_INO`).
const PROC_ROOT_INO: u64 = 1;

/// `ENOSYS` from `openat2` is a kernel older than 5.6; say so instead of a bare errno.
fn openat2_error(errno: rustix::io::Errno) -> io::Error {
    if errno == rustix::io::Errno::NOSYS {
        io::Error::new(io::ErrorKind::Unsupported, "openat2 requires Linux kernel >= 5.6")
    } else {
        errno.into()
    }
}

/// This process's [`ProcView`], from `self/status`'s `NSpid` read through one `/proc` dirfd.
pub(crate) fn proc_view() -> ProcView {
    #[cfg(test)]
    let forced = fault::take_forced_proc_view();
    #[cfg(test)]
    match forced {
        Some(fault::ForcedView::Diverged) => return ProcView::Diverged,
        Some(fault::ForcedView::Unassessable) => {
            return ProcView::Unassessable(ViewUnreadable::new("forced by a test", None));
        }
        Some(fault::ForcedView::Same) => {
            return match ProcDir::open() {
                Ok(dir) => ProcView::Same(dir),
                Err(why) => ProcView::Unassessable(why),
            };
        }
        None => {}
    }
    let dir = match ProcDir::open() {
        Ok(dir) => dir,
        Err(why) => return ProcView::Unassessable(why),
    };
    #[cfg(test)]
    let forced_status = fault::take_forced_status();
    #[cfg(not(test))]
    let forced_status: Option<String> = None;
    let status = match forced_status.map_or_else(|| dir.read_to_string("self/status"), Ok) {
        Ok(text) => text,
        Err(e) => {
            return ProcView::Unassessable(ViewUnreadable::new("self/status could not be read", Some(e)));
        }
    };
    let verdict = match classify_status(&status, || ns_pid_exists(&dir)) {
        Verdict::NoNspid => cross_check_with_thread_stat(&dir),
        decided => decided,
    };
    match verdict {
        Verdict::Same | Verdict::NoNspid => ProcView::Same(dir),
        Verdict::Diverged => ProcView::Diverged,
        Verdict::Unassessable(why) => ProcView::Unassessable(why),
    }
}

/// [`ProcView`] before the dirfd is attached; the pure part, so every arm runs without a
/// namespace.
#[derive(Debug)]
enum Verdict {
    Same,
    /// `NSpid` is absent although pid namespaces exist; only [`cross_check_with_thread_stat`]
    /// can decide. Never leaves [`proc_view`].
    NoNspid,
    Diverged,
    Unassessable(ViewUnreadable),
}

/// Classify `self/status`. `ns_pid_exists` answers whether `self/ns/pid` exists, and is asked
/// only when `NSpid` is absent.
///
/// `NSpid` exists only under `CONFIG_PID_NS`, and gVisor omits it. Absent, the kernel either
/// has no pid namespaces at all (then `self/ns/pid` does not exist and the view is trivially
/// `Same`), or does and this status file cannot say (gVisor): [`Verdict::NoNspid`].
fn classify_status(status: &str, ns_pid_exists: impl FnOnce() -> io::Result<bool>) -> Verdict {
    let Some(line) = status.lines().find_map(|l| l.strip_prefix("NSpid:")) else {
        return match ns_pid_exists() {
            Ok(false) => Verdict::Same,
            Ok(true) => Verdict::NoNspid,
            Err(e) => Verdict::Unassessable(ViewUnreadable::new(
                "self/status has no NSpid line and self/ns/pid could not be checked",
                Some(e),
            )),
        };
    };
    match line.split_whitespace().count() {
        0 => Verdict::Unassessable(ViewUnreadable::new("self/status has an empty NSpid line", None)),
        1 => Verdict::Same,
        _ => Verdict::Diverged,
    }
}

/// Decide [`Verdict::NoNspid`] from `thread-self/stat`: its first field is this thread's id as
/// the mounted procfs numbers it, which equals `gettid()` only when that procfs is this
/// thread's own pid namespace's.
fn cross_check_with_thread_stat(dir: &ProcDir) -> Verdict {
    #[cfg(test)]
    let forced = fault::take_forced_thread_stat();
    #[cfg(not(test))]
    let forced: Option<String> = None;
    match forced.map_or_else(|| dir.read_to_string("thread-self/stat"), Ok) {
        Ok(stat) => classify_thread_stat(&stat, rustix::thread::gettid().as_raw_nonzero().get() as u32),
        Err(e) => Verdict::Unassessable(ViewUnreadable::new(
            "self/status has no NSpid line and thread-self/stat could not be read",
            Some(e),
        )),
    }
}

/// Classify a `thread-self/stat` against `tid`, the caller's own `gettid()`.
fn classify_thread_stat(stat: &str, tid: u32) -> Verdict {
    match stat.split_once(' ').and_then(|(id, _)| id.parse::<u32>().ok()) {
        Some(id) if id == tid => Verdict::Same,
        Some(_) => Verdict::Diverged,
        None => Verdict::Unassessable(ViewUnreadable::new(
            "self/status has no NSpid line and thread-self/stat has no parseable id",
            None,
        )),
    }
}

fn ns_pid_exists(dir: &ProcDir) -> io::Result<bool> {
    dir.link_exists("self/ns/pid")
}

/// What a pidfd's fdinfo `Pid:` says about its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PidfdTarget {
    /// The target's pid as the procfs's pid namespace numbers it; `0` when not visible there.
    Pid(u32),
    /// The target was reaped.
    Reaped,
}

/// The `Pid:` of `pidfd`'s fdinfo through the procfs at `dir`.
pub(crate) fn pidfd_pid_in_view(dir: &ProcDir, pidfd: BorrowedFd<'_>) -> Result<PidfdTarget, ViewUnreadable> {
    #[cfg(test)]
    if let Some(forced) = fault::take_forced_fdinfo() {
        return forced.map_err(|errno| {
            ViewUnreadable::new(
                "the pidfd's fdinfo could not be read",
                Some(io::Error::from_raw_os_error(errno)),
            )
        });
    }
    let fdinfo = dir
        .read_to_string(&format!("thread-self/fdinfo/{}", pidfd.as_raw_fd()))
        .map_err(|e| ViewUnreadable::new("the pidfd's fdinfo could not be read", Some(e)))?;
    parse_fdinfo_pid(&fdinfo).ok_or_else(|| ViewUnreadable::new("the pidfd's fdinfo has no parseable Pid line", None))
}

/// The `Pid:` the kernel prints for a pidfd whose target no longer has a task (`pidfd_show_fdinfo`).
const REAPED: i64 = -1;

fn parse_fdinfo_pid(fdinfo: &str) -> Option<PidfdTarget> {
    fdinfo
        .lines()
        .find_map(|l| l.strip_prefix("Pid:"))?
        .trim()
        .parse::<i64>()
        .ok()
        .and_then(|p| match p {
            REAPED => Some(PidfdTarget::Reaped),
            _ => u32::try_from(p).ok().map(PidfdTarget::Pid),
        })
}

#[cfg(test)]
pub(crate) mod fault {
    use std::cell::{Cell, RefCell};

    /// A view to force. `Same` still opens the real `/proc`.
    #[derive(Debug, Clone, Copy)]
    pub(crate) enum ForcedView {
        Same,
        Diverged,
        Unassessable,
    }

    thread_local! {
        static FORCE_PROC_VIEW: Cell<Option<ForcedView>> = const { Cell::new(None) };
        static FORCE_STATUS: RefCell<Option<String>> = const { RefCell::new(None) };
        static FORCE_THREAD_STAT: RefCell<Option<String>> = const { RefCell::new(None) };
        static FORCE_FDINFO: Cell<Option<Result<super::PidfdTarget, i32>>> = const { Cell::new(None) };
    }

    /// Disarms every forced value on drop, even unconsumed — so a test that panics before
    /// reaching the seam cannot leave one armed for whatever runs next on this thread.
    #[must_use = "dropping this immediately disarms the forced values; bind it for the probe's duration"]
    pub(crate) struct Forced(());

    impl Drop for Forced {
        fn drop(&mut self) {
            FORCE_PROC_VIEW.with(|f| f.set(None));
            FORCE_FDINFO.with(|f| f.set(None));
            FORCE_STATUS.with(|f| f.take());
            FORCE_THREAD_STAT.with(|f| f.take());
        }
    }

    /// Make the NEXT [`proc_view`](super::proc_view) on THIS thread read `text` as its
    /// `status` file.
    pub(crate) fn force_status_once(text: &str) -> Forced {
        FORCE_STATUS.with(|f| *f.borrow_mut() = Some(text.to_owned()));
        Forced(())
    }

    /// Make the NEXT [`proc_view`](super::proc_view) on THIS thread read `text` as its
    /// `thread-self/stat` file.
    pub(crate) fn force_thread_stat_once(text: &str) -> Forced {
        FORCE_THREAD_STAT.with(|f| *f.borrow_mut() = Some(text.to_owned()));
        Forced(())
    }

    pub(crate) fn take_forced_status() -> Option<String> {
        FORCE_STATUS.with(|f| f.take())
    }

    pub(crate) fn take_forced_thread_stat() -> Option<String> {
        FORCE_THREAD_STAT.with(|f| f.take())
    }

    /// Force the NEXT [`proc_view`](super::proc_view) on THIS thread.
    pub(crate) fn force_proc_view_once(view: ForcedView) -> Forced {
        FORCE_PROC_VIEW.with(|f| f.set(Some(view)));
        Forced(())
    }

    /// Force the NEXT [`pidfd_pid_in_view`](super::pidfd_pid_in_view) on THIS thread to answer
    /// `Ok(pid)`, or to fail reading with the raw `errno`.
    pub(crate) fn force_fdinfo_once(answer: Result<super::PidfdTarget, i32>) -> Forced {
        FORCE_FDINFO.with(|f| f.set(Some(answer)));
        Forced(())
    }

    pub(crate) fn take_forced_proc_view() -> Option<ForcedView> {
        FORCE_PROC_VIEW.with(|f| f.take())
    }

    pub(crate) fn take_forced_fdinfo() -> Option<Result<super::PidfdTarget, i32>> {
        FORCE_FDINFO.with(|f| f.take())
    }
}

#[cfg(test)]
#[path = "proc_view_tests.rs"]
mod proc_view_tests;
