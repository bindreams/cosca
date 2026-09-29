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
//!   Where `NSpid` is absent but pid namespaces exist (gVisor), the procfs's pid 1 namespace
//!   link must name this thread's own pid namespace ([`cross_check_with_init_ns`]).
//!
//! [`ProcDir`] is proven procfs's root and reads only with `openat2` (Linux 5.6), so a mount
//! placed over `/proc`, or over a file below it, after the check is refused, not read.

use std::io::{self, Read};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};

use rustix::fs::{openat2, Mode, OFlags, ResolveFlags, CWD, PROC_SUPER_MAGIC};

use crate::error::Error;

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
    /// `openat2` itself is refused (kernel older than 5.6, or a seccomp filter that answers it
    /// `ENOSYS`/`EPERM`), so no `/proc` view can ever be established here: the errno's name.
    openat2_refused: Option<&'static str>,
}

impl ViewUnreadable {
    fn new(reason: impl Into<String>, source: Option<io::Error>) -> Self {
        ViewUnreadable {
            reason: reason.into(),
            source,
            openat2_refused: None,
        }
    }

    /// [`Error::Unsupported`] naming the `openat2` requirement, when that is why the view
    /// could not be established. `op` is what could not be done.
    pub(crate) fn unsupported(&self, op: impl Into<String>) -> Option<Error> {
        self.openat2_refused.map(|errno| Error::Unsupported {
            op: op.into(),
            platform: "linux",
            detail: format!("cosca requires openat2 (Linux ≥ 5.6), refused here: openat2 answered {errno}"),
        })
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
/// or below it after the check is ever read. Needs `openat2` (Linux 5.6, and not filtered by
/// seccomp): [`open`](Self::open) fails, flagged so [`ViewUnreadable::unsupported`] names it.
#[derive(Debug)]
pub(crate) struct ProcDir(OwnedFd);

impl ProcDir {
    /// Open `/proc` and prove it is procfs's root: `PROC_SUPER_MAGIC`, and inode 1.
    pub(crate) fn open() -> Result<ProcDir, ViewUnreadable> {
        let fd = open_proc_root().map_err(|e| ViewUnreadable {
            openat2_refused: match e {
                rustix::io::Errno::NOSYS => Some("ENOSYS"),
                rustix::io::Errno::PERM => Some("EPERM"),
                _ => None,
            },
            ..ViewUnreadable::new("/proc could not be opened", Some(e.into()))
        })?;
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
        .map_err(io::Error::from)
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

    /// The target of the symlink at `path` under this `/proc`, without following it.
    fn read_link(&self, path: &str) -> io::Result<Vec<u8>> {
        let link = self.open_beneath(path, OFlags::PATH | OFlags::NOFOLLOW)?;
        Ok(rustix::fs::readlinkat(&link, "", Vec::new())?.into_bytes())
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

/// The `openat2` of `/proc` itself, with a test seam: a forced errno replaces the syscall.
fn open_proc_root() -> Result<OwnedFd, rustix::io::Errno> {
    #[cfg(test)]
    if let Some(errno) = fault::forced_openat2_errno() {
        return Err(errno);
    }
    openat2(
        CWD,
        "/proc",
        OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_MAGICLINKS,
    )
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
        Verdict::NoNspid => cross_check_with_init_ns(&dir),
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
    /// `NSpid` is absent although pid namespaces exist; only [`cross_check_with_init_ns`] can
    /// decide. Never leaves [`proc_view`].
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

/// Decide [`Verdict::NoNspid`] by pid namespace identity. `thread-self/ns/pid` names this
/// thread's pid namespace (a namespace link names its task's namespace, whichever procfs shows
/// it), and `1/ns/pid` names the procfs's own, since its pid 1 is that namespace's init. Equal
/// links: `Same`.
///
/// Numbers cannot decide it: an outer procfs can number this thread exactly as `gettid()` does.
/// Nor can our own pidfd's fdinfo `Pid:`: Linux prints it in the procfs's namespace, where it
/// coincides with `getpid()` just as the thread id does, and gVisor prints it in the fd owner's.
///
/// No Linux kernel reaches this arm (it prints `NSpid` whenever it has pid namespaces). "pid 1 is
/// the init" holds on gVisor, whose allocator wraps to 2 and refuses a namespace whose init has
/// exited. Reading this thread's own link needs no ptrace right, even non-dumpable. Linux lets
/// only a reader with ptrace-read access to that pid 1 read its link (else `EACCES`:
/// `Unassessable`); gVisor does not check. gVisor printed a fake, per-link `pid:[…]` until
/// 2023-06 (commit 94bf4b6), but the arm needs `openat2` ([`ProcDir`]), which it gained in 2026-08.
fn cross_check_with_init_ns(dir: &ProcDir) -> Verdict {
    classify_ns_links(dir.read_link("thread-self/ns/pid"), || dir.read_link("1/ns/pid"))
}

/// Classify this thread's pid namespace link `own` against the procfs's pid 1's, which `init`
/// reads only once `own` has been read.
fn classify_ns_links(own: io::Result<Vec<u8>>, init: impl FnOnce() -> io::Result<Vec<u8>>) -> Verdict {
    let links = pid_ns_link(own, "thread-self/ns/pid")
        .and_then(|own| Ok((own, pid_ns_link(init(), "1/ns/pid (this /proc's pid 1)")?)));
    match links {
        Ok((own, init)) if own == init => Verdict::Same,
        Ok(_) => Verdict::Diverged,
        Err(why) => Verdict::Unassessable(why),
    }
}

/// `link`, the target read from `path`, if it names a pid namespace (`pid:[<inode>]`).
fn pid_ns_link(link: io::Result<Vec<u8>>, path: &str) -> Result<Vec<u8>, ViewUnreadable> {
    match link {
        Ok(target) if target.starts_with(b"pid:[") && target.ends_with(b"]") => Ok(target),
        Ok(target) => Err(ViewUnreadable::new(
            format!(
                "self/status has no NSpid line and {path} is not a pid namespace link ({:?})",
                String::from_utf8_lossy(&target)
            ),
            None,
        )),
        Err(e) => Err(ViewUnreadable::new(
            format!("self/status has no NSpid line and {path} could not be read"),
            Some(e),
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
        static FORCE_FDINFO: Cell<Option<Result<super::PidfdTarget, i32>>> = const { Cell::new(None) };
        static FORCE_OPENAT2_ERRNO: Cell<Option<rustix::io::Errno>> = const { Cell::new(None) };
        static FORCE_SELF_STAT: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
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
            FORCE_OPENAT2_ERRNO.with(|f| f.set(None));
            FORCE_SELF_STAT.with(|f| f.take());
        }
    }

    /// Make EVERY [`ProcDir::open`](super::ProcDir::open) on THIS thread fail as its `openat2`
    /// answering `errno`, as on a kernel older than 5.6 (`NOSYS`) or under a seccomp filter
    /// (`PERM`), until the guard drops.
    pub(crate) fn force_openat2_errno(errno: rustix::io::Errno) -> Forced {
        FORCE_OPENAT2_ERRNO.with(|f| f.set(Some(errno)));
        Forced(())
    }

    pub(crate) fn forced_openat2_errno() -> Option<rustix::io::Errno> {
        FORCE_OPENAT2_ERRNO.with(|f| f.get())
    }

    /// Make the NEXT read of this process's own `stat` on THIS thread return `bytes`.
    pub(crate) fn force_self_stat_once(bytes: &[u8]) -> Forced {
        FORCE_SELF_STAT.with(|f| *f.borrow_mut() = Some(bytes.to_vec()));
        Forced(())
    }

    pub(crate) fn take_forced_self_stat() -> Option<Vec<u8>> {
        FORCE_SELF_STAT.with(|f| f.take())
    }

    /// Make the NEXT [`proc_view`](super::proc_view) on THIS thread read `text` as its
    /// `status` file.
    pub(crate) fn force_status_once(text: &str) -> Forced {
        FORCE_STATUS.with(|f| *f.borrow_mut() = Some(text.to_owned()));
        Forced(())
    }

    pub(crate) fn take_forced_status() -> Option<String> {
        FORCE_STATUS.with(|f| f.take())
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
