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
//! - **With a pidfd** ([`pidfd_pid_in`]): a pidfd's fdinfo `Pid:` line is printed
//!   unconditionally, relative to the pid namespace of the procfs that printed it (`0` when the
//!   target is not visible there, `-1` when it was reaped). Equal to the pid the caller holds
//!   means this procfs names the target under that number.
//! - **Without one** ([`proc_view_with`]): the `NSpid` line of `self/status`, which has one entry per
//!   pid namespace from the procfs's down to the reader's. One entry means the same namespace.
//!   Where `NSpid` is absent but pid namespaces exist (gVisor), the procfs's pid 1 namespace
//!   link must name this process's own pid namespace ([`cross_check_with_init_ns`]).
//!
//! [`ProcDir`] is proven procfs's root and reads only with `openat2` (Linux 5.6), so a mount
//! placed over `/proc`, or over a file below it, after the check is refused, not read. It and
//! the failure of a read of it live in [`proc_read`](super::proc_read), below this module.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

use super::kernel::Kernel;
use super::pid_file::{self, ReadOutcome, Unreadable};
use super::proc_read::{read_own, utf8, OwnUnreadable, ProcDir, ProcOpenFailure, ReadFailure};
use super::prove::Refusal;
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

/// Why a [`ProcView::Diverged`] `/proc` cannot answer questions about the caller's pids.
pub(crate) const DIVERGED_REASON: &str = "this process's /proc is an outer pid namespace's";

/// Why a [`ProcView::Unassessable`] `/proc` could not say which namespace it is: reading
/// `self/status` failed, as I/O or as invalid UTF-8.
pub(crate) const UNREADABLE_STATUS_REASON: &str = "self/status could not be read";

impl ProcView {
    /// The `/proc` directory of a [`Same`](Self::Same) view; any other view is why not.
    pub(crate) fn into_dir(self) -> Result<ProcDir, ViewUnreadable> {
        match self {
            ProcView::Same(dir) => Ok(dir),
            ProcView::Diverged => Err(ViewUnreadable::new(DIVERGED_REASON, None)),
            ProcView::Unassessable(why) => Err(why),
        }
    }
}

/// Why a file read to establish a [`ProcView`] failed: an own file's failure ([`OwnUnreadable`]), or
/// pid 1's `ns/pid`, a foreign pid's file, with the verdict the pid-file rule ([`pid_file::read_link`])
/// gave it. `hidepid` can hide pid 1 from a reader, so its failure is told by that rule, not the
/// own-file one.
#[derive(Debug)]
pub(crate) enum ViewReadFailure {
    Own(OwnUnreadable),
    /// The rule's verdict on pid 1's link, kept as it is: any but [`ReadOutcome::Read`], which is no
    /// failure.
    Pid1(Result<ReadOutcome, Unreadable>),
}

impl From<OwnUnreadable> for ViewReadFailure {
    fn from(own: OwnUnreadable) -> Self {
        ViewReadFailure::Own(own)
    }
}

/// Why a `/proc` view or pidfd cross-check could not be established.
#[derive(Debug)]
pub(crate) struct ViewUnreadable {
    pub(crate) reason: String,
    /// The failure behind `reason`, when there was one: for a refusal, its whole chain
    /// ([`Refusal::cause_io`]), whose `openat2` errno is `refusal`'s. Held beside `refusal` rather than
    /// derived from it, because [`Error::source`](std::error::Error::source) lends a reference and
    /// the chain is built, not stored. Only [`of_failure`](Self::of_failure) sets `refusal`, and
    /// sets both together, so they cannot disagree.
    pub(crate) source: Option<io::Error>,
    /// The refused `openat2`, when that is why the view could not be established: of `/proc`
    /// itself or of a file read to check it.
    refusal: Option<Box<Refusal>>,
}

impl ViewUnreadable {
    fn new(reason: impl Into<String>, source: Option<io::Error>) -> Self {
        ViewUnreadable {
            reason: reason.into(),
            source,
            refusal: None,
        }
    }

    /// The view that the failed read of a file leaves, `reason` saying which: the one constructor
    /// from a read's failure, own file or pid 1's.
    pub(crate) fn of_failure(reason: impl Into<String>, failure: impl Into<ViewReadFailure>) -> Self {
        use crate::error::io_context;

        let (source, refusal) = match failure.into() {
            ViewReadFailure::Own(OwnUnreadable::Refused(refusal))
            | ViewReadFailure::Pid1(Ok(ReadOutcome::Refused(refusal))) => {
                (Some(refusal.cause_io()), Some(Box::new(refusal)))
            }
            ViewReadFailure::Own(OwnUnreadable::Failed(e)) => (Some(e), None),
            ViewReadFailure::Pid1(Ok(ReadOutcome::Exited(e))) => (Some(io_context("pid 1 exited", e)), None),
            ViewReadFailure::Pid1(Ok(ReadOutcome::Hidden(e))) => (
                Some(io_context(
                    "pid 1 is hidden from this process (gone, or hidepid hides it)",
                    e,
                )),
                None,
            ),
            ViewReadFailure::Pid1(Ok(ReadOutcome::Read(_))) => {
                debug_assert!(false, "a link that was read is no failure");
                (None, None)
            }
            ViewReadFailure::Pid1(Err(unreadable)) => (Some(unreadable.into_io()), None),
        };
        ViewUnreadable {
            refusal,
            ..ViewUnreadable::new(reason, source)
        }
    }

    /// [`Error::Unsupported`] naming the `openat2` requirement, when that is why the view
    /// could not be established. `op` is what could not be done.
    pub(crate) fn unsupported(&self, op: impl Into<String>) -> Option<Error> {
        self.refusal.as_ref().map(|refusal| refusal.unsupported(op))
    }

    /// The refused `openat2`, when that is why the view could not be established. For callers whose
    /// error type is not [`Error`].
    pub(crate) fn refusal(&self) -> Option<Refusal> {
        self.refusal.as_deref().cloned()
    }
}

impl From<ProcOpenFailure> for ViewUnreadable {
    fn from(failure: ProcOpenFailure) -> Self {
        match failure {
            ProcOpenFailure::Open(own) => ViewUnreadable::of_failure("/proc could not be opened", own),
            ProcOpenFailure::Check(e) => ViewUnreadable::new("/proc could not be checked", Some(e)),
            ProcOpenFailure::NotProcfs { f_type } => {
                ViewUnreadable::new(format!("/proc is not procfs (filesystem type {f_type:#x})"), None)
            }
            ProcOpenFailure::NotRoot { ino } => {
                ViewUnreadable::new(format!("/proc is not the root of procfs (inode {ino})"), None)
            }
        }
    }
}

/// The reason alone: the OS error behind it is the [`source`](std::error::Error::source).
impl std::fmt::Display for ViewUnreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for ViewUnreadable {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e as _)
    }
}

/// This process's [`ProcView`], from `self/status`'s `NSpid` read through one `/proc` dirfd that
/// `kernel` opens.
pub(crate) fn proc_view_with(kernel: &dyn Kernel) -> ProcView {
    let dir = match kernel.open_proc() {
        Ok(dir) => dir,
        Err(why) => return ProcView::Unassessable(why.into()),
    };
    let status = match read_own(kernel, &dir, "self/status") {
        Ok(bytes) => match utf8(bytes) {
            Ok(text) => text,
            Err(e) => return ProcView::Unassessable(ViewUnreadable::new(UNREADABLE_STATUS_REASON, Some(e))),
        },
        Err(own) => return ProcView::Unassessable(ViewUnreadable::of_failure(UNREADABLE_STATUS_REASON, own)),
    };
    let verdict = match classify_status(&status, || own_ns_link(kernel, &dir)) {
        Verdict::NoNspid(own) => cross_check_with_init_ns(kernel, &dir, own),
        decided => decided,
    };
    match verdict {
        Verdict::Same | Verdict::NoNspid(_) => ProcView::Same(dir),
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
    /// decide, by this process's pid namespace link, which is what was read to find they exist. Never
    /// leaves [`proc_view_with`].
    NoNspid(Vec<u8>),
    Diverged,
    Unassessable(ViewUnreadable),
}

/// Classify `self/status`. `own_ns_link` reads this process's `self/ns/pid`, and is asked only when
/// `NSpid` is absent.
///
/// `NSpid` exists only under `CONFIG_PID_NS`, and gVisor omits it. Absent, the kernel either
/// has no pid namespaces at all (then `self/ns/pid` does not exist and the view is trivially
/// `Same`), or does and this status file cannot say (gVisor): [`Verdict::NoNspid`], with the link.
fn classify_status(status: &str, own_ns_link: impl FnOnce() -> Result<Option<Vec<u8>>, OwnUnreadable>) -> Verdict {
    let Some(line) = status.lines().find_map(|l| l.strip_prefix("NSpid:")) else {
        return match own_ns_link() {
            Ok(None) => Verdict::Same,
            Ok(Some(own)) => Verdict::NoNspid(own),
            Err(own) => Verdict::Unassessable(ViewUnreadable::of_failure(
                "self/status has no NSpid line and self/ns/pid could not be checked",
                own,
            )),
        };
    };
    match line.split_whitespace().count() {
        0 => Verdict::Unassessable(ViewUnreadable::new("self/status has an empty NSpid line", None)),
        1 => Verdict::Same,
        _ => Verdict::Diverged,
    }
}

/// Decide [`Verdict::NoNspid`] by pid namespace identity. `own`, the target of `self/ns/pid`, names
/// this process's pid namespace (a namespace link names its task's namespace, whichever procfs shows
/// it; every thread of a process is in one), and `1/ns/pid` names the procfs's own, since its pid 1 is
/// that namespace's init. Equal links: `Same`.
///
/// Numbers cannot decide it: an outer procfs can number this thread exactly as `gettid()` does.
/// Nor can our own pidfd's fdinfo `Pid:`: Linux prints it in the procfs's namespace, where it
/// coincides with `getpid()` just as the thread id does, and gVisor prints it in the fd owner's.
///
/// No Linux kernel reaches this arm (it prints `NSpid` whenever it has pid namespaces). "pid 1 is
/// the init" holds on gVisor, whose allocator wraps to 2 and refuses a namespace whose init has
/// exited. Reading this process's own link needs no ptrace right, even non-dumpable. Linux lets
/// only a reader with ptrace-read access to that pid 1 read its link (else `EACCES`: pid 1 is
/// hidden from it, so `Unassessable`); gVisor does not check. gVisor printed a fake, per-link
/// `pid:[…]` until 2023-06 (commit 94bf4b6), but the arm needs `openat2` ([`ProcDir`]), which it
/// gained in 2026-08.
fn cross_check_with_init_ns(kernel: &dyn Kernel, dir: &ProcDir, own: Vec<u8>) -> Verdict {
    classify_ns_links(own, || init_ns_link(kernel, dir))
}

/// The target of the procfs's `1/ns/pid`. Pid 1 is a foreign pid to most readers, so this is a pid's
/// file, not an own one: `EPERM` is `hidepid` only if the checked directory still reads, and
/// [`pid_file::read_link`] decides that. Only a refusal is one here; a hidden or exited pid 1, or a
/// failed re-check, leaves the view unestablished, as the failure says.
fn init_ns_link(kernel: &dyn Kernel, dir: &ProcDir) -> Result<Vec<u8>, ViewReadFailure> {
    match pid_file::read_link(kernel, dir, 1, "ns/pid") {
        Ok(ReadOutcome::Read(target)) => Ok(target),
        failed => Err(ViewReadFailure::Pid1(failed)),
    }
}

/// Classify this process's pid namespace link `own` against the procfs's pid 1's, which `init`
/// reads only once `own` is known to name a pid namespace.
fn classify_ns_links(own: Vec<u8>, init: impl FnOnce() -> Result<Vec<u8>, ViewReadFailure>) -> Verdict {
    let links = pid_ns_link(Ok(own), "self/ns/pid")
        .and_then(|own| Ok((own, pid_ns_link(init(), "1/ns/pid (this /proc's pid 1)")?)));
    match links {
        Ok((own, init)) if own == init => Verdict::Same,
        Ok(_) => Verdict::Diverged,
        Err(why) => Verdict::Unassessable(why),
    }
}

/// `link`, the target read from `path`, if it names a pid namespace (`pid:[<inode>]`).
fn pid_ns_link(link: Result<Vec<u8>, ViewReadFailure>, path: &str) -> Result<Vec<u8>, ViewUnreadable> {
    match link {
        Ok(target) if target.starts_with(b"pid:[") && target.ends_with(b"]") => Ok(target),
        Ok(target) => Err(ViewUnreadable::new(
            format!(
                "self/status has no NSpid line and {path} is not a pid namespace link ({:?})",
                String::from_utf8_lossy(&target)
            ),
            None,
        )),
        Err(failure) => Err(ViewUnreadable::of_failure(
            format!("self/status has no NSpid line and {path} could not be read"),
            failure,
        )),
    }
}

/// The target of this process's `self/ns/pid`, or `None` when there is no such link: a kernel with no
/// pid namespaces. Only the `openat2` that finds nothing says so (`ENOENT`); an `ENOENT` after the open
/// is a link whose task has no namespace, which says nothing about the kernel, and any other failure is
/// the link's own, as every own file's is.
fn own_ns_link(kernel: &dyn Kernel, dir: &ProcDir) -> Result<Option<Vec<u8>>, OwnUnreadable> {
    match kernel.read_link(dir, "self/ns/pid") {
        Ok(target) => Ok(Some(target)),
        Err(ReadFailure::Open(e)) if e.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(failure) => Err(OwnUnreadable::of(failure)),
    }
}

/// What a pidfd's fdinfo `Pid:` says about its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PidfdTarget {
    /// The target's pid as the procfs's pid namespace numbers it; `0` when not visible there.
    Pid(u32),
    /// The target was reaped.
    Reaped,
}

/// The `Pid:` of `pidfd`'s fdinfo, read through the procfs at `dir`.
pub(crate) fn pidfd_pid_in(
    kernel: &dyn Kernel,
    dir: &ProcDir,
    pidfd: BorrowedFd<'_>,
) -> Result<PidfdTarget, ViewUnreadable> {
    const UNREADABLE: &str = "the pidfd's fdinfo could not be read";
    let bytes = read_own(kernel, dir, &format!("thread-self/fdinfo/{}", pidfd.as_raw_fd()))
        .map_err(|own| ViewUnreadable::of_failure(UNREADABLE, own))?;
    let fdinfo = utf8(bytes).map_err(|e| ViewUnreadable::new(UNREADABLE, Some(e)))?;
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
#[path = "proc_view_tests.rs"]
mod proc_view_tests;
