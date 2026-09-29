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
//! `/proc` dirfd so nothing re-resolves `/proc` by path between the check and the read:
//!
//! - **With a pidfd** ([`pidfd_pid_in_view`]): a pidfd's fdinfo `Pid:` line is printed
//!   unconditionally, relative to the pid namespace of the procfs that printed it (`0` when the
//!   target is not visible there). Equal to the pid the caller holds means this procfs names the
//!   target under that number.
//! - **Without one** ([`proc_view`]): the `NSpid` line of `self/status`, which has one entry per
//!   pid namespace from the procfs's down to the reader's. One entry means the same namespace.

use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use rustix::fs::{AtFlags, Mode, OFlags};

/// What this process's `/proc` says about its own pid namespace.
#[derive(Debug)]
pub(crate) enum ProcView {
    /// The `/proc` is this task's own pid namespace's. The dirfd is that `/proc`: read through
    /// it (`openat`), never through a fresh `/proc/...` path.
    Same(OwnedFd),
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

/// Open `/proc` as a directory fd.
pub(crate) fn open_proc_dir() -> io::Result<OwnedFd> {
    Ok(rustix::fs::open(
        "/proc",
        OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// Read the file at `path` relative to `dir`, as UTF-8 text.
pub(crate) fn read_at(dir: BorrowedFd<'_>, path: &str) -> io::Result<String> {
    let fd = rustix::fs::openat(dir, path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())?;
    let mut text = String::new();
    std::fs::File::from(fd).read_to_string(&mut text)?;
    Ok(text)
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
        // A forced `Same` still opens the real `/proc`, so the dirfd it carries is real.
        Some(fault::ForcedView::Same) => {
            return match open_proc_dir() {
                Ok(dir) => ProcView::Same(dir),
                Err(e) => ProcView::Unassessable(ViewUnreadable::new("/proc could not be opened", Some(e))),
            };
        }
        None => {}
    }
    let dir = match open_proc_dir() {
        Ok(dir) => dir,
        Err(e) => return ProcView::Unassessable(ViewUnreadable::new("/proc could not be opened", Some(e))),
    };
    let status = match read_at(dir.as_fd(), "self/status") {
        Ok(text) => text,
        Err(e) => {
            return ProcView::Unassessable(ViewUnreadable::new("self/status could not be read", Some(e)));
        }
    };
    match classify_status(&status, || ns_pid_exists(dir.as_fd())) {
        Verdict::Same => ProcView::Same(dir),
        Verdict::Diverged => ProcView::Diverged,
        Verdict::Unassessable(why) => ProcView::Unassessable(why),
    }
}

/// [`ProcView`] before the dirfd is attached; the pure part, so every arm runs without a
/// namespace.
#[derive(Debug)]
enum Verdict {
    Same,
    Diverged,
    Unassessable(ViewUnreadable),
}

/// Classify `self/status`. `ns_pid_exists` answers whether `self/ns/pid` exists, and is asked
/// only when `NSpid` is absent.
///
/// `NSpid` exists only under `CONFIG_PID_NS`, and gVisor omits it. Absent, the kernel either
/// has no pid namespaces at all (then `self/ns/pid` does not exist and the view is trivially
/// `Same`), or does and this status file cannot say (gVisor): that stays `Unassessable`, not
/// assumed `Same`.
fn classify_status(status: &str, ns_pid_exists: impl FnOnce() -> io::Result<bool>) -> Verdict {
    let Some(line) = status.lines().find_map(|l| l.strip_prefix("NSpid:")) else {
        return match ns_pid_exists() {
            Ok(false) => Verdict::Same,
            Ok(true) => Verdict::Unassessable(ViewUnreadable::new(
                "self/status has no NSpid line although pid namespaces exist, so this /proc cannot be told apart from an outer namespace's",
                None,
            )),
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

fn ns_pid_exists(dir: BorrowedFd<'_>) -> io::Result<bool> {
    match rustix::fs::statat(dir, "self/ns/pid", AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// The `Pid:` of `pidfd`'s fdinfo through the procfs at `dir`: the pidfd's target as that
/// procfs's pid namespace numbers it, `0` when the target is not visible there.
///
/// The kernel prints it unconditionally (`pidfd_show_fdinfo`), unlike `NSpid`.
pub(crate) fn pidfd_pid_in_view(dir: BorrowedFd<'_>, pidfd: BorrowedFd<'_>) -> Result<u32, ViewUnreadable> {
    #[cfg(test)]
    if let Some(forced) = fault::take_forced_fdinfo() {
        return forced.map_err(|errno| {
            ViewUnreadable::new(
                "the pidfd's fdinfo could not be read",
                Some(io::Error::from_raw_os_error(errno)),
            )
        });
    }
    let fdinfo = read_at(dir, &format!("self/fdinfo/{}", pidfd.as_raw_fd()))
        .map_err(|e| ViewUnreadable::new("the pidfd's fdinfo could not be read", Some(e)))?;
    parse_fdinfo_pid(&fdinfo).ok_or_else(|| ViewUnreadable::new("the pidfd's fdinfo has no parseable Pid line", None))
}

fn parse_fdinfo_pid(fdinfo: &str) -> Option<u32> {
    fdinfo
        .lines()
        .find_map(|l| l.strip_prefix("Pid:"))?
        .trim()
        .parse::<i64>()
        .ok()
        // The kernel prints a signed `pid_t`; nothing legitimate is negative.
        .and_then(|p| u32::try_from(p).ok())
}

#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;

    /// A view to force. `Same` still opens the real `/proc`.
    #[derive(Debug, Clone, Copy)]
    pub(crate) enum ForcedView {
        Same,
        Diverged,
        Unassessable,
    }

    thread_local! {
        static FORCE_PROC_VIEW: Cell<Option<ForcedView>> = const { Cell::new(None) };
        static FORCE_FDINFO: Cell<Option<Result<u32, i32>>> = const { Cell::new(None) };
    }

    /// Disarms every forced value on drop, even unconsumed — so a test that panics before
    /// reaching the seam cannot leave one armed for whatever runs next on this thread.
    #[must_use = "dropping this immediately disarms the forced values; bind it for the probe's duration"]
    pub(crate) struct Forced(());

    impl Drop for Forced {
        fn drop(&mut self) {
            FORCE_PROC_VIEW.with(|f| f.set(None));
            FORCE_FDINFO.with(|f| f.set(None));
        }
    }

    /// Force the NEXT [`proc_view`](super::proc_view) on THIS thread.
    pub(crate) fn force_proc_view_once(view: ForcedView) -> Forced {
        FORCE_PROC_VIEW.with(|f| f.set(Some(view)));
        Forced(())
    }

    /// Force the NEXT [`pidfd_pid_in_view`](super::pidfd_pid_in_view) on THIS thread to answer
    /// `Ok(pid)`, or to fail reading with the raw `errno`.
    pub(crate) fn force_fdinfo_once(answer: Result<u32, i32>) -> Forced {
        FORCE_FDINFO.with(|f| f.set(Some(answer)));
        Forced(())
    }

    pub(crate) fn take_forced_proc_view() -> Option<ForcedView> {
        FORCE_PROC_VIEW.with(|f| f.take())
    }

    pub(crate) fn take_forced_fdinfo() -> Option<Result<u32, i32>> {
        FORCE_FDINFO.with(|f| f.take())
    }
}

#[cfg(test)]
#[path = "proc_view_tests.rs"]
mod proc_view_tests;
