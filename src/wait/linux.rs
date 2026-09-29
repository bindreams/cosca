//! Linux death-watch + kill via pidfd. `pidfd_open` returns a fd that
//! becomes readable (POLLIN) when the task becomes a zombie (exits); polling never reaps.
//! `pidfd_send_signal` is identity-bound (no pid-reuse race).
//!
//! The kernel floor, the per-syscall versions, and how a refused syscall is classified
//! (`Unsupported` versus `Io`) are in the crate root's "Platform requirements". Without `openat2`
//! the checked `/proc` view cannot be built, and a live target is `Unassessable`.

use std::os::fd::AsFd;
use std::time::Instant;

use rustix::event::{poll, PollFd, PollFlags};
use rustix::process::{pidfd_open, pidfd_send_signal, Pid, PidfdFlags, Signal};

use crate::error::Error;
use crate::identity::{Existence, Liveness, PidfdTarget, ProcDir, ProcView, ProcessId};

/// Open a pidfd for `id`, re-verifying identity. `Ok(None)` => already gone (treat as exited).
///
/// Every `/proc` read goes through one checked `/proc` dirfd shown to describe `id`'s pid
/// namespace; otherwise [`Error::Unassessable`], never a `Gone` off a foreign `/proc`.
pub(crate) fn open_verified(
    id: ProcessId,
    op: &'static str,
    what: &'static str,
) -> Result<Option<rustix::fd::OwnedFd>, Error> {
    debug_assert!(
        id.pid() <= i32::MAX as u32,
        "pid {} exceeds i32::MAX; pidfd cast would truncate",
        id.pid()
    );
    let raw = Pid::from_raw(id.pid() as i32).expect("a resolvable ProcessId is never pid 0");
    match pidfd_open_checked(raw) {
        Ok(pidfd) => verify_pidfd_target(id, pidfd, what),
        Err(rustix::io::Errno::SRCH) => Ok(None),
        // pidfd_open needs a pid that resolves to a thread-group leader task. EINVAL (< 6.16) /
        // ENOENT (>= 6.16) means either a reaped process-group leader whose pid lives on as a PGID
        // (gone), or a non-leader tid: live, or a ptraced zombie thread kept until its tracer
        // waits. Errno alone can't tell, so re-verify.
        Err(e @ (rustix::io::Errno::INVAL | rustix::io::Errno::NOENT)) => verify_without_pidfd(id, what, e),
        Err(e @ (rustix::io::Errno::NOSYS | rustix::io::Errno::PERM | rustix::io::Errno::NODEV)) => {
            Err(pidfd_open_unsupported(op, e))
        }
        Err(e) => Err(Error::Io(std::io::Error::from(e))),
    }
}

/// The [`Error::Unsupported`] for a `pidfd_open` that answered `errno` (`ENOSYS`, `EPERM` or
/// `ENODEV`): the environment cannot provide a pidfd at all, so there is no fallback. `op` names
/// the caller. `pidfd_open(2)` documents no `EPERM`, so an `EPERM` is a sandbox filter's.
pub(crate) fn pidfd_open_unsupported(op: &'static str, errno: rustix::io::Errno) -> Error {
    let (name, cause) = match errno {
        rustix::io::Errno::NOSYS => ("ENOSYS", "the kernel predates Linux 5.3, or a sandbox filter denies it"),
        rustix::io::Errno::PERM => ("EPERM", "a sandbox filter denies it"),
        rustix::io::Errno::NODEV => ("ENODEV", "the kernel has no anonymous inode filesystem"),
        other => unreachable!("pidfd_open_unsupported is only for ENOSYS, EPERM and ENODEV, got {other}"),
    };
    Error::Unsupported {
        op: op.into(),
        platform: "linux",
        detail: format!("pidfd_open answered {name}: {cause}"),
    }
}

/// `pidfd_open` refused `id`'s pid with `errno`. `Ok(None)` when the process is provably gone;
/// otherwise an error, since a live target cannot be waited on or signalled through a pidfd.
///
/// - `kill(pid, 0)` answering `ESRCH` is `Gone` whatever `/proc` shows.
/// - Else the `/proc` view must be [`ProcView::Same`]: `Gone` means the process is gone.
///   `Present` is a non-leader thread: `Dead` (a ptraced zombie) is exited, `Alive` is
///   [`Error::NotThreadGroupLeader`]. `Unknown` from either query is `Unassessable`.
/// - `Diverged`, or a view that could not be established, is `Unassessable` naming the view and
///   the `pidfd_open` errno. A raw `Io` here would surface as a bare `NotFound` on 6.16+, which
///   reads as "gone", and `containment::unix::group` treats `Io` as "no pidfd" and falls back to
///   `kill(2)`.
///
/// No pidfd to cross-check against, so the view comes from [`proc_view`](crate::identity::proc_view).
fn verify_without_pidfd(
    id: ProcessId,
    what: &'static str,
    errno: rustix::io::Errno,
) -> Result<Option<rustix::fd::OwnedFd>, Error> {
    if id.signal_says_no_such_process() {
        return Ok(None);
    }
    match crate::identity::proc_view() {
        ProcView::Same(proc_dir) => match exists_checked(id, &proc_dir) {
            Existence::Gone => Ok(None),
            Existence::Present => match alive_checked(id, &proc_dir) {
                Liveness::Dead => Ok(None),
                Liveness::Alive => Err(Error::NotThreadGroupLeader {
                    pid: id.pid(),
                    detail: what.into(),
                    source: std::io::Error::from(errno),
                }),
                Liveness::Unknown => Err(unassessable(
                    id,
                    what,
                    "the OS refused the liveness query",
                    None,
                    Some(errno),
                )),
            },
            Existence::Unknown => Err(unassessable(
                id,
                what,
                "the OS refused the existence query",
                None,
                Some(errno),
            )),
        },
        ProcView::Diverged => Err(unassessable(
            id,
            what,
            "this process's /proc is an outer pid namespace's",
            None,
            Some(errno),
        )),
        ProcView::Unassessable(why) => Err(unassessable(id, what, &why.reason, why.source, Some(errno))),
    }
}

/// `pidfd_open` succeeded. Confirm that this process's `/proc` describes the target before
/// comparing its start token, and read that token through the same `/proc` dirfd.
///
/// The pidfd's fdinfo `Pid:` is the target as the mounted procfs numbers it (`0` if invisible
/// there). Equal to `id.pid()` means that procfs names the target under this number, so
/// `{pid}/stat` describes it: the start token then tells a recycled pid from the original.
/// Anything else is `Unassessable`.
fn verify_pidfd_target(
    id: ProcessId,
    pidfd: rustix::fd::OwnedFd,
    what: &'static str,
) -> Result<Option<rustix::fd::OwnedFd>, Error> {
    let proc_dir =
        crate::identity::ProcDir::open().map_err(|why| unassessable(id, what, &why.reason, why.source, None))?;
    match crate::identity::pidfd_pid_in_view(&proc_dir, pidfd.as_fd()) {
        Ok(PidfdTarget::Pid(pid)) if pid == id.pid() => {}
        // Reaped after `pidfd_open`: gone, and nothing to signal.
        Ok(PidfdTarget::Reaped) => return Ok(None),
        Ok(PidfdTarget::Pid(pid)) => {
            return Err(unassessable(
                id,
                what,
                &format!(
                    "the mounted /proc numbers the target {pid} (0 = invisible), so it is an outer pid namespace's"
                ),
                None,
                None,
            ));
        }
        Err(why) => return Err(unassessable(id, what, &why.reason, why.source, None)),
    }
    // A pid recycled before open means the original is already gone. An unassessable pid
    // (hidepid, EPERM) is NOT gone and must not be treated as one.
    match exists_checked(id, &proc_dir) {
        Existence::Present => Ok(Some(pidfd)),
        Existence::Gone => Ok(None),
        Existence::Unknown => Err(unassessable(id, what, "the OS refused the existence query", None, None)),
    }
}

/// [`Error::Unassessable`] for `id`, logged at `warn`. `why` (with `source`'s text, if any) and
/// the `pidfd_open` errno, if there was one, are in the message, so the cause survives a
/// caller that only prints it; `source()` is the OS error behind `why`, else the errno.
fn unassessable(
    id: ProcessId,
    what: &'static str,
    why: &str,
    source: Option<std::io::Error>,
    pidfd_errno: Option<rustix::io::Errno>,
) -> Error {
    let mut detail = format!("pid {} identity could not be confirmed: {why}", id.pid());
    if let Some(source) = &source {
        detail.push_str(&format!(": {source}"));
    }
    if let Some(errno) = pidfd_errno {
        detail.push_str(&format!(" (pidfd_open: {errno})"));
    }
    detail.push_str(&format!("; {what}"));
    log::warn!("wait: {detail}");
    Error::Unassessable {
        detail,
        source: source.or_else(|| pidfd_errno.map(std::io::Error::from)),
    }
}

/// `pidfd_open`, with a test seam: a forced errno (see [`fault::force_pidfd_open_errno_once`])
/// replaces the syscall once.
#[cfg(test)]
fn pidfd_open_checked(raw: Pid) -> Result<rustix::fd::OwnedFd, rustix::io::Errno> {
    match fault::take_forced_pidfd_open_errno() {
        Some(errno) => Err(errno),
        None => pidfd_open(raw, PidfdFlags::empty()),
    }
}
#[cfg(not(test))]
fn pidfd_open_checked(raw: Pid) -> Result<rustix::fd::OwnedFd, rustix::io::Errno> {
    pidfd_open(raw, PidfdFlags::empty())
}

/// `id.exists_in(proc_dir)`, with a test seam: a forced [`Existence`] (see
/// [`fault::force_exists_once`]) replaces the `/proc` read once, to drive the `Unknown` arms; runs
/// [`fault::between_check_and_read`]'s hook first.
#[cfg(test)]
fn exists_checked(id: ProcessId, proc_dir: &ProcDir) -> Existence {
    fault::run_between_hook();
    match fault::take_forced_exists() {
        Some(existence) => existence,
        None => id.exists_in(proc_dir),
    }
}
#[cfg(not(test))]
fn exists_checked(id: ProcessId, proc_dir: &ProcDir) -> Existence {
    id.exists_in(proc_dir)
}

/// `id.is_alive_in(proc_dir)`, with a test seam: a forced [`Liveness`] (see
/// [`fault::force_alive_once`]) replaces the `/proc` read once.
#[cfg(test)]
fn alive_checked(id: ProcessId, proc_dir: &ProcDir) -> Liveness {
    match fault::take_forced_alive() {
        Some(liveness) => liveness,
        None => id.is_alive_in(proc_dir),
    }
}
#[cfg(not(test))]
fn alive_checked(id: ProcessId, proc_dir: &ProcDir) -> Liveness {
    id.is_alive_in(proc_dir)
}

#[cfg(test)]
pub(crate) mod fault {
    use crate::identity::{Existence, Liveness};
    use std::cell::Cell;
    thread_local! {
        static FORCE_PIDFD_OPEN_ERRNO: Cell<Option<rustix::io::Errno>> = const { Cell::new(None) };
        static FORCE_EXISTS: Cell<Option<Existence>> = const { Cell::new(None) };
        static FORCE_ALIVE: Cell<Option<Liveness>> = const { Cell::new(None) };
        static BETWEEN_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    }

    /// Clears the between-check-and-read hook on drop, consumed or not.
    #[must_use = "dropping this immediately disarms the hook; bind it for the probe's duration"]
    pub(crate) struct BetweenHook(());

    /// Run `hook` once on THIS thread, after `open_verified` has checked that `/proc` describes
    /// the target and before it reads `{pid}/stat`: the window in which a `/proc` looked up by
    /// path could differ from the one that was checked.
    pub(crate) fn between_check_and_read(hook: impl FnOnce() + 'static) -> BetweenHook {
        BETWEEN_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
        BetweenHook(())
    }

    impl Drop for BetweenHook {
        fn drop(&mut self) {
            BETWEEN_HOOK.with(|h| h.borrow_mut().take());
        }
    }

    pub(super) fn run_between_hook() {
        if let Some(hook) = BETWEEN_HOOK.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }

    /// Disarms the forced errno on drop, so an unconsumed force can't leak into the next test on
    /// this thread.
    #[must_use = "dropping this immediately disarms the forced errno; bind it for the probe's duration"]
    pub(crate) struct ForcedPidfdOpenErrno(());

    /// Force the NEXT `pidfd_open` inside `open_verified` on THIS thread to fail with `errno`,
    /// consumed the first time it's read.
    pub(crate) fn force_pidfd_open_errno_once(errno: rustix::io::Errno) -> ForcedPidfdOpenErrno {
        FORCE_PIDFD_OPEN_ERRNO.with(|f| f.set(Some(errno)));
        ForcedPidfdOpenErrno(())
    }

    impl Drop for ForcedPidfdOpenErrno {
        fn drop(&mut self) {
            FORCE_PIDFD_OPEN_ERRNO.with(|f| f.set(None));
        }
    }

    pub(crate) fn take_forced_pidfd_open_errno() -> Option<rustix::io::Errno> {
        FORCE_PIDFD_OPEN_ERRNO.with(|f| f.take())
    }

    /// Disarms the forced `Existence` on drop; see [`ForcedPidfdOpenErrno`].
    #[must_use = "dropping this immediately disarms the forced existence; bind it for the probe's duration"]
    pub(crate) struct ForcedExists(());

    /// Force the NEXT `id.exists()` re-verify inside `open_verified` on THIS thread to answer
    /// `existence`, consumed the first time it's read.
    pub(crate) fn force_exists_once(existence: Existence) -> ForcedExists {
        FORCE_EXISTS.with(|f| f.set(Some(existence)));
        ForcedExists(())
    }

    impl Drop for ForcedExists {
        fn drop(&mut self) {
            FORCE_EXISTS.with(|f| f.set(None));
        }
    }

    pub(crate) fn take_forced_exists() -> Option<Existence> {
        FORCE_EXISTS.with(|f| f.take())
    }

    /// Disarms the forced `Liveness` on drop; see [`ForcedPidfdOpenErrno`].
    #[must_use = "dropping this immediately disarms the forced liveness; bind it for the probe's duration"]
    pub(crate) struct ForcedAlive(());

    /// Force the NEXT `id.is_alive_in(..)` inside `open_verified` on THIS thread to answer
    /// `liveness`, consumed the first time it's read.
    pub(crate) fn force_alive_once(liveness: Liveness) -> ForcedAlive {
        FORCE_ALIVE.with(|f| f.set(Some(liveness)));
        ForcedAlive(())
    }

    impl Drop for ForcedAlive {
        fn drop(&mut self) {
            FORCE_ALIVE.with(|f| f.set(None));
        }
    }

    pub(crate) fn take_forced_alive() -> Option<Liveness> {
        FORCE_ALIVE.with(|f| f.take())
    }
}

pub(crate) fn block_until_exit(id: ProcessId, deadline: Option<Option<Instant>>) -> Result<bool, Error> {
    let Some(pidfd) = open_verified(id, "foreign process wait", "its exit cannot be observed")? else {
        return Ok(true);
    };
    loop {
        let mut fds = [PollFd::new(&pidfd, PollFlags::IN)];
        // rustix 1.x poll takes Option<&Timespec> (None = infinite); Timespec is
        // { tv_sec: i64, tv_nsec: Nsecs }. Build it from the remaining duration.
        let ts = crate::wait::remaining(deadline).map(|d| rustix::event::Timespec {
            tv_sec: d.as_secs().min(i64::MAX as u64) as i64,
            tv_nsec: d.subsec_nanos() as _,
        });
        match poll(&mut fds, ts.as_ref()) {
            Ok(0) => return Ok(false), // timed out, still alive
            Ok(_) => {
                let revents = fds[0].revents();
                // POLLNVAL on an fd we own and hold alive is a contract violation.
                debug_assert!(
                    !revents.contains(PollFlags::NVAL),
                    "pidfd reported POLLNVAL — owned-fd contract violation"
                );
                if revents.contains(PollFlags::ERR) {
                    return Err(Error::Io(std::io::Error::other("pidfd poll returned POLLERR")));
                }
                return Ok(true); // POLLIN (zombie) / POLLHUP (reaped) => exited
            }
            Err(rustix::io::Errno::INTR) => continue, // retry only on EINTR (no cap)
            Err(e) => return Err(Error::Io(std::io::Error::from(e))),
        }
    }
}

pub(crate) fn kill(id: ProcessId) -> Result<(), Error> {
    let Some(pidfd) = open_verified(id, "foreign process kill", "no signal was sent")? else {
        return Ok(());
    };
    match pidfd_send_signal(&pidfd, Signal::KILL) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::SRCH) => Ok(()), // exited between re-verify and signal
        Err(e) => Err(Error::Io(std::io::Error::from(e))),
    }
}

pub(crate) fn terminate(id: ProcessId) -> Result<(), Error> {
    let Some(pidfd) = open_verified(id, "foreign process terminate", "no signal was sent")? else {
        return Ok(());
    };
    match pidfd_send_signal(&pidfd, Signal::TERM) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::SRCH) => Ok(()), // exited between re-verify and signal
        Err(e) => Err(Error::Io(std::io::Error::from(e))),
    }
}

#[cfg(test)]
#[path = "linux_tests.rs"]
mod linux_tests;

#[cfg(test)]
#[path = "linux_namespace_tests.rs"]
mod linux_namespace_tests;
