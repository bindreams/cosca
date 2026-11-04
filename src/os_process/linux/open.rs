//! Linux pidfd primitives for [`crate::os_process`]. `pidfd_open` returns a fd that
//! becomes readable (POLLIN) when the task becomes a zombie (exits); polling never reaps.
//! A signal through the pidfd is identity-bound (no pid-reuse race). A refused `pidfd_open` is
//! [`Error::Unsupported`], a transient one [`Error::Io`] prefixed `pidfd_open:`; the errno
//! classification is documented once, on [`Error::Unsupported`].
//!
//! The kernel floor, the per-syscall versions, and how a refused syscall is classified
//! (`Unsupported` versus `Io`) are in the crate root's "Platform requirements". Without `openat2`
//! the checked `/proc` view cannot be built, and `open_verified_with` is `Unsupported` naming `openat2`.
//! `spawn` probes `pidfd_open` on this process's own pid before it forks ([`probe_pidfd_support_with`]),
//! so a refusal fails the spawn with no child; see `child::spawn::pidfd_handshake` for the rest.

use std::os::fd::AsFd;

use rustix::process::Pid;

use crate::error::Error;
use crate::identity::{Existence, Kernel, Liveness, PidfdTarget, ProcView, ProcessId, ViewUnreadable};
use crate::os_process::OPEN_CONSEQUENCE;

/// The operation an `Unsupported` open names.
const OP_NAME: &str = "process open";

/// Open a pidfd for `id` through `kernel`, re-verifying identity. `Ok(None)` => already gone (treat
/// as exited).
///
/// Every `/proc` read goes through one checked `/proc` dirfd shown to describe `id`'s pid
/// namespace; otherwise [`Error::Unassessable`], never a `Gone` off a foreign `/proc`.
pub(crate) fn open_verified_with(kernel: &dyn Kernel, id: ProcessId) -> Result<Option<rustix::fd::OwnedFd>, Error> {
    debug_assert!(
        id.pid() <= i32::MAX as u32,
        "pid {} exceeds i32::MAX; pidfd cast would truncate",
        id.pid()
    );
    let raw = Pid::from_raw(id.pid() as i32).expect("a resolvable ProcessId is never pid 0");
    match pidfd_open_checked(kernel, raw) {
        Ok(pidfd) => verify_pidfd_target(kernel, id, pidfd),
        Err(rustix::io::Errno::SRCH) => Ok(None),
        // pidfd_open needs a pid that resolves to a thread-group leader task. EINVAL (< 6.16) /
        // ENOENT (>= 6.16) means either a reaped process-group leader whose pid lives on as a PGID
        // (gone), or a non-leader tid: live, or a ptraced zombie thread kept until its tracer
        // waits. Errno alone can't tell, so re-verify.
        Err(e @ (rustix::io::Errno::INVAL | rustix::io::Errno::NOENT)) => verify_without_pidfd(kernel, id, e),
        Err(e) => match refusal_name(e) {
            Some(name) => Err(pidfd_open_unsupported(OP_NAME, name)),
            None => Err(Error::Io(crate::error::io_context(
                "pidfd_open",
                std::io::Error::from(e),
            ))),
        },
    }
}

/// The name of `errno` if `pidfd_open` answering it is a refusal: no pidfd is possible here.
/// The classification is documented on [`Error::Unsupported`].
fn refusal_name(errno: rustix::io::Errno) -> Option<&'static str> {
    match errno {
        rustix::io::Errno::NOSYS => Some("ENOSYS"),
        rustix::io::Errno::PERM => Some("EPERM"),
        rustix::io::Errno::ACCESS => Some("EACCES"),
        rustix::io::Errno::NODEV => Some("ENODEV"),
        _ => None,
    }
}

fn pidfd_open_unsupported(op: &str, errno_name: &str) -> Error {
    Error::Unsupported {
        op: op.into(),
        platform: "linux",
        detail: format!(
            "cosca requires pidfd_open (Linux \u{2265} 5.3), refused here: pidfd_open answered {errno_name}"
        ),
    }
}

/// A `pidfd_open` failure while spawning: a refusal is [`Error::Unsupported`], anything else `Io`.
pub(crate) fn spawn_open_error(errno: rustix::io::Errno) -> Error {
    match refusal_name(errno) {
        Some(name) => pidfd_open_unsupported("spawn", name),
        None => Error::Io(crate::error::io_context("pidfd_open", std::io::Error::from(errno))),
    }
}

/// The pre-fork probe: `pidfd_open` through `kernel` on this process's own pid, closed at once. Spawning forks
/// through std, which cannot hand back a pidfd, so a kernel or filter that refuses `pidfd_open`
/// has to be found out BEFORE the fork, or the child would exist with no pidfd. A refusal is
/// [`Error::Unsupported`] naming `spawn`; any other failure (`EMFILE`, `ENFILE`, `ENOMEM`) is `Io`
/// naming `pidfd_open`. Either way no child exists.
///
/// Two syscalls per spawn, and no cached verdict: a cache is process-global state, and a filter
/// can be installed after the first spawn.
pub(crate) fn probe_pidfd_support_with(kernel: &dyn Kernel) -> Result<(), Error> {
    pidfd_open_checked(kernel, rustix::process::getpid())
        .map(drop)
        .map_err(spawn_open_error)
}

/// The next scripted `pidfd_open` outcome on THIS thread, for a `pidfd_open` made elsewhere: the
/// spawn handshake's is made by the child. See [`fault::force_pidfd_open_script`].
#[cfg(test)]
pub(crate) fn take_scripted_pidfd_open() -> Option<rustix::io::Errno> {
    fault::take_forced_pidfd_open_errno()
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
/// No pidfd to cross-check against, so the view comes from [`proc_view_with`](crate::identity::proc_view_with).
fn verify_without_pidfd(
    kernel: &dyn Kernel,
    id: ProcessId,
    errno: rustix::io::Errno,
) -> Result<Option<rustix::fd::OwnedFd>, Error> {
    if id.signal_says_no_such_process(kernel) {
        return Ok(None);
    }
    match crate::identity::proc_view_with(kernel) {
        ProcView::Same(proc_dir) => match id.exists_in(kernel, &proc_dir) {
            Existence::Gone => Ok(None),
            Existence::Present => match id.is_alive_in(kernel, &proc_dir) {
                Liveness::Dead => Ok(None),
                Liveness::Alive => Err(Error::NotThreadGroupLeader {
                    pid: id.pid(),
                    detail: OPEN_CONSEQUENCE.into(),
                    source: std::io::Error::from(errno),
                }),
                Liveness::Unknown => Err(unassessable(id, "the OS refused the liveness query", None, Some(errno))),
            },
            Existence::Unknown => Err(unassessable(
                id,
                "the OS refused the existence query",
                None,
                Some(errno),
            )),
        },
        ProcView::Diverged => Err(unassessable(
            id,
            "this process's /proc is an outer pid namespace's",
            None,
            Some(errno),
        )),
        ProcView::Unassessable(why) => Err(view_unreadable(id, why, Some(errno))),
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
    kernel: &dyn Kernel,
    id: ProcessId,
    pidfd: rustix::fd::OwnedFd,
) -> Result<Option<rustix::fd::OwnedFd>, Error> {
    let proc_dir = kernel.open_proc().map_err(|why| view_unreadable(id, why, None))?;
    match crate::identity::pidfd_pid_in(kernel, &proc_dir, pidfd.as_fd()) {
        Ok(PidfdTarget::Pid(pid)) if pid == id.pid() => {}
        // Reaped after `pidfd_open`: gone, and nothing to signal.
        Ok(PidfdTarget::Reaped) => return Ok(None),
        Ok(PidfdTarget::Pid(pid)) => {
            return Err(unassessable(
                id,
                &format!(
                    "the mounted /proc numbers the target {pid} (0 = invisible), so it is an outer pid namespace's"
                ),
                None,
                None,
            ));
        }
        Err(why) => return Err(unassessable(id, &why.reason, why.source, None)),
    }
    // A pid recycled before open means the original is already gone. An unassessable pid
    // (hidepid, EPERM) is NOT gone and must not be treated as one.
    match id.exists_in(kernel, &proc_dir) {
        Existence::Present => Ok(Some(pidfd)),
        Existence::Gone => Ok(None),
        Existence::Unknown => Err(unassessable(id, "the OS refused the existence query", None, None)),
    }
}

/// `why`, the `/proc` view that could not be established, as an error for `id`:
/// [`Error::Unsupported`] naming `openat2` when that is missing, else [`unassessable`].
fn view_unreadable(id: ProcessId, why: ViewUnreadable, pidfd_errno: Option<rustix::io::Errno>) -> Error {
    match why.unsupported(OP_NAME) {
        Some(unsupported) => {
            log::warn!("wait: pid {} {OP_NAME}: {unsupported}", id.pid());
            unsupported
        }
        None => unassessable(id, &why.reason, why.source, pidfd_errno),
    }
}

/// [`Error::Unassessable`] for `id`, logged at `warn`. `why` (with `source`'s text, if any) and
/// the `pidfd_open` errno, if there was one, are in the message, so the cause survives a
/// caller that only prints it; `source()` is the OS error behind `why`, else the errno.
fn unassessable(
    id: ProcessId,
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
    detail.push_str(&format!("; {OPEN_CONSEQUENCE}"));
    log::warn!("wait: {detail}");
    Error::Unassessable {
        detail,
        source: source.or_else(|| pidfd_errno.map(std::io::Error::from)),
    }
}

/// `pidfd_open`, with a test seam: a forced errno (see [`fault::force_pidfd_open_errno_once`])
/// replaces the syscall once.
#[cfg(test)]
fn pidfd_open_checked(kernel: &dyn Kernel, raw: Pid) -> Result<rustix::fd::OwnedFd, rustix::io::Errno> {
    match fault::take_forced_pidfd_open_errno() {
        Some(errno) => Err(errno),
        None => kernel.pidfd_open(raw),
    }
}
#[cfg(not(test))]
fn pidfd_open_checked(kernel: &dyn Kernel, raw: Pid) -> Result<rustix::fd::OwnedFd, rustix::io::Errno> {
    kernel.pidfd_open(raw)
}

#[cfg(test)]
pub(crate) mod fault {
    thread_local! {
        static FORCE_PIDFD_OPEN_ERRNO: std::cell::RefCell<std::collections::VecDeque<Option<rustix::io::Errno>>> =
            const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
    }

    /// Disarms the forced errno on drop, so an unconsumed force can't leak into the next test on
    /// this thread.
    #[must_use = "dropping this immediately disarms the forced errno; bind it for the probe's duration"]
    pub(crate) struct ForcedPidfdOpenErrno(());

    /// Force the NEXT `pidfd_open` inside `open_verified` on THIS thread to fail with `errno`,
    /// consumed the first time it's read.
    pub(crate) fn force_pidfd_open_errno_once(errno: rustix::io::Errno) -> ForcedPidfdOpenErrno {
        force_pidfd_open_script([Some(errno)])
    }

    /// Script the next `pidfd_open` calls inside `open_verified` on THIS thread, one entry per
    /// call: `Some(errno)` fails it, `None` lets it through. Calls past the script run for real.
    pub(crate) fn force_pidfd_open_script(
        script: impl IntoIterator<Item = Option<rustix::io::Errno>>,
    ) -> ForcedPidfdOpenErrno {
        FORCE_PIDFD_OPEN_ERRNO.with(|f| *f.borrow_mut() = script.into_iter().collect());
        ForcedPidfdOpenErrno(())
    }

    impl Drop for ForcedPidfdOpenErrno {
        fn drop(&mut self) {
            FORCE_PIDFD_OPEN_ERRNO.with(|f| f.borrow_mut().clear());
        }
    }

    pub(crate) fn take_forced_pidfd_open_errno() -> Option<rustix::io::Errno> {
        FORCE_PIDFD_OPEN_ERRNO.with(|f| f.borrow_mut().pop_front().flatten())
    }
}

#[cfg(test)]
#[path = "open_tests.rs"]
mod open_tests;

#[cfg(test)]
#[path = "open_namespace_tests.rs"]
mod open_namespace_tests;

#[cfg(test)]
#[path = "open_openat2_tests.rs"]
mod open_openat2_tests;
