//! Linux pidfd primitives for [`crate::os_process`]. `pidfd_open` returns a fd that
//! becomes readable (POLLIN) when the task becomes a zombie (exits); polling never reaps.
//! A signal through the pidfd is identity-bound (no pid-reuse race). A refused `pidfd_open` is
//! [`Error::Unsupported`], a transient one [`Error::Io`] prefixed `pidfd_open:`; the errno
//! classification is documented once, on [`Error::Unsupported`].
//!
//! The kernel floor, the per-syscall versions, and how a refused syscall is classified
//! (`Unsupported` versus `Io`) are in the crate root's "Platform requirements". Without `openat2`
//! the checked `/proc` view cannot be built, and `open_verified_with` of an id told by its
//! `starttime` (a host before Linux 6.9) is `Unsupported` naming `openat2`; an id told by its pidfd's
//! inode needs no `/proc` view.
//! `spawn` probes `pidfd_open` on this process's own pid before it forks ([`probe_pidfd_support_with`]),
//! so a refusal fails the spawn with no child; see `child::spawn::pidfd_handshake` for the rest.

use std::os::fd::AsFd as _;

use rustix::process::{Pid, PidfdFlags};

use crate::error::Error;
use crate::identity::{Existence, Kernel, Liveness, PidfdTarget, ProcView, ProcessId, Proof, ViewUnreadable};
use crate::os_process::OPEN_CONSEQUENCE;

/// The operation an `Unsupported` open names.
const OP_NAME: &str = "process open";

/// Open a pidfd for `id` through `kernel`, re-verifying identity. `Ok(None)` => already gone (treat
/// as exited).
///
/// A `Pidfs` id is proved by its pidfd's inode and reads no `/proc`. For a `Ticks` id every `/proc`
/// read goes through one checked `/proc` dirfd shown to describe `id`'s pid namespace; otherwise
/// [`Error::Unassessable`], never a `Gone` off a foreign `/proc`.
pub(crate) fn open_verified_with(kernel: &dyn Kernel, id: ProcessId) -> Result<Option<rustix::fd::OwnedFd>, Error> {
    debug_assert!(
        id.pid() <= i32::MAX as u32,
        "pid {} exceeds i32::MAX; pidfd cast would truncate",
        id.pid()
    );
    if let Some(ino) = id.pidfs_ino() {
        return open_proved(kernel, id, ino);
    }
    let raw = Pid::from_raw(id.pid() as i32).expect("a resolvable ProcessId is never pid 0");
    match kernel.pidfd_open(raw, PidfdFlags::empty()) {
        Ok(pidfd) => verify_pidfd_target(kernel, id, pidfd),
        Err(rustix::io::Errno::SRCH) => Ok(None),
        // pidfd_open needs a pid that resolves to a thread-group leader task. EINVAL (< 6.16) /
        // ENOENT (>= 6.16) means either a reaped process-group leader whose pid lives on as a PGID
        // (gone), or a non-leader tid: live, or a ptraced zombie thread kept until its tracer
        // waits. Errno alone can't tell, so re-verify.
        Err(e @ (rustix::io::Errno::INVAL | rustix::io::Errno::NOENT)) => verify_without_pidfd(kernel, id, e),
        Err(e) => Err(open_error(e)),
    }
}

/// `open_verified_with` for a `Pidfs` id: the pidfd's inode proves it, so no `/proc` is read.
///
/// A pid that holds a thread leading no group opens with `PIDFD_THREAD`: a live one is
/// [`Error::NotThreadGroupLeader`], and one that has exited (a ptraced zombie thread kept until its
/// tracer waits; its pidfd polls readable) is gone. A process reaped after the open still has its
/// inode, so the pidfd is returned and polls readable.
fn open_proved(kernel: &dyn Kernel, id: ProcessId, ino: u64) -> Result<Option<rustix::fd::OwnedFd>, Error> {
    match crate::identity::prove(kernel, id.pid(), ino) {
        Proof::Holds { fd, thread: None } => Ok(Some(fd)),
        Proof::Holds {
            fd,
            thread: Some(errno),
        } => match crate::os_process::poll::is_readable(fd.as_fd()) {
            Ok(true) => Ok(None),
            Ok(false) => Err(Error::NotThreadGroupLeader {
                pid: id.pid(),
                detail: OPEN_CONSEQUENCE.into(),
                source: std::io::Error::from(errno),
            }),
            Err(e) => Err(Error::Io(crate::error::io_context("poll", e))),
        },
        Proof::Lost => Ok(None),
        Proof::Unknown(cause) => Err(open_error(
            cause.errno().expect("a proof is unknown only for a failed pidfd call"),
        )),
    }
}

/// The error for a `pidfd_open` that failed with `errno` for a reason that says nothing about the
/// target: a refusal is [`Error::Unsupported`], anything else [`Error::Io`].
pub(crate) fn open_error(errno: rustix::io::Errno) -> Error {
    match refusal_name(errno) {
        Some(name) => pidfd_open_unsupported(OP_NAME, name),
        None => Error::Io(crate::error::io_context("pidfd_open", std::io::Error::from(errno))),
    }
}

/// The name of `errno` if `pidfd_open` answering it is a refusal: no pidfd is possible here.
/// The classification is documented on [`Error::Unsupported`].
pub(crate) fn refusal_name(errno: rustix::io::Errno) -> Option<&'static str> {
    match errno {
        rustix::io::Errno::NOSYS => Some("ENOSYS"),
        rustix::io::Errno::PERM => Some("EPERM"),
        rustix::io::Errno::ACCESS => Some("EACCES"),
        rustix::io::Errno::NODEV => Some("ENODEV"),
        _ => None,
    }
}

pub(crate) fn pidfd_open_unsupported(op: &str, errno_name: &str) -> Error {
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
    kernel
        .pidfd_open(rustix::process::getpid(), PidfdFlags::empty())
        .map(drop)
        .map_err(spawn_open_error)
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

#[cfg(test)]
#[path = "open_tests.rs"]
mod open_tests;

#[cfg(test)]
#[path = "open_namespace_tests.rs"]
mod open_namespace_tests;

#[cfg(test)]
#[path = "open_pidfs_tests.rs"]
mod open_pidfs_tests;
