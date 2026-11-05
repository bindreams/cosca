//! Layer 1 of the process stack: one OS-facing object per process, found by [`open`] and driven
//! by [`drive`].
//!
//! An [`OsProcess`] answers two questions about a process, "did it exit" and "signal it", and
//! never reaps it. It owns no wait loop: when the process still runs, [`OsProcess::exited`] hands
//! out the OS primitive a caller can block or register on ([`WaitFor`]), and the driver loops
//! "look; if running, wait on what the look returned".

use std::fmt;

use crate::error::Error;
use crate::identity::ProcessId;
use crate::signal::{Sent, Sig};

pub(crate) mod child;
pub(crate) mod drive;
#[cfg(test)]
pub(crate) mod fake;
#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "macos")]
pub(crate) mod macos;
#[cfg(unix)]
pub(crate) mod poll;
#[cfg(windows)]
pub(crate) mod windows;

#[cfg(unix)]
use std::os::fd::BorrowedFd;
#[cfg(windows)]
use std::os::windows::io::BorrowedHandle;

/// One process, as the OS names it. `Send` so a driver may move it to a blocking thread, and
/// `Sync` so one open serves a signal and a wait from different threads.
pub(crate) trait OsProcess: Send + Sync + fmt::Debug {
    /// Send `sig`. [`Sent::Gone`] when the process is no longer the one opened.
    fn signal(&self, sig: Sig) -> Result<Sent, Error>;

    /// Look at the process once, without blocking. A [`Exit::Running`] look carries what to wait
    /// on for the next change; the wait ends on any change, so look again after it.
    fn exited(&self) -> Result<Exit<'_>, Error>;

    /// The OS object that names the process, lent to platform-only consumers (Job Objects, resume,
    /// cgroup attach). A fake lends its own wake fd or event, which names no process: code that
    /// uses a handle is tested against real processes.
    #[cfg(any(target_os = "linux", windows))]
    fn os_handle(&self) -> child::OsHandle<'_>;
}

/// What one look at a process found.
#[derive(Debug)]
pub(crate) enum Exit<'a> {
    Exited,
    Running(WaitFor<'a>),
}

/// What to block or register on to learn that a running process may have changed. Spurious
/// wakes are allowed; a wake is never the answer, the next look is.
#[derive(Debug)]
pub(crate) enum WaitFor<'a> {
    /// Unix: a descriptor that polls readable once the process has exited, and that nothing reads:
    /// the pidfd on Linux, a kqueue armed for the exit on macOS.
    #[cfg(unix)]
    Readable(BorrowedFd<'a>),
    /// Windows: the process handle; signalled once the process has exited.
    #[cfg(windows)]
    Signalled(BorrowedHandle<'a>),
}

/// What is left undone when an [`open`] cannot go ahead, for the errors it returns: the one open
/// serves every act on the process.
#[cfg(unix)]
pub(crate) const OPEN_CONSEQUENCE: &str = "its exit cannot be observed and no signal was sent";

/// What a message calls a child whose pid is not known ([`OsChild::pid`](child::OsChild::pid)).
pub(crate) const PIDLESS_CHILD: &str = "the child (pid unknown)";

/// How a message names a child: `child 4242`, or what stands for a pid that is not known.
pub(crate) fn child_named(pid: Option<u32>) -> String {
    pid.map_or_else(|| PIDLESS_CHILD.to_owned(), |pid| format!("child {pid}"))
}

/// Open the process `id` names. `Ok(None)`: it is gone, or its pid now names another process.
pub(crate) fn open(id: ProcessId) -> Result<Option<Box<dyn OsProcess>>, Error> {
    #[cfg(target_os = "linux")]
    return Ok(linux::open::open_verified(id)?
        .map(|pidfd| Box::new(linux::LinuxProcess::new(Some(id.pid()), pidfd)) as Box<dyn OsProcess>));
    #[cfg(windows)]
    return Ok(windows::WindowsProcess::open(id)?.map(|p| Box::new(p) as Box<dyn OsProcess>));
    #[cfg(target_os = "macos")]
    return Ok(macos::MacProcess::open(id)?.map(|p| Box::new(p) as Box<dyn OsProcess>));
}

/// Hard-kill the held process. Already gone: `Ok`.
pub(crate) fn kill(p: &dyn OsProcess) -> Result<(), Error> {
    // `Gone` and `Delivered` are both success: nothing is left for the caller to do.
    p.signal(Sig::Kill).map(|_: Sent| ())
}

/// Send the graceful termination signal to the held process, without waiting. Already gone: `Ok`.
#[cfg(unix)]
pub(crate) fn terminate(p: &dyn OsProcess) -> Result<(), Error> {
    p.signal(Sig::Term).map(|_: Sent| ())
}

/// There is no [`Sig`] to send for it on Windows: `Unsupported`.
#[cfg(windows)]
pub(crate) fn terminate(_p: &dyn OsProcess) -> Result<(), Error> {
    Err(windows::terminate_unsupported())
}

/// [`terminate`] the process `id` names, identity-verified. Already gone: `Ok`. Windows: `Unsupported`,
/// with nothing opened.
#[cfg(unix)]
#[cfg_attr(
    not(feature = "tokio"),
    allow(dead_code, reason = "only the async child sends its graceful signal by number")
)]
pub(crate) fn terminate_by_id(id: ProcessId) -> Result<(), Error> {
    match open(id)? {
        Some(process) => terminate(&*process),
        None => Ok(()),
    }
}

/// There is no [`Sig`] to send for it on Windows: `Unsupported`, with nothing opened.
#[cfg(windows)]
pub(crate) fn terminate_by_id(_id: ProcessId) -> Result<(), Error> {
    Err(windows::terminate_unsupported())
}
