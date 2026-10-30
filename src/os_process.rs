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

pub(crate) mod drive;
#[cfg(test)]
pub(crate) mod fake;
#[cfg(target_os = "macos")]
#[allow(dead_code, reason = "MacProcess, its consumer, lands in a later task of #839")]
pub(crate) mod macos;

#[cfg(target_os = "linux")]
use std::os::fd::BorrowedFd;
#[cfg(windows)]
use std::os::windows::io::BorrowedHandle;

/// One process, as the OS names it. `Send` so a driver may move it to a blocking thread.
pub(crate) trait OsProcess: Send + fmt::Debug {
    /// The identity this object was opened for.
    fn identity(&self) -> ProcessId;

    /// Send `sig`. [`Sent::Gone`] when the process is no longer the one opened.
    fn signal(&mut self, sig: Sig) -> Result<Sent, Error>;

    /// Look at the process once, without blocking. A [`Exit::Running`] look carries what to wait
    /// on for the next change; the wait ends on any change, so look again after it.
    fn exited(&mut self) -> Result<Exit<'_>, Error>;

    /// The OS handle this object waits on, for a reactor that registers it itself. `None` for a
    /// stand-in with no OS handle.
    #[cfg(any(target_os = "linux", windows))]
    fn os_handle(&self) -> Option<OsHandle<'_>>;
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
    /// Linux: the pidfd; readable once the process has exited.
    #[cfg(target_os = "linux")]
    Readable(BorrowedFd<'a>),
    /// macOS: a kqueue armed for the process's exit.
    #[cfg(target_os = "macos")]
    Kqueue(&'a macos::ExitWatch),
    /// Windows: the process handle; signalled once the process has exited.
    #[cfg(windows)]
    Signalled(BorrowedHandle<'a>),
}

/// The OS handle behind an [`OsProcess`]: the pidfd.
#[cfg(target_os = "linux")]
pub(crate) type OsHandle<'a> = BorrowedFd<'a>;
/// The OS handle behind an [`OsProcess`]: the process handle.
#[cfg(windows)]
pub(crate) type OsHandle<'a> = BorrowedHandle<'a>;

/// The operation an [`open`] is for. It names the operation in `Unsupported` and `Unassessable`
/// errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    Wait,
    Kill,
    Terminate,
}

/// Open the process `id` names. `Ok(None)`: it is gone, or its pid now names another process.
pub(crate) fn open(id: ProcessId, op: Op) -> Result<Option<Box<dyn OsProcess>>, Error> {
    let _ = (id, op);
    #[cfg(target_os = "linux")]
    unimplemented!("OsProcess on Linux lands in task 2 of #839");
    #[cfg(windows)]
    unimplemented!("OsProcess on Windows lands in task 3 of #839");
    #[cfg(target_os = "macos")]
    unimplemented!("OsProcess on macOS lands in task 4 of #839");
}
