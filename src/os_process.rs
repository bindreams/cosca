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
#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "macos")]
pub(crate) mod macos;
#[cfg(windows)]
pub(crate) mod windows;

#[cfg(target_os = "linux")]
use std::os::fd::BorrowedFd;
#[cfg(windows)]
use std::os::windows::io::BorrowedHandle;

/// One process, as the OS names it. `Send` so a driver may move it to a blocking thread.
pub(crate) trait OsProcess: Send + fmt::Debug {
    /// Send `sig`. [`Sent::Gone`] when the process is no longer the one opened.
    fn signal(&mut self, sig: Sig) -> Result<Sent, Error>;

    /// Look at the process once, without blocking. A [`Exit::Running`] look carries what to wait
    /// on for the next change; the wait ends on any change, so look again after it.
    fn exited(&mut self) -> Result<Exit<'_>, Error>;
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

/// The operation an [`open`] is for. It names the operation in `Unsupported` and `Unassessable`
/// errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    Wait,
    Kill,
    Terminate,
}

/// Open the process `id` names. `Ok(None)`: it is gone, or its pid now names another process.
/// [`Op::Terminate`] on Windows is `Unsupported`: no handle is opened.
pub(crate) fn open(id: ProcessId, op: Op) -> Result<Option<Box<dyn OsProcess>>, Error> {
    #[cfg(target_os = "linux")]
    return Ok(crate::wait::backend::open_verified(id, op.into())?
        .map(|pidfd| Box::new(linux::LinuxProcess::new(id, pidfd)) as Box<dyn OsProcess>));
    #[cfg(windows)]
    return Ok(windows::WindowsProcess::open(id, op)?.map(|p| Box::new(p) as Box<dyn OsProcess>));
    #[cfg(target_os = "macos")]
    return Ok(macos::MacProcess::open(id, op)?.map(|p| Box::new(p) as Box<dyn OsProcess>));
}

/// Hard-kill the process `id` names, identity-verified. Already gone, or its pid now names another
/// process: `Ok`.
pub(crate) fn kill_by_id(id: ProcessId) -> Result<(), Error> {
    signal_by_id(id, Op::Kill, Sig::Kill)
}

/// Send the graceful termination signal to the process `id` names, identity-verified, without
/// waiting. Already gone: `Ok`. Windows has no such per-process signal: `Unsupported`.
#[cfg(unix)]
pub(crate) fn terminate_by_id(id: ProcessId) -> Result<(), Error> {
    signal_by_id(id, Op::Terminate, Sig::Term)
}

/// There is no [`Sig`] to send for it on Windows, and [`open`] refuses [`Op::Terminate`] there with
/// the `Unsupported` this returns.
#[cfg(windows)]
pub(crate) fn terminate_by_id(id: ProcessId) -> Result<(), Error> {
    open(id, Op::Terminate).map(|_| ())
}

fn signal_by_id(id: ProcessId, op: Op, sig: Sig) -> Result<(), Error> {
    let Some(mut process) = open(id, op)? else {
        return Ok(());
    };
    // `Gone` and `Delivered` are both success: nothing is left for the caller to do.
    process.signal(sig).map(|_: Sent| ())
}

#[cfg(target_os = "linux")]
impl From<Op> for crate::wait::backend::PidfdOp {
    fn from(op: Op) -> Self {
        match op {
            Op::Wait => Self::Wait,
            Op::Kill => Self::Kill,
            Op::Terminate => Self::Terminate,
        }
    }
}
