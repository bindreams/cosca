//! Windows: an [`OsProcess`] over a verified process handle. The handle pins the kernel object, so
//! a pid reused after [`open`](super::open) can be neither signalled nor mistaken for the original.
//!
//! A handle opened for [`Op::Kill`] lacks `SYNCHRONIZE`, so [`OsProcess::exited`] on it is the OS
//! error; wait on an [`Op::Wait`] one.

use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};

use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::WaitForSingleObject;

use super::{Exit, Op, OsProcess, WaitFor};
use crate::error::{win32_io_error, Error};
use crate::identity::{windows_terminate_held, ProcessId, Termination};
use crate::signal::{Sent, Sig};

#[derive(Debug)]
pub(crate) struct WindowsProcess {
    id: ProcessId,
    handle: OwnedHandle,
}

impl WindowsProcess {
    /// Open the process `id` names for `op`. `Ok(None)`: it is gone, or its pid now names another
    /// process. `op` picks the access rights, as the per-operation functions of [`crate::wait`]
    /// did.
    pub(crate) fn open(id: ProcessId, op: Op) -> Result<Option<Self>, Error> {
        use crate::wait::backend::{open_verified, open_verified_for_kill};
        let handle = match op {
            Op::Wait => open_verified(id)?,
            Op::Kill => open_verified_for_kill(id)?,
            Op::Terminate => return Err(terminate_unsupported()),
        };
        let Some(handle) = handle else {
            return Ok(None);
        };
        #[cfg(test)]
        crate::wait::read_probe::mark("identity verified");
        Ok(Some(Self {
            id,
            // SAFETY: `open_verified*` hands over a freshly opened handle that nothing else owns.
            handle: unsafe { OwnedHandle::from_raw_handle(handle.0 as _) },
        }))
    }

    fn raw(&self) -> HANDLE {
        HANDLE(self.handle.as_raw_handle())
    }
}

/// Windows has no per-process graceful-termination signal.
pub(crate) fn terminate_unsupported() -> Error {
    Error::Unsupported {
        op: "graceful terminate (SIGTERM-equivalent)".into(),
        platform: "windows",
        detail: "Windows has no per-process graceful-termination signal; for a contained \
                 child use graceful_shutdown_tree (CTRL_BREAK to the group)"
            .into(),
    }
}

impl OsProcess for WindowsProcess {
    fn signal(&mut self, sig: Sig) -> Result<Sent, Error> {
        match sig {
            Sig::Kill => match windows_terminate_held(self.raw()) {
                Termination::Terminated => Ok(Sent::Delivered),
                Termination::Exited => Ok(Sent::Gone),
                Termination::Failed(e) => {
                    log::warn!("wait: TerminateProcess(pid {}) failed ({e})", self.id.pid());
                    Err(Error::Io(win32_io_error(e)))
                }
            },
        }
    }

    fn exited(&mut self) -> Result<Exit<'_>, Error> {
        // SAFETY: `raw` is the live handle `self` owns; a zero-timeout wait only reads its state.
        match unsafe { WaitForSingleObject(self.raw(), 0) } {
            WAIT_OBJECT_0 => Ok(Exit::Exited),
            WAIT_TIMEOUT => Ok(Exit::Running(WaitFor::Signalled(self.handle.as_handle()))),
            _ => Err(Error::Io(std::io::Error::last_os_error())),
        }
    }
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
