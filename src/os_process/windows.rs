//! Windows: an [`OsProcess`] over a verified process handle. The handle pins the kernel object, so
//! a pid reused after [`open`](super::open) can be neither signalled nor mistaken for the original.
//!
//! Opening asks for `PROCESS_QUERY_LIMITED_INFORMATION` and for `SYNCHRONIZE` and `PROCESS_TERMINATE`,
//! and drops each of the two that the process refuses. Without `SYNCHRONIZE` a look reads the exit
//! code, which proves an exit and refuses to prove the absence of one; without `PROCESS_TERMINATE`
//! a kill of a live process fails with the OS's denial.

use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{PROCESS_ACCESS_RIGHTS, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE};

use super::{Exit, Op, OsProcess, WaitFor};
use crate::error::{win32_io_error, Error};
use crate::identity::{
    windows_exit_look, windows_open_dropping_refused, windows_terminate_held, HandleIdentity, Liveness, Look, Opened,
    ProcessId, Termination,
};
use crate::signal::{Sent, Sig};

pub(crate) mod cancel;

#[derive(Debug)]
pub(crate) struct WindowsProcess {
    id: ProcessId,
    handle: OwnedHandle,
    /// Whether the handle was granted `SYNCHRONIZE`: it decides how a look reads the exit.
    has_synchronize: bool,
}

impl WindowsProcess {
    /// Open the process `id` names. `Ok(None)`: it is gone, or its pid now names another process.
    /// `_op` is ignored: every open asks for the same rights (the parameter goes with `Op`).
    pub(crate) fn open(id: ProcessId, _op: Op) -> Result<Option<Self>, Error> {
        let Some((handle, granted)) = open_verified(id)? else {
            return Ok(None);
        };
        #[cfg(test)]
        crate::wait::read_probe::mark("identity verified");
        Ok(Some(Self {
            id,
            // SAFETY: `open_verified` hands over a freshly opened handle that nothing else owns.
            handle: unsafe { OwnedHandle::from_raw_handle(handle.0 as _) },
            has_synchronize: granted.0 & PROCESS_SYNCHRONIZE.0 != 0,
        }))
    }

    fn raw(&self) -> HANDLE {
        HANDLE(self.handle.as_raw_handle())
    }
}

fn close(handle: HANDLE) {
    // Match identity/windows.rs: a failed CloseHandle of an owned handle is a contract
    // violation, asserted in debug.
    let closed = unsafe { CloseHandle(handle) };
    debug_assert!(closed.is_ok(), "CloseHandle of an owned process handle should not fail");
}

/// Whether `handle` still names `id`'s process. `Ok(false)`: the pid was recycled before the
/// open, so the original is gone. The handle is closed on `Ok(false)` and on `Err`; on `Ok(true)`
/// the caller still holds it.
fn holds_process(handle: HANDLE, id: ProcessId) -> Result<bool, Error> {
    match crate::identity::windows_handle_identity(handle, id) {
        HandleIdentity::Same => Ok(true),
        HandleIdentity::Different => {
            close(handle);
            Ok(false)
        }
        HandleIdentity::Unreadable(e) => {
            log::warn!(
                "wait: pid {} opened but its identity could not be verified ({e})",
                id.pid()
            );
            close(handle);
            Err(Error::Unassessable {
                detail: format!("pid {} opened but its identity could not be verified", id.pid()),
                source: Some(win32_io_error(e)),
            })
        }
    }
}

/// Opens `id` with the rights it grants (see the module doc), verifies the handle names that
/// process, and returns it with the rights granted. `None`: it is gone, or its pid was recycled
/// before the open. The caller closes the handle.
pub(crate) fn open_verified(id: ProcessId) -> Result<Option<(HANDLE, PROCESS_ACCESS_RIGHTS)>, Error> {
    let (opened, granted) = windows_open_dropping_refused(id.pid(), &[PROCESS_SYNCHRONIZE, PROCESS_TERMINATE]);
    let handle = match opened {
        Opened::Found(h) => h,
        Opened::Gone => return Ok(None), // no such pid => exited
        // Denied on a LIVE process => a real failure: reporting "exited" would let a
        // supervisor conclude a healthy service had died, and an Unknown liveness must NOT be
        // reported as a successful kill. The error comes from the classifier: `is_alive()` below
        // overwrites the thread's last-error.
        Opened::Denied(e) => {
            return match id.is_alive() {
                Liveness::Dead => Ok(None),
                Liveness::Alive | Liveness::Unknown => {
                    log::warn!(
                        "wait: pid {} could not be opened ({e}) - reporting an error, not an exit or a kill",
                        id.pid()
                    );
                    Err(Error::Unassessable {
                        detail: format!("pid {} could not be opened", id.pid()),
                        source: Some(win32_io_error(e)),
                    })
                }
            }
        }
    };
    // The handle already in hand answers the recycle question with no race; a second by-pid
    // lookup would not. An UNREADABLE token is not proof the target is gone, so it is an error.
    if !holds_process(handle, id)? {
        return Ok(None); // recycled before open - the original is gone
    }
    Ok(Some((handle, granted)))
}

/// Windows has no per-process graceful-termination signal.
pub(super) fn terminate_unsupported() -> Error {
    Error::Unsupported {
        op: "graceful terminate (SIGTERM-equivalent)".into(),
        platform: "windows",
        detail: "Windows has no per-process graceful-termination signal; for a contained \
                 child use graceful_shutdown_tree (CTRL_BREAK to the group)"
            .into(),
    }
}

impl OsProcess for WindowsProcess {
    fn signal(&self, sig: Sig) -> Result<Sent, Error> {
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

    fn exited(&self) -> Result<Exit<'_>, Error> {
        match windows_exit_look(self.raw(), self.has_synchronize) {
            Ok(Look::Exited) => Ok(Exit::Exited),
            // `exit_look` reports a running process only for a handle that can be waited on.
            Ok(Look::Running) => Ok(Exit::Running(WaitFor::Signalled(self.handle.as_handle()))),
            Err(e) => Err(Error::Io(win32_io_error(e))),
        }
    }
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
