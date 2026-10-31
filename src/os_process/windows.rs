//! Windows: an [`OsProcess`] over a verified process handle. The handle pins the kernel object, so
//! a pid reused after [`open`](super::open) can be neither signalled nor mistaken for the original.
//!
//! A handle opened for [`Op::Kill`] lacks `SYNCHRONIZE`, so [`OsProcess::exited`] on it is an
//! error; wait on an [`Op::Wait`] one.

use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};

use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{
    WaitForSingleObject, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    PROCESS_TERMINATE,
};

use super::{Exit, Op, OsProcess, WaitFor};
use crate::error::{win32_io_error, Error};
use crate::identity::{windows_terminate_held, HandleIdentity, Liveness, Opened, ProcessId, Termination};
use crate::signal::{Sent, Sig};

pub(crate) mod cancel;
#[cfg(test)]
#[cfg_attr(
    not(feature = "tokio"),
    allow(unused_imports, reason = "only consumers are the tokio tests")
)]
pub(crate) use cancel::armed_probe;
#[cfg_attr(
    not(feature = "tokio"),
    allow(
        unused_imports,
        reason = "only consumers are the async driver and the async raw backend, behind the tokio feature"
    )
)]
pub(crate) use cancel::{new_cancel_event, signal_cancel, wait_process_or_cancel};

#[derive(Debug)]
pub(crate) struct WindowsProcess {
    id: ProcessId,
    op: Op,
    handle: OwnedHandle,
}

impl WindowsProcess {
    /// Open the process `id` names for `op`. `Ok(None)`: it is gone, or its pid now names another
    /// process.
    pub(crate) fn open(id: ProcessId, op: Op) -> Result<Option<Self>, Error> {
        let handle = match op {
            Op::Wait => open_verified(id)?,
            Op::Kill => open_verified_for_kill(id)?,
        };
        let Some(handle) = handle else {
            return Ok(None);
        };
        #[cfg(test)]
        crate::wait::read_probe::mark("identity verified");
        Ok(Some(Self {
            id,
            op,
            // SAFETY: `open_verified*` hands over a freshly opened handle that nothing else owns.
            handle: unsafe { OwnedHandle::from_raw_handle(handle.0 as _) },
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

/// Opens `id` for waiting and verifies the handle names that process. `None`: it is gone, or its
/// pid was recycled before the open. The caller closes the handle.
pub(crate) fn open_verified(id: ProcessId) -> Result<Option<HANDLE>, Error> {
    open_held(
        id,
        PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
        "to watch for its exit",
        "an exit",
    )
}

/// [`open_verified`] for terminating: the mask holds `PROCESS_TERMINATE` and the query right, so
/// the SAME held handle pins the kernel object (pid-reuse-safe) and lets identity be re-verified
/// before terminating.
fn open_verified_for_kill(id: ProcessId) -> Result<Option<HANDLE>, Error> {
    open_held(
        id,
        PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
        "to terminate it",
        "a kill",
    )
}

/// Opens `id` with `access` and verifies the handle names that process. `to` and `not_reported`
/// word the denial's error: "pid N could not be opened `to`" and "not `not_reported`".
fn open_held(
    id: ProcessId,
    access: PROCESS_ACCESS_RIGHTS,
    to: &str,
    not_reported: &str,
) -> Result<Option<HANDLE>, Error> {
    let handle = match crate::identity::windows_open_classified(id.pid(), access) {
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
                        "wait: pid {} could not be opened {to} ({e}) - reporting an error, not {not_reported}",
                        id.pid()
                    );
                    Err(Error::Unassessable {
                        detail: format!("pid {} could not be opened {to}", id.pid()),
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
    Ok(Some(handle))
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
        // A handle opened for a signal lacks `SYNCHRONIZE`.
        if self.op != Op::Wait {
            return Err(super::opened_for_a_signal());
        }
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
