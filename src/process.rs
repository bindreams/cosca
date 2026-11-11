//! An open handle on a process this process did not spawn — NO stdio (its pipes belong to its
//! real parent). The handle is opened from a `ProcessId`, never a bare pid, and every act through
//! it (`kill`, `terminate`, `wait*`, `graceful_shutdown`) reaches that process or reports it gone,
//! never a later holder of its pid. The tree acts (`kill_tree`, `terminate_tree`,
//! `graceful_shutdown_tree`) walk by identity and signal each member, through a handle opened by
//! its identity: a pidfd proved to name it on Linux, a process handle on Windows, an audit token on
//! macOS. The tree acts signal the root through this handle instead of a second open of it.
//! `wait()` is a death-watch yielding no `ExitStatus` (the kernel
//! hands exit status only to the real parent — contrast `Child::wait`). Its tree is
//! [`ProcessId::children`] and [`ProcessId::parent`].

use std::time::Duration;

use crate::error::Error;
use crate::identity::{Liveness, ProcessId, RawPid, Resolved};
use crate::os_process::{Exit, OsProcess};

#[path = "process/graceful.rs"]
mod graceful;

/// An open handle on a process, held since [`open`](Self::open). Acts through the handle
/// (`kill`, `terminate`, `wait*`, `graceful_shutdown`) reach this process or report it gone; never
/// a later holder of its pid. The tree acts (`kill_tree`, `terminate_tree`,
/// `graceful_shutdown_tree`) signal each member through a handle opened by its identity (a pidfd
/// proved to name it on Linux, a process handle on Windows, an audit token on macOS); each signals
/// the root through this handle. Not `Clone`: open the [`ProcessId`] again.
#[derive(Debug)]
pub struct Process {
    id: ProcessId,
    os: Box<dyn OsProcess>,
}

impl Process {
    /// Open the process `id` names. `Ok(None)`: no process has this identity (it is fully gone, or
    /// its pid now names another process). A process that has exited but is not yet reaped, or
    /// whose handle someone else still holds, opens as `Some` and reads [`Liveness::Dead`].
    ///
    /// # Errors
    ///
    /// - [`Error::Unassessable`]: the process exists but cannot be opened or its identity
    ///   verified (access denied, a `/proc` that is not this pid namespace's).
    /// - [`Error::Unsupported`]: the OS lacks the mechanism (on Linux, a refused `pidfd_open`).
    /// - [`Error::NotThreadGroupLeader`]: on Linux, `id` names a live thread that is not its
    ///   process's leader.
    /// - [`Error::Io`]: the open failed otherwise (on Linux a failed pidfd call: `pidfd_open`, the
    ///   pidfd's inode read, or its `poll`, prefixed with the call's name; a kqueue that cannot be
    ///   created or armed on macOS).
    pub fn open(id: ProcessId) -> Result<Option<Process>, Error> {
        Self::open_with(&crate::identity::HostKernel, id)
    }

    /// [`open`](Self::open), re-verifying `id` through `kernel`.
    pub(crate) fn open_with(kernel: &dyn crate::identity::Kernel, id: ProcessId) -> Result<Option<Process>, Error> {
        Ok(crate::os_process::open_with(kernel, id)
            .map_err(crate::os_process::OpenFailure::into_open_error)?
            .map(|os| Process { id, os }))
    }

    /// [`open`](Self::open) the process holding `pid` now. `Ok(None)` if no process has the pid;
    /// an exited but unreaped one opens as for [`open`](Self::open). Errors as for `open`; a pid
    /// whose identity cannot be read is [`Error::Unassessable`].
    pub fn open_pid(pid: RawPid) -> Result<Option<Process>, Error> {
        Self::open_pid_with(&crate::identity::HostKernel, pid)
    }

    /// [`open_pid`](Self::open_pid), reading the pid's identity and opening it through `kernel`.
    pub(crate) fn open_pid_with(kernel: &dyn crate::identity::Kernel, pid: RawPid) -> Result<Option<Process>, Error> {
        match ProcessId::of_with(kernel, pid) {
            (Resolved::Found(id), _) => Process::open_with(kernel, id),
            (Resolved::Gone, _) => Ok(None),
            (Resolved::Unknown, cause) => {
                // A pidfd call that failed is the open's own failure: a refusal is `Unsupported`
                // naming the open, as for `open`.
                #[cfg(target_os = "linux")]
                if let Some(call) = cause.call() {
                    return Err(crate::os_process::linux::open::open_error(call));
                }
                Err(crate::identity::unqueryable(&format!("pid {pid}"), cause))
            }
        }
    }

    /// An open handle on this process itself. Errors as for [`open`](Self::open).
    pub fn current() -> Result<Process, Error> {
        Process::open(ProcessId::try_current()?).map(|p| p.expect("the current process is not gone from itself"))
    }

    /// The stable identity (`(pid, key)`).
    pub fn id(&self) -> ProcessId {
        self.id
    }

    /// Whether the process is still running (zombie-exclusive), read through the handle.
    /// [`Liveness::Dead`] once it has exited, [`Liveness::Unknown`] when the look fails (on
    /// Windows, a handle without `SYNCHRONIZE` on a process that has not exited).
    pub fn is_alive(&self) -> Liveness {
        match self.os.exited() {
            Ok(Exit::Exited) => Liveness::Dead,
            Ok(Exit::Running(_)) => Liveness::Alive,
            Err(e) => {
                log::debug!(
                    "is_alive: reading the exit state of pid {} failed: {report}",
                    self.id.pid(),
                    report = crate::error::Report(&e)
                );
                Liveness::Unknown
            }
        }
    }

    /// Block until the process exits. Death-watch — yields no `ExitStatus` (only the real
    /// parent gets one). Non-reaping. Returns at once for a process that has already exited.
    /// `Err` only on a wait failure; on Windows, for a handle without `SYNCHRONIZE`, while the
    /// process runs (`ERROR_ACCESS_DENIED`).
    pub fn wait(&self) -> Result<(), Error> {
        let exited = crate::os_process::drive::exited_held(&*self.os, None)?;
        debug_assert!(exited);
        Ok(())
    }

    /// Block up to `timeout` for the process to exit. `Ok(true)` = exited; `Ok(false)` =
    /// still alive at expiry. `Duration::ZERO` polls once. Errors as for [`wait`](Self::wait).
    pub fn wait_timeout(&self, timeout: Duration) -> Result<bool, Error> {
        crate::os_process::drive::exited_held(&*self.os, Some(timeout))
    }

    /// Hard-kill the process (`SIGKILL` / `TerminateProcess`). Already-dead ⇒ `Ok`; a real
    /// failure (no rights / `EPERM` / access-denied on a live process) ⇒ `Err`.
    /// A process that reused the pid is never signalled, by a different mechanism per OS:
    /// Linux uses `pidfd_send_signal` on the pidfd opened with this handle and Windows pins the
    /// kernel object via its handle. macOS (14.4 and later) has no pidfd; it signals with
    /// `proc_signal_with_audittoken` (the pid plus the process's `p_idversion`, which `exec`
    /// changes), and the kernel checks the version while it holds a reference to the process.
    /// The one residual there: `p_idversion` is 32 bits, so it matches a different process only
    /// if it wrapped by a multiple of 2^32 between the read and the call while the pid was
    /// reused.
    pub fn kill(&self) -> Result<(), Error> {
        crate::os_process::kill(&*self.os)
    }

    /// The held OS process, for the async wrapper.
    #[cfg(feature = "tokio")]
    pub(crate) fn os(&self) -> &dyn OsProcess {
        &*self.os
    }
}

#[cfg(test)]
#[path = "process_tests.rs"]
mod process_tests;
