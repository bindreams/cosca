//! The process backend behind an async [`Child`](super::Child): tokio's own `process::Child`, or
//! (Windows) a raw `CreateProcessW` child that tokio's `Command` cannot express. `Child` forwards
//! its wait/kill/stream operations here so it stays backend-blind, mirroring the sync
//! [`ProcHandle`](crate::child::proc_handle::ProcHandle).

use std::process::ExitStatus;

use crate::error::Error;
use crate::signal::{Sent, Sig};

/// The process backend behind an async [`Child`](super::Child).
// The `Tokio` arm carries `::tokio::process::Child` inline — the common (and, on Unix, only)
// variant, and previously a plain `Child` field, so keeping it inline is no regression. Boxing it
// to shrink the rare Windows-only `Raw` variant would add a heap allocation + indirection to every
// async spawn, so the size difference is accepted deliberately.
#[allow(
    clippy::large_enum_variant,
    reason = "boxing Raw to shrink it would add an allocation to every async spawn on the common Tokio path"
)]
#[derive(Debug)]
pub(crate) enum ProcSource {
    /// A `::tokio::process::Child` (the default path), with what names the process for good.
    Tokio {
        child: ::tokio::process::Child,
        /// The pidfd the spawn handshake opened while the child was held before `exec`. It names
        /// this process for good, so a signal through it cannot reach a process that later reuses
        /// the pid.
        #[cfg(target_os = "linux")]
        pidfd: std::os::fd::OwnedFd,
        /// The child's unique id, read right after the spawn (see
        /// [`crate::signal::read_identity`]): the only identity a by-pid signal on macOS is checked
        /// against. `None`: the child was already reaped when it was read.
        #[cfg(target_os = "macos")]
        identity: Option<u64>,
    },
    /// A raw `CreateProcessW` child owning its process handle directly — the executable/argv[0]
    /// independence (and, later, arbitrary descriptors) that tokio's `Command` cannot express.
    #[cfg(windows)]
    Raw(crate::tokio::spawn::windows_raw::RawAsyncChild),
}

/// Counts the backend's drop, which drops tokio's `Child` with it, for the tests that pin the
/// hand-off to tokio's orphan queue (`fault::count_backend_drops`).
#[cfg(test)]
impl Drop for ProcSource {
    fn drop(&mut self) {
        super::fault::note_backend_drop();
    }
}

impl ProcSource {
    /// A tokio child that `pidfd`, opened by the spawn handshake, names.
    #[cfg(target_os = "linux")]
    pub(crate) fn new(child: ::tokio::process::Child, pidfd: std::os::fd::OwnedFd) -> ProcSource {
        ProcSource::Tokio { child, pidfd }
    }

    /// A tokio child whose unique id was read as `identity`.
    #[cfg(target_os = "macos")]
    pub(crate) fn new(child: ::tokio::process::Child, identity: Option<u64>) -> ProcSource {
        ProcSource::Tokio { child, identity }
    }

    /// A tokio child on Windows, where tokio's own process handle is the one that names it.
    #[cfg(windows)]
    pub(crate) fn new(child: ::tokio::process::Child) -> ProcSource {
        ProcSource::Tokio { child }
    }

    /// Take tokio's own stdin stream (the Raw backend serves its piped std ends via `owned_std`,
    /// so it has none here).
    pub(crate) fn take_stdin(&mut self) -> Option<::tokio::process::ChildStdin> {
        match self {
            ProcSource::Tokio { child: c, .. } => c.stdin.take(),
            #[cfg(windows)]
            ProcSource::Raw(_) => None,
        }
    }
    pub(crate) fn take_stdout(&mut self) -> Option<::tokio::process::ChildStdout> {
        match self {
            ProcSource::Tokio { child: c, .. } => c.stdout.take(),
            #[cfg(windows)]
            ProcSource::Raw(_) => None,
        }
    }
    pub(crate) fn take_stderr(&mut self) -> Option<::tokio::process::ChildStderr> {
        match self {
            ProcSource::Tokio { child: c, .. } => c.stderr.take(),
            #[cfg(windows)]
            ProcSource::Raw(_) => None,
        }
    }

    /// Block until the child exits, returning its status.
    pub(crate) async fn wait(&mut self) -> Result<ExitStatus, Error> {
        match self {
            ProcSource::Tokio { child: c, .. } => c.wait().await.map_err(Error::Io),
            #[cfg(windows)]
            ProcSource::Raw(r) => r.wait().await,
        }
    }

    /// Exit status if the child has already exited (non-blocking).
    pub(crate) fn try_wait(&mut self) -> Result<Option<ExitStatus>, Error> {
        match self {
            ProcSource::Tokio { child: c, .. } => c.try_wait().map_err(Error::Io),
            #[cfg(windows)]
            ProcSource::Raw(r) => r.try_wait(),
        }
    }

    /// Whether the backend still holds something that pins the child's pid against reuse.
    /// tokio's `Child` replaces its inner state the moment `wait`/`try_wait` observes the exit,
    /// dropping the guard that holds the process handle (`id()` goes `None` with it); the raw
    /// backend owns its handle for the child's whole life and never unpins.
    #[cfg(windows)]
    pub(crate) fn pins_pid(&self) -> bool {
        match self {
            ProcSource::Tokio { child: c, .. } => c.id().is_some(),
            ProcSource::Raw(_) => true,
        }
    }

    /// Send `sig` to the child. Does not reap. [`Sent::Gone`] means nothing was delivered because
    /// the child is already gone (reaped by tokio or by someone else); it is not an error.
    ///
    /// - **Linux:** `pidfd_send_signal` on the handshake pidfd, never by pid, so a foreign reap
    ///   followed by a pid reuse cannot redirect it.
    /// - **macOS:** by pid, only while the pid still has the unique id read at spawn. The window
    ///   between that check and `kill(2)` is macOS's own (principle 5): it has no handle to send
    ///   through.
    /// - **Windows:** through the process handle.
    pub(crate) fn signal(&self, sig: Sig) -> Result<Sent, Error> {
        match self {
            #[cfg(unix)]
            ProcSource::Tokio { child, .. } if child.id().is_none() => {
                log::debug!("the child is already reaped; {sig:?} not sent");
                Ok(Sent::Gone)
            }
            #[cfg(target_os = "linux")]
            ProcSource::Tokio { child, pidfd } => {
                let pid = child.id().expect("checked above");
                crate::signal::via_pidfd(Some(std::os::fd::AsFd::as_fd(pidfd)), pid, sig).map_err(Error::Io)
            }
            #[cfg(target_os = "macos")]
            ProcSource::Tokio { child, identity } => {
                let pid = child.id().expect("checked above");
                crate::signal::via_verified_pid(pid, *identity, sig).map_err(Error::Io)
            }
            #[cfg(windows)]
            ProcSource::Tokio { child } => {
                let Sig::Kill = sig;
                use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, HANDLE, WAIT_FAILED};
                use windows::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};
                // tokio drops its handle once it has reaped the child.
                let Some(h) = child.raw_handle() else {
                    return Ok(Sent::Gone);
                };
                // SAFETY: tokio owns the live process handle while `raw_handle` is `Some`; exit
                // code 1 is the forced-kill code std's `Child::kill` uses.
                match unsafe { TerminateProcess(HANDLE(h), 1) } {
                    Ok(()) => Ok(Sent::Delivered),
                    // As std's `Child::kill`: a process that is already exiting answers
                    // `ACCESS_DENIED`, which is success, unless the handle cannot even be waited on.
                    Err(e) if e.code() == windows::core::HRESULT::from_win32(ERROR_ACCESS_DENIED.0) => {
                        // SAFETY: as above; a zero-timeout wait only reads the handle's state.
                        if unsafe { WaitForSingleObject(HANDLE(h), 0) } == WAIT_FAILED {
                            Err(Error::Io(e.into()))
                        } else {
                            Ok(Sent::Delivered)
                        }
                    }
                    Err(e) => Err(Error::Io(e.into())),
                }
            }
            #[cfg(windows)]
            ProcSource::Raw(r) => {
                let Sig::Kill = sig;
                r.start_kill().map(|()| Sent::Delivered)
            }
        }
    }

    /// `true` once the backend has collected the child's status, so no reap remains.
    pub(crate) fn is_reaped(&self) -> bool {
        match self {
            ProcSource::Tokio { child: c, .. } => c.id().is_none(),
            #[cfg(windows)]
            ProcSource::Raw(r) => r.is_reaped(),
        }
    }

    /// Block until the child has exited, then let the backend reap it. **Never kills** — the
    /// caller's own successful kill is what bounds the wait.
    /// **Invariant:** no `wait()` future for this child is in flight when this runs.
    ///
    /// The caller's child was never awaited, so an already-reaped one is a broken precondition,
    /// asserted in debug.
    #[cfg(unix)]
    pub(crate) fn wait_and_reap(&mut self, pid: u32) {
        match self {
            ProcSource::Tokio { child: c, .. } => super::wait_and_reap(c, pid),
        }
    }

    /// Install the per-instance test wait observer (raw backend only). Panics on a Tokio child —
    /// the observer seam exists solely for the raw async wait path.
    #[cfg(all(test, windows))]
    pub(crate) fn install_wait_observer(
        &mut self,
        started: ::tokio::sync::oneshot::Sender<()>,
        outcome: ::tokio::sync::oneshot::Sender<crate::child::spawn::windows_raw::WaitOutcome>,
    ) {
        match self {
            ProcSource::Raw(r) => r.set_observer(started, outcome),
            ProcSource::Tokio { .. } => panic!("wait observer requires the raw CreateProcessW backend"),
        }
    }
}
