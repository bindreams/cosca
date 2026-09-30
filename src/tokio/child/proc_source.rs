//! The process backend behind an async [`Child`](super::Child): tokio's own `process::Child`, or
//! (Windows) a raw `CreateProcessW` child that tokio's `Command` cannot express. `Child` forwards
//! its wait/kill/stream operations here so it stays backend-blind, mirroring the sync
//! [`ProcHandle`](crate::child::proc_handle::ProcHandle).

use std::process::ExitStatus;

use crate::error::Error;
#[cfg(all(test, unix))]
use crate::send_log::Via;
use crate::signal::Sig;

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
    /// A `::tokio::process::Child` (the default path).
    Tokio {
        child: ::tokio::process::Child,
        /// Linux: the pidfd the spawn handshake opened while the child was held before `exec`.
        /// It names this process for good, so a signal through it cannot reach a process that
        /// later reuses the pid. `None` only when the child was already gone at the handshake
        /// (and in tests that build the backend by hand).
        #[cfg(target_os = "linux")]
        pidfd: Option<std::os::fd::OwnedFd>,
    },
    /// A raw `CreateProcessW` child owning its process handle directly — the executable/argv[0]
    /// independence (and, later, arbitrary descriptors) that tokio's `Command` cannot express.
    #[cfg(windows)]
    Raw(crate::tokio::spawn::windows_raw::RawAsyncChild),
}

/// What [`ProcSource::signal`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sent {
    /// The signal was handed to the OS for the child.
    Delivered,
    /// Nothing was delivered: the child is gone, or there was no handle to send through.
    Gone,
}

impl ProcSource {
    /// A tokio child with no handle beyond tokio's own.
    pub(crate) fn tokio(child: ::tokio::process::Child) -> ProcSource {
        ProcSource::Tokio {
            child,
            #[cfg(target_os = "linux")]
            pidfd: None,
        }
    }

    /// This backend, holding `held` as the pidfd that names the child.
    #[cfg(target_os = "linux")]
    pub(crate) fn with_pidfd(mut self, held: std::os::fd::OwnedFd) -> ProcSource {
        match &mut self {
            ProcSource::Tokio { pidfd, .. } => *pidfd = Some(held),
        }
        self
    }

    /// The pidfd naming this child, if it has one.
    #[cfg(target_os = "linux")]
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "the root waits borrow it from a later unit on")
    )]
    pub(crate) fn pidfd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        use std::os::fd::AsFd;
        match self {
            ProcSource::Tokio { pidfd, .. } => pidfd.as_ref().map(AsFd::as_fd),
        }
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
    /// the child is already gone (reaped by tokio or by someone else) or, on Linux, this backend
    /// holds no pidfd to send through; it is not an error.
    ///
    /// - **Linux:** `pidfd_send_signal` on the handshake pidfd, never by pid, so a foreign reap
    ///   followed by a pid reuse cannot redirect it. `ESRCH` is `Gone`.
    /// - **macOS:** by pid, after a `waitid(WNOWAIT)` peek that finds no foreign reap. That closes
    ///   the window except for a reap by someone else between the peek and the send, which is
    ///   principle 5's accepted gap: macOS has no handle to send through.
    /// - **Windows:** `Kill` only, through the process handle.
    pub(crate) fn signal(&self, sig: Sig) -> Result<Sent, Error> {
        match self {
            #[cfg(target_os = "linux")]
            ProcSource::Tokio { child, pidfd } => {
                let Some(pid) = child.id() else {
                    log::debug!("the child is already reaped; nothing to signal");
                    return Ok(Sent::Gone);
                };
                let Some(pidfd) = pidfd else {
                    log::debug!("child {pid} has no pidfd to signal it through; sending nothing");
                    return Ok(Sent::Gone);
                };
                #[cfg(test)]
                crate::send_log::record(pid, sig, Via::Pidfd);
                match rustix::process::pidfd_send_signal(pidfd, sig.as_rustix()) {
                    Ok(()) => Ok(Sent::Delivered),
                    Err(rustix::io::Errno::SRCH) => {
                        log::debug!("pidfd_send_signal({sig:?}) to child {pid}: it is already gone");
                        Ok(Sent::Gone)
                    }
                    Err(e) => Err(Error::Io(crate::error::io_context("pidfd_send_signal", e.into()))),
                }
            }
            #[cfg(target_os = "macos")]
            ProcSource::Tokio { child } => {
                use crate::wait::exit_only::{self, Peek, Target};
                let Some(pid) = child.id() else {
                    log::debug!("the child is already reaped; nothing to signal");
                    return Ok(Sent::Gone);
                };
                match exit_only::peek(&Target::pid(pid, None)).map_err(Error::Io)? {
                    Peek::Foreign(_) => {
                        log::debug!("child {pid} was reaped by someone else; nothing to signal");
                        return Ok(Sent::Gone);
                    }
                    Peek::Running | Peek::Exit(_) => {}
                }
                // SAFETY: the peek found `pid` to be our own unreaped child.
                if unsafe { libc::kill(pid as libc::pid_t, sig.as_libc()) } == 0 {
                    #[cfg(test)]
                    crate::send_log::record(pid, sig, Via::Pid);
                    return Ok(Sent::Delivered);
                }
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::ESRCH) {
                    log::debug!("kill({pid}, {sig:?}): the child is already gone");
                    return Ok(Sent::Gone);
                }
                Err(Error::Io(crate::error::io_context("kill", e)))
            }
            #[cfg(windows)]
            ProcSource::Tokio { .. } | ProcSource::Raw(_) if sig != Sig::Kill => {
                debug_assert!(false, "Windows can send only Kill, not {sig:?}");
                Err(Error::Unsupported {
                    op: format!("sending {sig:?} to a process"),
                    platform: "windows",
                    detail: "only Kill is sent through a process handle".to_owned(),
                })
            }
            #[cfg(windows)]
            ProcSource::Tokio { child } => {
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
            ProcSource::Raw(r) => r.start_kill().map(|()| Sent::Delivered),
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
    /// `done_ok` is `false` for every caller: both reach here only past an
    /// [`is_reaped`](ProcSource::is_reaped) check or on a child that was never awaited, so an
    /// already-reaped one is a broken precondition, not a case to return quietly from — the shape
    /// this entry exists to remove.
    pub(crate) fn wait_and_reap(&mut self, pid: u32) {
        match self {
            ProcSource::Tokio { child: c, .. } => super::wait_and_reap(c, pid, false),
            #[cfg(windows)]
            ProcSource::Raw(r) => r.wait_and_reap(),
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
