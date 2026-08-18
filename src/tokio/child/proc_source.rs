//! The process backend behind an async [`Child`](super::Child): tokio's own `process::Child`, or
//! (Windows) a raw `CreateProcessW` child that tokio's `Command` cannot express. `Child` forwards
//! its wait/kill/stream operations here so it stays backend-blind, mirroring the sync
//! [`ProcHandle`](crate::child::proc_handle::ProcHandle).

use std::process::ExitStatus;

use crate::error::Error;

/// The process backend behind an async [`Child`](super::Child).
// The `Tokio` arm carries `::tokio::process::Child` inline — the common (and, on Unix, only)
// variant, and previously a plain `Child` field, so keeping it inline is no regression. Boxing it
// to shrink the rare Windows-only `Raw` variant would add a heap allocation + indirection to every
// async spawn, so the size difference is accepted deliberately.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum ProcSource {
    /// A `::tokio::process::Child` (the default path).
    Tokio(::tokio::process::Child),
    /// A raw `CreateProcessW` child owning its process handle directly — the executable/argv[0]
    /// independence (and, later, arbitrary descriptors) that tokio's `Command` cannot express.
    #[cfg(windows)]
    Raw(crate::tokio::spawn::windows_raw::RawAsyncChild),
}

impl ProcSource {
    /// Take tokio's own stdin stream (the Raw backend serves its piped std ends via `owned_std`,
    /// so it has none here).
    pub(crate) fn take_stdin(&mut self) -> Option<::tokio::process::ChildStdin> {
        match self {
            ProcSource::Tokio(c) => c.stdin.take(),
            #[cfg(windows)]
            ProcSource::Raw(_) => None,
        }
    }
    pub(crate) fn take_stdout(&mut self) -> Option<::tokio::process::ChildStdout> {
        match self {
            ProcSource::Tokio(c) => c.stdout.take(),
            #[cfg(windows)]
            ProcSource::Raw(_) => None,
        }
    }
    pub(crate) fn take_stderr(&mut self) -> Option<::tokio::process::ChildStderr> {
        match self {
            ProcSource::Tokio(c) => c.stderr.take(),
            #[cfg(windows)]
            ProcSource::Raw(_) => None,
        }
    }

    /// Block until the child exits, returning its status.
    pub(crate) async fn wait(&mut self) -> Result<ExitStatus, Error> {
        match self {
            ProcSource::Tokio(c) => c.wait().await.map_err(Error::Io),
            #[cfg(windows)]
            ProcSource::Raw(r) => r.wait().await,
        }
    }

    /// Exit status if the child has already exited (non-blocking).
    pub(crate) fn try_wait(&mut self) -> Result<Option<ExitStatus>, Error> {
        match self {
            ProcSource::Tokio(c) => c.try_wait().map_err(Error::Io),
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
            ProcSource::Tokio(c) => c.id().is_some(),
            ProcSource::Raw(_) => true,
        }
    }

    /// Signal a hard kill (does not reap). Already-exited ⇒ `Ok`.
    pub(crate) fn start_kill(&mut self) -> Result<(), Error> {
        match self {
            ProcSource::Tokio(c) => c.start_kill().map_err(Error::Io),
            #[cfg(windows)]
            ProcSource::Raw(r) => r.start_kill(),
        }
    }

    /// `true` once the backend has collected the child's status, so no reap remains.
    pub(crate) fn is_reaped(&self) -> bool {
        match self {
            ProcSource::Tokio(c) => c.id().is_none(),
            #[cfg(windows)]
            ProcSource::Raw(r) => r.is_reaped(),
        }
    }

    /// Wait for exit, then let the backend reap. **Never kills** — the signal is issued by the
    /// caller, on the dropping thread.
    /// **Invariant:** no `wait()` future for this child is in flight when this runs.
    pub(crate) fn wait_and_reap(&mut self, pid: u32) {
        match self {
            ProcSource::Tokio(c) => super::reaper::wait_and_reap(c, pid, true),
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
            ProcSource::Tokio(_) => panic!("wait observer requires the raw CreateProcessW backend"),
        }
    }
}
