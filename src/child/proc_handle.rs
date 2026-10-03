//! Backend-agnostic owned-process handle. A `Child` holds one of these and
//! forwards its wait/kill/identity operations to whichever backend spawned it:
//! the std path's [`SharedChild`], or (Windows only) the raw `CreateProcessW`
//! child [`RawChild`]. Keeping the fan-out here lets `Child` stay backend-blind.

use std::io;
use std::process::ExitStatus;
use std::time::Instant;

use super::shared::SharedChild;

#[cfg(windows)]
use super::spawn::windows_raw::RawChild;

/// The process backend behind an owned [`Child`](super::Child).
#[derive(Debug)]
pub(crate) enum ProcHandle {
    /// std-spawned child, adopted into a [`SharedChild`] for concurrent wait/kill.
    Std(SharedChild),
    /// Raw `CreateProcessW` child owning the process handle directly.
    #[cfg(windows)]
    Raw(RawChild),
}

impl ProcHandle {
    /// Adopt a std-spawned child. Adoption never reaps, so nothing is reaped yet.
    pub(crate) fn std(shared: SharedChild) -> ProcHandle {
        ProcHandle::Std(shared)
    }

    /// Whether this handle itself has reaped the root: [`wait`](Self::wait),
    /// [`try_wait`](Self::try_wait) or [`wait_deadline`](Self::wait_deadline) recorded the exit.
    /// Read from the state that records the reap, so it is `true` from the moment of the reap, even
    /// while the waiter that made it is still returning. A reap by someone else is not seen here.
    /// `Raw` (Windows) reads the process handle's signalled state: nothing is consumed there.
    #[cfg_attr(
        not(unix),
        allow(dead_code, reason = "the Windows drop path does not read it yet; the tests do")
    )]
    pub(crate) fn is_reaped(&self) -> bool {
        match self {
            ProcHandle::Std(s) => s.is_reaped(),
            #[cfg(windows)]
            ProcHandle::Raw(r) => r.is_reaped(),
        }
    }

    /// Block until the child exits.
    pub(crate) fn wait(&self) -> io::Result<ExitStatus> {
        match self {
            ProcHandle::Std(s) => s.wait(),
            #[cfg(windows)]
            ProcHandle::Raw(r) => r.wait(),
        }
    }

    /// The exit status if the child has already exited, else `None`.
    pub(crate) fn try_wait(&self) -> io::Result<Option<ExitStatus>> {
        match self {
            ProcHandle::Std(s) => s.try_wait(),
            #[cfg(windows)]
            ProcHandle::Raw(r) => r.try_wait(),
        }
    }

    /// Block until the child exits or `deadline` passes (`Ok(None)` at expiry).
    pub(crate) fn wait_deadline(&self, deadline: Instant) -> io::Result<Option<ExitStatus>> {
        match self {
            // `SharedChild` decides expiry itself, from `crate::wait::now()`, never early.
            ProcHandle::Std(s) => s.wait_deadline(deadline),
            #[cfg(windows)]
            ProcHandle::Raw(r) => r.wait_deadline(deadline),
        }
    }

    /// Hard-kill the process (already-exited is success).
    pub(crate) fn kill(&self) -> io::Result<()> {
        match self {
            ProcHandle::Std(s) => s.kill(),
            #[cfg(windows)]
            ProcHandle::Raw(r) => r.kill(),
        }
    }

    /// [`kill`](ProcHandle::kill), reporting whether a signal was sent.
    #[cfg(unix)]
    pub(crate) fn kill_sent(&self) -> io::Result<crate::signal::Sent> {
        match self {
            ProcHandle::Std(s) => s.kill_sent(),
        }
    }

    /// The OS process id.
    pub(crate) fn id(&self) -> u32 {
        match self {
            ProcHandle::Std(s) => s.id(),
            #[cfg(windows)]
            ProcHandle::Raw(r) => r.id(),
        }
    }

    /// Best-effort teardown for `kill_on_drop`: kill then reap. NEVER blocks on an
    /// unkillable child (an elevated child a plain parent cannot signal — POSIX EPERM,
    /// Windows ACCESS_DENIED). The `Std` arm dispatches on the OBSERVED kill result, not
    /// on any "elevation requested" flag: a child that gained privilege on its OWN (a
    /// setuid helper, or `sudo` spawned with no `.elevate()`) also returns EPERM, and
    /// keying on a request flag would take the blocking `wait()` and hang Drop forever.
    /// The Windows `Raw` arm handles its own higher-integrity runas case via its flag.
    pub(crate) fn teardown_on_drop(&self) {
        #[cfg(all(test, unix))]
        crate::child::fault::note_root_teardown();
        match self {
            ProcHandle::Std(s) => {
                let kill_result = s.kill();
                match std_teardown_action(&kill_result) {
                    // Kill succeeded: reap the zombie with a bounded blocking wait (SIGKILL
                    // cannot be caught, so the child's exit is guaranteed — this is the
                    // sanctioned real-child-exit wait).
                    StdTeardown::ReapBlocking => {
                        if let Err(e) = s.wait() {
                            log_teardown_wait_failure(s.id(), &e);
                        }
                    }
                    // Kill failed: NEVER block. Reap non-blockingly; if it was EPERM and the
                    // child is still running (an elevated child we cannot signal), warn.
                    StdTeardown::ReapNonBlocking => {
                        let still_running = !matches!(s.try_wait(), Ok(Some(_)));
                        let permission_denied =
                            matches!(&kill_result, Err(e) if e.kind() == io::ErrorKind::PermissionDenied);
                        if still_running && permission_denied {
                            log::warn!(
                                "elevated child {} could not be terminated on drop (permission denied); leaving it running",
                                s.id()
                            );
                        }
                    }
                }
            }
            #[cfg(windows)]
            ProcHandle::Raw(r) => r.teardown_on_drop(),
        }
    }
}

/// A failed reap after a successful kill: `ECHILD` (someone else reaped the child) is expected
/// and quiet; anything else leaves a zombie or an unread exit, and is a `warn`.
fn log_teardown_wait_failure(pid: u32, e: &io::Error) {
    #[cfg(unix)]
    let gone = e.raw_os_error() == Some(libc::ECHILD);
    #[cfg(windows)]
    let gone = false;
    if gone {
        log::debug!("teardown of child {pid}: it was reaped elsewhere before the reap after the kill");
    } else {
        log::warn!("teardown of child {pid}: the reap after the kill failed: {e}");
    }
}

/// The teardown action for a `Std` child, decided purely from the observed kill result.
/// Extracted so the "any `Err` → NEVER a blocking wait" invariant is unit-testable without
/// a real EPERM (root-only) child.
#[derive(Debug, PartialEq, Eq)]
enum StdTeardown {
    /// Kill succeeded: reap with a bounded blocking wait.
    ReapBlocking,
    /// Kill failed: reap non-blockingly; the child may survive (elevated → EPERM).
    ReapNonBlocking,
}

fn std_teardown_action(kill_result: &io::Result<()>) -> StdTeardown {
    match kill_result {
        Ok(()) => StdTeardown::ReapBlocking,
        Err(_) => StdTeardown::ReapNonBlocking,
    }
}

#[cfg(test)]
#[path = "proc_handle_tests.rs"]
mod proc_handle_tests;
