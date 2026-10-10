//! Backend-agnostic owned-process handle. A `Child` holds one of these and
//! forwards its wait/kill/identity operations to whichever backend spawned it:
//! the std path's [`SharedChild`], or (Windows only) the raw `CreateProcessW`
//! child [`RawChild`]. Keeping the fan-out here lets `Child` stay backend-blind.

use std::io;
use std::process::ExitStatus;
use std::time::Instant;

use super::shared::SharedChild;
use crate::error::ChildFate;

#[cfg(windows)]
use super::spawn::windows_raw::RawChild;

/// What a teardown of the root did: the child's fate, and what it could not do, for the event's one
/// warn (a child it could not signal and left running, a reap that failed after the kill).
#[derive(Debug)]
pub(crate) struct Torn {
    pub(crate) fate: ChildFate,
    pub(crate) left: Option<String>,
}

impl Torn {
    /// A teardown with nothing to warn of.
    pub(crate) fn new(fate: ChildFate) -> Torn {
        Torn { fate, left: None }
    }
}

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

    /// The unique id the handle checks its by-pid actions against. Tests only.
    #[cfg(all(target_os = "macos", test))]
    pub(crate) fn adopted_unique(&self) -> Option<u64> {
        let ProcHandle::Std(shared) = self;
        shared.adopted_unique()
    }

    /// Whether this handle itself has reaped the root: [`wait`](Self::wait),
    /// [`try_wait`](Self::try_wait) or [`wait_deadline`](Self::wait_deadline) recorded the exit.
    /// True from the moment the reap is recorded, even before the recording waiter returns. A reap by someone else is not seen here.
    /// `Raw` (Windows) reads the process handle's signalled state: nothing is consumed there.
    #[cfg_attr(not(unix), allow(dead_code, reason = "read only on unix and in tests"))]
    pub(crate) fn is_reaped(&self) -> bool {
        match self {
            ProcHandle::Std(s) => s.is_reaped(),
            #[cfg(windows)]
            ProcHandle::Raw(r) => r.is_reaped(),
        }
    }

    /// Whether the root is still this handle's child to act on; see
    /// [`RootState`](crate::signal::RootState).
    #[cfg(unix)]
    pub(crate) fn state(&self) -> crate::signal::RootState {
        let ProcHandle::Std(s) = self;
        s.state()
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

    /// The pidfd naming the process, if it holds one (Linux).
    #[cfg(unix)]
    pub(crate) fn pidfd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        match self {
            #[cfg(target_os = "linux")]
            ProcHandle::Std(s) => s.pidfd(),
            #[cfg(not(target_os = "linux"))]
            ProcHandle::Std(_) => None,
        }
    }

    /// Whether the process is still running, read without reaping it.
    #[cfg(unix)]
    pub(crate) fn is_running(&self) -> io::Result<bool> {
        match self {
            ProcHandle::Std(s) => s.is_running(),
        }
    }

    /// Reap a child a tree kill has just ended, sending it nothing: the kill bounds the wait.
    /// Returns a failed reap for the caller's one warn, as [`teardown_on_drop`](Self::teardown_on_drop)
    /// does.
    #[cfg(unix)]
    pub(crate) fn reap_after_tree_kill(&self) -> Torn {
        use crate::error::ChildFate;
        match self {
            ProcHandle::Std(s) => {
                #[cfg(test)]
                crate::child::spawn::fault::run_between_kill_and_wait();
                match s.wait() {
                    Ok(_) => Torn::new(ChildFate::Reaped),
                    Err(e) => Torn {
                        fate: if e.raw_os_error() == Some(libc::ECHILD) {
                            ChildFate::Gone
                        } else {
                            ChildFate::Killed
                        },
                        left: teardown_wait_failure(s.id(), &e),
                    },
                }
            }
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
    ///
    /// Returns the child's fate, and what it could not do for the caller's one warn: a child it
    /// could not signal and left running, or a reap that failed after the kill. It logs neither
    /// above `debug`. (The Windows `Raw` arm still logs its own refusal.)
    pub(crate) fn teardown_on_drop(&self, id: crate::identity::ProcessId) -> Torn {
        use crate::error::ChildFate;
        #[cfg(all(test, unix))]
        crate::child::fault::note_root_teardown();
        match self {
            ProcHandle::Std(s) => {
                #[cfg(unix)]
                let (kill_result, delivered) = {
                    let sent = s.kill_sent();
                    let delivered = matches!(sent, Ok(crate::signal::Sent::Delivered));
                    (sent.map(drop), delivered)
                };
                #[cfg(not(unix))]
                let kill_result = s.kill();
                match std_teardown_action(&kill_result) {
                    // Kill succeeded: reap the zombie with a bounded blocking wait (SIGKILL
                    // cannot be caught, so the child's exit is guaranteed — this is the
                    // sanctioned real-child-exit wait).
                    StdTeardown::ReapBlocking => match s.wait() {
                        Ok(_) => Torn::new(ChildFate::Reaped),
                        Err(e) => {
                            let left = teardown_wait_failure(s.id(), &e);
                            #[cfg(unix)]
                            if e.raw_os_error() == Some(libc::ECHILD) {
                                // Delivered, the kill is `Killed`; found nothing to signal, `Gone`.
                                return Torn {
                                    fate: crate::wait::exit_only::Foreign::Gone.fate(delivered),
                                    left,
                                };
                            }
                            Torn {
                                fate: ChildFate::Killed,
                                left,
                            }
                        }
                    },
                    // Kill failed: NEVER block. Reap non-blockingly; if it was EPERM and the
                    // child is still running (an elevated child we cannot signal), report it.
                    StdTeardown::ReapNonBlocking => {
                        let looked = s.try_wait();
                        let still_running = !matches!(looked, Ok(Some(_)));
                        let permission_denied =
                            matches!(&kill_result, Err(e) if e.kind() == io::ErrorKind::PermissionDenied);
                        let left = (still_running && permission_denied).then(|| {
                            format!(
                                "elevated child {} could not be terminated on drop (permission denied); leaving it running",
                                s.id()
                            )
                        });
                        Torn {
                            fate: crate::child::spawn::fate_of_a_look(looked.map_err(|e| e.raw_os_error()), Some(id)),
                            left,
                        }
                    }
                }
            }
            #[cfg(windows)]
            ProcHandle::Raw(r) => Torn::new(r.teardown_on_drop(id)),
        }
    }
}

/// A failed reap after a successful kill: `ECHILD` (someone else reaped the child) is expected
/// and logged at `debug`; anything else leaves a zombie or an unread exit, and is returned for the
/// caller's warn.
fn teardown_wait_failure(pid: u32, e: &io::Error) -> Option<String> {
    #[cfg(unix)]
    let gone = e.raw_os_error() == Some(libc::ECHILD);
    #[cfg(windows)]
    let gone = false;
    if gone {
        log::debug!("teardown of child {pid}: it was reaped elsewhere before the reap after the kill");
        None
    } else {
        Some(format!("teardown of child {pid}: the reap after the kill failed: {e}"))
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
