//! Backend-agnostic owned-process handle. A `Child` holds one of these and
//! forwards its wait/kill/identity operations to whichever backend spawned it:
//! the std path's [`OwnedChild`], or (Windows only) the raw `CreateProcessW`
//! child [`RawChild`]. Keeping the fan-out here lets `Child` stay backend-blind. The `Std` arm
//! also maps an [`OwnedChild`]'s outcomes to the `io::Result`s `Child` expects.

use std::io;
use std::process::ExitStatus;
use std::time::Instant;

use super::owned::{ChildWaitOutcome, OwnedChild};
use crate::error::{ChildFate, Error};
use crate::signal::Sig;

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
    /// std-spawned child, adopted into an [`OwnedChild`] for concurrent wait/kill, and its pid.
    Std(OwnedChild, u32),
    /// Raw `CreateProcessW` child owning the process handle directly.
    #[cfg(windows)]
    Raw(RawChild),
}

/// Whether a wait that finds the child's zombie held by launchd (macOS) says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Orphaned {
    /// The wait reports it: the caller has nobody else to.
    Warn,
    /// The caller reports it itself, with the refusal it goes on to make, or has nothing to report.
    Quiet,
}

impl ProcHandle {
    /// Adopt the std-spawned child `pid`. Adoption never reaps, so nothing is reaped yet.
    pub(crate) fn std(owned: OwnedChild, pid: u32) -> ProcHandle {
        ProcHandle::Std(owned, pid)
    }

    /// The process handle, borrowed from `self`.
    #[cfg(windows)]
    pub(crate) fn raw_handle(&self) -> std::os::windows::io::RawHandle {
        use std::os::windows::io::AsRawHandle;
        match self {
            ProcHandle::Std(s, _) => s.os_handle().as_raw_handle(),
            ProcHandle::Raw(r) => r.raw_handle(),
        }
    }

    /// Whether this handle itself has reaped the root: [`wait`](Self::wait),
    /// [`try_wait`](Self::try_wait) or [`wait_deadline`](Self::wait_deadline) recorded the exit.
    /// True from the moment the reap is recorded, even before the recording waiter returns. A reap by someone else is not seen here.
    /// `Raw` (Windows) reads the reap its own wait recorded: nothing is consumed there, so an exit
    /// nobody waited on yet is not a reap.
    pub(crate) fn is_reaped(&self) -> bool {
        match self {
            ProcHandle::Std(s, _) => s.is_reaped(),
            #[cfg(windows)]
            ProcHandle::Raw(r) => r.is_reaped(),
        }
    }

    /// Whether the root is still this handle's child to act on; see
    /// [`RootState`](crate::signal::RootState).
    #[cfg(unix)]
    pub(crate) fn state(&self) -> crate::signal::RootState {
        let ProcHandle::Std(s, _) = self;
        s.hold().state()
    }

    /// Block until the child exits.
    pub(crate) fn wait(&self) -> io::Result<ExitStatus> {
        match self {
            ProcHandle::Std(s, pid) => match wait_std(s, *pid, None, Orphaned::Warn)? {
                Some(status) => Ok(status),
                None => {
                    debug_assert!(false, "an unbounded wait ended with no exit");
                    Err(io::Error::other("an unbounded wait ended with no exit"))
                }
            },
            #[cfg(windows)]
            ProcHandle::Raw(r) => r.wait(),
        }
    }

    /// The exit status if the child has already exited, else `None`.
    pub(crate) fn try_wait(&self) -> io::Result<Option<ExitStatus>> {
        match self {
            // One look at the present moment.
            ProcHandle::Std(s, pid) => wait_std(s, *pid, Some(crate::wait::now()), Orphaned::Quiet),
            #[cfg(windows)]
            ProcHandle::Raw(r) => r.try_wait(),
        }
    }

    /// Block until the child exits or `deadline` passes (`Ok(None)` at expiry).
    pub(crate) fn wait_deadline(&self, deadline: Instant) -> io::Result<Option<ExitStatus>> {
        match self {
            // `OwnedChild` decides expiry itself, from `crate::wait::now()`, never early.
            ProcHandle::Std(s, pid) => wait_std(s, *pid, Some(deadline), Orphaned::Warn),
            #[cfg(windows)]
            ProcHandle::Raw(r) => r.wait_deadline(deadline),
        }
    }

    /// [`wait`](Self::wait) up to `deadline` (`None`: unbounded), leaving a zombie launchd holds
    /// (macOS) unreported: the caller reports it with the refusal it goes on to make.
    #[cfg(unix)]
    pub(crate) fn wait_until_quiet(&self, deadline: Option<Instant>) -> io::Result<Option<ExitStatus>> {
        let ProcHandle::Std(s, pid) = self;
        wait_std(s, *pid, deadline, Orphaned::Quiet)
    }

    /// Hard-kill the process (already-exited is success).
    pub(crate) fn kill(&self) -> io::Result<()> {
        match self {
            ProcHandle::Std(s, _) => s.signal(Sig::Kill).map(drop).map_err(Error::into_io),
            #[cfg(windows)]
            ProcHandle::Raw(r) => r.kill(),
        }
    }

    /// [`kill`](ProcHandle::kill), reporting whether a signal was sent.
    #[cfg(unix)]
    pub(crate) fn kill_sent(&self) -> io::Result<crate::signal::Sent> {
        let ProcHandle::Std(s, _) = self;
        s.signal(Sig::Kill).map_err(Error::into_io)
    }

    /// [`kill_sent`](Self::kill_sent) for any `sig`.
    #[cfg(target_os = "linux")]
    pub(crate) fn signal_sent(&self, sig: Sig) -> io::Result<crate::signal::Sent> {
        let ProcHandle::Std(s, _) = self;
        s.signal(sig).map_err(Error::into_io)
    }

    /// Whether this thread holds the handle's lock. Tests only.
    #[cfg(all(unix, test))]
    pub(crate) fn is_held_by_current_thread(&self) -> bool {
        let ProcHandle::Std(s, _) = self;
        s.is_held_by_current_thread()
    }

    /// Hold off this handle's own reaps until the result drops (see [`OwnedChild::hold`]).
    #[cfg(unix)]
    pub(crate) fn hold_reaps(&self) -> super::owned::ReapHold<'_> {
        let ProcHandle::Std(s, _) = self;
        s.hold()
    }

    /// Whether the process has exited by the time `grace` is over, read through its handle's own
    /// look: nothing is reaped, and a zombie its tracer holds counts.
    #[cfg(target_os = "linux")]
    pub(crate) fn exited_within(&self, grace: std::time::Duration) -> io::Result<bool> {
        let ProcHandle::Std(s, _) = self;
        s.exited_by(crate::wait::deadline_from(grace)).map_err(Error::into_io)
    }

    /// The pidfd naming the process, if it holds one (Linux).
    #[cfg(unix)]
    pub(crate) fn pidfd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        match self {
            #[cfg(target_os = "linux")]
            ProcHandle::Std(s, _) => Some(s.os_handle()),
            #[cfg(not(target_os = "linux"))]
            ProcHandle::Std(..) => None,
        }
    }

    /// Whether the process is still running, read without reaping it.
    #[cfg(unix)]
    pub(crate) fn is_running(&self) -> io::Result<bool> {
        let ProcHandle::Std(s, _) = self;
        let peeked = s.hold().peek().map_err(Error::into_io)?;
        Ok(matches!(peeked, crate::os_process::child::PeekOutcome::Running))
    }

    /// Reap a child a tree kill has just ended, sending it nothing: the kill bounds the wait.
    /// Returns a failed reap for the caller's one warn, as [`teardown_on_drop`](Self::teardown_on_drop)
    /// does.
    #[cfg(unix)]
    pub(crate) fn reap_after_tree_kill(&self) -> Torn {
        use crate::error::ChildFate;
        let ProcHandle::Std(s, pid) = self;
        #[cfg(test)]
        crate::child::spawn::fault::run_between_kill_and_wait();
        match wait_unbounded(s, *pid) {
            Ok(_) => Torn::new(ChildFate::Reaped),
            // The tree kill was delivered: a wait that finds the exit collected elsewhere, or
            // fails, is `Killed` (see `Foreign::fate`).
            Err(e) => Torn {
                fate: if e.raw_os_error() == Some(libc::ECHILD) {
                    crate::os_process::child::Foreign::Gone.fate(true)
                } else {
                    ChildFate::Killed
                },
                left: teardown_wait_failure(*pid, &e),
            },
        }
    }

    /// The OS process id.
    pub(crate) fn id(&self) -> u32 {
        match self {
            ProcHandle::Std(_, pid) => *pid,
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
    /// The Windows `Raw` arm leaves a handle without `PROCESS_TERMINATE` (a higher-integrity runas
    /// child) running.
    ///
    /// Returns the child's fate, and what it could not do for the caller's one warn: a child it
    /// could not signal and left running, or a reap that failed after the kill. It logs neither
    /// above `debug`.
    pub(crate) fn teardown_on_drop(&self, id: crate::identity::ProcessId) -> Torn {
        use crate::error::ChildFate;
        #[cfg(all(test, unix))]
        crate::child::fault::note_root_teardown();
        #[cfg(all(test, windows))]
        crate::test_frozen::note_root_teardown();
        match self {
            ProcHandle::Std(s, pid) => {
                let sent = s.signal(Sig::Kill).map_err(Error::into_io);
                #[cfg(unix)]
                let delivered = matches!(sent, Ok(crate::signal::Sent::Delivered));
                let kill_result = sent.map(drop);
                match std_teardown_action(&kill_result) {
                    // Kill succeeded: reap the zombie with a bounded blocking wait (SIGKILL
                    // cannot be caught, so the child's exit is guaranteed — this is the
                    // sanctioned real-child-exit wait).
                    StdTeardown::ReapBlocking => match wait_after_drop_kill(s, *pid) {
                        Ok(_status) => {
                            #[cfg(test)]
                            crate::child::spawn::fault::record_teardown_reap(*pid, _status);
                            Torn::new(ChildFate::Reaped)
                        }
                        Err(e) => {
                            let left = teardown_wait_failure(*pid, &e);
                            #[cfg(unix)]
                            if e.raw_os_error() == Some(libc::ECHILD) {
                                // Delivered, the kill is `Killed`; found nothing to signal, `Gone`.
                                return Torn {
                                    fate: crate::os_process::child::Foreign::Gone.fate(delivered),
                                    left,
                                };
                            }
                            // A failed wait shows what became of the child only if the kill was delivered.
                            #[cfg(unix)]
                            let fate = if delivered {
                                ChildFate::Killed
                            } else {
                                ChildFate::Unknown
                            };
                            #[cfg(not(unix))]
                            let fate = ChildFate::Killed;
                            Torn { fate, left }
                        }
                    },
                    // Kill failed: NEVER block. Reap non-blockingly; if it was EPERM and the
                    // child is still running (an elevated child we cannot signal), report it.
                    StdTeardown::ReapNonBlocking => {
                        let looked = wait_std(s, *pid, Some(crate::wait::now()), Orphaned::Quiet);
                        let still_running = !matches!(looked, Ok(Some(_)));
                        let permission_denied =
                            matches!(&kill_result, Err(e) if e.kind() == io::ErrorKind::PermissionDenied);
                        let left = (still_running && permission_denied).then(|| {
                            format!(
                                "elevated child {pid} could not be terminated on drop (permission denied); leaving it running"
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
            ProcHandle::Raw(r) => r.teardown_on_drop(id),
        }
    }
}

/// A wait on `owned` as the `io::Result` `Child` expects: `deadline` is absolute (`None`: for ever),
/// and `Ok(None)` is a deadline that passed with the child still running.
fn wait_std(
    owned: &OwnedChild,
    pid: u32,
    deadline: Option<Instant>,
    orphaned: Orphaned,
) -> io::Result<Option<ExitStatus>> {
    match owned.wait(deadline).map_err(Error::into_io)? {
        ChildWaitOutcome::Exited(record) => status_of(record).map(Some),
        ChildWaitOutcome::Foreign(foreign) => {
            if foreign == crate::os_process::child::Foreign::Orphaned && orphaned == Orphaned::Warn {
                log::warn!("pid {pid}: not ours to reap (launchd holds its zombie, because its tracer died)");
            }
            Err(echild())
        }
        ChildWaitOutcome::DeadlinePassed => Ok(None),
    }
}

/// Block until `owned` is reaped.
fn wait_unbounded(owned: &OwnedChild, pid: u32) -> io::Result<ExitStatus> {
    wait_std(owned, pid, None, Orphaned::Warn)?.ok_or_else(|| io::Error::other("an unbounded wait ended with no exit"))
}

/// The `ECHILD` every method answers when the child was reaped by someone else.
fn echild() -> io::Error {
    #[cfg(unix)]
    {
        io::Error::from_raw_os_error(libc::ECHILD)
    }
    #[cfg(windows)]
    {
        io::Error::other("the child was already reaped elsewhere")
    }
}

/// The status a cached outcome answers.
fn status_of(record: crate::os_process::child::ExitRecord) -> io::Result<ExitStatus> {
    use crate::os_process::child::ExitRecord;
    match record {
        ExitRecord::Status(status) => Ok(status),
        ExitRecord::Unreadable { si_code } => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the child's exit record was unreadable (si_code {si_code})"),
        )),
    }
}

/// The blocking reap that follows the drop's delivered kill.
fn wait_after_drop_kill(s: &OwnedChild, pid: u32) -> io::Result<ExitStatus> {
    #[cfg(test)]
    crate::graceful_hooks::run_hook(crate::graceful_hooks::HookPoint::AfterDropKill);
    wait_unbounded(s, pid)
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
