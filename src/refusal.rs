//! What a refused signal (`EPERM` on POSIX, `ACCESS_DENIED` on Windows) means, and how it is
//! reported.
//!
//! The OS gives one answer for four situations: the target has exited (Linux refuses a signal to
//! a root-owned zombie), the target belongs to a more privileged user, a seccomp or LSM filter
//! refuses the syscall, or the call was never the signal's. Only the second is a statement about
//! the target, and only that one may become
//! [`ElevationErrorKind::Unkillable`](crate::error::ElevationErrorKind::Unkillable):
//!
//! - **Exited**: `Ok(())`, as for any already-exited child.
//! - **Privilege**: a `PermissionDenied` [`refused`] error, carrying whether the target is still
//!   running. [`map_elevated_kill_error`](crate::elevation::map_elevated_kill_error) turns exactly
//!   these into `Unkillable`, for an elevated wrapper child.
//! - **Filter** (Linux): [`Error::Unsupported`] naming the syscall, as for any refused syscall (see
//!   the crate root's "Platform requirements").

use std::io;

use crate::error::Error;
use crate::identity::ProcessId;

#[cfg(target_os = "linux")]
pub(crate) mod linux;

/// What a refused signal turned out to be.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The target had already exited.
    Exited,
    /// The OS's own permission rule refuses the signal.
    Privilege(TargetState),
    /// The kernel's rule would permit the signal, so a seccomp or LSM filter refused it.
    #[cfg(target_os = "linux")]
    Filter(linux::SignalCall),
}

/// What is known of the target of a signal the OS refused for privilege.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetState {
    /// It has not exited.
    Running,
    /// The check that would tell failed.
    #[cfg_attr(
        target_os = "linux",
        allow(
            dead_code,
            reason = "Linux answers exited-or-not exactly (waitid on a pidfd) or errors; only the liveness fallback of the other platforms can be unsure"
        )
    )]
    Unknown,
}

impl std::fmt::Display for TargetState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetState::Running => f.write_str("still running"),
            TargetState::Unknown => f.write_str("whether it has exited could not be determined"),
        }
    }
}

/// The payload of a [`refused`] error: the target's state, and the OS error's text.
#[derive(Debug)]
struct SignalRefused {
    state: TargetState,
    source: io::Error,
}

impl std::fmt::Display for SignalRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(f)
    }
}

impl std::error::Error for SignalRefused {}

/// A privilege refusal of the signal call itself: kind `PermissionDenied`, carrying the target's
/// `state` and the OS error `source` it replaces. The only error
/// [`map_elevated_kill_error`](crate::elevation::map_elevated_kill_error) turns into `Unkillable`:
/// a `PermissionDenied` from anywhere else on the path is not a statement about the target.
pub(crate) fn refused(state: TargetState, source: io::Error) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, SignalRefused { state, source })
}

/// The state a [`refused`] error carries; `None` for any other error.
pub(crate) fn refusal_state(err: &io::Error) -> Option<TargetState> {
    err.get_ref()?.downcast_ref::<SignalRefused>().map(|r| r.state)
}

/// The outcome of a refused signal whose `verdict` is known.
pub(crate) fn resolve(verdict: Verdict, os_error: io::Error) -> Result<(), Error> {
    match verdict {
        Verdict::Exited => Ok(()),
        Verdict::Privilege(state) => Err(Error::Io(refused(state, os_error))),
        #[cfg(target_os = "linux")]
        Verdict::Filter(call) => Err(call.unsupported()),
    }
}

/// Resolve the error of the platform's own signal call on `id`'s process (`kill(2)` /
/// `TerminateProcess`, by pid or handle), as returned by `std` or tokio. Only a
/// `PermissionDenied` is classified; anything else, and a [`refused`] error already classified,
/// passes through, mapped for an elevated wrapper child.
pub(crate) fn resolve_kill_error(err: io::Error, id: ProcessId, elevated_wrapper: bool) -> Result<(), Error> {
    if err.kind() != io::ErrorKind::PermissionDenied || refusal_state(&err).is_some() {
        return Err(crate::elevation::map_elevated_kill_error(err, elevated_wrapper));
    }
    match resolve(classify_kill(id)?, err) {
        Ok(()) => Ok(()),
        Err(Error::Io(refusal)) => Err(crate::elevation::map_elevated_kill_error(refusal, elevated_wrapper)),
        Err(other) => Err(other),
    }
}

#[cfg(target_os = "linux")]
fn classify_kill(id: ProcessId) -> Result<Verdict, Error> {
    linux::classify_kill(id)
}

/// Outside Linux there is no filter to tell from a privilege refusal (a sandbox profile is not
/// modelled), so the question is only whether the target has exited.
#[cfg(not(target_os = "linux"))]
pub(crate) fn classify_kill(id: ProcessId) -> Result<Verdict, Error> {
    use crate::identity::Liveness;
    Ok(match id.is_alive() {
        Liveness::Dead => Verdict::Exited,
        // `is_alive` reads the process's state, which can lag its exit edge; the reap-free
        // `waitid` is exact for our own child.
        Liveness::Alive | Liveness::Unknown if exited_unreaped_child(id.pid()) => Verdict::Exited,
        Liveness::Alive => Verdict::Privilege(TargetState::Running),
        Liveness::Unknown => Verdict::Privilege(TargetState::Unknown),
    })
}

/// Whether `pid` is a child of this process that has exited and is not yet reaped. `waitid` with
/// `WNOWAIT` leaves the zombie for its parent; any error (`ECHILD` for a process that is not our
/// child) is "no".
#[cfg(target_os = "macos")]
fn exited_unreaped_child(pid: u32) -> bool {
    // SAFETY: an all-zero `siginfo_t` is a valid value, and `waitid` only writes it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a valid out-pointer; the options and id type are the documented ones.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    // With `WNOHANG`, success and `si_pid == 0` mean "no child has changed state".
    rc == 0 && info.si_pid != 0
}

/// Windows has no zombie: a handle to an exited process is signalled, which `is_alive` reads.
#[cfg(windows)]
fn exited_unreaped_child(_pid: u32) -> bool {
    false
}

#[cfg(test)]
#[path = "refusal_tests.rs"]
mod refusal_tests;
