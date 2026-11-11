//! The signals cosca sends to a process it owns, and the one place each addressing mode's
//! "already gone" is decided.

#[cfg(unix)]
use std::io;

/// A signal cosca sends to an owned process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sig {
    Kill,
    #[cfg(unix)]
    Term,
}

#[cfg(target_os = "linux")]
impl Sig {
    fn as_rustix(self) -> rustix::process::Signal {
        match self {
            Sig::Kill => rustix::process::Signal::KILL,
            Sig::Term => rustix::process::Signal::TERM,
        }
    }
}

#[cfg(target_os = "macos")]
impl Sig {
    pub(crate) fn as_libc(self) -> libc::c_int {
        match self {
            Sig::Kill => libc::SIGKILL,
            Sig::Term => libc::SIGTERM,
        }
    }
}

/// What a send did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sent {
    /// The signal was handed to the OS for the child.
    Delivered,
    /// Nothing was delivered because the child is gone: reaped, or its pid no longer names it. Not
    /// an error; logged at `debug`.
    Gone,
    /// Nothing was delivered because there was nothing to verify the pid against (macOS: no unique
    /// id is held). The child may be running. Not an error; logged at `debug`.
    #[cfg_attr(
        not(target_os = "macos"),
        allow(dead_code, reason = "only macOS's audit-token send cannot verify a process")
    )]
    Unverified,
}

/// Whether an owned child's root is still its own child to act on, as its own handle says.
///
/// Unix only: a Windows process handle pins its process, so nothing there asks.
#[cfg(unix)]
#[derive(Debug)]
pub(crate) enum RootState {
    /// The root is an unreaped child (a zombie at worst): its pid names it, and a signal through
    /// its handle reaches it.
    Unreaped,
    /// The root was reaped: its pid may name another process. `own` says whether this handle's own
    /// wait collected it (else someone else did, or it was gone when adopted).
    Reaped { own: bool },
    /// The handle could not say: a failed peek, or (macOS) a refused unique-id read. Treated as
    /// neither reaped nor unreaped; callers skip what a reuse of the pid could redirect, and act
    /// only through the handle.
    Unknown(io::Error),
    /// The root exists, but this process does not pin it (macOS: launchd holds its zombie after
    /// its tracer died, and reaps it on its own schedule). Its pid is not ours: nothing may be
    /// signalled or waited on by it. [`UNPINNED_WHY`] says why.
    #[cfg_attr(
        not(target_os = "macos"),
        allow(dead_code, reason = "only macOS reports an unpinned root")
    )]
    Unpinned,
}

/// Why a root is [`RootState::Unpinned`], for every message that reports it.
#[cfg(unix)]
#[cfg_attr(
    not(target_os = "macos"),
    allow(dead_code, reason = "only macOS reports an unpinned root")
)]
pub(crate) const UNPINNED_WHY: &str = "launchd holds its zombie (its tracer died), so it is not ours to reap";

/// The refusal of a signal to a root that is [`RootState::Unpinned`]. `Unassessable` with no
/// `source`: nothing was asked of the OS, and the crate refuses to act on a pid it does not pin.
/// `op` names the call that sent nothing; `earlier` names what the same operation had already
/// sent before it got here, if anything, so the message never claims more than `op` did.
#[cfg(target_os = "macos")]
pub(crate) fn unpinned_refusal(pid: u32, op: &str, earlier: Option<&str>) -> crate::error::Error {
    let earlier = earlier.map_or_else(String::new, |sent| format!(", though {sent} was sent before it"));
    crate::error::Error::Unassessable {
        detail: format!("pid {pid}: the child cannot be shown to be ours: {UNPINNED_WHY}; {op} sent nothing{earlier}"),
        source: None,
    }
}

/// Whether the root's own handle says this process does not pin it: launchd holds its zombie, so
/// its pid is not ours. macOS only: no other platform reports an unpinned root, and `state` is not
/// read there.
#[cfg(unix)]
pub(crate) fn is_unpinned(state: impl FnOnce() -> RootState) -> bool {
    #[cfg(target_os = "macos")]
    return matches!(state(), RootState::Unpinned);
    #[cfg(not(target_os = "macos"))]
    {
        let _ = state;
        false
    }
}

/// The root of `op` is [`RootState::Unpinned`] at the end of it: the tree was signalled, but the
/// exit status of a zombie launchd holds cannot be collected.
#[cfg(target_os = "macos")]
pub(crate) fn unpinned_status(pid: u32, op: &str) -> crate::error::Error {
    crate::error::Error::Unassessable {
        detail: format!("pid {pid}: {op} signalled the tree, but its exit status cannot be collected: {UNPINNED_WHY}"),
        source: None,
    }
}

/// Refuse `op` if [`is_unpinned`], so the lone `kill` and `terminate` send no signal by number to a
/// pid launchd may reap and reuse. The tree paths do not refuse outright: each mechanism that names
/// its tree by the root's number sends what it still may and says what it skipped.
#[cfg(unix)]
pub(crate) fn refuse_unpinned(
    pid: u32,
    op: &str,
    earlier: Option<&str>,
    state: impl FnOnce() -> RootState,
) -> Result<(), crate::error::Error> {
    #[cfg(target_os = "macos")]
    if is_unpinned(state) {
        return Err(unpinned_refusal(pid, op, earlier));
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (pid, op, earlier, state);
    Ok(())
}

/// Why `state` leaves the root's number untrusted, for a message.
#[cfg(unix)]
pub(crate) fn why_untrusted(state: &RootState) -> String {
    match state {
        RootState::Unpinned => format!("the root is not pinned by this process (RootState::Unpinned: {UNPINNED_WHY})"),
        RootState::Unknown(e) => format!("the root could not be shown to be unreaped (RootState::Unknown: {e})"),
        RootState::Unreaped | RootState::Reaped { .. } => {
            debug_assert!(false, "{state:?} leaves the root's number trusted");
            "the root's number is trusted".to_owned()
        }
    }
}

#[cfg(unix)]
impl RootState {
    /// What a peek through the root's own handle shows.
    pub(crate) fn of_peek(peeked: io::Result<crate::os_process::child::PeekOutcome>) -> RootState {
        use crate::os_process::child::PeekOutcome;
        match peeked {
            Ok(PeekOutcome::Running | PeekOutcome::Exit(_)) => RootState::Unreaped,
            Ok(PeekOutcome::Foreign(crate::os_process::child::Foreign::Orphaned)) => RootState::Unpinned,
            Ok(PeekOutcome::Foreign(_)) => RootState::Reaped { own: false },
            Err(e) => RootState::Unknown(e),
        }
    }

    /// The same answer, for a second reader of one look: an `Unknown`'s error keeps its kind and its
    /// text, not its source.
    pub(crate) fn duplicate(&self) -> RootState {
        match self {
            RootState::Unreaped => RootState::Unreaped,
            RootState::Reaped { own } => RootState::Reaped { own: *own },
            RootState::Unknown(e) => RootState::Unknown(io::Error::new(e.kind(), e.to_string())),
            RootState::Unpinned => RootState::Unpinned,
        }
    }
}

/// Send `sig` through `pidfd`, which names the child for good, so a reused pid cannot be hit, with
/// the bare errno of a refused send, for a caller that promises its own caller the raw errno. `pid`
/// only names the child in messages and in the test send log (where `None` is 0); the send goes by
/// `pidfd`.
#[cfg(target_os = "linux")]
pub(crate) fn send_pidfd(
    pidfd: std::os::fd::BorrowedFd<'_>,
    pid: Option<u32>,
    sig: Sig,
) -> Result<Sent, rustix::io::Errno> {
    #[cfg(test)]
    let seam = seams::kills_refused();
    #[cfg(not(test))]
    let seam: Option<i32> = None;
    let sent = match seam {
        Some(errno) => Err(rustix::io::Errno::from_raw_os_error(errno)),
        None => rustix::process::pidfd_send_signal(pidfd, sig.as_rustix()),
    };
    #[cfg(test)]
    crate::send_log::record(pid.unwrap_or(0), sig, crate::send_log::Via::Pidfd);
    match sent {
        Ok(()) => Ok(Sent::Delivered),
        Err(rustix::io::Errno::SRCH) => {
            log::debug!(
                "pidfd_send_signal({sig:?}) to {}: it is already gone",
                crate::os_process::child_named(pid)
            );
            Ok(Sent::Gone)
        }
        Err(e) => Err(e),
    }
}

/// A process's unique id by pid: the 64-bit id that is never reused and survives `exec`, which is
/// the only identity macOS checks a by-pid action against. `Ok(None)` is a pid with no process
/// (`ESRCH`); `Err(errno)` is a refused read. Tests only: production spawns take the child's own
/// report (`child::spawn::unique_report`).
#[cfg(all(target_os = "macos", test))]
pub(crate) fn read_identity(pid: u32) -> Result<Option<u64>, i32> {
    use crate::identity::{uniq_info, ReadPurpose, UniqRead};
    match uniq_info(pid, ReadPurpose::Adopt) {
        UniqRead::Found(info) => Ok(Some(info.unique_id)),
        UniqRead::Gone => Ok(None),
        UniqRead::Refused(errno) => Err(errno),
    }
}

/// The error for adopting a child whose by-pid identity read was refused with `errno`. Tests
/// only: a spawn takes the child's own report.
#[cfg(all(target_os = "macos", test))]
pub(crate) fn identity_unreadable(pid: u32, errno: i32) -> crate::error::Error {
    crate::error::Error::Unassessable {
        detail: format!("pid {pid}: its identity could not be read; the child was not adopted"),
        source: Some(crate::error::Error::io_cause(io::Error::from_raw_os_error(errno))),
    }
}

/// Send `sig` to the child at `pid` through an audit token, only while the pid still has the unique
/// id `identity` (`None`: no id is held, so nothing is sent). The kernel checks the pid with its
/// `p_idversion` and signals while it holds a reference, so a reused pid is never signalled; only
/// the documented 2^32 version wrap is left, and the id read right before each send follows an
/// `exec`. A refused send is the bare errno, so an `EPERM` stays raw; a refused id read keeps its
/// errno's kind, so an `EPERM` stays `PermissionDenied`.
///
/// A child that has exited and is not reaped is [`Sent::Delivered`], as on Linux: it is ours, and
/// its zombie holds the pid.
#[cfg(target_os = "macos")]
pub(crate) fn via_audit_token(pid: u32, identity: Option<u64>, sig: Sig) -> io::Result<Sent> {
    use crate::os_process::macos::{read_version, signal_by_token, SignalByTokenOutcome};

    let Some(unique) = identity else {
        log::debug!("child {pid} holds no unique id; {sig:?} not sent");
        return Ok(Sent::Unverified);
    };
    let Some(mut idversion) = read_version(pid, unique, sig)? else {
        log::debug!("child {pid} is gone or its pid names another process; {sig:?} not sent");
        return Ok(Sent::Gone);
    };
    let sent = signal_by_token(pid, unique, &mut idversion, sig);
    // Every return of `signal_by_token` follows a send attempt, whatever it answered.
    #[cfg(test)]
    crate::send_log::record(pid, sig, crate::send_log::Via::Identity);
    Ok(match sent? {
        SignalByTokenOutcome::Delivered | SignalByTokenOutcome::ExitedUnreaped => Sent::Delivered,
        SignalByTokenOutcome::Gone => Sent::Gone,
    })
}

/// Test seam: while the guard lives, every kill sent on this thread is refused with `EPERM` and
/// not sent, as the kernel refuses a signal to another user's process. Thread-local, with an RAII
/// reset. The refusal is real: an unprivileged kill of a root-owned zombie fails with `EPERM`
/// (measured in a container), and #552's ELEVATION lanes run the real case.
#[cfg(all(test, unix))]
pub(crate) mod seams {
    use std::cell::Cell;

    thread_local! {
        static REFUSED: Cell<Option<i32>> = const { Cell::new(None) };
    }

    pub(crate) fn refuse_kills() -> RefusedKills {
        fail_kills_with(libc::EPERM)
    }

    /// [`refuse_kills`], failing each kill with `errno` instead.
    pub(crate) fn fail_kills_with(errno: i32) -> RefusedKills {
        REFUSED.with(|r| r.set(Some(errno)));
        RefusedKills(())
    }

    #[must_use = "kills are sent again as soon as the guard is dropped"]
    pub(crate) struct RefusedKills(());

    impl Drop for RefusedKills {
        fn drop(&mut self) {
            REFUSED.with(|r| r.set(None));
        }
    }

    pub(crate) fn kills_refused() -> Option<i32> {
        REFUSED.with(Cell::get)
    }
}

#[cfg(all(test, unix))]
#[path = "signal_tests.rs"]
mod signal_tests;
