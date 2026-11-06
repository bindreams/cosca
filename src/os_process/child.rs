//! What a parent learns about its child's exit, and [`OsChild`], the parent's extras over an
//! [`OsProcess`].

use std::process::ExitStatus;

use super::{OsProcess, WaitFor};
use crate::error::{ChildFate, Error};

#[cfg(target_os = "linux")]
use std::os::fd::BorrowedFd;
#[cfg(windows)]
use std::os::windows::io::BorrowedHandle;

/// The OS object that names a process, lent by [`OsProcess::os_handle`].
#[cfg(target_os = "linux")]
pub(crate) type OsHandle<'a> = BorrowedFd<'a>;
/// The OS object that names a process, lent by [`OsProcess::os_handle`].
#[cfg(windows)]
pub(crate) type OsHandle<'a> = BorrowedHandle<'a>;

/// A process this process is the parent of: what only the parent gets, the exit record and the reap.
/// Policy (reap once, "already reaped is gone") belongs to the caller: these calls state what the OS
/// says now.
pub(crate) trait OsChild: OsProcess {
    /// The child's pid, for messages. `None`: the spawn never learned it (a Linux child whose spawn
    /// failed after the handshake opened its pidfd); acts go by the handle either way.
    fn pid(&self) -> Option<u32>;

    /// What a kill through this handle may be refused for, as whatever built the handle knows it.
    /// A teardown's contract with its caller reads it.
    #[cfg(any(target_os = "linux", windows))]
    fn kill_refusal(&self) -> KillRefusal;

    /// Look at the exit record without consuming it, and without touching anything a waiter waits
    /// on. A stop, or a zombie only its tracer sees, is [`PeekOutcome::Running`]. Any thread, any
    /// time.
    fn peek(&self) -> Result<PeekOutcome, Error>;

    /// The waiter's look: prepare what it will wait on, then consume the exit record if there is
    /// one (never a stop). [`TryReapOutcome::Running`] carries the wait, which the caller waits on
    /// before it calls again. Only the one waiter that holds the reap calls it.
    fn try_reap(&self) -> Result<TryReapOutcome<'_>, Error>;
}

/// What a kill through a handle may be refused for. The handle's constructor decides: it knows the
/// rights it asked for or was granted.
#[cfg_attr(
    not(any(target_os = "linux", windows)),
    allow(
        dead_code,
        reason = "only the Linux and Windows spawns tear a child down over a handle"
    )
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KillRefusal {
    /// Never: the handle can kill its process, so a refusal of the kill is a contract breach (a
    /// refusal that only says the process is exiting is not one: the kill answers it as an exit). A
    /// Windows handle that holds `PROCESS_TERMINATE`.
    Never,
    /// For want of permission alone ([`PermissionDenied`](std::io::ErrorKind::PermissionDenied)): a
    /// Linux pidfd (`EPERM`), a Windows handle that lacks `PROCESS_TERMINATE`.
    Permission,
}

/// What [`OsChild::try_reap`] did.
#[derive(Debug)]
pub(crate) enum TryReapOutcome<'a> {
    /// The exit record, consumed.
    Reaped(ExitRecord),
    /// Not exited: wait on this, then look again.
    Running(WaitFor<'a>),
    /// An exit was seen but there is no record to consume, and nothing will signal the change (a
    /// tracer holds the zombie, or the OS is still finishing the exit): look again after a backoff.
    #[cfg_attr(
        windows,
        allow(
            dead_code,
            reason = "a process handle pins its process: nothing waits for a zombie a tracer holds"
        )
    )]
    Recheck,
    Foreign(Foreign),
}

/// A child's exit as its exit record states it. A peek sees one too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExitRecord {
    Status(ExitStatus),
    /// A consuming `waitid` that should have handed back a zombie's exit record gave another
    /// `si_code`. A contract breach, but the zombie is consumed, so it is a cached outcome.
    #[cfg_attr(windows, allow(dead_code, reason = "Windows has no `waitid` records"))]
    Unreadable {
        si_code: i32,
    },
}

/// Why a child is not this process's to reap any more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    windows,
    allow(dead_code, reason = "a process handle pins its process: no foreign reap")
)]
pub(crate) enum Foreign {
    /// The OS answered `ECHILD`, or a by-pid consume found nothing: something else reaped it.
    Gone,
    /// The pid names another process now: its start time differs from the child's.
    #[cfg_attr(
        not(target_os = "macos"),
        allow(dead_code, reason = "only macOS reads a child by a pid that can be reused")
    )]
    Other,
    /// `ECHILD` for a pid that still names the child, held by launchd: its tracer died and XNU
    /// reparented it. It has exited and is not this process's to reap. Kept apart from `Gone` so
    /// that a log can say why.
    #[cfg_attr(
        not(target_os = "macos"),
        allow(dead_code, reason = "only macOS has a zombie launchd holds")
    )]
    Orphaned,
}

impl Foreign {
    /// The fate of a child that is not this process's to reap. Every path that maps a `Foreign` to a
    /// fate uses this:
    ///
    /// - `kill_delivered`: cosca's kill was delivered, so the child is [`Killed`](ChildFate::Killed):
    ///   dead or dying, its exit not collected by cosca.
    /// - Otherwise cosca delivered nothing, and the child is [`Gone`](ChildFate::Gone).
    #[cfg_attr(
        windows,
        allow(dead_code, reason = "a process handle pins its process: no foreign reap")
    )]
    pub(crate) fn fate(self, kill_delivered: bool) -> ChildFate {
        // Every foreign verdict is the same situation for the fate: only the kill tells them apart.
        let _ = self;
        if kill_delivered {
            ChildFate::Killed
        } else {
            ChildFate::Gone
        }
    }
}

/// What a peek saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeekOutcome {
    /// An exit record, not consumed.
    Exit(ExitRecord),
    /// No exit record: still running, stopped under a tracer, or a zombie only its tracer sees.
    Running,
    #[cfg_attr(
        windows,
        allow(dead_code, reason = "a process handle pins its process: no foreign reap")
    )]
    Foreign(Foreign),
}

/// Take over the std `child`, whose identity `id` the caller has just read, as the [`OsChild`] of
/// its platform. **Never reaps**: an already-exited child is still a zombie afterwards. A child
/// already reaped elsewhere cannot be adopted: `Err`, and the child handed back untouched.
///
/// - Linux: the `pidfd_open` of its pid fails, or `waitid(P_PIDFD, WEXITED | WNOHANG | WNOWAIT)` on
///   the pidfd answers `ECHILD`: it names no child of this process. A running child, or an exit
///   not yet reaped, is adopted.
/// - macOS: `ECHILD`, or an unreadable identity.
///
/// Tests only: a spawn adopts through the handle it holds.
#[cfg(test)]
#[allow(
    clippy::result_large_err,
    reason = "the child is handed back untouched for the caller to deal with"
)]
pub(crate) fn adopt_std(
    child: std::process::Child,
    id: crate::identity::ProcessId,
) -> Result<Box<dyn OsChild>, (Error, std::process::Child)> {
    debug_assert_eq!(child.id(), id.pid(), "the identity must be the child's");
    #[cfg(target_os = "macos")]
    let gone = || Error::Io(std::io::Error::from_raw_os_error(libc::ECHILD));
    #[cfg(target_os = "linux")]
    let os = match adopt_pidfd(&crate::identity::HostKernel, id) {
        Ok(os) => os,
        Err(e) => return Err((e, child)),
    };
    #[cfg(target_os = "macos")]
    let os: Box<dyn OsChild> = match crate::signal::read_identity(id.pid()) {
        Ok(Some(unique)) => match super::macos::child::MacChild::new(id.pid(), unique) {
            Ok(os) => Box::new(os),
            Err(e) => return Err((e, child)),
        },
        Ok(None) => return Err((gone(), child)),
        Err(errno) => return Err((crate::signal::identity_unreadable(id.pid(), errno), child)),
    };
    #[cfg(windows)]
    let os: Box<dyn OsChild> = Box::new(super::windows::WindowsProcess::for_child(
        std::os::windows::io::OwnedHandle::from(child),
        id.pid(),
    ));
    // std's `Child` holds nothing else the tests use: dropping it neither kills nor reaps.
    #[cfg(unix)]
    drop(child);
    Ok(os)
}

/// [`adopt_std`]'s Linux half: the pidfd of `id`'s pid, confirmed to name a child of this process.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn adopt_pidfd(
    kernel: &dyn crate::identity::Kernel,
    id: crate::identity::ProcessId,
) -> Result<Box<dyn OsChild>, Error> {
    use std::os::fd::AsFd as _;

    use crate::wait::exit_only::{peek, Target};

    let target = rustix::process::Pid::from_raw(id.pid() as i32).expect("a spawned child's pid is never 0");
    let pidfd = kernel
        .pidfd_open(target, rustix::process::PidfdFlags::empty())
        .map_err(|e| Error::Io(crate::error::io_context("pidfd_open", std::io::Error::from(e))))?;
    // Never in a stdio slot: with 0, 1 or 2 closed, the lowest free number is one, and the
    // application may `dup2` its stdio back over it, destroying the pidfd.
    let pidfd = crate::above_stdio::above_stdio(pidfd).map_err(Error::Io)?;
    match peek(&Target::PidFd(pidfd.as_fd())).map_err(Error::Io)? {
        PeekOutcome::Foreign(_) => Err(Error::Io(std::io::Error::from_raw_os_error(libc::ECHILD))),
        PeekOutcome::Exit(_) | PeekOutcome::Running => {
            Ok(Box::new(super::linux::LinuxProcess::new(Some(id.pid()), pidfd)))
        }
    }
}

/// A running blocker child (see [`crate::test_child::held_std_killable_blocker`]) adopted by
/// [`adopt_std`], its identity, and the write end of its stdin: closing it ends the child.
#[cfg(test)]
pub(crate) fn adopted_blocker() -> (Box<dyn OsChild>, crate::identity::ProcessId, std::process::ChildStdin) {
    let mut cmd = crate::test_child::held_std_killable_blocker();
    let mut child = crate::test_spawn::spawn(&mut cmd).expect("spawn the blocker");
    let stdin = child.stdin.take().expect("piped stdin");
    let id = crate::identity::ProcessId::of(child.id())
        .found()
        .expect("the live child has an identity");
    let os = adopt_std(child, id).unwrap_or_else(|(e, _)| panic!("adopt: {e}"));
    (os, id, stdin)
}
