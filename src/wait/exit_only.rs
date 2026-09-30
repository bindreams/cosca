//! The exit-only discipline: peek at a child's exit and reap it, and never mistake a stop for an
//! exit. Every function takes a [`Target`], the handle that names the child, never a bare pid.
//!
//! - [`peek`] looks without consuming: a non-blocking `waitid(WEXITED | WNOHANG | WNOWAIT)` on
//!   Unix, `WaitForSingleObject(h, 0)` on Windows.
//! - [`try_reap`] peeks, then consumes only an exit record.
//!
//! An exit record is an `si_code` of `CLD_EXITED`, `CLD_KILLED` or `CLD_DUMPED`. A ptrace stop
//! (`CLD_TRAPPED`) reaches the tracer whatever the options say, and a consuming `waitid` clears
//! it, so a one-step reap of a child this process traces would steal the tracer's stop event.
//! Peeking first reads that as "running" and consumes nothing.
//!
//! **No panic between a consuming reap and the caller recording its status.** The `si_code`
//! mapping is total; a code that is not an exit record becomes [`Reaped::Unreadable`].

use std::io;
use std::process::ExitStatus;

#[cfg(target_os = "linux")]
#[path = "exit_only/linux.rs"]
mod linux;
#[cfg(target_os = "macos")]
#[path = "exit_only/macos.rs"]
mod macos;
#[cfg(windows)]
#[path = "exit_only/windows.rs"]
mod windows;

#[cfg(target_os = "linux")]
use linux as backend;
#[cfg(target_os = "macos")]
use macos as backend;
#[cfg(windows)]
use windows as backend;

/// The second peek-and-consume every first reap on macOS is followed by; tests drive it directly.
#[cfg(all(target_os = "macos", test))]
pub(crate) use macos::second_reap;

#[cfg(test)]
#[cfg_attr(
    windows,
    allow(
        dead_code,
        reason = "the Unix holder steps and record rewrites have no Windows caller"
    )
)]
#[path = "exit_only/seams.rs"]
pub(crate) mod seams;

/// A reaped child's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reaped {
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
    #[cfg(target_os = "macos")]
    Other,
}

/// What [`peek`] saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Peek {
    /// An exit record, not consumed.
    Exit(Reaped),
    /// No exit record: still running, stopped under a tracer, or a zombie only its tracer sees.
    Running,
    #[cfg_attr(
        windows,
        allow(dead_code, reason = "a process handle pins its process: no foreign reap")
    )]
    Foreign(Foreign),
}

/// What [`try_reap`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reap {
    Reaped(Reaped),
    /// Nothing to consume: not exited, or (Linux) a zombie only its tracer sees.
    Running,
    #[cfg_attr(
        windows,
        allow(dead_code, reason = "a process handle pins its process: no foreign reap")
    )]
    Foreign(Foreign),
}

/// The handle that names the child.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Target<'a> {
    /// The child's pidfd: pinned, so a reused pid cannot be mistaken for it.
    #[cfg(target_os = "linux")]
    PidFd(std::os::fd::BorrowedFd<'a>),
    /// The child by number. Only sound while the child is an unreaped zombie at worst.
    #[cfg(target_os = "macos")]
    Pid {
        pid: u32,
        /// The child's unique id (`proc_pidinfo` flavor 17): never reused, so it names the child.
        unique: Option<u64>,
        _lt: std::marker::PhantomData<&'a ()>,
    },
    /// A process handle: pinned.
    #[cfg(windows)]
    Handle(std::os::windows::io::BorrowedHandle<'a>),
}

#[cfg(target_os = "macos")]
impl Target<'_> {
    /// The child `pid`, checked against `unique` when there is one.
    pub(crate) fn pid(pid: u32, unique: Option<u64>) -> Target<'static> {
        Target::Pid {
            pid,
            unique,
            _lt: std::marker::PhantomData,
        }
    }
}

/// Look at `target` without consuming anything.
pub(crate) fn peek(target: &Target<'_>) -> io::Result<Peek> {
    #[cfg(test)]
    if let Some(forced) = seams::take_forced_peek() {
        return forced;
    }
    backend::peek(target)
}

/// [`peek`], then consume `target`'s exit record if it has one.
pub(crate) fn try_reap(target: &Target<'_>) -> io::Result<Reap> {
    backend::try_reap(target)
}

/// Block until `target`'s exit record is visible to this process. **Linux only.** A zombie that
/// another process traces is visible only to its tracer, so a pidfd that polls readable can still
/// have nothing to peek at or reap; this blocks in `waitid(P_PIDFD, WEXITED | WNOWAIT)` until the
/// tracer lets go. A stop cannot wake it: an invisible zombie means this process is not the
/// tracer. Consumes nothing.
#[cfg(target_os = "linux")]
pub(crate) fn wait_visible_exit(target: &Target<'_>) -> io::Result<Peek> {
    linux::wait_visible_exit(target)
}

// The wait status of an `si_code` record =====

/// One `waitid` record: the `si_code` and `si_status` of the `siginfo_t`.
#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Record {
    pub(crate) si_code: i32,
    pub(crate) si_status: i32,
}

/// `record`, as the test seam [`seams::force_consuming_record_once`] may have rewritten it.
#[cfg(unix)]
fn consumed(record: Record) -> Record {
    #[cfg(test)]
    if let Some(si_code) = seams::take_forced_si_code() {
        return Record { si_code, ..record };
    }
    record
}

/// Whether `si_code` is an exit record: `CLD_EXITED`, `CLD_KILLED` or `CLD_DUMPED`.
#[cfg(unix)]
pub(crate) fn is_exit_record(si_code: i32) -> bool {
    matches!(si_code, libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED)
}

/// The wait status `record` describes. Total: a code that is not an exit record is
/// [`Reaped::Unreadable`]. The masks drop the bits XNU ORs into `si_status`'s high byte.
#[cfg(unix)]
pub(crate) fn reaped_from_record(record: Record) -> Reaped {
    use std::os::unix::process::ExitStatusExt;
    let Record { si_code, si_status } = record;
    let raw = match si_code {
        libc::CLD_EXITED => (si_status & 0xFF) << 8,
        libc::CLD_KILLED => si_status & 0x7F,
        libc::CLD_DUMPED => (si_status & 0x7F) | 0x80,
        other => return Reaped::Unreadable { si_code: other },
    };
    Reaped::Status(ExitStatus::from_raw(raw))
}

#[cfg(test)]
#[path = "exit_only_tests.rs"]
mod exit_only_tests;
