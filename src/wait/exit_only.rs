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
//! mapping is total; a code that is not an exit record becomes [`ExitRecord::Unreadable`].

use std::io;
#[cfg(unix)]
use std::process::ExitStatus;

use crate::os_process::child::{ExitRecord, Foreign, PeekOutcome};

#[cfg(target_os = "linux")]
#[path = "exit_only/linux.rs"]
pub(crate) mod linux;
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

#[cfg(target_os = "macos")]
use crate::identity::Kernel;

#[cfg(all(target_os = "macos", test))]
#[path = "exit_only/macos_tests.rs"]
pub(crate) mod macos_tests;

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
#[path = "exit_only/seams.rs"]
pub(crate) mod seams;

/// What [`try_reap`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reap {
    Reaped(ExitRecord),
    /// Nothing to consume: not exited, or (Linux) a zombie only its tracer sees.
    Running,
    #[cfg_attr(
        windows,
        allow(dead_code, reason = "a process handle pins its process: no foreign reap")
    )]
    Foreign(Foreign),
}

/// The handle that names the child.
#[derive(Clone, Copy)]
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
        /// What answers every read about the child: macOS has no handle that does.
        kernel: &'a dyn Kernel,
    },
    /// A process handle: pinned.
    #[cfg(windows)]
    Handle(std::os::windows::io::BorrowedHandle<'a>),
}

impl std::fmt::Debug for Target<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(target_os = "linux")]
            Target::PidFd(fd) => f.debug_tuple("PidFd").field(fd).finish(),
            #[cfg(target_os = "macos")]
            Target::Pid { pid, unique, .. } => f.debug_struct("Pid").field("pid", pid).field("unique", unique).finish(),
            #[cfg(windows)]
            Target::Handle(handle) => f.debug_tuple("Handle").field(handle).finish(),
        }
    }
}

#[cfg(target_os = "macos")]
impl<'a> Target<'a> {
    /// The child `pid`, checked against `unique` when there is one, read through `kernel`.
    pub(crate) fn pid(kernel: &'a dyn Kernel, pid: u32, unique: Option<u64>) -> Target<'a> {
        Target::Pid { pid, unique, kernel }
    }
}

/// Look at `target` without consuming anything. The handle `target` holds answers; macOS has no
/// handle, so its target carries the kernel that does.
pub(crate) fn peek(target: &Target<'_>) -> io::Result<PeekOutcome> {
    #[cfg(all(test, target_os = "macos"))]
    if let Some(forced) = seams::take_forced_peek() {
        return forced;
    }
    backend::peek(target)
}

/// [`peek`] for a caller that treats `Running` as "this is our child". On macOS a running child
/// whose unique id cannot be read (a MACF denial) is then an error, not `Running`: the id is all
/// that tells it from a reuse of the pid. Other platforms use [`peek`].
#[cfg(target_os = "macos")]
pub(crate) fn peek_verified(target: &Target<'_>) -> io::Result<PeekOutcome> {
    #[cfg(test)]
    if let Some(forced) = seams::take_forced_peek() {
        return forced;
    }
    backend::peek_with(target, true)
}

/// [`peek`], and the tracer that holds the child when the verdict is `Running` because a process
/// other than this one and launchd holds it (`waitid` answered `ECHILD`). **macOS only.**
#[cfg(target_os = "macos")]
pub(crate) fn peek_traced(target: &Target<'_>) -> io::Result<(PeekOutcome, Option<u32>)> {
    #[cfg(test)]
    if let Some(forced) = seams::take_forced_peek() {
        return forced.map(|peeked| (peeked, None));
    }
    backend::peek_holder(target, false)
}

/// [`peek`], then consume `target`'s exit record if it has one.
pub(crate) fn try_reap(target: &Target<'_>) -> io::Result<Reap> {
    backend::try_reap(target)
}

// The wait status of an `si_code` record =====

#[cfg(unix)]
pub(crate) use crate::identity::Record;

/// Whether `si_code` is an exit record: `CLD_EXITED`, `CLD_KILLED` or `CLD_DUMPED`.
#[cfg(unix)]
pub(crate) fn is_exit_record(si_code: i32) -> bool {
    matches!(si_code, libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED)
}

/// The wait status `record` describes. Total: a code that is not an exit record is
/// [`ExitRecord::Unreadable`]. The masks drop the bits XNU ORs into `si_status`'s high byte.
#[cfg(unix)]
pub(crate) fn exit_record_of(record: Record) -> ExitRecord {
    use std::os::unix::process::ExitStatusExt;
    let Record { si_code, si_status } = record;
    let raw = match si_code {
        libc::CLD_EXITED => (si_status & 0xFF) << 8,
        libc::CLD_KILLED => si_status & 0x7F,
        libc::CLD_DUMPED => (si_status & 0x7F) | 0x80,
        other => return ExitRecord::Unreadable { si_code: other },
    };
    ExitRecord::Status(ExitStatus::from_raw(raw))
}

#[cfg(test)]
#[path = "exit_only_tests.rs"]
mod exit_only_tests;
