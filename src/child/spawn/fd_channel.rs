//! The skeleton of a `pre_exec` hook that talks to its parent over a descriptor made under
//! `spawn_lock`, as [`pidfd_handshake`](super::pidfd_handshake) does.
//!
//! A hook is registered on the command first and the channel is made later, under `spawn_lock`, so
//! the descriptor numbers are published to the hook between the two. The hook reads only atomics.
//! [`Shared::is_live`] says the numbers name this spawn's channel: it is cleared when the spawn is
//! over, so a command spawned again later fails in the hook instead of using whatever now owns the
//! numbers.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;

use crate::error::Error;

/// What a hook reads in the child: fd numbers only.
pub(crate) struct Shared {
    child_end: AtomicI32,
    parent_end: AtomicI32,
    live: AtomicBool,
}

impl Shared {
    /// The child's end of the channel. Async-signal-safe.
    pub(crate) fn child_end(&self) -> RawFd {
        self.child_end.load(Ordering::Relaxed)
    }

    /// The parent's end, as inherited by the child; `-1` for a channel with none. Async-signal-safe.
    pub(crate) fn parent_end(&self) -> RawFd {
        self.parent_end.load(Ordering::Relaxed)
    }

    /// Whether the numbers name this spawn's channel. Async-signal-safe.
    pub(crate) fn is_live(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }

    /// Publishes the channel's fd numbers to the hook, before the fork.
    pub(crate) fn publish(&self, child_end: RawFd, parent_end: RawFd) {
        self.child_end.store(child_end, Ordering::Relaxed);
        self.parent_end.store(parent_end, Ordering::Relaxed);
        self.live.store(true, Ordering::Release);
    }

    /// Withdraws the numbers, after the fork.
    pub(crate) fn withdraw(&self) {
        self.live.store(false, Ordering::Release);
    }
}

/// Registers `hook` as a `pre_exec` hook on `cmd`, with the channel not yet made: [`Shared::publish`]
/// it later, under `spawn_lock`. A hook run while the channel is not live must fail its spawn.
///
/// # Safety
///
/// `hook` runs between `fork` and `exec`, so it must be async-signal-safe: atomics and direct
/// syscalls only, with no allocation, lock, panic or reference-count change.
pub(crate) unsafe fn register(
    cmd: &mut std::process::Command,
    hook: impl Fn(&Shared) -> io::Result<()> + Send + Sync + 'static,
) -> Arc<Shared> {
    let shared = Arc::new(Shared {
        child_end: AtomicI32::new(-1),
        parent_end: AtomicI32::new(-1),
        live: AtomicBool::new(false),
    });
    let in_child = Arc::clone(&shared);
    // SAFETY: the caller guarantees the hook is async-signal-safe. `in_child` is owned by the
    // closure and only borrowed in the child, so no reference count changes there.
    unsafe {
        cmd.pre_exec(move || hook(&in_child));
    }
    shared
}

/// Moves a channel's two ends to 3 or above and publishes their numbers to the hook. Returns
/// `(child_end, parent_end)`.
pub(crate) fn publish_ends(
    shared: &Shared,
    child_end: OwnedFd,
    parent_end: OwnedFd,
) -> Result<(OwnedFd, OwnedFd), Error> {
    let parent_end = above_stdio(parent_end)?;
    let child_end = above_stdio(child_end)?;
    shared.publish(child_end.as_raw_fd(), parent_end.as_raw_fd());
    Ok((child_end, parent_end))
}

/// `fd`, moved to 3 or above: with 0, 1 or 2 closed, the lowest free number is one, and the
/// application may `dup2` its stdio back over it.
///
/// This narrows that hazard, it does not close it: no syscall that makes a descriptor takes a
/// minimum number, so each one creates it at the lowest free number first, and the move follows. A
/// `dup2` by another thread onto a closed stdio slot in that gap is outside this function's
/// contract, as it is outside every other spawn's.
pub(crate) fn above_stdio(fd: OwnedFd) -> Result<OwnedFd, Error> {
    above_stdio_keeping(fd).map_err(|(e, _)| e)
}

/// [`above_stdio`], handing `fd` back if it could not be moved.
pub(crate) fn above_stdio_keeping(fd: OwnedFd) -> Result<OwnedFd, (Error, OwnedFd)> {
    if fd.as_raw_fd() >= 3 {
        return Ok(fd);
    }
    match rustix::io::fcntl_dupfd_cloexec(&fd, 3) {
        Ok(moved) => Ok(moved),
        Err(e) => Err((Error::Io(crate::error::io_context("fcntl", e.into())), fd)),
    }
}

#[cfg(test)]
#[path = "fd_channel_tests.rs"]
mod fd_channel_tests;
