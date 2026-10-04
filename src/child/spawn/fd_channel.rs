//! The skeleton of a `pre_exec` hook that talks to its parent over a descriptor made under
//! `spawn_lock`, as [`pidfd_handshake`](super::pidfd_handshake) and, on macOS,
//! [`unique_report`](super::unique_report) do.
//!
//! A hook is registered on the command first and the channel is made later, under `spawn_lock`, so
//! the descriptor numbers are published to the hook between the two. The hook reads only atomics.
//! The channel is live from [`Shared::publish`] to [`Shared::withdraw`], so a command spawned
//! again later never uses whatever now owns the numbers.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;

use crate::error::Error;

/// What a hook reads in the child: fd numbers only. Every accessor is async-signal-safe.
pub(crate) struct Shared {
    child_end: AtomicI32,
    parent_end: AtomicI32,
    live: AtomicBool,
}

impl Shared {
    /// The child's end of the channel.
    pub(crate) fn child_end(&self) -> RawFd {
        self.child_end.load(Ordering::Relaxed)
    }

    /// The parent's end, as inherited by the child.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn parent_end(&self) -> RawFd {
        self.parent_end.load(Ordering::Relaxed)
    }

    fn is_live(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }

    /// Publishes the fd numbers before the fork; the `Release` store of `live` makes the `Relaxed`
    /// stores visible to the hook.
    pub(crate) fn publish(&self, child_end: RawFd, parent_end: RawFd) {
        self.child_end.store(child_end, Ordering::Relaxed);
        self.parent_end.store(parent_end, Ordering::Relaxed);
        self.live.store(true, Ordering::Release);
    }

    /// Ends the window after the fork.
    pub(crate) fn withdraw(&self) {
        self.live.store(false, Ordering::Release);
    }
}

/// Registers `hook` as a `pre_exec` hook on `cmd`. Until [`Shared::publish`], and after
/// [`Shared::withdraw`], the spawn fails with `EBADF` and `hook` does not run.
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
        cmd.pre_exec(move || {
            if !in_child.is_live() {
                return Err(io::Error::from_raw_os_error(libc::EBADF));
            }
            hook(&in_child)
        });
    }
    shared
}

/// Moves both ends to 3 or above (see [`above_stdio`]) and publishes their numbers; returns them in
/// `(child_end, parent_end)` order.
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

/// [`crate::above_stdio::above_stdio`], with the error in this crate's terms.
pub(crate) fn above_stdio(fd: OwnedFd) -> Result<OwnedFd, Error> {
    above_stdio_keeping(fd).map_err(|(e, _)| e)
}

/// [`above_stdio`], handing `fd` back if it could not be moved.
pub(crate) fn above_stdio_keeping(fd: OwnedFd) -> Result<OwnedFd, (Error, OwnedFd)> {
    crate::above_stdio::above_stdio_keeping(fd).map_err(|(e, fd)| (Error::Io(crate::error::io_context("fcntl", e)), fd))
}

#[cfg(test)]
#[path = "fd_channel_tests.rs"]
mod fd_channel_tests;
