//! macOS: the child reports its own unique id before `exec`.
//!
//! macOS has no pidfd, so nothing pins a pid. A parent that read a fresh child's unique id by pid
//! after `spawn()` would race a foreign reap and a reuse of the number: it would take a stranger's
//! id for the child's. So the child reads `proc_pidinfo(getpid(), PROC_PIDUNIQIDENTIFIERINFO)`
//! itself, in a `pre_exec` hook, and writes the answer to a pipe the parent reads once `spawn()`
//! returns. The id belongs to the process that forked, whatever the number is by then.
//!
//! ```text
//! child (pre_exec hook)                      parent
//! ---------------------                      ------
//! own_unique_id()
//! write ID + id, or ERRNO + errno  ------->  spawn() returns (the child has execed)
//!                                            close the write end
//!                                            read the 12-byte report
//! ```
//!
//! The hook is async-signal-safe: it reads atomics, makes one `proc_pidinfo` call, which is a
//! direct `__proc_info` syscall with no allocation, and one `write` (atomic: under `PIPE_BUF`).
//!
//! The pipe is made under `spawn_lock`, `FD_CLOEXEC` on both ends, and sits at fd 3 or above. The
//! hook is registered before every other, so `fd_map`'s `dup2` onto a number cannot come first.
//!
//! If the child's own read is refused, the hook reports the errno and then fails, so `exec` never
//! runs: the spawn is an `Err`, std collects the child, and the program did not start. The parent
//! maps that to [`refused_error`].
//!
//! The parent reads exactly one report. `spawn()` returning `Ok` means the child execed, so its hook
//! wrote the report first; the read does not wait for anything else. A report that never came (EOF)
//! is [`UNREPORTED`].

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;

use super::SpawnLockGuard;
use crate::error::Error;

/// A report's tag: the value is the child's unique id.
const REPORT_ID: u32 = 1;
/// A report's tag: the child's own read failed; the value is its errno.
const REPORT_ERRNO: u32 = 2;
/// A report is a native-endian `u32` tag, then a native-endian `u64` value.
const REPORT_LEN: usize = 12;
/// The "errno" of a report that never came (the pipe ended before the child wrote it): negative, so
/// no real errno equals it.
pub(crate) const UNREPORTED: i32 = -1;

/// What the hook reads in the child: an fd number, published before the fork and withdrawn after.
struct Shared {
    write_fd: AtomicI32,
    /// Whether the fd number names this spawn's pipe. Cleared when the spawn is over: a command
    /// spawned again after that would otherwise write to whatever now owns the number; the hook
    /// fails it instead.
    live: AtomicBool,
}

/// The child's report: its unique id, or the errno of a read that failed or never came.
pub(crate) type Reported = Result<u64, i32>;

/// The hook is registered; the pipe is not yet made. See [`register`].
pub(crate) struct Pending {
    shared: Arc<Shared>,
}

/// The pipe to one child. Consumed by [`run`](Self::run).
pub(crate) struct Channel {
    read_end: OwnedFd,
    write_end: OwnedFd,
    shared: Arc<Shared>,
}

/// Registers the reporting hook on `cmd`. Call it before anything else registers a hook, so it runs
/// first in the child. A hook whose pipe was never opened fails the spawn it belongs to.
pub(crate) fn register(cmd: &mut std::process::Command) -> Pending {
    let shared = Arc::new(Shared {
        write_fd: AtomicI32::new(-1),
        live: AtomicBool::new(false),
    });
    // The child reads its own id where a thread-local seam cannot reach: take it here.
    #[cfg(test)]
    let forced = seams::forced_errno();
    let hook = Arc::clone(&shared);
    // SAFETY: the hook runs between fork and exec and is async-signal-safe (see the module doc): it
    // allocates nothing and takes no lock.
    unsafe {
        cmd.pre_exec(move || {
            report(
                &hook,
                #[cfg(test)]
                forced,
            )
        });
    }
    Pending { shared }
}

impl Pending {
    /// Makes the pipe and publishes its write end to the hook. `_lock` is the witness that no other
    /// cosca fork can inherit the ends between their creation and their `FD_CLOEXEC`.
    pub(crate) fn open(self, _lock: &SpawnLockGuard) -> Result<Channel, Error> {
        let (read_end, write_end) = std::io::pipe().map_err(|e| Error::Io(crate::error::io_context("pipe", e)))?;
        let (read_end, write_end) = (OwnedFd::from(read_end), OwnedFd::from(write_end));
        let read_end = above_stdio_cloexec(read_end)?;
        let write_end = above_stdio_cloexec(write_end)?;
        set_nonblocking(&read_end)?;
        self.shared.write_fd.store(write_end.as_raw_fd(), Ordering::Relaxed);
        self.shared.live.store(true, Ordering::Release);
        Ok(Channel {
            read_end,
            write_end,
            shared: self.shared,
        })
    }
}

/// `fd` at 3 or above (a descriptor made while one of 0 to 2 is closed lands on it), with
/// `FD_CLOEXEC`.
fn above_stdio_cloexec(fd: OwnedFd) -> Result<OwnedFd, Error> {
    // SAFETY: `F_DUPFD_CLOEXEC` takes an fd and a minimum, and returns a new descriptor.
    let moved = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if moved < 0 {
        return Err(Error::Io(crate::error::io_context("fcntl", io::Error::last_os_error())));
    }
    // SAFETY: `fcntl` just made `moved`, and nothing else owns it. `fd` closes on drop.
    Ok(unsafe { OwnedFd::from_raw_fd(moved) })
}

/// The read end never blocks: a report is read only after the child wrote it or is gone, but a copy
/// of the write end held by a fork without `exec` must not be able to hang the read.
fn set_nonblocking(fd: &OwnedFd) -> Result<(), Error> {
    // SAFETY: `fcntl` on an fd this function owns.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    // SAFETY: as above.
    if flags < 0 || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(Error::Io(crate::error::io_context("fcntl", io::Error::last_os_error())));
    }
    Ok(())
}

/// The error for a spawn whose child could not read its own unique id (`errno`): the hook failed
/// before `exec`, so the program did not start. It is a refusal, not a vanish.
pub(crate) fn refused_error(errno: i32) -> Error {
    Error::Unassessable {
        detail: format!(
            "the spawned child could not read its own unique id (errno {errno}); it was stopped before exec, so the program did not start"
        ),
        source: Some(io::Error::from_raw_os_error(errno)),
    }
}

impl Channel {
    /// Runs `spawn` with the pipe published, then reads the child's report. Ok: the spawn's value
    /// and the child's unique id, or the errno of a report that is missing ([`UNREPORTED`]). Err: the
    /// spawn's error, and the errno when the child's own read was refused (the hook then failed
    /// before `exec`; the error is to be mapped with [`refused_error`]).
    pub(crate) fn run<T, E>(self, spawn: impl FnOnce() -> Result<T, E>) -> Result<(T, Reported), (E, Option<i32>)> {
        let Channel {
            read_end,
            write_end,
            shared,
        } = self;
        let spawned = spawn();
        shared.live.store(false, Ordering::Release);
        // Closed before the read, so a child that never wrote leaves the pipe at EOF.
        drop(write_end);
        match spawned {
            Ok(child) => Ok((child, read_report(&read_end))),
            Err(e) => Err((e, read_report(&read_end).err().filter(|errno| *errno != UNREPORTED))),
        }
    }
}

fn read_report(read_end: &OwnedFd) -> Result<u64, i32> {
    let mut buf = [0u8; REPORT_LEN];
    let mut got = 0;
    while got < REPORT_LEN {
        // SAFETY: the pointer and length name the unfilled tail of `buf`.
        let n = unsafe { libc::read(read_end.as_raw_fd(), buf[got..].as_mut_ptr().cast(), REPORT_LEN - got) };
        match n {
            0 => return Err(UNREPORTED),
            n if n > 0 => got += n as usize,
            _ => {
                let e = io::Error::last_os_error();
                match e.raw_os_error() {
                    Some(libc::EINTR) => {}
                    Some(libc::EAGAIN) => return Err(UNREPORTED),
                    other => return Err(other.unwrap_or(libc::EIO)),
                }
            }
        }
    }
    let tag = u32::from_ne_bytes(buf[..4].try_into().expect("four bytes"));
    let value = u64::from_ne_bytes(buf[4..].try_into().expect("eight bytes"));
    match tag {
        REPORT_ID => Ok(value),
        REPORT_ERRNO => Err(value as i32),
        other => {
            debug_assert!(false, "a unique-id report with tag {other}");
            Err(libc::EIO)
        }
    }
}

/// The hook: the child reads its own unique id and writes the report. Async-signal-safe.
fn report(shared: &Shared, #[cfg(test)] forced_errno: i32) -> io::Result<()> {
    if !shared.live.load(Ordering::Acquire) {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }
    let fd = shared.write_fd.load(Ordering::Relaxed);
    #[cfg(test)]
    let read = if forced_errno != 0 {
        Err(forced_errno)
    } else {
        crate::identity::own_unique_id()
    };
    #[cfg(not(test))]
    let read = crate::identity::own_unique_id();
    let (tag, value) = match read {
        Ok(id) => (REPORT_ID, id),
        Err(errno) => (REPORT_ERRNO, errno as u64),
    };
    let mut buf = [0u8; REPORT_LEN];
    buf[..4].copy_from_slice(&tag.to_ne_bytes());
    buf[4..].copy_from_slice(&value.to_ne_bytes());
    loop {
        // SAFETY: `buf` is valid for `REPORT_LEN` bytes.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), REPORT_LEN) };
        if n == REPORT_LEN as isize {
            // A refused read stops the child here, before `exec`: the program never runs.
            return match tag {
                REPORT_ERRNO => Err(io::Error::from_raw_os_error(value as i32)),
                _ => Ok(()),
            };
        }
        let e = io::Error::last_os_error();
        if n < 0 && e.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(e);
    }
}

/// Test seams. Thread-local, armed on the thread that spawns.
#[cfg(test)]
pub(crate) mod seams {
    use std::cell::Cell;

    thread_local! {
        static FORCED_ERRNO: Cell<i32> = const { Cell::new(0) };
    }

    /// The next spawns on this thread have their child's own read fail with `errno`, until the
    /// guard drops.
    #[must_use = "dropping this immediately disarms the force; bind it for the probe's duration"]
    pub(crate) fn force_child_read_errno(errno: i32) -> Forced {
        FORCED_ERRNO.with(|f| f.set(errno));
        Forced(())
    }

    pub(crate) struct Forced(());

    impl Drop for Forced {
        fn drop(&mut self) {
            FORCED_ERRNO.with(|f| f.set(0));
        }
    }

    pub(super) fn forced_errno() -> i32 {
        FORCED_ERRNO.with(Cell::get)
    }
}
