//! The link's system calls: its sockets and descriptors.
//!
//! Every descriptor is created `CLOEXEC`. macOS cannot do it atomically, so creation runs under
//! `spawn_lock`: a cosca spawn never inherits one, though a spawn outside cosca can.

use std::io::{self, PipeReader, PipeWriter};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use rustix::event::{poll, PollFd, PollFlags};
use rustix::io::Errno;
use rustix::net::SendFlags;

use super::probe::Probe;
use crate::elevation::shim::private_dir::PrivateDir;

/// Runs `create`, which makes descriptors, under `spawn_lock` on macOS.
fn create_fds<T>(probe: &Probe, create: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    #[cfg(target_os = "macos")]
    let _guard = crate::child::spawn::spawn_lock();
    let made = create()?;
    probe.fd_created(spawn_lock_is_held());
    Ok(made)
}

#[cfg(all(test, target_os = "macos"))]
fn spawn_lock_is_held() -> bool {
    crate::child::spawn::spawn_lock_held_by_this_thread()
}

#[cfg(not(all(test, target_os = "macos")))]
fn spawn_lock_is_held() -> bool {
    false
}

/// macOS: sets and checks `SO_NOSIGPIPE` (std sets it already). Linux uses `MSG_NOSIGNAL` per send
/// instead.
#[cfg(target_os = "macos")]
pub(super) fn set_nosigpipe(fd: BorrowedFd<'_>) -> io::Result<()> {
    rustix::net::sockopt::set_socket_nosigpipe(fd, true)?;
    debug_assert!(rustix::net::sockopt::socket_nosigpipe(fd)?, "SO_NOSIGPIPE is set");
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub(super) fn set_nosigpipe(_: BorrowedFd<'_>) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "macos")]
const SEND_FLAGS: SendFlags = SendFlags::empty();
#[cfg(not(target_os = "macos"))]
const SEND_FLAGS: SendFlags = SendFlags::NOSIGNAL;

/// Why the socket's path could not be made.
pub(super) enum SocketPathError {
    /// `/proc` is not mounted, not this process's, or not readable.
    Proc(io::Error),
    /// Anything else (out of descriptors or memory).
    Other(io::Error),
}

/// The path to bind the socket named `name` in `dir` at.
///
/// Linux: through `/proc/thread-self/fd/<dir fd>` (`/proc/self` is the main thread's, which is wrong
/// after `unshare(CLONE_FILES)` or when that thread is gone), so that `sun_path` holds a short name whatever the length
/// of `TMPDIR`. The path is tried and compared with the descriptor before it is used; if `/proc` is
/// not usable (not mounted, a different one mounted), that is the error, and there is no fallback to
/// the long path.
#[cfg(target_os = "linux")]
pub(super) fn socket_path(probe: &Probe, dir: &PrivateDir, name: &str) -> Result<std::path::PathBuf, SocketPathError> {
    use std::os::fd::AsRawFd;
    let via_proc = probe
        .proc_root()
        .join(format!("thread-self/fd/{}", dir.dir_fd().as_raw_fd()));
    let opened = match probe.proc_open_error() {
        Some(injected) => Err(injected),
        None => rustix::fs::openat(
            rustix::fs::CWD,
            &via_proc,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ),
    };
    let opened = opened.map_err(|e| {
        // Only these say that `/proc` is not what it must be; running out of descriptors or memory
        // is not about `/proc`.
        if matches!(e, Errno::NOENT | Errno::NOTDIR | Errno::LOOP | Errno::ACCESS) {
            SocketPathError::Proc(e.into())
        } else {
            SocketPathError::Other(e.into())
        }
    })?;
    let (through_proc, own) = (
        rustix::fs::fstat(&opened).map_err(|e| SocketPathError::Other(e.into()))?,
        rustix::fs::fstat(dir.dir_fd()).map_err(|e| SocketPathError::Other(e.into()))?,
    );
    if (through_proc.st_dev, through_proc.st_ino) != (own.st_dev, own.st_ino) {
        return Err(SocketPathError::Proc(io::Error::other(format!(
            "{} is not this process's descriptor {}",
            via_proc.display(),
            dir.dir_fd().as_raw_fd()
        ))));
    }
    Ok(via_proc.join(name))
}

/// The longest `<real tmp>/<directory name>/<name>` that works. macOS binds by that full path, so
/// the limit is `sun_path` less its NUL. Linux binds through `/proc`, but the shim opens the
/// directory by its full path (and a path of `PATH_MAX` or more cannot be opened), so the limit is
/// `PATH_MAX` less the NUL.
pub(super) fn socket_path_limit() -> usize {
    #[cfg(target_os = "linux")]
    return libc::PATH_MAX as usize - 1;
    #[cfg(not(target_os = "linux"))]
    // SAFETY: an all-zero `sockaddr_un` is valid.
    return unsafe { std::mem::zeroed::<libc::sockaddr_un>() }.sun_path.len() - 1;
}

/// Whether the socket's full path, `<real tmp>/<directory name>/<name>`, is short enough.
/// `Err((length, limit))`: it would be `length` bytes, over the longest that works, `limit`.
pub(super) fn full_path_fits(real_tmp: &Path, name: &str) -> Result<(), (usize, usize)> {
    let length = real_tmp.as_os_str().len() + 1 + crate::elevation::shim::private_dir::NAME_LEN + 1 + name.len();
    let limit = socket_path_limit();
    if length > limit {
        Err((length, limit))
    } else {
        Ok(())
    }
}

/// macOS has no `bindat`, so the socket is bound at its full path.
#[cfg(not(target_os = "linux"))]
pub(super) fn socket_path(_: &Probe, dir: &PrivateDir, name: &str) -> Result<std::path::PathBuf, SocketPathError> {
    Ok(dir.path().join(name))
}

/// Removes the socket named `name` from the directory open as `dir`: relative to the descriptor, so
/// no path length matters.
pub(super) fn unlink_socket(dir: BorrowedFd<'_>, name: &str) -> Result<(), Errno> {
    rustix::fs::unlinkat(dir, name, rustix::fs::AtFlags::empty())
}

/// Binds the listener at `path`, nonblocking.
pub(super) fn bind_listener(probe: &Probe, path: &Path) -> io::Result<UnixListener> {
    let listener = create_fds(probe, || {
        let listener = UnixListener::bind(path)?;
        set_nosigpipe(listener.as_fd())?;
        probe.listener_made(listener.as_fd());
        Ok::<_, io::Error>(listener)
    })?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Accepts one connection; the caller prepares it ([`prepare_conn`]), because a peer that already
/// left makes that fail. `Ok(None)` when none is queued.
///
/// On macOS the accepted socket inherits `O_NONBLOCK` and `SO_NOSIGPIPE` from the listener; on Linux
/// it inherits neither. `prepare_conn` therefore sets both.
pub(super) fn accept(probe: &Probe, listener: &UnixListener) -> io::Result<Option<UnixStream>> {
    match create_fds(probe, || listener.accept().map(|(conn, _)| conn)) {
        Ok(conn) => Ok(Some(conn)),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

/// Makes an accepted connection nonblocking and `SIGPIPE`-free.
pub(super) fn prepare_conn(conn: &UnixStream) -> io::Result<()> {
    conn.set_nonblocking(true)?;
    set_nosigpipe(conn.as_fd())
}

/// A pipe with a nonblocking write end, for the wake pipe and the settled pipe. A write to a full
/// pipe then fails with `EAGAIN` instead of blocking, and the pipe is readable, which is all either
/// byte is for.
pub(super) fn pipe(probe: &Probe) -> io::Result<(PipeReader, PipeWriter)> {
    create_fds(probe, || {
        let (reader, writer) = std::io::pipe()?;
        let flags = rustix::fs::fcntl_getfl(&writer)?;
        rustix::fs::fcntl_setfl(&writer, flags | rustix::fs::OFlags::NONBLOCK)?;
        Ok((reader, writer))
    })
}

/// Writes one byte to a nonblocking pipe.
pub(super) fn write_byte(fd: BorrowedFd<'_>) -> Result<(), Errno> {
    loop {
        match rustix::io::write(fd, &[1]) {
            Ok(_) => return Ok(()),
            Err(Errno::INTR) => continue,
            Err(e) => return Err(e),
        }
    }
}

/// The effective uid of the process that connected `conn`.
#[cfg(target_os = "linux")]
pub(super) fn peer_euid(conn: BorrowedFd<'_>) -> io::Result<u32> {
    Ok(rustix::net::sockopt::socket_peercred(conn)?.uid.as_raw())
}

#[cfg(not(target_os = "linux"))]
pub(super) fn peer_euid(conn: BorrowedFd<'_>) -> io::Result<u32> {
    use std::os::fd::AsRawFd;
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: `conn` is a live socket and both out-pointers are valid for the call.
    if unsafe { libc::getpeereid(conn.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(uid)
}

/// Sends one byte without ever raising `SIGPIPE`.
pub(super) fn send_byte(conn: BorrowedFd<'_>, byte: u8) -> Result<(), Errno> {
    loop {
        match rustix::net::send(conn, &[byte], SEND_FLAGS) {
            Ok(1) => return Ok(()),
            // A one-byte send that sends nothing cannot be told from a full buffer.
            Ok(_) => return Err(Errno::AGAIN),
            Err(Errno::INTR) => continue,
            Err(e) => return Err(e),
        }
    }
}

/// What one nonblocking read found.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Read {
    Bytes(usize),
    Eof,
    /// Nothing to read yet.
    Empty,
    Failed(Errno),
}

pub(super) fn read_some(conn: BorrowedFd<'_>, buf: &mut [u8]) -> Read {
    debug_assert!(!buf.is_empty(), "a read of nothing reads as EOF");
    loop {
        return match rustix::io::read(conn, &mut *buf) {
            Ok(0) => Read::Eof,
            Ok(n) => Read::Bytes(n),
            Err(Errno::INTR) => continue,
            Err(Errno::AGAIN) => Read::Empty,
            Err(e) => Read::Failed(e),
        };
    }
}

/// Blocks until `fds` has an event, retrying `EINTR`.
pub(super) fn poll_ready(fds: &mut [PollFd<'_>]) -> Result<(), Errno> {
    loop {
        match poll(fds, None) {
            Ok(_) => return Ok(()),
            Err(Errno::INTR) => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Blocks until `conn` is readable (or hung up, or in error) or `settled` is. `on_armed` gets the
/// number of descriptors about to be polled. Returns on `EINTR` too: the caller re-checks the
/// outcome after every wake.
pub(super) fn wait_for_frame_or_outcome(
    conn: BorrowedFd<'_>,
    settled: &PipeReader,
    on_armed: impl FnOnce(usize),
) -> Result<(), Errno> {
    let mut fds = [PollFd::new(&conn, PollFlags::IN), PollFd::new(settled, PollFlags::IN)];
    on_armed(fds.len());
    match poll(&mut fds, None) {
        Ok(_) | Err(Errno::INTR) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Whether `fd` is readable now, without blocking.
pub(super) fn is_readable(fd: &PipeReader) -> bool {
    let zero = rustix::event::Timespec { tv_sec: 0, tv_nsec: 0 };
    let mut fds = [PollFd::new(fd, PollFlags::IN)];
    matches!(poll(&mut fds, Some(&zero)), Ok(n) if n > 0)
}
