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

/// The path to bind the socket named `name` in `dir` at.
///
/// Linux: through `/proc/self/fd/<dir fd>`, so that `sun_path` holds a short name whatever the length
/// of `TMPDIR`. The path is tried and compared with the descriptor before it is used; if `/proc` is
/// not usable (not mounted, a different one mounted), that is the error, and there is no fallback to
/// the long path.
#[cfg(target_os = "linux")]
pub(super) fn socket_path(probe: &Probe, dir: &PrivateDir, name: &str) -> io::Result<std::path::PathBuf> {
    use std::os::fd::AsRawFd;
    let via_proc = probe.proc_root().join(format!("self/fd/{}", dir.dir_fd().as_raw_fd()));
    let opened = rustix::fs::openat(
        rustix::fs::CWD,
        &via_proc,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let (through_proc, own) = (rustix::fs::fstat(&opened)?, rustix::fs::fstat(dir.dir_fd())?);
    if (through_proc.st_dev, through_proc.st_ino) != (own.st_dev, own.st_ino) {
        return Err(io::Error::other(format!(
            "{} is not this process's descriptor {}",
            via_proc.display(),
            dir.dir_fd().as_raw_fd()
        )));
    }
    Ok(via_proc.join(name))
}

/// macOS has no `bindat`, so the socket is bound at its full path.
#[cfg(not(target_os = "linux"))]
pub(super) fn socket_path(_: &Probe, dir: &PrivateDir, name: &str) -> io::Result<std::path::PathBuf> {
    Ok(dir.path().join(name))
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
