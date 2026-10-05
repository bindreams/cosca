//! The link's system calls: its sockets and descriptors.
//!
//! Every descriptor is created `CLOEXEC`. Linux does it atomically. macOS cannot, so there the
//! creation runs under `spawn_lock` (D23): a cosca spawn never inherits one. A spawn outside cosca
//! still can, which D23 accepts.

use std::io::{self, PipeReader, PipeWriter};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use rustix::event::{poll, PollFd, PollFlags};
use rustix::io::Errno;
use rustix::net::SendFlags;

use super::probe::Probe;

/// Runs `create`, which makes descriptors, under `spawn_lock` on macOS (D23).
fn create_fds<T>(probe: &Probe, create: impl FnOnce() -> T) -> T {
    #[cfg(target_os = "macos")]
    let _guard = crate::child::spawn::spawn_lock();
    let made = create();
    probe.fd_created(spawn_lock_is_held());
    made
}

#[cfg(all(test, target_os = "macos"))]
fn spawn_lock_is_held() -> bool {
    crate::child::spawn::spawn_lock_held_by_this_thread()
}

#[cfg(not(all(test, target_os = "macos")))]
fn spawn_lock_is_held() -> bool {
    false
}

/// `SO_NOSIGPIPE` on macOS; Linux uses `MSG_NOSIGNAL` per send (D20).
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

/// Binds the listener at `path`, nonblocking.
pub(super) fn bind_listener(probe: &Probe, path: &Path) -> io::Result<UnixListener> {
    let listener = create_fds(probe, || {
        let listener = UnixListener::bind(path)?;
        set_nosigpipe(listener.as_fd())?;
        Ok::<_, io::Error>(listener)
    })?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Accepts one connection, still blocking and without `SO_NOSIGPIPE`; the caller prepares it
/// ([`prepare_conn`]), because a peer that already left makes that fail. `Ok(None)` when none is
/// queued.
pub(super) fn accept(probe: &Probe, listener: &UnixListener) -> io::Result<Option<UnixStream>> {
    match create_fds(probe, || listener.accept()) {
        Ok((conn, _)) => Ok(Some(conn)),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

/// Makes an accepted connection nonblocking and `SIGPIPE`-free.
pub(super) fn prepare_conn(conn: &UnixStream) -> io::Result<()> {
    conn.set_nonblocking(true)?;
    set_nosigpipe(conn.as_fd())
}

/// The wake pipe: the acceptor polls its read end, teardown writes the stop byte to its write end.
pub(super) fn wake_pipe(probe: &Probe) -> io::Result<(PipeReader, PipeWriter)> {
    create_fds(probe, std::io::pipe)
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

/// Blocks until `fds` has an event, retrying `EINTR`. Returns when any of `fds` is ready.
pub(super) fn poll_ready(fds: &mut [PollFd<'_>]) -> Result<(), Errno> {
    loop {
        match poll(fds, None) {
            Ok(_) => return Ok(()),
            Err(Errno::INTR) => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Blocks until `conn` is readable, hung up or in error.
pub(super) fn wait_readable(conn: BorrowedFd<'_>) -> Result<(), Errno> {
    poll_ready(&mut [PollFd::new(&conn, PollFlags::IN)])
}
