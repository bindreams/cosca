//! Opaque async child-stream types. Each wraps EITHER tokio's own child stream (tokio-owned
//! std pipes — the default) OR an our-owned reactor-registered pipe end (merge-into-piped
//! targets, where tokio's internal pipe cannot be shared) — std's `ChildStdout` opacity
//! pattern. Public API: `AsyncRead`/`AsyncWrite` only.

use std::pin::Pin;
use std::task::{Context, Poll};

use ::tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(unix)]
pub(super) type OwnedRead = ::tokio::net::unix::pipe::Receiver;
/// The parent's end of a child pipe, which `make_pipe` made overlapped and unassociated, adopted by
/// the reactor at take time.
#[cfg(windows)]
pub(super) type OwnedRead = ::tokio::net::windows::named_pipe::NamedPipeServer;

/// The child's stdin (write end). Dropping it closes the pipe (EOF to the child).
pub struct ChildStdin {
    pub(super) inner: InInner,
}

pub(super) enum InInner {
    Tokio(::tokio::process::ChildStdin),
    /// An our-owned merge-target write end (a piped In target with mergers), reactor-registered.
    Owned(OwnedWrite),
}

#[cfg(unix)]
pub(super) type OwnedWrite = ::tokio::net::unix::pipe::Sender;
#[cfg(windows)]
pub(super) type OwnedWrite = ::tokio::net::windows::named_pipe::NamedPipeServer;

/// The child's stdout (read end).
pub struct ChildStdout {
    pub(super) inner: OutInner,
}

/// The child's stderr (read end).
pub struct ChildStderr {
    pub(super) inner: OutInner,
}

pub(super) enum OutInner {
    Stdout(::tokio::process::ChildStdout),
    Stderr(::tokio::process::ChildStderr),
    /// An our-owned merge-target pipe end, reactor-registered.
    Owned(OwnedRead),
}

/// A parent end of an our-owned merge-target pipe, stashed at spawn (keyed by the target
/// slot) until its accessor takes it.
pub(super) type OwnedStd = crate::pipe::ParentEnd;

impl AsyncWrite for ChildStdin {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match &mut self.inner {
            InInner::Tokio(s) => Pin::new(s).poll_write(cx, buf),
            InInner::Owned(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.inner {
            InInner::Tokio(s) => Pin::new(s).poll_flush(cx),
            InInner::Owned(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut self.inner {
            InInner::Tokio(s) => Pin::new(s).poll_shutdown(cx),
            InInner::Owned(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl OutInner {
    fn poll_read_inner(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self {
            OutInner::Stdout(s) => Pin::new(s).poll_read(cx, buf),
            OutInner::Stderr(s) => Pin::new(s).poll_read(cx, buf),
            OutInner::Owned(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncRead for ChildStdout {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        self.inner.poll_read_inner(cx, buf)
    }
}
impl AsyncRead for ChildStderr {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        self.inner.poll_read_inner(cx, buf)
    }
}

impl std::fmt::Debug for ChildStdin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildStdin").finish_non_exhaustive()
    }
}
impl std::fmt::Debug for ChildStdout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildStdout").finish_non_exhaustive()
    }
}
impl std::fmt::Debug for ChildStderr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildStderr").finish_non_exhaustive()
    }
}

/// Registers a parent read end with the reactor. On failure the end is closed.
///
/// # Panics
///
/// Panics outside a runtime with the IO driver enabled.
pub(super) fn register_reader(end: crate::PipeReader) -> std::io::Result<OwnedRead> {
    #[cfg(unix)]
    {
        ::tokio::net::unix::pipe::Receiver::from_owned_fd(std::os::fd::OwnedFd::from(end))
    }
    #[cfg(windows)]
    {
        adopt(end.into())
    }
}

/// [`register_reader`] for a write end.
pub(super) fn register_writer(end: crate::PipeWriter) -> std::io::Result<OwnedWrite> {
    #[cfg(unix)]
    {
        ::tokio::net::unix::pipe::Sender::from_owned_fd(std::os::fd::OwnedFd::from(end))
    }
    #[cfg(windows)]
    {
        adopt(end.into())
    }
}

/// Windows: an overlapped end that nothing has associated with a completion port (the sync pipe
/// types' I/O does not), so tokio can. Only `make_pipe` ends arrive here; a synchronous one would
/// block the reactor's thread on every operation.
#[cfg(windows)]
fn adopt(
    end: std::os::windows::io::OwnedHandle,
) -> std::io::Result<::tokio::net::windows::named_pipe::NamedPipeServer> {
    use std::os::windows::io::{AsHandle, IntoRawHandle};
    debug_assert!(
        crate::pipe::windows::is_overlapped(end.as_handle()).expect("query the end's mode"),
        "a pipe end registered with the reactor is overlapped"
    );
    let handle = end.into_raw_handle();
    // SAFETY: `from_raw_handle` requires a valid handle the caller owns and passes on to the
    // server: `handle` is, from `end`'s `into_raw_handle`. The reactor issues overlapped I/O on it,
    // so it must be an overlapped pipe handle: every end reaching here is `make_pipe`'s (asserted
    // above in debug). An end that another completion port already holds is refused by tokio with
    // an error (os error 87), which the caller handles.
    unsafe { ::tokio::net::windows::named_pipe::NamedPipeServer::from_raw_handle(handle) }
}

#[cfg(test)]
#[path = "stdio_tests.rs"]
mod stdio_tests;
