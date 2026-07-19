//! Opaque async child-stream types. Each wraps EITHER tokio's own child stream (tokio-owned
//! std pipes — the default) OR an our-owned reactor-registered pipe end (merge-into-piped
//! targets, where tokio's internal pipe cannot be shared) — std's `ChildStdout` opacity
//! pattern. Public API: `AsyncRead`/`AsyncWrite` only.

#[cfg(windows)]
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use ::tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(unix)]
type OwnedRead = ::tokio::net::unix::pipe::Receiver;
#[cfg(windows)]
type OwnedRead = WinOwnedRead; // Connecting/Ready state machine (see below)

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
type OwnedWrite = ::tokio::net::unix::pipe::Sender;
#[cfg(windows)]
type OwnedWrite = WinOwnedWrite; // Connecting/Ready state machine (see below)

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
/// slot) until its accessor takes it. Unix stashes the raw sync `ParentEnd` (converted to a
/// reactor pipe at take time); Windows stashes the already-registered wrapper directly (the
/// `NamedPipeServer` and its connect task were created at spawn, inside the runtime —
/// reconstructing via `from_raw_handle` would double-register the IOCP handle).
#[cfg(unix)]
pub(super) type OwnedStd = crate::child::ParentEnd;
#[cfg(windows)]
#[derive(Debug)]
pub(super) enum OwnedStd {
    Read(WinOwnedRead),
    Write(WinOwnedWrite),
}

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

// (Windows: `WinOwnedRead` and `WinOwnedWrite` are thin wrappers over ONE shared
// `ConnectingPipe` state machine — the connect transition and JoinError taxonomy exist
// exactly once.)

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

/// An "anonymous" pipe with an overlapped, reactor-registered parent end (std's `anon_pipe`
/// technique via tokio's PUBLIC API): a uniquely named server end (ours) + a sync
/// `OpenOptions` client end (the child's; std's spawn duplicates stdio handles inheritable
/// itself). Out-direction: parent reads, child writes. Any failure surfaces as a typed
/// `Err` — no retry. Call inside the runtime.
#[cfg(windows)]
pub(crate) fn overlapped_out_pipe() -> Result<
    (
        ::tokio::net::windows::named_pipe::NamedPipeServer,
        std::os::windows::io::OwnedHandle,
    ),
    crate::error::Error,
> {
    overlapped_pipe(false)
}

/// The In-direction twin: parent writes (outbound server), child reads. Dropping the server
/// end delivers buffered data first, then clean EOF to the client — verified; `disconnect()`
/// would DISCARD buffered data and is deliberately never used.
#[cfg(windows)]
pub(crate) fn overlapped_in_pipe() -> Result<
    (
        ::tokio::net::windows::named_pipe::NamedPipeServer,
        std::os::windows::io::OwnedHandle,
    ),
    crate::error::Error,
> {
    overlapped_pipe(true)
}

/// Unique, UNPREDICTABLE name: pid + counter (in-process uniqueness independent of the
/// RNG) + a 64-bit `getrandom` component — std parity (std randomizes its anon-pipe
/// names): an unpredictable name turns squatting/slot-stealing from name arithmetic into
/// an enumeration race.
#[cfg(windows)]
fn overlapped_pipe(
    parent_writes: bool,
) -> Result<
    (
        ::tokio::net::windows::named_pipe::NamedPipeServer,
        std::os::windows::io::OwnedHandle,
    ),
    crate::error::Error,
> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).map_err(|e| crate::error::Error::Io(std::io::Error::other(e)))?;
    let name = format!(
        r"\\.\pipe\subprocess.{}.{}.{:016x}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
        u64::from_ne_bytes(r)
    );
    overlapped_pipe_named(&name, parent_writes)
}

/// The name-parameterized core (split so the unit tests can pin the squat, slot-theft, and
/// connect-state contracts against a name they control).
#[cfg(windows)]
pub(crate) fn overlapped_pipe_named(
    name: &str,
    parent_writes: bool,
) -> Result<
    (
        ::tokio::net::windows::named_pipe::NamedPipeServer,
        std::os::windows::io::OwnedHandle,
    ),
    crate::error::Error,
> {
    use ::tokio::net::windows::named_pipe::ServerOptions;

    let server = ServerOptions::new()
        .access_inbound(!parent_writes)
        .access_outbound(parent_writes)
        .first_pipe_instance(true) // a squatted name FAILS here — never silently attach
        .reject_remote_clients(true)
        .max_instances(1)
        .create(name)
        .map_err(|e| {
            // Terminal either way (no retry). PermissionDenied is squat-suspected — the
            // security-relevant case — and logs at warn; anything else at debug.
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                log::warn!("merge-target pipe name {name} already claimed (squat suspected) or ACL-denied: {e}");
            } else {
                log::debug!("merge-target pipe creation failed for {name}: {e}");
            }
            crate::error::Error::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "creating merge-target pipe {name}: {e} (PermissionDenied means the name is already claimed — never attached — or creation is denied)"
                ),
            ))
        })?;
    let client = open_client_slot(name, parent_writes)?;
    // The IOCP server has no I/O completions until `ConnectNamedPipe` runs; the caller
    // awaits that in `connect_task` before any read or write.
    Ok((server, client))
}

/// Claim the pipe's SINGLE client slot, immediately after creation and before the name is
/// ever handed anywhere (split out so the slot-theft test drives the production claim
/// path). `max_instances(1)` makes the slot exclusive: if a hostile local client wins the
/// create->open race, THIS open fails (`ERROR_PIPE_BUSY`, verified) and spawn errors out
/// before any child exists or any byte moves — the parent can never read a stranger's
/// bytes, and the worst case is a typed spawn failure. Conversely, once this open
/// succeeds, `first_pipe_instance` + `max_instances(1)` guarantee both handles belong to
/// our own pipe.
#[cfg(windows)]
pub(crate) fn open_client_slot(
    name: &str,
    parent_writes: bool,
) -> Result<std::os::windows::io::OwnedHandle, crate::error::Error> {
    std::fs::OpenOptions::new()
        .read(parent_writes)
        .write(!parent_writes)
        .open(name)
        .map(std::os::windows::io::OwnedHandle::from)
        .map_err(|e| {
            log::warn!("merge-target pipe {name}: client-slot open failed ({e}); slot theft suspected");
            // Returned UNWRAPPED: `ERROR_PIPE_BUSY` (231) has no stable `ErrorKind`
            // (`Uncategorized`), so the raw OS code is the only stable identity — a message
            // wrapper would erase `raw_os_error()`. The name/context lives in the warn above.
            crate::error::Error::Io(e)
        })
}

/// Spawn the mandatory connect as a real task; the returned `JoinHandle` is itself a future
/// that the stream wrapper polls to completion before its first I/O (`WinOwnedRead` /
/// `WinOwnedWrite`).
#[cfg(windows)]
pub(crate) fn connect_task(
    server: ::tokio::net::windows::named_pipe::NamedPipeServer,
) -> ::tokio::task::JoinHandle<std::io::Result<::tokio::net::windows::named_pipe::NamedPipeServer>> {
    ::tokio::spawn(async move { server.connect().await.map(|()| server) })
}

/// The ONE Connecting/Ready/Failed state machine both owned-stream directions share:
/// drives the spawned `ConnectNamedPipe` task to completion, then yields the
/// reactor-registered server. The connect transition and the JoinError taxonomy exist
/// exactly here — never duplicated per direction. A failed connect (or a
/// panicked/cancelled connect task) parks the machine in the terminal `Failed`, which
/// re-yields the error on every later poll — a completed `JoinHandle` is never re-polled
/// (tokio panics on that), so retrying I/O after an `Err` stays an `Err`, never a panic.
#[cfg(windows)]
#[derive(Debug)]
pub(super) enum ConnectingPipe {
    Connecting(::tokio::task::JoinHandle<std::io::Result<::tokio::net::windows::named_pipe::NamedPipeServer>>),
    Ready(::tokio::net::windows::named_pipe::NamedPipeServer),
    /// Terminal: the original error's kind + message, reproduced on every later poll.
    Failed(std::io::ErrorKind, String),
}

#[cfg(windows)]
impl ConnectingPipe {
    /// Drive Connecting -> Ready (or the terminal Failed); yields a borrow of the
    /// connected server.
    fn poll_ready_server(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<&mut ::tokio::net::windows::named_pipe::NamedPipeServer>> {
        loop {
            match self {
                ConnectingPipe::Connecting(handle) => match Pin::new(handle).poll(cx) {
                    Poll::Ready(Ok(Ok(server))) => *self = ConnectingPipe::Ready(server),
                    Poll::Ready(Ok(Err(e))) => {
                        *self = ConnectingPipe::Failed(e.kind(), e.to_string());
                        return Poll::Ready(Err(e));
                    }
                    // A panicked/cancelled connect task is a bug surfaced as an error,
                    // never a false EOF (mirrors the grace_wait JoinError taxonomy).
                    Poll::Ready(Err(join)) => {
                        let e = std::io::Error::other(join);
                        *self = ConnectingPipe::Failed(e.kind(), e.to_string());
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                ConnectingPipe::Ready(server) => return Poll::Ready(Ok(server)),
                ConnectingPipe::Failed(kind, msg) => return Poll::Ready(Err(std::io::Error::new(*kind, msg.clone()))),
            }
        }
    }
}

/// The Windows owned read end (Out-direction merge target).
#[cfg(windows)]
#[derive(Debug)]
pub(super) struct WinOwnedRead(pub(super) ConnectingPipe);

#[cfg(windows)]
impl WinOwnedRead {
    fn poll_read_inner(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let server = std::task::ready!(self.0.poll_ready_server(cx))?;
        Pin::new(server).poll_read(cx, buf)
    }
}

#[cfg(windows)]
impl AsyncRead for WinOwnedRead {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        self.poll_read_inner(cx, buf)
    }
}

/// The Windows owned WRITE end (In-direction merge target). Dropping it (either state)
/// closes the server handle, which delivers any buffered data first and THEN clean EOF to
/// the child (verified); `disconnect()` is deliberately never called — it DISCARDS
/// buffered data. A drop while still `Connecting` detaches the task, which completes the
/// connect and drops the server — teardown, not a leak.
#[cfg(windows)]
#[derive(Debug)]
pub(super) struct WinOwnedWrite(pub(super) ConnectingPipe);

#[cfg(windows)]
impl WinOwnedWrite {
    fn poll_write_inner(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let server = std::task::ready!(self.0.poll_ready_server(cx))?;
        Pin::new(server).poll_write(cx, buf)
    }
    fn poll_flush_inner(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let server = std::task::ready!(self.0.poll_ready_server(cx))?;
        Pin::new(server).poll_flush(cx)
    }
    fn poll_shutdown_inner(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let server = std::task::ready!(self.0.poll_ready_server(cx))?;
        Pin::new(server).poll_shutdown(cx)
    }
}

#[cfg(windows)]
impl AsyncWrite for WinOwnedWrite {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        self.poll_write_inner(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_flush_inner(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_shutdown_inner(cx)
    }
}

/// Build a direction-appropriate overlapped (reactor-registered) pipe: the child's raw handle end
/// plus our owned parent wrapper, whose mandatory `ConnectNamedPipe` is spawned as a task here
/// (inside the runtime). Shared by the async std spawn's merge pre-pass and the async raw backend's
/// piped std slots. Any failure is a typed `Err` — no retry.
#[cfg(windows)]
pub(crate) fn owned_overlapped_pipe(
    dir: crate::stdio::Direction,
) -> Result<(std::os::windows::io::OwnedHandle, OwnedStd), crate::error::Error> {
    use crate::stdio::Direction;
    match dir {
        Direction::In => {
            let (server, client) = overlapped_in_pipe()?;
            let connecting = ConnectingPipe::Connecting(connect_task(server));
            Ok((client, OwnedStd::Write(WinOwnedWrite(connecting))))
        }
        Direction::Out => {
            let (server, client) = overlapped_out_pipe()?;
            let connecting = ConnectingPipe::Connecting(connect_task(server));
            Ok((client, OwnedStd::Read(WinOwnedRead(connecting))))
        }
    }
}

#[cfg(test)]
#[path = "stdio_tests.rs"]
mod stdio_tests;
