//! Unix: std's pipe ends, which already read and write through a shared reference from any thread.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::process::Stdio;

use super::{ParentEnd, PipeReader, PipeWriter};
use crate::stdio::Direction;

pub(super) type Reader = std::io::PipeReader;
pub(super) type Writer = std::io::PipeWriter;

/// The pipe for one piped slot: the child's end, and the parent's, as `dir` says (`In`: the child
/// reads, the parent writes).
///
/// On macOS the caller holds `spawn_lock`: `std::io::pipe` is `pipe()` and then `FD_CLOEXEC`, so
/// another cosca fork between the two would inherit an end. Linux's `pipe2(O_CLOEXEC)` needs none.
pub(crate) fn child_pipe(dir: Direction) -> io::Result<(OwnedFd, ParentEnd)> {
    #[cfg(all(target_os = "macos", any(test, debug_assertions)))]
    debug_assert!(
        crate::child::spawn::spawn_lock_held_by_this_thread(),
        "a pipe is made under spawn_lock on macOS"
    );
    let (reader, writer) = std::io::pipe()?;
    Ok(match dir {
        Direction::In => (reader.into(), ParentEnd::Writer(writer.into())),
        Direction::Out => (writer.into(), ParentEnd::Reader(reader.into())),
    })
}

impl From<std::io::PipeReader> for PipeReader {
    fn from(p: std::io::PipeReader) -> PipeReader {
        PipeReader(p)
    }
}

impl From<std::io::PipeWriter> for PipeWriter {
    fn from(p: std::io::PipeWriter) -> PipeWriter {
        PipeWriter(p)
    }
}

impl From<OwnedFd> for PipeReader {
    fn from(fd: OwnedFd) -> PipeReader {
        PipeReader(fd.into())
    }
}

impl From<OwnedFd> for PipeWriter {
    fn from(fd: OwnedFd) -> PipeWriter {
        PipeWriter(fd.into())
    }
}

impl FromRawFd for PipeReader {
    /// # Safety
    ///
    /// As [`OwnedFd::from_raw_fd`]: `fd` is open and owned by nothing else. It must be a pipe's
    /// read end.
    unsafe fn from_raw_fd(fd: RawFd) -> PipeReader {
        // SAFETY: the caller's contract.
        PipeReader::from(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

impl FromRawFd for PipeWriter {
    /// # Safety
    ///
    /// As [`OwnedFd::from_raw_fd`]: `fd` is open and owned by nothing else. It must be a pipe's
    /// write end.
    unsafe fn from_raw_fd(fd: RawFd) -> PipeWriter {
        // SAFETY: the caller's contract.
        PipeWriter::from(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

impl IntoRawFd for PipeReader {
    fn into_raw_fd(self) -> RawFd {
        OwnedFd::from(self).into_raw_fd()
    }
}

impl IntoRawFd for PipeWriter {
    fn into_raw_fd(self) -> RawFd {
        OwnedFd::from(self).into_raw_fd()
    }
}

impl From<PipeReader> for OwnedFd {
    fn from(p: PipeReader) -> OwnedFd {
        p.0.into()
    }
}

impl From<PipeWriter> for OwnedFd {
    fn from(p: PipeWriter) -> OwnedFd {
        p.0.into()
    }
}

impl AsFd for PipeReader {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsFd for PipeWriter {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsRawFd for PipeReader {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl AsRawFd for PipeWriter {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl From<PipeReader> for Stdio {
    fn from(p: PipeReader) -> Stdio {
        Stdio::from(p.0)
    }
}

impl From<PipeWriter> for Stdio {
    fn from(p: PipeWriter) -> Stdio {
        Stdio::from(p.0)
    }
}
