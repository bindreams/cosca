//! Unix: std's pipe ends, which already read and write through a shared reference from any thread.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::process::Stdio;

use super::{PipeReader, PipeWriter};

pub(super) type Reader = std::io::PipeReader;
pub(super) type Writer = std::io::PipeWriter;

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
