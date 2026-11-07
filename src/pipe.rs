//! The parent's end of a child's pipe: [`PipeReader`] and [`PipeWriter`].
//!
//! Each is `Send + Sync`, and one end may be used from several threads at once, through a shared
//! reference or a [`try_clone`](PipeReader::try_clone). On Unix they wrap std's pipe ends and add
//! nothing. On Windows an end is the parent end of a child's pipe (overlapped) as the spawn makes
//! it, or any pipe handle a caller converts in: std's ends, an `OwnedHandle`. Either way every read
//! and write waits on an event of its own, never on the pipe's handle, which is what keeps one
//! thread's completion from releasing another's wait (std's pipe ends abort the process when two
//! threads share an end).
//!
//! A raw handle taken out of an end and wrapped in std's types is the caller's own act: std's types
//! wait on the handle itself, and are not safe to share between threads.
//!
//! On Windows a wait that fails after the kernel took a buffer cannot be answered with an error;
//! it aborts the process instead.

use std::io::{self, IoSlice, IoSliceMut, Read, Write};

#[cfg(unix)]
pub(crate) mod unix;
#[cfg(unix)]
use unix as sys;

#[cfg(windows)]
pub(crate) mod windows;
#[cfg(windows)]
use windows as sys;

pub(crate) use sys::child_pipe;

/// The parent's read end of a pipe to a child.
#[derive(Debug)]
pub struct PipeReader(sys::Reader);

/// The parent's write end of a pipe to a child.
#[derive(Debug)]
pub struct PipeWriter(sys::Writer);

impl PipeReader {
    /// A second handle on the same end; reads through either take from the same stream.
    pub fn try_clone(&self) -> io::Result<PipeReader> {
        self.0.try_clone().map(PipeReader)
    }
}

impl PipeWriter {
    /// A second handle on the same end; writes through either go to the same stream.
    pub fn try_clone(&self) -> io::Result<PipeWriter> {
        self.0.try_clone().map(PipeWriter)
    }
}

impl Read for PipeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self).read(buf)
    }
    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        (&*self).read_vectored(bufs)
    }
}

impl Read for &PipeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.0).read(buf)
    }
    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        (&self.0).read_vectored(bufs)
    }
}

impl Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self).write(buf)
    }
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        (&*self).write_vectored(bufs)
    }
    fn flush(&mut self) -> io::Result<()> {
        (&*self).flush()
    }
}

impl Write for &PipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&self.0).write(buf)
    }
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        (&self.0).write_vectored(bufs)
    }
    fn flush(&mut self) -> io::Result<()> {
        (&self.0).flush()
    }
}

#[cfg(test)]
#[path = "pipe_tests.rs"]
mod pipe_tests;
