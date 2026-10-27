//! The filesystem questions a resolver asks, and the two implementations that answer them.

use std::io;

use crate::PurePath;

mod fake;
#[cfg(any(unix, windows))]
mod host;

pub(crate) use fake::sealed;
pub use fake::{FakeFilesystem, FakePath};
#[cfg(any(unix, windows))]
pub use host::HostFilesystem;

/// What is at a path.
///
/// `is_file` and `is_dir` return `Err` when the filesystem could not say (a permission, I/O or
/// network failure), and `Ok(false)` when it says there is nothing there: a caller never reads
/// their `Err` as absence.
///
/// `canonical` and `same_file` have no `Ok` for "nothing there", so absence is
/// [`NotFound`](io::ErrorKind::NotFound) from them. Every other `Err` is a failure to say, as for
/// the other two.
pub trait Filesystem {
    type Path: PurePath + ?Sized;

    /// Whether `p` is a file, following links.
    fn is_file(&self, p: &Self::Path) -> io::Result<bool>;

    /// Whether `p` is a directory, following links.
    fn is_dir(&self, p: &Self::Path) -> io::Result<bool>;

    /// `p` with every link resolved. `Err` if `p` does not exist.
    fn canonical(&self, p: &Self::Path) -> io::Result<<Self::Path as PurePath>::Buf>;

    /// Whether `a` and `b` are one file, by identity. `Err` unless both exist.
    fn same_file(&self, a: &Self::Path, b: &Self::Path) -> io::Result<bool>;
}

/// A path bound to the filesystem that answers questions about it.
pub struct BoundPath<'a, F: Filesystem + ?Sized> {
    fs: &'a F,
    path: &'a F::Path,
}

impl<'a, F: Filesystem + ?Sized> BoundPath<'a, F> {
    pub fn new(fs: &'a F, path: &'a F::Path) -> Self {
        BoundPath { fs, path }
    }

    pub fn path(&self) -> &'a F::Path {
        self.path
    }

    /// [`Filesystem::is_file`] on the bound path.
    pub fn is_file(&self) -> io::Result<bool> {
        self.fs.is_file(self.path)
    }

    /// [`Filesystem::is_dir`] on the bound path.
    pub fn is_dir(&self) -> io::Result<bool> {
        self.fs.is_dir(self.path)
    }

    /// [`Filesystem::canonical`] on the bound path.
    pub fn canonical(&self) -> io::Result<<F::Path as PurePath>::Buf> {
        self.fs.canonical(self.path)
    }
}
