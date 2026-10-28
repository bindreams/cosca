//! The filesystem questions a resolver asks, and the two implementations that answer them: this
//! machine's, and a table a test states.

use std::io;

use crate::PurePath;

mod fake;
#[cfg(any(unix, windows))]
mod host;

pub use fake::FakeFilesystem;
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
/// the other two. They need a handle on the object, so they can fail where `is_file` says
/// `Ok(true)`.
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
///
/// Two shared references: `Clone`, `Copy` and `Debug` (it prints the path) whatever `F` is, a
/// `dyn Filesystem` included.
pub struct BoundPath<'a, F: Filesystem + ?Sized> {
    fs: &'a F,
    path: &'a F::Path,
}

impl<F: Filesystem + ?Sized> Clone for BoundPath<'_, F> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<F: Filesystem + ?Sized> Copy for BoundPath<'_, F> {}

impl<F: Filesystem + ?Sized> std::fmt::Debug for BoundPath<'_, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("BoundPath").field(&self.path).finish()
    }
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

    /// [`Filesystem::same_file`] on the bound path and `other`'s path, asked of this path's
    /// filesystem: `other` must be bound to the same one. A filesystem with no state (a zero-sized
    /// one, such as [`HostFilesystem`]) has no identity to compare, so it is not checked.
    pub fn same_file(&self, other: &BoundPath<'_, F>) -> io::Result<bool> {
        debug_assert!(
            std::mem::size_of_val(self.fs) == 0 || std::ptr::addr_eq(self.fs, other.fs),
            "BoundPath::same_file: the two paths are bound to different filesystems"
        );
        self.fs.same_file(self.path, other.path)
    }
}

#[cfg(test)]
#[path = "fs_tests.rs"]
mod fs_tests;
