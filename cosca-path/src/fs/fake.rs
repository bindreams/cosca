use std::borrow::Borrow;
use std::io;

use super::Filesystem;
use crate::PurePath;

/// A filesystem that is a table the test states, for paths of one OS: see
/// [`windows::FakeFilesystem`](crate::windows::FakeFilesystem) and
/// [`posix::FakeFilesystem`](crate::posix::FakeFilesystem).
///
/// Each query answers exactly what was stated for that path, and a path is looked up by `==` of
/// its type, so what the type calls equal is one entry. Nothing is imitated of any OS: no `.` or
/// `..` is resolved, no alias or device spelling is read, no entry implies another (a stated file
/// does not make its directory exist), and nothing is refused for how it is spelled. What a real
/// host does with a spelling is for a test on that host, against
/// [`HostFilesystem`](crate::fs::HostFilesystem).
///
/// A path that is not stated is absent: `Ok(false)` from `is_file` and `is_dir`, and
/// [`NotFound`](io::ErrorKind::NotFound) from `canonical` and `same_file`. A later statement about
/// a path replaces an earlier one.
///
/// [`canonical`](Filesystem::canonical) of a stated path is the path as the test wrote it, or what
/// [`with_canonical`](Self::with_canonical) gives it. [`same_file`](Filesystem::same_file) is
/// whether the two canonical forms are equal.
pub struct FakeFilesystem<P: PurePath + ?Sized> {
    entries: Vec<(P::Buf, Entry)>,
    links: Vec<(P::Buf, P::Buf)>,
}

#[derive(Debug, Clone, Copy)]
enum Entry {
    File,
    Dir,
    Error(io::ErrorKind),
}

impl<P: PurePath + ?Sized> FakeFilesystem<P> {
    /// A filesystem with nothing in it.
    pub fn new() -> Self {
        FakeFilesystem {
            entries: Vec::new(),
            links: Vec::new(),
        }
    }

    /// States that `path` is a file.
    pub fn with_file(self, path: &P) -> Self {
        self.with(path, Entry::File)
    }

    /// States that `path` is a directory.
    pub fn with_dir(self, path: &P) -> Self {
        self.with(path, Entry::Dir)
    }

    /// States that every question about `path` itself, whether it exists included, fails with
    /// `kind`. No other path is affected.
    pub fn with_error(self, path: &P, kind: io::ErrorKind) -> Self {
        self.with(path, Entry::Error(kind))
    }

    /// States that [`canonical`](Filesystem::canonical) of `path` is `target`, returned as given.
    /// It does not make `path` exist: a link is also stated with [`with_file`](Self::with_file) or
    /// [`with_dir`](Self::with_dir). It moves only `path`, not what is below it.
    pub fn with_canonical(mut self, path: &P, target: &P) -> Self {
        match self.links.iter_mut().find(|(link, _)| link.borrow() == path) {
            Some((_, to)) => *to = target.to_owned(),
            None => self.links.push((path.to_owned(), target.to_owned())),
        }
        self
    }

    fn with(mut self, path: &P, entry: Entry) -> Self {
        match self.entries.iter_mut().find(|(stated, _)| stated.borrow() == path) {
            Some((_, old)) => *old = entry,
            None => self.entries.push((path.to_owned(), entry)),
        }
        self
    }

    /// What was stated for `p`: `Err` for a stated error, `None` if nothing.
    fn stated(&self, p: &P) -> io::Result<Option<Entry>> {
        match self.entries.iter().find(|(stated, _)| stated.borrow() == p) {
            Some((_, Entry::Error(kind))) => Err((*kind).into()),
            Some((_, entry)) => Ok(Some(*entry)),
            None => Ok(None),
        }
    }
}

impl<P: PurePath + ?Sized> Clone for FakeFilesystem<P> {
    fn clone(&self) -> Self {
        FakeFilesystem {
            entries: self.entries.clone(),
            links: self.links.clone(),
        }
    }
}

impl<P: PurePath + ?Sized> std::fmt::Debug for FakeFilesystem<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeFilesystem")
            .field("entries", &self.entries)
            .field("links", &self.links)
            .finish()
    }
}

impl<P: PurePath + ?Sized> Default for FakeFilesystem<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: PurePath + ?Sized> Filesystem for FakeFilesystem<P> {
    type Path = P;

    fn is_file(&self, p: &P) -> io::Result<bool> {
        Ok(matches!(self.stated(p)?, Some(Entry::File)))
    }

    fn is_dir(&self, p: &P) -> io::Result<bool> {
        Ok(matches!(self.stated(p)?, Some(Entry::Dir)))
    }

    fn canonical(&self, p: &P) -> io::Result<P::Buf> {
        if self.stated(p)?.is_none() {
            return Err(io::ErrorKind::NotFound.into());
        }
        Ok(match self.links.iter().find(|(link, _)| link.borrow() == p) {
            Some((_, target)) => target.clone(),
            None => p.to_owned(),
        })
    }

    fn same_file(&self, a: &P, b: &P) -> io::Result<bool> {
        Ok(self.canonical(a)? == self.canonical(b)?)
    }
}
