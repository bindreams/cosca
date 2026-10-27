use std::borrow::Borrow;
use std::io;

use super::Filesystem;
use crate::{Component, PurePath};

/// A path type [`FakeFilesystem`] can model: [`windows::Path`](crate::windows::Path) and
/// [`posix::Path`](crate::posix::Path). Sealed: no other type implements it.
pub trait FakePath: sealed::Lookup {}

impl<P: sealed::Lookup + ?Sized> FakePath for P {}

pub(crate) mod sealed {
    use crate::PurePath;

    /// What [`FakePath`](super::FakePath) requires, kept out of the public API.
    pub trait Lookup: PurePath {
        /// The path as the OS looks it up, so that two spellings of one entry are equal.
        ///
        /// Repeated separators collapse. A trailing separator stays: it names only a directory. On
        /// Windows the lookup also writes `\` for `/`, resolves `.` and `..` lexically as Win32 does
        /// for a non-verbatim path (a final `.` or `..` leaves no trailing separator), and ends a UNC
        /// share root in `\`. On POSIX `.` and `..` stay: the kernel resolves `..` physically, through
        /// links the fake does not model.
        fn lookup_spelling(&self) -> Self::Buf;
    }
}

/// A filesystem described by the test that uses it, for paths of one OS: see
/// [`windows::FakeFilesystem`](crate::windows::FakeFilesystem) and
/// [`posix::FakeFilesystem`](crate::posix::FakeFilesystem).
///
/// Anything the test does not state is absent. A stated file implies its ancestors are
/// directories, a stated directory likewise (never the empty path of a relative one). A later
/// statement about a path replaces an earlier one.
///
/// A query names an entry as the real filesystem resolves it, up to what no OS distinguishes:
/// repeated and trailing separators do not matter (`C:\bin\` is `C:\bin`, `/usr/bin//tool` is
/// `/usr/bin/tool`), a UNC share root is one entry with or without its trailing separator, and
/// `/` is `\` on Windows. A trailing separator names only a directory.
///
/// The Windows fake resolves `.` and `..` lexically, as Win32 does for a non-verbatim path:
/// `C:\Windows\nope\..\System32` is `C:\Windows\System32`. The POSIX fake does not, because the
/// kernel resolves `..` physically, through symlinks the fake does not model; a test queries the
/// spelling it states.
///
/// Case is exact, even for Windows paths: the test states the case it queries. Windows trailing
/// dots and spaces are not modelled (`notepad.exe.` is not `notepad.exe`).
///
/// Entries are matched by scanning, which is fine for the handful a test states.
pub struct FakeFilesystem<P: FakePath + ?Sized> {
    entries: Vec<(P::Buf, Entry)>,
    links: Vec<(P::Buf, P::Buf)>,
}

enum Entry {
    File,
    Dir,
    /// A directory that stats fine, with nothing strictly below it examinable.
    UnreadableDir(io::ErrorKind),
    Error(io::ErrorKind),
}

/// Whether `p` ends in a separator, so that only a directory answers to it.
fn ends_in_separator<P: PurePath + ?Sized>(p: &P) -> bool {
    matches!(p.components().next_back(), Some(Component::Empty))
}

/// The entry `p` names, and whether it was spelled with a trailing separator.
fn lookup<P: FakePath + ?Sized>(p: &P) -> (P::Buf, bool) {
    let spelled = p.lookup_spelling();
    let spelled: &P = spelled.borrow();
    if ends_in_separator(spelled) {
        let name = spelled.parent().expect("a trailing separator follows a name");
        (name.to_owned(), true)
    } else {
        (spelled.to_owned(), false)
    }
}

impl<P: FakePath + ?Sized> FakeFilesystem<P> {
    pub fn new() -> Self {
        FakeFilesystem {
            entries: Vec::new(),
            links: Vec::new(),
        }
    }

    /// States that `path` is a file.
    pub fn with_file(mut self, path: &P) -> Self {
        self.state(path, Entry::File);
        self
    }

    /// States that `path` is a directory.
    pub fn with_dir(mut self, path: &P) -> Self {
        self.state(path, Entry::Dir);
        self
    }

    /// States that `path` is a directory that stats fine, but whose contents cannot be examined:
    /// every question about anything strictly below it fails with `kind`. This is a directory
    /// without the permission to list or traverse it.
    pub fn with_unreadable_dir(mut self, path: &P, kind: io::ErrorKind) -> Self {
        self.state(path, Entry::UnreadableDir(kind));
        self
    }

    /// States that every question about `path`, or about anything below it, fails with `kind`,
    /// including whether `path` itself exists. It says nothing about `path`'s parent, which stays
    /// as stated (absent, unless something else implies it). A directory that answers for itself
    /// but not for its contents is [`with_unreadable_dir`](Self::with_unreadable_dir).
    pub fn with_error(mut self, path: &P, kind: io::ErrorKind) -> Self {
        self.set(lookup(path).0, Entry::Error(kind));
        self
    }

    /// States that [`canonical`](Filesystem::canonical) of `path` is `target`, returned as given
    /// and not checked. It does not make `path` exist: a link is also stated with
    /// [`with_file`](Self::with_file) or [`with_dir`](Self::with_dir).
    ///
    /// It moves exactly `path`, not what is below it: `with_canonical("/bin", "/usr/bin")` leaves
    /// `canonical("/bin/tool")` as `/bin/tool`. A path cannot be built from a component
    /// generically, so the fake cannot rebase the rest. A resolver canonicalises the candidate it
    /// found, so the test states that candidate's target too.
    pub fn with_canonical(mut self, path: &P, target: &P) -> Self {
        let key = lookup(path).0;
        match self.links.iter_mut().find(|(link, _)| link == &key) {
            Some((_, to)) => *to = target.to_owned(),
            None => self.links.push((key, target.to_owned())),
        }
        self
    }

    /// Records the entry `key` as `entry`, replacing an earlier statement.
    fn set(&mut self, key: P::Buf, entry: Entry) {
        match self.entries.iter_mut().find(|(stated, _)| stated == &key) {
            Some((_, old)) => *old = entry,
            None => self.entries.push((key, entry)),
        }
    }

    /// Records `path` as `entry`, and its ancestors as directories where nothing is stated. The
    /// empty parent of a relative path is not an ancestor: nothing resolves it.
    fn state(&mut self, path: &P, entry: Entry) {
        let key = lookup(path).0;
        let mut ancestors = Vec::new();
        let mut child: &P = key.borrow();
        while let Some(parent) = child.parent() {
            if parent.to_native_bytes().is_empty() {
                break;
            }
            ancestors.push(parent.to_owned());
            child = parent;
        }
        for ancestor in ancestors {
            if self.find(ancestor.borrow()).is_none() {
                self.entries.push((ancestor, Entry::Dir));
            }
        }
        self.set(key, entry);
    }

    fn find(&self, key: &P) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|(stated, _)| Borrow::<P>::borrow(stated) == key)
            .map(|(_, entry)| entry)
    }

    /// What is at the entry `key`: an `Err` if it or an ancestor has a stated error, or an
    /// ancestor is an unreadable directory (the one nearest the root, which a walk down meets
    /// first), else the stated entry, if any. A file does not answer to a name that ends in a
    /// separator.
    fn entry(&self, key: &P, dir_only: bool) -> io::Result<Option<&Entry>> {
        let mut chain = vec![key];
        while let Some(parent) = chain.last().and_then(|c| c.parent()) {
            chain.push(parent);
        }
        let last = chain.len() - 1;
        for (depth, node) in chain.into_iter().rev().enumerate() {
            match self.find(node) {
                Some(Entry::Error(kind)) => return Err((*kind).into()),
                Some(Entry::UnreadableDir(kind)) if depth != last => return Err((*kind).into()),
                _ => {}
            }
        }
        Ok(match self.find(key) {
            Some(Entry::File) if dir_only => None,
            entry => entry,
        })
    }

    fn at(&self, p: &P) -> io::Result<Option<&Entry>> {
        let (key, dir_only) = lookup(p);
        self.entry(key.borrow(), dir_only)
    }

    /// The entry `p` names with its stated link followed, once.
    fn resolved(&self, p: &P) -> io::Result<P::Buf> {
        let (key, dir_only) = lookup(p);
        match self.entry(key.borrow(), dir_only)? {
            None => Err(io::ErrorKind::NotFound.into()),
            Some(_) => Ok(match self.links.iter().find(|(link, _)| link == &key) {
                Some((_, target)) => target.clone(),
                None => key,
            }),
        }
    }
}

impl<P: FakePath + ?Sized> Default for FakeFilesystem<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: FakePath + ?Sized> Filesystem for FakeFilesystem<P> {
    type Path = P;

    fn is_file(&self, p: &P) -> io::Result<bool> {
        Ok(matches!(self.at(p)?, Some(Entry::File)))
    }

    fn is_dir(&self, p: &P) -> io::Result<bool> {
        Ok(matches!(self.at(p)?, Some(Entry::Dir | Entry::UnreadableDir(_))))
    }

    fn canonical(&self, p: &P) -> io::Result<P::Buf> {
        self.resolved(p)
    }

    fn same_file(&self, a: &P, b: &P) -> io::Result<bool> {
        let (a, b) = (self.resolved(a)?, self.resolved(b)?);
        Ok(lookup(a.borrow()).0 == lookup(b.borrow()).0)
    }
}

#[cfg(test)]
#[path = "fake_tests.rs"]
mod fake_tests;
