use std::borrow::Borrow;
use std::io;

use super::sealed::{self, Cwd, Implicit, Spelling};
use super::Filesystem;

/// A path type [`FakeFilesystem`] can model: [`windows::Path`](crate::windows::Path) and
/// [`posix::Path`](crate::posix::Path). Sealed: no other type implements it.
pub trait FakePath: sealed::Lookup {}

impl<P: sealed::Lookup + ?Sized> FakePath for P {}

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
/// `/` is `\` on Windows. A trailing separator names only a directory. `.` is dropped on both OSes
/// (`./tool` is `tool`). Case is exact, even for Windows paths: the test states the case it queries.
///
/// On Windows, `..` resolves as text, as Win32 does for a non-verbatim path:
/// `C:\Windows\nope\..\System32` is `C:\Windows\System32`. A `.` or `?` device path named for a drive
/// or `UNC` is the path it names (`\\.\C:\Windows` is `C:\Windows`), also after `Global\` or
/// `GLOBALROOT\??\`. `f::$DATA` is the file `f` (and `PermissionDenied` for a directory), and
/// `d:$I30:$INDEX_ALLOCATION` and `d::$INDEX_ALLOCATION` are the directory `d`.
///
/// On POSIX, `..` leaves the directory before it, which has to exist (`/a/x/..` is absent unless
/// `/a/x` is stated), and a `.` or `..` inside an unreadable directory needs the permission to
/// search it. A `..` after a link stated with [`with_canonical`](Self::with_canonical) goes through
/// the link's target, which the fake does not follow, so it is refused.
///
/// The current directory and its ancestors are directories on every host, stated or not: `.`, `..`
/// and `../..`, and on Windows the root of the current drive `\` and a drive's current directory `C:`
/// where `C:\` is there. What any other relative path names depends on the current directory, which
/// the fake has no value for. So [`canonical`](Filesystem::canonical) of a relative path that exists is
/// `InvalidInput` (the host's is absolute), and so is [`same_file`](Filesystem::same_file) of two
/// paths that may be one file through the current directory: a relative and an absolute one, two
/// that are relative to different things (`a`, `\a`, `C:a`), or one that starts with `..` and another.
///
/// A path the host refuses before it looks anything up is an error from every question, whatever
/// else the test stated about it:
///
/// - [`InvalidInput`](io::ErrorKind::InvalidInput): a NUL; on Windows, each path that
///   [`to_wide`](crate::windows::Path::to_wide) has no string for (the empty path, a relative `tool.`,
///   a `//?/UNC/?/` server); an alternate data stream (`f:x`), which the fake does not model.
/// - [`PermissionDenied`](io::ErrorKind::PermissionDenied): on Windows, a DOS device name (`nul`,
///   `com1`, `lpt1`, `aux`, `con`, `prn`, `clock$`) as the last name under a UNC share, which a
///   Windows server refuses.
/// - [`Other`](io::ErrorKind::Other): on Windows, the device of a volume whose drive is there
///   (`\\.\C:`), and `\\.\Global` alone.
///
/// The empty path is absent on POSIX, as on a Unix host.
///
/// [`canonical`](Filesystem::canonical) returns the host's spelling of the entry: separators
/// collapsed, `/` as `\` on Windows, `.` and `..` resolved as for a query, and no separator after a
/// UNC share root. A stated link gives its target as the test wrote it.
///
/// A file has no children: stating a path under a stated file, or a file (or a stated error) over
/// a path that has entries below it, panics in the builder in either order, since no filesystem
/// holds that. So does a file stated at a name only a directory has (a trailing separator, a root,
/// `.`, a final `..`, on POSIX a final `.` after a name, a directory index), a directory stated as
/// a data stream (`d::$DATA`), and any entry stated in a volume's device.
pub struct FakeFilesystem<P: FakePath + ?Sized> {
    entries: Vec<(P::Buf, Entry)>,
    links: Vec<(P::Buf, P::Buf)>,
}

#[derive(Debug, Clone)]
enum Entry {
    File,
    Dir,
    /// A directory that stats fine, with nothing strictly below it examinable.
    UnreadableDir(io::ErrorKind),
    Error(io::ErrorKind),
}

/// The ancestors of `key`, nearest first. The empty parent of a relative path is not one: nothing
/// resolves it.
fn ancestors<P: FakePath + ?Sized>(key: &P) -> Vec<P::Buf> {
    let mut out = Vec::new();
    let mut child = key;
    while let Some(parent) = child.parent() {
        if parent.to_native_bytes().is_empty() {
            break;
        }
        out.push(parent.to_owned());
        child = parent;
    }
    out
}

/// Whether `key` is strictly below `ancestor`.
fn is_below<P: FakePath + ?Sized>(key: &P, ancestor: &P) -> bool {
    let mut up = key;
    while let Some(parent) = up.parent() {
        if parent == ancestor {
            return true;
        }
        up = parent;
    }
    false
}

fn refuse<B>(spelling: &Spelling<B>) -> io::Result<()> {
    match &spelling.refusal {
        Some((kind, why)) => Err(io::Error::new(*kind, why.as_str())),
        None => Ok(()),
    }
}

/// The directory every host has, for [`Implicit::Always`].
static DIR: Entry = Entry::Dir;

/// What `canonical` knows about a path that exists.
struct Resolved<B> {
    /// The path: the stated target of a link, else the entry's spelling.
    path: B,
    /// Whether `path` is a stated target, which the test said and the fake does not check.
    stated: bool,
    cwd: Cwd,
}

impl<P: FakePath + ?Sized> FakeFilesystem<P> {
    /// A filesystem with nothing in it.
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
    /// every question about anything strictly below it fails with `kind`.
    pub fn with_unreadable_dir(mut self, path: &P, kind: io::ErrorKind) -> Self {
        self.state(path, Entry::UnreadableDir(kind));
        self
    }

    /// States that every question about `path`, or about anything below it, fails with `kind`,
    /// including whether `path` itself exists. It says nothing about `path`'s parent, which stays
    /// as stated (absent, unless something else implies it). A directory that answers for itself
    /// but not for its contents is [`with_unreadable_dir`](Self::with_unreadable_dir).
    pub fn with_error(mut self, path: &P, kind: io::ErrorKind) -> Self {
        let key = Self::key(path);
        self.refuse_under_file(path, key.borrow());
        self.set(key, Entry::Error(kind));
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
        let key = Self::key(path);
        match self.links.iter_mut().find(|(link, _)| link == &key) {
            Some((_, to)) => *to = target.to_owned(),
            None => self.links.push((key, target.to_owned())),
        }
        self
    }

    /// The entry a statement about `path` is about. A volume's device has no entries to state.
    fn key(path: &P) -> P::Buf {
        let spelling = path.lookup();
        assert!(
            spelling.volume.is_none(),
            "{path:?} is a volume's device, which holds no entries"
        );
        spelling.key
    }

    fn set(&mut self, key: P::Buf, entry: Entry) {
        match self.entries.iter_mut().find(|(stated, _)| stated == &key) {
            Some((_, old)) => *old = entry,
            None => self.entries.push((key, entry)),
        }
    }

    /// Records `path` as `entry`, and its ancestors as directories where nothing is stated.
    fn state(&mut self, path: &P, entry: Entry) {
        let spelling = path.lookup();
        assert!(
            spelling.volume.is_none(),
            "{path:?} is a volume's device, which holds no entries"
        );
        let key = spelling.key;
        match entry {
            Entry::File => {
                assert!(
                    !spelling.dir_only,
                    "{path:?} names only a directory, so it cannot be a file"
                );
                let key: &P = key.borrow();
                let has_children = self.entries.iter().any(|(stated, _)| is_below(stated.borrow(), key));
                assert!(!has_children, "{key:?} has entries below it, so it cannot be a file");
            }
            _ => assert!(
                !spelling.data_stream,
                "{path:?} is the data stream of a name, which a directory does not have"
            ),
        }
        self.refuse_under_file(path, key.borrow());
        for ancestor in ancestors(key.borrow()) {
            if self.find(ancestor.borrow()).is_none() {
                self.entries.push((ancestor, Entry::Dir));
            }
        }
        self.set(key, entry);
    }

    /// Panics if an ancestor of `key`, the entry `path` names, is a stated file.
    fn refuse_under_file(&self, path: &P, key: &P) {
        for ancestor in ancestors(key) {
            if matches!(self.find(ancestor.borrow()), Some(Entry::File)) {
                panic!("{path:?} is under {ancestor:?}, which is a file");
            }
        }
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
    /// separator. With `inside`, `key` is a directory something is looked up in, so an unreadable
    /// one fails too.
    fn entry(&self, key: &P, dir_only: bool, inside: bool) -> io::Result<Option<&Entry>> {
        let mut chain = vec![key];
        while let Some(parent) = chain.last().and_then(|c| c.parent()) {
            chain.push(parent);
        }
        let last = chain.len() - 1;
        for (depth, node) in chain.into_iter().rev().enumerate() {
            match self.find(node) {
                Some(Entry::Error(kind)) => return Err((*kind).into()),
                Some(Entry::UnreadableDir(kind)) if depth != last || inside => return Err((*kind).into()),
                _ => {}
            }
        }
        Ok(match self.find(key) {
            Some(Entry::File) if dir_only => None,
            entry => entry,
        })
    }

    /// Whether a stated link is at `key` or above it.
    fn is_under_link(&self, key: &P) -> bool {
        self.links
            .iter()
            .any(|(link, _)| Borrow::<P>::borrow(link) == key || is_below(key, link.borrow()))
    }

    /// How the host reads `p` and what is there. With `search`, a `.` or `..` after a directory needs
    /// the permission to search it (what the kernel asks of any path it opens), where `canonical`
    /// takes them as text.
    fn at(&self, p: &P, search: bool) -> io::Result<(Spelling<P::Buf>, Option<&Entry>)> {
        let spelling = p.lookup();
        refuse(&spelling)?;
        if spelling.nothing {
            return Ok((spelling, None));
        }
        if let Some(root) = &spelling.volume {
            // The volume's device exists where its drive does, and the host refuses it.
            return match self.entry(root.borrow(), false, false)? {
                Some(_) => Err(io::Error::other(
                    "the path is a volume's device, which is no file or directory",
                )),
                None => Ok((spelling, None)),
            };
        }
        let key: &P = spelling.key.borrow();
        for (at, is_pop) in &spelling.inside {
            if *is_pop && self.is_under_link(at.borrow()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a `..` after a stated link goes through the link's target, which the fake does not follow",
                ));
            }
        }
        // The directories a `.` or `..` is looked up in must be there; those the path passes through
        // anyway are covered by the walk to the entry.
        for (at, _) in spelling.inside.iter().filter(|(at, _)| !is_below(key, at.borrow())) {
            match self.entry(at.borrow(), true, search)? {
                Some(Entry::Dir | Entry::UnreadableDir(_)) => {}
                _ => return Ok((spelling, None)),
            }
        }
        let mut found = self.entry(key, spelling.dir_only, false)?;
        if found.is_none() {
            found = match &spelling.implicit {
                Some(Implicit::Always) => Some(&DIR),
                Some(Implicit::IfExists(root)) => self.entry(root.borrow(), false, false)?.map(|_| &DIR),
                None => None,
            };
        }
        if spelling.data_stream && matches!(found, Some(Entry::Dir | Entry::UnreadableDir(_))) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "a directory has no default data stream to open",
            ));
        }
        Ok((spelling, found))
    }

    /// The entry `p` names with its stated link followed, once.
    fn resolved(&self, p: &P, search: bool) -> io::Result<Resolved<P::Buf>> {
        let (spelling, found) = self.at(p, search)?;
        if found.is_none() {
            return Err(io::ErrorKind::NotFound.into());
        }
        Ok(match self.links.iter().find(|(link, _)| link == &spelling.key) {
            Some((_, target)) => Resolved {
                cwd: Borrow::<P>::borrow(target).lookup().cwd,
                path: target.clone(),
                stated: true,
            },
            None => Resolved {
                path: Borrow::<P>::borrow(&spelling.key).canonical_spelling(),
                stated: false,
                cwd: spelling.cwd,
            },
        })
    }
}

impl<P: FakePath + ?Sized> Clone for FakeFilesystem<P> {
    fn clone(&self) -> Self {
        FakeFilesystem {
            entries: self.entries.clone(),
            links: self.links.clone(),
        }
    }
}

impl<P: FakePath + ?Sized> std::fmt::Debug for FakeFilesystem<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeFilesystem")
            .field("entries", &self.entries)
            .field("links", &self.links)
            .finish()
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
        Ok(matches!(self.at(p, true)?.1, Some(Entry::File)))
    }

    fn is_dir(&self, p: &P) -> io::Result<bool> {
        Ok(matches!(
            self.at(p, true)?.1,
            Some(Entry::Dir | Entry::UnreadableDir(_))
        ))
    }

    fn canonical(&self, p: &P) -> io::Result<P::Buf> {
        let resolved = self.resolved(p, false)?;
        if !resolved.stated && resolved.cwd != Cwd::Absolute {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a relative path's canonical form is absolute, and the fake has no current directory",
            ));
        }
        Ok(resolved.path)
    }

    fn same_file(&self, a: &P, b: &P) -> io::Result<bool> {
        let (a, b) = (self.resolved(a, true)?, self.resolved(b, true)?);
        let (ka, kb) = (
            Borrow::<P>::borrow(&a.path).lookup().key,
            Borrow::<P>::borrow(&b.path).lookup().key,
        );
        if ka == kb {
            return Ok(true);
        }
        match (&a.cwd, &b.cwd) {
            (Cwd::Absolute, Cwd::Absolute) => Ok(false),
            (Cwd::Relative { tag: ta, dotdot: false }, Cwd::Relative { tag: tb, dotdot: false }) if ta == tb => {
                Ok(false)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "whether these are one file depends on the current directory, which the fake has no value for",
            )),
        }
    }
}

#[cfg(test)]
#[path = "fake_tests.rs"]
mod fake_tests;
