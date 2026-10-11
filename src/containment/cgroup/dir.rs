//! A leaf's directory, held open from its creation: every operation on it goes through a held
//! descriptor, never through its path.
//!
//! A path is resolved afresh on each use, so a mount over the leaf or its parent would redirect
//! it: `cgroup.kill` written into the mount kills nothing, an `rmdir` through it answers for the
//! mount, and an `ENOENT` from it says nothing about the leaf. A descriptor stays on the directory
//! it was opened on.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::Path;

use rustix::fs::{AtFlags, Mode, OFlags};

/// `FILEID_KERNFS`: the type of a kernfs node's file handle, whose 8 bytes are the node's id.
const FILEID_KERNFS: libc::c_int = 0xfe;

/// The cgroup id of the cgroup directory `dir` names: its kernfs node id, read from its file
/// handle. That carries all 64 bits on every architecture, where `stx_ino` carries only the low 32
/// on a 32-bit kernel. It is the id `PIDFD_GET_INFO` gives a member.
pub(crate) fn cgroup_id(dir: BorrowedFd<'_>) -> io::Result<u64> {
    /// `struct file_handle` with room for a kernfs handle.
    #[repr(C)]
    struct KernfsHandle {
        handle_bytes: libc::c_uint,
        handle_type: libc::c_int,
        f_handle: [u8; 8],
    }
    let mut handle = KernfsHandle {
        handle_bytes: 8,
        handle_type: 0,
        f_handle: [0; 8],
    };
    let mut mount_id: libc::c_int = 0;
    // SAFETY: `handle` is a `struct file_handle` whose `handle_bytes` is the room after its header,
    // and the path is an empty C string, which `AT_EMPTY_PATH` reads as `dir` itself.
    let rc = unsafe {
        libc::name_to_handle_at(
            dir.as_raw_fd(),
            c"".as_ptr(),
            (&raw mut handle).cast::<libc::file_handle>(),
            &mut mount_id,
            libc::AT_EMPTY_PATH,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    id_of_handle(handle.handle_type, handle.handle_bytes, handle.f_handle)
}

/// The cgroup id a file handle of `handle_type` and `handle_bytes` bytes carries in `bytes`, in
/// this machine's byte order (`kernfs_encode_fh`); an error for any other handle.
pub(crate) fn id_of_handle(handle_type: libc::c_int, handle_bytes: libc::c_uint, bytes: [u8; 8]) -> io::Result<u64> {
    if handle_type != FILEID_KERNFS || handle_bytes != 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("not a cgroup's file handle (type {handle_type:#x}, {handle_bytes} bytes)"),
        ));
    }
    Ok(u64::from_ne_bytes(bytes))
}

/// A leaf's directory and its parent, each held as an `O_PATH` descriptor.
pub(crate) struct LeafDir {
    parent: OwnedFd,
    /// Shared with the leaf's [`Subtree`](super::Subtree)s, which read it after the leaf is gone.
    dir: std::sync::Arc<OwnedFd>,
    /// The ids of the cgroups [`remove_children`](Self::remove_children) removed, shared with the
    /// leaf's [`Subtree`](super::Subtree)s: a task in one is in the subtree, which no walk can show
    /// once it is removed.
    swept: Swept,
    name: OsString,
}

impl LeafDir {
    /// Create the leaf `name` under `parent` and hold both.
    pub(crate) fn create(parent: &Path, name: &str) -> io::Result<LeafDir> {
        let parent = open_dir(rustix::fs::CWD, parent)?;
        rustix::fs::mkdirat(&parent, name, Mode::from_raw_mode(0o777))?;
        #[cfg(test)]
        let held = if super::fault::take_force_leaf_open_failure() {
            Err(io::Error::from_raw_os_error(libc::EMFILE))
        } else {
            open_dir(&parent, name)
        };
        #[cfg(not(test))]
        let held = open_dir(&parent, name);
        let dir = match held {
            Ok(dir) => dir,
            Err(e) => {
                // The directory it just made, still empty: nothing is placed in a leaf before it
                // is held.
                if let Err(rm) = rustix::fs::unlinkat(&parent, name, AtFlags::REMOVEDIR) {
                    log::warn!(
                        "cgroup leaf {name} was not removed: rmdir failed ({rm}) after it could not be opened \
                         ({e}); it stays on this host until a cgroup manager reaps it"
                    );
                }
                return Err(e);
            }
        };
        Ok(LeafDir {
            parent,
            dir: std::sync::Arc::new(dir),
            swept: Swept::default(),
            name: name.into(),
        })
    }

    /// Hold the existing directory at `path`, for a test that shapes a leaf with ordinary files.
    /// A path that does not exist gives a leaf already removed: every operation on it finds it
    /// gone.
    #[cfg(test)]
    pub(crate) fn open_for_test(path: &Path) -> LeafDir {
        let name = path.file_name().expect("a leaf path has a name").to_os_string();
        if path.exists() {
            let parent = open_dir(rustix::fs::CWD, path.parent().expect("a leaf path has a parent"))
                .expect("open the leaf's parent");
            let dir = open_dir(&parent, &name).expect("open the leaf");
            return LeafDir {
                parent,
                dir: std::sync::Arc::new(dir),
                swept: Swept::default(),
                name,
            };
        }
        let gone = tempfile::tempdir().expect("tempdir");
        let parent = open_dir(rustix::fs::CWD, gone.path()).expect("open a stand-in parent");
        rustix::fs::mkdirat(&parent, &name, Mode::from_raw_mode(0o777)).expect("make a stand-in leaf");
        let dir = open_dir(&parent, &name).expect("open the stand-in leaf");
        rustix::fs::unlinkat(&parent, &name, AtFlags::REMOVEDIR).expect("remove the stand-in leaf");
        LeafDir {
            parent,
            dir: std::sync::Arc::new(dir),
            swept: Swept::default(),
            name,
        }
    }

    /// The leaf's directory.
    pub(crate) fn dir(&self) -> BorrowedFd<'_> {
        self.dir.as_fd()
    }

    /// The leaf's directory, shared: it stays on the directory once the leaf is removed.
    pub(crate) fn shared(&self) -> std::sync::Arc<OwnedFd> {
        std::sync::Arc::clone(&self.dir)
    }

    /// The record of the cgroups the leaf's sweep removed (see [`Swept`]).
    pub(crate) fn swept(&self) -> Swept {
        self.swept.clone()
    }

    /// The leaf's parent directory.
    pub(crate) fn parent(&self) -> BorrowedFd<'_> {
        self.parent.as_fd()
    }

    /// The leaf's name in its parent.
    pub(crate) fn name(&self) -> &OsStr {
        &self.name
    }

    /// Open the leaf's interface file `file`, close-on-exec.
    pub(crate) fn open(&self, file: &str, flags: OFlags) -> io::Result<OwnedFd> {
        Ok(rustix::fs::openat(
            &self.dir,
            file,
            flags | OFlags::CLOEXEC,
            Mode::empty(),
        )?)
    }

    /// Read the leaf's interface file `file`.
    pub(crate) fn read(&self, file: &str) -> io::Result<String> {
        io::read_to_string(std::fs::File::from(self.open(file, OFlags::RDONLY)?))
    }

    /// Write `bytes` to the leaf's interface file `file`, as `fs::write` does. A removed leaf
    /// answers `ENOENT`: nothing is created in a dead directory.
    pub(crate) fn write(&self, file: &str, bytes: &[u8]) -> io::Result<()> {
        use std::io::Write as _;
        let fd = rustix::fs::openat(
            &self.dir,
            file,
            OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o666),
        )?;
        std::fs::File::from(fd).write_all(bytes)
    }

    /// `rmdir` the leaf from its parent. `Ok` only once it removed the leaf; `ENOENT` if the leaf
    /// is gone, removed by another party; any other error leaves the leaf in place.
    ///
    /// `unlinkat` goes by name, so the name is first looked up on the parent's own mount, and
    /// removed only if it leads to the held leaf. A mount on the name is `EBUSY`, as `rmdir` of a
    /// mount point is. A name leading elsewhere, or nowhere, is `ENOENT` if the held leaf is gone,
    /// and an error otherwise.
    ///
    /// The lookup and the `unlinkat` are two steps, and nothing removes a directory through a
    /// descriptor. The random part of the leaf's name ([`leaf_name`](super::leaf_name)) keeps the
    /// name from recurring by accident; a party with write access to the delegated parent can
    /// still remove the leaf and make another under its name between the two, and have that
    /// removed instead. Such a party already controls the subtree.
    pub(crate) fn rmdir(&self) -> io::Result<()> {
        use rustix::io::Errno;

        let named = open_beneath(self.parent.as_fd(), &self.name);
        let ours = match named {
            Ok(named) => {
                let (named, held) = (rustix::fs::fstat(&named)?, rustix::fs::fstat(&self.dir)?);
                (named.st_dev, named.st_ino) == (held.st_dev, held.st_ino)
            }
            Err(Errno::XDEV) => return Err(io::Error::from_raw_os_error(libc::EBUSY)),
            // Nothing there, a symlink, or not a directory: not the leaf.
            Err(Errno::NOENT | Errno::LOOP | Errno::NOTDIR) => false,
            Err(e) => return Err(e.into()),
        };
        if !ours {
            return Err(match self.open("cgroup.events", OFlags::PATH) {
                Err(e) if super::removed_after_drain(&e) => io::Error::from_raw_os_error(libc::ENOENT),
                Err(e) => e,
                Ok(_) => io::Error::other(format!(
                    "{} no longer names the leaf, which is still there",
                    self.name.to_string_lossy()
                )),
            });
        }
        Ok(rustix::fs::unlinkat(&self.parent, &self.name, AtFlags::REMOVEDIR)?)
    }

    /// The leaf's cgroup id (see [`cgroup_id`]).
    pub(crate) fn id(&self) -> io::Result<u64> {
        cgroup_id(self.dir.as_fd())
    }

    /// Remove every child cgroup of the leaf, deepest first, and count those removed. A child that
    /// `rmdir` refuses as busy — something re-entered it — is left for the caller's next kill. A
    /// directory already gone has nothing left to remove.
    pub(crate) fn remove_children(&self) -> io::Result<usize> {
        remove_children(self.dir.as_fd(), &self.swept)
    }
}

/// The ids of the cgroups a leaf's sweep removed, shared by the leaf and its subtrees. Holds one
/// id per cgroup the leaf's tree made, so as many as that tree made.
#[derive(Debug, Clone, Default)]
pub(crate) struct Swept(std::sync::Arc<std::sync::Mutex<Vec<u64>>>);

impl Swept {
    fn record(&self, id: u64) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(id);
    }

    /// Whether the sweep removed the cgroup `id`.
    pub(crate) fn holds(&self, id: u64) -> bool {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&id)
    }
}

/// What a walk of the cgroups under a leaf found of one cgroup id (see [`find_descendant`]).
#[derive(Debug)]
pub(crate) enum Walked {
    /// A cgroup under the leaf has the id.
    Found,
    /// No cgroup the walk could list has it, and it could list every one that it found: none was
    /// behind a mount. A cgroup removed during the walk is not listed, and is not one the walk
    /// could list.
    Absent,
    /// The walk could not list every cgroup, or its root is gone: why.
    Unknown(io::Error),
}

/// Whether a cgroup under `dir`, not `dir` itself, has the cgroup id `id` (see [`cgroup_id`]).
///
/// A [`traverse`] of the tree: the walk holds two descriptors at most, however large or deep the
/// tree. A cgroup removed during the walk (`ENOENT`, or `ENODEV` from a removed directory's files)
/// has nothing under it to find, and is skipped; `dir` itself removed lists nothing, and answers
/// [`Walked::Unknown`]. A cgroup behind a mount (`EXDEV`) cannot be listed, so a walk that meets
/// one answers [`Walked::Unknown`] if it finds nothing, as it does for any other failure: a cgroup
/// this process may not read (`EACCES`), or any other refusal, `ENAMETOOLONG` included, though a
/// path from `dir` longer than `PATH_MAX` is not one: it is opened in pieces (see [`open_cgroup`]).
///
/// One `openat2`, `name_to_handle_at`, `openat` and `getdents` per cgroup. Bounded: the tree is
/// finite and each cgroup is visited once, since cgroup v2 refuses to rename or move one; it is
/// sized by the cgroups the contained program made.
pub(crate) fn find_descendant(dir: BorrowedFd<'_>, id: u64) -> Walked {
    match walk(dir, id) {
        Ok(Some(())) => Walked::Found,
        Ok(None) => Walked::Absent,
        Err(e) => Walked::Unknown(e),
    }
}

/// [`find_descendant`]'s walk: `Some` once found, `None` once every cgroup was listed.
fn walk(dir: BorrowedFd<'_>, id: u64) -> io::Result<Option<()>> {
    let traversed = traverse(&mut Tree::new(), dir, true, |tree, node, cgroup| {
        match step_fault(tree, node, WalkStep::Id)
            .map_err(io::Error::from)
            .and_then(|()| cgroup_id(cgroup))
        {
            Ok(found) if found == id => Ok(Visit::Stop),
            Ok(_) => Ok(Visit::Continue),
            Err(e) if gone_io(&e) => Ok(Visit::Skip),
            Err(e) => Err(io::Error::new(e.kind(), format!("{}: {e}", tree.path(node).display()))),
        }
    })
    .map_err(Failure::into_error)?;
    match traversed {
        Traversed::Stopped => Ok(Some(())),
        Traversed::Listed { behind_a_mount: None } => Ok(None),
        Traversed::Listed {
            behind_a_mount: Some(path),
        } => Err(io::Error::other(format!(
            "{} is behind a mount, so the cgroups under it cannot be listed",
            path.display()
        ))),
    }
}

/// What a visitor of [`traverse`] decides of the cgroup it was shown.
enum Visit {
    /// List the cgroup, and visit what is under it.
    Continue,
    /// The cgroup is gone: nothing is under it to visit.
    Skip,
    /// End the traversal.
    Stop,
}

/// How a [`traverse`] that did not fail ended.
enum Traversed {
    /// A visitor said [`Visit::Stop`].
    Stopped,
    /// Every cgroup that could be listed was; `behind_a_mount` is the path of the first that could
    /// not be, being behind a mount.
    Listed { behind_a_mount: Option<std::path::PathBuf> },
}

/// Why a [`traverse`] failed.
enum Failure {
    /// The root is gone, so nothing of what was under it was listed.
    RootGone(io::Error),
    /// Anything else, a visitor's error included.
    Other(io::Error),
}

impl Failure {
    fn into_error(self) -> io::Error {
        match self {
            Failure::RootGone(e) | Failure::Other(e) => e,
        }
    }
}

/// The cgroups a traversal found, each as its name and its parent: a name is stored once, however
/// deep the cgroup under it, so the tree costs the bytes of its names and no more. A cgroup's path
/// is rebuilt only where it is used, to open it. Node 0 is the root, the cgroup the traversal
/// started at.
struct Tree {
    nodes: Vec<Node>,
}

struct Node {
    parent: usize,
    name: std::ffi::OsString,
}

impl Tree {
    const ROOT: usize = 0;

    fn new() -> Tree {
        Tree {
            nodes: vec![Node {
                parent: Self::ROOT,
                name: std::ffi::OsString::new(),
            }],
        }
    }

    /// Add the cgroup `name` under `parent`.
    fn push(&mut self, parent: usize, name: &OsStr) -> usize {
        self.nodes.push(Node {
            parent,
            name: name.to_owned(),
        });
        self.nodes.len() - 1
    }

    fn parent(&self, node: usize) -> usize {
        self.nodes[node].parent
    }

    /// The name of a cgroup other than the root.
    fn name(&self, node: usize) -> &OsStr {
        debug_assert_ne!(node, Self::ROOT, "the root has no name");
        &self.nodes[node].name
    }

    /// The names from the root down to `node`, the root's own left out.
    fn names(&self, node: usize) -> Vec<&OsStr> {
        let mut names = Vec::new();
        let mut at = node;
        while at != Self::ROOT {
            names.push(self.name(at));
            at = self.parent(at);
        }
        names.reverse();
        names
    }

    /// `node`'s path from the root, `.` for the root itself: for messages and test seams, never
    /// for an open (see [`open_cgroup`]).
    fn path(&self, node: usize) -> std::path::PathBuf {
        let mut path = std::path::PathBuf::from(".");
        path.extend(self.names(node));
        path
    }

    /// The bytes of the names stored.
    #[cfg(test)]
    fn stored_bytes(&self) -> usize {
        self.nodes.iter().map(|n| n.name.len()).sum()
    }
}

/// Visit each cgroup under `dir`, not `dir` itself, once, breadth first, so a cgroup comes before
/// the ones under it. The one traversal of a leaf's tree: the walk and the sweep both run on it.
/// The cgroups found are left in `tree`.
///
/// Each cgroup is opened from `dir` by its path relative to it, with [`open_cgroup`], shown to
/// `visit` by its node and descriptor, listed, and closed before the next: two descriptors at most
/// are held, however large or deep the tree, where holding the cgroups on the way down would hold
/// one per level. What remains to visit is node numbers in memory, sized by the tree.
///
/// A cgroup gone (`ENOENT`, or `ENODEV` from a removed directory's files) is skipped, as is one
/// behind a mount (`EXDEV`), which cannot be listed and is remembered. `dir` itself gone is
/// [`Failure::RootGone`]. `confirm_root` reads a file of `dir` after listing it, which a removed
/// directory answers `ENODEV` to: it lists as empty, which says nothing of the cgroups that were
/// under it.
fn traverse(
    tree: &mut Tree,
    dir: BorrowedFd<'_>,
    confirm_root: bool,
    mut visit: impl FnMut(&Tree, usize, BorrowedFd<'_>) -> io::Result<Visit>,
) -> Result<Traversed, Failure> {
    use std::collections::VecDeque;
    use std::os::unix::ffi::OsStrExt as _;

    debug_assert_eq!(tree.nodes.len(), 1, "a traversal starts from a tree of its root alone");
    // Each cgroup still to look at; `dir` itself first.
    let mut pending: VecDeque<usize> = VecDeque::from([Tree::ROOT]);
    let mut behind_a_mount = None;
    while let Some(node) = pending.pop_front() {
        #[cfg(test)]
        super::fault::run_before_walk_open(&tree.path(node));
        // A cgroup under `dir` that is gone has nothing under it to visit; `dir` gone is a failure.
        let is_root = node == Tree::ROOT;
        let skippable = |e: rustix::io::Errno| gone(e) && !is_root;
        let failed = |tree: &Tree, e: rustix::io::Errno| {
            if is_root && gone(e) {
                Failure::RootGone(named(e, tree, node))
            } else {
                Failure::Other(named(e, tree, node))
            }
        };
        let cgroup = match step_fault(tree, node, WalkStep::Open).and_then(|()| open_cgroup(dir, &tree.names(node))) {
            Ok(cgroup) => cgroup,
            Err(e) if skippable(e) => continue,
            Err(rustix::io::Errno::XDEV) => {
                behind_a_mount.get_or_insert_with(|| tree.path(node));
                continue;
            }
            Err(e) => return Err(failed(tree, e)),
        };
        if !is_root {
            match visit(tree, node, cgroup.as_fd()).map_err(Failure::Other)? {
                Visit::Continue => {}
                Visit::Skip => continue,
                Visit::Stop => return Ok(Traversed::Stopped),
            }
        }
        // Listing needs a readable descriptor; `cgroup` is `O_PATH`.
        let listing = match step_fault(tree, node, WalkStep::List).and_then(|()| {
            rustix::fs::openat(
                &cgroup,
                ".",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
        }) {
            Ok(listing) => listing,
            Err(e) if skippable(e) => continue,
            Err(e) => return Err(failed(tree, e)),
        };
        let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); LISTING_BUFFER];
        let mut entries = rustix::fs::RawDir::new(&listing, &mut buf);
        let mut first = true;
        while let Some(entry) = entries.next() {
            let entry = if std::mem::take(&mut first) {
                step_fault(tree, node, WalkStep::Entries).and(entry)
            } else {
                entry
            };
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) if skippable(e) => break,
                Err(e) => return Err(failed(tree, e)),
            };
            let name = entry.file_name();
            if !matches!(name.to_bytes(), b"." | b"..")
                && is_dir(cgroup.as_fd(), entry.file_type(), name).map_err(Failure::Other)?
            {
                pending.push_back(tree.push(node, OsStr::from_bytes(name.to_bytes())));
            }
        }
        // A removed `dir` still lists, as nothing: read one of its files, after the listing, which
        // a removal during it then cannot have cut short unseen.
        if is_root && confirm_root {
            step_fault(tree, node, WalkStep::Alive)
                .and_then(|()| {
                    rustix::fs::openat(&cgroup, "cgroup.events", OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
                })
                .map_err(|e| failed(tree, e))?;
        }
    }
    Ok(Traversed::Listed { behind_a_mount })
}

/// A step of the walk at one cgroup, as a test makes it fail (see `fault::fail_walk_step`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WalkStep {
    /// The `openat2` of the cgroup's path.
    Open,
    /// The read of the cgroup's id.
    Id,
    /// The `openat` of the cgroup for listing.
    List,
    /// The `getdents` of the listing.
    Entries,
    /// The read, after the listing of the walk's root, that shows it was not removed.
    Alive,
}

/// What a test made `step` of the walk at the cgroup `node` of `tree` fail with, or `Ok`.
fn step_fault(tree: &Tree, node: usize, step: WalkStep) -> rustix::io::Result<()> {
    #[cfg(test)]
    if let Some(errno) = super::fault::walk_step_failure(&tree.path(node), step) {
        return Err(rustix::io::Errno::from_raw_os_error(errno));
    }
    let _ = (tree, node, step);
    Ok(())
}

/// `errno` from the walk at the cgroup `node` of `tree`, named by its path from the leaf.
fn named(errno: rustix::io::Errno, tree: &Tree, node: usize) -> io::Error {
    let e = io::Error::from(errno);
    let at = if node == Tree::ROOT {
        "the root of the walk".to_owned()
    } else {
        tree.path(node).display().to_string()
    };
    io::Error::new(e.kind(), format!("{at}: {e}"))
}

/// The bytes a listing reads at once. One entry takes at most the header and a name of `PATH_MAX - 1`
/// bytes, which a program in the tree can make; `rustix::fs::Dir` starts with 768 and does not grow
/// past an entry that is larger, so it fails on a name of about 750 bytes.
const LISTING_BUFFER: usize = 8192;

/// The longest path `openat2` takes, without its NUL.
const PATH_MAX_BYTES: usize = libc::PATH_MAX as usize - 1;

/// Split `names` into runs whose `/`-joined paths are each at most `max` bytes, as long as they
/// can be: a name longer than `max` is a run of its own, which no open will take.
fn pieces(names: &[&OsStr], max: usize) -> Vec<std::ops::Range<usize>> {
    let mut runs = Vec::new();
    let (mut start, mut len) = (0, 0);
    for (i, name) in names.iter().enumerate() {
        let joined = len + usize::from(i > start) + name.len();
        if i > start && joined > max {
            runs.push(start..i);
            (start, len) = (i, name.len());
        } else {
            len = joined;
        }
    }
    if start < names.len() {
        runs.push(start..names.len());
    }
    runs
}

/// Open the cgroup that `names` lead to under `dir`, however long their path: [`open_beneath`] in
/// pieces (see [`pieces`]), each from the one before it, so that no path the kernel is given is
/// too long. Each piece is opened with every guard [`open_beneath`] has, and the one before it is
/// closed as the next is opened: two descriptors at most are held, however long the path is. No
/// names is `dir` itself.
fn open_cgroup(dir: BorrowedFd<'_>, names: &[&OsStr]) -> rustix::io::Result<OwnedFd> {
    use std::os::unix::ffi::OsStrExt as _;

    debug_assert!(
        names.iter().all(|n| {
            let mut parts = std::path::Path::new(n).components();
            matches!(parts.next(), Some(std::path::Component::Normal(_))) && parts.next().is_none()
        }),
        "every name is one plain path component: {names:?}"
    );
    let mut held: Option<OwnedFd> = None;
    for run in pieces(names, PATH_MAX_BYTES) {
        let mut piece = names[run.start].as_bytes().to_vec();
        for name in &names[run.start + 1..run.end] {
            piece.push(b'/');
            piece.extend_from_slice(name.as_bytes());
        }
        let opened = open_beneath(held.as_ref().map_or(dir, AsFd::as_fd), OsStr::from_bytes(&piece))?;
        held = Some(opened);
    }
    match held {
        Some(held) => Ok(held),
        None => open_beneath(dir, "."),
    }
}

/// Open the directory at `path` under `dir`, never across a mount or a symlink, nor out of `dir`,
/// as an `O_PATH` descriptor above stdio.
fn open_beneath(dir: BorrowedFd<'_>, path: impl rustix::path::Arg) -> rustix::io::Result<OwnedFd> {
    use rustix::fs::ResolveFlags;

    let fd = rustix::fs::openat2(
        dir,
        path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_XDEV | ResolveFlags::NO_SYMLINKS | ResolveFlags::BENEATH,
    )?;
    above_stdio(fd).map_err(|e| rustix::io::Errno::from_io_error(&e).unwrap_or(rustix::io::Errno::IO))
}

/// Whether `e` says a cgroup is gone: removed, or listed from a removed directory.
fn gone(e: rustix::io::Errno) -> bool {
    matches!(e, rustix::io::Errno::NOENT | rustix::io::Errno::NODEV)
}

/// [`gone`], for an error that carries an `errno`.
fn gone_io(e: &io::Error) -> bool {
    e.raw_os_error()
        .is_some_and(|errno| gone(rustix::io::Errno::from_raw_os_error(errno)))
}

/// Whether the entry `name` of type `file_type`, listed in `at`, is a directory: a cgroup's own interface files are files, and
/// its child cgroups are its directories. One gone since is not.
fn is_dir(at: BorrowedFd<'_>, file_type: rustix::fs::FileType, name: &std::ffi::CStr) -> io::Result<bool> {
    Ok(match file_type {
        rustix::fs::FileType::Directory => true,
        rustix::fs::FileType::Unknown => match rustix::fs::statat(at, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => rustix::fs::FileType::from_raw_mode(st.st_mode) == rustix::fs::FileType::Directory,
            Err(e) if gone(e) => false,
            Err(e) => return Err(e.into()),
        },
        _ => false,
    })
}

/// A path through which a watch or an open reaches `fd`'s own inode, whatever is mounted over its
/// path since. `thread-self`, not `self`: after `unshare(CLONE_FILES)` a thread has its own
/// descriptor table, and `/proc/self/fd` shows the thread-group leader's.
pub(crate) fn fd_path(fd: BorrowedFd<'_>) -> String {
    format!("/proc/thread-self/fd/{}", fd.as_raw_fd())
}

fn open_dir(at: impl AsFd, path: impl rustix::path::Arg) -> io::Result<OwnedFd> {
    above_stdio(rustix::fs::openat(
        at,
        path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

pub(crate) use crate::above_stdio::above_stdio;

/// Remove every cgroup under `dir`, deepest first, and count those removed.
///
/// A [`traverse`] lists the tree and the id of each cgroup in it, then each is removed from its
/// parent, opened by its path as the traversal opened it, in the reverse of the order it was
/// visited in: a cgroup is visited before the ones under it, so it is removed after them. One
/// descriptor is held at a time.
fn remove_children(dir: BorrowedFd<'_>, swept: &Swept) -> io::Result<usize> {
    // Each cgroup found, with the id the sweep records of it if it removes it. One whose id cannot
    // be read leaves no record, and is removed all the same: a leaf left behind for it would leak a
    // cgroup (on a kernel without `CONFIG_FHANDLE`, every leaf), while a task in a cgroup removed
    // unrecorded is still placed by its `/proc` path, or not at all, never wrongly.
    let mut found: Vec<(usize, Option<u64>)> = Vec::new();
    let mut tree = Tree::new();
    let traversed = traverse(&mut tree, dir, false, |tree, node, cgroup| {
        let id = match cgroup_id(cgroup) {
            Ok(id) => Some(id),
            // A cgroup gone since it was opened has nothing to record.
            Err(e) if gone_io(&e) => return Ok(Visit::Skip),
            Err(e) => {
                log::debug!(
                    "cgroup v2: the id of child cgroup {} cannot be read ({e}); it is removed unrecorded",
                    tree.name(node).to_string_lossy()
                );
                None
            }
        };
        found.push((node, id));
        Ok(Visit::Continue)
    });
    // What was found is removed even if the traversal failed part-way: the rest is left for the
    // caller's next kill, as a cgroup `rmdir` refuses as busy is.
    let mut removed = 0;
    for &(node, id) in found.iter().rev() {
        // Never across a mount: a mount on a cgroup shows some other directory, whose contents are
        // not the leaf's to remove. `EXDEV` says the path leads onto one.
        let parent = match open_cgroup(dir, &tree.names(tree.parent(node))) {
            Ok(parent) => parent,
            Err(e) if gone(e) || e == rustix::io::Errno::XDEV => continue,
            Err(e) => return Err(e.into()),
        };
        // `parent` was reached without crossing a mount, so this removes a directory entry of the
        // leaf's own filesystem; one mounted on since is refused `EBUSY`, not followed.
        match rustix::fs::unlinkat(&parent, tree.name(node), AtFlags::REMOVEDIR) {
            Ok(()) => {
                removed += 1;
                // The name may lead to another cgroup since the id was read, if someone removed
                // that one and made this; both were under the leaf, so the id is of one that was.
                if let Some(id) = id {
                    swept.record(id);
                }
            }
            Err(e) if gone(e) || e == rustix::io::Errno::BUSY => {}
            Err(e) => return Err(e.into()),
        }
    }
    match traversed {
        Ok(_) => Ok(removed),
        // A leaf already gone has nothing left to remove.
        Err(Failure::RootGone(_)) => Ok(removed),
        Err(Failure::Other(e)) => Err(e),
    }
}

#[cfg(test)]
#[path = "dir_tests.rs"]
mod dir_tests;

#[cfg(test)]
#[path = "dir_walk_tests.rs"]
pub(crate) mod dir_walk_tests;

#[cfg(test)]
#[path = "dir_sweep_tests.rs"]
mod dir_sweep_tests;

#[cfg(test)]
#[path = "dir_pieces_tests.rs"]
mod dir_pieces_tests;
