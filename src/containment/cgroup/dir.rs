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
        use rustix::fs::ResolveFlags;
        use rustix::io::Errno;

        let named = rustix::fs::openat2(
            &self.parent,
            &self.name,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_XDEV | ResolveFlags::NO_SYMLINKS | ResolveFlags::BENEATH,
        );
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
/// Breadth first, each cgroup opened from `dir` by its path relative to it, with `openat2`
/// (`RESOLVE_BENEATH | RESOLVE_NO_XDEV | RESOLVE_NO_SYMLINKS`), read, and closed before the next:
/// the walk holds two descriptors at most, however large the tree. A cgroup removed during the walk
/// (`ENOENT`, or `ENODEV` from a removed directory's files) has nothing under it to find, and is
/// skipped; `dir` itself removed lists nothing, and answers [`Walked::Unknown`]. A cgroup behind a
/// mount (`EXDEV`) cannot be listed, so a walk that meets one answers [`Walked::Unknown`] if it
/// finds nothing, as it does for any other failure: a cgroup this process may not read (`EACCES`),
/// or one whose path from the leaf is longer than `PATH_MAX` (`ENAMETOOLONG`).
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
    use std::collections::VecDeque;
    use std::os::unix::ffi::OsStrExt as _;

    let gone = |e: rustix::io::Errno| matches!(e, rustix::io::Errno::NOENT | rustix::io::Errno::NODEV);
    // Each cgroup still to look at, by its path relative to `dir`; `dir` itself first.
    let mut pending: VecDeque<std::path::PathBuf> = VecDeque::from([std::path::PathBuf::from(".")]);
    let mut behind_a_mount = None;
    while let Some(path) = pending.pop_front() {
        #[cfg(test)]
        super::fault::run_before_walk_open(&path);
        // A cgroup under `dir` that is gone has nothing under it to find. `dir` itself gone lists
        // nothing, which says nothing of the cgroups that were under it.
        let is_root = path.as_os_str() == ".";
        let skippable = |e: rustix::io::Errno| gone(e) && !is_root;
        let cgroup = match step_fault(&path, WalkStep::Open).and_then(|()| open_beneath(dir, &path)) {
            Ok(cgroup) => cgroup,
            Err(e) if skippable(e) => continue,
            Err(rustix::io::Errno::XDEV) => {
                behind_a_mount.get_or_insert(path);
                continue;
            }
            Err(e) => return Err(named(e, &path)),
        };
        if !is_root {
            match step_fault(&path, WalkStep::Id)
                .map_err(io::Error::from)
                .and_then(|()| cgroup_id(cgroup.as_fd()))
            {
                Ok(found) if found == id => return Ok(Some(())),
                Ok(_) => {}
                Err(e)
                    if e.raw_os_error()
                        .is_some_and(|errno| gone(rustix::io::Errno::from_raw_os_error(errno))) =>
                {
                    continue
                }
                Err(e) => return Err(io::Error::new(e.kind(), format!("{}: {e}", path.display()))),
            }
        }
        // Listing needs a readable descriptor; `cgroup` is `O_PATH`.
        let entries = match step_fault(&path, WalkStep::List)
            .and_then(|()| {
                rustix::fs::openat(
                    &cgroup,
                    ".",
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
            })
            .and_then(rustix::fs::Dir::new)
        {
            Ok(entries) => entries,
            Err(e) if skippable(e) => continue,
            Err(e) => return Err(named(e, &path)),
        };
        let mut first = true;
        for entry in entries {
            let entry = if std::mem::take(&mut first) {
                step_fault(&path, WalkStep::Entries).and(entry)
            } else {
                entry
            };
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) if skippable(e) => break,
                Err(e) => return Err(named(e, &path)),
            };
            let name = entry.file_name();
            if !matches!(name.to_bytes(), b"." | b"..") && is_dir(cgroup.as_fd(), &entry)? {
                pending.push_back(path.join(std::ffi::OsStr::from_bytes(name.to_bytes())));
            }
        }
        // A removed `dir` still lists, as nothing: its files answer `ENODEV`, so read one, after the
        // listing, which a removal during it then cannot have cut short unseen.
        if is_root {
            step_fault(&path, WalkStep::Alive)
                .and_then(|()| {
                    rustix::fs::openat(&cgroup, "cgroup.events", OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
                })
                .map_err(|e| named(e, &path))?;
        }
    }
    match behind_a_mount {
        Some(path) => Err(io::Error::other(format!(
            "{} is behind a mount, so the cgroups under it cannot be listed",
            path.display()
        ))),
        None => Ok(None),
    }
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

/// What a test made `step` of the walk at `path` fail with, or `Ok`.
fn step_fault(path: &std::path::Path, step: WalkStep) -> rustix::io::Result<()> {
    #[cfg(test)]
    if let Some(errno) = super::fault::walk_step_failure(path, step) {
        return Err(rustix::io::Errno::from_raw_os_error(errno));
    }
    let _ = (path, step);
    Ok(())
}

/// `errno` from the walk at `path`, relative to the leaf.
fn named(errno: rustix::io::Errno, path: &std::path::Path) -> io::Error {
    let e = io::Error::from(errno);
    let at = if path.as_os_str() == "." {
        "the root of the walk".to_owned()
    } else {
        path.display().to_string()
    };
    io::Error::new(e.kind(), format!("{at}: {e}"))
}

/// Open the directory at `path` under `dir`, never across a mount or a symlink, nor out of `dir`.
fn open_beneath(dir: BorrowedFd<'_>, path: &std::path::Path) -> rustix::io::Result<OwnedFd> {
    use rustix::fs::ResolveFlags;

    rustix::fs::openat2(
        dir,
        path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_XDEV | ResolveFlags::NO_SYMLINKS | ResolveFlags::BENEATH,
    )
}

/// Whether `entry`, listed in `at`, is a directory: a cgroup's own interface files are files, and
/// its child cgroups are its directories. One gone since is not.
fn is_dir(at: BorrowedFd<'_>, entry: &rustix::fs::DirEntry) -> io::Result<bool> {
    Ok(match entry.file_type() {
        rustix::fs::FileType::Directory => true,
        rustix::fs::FileType::Unknown => match rustix::fs::statat(at, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => rustix::fs::FileType::from_raw_mode(st.st_mode) == rustix::fs::FileType::Directory,
            Err(rustix::io::Errno::NOENT | rustix::io::Errno::NODEV) => false,
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

/// Open `name` in `dir` as a directory, refusing to cross a mount or follow a symlink on the way.
fn open_child_on_this_mount(dir: BorrowedFd<'_>, name: &std::ffi::CStr) -> rustix::io::Result<OwnedFd> {
    use rustix::fs::ResolveFlags;

    let fd = rustix::fs::openat2(
        dir,
        name,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_XDEV | ResolveFlags::NO_SYMLINKS | ResolveFlags::BENEATH,
    )?;
    above_stdio(fd).map_err(|e| rustix::io::Errno::from_io_error(&e).unwrap_or(rustix::io::Errno::IO))
}

fn remove_children(dir: BorrowedFd<'_>, swept: &Swept) -> io::Result<usize> {
    let gone = |e: rustix::io::Errno| matches!(e, rustix::io::Errno::NOENT | rustix::io::Errno::NODEV);
    // Listing needs a readable descriptor; the held one is `O_PATH`.
    let listing = rustix::fs::openat(
        dir,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .and_then(rustix::fs::Dir::new);
    let entries = match listing {
        Ok(entries) => entries,
        Err(e) if gone(e) => return Ok(0),
        Err(e) => return Err(e.into()),
    };
    let mut removed = 0;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) if gone(e) => return Ok(removed),
            Err(e) => return Err(e.into()),
        };
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        // A cgroup's own interface files are files; its child cgroups are its directories.
        let is_dir = match entry.file_type() {
            rustix::fs::FileType::Directory => true,
            rustix::fs::FileType::Unknown => match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(st) => rustix::fs::FileType::from_raw_mode(st.st_mode) == rustix::fs::FileType::Directory,
                Err(e) if gone(e) => false,
                Err(e) => return Err(e.into()),
            },
            _ => false,
        };
        if !is_dir {
            continue;
        }
        // Never across a mount: a mount on a child cgroup shows some other directory, whose
        // contents are not the leaf's to remove. `EXDEV` says the name leads onto one.
        let child = match open_child_on_this_mount(dir, name) {
            Ok(child) => child,
            Err(e) if gone(e) || e == rustix::io::Errno::XDEV => continue,
            Err(e) => return Err(e.into()),
        };
        // The id is what the sweep records of a cgroup it removes. One that cannot be read leaves no
        // record, and the cgroup is removed all the same: a leaf left behind for it would leak a
        // cgroup (on a kernel without `CONFIG_FHANDLE`, every leaf), while a task in a cgroup
        // removed unrecorded is still placed by its `/proc` path, or not at all, never wrongly.
        // A cgroup gone since it was opened has nothing to record.
        let child_id = match cgroup_id(child.as_fd()) {
            Ok(id) => Some(id),
            Err(e)
                if e.raw_os_error()
                    .is_some_and(|errno| gone(rustix::io::Errno::from_raw_os_error(errno))) =>
            {
                continue
            }
            Err(e) => {
                log::debug!(
                    "cgroup v2: the id of child cgroup {} cannot be read ({e}); it is removed unrecorded",
                    name.to_string_lossy()
                );
                None
            }
        };
        removed += remove_children(child.as_fd(), swept)?;
        // `dir` was reached without crossing a mount, so this removes a directory entry of the
        // leaf's own filesystem; one mounted on since is refused `EBUSY`, not followed.
        match rustix::fs::unlinkat(dir, name, AtFlags::REMOVEDIR) {
            Ok(()) => {
                removed += 1;
                // The name may lead to another cgroup since `child` was opened, if someone removed
                // that one and made this; both were under the leaf, so the id is of one that was.
                if let Some(child_id) = child_id {
                    swept.record(child_id);
                }
            }
            Err(e) if gone(e) || e == rustix::io::Errno::BUSY => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(removed)
}

#[cfg(test)]
#[path = "dir_tests.rs"]
mod dir_tests;

#[cfg(test)]
#[path = "dir_walk_tests.rs"]
pub(crate) mod dir_walk_tests;
