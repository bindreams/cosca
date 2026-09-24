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

/// A leaf's directory and its parent, each held as an `O_PATH` descriptor.
pub(crate) struct LeafDir {
    parent: OwnedFd,
    dir: OwnedFd,
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
            dir,
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
            return LeafDir { parent, dir, name };
        }
        let gone = tempfile::tempdir().expect("tempdir");
        let parent = open_dir(rustix::fs::CWD, gone.path()).expect("open a stand-in parent");
        rustix::fs::mkdirat(&parent, &name, Mode::from_raw_mode(0o777)).expect("make a stand-in leaf");
        let dir = open_dir(&parent, &name).expect("open the stand-in leaf");
        rustix::fs::unlinkat(&parent, &name, AtFlags::REMOVEDIR).expect("remove the stand-in leaf");
        LeafDir { parent, dir, name }
    }

    /// The leaf's directory.
    pub(crate) fn dir(&self) -> BorrowedFd<'_> {
        self.dir.as_fd()
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

    /// `rmdir` the leaf from its parent, if its name still names it. `unlinkat` goes by name, so
    /// the name's inode is checked against the held leaf's first; if they differ, the leaf is
    /// already gone and whatever holds its name is left alone. A random part in every leaf name
    /// ([`leaf_name`](super::leaf_name)) keeps anyone else from taking the name in between.
    pub(crate) fn rmdir(&self) -> io::Result<()> {
        let held = rustix::fs::fstat(&self.dir)?;
        let named = rustix::fs::statat(&self.parent, &self.name, AtFlags::SYMLINK_NOFOLLOW)?;
        if (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino) {
            return Ok(());
        }
        Ok(rustix::fs::unlinkat(&self.parent, &self.name, AtFlags::REMOVEDIR)?)
    }

    /// Remove every child cgroup of the leaf, deepest first, and count those removed. A child that
    /// `rmdir` refuses as busy — something re-entered it — is left for the caller's next kill. A
    /// directory already gone has nothing left to remove.
    pub(crate) fn remove_children(&self) -> io::Result<usize> {
        remove_children(self.dir.as_fd())
    }
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

/// `fd`, moved to 3 or above, close-on-exec. A descriptor the leaf holds for the child's lifetime
/// must not share its number with a closed stdio slot: std `dup2`s the child's stdio into those
/// slots, and an inherited slot left pointing at the leaf would hand the child a cgroup
/// directory, or a watch, for its stdin.
pub(crate) fn above_stdio(fd: OwnedFd) -> io::Result<OwnedFd> {
    if fd.as_raw_fd() >= 3 {
        return Ok(fd);
    }
    Ok(rustix::io::fcntl_dupfd_cloexec(&fd, 3)?)
}

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

fn remove_children(dir: BorrowedFd<'_>) -> io::Result<usize> {
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
        removed += remove_children(child.as_fd())?;
        // `dir` was reached without crossing a mount, so this removes a directory entry of the
        // leaf's own filesystem; one mounted on since is refused `EBUSY`, not followed.
        match rustix::fs::unlinkat(dir, name, AtFlags::REMOVEDIR) {
            Ok(()) => removed += 1,
            Err(e) if gone(e) || e == rustix::io::Errno::BUSY => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(removed)
}

#[cfg(test)]
#[path = "dir_tests.rs"]
mod dir_tests;
