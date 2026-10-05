//! The private directory that holds the shim's socket: a directory made `0700` (whatever the
//! umask says) with a random name in a temp directory no other user can tamper with, removed
//! through file descriptors.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

use rustix::fs::{fchmod, fstat, mkdirat, openat, statat, unlinkat, AtFlags, FileType, Mode, OFlags, Stat, CWD};
use rustix::io::Errno;

use super::fork_guard::{ForkGuard, Origin};

mod facts;

use facts::{check_dir, check_facts, DirFacts, FsOverride, Unfit};

/// The length of the directory's name, `cosca-` and 16 hex digits: a caller can tell how long a path
/// into the directory will be before it creates one.
pub(crate) const NAME_LEN: usize = 22;

#[derive(Debug, thiserror::Error)]
pub(crate) enum PrivateDirError {
    #[error("the temp directory {} is not an absolute path", .0.display())]
    TmpdirNotAbsolute(PathBuf),
    #[error("the temp directory {}: {source}", path.display())]
    Tmpdir { path: PathBuf, source: io::Error },
    #[error(
        "the temp directory {} is not safe: {} lets another user rename entries on the way to it",
        tmpdir.display(), offender.display()
    )]
    Unsafe { tmpdir: PathBuf, offender: PathBuf },
    #[error(
        "the temp directory {} (resolved to {}) is on {filesystem}, which the private directory refuses; set TMPDIR to a local directory",
        tmpdir.display(), offender.display()
    )]
    Filesystem {
        tmpdir: PathBuf,
        offender: PathBuf,
        filesystem: &'static str,
    },
    #[error("cannot create the private directory {}: {source}", path.display())]
    Create { path: PathBuf, source: io::Error },
    #[error("cannot set up the fork guard of the private directory: {0}")]
    ForkGuard(io::Error),
}

/// [`PrivateDir::remove`] refused the caller's origin.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("the private directory can only be removed by the process that created it, not by {0:?}")]
pub(crate) struct NotOriginal(pub(crate) Origin);

/// What removing a [`PrivateDir`] found. Every outcome except `Removed` is logged: `Gone` at
/// `debug`, the rest at `warn`, naming the path.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Removal {
    Removed,
    Gone,
    NotOurs,
    NotEmpty,
    Failed(Errno),
}

/// A private directory, identified by `(dev, ino)` and removed only if the name still holds it.
///
/// Only the process that created the directory removes it; a fork copy closes its own descriptors
/// and nothing else. [`create_in`](Self::create_in) gives the directory its own fork guard, and
/// its `Drop` removes it. [`create_unguarded`](Self::create_unguarded) is for an owner that already
/// has one: it must call [`remove`](Self::remove) with its own [`Origin`], and `Drop` does nothing.
pub(crate) struct PrivateDir {
    parent: OwnedFd,
    name: OsString,
    id: (u64, u64),
    path: PathBuf,
    /// The directory itself, for binding and connecting relative to it.
    dir: OwnedFd,
    /// Tells the creating process from a fork copy of it, for a directory that is dropped on its own.
    creator: Option<ForkGuard>,
    removed: bool,
}

/// Opens the directory `name` in `parent`, makes it `0700` and returns it with its `stat`.
type OpenMade = fn(&OwnedFd, &OsStr) -> rustix::io::Result<(OwnedFd, Stat)>;

fn open_and_harden(parent: &OwnedFd, name: &OsStr) -> rustix::io::Result<(OwnedFd, Stat)> {
    // `NOFOLLOW`: whatever now holds the name, we record the directory itself.
    let dir = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    // `mkdirat`'s mode is masked by the umask; the descriptor's is not.
    fchmod(&dir, Mode::RWXU)?;
    let st = fstat(&dir)?;
    Ok((dir, st))
}

#[allow(
    clippy::unnecessary_cast,
    reason = "`st_dev` and `st_ino` have different widths per platform"
)]
fn id_of(st: &Stat) -> (u64, u64) {
    (st.st_dev as u64, st.st_ino as u64)
}

fn io_err(e: Errno) -> io::Error {
    e.into()
}

/// `path` and every ancestor, leaf first, with the first one that fails [`check_facts`]. Only the
/// temp directory itself is checked for its filesystem: a local one under a network root is fine.
fn unsafe_ancestor(real: &Path, euid: u32) -> io::Result<Option<PathBuf>> {
    for path in real.ancestors() {
        let st = statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW).map_err(io_err)?;
        if !check_facts(&DirFacts::read(path, &st, euid)?, euid) {
            return Ok(Some(path.to_owned()));
        }
    }
    Ok(None)
}

impl PrivateDir {
    /// In [`std::env::temp_dir`].
    pub(crate) fn create() -> Result<Self, PrivateDirError> {
        Self::create_in(&std::env::temp_dir())
    }

    /// The real path of `tmp`, which must be absolute. A caller that needs to look at the path
    /// before anything is created resolves once and passes it to
    /// [`create_unguarded_resolved`](Self::create_unguarded_resolved).
    pub(crate) fn resolve(tmp: &Path) -> Result<PathBuf, PrivateDirError> {
        if !tmp.is_absolute() {
            return Err(PrivateDirError::TmpdirNotAbsolute(tmp.to_owned()));
        }
        std::fs::canonicalize(tmp).map_err(|source| PrivateDirError::Tmpdir {
            path: tmp.to_owned(),
            source,
        })
    }

    /// In `tmp`, which must be absolute. Every ancestor of its real path must pass [`check_facts`],
    /// and `tmp` itself [`check_dir`]; otherwise nothing is created.
    pub(crate) fn create_in(tmp: &Path) -> Result<Self, PrivateDirError> {
        Self::create_with(tmp, open_and_harden, true)
    }

    /// [`create_in`](Self::create_in) for an owner that tells its own [`Origin`]: no fork guard of
    /// the directory's own, and nothing happens on `Drop`.
    pub(crate) fn create_unguarded(tmp: &Path) -> Result<Self, PrivateDirError> {
        Self::create_with(tmp, open_and_harden, false)
    }

    /// [`create_unguarded`](Self::create_unguarded) for a `real` path from [`resolve`](Self::resolve).
    pub(crate) fn create_unguarded_resolved(tmp: &Path, real: PathBuf) -> Result<Self, PrivateDirError> {
        Self::create_resolved(tmp, real, open_and_harden, false, None)
    }

    fn create_with(tmp: &Path, open: OpenMade, guarded: bool) -> Result<Self, PrivateDirError> {
        let real = Self::resolve(tmp)?;
        Self::create_resolved(tmp, real, open, guarded, None)
    }

    /// [`create_in`](Self::create_in) with the opening of the new directory replaced by `open`, and
    /// `over` standing in for the temp directory's `statfs`. A failure removes the directory.
    fn create_resolved(
        tmp: &Path,
        real: PathBuf,
        open: OpenMade,
        guarded: bool,
        over: Option<FsOverride>,
    ) -> Result<Self, PrivateDirError> {
        // SAFETY: `geteuid` has no preconditions and cannot fail.
        let euid = unsafe { libc::geteuid() };
        let tmp_err = |source| PrivateDirError::Tmpdir {
            path: tmp.to_owned(),
            source,
        };
        let unsafe_err = |offender| PrivateDirError::Unsafe {
            tmpdir: tmp.to_owned(),
            offender,
        };
        if let Some(offender) = unsafe_ancestor(&real, euid).map_err(tmp_err)? {
            return Err(unsafe_err(offender));
        }
        let parent = openat(
            CWD,
            &real,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| tmp_err(io_err(e)))?;
        // The path walk above may have raced a rename; the descriptor we hold is checked again.
        let st = fstat(&parent).map_err(|e| tmp_err(io_err(e)))?;
        let facts = DirFacts::read_fd(parent.as_fd(), &real, &st, euid, over).map_err(tmp_err)?;
        match check_dir(&facts, euid) {
            Ok(()) => {}
            Err(Unfit::Writable) => return Err(unsafe_err(real)),
            Err(Unfit::Filesystem(filesystem)) => {
                return Err(PrivateDirError::Filesystem {
                    tmpdir: tmp.to_owned(),
                    offender: real,
                    filesystem,
                })
            }
        }
        let creator = if guarded {
            Some(ForkGuard::new().map_err(PrivateDirError::ForkGuard)?)
        } else {
            None
        };
        loop {
            let mut random = [0u8; 8];
            getrandom::fill(&mut random).map_err(|e| PrivateDirError::Create {
                path: real.clone(),
                source: io::Error::other(e),
            })?;
            let name = OsString::from(format!("cosca-{:016x}", u64::from_ne_bytes(random)));
            debug_assert_eq!(name.len(), NAME_LEN);
            let path = real.join(&name);
            match mkdirat(&parent, &name, Mode::RWXU) {
                Ok(()) => {}
                Err(Errno::EXIST) => continue,
                Err(e) => {
                    return Err(PrivateDirError::Create {
                        path,
                        source: io_err(e),
                    })
                }
            }
            let made = open(&parent, &name);
            let (dir, id) = match made {
                Ok((dir, st)) => {
                    debug_assert_eq!(FileType::from_raw_mode(st.st_mode), FileType::Directory);
                    debug_assert_eq!(st.st_uid, euid);
                    debug_assert_eq!(Mode::from_raw_mode(st.st_mode), Mode::RWXU);
                    (dir, id_of(&st))
                }
                Err(e) => {
                    if let Err(rm) = unlinkat(&parent, &name, AtFlags::REMOVEDIR) {
                        log::warn!("cannot remove the private directory {}: {rm}", path.display());
                    }
                    return Err(PrivateDirError::Create {
                        path,
                        source: io_err(e),
                    });
                }
            };
            return Ok(Self {
                parent,
                name,
                id,
                path,
                dir,
                creator,
                removed: false,
            });
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// The directory itself. On Linux a socket in it is bound and connected relative to this
    /// descriptor, so that a long `TMPDIR` cannot overflow `sun_path`; macOS has no `bindat`, and
    /// binds by full path.
    pub(crate) fn dir_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.dir.as_fd()
    }

    /// Removes the directory if the name still holds the one we made, by `(dev, ino)`, with
    /// `unlinkat` on the parent's descriptor. Never deletes anything inside. Logs as [`Removal`]
    /// says. Refused, in release builds too, for any `origin` but [`Origin::Original`].
    pub(crate) fn remove(mut self, origin: Origin) -> Result<Removal, NotOriginal> {
        if origin != Origin::Original {
            return Err(NotOriginal(origin));
        }
        self.removed = true;
        Ok(self.remove_by_fd())
    }

    /// `Drop`'s body: nothing once removed. An origin that cannot be told leaves the directory, and
    /// says so without the `log` facade, which a fork copy must not touch.
    fn release(&mut self, origin: Origin) {
        if self.removed {
            return;
        }
        match origin {
            Origin::Original => {
                self.removed = true;
                self.remove_by_fd();
            }
            Origin::Copy => {}
            Origin::Unknown => super::fork_guard::warn_unlogged(
                b"cosca: cannot tell which process made a shim directory; left in place\n",
            ),
        }
    }

    fn remove_by_fd(&self) -> Removal {
        let name = &self.name;
        let removal = match statat(&self.parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => Removal::Gone,
            Err(e) => Removal::Failed(e),
            Ok(st) if FileType::from_raw_mode(st.st_mode) != FileType::Directory || id_of(&st) != self.id => {
                Removal::NotOurs
            }
            Ok(_) => match unlinkat(&self.parent, name, AtFlags::REMOVEDIR) {
                Ok(()) => Removal::Removed,
                Err(Errno::NOENT) => Removal::Gone,
                // POSIX allows either for a non-empty directory.
                Err(Errno::NOTEMPTY | Errno::EXIST) => Removal::NotEmpty,
                Err(e) => Removal::Failed(e),
            },
        };
        let path = self.path.display();
        match &removal {
            Removal::Removed => {}
            Removal::Gone => log::debug!("the private directory {path} was already gone"),
            Removal::NotOurs => log::warn!("{path} is no longer the private directory cosca made; left alone"),
            Removal::NotEmpty => log::warn!("the private directory {path} is not empty; left in place"),
            Removal::Failed(e) => log::warn!("cannot remove the private directory {path}: {e}"),
        }
        removal
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        if let Some(creator) = &self.creator {
            self.release(creator.origin());
        }
    }
}

#[cfg(test)]
#[path = "private_dir_tests.rs"]
mod private_dir_tests;
