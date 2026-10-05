//! The private directory that holds the shim's socket (D14): a directory made `0700` (whatever the
//! umask says) with a random name in a temp directory no other user can tamper with, removed
//! through file descriptors.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{fchmod, fstat, mkdirat, openat, statat, unlinkat, AtFlags, FileType, Mode, OFlags, Stat, CWD};
use rustix::io::Errno;

use super::fork_guard::{ForkGuard, Origin};

mod facts;

use facts::{check_facts, DirFacts};

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
    #[error("cannot create the private directory {}: {source}", path.display())]
    Create { path: PathBuf, source: io::Error },
    #[error("cannot set up the fork guard of the private directory: {0}")]
    ForkGuard(io::Error),
}

/// What removing a [`PrivateDir`] found. Every outcome except `Removed` is logged: `Gone` at
/// `debug`, the rest at `warn`, naming the path.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Removal {
    Removed,
    /// Already gone.
    Gone,
    /// The name no longer holds the directory we made. Left alone.
    NotOurs,
    /// Something is still inside. Left alone.
    NotEmpty,
    /// The directory could not be removed.
    Failed(Errno),
}

/// A private directory, identified by `(dev, ino)` and removed only if the name still holds it.
///
/// [`remove`](Self::remove) is the explicit teardown. `Drop` is the same removal, with the same
/// logging, so no path leaks the directory silently. Only the process that created the directory
/// (told by its fork guard) removes it: a fork copy's `Drop` closes its own descriptors and nothing
/// else.
pub(crate) struct PrivateDir {
    parent: OwnedFd,
    name: OsString,
    id: (u64, u64),
    path: PathBuf,
    /// Tells the creating process from a fork copy of it (no I/O: `Drop` uses it).
    creator: ForkGuard,
    removed: bool,
}

/// Opens the directory `name` in `parent`, makes it `0700` and returns its `stat`.
type OpenMade = fn(&OwnedFd, &OsStr) -> rustix::io::Result<Stat>;

fn open_and_harden(parent: &OwnedFd, name: &OsStr) -> rustix::io::Result<Stat> {
    // `NOFOLLOW`: whatever now holds the name, we record the directory itself.
    let dir = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    // `mkdirat`'s mode is masked by the umask; the descriptor's is not.
    fchmod(&dir, Mode::RWXU)?;
    fstat(&dir)
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

/// `path` and every ancestor, leaf first, with the first one that fails [`check_facts`].
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

    /// In `tmp`, which must be absolute, and whose real path and every ancestor of it must pass
    /// [`check_facts`]; otherwise nothing is created.
    pub(crate) fn create_in(tmp: &Path) -> Result<Self, PrivateDirError> {
        Self::create_with(tmp, open_and_harden)
    }

    /// [`create_in`](Self::create_in), where `open` opens the directory just made, in `parent`
    /// under `name`, and returns its `stat`. A failure removes the directory.
    fn create_with(tmp: &Path, open: OpenMade) -> Result<Self, PrivateDirError> {
        // SAFETY: `geteuid` has no preconditions and cannot fail.
        let euid = unsafe { libc::geteuid() };
        let tmp_err = |source| PrivateDirError::Tmpdir {
            path: tmp.to_owned(),
            source,
        };
        if !tmp.is_absolute() {
            return Err(PrivateDirError::TmpdirNotAbsolute(tmp.to_owned()));
        }
        let real = std::fs::canonicalize(tmp).map_err(tmp_err)?;
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
        let facts = DirFacts::read(&real, &st, euid).map_err(tmp_err)?;
        if !check_facts(&facts, euid) {
            return Err(unsafe_err(real));
        }
        let creator = ForkGuard::new().map_err(PrivateDirError::ForkGuard)?;
        loop {
            let mut random = [0u8; 8];
            getrandom::fill(&mut random).map_err(|e| PrivateDirError::Create {
                path: real.clone(),
                source: io::Error::other(e),
            })?;
            let name = OsString::from(format!("cosca-{:016x}", u64::from_ne_bytes(random)));
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
            let id = match made {
                Ok(st) => {
                    debug_assert_eq!(FileType::from_raw_mode(st.st_mode), FileType::Directory);
                    debug_assert_eq!(st.st_uid, euid);
                    debug_assert_eq!(Mode::from_raw_mode(st.st_mode), Mode::RWXU);
                    id_of(&st)
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
                creator,
                removed: false,
            });
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Removes the directory if the name still holds the one we made, by `(dev, ino)`, with
    /// `unlinkat` on the parent's descriptor. Never deletes anything inside. Logs as [`Removal`]
    /// says. Only the process that created the directory may call it.
    pub(crate) fn remove(mut self) -> Removal {
        debug_assert_eq!(
            self.creator.origin(),
            Origin::Original,
            "removed by a process that did not make it"
        );
        self.removed = true;
        self.remove_by_fd()
    }

    /// `Drop`'s body, for a process of this `origin`: nothing unless it is the process that created
    /// the directory (told by its fork guard, not a bare pid), and the directory is not removed yet.
    /// An origin that cannot be told leaves the directory: removing it from a copy would take the
    /// original's.
    fn release(&mut self, origin: Origin) {
        if origin == Origin::Unknown {
            log::warn!(
                "cannot tell who made the private directory {}; left in place",
                self.path.display()
            );
        }
        if origin == Origin::Original && !self.removed {
            self.removed = true;
            self.remove_by_fd();
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
        self.release(self.creator.origin());
    }
}

#[cfg(test)]
#[path = "private_dir_tests.rs"]
mod private_dir_tests;
