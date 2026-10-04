//! The private directory that holds the shim's socket (D14): a `0700` directory with a random
//! name in a temp directory no other user can tamper with, removed through file descriptors.

use std::ffi::OsString;
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{fstat, mkdirat, openat, statat, unlinkat, AtFlags, FileType, Mode, OFlags, Stat, CWD};
use rustix::io::Errno;

const STICKY: u32 = 0o1000;
const GROUP_OTHER_WRITE: u32 = 0o022;

/// What the path check looks at in a directory's `stat`.
pub(crate) struct DirFacts {
    pub(crate) uid: u32,
    pub(crate) mode: u32,
}

impl DirFacts {
    fn of(st: &Stat) -> Self {
        Self {
            uid: st.st_uid,
            mode: st.st_mode.into(),
        }
    }
}

/// True if no user but `euid` and root can rename an entry of this directory: it is owned by one of
/// them, and either sticky (others may not rename entries they do not own) or not writable by
/// group or others.
pub(crate) fn check_facts(facts: &DirFacts, euid: u32) -> bool {
    (facts.uid == 0 || facts.uid == euid) && (facts.mode & STICKY != 0 || facts.mode & GROUP_OTHER_WRITE == 0)
}

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
}

/// What [`PrivateDir::remove`] found.
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
/// Dropping it closes its descriptors and leaves the directory; [`remove`](Self::remove) is the
/// teardown, and only the pid that made it may call it.
pub(crate) struct PrivateDir {
    parent: OwnedFd,
    name: OsString,
    id: (u64, u64),
    path: PathBuf,
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
        if !check_facts(&DirFacts::of(&st), euid) {
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
        if !check_facts(&DirFacts::of(&st), euid) {
            return Err(unsafe_err(real));
        }
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
            // `NOFOLLOW`: whatever now holds the name, we record the directory itself.
            let create_err = |e| PrivateDirError::Create {
                path: path.clone(),
                source: io_err(e),
            };
            let dir = openat(
                &parent,
                &name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(create_err)?;
            let id = id_of(&fstat(&dir).map_err(create_err)?);
            return Ok(Self { parent, name, id, path });
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Removes the directory if the name still holds the one we made, by `(dev, ino)`, with
    /// `unlinkat` on the parent's descriptor. Never deletes anything inside. Everything but "already
    /// gone" is logged at `warn`, naming the path.
    pub(crate) fn remove(self) -> Removal {
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

#[cfg(test)]
#[path = "private_dir_tests.rs"]
mod private_dir_tests;
