//! The checked `/proc` and what a failed read of it means, below every question asked through it:
//! [`ProcDir`] is a directory fd proven to be procfs's root, and the only way to read `/proc`; a failed
//! read is a [`ReadFailure`] by the call that failed, and a failed read of one of this process's own
//! files is an [`OwnUnreadable`] by the one own-file rule ([`read_own`]).
//!
//! Nothing here knows a pid's file ([`pid_file`](super::pid_file)) or the namespace view
//! ([`proc_view`](super::proc_view)); both are built on it.

use std::io::{self, Read};
use std::os::fd::OwnedFd;

use rustix::fs::{openat2, FsWord, Mode, OFlags, ResolveFlags, CWD, PROC_SUPER_MAGIC};
use rustix::io::Errno;

use super::kernel::Kernel;
use super::refusal::{FailedCall, Refusal};

/// A failed [`ProcDir::read`], [`ProcDir::read_link`] or [`ProcDir::pids`] (and so a
/// [`Kernel`] call that answers one), by the call that failed: only an `openat2`'s errno can be a
/// refusal ([`FailedCall::openat2`]), and only a file, link or directory that opened can fail
/// reading it (`read(2)`, `readlinkat`, or the directory's setup and `getdents64`).
#[derive(Debug)]
pub(crate) enum ReadFailure {
    Open(io::Error),
    Read(io::Error),
}

impl ReadFailure {
    pub(crate) fn into_io(self) -> io::Error {
        match self {
            ReadFailure::Open(e) | ReadFailure::Read(e) => e,
        }
    }

    /// The [`Refusal`] this failure is, if any: an `openat2` errno in
    /// [`FailedCall::requirement`]'s table. A failure after the `openat2` (a `read(2)`, a
    /// `readlinkat`, a listing) is none, whatever its errno.
    pub(crate) fn refusal(&self) -> Option<Refusal> {
        match self {
            ReadFailure::Open(e) => FailedCall::openat2(Errno::from_io_error(e)?).refusal(),
            ReadFailure::Read(_) => None,
        }
    }
}

/// Why one of this process's own files could not be read: `self/status`, `self/stat`,
/// `thread-self/fdinfo/<fd>`, `thread-self/ns/pid`. `hidepid` hides other users' pid directories and
/// cannot hide these, so an `EPERM` of one is nothing to re-check. The one rule: a
/// [`ReadFailure::refusal`] is a [`Refusal`], and every other failure, any `read(2)` errno included,
/// is the file's own.
#[derive(Debug)]
pub(crate) enum OwnUnreadable {
    Refused(Refusal),
    Failed(io::Error),
}

impl OwnUnreadable {
    fn of(failure: ReadFailure) -> Self {
        match failure.refusal() {
            Some(refusal) => OwnUnreadable::Refused(refusal),
            None => OwnUnreadable::Failed(failure.into_io()),
        }
    }

    /// An `openat2` of an own file that answered `errno`.
    pub(crate) fn opening(errno: Errno) -> Self {
        Self::of(ReadFailure::Open(errno.into()))
    }
}

/// This process's own file `path` under `dir`, read through `kernel`: the one read of such a file.
/// `path` is `self/...` or `thread-self/...`, the files `hidepid` cannot hide from their reader.
pub(crate) fn read_own(kernel: &dyn Kernel, dir: &ProcDir, path: &str) -> Result<Vec<u8>, OwnUnreadable> {
    debug_assert_own(path);
    kernel.read(dir, path).map_err(OwnUnreadable::of)
}

/// [`read_own`] of an own symlink, its target the bytes: `None` when the `openat2` finds no such link
/// (`ENOENT`), as a kernel with no pid namespaces has no `thread-self/ns/pid`. An `ENOENT` after the
/// open is the link's own failure, which says nothing of the kernel.
pub(crate) fn read_own_link(kernel: &dyn Kernel, dir: &ProcDir, path: &str) -> Result<Option<Vec<u8>>, OwnUnreadable> {
    debug_assert_own(path);
    match kernel.read_link(dir, path) {
        Ok(target) => Ok(Some(target)),
        Err(ReadFailure::Open(e)) if e.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(failure) => Err(OwnUnreadable::of(failure)),
    }
}

/// The own-file rule holds only of this process's own files; `hidepid` hides any other pid's.
fn debug_assert_own(path: &str) {
    debug_assert!(
        path.starts_with("self/") || path.starts_with("thread-self/"),
        "{path:?} is not one of this process's own files"
    );
}

/// Why `/proc` could not be opened as a [`ProcDir`].
#[derive(Debug)]
pub(crate) enum ProcOpenFailure {
    /// The `openat2` of `/proc` failed.
    Open(OwnUnreadable),
    /// The opened directory could not be checked (`fstatfs`, `fstat`).
    Check(io::Error),
    NotProcfs {
        f_type: FsWord,
    },
    NotRoot {
        ino: u64,
    },
}

impl ProcOpenFailure {
    /// The `openat2` of `/proc` answering `errno`.
    pub(crate) fn opening(errno: Errno) -> Self {
        ProcOpenFailure::Open(OwnUnreadable::opening(errno))
    }
}

/// A `/proc` directory fd proven to be procfs's root, and the only way to read `/proc`: every
/// read is an `openat2` beneath it that cannot cross a mount, so nothing mounted over `/proc`
/// or below it after the check is ever read. Needs `openat2` (Linux 5.6, and not filtered by
/// seccomp): [`open`](Self::open) fails with a [`ReadFailure::refusal`] that names it.
#[derive(Debug)]
pub(crate) struct ProcDir(OwnedFd);

impl ProcDir {
    /// Open `/proc` and prove it is procfs's root: `PROC_SUPER_MAGIC`, and inode 1.
    pub(crate) fn open() -> Result<ProcDir, ProcOpenFailure> {
        let fd = open_proc_root().map_err(ProcOpenFailure::opening)?;
        let fs = rustix::fs::fstatfs(&fd).map_err(|e| ProcOpenFailure::Check(e.into()))?;
        if fs.f_type != PROC_SUPER_MAGIC {
            return Err(ProcOpenFailure::NotProcfs { f_type: fs.f_type });
        }
        let ino = rustix::fs::fstat(&fd)
            .map_err(|e| ProcOpenFailure::Check(e.into()))?
            .st_ino;
        if ino != PROC_ROOT_INO {
            return Err(ProcOpenFailure::NotRoot { ino });
        }
        Ok(ProcDir(fd))
    }

    /// Open `path` under this `/proc`, refusing to leave it, cross a mount, or follow a magic link.
    fn open_beneath(&self, path: &str, oflags: OFlags) -> io::Result<OwnedFd> {
        openat2(
            &self.0,
            path,
            oflags | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(io::Error::from)
    }

    /// This process's `self/fd` directory under this `/proc`, opened as
    /// [`open_beneath`](Self::open_beneath) opens. Async-signal-safe (one `openat2`, no allocation);
    /// in a forked child `self` is the child.
    pub(crate) fn open_own_fd_dir(&self) -> rustix::io::Result<OwnedFd> {
        openat2(
            &self.0,
            c"self/fd",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | ResolveFlags::NO_MAGICLINKS,
        )
    }

    /// Read the file at `path` under this `/proc`.
    pub(crate) fn read(&self, path: &str) -> Result<Vec<u8>, ReadFailure> {
        let file = self.open_beneath(path, OFlags::RDONLY).map_err(ReadFailure::Open)?;
        let mut bytes = Vec::new();
        std::fs::File::from(file)
            .read_to_end(&mut bytes)
            .map_err(ReadFailure::Read)?;
        Ok(bytes)
    }

    /// The target of the symlink at `path` under this `/proc`, without following it. A failure says
    /// whether the `openat2` or the `readlinkat` failed.
    pub(super) fn read_link(&self, path: &str) -> Result<Vec<u8>, ReadFailure> {
        let link = self
            .open_beneath(path, OFlags::PATH | OFlags::NOFOLLOW)
            .map_err(ReadFailure::Open)?;
        let target = rustix::fs::readlinkat(&link, "", Vec::new()).map_err(|e| ReadFailure::Read(e.into()))?;
        Ok(target.into_bytes())
    }

    /// The pids listed under this `/proc`: its decimal-named entries. The `openat2` of `.` is
    /// [`ReadFailure::Open`]; the directory's setup and listing are [`ReadFailure::Read`].
    pub(super) fn pids(&self) -> Result<Vec<u32>, ReadFailure> {
        let fd = self
            .open_beneath(".", OFlags::RDONLY | OFlags::DIRECTORY)
            .map_err(ReadFailure::Open)?;
        let dir = rustix::fs::Dir::new(fd).map_err(|e| ReadFailure::Read(e.into()))?;
        collect_pids(dir.map(|entry| Ok(entry?.file_name().to_bytes().to_vec()))).map_err(ReadFailure::Read)
    }
}

/// The inode of procfs's root directory (`PROC_ROOT_INO`).
const PROC_ROOT_INO: u64 = 1;

/// The `openat2` of `/proc` itself.
fn open_proc_root() -> Result<OwnedFd, Errno> {
    openat2(
        CWD,
        "/proc",
        OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_MAGICLINKS,
    )
}

/// `bytes` as UTF-8 text.
pub(crate) fn utf8(bytes: Vec<u8>) -> io::Result<String> {
    String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// The pids among directory entry `names`: the all-digit ones. `self`, `thread-self`, `net`, ...
/// are not pids. An all-digit name that is no `u32` is a corrupt listing, so an error: a live
/// process dropped from the list would read as one that is not there.
fn collect_pids(names: impl IntoIterator<Item = io::Result<Vec<u8>>>) -> io::Result<Vec<u32>> {
    /// The kernel's `PID_MAX_LIMIT` on 64-bit.
    const PID_MAX_LIMIT: u32 = 1 << 22;
    let mut pids = Vec::new();
    for name in names {
        let name = name?;
        if name.is_empty() || !name.iter().all(u8::is_ascii_digit) {
            continue;
        }
        // All ASCII digits, so UTF-8; the only way to fail is overflow.
        let text = String::from_utf8_lossy(&name);
        let pid = text.parse::<u32>().map_err(|e| {
            crate::error::io_context(
                format!("the /proc entry {text:?} is all digits but not a pid"),
                io::Error::new(io::ErrorKind::InvalidData, e),
            )
        })?;
        debug_assert!(
            pid <= PID_MAX_LIMIT,
            "/proc lists pid {pid} beyond the kernel's PID_MAX_LIMIT"
        );
        pids.push(pid);
    }
    Ok(pids)
}

#[cfg(test)]
#[path = "proc_read_tests.rs"]
mod proc_read_tests;
