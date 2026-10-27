use std::io;

use super::Filesystem;
#[cfg(unix)]
use crate::posix::{Path, PathBuf};
#[cfg(windows)]
use crate::windows::{Path, PathBuf};

/// This machine's filesystem: [`windows::Path`](crate::windows::Path)s on Windows,
/// [`posix::Path`](crate::posix::Path)s on Unix. It is not implemented elsewhere.
///
/// Answers come from `std::fs`, so links are followed. A Windows path reaches `std` through
/// `windows::Path::to_std_path`, so it names what its names spell: `C:\x\tool.` is the file
/// `tool.`, not `tool`. A path with no such string (a relative `tool.`) is an
/// [`InvalidInput`](io::ErrorKind::InvalidInput) error.
///
/// [`canonical`](Filesystem::canonical) is parsed back into a stored (lexical) spelling, so a
/// Win32 `\\?\` prefix is not in the result (see the [`windows`](crate::windows) module docs).
#[derive(Debug, Clone, Copy, Default)]
pub struct HostFilesystem;

/// Whether a metadata error says definitely "no such file": nothing at the path, a non-directory
/// in it, a name no filesystem accepts, or (Windows) no such drive.
///
/// Decided on the raw OS code, not [`io::ErrorKind`]: std maps `ERROR_BAD_NETPATH` and
/// `ERROR_BAD_NET_NAME` to `NotFound` too, and an unreachable share may only be unreachable for now.
fn is_absence(e: &io::Error) -> bool {
    let Some(code) = e.raw_os_error() else {
        return e.kind() == io::ErrorKind::NotFound;
    };
    #[cfg(windows)]
    {
        // FILE_NOT_FOUND, PATH_NOT_FOUND, INVALID_DRIVE, INVALID_NAME, BAD_PATHNAME, DIRECTORY.
        matches!(code, 2 | 3 | 15 | 123 | 161 | 267)
    }
    #[cfg(unix)]
    {
        matches!(code, libc::ENOENT | libc::ENOTDIR)
    }
}

#[cfg(windows)]
fn std_path(p: &Path) -> io::Result<std::path::PathBuf> {
    p.to_std_path()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

#[cfg(unix)]
fn std_path(p: &Path) -> io::Result<&std::path::Path> {
    Ok(p.as_std_path())
}

/// The metadata of `p`, or `None` where there is definitely nothing.
fn metadata(p: &Path) -> io::Result<Option<std::fs::Metadata>> {
    match std::fs::metadata(std_path(p)?) {
        Ok(meta) => Ok(Some(meta)),
        Err(e) if is_absence(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

impl Filesystem for HostFilesystem {
    type Path = Path;

    fn is_file(&self, p: &Path) -> io::Result<bool> {
        Ok(metadata(p)?.is_some_and(|meta| meta.is_file()))
    }

    fn is_dir(&self, p: &Path) -> io::Result<bool> {
        Ok(metadata(p)?.is_some_and(|meta| meta.is_dir()))
    }

    fn canonical(&self, p: &Path) -> io::Result<PathBuf> {
        let canonical = std::fs::canonicalize(std_path(p)?)?;
        #[cfg(windows)]
        return PathBuf::from_std_path(&canonical).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
        #[cfg(unix)]
        return Ok(Path::from_std_path(&canonical).to_path_buf());
    }

    fn same_file(&self, a: &Path, b: &Path) -> io::Result<bool> {
        same_file::is_same_file(std_path(a)?, std_path(b)?)
    }
}

#[cfg(test)]
#[path = "host_tests.rs"]
mod host_tests;
