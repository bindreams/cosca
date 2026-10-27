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
        identity::same_file(std_path(a)?, std_path(b)?).map_err(|e| {
            if is_absence(&e) {
                io::Error::new(io::ErrorKind::NotFound, e)
            } else {
                e
            }
        })
    }
}

/// File identity without opening for data, so it works wherever [`metadata`] does: no read
/// access is needed and a FIFO has nothing to wait for.
mod identity {
    use std::io;
    use std::path::Path;

    /// `(dev, ino)` from `metadata`, which follows links.
    #[cfg(unix)]
    pub(super) fn same_file(a: impl AsRef<Path>, b: impl AsRef<Path>) -> io::Result<bool> {
        use std::os::unix::fs::MetadataExt;

        let (a, b) = (std::fs::metadata(a)?, std::fs::metadata(b)?);
        Ok((a.dev(), a.ino()) == (b.dev(), b.ino()))
    }

    /// The volume serial number and 128-bit file id of two handles opened with no data access.
    /// `GetFileInformationByHandle`'s 64-bit index is not unique on ReFS. Both handles stay open
    /// until the comparison is made, so neither file can be deleted and its id reused between the
    /// two queries.
    #[cfg(windows)]
    pub(super) fn same_file(a: impl AsRef<Path>, b: impl AsRef<Path>) -> io::Result<bool> {
        let (a, b) = (open(a.as_ref())?, open(b.as_ref())?);
        let (a, b) = (file_id(&a)?, file_id(&b)?);
        Ok(a.VolumeSerialNumber == b.VolumeSerialNumber && a.FileId.Identifier == b.FileId.Identifier)
    }

    /// `p` with no access rights, full sharing and `FILE_FLAG_BACKUP_SEMANTICS` (which lets a
    /// directory open): only its identity can be asked of the handle, and no other holder's share
    /// mode refuses it.
    #[cfg(windows)]
    fn open(p: &Path) -> io::Result<std::fs::File> {
        use std::os::windows::fs::OpenOptionsExt;

        use windows::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };

        std::fs::OpenOptions::new()
            .access_mode(0)
            .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
            .open(p)
    }

    #[cfg(windows)]
    fn file_id(f: &std::fs::File) -> io::Result<windows::Win32::Storage::FileSystem::FILE_ID_INFO> {
        use std::os::windows::io::AsRawHandle;

        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Storage::FileSystem::{FileIdInfo, GetFileInformationByHandleEx, FILE_ID_INFO};

        let mut info = FILE_ID_INFO::default();
        // SAFETY: the handle is open for the call, and the buffer is a `FILE_ID_INFO` of the size passed.
        unsafe {
            GetFileInformationByHandleEx(
                HANDLE(f.as_raw_handle()),
                FileIdInfo,
                (&raw mut info).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        }?;
        Ok(info)
    }
}

#[cfg(test)]
#[path = "host_tests.rs"]
mod host_tests;
