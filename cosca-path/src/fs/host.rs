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
/// `windows::Path::to_std_path`, so each name is read as spelled: `C:\x\tool.` is the file
/// `tool.`, not `tool`. A path with no such string (a relative `tool.`, or the empty path) is an
/// [`InvalidInput`](io::ErrorKind::InvalidInput) error. On Unix the empty path is absent.
///
/// [`canonical`](Filesystem::canonical) is parsed back into a stored (lexical) spelling, so a
/// Win32 `\\?\` prefix is not in the result (see the [`windows`](crate::windows) module docs). A
/// UNC server and share keep the case the redirector holds, which may differ from the query's, so
/// two results for one directory can differ in case.
///
/// An `Err` of kind [`NotFound`](io::ErrorKind::NotFound) is absence and nothing else: an
/// unreachable server or share (`ERROR_BAD_NETPATH`, `ERROR_BAD_NET_NAME`), which `std` also calls
/// `NotFound`, comes back as [`Other`](io::ErrorKind::Other) with the OS error inside.
///
/// [`is_file`](Filesystem::is_file) and [`is_dir`](Filesystem::is_dir) need no handle on the
/// object, so they answer wherever `std::fs::metadata` does. [`canonical`](Filesystem::canonical)
/// and [`same_file`](Filesystem::same_file) open it, so on Windows they can fail where those two
/// succeed: an app-execution alias (`%LOCALAPPDATA%\Microsoft\WindowsApps\*.exe`, os error 1920),
/// `pagefile.sys` and its like (32), a protected directory such as `System Volume Information`
/// (`PermissionDenied`). The error is returned as it is.
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

/// `e` as [`NotFound`](io::ErrorKind::NotFound) if it is [`is_absence`], else as [`not_absence`]: how
/// the operations with no `Ok` for "nothing there" (`canonical`, `same_file`) report absence.
fn absence_as_not_found(e: io::Error) -> io::Error {
    if is_absence(&e) {
        io::Error::new(io::ErrorKind::NotFound, e)
    } else {
        not_absence(e)
    }
}

/// `e`, which is not absence, without the kind `NotFound`, so that the kind alone tells absence
/// from a failure to say. The OS error stays inside.
fn not_absence(e: io::Error) -> io::Error {
    if e.kind() == io::ErrorKind::NotFound {
        io::Error::other(e)
    } else {
        e
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
        Err(e) => Err(not_absence(e)),
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
        let canonical = std::fs::canonicalize(std_path(p)?).map_err(absence_as_not_found)?;
        #[cfg(windows)]
        return PathBuf::from_std_path(&canonical).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
        #[cfg(unix)]
        return Ok(Path::from_std_path(&canonical).to_path_buf());
    }

    fn same_file(&self, a: &Path, b: &Path) -> io::Result<bool> {
        identity::same_file(std_path(a)?, std_path(b)?).map_err(absence_as_not_found)
    }
}

/// File identity without opening for data: no read access is needed and a FIFO has nothing to
/// wait for. On Windows it still needs a handle on the object (see [`HostFilesystem`]).
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
    ///
    /// Where the 128-bit query fails for either handle, both are compared by the volume serial
    /// number and 64-bit index of `GetFileInformationByHandle` instead, so two kinds of id are
    /// never compared. Microsoft's pages for `FileIdInfo` and `FILE_ID_INFO` say it is unsupported
    /// before Windows 8 and Server 2012 and list no filesystems; so the 64-bit call is the
    /// fallback where the 128-bit one fails.
    #[cfg(windows)]
    pub(super) fn same_file(a: impl AsRef<Path>, b: impl AsRef<Path>) -> io::Result<bool> {
        same_file_with(a, b, wide_file_id)
    }

    /// [`same_file`] with the 128-bit id query given, so a test can make it fail.
    #[cfg(windows)]
    pub(super) fn same_file_with(
        a: impl AsRef<Path>,
        b: impl AsRef<Path>,
        wide_id: impl Fn(&std::fs::File) -> io::Result<windows::Win32::Storage::FileSystem::FILE_ID_INFO>,
    ) -> io::Result<bool> {
        let (a, b) = (open(a.as_ref())?, open(b.as_ref())?);
        if let (Ok(a), Ok(b)) = (wide_id(&a), wide_id(&b)) {
            return Ok(a.VolumeSerialNumber == b.VolumeSerialNumber && a.FileId.Identifier == b.FileId.Identifier);
        }
        Ok(narrow_file_id(&a)? == narrow_file_id(&b)?)
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

    /// `e` as the Win32 code it wraps: the `windows` crate's own conversion keeps the `HRESULT`.
    /// Decoded from `e` itself, as building `e` called `GetErrorInfo` after `GetLastError`.
    #[cfg(windows)]
    fn win32_error(e: windows::core::Error) -> io::Error {
        let code = e.code().0 as u32;
        if code & 0xFFFF_0000 == 0x8007_0000 {
            io::Error::from_raw_os_error((code & 0xFFFF) as i32)
        } else {
            e.into()
        }
    }

    /// The 128-bit file id of `f`, or the Win32 code of the failure.
    #[cfg(windows)]
    pub(super) fn wide_file_id(f: &std::fs::File) -> io::Result<windows::Win32::Storage::FileSystem::FILE_ID_INFO> {
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
        }
        .map_err(win32_error)?;
        Ok(info)
    }

    /// The volume serial number and 64-bit file index of `f`, or the Win32 code of the failure.
    #[cfg(windows)]
    fn narrow_file_id(f: &std::fs::File) -> io::Result<(u32, u64)> {
        use std::os::windows::io::AsRawHandle;

        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};

        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the handle is open for the call, and `info` is a `BY_HANDLE_FILE_INFORMATION`.
        unsafe { GetFileInformationByHandle(HANDLE(f.as_raw_handle()), &mut info) }.map_err(win32_error)?;
        Ok((
            info.dwVolumeSerialNumber,
            u64::from(info.nFileIndexHigh) << 32 | u64::from(info.nFileIndexLow),
        ))
    }
}

#[cfg(test)]
#[path = "host_tests.rs"]
mod host_tests;
