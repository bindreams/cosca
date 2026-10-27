use std::io;

use super::Filesystem;
#[cfg(unix)]
use crate::posix::{Path, PathBuf};
#[cfg(windows)]
use crate::windows::{Path, PathBuf};

/// This machine's filesystem: [`windows::Path`](crate::windows::Path)s on Windows,
/// [`posix::Path`](crate::posix::Path)s on Unix.
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
/// and, on Windows, [`same_file`](Filesystem::same_file) open it, so on Windows they can fail where
/// those two succeed: an app-execution alias (`%LOCALAPPDATA%\Microsoft\WindowsApps\*.exe`, os
/// error 1920), `pagefile.sys` and its like (32), a protected directory such as
/// `System Volume Information` (`PermissionDenied`). The error is returned as it is.
///
/// # `same_file`
///
/// Links are followed, and no read access to the file is needed.
///
/// - **Windows:** two handles opened with no data access, compared by volume serial number and file
///   id. Both stay open until the comparison is made, so no change to either path can change it.
/// - **Linux and Android:** both files are opened with `O_PATH` and `(st_dev, st_ino)` is read from
///   the open files, so no change to either path while it runs can change the answer. A FIFO is not
///   opened.
/// - **macOS and every other Unix:** there is no such open (`O_EVTONLY` and `O_SYMLINK` still
///   authorize reading the data), so each path is `stat`ed in turn, nothing is opened, and
///   `(st_dev, st_ino, birth time)` must agree. Comparing `(st_dev, st_ino)` alone would let a
///   delete and recreate that reuses an inode number make two different files equal; a replacement
///   is created later, so its birth time differs. A write, `chmod` or new hard link between the two
///   `stat`s does not change the birth time (`ctime` would change), so the same file is still one
///   file. A volume that reports no birth time is an [`Unsupported`](io::ErrorKind::Unsupported)
///   error naming the path: the comparison is never weakened to `(st_dev, st_ino)` or `ctime`.
///
///   The gap that remains: a delete and recreate within one birth-time tick on a volume that
///   reuses inode numbers, such as FAT and exFAT (10 ms creation times) and SMB or NFS (the server
///   supplies the time). Apple's APFS reference (2020-06-22) describes a per-volume counter for
///   file-system object identifiers (`apfs_next_obj_id`) but does not say they are never reused, so
///   APFS is not assumed immune; its birth time has nanosecond resolution.
///
///   The file's owner can set the birth time (`setattrlist`), which can make a replacement match.
///   That is outside cosca's model: two ordinary programs racing do not fake it.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostFilesystem;

/// Whether a metadata error says definitely "no such file": nothing at the path (a missing drive
/// included, which Windows reports as `PATH_NOT_FOUND`), a non-directory in it, or a name no
/// filesystem accepts.
///
/// Decided on the raw OS code, not [`io::ErrorKind`]: std maps `ERROR_BAD_NETPATH` and
/// `ERROR_BAD_NET_NAME` to `NotFound` too, and an unreachable share may only be unreachable for now.
fn is_absence(e: &io::Error) -> bool {
    let Some(code) = e.raw_os_error() else {
        return e.kind() == io::ErrorKind::NotFound;
    };
    #[cfg(windows)]
    {
        // FILE_NOT_FOUND, PATH_NOT_FOUND, INVALID_NAME, BAD_PATHNAME, DIRECTORY.
        matches!(code, 2 | 3 | 123 | 161 | 267)
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

/// File identity: see [`HostFilesystem`] for what is compared on each platform.
mod identity {
    use std::io;
    use std::path::Path;

    /// `(dev, ino)` of two files that are both open while they are compared, so that neither can be
    /// deleted and its number reused by the other path between the two reads. Links are followed.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(super) fn same_file(a: impl AsRef<Path>, b: impl AsRef<Path>) -> io::Result<bool> {
        same_file_pinned_with(a, b, || {})
    }

    /// `(dev, ino, birth time)` of each path, from `stat`. Nothing is opened.
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
    pub(super) fn same_file(a: impl AsRef<Path>, b: impl AsRef<Path>) -> io::Result<bool> {
        same_file_by_stat(a, b)
    }

    /// [`same_file`] with `between` run once both files are open and before either is
    /// compared, so a test can change the paths there.
    ///
    /// Each is opened with `O_PATH` ([`open`]), which needs no permission on the file and does not
    /// open a FIFO.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(super) fn same_file_pinned_with(
        a: impl AsRef<Path>,
        b: impl AsRef<Path>,
        between: impl FnOnce(),
    ) -> io::Result<bool> {
        use std::os::unix::fs::MetadataExt;

        let (a, b) = (open(a.as_ref())?, open(b.as_ref())?);
        between();
        let (a, b) = (a.metadata()?, b.metadata()?);
        Ok((a.dev(), a.ino()) == (b.dev(), b.ino()))
    }

    /// `p` opened for nothing but its identity: `open(2)` `O_PATH` ignores the access mode and
    /// `fstat` works on the result.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn open(p: &Path) -> io::Result<std::fs::File> {
        use std::os::unix::fs::OpenOptionsExt;

        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open(p)
    }

    /// The stat comparison, kept on every Unix under `cfg(test)` so that Linux CI runs it too.
    #[cfg(all(unix, any(test, not(any(target_os = "linux", target_os = "android")))))]
    pub(super) fn same_file_by_stat(a: impl AsRef<Path>, b: impl AsRef<Path>) -> io::Result<bool> {
        same_file_by_stat_with(a, b, || {})
    }

    /// [`same_file_by_stat`] with `between` run after `a` is read and before `b` is, so a test can
    /// change the paths there.
    #[cfg(all(unix, any(test, not(any(target_os = "linux", target_os = "android")))))]
    pub(super) fn same_file_by_stat_with(
        a: impl AsRef<Path>,
        b: impl AsRef<Path>,
        between: impl FnOnce(),
    ) -> io::Result<bool> {
        use std::os::unix::fs::MetadataExt;

        let stamp = |p: &Path| -> io::Result<_> {
            let m = std::fs::metadata(p)?;
            let born = m.created().map_err(|e| {
                // A volume with no birth time is an error, not a weaker comparison.
                if e.kind() == io::ErrorKind::Unsupported {
                    io::Error::new(
                        e.kind(),
                        format!(
                            "{} has no birth time, so its identity cannot be told from a replacement's",
                            p.display()
                        ),
                    )
                } else {
                    e
                }
            })?;
            Ok((m.dev(), m.ino(), born))
        };
        let a = stamp(a.as_ref())?;
        between();
        Ok(a == stamp(b.as_ref())?)
    }

    /// The volume serial number and 128-bit file id of two handles opened with no data access.
    /// `GetFileInformationByHandle`'s 64-bit index is not unique on ReFS. Both handles stay open
    /// until the comparison is made, so neither file can be deleted and its id reused between the
    /// two queries.
    ///
    /// Where the 128-bit query fails for either handle, both are compared by the volume serial
    /// number and 64-bit index of `GetFileInformationByHandle` instead, so two kinds of id are
    /// never compared. The 128-bit query is unsupported before Windows 8 / Server 2012, so the
    /// 64-bit call is the fallback wherever it fails.
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

    /// `e` as the Win32 code it wraps; the `windows` crate's own conversion keeps the `HRESULT`.
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
    pub(super) fn narrow_file_id(f: &std::fs::File) -> io::Result<(u32, u64)> {
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
