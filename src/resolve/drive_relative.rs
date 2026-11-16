//! Which directory a drive-relative name (`E:tool`) is completed onto, as Win32 chooses it: the
//! child's directory when that is on the name's drive, else the child's own current directory on
//! that drive. One function for every caller; each passes its own readers, so this module reads no
//! process state.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use super::{is_absolute_name, split_drive};
use crate::error::Error;

/// The directory a drive-relative name is completed onto.
pub(crate) enum DriveBase<'a> {
    /// The child's directory.
    Cwd(&'a Path),
    /// The child's directory on the name's drive, or that drive's root.
    Drive(PathBuf),
}

impl DriveBase<'_> {
    pub(crate) fn path(&self) -> &Path {
        match self {
            DriveBase::Cwd(cwd) => cwd,
            DriveBase::Drive(dir) => dir,
        }
    }
}

/// The directory `name`, a drive-relative path (`C:x`), is completed onto, and the rest of the name
/// after its drive. On the drive of `cwd` (compared by `same_drive`; a `cwd` with no drive, a UNC or
/// verbatim one, is on none) that is `cwd`. On another it is `drive_dir`'s answer for the drive's
/// prefix (`E:`), else the drive's root. `drive_dir` is called only for another drive, and answers
/// only a directory the caller has found usable (so fully qualified).
///
/// The caller appends the rest as units, never `Path::join`ed: see [`super::join::append`].
///
/// # Panics
///
/// If `name` is not drive-relative; in debug builds, if `drive_dir` answers a directory that is not
/// fully qualified.
pub(crate) fn drive_base<'a, 'n>(
    name: &'n OsStr,
    cwd: &'a Path,
    same_drive: &dyn Fn(&OsStr, &OsStr) -> bool,
    drive_dir: impl FnOnce(&OsStr) -> Result<Option<OsString>, Error>,
) -> Result<(DriveBase<'a>, &'n OsStr), Error> {
    debug_assert!(
        super::path_type(name) == super::PathType::DriveRelative,
        "{name:?} is not drive-relative"
    );
    let (drive, rest) = split_drive(name).expect("a drive-relative path has a drive");
    if split_drive(cwd.as_os_str()).is_some_and(|(d, _)| same_drive(d, drive)) {
        return Ok((DriveBase::Cwd(cwd), rest));
    }
    let base = match drive_dir(drive)? {
        Some(dir) => {
            debug_assert!(
                is_absolute_name(&dir, true),
                "the directory of {drive:?} must be fully qualified: {dir:?}"
            );
            dir
        }
        None => {
            let mut root = drive.to_os_string();
            root.push("\\");
            root
        }
    };
    Ok((DriveBase::Drive(PathBuf::from(base)), rest))
}

#[cfg(test)]
#[path = "drive_relative_tests.rs"]
mod drive_relative_tests;
