//! The helper side of the `SETUID` group (`test_groups.rs`): tests that need a real setuid-root
//! helper. Depends only on std and libc, so an integration test includes this file with `#[path]`.
//!
//! `COSCA_TEST_SETUID_HELPER` names a copy of `cosca_testbin` that is owned by root with the
//! set-user-ID bit, on a filesystem not mounted `nosuid`.

use std::ffi::OsString;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

const HELPER: &str = "COSCA_TEST_SETUID_HELPER";

/// The helper's path. Call it only from a test that joined the `SETUID` group.
///
/// # Panics
/// As [`check_helper`] does.
pub fn setuid_helper() -> PathBuf {
    // SAFETY: `geteuid` has no preconditions.
    let euid = unsafe { libc::geteuid() };
    check_helper(std::env::var_os(HELPER), stat, euid)
}

/// What [`check_helper`] needs to know about the helper file.
pub struct Meta {
    pub uid: u32,
    pub mode: u32,
    pub is_file: bool,
}

/// [`Meta`] of `path`, following symlinks.
pub fn stat(path: &Path) -> std::io::Result<Meta> {
    let meta = std::fs::metadata(path)?;
    Ok(Meta {
        uid: meta.uid(),
        mode: meta.mode(),
        is_file: meta.is_file(),
    })
}

/// The validated helper path.
///
/// # Panics
/// When `helper` (`COSCA_TEST_SETUID_HELPER`) is unset, when `stat` fails, when the path is not a
/// regular file, when the file is not owned by root with the set-user-ID bit, or when the caller
/// (`euid`) is root, since then nothing is unsignalable by it.
pub fn check_helper(helper: Option<OsString>, stat: impl FnOnce(&Path) -> std::io::Result<Meta>, euid: u32) -> PathBuf {
    let helper = helper.unwrap_or_else(|| {
        panic!("{HELPER} is not set: point it at a root-owned, mode u+s copy of cosca_testbin (CI's \"Set up setuid-root helper\" step)")
    });
    let path = PathBuf::from(helper);
    let meta = stat(&path).unwrap_or_else(|e| panic!("{HELPER}={path:?} is unreadable: {e}"));
    assert!(meta.is_file, "{HELPER}={path:?} is not a regular file");
    assert!(
        meta.uid == 0 && meta.mode & 0o4000 != 0,
        "{HELPER}={path:?} must be owned by root with the set-user-ID bit (owner uid {}, mode {:o}): chown root and chmod u+s it",
        meta.uid,
        meta.mode & 0o7777
    );
    assert!(
        euid != 0,
        "the caller is root, so the setuid helper is signalable by it and the group tests nothing: run as an unprivileged user"
    );
    path
}
