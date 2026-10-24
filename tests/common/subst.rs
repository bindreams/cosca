//! A drive letter mapped to a directory with `DefineDosDeviceW`, for the logon session. System-affecting: only
//! the `DRIVE_MAPPING` tests and `cosca_testbin_cwd` (which includes this file by `#[path]`, so there is
//! one definition) use it.
#![cfg(windows)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{
    DefineDosDeviceW, DDD_EXACT_MATCH_ON_REMOVE, DDD_REMOVE_DEFINITION, DEFINE_DOS_DEVICE_FLAGS,
};

/// The mapping lives until [`Subst::remove`] or drop. Drop only prints a failed removal, since it
/// runs while unwinding too and a second panic would abort; a caller that must fail on it calls
/// `remove` on its success path.
pub struct Subst {
    drive: String,
    target: Vec<u16>,
    removed: bool,
}

impl Subst {
    pub fn new(drive: &str, target: &Path) -> Result<Self, String> {
        let name: Vec<u16> = OsStr::new(drive).encode_wide().chain([0]).collect();
        let target: Vec<u16> = target.as_os_str().encode_wide().chain([0]).collect();
        // SAFETY: both strings are NUL-terminated and outlive the call.
        unsafe {
            DefineDosDeviceW(
                DEFINE_DOS_DEVICE_FLAGS(0),
                PCWSTR(name.as_ptr()),
                PCWSTR(target.as_ptr()),
            )
        }
        .map_err(|e| format!("{e}"))?;
        Ok(Self {
            drive: drive.to_owned(),
            target,
            removed: false,
        })
    }

    /// Removes the mapping; a second call is a no-op.
    pub fn remove(&mut self) -> Result<(), String> {
        if self.removed {
            return Ok(());
        }
        let name: Vec<u16> = OsStr::new(&self.drive).encode_wide().chain([0]).collect();
        // SAFETY: both strings are NUL-terminated and outlive the call.
        unsafe {
            DefineDosDeviceW(
                DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE,
                PCWSTR(name.as_ptr()),
                PCWSTR(self.target.as_ptr()),
            )
        }
        .map_err(|e| format!("could not remove the {} mapping: {e}", self.drive))?;
        self.removed = true;
        Ok(())
    }
}

impl Drop for Subst {
    fn drop(&mut self) {
        if let Err(e) = self.remove() {
            eprintln!("{e}");
        }
    }
}
