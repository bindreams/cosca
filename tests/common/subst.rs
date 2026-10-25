//! A drive letter mapped to a directory with `DefineDosDeviceW`, for the logon session. System-affecting: only
//! the `DRIVE_MAPPING` tests and `cosca_testbin_cwd` (which includes this file by `#[path]`, so there is
//! one definition) use it.
#![cfg(windows)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{
    DefineDosDeviceW, QueryDosDeviceW, DDD_EXACT_MATCH_ON_REMOVE, DDD_REMOVE_DEFINITION, DEFINE_DOS_DEVICE_FLAGS,
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
    /// Maps `drive` (`X:`) to `target`. Fails, leaving no mapping of ours, when `drive` already had
    /// a definition or another process defined it meanwhile: `DefineDosDeviceW` stacks definitions,
    /// so it succeeds for a letter someone else holds. Two processes racing for one letter both
    /// fail.
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
        let mut mapping = Self {
            drive: drive.to_owned(),
            target,
            removed: false,
        };
        if let Err(held) = mapping.check_sole_definition(&name) {
            return match mapping.remove() {
                Ok(()) => Err(held),
                Err(e) => Err(format!("{held}; {e}")),
            };
        }
        Ok(mapping)
    }

    /// `Ok` when the drive's definitions are exactly ours: `QueryDosDeviceW` lists every target
    /// stacked on the name, each as `\??\<path>`.
    fn check_sole_definition(&self, name: &[u16]) -> Result<(), String> {
        let mut buf = vec![0u16; 32 * 1024];
        // SAFETY: `name` is NUL-terminated; `buf` is a live buffer the call writes at most its length of.
        let n = unsafe { QueryDosDeviceW(PCWSTR(name.as_ptr()), Some(&mut buf)) } as usize;
        if n == 0 {
            return Err(format!(
                "could not query {}: {}",
                self.drive,
                std::io::Error::last_os_error()
            ));
        }
        let targets: Vec<String> = buf[..n]
            .split(|&u| u == 0)
            .filter(|t| !t.is_empty())
            .map(String::from_utf16_lossy)
            .collect();
        let ours = format!(
            r"\??\{}",
            String::from_utf16_lossy(&self.target[..self.target.len() - 1])
        );
        match targets.as_slice() {
            [only] if only.eq_ignore_ascii_case(&ours) => Ok(()),
            _ => Err(format!(
                "{} is not ours alone: its definitions are {targets:?}, ours is {ours:?}",
                self.drive
            )),
        }
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
