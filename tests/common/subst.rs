//! A drive letter mapped to a directory with `DefineDosDeviceW`, for the logon session. System-affecting: only
//! the `DRIVE_MAPPING` tests and `cosca_testbin_cwd` (which includes this file by `#[path]`, so there is
//! one definition) use it.
#![cfg(windows)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{
    DefineDosDeviceW, GetLogicalDrives, QueryDosDeviceW, DDD_EXACT_MATCH_ON_REMOVE, DDD_REMOVE_DEFINITION,
    DEFINE_DOS_DEVICE_FLAGS,
};

const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_INSUFFICIENT_BUFFER: i32 = 122;

/// The mapping lives until [`Subst::remove`] or drop. Drop only prints a failed removal, since it
/// runs while unwinding too and a second panic would abort; a caller that must fail on it calls
/// `remove` on its success path.
pub struct Subst {
    drive: String,
    target: Vec<u16>,
    removed: bool,
}

/// Why a letter could not be mapped.
#[derive(Debug)]
pub enum MapError {
    /// The letter's definitions were not just ours over the expected ones. Ours is removed again.
    Held(String),
    /// Ours could not be defined, checked or removed.
    Failed(String),
}

impl std::fmt::Display for MapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Held(why) | Self::Failed(why) => f.write_str(why),
        }
    }
}

impl Subst {
    /// Maps the highest letter from `Z:` down to `M:` that nothing else defines to `target`. It
    /// skips the letters `GetLogicalDrives` reports, then defines first and looks, and gives up a
    /// letter whose definitions are not ours alone: another process may define it in between.
    pub fn map_free(target: &Path) -> Result<Self, String> {
        // SAFETY: no arguments; reads the drives this logon session sees.
        let mask = unsafe { GetLogicalDrives() };
        for letter in (b'M'..=b'Z').rev().filter(|l| mask & (1 << (l - b'A')) == 0) {
            match Self::new(&format!("{}:", letter as char), target) {
                Ok(subst) => return Ok(subst),
                Err(MapError::Held(_)) => continue,
                Err(MapError::Failed(why)) => return Err(why),
            }
        }
        Err("every letter from M: to Z: is already defined".to_owned())
    }

    /// Maps `drive` (`X:`) to `target`. Fails, leaving no mapping of ours, when `drive` already had
    /// a definition or another process defined it meanwhile: `DefineDosDeviceW` stacks definitions,
    /// so it succeeds for a letter someone else holds. Two processes racing for one letter both
    /// fail.
    pub fn new(drive: &str, target: &Path) -> Result<Self, MapError> {
        Self::define(drive, target, &[])
    }

    /// Maps `under`'s letter to `target` on top of `under`, which shadows it until this one is
    /// removed. Fails, leaving no mapping of ours, unless the letter's definitions are exactly this
    /// one over `under`'s.
    pub fn over(under: &Subst, target: &Path) -> Result<Self, MapError> {
        Self::define(&under.drive, target, &[under.listed()])
    }

    fn define(drive: &str, target: &Path, below: &[String]) -> Result<Self, MapError> {
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
        .map_err(|e| MapError::Failed(format!("could not map {drive}: {e}")))?;
        let mut mapping = Self {
            drive: drive.to_owned(),
            target,
            removed: false,
        };
        let held = match definitions(drive) {
            Err(code) => MapError::Failed(format!("could not query {drive}: QueryDosDeviceW err={code}")),
            Ok(all) => {
                let ours = mapping.listed();
                let expected = || std::iter::once(&ours).chain(below);
                if all.len() == below.len() + 1 && all.iter().zip(expected()).all(|(a, e)| a.eq_ignore_ascii_case(e)) {
                    return Ok(mapping);
                }
                let expected: Vec<&String> = expected().collect();
                MapError::Held(format!("{drive}'s definitions are {all:?}, expected {expected:?}"))
            }
        };
        match mapping.remove() {
            Ok(()) => Err(held),
            Err(e) => Err(MapError::Failed(format!("{held}; {e}"))),
        }
    }

    /// This mapping as `QueryDosDeviceW` lists it: `\??\<target>`.
    fn listed(&self) -> String {
        format!(
            r"\??\{}",
            String::from_utf16_lossy(&self.target[..self.target.len() - 1])
        )
    }

    pub fn drive(&self) -> &str {
        &self.drive
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

/// Every definition of `drive` (`X:`), newest first, each as `\??\<path>`, or the OS error code:
/// `ERROR_FILE_NOT_FOUND` when it has none.
fn definitions(drive: &str) -> Result<Vec<String>, i32> {
    let name: Vec<u16> = OsStr::new(drive).encode_wide().chain([0]).collect();
    let mut buf = vec![0u16; 1024];
    loop {
        // SAFETY: `name` is NUL-terminated; `buf` is a live buffer the call writes at most its length of.
        let n = unsafe { QueryDosDeviceW(PCWSTR(name.as_ptr()), Some(&mut buf)) } as usize;
        if n != 0 {
            return Ok(buf[..n]
                .split(|&u| u == 0)
                .filter(|s| !s.is_empty())
                .map(String::from_utf16_lossy)
                .collect());
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(ERROR_INSUFFICIENT_BUFFER) => buf.resize(buf.len() * 2, 0),
            other => return Err(other.unwrap_or(-1)),
        }
    }
}

/// Panics unless `drive` has no definition at all.
pub fn assert_undefined(drive: &str) {
    match definitions(drive) {
        Err(ERROR_FILE_NOT_FOUND) => {}
        other => panic!("{drive} should have no definition left: {other:?}"),
    }
}
