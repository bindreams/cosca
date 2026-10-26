//! Reparse points a Windows test sets on its own files: `FSCTL_SET_REPARSE_POINT` with a raw
//! buffer, which also allows tags and targets the shell's `mklink` does not.
#![cfg(windows)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GENERIC_WRITE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_MODE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;

/// An app execution alias, as in `%LOCALAPPDATA%\Microsoft\WindowsApps`.
pub const IO_REPARSE_TAG_APPEXECLINK: u32 = 0x8000_001B;
const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;

/// The data of an app execution alias to `target`, under a made-up package.
pub fn app_exec_link_data(target: &OsStr) -> Vec<u8> {
    let mut data = 3u32.to_le_bytes().to_vec();
    for s in [
        OsStr::new("cosca.test_0000000000000"),
        OsStr::new("cosca.test_0000000000000!App"),
        target,
        OsStr::new("0"),
    ] {
        for unit in s.encode_wide().chain([0]) {
            data.extend_from_slice(&unit.to_le_bytes());
        }
    }
    data
}

/// Sets a reparse point with `tag` and `data` on the existing `path`.
pub fn set_reparse(path: &Path, tag: u32, data: &[u8]) -> Result<(), String> {
    let mut buffer = tag.to_le_bytes().to_vec();
    buffer.extend_from_slice(&(data.len() as u16).to_le_bytes());
    buffer.extend_from_slice(&0u16.to_le_bytes());
    buffer.extend_from_slice(data);
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    // SAFETY: `wide` is NUL-terminated and outlives the call.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    }
    .map_err(|e| format!("CreateFileW: err={}", e.code().0 & 0xFFFF))?;
    // SAFETY: `handle` is live; `buffer` is a whole reparse buffer of the length passed.
    let set = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_SET_REPARSE_POINT,
            Some(buffer.as_ptr().cast()),
            buffer.len() as u32,
            None,
            0,
            None,
            None,
        )
    };
    // SAFETY: `handle` is owned here and closed once.
    let _ = unsafe { CloseHandle(handle) };
    set.map_err(|e| format!("FSCTL_SET_REPARSE_POINT: err={}", e.code().0 & 0xFFFF))
}
