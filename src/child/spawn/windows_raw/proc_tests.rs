use std::os::windows::ffi::OsStrExt;

use windows::Win32::Foundation::{ERROR_INVALID_HANDLE, HANDLE};
use windows::Win32::System::Threading::{EXTENDED_STARTUPINFO_PRESENT, STARTUPINFOEXW};

use super::create_process;

/// A failed `GetExitCodeProcess` reports the plain Win32 code. A null handle is a real
/// `ERROR_INVALID_HANDLE`.
///
/// Mutant: `exit_status` propagates the `windows::core::Error` with `?`, whose `io::Error`
/// conversion keeps the HRESULT.
#[skuld::test]
fn a_failed_exit_status_read_is_reported_as_its_win32_code() {
    let err = super::exit_status(HANDLE::default()).expect_err("a null handle has no exit status");
    assert_eq!(err.raw_os_error(), Some(ERROR_INVALID_HANDLE.0 as i32), "{err:?}");
}

/// `CreateProcessW` refusing a working directory surfaces `ERROR_DIRECTORY`, not its HRESULT.
#[skuld::test]
fn a_refused_cwd_is_reported_as_its_win32_code() {
    let base = tempfile::tempdir().unwrap();
    let missing: Vec<u16> = base
        .path()
        .join("missing")
        .as_os_str()
        .encode_wide()
        .chain([0])
        .collect();
    let mut cmdline: Vec<u16> = "cmd /c exit 0\0".encode_utf16().collect();
    let mut si = STARTUPINFOEXW::default();
    let err = create_process(
        None,
        &mut cmdline,
        &mut si,
        None,
        &Some(missing),
        EXTENDED_STARTUPINFO_PRESENT.0,
    )
    .expect_err("a missing cwd must be refused");
    let crate::error::Error::Io(err) = err else {
        panic!("expected Error::Io, got {err:?}");
    };
    assert_eq!(err.raw_os_error(), Some(267), "{err:?}");
    assert_eq!(err.kind(), std::io::ErrorKind::NotADirectory, "{err:?}");
}
