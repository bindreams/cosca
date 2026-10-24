//! The `full-path <name>` mode: what this process's own `GetFullPathNameW` makes of `name`, from
//! the cwd and environment block it was started with.

use std::ffi::OsStr;
use std::os::windows::ffi::{OsStrExt, OsStringExt};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{GetLastError, SetLastError, ERROR_ENVVAR_NOT_FOUND, WIN32_ERROR};
use windows::Win32::Storage::FileSystem::GetFullPathNameW;
use windows::Win32::System::Environment::{GetCurrentDirectoryW, GetEnvironmentVariableW};

/// Prints `cwd=` (`GetCurrentDirectoryW`), `var=` (`GetEnvironmentVariableW("=X:")` for `name`'s
/// drive `X:`, or `<unset>`), `full=` (`GetFullPathNameW(name)`, or `err=<code>`), then `var_after=`,
/// read again after the call.
pub fn run(name: &str) {
    let mut buf = vec![0u16; 32 * 1024];
    // SAFETY: `buf` is a live buffer the call writes at most its length of.
    let n = unsafe { GetCurrentDirectoryW(Some(&mut buf)) } as usize;
    assert!(n > 0 && n <= buf.len(), "GetCurrentDirectoryW failed");
    println!("cwd={}", String::from_utf16_lossy(&buf[..n]));

    let drive: Vec<u16> = OsStr::new(name).encode_wide().take(2).collect();
    let var: Vec<u16> = [u16::from(b'=')].into_iter().chain(drive).chain([0]).collect();
    println!("var={}", drive_dir(&var));

    let wide: Vec<u16> = OsStr::new(name).encode_wide().chain([0]).collect();
    // SAFETY: `wide` is NUL-terminated; `buf` is a live buffer the call writes at most its length of.
    let n = unsafe { GetFullPathNameW(PCWSTR(wide.as_ptr()), Some(&mut buf), None) } as usize;
    if n == 0 {
        println!(
            "full=err={}",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        );
    } else {
        assert!(n <= buf.len(), "GetFullPathNameW needs {n} units");
        println!("full={}", std::ffi::OsString::from_wide(&buf[..n]).to_string_lossy());
    }
    println!("var_after={}", drive_dir(&var));
}

/// The value of the NUL-terminated variable `var`, or `<unset>`.
fn drive_dir(var: &[u16]) -> String {
    let mut buf = vec![0u16; 32 * 1024];
    // SAFETY: no preconditions; an empty value returns 0 without setting an error.
    unsafe { SetLastError(WIN32_ERROR(0)) };
    // SAFETY: `var` is NUL-terminated; `buf` is a live buffer the call writes at most its length of.
    let n = unsafe { GetEnvironmentVariableW(PCWSTR(var.as_ptr()), Some(&mut buf)) } as usize;
    if n == 0 {
        // SAFETY: no preconditions.
        let err = unsafe { GetLastError() };
        if err == ERROR_ENVVAR_NOT_FOUND {
            return "<unset>".to_owned();
        }
        assert_eq!(
            err,
            WIN32_ERROR(0),
            "GetEnvironmentVariableW returned 0, neither an empty value nor not-found"
        );
    }
    assert!(n <= buf.len(), "GetEnvironmentVariableW needs {n} units");
    std::ffi::OsString::from_wide(&buf[..n]).to_string_lossy().into_owned()
}
