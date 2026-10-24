//! Path-canary payload: report the file this process was loaded from, then exit 0.
//!
//! `tests/windows_path_resolution.rs` copies this image to odd names and spawns it, so its only
//! job is to say which file ran. It depends on nothing else in the testbin, so a testbin change
//! cannot fail the canary. Two optional flags serve a launch whose stdout cannot be read
//! (`ShellExecuteEx`'s `runas`): `--report-to <path>` writes the same lines to `<path>` as well, and
//! `--dump-env-to <path>` writes this process's raw `GetEnvironmentStringsW` block to `<path>`,
//! UTF-16LE, through its closing empty entry.
//!
//! Prints four lines:
//! - `image=`: `QueryFullProcessImageNameW`, the file the image section was created from. This is
//!   the proof of which file loaded.
//! - `module=`: `std::env::current_exe` (`GetModuleFileNameW`), the name the loader recorded.
//!   Printed for the record only: it is not guaranteed to name the same file.
//! - `cwd=`: the current directory, which a `ShellExecuteEx` launch takes from `lpDirectory`.
//! - `elevated=`: `1` or `0`, the token's `TokenElevation`.
//!
//! Exits 2 if `image=` could not be measured. A `[[bin]]` cannot be `cfg`-ed out, so off Windows
//! it exits 1.

#[cfg(windows)]
fn main() {
    use windows::core::PWSTR;
    use windows::Win32::System::Threading::{GetCurrentProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32};

    let mut buf = vec![0u16; 32 * 1024];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` is a live allocation of `len` units, which the call writes at most that many
    // of; the pseudo-handle needs no closing.
    let got = unsafe {
        QueryFullProcessImageNameW(
            GetCurrentProcess(),
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
    };
    let module = match std::env::current_exe() {
        Ok(p) => format!("module={}", p.display()),
        Err(e) => format!("module-error={e}"),
    };
    let (image, code) = match got {
        Ok(()) => (format!("image={}", String::from_utf16_lossy(&buf[..len as usize])), 0),
        Err(e) => (format!("image-error={e}"), 2),
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => format!("cwd={}", p.display()),
        Err(e) => format!("cwd-error={e}"),
    };
    let elevated = match is_elevated() {
        Ok(e) => format!("elevated={}", u8::from(e)),
        Err(e) => format!("elevated-error={e}"),
    };
    let report = format!("{module}\n{image}\n{cwd}\n{elevated}\n");
    print!("{report}");
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let mut flags = args.iter();
    while let Some(flag) = flags.next() {
        let path = flags.next().unwrap_or_else(|| panic!("{flag:?} needs a path argument"));
        if flag == "--report-to" {
            std::fs::write(path, &report).expect("write the report file");
        } else if flag == "--dump-env-to" {
            std::fs::write(path, env_block()).expect("write the env dump");
        } else {
            panic!("unknown argument {flag:?}");
        }
    }
    std::process::exit(code);
}

/// This process's environment block, UTF-16LE, through the empty entry that closes it. Copied from
/// `env_block.rs` on purpose: this image depends on nothing else in the testbin.
#[cfg(windows)]
fn env_block() -> Vec<u8> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Environment::{FreeEnvironmentStringsW, GetEnvironmentStringsW};

    // SAFETY: no preconditions; the block is freed below.
    let block = unsafe { GetEnvironmentStringsW() };
    assert!(!block.is_null(), "GetEnvironmentStringsW failed");
    // SAFETY: the block is a run of NUL-terminated entries closed by an empty one, so every read up
    // to the first two NULs in a row is in bounds.
    let end = (1..)
        .find(|&i| unsafe { *block.0.add(i - 1) == 0 && *block.0.add(i) == 0 })
        .unwrap();
    // SAFETY: the `end + 1` units starting at `block` were just read.
    let units = unsafe { std::slice::from_raw_parts(block.0, end + 1) };
    let bytes = units.iter().flat_map(|u| u.to_le_bytes()).collect();
    // SAFETY: `block` came from `GetEnvironmentStringsW` and is freed once.
    unsafe { FreeEnvironmentStringsW(PCWSTR(block.0)) }.expect("FreeEnvironmentStringsW");
    bytes
}

/// Whether this process's token is elevated (`TokenElevation`).
#[cfg(windows)]
fn is_elevated() -> windows::core::Result<bool> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = HANDLE::default();
    // SAFETY: the pseudo-handle needs no closing; `token` is closed below.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }?;
    let mut elevation = TOKEN_ELEVATION::default();
    let mut len = 0u32;
    // SAFETY: `elevation` is a live `TOKEN_ELEVATION` of the size passed.
    let got = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some((&raw mut elevation).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    };
    // SAFETY: `token` was opened above and is closed once.
    unsafe { CloseHandle(token) }?;
    got.map(|()| elevation.TokenIsElevated != 0)
}

#[cfg(not(windows))]
fn main() {
    eprintln!("cosca_testbin_image is a Windows canary payload");
    std::process::exit(1);
}
