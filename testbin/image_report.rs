//! Path-canary payload: report the file this process was loaded from, then exit 0.
//!
//! `tests/windows_path_resolution.rs` copies this image to odd names and spawns it, so its only
//! job is to say which file ran. It depends on nothing else in the testbin, so a testbin change
//! cannot fail the canary. Its one argument is optional: `--report-to <path>` writes the same lines
//! to `<path>` as well, for a launch whose stdout cannot be read (`ShellExecuteEx`'s `runas`).
//!
//! Prints three lines:
//! - `image=`: `QueryFullProcessImageNameW`, the file the image section was created from. This is
//!   the proof of which file loaded.
//! - `module=`: `std::env::current_exe` (`GetModuleFileNameW`), the name the loader recorded.
//!   Printed for the record only: it is not guaranteed to name the same file.
//! - `cwd=`: the current directory, which a `ShellExecuteEx` launch takes from `lpDirectory`.
//!
//! Exits 2 if `image=` could not be measured. A `[[bin]]` cannot be `cfg`-ed out, so off Windows
//! it exits 1.

// See `src/lib.rs`'s header for why: this bin is its own clippy-linted crate root, so it needs
// its own copy of the deny.
#![deny(clippy::allow_attributes_without_reason)]

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
    let report = format!("{module}\n{image}\n{cwd}\n");
    print!("{report}");
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    if let [flag, path] = args.as_slice() {
        if flag == "--report-to" {
            std::fs::write(path, &report).expect("write the report file");
        }
    }
    std::process::exit(code);
}

#[cfg(not(windows))]
fn main() {
    eprintln!("cosca_testbin_image is a Windows canary payload");
    std::process::exit(1);
}
