//! Path-canary payload: report the file this process was loaded from, then exit 0.
//!
//! `tests/windows_path_resolution.rs` copies this image to odd names and spawns it, so its only
//! job is to say which file ran. It ignores its arguments and depends on nothing else in the
//! testbin, so a testbin change cannot fail the canary.
//!
//! Prints two lines:
//! - `image=`: `QueryFullProcessImageNameW`, the file the image section was created from. This is
//!   the proof of which file loaded.
//! - `module=`: `std::env::current_exe` (`GetModuleFileNameW`), the name the loader recorded.
//!   Printed for the record only: it is not guaranteed to name the same file.
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
    match std::env::current_exe() {
        Ok(p) => println!("module={}", p.display()),
        Err(e) => println!("module-error={e}"),
    }
    match got {
        Ok(()) => println!("image={}", String::from_utf16_lossy(&buf[..len as usize])),
        Err(e) => {
            println!("image-error={e}");
            std::process::exit(2);
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("cosca_testbin_image is a Windows canary payload");
    std::process::exit(1);
}
