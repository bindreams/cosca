//! M15: the `long-image <base> <image>` mode, in both halves of the manifest pair
//! (`cosca_testbin_cwd` is long-path aware, `cosca_testbin` is not).
//!
//! Prints `long_paths_enabled=` (`RtlAreLongPathsEnabled`: the manifest and the `LongPathsEnabled`
//! policy together), then one line per name: `CreateProcessW` given a copy of `<image>` as
//! `lpApplicationName` of 259, 260 and 300 units, plain and `\\?\` (the prefix counted). A launch
//! reports `ok,loaded_target=<bool>`: whether the child's own image is that copy.

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

#[link(name = "ntdll", kind = "raw-dylib")]
extern "system" {
    fn RtlAreLongPathsEnabled() -> u8;
}

/// Whether this process may use paths past `MAX_PATH`: its manifest opts in AND the
/// `LongPathsEnabled` policy is set.
pub fn long_paths_enabled() -> bool {
    // SAFETY: no arguments; reads this process's own state.
    unsafe { RtlAreLongPathsEnabled() != 0 }
}

pub fn run(base: &str, image: &str) {
    println!("long_paths_enabled={}", long_paths_enabled());
    let base = Path::new(base);
    let report = base.join("report.txt");
    for units in [259, 260, 300] {
        for (form, prefix) in [("plain", ""), ("verbatim", r"\\?\")] {
            let plain_units = units - prefix.len();
            let dir = crate::measure::dir_of_len(&base.join(format!("{form}{units}")), plain_units - r"\t.exe".len());
            let file = dir.join("t.exe");
            std::fs::copy(image, &file).unwrap_or_else(|e| panic!("copy the image to {file:?}: {e}"));
            let mut name = OsString::from(prefix);
            name.push(&file);
            assert_eq!(
                name.encode_wide().count(),
                units,
                "precondition: the name is {units} units"
            );
            println!("{form}_{units}={}", launch(&name, &file, &report));
        }
    }
}

/// `CreateProcessW(lpApplicationName = name)`, the child writing its report to `report`.
fn launch(name: &OsStr, file: &Path, report: &Path) -> String {
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        CreateProcessW, WaitForSingleObject, INFINITE, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION,
        STARTF_USESTDHANDLES, STARTUPINFOW,
    };
    if let Err(e) = std::fs::remove_file(report) {
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "remove {report:?}: {e}");
    }
    let app: Vec<u16> = name.encode_wide().chain([0]).collect();
    let mut line = OsString::from("t --report-to \"");
    line.push(report);
    line.push("\"");
    let mut line: Vec<u16> = line.encode_wide().chain([0]).collect();
    // Null std handles: the child reports through the file only.
    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESTDHANDLES,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    // SAFETY: `app` and `line` are NUL-terminated and outlive the call; `line` is writable; `si`
    // and `pi` are live.
    let created = unsafe {
        CreateProcessW(
            PCWSTR(app.as_ptr()),
            Some(PWSTR(line.as_mut_ptr())),
            None,
            None,
            false,
            PROCESS_CREATION_FLAGS(0),
            None,
            PCWSTR::null(),
            &si,
            &mut pi,
        )
    };
    if let Err(e) = created {
        return format!("err={}", e.code().0 & 0xFFFF);
    }
    // SAFETY: `pi`'s handles are live and owned here, each closed once after the wait. The child
    // is `cosca_testbin_image`, which exits on its own.
    unsafe {
        WaitForSingleObject(pi.hProcess, INFINITE);
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
    }
    let text = match std::fs::read_to_string(report) {
        Ok(text) => text,
        Err(e) => return format!("ok,no report ({e})"),
    };
    match text.lines().find_map(|l| l.strip_prefix("image=")) {
        Some(image) => {
            let image = image.strip_prefix(r"\\?\").unwrap_or(image);
            format!(
                "ok,loaded_target={}",
                image.eq_ignore_ascii_case(&file.to_string_lossy())
            )
        }
        None => "ok,no image= line".to_owned(),
    }
}
