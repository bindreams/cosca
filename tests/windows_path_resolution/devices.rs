//! M14 (DOS device names, input to #186) and M20 (std's parse of a doubled-separator UNC path).
//! String-level only: no device is opened and no share contacted.

use crate::provenance::survey_platform;
use crate::test_groups::{path_probes, Group};
use crate::winapi::{full_path_name, wide};

#[link(name = "ntdll", kind = "raw-dylib")]
extern "system" {
    /// The device-name check Win32 path conversion uses: `(offset << 16) | length` in bytes of the
    /// device name inside the path, or 0 when the path names no DOS device.
    fn RtlIsDosDeviceName_U(path: *const u16) -> u32;
}

/// M14: for each spelling, the `GetFullPathNameW` result and `RtlIsDosDeviceName_U`'s answer,
/// rendered as the device name it found (`-` for none).
#[skuld::test]
fn m14_device_name_mapping(#[fixture(path_probes)] _group: &Group) {
    survey_platform();
    for name in [
        "NUL",
        "nul",
        "NUL.exe",
        "nul.txt",
        "NUL.tar.gz",
        "NUL ",
        "NUL.",
        "NUL:",
        "NUL  .exe",
        r".\NUL",
        r"C:\x\NUL",
        r"C:\x\NUL.exe",
        r"C:\x\NUL\y.exe",
        r"\\?\C:\x\NUL",
        r"\\.\NUL",
        "CON",
        "CON.exe",
        "CONIN$",
        "CONOUT$",
        "PRN",
        "AUX",
        "COM1",
        "COM9",
        "COM0",
        "COM¹",
        "COM².exe",
        "LPT1",
        "LPT1.exe",
        "LPT³",
        "CLOCK$",
    ] {
        let units = wide(name);
        // SAFETY: `units` is NUL-terminated and outlives the call, which only reads it.
        let found = unsafe { RtlIsDosDeviceName_U(units.as_ptr()) };
        let device = if found == 0 {
            "-".to_owned()
        } else {
            let (offset, len) = ((found >> 16) as usize / 2, (found & 0xFFFF) as usize / 2);
            String::from_utf16_lossy(&units[offset..offset + len])
        };
        let full = full_path_name(name).unwrap_or_else(|why| format!("err({why})"));
        println!("M14 {name:?} device={device} gfpn={full:?}");
    }
}

/// M20: `Path::is_absolute` and the first component of a UNC path with a doubled separator before
/// the share. `main`'s `accepted` reads `is_absolute` first, so this decided whether `main` kept
/// such a `PATH` entry.
#[skuld::test]
fn m20_a_doubled_separator_unc_path_as_std_parses_it(#[fixture(path_probes)] _group: &Group) {
    survey_platform();
    for path in [r"\\srv\\shr", r"\\srv\\shr\tool.exe", r"\\srv\shr\tool.exe"] {
        let p = std::path::Path::new(path);
        let first = p.components().next().map(|c| format!("{c:?}"));
        println!(
            "M20 {path:?} is_absolute={} first={}",
            p.is_absolute(),
            first.as_deref().unwrap_or("-")
        );
    }
}
