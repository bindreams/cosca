//! Which OS build a run measured, stamped on every test's output.

use crate::pure::read_growing;

use crate::winapi::wide;
use std::sync::OnceLock;
use windows::core::PCWSTR;
use windows::Wdk::System::SystemServices::RtlGetVersion;
use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ};
use windows::Win32::System::SystemInformation::OSVERSIONINFOW;

/// The OS build a run measured: one line for stamping, one block for the top of the log.
pub(crate) struct Platform {
    summary: String,
    detail: String,
}

/// A registry string under `HKLM`, or the Win32 error that stopped it being read. A value that
/// grows while being read is read again at its new size.
pub(crate) fn reg_sz(subkey: &str, value: &str) -> Result<String, String> {
    use std::os::windows::ffi::OsStringExt;
    let (subkey_w, value_w) = (wide(subkey), wide(value));
    let buf = read_growing(|buf, bytes| {
        // SAFETY: both name buffers are nul-terminated and outlive the call; `buf` is a live
        // allocation of `*bytes` bytes that the call writes at most that many bytes into.
        unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(subkey_w.as_ptr()),
                PCWSTR(value_w.as_ptr()),
                RRF_RT_REG_SZ,
                None,
                Some(buf.as_mut_ptr().cast()),
                Some(bytes),
            )
        }
        .0
    })
    .map_err(|rc| format!("RegGetValueW failed: error {rc}"))?;
    let units = buf.iter().position(|&u| u == 0).unwrap_or(buf.len());
    Ok(std::ffi::OsString::from_wide(&buf[..units])
        .to_string_lossy()
        .into_owned())
}

/// A registry `REG_DWORD` under `HKLM`, or the Win32 error that stopped it being read.
pub(crate) fn reg_dword(subkey: &str, value: &str) -> Result<u32, String> {
    let (subkey_w, value_w) = (wide(subkey), wide(value));
    let mut data = 0u32;
    let mut bytes = size_of::<u32>() as u32;
    // SAFETY: both name buffers are nul-terminated and outlive the call; `data` is a live
    // four-byte out-parameter and `bytes` says so.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_w.as_ptr()),
            PCWSTR(value_w.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(std::ptr::addr_of_mut!(data).cast()),
            Some(&mut bytes),
        )
    };
    if rc.0 != 0 {
        return Err(format!("RegGetValueW failed: error {}", rc.0));
    }
    Ok(data)
}

/// `Ok` rendered, `Err` rendered as the reason it is missing — for enrichment that must not sink
/// the run if one image lacks a value.
pub(crate) fn or_missing<T: std::fmt::Display>(v: Result<T, String>) -> String {
    v.map_or_else(|why| format!("<absent: {why}>"), |v| v.to_string())
}

/// What `windows-latest` meant on THIS run.
///
/// The label floats: the image behind it is replaced every few weeks, so a measurement filed under
/// the label alone stops being reproducible as soon as the label moves. `RtlGetVersion` is the
/// version call Windows does not shim per application manifest, and `UBR` is the patch level it
/// does not carry; together they are the full four-part build.
pub(crate) fn measure_platform() -> Result<Platform, String> {
    const KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let mut info = OSVERSIONINFOW {
        dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32,
        ..Default::default()
    };
    // SAFETY: `info` is a live, correctly sized out-parameter whose `dwOSVersionInfoSize` is set,
    // which is the one precondition the call has.
    let status = unsafe { RtlGetVersion(&mut info) };
    if status.is_err() {
        return Err(format!("RtlGetVersion failed: NTSTATUS {:#010x}", status.0));
    }
    let ubr = reg_dword(KEY, "UBR");
    let build = match &ubr {
        Ok(ubr) => format!(
            "{}.{}.{}.{ubr}",
            info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber
        ),
        Err(_) => format!(
            "{}.{}.{}.?",
            info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber
        ),
    };
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| "<unset>".to_string());
    // Each value read once, so the stamp and the detail block cannot disagree.
    let display_version = or_missing(reg_sz(KEY, "DisplayVersion"));
    let edition = or_missing(reg_sz(KEY, "EditionID"));
    let (image_os, image_version) = (env("ImageOS"), env("ImageVersion"));
    let arch = std::env::consts::ARCH;
    let summary = format!("{build} {display_version} {edition} / {arch} / runner image {image_os} {image_version}");
    let detail = format!(
        "\n\
         ===== PLATFORM =========================================================\n\
         This is what the floating label resolved to on this run. Quote THIS, not the label.\n\
        \x20 OS build (RtlGetVersion + UBR) : {build}\n\
        \x20 DisplayVersion                 : {display_version}\n\
        \x20 ProductName                    : {}\n\
        \x20 EditionID                      : {edition}\n\
        \x20 BuildLabEx                     : {}\n\
        \x20 CSD version                    : {:?}\n\
        \x20 process architecture           : {arch}\n\
        \x20 PROCESSOR_ARCHITECTURE         : {}\n\
        \x20 runner label / image           : {} / {image_os} {image_version}\n\
        \x20 RUNNER_OS / RUNNER_ARCH        : {} / {}\n\
         ========================================================================",
        or_missing(reg_sz(KEY, "ProductName")),
        or_missing(reg_sz(KEY, "BuildLabEx")),
        String::from_utf16_lossy(&info.szCSDVersion)
            .trim_end_matches('\0')
            .to_string(),
        env("PROCESSOR_ARCHITECTURE"),
        env("RUNNER_NAME"),
        env("RUNNER_OS"),
        env("RUNNER_ARCH"),
    );
    Ok(Platform { summary, detail })
}

pub(crate) static PLATFORM: OnceLock<Result<Platform, String>> = OnceLock::new();

pub(crate) static DETAIL_CLAIMED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Stamp this test's output with the OS build it is measuring.
///
/// The first caller prints the whole block, every later one a single line, so the detail sits at
/// the top of the log exactly once however the tests are ordered. `swap` decides who "first" is,
/// rather than a read-then-write that two threads could both win.
pub(crate) fn announce_platform() -> Result<(), String> {
    match PLATFORM.get_or_init(measure_platform) {
        Ok(platform) => {
            if DETAIL_CLAIMED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                println!("platform: {}", platform.summary);
            } else {
                println!("{}", platform.detail);
            }
            Ok(())
        }
        Err(why) => Err(format!(
            "the OS build this run measured could not be identified, so no measurement here has \
             provenance: {why}"
        )),
    }
}

/// [`announce_platform`] for a survey: a missing build is printed, not raised, since a survey
/// fails only on its own scaffolding.
pub(crate) fn survey_platform() {
    if let Err(why) = announce_platform() {
        println!("PROVENANCE MISSING: {why}");
    }
}
