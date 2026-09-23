//! Windows path-resolution canary: how Windows and `std::process` normalise path strings, checked
//! on a real Windows runner.
//!
//! cosca's `.bat`/`.cmd` gate (CVE-2024-24576) rests on a model of how Windows normalises path
//! strings, and that model depends on platform facts like these: how trailing dots and spaces,
//! `.`/`..`, verbatim `\\?\` prefixes, UNC and device roots and stream suffixes resolve.
//! `windows-latest` is a floating label: a Windows build can change those facts with no commit
//! here, so the `windows-probes` workflow runs this file on pull requests touching the code that
//! depends on it, weekly, and on demand.
//!
//! This file describes the platform only. It does not say what any gate in the tree does.
//!
//! # Two kinds of test
//!
//! **Canaries** assert a platform fact and FAIL when Windows disagrees, when an asserted
//! measurement could not be taken, or when they checked nothing at all. A failure means any code modelling that fact must be re-derived
//! from the new behaviour; do not loosen the assertion.
//!
//! **Surveys**, and the rows a canary prints without asserting, only print. A Win32 error there is
//! printed as the measurement, not raised, so a change in behaviour nothing asserts on never turns
//! the run red. They fail only if their own scaffolding (a temp directory) cannot be set up.
//!
//! Every test stamps its output with the OS build it ran on.
//!
//! # How to run it
//!
//! ```text
//! cargo test --test windows_path_resolution -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `#[ignore]`d so that an ordinary `cargo test` never mistakes a platform measurement for coverage
//! of cosca. The canary's own string logic is tested by `windows_path_logic`, which runs by default
//! on every host. `GetFullPathNameW` works on the string alone and touches no disk or network, so
//! UNC and device inputs here reach no server or device. The file and spawn tests write only inside
//! a `tempfile` directory of their own and launch only `cosca_testbin_image`. Nothing here runs a
//! batch file or needs elevation. Temp directories are removed on drop and planted files
//! explicitly, but a removal failure is only printed; whatever it leaves goes with the ephemeral
//! runner.
#![cfg(windows)]

#[path = "windows_path_resolution/pure.rs"]
mod pure;

use std::sync::OnceLock;

use pure::{compare_across_roots, pop_past_expectation, read_growing, rooted_prefix, verbatim_spelling};

use windows::core::{PCWSTR, PWSTR};
use windows::Wdk::System::SystemServices::RtlGetVersion;
use windows::Win32::Foundation::{CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0};
use windows::Win32::Storage::FileSystem::{FileIdInfo, GetFileInformationByHandleEx, GetFullPathNameW, FILE_ID_INFO};
use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ};
use windows::Win32::System::SystemInformation::OSVERSIONINFOW;
use windows::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, WaitForSingleObject, CREATE_NO_WINDOW, INFINITE, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOW,
};

// Measuring helpers =====

fn wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

// Provenance =====

/// The OS build a run measured: one line for stamping, one block for the top of the log.
struct Platform {
    summary: String,
    detail: String,
}

/// A registry string under `HKLM`, or the Win32 error that stopped it being read. A value that grows
/// while being read is read again at its new size.
fn reg_sz(subkey: &str, value: &str) -> Result<String, String> {
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
fn reg_dword(subkey: &str, value: &str) -> Result<u32, String> {
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
fn or_missing<T: std::fmt::Display>(v: Result<T, String>) -> String {
    v.map_or_else(|why| format!("<absent: {why}>"), |v| v.to_string())
}

/// What `windows-latest` meant on THIS run.
///
/// The label floats: the image behind it is replaced every few weeks, so a measurement filed under
/// the label alone stops being reproducible as soon as the label moves. `RtlGetVersion` is the
/// version call Windows does not shim per application manifest, and `UBR` is the patch level it
/// does not carry; together they are the full four-part build.
fn measure_platform() -> Result<Platform, String> {
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

static PLATFORM: OnceLock<Result<Platform, String>> = OnceLock::new();
static DETAIL_CLAIMED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Stamp this test's output with the OS build it is measuring.
///
/// The first caller prints the whole block, every later one a single line, so the detail sits at
/// the top of the log exactly once however the tests are ordered. `swap` decides who "first" is,
/// rather than a read-then-write that two threads could both win.
fn announce_platform() -> Result<(), String> {
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
fn survey_platform() {
    if let Err(why) = announce_platform() {
        println!("PROVENANCE MISSING: {why}");
    }
}

/// `GetFullPathNameW(input)` as the resolved path plus its `lpFilePart`, or an error describing
/// why no measurement was taken.
///
/// `lpFilePart` is the second half of the answer and not a decoration: Win32 sets it to the final
/// component of the result, or to NULL when the result names a directory. So it says directly
/// whether `C:\dir\...` came back still naming a file.
fn full_path_name_parts(input: &str) -> Result<(String, Option<String>), String> {
    use std::os::windows::ffi::OsStringExt;
    let input_w = wide(input);
    let mut buf = vec![0u16; 1024];
    let mut file_part = PWSTR::null();
    // SAFETY: `input_w` is nul-terminated and outlives the call; `buf` is a live, correctly sized
    // slice and the function writes at most `buf.len()` units into it; `file_part` is a live
    // out-pointer the function sets to an interior pointer of `buf`.
    let len = unsafe { GetFullPathNameW(PCWSTR(input_w.as_ptr()), Some(&mut buf), Some(&mut file_part)) };
    if len == 0 {
        return Err(format!(
            "GetFullPathNameW({input:?}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if len as usize >= buf.len() {
        return Err(format!(
            "GetFullPathNameW({input:?}) wants {len} units; the probe gave 1024"
        ));
    }
    let resolved = std::ffi::OsString::from_wide(&buf[..len as usize])
        .to_string_lossy()
        .into_owned();
    let part = if file_part.is_null() {
        None
    } else {
        // SAFETY: on success Win32 points `file_part` into `buf` at the final component, which is
        // nul-terminated inside the prefix it just wrote. `buf` is still alive.
        Some(unsafe { file_part.to_string() }.map_err(|e| format!("lpFilePart of {input:?} is not UTF-16: {e}"))?)
    };
    Ok((resolved, part))
}

/// `GetFullPathNameW(input)`, resolved path only.
fn full_path_name(input: &str) -> Result<String, String> {
    full_path_name_parts(input).map(|(resolved, _)| resolved)
}

/// `GetFullPathNameW(input)` reported at the UTF-16 unit level.
///
/// A result that looks cut off — `\\?\C:` with no trailing separator, say — was cut off either by
/// Win32 or by the probe, and a trimmed `String` cannot tell the two apart. So this reports the
/// length Win32 returned, the length an independent size query says it should be, the raw units
/// including the ones past the end of the answer, and where `lpFilePart` points inside the buffer.
/// The buffer is poisoned first, so "Win32 wrote nothing here" is visible rather than inferred.
fn full_path_name_raw(input: &str) -> Result<String, String> {
    use std::fmt::Write as _;
    const CAP: usize = 1024;
    const POISON: u16 = 0xFEED;

    let input_w = wide(input);
    // The size query first, with no buffer at all: on success it returns the length INCLUDING the
    // terminating nul, so it is a witness to the answer's length that the write call below cannot
    // influence. A probe buffer too small to hold the answer cannot fake agreement between them.
    // SAFETY: `input_w` is nul-terminated and outlives the call; passing no buffer is the
    // documented size-query form, in which the function writes nothing.
    let needed = unsafe { GetFullPathNameW(PCWSTR(input_w.as_ptr()), None, None) };
    if needed == 0 {
        return Err(format!(
            "GetFullPathNameW({input:?}) size query failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut buf = vec![POISON; CAP];
    let mut file_part = PWSTR::null();
    // SAFETY: as above; `buf` is a live slice of `CAP` units that the call writes at most `CAP`
    // units into, and `file_part` is a live out-pointer set to an interior pointer of `buf`.
    let len = unsafe { GetFullPathNameW(PCWSTR(input_w.as_ptr()), Some(&mut buf), Some(&mut file_part)) };
    if len == 0 {
        return Err(format!(
            "GetFullPathNameW({input:?}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if len as usize >= CAP {
        return Err(format!(
            "GetFullPathNameW({input:?}) wants {len} units; the probe gave {CAP}"
        ));
    }

    let show = (len as usize + 4).min(CAP);
    let units: Vec<String> = buf[..show]
        .iter()
        .enumerate()
        .map(|(i, &u)| {
            let value = match u {
                0 => "NUL".to_string(),
                POISON => "POISON".to_string(),
                _ => char::from_u32(u32::from(u)).map_or_else(|| "?".to_string(), |c| format!("'{c}'")),
            };
            let end = if i == len as usize { "|len ends|" } else { "" };
            format!("{end}{i}:{u:#06x}={value}")
        })
        .collect();

    let mut out = String::new();
    let w = &mut out;
    writeln!(
        w,
        "  probe buffer            : {CAP} units, pre-filled with {POISON:#06x}"
    )
    .unwrap();
    writeln!(
        w,
        "  size query (no buffer)  : {needed} units = {} of text + 1 nul",
        needed.saturating_sub(1)
    )
    .unwrap();
    writeln!(
        w,
        "  write call returned     : {len} units{}",
        if len + 1 == needed {
            " — agrees with the size query, so nothing was lost"
        } else {
            " — DISAGREES with the size query"
        }
    )
    .unwrap();
    writeln!(w, "  raw units               : {}", units.join(" ")).unwrap();
    writeln!(
        w,
        "  unit at index {len:<10}: {:#06x} ({})",
        buf[len as usize],
        if buf[len as usize] == 0 {
            "NUL — Win32 terminated the string exactly there"
        } else {
            "NOT nul — Win32 wrote past its own returned length"
        }
    )
    .unwrap();

    use std::os::windows::ffi::OsStringExt;
    let resolved = std::ffi::OsString::from_wide(&buf[..len as usize])
        .to_string_lossy()
        .into_owned();
    writeln!(w, "  resolved string         : {resolved:?}").unwrap();
    writeln!(w, "  ends with a separator   : {}", resolved.ends_with('\\')).unwrap();

    if file_part.is_null() {
        writeln!(
            w,
            "  lpFilePart              : NULL — Win32 says the result names a directory"
        )
        .unwrap();
    } else {
        let base = buf.as_ptr() as usize;
        let at = file_part.0 as usize;
        if at < base || at >= base + CAP * 2 {
            writeln!(
                w,
                "  lpFilePart              : {at:#x}, OUTSIDE the probe buffer ({base:#x}..{:#x})",
                base + CAP * 2
            )
            .unwrap();
        } else {
            // SAFETY: the pointer is inside `buf`, which Win32 nul-terminated within the prefix it
            // wrote, and `buf` is still alive.
            let text =
                unsafe { file_part.to_string() }.map_err(|e| format!("lpFilePart of {input:?} is not UTF-16: {e}"))?;
            writeln!(
                w,
                "  lpFilePart              : inside the buffer at unit offset {} of {len}, reads {text:?}",
                (at - base) / 2
            )
            .unwrap();
        }
    }
    Ok(out)
}

/// std's `has_bat_extension`, verbatim: a case-insensitive `ends_with` of `.bat` or `.cmd` on the
/// RESOLVED path. This is the predicate that decides whether `std::process` swaps in `cmd.exe`.
fn has_bat_extension(resolved: &str) -> bool {
    let lower = resolved.to_ascii_lowercase();
    lower.ends_with(".bat") || lower.ends_with(".cmd")
}

/// The final components under test, each only dots and/or spaces or ending in one, with whether a
/// VERBATIM spelling can hold a file of that name. `.` and `..` cannot: they fail
/// `ERROR_INVALID_NAME` even under `\\?\`. `. ` rides along because under the prefix it is a
/// different literal name from `.`, not a spelling of it.
const WEIRD_NAMES: &[(&str, &str, bool)] = &[
    ("...", "three dots", true),
    ("....", "four dots", true),
    (" ", "a single space", true),
    ("x ", "an ordinary name with a trailing space", true),
    ("..", "the parent-directory component, spelled as a literal name", false),
    (".", "the self component, spelled as a literal name", false),
    (". ", "the self component plus a space: a different literal name", true),
];

/// `ERROR_INVALID_NAME`: "The filename, directory name, or volume label syntax is incorrect."
const ERROR_INVALID_NAME: i32 = 123;

/// Platform facts a canary found no longer hold. Distinct from a measurement that could not be
/// taken: that is a broken probe, this is a changed platform.
struct Disagreements {
    /// What the facts are about, named in the failure: `Windows`, or `Windows and Rust's
    /// std::process` when the route under test runs through std.
    subject: &'static str,
    broken: Vec<String>,
    /// Facts checked so far, broken or not.
    checked: usize,
}

impl Default for Disagreements {
    fn default() -> Self {
        Self::about("Windows")
    }
}

impl Disagreements {
    fn about(subject: &'static str) -> Self {
        Self {
            subject,
            broken: Vec::new(),
            checked: 0,
        }
    }

    /// Record `fact` as broken unless `holds`, with what was measured instead.
    fn check(&mut self, holds: bool, fact: &str, measured: impl std::fmt::Display) {
        self.checked += 1;
        if !holds {
            self.broken.push(format!("{fact} — measured {measured}"));
        }
    }

    /// Fail the test if any fact disagreed, or if none was checked: a canary whose loops never ran
    /// has measured nothing. Call after the measurement-failure assert, so a broken probe is
    /// reported as one rather than as a platform change.
    fn assert_none(self) {
        println!("facts checked: {}", self.checked);
        assert!(
            self.checked > 0,
            "the measurement could not be taken: this canary checked no fact"
        );
        assert!(
            self.broken.is_empty(),
            "The measured behaviour of {} has changed. Any code that models these facts (cosca's \
             batch gate among it) must be re-derived from the new behaviour. Facts that changed:\n  {}",
            self.subject,
            self.broken.join("\n  ")
        );
    }
}

/// A `Result` rendered for the log: `ok` or the OS error behind it.
fn outcome<T>(r: &std::io::Result<T>) -> String {
    match r {
        Ok(_) => "ok".to_string(),
        Err(e) => format!("FAILED: {e} (raw_os_error={:?})", e.raw_os_error()),
    }
}

/// Say which of a probe's inputs name a directory that is actually on disk.
///
/// `GetFullPathNameW` is documented as pure string manipulation and is expected not to care;
/// stating it lets the record say so. [`which_segment_positions_get_trimmed`] measures it.
fn report_roots(roots: &[&str]) {
    println!("roots these inputs are built on (GetFullPathNameW should not care — stated so the record can say):");
    for root in roots {
        let path = std::path::Path::new(root);
        println!("  {root:?}  exists={}  is_dir={}", path.exists(), path.is_dir());
    }
}

/// Every name in `dir`, as `FindFirstFileW` reports it.
fn entries(dir: &str) -> Result<Vec<std::ffi::OsString>, String> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| format!("read_dir({dir:?}) failed: {e}"))? {
        let entry = entry.map_err(|e| format!("read_dir({dir:?}) entry failed: {e}"))?;
        names.push(entry.file_name());
    }
    names.sort();
    Ok(names)
}

/// [`entries`], quoted for the log.
fn listing(dir: &str) -> Result<Vec<String>, String> {
    entries(dir).map(|names| names.iter().map(|n| format!("{n:?}")).collect())
}

// Probes =====

/// Canary: a final component of only dots and spaces DROPS OUT and pops nothing, while `..` pops.
///
/// The inputs are chosen so the two candidate readings of a dots-and-spaces component give
/// OPPOSITE answers — dropping it leaves `y`, reading it as `..` leaves `x.bat` — and, since std
/// tests the RESOLVED path, which one Win32 picks decides whether `cmd.exe` runs. `x.bat\y\..`
/// reaches a batch name through `..`. `x\..\..` shows that a relative path popping past its own
/// first component lands in the current directory's ancestors, which the string alone does not
/// name. The trailing separator on an elided result matters too: std's `has_bat_extension` does
/// not read `…\x.bat\` as a batch file.
///
/// Relative inputs, so each is compared against the current directory `GetFullPathNameW` resolves
/// them in.
#[test]
#[ignore = "platform canary: needs a Windows runner"]
fn a_final_dots_and_spaces_component_drops_out_and_pops_nothing() {
    // (input, what follows the current directory in the result, why)
    let probes = [
        (r"x.bat\y\..", r"x.bat", "`..` pops `y`, exposing the batch file"),
        (r"x.bat\y\.. ", r"x.bat\y\", "`.. ` is NOT `..`: it drops out"),
        (r"x.bat\y\. ", r"x.bat\y\", "`. ` drops out"),
        (r"x.bat\y\.. .", r"x.bat\y\", "drops out, so `y` survives"),
        (r"x.bat\y\...", r"x.bat\y\", "drops out, so `y` survives"),
        (r"x.bat\y\....", r"x.bat\y\", "drops out, so `y` survives"),
        (r"x.bat\y\.. ..", r"x.bat\y\", "drops out, so `y` survives"),
        (r"x.bat\y\ ", r"x.bat\y\", "drops out, so `y` survives"),
        (
            r"x.bat\...",
            r"x.bat\",
            "drops out, leaving a separator after the batch name",
        ),
        (
            r"x.bat\y\...\z.exe",
            r"x.bat\y\...\z.exe",
            "an interior `...` is kept verbatim",
        ),
    ];
    let mut failures: Vec<String> = announce_platform().err().into_iter().collect();
    let mut facts = Disagreements::default();
    match std::env::current_dir() {
        Ok(cwd) => {
            let cwd = cwd
                .to_str()
                .expect("cwd is not UTF-8")
                .trim_end_matches('\\')
                .to_string();
            println!("current directory: {cwd:?}");
            for (probe, tail, why) in probes {
                match full_path_name(probe) {
                    Ok(resolved) => {
                        println!(
                            "{probe:?} -> {resolved:?}  batch_to_std={}  ({why})",
                            has_bat_extension(&resolved)
                        );
                        let want = format!(r"{cwd}\{tail}");
                        facts.check(
                            resolved == want,
                            &format!("{probe:?} resolves to {want:?} ({why})"),
                            format_args!("{resolved:?}"),
                        );
                    }
                    Err(why) => failures.push(why),
                }
            }
            // Popping past the path's own first component continues into the cwd's ancestors, or
            // stays at the root when the cwd is one.
            const POP_PAST: &str = r"x\..\..";
            match full_path_name(POP_PAST) {
                Ok(resolved) => {
                    println!("{POP_PAST:?} -> {resolved:?}  (pops past its own first component)");
                    let want = pop_past_expectation(&cwd);
                    let got = resolved.trim_end_matches('\\');
                    facts.check(
                        got == want,
                        &format!("{POP_PAST:?} resolves to the cwd's parent, or its root, {want:?}"),
                        format_args!("{resolved:?}"),
                    );
                }
                Err(why) => failures.push(why),
            }
        }
        Err(e) => failures.push(format!(
            "could not read the working directory these resolve against: {e}"
        )),
    }
    assert!(
        failures.is_empty(),
        "the measurement could not be taken: {}",
        failures.join("; ")
    );
    facts.assert_none();
}

/// Canary: `GetFullPathNameW` strips a final dots-and-spaces component in BOTH spellings — the
/// verbatim `\\?\` prefix does not stop it — and a trailing separator does.
///
/// So for a verbatim path the string and the file disagree: `\\?\C:\dir\...` OPENS the file `...`
/// (see [`a_verbatim_dots_and_spaces_file_exists_and_loads`]) while `GetFullPathNameW` says it
/// names `C:\dir\`. A model of verbatim paths has to read the literal string, not this result. If
/// Win32 began honouring the prefix here, the two readings would converge.
///
/// The trailing-separator rows are printed, not asserted. `C:\dir\x` must come back untouched, or
/// the probe itself is broken.
#[test]
#[ignore = "platform canary: needs a Windows runner"]
fn a_final_dots_and_spaces_component_is_stripped_even_verbatim() {
    // (tail, note, stripped): `stripped` tails lose the whole final component without a trailing
    // separator, in either spelling.
    let tails = [
        ("...", "three dots", true),
        ("....", "four dots", true),
        (". ", "`.` plus a space", true),
        (" ", "a single space", true),
        (".. .", "neither `.` nor `..`, but trims to `..`", true),
        ("..", "the parent-directory component", false),
        (".", "the self component", false),
        ("x", "control: an ordinary name", false),
    ];
    let mut failures: Vec<String> = announce_platform().err().into_iter().collect();
    let mut facts = Disagreements::default();
    report_roots(&[r"C:\dir", r"C:\"]);
    for (tail, note, stripped) in tails {
        println!("--- {tail:?}  ({note})");
        for prefix in ["", r"\\?\"] {
            for trailing_sep in ["", r"\"] {
                let input = format!(r"{prefix}C:\dir\{tail}{trailing_sep}");
                match full_path_name_parts(&input) {
                    Ok((resolved, part)) => {
                        let shown = part
                            .as_ref()
                            .map_or_else(|| "<none: names a directory>".to_string(), |p| format!("{p:?}"));
                        let verdict = if resolved == input { "unchanged" } else { "REWRITTEN" };
                        println!("  {input:?} -> {resolved:?}  file_part={shown}  [{verdict}]");
                        if trailing_sep.is_empty() && stripped {
                            let want = format!(r"{prefix}C:\dir\");
                            facts.check(
                                resolved == want && part.is_none(),
                                &format!("{input:?} is stripped to the directory {want:?}"),
                                format_args!("{resolved:?} with file_part={shown}"),
                            );
                        }
                        if tail == "x" {
                            facts.check(
                                resolved == input,
                                &format!("control {input:?} comes back unchanged"),
                                format_args!("{resolved:?}"),
                            );
                        }
                    }
                    Err(why) if (trailing_sep.is_empty() && stripped) || tail == "x" => failures.push(why),
                    Err(why) => println!("  {why}  [printed row: not asserted]"),
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "the measurement could not be taken: {}",
        failures.join("; ")
    );
    facts.assert_none();
}

/// Canary: through `\\?\`, a dots-and-spaces name is an ordinary file — except `.` and `..`,
/// which fail `ERROR_INVALID_NAME`.
///
/// So a verbatim final `.` or `..` can never name a file, while `...`, `" "`, `"x "` and `". "` can.
/// A model of verbatim paths that treats either group otherwise is wrong on this Windows.
///
/// The plain-spelling rows, `GetFullPathNameW` and the listings are printed, not asserted. Each
/// (name, spelling) pair gets its OWN directory, so a listing can never be ambiguous about which
/// attempt produced which entry.
#[test]
#[ignore = "platform canary: needs a Windows runner"]
fn only_dot_and_dotdot_are_refused_as_verbatim_file_names() {
    let mut failures: Vec<String> = announce_platform().err().into_iter().collect();
    let mut facts = Disagreements::default();
    let root = tempfile::tempdir().expect("tempdir");
    let root = root.path().to_str().expect("temp path is not UTF-8").to_string();
    println!("temp root: {root:?}");

    for (i, &(name, note, creatable)) in WEIRD_NAMES.iter().enumerate() {
        for (tag, prefix) in [("plain", ""), ("verbatim", r"\\?\")] {
            let case_dir = format!(r"{root}\case{i}_{tag}");
            if let Err(e) = std::fs::create_dir(&case_dir) {
                failures.push(format!("could not create the case directory {case_dir:?}: {e}"));
                continue;
            }
            let target = format!(r"{prefix}{case_dir}\{name}");
            println!("--- create {target:?}  ({note}, {tag} spelling)");
            let written = std::fs::write(&target, b"probe");
            let created = written.is_ok();
            if !prefix.is_empty() {
                let code = written.as_ref().err().and_then(std::io::Error::raw_os_error);
                let fact = if creatable {
                    format!("{name:?} can be created through the verbatim spelling")
                } else {
                    format!(
                        "{name:?} fails ERROR_INVALID_NAME ({ERROR_INVALID_NAME}) even through the verbatim spelling"
                    )
                };
                facts.check(
                    if creatable {
                        created
                    } else {
                        code == Some(ERROR_INVALID_NAME)
                    },
                    &fact,
                    outcome(&written),
                );
            }
            println!("  write: {}", outcome(&written));

            // Everything below is what the platform says about whatever that write produced —
            // including nothing, which is itself an answer.
            match full_path_name_parts(&target) {
                Ok((resolved, part)) => {
                    let part = part.map_or_else(|| "<none: names a directory>".to_string(), |p| format!("{p:?}"));
                    println!("  GetFullPathNameW -> {resolved:?}  file_part={part}");
                }
                Err(why) => println!("  {why}"),
            }
            match listing(&format!(r"\\?\{case_dir}")) {
                Ok(names) => println!("  listing: {names:?}"),
                Err(why) => println!("  listing: {why}"),
            }
            let plain_back = format!(r"{case_dir}\{name}");
            let verbatim_back = format!(r"\\?\{case_dir}\{name}");
            println!(
                "  open as plain    {plain_back:?}: {}",
                outcome(&std::fs::File::open(&plain_back))
            );
            let reopened = std::fs::File::open(&verbatim_back);
            println!("  open as verbatim {verbatim_back:?}: {}", outcome(&reopened));
            if created && !prefix.is_empty() {
                facts.check(
                    reopened.is_ok(),
                    &format!("{name:?}, created verbatim, opens back through the verbatim spelling"),
                    outcome(&reopened),
                );
            }
            // Remove whatever the write produced — a plain `x ` creates `x` — through the verbatim
            // spelling, the only one guaranteed to name the literal entry. The directory is this
            // case's alone. A failure here leaves the ephemeral runner to clean up, but say so.
            drop(reopened);
            match entries(&format!(r"\\?\{case_dir}")) {
                Ok(names) => {
                    for entry in names {
                        let path = format!(r"\\?\{case_dir}\{}", entry.to_string_lossy());
                        if let Err(e) = std::fs::remove_file(&path) {
                            println!("  CLEANUP: {path:?} could not be removed: {e}");
                        }
                    }
                }
                Err(why) => println!("  CLEANUP: {why}"),
            }
        }
    }
    assert!(
        failures.is_empty(),
        "the measurement could not be taken: {}",
        failures.join("; ")
    );
    facts.assert_none();
}

/// Canary: an image under a verbatim dots-and-spaces name LOADS through `std::process`, and the
/// file that loads is the one under that name.
///
/// This measures Rust's `std::process` as well as Windows. For a `\\?\C:\…` program shorter than
/// `MAX_PATH`, std runs `GetFullPathNameW` on the part after the prefix and drops the prefix only
/// if that comes back unchanged. For these names it does not (the final component is stripped, see
/// [`a_final_dots_and_spaces_component_is_stripped_even_verbatim`]), so std keeps the verbatim
/// string and hands it to `CreateProcessW`. The loaded image being the planted file witnesses
/// that: the stripped string names a directory. That std's `.bat`/`.cmd` test also reads the
/// literal verbatim string (`is_verbatim` → `has_bat_extension` on the program) is read from
/// rust-src, not witnessed here; witnessing it would need a batch-shaped name.
///
/// So refusing these names would refuse a loadable executable. Raw `CreateProcessW` and both plain
/// spellings are printed alongside.
///
/// The payload, `cosca_testbin_image`, only reports its image and exits 0. Its `image=` line is
/// `QueryFullProcessImageNameW`; the canary opens that path verbatim and compares file identity
/// with the planted copy, so a spawn that ran any other file fails. Its `module=` line, the name
/// the loader recorded, is printed only.
#[test]
#[ignore = "platform canary: needs a Windows runner"]
fn a_verbatim_dots_and_spaces_file_exists_and_loads() {
    let mut failures: Vec<String> = announce_platform().err().into_iter().collect();
    let mut facts = Disagreements::about("Windows and Rust's std::process");
    let root = tempfile::tempdir().expect("tempdir");
    let root = root.path().to_str().expect("temp path is not UTF-8").to_string();
    let source = env!("CARGO_BIN_EXE_cosca_testbin_image");
    println!("temp root: {root:?}\nsource image: {source:?}");
    let mut spawnable = 0usize;

    for (i, &(name, note, creatable)) in WEIRD_NAMES.iter().enumerate() {
        let case_dir = format!(r"{root}\case{i}");
        if let Err(e) = std::fs::create_dir(&case_dir) {
            failures.push(format!("could not create the case directory {case_dir:?}: {e}"));
            continue;
        }
        let verbatim = format!(r"\\?\{case_dir}\{name}");
        let plain = format!(r"{case_dir}\{name}");
        println!("--- {verbatim:?}  ({note})");
        match std::fs::copy(source, &verbatim) {
            Ok(_) => {}
            Err(e) => {
                // Not a missing measurement: a name that cannot hold an image answers the
                // question for that name. [`only_dot_and_dotdot_are_refused_as_verbatim_file_names`]
                // owns which names those are.
                facts.check(!creatable, &format!("an image can be copied to verbatim {name:?}"), &e);
                println!(
                    "  copy: FAILED: {e} (raw_os_error={:?}) — nothing to spawn",
                    e.raw_os_error()
                );
                continue;
            }
        }
        spawnable += 1;
        let planted = match file_identity(&verbatim) {
            Ok(id) => id,
            Err(why) => {
                failures.push(why);
                continue;
            }
        };
        println!("  planted file identity: {planted:?}");
        for (tag, program) in [("verbatim", &verbatim), ("plain", &plain)] {
            let out = format!(r"\\?\{case_dir}\out_{tag}.txt");
            match create_process(program, &out) {
                Ok((code, captured)) => {
                    println!("  CreateProcessW as {tag} {program:?}: ran, exit={code}, child said {captured:?}")
                }
                Err(why) => println!("  CreateProcessW as {tag} {program:?}: {why}"),
            }
            // std::process is the route cosca actually takes, and it resolves the program itself
            // before calling CreateProcessW — so it can disagree with the line above.
            let ran = std::process::Command::new(program).output();
            match &ran {
                Ok(o) => println!(
                    "  std::process as {tag} {program:?}: ran, {:?}, child said {:?}",
                    o.status,
                    String::from_utf8_lossy(&o.stdout)
                ),
                Err(e) => println!(
                    "  std::process as {tag} {program:?}: FAILED: {e} (raw_os_error={:?})",
                    e.raw_os_error()
                ),
            }
            if tag != "verbatim" {
                continue;
            }
            let output = match ran {
                Ok(o) if o.status.success() => o,
                other => {
                    facts.check(
                        false,
                        &format!("std::process runs the image at verbatim {name:?}"),
                        other.map_or_else(|e| e.to_string(), |o| format!("{:?}", o.status)),
                    );
                    continue;
                }
            };
            let stdout = String::from_utf8_lossy(&output.stdout);
            let Some(image) = stdout.lines().find_map(|l| l.strip_prefix("image=")) else {
                failures.push(format!("the payload at {verbatim:?} exited 0 without an image= line"));
                continue;
            };
            // An image path that cannot be opened is a broken probe, not a changed platform.
            let loaded = match file_identity(&verbatim_spelling(image)) {
                Ok(id) => id,
                Err(why) => {
                    failures.push(format!("the reported image {image:?}: {why}"));
                    continue;
                }
            };
            println!("  image={image:?} opened verbatim has identity {loaded:?}");
            facts.check(
                loaded == planted,
                &format!("std::process on verbatim {name:?} loads that file, not another"),
                format_args!("image={image:?} with identity {loaded:?}, planted {planted:?}"),
            );
        }
        if let Err(e) = std::fs::remove_file(&verbatim) {
            println!("  CLEANUP: {verbatim:?} could not be removed: {e}");
        }
    }
    println!("names that could hold an image: {spawnable} of {}", WEIRD_NAMES.len());
    assert!(
        failures.is_empty(),
        "the measurement could not be taken: {}",
        failures.join("; ")
    );
    // A creatable name that could not hold an image is a changed platform, reported here first.
    facts.assert_none();
    // Otherwise every creatable name was spawned; without this a run that planted nothing would
    // measure nothing and pass.
    let expected = WEIRD_NAMES.iter().filter(|&&(_, _, creatable)| creatable).count();
    assert!(
        expected > 0 && spawnable == expected,
        "the measurement could not be taken: images were planted under {spawnable} names, not the \
         {expected} that can hold one"
    );
}

/// The volume serial number and 128-bit file ID of `path`: the file's identity, whatever the
/// spelling. `GetFileInformationByHandle`'s 64-bit index is not unique on ReFS; `FileIdInfo` is.
fn file_identity(path: &str) -> Result<(u64, [u8; 16]), String> {
    use std::os::windows::io::AsRawHandle;
    let file = std::fs::File::open(path).map_err(|e| format!("could not open {path:?}: {e}"))?;
    let mut info = FILE_ID_INFO::default();
    // SAFETY: the handle is owned by `file`, alive for the call; `info` is a live out-parameter of
    // exactly the size passed, the one `FileIdInfo` requires.
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(file.as_raw_handle()),
            FileIdInfo,
            std::ptr::addr_of_mut!(info).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    }
    .map_err(|e| format!("GetFileInformationByHandleEx({path:?}, FileIdInfo) failed: {e}"))?;
    Ok((info.VolumeSerialNumber, info.FileId.Identifier))
}

/// Canary: a plain `x.bat.` or `x.bat ` IS `x.bat`, while a verbatim one is a distinct file, and a
/// slash in the verbatim marker makes the path plain.
///
/// Plain: `GetFullPathNameW` hands std `…\x.bat`, which std tests for `.bat`/`.cmd` and so runs
/// through `cmd.exe`, so a model of plain paths must trim trailing dots and spaces before reading
/// the extension. Verbatim: `x.bat.` is a file of its own, which std tests as given.
///
/// Which spellings are verbatim is part of the fact. `\\?\` and the NT prefix `\??\` open the
/// literal name; `//?/` and `\\?/`, a slash anywhere in the marker, open `x.bat` like a plain path.
///
/// The `GetFullPathNameW` result of a verbatim spelling is printed, not asserted.
///
/// Each file holds its own name, so reading a spelling back says exactly which entry it reached.
/// **Nothing here is executed**: the files are text, not images.
#[test]
#[ignore = "platform canary: needs a Windows runner"]
fn a_trailing_dot_or_space_reaches_the_batch_file_only_when_plain() {
    const LOOKALIKES: &[&str] = &["x.bat.", "x.bat ", "x.bat"];
    let mut failures: Vec<String> = announce_platform().err().into_iter().collect();
    let mut facts = Disagreements::default();
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path().to_str().expect("temp path is not UTF-8").to_string();
    println!("temp dir: {dir:?}");

    for name in LOOKALIKES {
        let verbatim = format!(r"\\?\{dir}\{name}");
        let written = std::fs::write(&verbatim, name.as_bytes());
        println!("write {verbatim:?}: {}", outcome(&written));
        if let Err(e) = written {
            failures.push(format!("could not plant {verbatim:?}: {e}"));
        }
    }
    match listing(&format!(r"\\?\{dir}")) {
        Ok(names) => println!("listing: {names:?}"),
        Err(why) => println!("listing: {why}"),
    }
    for name in LOOKALIKES {
        println!("--- {name:?}");
        for (verbatim, path) in [(false, format!(r"{dir}\{name}")), (true, format!(r"\\?\{dir}\{name}"))] {
            let tag = if verbatim { "verbatim" } else { "plain   " };
            match full_path_name(&path) {
                // `std_has_bat_extension` is std's own `has_bat_extension` on the resolved name:
                // true is what makes `std::process` swap in cmd.exe for a plain path.
                Ok(resolved) => {
                    println!(
                        "  {tag} GetFullPathNameW -> {resolved:?}  std_has_bat_extension={}",
                        has_bat_extension(&resolved)
                    );
                    if !verbatim {
                        let want = format!(r"{dir}\x.bat");
                        facts.check(
                            resolved == want,
                            &format!("plain {name:?} resolves to {want:?}"),
                            format_args!("{resolved:?}"),
                        );
                    }
                }
                Err(why) if !verbatim => failures.push(why),
                Err(why) => println!("  {tag} {why}"),
            }
            let body = std::fs::read_to_string(&path);
            match &body {
                Ok(body) => println!("  {tag} reads the file named {body:?}"),
                Err(e) => println!("  {tag} read FAILED: {e} (raw_os_error={:?})", e.raw_os_error()),
            }
            let want = if verbatim { *name } else { "x.bat" };
            facts.check(
                body.as_deref().is_ok_and(|b| b == want),
                &format!("{} {name:?} opens the file {want:?}", tag.trim_end()),
                format_args!("{body:?}"),
            );
        }
    }
    // The other verbatim-looking spellings: a slash anywhere in the marker makes it plain, while
    // the NT prefix `\??\` is as literal as `\\?\`.
    let forward = dir.replace('\\', "/");
    for name in LOOKALIKES {
        for (tag, path, want) in [
            ("//?/", format!("//?/{forward}/{name}"), "x.bat"),
            (r"\\?/", format!(r"\\?/{dir}\{name}"), "x.bat"),
            (r"\??\", format!(r"\??\{dir}\{name}"), *name),
        ] {
            let body = std::fs::read_to_string(&path);
            match &body {
                Ok(body) => println!("  {tag:<5} {path:?} reads the file named {body:?}"),
                Err(e) => println!(
                    "  {tag:<5} {path:?} read FAILED: {e} (raw_os_error={:?})",
                    e.raw_os_error()
                ),
            }
            facts.check(
                body.as_deref().is_ok_and(|b| b == want),
                &format!("{tag} {name:?} opens the file {want:?}"),
                format_args!("{body:?}"),
            );
        }
    }
    assert!(
        failures.is_empty(),
        "the measurement could not be taken: {}",
        failures.join("; ")
    );
    facts.assert_none();
}

/// One expected `GetFullPathNameW` result: `(input, the result, why)`.
type Resolution = (String, String, &'static str);

/// Check each row's `GetFullPathNameW` result exactly, printing every one.
fn check_resolutions(rows: &[Resolution], facts: &mut Disagreements, failures: &mut Vec<String>) {
    for (input, want, why) in rows {
        match full_path_name(input) {
            Ok(resolved) => {
                println!(
                    "  {input:?} -> {resolved:?}  std_has_bat_extension={}  ({why})",
                    has_bat_extension(&resolved)
                );
                facts.check(
                    &resolved == want,
                    &format!("{input:?} resolves to {want:?} ({why})"),
                    format_args!("{resolved:?}"),
                );
            }
            Err(why) => failures.push(why),
        }
    }
}

/// Rows whose input and result are both literal.
fn literal_rows(rows: &[(&str, &str, &'static str)]) -> Vec<Resolution> {
    rows.iter()
        .map(|&(input, want, why)| (input.to_string(), want.to_string(), why))
        .collect()
}

/// Canary: `..` never pops a UNC path's `\\server\share`, but pops everything after `\\.\`.
///
/// So under a UNC root the share name is the floor: `\\srv\x.bat\y\..\..` is `\\srv\x.bat`, a
/// batch-shaped name. Under `\\.\` the device name is an ordinary component: `\\.\C:\..\..\x.bat`
/// is `\\.\x.bat`. `/` and `\` are interchangeable in the leading pair, so `//srv/…` and `\/srv\…`
/// are UNC paths too. A `..` in the share slot is not popped: it IS the share name.
///
/// String-level only: `GetFullPathNameW` contacts no server and opens no device.
#[test]
#[ignore = "platform canary: needs a Windows runner"]
fn dotdot_stops_at_the_unc_share_but_not_at_a_device_name() {
    let mut failures: Vec<String> = announce_platform().err().into_iter().collect();
    let mut facts = Disagreements::default();
    let rows = literal_rows(&[
        (
            r"\\srv\x.bat\..",
            r"\\srv\x.bat",
            "`..` right after the share pops nothing",
        ),
        (r"\\srv\x.bat\y\..\..", r"\\srv\x.bat", "the second `..` pops nothing"),
        (
            r"\\srv\x.bat\y.bat\..",
            r"\\srv\x.bat",
            "`..` pops the component after the share",
        ),
        (
            r"\\srv\x.bat\..\y",
            r"\\srv\x.bat\y",
            "the walk continues from the share",
        ),
        (r"\\srv\x.bat\..\..\y", r"\\srv\x.bat\y", "however many `..`"),
        (
            r"\\srv\x.bat\...",
            r"\\srv\x.bat\",
            "a dots-only final component drops out",
        ),
        (r"\\srv\x.bat.", r"\\srv\x.bat", "the share name loses its trailing dot"),
        (
            r"\\srv\..\x.bat",
            r"\\srv\..\x.bat",
            "`..` in the share slot is the share name",
        ),
        (r"//srv/x.bat/..", r"\\srv\x.bat", "`//` is a UNC root"),
        (r"\/srv\x.cmd\..", r"\\srv\x.cmd", r"`\/` is a UNC root"),
        (r"/\srv\x.bat\..", r"\\srv\x.bat", r"`/\` is a UNC root"),
        (
            r"//srv/x.bat/y/../..",
            r"\\srv\x.bat",
            "slash-spelled, the share is still the floor",
        ),
        (
            r"//srv/x.bat/../y",
            r"\\srv\x.bat\y",
            "slash-spelled, the walk continues from the share",
        ),
        (
            r"\\.\C:\x.bat\..",
            r"\\.\C:",
            "a device path's `..` pops an ordinary component",
        ),
        (r"\\.\C:\..", r"\\.\", "the device name `C:` is popped too"),
        (
            r"\\.\C:\..\..\x.bat",
            r"\\.\x.bat",
            "popped past the device, a batch name is left",
        ),
        (r"\\.\x.bat\..", r"\\.\", "the device name is popped"),
        (r"\\.\x.bat\y\..\..", r"\\.\", r"`\\.\` is the floor"),
        (r"\\.\pipe\x.bat\..", r"\\.\pipe", "`pipe` is an ordinary component"),
        (r"//./C:/x.bat/..", r"\\.\C:", r"`//./` is `\\.\`"),
        (
            r"\\.\C:\dir\x.bat.",
            r"\\.\C:\dir\x.bat",
            "a device path loses a trailing dot",
        ),
    ]);
    check_resolutions(&rows, &mut facts, &mut failures);
    assert!(
        failures.is_empty(),
        "the measurement could not be taken: {}",
        failures.join("; ")
    );
    facts.assert_none();
}

/// Canary: in `GetFullPathNameW`, `\\?\` and every slash spelling of it (`//?/`, `\\?/`, `/\?\`,
/// `\/?\`) resolve alike — separators become `\`, trailing dots drop, `..` pops — while `\??\` is
/// a rooted path on the current drive.
///
/// So `GetFullPathNameW`'s answer never says whether a string is verbatim: that is decided by the
/// literal prefix, and only std's `is_verbatim` (`\\?\` or `\??\`, exactly) and the file APIs
/// read it. [`a_trailing_dot_or_space_reaches_the_batch_file_only_when_plain`] shows which file
/// each spelling opens.
#[test]
#[ignore = "platform canary: needs a Windows runner"]
fn verbatim_marker_spellings_resolve_alike() {
    let mut failures: Vec<String> = announce_platform().err().into_iter().collect();
    let mut facts = Disagreements::default();
    let mut rows = literal_rows(&[
        (r"\\?\C:\dir\x.bat.", r"\\?\C:\dir\x.bat", "the verbatim marker"),
        (r"//?/C:/dir/x.bat.", r"\\?\C:\dir\x.bat", "slash-spelled"),
        (
            r"//?/C:/dir/...",
            r"\\?\C:\dir\",
            "slash-spelled, a dots-only name drops out",
        ),
        (
            r"//?/C:/dir/x.bat/y/..",
            r"\\?\C:\dir\x.bat",
            "slash-spelled, `..` pops",
        ),
        (r"\\?/C:\dir\x.bat.", r"\\?\C:\dir\x.bat", "slash after `?`"),
        (r"/\?\C:\dir\x.bat.", r"\\?\C:\dir\x.bat", "slash first"),
        (r"\/?\C:\dir\x.bat.", r"\\?\C:\dir\x.bat", "slash second"),
        (r"\\?\C:/dir/x.bat.", r"\\?\C:\dir\x.bat", "slashes after the marker"),
    ]);
    match std::env::current_dir() {
        Ok(cwd) => {
            let cwd = cwd.to_str().expect("cwd is not UTF-8").to_string();
            println!("current directory: {cwd:?}");
            match rooted_prefix(&cwd) {
                Some(root) => rows.push((
                    r"\??\C:\dir\x.bat.".to_string(),
                    format!(r"{root}\??\C:\dir\x.bat"),
                    r"`\??\` is rooted on the current drive or share",
                )),
                None => failures.push(format!("the current directory {cwd:?} has no root")),
            }
        }
        Err(e) => failures.push(format!("could not read the current directory: {e}")),
    }
    check_resolutions(&rows, &mut facts, &mut failures);
    assert!(
        failures.is_empty(),
        "the measurement could not be taken: {}",
        failures.join("; ")
    );
    facts.assert_none();
}

/// Canary: a `:stream` suffix stays in the final component, and only a trailing dot or space is
/// trimmed from it.
///
/// So the resolved name ends in the stream name: `x.exe:payload.bat` resolves to a string std's
/// `has_bat_extension` reads as a batch file, `x.bat:s` to one it does not. String-level only: no
/// stream is created or opened.
#[test]
#[ignore = "platform canary: needs a Windows runner"]
fn a_stream_suffix_stays_in_the_final_component() {
    let mut failures: Vec<String> = announce_platform().err().into_iter().collect();
    let mut facts = Disagreements::default();
    let mut rows = literal_rows(&[
        (r"C:\dir\x.bat:s", r"C:\dir\x.bat:s", "kept as given"),
        (
            r"C:\dir\x.exe:payload.bat",
            r"C:\dir\x.exe:payload.bat",
            "kept as given",
        ),
        (r"C:\dir\x.bat::$DATA", r"C:\dir\x.bat::$DATA", "a stream type is kept"),
        (
            r"C:\dir\x.exe:p.bat:$DATA",
            r"C:\dir\x.exe:p.bat:$DATA",
            "a stream type is kept",
        ),
        (r"C:\dir\x.bat:", r"C:\dir\x.bat:", "an empty stream name is kept"),
        (
            r"C:\dir\x.bat:s.",
            r"C:\dir\x.bat:s",
            "a trailing dot is trimmed from the stream name",
        ),
        (
            r"C:\dir\x.exe:p.bat.",
            r"C:\dir\x.exe:p.bat",
            "a trailing dot is trimmed",
        ),
        (
            r"C:\dir\x.exe:p.bat ",
            r"C:\dir\x.exe:p.bat",
            "a trailing space is trimmed",
        ),
        (
            r"\\?\C:\dir\x.exe:p.bat",
            r"\\?\C:\dir\x.exe:p.bat",
            "kept under the verbatim marker",
        ),
    ]);
    match std::env::current_dir() {
        Ok(cwd) => {
            let cwd = cwd
                .to_str()
                .expect("cwd is not UTF-8")
                .trim_end_matches('\\')
                .to_string();
            println!("current directory: {cwd:?}");
            rows.push(("x.bat:s".to_string(), format!(r"{cwd}\x.bat:s"), "relative, kept"));
            rows.push((
                "x.exe:payload.bat".to_string(),
                format!(r"{cwd}\x.exe:payload.bat"),
                "relative, kept",
            ));
        }
        Err(e) => failures.push(format!("could not read the current directory: {e}")),
    }
    check_resolutions(&rows, &mut facts, &mut failures);
    // Drive-relative: which directory `C:` means depends on the per-drive current directory, so
    // only the shape is asserted.
    const DRIVE_RELATIVE: &str = r"C:x.bat:s";
    match full_path_name(DRIVE_RELATIVE) {
        Ok(resolved) => {
            println!("  {DRIVE_RELATIVE:?} -> {resolved:?}  (drive-relative)");
            facts.check(
                resolved.starts_with(r"C:\") && resolved.ends_with(r"\x.bat:s"),
                &format!(r"{DRIVE_RELATIVE:?} resolves to C:\…\x.bat:s"),
                format_args!("{resolved:?}"),
            );
        }
        Err(why) => failures.push(why),
    }
    assert!(
        failures.is_empty(),
        "the measurement could not be taken: {}",
        failures.join("; ")
    );
    facts.assert_none();
}

/// Canary: an INTERIOR segment loses a single trailing period and nothing else.
///
/// A trailing run of two or more periods is kept, and so are trailing spaces: interior `...`, `" "`
/// and `x ` are names, `x.` becomes `x`, `.. .` becomes `.. `. Being names, a following `..` pops
/// them: `y\x.bat\...\..` is `y\x.bat`. Both spellings, at one and two segments from the end,
/// behave alike. This differs from the FINAL-component rule
/// ([`a_final_dots_and_spaces_component_drops_out_and_pops_nothing`]), so a model of path
/// normalisation needs both.
#[test]
#[ignore = "platform canary: needs a Windows runner"]
fn an_interior_segment_loses_only_a_single_trailing_period() {
    // (segment, what it becomes when not final)
    const INTERIOR: &[(&str, &str)] = &[
        ("x", "x"),
        (".x", ".x"),
        ("x.", "x"),
        ("x..", "x.."),
        ("x...", "x..."),
        ("x....", "x...."),
        ("x ", "x "),
        ("x  ", "x  "),
        ("x. ", "x. "),
        ("x .", "x "),
        ("...", "..."),
        (".. .", ".. "),
        (" ", " "),
    ];
    let mut failures: Vec<String> = announce_platform().err().into_iter().collect();
    let mut facts = Disagreements::default();
    let mut rows = Vec::new();
    for (seg, kept) in INTERIOR {
        for prefix in ["", r"\\?\"] {
            for tail in [r"z.exe", r"mid\z.exe"] {
                rows.push((
                    format!(r"{prefix}C:\dir\{seg}\{tail}"),
                    format!(r"{prefix}C:\dir\{kept}\{tail}"),
                    "interior segment",
                ));
            }
        }
    }
    check_resolutions(&rows, &mut facts, &mut failures);

    // A kept interior segment is a name, so the `..` after it pops it.
    match std::env::current_dir() {
        Ok(cwd) => {
            let cwd = cwd
                .to_str()
                .expect("cwd is not UTF-8")
                .trim_end_matches('\\')
                .to_string();
            println!("current directory: {cwd:?}");
            let popped = [
                (r"y\x.bat\...\..", "`...` is kept, then popped"),
                (r"y\x.bat\ \..", "a lone space is kept, then popped"),
                (r"y\x.bat\.. .\..", "`.. .` becomes the name `.. `, then popped"),
            ]
            .map(|(input, why)| (input.to_string(), format!(r"{cwd}\y\x.bat"), why));
            check_resolutions(&popped, &mut facts, &mut failures);
        }
        Err(e) => failures.push(format!("could not read the current directory: {e}")),
    }
    assert!(
        failures.is_empty(),
        "the measurement could not be taken: {}",
        failures.join("; ")
    );
    facts.assert_none();
}

/// Segment shapes for [`which_segment_positions_get_trimmed`]. Every one is an ORDINARY name — `x`
/// with something trailing — or a named control, so "was this segment trimmed?" has an
/// unambiguous answer wherever it sits.
const SEGMENTS: &[(&str, &str)] = &[
    ("x", "control: nothing to trim"),
    (".x", "control: the period is LEADING, not trailing"),
    ("x.", "one trailing period"),
    ("x..", "two trailing periods"),
    (
        "x...",
        "three trailing periods — is the exemption about the segment or its position?",
    ),
    ("x....", "four trailing periods"),
    ("x ", "one trailing space"),
    ("x  ", "two trailing spaces"),
    ("x. ", "period then space"),
    ("x .", "space then period"),
    (
        "...",
        "nothing but three periods: the documented exemption, for comparison",
    ),
    (".. .", "trims to `..` if trimmed at all"),
];

/// The positions a segment can occupy, as templates over `{root}` and `{seg}`.
const POSITIONS: &[(&str, &str)] = &[
    ("final, no sep", r"{root}\{seg}"),
    ("final, +sep  ", r"{root}\{seg}\"),
    ("interior x1  ", r"{root}\{seg}\z.exe"),
    ("interior x2  ", r"{root}\{seg}\mid\z.exe"),
];

fn build(shape: &str, root: &str, seg: &str) -> String {
    shape.replace("{root}", root).replace("{seg}", seg)
}

/// Survey: which SEGMENT POSITIONS does `GetFullPathNameW` trim, and does the root's existence
/// change the answer?
///
/// [`an_interior_segment_loses_only_a_single_trailing_period`] asserts the interior rows.
///
/// Each case is also run under two sibling roots of EQUAL length, one created on disk and one not,
/// so "does the directory have to exist?" is settled by comparing two strings rather than by
/// trusting the documentation's claim that this is pure string manipulation.
#[test]
#[ignore = "platform survey: needs a Windows runner; prints a measurement rather than asserting"]
fn which_segment_positions_get_trimmed() {
    survey_platform();

    let tmp = tempfile::tempdir().expect("tempdir");
    let tmp = tmp.path().to_str().expect("temp path is not UTF-8").to_string();
    assert!(
        !tmp.contains(r"\edir") && !tmp.contains(r"\ndir"),
        "the temp root {tmp:?} already contains one of the substitution tokens, so the \
         existing-versus-missing comparison below would be meaningless"
    );
    let root_e = format!(r"{tmp}\edir");
    let root_n = format!(r"{tmp}\ndir");
    std::fs::create_dir(&root_e).expect("create the root that exists");

    report_roots(&[r"C:\dir", root_e.as_str(), root_n.as_str()]);
    println!(
        "each row resolves under {:?}; `root-existence` re-runs the SAME shape under {root_e:?} \
         (created) and {root_n:?} (never created) and compares them after mapping one name onto \
         the other",
        r"C:\dir"
    );

    for (seg, note) in SEGMENTS {
        println!("--- segment {seg:?}  ({note})");
        for (position, shape) in POSITIONS {
            for (spelling, prefix) in [("plain   ", ""), ("verbatim", r"\\?\")] {
                let input = format!("{prefix}{}", build(shape, r"C:\dir", seg));
                match full_path_name_parts(&input) {
                    Ok((resolved, part)) => {
                        let part = part.map_or_else(|| "<none: names a directory>".to_string(), |p| format!("{p:?}"));
                        let verdict = if resolved == input { "unchanged" } else { "REWRITTEN" };
                        let existence = cross_root(prefix, shape, seg, &root_e, &root_n);
                        println!(
                            "  {position} {spelling} {input:?} -> {resolved:?}  file_part={part}  \
                             [{verdict}]  root-existence: {existence}"
                        );
                    }
                    Err(why) => println!("  {position} {spelling} {why}"),
                }
            }
        }
    }

    // Relative shapes resolve against the working directory rather than a drive root, which is a
    // third position again.
    println!("--- relative shapes");
    match std::env::current_dir() {
        Ok(cwd) => println!(
            "  resolved against the CWD {cwd:?}; `x.bat` there exists={}",
            cwd.join("x.bat").exists()
        ),
        Err(e) => println!("  could not read the working directory these resolve against: {e}"),
    }
    for input in [
        r"x.bat\y.\z.exe",
        r"x.bat\y. \z.exe",
        r"x.bat\y...\z.exe",
        r"x.bat\y.",
        r"x.bat\y. ",
        r"x.bat\y...",
        r"x.bat\y.\",
        r"x.bat\y. \",
        r"x.bat\y...\",
    ] {
        match full_path_name_parts(input) {
            Ok((resolved, part)) => {
                let part = part.map_or_else(|| "<none: names a directory>".to_string(), |p| format!("{p:?}"));
                println!("  {input:?} -> {resolved:?}  file_part={part}");
            }
            Err(why) => println!("  {why}"),
        }
    }
}

/// The same shape resolved under a root that exists and a root that does not, compared after
/// mapping the missing root's name onto the existing one. An error on either side is part of the
/// comparison.
///
/// The two roots are siblings of equal length, so the mapping is a plain substring replacement and
/// cannot itself introduce a difference. A case that pops above both roots produces text mentioning
/// neither, which compares equal without any mapping at all — also correct.
fn cross_root(prefix: &str, shape: &str, seg: &str, root_e: &str, root_n: &str) -> String {
    let existing = full_path_name(&format!("{prefix}{}", build(shape, root_e, seg)));
    let missing = full_path_name(&format!("{prefix}{}", build(shape, root_n, seg)));
    compare_across_roots(&existing, &missing, root_e, root_n)
}

/// Survey: is `\\?\C:\dir\..` -> `\\?\C:` a Win32 answer or a probe artefact?
///
/// It is the only result of [`a_final_dots_and_spaces_component_is_stripped_even_verbatim`] that
/// is not a usable path — no trailing separator, and drive-relative under a prefix whose whole
/// point is that nothing is relative. A trimmed `String` cannot say
/// whether Win32 produced that or the probe cut it short, so this reports the raw UTF-16 units,
/// the length Win32 returned, an independent size query, and where `lpFilePart` lands in the
/// buffer.
#[test]
#[ignore = "platform survey: needs a Windows runner; prints a measurement rather than asserting"]
fn the_verbatim_parent_result_is_raw_or_truncated() {
    survey_platform();
    report_roots(&[r"C:\dir", r"C:\"]);
    for (input, note) in [
        (
            r"\\?\C:\dir\..",
            "the suspect: resolves to \"\\\\?\\C:\" with file_part \"C:\"",
        ),
        (
            r"\\?\C:\dir\..\",
            "the same input with a trailing separator, which resolves normally",
        ),
        (r"C:\dir\..", "control: the plain spelling of the suspect"),
        (r"\\?\C:\dir\x", "control: an ordinary name comes back whole"),
        (r"\\?\C:\..", "one level further up than the suspect"),
    ] {
        println!("--- {input:?}  ({note})");
        match full_path_name_raw(input) {
            Ok(report) => print!("{report}"),
            Err(why) => println!("  {why}"),
        }
    }
}

/// Survey: `x<sp>`, start to finish, in ONE directory.
///
/// [`only_dot_and_dotdot_are_refused_as_verbatim_file_names`] gives each spelling its own
/// directory; here every step touches the same one and says so, so the plain and verbatim `x<sp>`
/// can be seen coexisting.
#[test]
#[ignore = "platform survey: needs a Windows runner; prints a measurement rather than asserting"]
fn x_space_measured_in_a_single_directory() {
    survey_platform();
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path().to_str().expect("temp path is not UTF-8").to_string();
    println!("THE ONE DIRECTORY. Every step below reads or writes inside {dir:?} and nowhere else.");

    let spellings = [
        ("plain    x<sp>", format!(r"{dir}\x ")),
        ("verbatim x<sp>", format!(r"\\?\{dir}\x ")),
        ("plain    x", format!(r"{dir}\x")),
        ("verbatim x", format!(r"\\?\{dir}\x")),
    ];
    let verbatim_dir = format!(r"\\?\{dir}");

    let show_dir = |label: &str| match listing(&verbatim_dir) {
        Ok(names) => println!("  listing of {dir:?} {label}: {names:?}"),
        Err(why) => println!("  listing of {dir:?} {label}: {why}"),
    };
    let read_back = |label: &str| {
        println!("  reading every spelling {label}:");
        for (tag, path) in &spellings {
            match std::fs::read_to_string(path) {
                Ok(body) => println!("    {tag} {path:?} -> reads the file written as {body:?}"),
                Err(e) => println!(
                    "    {tag} {path:?} -> FAILED: {e} (raw_os_error={:?})",
                    e.raw_os_error()
                ),
            }
        }
    };

    println!("step 1: the directory starts empty");
    show_dir("at step 1");

    println!(r"step 2: create through the PLAIN spelling {:?}", spellings[0].1);
    println!("  write: {}", outcome(&std::fs::write(&spellings[0].1, b"plain x<sp>")));
    show_dir("after step 2");
    read_back("after step 2");

    println!(r"step 3: create through the VERBATIM spelling {:?}", spellings[1].1);
    println!(
        "  write: {}",
        outcome(&std::fs::write(&spellings[1].1, b"verbatim x<sp>"))
    );
    show_dir("after step 3");
    read_back("after step 3");

    println!("step 4: what GetFullPathNameW makes of each spelling, with the files now on disk");
    for (tag, path) in &spellings {
        match full_path_name_parts(path) {
            Ok((resolved, part)) => {
                let part = part.map_or_else(|| "<none: names a directory>".to_string(), |p| format!("{p:?}"));
                println!("  {tag} {path:?} -> {resolved:?}  file_part={part}");
            }
            Err(why) => println!("  {tag} {why}"),
        }
    }
}

/// `CreateProcessW(lpApplicationName = program)` with no arguments, stdout captured to `out_path`. `Err` is a spawn that did not happen, rendered with its Win32 error.
fn create_process(program: &str, out_path: &str) -> Result<(u32, String), String> {
    use std::os::windows::io::AsRawHandle;

    let file = std::fs::File::create(out_path).map_err(|e| format!("could not open the capture file: {e}"))?;
    let handle = HANDLE(file.as_raw_handle());
    // SAFETY: `handle` is a live handle owned by `file` for the whole call.
    unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }
        .map_err(|e| format!("could not make the capture handle inheritable: {e}"))?;

    let program_w = wide(program);
    let mut cmdline_w = wide(&format!("\"{program}\""));
    let si = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESTDHANDLES,
        hStdOutput: handle,
        hStdError: handle,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    // SAFETY: both wide buffers are nul-terminated and outlive the call; `cmdline_w` is writable,
    // as CreateProcessW requires; `si` and `pi` are live and correctly sized.
    let spawned = unsafe {
        CreateProcessW(
            PCWSTR(program_w.as_ptr()),
            Some(PWSTR(cmdline_w.as_mut_ptr())),
            None,
            None,
            true,
            CREATE_NO_WINDOW,
            None,
            None,
            &si,
            &mut pi,
        )
    };
    if let Err(e) = spawned {
        return Err(format!("did not spawn: {e} (HRESULT {:#010x})", e.code().0));
    }

    // SAFETY: `pi.hProcess` is the live handle CreateProcessW just handed us. INFINITE is not a
    // chosen timeout — the child is `cosca_testbin_image`, which exits on its own.
    let waited = unsafe { WaitForSingleObject(pi.hProcess, INFINITE) };
    // Captured before anything else can overwrite the thread's last error.
    let wait_error = std::io::Error::last_os_error();
    let mut code = 0u32;
    let got_code = if waited == WAIT_OBJECT_0 {
        // SAFETY: the process has exited and `code` is a live out-parameter.
        unsafe { GetExitCodeProcess(pi.hProcess, &mut code) }.map_err(|e| format!("GetExitCodeProcess failed: {e}"))
    } else {
        // Anything else leaves the child possibly running and the capture incomplete.
        Err(format!(
            "WaitForSingleObject returned {:#x}, not WAIT_OBJECT_0: {wait_error}",
            waited.0
        ))
    };
    // SAFETY: both handles are owned by us and not used again.
    unsafe {
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
    }
    got_code?;

    drop(file);
    let captured = std::fs::read_to_string(out_path).map_err(|e| format!("could not read the capture file: {e}"))?;
    Ok((code, captured))
}
