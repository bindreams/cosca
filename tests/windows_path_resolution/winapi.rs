//! Thin wrappers over the Win32 calls the probes measure with, and log helpers.

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Storage::FileSystem::GetFullPathNameW;

pub(crate) fn wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// `GetFullPathNameW(input)` as the resolved path plus its `lpFilePart`, or an error describing
/// why no measurement was taken.
///
/// `lpFilePart` is the second half of the answer and not a decoration: Win32 sets it to the final
/// component of the result, or to NULL when the result names a directory. So it says directly
/// whether `C:\dir\...` came back still naming a file.
pub(crate) fn full_path_name_parts(input: &str) -> Result<(String, Option<String>), String> {
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
pub(crate) fn full_path_name(input: &str) -> Result<String, String> {
    full_path_name_parts(input).map(|(resolved, _)| resolved)
}

/// `GetFullPathNameW(input)` reported at the UTF-16 unit level.
///
/// A result that looks cut off — `\\?\C:` with no trailing separator, say — was cut off either by
/// Win32 or by the probe, and a trimmed `String` cannot tell the two apart. So this reports the
/// length Win32 returned, the length an independent size query says it should be, the raw units
/// including the ones past the end of the answer, and where `lpFilePart` points inside the buffer.
/// The buffer is poisoned first, so "Win32 wrote nothing here" is visible rather than inferred.
pub(crate) fn full_path_name_raw(input: &str) -> Result<String, String> {
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
pub(crate) fn has_bat_extension(resolved: &str) -> bool {
    let lower = resolved.to_ascii_lowercase();
    lower.ends_with(".bat") || lower.ends_with(".cmd")
}

/// A `Result` rendered for the log: `ok` or the OS error behind it.
pub(crate) fn outcome<T>(r: &std::io::Result<T>) -> String {
    match r {
        Ok(_) => "ok".to_string(),
        Err(e) => format!("FAILED: {e} (raw_os_error={:?})", e.raw_os_error()),
    }
}

/// Say which of a probe's inputs name a directory that is actually on disk.
///
/// `GetFullPathNameW` is documented as pure string manipulation and is expected not to care;
/// stating it lets the record say so. `surveys::which_segment_positions_get_trimmed` measures it.
pub(crate) fn report_roots(roots: &[&str]) {
    println!("roots these inputs are built on (GetFullPathNameW should not care — stated so the record can say):");
    for root in roots {
        let path = std::path::Path::new(root);
        println!("  {root:?}  exists={}  is_dir={}", path.exists(), path.is_dir());
    }
}

/// Every name in `dir`, as `FindFirstFileW` reports it.
pub(crate) fn entries(dir: &str) -> Result<Vec<std::ffi::OsString>, String> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| format!("read_dir({dir:?}) failed: {e}"))? {
        let entry = entry.map_err(|e| format!("read_dir({dir:?}) entry failed: {e}"))?;
        names.push(entry.file_name());
    }
    names.sort();
    Ok(names)
}

/// [`entries`], quoted for the log.
pub(crate) fn listing(dir: &str) -> Result<Vec<String>, String> {
    entries(dir).map(|names| names.iter().map(|n| format!("{n:?}")).collect())
}
