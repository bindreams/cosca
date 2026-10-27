//! The conversions against Win32's own string functions. Pure calls only: no file is opened.

use windows::core::PCWSTR;
use windows::Wdk::Storage::FileSystem::{RtlDosPathNameToNtPathName_U_WithStatus, RtlIsDosDeviceName_U};
use windows::Win32::Foundation::UNICODE_STRING;
use windows::Win32::Storage::FileSystem::GetFullPathNameW;
use windows::Win32::System::WindowsProgramming::RtlFreeUnicodeString;

use super::convert_tests::strings_over;
use super::ConversionReason;
use crate::windows::{Anchor, OsStr, ParseError, PathBuf};
use crate::{Component, PurePath};

fn wide_nul(s: &str) -> Vec<u16> {
    let mut units = OsStr::new(s).to_wide();
    units.push(0);
    units
}

/// `GetFullPathNameW`'s reading of `s`, or `None` where it fails or does not fit.
fn try_get_full_path_name(s: &str) -> Option<String> {
    let input = wide_nul(s);
    let mut buf = vec![0u16; 1024];
    // SAFETY: `input` is NUL-terminated and `buf` is writable for its length.
    let len = unsafe { GetFullPathNameW(PCWSTR(input.as_ptr()), Some(&mut buf), None) } as usize;
    (len > 0 && len < buf.len()).then(|| String::from_utf16(&buf[..len]).unwrap())
}

/// `GetFullPathNameW`'s reading of `s`, parsed.
fn get_full_path_name(s: &str) -> PathBuf {
    let read = try_get_full_path_name(s).unwrap_or_else(|| panic!("GetFullPathNameW({s:?}) failed"));
    PathBuf::parse(&read).unwrap_or_else(|e| panic!("GetFullPathNameW({s:?}) does not parse: {e}"))
}

/// Whether `RtlIsDosDeviceName_U` reads `s` as a device.
fn is_dos_device(s: &str) -> bool {
    let input = wide_nul(s);
    // SAFETY: `input` is NUL-terminated.
    unsafe { RtlIsDosDeviceName_U(PCWSTR(input.as_ptr())) != 0 }
}

/// The NT path `CreateFileW` would open for `s`.
fn nt_path_name(s: &str) -> String {
    try_nt_path_name(s).unwrap_or_else(|| panic!("RtlDosPathNameToNtPathName_U_WithStatus({s:?}) failed"))
}

/// The NT path `CreateFileW` would open for `s`, or `None` where Win32 refuses the string.
fn try_nt_path_name(s: &str) -> Option<String> {
    let input = wide_nul(s);
    let mut nt = UNICODE_STRING::default();
    // SAFETY: `input` is NUL-terminated; on success `nt` owns a buffer freed below.
    let status = unsafe { RtlDosPathNameToNtPathName_U_WithStatus(PCWSTR(input.as_ptr()), &mut nt, None, None) };
    if status.is_err() {
        return None;
    }
    // SAFETY: `nt.Buffer` holds `nt.Length` bytes of UTF-16.
    let units = unsafe { std::slice::from_raw_parts(nt.Buffer.0, usize::from(nt.Length) / 2) };
    let path = String::from_utf16(units).unwrap();
    // SAFETY: `nt` was allocated by the call above and is freed once.
    unsafe { RtlFreeUnicodeString(&mut nt) };
    Some(path)
}

/// The samples a differential skips because they do not parse, by class. A `/` after `\\?\` is
/// pinned by the parse tests, and a `.`, `..` or empty name there is compared by
/// `to_wide_names_the_nt_path_a_verbatim_input_named`. Any other parse error fails the test.
#[derive(Default)]
struct ParseSkips {
    slash_in_verbatim: usize,
    dots_in_verbatim: usize,
}

impl ParseSkips {
    fn count(&mut self, s: &str, err: ParseError) {
        match err {
            ParseError::SlashInVerbatim => self.slash_in_verbatim += 1,
            ParseError::DotOrEmptyNameInVerbatim => self.dots_in_verbatim += 1,
            other => panic!("{s:?} does not parse: {other}"),
        }
    }

    /// A class that never occurs is no longer skipped, and its count would vouch for nothing.
    fn assert_each_class_seen(&self) {
        let Self {
            slash_in_verbatim,
            dots_in_verbatim,
        } = self;
        assert!(
            *slash_in_verbatim > 5,
            "only {slash_in_verbatim} samples skipped for a `/` in a verbatim path"
        );
        assert!(
            *dots_in_verbatim > 5,
            "only {dots_in_verbatim} samples skipped for a dot or empty name in a verbatim path"
        );
    }
}

/// Small spellings, alone and after each kind of anchor, in both separators. Some anchors end in a
/// name the rest extends, some servers and shares end in a dot or a space, and some prefixes are
/// not fully qualified. The names include device names, which Win32 reads by position.
fn samples() -> Vec<String> {
    let prefixes = [
        "",
        "/",
        r"\",
        "C:",
        r"C:\",
        "c:/",
        r".\",
        r"x\",
        r"\s\h\",
        "//s/h/",
        r"\s\h",
        r"\s.\h.\",
        r"\s \h \",
        r"\s\..\",
        r"\.\",
        r"\.\x",
        "//?/",
        r"\?/",
        r"\\s\h\",
        r"\\s\h",
        r"\\s.\h.\",
        r"\\s \h \",
        r"\\s\..\",
        r"\\s\\",
        r"\\s\\h\",
        r"\\.\",
        r"\\.\x",
        r"\\.\..\",
        r"\\?/",
    ];
    let rests = strings_over(&["a", ".", " ", ":", "?", "\\", "/", "nul", "com1"], 5);
    prefixes
        .iter()
        .flat_map(|prefix| rests.iter().map(move |rest| format!("{prefix}{rest}")))
        .collect()
}

/// For every sample, a device to Win32 is refused as a reserved name; for every fully qualified
/// one, a reserved-name refusal names a real device (see `device_stem`), `win32_normalized` gives
/// `GetFullPathNameW`'s reading, and `to_win32_string` refuses for a trailing dot or space exactly
/// when that reading differs from the one with no names trimmed. This compares
/// `GetFullPathNameW` strings, not NT paths; the NT path is compared in
/// `to_wide_names_the_nt_path_win32_reaches_by_the_names_as_written`.
///
/// Mutants: `to_win32_string` refuses a single trailing dot on the share, which Win32 keeps; the
/// reserved-name check ignores a rooted name that starts with `:`, so `\:nul` passes;
/// `win32_normalized` returns a reading that is a device to Win32 (`C:\x\nul\.` gives `C:\x\nul`).
#[skuld::test]
fn win32_normalized_matches_get_full_path_name() {
    let mut checked = 0;
    let mut devices = 0;
    let mut nt_prefixed = 0;
    let mut refused_as_reserved = 0;
    let mut skips = ParseSkips::default();
    for s in samples() {
        let path = match PathBuf::parse(&s) {
            Ok(path) => path,
            Err(err) => {
                skips.count(&s, err);
                continue;
            }
        };
        if s.starts_with(r"\??\") {
            // The NT path `\??\...` is not the plain path; `to_win32_string` refuses it, and
            // `to_wide_names_the_nt_path_win32_reaches_by_the_names_as_written` compares what
            // `to_wide` gives.
            let err = path.to_win32_string().unwrap_err();
            assert_eq!(err.reason(), ConversionReason::NtPrefix, "{s:?}");
            nt_prefixed += 1;
            continue;
        }
        if is_dos_device(&s) {
            devices += 1;
            let err = path.to_win32_string().unwrap_err();
            assert_eq!(
                err.reason(),
                ConversionReason::ReservedName,
                "{s:?} is a device to Win32, refused as {err}"
            );
        }
        if !path.is_fully_qualified() {
            continue;
        }
        let win32 = get_full_path_name(&s);
        match path.win32_normalized() {
            Ok(normal) => {
                assert!(!is_dos_device(&s), "{s:?} is a device to Win32");
                assert_eq!(normal, win32, "{s:?}");
                let reading = normal.as_os_str().to_str().unwrap();
                assert!(!is_dos_device(reading), "{s:?} reads as {reading:?}, a device to Win32");
            }
            Err(err) => {
                assert_eq!(err.reason(), ConversionReason::ReservedName, "{s:?}");
                // The refusal is real: the string, its reading or the name's stem is a device to
                // Win32, or the stem is one only Windows 11 maps. Build 26100 maps `CON` and the
                // like only as a bare name; Microsoft documents them as devices in any position
                // and with any extension before Windows 11, so the stem stands in for the name.
                let reading = path.win32_reading(true);
                let reading = reading.as_os_str().to_str().unwrap();
                let stem = device_stem(err.component().and_then(OsStr::to_str).unwrap());
                assert!(
                    is_dos_device(&s)
                        || is_dos_device(reading)
                        || is_dos_device(stem)
                        || is_windows_11_device_stem(stem),
                    "{s:?} was refused ({err}), but neither it, its reading {reading:?} nor {stem:?} is a device to Win32"
                );
                refused_as_reserved += 1;
            }
        }
        let trimmed = win32 != path.win32_reading(false);
        match path.to_win32_string() {
            Ok(_) => assert!(!trimmed, "{s:?} was accepted, but Win32 reads it as {win32:?}"),
            Err(err) => match err.reason() {
                ConversionReason::TrailingDotOrSpace | ConversionReason::SingleTrailingDot => {
                    assert!(trimmed, "{s:?} was refused ({err}), but Win32 reads it as written")
                }
                ConversionReason::DotComponent | ConversionReason::ReservedName => {}
                other => panic!("{s:?}: unexpected {other:?}"),
            },
        }
        checked += 1;
    }
    assert!(checked > 10_000, "only {checked} samples checked");
    skips.assert_each_class_seen();
    assert!(devices > 1_000, "only {devices} devices seen");
    assert!(nt_prefixed > 100, "only {nt_prefixed} NT-prefixed samples seen");
    assert!(
        refused_as_reserved > 1_000,
        "only {refused_as_reserved} fully qualified samples refused as reserved"
    );
}

/// The part of `name` before its first `.` or `:`, less trailing spaces: what a device name is
/// matched on.
fn device_stem(name: &str) -> &str {
    name.split(['.', ':']).next().unwrap().trim_end_matches(' ')
}

/// Whether `stem` is one only Windows 11 maps to a device: `CONIN$`, `CONOUT$`, or `COM` or `LPT` and
/// a superscript digit. Build 26100 maps them as a bare name only, and `is_reserved` refuses them in
/// any position.
fn is_windows_11_device_stem(stem: &str) -> bool {
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CONIN$" | "CONOUT$")
        || ["COM", "LPT"]
            .iter()
            .any(|class| upper.strip_prefix(class).is_some_and(|d| matches!(d, "¹" | "²" | "³")))
}

/// `nt_path_name(s)` with the `UNC` keyword in upper case: the object manager matches it in any
/// case, and Win32 passes a verbatim `\\?\unc\` through as written. `None` where Win32 refuses `s`.
fn nt_path_folded(s: &str) -> Option<String> {
    let nt = try_nt_path_name(s)?;
    Some(match nt.get(..8) {
        Some(head) if head.eq_ignore_ascii_case(r"\??\UNC\") => format!(r"\??\UNC\{}", &nt[8..]),
        _ => nt,
    })
}

/// The plain spelling of the verbatim string `s`, as the parse would store it: `\\` and what
/// follows `UNC\`, a drive path as written, or `\\.\` and the rest.
fn plain_spelling(s: &str) -> String {
    let rest = &s[4..];
    let units: Vec<char> = rest.chars().collect();
    if rest.get(..4).is_some_and(|head| head.eq_ignore_ascii_case(r"UNC\")) {
        format!(r"\\{}", &rest[4..])
    } else if units.len() >= 3 && units[0] != '\\' && units[1] == ':' && units[2] == '\\' {
        rest.to_owned()
    } else {
        format!(r"\\.\{rest}")
    }
}

/// Every verbatim spelling over a small alphabet that parses gives, through `to_wide`, a string
/// Win32 sends to the NT path the input named, a long one included. Each one refused for a `.`,
/// `..` or empty name would name another NT path in its plain spelling.
///
/// Mutants: `to_wide` is the stored text, so `\\?\C:\a.` names `\??\C:\a`; the parse keeps
/// `\\?\C:\a\..`, which `to_wide` spells `C:\a\..`, `\??\C:\`; the parse refuses `\\?\UNC\s\h` as an
/// unspellable server.
#[skuld::test]
fn to_wide_names_the_nt_path_a_verbatim_input_named() {
    let heads = ["", r"C:\", r"UNC\", r"UNC\s", r"UNC\s\h\", r"unc\s\.", r"x\"];
    let rests = strings_over(&["a", ".", " ", "\\", ":", "nul"], 5);
    let mut inputs: Vec<String> = heads
        .iter()
        .flat_map(|head| rests.iter().map(move |rest| format!(r"\\?\{head}{rest}")))
        .collect();
    inputs.push(format!(r"\\?\C:\{}\a.", "a".repeat(300)));
    let (mut converted, mut refused, mut unspellable) = (0, 0, 0);
    for s in inputs {
        match PathBuf::parse(&s) {
            Ok(path) => {
                let units = path.to_wide().unwrap_or_else(|e| panic!("{s:?} as {path:?}: {e}"));
                let w = String::from_utf16(&units).unwrap();
                let want = nt_path_folded(&s).unwrap_or_else(|| panic!("Win32 refuses {s:?}"));
                assert_eq!(nt_path_folded(&w), Some(want), "{s:?} became {w:?}");
                converted += 1;
            }
            Err(e @ (ParseError::DotOrEmptyNameInVerbatim | ParseError::UnspellableUncServer)) => {
                let plain = plain_spelling(&s);
                assert_ne!(
                    nt_path_folded(&plain),
                    nt_path_folded(&s),
                    "{s:?} was refused ({e}), but {plain:?} names it"
                );
                match e {
                    ParseError::UnspellableUncServer => unspellable += 1,
                    _ => refused += 1,
                }
            }
            Err(e) => panic!("{s:?}: {e}"),
        }
    }
    assert!(converted > 10_000, "only {converted} converted");
    assert!(refused > 10_000, "only {refused} refused");
    assert!(unspellable > 10, "only {unspellable} unspellable UNC servers refused");
}

/// Every spelling Win32 maps to a device on this host is refused by both conversions, and `to_wide`
/// gives a string that is no device, with extensions, positions, trailing dots, spaces and colons.
///
/// Mutants: the reserved-name check compares the whole last name, so `NUL.` passes; `to_wide`
/// returns the stored text for a reserved name.
#[skuld::test]
fn reserved_names_cover_every_device_win32_reports() {
    let names = [
        "NUL", "nul", "CON", "PRN", "AUX", "COM1", "COM9", "COM¹", "COM²", "COM³", "LPT1", "LPT³", "CONIN$", "CONOUT$",
        "COM0", "CLOCK$",
    ];
    let suffixes = [
        "", ".", " ", ":", ".:", ":.", "..", ". .", ".txt", ".tar.gz", "  .exe", ":x", ".exe.",
    ];
    let dirs = [
        "",
        r".\",
        r"..\",
        "C:",
        r"\",
        r"C:\x\",
        r"C:\x\a\..\",
        r"\\s\h\",
        r"\\.\x\",
    ];
    let mut devices = 0;
    for dir in dirs {
        for name in names {
            for suffix in suffixes {
                let s = format!("{dir}{name}{suffix}");
                if !is_dos_device(&s) {
                    continue;
                }
                devices += 1;
                let path = PathBuf::parse(&s).unwrap();
                let err = path.to_win32_string().unwrap_err();
                assert_eq!(err.reason(), ConversionReason::ReservedName, "{s:?}");
                // `to_wide` names the file, or has no string for a trailing dot or space.
                match path.to_wide() {
                    Ok(units) => {
                        let w = String::from_utf16(&units).unwrap();
                        assert!(!is_dos_device(&w), "{s:?} is a device to Win32, to_wide gave {w:?}");
                    }
                    Err(e) => assert_eq!(e.reason(), ConversionReason::TrailingDotOrSpace, "{s:?}"),
                }
                if path.is_fully_qualified() {
                    let err = path.win32_normalized().unwrap_err();
                    assert_eq!(err.reason(), ConversionReason::ReservedName, "{s:?}");
                }
            }
        }
    }
    assert!(devices > 50, "only {devices} devices seen");
}

/// `\??\` passes the rest to the object manager untrimmed, while `GetFullPathNameW` reads it as a
/// rooted path, so neither reading is the plain path; a `/` anywhere in the marker makes it rooted
/// for both.
///
/// Mutant: the `\??\` check folds `/` into `\`, so `/??/C:/x` is refused.
#[skuld::test]
fn nt_prefix_passes_through_to_the_object_manager() {
    let s = r"\??\C:\x.";
    assert_eq!(nt_path_name(s), s);
    assert_ne!(get_full_path_name(s), PathBuf::parse(r"C:\x.").unwrap());
    let err = PathBuf::parse(s).unwrap().to_win32_string().unwrap_err();
    assert_eq!(err.reason(), ConversionReason::NtPrefix);
    for s in ["/??/C:/x", r"\??/C:\x", r"/??\C:\x"] {
        assert!(nt_path_name(s).ends_with(r"\??\C:\x"), "{s:?}");
        assert_ne!(nt_path_name(s), r"\??\C:\x", "{s:?}");
        assert!(PathBuf::parse(s).unwrap().to_win32_string().is_ok(), "{s:?}");
    }
}

/// `name` as [`sentinel`] spells it with the letter `mark`: `ZZ{name}Z` for `Z`, except `.`, `..` and
/// the empty name, which stay.
///
/// The trailing mark leaves Win32 nothing to trim. The leading two keep the name from being a device
/// under Windows 10's rules, where the part before the first `.` or `:` decides (`nul.Z` is still
/// NUL). Two `Z`s, because one before a `:` would read as a drive (`Z:`).
fn marked_name(name: &str, mark: char) -> String {
    match name {
        "" | "." | ".." => name.to_owned(),
        _ => format!("{mark}{mark}{name}{mark}"),
    }
}

/// `s` with every name [marked](marked_name) with `mark`. A leading drive designator (`C:`, and `.:`,
/// `?:` or `::`, which Win32 skips the same way) and the `?` of a leading `\\?` are not names:
/// marking them would change what the string is.
fn sentinel(s: &str, mark: char) -> String {
    let separators: Vec<char> = s.chars().filter(|c| matches!(c, '\\' | '/')).collect();
    let segments: Vec<&str> = s.split(['\\', '/']).collect();
    let mut out = String::new();
    for (i, segment) in segments.iter().enumerate() {
        match segment.as_bytes() {
            [drive, b':', ..] if i == 0 => {
                out.push(char::from(*drive));
                out.push(':');
                out.push_str(&marked_name(&segment[2..], mark));
            }
            _ if i == 2 && segments[..2] == ["", ""] && *segment == "?" => out.push('?'),
            _ => out.push_str(&marked_name(segment, mark)),
        }
        if let Some(separator) = separators.get(i) {
            out.push(*separator);
        }
    }
    out
}

/// Whether `path` is a UNC path whose server or share is `.` or `..` and that ends the reading:
/// the names after the anchor, with `.`, `..` and empty ones applied, leave none, and the text does
/// not end in a separator. That includes a path whose later names pop back to the dots share
/// (`\\s\.\b \..`). Win32 trims that dots name from the oracle's reading and the sentinel cannot
/// guard a name that is itself dots, while `to_wide` keeps it as a server or share (the lexical
/// decision). Every other path is compared: with a name kept after the dots, or a trailing
/// separator, nothing is trimmed.
fn dots_end_the_reading(path: &PathBuf) -> bool {
    let Anchor::Unc { server, share } = path.anchor() else {
        return false;
    };
    let dots = |name: &OsStr| matches!(name.to_str(), Some("." | ".."));
    let (mut kept, mut trailing) = (0usize, false);
    for component in path.components() {
        trailing = matches!(component, Component::Empty);
        match component {
            Component::Normal(_) => kept += 1,
            Component::ParentDir => kept = kept.saturating_sub(1),
            Component::CurDir | Component::Empty => {}
        }
    }
    (dots(server) || dots(share)) && kept == 0 && !trailing
}

/// Whether `marked` is `path` with [`sentinel`] (mark `Z`) applied to its names: the same anchor, and
/// the same components. A `Z` can change what a string is (`a:` is a drive, `a:Z` is not; `a:.` has
/// a `.`, `a:.Z` a name), and the oracle is no use then.
fn is_marked_spelling(path: &PathBuf, marked: &PathBuf) -> bool {
    let spelled = |name: &OsStr| marked_name(name.to_str().unwrap(), 'Z');
    let same_anchor = match (path.anchor(), marked.anchor()) {
        (Anchor::Unc { server: s, share: h }, Anchor::Unc { server: ms, share: mh }) => {
            spelled(s) == ms.to_str().unwrap() && spelled(h) == mh.to_str().unwrap()
        }
        (Anchor::Device { name }, Anchor::Device { name: marked }) => spelled(name) == marked.to_str().unwrap(),
        (a, b) => std::mem::discriminant(&a) == std::mem::discriminant(&b),
    };
    let names = path.components().collect::<Vec<_>>();
    let marked_names = marked.components().collect::<Vec<_>>();
    same_anchor
        && path.is_fully_qualified() == marked.is_fully_qualified()
        && path.is_drive_relative() == marked.is_drive_relative()
        && names.len() == marked_names.len()
        && names.iter().zip(&marked_names).all(|pair| match pair {
            (Component::Normal(n), Component::Normal(m)) => spelled(n) == m.to_str().unwrap(),
            (a, b) => std::mem::discriminant(a) == std::mem::discriminant(b),
        })
}

/// Whether `s` holds a name that ends in a dot or space and that `.` and `..` leave in place: one
/// Win32 strips, which no escape prevents. It reads the text only, so it stands apart from the
/// oracle and from `to_wide`.
fn holds_a_name_win32_strips(s: &str) -> bool {
    let mut kept: Vec<&str> = Vec::new();
    for (i, segment) in s.split(['\\', '/']).enumerate() {
        // A leading `X:` is skipped, as in `sentinel`.
        let name = match segment.as_bytes() {
            [_, b':', ..] if i == 0 => &segment[2..],
            _ => segment,
        };
        match name {
            "" | "." => {}
            ".." => {
                kept.pop();
            }
            _ => kept.push(name),
        }
    }
    kept.iter().any(|name| name.ends_with(['.', ' ']))
}

/// The NT path Win32 reaches for the names of `s` as written, or `None` where Win32 refuses `s`.
///
/// The names are [marked](sentinel) so that nothing is left to trim and none is a device, and the
/// marks come off again by structure. Win32's NT path also holds the current directory or the drive
/// directory, which may hold any letter, so the oracle resolves `s` marked with `Z` and with `Y`. A
/// component that differs came from a name of `s`, and its marks come off; one that is the same is
/// from Win32.
fn expected_nt_path(s: &str) -> Option<String> {
    let resolve = |mark| try_get_full_path_name(&sentinel(s, mark)).and_then(|g| nt_path_folded(&g));
    let (with_z, with_y) = (resolve('Z')?, resolve('Y')?);
    let (zs, ys): (Vec<&str>, Vec<&str>) = (with_z.split('\\').collect(), with_y.split('\\').collect());
    assert_eq!(
        zs.len(),
        ys.len(),
        "{s:?} marked with Z and with Y gave different NT paths"
    );
    let unmarked: Vec<&str> = zs
        .into_iter()
        .zip(ys)
        .map(|(z, y)| {
            if z == y {
                return z;
            }
            let name = z.strip_prefix("ZZ").and_then(|n| n.strip_suffix('Z'));
            assert!(
                name.is_some(),
                "{s:?}: {z:?} differs from {y:?} but is not a marked name"
            );
            assert_eq!(name, y.strip_prefix("YY").and_then(|n| n.strip_suffix('Y')), "{s:?}");
            name.unwrap()
        })
        .collect();
    Some(unmarked.join("\\"))
}

/// `s` and the strings that add to it the `.` Win32 drops, where a name would read as a device or an
/// NT path: `.\` before the first name or after a leading drive designator or root, and `\.` at the
/// end. Used to check that a refused `s` has no string that spells its names.
fn with_escapes(s: &str) -> Vec<String> {
    let mut heads = vec![s.to_owned(), format!(r".\{s}")];
    if s.starts_with(['\\', '/']) {
        heads.push(format!(r"{}.{}", &s[..1], s));
    }
    if let [_, b':', ..] = s.as_bytes() {
        heads.push(format!(r"{}.\{}", &s[..2], &s[2..]));
    }
    heads.into_iter().flat_map(|h| [format!(r"{h}\."), h]).collect()
}

/// For every plain sample, fully qualified or not, `to_wide` gives a string whose NT path is the one
/// Win32 reaches by the names as written. The oracle is `GetFullPathNameW` of the sample with each
/// name [marked](marked_name) (nothing left to trim, no device), the NT path of that, and the marks
/// removed again ([`expected_nt_path`]); the current directory is the test process's. Whatever the
/// reason, a refusal must hold a name that ends in a dot or space ([`holds_a_name_win32_strips`]), be
/// for that dot or space and never the reserved name or NT prefix, and neither the sample nor any of
/// its [escapes](with_escapes) may reach the oracle's NT path. Where `to_verbatim` accepts a sample,
/// its NT path is the oracle's too. A few longer dotted-UNC paths are added, where later names pop
/// back to the dots. Every prefix must compare at least `MIN_PER_PREFIX` samples, so one whose
/// samples are all skipped fails here. Two kinds of sample are skipped, and counted: the dotted UNC
/// paths of [`dots_end_the_reading`], and the verbatim spellings of [`ParseSkips`]. A sample the sentinel changes, or that Win32 refuses
/// and is not empty, fails the test.
///
/// Mutants: a non-fully-qualified UNC path takes the verbatim string of its stored text, so
/// `\\\.\.` is refused; `to_wide` returns the stored text for every path `to_win32_string` refuses;
/// the sentinel marks the drive, so no drive-absolute sample is compared; `to_wide` leaves out the
/// `.\` after the root of a `\??\` path, so `\??\x` reaches the object manager as the NT path `x`;
/// `to_wide` refuses `\??\a`, which has the string `\.\??\a`; `is_reserved` leaves out `com1`,
/// `lpt¹` or `conin$`, so that name reaches Win32 bare; `to_verbatim` keeps `/` as written, so
/// `a:/` names another NT path; `dots_end_the_reading` ignores a pop back, so `\\s\.\b \..` is
/// compared and `to_wide` keeps the share `.` against Win32's `\\s\`; `win32_string(true)` refuses a
/// kept name ending `..` when the last name is reserved, so `a..\nul` is refused though `a..\nul\.`
/// names it.
#[skuld::test]
fn to_wide_names_the_nt_path_win32_reaches_by_the_names_as_written() {
    const MIN_PER_PREFIX: usize = 1_000;
    let prefixes = [
        "",
        "/",
        r"\",
        "C:",
        r"C:\",
        "c:/",
        r".\",
        r"..\",
        r"x\",
        r"\x\",
        r"C:x\",
        r"C:\x\",
        r"\\\",
        r"\\",
        r"\\\a\",
        r"\\s",
        r"\\s\",
        r"\\s\h",
        r"\\s\h\",
        "//s/h/",
        r"\\s\\h\",
        r"\\s\h\x\",
        r"\\s.\h.\",
        r"\\s\\..\",
        r"\\.",
        r"\\.\",
        r"\\.\x\",
        r"\\.\..\",
        "//./",
        r"\\.\\",
        r"\\?/",
        "//?/",
        r"\??\",
        r"\??\C:\",
        r"\??\x\",
    ];
    // One name of each family of reserved names, so each reaches the NT comparison.
    let rests = strings_over(
        &[
            "a", ".", " ", ":", "?", "\\", "/", "nul", "con", "com1", "lpt¹", "conin$",
        ],
        4,
    );
    let (mut compared, mut verbatim_compared, mut devices, mut refused, mut nt_refused, mut dotted) =
        (0, 0, 0, 0, 0, 0);
    let mut skips = ParseSkips::default();
    let mut per_prefix = vec![0usize; prefixes.len()];
    // Longer rests than `rests` holds. The first three pop back to a dotted UNC server or share. The
    // others keep a name ending `..` before a reserved last name.
    let longer_rests = [
        r"\\s\.\b \..",
        r"\\\./com /..",
        r"\\\..\...con\..",
        r"a..\nul",
        r"...\com1",
        r"C:a..\con.txt",
    ];
    let cases = prefixes
        .iter()
        .enumerate()
        .flat_map(|(i, prefix)| rests.iter().map(move |rest| (Some(i), format!("{prefix}{rest}"))))
        .chain(longer_rests.iter().map(|s| (None, (*s).to_owned())));
    for (i, s) in cases {
        let path = match PathBuf::parse(&s) {
            Ok(path) => path,
            Err(err) => {
                skips.count(&s, err);
                continue;
            }
        };
        if dots_end_the_reading(&path) {
            dotted += 1;
            continue;
        }
        let marked = sentinel(&s, 'Z');
        if !PathBuf::parse(&marked).is_ok_and(|m| is_marked_spelling(&path, &m)) {
            panic!("the sentinel changes what {s:?} is: {marked:?}");
        }
        let Some(expected) = expected_nt_path(&s) else {
            // Win32 refuses only the empty path.
            assert!(s.is_empty(), "Win32 refuses {marked:?}, from {s:?}");
            assert_eq!(path.to_wide().unwrap_err().reason(), ConversionReason::EmptyPath);
            continue;
        };
        if let Ok(verbatim) = path.to_verbatim() {
            let v = verbatim.to_str().unwrap();
            assert_eq!(nt_path_folded(v), Some(expected.clone()), "{s:?} became {v:?}");
            verbatim_compared += 1;
        }
        match path.to_wide() {
            Ok(units) => {
                let w = String::from_utf16(&units).unwrap();
                let nt = nt_path_folded(&w).unwrap_or_else(|| panic!("Win32 refuses {w:?}, from {s:?}"));
                assert_eq!(nt, expected, "{s:?} became {w:?}");
                devices += usize::from(is_dos_device(&s));
                if let Some(i) = i {
                    per_prefix[i] += 1;
                }
                compared += 1;
            }
            // Whatever the reason given, a refusal is real only where no string spells the names:
            // Win32 strips a trailing dot or space from a name, and no escape stops it.
            Err(e) => {
                assert!(
                    holds_a_name_win32_strips(&s),
                    "{s:?} was refused ({e}), but no name in it ends in a dot or space"
                );
                // The reason is the stripped name, never the reserved name or the NT prefix that
                // the escape would have handled.
                assert!(
                    matches!(
                        e.reason(),
                        ConversionReason::TrailingDotOrSpace | ConversionReason::SingleTrailingDot
                    ),
                    "{s:?} was refused: {e}"
                );
                assert!(!path.is_fully_qualified(), "{s:?} is fully qualified, refused as {e}");
                for candidate in with_escapes(&s) {
                    assert_ne!(
                        nt_path_folded(&candidate),
                        Some(expected.clone()),
                        "{s:?} was refused ({e}), but Win32 reads {candidate:?} as the names written"
                    );
                }
                refused += 1;
                nt_refused += usize::from(s.starts_with(r"\??\"));
            }
        }
    }
    assert!(compared > 100_000, "only {compared} compared");
    skips.assert_each_class_seen();
    assert!(
        verbatim_compared > 10_000,
        "only {verbatim_compared} verbatim strings compared"
    );
    assert!(devices > 1_000, "only {devices} devices compared");
    assert!(refused > 1_000, "only {refused} refused");
    assert!(nt_refused > 100, "only {nt_refused} NT-prefixed samples refused");
    assert!(dotted > 100, "only {dotted} dotted-UNC samples skipped");
    // A prefix whose samples are all skipped would compare nothing and hide in the total.
    for (prefix, count) in prefixes.iter().zip(&per_prefix) {
        assert!(
            *count > MIN_PER_PREFIX,
            "only {count} samples compared after {prefix:?}"
        );
    }
}
