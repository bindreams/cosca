use super::{ConversionError, ConversionReason};
use crate::windows::{Anchor, OsStr, OsString, PathBuf};
use crate::PurePath;

fn p(s: &str) -> PathBuf {
    PathBuf::parse(s).unwrap_or_else(|e| panic!("{s:?} does not parse: {e}"))
}

fn os(s: &str) -> OsString {
    OsStr::new(s).to_owned()
}

/// The reason and component of `err`, for comparing against a table row.
fn parts(err: &ConversionError) -> (ConversionReason, Option<&str>) {
    (err.reason(), err.component().map(|c| c.to_str().unwrap()))
}

#[track_caller]
fn assert_refused(
    convert: impl Fn(&PathBuf) -> Result<(), ConversionError>,
    s: &str,
    reason: ConversionReason,
    component: Option<&str>,
) {
    match convert(&p(s)) {
        Ok(()) => panic!("{s:?} was accepted, expected {reason:?} on {component:?}"),
        Err(err) => assert_eq!(parts(&err), (reason, component), "{s:?}"),
    }
}

fn win32(path: &PathBuf) -> Result<(), ConversionError> {
    path.to_win32_string().map(drop)
}

fn verbatim(path: &PathBuf) -> Result<(), ConversionError> {
    path.to_verbatim().map(drop)
}

fn normalized(path: &PathBuf) -> Result<(), ConversionError> {
    path.win32_normalized().map(drop)
}

// to_win32_string =====================================================================================================

/// Each spelling Win32 would read as something else is refused with its reason and component.
///
/// Mutant: `to_win32_string` returns the text as written, whatever it holds.
#[skuld::test]
fn win32_string_refuses_every_rewrite() {
    use ConversionReason::*;
    let rows: &[(&str, ConversionReason, Option<&str>)] = &[
        // Win32 strips every trailing dot and space from the last name.
        (r"C:\x\tool.", TrailingDotOrSpace, Some("tool.")),
        (r"C:\x\tool ", TrailingDotOrSpace, Some("tool ")),
        (r"C:\x\tool. .", TrailingDotOrSpace, Some("tool. .")),
        (r"C:\x\...", TrailingDotOrSpace, Some("...")),
        (r"tool.", TrailingDotOrSpace, Some("tool.")),
        (r"\\s\h.", TrailingDotOrSpace, Some("h.")),
        (r"\\s\..", TrailingDotOrSpace, Some("..")),
        (r"\\.\pipe ", TrailingDotOrSpace, Some("pipe ")),
        // And one trailing dot from any other name that the path keeps.
        (r"C:\x\sub.\t.exe", SingleTrailingDot, Some("sub.")),
        (r"C:\x\sub .\t.exe", SingleTrailingDot, Some("sub .")),
        (r"C:\x\sub.\", SingleTrailingDot, Some("sub.")),
        (r"a.\b", SingleTrailingDot, Some("a.")),
        (r"\\.\x.\y", SingleTrailingDot, Some("x.")),
        // A last name that any supported Windows maps to a device.
        (r"C:\x\NUL", ReservedName, Some("NUL")),
        (r"C:\x\nul.txt", ReservedName, Some("nul.txt")),
        (r"C:\x\COM1", ReservedName, Some("COM1")),
        (r"C:\x\con:x", ReservedName, Some("con:x")),
        (r"C:\x\LPT³", ReservedName, Some("LPT³")),
        (r"C:\x\COM¹", ReservedName, Some("COM¹")),
        (r"C:\x\CONIN$", ReservedName, Some("CONIN$")),
        (r"C:\x\CONIN$.txt", ReservedName, Some("CONIN$.txt")),
        (r"C:\x\a\..\nul", ReservedName, Some("nul")),
        // A reserved name that also ends in a dot or space is refused for the name.
        (r"C:\x\NUL ", ReservedName, Some("NUL ")),
        (r"a\nul.", ReservedName, Some("nul.")),
        (r"nul.\x", ReservedName, Some("nul.")),
        // Win32 refuses an empty string, and no object has an empty name.
        ("", EmptyPath, None),
        (r"nul", ReservedName, Some("nul")),
        (r"C:nul", ReservedName, Some("nul")),
        (r"\aux", ReservedName, Some("aux")),
        // Win32 skips the first two units of a string whose second unit is `:`, so a rooted
        // path whose only name starts with `:` is read from after the colon.
        (r"\:nul", ReservedName, Some(":nul")),
        ("/:nul", ReservedName, Some(":nul")),
        (r"\:NUL:", ReservedName, Some(":NUL:")),
        (r"\:nul.:", ReservedName, Some(":nul.:")),
        (r"\:nul .:", ReservedName, Some(":nul .:")),
        (r"\:nul::", ReservedName, Some(":nul::")),
        (r"\:nul.", ReservedName, Some(":nul.")),
        (r"\:COM1", ReservedName, Some(":COM1")),
        (r"\:nul\x", ReservedName, Some(":nul")),
        ("/:nul/x", ReservedName, Some(":nul")),
        (r"\:com1.txt\y", ReservedName, Some(":com1.txt")),
        (r"\:nul\..\a", ReservedName, Some(":nul")),
        // The first name of a relative or drive-relative path (see `to_win32_string`).
        (r"COM1.TXT\file1.txt", ReservedName, Some("COM1.TXT")),
        (r"NUL\x", ReservedName, Some("NUL")),
        (r"nul.txt\..\a", ReservedName, Some("nul.txt")),
        (r"C:COM1.TXT\f", ReservedName, Some("COM1.TXT")),
        (r"C:NUL\x", ReservedName, Some("NUL")),
        (r"con:x\y", ReservedName, Some("con:x")),
        // A NUL unit ends the string early.
        ("C:\\x\\a\0b", InteriorNul, Some("a\0b")),
        // `\??\` sends the rest to the object manager untouched.
        (r"\??\C:\x", NtPrefix, Some("??")),
    ];
    for &(s, reason, component) in rows {
        assert_refused(win32, s, reason, component);
    }
}

/// A spelling Win32 reads as written converts to that text, separators and all.
///
/// Mutant: every refusal check fires on any trailing dot, so `C:\a\x..\b` is refused.
#[skuld::test]
fn win32_string_keeps_what_win32_reads_as_written() {
    for s in [
        r"C:\x\tool.exe",
        "C:/x/y",
        r"C:\a\.\b",
        r"C:\a\\b\",
        r"C:\a\x..\b",
        r"C:\a\. \b",
        r"C:\a\x. \",
        r"C:\a\x.\..\y",
        r"\\s.\h\x",
        r"\\s\h.\x",
        r"\\s\..\x",
        r"\\.\x\y\..",
        // A device name, and a share after extra separators, is a name `.` skips and `..` removes,
        // for Win32 and for the path alike.
        r"\\.\..\x",
        r"\\.\.",
        r"\\.\x\..",
        r"\\.\x\y\..\..",
        r"\\s\\h\..\x",
        r"\\s\\h.\..\x",
        r"C:\x\NUL\",
        r"C:\x\nul\.",
        r"C:\x\ nul",
        r"C:\x\COM0",
        r"C:\x\CLOCK$",
        r"C:\x\nul¹",
        r"\\s\h\nul",
        r"\\.\x\nul",
        r"\\.\NUL",
        // A device name past the leading component of a relative path is not documented as
        // mapped, and a rooted path skips a `:` only at its head: a later `:nul` is a plain name.
        r"C:\NUL\x",
        r"C:\x\COM1.TXT\f",
        r"\NUL.txt\x",
        r".\nul\x",
        r"..\nul\x",
        r"x\NUL\y",
        r"\\s\h\nul\x",
        r"\\.\x\NUL\y",
        r"\:x",
        r"x\:nul",
        r"\x\:nul",
        "/x/:nul",
        r"\a\:com1",
        r"C:\:nul",
        "/??/C:/x",
        r"\??",
        r"..\x",
    ] {
        assert_eq!(p(s).to_win32_string(), Ok(os(s)), "{s:?}");
    }
}

/// A run of two or more dots ends a name Win32 keeps, except as the last name.
///
/// Mutant: any trailing dot on a non-last name is refused, so `...` and `x..` are too.
#[skuld::test]
fn three_dots_are_a_name() {
    for s in [r"C:\a\...\b", r"C:\a\x..\b", r"C:\a\....\b"] {
        assert_eq!(p(s).to_win32_string(), Ok(os(s)), "{s:?}");
        assert_eq!(p(s).win32_normalized(), Ok(p(s)), "{s:?}");
    }
    assert_refused(win32, r"C:\a\...", ConversionReason::TrailingDotOrSpace, Some("..."));
}

// to_verbatim =========================================================================================================

/// The verbatim form keeps every name as written and writes each separator as `\`.
///
/// Mutant: `to_verbatim` writes the separators as written, so `C:/x` becomes `\\?\C:/x`.
#[skuld::test]
fn verbatim_is_faithful() {
    let rows = [
        (r"C:\x\tool.", r"\\?\C:\x\tool."),
        ("C:/x/NUL", r"\\?\C:\x\NUL"),
        (r"C:\x\a. \b", r"\\?\C:\x\a. \b"),
        (r"C:\", r"\\?\C:\"),
        (r"\\s\h\x ", r"\\?\UNC\s\h\x "),
        ("//s/h", r"\\?\UNC\s\h"),
        (r"\\.\pipe\x", r"\\?\pipe\x"),
        ("//?/C:/x", r"\\?\C:\x"),
        (r"\\?\C:\x.", r"\\?\C:\x."),
        // A share `.` or `..` right after the server is a name to Win32 too.
        (r"\\s\..\x", r"\\?\UNC\s\..\x"),
        // A UNC path with no share has a verbatim form.
        (r"\\s", r"\\?\UNC\s"),
        (r"\\s.\", r"\\?\UNC\s.\"),
    ];
    for (s, expected) in rows {
        assert_eq!(p(s).to_verbatim(), Ok(os(expected)), "{s:?}");
    }
}

/// The verbatim form drops the text Win32 skips before a device name or a share: it belongs to the
/// anchor.
///
/// Mutant: `to_verbatim` copies the device path's text, so `\\.\..\x` becomes `\\?\..\x`.
#[skuld::test]
fn verbatim_drops_what_win32_skips_before_a_name() {
    let rows = [
        (r"\\.\..\x\y", r"\\?\x\y"),
        (r"\\.\.\\x", r"\\?\x"),
        ("//?/./x", r"\\?\x"),
        (r"\\s\\h\x", r"\\?\UNC\s\h\x"),
        (r"\\s\\.\..\h", r"\\?\UNC\s\h"),
    ];
    for (s, expected) in rows {
        assert_eq!(p(s).to_verbatim(), Ok(os(expected)), "{s:?}");
    }
}

/// Verbatim has no relative form, and nothing below Win32 reads `.` or `..`.
///
/// Mutant: `to_verbatim` accepts a drive-relative path and spells it `\\?\C:a`, the device `C:a`.
#[skuld::test]
fn verbatim_refuses_dots_and_relative_paths() {
    use ConversionReason::*;
    let rows: &[(&str, ConversionReason, Option<&str>)] = &[
        (r"a\b", NotFullyQualified, None),
        (r"\a", NotFullyQualified, None),
        (r"C:a", NotFullyQualified, None),
        (r"\\.", NotFullyQualified, None),
        (r"\??\C:\x", NotFullyQualified, None),
        ("", NotFullyQualified, None),
        (r"C:\a\.\b", DotComponent, Some(".")),
        (r"C:\a\..", DotComponent, Some("..")),
        (r"\\s\h\..\x", DotComponent, Some("..")),
        (r"\\s\\h\..", DotComponent, Some("..")),
        (r"\\.\x\..\y", DotComponent, Some("..")),
        // A repeated separator is an empty name under `\\?\`; a plain path skips it.
        (r"C:\a\\b", EmptyComponent, Some("")),
        (r"C:\a\\", EmptyComponent, Some("")),
        (r"\\s\h\\x", EmptyComponent, Some("")),
        (r"\\.\x\\y", EmptyComponent, Some("")),
        ("C:\\a\0", InteriorNul, Some("a\0")),
    ];
    for &(s, reason, component) in rows {
        assert_refused(verbatim, s, reason, component);
    }
}

// to_wide =============================================================================================================

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// The string for Win32 is the path as written where Win32 reads it so, else the verbatim string.
/// Length is not checked.
///
/// Mutants: `to_wide` is the stored text, so `\\?\C:\a.` becomes `C:\a.`, which Win32 reads as
/// `C:\a`; the verbatim fallback is `to_verbatim` of the path as written, which refuses the `.`,
/// `..` and repeated separators Win32 applies (`C:\a\..\b.`); the fallback of a UNC path with no
/// server is `to_verbatim` of the path as written, so `\\\.\.` is refused.
#[skuld::test]
fn to_wide_names_what_the_path_names() {
    let long = format!(r"C:\{}\b", "a".repeat(300));
    let long_verbatim = format!(r"\\?\{long}");
    let rows = [
        (r"\\?\C:\a.", r"\\?\C:\a."),
        (r"\\?\C:\nul", r"\\?\C:\nul"),
        (r"\\?\C:\x", r"C:\x"),
        (r"\\?\UNC\s\h\x ", r"\\?\UNC\s\h\x "),
        (r"\\?\pipe\x", r"\\.\pipe\x"),
        (r"C:\x\tool.", r"\\?\C:\x\tool."),
        (r"\\.\..\x.", r"\\?\x."),
        (r"\\.\x\..", r"\\.\x\.."),
        (r"C:\a\..\b", r"C:\a\..\b"),
        ("C:/x/y", "C:/x/y"),
        (r"a\b", r"a\b"),
        (long_verbatim.as_str(), long.as_str()),
        // `.`, `..` and repeated separators are applied, then the names are kept as written.
        (r"C:\a\..\b.", r"\\?\C:\b."),
        (r"C:\.\con", r"\\?\C:\con"),
        (r"C:\a\nul", r"\\?\C:\a\nul"),
        (r"C:\a\\nul", r"\\?\C:\a\nul"),
        // A reserved name is kept as the file: verbatim where the path is fully qualified, escaped
        // where it is not (see `to_wide_spells_a_reserved_name_or_nt_prefix_as_the_file`).
        (r"C:\x\NUL", r"\\?\C:\x\NUL"),
        ("C:/x/nul", r"\\?\C:\x\nul"),
        // Windows 11's extra names are refused in every position, though build 26100 maps them only
        // as a bare name (see `is_reserved`).
        (r"C:\x\COM¹", r"\\?\C:\x\COM¹"),
        (r"C:\x\CONIN$.txt", r"\\?\C:\x\CONIN$.txt"),
        (r"C:nul", r"C:.\nul\."),
        (r"\\s\h\\x.", r"\\?\UNC\s\h\x."),
        (r"C:\x\.\tool.exe ", r"\\?\C:\x\tool.exe "),
        (r"\\.\x\..\y.", r"\\?\y."),
        // A UNC path with no server is not fully qualified, and its names are kept the same way.
        (r"\\\.\.", r"\\?\UNC\\."),
        (r"\\\a.\.", r"\\?\UNC\\a."),
        (r"\\\a.\\b.", r"\\?\UNC\\a.\b."),
        (r"\\\a\\b.", r"\\?\UNC\\a\b."),
    ];
    for (s, expected) in rows {
        assert_eq!(p(s).to_wide(), Ok(wide(expected)), "{s:?}");
    }
}

/// A path that is not fully qualified and names a device to some Windows, or starts `\??\`, gets a
/// string that names the file instead: `\.` after a reserved last name, `.\` before a reserved first
/// name of a relative or drive-relative path, and `.\` after the root of a rooted path whose first
/// name is `:` and a device name, or is `??`. Win32 drops the `.` and keeps the name (measured on
/// Windows Server 2022, build 20348, Server 2025, build 26100, and Windows 11 on ARM, build 26200:
/// each reads every spelling as the file, `RtlIsDosDeviceName_U` is 0).
///
/// Mutants: `to_wide` refuses a reserved name; it leaves the last name bare, so `a\nul` stays the
/// device; it leaves a reserved first name bare, so `NUL\x` stays the device; it puts the `.\` before
/// the drive of `C:nul`, or leaves `\:nul` bare; it spells only the last name of `nul\nul`; it
/// refuses a leading `\??\`, or puts the `.\` after the `??`.
#[skuld::test]
fn to_wide_spells_a_reserved_name_or_nt_prefix_as_the_file() {
    let rows = [
        // A rooted path that starts `\??\`, which Win32 would hand to the object manager.
        (r"\??\C:\x", r"\.\??\C:\x"),
        (r"\??\x", r"\.\??\x"),
        (r"\??\", r"\.\??\"),
        (r"\??\nul", r"\.\??\nul\."),
        (r"\??\C:\nul", r"\.\??\C:\nul\."),
        // The last name, under each anchor.
        (r"a\nul", r"a\nul\."),
        (r"a\com1", r"a\com1\."),
        (r"a\nul.txt", r"a\nul.txt\."),
        (r"..\nul", r"..\nul\."),
        (r".\nul", r".\nul\."),
        (r"\x\nul", r"\x\nul\."),
        (r"\nul", r"\nul\."),
        (r"\aux", r"\aux\."),
        (r"C:.\nul", r"C:.\nul\."),
        // The first name of a relative or drive-relative path (see `to_win32_string`).
        (r"nul", r".\nul\."),
        (r"C:nul", r"C:.\nul\."),
        (r"COM1.TXT\file1.txt", r".\COM1.TXT\file1.txt"),
        (r"NUL\x", r".\NUL\x"),
        (r"nul.txt\..\a", r".\nul.txt\..\a"),
        (r"C:COM1.TXT\f", r"C:.\COM1.TXT\f"),
        (r"C:NUL\x", r"C:.\NUL\x"),
        (r"con:x\y", r".\con:x\y"),
        (r"nul\nul", r".\nul\nul\."),
        // A rooted path whose first name is `:` and a device name, which Win32 reads from after the
        // colon.
        (r"\:nul", r"\.\:nul"),
        ("/:nul", r"/.\:nul"),
        (r"\:NUL:", r"\.\:NUL:"),
        (r"\:nul.:", r"\.\:nul.:"),
        (r"\:nul .:", r"\.\:nul .:"),
        (r"\:nul::", r"\.\:nul::"),
        (r"\:COM1", r"\.\:COM1"),
        (r"\:nul\x", r"\.\:nul\x"),
        ("/:nul/x", r"/.\:nul/x"),
        (r"\:com1.txt\y", r"\.\:com1.txt\y"),
        (r"\:nul\..\a", r"\.\:nul\..\a"),
        (r"\:nul\nul", r"\.\:nul\nul\."),
    ];
    for (s, expected) in rows {
        assert_eq!(p(s).to_wide(), Ok(wide(expected)), "{s:?}");
        // The spelling is a Win32 string as written, so it is its own.
        assert_eq!(p(expected).to_win32_string(), Ok(os(expected)), "{s:?}");
    }
}

/// A path with no faithful string is refused for the reason that blocks every route: a NUL, or, for
/// a path that is not fully qualified, the trailing dot or space Win32 would strip, even where the
/// name is also reserved (`nul.`) or the path starts `\??\`.
///
/// Mutants: a path neither form keeps falls back to its stored text; `to_wide` reports the Win32
/// string's reason, so `nul.` is `ReservedName` and `\??\a.` is `NtPrefix`.
#[skuld::test]
fn to_wide_refuses_a_path_with_no_faithful_string() {
    use ConversionReason::*;
    let rows: &[(&str, ConversionReason, Option<&str>)] = &[
        (r"a.", TrailingDotOrSpace, Some("a.")),
        (r"nul.", TrailingDotOrSpace, Some("nul.")),
        (r"\:nul.", TrailingDotOrSpace, Some(":nul.")),
        (r"\x\a.\b", SingleTrailingDot, Some("a.")),
        (r"\??\a.", TrailingDotOrSpace, Some("a.")),
        ("C:\\a\0", InteriorNul, Some("a\0")),
        // A later `..` pops the NUL name from Win32's reading; the NUL is still refused.
        ("C:\\a\\x\0y\\..\\b", InteriorNul, Some("x\0y")),
        ("\\\\s\\h\\x\0y\\..\\b", InteriorNul, Some("x\0y")),
        ("\\\\.\\x\0y\\..\\b", InteriorNul, Some("x\0y")),
        ("", EmptyPath, None),
    ];
    for &(s, reason, component) in rows {
        assert_refused(|path| path.to_wide().map(drop), s, reason, component);
    }
}

/// For every fully qualified sample (none holds a NUL), `to_wide` gives the Win32 string or, where
/// that is refused, the verbatim string of the reading that trims no name; the result parses back
/// to a path that gives that string again.
///
/// Mutants: `to_wide` prefers the verbatim string, so `C:\a` becomes `\?\C:\a`; the fallback is
/// `to_verbatim` of the path as written, so `C:\a\..\b.` is refused.
#[skuld::test]
fn to_wide_is_the_win32_string_else_verbatim() {
    let mut verbatim = 0;
    for path in fully_qualified_samples() {
        let units = path.to_wide().unwrap_or_else(|e| panic!("{path:?} is refused: {e}"));
        match path.to_win32_string() {
            Ok(plain) => assert_eq!(units, plain.to_wide(), "{path:?}"),
            Err(_) => {
                let reading = path.win32_reading(false);
                assert_eq!(
                    Ok(units.clone()),
                    reading.to_verbatim().map(|v| v.to_wide()),
                    "{path:?}"
                );
                verbatim += 1;
            }
        }
        let back = PathBuf::from_wide(&units).unwrap();
        assert_eq!(back.to_wide(), Ok(units), "{path:?}");
    }
    assert!(verbatim > 100, "only {verbatim} verbatim samples");
}

/// `to_std_path` is `to_wide` as a `std` path, refusals included.
///
/// Mutant: `to_std_path` is the stored text.
#[cfg(windows)]
#[skuld::test]
fn to_std_path_is_to_wide() {
    use std::os::windows::ffi::OsStrExt;
    for s in [
        r"\\?\C:\a.",
        r"C:\x",
        r"\\.\..\x",
        r"a.",
        r"C:\a\..\b.",
        r"\\\.\.",
        "",
        "C:\\a\\x\0y\\..\\b",
    ] {
        let path = p(s);
        let std = path
            .to_std_path()
            .map(|std| std.as_os_str().encode_wide().collect::<Vec<u16>>());
        assert_eq!(std, path.to_wide(), "{s:?}");
    }
}

// win32_normalized ====================================================================================================

/// `win32_normalized` reads a path as `GetFullPathNameW` does: `.` and `..` resolved, separators
/// collapsed, trailing dots and spaces stripped.
///
/// Mutant: `win32_normalized` is `lexically_normal`, which keeps `tool.`.
#[skuld::test]
fn win32_normalized_applies_win32_rules() {
    let rows = [
        (r"C:\x\tool. .", r"C:\x\tool"),
        (r"C:\x\sub.\t.exe", r"C:\x\sub\t.exe"),
        (r"C:\x\sub .\t", r"C:\x\sub \t"),
        (r"C:\x\a. \b", r"C:\x\a. \b"),
        (r"C:\x\...", r"C:\x\"),
        (r"C:\a\..\b", r"C:\b"),
        (r"C:\a\.", r"C:\a"),
        (r"C:/a//b/", r"C:\a\b\"),
        (r"C:\..\..", r"C:\"),
        (r"\\s\h\..", r"\\s\h"),
        (r"\\s\h\x.", r"\\s\h\x"),
        (r"\\s\h.\x", r"\\s\h.\x"),
        (r"\\s\h ", r"\\s\h"),
        (r"\\.\x\..", r"\\.\"),
        (r"\\.\x.\y", r"\\.\x\y"),
        (r"\\.\..\x", r"\\.\x"),
        (r"\\s\\h\..\x", r"\\s\x"),
        (r"\\s\\h.\x", r"\\s\h\x"),
        ("//?/C:/x.", r"C:\x"),
    ];
    for (s, expected) in rows {
        assert_eq!(p(s).win32_normalized(), Ok(p(expected)), "{s:?}");
    }
}

/// Win32's reading of a relative path depends on the process, and a device name's on the Windows
/// version, so the pure function refuses both.
///
/// Mutants: `win32_normalized` normalises a relative path as if it were rooted; it checks only the
/// path as written, so `C:\x\nul\.` reads as `C:\x\nul`, the device on Win32.
#[skuld::test]
fn win32_normalized_refuses_what_it_cannot_know() {
    use ConversionReason::*;
    let rows: &[(&str, ConversionReason, Option<&str>)] = &[
        (r"a\b.", NotFullyQualified, None),
        (r"C:a", NotFullyQualified, None),
        (r"\a", NotFullyQualified, None),
        (r"C:\x\nul.txt", ReservedName, Some("nul.txt")),
        // The reading's last name is checked too, not only the path's as written.
        (r"C:\x\nul\.", ReservedName, Some("nul")),
        (r"C:\nul\.", ReservedName, Some("nul")),
        (r"C:\x\nul.\.", ReservedName, Some("nul")),
        (r"C:\x\a\nul .txt\.", ReservedName, Some("nul .txt")),
        (r"\??\C:\x", NtPrefix, Some("??")),
        ("C:\\a\0", InteriorNul, Some("a\0")),
    ];
    for &(s, reason, component) in rows {
        assert_refused(normalized, s, reason, component);
    }
}

// Properties ==========================================================================================================

/// Fully qualified spellings over a small alphabet, under each kind of anchor.
fn fully_qualified_samples() -> Vec<PathBuf> {
    let mut all = Vec::new();
    for prefix in [r"C:\", r"\\s\h\", r"\\.\", "//?/"] {
        for rest in small_strings(5) {
            if let Ok(path) = PathBuf::parse(&format!("{prefix}{rest}")) {
                if path.is_fully_qualified() {
                    all.push(path);
                }
            }
        }
    }
    all
}

/// Every string over `{a, ., space, :, ?, \, /}` of up to `max_len` units.
pub(super) fn small_strings(max_len: usize) -> Vec<String> {
    strings_over(&["a", ".", " ", ":", "?", "\\", "/"], max_len)
}

/// Every concatenation of up to `max_len` of `tokens`.
pub(super) fn strings_over(tokens: &[&str], max_len: usize) -> Vec<String> {
    let mut all = vec![String::new()];
    let mut level = vec![String::new()];
    for _ in 0..max_len {
        level = level
            .iter()
            .flat_map(|s| tokens.iter().map(move |t| format!("{s}{t}")))
            .collect();
        all.extend(level.iter().cloned());
    }
    all
}

/// A drive or UNC path `to_win32_string` accepts and that is already in normal form is its own
/// Win32 reading. Device paths are left out: Win32 reads `\\?/x` as `\\?\x` and `\\.\\x` as
/// `\\.\x`, a different anchor from the one written.
///
/// Mutant: `win32_normalized` drops a trailing separator, so `C:\a\` becomes `C:\a`.
#[skuld::test]
fn accepted_normal_paths_are_their_own_win32_reading() {
    let mut checked = 0;
    for path in fully_qualified_samples() {
        let is_device = matches!(path.anchor(), Anchor::Device { .. });
        if is_device || path.to_win32_string().is_err() || path.lexically_normal() != path {
            continue;
        }
        assert_eq!(path.win32_normalized(), Ok(path.clone()), "{path:?}");
        checked += 1;
    }
    assert!(checked > 100, "only {checked} samples checked");
}

/// Win32's reading needs no further rewrite: it converts as written, and reading it again changes
/// nothing.
///
/// Mutants: `win32_normalized` strips only one trailing dot from the last name; it returns a
/// reading that ends in a device name.
#[skuld::test]
fn win32_normalized_is_a_fixed_point() {
    for path in fully_qualified_samples() {
        let Ok(normal) = path.win32_normalized() else {
            continue;
        };
        assert!(normal.to_win32_string().is_ok(), "{path:?} gave {normal:?}");
        assert_eq!(normal.win32_normalized(), Ok(normal.clone()), "{path:?}");
    }
}

// Errors ==============================================================================================================

/// The message of every reason, with its component where it has one, is exact.
///
/// Mutants: `Display` prints only the reason, or drops the component of a reason that has one;
/// a reason's text is swapped with another's.
#[skuld::test]
fn conversion_error_displays_every_reason() {
    let win32 = |s: &str| p(s).to_win32_string().unwrap_err();
    let verbatim = |s: &str| p(s).to_verbatim().unwrap_err();
    let rows = [
        (
            win32(r"C:\x\tool."),
            r#"component "tool." ends in a trailing dot or space, which Win32 strips from the last name"#,
        ),
        (
            win32(r"C:\x\sub.\t"),
            r#"component "sub." ends in a single trailing dot, which Win32 strips"#,
        ),
        (
            win32(r"C:\x\NUL"),
            r#"component "NUL" is a reserved device name, which some Windows versions map to the device"#,
        ),
        (
            win32("C:\\a\0"),
            r#"component "a\0" holds a NUL, which ends a Win32 string"#,
        ),
        (verbatim(r"a\b"), "the path is not fully qualified"),
        (
            verbatim(r"C:\a\.."),
            r#"component ".." is a `.` or `..` this form cannot keep"#,
        ),
        (
            win32(r"\??\C:\x"),
            r#"component "??" starts an NT path (\??\), which Win32 does not interpret"#,
        ),
        (
            verbatim(r"C:\a\\b"),
            r#"component "" is an empty name this form cannot keep"#,
        ),
        (win32(""), "the path is empty, which names nothing"),
    ];
    for (err, message) in rows {
        assert_eq!(err.to_string(), message);
    }
    let _: &dyn std::error::Error = &win32("");
}
