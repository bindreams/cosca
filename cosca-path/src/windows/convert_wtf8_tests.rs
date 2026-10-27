//! The conversions on names a `str` cannot hold: a lone surrogate, and a character outside the BMP.

use super::{ConversionError, ConversionReason};
use crate::windows::{OsStr, OsString, PathBuf};

/// A lone surrogate, which no `&str` spells.
const LONE: u16 = 0xD800;

/// The UTF-16 units of `s`, with `@` standing for a lone surrogate. `😀` is a surrogate pair.
fn with_lone(s: &str) -> Vec<u16> {
    s.chars()
        .flat_map(|c| match c {
            '@' => vec![LONE],
            c => c.encode_utf16(&mut [0; 2]).to_vec(),
        })
        .collect()
}

fn p(s: &str) -> PathBuf {
    PathBuf::from_wide(&with_lone(s)).unwrap_or_else(|e| panic!("{s:?} does not parse: {e}"))
}

/// The reason and component of `err`, the component as UTF-16 units.
fn parts(err: &ConversionError) -> (ConversionReason, Option<Vec<u16>>) {
    (err.reason(), err.component().map(OsStr::to_wide))
}

#[track_caller]
fn assert_refused(
    convert: impl Fn(&PathBuf) -> Result<(), ConversionError>,
    s: &str,
    reason: ConversionReason,
    component: &str,
) {
    match convert(&p(s)) {
        Ok(()) => panic!("{s:?} was accepted, expected {reason:?} on {component:?}"),
        Err(err) => assert_eq!(parts(&err), (reason, Some(with_lone(component))), "{s:?}"),
    }
}

/// A Win32 string, as the UTF-16 units a conversion should give for `s`.
fn units(result: Result<OsString, ConversionError>) -> Result<Vec<u16>, ConversionError> {
    result.map(|string| string.to_wide())
}

// to_win32_string =====================================================================================================

/// A lone surrogate and a surrogate pair pass through, unit for unit, and are named in a refusal as
/// written.
///
/// Mutant: the names go through `str`, so a lone surrogate becomes U+FFFD in the string or in the
/// refusal's component.
#[skuld::test]
fn win32_string_keeps_names_a_str_cannot_hold() {
    use ConversionReason::*;
    for s in [r"C:\x\😀@b.exe", r"\\s\h\😀@\y", r"\\.\😀@\x", "C:/😀/@"] {
        assert_eq!(units(p(s).to_win32_string()), Ok(with_lone(s)), "{s:?}");
    }
    let rows = [
        (r"C:\x\😀@b.", TrailingDotOrSpace, "😀@b."),
        (r"C:\x\😀@.\y", SingleTrailingDot, "😀@."),
        (r"C:\x\nul.😀@", ReservedName, "nul.😀@"),
        ("C:\\x\\😀@\0", InteriorNul, "😀@\0"),
    ];
    for (s, reason, component) in rows {
        assert_refused(|path| path.to_win32_string().map(drop), s, reason, component);
    }
}

// to_verbatim =========================================================================================================

/// The verbatim string keeps a lone surrogate and a surrogate pair unit for unit, and a refusal
/// names them as written.
///
/// Mutant: `to_verbatim` goes through `str`, so a lone surrogate becomes U+FFFD.
#[skuld::test]
fn verbatim_keeps_names_a_str_cannot_hold() {
    let rows = [
        (r"C:/x/😀@b.", r"\\?\C:\x\😀@b."),
        (r"\\s\h\😀@ ", r"\\?\UNC\s\h\😀@ "),
        (r"\\.\😀@\x", r"\\?\😀@\x"),
        ("//😀@/h/x", r"\\?\UNC\😀@\h\x"),
    ];
    for (s, expected) in rows {
        assert_eq!(units(p(s).to_verbatim()), Ok(with_lone(expected)), "{s:?}");
    }
    assert_refused(
        |path| path.to_verbatim().map(drop),
        "C:\\😀@\0\\x",
        ConversionReason::InteriorNul,
        "😀@\0",
    );
}

// to_wide =============================================================================================================

/// `to_wide` keeps a lone surrogate and a surrogate pair unit for unit in the plain, verbatim and
/// escaped strings, and names them in a refusal as written.
///
/// Mutant: `to_wide` goes through `str`, so a lone surrogate becomes U+FFFD.
#[skuld::test]
fn to_wide_keeps_names_a_str_cannot_hold() {
    use ConversionReason::*;
    let rows = [
        (r"C:\😀@\b", r"C:\😀@\b"),
        (r"C:\😀@\.\c.", r"\\?\C:\😀@\c."),
        (r"a\😀@\nul", r"a\😀@\nul\."),
        (r"nul.😀@\x", r".\nul.😀@\x"),
    ];
    for (s, expected) in rows {
        assert_eq!(p(s).to_wide(), Ok(with_lone(expected)), "{s:?}");
    }
    let refusals = [
        (r"\x\😀@.\b", SingleTrailingDot, "😀@."),
        ("C:\\x\\😀@\0y\\..\\b", InteriorNul, "😀@\0y"),
    ];
    for (s, reason, component) in refusals {
        assert_refused(|path| path.to_wide().map(drop), s, reason, component);
    }
}

// win32_normalized ====================================================================================================

/// Win32's reading strips a dot or space after a lone surrogate and a surrogate pair, keeps them,
/// and a refusal names them as written.
///
/// Mutant: `win32_normalized` goes through `str`, so a lone surrogate becomes U+FFFD.
#[skuld::test]
fn win32_normalized_keeps_names_a_str_cannot_hold() {
    let rows = [
        (r"C:\😀@b.\y", r"C:\😀@b\y"),
        (r"C:\😀@\..\😀@ . .", r"C:\😀@"),
        (r"\\s\h\😀@\..\@.", r"\\s\h\@"),
    ];
    for (s, expected) in rows {
        assert_eq!(p(s).win32_normalized(), Ok(p(expected)), "{s:?}");
    }
    let refusals = [
        (r"C:\x\nul.😀@", ConversionReason::ReservedName, "nul.😀@"),
        ("C:\\x\\😀@\0", ConversionReason::InteriorNul, "😀@\0"),
    ];
    for (s, reason, component) in refusals {
        assert_refused(|path| path.win32_normalized().map(drop), s, reason, component);
    }
}

// Display =============================================================================================================

/// The message prints a lone surrogate as its code unit and keeps a surrogate pair as written.
///
/// Mutant: `Display` prints the component lossily, so a lone surrogate becomes U+FFFD.
#[skuld::test]
fn conversion_error_displays_a_component_a_str_cannot_hold() {
    let err = p(r"C:\x\😀@b.").to_win32_string().unwrap_err();
    assert_eq!(
        err.to_string(),
        r#"component "😀\u{D800}b." ends in a trailing dot or space, which Win32 strips from the last name"#
    );
}
