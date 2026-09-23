use std::path::Path;

use crate::error::Error;

fn refused(token: &str) -> bool {
    matches!(
        super::reject_shell_rewrite(Path::new(token)),
        Err(Error::Unsupported { .. })
    )
}

#[test]
fn a_quote_anywhere_is_refused() {
    for token in [
        r#""C:\tools\setup.bat""#,
        r#""setup.bat""#,
        r#""C:\tools\setup.bat" x"#,
        r#"C:\tools\"setup.bat"#,
        r#"""#,
    ] {
        assert!(refused(token), "{token:?}: ShellExecuteEx unquotes it before opening");
    }
}

#[test]
fn a_url_scheme_is_refused() {
    for token in [
        "file:///C:/tools/setup%2Ebat",
        "file:///C:/tools/setup.bat",
        "FILE:C:/tools/setup.bat",
        "file://server/share/setup.bat",
        "http://example.com/setup.bat",
        "ms-settings:",
        "x.exe:s",
        "ab:",
        // Two UTF-16 units before the colon: no drive, so a scheme-shaped prefix.
        "𝒳:x",
        // Not a scheme to `ParseURLW`, which takes letters, digits, `+`, `-` and `.` only, but
        // refused all the same: this checks the shape, not the scheme grammar.
        " file:///C:/setup.bat",
    ] {
        assert!(refused(token), "{token:?} is read as a URL, not a path");
    }
}

#[test]
fn a_shell_namespace_name_is_refused() {
    for token in [
        "shell:startup",
        r"SHELL:Common Startup\setup.bat",
        "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}",
        r"::{20D04FE0-3AEA-1069-A2D8-08002B30309D}\C:\setup.bat",
    ] {
        assert!(refused(token), "{token:?} names a shell namespace item, not a file");
    }
}

#[test]
fn a_percent_sign_is_refused() {
    for token in [r"C:\tools\%SETUP%", "%COMSPEC%", r"C:\tools\100%.exe"] {
        assert!(refused(token), "{token:?} may be environment-expanded");
    }
}

/// Ordinary paths, including every drive and stream spelling the batch gate judges, pass this
/// check untouched: it refuses only what ShellExecuteEx rewrites.
#[test]
fn a_plain_path_passes() {
    for token in [
        r"C:\tools\setup.exe",
        "C:/tools/setup.exe",
        r"C:tools\setup.exe",
        "setup.exe",
        r"tools\setup.exe",
        r"\tools\setup.exe",
        r"\\server\share\setup.exe",
        r"\\?\C:\tools\setup.exe",
        r"\\.\C:\tools\setup.exe",
        r"C:\tools\x.exe:s",
        r"1:\tools\setup.exe",
        r"é:setup.exe",
        "www.example.exe",
        "",
    ] {
        assert!(
            super::reject_shell_rewrite(Path::new(token)).is_ok(),
            "{token:?} reaches ShellExecuteEx as the path it is"
        );
    }
}
