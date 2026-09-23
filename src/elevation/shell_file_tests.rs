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

/// ShellExecuteEx completes an extension-less token by lookup (`PathResolveW` with
/// `PRF_TRYPROGRAMEXTENSIONS`, `PathFileExistsDefExtW`), trying `.bat` and `.cmd` among others, so
/// the elevated path takes only a token that already names an image.
#[test]
fn an_elevated_token_must_end_in_exe_or_com() {
    for token in [
        r"C:\tools\setup.exe",
        "setup.COM",
        "x.EXE",
        r"\\server\share\x.exe",
        "a.b.exe",
    ] {
        assert!(
            super::reject_non_image(Path::new(token)).is_ok(),
            "{token:?} names an image"
        );
    }
    for token in [
        r"C:\tools\setup",
        "setup",
        "setup.bat",
        "setup.cmd",
        "setup.lnk",
        "setup.msc",
        "setup.exe.",
        "setup.exe ",
        "setup.exe:s",
        r"C:\tools\",
        r"C:\tools\setup.exe\",
        "",
    ] {
        assert!(
            matches!(
                super::reject_non_image(Path::new(token)),
                Err(Error::Unsupported { .. })
            ),
            "{token:?} does not end in .exe or .com"
        );
    }
}

/// The subkeys shell32 opens under `App Paths`: the token, then the token with `.exe` appended
/// (Wine appends unconditionally on a miss).
#[test]
fn app_paths_subkeys_are_the_token_and_the_token_plus_exe() {
    assert_eq!(
        super::app_paths_subkeys(std::ffi::OsStr::new(r"C:\tools\foo.exe")),
        [
            std::ffi::OsString::from(r"C:\tools\foo.exe"),
            std::ffi::OsString::from(r"C:\tools\foo.exe.exe")
        ]
    );
}

#[test]
fn an_app_paths_registration_must_name_an_image() {
    use super::AppPath::{Absent, Target, Unreadable};
    let token = Path::new("foo.exe");
    let target = |s: &str| Target(std::ffi::OsString::from(s));
    for registered in [
        vec![Absent, Absent],
        vec![target(r"C:\Program Files\Foo\foo.exe"), Absent],
        vec![Absent, target(r#""C:\Program Files\Foo\foo.exe""#)],
        vec![target(r"C:\Foo\FOO.COM")],
    ] {
        assert!(
            super::reject_app_path(token, &registered).is_ok(),
            "{registered:?} runs an image"
        );
    }
    for registered in [
        vec![target(r"C:\Foo\setup.bat"), Absent],
        vec![Absent, target(r"C:\Foo\setup.cmd")],
        vec![target(r"C:\Foo\setup")],
        vec![target(r"%ProgramFiles%\Foo\foo.exe")],
        vec![target(r"C:\Foo\foo.exe.")],
        vec![target(r#""C:\Foo\foo.exe" x"#)],
        vec![target(r#"C:\Foo\f"o.exe"#)],
        vec![target("")],
        vec![Unreadable],
        vec![target(r"C:\Foo\foo.exe"), Unreadable],
    ] {
        assert!(
            matches!(
                super::reject_app_path(token, &registered),
                Err(Error::Unsupported { .. })
            ),
            "{registered:?} may run something other than an image"
        );
    }
}

/// `lpDirectory` is environment-expanded (Wine, with or without `SEE_MASK_DOENVSUBST`) and then
/// `GetFullPathNameW`-normalised before a relative `lpFile` is searched in it.
#[test]
fn a_directory_shell_execute_rewrites_is_refused() {
    for dir in [r"C:\work\%TEMP%", "%USERPROFILE%", r#""C:\work""#, r#"C:\wo"rk"#] {
        assert!(
            matches!(
                super::reject_directory_rewrite(Path::new(dir)),
                Err(Error::Unsupported { .. })
            ),
            "{dir:?} is rewritten before the search"
        );
    }
    // No URL or namespace handling applies to lpDirectory, so these are plain directories.
    for dir in [
        r"C:\work",
        r"\\server\share\work",
        r"C:\work\ms-settings:x",
        "shell",
        r"C:\www",
    ] {
        assert!(
            super::reject_directory_rewrite(Path::new(dir)).is_ok(),
            "{dir:?} reaches ShellExecuteEx as the directory it is"
        );
    }
}
