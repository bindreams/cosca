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

/// When lookup fails, Wine and ReactOS turn an `lpFile` starting with `www` into `http://www…` and
/// launch that. Refused on the prefix alone, relative paths such as `wwwroot\setup.exe` included.
#[test]
fn a_www_prefix_is_refused() {
    for token in [
        "www.example.exe",
        "WWW.example.exe",
        "Www",
        r"wwwroot\setup.exe",
        "wwwsetup.exe",
    ] {
        assert!(refused(token), "{token:?} may be relaunched as an http URL");
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
        // Two or more units before the colon, but a separator among them: a path, not a scheme.
        r"tools\setup.exe:s",
        r"C:\tools\ms-settings:x",
        r"1:\tools\setup.exe",
        r"é:setup.exe",
        r"tools\www.exe",
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

/// The elevated program is launched as `exefile`, which skips shell32's lookup — App Paths
/// included — and runs `lpFile` as given, so only a fully qualified path is found at all
/// (measured: a bare name fails in `lpDirectory` and on `PATH`).
#[test]
fn an_elevated_program_must_be_fully_qualified() {
    for token in [
        r"C:\tools\setup.exe",
        "C:/tools/setup.exe",
        r"c:\setup.com",
        r"é:\setup.exe",
        r"\\server\share\setup.exe",
        "//server/share/setup.exe",
        r"\\?\C:\tools\setup.exe",
        r"\\.\C:\tools\setup.exe",
    ] {
        assert!(
            super::reject_not_fully_qualified(Path::new(token)).is_ok(),
            "{token:?} is fully qualified"
        );
    }
    for token in [
        "setup.exe",
        r"tools\setup.exe",
        r".\setup.exe",
        r"..\setup.exe",
        r"\tools\setup.exe",
        "/tools/setup.exe",
        "C:setup.exe",
        r"C:tools\setup.exe",
        r"𝒳:\setup.exe",
        "",
    ] {
        assert!(
            matches!(
                super::reject_not_fully_qualified(Path::new(token)),
                Err(Error::Unsupported { .. })
            ),
            "{token:?} is resolved against a directory, which an exefile launch does not search"
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
