use std::path::Path;

use crate::error::Error;

fn refused(token: &str) -> bool {
    matches!(
        super::reject_elevated_program(Path::new(token)),
        Err(Error::Unsupported { .. })
    )
}

/// A `"` would end the `"%1"` quote in `exefile`'s `runas` command early, and no Win32 file name
/// holds one, so it is refused wherever it stands.
#[test]
fn a_quote_anywhere_is_refused() {
    for token in [
        r#""C:\tools\setup.exe""#,
        r#"C:\tools\"setup.exe"#,
        r#"C:\tools\setup" x.exe"#,
        r#"""#,
    ] {
        assert!(refused(token), "{token:?} would break the quoting of \"%1\"");
    }
}

/// The spellings ShellExecuteEx rewrites WITHOUT a class — a URL, a shell namespace name, a `www`
/// prefix, `%VAR%` — are none of them a fully qualified `.exe`/`.com` path, so the class launch
/// never sees one.
#[test]
fn every_rewritten_spelling_is_refused_as_not_a_fully_qualified_image() {
    for token in [
        "file:///C:/tools/setup%2Eexe",
        "http://example.com/setup.exe",
        "ms-settings:",
        "x.exe:s",
        "shell:startup",
        "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}",
        "www.example.exe",
        r"wwwroot\setup.exe",
        "%COMSPEC%",
        r"%SystemRoot%\setup.exe",
    ] {
        assert!(refused(token), "{token:?} is not a fully qualified image path");
    }
}

/// Launched as `exefile`, a `%` is a literal file-name character (measured: `lpFile` and
/// `lpDirectory` alike), so a fully qualified image path holding one runs as named.
#[test]
fn a_fully_qualified_image_path_passes() {
    for token in [
        r"C:\tools\setup.exe",
        r"C:\tools\setup.COM",
        r"C:\tools\100%.exe",
        r"C:\%X%\setup.exe",
        r"\\server\share\setup.exe",
        r"\\?\C:\tools\setup.exe",
        r"C:\www\setup.exe",
    ] {
        assert!(
            super::reject_elevated_program(Path::new(token)).is_ok(),
            "{token:?} is a fully qualified image path"
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
