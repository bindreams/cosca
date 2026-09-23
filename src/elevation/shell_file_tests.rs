use std::path::Path;

use crate::error::Error;

fn refused(token: &str) -> bool {
    match super::reject_elevated_program(Path::new(token)) {
        Err(Error::Unsupported { .. }) => true,
        Err(Error::Io(e)) => e.kind() == std::io::ErrorKind::InvalidInput,
        other => panic!("{token:?}: unexpected {other:?}"),
    }
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

#[test]
fn a_fully_qualified_image_path_passes() {
    for token in [
        r"C:\tools\setup.exe",
        r"C:\tools\setup.COM",
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

/// ShellExecuteEx without a class completes an extension-less token by lookup (`PathResolveW` with
/// `PRF_TRYPROGRAMEXTENSIONS`, `PathFileExistsDefExtW`), trying `.bat` and `.cmd` among others, and
/// whether the `exefile` launch does on the consent route is unmeasured, so the elevated path takes
/// only a token that already names an image. The rule is
/// [`crate::resolve::reject_unloadable_image`]'s, so it refuses with `InvalidInput` and names
/// `PATHEXT`, ahead of the fully-qualified rule.
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
            !matches!(super::reject_elevated_program(Path::new(token)), Err(Error::Io(_))),
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
        // A UNC root names a share, not a file.
        r"\\server\share.exe",
        "",
    ] {
        match super::reject_elevated_program(Path::new(token)) {
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput => {
                assert!(e.to_string().contains("PATHEXT"), "{token:?}: {e}");
            }
            other => panic!("{token:?} does not name an .exe or .com image, got {other:?}"),
        }
    }
}

/// A relative or bare name would leave ShellExecuteEx a lookup to make — App Paths, `lpDirectory`,
/// `PATH` — which is unmeasured for the consent launch, so only a fully qualified path is taken.
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
        // The verbatim namespace `UNC/srv`, as NT reads it: `/` is no separator after `\\?\`, so
        // this is no share-less UNC path.
        r"\\?\UNC/srv",
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
        // Separators are read before a drive, as Win32 reads them: rooted, not drive `\`.
        r"\:\setup.exe",
        // Two separators with no share name no file on any drive or share.
        r"\\setup.exe",
    ] {
        assert!(
            matches!(
                super::reject_not_fully_qualified(Path::new(token)),
                Err(Error::Unsupported { .. })
            ),
            "{token:?} is resolved against a directory or looked up"
        );
    }
}

/// A `%` is refused in the program and in the directory, with `InvalidInput`: whether the consent
/// launch expands it is unmeasured, so the refusal is conservative.
#[test]
fn a_percent_is_refused_in_the_program_and_the_directory() {
    let invalid = |r: Result<(), Error>, what: &str| match r {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput => {
            assert!(e.to_string().contains('%'), "{what}: {e}");
        }
        other => panic!("{what}: expected Io(InvalidInput), got {other:?}"),
    };
    for token in [r"C:\tools\100%.exe", r"C:\%X%\setup.exe", r"\\server\share\%X%.exe"] {
        invalid(super::reject_elevated_program(Path::new(token)), token);
    }
    for dir in [r"C:\work\%TEMP%", "%X%", r"C:\100%"] {
        invalid(super::reject_percent_in_directory(Path::new(dir)), dir);
    }
    super::reject_percent_in_directory(Path::new(r"C:\work")).expect("no % here");
}
