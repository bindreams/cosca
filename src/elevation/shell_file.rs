//! The elevated path's second gate: refuse an `lpFile` that `ShellExecuteEx` rewrites before it
//! opens it. The batch gate judges the string it is given, so a token the shell turns into a
//! different string is judged on the wrong one: `"C:\tools\setup.bat"` loses its quotes, and
//! `file:///C:/tools/setup%2Ebat` is decoded by `PathCreateFromUrlW`, and both then open
//! `setup.bat` through the `batfile` association — an elevated cmd.exe with an unescaped `%*`.
//!
//! Refused rather than modelled. Each rule below is a rewrite in `SHELL_execute`, read from
//! Wine's `dlls/shell32/shlexec.c` and ReactOS's `dll/win32/shell32/shlexec.cpp`; no Windows
//! measurement stands behind them, so each rule is a superset of the spellings it names.

use std::path::Path;

use crate::error::Error;

/// Refuse a program token `ShellExecuteEx` would rewrite before opening:
///
/// - **a `"` anywhere.** Both strip one pair of surrounding quotes, and ReactOS also splits a
///   token that opens with one into a path and arguments (`PathGetArgsW`/`PathUnquoteSpacesW`).
///   No Win32 file name contains a `"`, so this refuses nothing loadable.
/// - **a URL scheme**: text before the first `:` that is two or more UTF-16 units and holds no
///   separator. A `file:` URL is converted with `PathCreateFromUrlW`, which decodes `%xx`; any
///   other URL goes to its protocol handler. One unit before the colon is a drive (see the batch
///   gate's `drive_prefix_len`), so this cannot refuse a drive-relative path. It does refuse a
///   bare `x.exe:s`, a stream spelling the shell would read as a scheme.
/// - **`shell:` or `::` at the front**: a shell namespace name (ReactOS parses it with
///   `SHParseDisplayName` and invokes the item), not a file path.
/// - **`www` at the front**, in any case: when lookup finds nothing, Wine and ReactOS prefix the
///   token with `http://` and launch that. The prefix alone decides, so a relative
///   `wwwroot\setup.exe` is refused too.
/// - **a `%` anywhere.** Wine runs `ExpandEnvironmentStringsW` over every `lpFile` that is not a
///   `file:` URL, with or without `SEE_MASK_DOENVSUBST` (which this crate does not set); ReactOS
///   expands only under that mask. Windows' own behaviour is unmeasured, so the wider reading wins.
pub(crate) fn reject_shell_rewrite(program: &Path) -> Result<(), Error> {
    let text = program.as_os_str().to_string_lossy();
    let detail = if text.contains('"') {
        Some("ShellExecuteEx strips quotes from lpFile before opening it, so the file it opens is not the one checked; pass the path unquoted")
    } else if text.contains('%') {
        Some("ShellExecuteEx may expand %VARIABLES% in lpFile before opening it, so the file it opens is not the one checked; name the executable")
    } else if text.get(..6).is_some_and(|p| p.eq_ignore_ascii_case("shell:")) || text.starts_with("::") {
        Some("a shell namespace name is not a file path, and ShellExecuteEx invokes whatever item it names; name the executable")
    } else if text.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("www")) {
        Some("ShellExecuteEx relaunches an lpFile starting with `www` as an http:// URL when it finds no file; name the executable by a path that does not start with www")
    } else if has_scheme(&text) {
        Some("ShellExecuteEx reads a `scheme:` prefix as a URL and converts or dispatches it before opening anything; name the executable by a path")
    } else {
        None
    };
    match detail {
        Some(detail) => Err(unsupported(program, detail)),
        None => Ok(()),
    }
}

fn unsupported(program: &Path, detail: &str) -> Error {
    Error::Unsupported {
        op: format!("elevating {}", program.display()),
        platform: "windows",
        detail: detail.into(),
    }
}

/// Refuse a working directory `ShellExecuteEx` rewrites before it searches a relative `lpFile`
/// in it. Wine runs `ExpandEnvironmentStringsW` and then `GetFullPathNameW` over every non-empty
/// `lpDirectory` (`shlexec.c` `SHELL_execute`, with or without `SEE_MASK_DOENVSUBST`), so a `%` is
/// refused, as it is in `lpFile`. A `"` is refused too: no directory name holds one, and it is the
/// character the shell treats as quoting. No URL, namespace or `www` handling applies to
/// `lpDirectory`, and `GetFullPathNameW` is the normalisation the batch gate already models.
pub(crate) fn reject_directory_rewrite(dir: &Path) -> Result<(), Error> {
    if !dir.as_os_str().to_string_lossy().contains(['%', '"']) {
        return Ok(());
    }
    Err(Error::Unsupported {
        op: format!("elevating in {}", dir.display()),
        platform: "windows",
        detail: "ShellExecuteEx expands %VARIABLES% in lpDirectory and searches a relative program \
                 there, so the directory it uses is not the one given; pass it without % or \""
            .into(),
    })
}

/// Refuse an elevated token whose final component does not end, case-insensitively, in `.exe` or
/// `.com`. ShellExecuteEx completes a token by LOOKUP — `PathResolveW` with
/// `PRF_TRYPROGRAMEXTENSIONS` for a bare name and `PathFileExistsDefExtW` for one with a directory
/// (Wine and ReactOS `SHELL_FindExecutable`), both trying `.bat` and `.cmd` — and dispatches any
/// other extension through its association. A string rule, so it needs no resolution.
pub(crate) fn reject_non_image(program: &Path) -> Result<(), Error> {
    let lower = program.as_os_str().to_string_lossy().to_ascii_lowercase();
    if lower.ends_with(".exe") || lower.ends_with(".com") {
        return Ok(());
    }
    Err(unsupported(
        program,
        "an elevated program must name its image, ending in .exe or .com: ShellExecuteEx completes \
         any other token by lookup, which can reach a .bat, and dispatches other extensions through \
         their association",
    ))
}

/// Refuse an elevated program that is not fully qualified: a drive and a root (`C:\`), or two
/// leading separators (UNC, `\\?\`, `\\.\`). The program is launched as `exefile`
/// (`SEE_MASK_CLASSNAME`), which skips shell32's lookup — App Paths, the default-extension search —
/// and runs `lpFile` as given; measured on x64 and arm64 runners, such a launch finds nothing by a
/// bare name, in `lpDirectory` or on `PATH`. A drive-relative (`C:x.exe`) or rooted (`\x.exe`)
/// token would be resolved against a current directory, so it is refused too.
pub(crate) fn reject_not_fully_qualified(program: &Path) -> Result<(), Error> {
    let text = program.as_os_str().to_string_lossy();
    let is_sep = |c: Option<char>| matches!(c, Some('\\' | '/'));
    let drive_rooted =
        crate::child::spawn::drive_prefix_len(&text).is_some_and(|len| is_sep(text[len..].chars().next()));
    let mut chars = text.chars();
    let two_separators = is_sep(chars.next()) && is_sep(chars.next());
    if drive_rooted || two_separators {
        return Ok(());
    }
    Err(unsupported(
        program,
        "an elevated program must be a fully qualified path (C:\\… or \\\\server\\…): it is launched \
         without shell32's lookup, which would otherwise consult App Paths; resolve it first",
    ))
}

/// Whether the text before the first `:` is a non-empty run with no separator in it that is not a
/// drive — two or more UTF-16 units, by the rule [`drive_prefix_len`] applies.
///
/// [`drive_prefix_len`]: crate::child::spawn::drive_prefix_len
fn has_scheme(text: &str) -> bool {
    text.split_once(':').is_some_and(|(scheme, _)| {
        !scheme.is_empty() && !scheme.contains(['\\', '/']) && crate::child::spawn::drive_prefix_len(text).is_none()
    })
}

#[cfg(test)]
#[path = "shell_file_tests.rs"]
mod shell_file_tests;
