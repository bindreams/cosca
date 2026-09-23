//! The elevated path's program gate, beside the batch gate: the program must be a fully
//! qualified `.exe`/`.com` path with no `"` in it.
//!
//! The launch is `ShellExecuteEx` with `SEE_MASK_CLASSNAME` and `lpClass = "exefile"`, which runs
//! `HKCR\exefile\shell\runas\command` (`"%1" %*`) on `lpFile` as given: the class branch returns
//! before shell32's lookup and rewrites (Wine `shlexec.c` `SHELL_execute`, `:1790-1802`). Measured
//! on x64 and arm64 runners (`tests/windows_shell_execute.rs`): such a launch consults no App Paths
//! registration, finds nothing by a bare name, and takes a `%` in `lpFile` or `lpDirectory`
//! literally. So the rewrites shell32 makes without a class — quotes stripped, a `file:` URL
//! decoded, `shell:`, `::{CLSID}`, `www`, `%VAR%` — need no rule of their own: none of those
//! spellings is a fully qualified image path, and the class launch rewrites none.

use std::path::Path;

use crate::error::Error;

/// Refuse an elevated program unless it is a fully qualified `.exe`/`.com` path with no `"`:
/// [`reject_quote`], [`reject_non_image`] and [`reject_not_fully_qualified`], in that order.
pub(crate) fn reject_elevated_program(program: &Path) -> Result<(), Error> {
    reject_quote(program)?;
    reject_non_image(program)?;
    reject_not_fully_qualified(program)
}

/// Refuse a program holding a `"`, a deliberate over-refusal: no Win32 file name contains one, and
/// in `exefile`'s `"%1" %*` command it would close the quote around `%1` early, so the command line
/// `CreateProcessW` parses names a file other than the one checked.
fn reject_quote(program: &Path) -> Result<(), Error> {
    if !program.as_os_str().to_string_lossy().contains('"') {
        return Ok(());
    }
    Err(unsupported(
        program,
        "a \" in the program would end the quotes ShellExecuteEx puts around it; no file name holds one",
    ))
}

fn unsupported(program: &Path, detail: &str) -> Error {
    Error::Unsupported {
        op: format!("elevating {}", program.display()),
        platform: "windows",
        detail: detail.into(),
    }
}

/// Refuse an elevated program whose final component does not end, case-insensitively, in `.exe` or
/// `.com`: `exefile` is the class for an image, and without the class ShellExecuteEx would complete
/// any other token by lookup (`PathResolveW`, `PathFileExistsDefExtW`, both trying `.bat` and
/// `.cmd`) or dispatch it through its own association. A string rule, so it needs no resolution.
fn reject_non_image(program: &Path) -> Result<(), Error> {
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
fn reject_not_fully_qualified(program: &Path) -> Result<(), Error> {
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

#[cfg(test)]
#[path = "shell_file_tests.rs"]
mod shell_file_tests;
