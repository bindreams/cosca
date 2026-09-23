//! The elevated path's program gate, beside the batch gate: the program must be a fully
//! qualified `.exe`/`.com` path with no `"` or `%` in it, and the directory must hold no `%`.
//!
//! The launch is `ShellExecuteEx` with `SEE_MASK_CLASSNAME` and `lpClass = "exefile"`, which runs
//! `HKCR\exefile\shell\runas\command` (`"%1" %*`) on `lpFile`: the class branch returns before
//! shell32's lookup and rewrites (Wine `shlexec.c` `SHELL_execute`, `:1790-1802`).
//!
//! What is measured (`tests/windows_shell_execute.rs`, x64 and arm64 runners) is an ELEVATED
//! caller's `exefile` launch: it consults no App Paths registration, finds nothing by a bare name,
//! and takes a `%` in `lpFile` or `lpDirectory` literally. The production route is different: cosca
//! calls `ShellExecuteEx` only when the caller is NOT elevated, and that launch goes through the
//! consent service. That route is unmeasured, so every rule here is conservative until it is: a
//! fully qualified `.exe`/`.com` path leaves no lookup or default extension to apply whatever the
//! launch does, and a `%` is refused rather than trusted to stay literal. The rewrites shell32
//! makes without a class — quotes stripped, a `file:` URL decoded, `shell:`, `::{CLSID}`, `www`,
//! `%VAR%` — are refused by the same rules, since none of those spellings is a fully qualified image
//! path free of `"` and `%`.

use std::path::Path;

use crate::error::Error;

/// Refuse an elevated program unless it is a fully qualified `.exe`/`.com` path with no `"` or `%`:
/// [`reject_quote`], [`crate::resolve::reject_unloadable_image`], [`reject_percent`] and
/// [`reject_not_fully_qualified`], in that order.
pub(crate) fn reject_elevated_program(program: &Path) -> Result<(), Error> {
    reject_quote(program)?;
    crate::resolve::reject_unloadable_image(program, true)?;
    reject_percent("program", program)?;
    reject_not_fully_qualified(program)
}

/// Refuse an elevated `current_dir()` holding a `%`, for [`reject_percent`]'s reason.
pub(crate) fn reject_percent_in_directory(dir: &Path) -> Result<(), Error> {
    reject_percent("working directory", dir)
}

/// Refuse a `%` in `path`, conservatively: shell32 expands `%VAR%` in `lpFile` and `lpDirectory`
/// on a launch without a class, and whether the consent launch cosca makes does is unmeasured. An
/// elevated caller's `exefile` launch takes it literally (measured), but cosca never makes that
/// launch. The string is refused before any search, so `InvalidInput`.
fn reject_percent(what: &str, path: &Path) -> Result<(), Error> {
    if !path.as_os_str().to_string_lossy().contains('%') {
        return Ok(());
    }
    Err(Error::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "an elevated {what} may not hold a %: ShellExecuteEx may expand it as an environment \
             variable, and whether the consent launch does is unmeasured: {path:?}"
        ),
    )))
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

/// Refuse an elevated program that is not fully qualified: a drive and a root (`C:\`), or two
/// leading separators (UNC, `\\?\`, `\\.\`). A relative or bare name leaves ShellExecuteEx a
/// lookup to make — App Paths, `lpDirectory`, `PATH` — and whether the consent launch makes one is
/// unmeasured; an elevated caller's `exefile` launch finds nothing by a bare name (measured). A
/// drive-relative (`C:x.exe`) or rooted (`\x.exe`) token would be resolved against a current
/// directory, so it is refused too.
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
        "an elevated program must be a fully qualified path (C:\\… or \\\\server\\…): a relative or bare \
         name leaves ShellExecuteEx a lookup to make, which could consult App Paths; resolve it first",
    ))
}

#[cfg(test)]
#[path = "shell_file_tests.rs"]
mod shell_file_tests;
