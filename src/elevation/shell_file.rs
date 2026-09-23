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
    } else if has_scheme(&text) {
        Some("ShellExecuteEx reads a `scheme:` prefix as a URL and converts or dispatches it before opening anything; name the executable by a path")
    } else {
        None
    };
    match detail {
        Some(detail) => Err(Error::Unsupported {
            op: format!("elevating {}", program.display()),
            platform: "windows",
            detail: detail.into(),
        }),
        None => Ok(()),
    }
}

/// Whether the text before the first `:` is two or more UTF-16 units with no separator in it.
fn has_scheme(text: &str) -> bool {
    text.split_once(':')
        .is_some_and(|(scheme, _)| !scheme.contains(['\\', '/']) && scheme.encode_utf16().nth(1).is_some())
}

#[cfg(test)]
#[path = "shell_file_tests.rs"]
mod shell_file_tests;
