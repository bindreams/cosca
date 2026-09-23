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

/// What one `App Paths` subkey holds, as [`reject_app_path`] needs it.
#[derive(Debug)]
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) enum AppPath {
    /// No such key, or no default value in it.
    Absent,
    /// The default value, unexpanded.
    Target(std::ffi::OsString),
    /// Present but not readable as a string: access denied, or another value type.
    Unreadable,
}

/// The subkeys of `Software\Microsoft\Windows\CurrentVersion\App Paths` shell32 opens for
/// `program`: the token as given, then with `.exe` appended (Wine `shlexec.c` `SHELL_TryAppPathW`
/// appends on any miss; ReactOS only when there is no extension). The token is appended whole, so a
/// token with a directory opens a nested key.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn app_paths_subkeys(program: &std::ffi::OsStr) -> [std::ffi::OsString; 2] {
    let mut with_exe = program.to_os_string();
    with_exe.push(".exe");
    [program.to_os_string(), with_exe]
}

/// Refuse `program` unless every `App Paths` registration shell32 would consult for it names an
/// image. `SHELL_FindExecutable` asks App Paths FIRST — before any file-exists check, and for any
/// token, bare or not (Wine `shlexec.c:624`; ReactOS `shlexec.cpp:1066`, reached for an `.exe`
/// once the direct launch at `:2534` fails) — and runs the registered target in place of the
/// token. So `foo.exe` registered to `C:\x\setup.bat` runs the batch file.
///
/// `registered` is what each hive holds at each of [`app_paths_subkeys`]. A target must be one
/// path, optionally in one pair of quotes, with no `%` (a `REG_EXPAND_SZ` may be expanded), ending
/// in `.exe` or `.com`; anything unreadable is refused.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn reject_app_path(program: &Path, registered: &[AppPath]) -> Result<(), Error> {
    for entry in registered {
        let acceptable = match entry {
            AppPath::Absent => true,
            AppPath::Unreadable => false,
            AppPath::Target(target) => {
                let target = target.to_string_lossy();
                let bare = target
                    .strip_prefix('"')
                    .and_then(|t| t.strip_suffix('"'))
                    .unwrap_or(&target);
                !bare.contains(['"', '%']) && reject_non_image(Path::new(bare)).is_ok()
            }
        };
        if !acceptable {
            return Err(unsupported(
                program,
                "an App Paths registration for this name runs something that is not an .exe or .com \
                 image, and ShellExecuteEx consults it before the file; name the executable by its path",
            ));
        }
    }
    Ok(())
}

/// Whether the text before the first `:` is two or more UTF-16 units with no separator in it.
fn has_scheme(text: &str) -> bool {
    text.split_once(':')
        .is_some_and(|(scheme, _)| !scheme.contains(['\\', '/']) && scheme.encode_utf16().nth(1).is_some())
}

#[cfg(test)]
#[path = "shell_file_tests.rs"]
mod shell_file_tests;
