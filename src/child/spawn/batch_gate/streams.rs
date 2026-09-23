//! The batch gate's stream and extension predicates: which pieces a path component names, and
//! whether any of them is a batch file.

use super::walk::drive_prefix_len;

/// Whether `file_name` names a batch script to Win32 — every stream piece, not just the name.
///
/// A name reaches a batch file if ANY piece [`ntfs_stream_names`] yields from it does. That
/// covers both ways one can be spelled at once:
///
/// - **As the filesystem resolves it.** `x.bat:s` names `x.bat` through a data stream, and
///   `x.bat ` / `x.bat.` reach it because Win32 strips trailing spaces and dots. The stream half is
///   conservative as far as std goes: `C:\x.bat:s`, `C:\x.bat:` and `C:\x.bat::$DATA` resolve to
///   themselves, which `has_bat_extension` does not read as batch (measured), so std does not
///   substitute cmd.exe. Whether `CreateProcessW` then launches cmd.exe for them itself is
///   unmeasured; [`verbatim_refusal`] names the measurement that would settle it.
/// - **As written.** `ShellExecuteEx` reads the handler off the last `.` anywhere in the string
///   (`PathFindExtension`). std asks a differently-worded question with the same answer: it runs
///   the program through `GetFullPathNameW` — or, for a verbatim `\\?\` path, takes it literally —
///   and tests whether the result ENDS in `.bat`/`.cmd`, case-insensitively
///   (`sys/process/windows.rs`'s `has_bat_extension`). So `x.exe:payload.bat` is a batch file that
///   runs out of the alternate data stream — and it is refused as the PIECE `payload.bat`, not by
///   any separate rule. Testing the whole string for a batch extension beside this adds no
///   refusal; `the_stream_reading_subsumes_the_shell_reading` checks that exhaustively to six
///   characters and keeps it true.
///
/// Reading only the piece before the FIRST separator loosens the gate, because the extension then
/// comes from before the stream name.
///
/// A verbatim (`\\?\`) path reaches here only through [`verbatim_refusal`], which judges its final
/// component by this rule as a stricter reading than std's literal one. Off Win32 nothing reaches
/// here at all — [`reject_batch_path_on`] returns before this, because a `.bat` is an ordinary
/// executable to every other host.
pub(super) fn is_batch_program(file_name: &str) -> bool {
    ntfs_stream_names(file_name).any(is_batch_by_shell)
}

/// Whether the shell would treat `name` as a batch file: the extension is everything after the
/// LAST `.` anywhere in the name, matching `PathFindExtension` and std's own `has_bat_extension`
/// (a case-insensitive `ends_with(".bat" | ".cmd")`, which is the same predicate).
///
/// Deliberately not `Path::extension()`, which differs in two ways that both matter. It returns
/// `None` for a name that IS `.bat` (a leading dot with no other dot), and it stops at nothing —
/// so `x.exe:payload.bat` reads as extension `exe:payload.bat` rather than the `bat` the shell
/// acts on.
pub(super) fn is_batch_by_shell(name: &str) -> bool {
    match name.rfind('.') {
        Some(dot) => {
            let ext = name[dot + 1..].to_ascii_lowercase();
            ext == "bat" || ext == "cmd"
        }
        None => false,
    }
}

/// The file name and every data-stream name inside a path component, each trimmed the way Win32
/// trims a component.
///
/// Split at the stream separators FIRST, then trim each piece — which is NOT what
/// `GetFullPathNameW` does. Measured on x64 and arm64 (the Windows path probe's
/// `a_stream_suffix_stays_in_the_final_component`), it trims only the end of the whole component:
/// `x.bat.:s` and `x.bat :s` come back unchanged. Split-then-trim reads both as the file `x.bat`,
/// and refuses them; whether the filesystem opens stream `s` of `x.bat` or of a file named
/// `x.bat.` for them is unmeasured, so that refusal is conservative. Trim-then-split would leave
/// `x.bat.` / `x.bat `, which the extension check misses.
///
/// EVERY piece, not just the one before the first separator: taking only the first read
/// `x.exe:payload.bat:` as the file `x.exe`, losing the batch name, while the same stream spelled
/// `x.exe:payload.bat` was refused.
///
/// A leading drive prefix (`C:`, or any one UTF-16 unit and `:`; see [`drive_prefix_len`]) is a
/// drive, not a separator. Skipping it changes NO VERDICT — the only piece it suppresses is one
/// UTF-16 unit, which is never a batch name — and it is kept for the contract rather than the
/// verdict: every piece this yields is a name Win32 would open, and a drive is not one.
pub(super) fn ntfs_stream_names(name: &str) -> impl Iterator<Item = &str> {
    let rest = match drive_prefix_len(name) {
        Some(len) => &name[len..],
        None => name,
    };
    rest.split(':').map(|part| part.trim_end_matches([' ', '.']))
}

#[cfg(test)]
#[path = "streams_tests.rs"]
mod streams_tests;
