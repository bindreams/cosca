//! Joining Windows paths as Win32 reads them: by [`path_type`](super::path_type), never by
//! `PathBuf::join`, which parses a prefix with std's letter-only drive rule and so drops a digit
//! drive's prefix for a rooted name. Every place cosca completes a Windows path uses these two
//! functions: the resolver's candidates and the elevated launch's `lpFile` and `lpDirectory`.
//!
//! Host-independent string operations, so they are exercised from any host.

use std::ffi::{OsStr, OsString};

use super::{drive_len, is_sep, path_type, windows_prefix_len, PathType};

/// `rest` appended to the directory `base`, a separator `sep` between them.
///
/// A verbatim (`\\?\`) base is normalised as std's `PathBuf::push` normalises one: `rest` is split
/// on both separators, `.` dropped, `..` popped but never into the prefix and root, and each
/// remaining component joined with `\`. Win32 passes a verbatim path through unparsed, so a `.`,
/// `..` or `/` left in it would name nothing.
///
/// Any other base takes `rest` as units: Win32 reads the result itself. No separator follows a bare
/// drive (`C:`), which is that drive's current directory, so the result stays drive-relative.
pub(crate) fn append(base: &OsStr, rest: &OsStr, sep: &str) -> OsString {
    if rest.is_empty() {
        return base.to_os_string();
    }
    let bytes = base.as_encoded_bytes();
    if is_verbatim(bytes) {
        return append_verbatim(base, rest);
    }
    let mut out = base.to_os_string();
    let ends_in_sep = bytes.last().is_some_and(|&b| is_sep(b, true));
    if !bytes.is_empty() && !ends_in_sep && drive_len(bytes) != Some(bytes.len()) {
        out.push(sep);
    }
    out.push(rest);
    out
}

/// `name` joined under the directory `base` by its [`PathType`]: a Rooted name keeps `base`'s
/// drive or share, a Relative one is [`append`]ed, and anything else names its own location.
pub(crate) fn join(base: &OsStr, name: &OsStr, sep: &str) -> OsString {
    match path_type(name) {
        PathType::Rooted => {
            let bytes = base.as_encoded_bytes();
            // SAFETY: a prefix ends at a boundary between whole WTF-8 substrings; see
            // `windows_prefix_len`.
            let prefix = unsafe { OsStr::from_encoded_bytes_unchecked(&bytes[..windows_prefix_len(bytes)]) };
            if is_verbatim(bytes) {
                let mut root = prefix.to_os_string();
                root.push("\\");
                return append_verbatim(&root, name);
            }
            let mut out = prefix.to_os_string();
            out.push(name);
            out
        }
        PathType::Relative => append(base, name, sep),
        PathType::Unc | PathType::DriveAbsolute | PathType::DriveRelative => name.to_os_string(),
    }
}

fn is_verbatim(bytes: &[u8]) -> bool {
    bytes.starts_with(br"\\?\")
}

/// [`append`] on a verbatim base.
fn append_verbatim(base: &OsStr, rest: &OsStr) -> OsString {
    let bytes = base.as_encoded_bytes();
    let prefix = windows_prefix_len(bytes);
    // Nothing at or before the root after the prefix is ever popped.
    let floor = prefix + usize::from(bytes.get(prefix).is_some_and(|&b| is_sep(b, true)));
    let mut out: Vec<u8> = bytes.to_vec();
    for piece in rest.as_encoded_bytes().split(|&b| is_sep(b, true)) {
        match piece {
            b"" | b"." => {}
            b".." => {
                while out.len() > floor && out.last().is_some_and(|&b| is_sep(b, true)) {
                    out.pop();
                }
                match out[floor.min(out.len())..].iter().rposition(|&b| is_sep(b, true)) {
                    Some(i) => out.truncate(floor + i),
                    None => out.truncate(floor),
                }
            }
            piece => {
                if !out.last().is_some_and(|&b| is_sep(b, true)) {
                    out.push(b'\\');
                }
                out.extend_from_slice(piece);
            }
        }
    }
    // SAFETY: built from whole WTF-8 substrings of `base` and `rest`, split and joined only at ASCII
    // separators.
    unsafe { OsString::from_encoded_bytes_unchecked(out) }
}

#[cfg(test)]
#[path = "join_tests.rs"]
mod join_tests;
