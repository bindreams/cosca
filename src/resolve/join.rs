//! Joining Windows paths as Win32 reads them: by [`path_type`](super::path_type), never by
//! `PathBuf::join`, which parses a prefix with std's letter-only drive rule and so drops a digit
//! drive's prefix for a rooted name. Every place cosca completes a Windows path uses these
//! functions: the resolver's candidates and the raw backend's completed program and working
//! directory. A name made verbatim by a verbatim cwd takes [`concat`], so `GetFullPathNameW`
//! collapses it with Win32's floor.
//!
//! Host-independent string operations, so they are exercised from any host.

use std::ffi::{OsStr, OsString};

use super::{drive_len, has_ascii_drive, is_sep, path_type, windows_prefix_len, PathType};

/// `rest` appended to the directory `base`, a separator `sep` between them.
///
/// A verbatim (`\\?\`) base is rebuilt as std's `PathBuf::push` rebuilds one; see
/// `append_verbatim`. Win32 passes a verbatim path through unparsed, so a `.`, `..`, `/` or empty
/// component left in it by a plain concatenation would name nothing.
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

/// `rest` after the directory `base` as units, a separator `sep` between them unless `base` ends
/// in one, and nothing else. On a verbatim base this is the string Win32 completes a relative name
/// from: `GetFullPathNameW` then collapses its `.` and `..` with Win32's floor (after `\\?\UNC\`),
/// where [`append`] would collapse them with std's (after the share).
pub(crate) fn concat(base: &OsStr, rest: &OsStr, sep: &str) -> OsString {
    let mut out = base.to_os_string();
    if !base.as_encoded_bytes().last().is_some_and(|&b| is_sep(b, true)) {
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
            if is_verbatim(bytes) {
                return append_verbatim(base, name);
            }
            // SAFETY: a prefix ends at a boundary between whole WTF-8 substrings; see
            // `windows_prefix_len`.
            let prefix = unsafe { OsStr::from_encoded_bytes_unchecked(&bytes[..windows_prefix_len(bytes)]) };
            let mut out = prefix.to_os_string();
            out.push(name);
            out
        }
        PathType::Relative => append(base, name, sep),
        PathType::Unc | PathType::DriveAbsolute | PathType::DriveRelative => name.to_os_string(),
    }
}

pub(super) fn is_verbatim(bytes: &[u8]) -> bool {
    bytes.starts_with(br"\\?\")
}

/// The length of a verbatim path's prefix as std parses it, its components split on `\` alone:
/// `\\?\UNC\server\share`, or else `\\?\` and one component (a namespace). So `srv/shr` is one
/// server name, where [`windows_prefix_len`] splits it for its own reasons. `UNC` is matched
/// case-insensitively and only before `\`, as NT matches it, where std matches only `UNC` and
/// also takes `UNC/`: `\\?\UNC/srv` is the namespace `UNC/srv`.
///
/// A drive is std's exception: an ASCII letter and `:` that end the path or precede either
/// separator are the prefix `\\?\C:` alone, so `\\?\C:/x` is drive C, rooted at the `/`. A
/// digit makes no drive here, so `\\?\1:/x` is one namespace.
fn verbatim_prefix_len(bytes: &[u8]) -> usize {
    debug_assert!(is_verbatim(bytes), "{bytes:?} must be verbatim");
    let end = |at: usize| {
        bytes[at..]
            .iter()
            .position(|&b| b == b'\\')
            .map_or(bytes.len(), |i| at + i)
    };
    if bytes.len() >= 8 && bytes[4..7].eq_ignore_ascii_case(b"UNC") && bytes[7] == b'\\' {
        let server = end(8);
        if server >= bytes.len() {
            return bytes.len();
        }
        let share = end(server + 1);
        return if share == server + 1 { server } else { share };
    }
    if has_ascii_drive(&bytes[4..]) && bytes.get(6).is_none_or(|&b| is_sep(b, true)) {
        return 6;
    }
    end(4)
}

/// One component of a verbatim path, as std's `Components` yields it.
#[derive(Clone, Copy, PartialEq)]
enum Part<'a> {
    Cur,
    Parent,
    Normal(&'a [u8]),
}

/// [`append`] on a verbatim base, as std's `PathBuf::push` does it: the base's components (after
/// the prefix, one `\` or `/` taken as the root, the rest split on `\` alone, empty ones dropped,
/// `.` and `..` kept), then `rest`'s (split on both
/// separators, `.` dropped; a leading separator clears back to the root; `..` pops only a normal
/// component), rebuilt as the prefix, its root and the components joined with `\`. A verbatim prefix
/// always has a root, so `\\?\C:` + `t` is `\\?\C:\t`. The prefix is [`verbatim_prefix_len`]'s.
fn append_verbatim(base: &OsStr, rest: &OsStr) -> OsString {
    let bytes = base.as_encoded_bytes();
    let prefix = verbatim_prefix_len(bytes);
    let body = &bytes[prefix..];
    let body = match body.first() {
        Some(&b) if is_sep(b, true) => &body[1..],
        _ => body,
    };
    let mut parts: Vec<Part<'_>> = body
        .split(|&b| b == b'\\')
        .filter_map(|piece| match piece {
            b"" => None,
            b"." => Some(Part::Cur),
            b".." => Some(Part::Parent),
            piece => Some(Part::Normal(piece)),
        })
        .collect();
    let rest = rest.as_encoded_bytes();
    if rest.first().is_some_and(|&b| is_sep(b, true)) {
        parts.clear();
    }
    for piece in rest.split(|&b| is_sep(b, true)) {
        match piece {
            b"" | b"." => {}
            b".." => {
                if let Some(Part::Normal(_)) = parts.last() {
                    parts.pop();
                }
            }
            piece => parts.push(Part::Normal(piece)),
        }
    }
    let mut out: Vec<u8> = bytes[..prefix].to_vec();
    out.push(b'\\');
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            out.push(b'\\');
        }
        out.extend_from_slice(match part {
            Part::Cur => b".",
            Part::Parent => b"..",
            Part::Normal(piece) => piece,
        });
    }
    // SAFETY: built from whole WTF-8 substrings of `base` and `rest`, split and joined only at ASCII
    // separators.
    unsafe { OsString::from_encoded_bytes_unchecked(out) }
}

#[cfg(test)]
#[path = "join_tests.rs"]
mod join_tests;
