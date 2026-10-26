//! The parser and `lexically_normal` against Win32's own string functions, which read no
//! filesystem: `RtlDetermineDosPathNameType_U` for the anchor kind, `GetFullPathNameW` for UNC and
//! device anchors and the normal form.
//!
//! Deliberate deviations, each excluded or allowed for by name below:
//! - Names ending in a dot or a space where Win32 strips them (`has_strippable_name`): the Win32
//!   conversions refuse those.
//! - A trailing separator after a name: Win32 drops the one a final `.` leaves (`C:\a\.` is
//!   `C:\a`); the normal form keeps it, as C++'s does.
//! - `\\.` or `\\?` alone: Win32 completes it to `\\.\` (`\\?\`); the normal form keeps the anchor.
//! - Verbatim spellings: Win32 takes the rest as written; parsing drops the prefix.
//!
//! Win32 reads an anchor only after resolving `..`, which can pop a device name or a share after
//! extra separators; the parse reads it as written. Where a `..` follows, the anchor is compared
//! on the normal form.

use std::ptr;

use super::{p, paths_over, small_paths};
use crate::windows::{parts, Anchor, OsStr, Path};
use crate::{Component, PurePath};

#[link(name = "ntdll", kind = "raw-dylib")]
extern "system" {
    /// Classifies a DOS path from its string alone. Undocumented; exported by every ntdll since
    /// Windows NT.
    fn RtlDetermineDosPathNameType_U(path: *const u16) -> u32;
}

#[link(name = "kernel32", kind = "raw-dylib")]
extern "system" {
    fn GetFullPathNameW(name: *const u16, len: u32, buf: *mut u16, file_part: *mut *mut u16) -> u32;
}

// `RTL_PATH_TYPE` values.
const UNC_ABSOLUTE: u32 = 1;
const DRIVE_ABSOLUTE: u32 = 2;
const DRIVE_RELATIVE: u32 = 3;
const ROOTED: u32 = 4;
const RELATIVE: u32 = 5;
const LOCAL_DEVICE: u32 = 6;
const ROOT_LOCAL_DEVICE: u32 = 7;

/// A directory deep enough that no `..` in the grid climbs out of it.
const BASE: &str = r"\b\b\b\b\b\";

fn wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn path_type(s: &str) -> u32 {
    let units = wide_nul(s);
    // SAFETY: `units` is NUL-terminated and outlives the call, which only reads it.
    unsafe { RtlDetermineDosPathNameType_U(units.as_ptr()) }
}

/// `GetFullPathNameW` of `s`. Callers pass only strings that need no current directory.
fn full_path(s: &str) -> String {
    let units = wide_nul(s);
    let mut buf = vec![0u16; 1024];
    let len = u32::try_from(buf.len()).unwrap();
    // SAFETY: `units` is NUL-terminated, `buf` holds `len` units, and both outlive the call.
    let n = unsafe { GetFullPathNameW(units.as_ptr(), len, buf.as_mut_ptr(), ptr::null_mut()) };
    assert!(n != 0 && n < len, "GetFullPathNameW({s:?}) returned {n}");
    String::from_utf16(&buf[..n as usize]).unwrap()
}

/// Every small path, and longer ones after `\\`, `\\.\` and `C:\` that reach extra separators
/// before a share or device name and a device name popped by `..`. No verbatim spellings.
fn win32_grid() -> Vec<String> {
    let mut all = small_paths();
    let tails = paths_over(&["a", ".", "..", "\\", "/"], 6);
    for prefix in [r"\\", r"\\.\", r"C:\"] {
        all.extend(tails.iter().map(|tail| format!("{prefix}{tail}")));
    }
    all.retain(|s| !s.starts_with(r"\\?\"));
    all.sort_unstable();
    all.dedup();
    all
}

/// Whether `path` has a name ending in a dot or a space that Win32 strips: a component, device name
/// or share after extra separators anywhere, and a share right after the server, or a server
/// alone, only where no name follows it once `.` and `..` resolve (`\\s\h.` and `\\s\h.\x\..` but
/// not `\\s\h.\x`), as measured.
fn has_strippable_name(path: &Path) -> bool {
    let strippable = |name: &OsStr| matches!(name.as_wtf8().last(), Some(b'.' | b' '));
    let bytes = path.as_os_str().as_wtf8();
    let parts = parts(bytes);
    let anchor_name = match parts.anchor {
        // Win32 skips `.` and `..` here; were one read as the name, it should fail the comparison.
        Anchor::Device { name } | Anchor::Unc { share: name, .. } if parts.loose_root.is_some() => {
            strippable(name) && !matches!(name.as_wtf8(), b"." | b"..")
        }
        Anchor::Unc { server, share } => {
            let last = if share.as_wtf8().is_empty() { server } else { share };
            let named = |c: Component<'_, OsStr>| matches!(c, Component::Normal(_));
            strippable(last) && !path.lexically_normal().components().any(named)
        }
        _ => false,
    };
    anchor_name
        || path.components().any(|c| match c {
            Component::Normal(name) => strippable(name),
            _ => false,
        })
}

/// The server and share of Win32's full UNC path `full`; the share is empty when missing.
fn win32_unc(full: &str) -> (&str, &str) {
    let rest = full.strip_prefix(r"\\").unwrap();
    let mut parts = rest.splitn(3, '\\');
    (parts.next().unwrap(), parts.next().unwrap_or(""))
}

/// The device name of Win32's full device path `full`.
fn win32_device(full: &str) -> &str {
    full[4..].split('\\').next().unwrap()
}

/// `s` without a trailing separator after a name (see the module docs). The separator after a
/// drive, `\\.`, `\\?` or another separator stays.
fn trim(s: &str) -> &str {
    let is_drive = |rest: &str| rest.chars().count() == 2 && rest.ends_with(':');
    match s.strip_suffix('\\') {
        Some(rest) if !rest.ends_with('\\') && !is_drive(rest) && !matches!(rest, "" | r"\\." | r"\\?") => rest,
        _ => s,
    }
}

/// The anchor kind is Win32's, and a path is fully qualified when Win32 reads it as a rooted drive,
/// a device path under `\\.\` or a UNC path with a server and a share. A UNC path's server and
/// share and a device name are Win32's. Where a `..` follows them, it can pop a device name or a
/// share after extra separators, and Win32 reads only the result: there the normal form's anchor
/// is compared instead.
///
/// Mutant: the parse reads the empty name after `\\s\` as the share, so `\\s\\h` has an empty share
/// and is not fully qualified.
#[skuld::test]
fn anchors_agree_with_win32() {
    for input in win32_grid() {
        let path = p(&input);
        let kind = path_type(&input);
        let want_kinds: &[u32] = match path.anchor() {
            Anchor::None => &[RELATIVE],
            Anchor::Rooted => &[ROOTED],
            Anchor::Drive { rooted: true, .. } => &[DRIVE_ABSOLUTE],
            Anchor::Drive { rooted: false, .. } => &[DRIVE_RELATIVE],
            Anchor::Unc { .. } => &[UNC_ABSOLUTE],
            Anchor::Device { .. } => &[LOCAL_DEVICE, ROOT_LOCAL_DEVICE],
        };
        assert!(
            want_kinds.contains(&kind),
            "{input:?} is {:?}; Win32 type {kind}",
            path.anchor()
        );
        if has_strippable_name(&path) {
            continue;
        }
        let normal = path.lexically_normal();
        let subject = if path.components().any(|c| c == Component::ParentDir) {
            normal.as_path()
        } else {
            path.as_path()
        };
        let qualified = match kind {
            DRIVE_ABSOLUTE | LOCAL_DEVICE => true,
            UNC_ABSOLUTE => {
                let full = full_path(&input);
                let (server, share) = win32_unc(&full);
                let want = Anchor::Unc {
                    server: OsStr::new(server),
                    share: OsStr::new(share),
                };
                assert_eq!(subject.anchor(), want, "{input:?} as {subject:?}; Win32 {full:?}");
                !server.is_empty() && !share.is_empty()
            }
            _ => false,
        };
        let ctx = format!("{input:?} as {subject:?}; Win32 type {kind}");
        assert_eq!(subject.is_fully_qualified(), qualified, "{ctx}");
        if kind == LOCAL_DEVICE {
            let full = full_path(&input);
            let want = Anchor::Device {
                name: OsStr::new(win32_device(&full)),
            };
            assert_eq!(subject.anchor(), want, "{ctx}; Win32 {full:?}");
        }
    }
}

/// `lexically_normal` is `GetFullPathNameW` without the current directory: a path that needs none
/// normalises to Win32's full path, and any other names the same file as the input under a deep
/// enough base. Up to the deviations the module docs list.
///
/// Mutant: the device name is part of the anchor, so `\\.\d\..` keeps `d`.
#[skuld::test]
fn lexically_normal_agrees_with_win32() {
    for input in win32_grid() {
        let path = p(&input);
        if has_strippable_name(&path) {
            continue;
        }
        let normal = path.lexically_normal();
        let normal = normal.to_str().unwrap();
        let ctx = format!("{input:?} normalises to {normal:?}");
        let (from_input, from_normal) = match path.anchor() {
            Anchor::None => (
                full_path(&format!("C:{BASE}{input}")),
                full_path(&format!("C:{BASE}{normal}")),
            ),
            Anchor::Rooted => (full_path(&format!("C:{input}")), full_path(&format!("C:{normal}"))),
            Anchor::Drive { rooted: false, .. } => {
                let under_base = |s: &str| {
                    let drive_len = s.chars().next().unwrap().len_utf8() + 1;
                    full_path(&format!("{}{BASE}{}", &s[..drive_len], &s[drive_len..]))
                };
                (under_base(&input), under_base(normal))
            }
            _ if path_type(&input) == ROOT_LOCAL_DEVICE => (full_path(&input), full_path(normal)),
            _ => {
                let full = full_path(&input);
                assert_eq!(trim(&normal.replace('/', "\\")), trim(&full), "{ctx}; Win32 {full:?}");
                if let Anchor::Device { name } = p(normal).anchor() {
                    assert_eq!(name, OsStr::new(win32_device(&full)), "{ctx}; Win32 {full:?}");
                }
                continue;
            }
        };
        assert_eq!(trim(&from_normal), trim(&from_input), "{ctx}");
    }
}
