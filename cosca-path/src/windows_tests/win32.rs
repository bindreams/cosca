//! The parser and `lexically_normal` against Win32's own string functions, which read no
//! filesystem: `RtlDetermineDosPathNameType_U` for the anchor kind, `GetFullPathNameW` for UNC and
//! device anchors and the normal form.
//!
//! Deliberate deviations, each excluded or allowed for by name below:
//! - Names ending in a dot or a space, which Win32 strips (`has_strippable_name`): the Win32
//!   conversions refuse those.
//! - A trailing separator after a name: Win32 drops the one a final `.` leaves (`C:\a\.` is
//!   `C:\a`); the normal form keeps it, as C++'s does.
//! - `\\.` or `\\?` alone: Win32 completes it to `\\.\` (`\\?\`); the normal form keeps the anchor.
//! - Verbatim spellings: Win32 takes the rest as written; parsing drops the prefix.
//!
//! Win32 reads a path's type from the string as written, and `lexically_normal` is a separate
//! step: `\\s\h\..` is a UNC path with a share as written, and resolves to `\\s\`, which is not.
//! The anchor is compared on the string as written (`without_pops`), and the normal form on its own.

use std::ptr;

use super::{os, p, paths_over, small_paths};
use crate::windows::{Anchor, OsStr};
use crate::PurePath;

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

/// Whether `input` has a segment, between separators, that ends in a dot or a space: what Win32
/// strips, found from the string alone. `.` and `..` are exempt (Win32 resolves them) except as the
/// last name in the server, share or device slot of a path that starts with two separators and has
/// no name left after it (`\\..`, `\\s\.`, `\\s\.\a\..`), where Win32 strips them as a name. Wider than Win32, which leaves some
/// (`\\s\h.\x`, `C:\a. \x`).
fn has_strippable_name(input: &str) -> bool {
    let segments: Vec<&str> = input.split(['\\', '/']).collect();
    let two_separators = segments.len() > 2 && segments[0].is_empty() && segments[1].is_empty();
    segments.iter().enumerate().any(|(i, segment)| {
        let in_slot = two_separators && (2..4).contains(&i) && names_left(&segments[i + 1..]) == 0;
        segment.ends_with(['.', ' ']) && (in_slot || !matches!(*segment, "." | ".."))
    })
}

/// How many names are left once `segments` resolve their `.` and `..`.
fn names_left(segments: &[&str]) -> usize {
    segments.iter().fold(0, |depth, segment| match *segment {
        "" | "." => depth,
        ".." => depth.saturating_sub(1),
        _ => depth + 1,
    })
}

/// `input` with every `..` segment replaced by a name, so that nothing after the anchor pops it
/// when Win32 resolves the string; `None` when a `..` comes before the anchor is complete (a share
/// or device name), where the anchor as written cannot be told from the string alone. `kind` is
/// `input`'s type: `UNC_ABSOLUTE` or `LOCAL_DEVICE`.
fn without_pops(input: &str, kind: u32) -> Option<String> {
    let mut start = 0;
    let mut first_pop = None;
    for segment in input.split(['\\', '/']) {
        if segment == ".." {
            first_pop.get_or_insert(start);
        }
        start += segment.len() + 1;
    }
    let Some(pop) = first_pop else {
        return Some(input.to_owned());
    };
    let full = full_path(&input[..pop]);
    let complete = match kind {
        UNC_ABSOLUTE => !win32_unc(&full).1.is_empty(),
        _ => !win32_device(&full).is_empty(),
    };
    complete.then(|| {
        let mut out = String::new();
        let mut rest = input;
        while let Some(i) = rest.find(['\\', '/']) {
            let (segment, tail) = rest.split_at(i);
            out.push_str(if segment == ".." { "zz" } else { segment });
            out.push_str(&tail[..1]);
            rest = &tail[1..];
        }
        out.push_str(if rest == ".." { "zz" } else { rest });
        out
    })
}

/// Whether Win32 reads the full path `full` as needing no current directory: a rooted drive, a
/// device path under `\\.\`, or a UNC path with a server and a share.
fn win32_qualified(full: &str) -> bool {
    match path_type(full) {
        DRIVE_ABSOLUTE | LOCAL_DEVICE => true,
        UNC_ABSOLUTE => {
            let (server, share) = win32_unc(full);
            !server.is_empty() && !share.is_empty()
        }
        _ => false,
    }
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
        if has_strippable_name(&input) {
            continue;
        }
        let ctx = format!("{input:?}; Win32 type {kind}");
        match kind {
            UNC_ABSOLUTE | LOCAL_DEVICE => {
                let Some(written) = without_pops(&input, kind) else {
                    continue;
                };
                let full = full_path(&written);
                let want = if kind == UNC_ABSOLUTE {
                    let (server, share) = win32_unc(&full);
                    Anchor::Unc {
                        server: OsStr::new(server),
                        share: OsStr::new(share),
                    }
                } else {
                    Anchor::Device {
                        name: OsStr::new(win32_device(&full)),
                    }
                };
                assert_eq!(path.anchor(), want, "{ctx}; Win32 {full:?} of {written:?}");
                assert_eq!(path.is_fully_qualified(), win32_qualified(&full), "{ctx}");
            }
            _ => assert_eq!(path.is_fully_qualified(), kind == DRIVE_ABSOLUTE, "{ctx}"),
        }
        assert_eq!(path.is_absolute(), path.is_fully_qualified(), "{ctx}");
    }
}

/// `is_fully_qualified`, `is_absolute` and `anchor` classify the path as written, as
/// `RtlDetermineDosPathNameType_U` does, and `lexically_normal` is a separate step: a `..` after a
/// complete share or device name leaves the written path qualified, and its normal form, which is
/// what Win32 resolves the string to, may not be. For each input the raw string has Win32's path
/// type, the written anchor is the share or device before the `..`, and the normal form is Win32's
/// full path with Win32's qualification.
///
/// Mutant: `is_fully_qualified` reads a UNC path's share from the normal form, so `\\s\h\..` is not
/// fully qualified.
#[skuld::test]
fn anchor_is_read_as_written_before_a_pop() {
    let unc = |server, share| Anchor::Unc {
        server: OsStr::new(server),
        share: OsStr::new(share),
    };
    let device = |name| Anchor::Device { name: OsStr::new(name) };
    // (input, path type, anchor as written); the first is a control, where the `..` pops nothing.
    let cases = [
        (r"\\s\h\..", UNC_ABSOLUTE, unc("s", "h")),
        (r"\\s\\h\..", UNC_ABSOLUTE, unc("s", "h")),
        (r"\\s\\h\.\..", UNC_ABSOLUTE, unc("s", "h")),
        (r"\\s\\h\..\..", UNC_ABSOLUTE, unc("s", "h")),
        (r"//s//h/..", UNC_ABSOLUTE, unc("s", "h")),
        (r"//s//h/./..", UNC_ABSOLUTE, unc("s", "h")),
        (r"\\s\\h\..\x", UNC_ABSOLUTE, unc("s", "h")),
        (r"\\.\d\..", LOCAL_DEVICE, device("d")),
        (r"\\.\\d\..", LOCAL_DEVICE, device("d")),
        (r"//.//d/..", LOCAL_DEVICE, device("d")),
        (r"\\.\\d\.\..", LOCAL_DEVICE, device("d")),
    ];
    for (input, want_kind, want_anchor) in cases {
        let path = p(input);
        let normal = path.lexically_normal();
        let full = full_path(input);
        let ctx = format!("{input:?} normalises to {normal:?}; Win32 {full:?}");
        assert_eq!(path_type(input), want_kind, "{ctx}");
        assert_eq!(path.anchor(), want_anchor, "{ctx}");
        // The written path is qualified, even where its normal form is not.
        assert!(path.is_fully_qualified() && path.is_absolute(), "{ctx}");
        assert_eq!(trim(&normal.to_str().unwrap().replace('/', "\\")), trim(&full), "{ctx}");
        assert_eq!(normal.is_fully_qualified(), win32_qualified(&full), "{ctx}");
    }
    // The class exists: a share that the `..` pops is gone from the normal form.
    let popped = p(r"\\s\\h\..");
    assert!(popped.is_fully_qualified() && !popped.lexically_normal().is_fully_qualified());
    assert_eq!(popped.lexically_normal(), p(r"\\s\"));
    assert_eq!(popped.as_unc().map(|u| (u.server, u.share)), Some((os("s"), os("h"))));
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
        if has_strippable_name(&input) {
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
