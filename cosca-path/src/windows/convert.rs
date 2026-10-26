//! Conversion out: the Win32 string, the verbatim string, and Win32's reading of a path.

use std::fmt;

use super::{fold_separator, is_separator, Anchor, OsStr, OsString, Path, PathBuf, VERBATIM};
use crate::{Component, PurePath};

const NT_PREFIX: &[u8] = br"\??\";

/// Why a [`Path`] did not convert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ConversionReason {
    /// The name that ends Win32's reading ends in a dot or a space, which Win32 strips.
    TrailingDotOrSpace,
    /// Another name the path keeps ends in exactly one dot, which Win32 strips.
    SingleTrailingDot,
    /// A name is one some supported Windows maps to a device (`NUL`, `nul.txt`, `COM1`): the last
    /// name, or the first of a relative path.
    ReservedName,
    /// A NUL unit, which ends a Win32 string early.
    InteriorNul,
    /// The form needs a fully qualified path; the verbatim form also takes a UNC path with no
    /// share.
    NotFullyQualified,
    /// A `.` or `..` component, which the verbatim string would keep as a name.
    DotComponent,
    /// The path starts with `\??\`, which Win32 passes to the object manager untouched.
    NtPrefix,
    /// An empty name from a repeated separator, which the form would keep and Win32 skips.
    EmptyComponent,
    /// The path is empty: Win32 refuses an empty string, and it names nothing.
    EmptyPath,
}

impl ConversionReason {
    fn describe(self) -> &'static str {
        match self {
            ConversionReason::TrailingDotOrSpace => {
                "ends in a trailing dot or space, which Win32 strips from the last name"
            }
            ConversionReason::SingleTrailingDot => "ends in a single trailing dot, which Win32 strips",
            ConversionReason::ReservedName => {
                "is a reserved device name, which some Windows versions map to the device"
            }
            ConversionReason::InteriorNul => "holds a NUL, which ends a Win32 string",
            ConversionReason::NotFullyQualified => "the path is not fully qualified",
            ConversionReason::DotComponent => "is a `.` or `..` this form cannot keep",
            ConversionReason::NtPrefix => r"starts an NT path (\??\), which Win32 does not interpret",
            ConversionReason::EmptyComponent => "is an empty name this form cannot keep",
            ConversionReason::EmptyPath => "the path is empty, which names nothing",
        }
    }
}

/// A [`Path`] that did not convert: the reason, and the component it is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversionError {
    reason: ConversionReason,
    component: Option<OsString>,
}

impl ConversionError {
    fn new(reason: ConversionReason, component: Option<&[u8]>) -> ConversionError {
        ConversionError {
            reason,
            component: component.map(|c| OsStr::from_wtf8(c).to_owned()),
        }
    }

    pub fn reason(&self) -> ConversionReason {
        self.reason
    }

    /// The component, server, share or device name the reason is about, as written; `None` when
    /// the reason is about the whole path.
    pub fn component(&self) -> Option<&OsStr> {
        self.component.as_deref()
    }
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.component {
            Some(c) => write!(f, "component {c:?} {}", self.reason.describe()),
            None => f.write_str(self.reason.describe()),
        }
    }
}

impl std::error::Error for ConversionError {}

// Win32's reading =====================================================================================================

/// What a name in a path's text is to Win32.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// A UNC server, or a share right after it: positional, never navigated, and trimmed only
    /// when it ends the reading.
    Server,
    Share,
    /// A name `.` and `..` apply to: a component, or a device name or share after a loose root.
    Component,
}

#[derive(Debug, Clone, Copy)]
struct Segment<'a> {
    text: &'a [u8],
    role: Role,
}

/// Win32's navigation of a path's segments.
struct Navigation {
    /// The indices of the device name and components Win32 keeps, in order.
    kept: Vec<usize>,
    /// Whether the reading ends in a separator.
    trailing: bool,
}

/// Whether `name` ends in exactly one dot, which Win32 strips from a name that does not end the
/// reading.
fn has_single_trailing_dot(name: &[u8]) -> bool {
    match name {
        [.., b'.', b'.'] => false,
        [.., b'.'] => name.len() > 1,
        _ => false,
    }
}

fn ends_in_dot_or_space(name: &[u8]) -> bool {
    matches!(name, [.., b'.' | b' '])
}

fn trim_trailing_dots_and_spaces(mut name: &[u8]) -> &[u8] {
    while let [rest @ .., b'.' | b' '] = name {
        name = rest;
    }
    name
}

/// Whether some supported Windows maps a name to a device: the union of Windows 10's rule,
/// where the part before the first `.` or `:` counts (`nul.txt`), and Windows 11's, which adds
/// `CONIN$`, `CONOUT$` and the superscript digits.
///
/// The Windows 11 names are refused in any position and with any extension, as Windows 10's rule
/// treats the classic ones. Build 26100 maps them only as a bare name, but builds 22000-22631 are
/// unmeasured, so the widest reading stands; the cost is that `to_wide` spells such a path escaped
/// or verbatim instead of plain.
fn is_reserved(name: &[u8]) -> bool {
    let stem_end = name.iter().position(|&b| b == b'.' || b == b':').unwrap_or(name.len());
    let mut stem = &name[..stem_end];
    while let [rest @ .., b' '] = stem {
        stem = rest;
    }
    let fixed: [&[u8]; 6] = [b"CON", b"PRN", b"AUX", b"NUL", b"CONIN$", b"CONOUT$"];
    if fixed.iter().any(|f| stem.eq_ignore_ascii_case(f)) {
        return true;
    }
    if stem.len() < 4 {
        return false;
    }
    let (prefix, digit) = stem.split_at(3);
    let numbered = prefix.eq_ignore_ascii_case(b"COM") || prefix.eq_ignore_ascii_case(b"LPT");
    // `¹`, `²`, `³` in UTF-8.
    numbered && matches!(digit, [b'1'..=b'9'] | [0xC2, 0xB9 | 0xB2 | 0xB3])
}

/// The names of a path that some Windows maps to a device, as written.
#[derive(Default)]
struct ReservedNames<'a> {
    /// The last name.
    last: Option<&'a [u8]>,
    /// The first name, where it counts: that of a relative or drive-relative path, or the `:` name
    /// of a rooted one.
    first: Option<&'a [u8]>,
}

/// The name of a `Normal` component.
fn normal_name(component: Component<'_, OsStr>) -> Option<&[u8]> {
    match component {
        Component::Normal(name) => Some(name.as_wtf8()),
        _ => None,
    }
}

impl Path {
    /// Every name in the text, in order. After a loose root (`\\.\`, `\\server\`) that is each
    /// piece, the device name or share among them; otherwise the UNC server and share, then the
    /// components.
    fn segments(&self) -> Vec<Segment<'_>> {
        let parts = self.parts();
        let component = |text| Segment {
            text,
            role: Role::Component,
        };
        if let Some(root) = parts.loose_root {
            return self.bytes()[root..].split(is_separator).map(component).collect();
        }
        let mut segments = Vec::new();
        if let Anchor::Unc { server, share } = parts.anchor {
            segments.push(Segment {
                text: server.as_wtf8(),
                role: Role::Server,
            });
            if parts.head > 2 + server.as_wtf8().len() {
                segments.push(Segment {
                    text: share.as_wtf8(),
                    role: Role::Share,
                });
            }
        }
        segments.extend(self.components().map(|c| component(c.as_wtf8())));
        segments
    }

    /// Applies `.`, `..` and empty names to `segments` as Win32 does.
    fn navigate(&self, segments: &[Segment<'_>]) -> Navigation {
        let mut nav = Navigation {
            kept: Vec::new(),
            trailing: false,
        };
        for (i, segment) in segments.iter().enumerate() {
            if segment.role != Role::Component {
                continue;
            }
            nav.trailing = segment.text.is_empty();
            match segment.text {
                b"" | b"." => {}
                b".." => {
                    nav.kept.pop();
                }
                _ => nav.kept.push(i),
            }
        }
        nav.trailing |= self.bytes().last().is_some_and(is_separator);
        nav
    }

    /// The segment whose end is the end of Win32's reading, if a name is there.
    fn reading_end<'a>(segments: &[Segment<'a>], nav: &Navigation) -> Option<Segment<'a>> {
        if nav.trailing {
            return None;
        }
        match nav.kept.last() {
            Some(&k) => Some(segments[k]),
            None => segments
                .iter()
                .rev()
                .find(|s| matches!(s.role, Role::Server | Role::Share))
                .copied(),
        }
    }

    /// The separator-delimited piece of the text that holds a NUL, if any.
    fn nul_piece(&self) -> Option<&[u8]> {
        self.bytes().split(is_separator).find(|piece| piece.contains(&0))
    }

    /// The refusals [`to_win32_string`](Self::to_win32_string) and
    /// [`win32_normalized`](Self::win32_normalized) share. With `spell`, a leading `\??\` and a
    /// reserved name are left for the caller to escape.
    fn check_win32(&self, need_fully_qualified: bool, spell: bool) -> Result<(), ConversionError> {
        if let Some(piece) = self.nul_piece() {
            return Err(ConversionError::new(ConversionReason::InteriorNul, Some(piece)));
        }
        if !spell && self.bytes().starts_with(NT_PREFIX) {
            return Err(ConversionError::new(ConversionReason::NtPrefix, Some(b"??")));
        }
        if need_fully_qualified && !self.is_fully_qualified() {
            return Err(ConversionError::new(ConversionReason::NotFullyQualified, None));
        }
        let reserved = self.reserved_names();
        match reserved.last.or(reserved.first) {
            Some(name) if !spell => Err(ConversionError::new(ConversionReason::ReservedName, Some(name))),
            _ => Ok(()),
        }
    }

    /// The names some Windows may map to a device, as written. UNC and device paths never map
    /// (measured on builds 20348, 26100 and 26200: `\\s\h\com1` and `\\.\x\nul` are not devices).
    fn reserved_names(&self) -> ReservedNames<'_> {
        let anchor = self.anchor();
        if matches!(anchor, Anchor::Unc { .. } | Anchor::Device { .. }) {
            return ReservedNames::default();
        }
        let first = self.components().next().and_then(normal_name);
        let last = self.components().next_back().and_then(normal_name);
        ReservedNames {
            last: last.filter(|name| is_reserved(name)),
            first: match anchor {
                // Win32 skips the first two units of a string whose second unit is `:`. A drive
                // anchor already holds them; `\:` and `/:` leave a rooted path whose first name
                // starts with `:` and is read from after it.
                Anchor::Rooted => first.filter(|name| name.starts_with(b":") && is_reserved(&name[1..])),
                // Microsoft documents that before Windows 11 a path that begins with a device name is
                // the device, wherever the name ends (`COM1.TXT\file1.txt`). Build 20348 did not
                // reproduce it and Windows 10 client builds are unmeasured, so the name is kept apart.
                Anchor::None | Anchor::Drive { rooted: false, .. } => first.filter(|name| is_reserved(name)),
                _ => None,
            },
        }
    }

    /// The Win32 string: the path as written, with no prefix, or a refusal. It never rewrites. Refused
    /// where Win32 would read the text as something else:
    ///
    /// - a trailing dot or space on the name that ends Win32's reading (`x.`, and `x..` in
    ///   `x..\.`), a server, share or device name included;
    /// - one trailing dot on another name the reading keeps (`x.\y`; `x..` and `...` are names);
    /// - a last name some supported Windows maps to a device (`NUL`, `nul.txt`, `COM1`), and the
    ///   first name of a relative or drive-relative path (`NUL\x`, `COM1.TXT\file1.txt`, `C:NUL\x`),
    ///   which Microsoft documents as read as the device wherever the name ends before Windows 11
    ///   ("File path formats on Windows systems", "Handle legacy devices"). Builds 20348 and 26100
    ///   read these as files, but Windows 10 client builds are unmeasured, so the refusal follows
    ///   the documentation: a name is accepted only if no supported Windows maps it. `to_wide`
    ///   escapes these names instead.
    ///   Nothing else is documented as mapped, so `C:\x\COM1.TXT\f` is kept, and so is any UNC or
    ///   device path, which Windows does not map (measured on builds 20348, 26100 and 26200);
    /// - a rooted path whose first name is `:` and a device name (`\:nul\x`), which Win32 reads
    ///   from after the `:`; no file name holds a `:`;
    /// - an empty path, which Win32 refuses and which names nothing; a NUL, or a leading `\??\`.
    ///
    /// Use [`to_wide`](Self::to_wide) for a string that names what the path names, escaping a
    /// reserved name or a leading `\??\`; [`to_verbatim`](Self::to_verbatim) to keep a refused path;
    /// or [`win32_normalized`](Self::win32_normalized) for Win32's reading of it. Length is not
    /// checked.
    pub fn to_win32_string(&self) -> Result<OsString, ConversionError> {
        self.win32_string(false)
    }

    /// [`to_win32_string`](Self::to_win32_string), or with `spell` a string for the same names with a
    /// `.` that Win32 drops, so that no Windows reads a device or an NT path: `\.` after a reserved
    /// last name (`a\nul` is `a\nul\.`), `.\` before a reserved first name of a relative or
    /// drive-relative path, and `.\` after the root of a rooted path that starts `\??\` (`\.\??\x`)
    /// or whose first name is `:` and a device name (`\:nul` is `\.\:nul`). Still refused for a
    /// trailing dot or space, an empty path and a NUL.
    fn win32_string(&self, spell: bool) -> Result<OsString, ConversionError> {
        if self.bytes().is_empty() {
            return Err(ConversionError::new(ConversionReason::EmptyPath, None));
        }
        self.check_win32(false, spell)?;
        let segments = self.segments();
        let nav = self.navigate(&segments);
        let end = Path::reading_end(&segments, &nav);
        if let Some(end) = end.filter(|end| ends_in_dot_or_space(end.text)) {
            return Err(ConversionError::new(
                ConversionReason::TrailingDotOrSpace,
                Some(end.text),
            ));
        }
        let ends_reading = |k: usize| !nav.trailing && nav.kept.last() == Some(&k);
        let single_dot = nav
            .kept
            .iter()
            .find(|&&k| !ends_reading(k) && has_single_trailing_dot(segments[k].text));
        if let Some(&k) = single_dot {
            return Err(ConversionError::new(
                ConversionReason::SingleTrailingDot,
                Some(segments[k].text),
            ));
        }
        let reserved = self.reserved_names();
        let nt_prefix = self.bytes().starts_with(NT_PREFIX);
        if reserved.first.is_none() && reserved.last.is_none() && !nt_prefix {
            return Ok(self.as_os_str().to_owned());
        }
        debug_assert!(spell, "check_win32 refuses these unless spelling");
        // Windows Server 2022 (build 20348), Server 2025 (26100) and Windows 11 on ARM (26200)
        // each read `a\nul\.`, `.\nul\.`, `\.\:nul`, `\.\??\x` and `\.\??\nul\.` as the file
        // (`C:\??\x`, `C:\??\nul`), and none as a device or an NT path.
        let bytes = self.bytes();
        let at = self.parts().start();
        let mut out = bytes[..at].to_vec();
        if reserved.first.is_some() || nt_prefix {
            out.extend_from_slice(b".\\");
        }
        out.extend_from_slice(&bytes[at..]);
        if reserved.last.is_some() {
            out.extend_from_slice(b"\\.");
        }
        Ok(OsString(out))
    }

    /// The verbatim string, `\\?\C:\…`, `\\?\UNC\server\share\…` or `\\?\name\…` for a device
    /// path. It keeps every name as written, trailing dots and device names included, drops what
    /// Win32 skips before a device name or share (`\\.\..\x` is `\\?\x`), and writes each
    /// separator as `\`. Refused for a NUL; for a relative, rooted or drive-relative path, or `\\.`
    /// alone, since verbatim has no such form (`\\?\C:a` is the device `C:a`); and for a `.` or `..`
    /// component, or an empty one before the last, which Win32 would read as a name here and
    /// apply in the plain path.
    pub fn to_verbatim(&self) -> Result<OsString, ConversionError> {
        if let Some(piece) = self.nul_piece() {
            return Err(ConversionError::new(ConversionReason::InteriorNul, Some(piece)));
        }
        let bytes = self.bytes();
        let parts = self.parts();
        let has_form = match parts.anchor {
            Anchor::Drive { rooted, .. } => rooted,
            Anchor::Unc { .. } => true,
            Anchor::Device { .. } => bytes.len() > 3,
            Anchor::None | Anchor::Rooted => false,
        };
        if !has_form {
            return Err(ConversionError::new(ConversionReason::NotFullyQualified, None));
        }
        let components: Vec<_> = self.components().collect();
        for (i, c) in components.iter().enumerate() {
            match c {
                Component::CurDir | Component::ParentDir => {
                    return Err(ConversionError::new(ConversionReason::DotComponent, Some(c.as_wtf8())));
                }
                Component::Empty if i + 1 < components.len() => {
                    return Err(ConversionError::new(ConversionReason::EmptyComponent, Some(b"")));
                }
                _ => {}
            }
        }
        let rest = match (parts.anchor, self.loose_name_start()) {
            (Anchor::Unc { server, .. }, Some(start)) => {
                [b"UNC\\".as_slice(), server.as_wtf8(), b"\\", &bytes[start..]].concat()
            }
            (Anchor::Unc { .. }, None) => [b"UNC\\".as_slice(), &bytes[2..]].concat(),
            (_, Some(start)) => bytes[start..].to_vec(),
            _ => bytes.to_vec(),
        };
        let mut out = VERBATIM.to_vec();
        out.extend(rest.iter().map(fold_separator));
        Ok(OsString(out))
    }

    /// The string to hand Win32 for this path, naming what the path's names spell, with `.`, `..`
    /// and repeated separators as Win32 applies them. In order:
    ///
    /// 1. the [Win32 string](Self::to_win32_string), where it exists;
    /// 2. for a fully qualified path, or a UNC path missing its server or share, the verbatim string
    ///    of its reading with no name trimmed (`C:\a\..\b.` is `\\?\C:\b.`, `C:\x\nul` is
    ///    `\\?\C:\x\nul`, `\\\a.\.` is `\\?\UNC\\a.`);
    /// 3. for any other path, the Win32 string with the `.` that Win32 drops where a name would read
    ///    as a device or an NT path: `a\nul` is `a\nul\.`, `NUL\x` is `.\NUL\x`, `\:nul` is
    ///    `\.\:nul`, `\??\x` is `\.\??\x`.
    ///
    /// Refused for a NUL, an empty path, and a path that is not fully qualified and whose trailing
    /// dot or space Win32 would strip (`tool.`, `\x\a.`), with that trailing dot as the reason, also
    /// where the name is reserved or the path starts `\??\` (`nul.`, `\??\x.`).
    ///
    /// Length is not checked: a plain string past `MAX_PATH` names the same object, but a process
    /// that is not long-path aware cannot open it. Such a caller uses `to_verbatim`.
    pub fn to_wide(&self) -> Result<Vec<u16>, ConversionError> {
        if let Ok(plain) = self.to_win32_string() {
            return Ok(plain.to_wide());
        }
        // `.`, `..` and repeated separators are Win32's to apply, not reasons to refuse: the
        // verbatim string of the reading that trims no name keeps every name as written.
        let verbatim = if self.has_pure_reading() {
            self.win32_reading(false).to_verbatim()
        } else {
            self.to_verbatim()
        };
        match verbatim {
            Ok(verbatim) => Ok(verbatim.to_wide()),
            // Not fully qualified: escape what Win32 would read as a device or an NT path. What the
            // escape cannot spell is the reason that blocks every route, not the name it would have
            // escaped.
            Err(e) if e.reason() == ConversionReason::NotFullyQualified => {
                self.win32_string(true).map(|spelled| spelled.to_wide())
            }
            Err(e) => Err(e),
        }
    }

    /// [`to_wide`](Self::to_wide) as a `std` path. `std` itself adds `\\?\` to a long plain path.
    #[cfg(windows)]
    pub fn to_std_path(&self) -> Result<std::path::PathBuf, ConversionError> {
        use std::os::windows::ffi::OsStringExt;
        Ok(std::ffi::OsString::from_wide(&self.to_wide()?).into())
    }

    /// Win32's reading of the path, as `GetFullPathNameW` gives it: `.` and `..` applied (a device
    /// name, or a share after extra separators, is a component they can remove; a share right
    /// after the server is not), separators collapsed, every
    /// trailing dot and space stripped from the name that ends the reading and one trailing dot
    /// from any other. A device path spelled with `?` reads as the verbatim path it names
    /// (`//?/C:/x` is `C:\x`).
    ///
    /// Refused for a path that is not fully qualified, whose reading depends on the process; for
    /// a last name some supported Windows maps to a device, whose reading depends on the version,
    /// in the path as written or in the reading (`C:\x\nul\.` reads as `C:\x\nul`); and for a NUL
    /// or a leading `\??\`. So the result is never a string Win32 may open as a device.
    pub fn win32_normalized(&self) -> Result<PathBuf, ConversionError> {
        self.check_win32(true, false)?;
        let reading = self.win32_reading(true);
        match reading.reserved_names().last {
            Some(name) => Err(ConversionError::new(ConversionReason::ReservedName, Some(name))),
            None => Ok(reading),
        }
    }

    /// Whether Win32 reads the path the same way in every process: a fully qualified path, or a UNC
    /// path missing its server or share, which names no object relative to the process.
    fn has_pure_reading(&self) -> bool {
        self.is_fully_qualified() || matches!(self.anchor(), Anchor::Unc { .. })
    }

    /// Win32's reading of a path with a [pure reading](Self::has_pure_reading), with names trimmed
    /// only if `strip`.
    fn win32_reading(&self, strip: bool) -> PathBuf {
        debug_assert!(self.has_pure_reading(), "only this path has a pure reading");
        let bytes = self.bytes();
        let parts = self.parts();
        let segments = self.segments();
        let mut nav = self.navigate(&segments);
        let mut names: Vec<&[u8]> = nav
            .kept
            .iter()
            .map(|&k| match segments[k].text {
                text if strip && has_single_trailing_dot(text) => &text[..text.len() - 1],
                text => text,
            })
            .collect();
        // A share after a loose root is among the names.
        let mut share = match parts.anchor {
            Anchor::Unc { share, .. } if parts.loose_root.is_none() => share.as_wtf8(),
            _ => b"",
        };
        let no_share = share.is_empty();
        if strip && !nav.trailing {
            match names.last_mut() {
                Some(last) => {
                    *last = trim_trailing_dots_and_spaces(last);
                    if last.is_empty() {
                        names.pop();
                        nav.trailing = true;
                    }
                }
                None => share = trim_trailing_dots_and_spaces(share),
            }
        }
        let mut out: Vec<u8> = match parts.anchor {
            Anchor::Drive { .. } => [&bytes[..parts.head], b"\\"].concat(),
            // A UNC path with no share is `\\server`, and a trailing separator comes from `nav`.
            Anchor::Unc { server, .. } if no_share && parts.loose_root.is_none() => {
                [b"\\\\".as_slice(), server.as_wtf8()].concat()
            }
            Anchor::Unc { server, .. } => [b"\\\\".as_slice(), server.as_wtf8(), b"\\", share].concat(),
            _ => vec![b'\\', b'\\', bytes[2], b'\\'],
        };
        for name in names {
            if !out.ends_with(b"\\") {
                out.push(b'\\');
            }
            out.extend_from_slice(name);
        }
        if nav.trailing && !out.ends_with(b"\\") {
            out.push(b'\\');
        }
        // A `?` device path reads as the verbatim path it names. A UNC server `.` or `?` has no
        // plain spelling, so that one stays a `\\.\` device path, which names the same object.
        PathBuf::parse(&OsString(out.clone())).unwrap_or_else(|_| {
            out[2] = b'.';
            PathBuf::from_wtf8(out)
        })
    }
}

#[cfg(test)]
#[path = "convert_tests.rs"]
mod convert_tests;

#[cfg(all(test, windows))]
#[path = "convert_win32_tests.rs"]
mod convert_win32_tests;
