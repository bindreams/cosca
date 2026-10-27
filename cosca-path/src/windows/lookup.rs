//! What [`FakeFilesystem`](crate::fs::FakeFilesystem) needs to know about a Windows path.

use std::io;

use super::{
    drive_len, fold_separator, is_separator, next_separator, plain_spelling, respell_verbatim, unc_rest, Anchor, Path,
    PathBuf, DEVICE, VERBATIM,
};
use crate::fs::sealed::{Cwd, Implicit, Lookup, Spelling};
use crate::{Component, PurePath};

/// The device names a Windows server refuses directly under a share (measured on build 26100, with
/// `\\localhost\C$` and `\\localhost\ADMIN$`), in lower case: the DOS devices `AUX`, `CLOCK$`, `CON`,
/// `NUL`, `PRN`, `COM1` to `COM9` and `LPT1` to `LPT9`.
fn is_server_device_name(name: &[u8]) -> bool {
    let lower = name.to_ascii_lowercase();
    let numbered = |prefix: &[u8]| {
        lower.len() == prefix.len() + 1
            && lower.starts_with(prefix)
            && lower[prefix.len()] != b'0'
            && lower[prefix.len()].is_ascii_digit()
    };
    matches!(lower.as_slice(), b"aux" | b"clock$" | b"con" | b"nul" | b"prn") || numbered(b"com") || numbered(b"lpt")
}

/// `bytes` after `prefix`, which it starts with in any ASCII case.
fn strip_prefix_ci<'a>(bytes: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    (bytes.len() >= prefix.len() && bytes[..prefix.len()].eq_ignore_ascii_case(prefix)).then(|| &bytes[prefix.len()..])
}

/// What the rest of a `\\.\` device path, after the device prefix, names.
enum Device {
    /// The path it names: a drive or UNC path, as Win32 reads it (also after `Global\` and
    /// `GLOBALROOT\??\`).
    Path(Vec<u8>),
    /// The device of the volume of this drive, `C:`.
    Volume(Vec<u8>),
    /// `Global` or `GLOBALROOT\??` with nothing after, which the host refuses.
    Bare,
    /// A device of its own.
    Other,
}

/// What the `\\.\` path whose text after the prefix is `rest` names. `Global\` and `GLOBALROOT\??\`
/// (in any case, repeated) are the namespace of the drive and UNC paths themselves, so they
/// change nothing before one.
fn device(rest: &[u8]) -> Device {
    let is_bare = |s: &[u8]| s.eq_ignore_ascii_case(b"Global") || s.eq_ignore_ascii_case(br"GLOBALROOT\??");
    let mut inner = rest;
    while let Some(after) = strip_prefix_ci(inner, br"Global\").or_else(|| strip_prefix_ci(inner, br"GLOBALROOT\??\")) {
        inner = after;
    }
    if is_bare(inner) {
        return Device::Bare;
    }
    if let Some(plain) = device_plain_spelling(inner) {
        return Device::Path(plain);
    }
    // The raw volume `\\.\C:` is a device.
    if inner.first() != Some(&b'\\') && drive_len(inner) == Some(inner.len()) {
        return Device::Volume(inner.to_vec());
    }
    Device::Other
}

/// The plain spelling of the `\\.\` path whose name and rest are `rest`, if the name is a drive
/// (`C:\x`) or `UNC` followed by something (`UNC\s\h`): Win32 reads those as the path they name.
/// The raw volume `\\.\C:` is a device and has none, nor has a UNC server `?`.
fn device_plain_spelling(rest: &[u8]) -> Option<Vec<u8>> {
    let is_drive = rest.first() != Some(&b'\\') && drive_len(rest).is_some_and(|len| rest.get(len) == Some(&b'\\'));
    if is_drive {
        return Some(rest.to_vec());
    }
    unc_rest(rest)
        .filter(|unc| !unc.is_empty() && unc[..next_separator(unc, 0)] != *b"?")
        .map(|unc| [br"\\", unc].concat())
}

/// How a name of an NTFS path reads when it carries a stream.
enum Stream<'a> {
    /// `name::$DATA`: the data of `name`.
    DefaultData(&'a [u8]),
    /// `name:$I30:$INDEX_ALLOCATION` or `name::$INDEX_ALLOCATION`: the directory `name`.
    Index(&'a [u8]),
    /// Any other `name:stream`.
    Named,
}

/// The stream a name of an NTFS path carries, if it has a `:`. Measured on build 26100.
fn stream(name: &[u8]) -> Option<Stream<'_>> {
    let colon = name.iter().position(|&b| b == b':')?;
    let (base, rest) = (&name[..colon], &name[colon..]);
    Some(if rest.eq_ignore_ascii_case(b"::$DATA") {
        Stream::DefaultData(base)
    } else if rest.eq_ignore_ascii_case(b":$I30:$INDEX_ALLOCATION") || rest.eq_ignore_ascii_case(b"::$INDEX_ALLOCATION")
    {
        Stream::Index(base)
    } else {
        Stream::Named
    })
}

impl Path {
    /// Whether the path, a `?` device path, reads as the verbatim `\\?\UNC\` path of the server
    /// `.` or `?`, which [`PathBuf::parse`] refuses with [`ParseError::UnspellableUncServer`](super::ParseError::UnspellableUncServer).
    fn names_unspellable_unc_server(&self) -> bool {
        let folded: Vec<u8> = self.lexically_normal().bytes().iter().map(fold_separator).collect();
        folded
            .strip_prefix(VERBATIM)
            .and_then(unc_rest)
            .is_some_and(|unc| matches!(&unc[..next_separator(unc, 0)], b"." | b"?"))
    }

    /// A UNC share with nothing below it, with or without the separator after it.
    fn is_share_root(&self) -> bool {
        self.as_unc().is_some() && self.is_fully_qualified() && self.components().next().is_none()
    }

    /// The path as Win32 reads its text, with the names as written: `.` and `..` applied, `\` for
    /// `/`, a `?` device path as the plain path it names (`//?/C:/x` is `C:\x`) and so a `.` device
    /// path that names a drive or UNC path, with or without `Global\` or `GLOBALROOT\??\`, and a UNC
    /// share root ending in `\`. A trailing separator is still there. Also the device of the volume
    /// it names, with the root of the volume's drive, and whether it is a bare `Global`.
    fn text(&self) -> (PathBuf, Option<PathBuf>, bool) {
        let normal = self.lexically_normal();
        let mut bytes = normal.bytes().to_vec();
        // `x\.` and `x\..` name an entry, not a directory spelled with a separator.
        let ends_in_dot = matches!(
            self.components().next_back(),
            Some(Component::CurDir | Component::ParentDir)
        );
        if ends_in_dot && normal.components().next_back() == Some(Component::Empty) {
            bytes.pop();
        }
        for b in &mut bytes {
            if *b == b'/' {
                *b = b'\\';
            }
        }
        // A device path spelled `?` reads as the verbatim path it names: `//?/C:/x` is `C:\x`.
        if let Some(rest) = bytes.strip_prefix(VERBATIM) {
            bytes = plain_spelling(rest);
            respell_verbatim(&mut bytes);
        }
        let (mut volume, mut bare) = (None, false);
        if let Some(rest) = bytes.strip_prefix(DEVICE) {
            match device(rest) {
                Device::Path(plain) => bytes = plain,
                Device::Volume(drive) => {
                    volume = Some(PathBuf::from_wtf8([&drive[..], br"\"].concat()));
                    bytes = [DEVICE, &drive[..]].concat();
                }
                Device::Bare => bare = true,
                Device::Other => {}
            }
        }
        let spelled = PathBuf::from_wtf8(bytes.clone());
        // A share root is one entry with or without its separator; spell it with.
        if spelled.is_share_root() && bytes.last() != Some(&b'\\') {
            bytes.push(b'\\');
            return (PathBuf::from_wtf8(bytes), volume, bare);
        }
        (spelled, volume, bare)
    }
}

impl Lookup for Path {
    /// The text of the path as [`Path::text`] reads it, then its names: a trailing separator names only
    /// a directory; a stream of the last name is the name (`f::$DATA` is the file `f`, and
    /// `d:$I30:$INDEX_ALLOCATION` the directory `d`); any other stream is refused, and one on a name
    /// that is not the last names nothing. A name that is neither is the entry as written.
    fn lookup(&self) -> Spelling<PathBuf> {
        let (text, volume, bare) = self.text();
        let mut key = text;
        let mut dir_only = false;
        if matches!(key.components().next_back(), Some(Component::Empty)) {
            if let Some(parent) = key.parent() {
                // Spelling the entry again settles the forms whose bare name differs from the one that
                // carries the separator (the drive-relative `C:.\` over `C:.`).
                dir_only = true;
                key = parent.text().0;
            }
        }
        let mut spelling = Spelling::new(key);
        spelling.volume = volume;
        // A device named `\\.\x` is no directory, and the root of the devices `\\.\` is.
        let nameless = match spelling.key.anchor() {
            Anchor::Device { name } => name.as_wtf8().is_empty(),
            _ => spelling.key.file_name().is_none(),
        };
        spelling.dir_only = dir_only || nameless;

        // The refusals the host makes before it looks anything up.
        if let Err(e) = self.to_wide() {
            spelling.refusal = Some((io::ErrorKind::InvalidInput, e.to_string()));
        } else if self.names_unspellable_unc_server() {
            spelling.refusal = Some((
                io::ErrorKind::InvalidInput,
                "the path is a verbatim UNC path whose server `.` or `?` has no plain spelling".to_owned(),
            ));
        } else if bare {
            spelling.refusal = Some((
                io::ErrorKind::Other,
                "the path is the root of the global namespace, which is no file or directory".to_owned(),
            ));
        }
        if spelling.volume.is_some() {
            return spelling;
        }

        if !matches!(spelling.key.anchor(), Anchor::Device { .. }) {
            spelling.streams(self);
        }
        spelling.relativity();
        spelling
    }

    fn canonical_spelling(&self) -> PathBuf {
        match self.bytes().strip_suffix(b"\\") {
            Some(root) if self.is_share_root() => PathBuf::from_wtf8(root.to_vec()),
            _ => self.to_path_buf(),
        }
    }
}

impl Spelling<PathBuf> {
    /// Reads the streams in the names of the key, and the names a server refuses. `path` is the
    /// path as written.
    fn streams(&mut self, path: &Path) {
        let bytes = self.key.bytes().to_vec();
        let start = self.key.parts().start();
        let mut pieces: Vec<&[u8]> = bytes[start..].split(is_separator).collect();
        if pieces.len() == 1 && pieces[0].is_empty() {
            return;
        }
        let last = pieces.len() - 1;
        for (i, piece) in pieces.iter_mut().enumerate() {
            match stream(piece) {
                None => {}
                Some(Stream::Index(base)) => {
                    *piece = base;
                    self.dir_only |= i == last;
                }
                Some(Stream::DefaultData(base)) if i == last => {
                    *piece = base;
                    self.data_stream = true;
                }
                Some(Stream::Named) if i == last && self.refusal.is_none() => {
                    self.refusal = Some((
                        io::ErrorKind::InvalidInput,
                        format!("{path:?} names an alternate data stream, which the fake does not model"),
                    ));
                }
                Some(_) => self.nothing = true,
            }
        }
        // A name that is only a stream is the entry before it.
        pieces.retain(|piece| !piece.is_empty());
        let mut text = bytes[..start].to_vec();
        for (i, piece) in pieces.iter().enumerate() {
            if i > 0 {
                text.push(b'\\');
            }
            text.extend_from_slice(piece);
        }
        let key = PathBuf::from_wtf8(text);
        if let (Some(name), Anchor::Unc { .. }, true) = (pieces.last(), key.anchor(), key.is_fully_qualified()) {
            if self.refusal.is_none() && !self.nothing && is_server_device_name(name) {
                self.refusal = Some((
                    io::ErrorKind::PermissionDenied,
                    "a server refuses a DOS device name directly under a share".to_owned(),
                ));
            }
        }
        self.key = key;
    }

    /// What the key depends on besides what is stated, and which directories exist without a
    /// statement.
    fn relativity(&mut self) {
        let key = &self.key;
        let parts = key.parts();
        let only_dotdot = key
            .components()
            .all(|c| matches!(c, Component::ParentDir | Component::CurDir));
        let dotdot = matches!(key.components().next(), Some(Component::ParentDir));
        match parts.anchor {
            Anchor::None => {
                self.cwd = Cwd::Relative {
                    tag: Vec::new(),
                    dotdot,
                };
                if only_dotdot && !key.bytes().is_empty() {
                    self.implicit = Some(Implicit::Always);
                }
            }
            Anchor::Rooted => {
                self.cwd = Cwd::Relative {
                    tag: br"\".to_vec(),
                    dotdot,
                };
                if only_dotdot {
                    self.implicit = Some(Implicit::Always);
                }
            }
            Anchor::Drive { drive, rooted: false } => {
                self.cwd = Cwd::Relative {
                    tag: drive.unit().to_le_bytes().to_vec(),
                    dotdot,
                };
                if only_dotdot {
                    let root = [&key.bytes()[..parts.head], br"\"].concat();
                    self.implicit = Some(Implicit::IfExists(PathBuf::from_wtf8(root)));
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
#[path = "lookup_tests.rs"]
mod lookup_tests;
