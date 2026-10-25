//! Windows paths, usable on any host. Storage is WTF-8, so ill-formed UTF-16 survives.
//!
//! A path is an [`Anchor`], then components separated by `\` or `/`. The anchors follow Win32's
//! path types (`RtlDetermineDosPathNameType_U`): two separators and `.` or `?` and a separator
//! start a device path, any other two separators a UNC path, one a rooted path, and any one UTF-16
//! unit then `:` a drive. A repeated or trailing separator is an
//! [`Empty`](crate::Component::Empty) component, so the anchor and the components spell the path
//! back exactly.
//!
//! Parsing drops a verbatim `\\?\` prefix: `\\?\C:\x` is stored as `C:\x`, `\\?\UNC\s\h` as
//! `\\s\h`, and any other verbatim rest as the device path `\\.\` and that rest. Stored text never
//! starts with `\\?\`.

use std::borrow::{Borrow, Cow};
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;

use ref_cast::{ref_cast_custom, RefCastCustom};

use crate::{Component, PurePath};

mod os_str;
pub use os_str::{OsStr, OsString};

const VERBATIM: &[u8] = br"\\?\";

// Anchors =============================================================================================================

/// A drive designator: one UTF-16 unit, as written (`C`, `c`, `1`, `é`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Drive(pub(crate) u16);

impl Drive {
    pub fn unit(self) -> u16 {
        self.0
    }
}

/// What a path is anchored to. A verbatim `\\?\` spelling parses to the same anchors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Anchor<'a> {
    /// `a\b`, relative to the current directory.
    None,
    /// `\a`, relative to the current drive or share.
    Rooted,
    /// `C:a` (`rooted: false`, relative to that drive's current directory) or `C:\a`.
    Drive { drive: Drive, rooted: bool },
    /// `\\server\share`. The share is empty when missing: `\\server`, `\\server\`.
    Unc { server: &'a OsStr, share: &'a OsStr },
    /// `\\.\name` or `\\?/name`, and `\\?\name` for any verbatim rest that is not a drive or UNC
    /// path (`\\?\C:foo` is the device `C:foo`). `\\.` alone is the device with an empty name.
    Device { name: &'a OsStr },
}

/// A UNC path's parts, from [`Path::as_unc`].
#[derive(Debug, Clone, Copy)]
pub struct Unc<'a> {
    pub server: &'a OsStr,
    pub share: &'a OsStr,
    /// The text after the share and its separator, as written. It is not a path of its own:
    /// `\\s\h\\x` has the rest `\x`, which would parse as rooted.
    pub rest: &'a OsStr,
}

/// Whether `s` starts with the verbatim prefix `\\?\`, exactly: `//?/` is a device path, not
/// verbatim. A check on a string's spelling; a parsed [`Path`] never holds the prefix.
pub fn is_verbatim_spelling(s: &OsStr) -> bool {
    s.as_wtf8().starts_with(VERBATIM)
}

fn is_separator(b: &u8) -> bool {
    matches!(b, b'\\' | b'/')
}

/// The index of the first separator at or after `from`, or `bytes.len()`.
fn next_separator(bytes: &[u8], from: usize) -> usize {
    bytes[from..]
        .iter()
        .position(is_separator)
        .map_or(bytes.len(), |i| from + i)
}

/// The byte length of a leading drive, one UTF-16 unit and `:`, or `None`. A lead byte of up to
/// three bytes is one unit; a four-byte one is two. The caller rules out a separator unit.
fn drive_len(bytes: &[u8]) -> Option<usize> {
    let unit = match *bytes.first()? {
        b if b < 0x80 => 1,
        b if b >= 0xF0 => return None,
        b if b >= 0xE0 => 3,
        _ => 2,
    };
    (bytes.get(unit) == Some(&b':')).then_some(unit + 1)
}

/// Whether `name`, at the start of a path, would read as a drive.
fn reads_as_drive(name: &[u8]) -> bool {
    drive_len(name).is_some()
}

impl<'a> Component<'a, OsStr> {
    /// The component as written.
    fn as_wtf8(&self) -> &'a [u8] {
        match self {
            Component::CurDir => b".",
            Component::ParentDir => b"..",
            Component::Empty => b"",
            Component::Normal(name) => name.as_wtf8(),
        }
    }
}

/// A parsed anchor: the anchor, the length of its text without the root separator, and whether a
/// root separator follows. Components start after both.
struct Parts<'a> {
    anchor: Anchor<'a>,
    head: usize,
    root: bool,
}

impl Parts<'_> {
    fn start(&self) -> usize {
        self.head + usize::from(self.root)
    }
}

fn parts(bytes: &[u8]) -> Parts<'_> {
    let sep = |i: usize| bytes.get(i).is_some_and(is_separator);
    let text = |range: std::ops::Range<usize>| OsStr::from_wtf8(&bytes[range]);
    if sep(0) {
        if !sep(1) {
            return Parts {
                anchor: Anchor::Rooted,
                head: 0,
                root: true,
            };
        }
        if matches!(bytes.get(2), Some(b'.' | b'?')) {
            if bytes.len() == 3 {
                return Parts {
                    anchor: Anchor::Device { name: text(3..3) },
                    head: 3,
                    root: false,
                };
            }
            if sep(3) {
                let end = next_separator(bytes, 4);
                let anchor = Anchor::Device { name: text(4..end) };
                return Parts {
                    anchor,
                    head: end,
                    root: sep(end),
                };
            }
        }
        let server_end = next_separator(bytes, 2);
        if !sep(server_end) {
            let anchor = Anchor::Unc {
                server: text(2..server_end),
                share: text(server_end..server_end),
            };
            return Parts {
                anchor,
                head: server_end,
                root: false,
            };
        }
        let share_end = next_separator(bytes, server_end + 1);
        let anchor = Anchor::Unc {
            server: text(2..server_end),
            share: text(server_end + 1..share_end),
        };
        return Parts {
            anchor,
            head: share_end,
            root: sep(share_end),
        };
    }
    if let Some(len) = drive_len(bytes) {
        let unit = text(0..len - 1).to_wide()[0];
        let rooted = sep(len);
        return Parts {
            anchor: Anchor::Drive {
                drive: Drive(unit),
                rooted,
            },
            head: len,
            root: rooted,
        };
    }
    Parts {
        anchor: Anchor::None,
        head: 0,
        root: false,
    }
}

// Paths ===============================================================================================================

/// A borrowed Windows path. See the [module docs](self) for its grammar.
///
/// There is no borrowed constructor from a string: parsing drops a verbatim prefix, so it
/// allocates. Use [`PathBuf::parse`].
#[derive(RefCastCustom)]
#[repr(transparent)]
pub struct Path(OsStr);

/// An owned [`Path`].
#[derive(Clone, Default)]
pub struct PathBuf(OsString);

/// A string [`PathBuf::parse`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// A `/` after `\\?\`. It is no separator there, and no Microsoft filesystem accepts it in a
    /// name.
    SlashInVerbatim,
    /// `\\?\UNC\.\…` or `\\?\UNC\?\…`: without the prefix, a server named `.` or `?` reads as a
    /// device path.
    UnspellableUncServer,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ParseError::SlashInVerbatim => {
                r"a verbatim (\\?\) path holds `/`, which no Microsoft filesystem accepts in a name"
            }
            ParseError::UnspellableUncServer => {
                r"a verbatim UNC path (\\?\UNC\) names the server `.` or `?`, which has no plain spelling"
            }
        })
    }
}

impl std::error::Error for ParseError {}

impl Path {
    #[ref_cast_custom]
    const fn from_os_str(s: &OsStr) -> &Path;

    fn from_wtf8(bytes: &[u8]) -> &Path {
        Path::from_os_str(OsStr::from_wtf8(bytes))
    }

    fn bytes(&self) -> &[u8] {
        self.0.as_wtf8()
    }

    fn parts(&self) -> Parts<'_> {
        parts(self.bytes())
    }

    pub fn as_os_str(&self) -> &OsStr {
        &self.0
    }

    pub fn to_path_buf(&self) -> PathBuf {
        PathBuf(self.0.to_os_string())
    }

    pub fn anchor(&self) -> Anchor<'_> {
        self.parts().anchor
    }

    pub fn drive(&self) -> Option<Drive> {
        match self.anchor() {
            Anchor::Drive { drive, .. } => Some(drive),
            _ => None,
        }
    }

    /// Whether the path needs no current directory: a drive and a root, a UNC path (even one
    /// missing its share) or a device path.
    pub fn is_fully_qualified(&self) -> bool {
        matches!(
            self.anchor(),
            Anchor::Drive { rooted: true, .. } | Anchor::Unc { .. } | Anchor::Device { .. }
        )
    }

    /// Whether the path is a drive with no root, `C:a`, relative to that drive's own current
    /// directory.
    pub fn is_drive_relative(&self) -> bool {
        matches!(self.anchor(), Anchor::Drive { rooted: false, .. })
    }

    /// Whether the anchor is [`Anchor::Rooted`]: `\a`, relative to the current drive or share.
    pub fn is_rooted(&self) -> bool {
        self.anchor() == Anchor::Rooted
    }

    /// The server, share and rest of a UNC path; `None` for any other anchor.
    pub fn as_unc(&self) -> Option<Unc<'_>> {
        let parts = self.parts();
        match parts.anchor {
            Anchor::Unc { server, share } => Some(Unc {
                server,
                share,
                rest: OsStr::from_wtf8(&self.bytes()[parts.start()..]),
            }),
            _ => None,
        }
    }

    /// The path as UTF-16 units, as written.
    pub fn to_wide(&self) -> Vec<u16> {
        self.0.to_wide()
    }

    /// The path as a `std` path, unit for unit.
    #[cfg(windows)]
    pub fn to_std_path(&self) -> std::path::PathBuf {
        self.0.to_std_os_string().into()
    }

    /// Whether appending a relative path needs a `\` first.
    fn needs_separator_to_append(&self) -> bool {
        let parts = self.parts();
        let has_components = self.bytes().len() > parts.start();
        has_components || !(parts.root || matches!(parts.anchor, Anchor::Drive { .. } | Anchor::None))
    }
}

/// The components of a [`Path`], from [`PurePath::components`].
pub struct Components<'a> {
    pieces: Option<Pieces<'a>>,
}

type Pieces<'a> = std::slice::Split<'a, u8, fn(&u8) -> bool>;

fn component(piece: &[u8]) -> Component<'_, OsStr> {
    match piece {
        b"" => Component::Empty,
        b"." => Component::CurDir,
        b".." => Component::ParentDir,
        name => Component::Normal(OsStr::from_wtf8(name)),
    }
}

impl<'a> Iterator for Components<'a> {
    type Item = Component<'a, OsStr>;
    fn next(&mut self) -> Option<Self::Item> {
        self.pieces.as_mut()?.next().map(component)
    }
}

impl DoubleEndedIterator for Components<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.pieces.as_mut()?.next_back().map(component)
    }
}

impl PurePath for Path {
    type Str = OsStr;
    type Buf = PathBuf;
    type Components<'a> = Components<'a>;

    fn components(&self) -> Components<'_> {
        // Splitting an empty remainder would give one `Empty`; it has no components.
        let rest = &self.bytes()[self.parts().start()..];
        let pieces = (!rest.is_empty()).then(|| rest.split(is_separator as fn(&u8) -> bool));
        Components { pieces }
    }

    /// As std's `push`: an `rhs` with a drive, share or device replaces `self`; a rooted `rhs`
    /// keeps `self`'s drive, share or device and replaces the rest; any other `rhs` is appended
    /// after a `\` where one is needed (`C:` joined with `a` is `C:a`). An unfinished anchor takes
    /// the first appended component as its own, as Win32 reads the string: `\\s` joined with `h`
    /// is the share `\\s\h`. `\\?` joined with `x` is `\\?/x`, not the verbatim `\\?\x`.
    fn join(&self, rhs: &Path) -> PathBuf {
        match rhs.anchor() {
            Anchor::None => {}
            Anchor::Rooted => {
                let lhs = self.parts();
                if !matches!(
                    lhs.anchor,
                    Anchor::Drive { .. } | Anchor::Unc { .. } | Anchor::Device { .. }
                ) {
                    return rhs.to_path_buf();
                }
                let mut bytes = [&self.bytes()[..lhs.head], rhs.bytes()].concat();
                respell_verbatim(&mut bytes);
                return PathBuf::from_wtf8(bytes);
            }
            _ => return rhs.to_path_buf(),
        }
        let mut buf = self.to_path_buf();
        buf.append_relative(rhs.bytes());
        buf
    }

    /// `self` without its last component, or `None` if it has none. A root followed by just one
    /// `Empty` component (`C:\\x`) cannot spell that, so its parent is the root `C:\`.
    fn parent(&self) -> Option<&Path> {
        let start = self.parts().start();
        let rest = &self.bytes()[start..];
        if rest.is_empty() {
            return None;
        }
        let end = rest.iter().rposition(is_separator).map_or(start, |i| start + i);
        Some(Path::from_wtf8(&self.bytes()[..end]))
    }

    fn file_name(&self) -> Option<&OsStr> {
        match self.components().next_back()? {
            Component::Normal(name) => Some(name),
            _ => None,
        }
    }

    /// Whether the path is [fully qualified](Path::is_fully_qualified).
    fn is_absolute(&self) -> bool {
        self.is_fully_qualified()
    }

    /// A non-empty path with no separator and no drive. `C:tool` is not bare: joining a directory
    /// to it gives back `C:tool`.
    fn is_bare_name(&self) -> bool {
        !self.bytes().is_empty() && !self.bytes().iter().any(is_separator) && self.anchor() == Anchor::None
    }

    /// As for POSIX, and: the anchor is kept as written, `\` goes between components, `..` is
    /// dropped after a root separator (`C:\..` is `C:\`) and kept after `C:`, an emptied path
    /// after `C:` stays `C:`, and a first name that would read as a drive keeps a `.` before it
    /// (`.\a:`).
    fn lexically_normal(&self) -> PathBuf {
        if self.bytes().is_empty() {
            return PathBuf::new();
        }
        let parts = self.parts();
        // Only `Normal` and `ParentDir` survive.
        let mut names: Vec<Component<'_, OsStr>> = Vec::new();
        let mut trailing = false;
        for c in self.components() {
            match c {
                Component::Normal(_) => {
                    names.push(c);
                    trailing = false;
                }
                Component::Empty | Component::CurDir => trailing = !names.is_empty(),
                Component::ParentDir => match names.last() {
                    Some(Component::Normal(_)) => {
                        names.pop();
                        trailing = !names.is_empty();
                    }
                    None if parts.root => {}
                    _ => {
                        names.push(c);
                        trailing = false;
                    }
                },
            }
        }
        if names.last() == Some(&Component::ParentDir) {
            trailing = false;
        }
        let mut bytes = self.bytes()[..parts.start()].to_vec();
        if parts.anchor == Anchor::None && names.first().is_some_and(|c| reads_as_drive(c.as_wtf8())) {
            bytes.extend_from_slice(br".\");
        }
        for (i, c) in names.iter().enumerate() {
            if i > 0 {
                bytes.push(b'\\');
            }
            bytes.extend_from_slice(c.as_wtf8());
        }
        if trailing {
            bytes.push(b'\\');
        }
        if bytes.is_empty() {
            bytes.push(b'.');
        }
        PathBuf::from_wtf8(bytes)
    }

    fn to_str(&self) -> Option<&str> {
        self.0.to_str()
    }

    fn to_string_lossy(&self) -> Cow<'_, str> {
        self.0.to_string_lossy()
    }

    fn to_native_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.to_wide().into_iter().flat_map(u16::to_le_bytes).collect())
    }
}

/// Writes the separator after a leading `\\?` as `/`. Appending to the device anchor `\\?` would
/// otherwise spell the verbatim prefix, which reads differently; `\\?/` is the device path `\\?`
/// already was.
fn respell_verbatim(bytes: &mut [u8]) {
    if bytes.starts_with(VERBATIM) {
        bytes[3] = b'/';
    }
}

fn fold_separator(b: &u8) -> u8 {
    if *b == b'/' {
        b'\\'
    } else {
        *b
    }
}

// `Eq` and `Hash` compare the spelling with `/` read as `\`. `Ord` walks the anchor and the
// components first, and breaks the remaining ties (`\\s` against `\\s\`) on that spelling.
impl PartialEq for Path {
    fn eq(&self, other: &Path) -> bool {
        let (a, b) = (self.bytes(), other.bytes());
        a.len() == b.len() && a.iter().map(fold_separator).eq(b.iter().map(fold_separator))
    }
}

impl Eq for Path {}

impl Hash for Path {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_usize(self.bytes().len());
        for b in self.bytes() {
            state.write_u8(fold_separator(b));
        }
    }
}

impl PartialOrd for Path {
    fn partial_cmp(&self, other: &Path) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Path {
    fn cmp(&self, other: &Path) -> Ordering {
        self.anchor()
            .cmp(&other.anchor())
            .then_with(|| self.components().cmp(other.components()))
            .then_with(|| {
                let (a, b) = (self.bytes(), other.bytes());
                a.iter().map(fold_separator).cmp(b.iter().map(fold_separator))
            })
    }
}

impl fmt::Debug for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl ToOwned for Path {
    type Owned = PathBuf;
    fn to_owned(&self) -> PathBuf {
        self.to_path_buf()
    }
}

impl AsRef<Path> for Path {
    fn as_ref(&self) -> &Path {
        self
    }
}

impl AsRef<Path> for PathBuf {
    fn as_ref(&self) -> &Path {
        self
    }
}

impl PathBuf {
    pub fn new() -> PathBuf {
        PathBuf(OsString::new())
    }

    /// Stores well-formed WTF-8 that is not a verbatim spelling.
    fn from_wtf8(bytes: Vec<u8>) -> PathBuf {
        debug_assert!(!bytes.starts_with(VERBATIM), "a stored path holds no verbatim prefix");
        PathBuf(OsString(bytes))
    }

    /// Parses `s`, keeping every component as written. A verbatim `\\?\` prefix is dropped (see
    /// the [module docs](self)); a verbatim rest that holds `/`, or names a UNC server `.` or `?`,
    /// is refused.
    pub fn parse<S: AsRef<OsStr> + ?Sized>(s: &S) -> Result<PathBuf, ParseError> {
        let bytes = s.as_ref().as_wtf8();
        let Some(rest) = bytes.strip_prefix(VERBATIM) else {
            return Ok(PathBuf::from_wtf8(bytes.to_vec()));
        };
        if rest.contains(&b'/') {
            return Err(ParseError::SlashInVerbatim);
        }
        let is_drive = rest.first() != Some(&b'\\') && drive_len(rest).is_some_and(|len| rest.get(len) == Some(&b'\\'));
        if is_drive {
            return Ok(PathBuf::from_wtf8(rest.to_vec()));
        }
        let unc = (rest.len() >= 4 && rest[..3].eq_ignore_ascii_case(b"UNC") && rest[3] == b'\\').then(|| &rest[4..]);
        if let Some(unc) = unc {
            let server = &unc[..next_separator(unc, 0)];
            if matches!(server, b"." | b"?") {
                return Err(ParseError::UnspellableUncServer);
            }
            return Ok(PathBuf::from_wtf8([br"\\", unc].concat()));
        }
        Ok(PathBuf::from_wtf8([br"\\.\", rest].concat()))
    }

    /// Parses the path `units` spell, as [`parse`](Self::parse) does.
    pub fn from_wide(units: &[u16]) -> Result<PathBuf, ParseError> {
        PathBuf::parse(&OsString::from_wide(units))
    }

    /// Parses a `std` path, unit for unit, as [`parse`](Self::parse) does.
    #[cfg(windows)]
    pub fn from_std_path(path: &std::path::Path) -> Result<PathBuf, ParseError> {
        PathBuf::parse(&OsString::from(path.as_os_str()))
    }

    pub fn as_path(&self) -> &Path {
        Path::from_os_str(&self.0)
    }

    pub fn into_os_string(self) -> OsString {
        self.0
    }

    /// Appends `rest`, which has no anchor of its own, after a `\` where one is needed.
    fn append_relative(&mut self, rest: &[u8]) {
        if rest.is_empty() {
            return;
        }
        if self.needs_separator_to_append() && !self.0 .0.is_empty() {
            self.0 .0.push(b'\\');
        }
        self.0 .0.extend_from_slice(rest);
        respell_verbatim(&mut self.0 .0);
    }

    /// Replaces `self` with `self.join(rhs)`.
    pub fn push(&mut self, rhs: &Path) {
        *self = self.join(rhs);
    }

    /// Truncates `self` to its [`parent`](PurePath::parent). Returns `false`, and leaves `self`
    /// unchanged, if there is none.
    pub fn pop(&mut self) -> bool {
        let Some(len) = self.parent().map(|p| p.bytes().len()) else {
            return false;
        };
        self.0 .0.truncate(len);
        true
    }

    /// Replaces the last component with `name` if it is a [`Component::Normal`] name, keeping
    /// every other component and separator; otherwise appends `name` after a `\` where one is
    /// needed. `name` is one component: it holds no `\` or `/`. A `name` that would start the
    /// path and read as a drive gets `.\` before it: `x` with the name `a:` becomes `.\a:`.
    pub fn set_file_name(&mut self, name: &OsStr) {
        let name = name.as_wtf8();
        debug_assert!(
            !name.iter().any(is_separator),
            "set_file_name takes one component, not a path"
        );
        let replaced = self.file_name().is_some();
        if replaced {
            let start = self.parts().start();
            let keep = self.bytes()[start..]
                .iter()
                .rposition(is_separator)
                .map_or(start, |i| start + i + 1);
            self.0 .0.truncate(keep);
        }
        if self.0 .0.is_empty() {
            if reads_as_drive(name) {
                self.0 .0.extend_from_slice(br".\");
            }
            self.0 .0.extend_from_slice(name);
        } else if replaced {
            self.0 .0.extend_from_slice(name);
        } else {
            self.append_relative(name);
        }
    }
}

impl Deref for PathBuf {
    type Target = Path;
    fn deref(&self) -> &Path {
        self.as_path()
    }
}

impl Borrow<Path> for PathBuf {
    fn borrow(&self) -> &Path {
        self
    }
}

impl PartialEq for PathBuf {
    fn eq(&self, other: &PathBuf) -> bool {
        self.as_path() == other.as_path()
    }
}

impl Eq for PathBuf {}

impl Hash for PathBuf {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_path().hash(state);
    }
}

impl PartialOrd for PathBuf {
    fn partial_cmp(&self, other: &PathBuf) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PathBuf {
    fn cmp(&self, other: &PathBuf) -> Ordering {
        self.as_path().cmp(other.as_path())
    }
}

impl fmt::Debug for PathBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_path(), f)
    }
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
