//! Windows paths, usable on any host. Storage is WTF-8, so ill-formed UTF-16 survives.
//!
//! A path is an [`Anchor`], then components separated by `\` or `/`. The anchors follow Win32's
//! path types (`RtlDetermineDosPathNameType_U`): two separators and `.` or `?` and a separator
//! start a device path, any other two separators a UNC path, one a rooted path, and any one UTF-16
//! unit then `:` a drive. Within an anchor, the parse skips what Win32 skips (see [`Anchor`]). A
//! repeated or trailing separator after the anchor is an [`Empty`](crate::Component::Empty)
//! component, so the anchor's text, its root separator and the components spell the path back, up
//! to the choice of separator. The [`Anchor`] value alone does not: `\\s` and `\\s\`, `\\s\h` and
//! `\\s\\h`, `\\.\x` and `\\?/x`, `C:/a` and `C:\a` each share an anchor and components.
//!
//! Parsing drops a verbatim `\\?\` prefix: `\\?\C:\x` is stored as `C:\x`, `\\?\UNC\s\h` as
//! `\\s\h`, and any other verbatim rest as the device path `\\.\` and that rest. Stored text never
//! starts with `\\?\`. A `.` or `..` in a verbatim rest is a literal name to Win32's file APIs
//! (`\\?\C:\Windows\..\Windows` is invalid), but parses as [`CurDir`](crate::Component::CurDir) or
//! [`ParentDir`](crate::Component::ParentDir) here, as in any other spelling.
//!
//! So the stored text ([`Path::as_os_str`]) is a lexical spelling, not a string to hand Win32.
//! Win32 reads `\\?\C:\a.` as written but the stored `C:\a.` as `C:\a`, and `\\?\C:\nul` as a
//! file but `C:\nul` as the NUL device; the stored text also loses a long verbatim path's exemption
//! from `MAX_PATH`. Nothing here converts a path for Win32 yet: `Path::to_wide` and
//! `Path::to_std_path` arrive with that conversion, and will hand over the string that names the
//! same object.

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
///
/// Ordered by variant as declared, then by drive unit and `rooted`, by server then share, or by
/// name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Anchor<'a> {
    /// `a\b`, relative to the current directory.
    None,
    /// `\a`, relative to the current drive or share.
    Rooted,
    /// `C:a` (`rooted: false`, relative to that drive's current directory) or `C:\a`.
    Drive { drive: Drive, rooted: bool },
    /// `\\server\share`. A share that does not directly follow the server's separator Win32
    /// resolves against `\\server\`, as it does a device name: empty names, `.` and `..` before it
    /// are skipped (`\\s\\h` and `\\s\\.\h` are the share `h`; `\\s\.\h` is the share `.`), and
    /// to `..` after it the share is a component. The share is empty when missing: `\\server`,
    /// `\\server\`, `\\server\\`. A share that is only dots or spaces and ends the path
    /// (`\\s\.`, `\\s\ `) stays the share as written, though Win32 strips it to `\\s\`.
    Unc { server: &'a OsStr, share: &'a OsStr },
    /// `\\.\name` or `\\?/name`, and `\\?\name` for any verbatim rest that is not a drive or UNC
    /// path (`\\?\C:foo` is the device `C:foo`). Win32 resolves the name against the device root,
    /// so empty names, `.` and `..` before it are skipped (`\\.\.\x` and `\\.\..\x` are the
    /// device `x`), and to `..` after it the name is a component (see
    /// [`PurePath::lexically_normal`]). The name is empty when missing: `\\.`, `\\.\`, `\\.\..`. A name
    /// that ends in dots or spaces stays as written, though Win32 strips them: `\\.\d.\x` is the
    /// device `d.`, which Win32 reads as `\\.\d\x`.
    Device { name: &'a OsStr },
}

/// A UNC path's parts, from [`Path::as_unc`].
#[derive(Debug, Clone, Copy)]
pub struct Unc<'a> {
    pub server: &'a OsStr,
    pub share: &'a OsStr,
    /// The path within the share: the text from the last separator after the share, so empty or
    /// rooted. Win32 collapses the separators it skips: `\\s\h\a` and `\\s\h\\a` both have the
    /// rest `\a`, and `\\s\h` the empty rest. After a share that Win32 reads as a component (see
    /// [`Anchor::Unc`]), a `..` in the rest pops the share itself: `\\s\\h\..\x` has the share `h`
    /// and the rest `\..\x`, and Win32 reads it as the share `x`.
    pub rest: &'a Path,
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

/// The byte length of a leading drive, one UTF-16 unit and `:`, or `None`. The caller rules out a
/// separator unit.
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
    /// Whether the anchor's text ends in a separator after the server or `\\.`. Read only for an
    /// unfinished anchor.
    open: bool,
    /// For a device path, or a UNC path whose share does not directly follow the server's
    /// separator: the length of the root Win32 resolves the rest against, `\\.\` or `\\server\`.
    /// Under that root the device name or share is a component that `..` can pop.
    loose_root: Option<usize>,
}

impl Parts<'_> {
    fn start(&self) -> usize {
        self.head + usize::from(self.root)
    }

    /// For a UNC path with no share or a device path with no name: whether the anchor ends in a
    /// separator after the server (or after `\\.`). `None` for any other anchor. Such an anchor
    /// takes the first component appended to it as its own, and has no root separator.
    fn unfinished(&self) -> Option<bool> {
        match self.anchor {
            Anchor::Unc { share, .. } if share.as_wtf8().is_empty() => Some(self.open),
            Anchor::Device { name } if name.as_wtf8().is_empty() => Some(self.open),
            _ => None,
        }
    }
}

fn parts(bytes: &[u8]) -> Parts<'_> {
    let sep = |i: usize| bytes.get(i).is_some_and(is_separator);
    let text = |range: std::ops::Range<usize>| OsStr::from_wtf8(&bytes[range]);
    let plain = |anchor, head, root| Parts {
        anchor,
        head,
        root,
        open: false,
        loose_root: None,
    };
    if sep(0) {
        if !sep(1) {
            return plain(Anchor::Rooted, 0, true);
        }
        if matches!(bytes.get(2), Some(b'.' | b'?')) {
            if bytes.len() == 3 {
                return plain(Anchor::Device { name: text(3..3) }, 3, false);
            }
            if sep(3) {
                return loose_parts(bytes, 4, |name| Anchor::Device { name });
            }
        }
        let server_end = next_separator(bytes, 2);
        let server = text(2..server_end);
        if !sep(server_end) {
            return plain(
                Anchor::Unc {
                    server,
                    share: text(server_end..server_end),
                },
                server_end,
                false,
            );
        }
        if sep(server_end + 1) || server_end + 1 == bytes.len() {
            return loose_parts(bytes, server_end + 1, |share| Anchor::Unc { server, share });
        }
        let share_end = next_separator(bytes, server_end + 1);
        let anchor = Anchor::Unc {
            server,
            share: text(server_end + 1..share_end),
        };
        return plain(anchor, share_end, sep(share_end));
    }
    if let Some(len) = drive_len(bytes) {
        let unit = text(0..len - 1).to_wide()[0];
        let rooted = sep(len);
        let anchor = Anchor::Drive {
            drive: Drive(unit),
            rooted,
        };
        return plain(anchor, len, rooted);
    }
    plain(Anchor::None, 0, false)
}

/// The parts of a path whose device name or share Win32 resolves against the root `bytes[..root]`
/// (`\\.\`, `\\server\`). Empty names, `.` and `..` change nothing there: the name is the first
/// other one, and the text before it belongs to the anchor.
fn loose_parts<'a>(bytes: &'a [u8], root: usize, anchor: impl Fn(&'a OsStr) -> Anchor<'a>) -> Parts<'a> {
    let mut start = root;
    loop {
        let end = next_separator(bytes, start);
        let name = &bytes[start..end];
        if !matches!(name, b"" | b"." | b"..") {
            return Parts {
                anchor: anchor(OsStr::from_wtf8(name)),
                head: end,
                root: end < bytes.len(),
                open: false,
                loose_root: Some(root),
            };
        }
        if end == bytes.len() {
            return Parts {
                anchor: anchor(OsStr::from_wtf8(&bytes[end..])),
                head: end,
                root: false,
                open: is_separator(&bytes[end - 1]),
                loose_root: Some(root),
            };
        }
        start = end + 1;
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

    /// The stored text: a lexical spelling, not a string for Win32 (see the [module docs](self)).
    pub fn as_os_str(&self) -> &OsStr {
        &self.0
    }

    pub fn to_path_buf(&self) -> PathBuf {
        PathBuf(self.0.to_owned())
    }

    /// The anchor as written, as `RtlDetermineDosPathNameType_U` classifies a string. A `..` after
    /// a share or device name that follows extra separators pops it only when the path is
    /// resolved: `\\s\\h\..` is anchored at the share `h`, and its
    /// [normal form](PurePath::lexically_normal), `\\s\`, is not.
    pub fn anchor(&self) -> Anchor<'_> {
        self.parts().anchor
    }

    pub fn drive(&self) -> Option<Drive> {
        match self.anchor() {
            Anchor::Drive { drive, .. } => Some(drive),
            _ => None,
        }
    }

    /// Whether the path needs no current directory: a drive and a root, a UNC path with a server
    /// and a share, or a device path longer than `\\.` or `\\?` alone. The path is judged as
    /// written, as Win32 judges a string, not as resolved: `\\s\\h\..` is fully qualified and its
    /// [normal form](PurePath::lexically_normal), `\\s\`, is not. A share that is only dots or
    /// spaces and ends the path counts as a share, though Win32 strips it: `\\s\.` is fully
    /// qualified and Win32 resolves it to `\\s\`. A device path with no name
    /// (`\\.\`) counts, as `RtlDetermineDosPathNameType_U` reports it a local device path rather
    /// than the root local device `\\.`.
    pub fn is_fully_qualified(&self) -> bool {
        match self.anchor() {
            Anchor::Drive { rooted, .. } => rooted,
            Anchor::Unc { server, share } => !server.as_wtf8().is_empty() && !share.as_wtf8().is_empty(),
            Anchor::Device { .. } => self.bytes().len() > 3,
            Anchor::None | Anchor::Rooted => false,
        }
    }

    /// Whether the path is a drive with no root, `C:a`, relative to that drive's own current
    /// directory.
    pub fn is_drive_relative(&self) -> bool {
        matches!(self.anchor(), Anchor::Drive { rooted: false, .. })
    }

    /// Whether the anchor is [`Anchor::Rooted`].
    pub fn is_rooted(&self) -> bool {
        self.anchor() == Anchor::Rooted
    }

    /// The server, share and rest of a UNC path, as written (see [`Path::anchor`]); `None` for any
    /// other anchor.
    pub fn as_unc(&self) -> Option<Unc<'_>> {
        let parts = self.parts();
        match parts.anchor {
            Anchor::Unc { server, share } => {
                let bytes = self.bytes();
                let separators = bytes[parts.head..].iter().take_while(|b| is_separator(b)).count();
                let rest = &bytes[parts.head + separators.saturating_sub(1)..];
                Some(Unc {
                    server,
                    share,
                    rest: Path::from_wtf8(rest),
                })
            }
            _ => None,
        }
    }

    /// Whether appending a relative path needs a `\` first.
    fn needs_separator_to_append(&self) -> bool {
        let parts = self.parts();
        let has_components = self.bytes().len() > parts.start();
        has_components
            || match parts.unfinished() {
                Some(has_separator) => !has_separator,
                None => !(parts.root || matches!(parts.anchor, Anchor::Drive { .. } | Anchor::None)),
            }
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
    /// after a `\` where one is needed (`C:` joined with `a` is `C:a`). An anchor with no share or
    /// device name takes the first appended name as its own, as Win32 reads the joined string:
    /// `\\s`, `\\s\` and `\\s\\` joined with `h` all have the share `h`, and a first `.` or `..`
    /// counts only where it directly follows the server's separator (see [`Anchor::Unc`]). `\\?`
    /// joined with `x` is `\\?/x` (see `respell_verbatim`).
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
                // An unfinished anchor's own separator is the rhs's root.
                let head = lhs.head - usize::from(lhs.unfinished() == Some(true));
                let mut bytes = [&self.bytes()[..head], rhs.bytes()].concat();
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

    /// As for POSIX, and as Win32 reads `.` and `..`: the anchor is kept as written; `\` goes
    /// between components; a final `.` or `..` leaves no trailing separator, and only one written
    /// last stays (`C:\a\b\..` is `C:\a`, `C:\a\.\` is `C:\a\`); `..` is dropped after a root
    /// separator (`C:\..` is `C:\`) and kept after `C:`; an emptied path after `C:` stays `C:`;
    /// and a first name that would read as a drive keeps a `.` before it (`.\a:`). A device name,
    /// and a share after extra separators, is the first component under `\\.\` or `\\server\` (see
    /// [`Anchor`]), so `..` pops it:
    /// `\\.\d\..\a` is `\\.\a`, `\\s\\h\x` is `\\s\h\x` and `\\s\\h\..` is `\\s\`.
    ///
    /// A separate step from classification: [`Path::is_fully_qualified`] and [`Path::anchor`] read
    /// the path as written, so a path and its normal form can differ in both (`\\s\\h\..` is fully
    /// qualified, `\\s\` is not).
    fn lexically_normal(&self) -> PathBuf {
        let bytes = self.bytes();
        if bytes.is_empty() {
            return PathBuf::new();
        }
        let parts = self.parts();
        let (prefix, root, pieces): (usize, bool, Vec<Component<'_, OsStr>>) = match parts.loose_root {
            Some(len) => (len, true, bytes[len..].split(is_separator).map(component).collect()),
            None => (parts.start(), parts.root, self.components().collect()),
        };
        let mut out = bytes[..prefix].to_vec();
        // After a UNC share, the separator is a trailing one like any other: it stays only if the
        // path ends in one (`\\s\h\..` is `\\s\h`, `\\s\h\.\` is `\\s\h\`).
        let share_separator = parts.loose_root.is_none() && parts.root && matches!(parts.anchor, Anchor::Unc { .. });
        // Only `Normal` and `ParentDir` survive.
        let mut names: Vec<Component<'_, OsStr>> = Vec::new();
        let mut trailing = false;
        for c in pieces {
            match c {
                Component::Normal(_) => {
                    names.push(c);
                    trailing = false;
                }
                // Only a separator written last leaves one; a final `.` or `..` does not.
                Component::Empty => trailing = !names.is_empty(),
                Component::CurDir => trailing = false,
                Component::ParentDir => {
                    trailing = false;
                    match names.last() {
                        Some(Component::Normal(_)) => {
                            names.pop();
                        }
                        None if root => {}
                        _ => names.push(c),
                    }
                }
            }
        }
        if names.last() == Some(&Component::ParentDir) {
            trailing = false;
        }
        if share_separator && names.is_empty() && !bytes.last().is_some_and(is_separator) {
            out.pop();
        }
        if parts.anchor == Anchor::None && names.first().is_some_and(|c| reads_as_drive(c.as_wtf8())) {
            out.extend_from_slice(br".\");
        }
        for (i, c) in names.iter().enumerate() {
            if i > 0 {
                out.push(b'\\');
            }
            out.extend_from_slice(c.as_wtf8());
        }
        if trailing {
            out.push(b'\\');
        }
        if out.is_empty() {
            out.push(b'.');
        }
        PathBuf::from_wtf8(out)
    }

    fn to_str(&self) -> Option<&str> {
        self.0.to_str()
    }

    fn to_string_lossy(&self) -> Cow<'_, str> {
        self.0.to_string_lossy()
    }

    /// The stored text as UTF-16LE: an encoding of the spelling, not a string for Win32 (see the
    /// [module docs](self)).
    fn to_native_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.0.to_wide().into_iter().flat_map(u16::to_le_bytes).collect())
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

    /// The stored text, as [`Path::as_os_str`].
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
