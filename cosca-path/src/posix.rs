//! POSIX paths, usable on any host. Storage is bytes, as the kernel sees them.
//!
//! A path is an optional root `/`, then components separated by `/`. A repeated or trailing `/`
//! is an [`Empty`](crate::Component::Empty) component, so the root and the components spell the
//! path back exactly.

use std::borrow::{Borrow, Cow};
use std::cmp::Ordering;
use std::ffi::CString;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;

use ref_cast::{ref_cast_custom, RefCastCustom};

use crate::{Component, PurePath};

// Strings =============================================================================================================

/// A borrowed POSIX string: any bytes. `Debug` is faithful: invalid UTF-8 shows as `\xNN`.
#[derive(RefCastCustom, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct OsStr([u8]);

/// An owned [`OsStr`].
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OsString(Vec<u8>);

impl OsStr {
    /// Borrows `s` as an `OsStr`, without copying.
    pub fn new<S: AsRef<OsStr> + ?Sized>(s: &S) -> &OsStr {
        s.as_ref()
    }

    /// Borrows `bytes` as an `OsStr`, without copying.
    #[ref_cast_custom]
    pub const fn from_bytes(bytes: &[u8]) -> &OsStr;

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The string as `str`, if it is valid UTF-8.
    pub fn to_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// The string with invalid UTF-8 replaced by U+FFFD.
    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.0)
    }

    pub fn to_os_string(&self) -> OsString {
        OsString(self.0.to_vec())
    }
}

impl fmt::Debug for OsStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"")?;
        for chunk in self.0.utf8_chunks() {
            write!(f, "{}", chunk.valid().escape_debug())?;
            for b in chunk.invalid() {
                write!(f, "\\x{b:02X}")?;
            }
        }
        f.write_str("\"")
    }
}

impl ToOwned for OsStr {
    type Owned = OsString;
    fn to_owned(&self) -> OsString {
        self.to_os_string()
    }
}

impl AsRef<OsStr> for OsStr {
    fn as_ref(&self) -> &OsStr {
        self
    }
}

impl AsRef<OsStr> for str {
    fn as_ref(&self) -> &OsStr {
        OsStr::from_bytes(self.as_bytes())
    }
}

impl AsRef<OsStr> for String {
    fn as_ref(&self) -> &OsStr {
        self.as_str().as_ref()
    }
}

impl AsRef<OsStr> for [u8] {
    fn as_ref(&self) -> &OsStr {
        OsStr::from_bytes(self)
    }
}

impl AsRef<OsStr> for OsString {
    fn as_ref(&self) -> &OsStr {
        self
    }
}

impl OsString {
    pub fn new() -> OsString {
        OsString(Vec::new())
    }

    pub fn as_os_str(&self) -> &OsStr {
        OsStr::from_bytes(&self.0)
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl Deref for OsString {
    type Target = OsStr;
    fn deref(&self) -> &OsStr {
        self.as_os_str()
    }
}

impl Borrow<OsStr> for OsString {
    fn borrow(&self) -> &OsStr {
        self
    }
}

impl fmt::Debug for OsString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_os_str(), f)
    }
}

impl From<Vec<u8>> for OsString {
    fn from(bytes: Vec<u8>) -> OsString {
        OsString(bytes)
    }
}

impl From<String> for OsString {
    fn from(s: String) -> OsString {
        OsString(s.into_bytes())
    }
}

impl From<&str> for OsString {
    fn from(s: &str) -> OsString {
        OsString(s.as_bytes().to_vec())
    }
}

// Paths ===============================================================================================================

/// A borrowed POSIX path. See the [module docs](self) for its grammar.
#[derive(RefCastCustom)]
#[repr(transparent)]
pub struct Path(OsStr);

/// An owned [`Path`].
#[derive(Clone, Default)]
pub struct PathBuf(OsString);

impl Path {
    /// Borrows `s` as a path, without copying or parsing.
    pub fn new<S: AsRef<OsStr> + ?Sized>(s: &S) -> &Path {
        Path::from_os_str(s.as_ref())
    }

    #[ref_cast_custom]
    const fn from_os_str(s: &OsStr) -> &Path;

    /// Borrows `bytes` as a path, without copying.
    pub fn from_bytes(bytes: &[u8]) -> &Path {
        Path::from_os_str(OsStr::from_bytes(bytes))
    }

    pub fn as_os_str(&self) -> &OsStr {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Whether the path starts with `/`.
    pub fn has_root(&self) -> bool {
        self.as_bytes().first() == Some(&b'/')
    }

    /// The bytes after the root.
    fn relative_bytes(&self) -> &[u8] {
        &self.as_bytes()[usize::from(self.has_root())..]
    }

    pub fn to_path_buf(&self) -> PathBuf {
        PathBuf(self.0.to_os_string())
    }

    /// The path as a C string for a system call. Refuses only a NUL byte, which would end the
    /// string early.
    pub fn to_cstring(&self) -> Result<CString, ConversionError> {
        CString::new(self.as_bytes()).map_err(|e| ConversionError {
            nul_at: e.nul_position(),
        })
    }

    /// Borrows the path as a `std` path, without copying.
    #[cfg(unix)]
    pub fn as_std_path(&self) -> &std::path::Path {
        use std::os::unix::ffi::OsStrExt;
        std::path::Path::new(std::ffi::OsStr::from_bytes(self.as_bytes()))
    }

    /// Borrows a `std` path as a path, without copying.
    #[cfg(unix)]
    pub fn from_std_path(path: &std::path::Path) -> &Path {
        use std::os::unix::ffi::OsStrExt;
        Path::from_bytes(path.as_os_str().as_bytes())
    }
}

/// The components of a [`Path`], from [`PurePath::components`].
pub struct Components<'a> {
    pieces: Option<Pieces<'a>>,
}

type Pieces<'a> = std::slice::Split<'a, u8, fn(&u8) -> bool>;

fn is_separator(b: &u8) -> bool {
    *b == b'/'
}

fn component(piece: &[u8]) -> Component<'_, OsStr> {
    match piece {
        b"" => Component::Empty,
        b"." => Component::CurDir,
        b".." => Component::ParentDir,
        name => Component::Normal(OsStr::from_bytes(name)),
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
        let rest = self.relative_bytes();
        let pieces = (!rest.is_empty()).then(|| rest.split(is_separator as fn(&u8) -> bool));
        Components { pieces }
    }

    fn join(&self, rhs: &Path) -> PathBuf {
        if rhs.has_root() || self.as_bytes().is_empty() {
            return rhs.to_path_buf();
        }
        let mut bytes = self.as_bytes().to_vec();
        if !rhs.as_bytes().is_empty() {
            // A root alone already ends with its separator.
            if !self.relative_bytes().is_empty() {
                bytes.push(b'/');
            }
            bytes.extend_from_slice(rhs.as_bytes());
        }
        PathBuf::from(bytes)
    }

    fn parent(&self) -> Option<&Path> {
        let root = usize::from(self.has_root());
        let rest = self.relative_bytes();
        if rest.is_empty() {
            return None;
        }
        let end = rest.iter().rposition(is_separator).map_or(root, |i| root + i);
        Some(Path::from_bytes(&self.as_bytes()[..end]))
    }

    fn file_name(&self) -> Option<&OsStr> {
        match self.components().next_back()? {
            Component::Normal(name) => Some(name),
            _ => None,
        }
    }

    fn is_absolute(&self) -> bool {
        self.has_root()
    }

    /// A non-empty path with no `/`: `execvp` searches `PATH` for it.
    fn is_bare_name(&self) -> bool {
        !self.as_bytes().is_empty() && !self.as_bytes().contains(&b'/')
    }

    fn lexically_normal(&self) -> PathBuf {
        if self.as_bytes().is_empty() {
            return PathBuf::new();
        }
        let root = self.has_root();
        // Only `Normal` and `ParentDir` survive.
        let mut names: Vec<Component<'_, OsStr>> = Vec::new();
        // Whether the result ends with a separator after its last name.
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
                    None if root => {}
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
        let mut bytes = Vec::new();
        if root {
            bytes.push(b'/');
        }
        for (i, c) in names.iter().enumerate() {
            if i > 0 {
                bytes.push(b'/');
            }
            bytes.extend_from_slice(match c {
                Component::Normal(name) => name.as_bytes(),
                _ => b"..",
            });
        }
        if trailing {
            bytes.push(b'/');
        }
        if bytes.is_empty() {
            bytes.push(b'.');
        }
        PathBuf::from(bytes)
    }

    fn to_str(&self) -> Option<&str> {
        self.0.to_str()
    }

    fn to_string_lossy(&self) -> Cow<'_, str> {
        self.0.to_string_lossy()
    }

    fn to_native_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.as_bytes())
    }
}

// The root and the components spell the bytes back exactly, so comparing bytes is comparing
// components, for `Eq` and `Hash`. `Ord` still walks components: the bytes would sort `a-b` before
// `a/b`.
impl PartialEq for Path {
    fn eq(&self, other: &Path) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Path {}

impl Hash for Path {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl PartialOrd for Path {
    fn partial_cmp(&self, other: &Path) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Path {
    fn cmp(&self, other: &Path) -> Ordering {
        self.has_root()
            .cmp(&other.has_root())
            .then_with(|| self.components().cmp(other.components()))
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

impl AsRef<Path> for str {
    fn as_ref(&self) -> &Path {
        Path::new(self)
    }
}

impl AsRef<Path> for OsStr {
    fn as_ref(&self) -> &Path {
        Path::new(self)
    }
}

impl PathBuf {
    pub fn new() -> PathBuf {
        PathBuf(OsString::new())
    }

    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    pub fn into_os_string(self) -> OsString {
        self.0
    }

    /// Replaces `self` with `self.join(rhs)`.
    pub fn push<P: AsRef<Path> + ?Sized>(&mut self, rhs: &P) {
        *self = self.join(rhs.as_ref());
    }

    /// Truncates `self` to its [`parent`](PurePath::parent). Returns `false`, and leaves `self`
    /// unchanged, if there is none. As for `parent`, `//x` becomes `/`.
    pub fn pop(&mut self) -> bool {
        let Some(len) = self.parent().map(|p| p.as_bytes().len()) else {
            return false;
        };
        self.0 .0.truncate(len);
        true
    }

    /// Replaces the last component with `name` if it is a [`Component::Normal`] name, keeping
    /// every other component and separator (`//x` becomes `//name`); otherwise appends `name`, as
    /// [`push`](Self::push) does. `name` is one component: it holds no `/`.
    pub fn set_file_name<S: AsRef<OsStr> + ?Sized>(&mut self, name: &S) {
        debug_assert!(
            !name.as_ref().as_bytes().iter().any(is_separator),
            "set_file_name takes one component, not a path"
        );
        if self.file_name().is_none() {
            self.push(Path::new(name));
            return;
        }
        // The last component is a name, so everything up to the last separator stays.
        let keep = self.as_bytes().iter().rposition(is_separator).map_or(0, |i| i + 1);
        self.0 .0.truncate(keep);
        self.0 .0.extend_from_slice(name.as_ref().as_bytes());
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

impl From<OsString> for PathBuf {
    fn from(s: OsString) -> PathBuf {
        PathBuf(s)
    }
}

impl From<Vec<u8>> for PathBuf {
    fn from(bytes: Vec<u8>) -> PathBuf {
        PathBuf(OsString(bytes))
    }
}

impl From<String> for PathBuf {
    fn from(s: String) -> PathBuf {
        PathBuf(s.into())
    }
}

impl From<&str> for PathBuf {
    fn from(s: &str) -> PathBuf {
        PathBuf(s.into())
    }
}

// Conversion ==========================================================================================================

/// A path that cannot become a C string: it holds a NUL byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversionError {
    nul_at: usize,
}

impl ConversionError {
    /// The byte offset of the first NUL.
    pub fn nul_at(&self) -> usize {
        self.nul_at
    }
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the path holds a NUL byte at offset {}", self.nul_at)
    }
}

impl std::error::Error for ConversionError {}

#[cfg(test)]
#[path = "posix_tests.rs"]
mod posix_tests;
