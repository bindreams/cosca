//! Pure per-OS paths: [`posix::Path`] works on any host, with POSIX rules.
//!
//! Nothing here normalises implicitly. Constructors, [`PurePath::join`], equality and `Debug` keep
//! every component as written: `a/./b` has the components `a`, `.`, `b`, and differs from `a/b`.
//! Only [`PurePath::lexically_normal`] collapses `.`, `..` and separators, and only when asked.
//!
//! No path type implements [`std::fmt::Display`]: a lossy string would silently name a different
//! file. Use [`PurePath::display`] for messages, `Debug` for a faithful rendering, and
//! [`PurePath::to_str`] for an exact string.

use std::borrow::{Borrow, Cow};
use std::fmt::{self, Debug};
use std::hash::Hash;

pub mod posix;

/// One component of a path after its anchor, exactly as written.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Component<'a, S: ?Sized> {
    /// `.`
    CurDir,
    /// `..`
    ParentDir,
    /// The empty name between two separators, or after a trailing one: `a//b/` is `a`, `Empty`,
    /// `b`, `Empty`.
    Empty,
    /// Any other name.
    Normal(&'a S),
}

impl<S: ?Sized> Clone for Component<'_, S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S: ?Sized> Copy for Component<'_, S> {}

/// The operations every per-OS path shares.
///
/// `==`, `Hash` and `Ord` are lexical: the anchor, then component by component, with the choice of
/// separator not significant and case exact. Equal paths are spelled the same up to separator
/// syntax; they are not "the same file".
pub trait PurePath: Eq + Ord + Hash + Debug + ToOwned<Owned = Self::Buf> {
    /// The string type of one component.
    type Str: ?Sized + Debug;
    /// The owned path.
    type Buf: Borrow<Self> + Clone + Eq + Ord + Hash + Debug;
    /// The iterator [`components`](Self::components) returns.
    type Components<'a>: DoubleEndedIterator<Item = Component<'a, Self::Str>>
    where
        Self: 'a;

    /// The components after the anchor, as written. An empty path, or one that is only an anchor,
    /// has none.
    fn components(&self) -> Self::Components<'_>;

    /// `rhs` appended to `self`. An `rhs` with an anchor of its own replaces `self`, as in std.
    /// Otherwise the result's components are `self`'s followed by `rhs`'s, so a trailing separator
    /// on `self` stays an `Empty` component: `a/` joined with `b` is `a//b`.
    fn join(&self, rhs: &Self) -> Self::Buf;

    /// `self` without its last component, or `None` if it has no components.
    fn parent(&self) -> Option<&Self>;

    /// The last component, if it is a [`Component::Normal`] name.
    fn file_name(&self) -> Option<&Self::Str>;

    /// Whether the path names the same file whatever the process's current directory.
    fn is_absolute(&self) -> bool;

    /// Whether the path is a name an OS's program search looks up, rather than a location.
    fn is_bare_name(&self) -> bool;

    /// The path with `.` components, `name/..` pairs and repeated separators removed, as C++'s
    /// `std::filesystem::path::lexically_normal` does. Nothing else changes: a trailing separator
    /// stays (except after `..`), and names stay as written, trailing dots included. A `..` at the
    /// root is dropped, and a relative path left empty becomes `.`. Lexical only: `link/..` is not
    /// the parent of `link`'s target.
    fn lexically_normal(&self) -> Self::Buf;

    /// A lossy adapter for user messages: anything that is not Unicode becomes U+FFFD.
    fn display(&self) -> Display<'_, Self> {
        Display(self)
    }

    /// The path as `str`, if it is valid Unicode.
    fn to_str(&self) -> Option<&str>;

    /// The path as a string, with anything that is not Unicode replaced by U+FFFD.
    fn to_string_lossy(&self) -> Cow<'_, str>;

    /// The path in the OS's native encoding: POSIX bytes, borrowed; Windows UTF-16LE, possibly
    /// ill-formed, owned.
    fn to_native_bytes(&self) -> Cow<'_, [u8]>;
}

/// A lossy [`fmt::Display`] of a path, from [`PurePath::display`].
pub struct Display<'a, P: ?Sized>(&'a P);

impl<P: PurePath + ?Sized> fmt::Display for Display<'_, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_string_lossy())
    }
}

impl<P: PurePath + ?Sized> Debug for Display<'_, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(self.0, f)
    }
}

#[cfg(test)]
fn main() {
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
