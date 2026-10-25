use std::borrow::Cow;
use std::collections::HashSet;
use std::hash::{BuildHasher, RandomState};

use super::{OsStr, Path, PathBuf};
use crate::{Component, PurePath};

fn p(s: &str) -> &Path {
    Path::new(s)
}

fn components(s: &str) -> Vec<Component<'_, OsStr>> {
    p(s).components().collect()
}

fn n(s: &str) -> Component<'_, OsStr> {
    Component::Normal(OsStr::new(s))
}

// Components ==========================================================================================================

/// `.` and repeated or trailing separators stay components.
///
/// Mutant: std's parser, which drops `.` and empty names.
#[skuld::test]
fn posix_components_are_faithful() {
    assert_eq!(components("a/./b"), [n("a"), Component::CurDir, n("b")]);
    assert_eq!(
        components("a//b/"),
        [n("a"), Component::Empty, n("b"), Component::Empty]
    );
    assert_eq!(components("../a"), [Component::ParentDir, n("a")]);
}

/// The root is the anchor, not a component.
///
/// Mutant: the leading `/` splits off an `Empty` component.
#[skuld::test]
fn the_root_is_not_a_component() {
    assert_eq!(components("/"), []);
    assert_eq!(components(""), []);
    assert_eq!(components("/a"), [n("a")]);
    assert_eq!(components("//"), [Component::Empty, Component::Empty]);
    assert!(p("/a").has_root());
    assert!(!p("a").has_root());
}

/// Components read from the back are the same components.
///
/// Mutant: `next_back` returns the front piece.
#[skuld::test]
fn components_reverse() {
    let back: Vec<_> = p("a//b/").components().rev().collect();
    assert_eq!(back, [Component::Empty, n("b"), Component::Empty, n("a")]);
}

// Equality and order ==================================================================================================

/// Spellings that name one file stay unequal.
///
/// Mutant: equality compares `lexically_normal()` forms.
#[skuld::test]
fn posix_equality_is_exact() {
    assert_ne!(p("a/./b"), p("a/b"));
    assert_ne!(p("a//b"), p("a/b"));
    assert_ne!(p("a/b/"), p("a/b"));
    assert_ne!(p("A"), p("a"));
    assert_ne!(p("/a"), p("a"));
    assert_eq!(p("a/b"), PathBuf::from("a/b").as_path());
}

/// Order is component by component, not by bytes.
///
/// Mutant: order by the bytes, where `-` sorts before `/`.
#[skuld::test]
fn order_is_component_wise() {
    assert!(p("a/b") < p("a-b"));
    assert!(p("a") < p("a/b"));
}

/// Equal paths hash equal, so a borrowed `Path` finds an owned key.
///
/// Mutant: the hash includes the storage address.
#[skuld::test]
fn equal_paths_hash_equal() {
    let owned = PathBuf::from("a/b");
    let state = RandomState::new();
    assert_eq!(state.hash_one(owned.as_path()), state.hash_one(p("a/b")));
    let set: HashSet<PathBuf> = [owned].into();
    assert!(set.contains(p("a/b")));
    assert!(!set.contains(p("a/./b")));
}

// Join ================================================================================================================

/// An rhs with a root replaces the lhs.
///
/// Mutant: the rhs is appended after a separator.
#[skuld::test]
fn join_with_an_absolute_rhs_replaces() {
    assert_eq!(p("a/b").join(p("/c")), PathBuf::from("/c"));
    assert_eq!(p("/a").join(p("/")), PathBuf::from("/"));
}

/// A relative rhs appends its components to the lhs's, as written.
///
/// Mutant: std's `push`, which reuses a trailing separator and adds one for an empty rhs.
#[skuld::test]
fn join_appends_components() {
    assert_eq!(p("a/b").join(p("c")), PathBuf::from("a/b/c"));
    assert_eq!(p("a/").join(p("b")), PathBuf::from("a//b"));
    assert_eq!(p("a").join(p("./b")), PathBuf::from("a/./b"));
    assert_eq!(p("").join(p("c")), PathBuf::from("c"));
    assert_eq!(p("/").join(p("c")), PathBuf::from("/c"));
    assert_eq!(p("a").join(p("")), PathBuf::from("a"));
}

/// `push` is an in-place `join`.
///
/// Mutant: `push` does nothing.
#[skuld::test]
fn push_is_join() {
    let mut buf = PathBuf::from("a/");
    buf.push("b");
    assert_eq!(buf, PathBuf::from("a//b"));
    buf.push("/c");
    assert_eq!(buf, PathBuf::from("/c"));
}

// Lexical normalisation ===============================================================================================

/// `lexically_normal` collapses `.`, `name/..` and separators, and keeps names as written.
///
/// Mutant: it returns the path unchanged.
#[skuld::test]
fn lexically_normal_collapses_only_dots_and_separators() {
    assert_eq!(p("a/b/../c").lexically_normal(), PathBuf::from("a/c"));
    assert_eq!(p("/..").lexically_normal(), PathBuf::from("/"));
    assert_eq!(p("/../a").lexically_normal(), PathBuf::from("/a"));
    assert_eq!(p("a//./b").lexically_normal(), PathBuf::from("a/b"));
    assert_eq!(p("../a").lexically_normal(), PathBuf::from("../a"));
    assert_eq!(p("a./b../...").lexically_normal(), PathBuf::from("a./b../..."));
    assert_eq!(p("a /b").lexically_normal(), PathBuf::from("a /b"));
}

/// At the edges, `lexically_normal` gives what C++'s `lexically_normal` gives (libstdc++ 14).
///
/// Mutant: a trailing separator is dropped, and an emptied relative path stays empty.
#[skuld::test]
fn lexically_normal_matches_cpp_at_the_edges() {
    let cases = [
        ("foo/./bar/..", "foo/"),
        ("foo/.///bar/../", "foo/"),
        ("a/", "a/"),
        ("a/.", "a/"),
        ("a/..", "."),
        (".", "."),
        ("../", ".."),
        ("a/../../", ".."),
        ("", ""),
    ];
    for (input, expected) in cases {
        assert_eq!(p(input).lexically_normal(), PathBuf::from(expected), "input {input:?}");
    }
}

/// A run of separators is repeated separators, so it collapses to the root. libstdc++ keeps `//`
/// and `///` as they are; this is the one place `lexically_normal` differs from C++'s.
///
/// Mutant: an all-slash path is returned unchanged, as libstdc++ does.
#[skuld::test]
fn lexically_normal_collapses_a_run_of_slashes_to_the_root() {
    for input in ["/", "//", "///", "////"] {
        assert_eq!(p(input).lexically_normal(), PathBuf::from("/"), "input {input:?}");
    }
}

// Parent and file name ================================================================================================

/// `parent` drops exactly the last component and the separator before it.
///
/// Mutant: std's `parent`, which skips a trailing separator and `.`.
#[skuld::test]
fn parent_drops_only_the_last_component() {
    assert_eq!(p("a/b").parent(), Some(p("a")));
    assert_eq!(p("a/b/").parent(), Some(p("a/b")));
    assert_eq!(p("a/.").parent(), Some(p("a")));
    assert_eq!(p("a//").parent(), Some(p("a/")));
    assert_eq!(p("/a").parent(), Some(p("/")));
    assert_eq!(p("a").parent(), Some(p("")));
    assert_eq!(p("/").parent(), None);
    assert_eq!(p("").parent(), None);
}

/// `pop` truncates to the parent and reports whether there was one.
///
/// Mutant: `pop` does nothing and returns `false`.
#[skuld::test]
fn pop_truncates_to_the_parent() {
    let mut buf = PathBuf::from("/a/b/");
    assert!(buf.pop());
    assert_eq!(buf, PathBuf::from("/a/b"));
    let mut root = PathBuf::from("/");
    assert!(!root.pop());
    assert_eq!(root, PathBuf::from("/"));
}

/// The file name is the last component when it is a name.
///
/// Mutant: std's `file_name`, which skips a trailing separator.
#[skuld::test]
fn file_name_is_a_trailing_normal_name() {
    assert_eq!(p("a/b").file_name(), Some(OsStr::new("b")));
    assert_eq!(p("a/").file_name(), None);
    assert_eq!(p("a/..").file_name(), None);
    assert_eq!(p("a/.").file_name(), None);
    assert_eq!(p("/").file_name(), None);
}

/// `set_file_name` replaces a trailing name and otherwise appends.
///
/// Mutant: it always appends.
#[skuld::test]
fn set_file_name_replaces_only_a_name() {
    let mut buf = PathBuf::from("a/b");
    buf.set_file_name("c");
    assert_eq!(buf, PathBuf::from("a/c"));
    let mut dir = PathBuf::from("a/");
    dir.set_file_name("c");
    assert_eq!(dir, PathBuf::from("a//c"));
    // An empty name is an `Empty` component, not a deletion.
    let mut gone = PathBuf::from("a/b");
    gone.set_file_name("");
    assert_eq!(gone, PathBuf::from("a/"));
}

/// A name holding `/` is not one component: a contract, asserted in debug.
/// Mutant: the assertion removed, so `a/b` with `x/y` becomes `a/x/y`.
#[skuld::test]
fn set_file_name_refuses_a_path_in_debug() {
    let caught = std::panic::catch_unwind(|| PathBuf::from("a/b").set_file_name("x/y"));
    assert_eq!(
        caught.is_err(),
        cfg!(debug_assertions),
        "debug builds assert; release builds append"
    );
}

/// Every path over `{a, ., /}` of up to six bytes: the class that single examples miss, such as a
/// root followed by a leading `Empty` component.
fn small_paths() -> Vec<String> {
    let mut all = vec![String::new()];
    let mut level = vec![String::new()];
    for _ in 0..6 {
        level = level
            .iter()
            .flat_map(|s| ["a", ".", "/"].map(|c| format!("{s}{c}")))
            .collect();
        all.extend(level.iter().cloned());
    }
    all
}

/// `parent` is the path without its last component, for every path that can spell that.
///
/// A root followed by a single `Empty` component spells `/`, which parses to no components, so
/// the parent of `//x` is `/`.
///
/// Mutant: `parent` cuts at `i` instead of `root + i`, which drops the root's offset.
#[skuld::test]
fn parent_is_the_components_minus_the_last() {
    for input in small_paths() {
        let path = p(&input);
        let all = components(&input);
        let Some(parent) = path.parent() else {
            assert!(all.is_empty(), "{input:?} has components and no parent");
            continue;
        };
        let got: Vec<_> = parent.components().collect();
        let mut want = all[..all.len() - 1].to_vec();
        if path.has_root() && want == [Component::Empty] {
            want.clear();
        }
        assert_eq!(got, want, "parent of {input:?}");
        assert_eq!(parent.has_root(), path.has_root(), "root of the parent of {input:?}");
        assert!(path.as_bytes().starts_with(parent.as_bytes()), "{input:?}");
    }
}

/// The parent of `//` and one more component is `/`, the nearest path that can be spelled.
///
/// Mutant: `parent` of `//x` is `None`.
#[skuld::test]
fn parent_of_a_double_slash_path_is_the_root() {
    for input in ["//x", "//", "//.", "//.."] {
        assert_eq!(p(input).parent(), Some(p("/")), "{input:?}");
    }
    assert_eq!(p("//x/y").parent(), Some(p("//x")));
    assert_eq!(p("///").parent(), Some(p("//")));
    let mut buf = PathBuf::from("//x");
    assert!(buf.pop());
    assert_eq!(buf, PathBuf::from("/"));
}

/// `set_file_name` changes the last component and nothing else, for every path.
///
/// Mutant: `set_file_name` is `pop` then `push`, which turns `//x` into `/y`.
#[skuld::test]
fn set_file_name_changes_only_the_last_component() {
    for input in small_paths() {
        let mut buf = PathBuf::from(input.as_str());
        buf.set_file_name("z");
        let mut want = components(&input);
        if p(&input).file_name().is_some() {
            want.pop();
        }
        want.push(n("z"));
        assert_eq!(buf.components().collect::<Vec<_>>(), want, "set_file_name on {input:?}");
        assert_eq!(buf.has_root(), p(&input).has_root(), "root of {input:?}");
    }
    let mut buf = PathBuf::from("//x");
    buf.set_file_name("y");
    assert_eq!(buf, PathBuf::from("//y"));
}

// Shape ===============================================================================================================

/// A path is absolute exactly when it has a root.
///
/// Mutant: absolute means non-empty.
#[skuld::test]
fn absolute_means_rooted() {
    assert!(p("/a").is_absolute());
    assert!(p("/").is_absolute());
    assert!(!p("a").is_absolute());
    assert!(!p("").is_absolute());
}

/// A bare name is any non-empty path without `/`, as `execvp` decides.
///
/// Mutant: a bare name is a single `Normal` component, which excludes `.` and `..`.
#[skuld::test]
fn a_bare_name_has_no_slash() {
    for bare in ["ls", ".", "..", "a b"] {
        assert!(p(bare).is_bare_name(), "{bare:?}");
    }
    for located in ["a/b", "./ls", "/ls", "ls/", ""] {
        assert!(!p(located).is_bare_name(), "{located:?}");
    }
}

// Conversion ==========================================================================================================

/// A C string refuses a NUL byte and nothing else.
///
/// Mutant: it also refuses invalid UTF-8.
#[skuld::test]
fn to_cstring_refuses_only_an_interior_nul() {
    assert_eq!(Path::from_bytes(b"a\0b").to_cstring().unwrap_err().nul_at(), 1);
    assert_eq!(Path::from_bytes(b"\0").to_cstring().unwrap_err().nul_at(), 0);
    let c = Path::from_bytes(b"/a\xffb").to_cstring().unwrap();
    assert_eq!(c.as_bytes(), b"/a\xffb");
}

/// `Path::new` borrows its argument.
///
/// Mutant: it copies into a leaked allocation.
#[skuld::test]
fn new_borrows_without_copying() {
    let s = String::from("a/b");
    assert_eq!(Path::new(&s).as_bytes().as_ptr(), s.as_ptr());
}

/// The native bytes are the path's own bytes, borrowed.
///
/// Mutant: they are copied.
#[skuld::test]
fn native_bytes_are_borrowed() {
    let path = Path::from_bytes(b"a\xff");
    match path.to_native_bytes() {
        Cow::Borrowed(bytes) => assert_eq!(bytes.as_ptr(), path.as_bytes().as_ptr()),
        Cow::Owned(_) => panic!("the native bytes were copied"),
    }
}

/// `to_str` is exact or nothing; `to_string_lossy` replaces what is not UTF-8.
///
/// Mutant: `to_str` is lossy.
#[skuld::test]
fn to_str_is_exact_or_nothing() {
    assert_eq!(p("a/é").to_str(), Some("a/é"));
    assert_eq!(Path::from_bytes(b"a\xff").to_str(), None);
    assert_eq!(Path::from_bytes(b"a\xff").to_string_lossy(), "a\u{FFFD}");
    assert_eq!(OsStr::from_bytes(b"a\xff").to_str(), None);
    assert_eq!(OsStr::new("é").to_str(), Some("é"));
}

/// `Debug` is quoted and escaped, and distinguishes a byte from its escape's spelling.
///
/// Mutant: `Debug` is the lossy string.
#[skuld::test]
fn debug_is_faithful_for_a_non_utf8_byte() {
    assert_eq!(format!("{:?}", Path::from_bytes(b"a\xffb")), r#""a\xFFb""#);
    assert_eq!(format!("{:?}", p(r"a\xFFb")), r#""a\\xFFb""#);
    assert_eq!(format!("{:?}", p("a\"b\n")), r#""a\"b\n""#);
    assert_eq!(format!("{:?}", PathBuf::from("é")), r#""é""#);
}

/// `display` replaces what is not UTF-8 with U+FFFD.
///
/// Mutant: `display` writes nothing.
#[skuld::test]
fn display_is_lossy() {
    assert_eq!(Path::from_bytes(b"a\xffb").display().to_string(), "a\u{FFFD}b");
}

/// The `std` conversions borrow, in both directions.
///
/// Mutant: either direction copies.
#[cfg(unix)]
#[skuld::test]
fn std_conversions_borrow() {
    let path = Path::from_bytes(b"/a\xff");
    let std_path = path.as_std_path();
    assert_eq!(std_path.as_os_str().len(), 3);
    assert_eq!(
        std_path.as_os_str().as_encoded_bytes().as_ptr(),
        path.as_bytes().as_ptr()
    );
    let back = Path::from_std_path(std_path);
    assert_eq!(back.as_bytes().as_ptr(), path.as_bytes().as_ptr());
    assert_eq!(back, path);
}
