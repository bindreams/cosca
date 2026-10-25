use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::hash::{BuildHasher, RandomState};

use super::{is_verbatim_spelling, parts, Anchor, Drive, OsStr, OsString, ParseError, Path, PathBuf};
use crate::{Component, PurePath};

fn p(s: &str) -> PathBuf {
    PathBuf::parse(s).unwrap_or_else(|e| panic!("{s:?} does not parse: {e}"))
}

fn components(s: &str) -> Vec<Component<'static, OsStr>> {
    // Leaked so the components outlive the parsed path; test-only.
    let path: &'static PathBuf = Box::leak(Box::new(p(s)));
    path.components().collect()
}

fn n(s: &str) -> Component<'_, OsStr> {
    Component::Normal(OsStr::new(s))
}

fn os(s: &str) -> &OsStr {
    OsStr::new(s)
}

fn drive(c: char) -> Drive {
    Drive(u16::try_from(u32::from(c)).unwrap())
}

/// A path from UTF-16 units, possibly ill-formed.
fn wide(units: &[u16]) -> PathBuf {
    PathBuf::from_wide(units).unwrap()
}

/// `C:\` followed by `rest`, as UTF-16 units.
fn c_root_then(rest: &[u16]) -> Vec<u16> {
    let mut units: Vec<u16> = r"C:\".encode_utf16().collect();
    units.extend_from_slice(rest);
    units
}

// Parsing =============================================================================================================

/// A verbatim spelling parses to the plain path it names, with the prefix gone from storage.
///
/// Mutant: the `\\?\` prefix is kept, so `\\?\C:\x` is a device path unequal to `C:\x`.
#[skuld::test]
fn verbatim_input_parses_without_its_prefix() {
    assert_eq!(p(r"\\?\C:\x"), p(r"C:\x"));
    assert_eq!(p(r"\\?\C:\x").to_str(), Some(r"C:\x"));
    assert_eq!(p(r"\\?\UNC\s\h\x"), p(r"\\s\h\x"));
    assert_eq!(p(r"\\?\UNC\s\h\x").to_str(), Some(r"\\s\h\x"));
    assert_eq!(
        p(r"\\?\UNC\s\h\x").anchor(),
        Anchor::Unc {
            server: os("s"),
            share: os("h")
        }
    );
    assert_eq!(p(r"\\?\C:foo").anchor(), Anchor::Device { name: os("C:foo") });
    assert_eq!(p(r"\\?\C:foo"), p(r"\\.\C:foo"));
}

/// `UNC` after `\\?\` is a keyword the object manager matches in any case.
///
/// Mutant: only `UNC` in upper case is a UNC path; `unc` is a device named `unc`.
#[skuld::test]
fn verbatim_unc_keyword_ignores_case() {
    assert_eq!(p(r"\\?\unc\s\h"), p(r"\\s\h"));
    assert_eq!(
        p(r"\\?\Unc\s\h\x").anchor(),
        Anchor::Unc {
            server: os("s"),
            share: os("h")
        }
    );
}

/// Under `\\?\` a `/` is not a separator, and no Microsoft filesystem takes it in a name, so the
/// parse refuses it. Without the exact prefix, `/` is a separator again.
///
/// Mutant: the verbatim rest is split on `/` too.
#[skuld::test]
fn verbatim_input_with_a_slash_is_refused() {
    for input in [r"\\?\C:\a/b", r"\\?\C:/a", r"\\?\UNC\s\h/x", r"\\?\d/x", r"\\?\/"] {
        assert_eq!(PathBuf::parse(input), Err(ParseError::SlashInVerbatim), "{input:?}");
    }
    assert_eq!(p(r"\\?/C:/x").anchor(), Anchor::Device { name: os("C:") });
    assert_eq!(p(r"//?/C:/x").anchor(), Anchor::Device { name: os("C:") });
}

/// A verbatim UNC server named `.` or `?` would read back as a device path, so it is refused.
///
/// Mutant: `\\?\UNC\.\h` is stored as `\\.\h`, a device named `h`.
#[skuld::test]
fn verbatim_unc_server_with_no_plain_spelling_is_refused() {
    for input in [r"\\?\UNC\.\h", r"\\?\UNC\?\h\x", r"\\?\UNC\.", r"\\?\UNC\?"] {
        assert_eq!(
            PathBuf::parse(input),
            Err(ParseError::UnspellableUncServer),
            "{input:?}"
        );
    }
    assert_eq!(p(r"\\?\UNC\.x\h"), p(r"\\.x\h"));
    assert_eq!(
        p(r"\\?\UNC\..\h").anchor(),
        Anchor::Unc {
            server: os(".."),
            share: os("h")
        }
    );
}

/// For every small rest without `/`, `\\?\` and that rest is the plain drive path it spells, or
/// else the device path `\\.\` and that rest.
///
/// Mutant: a separator counts as a verbatim drive's unit, so `\\?\\:\` is stored as the rooted
/// `\:\`.
#[skuld::test]
fn verbatim_parses_like_its_plain_spelling() {
    for rest in small_paths_up_to(5) {
        if rest.contains('/') {
            continue;
        }
        let verbatim = p(&format!(r"\\?\{rest}"));
        let plain = p(&rest);
        let want = match plain.anchor() {
            Anchor::Drive { rooted: true, .. } => plain,
            _ => p(&format!(r"\\.\{rest}")),
        };
        assert_eq!(verbatim, want, "\\\\?\\ then {rest:?}");
        assert!(!is_verbatim_spelling(verbatim.as_os_str()), "{rest:?} kept its prefix");
    }
}

/// Only the exact four units `\\?\` are the verbatim spelling.
///
/// Mutant: any two separators, `?` and a separator count.
#[skuld::test]
fn verbatim_spelling_is_the_exact_prefix() {
    assert!(is_verbatim_spelling(os(r"\\?\C:\x")));
    assert!(is_verbatim_spelling(os(r"\\?\")));
    for plain in [r"//?/C:/x", r"\\?/x", r"/\?\x", r"\\.\x", r"\\?", r"C:\x", ""] {
        assert!(!is_verbatim_spelling(os(plain)), "{plain:?}");
    }
}

/// Every small path parses, unless it is verbatim with a `/`; it is stored as written unless
/// verbatim; its stored spelling parses back to itself; and its anchor and components spell it
/// back, up to separator choice.
///
/// Mutant: the components drop `.` and empty names, as std's do.
#[skuld::test]
fn parse_and_spell_round_trip() {
    for input in small_paths() {
        let parsed = match PathBuf::parse(input.as_str()) {
            Ok(path) => path,
            Err(e) => {
                assert!(
                    input.starts_with(r"\\?\") && input[4..].contains('/'),
                    "{input:?} refused: {e}"
                );
                continue;
            }
        };
        if !input.starts_with(r"\\?\") {
            assert_eq!(parsed.to_str(), Some(input.as_str()), "{input:?} was rewritten");
        }
        let again = PathBuf::parse(parsed.as_os_str()).unwrap();
        assert_eq!(again.to_str(), parsed.to_str(), "{input:?} does not reparse to itself");
        assert_eq!(spell(&parsed), parsed.to_str().unwrap().replace('/', "\\"), "{input:?}");
    }
}

/// The anchor's text as written, then each component after a `\`, with every separator `\`.
fn spell(path: &Path) -> String {
    let text = path.to_str().unwrap();
    let mut out = text[..head_len(path)].replace('/', "\\");
    if has_root_separator(path) {
        out.push('\\');
    }
    for (i, c) in path.components().enumerate() {
        if i > 0 {
            out.push('\\');
        }
        out.push_str(match c {
            Component::CurDir => ".",
            Component::ParentDir => "..",
            Component::Empty => "",
            Component::Normal(name) => name.to_str().unwrap(),
        });
    }
    out
}

/// The parse error says what was refused and why.
///
/// Mutant: the message is empty.
#[skuld::test]
fn parse_error_messages_name_the_spelling() {
    assert!(ParseError::SlashInVerbatim.to_string().contains(r"\\?\"));
    assert!(ParseError::UnspellableUncServer.to_string().contains("server"));
}

// Anchors =============================================================================================================

/// The anchor follows Win32's path types: two separators then `.` or `?` and a separator is a
/// device, other double separators are UNC, a drive is any one UTF-16 unit and `:`.
///
/// Mutant: a drive is only an ASCII letter, so `1:a` and `é:a` are relative.
#[skuld::test]
fn anchors_follow_win32_path_types() {
    let cases: &[(&str, Anchor<'_>)] = &[
        ("", Anchor::None),
        ("a", Anchor::None),
        (r"a\b", Anchor::None),
        (r"\a", Anchor::Rooted),
        ("/a", Anchor::Rooted),
        (r"\:a", Anchor::Rooted),
        (
            "C:a",
            Anchor::Drive {
                drive: drive('C'),
                rooted: false,
            },
        ),
        (
            "C:",
            Anchor::Drive {
                drive: drive('C'),
                rooted: false,
            },
        ),
        (
            r"C:\a",
            Anchor::Drive {
                drive: drive('C'),
                rooted: true,
            },
        ),
        (
            "c:/",
            Anchor::Drive {
                drive: drive('c'),
                rooted: true,
            },
        ),
        (
            "1:a",
            Anchor::Drive {
                drive: drive('1'),
                rooted: false,
            },
        ),
        (
            "é:a",
            Anchor::Drive {
                drive: drive('é'),
                rooted: false,
            },
        ),
        (
            "::a",
            Anchor::Drive {
                drive: drive(':'),
                rooted: false,
            },
        ),
        ("\u{1D538}:a", Anchor::None),
        (
            r"\\s\h\x",
            Anchor::Unc {
                server: os("s"),
                share: os("h"),
            },
        ),
        (
            "//s/h",
            Anchor::Unc {
                server: os("s"),
                share: os("h"),
            },
        ),
        (
            r"\\s",
            Anchor::Unc {
                server: os("s"),
                share: os(""),
            },
        ),
        (
            r"\\s\",
            Anchor::Unc {
                server: os("s"),
                share: os(""),
            },
        ),
        (
            r"\\",
            Anchor::Unc {
                server: os(""),
                share: os(""),
            },
        ),
        (
            r"\\\h",
            Anchor::Unc {
                server: os(""),
                share: os("h"),
            },
        ),
        (
            r"\\.x\h",
            Anchor::Unc {
                server: os(".x"),
                share: os("h"),
            },
        ),
        (
            r"\\..\h",
            Anchor::Unc {
                server: os(".."),
                share: os("h"),
            },
        ),
        (r"\\.\d\x", Anchor::Device { name: os("d") }),
        (r"//./d", Anchor::Device { name: os("d") }),
        (r"\\?/d", Anchor::Device { name: os("d") }),
        (r"\\.\", Anchor::Device { name: os("") }),
        (r"\\.", Anchor::Device { name: os("") }),
        (r"\\?", Anchor::Device { name: os("") }),
    ];
    for (input, anchor) in cases {
        assert_eq!(p(input).anchor(), *anchor, "{input:?}");
    }
}

/// A drive's unit is any UTF-16 unit, a lone surrogate included.
///
/// Mutant: the drive is read from the first byte, not the first unit.
#[skuld::test]
fn a_drive_is_one_utf16_unit() {
    let path = wide(&[0xD800, u16::from(b':'), u16::from(b'x')]);
    assert_eq!(path.drive(), Some(Drive(0xD800)));
    assert_eq!(p(r"é:\x").drive().map(Drive::unit), Some(0xE9));
    assert_eq!(p(r"\\s\h").drive(), None);
}

/// The shape predicates partition the anchors: none or rooted need a current directory, a
/// drive without a root needs that drive's, and the rest are fully qualified.
///
/// Mutant: a rooted path counts as fully qualified.
#[skuld::test]
fn shape_predicates_follow_the_anchor() {
    // (input, fully qualified, drive-relative, rooted)
    let cases = [
        ("a", false, false, false),
        (r"\a", false, false, true),
        ("C:a", false, true, false),
        (r"C:\a", true, false, false),
        (r"\\s\h", true, false, false),
        (r"\\s", false, false, false),
        (r"\\.\d", true, false, false),
        ("", false, false, false),
    ];
    for (input, qualified, drive_relative, rooted) in cases {
        let path = p(input);
        assert_eq!(path.is_fully_qualified(), qualified, "{input:?}");
        assert_eq!(path.is_absolute(), qualified, "{input:?}");
        assert_eq!(path.is_drive_relative(), drive_relative, "{input:?}");
        assert_eq!(path.is_rooted(), rooted, "{input:?}");
    }
}

/// A UNC path needs a non-empty server and share, and a device path more than `\\.` or `\\?`
/// alone: otherwise it is not fully qualified, as main's `is_absolute_name` has it.
///
/// Mutant: any UNC anchor, or a bare `\\.` or `\\?`, counts as fully qualified.
#[skuld::test]
fn an_incomplete_unc_or_device_is_not_fully_qualified() {
    let cases = [
        (r"\\s", false),
        (r"\\s\", false),
        (r"\\", false),
        (r"\\\", false),
        (r"\\\h", false),
        (r"\\s\\", false),
        (r"\\.", false),
        (r"\\?", false),
        (r"\\s\h", true),
        (r"\\s\h\", true),
        (r"\\s\h\x", true),
        (r"\\.\", true),
        (r"\\.\d", true),
        (r"\\?/", true),
    ];
    for (input, qualified) in cases {
        let path = p(input);
        assert_eq!(path.is_fully_qualified(), qualified, "{input:?}");
        assert_eq!(path.is_absolute(), qualified, "{input:?}");
    }
}

/// A bare name has no separator and no drive.
///
/// Mutant: a drive-relative `C:tool` counts as bare, though no directory can be joined to it.
#[skuld::test]
fn a_bare_name_has_no_separator_or_drive() {
    for bare in ["tool", ".", "..", "a b", "a.exe"] {
        assert!(p(bare).is_bare_name(), "{bare:?}");
    }
    for located in [r"a\b", "a/b", "C:tool", "C:", r"\tool", "", r"\\s\h"] {
        assert!(!p(located).is_bare_name(), "{located:?}");
    }
}

/// `as_unc` views a UNC path's server, share and the text after the share's separator.
///
/// Mutant: `rest` keeps the separator after the share.
#[skuld::test]
fn as_unc_views_server_share_and_rest() {
    let path = p(r"\\s\h\a\\b");
    let unc = path.as_unc().unwrap();
    assert_eq!((unc.server, unc.share, unc.rest), (os("s"), os("h"), os(r"a\\b")));
    let bare = p(r"\\s\h");
    assert_eq!(bare.as_unc().unwrap().rest, os(""));
    assert!(p(r"\\.\d\x").as_unc().is_none());
    assert!(p(r"C:\x").as_unc().is_none());
}

// Components ==========================================================================================================

/// `.` and repeated or trailing separators stay components, after any anchor.
///
/// Mutant: std's parser, which drops `.` and empty names.
#[skuld::test]
fn windows_components_are_faithful() {
    assert_eq!(components(r"a\.\b"), [n("a"), Component::CurDir, n("b")]);
    assert_eq!(
        components(r"a\\b/"),
        [n("a"), Component::Empty, n("b"), Component::Empty]
    );
    assert_eq!(components(r"C:\\a"), [Component::Empty, n("a")]);
    assert_eq!(components(r"C:a\.."), [n("a"), Component::ParentDir]);
    assert_eq!(components(r"\\s\h\x\"), [n("x"), Component::Empty]);
    assert_eq!(components(r"\\.\d\x"), [n("x")]);
}

/// An anchor alone has no components, with or without its root.
///
/// Mutant: the root separator splits off an `Empty` component.
#[skuld::test]
fn an_anchor_alone_has_no_components() {
    for anchor in [
        "", r"\", "C:", r"C:\", r"\\s", r"\\s\h", r"\\s\h\", r"\\.\d", r"\\.\d\", r"\\.",
    ] {
        assert_eq!(components(anchor), [], "{anchor:?}");
    }
}

/// Components read from the back are the same components.
///
/// Mutant: `next_back` returns the front piece.
#[skuld::test]
fn components_reverse() {
    let path = p(r"C:\a\\b\");
    let back: Vec<_> = path.components().rev().collect();
    assert_eq!(back, [Component::Empty, n("b"), Component::Empty, n("a")]);
}

// Equality and order ==================================================================================================

/// `/` and `\` are one separator, in the anchor and between components.
///
/// Mutant: only `\` separates, so `C:/a/b` is the drive-relative name `/a/b`.
#[skuld::test]
fn slash_and_backslash_are_one_separator() {
    assert_eq!(p("C:/a/b"), p(r"C:\a\b"));
    assert_eq!(components("C:/a/b"), components(r"C:\a\b"));
    assert_eq!(p("//s/h/x"), p(r"\\s\h\x"));
    assert_eq!(p(r"a/b\c"), p(r"a\b/c"));
    let state = RandomState::new();
    assert_eq!(state.hash_one(p("C:/a/b")), state.hash_one(p(r"C:\a\b")));
}

/// Spellings that name one file on Windows stay unequal and keep their components; only
/// `lexically_normal` merges `.` and repeated separators.
///
/// Mutant: equality compares the `lexically_normal()` forms.
#[skuld::test]
fn spellings_that_name_one_file_stay_unequal() {
    let plain = p(r"C:\a\b");
    for other in [r"C:\a\.\b", r"C:\a\\b", r"C:\a\b\"] {
        assert_ne!(p(other), plain, "{other:?}");
        assert_ne!(components(other), components(r"C:\a\b"), "{other:?}");
    }
    assert_eq!(p(r"C:\a\.\b").lexically_normal(), plain);
    assert_eq!(p(r"C:\a\\b").lexically_normal(), plain);
    assert_ne!(p(r"\\s\h"), p(r"\\s\h\"));
    assert_ne!(p(r"\\s"), p(r"\\s\"));
}

/// Case is exact, the drive letter included.
///
/// Mutant: equality folds case.
#[skuld::test]
fn drive_letters_compare_exactly() {
    assert_ne!(p(r"c:\x"), p(r"C:\x"));
    assert_ne!(p(r"C:\X"), p(r"C:\x"));
    assert_ne!(p(r"\\S\h"), p(r"\\s\h"));
}

/// `cmp` is `Equal` exactly when `==` holds, swapping the operands reverses it, and equal paths
/// hash equal.
///
/// Mutant: `cmp` compares only the anchor and components, so `\\s` equals `\\s\`.
#[skuld::test]
fn order_agrees_with_equality() {
    let all: Vec<PathBuf> = small_paths_up_to(4)
        .iter()
        .filter_map(|s| PathBuf::parse(s.as_str()).ok())
        .collect();
    let state = RandomState::new();
    for a in &all {
        for b in &all {
            assert_eq!(a.cmp(b) == Ordering::Equal, a == b, "{a:?} against {b:?}");
            assert_eq!(a.cmp(b), b.cmp(a).reverse(), "{a:?} against {b:?}");
            if a == b {
                assert_eq!(state.hash_one(a), state.hash_one(b), "{a:?} against {b:?}");
            }
        }
    }
}

/// Choosing `/` or `\` for a separator changes no comparison: `cmp` gives the same answer for a
/// pair of paths and for the same pair with every `/` written `\`.
///
/// Mutant: `cmp` compares the raw bytes, where `/` sorts before `\`.
#[skuld::test]
fn order_ignores_the_choice_of_separator() {
    // Writing every `/` as `\` would spell the device path `\\?/x` as the verbatim `\\?\x`.
    let pairs: Vec<(PathBuf, PathBuf)> = small_paths_up_to(4)
        .iter()
        .filter_map(|s| PathBuf::parse(s.as_str()).ok())
        .filter_map(|path| {
            let folded = path.to_str().unwrap().replace('/', "\\");
            (!folded.starts_with(r"\\?\")).then(|| (path, p(&folded)))
        })
        .collect();
    assert_eq!(p("C:/a").cmp(&p(r"C:\a")), Ordering::Equal);
    assert_eq!(p("C:/b").cmp(&p(r"C:\a")), Ordering::Greater);
    for (a, folded_a) in &pairs {
        for (b, folded_b) in &pairs {
            assert_eq!(a.cmp(b), folded_a.cmp(folded_b), "{a:?} against {b:?}");
        }
    }
}

/// Order is by anchor, then component by component.
///
/// Mutant: order by the bytes, where `-` sorts before `\`.
#[skuld::test]
fn order_is_anchor_then_components() {
    assert!(p(r"a\b") < p("a-b"));
    assert!(p("a") < p(r"\a"));
    assert!(p(r"\a") < p(r"C:\a"));
    assert!(p(r"C:\z") < p(r"\\s\h"));
    assert!(p(r"\\s\h") < p(r"\\.\d"));
}

/// A borrowed `Path` finds an owned key spelled with the other separator.
///
/// Mutant: the hash uses the raw bytes, so `/` and `\` hash apart.
#[skuld::test]
fn a_set_finds_a_path_by_either_separator() {
    let set: HashSet<PathBuf> = [p(r"C:\a\b")].into();
    assert!(set.contains(p("C:/a/b").as_path()));
    assert!(!set.contains(p(r"C:\a\.\b").as_path()));
}

// Join ================================================================================================================

/// `join` follows std's `push`: an rhs with a drive, share or device replaces the lhs; a rooted
/// rhs keeps the lhs's drive, share or device; a relative rhs appends after a `\`.
///
/// Mutant: a rooted rhs replaces the lhs entirely, so `C:\a` joined with `\x` is `\x`.
#[skuld::test]
fn join_follows_std() {
    let cases = [
        (r"C:\a", r"\x", r"C:\x"),
        (r"C:a", r"\x", r"C:\x"),
        (r"\\s\h\a", r"\x", r"\\s\h\x"),
        (r"\\.\d\a", r"\x", r"\\.\d\x"),
        (r"\a", r"\x", r"\x"),
        ("a", r"\x", r"\x"),
        (r"C:\a", "D:x", "D:x"),
        (r"C:\a", "C:x", "C:x"),
        ("a", r"\\s\h", r"\\s\h"),
        (r"C:\a", "b", r"C:\a\b"),
        (r"C:\a\", "b", r"C:\a\\b"),
        ("C:", "b", "C:b"),
        (r"C:\", "b", r"C:\b"),
        (r"\\s\h", "b", r"\\s\h\b"),
        (r"\\s\h\", "b", r"\\s\h\b"),
        ("", "b", "b"),
        ("a", "", "a"),
        ("a", "./b", r"a\./b"),
    ];
    for (lhs, rhs, want) in cases {
        let joined = p(lhs).join(&p(rhs));
        assert_eq!(joined.to_str(), Some(want), "{lhs:?} joined with {rhs:?}");
    }
}

/// An unfinished UNC or device anchor takes the rhs's first component, as Win32 reads the
/// string.
///
/// Mutant: the join adds no separator after `\\s`, giving the server `sh`.
#[skuld::test]
fn join_completes_an_unfinished_anchor() {
    assert_eq!(
        p(r"\\s").join(&p("h")).anchor(),
        Anchor::Unc {
            server: os("s"),
            share: os("h")
        }
    );
    assert_eq!(p(r"\\.").join(&p("d")).anchor(), Anchor::Device { name: os("d") });
    assert_eq!(
        p(r"\\s").join(&p(r"\h")).anchor(),
        Anchor::Unc {
            server: os("s"),
            share: os("h")
        }
    );
}

/// An unfinished anchor takes the first appended component whether or not its own separator is
/// there: `\\s\` joined with `b` is `\\s\b`, as `\\s` joined with `b` is. A separator that ends the
/// path after a name or share (`\\s\\`) is a root, and the component after it stays a component.
///
/// Mutant: the join adds a second `\` after `\\s\`, so the share stays empty.
#[skuld::test]
fn join_completes_an_unfinished_anchor_with_or_without_its_separator() {
    let cases = [
        (r"\\s", "b", r"\\s\b"),
        (r"\\s\", "b", r"\\s\b"),
        (r"\\s", r"\b", r"\\s\b"),
        (r"\\s\", r"\b", r"\\s\b"),
        (r"\\", "b", r"\\\b"),
        (r"\\\", "b", r"\\\b"),
        (r"\\.", "b", r"\\.\b"),
        (r"\\.\", "b", r"\\.\b"),
        (r"\\.\", r"\b", r"\\.\b"),
        (r"\\?", "b", r"\\?/b"),
        (r"\\?/", "b", r"\\?/b"),
        (r"\\?/", r"\b", r"\\?/b"),
        (r"\\s\\", "b", r"\\s\\b"),
    ];
    for (lhs, rhs, want) in cases {
        let joined = p(lhs).join(&p(rhs));
        assert_eq!(joined.to_str(), Some(want), "{lhs:?} joined with {rhs:?}");
    }
}

/// For every small path whose anchor lacks its share or device name but has the separator after
/// the server (or `\\.`), dropping that separator changes no join.
///
/// Mutant: the join keeps the separator when the rhs is rooted, so `\\s\` joined with `\h` is
/// `\\s\\h`.
#[skuld::test]
fn an_unfinished_anchor_joins_the_same_with_or_without_its_separator() {
    let rhs_all = small_paths_up_to(3);
    for lhs in small_paths_up_to(5)
        .iter()
        .filter_map(|s| PathBuf::parse(s.as_str()).ok())
    {
        if parts(lhs.bytes()).unfinished() != Some(true) {
            continue;
        }
        let text = lhs.to_str().unwrap();
        let without = p(&text[..text.len() - 1]);
        assert_eq!(parts(without.bytes()).unfinished(), Some(false), "{lhs:?}");
        // An empty rhs adds nothing, so it leaves each spelling as it was.
        for rhs in rhs_all
            .iter()
            .filter(|s| !s.is_empty())
            .filter_map(|s| PathBuf::parse(s.as_str()).ok())
        {
            assert_eq!(lhs.join(&rhs), without.join(&rhs), "{lhs:?} joined with {rhs:?}");
        }
    }
}

/// Completing `\\?` never spells the verbatim prefix: the separator after it is written `/`, so
/// the path stays the device path Win32 reads `\\?` as.
///
/// Mutant: the `\` is kept, so `\\?` joined with `x` is stored as `\\?\x`.
#[skuld::test]
fn completing_an_unfinished_anchor_never_spells_verbatim() {
    for rhs in ["x", r"\x", "/x"] {
        let joined = p(r"\\?").join(&p(rhs));
        assert_eq!(joined.to_str(), Some(r"\\?/x"), "{rhs:?}");
        assert_eq!(joined.anchor(), Anchor::Device { name: os("x") }, "{rhs:?}");
    }
    let mut buf = p(r"\\?");
    buf.set_file_name(os("z"));
    assert_eq!(buf.to_str(), Some(r"\\?/z"));
}

/// For every pair of small paths, the joined path holds no verbatim prefix and parses back to
/// itself.
///
/// Mutant: the `\` after `\\?` is kept, so the join spells `\\?\`.
#[skuld::test]
fn join_reparses_to_itself() {
    let all = small_paths_up_to(4);
    let rhs_all = small_paths_up_to(3);
    for lhs in all.iter().filter_map(|s| PathBuf::parse(s.as_str()).ok()) {
        for rhs in rhs_all.iter().filter_map(|s| PathBuf::parse(s.as_str()).ok()) {
            let joined = lhs.join(&rhs);
            let ctx = format!("{lhs:?} joined with {rhs:?} is {joined:?}");
            assert!(!is_verbatim_spelling(joined.as_os_str()), "{ctx}");
            let again = PathBuf::parse(joined.as_os_str()).unwrap();
            assert_eq!(again.to_str(), joined.to_str(), "{ctx}");
        }
    }
}

/// For every pair of small paths, a drive, share or device rhs replaces the lhs, a rooted rhs
/// keeps the lhs's drive, share or device and takes the rhs's components, and a relative rhs adds
/// its components after the lhs's. Unfinished anchors (`\\s`, `\\.`) are the exception
/// [`join_completes_an_unfinished_anchor`] covers.
///
/// Mutant: no separator is added after a share, so `\\s\h` joined with `b` is `\\s\hb`.
#[skuld::test]
fn join_concatenates_components() {
    let mut lhs_all = small_paths_up_to(4);
    lhs_all.extend([r"\\s\h", r"\\s\h\", r"\\s\h\a", r"\\.\d", r"\\.\d\a", r"C:\a"].map(String::from));
    let rhs_all = small_paths_up_to(3);
    for lhs in lhs_all.iter().filter_map(|s| PathBuf::parse(s.as_str()).ok()) {
        if has_unfinished_anchor(&lhs) {
            continue;
        }
        for rhs in rhs_all.iter().filter_map(|s| PathBuf::parse(s.as_str()).ok()) {
            let joined = lhs.join(&rhs);
            let ctx = format!("{lhs:?} joined with {rhs:?} is {joined:?}");
            let keeps_lhs_prefix = matches!(
                lhs.anchor(),
                Anchor::Drive { .. } | Anchor::Unc { .. } | Anchor::Device { .. }
            );
            match rhs.anchor() {
                Anchor::None => {
                    let mut want: Vec<_> = lhs.components().collect();
                    want.extend(rhs.components());
                    assert_eq!(joined.components().collect::<Vec<_>>(), want, "{ctx}");
                    assert_eq!(joined.anchor(), lhs.anchor(), "{ctx}");
                }
                Anchor::Rooted if keeps_lhs_prefix => {
                    let want_anchor = match lhs.anchor() {
                        Anchor::Drive { drive, .. } => Anchor::Drive { drive, rooted: true },
                        other => other,
                    };
                    assert_eq!(joined.anchor(), want_anchor, "{ctx}");
                    assert_eq!(
                        joined.components().collect::<Vec<_>>(),
                        rhs.components().collect::<Vec<_>>(),
                        "{ctx}"
                    );
                }
                _ => assert_eq!(joined.to_str(), rhs.to_str(), "{ctx}"),
            }
        }
    }
}

/// `push` is an in-place `join`.
///
/// Mutant: `push` ignores a rooted rhs.
#[skuld::test]
fn push_is_join() {
    let mut buf = p(r"C:\a\");
    buf.push(&p("b"));
    assert_eq!(buf.to_str(), Some(r"C:\a\\b"));
    buf.push(&p(r"\c"));
    assert_eq!(buf.to_str(), Some(r"C:\c"));
}

// Lexical normalisation ===============================================================================================

/// `lexically_normal` collapses `.`, `name\..` and repeated separators, keeps names and the
/// anchor as written, and writes `\` between components.
///
/// Mutant: it returns the path unchanged.
#[skuld::test]
fn lexically_normal_collapses_only_dots_and_separators() {
    let cases = [
        (r"C:\a\b\..\c", r"C:\a\c"),
        (r"C:\..", r"C:\"),
        (r"C:\..\a", r"C:\a"),
        (r"\..\a", r"\a"),
        (r"\\s\h\..\a", r"\\s\h\a"),
        (r"\\.\d\..", r"\\.\d\"),
        (r"C:..\a", r"C:..\a"),
        (r"..\a", r"..\a"),
        (r"a\\.\b", r"a\b"),
        (r"a/b", r"a\b"),
        ("C:/a/./b", r"C:/a\b"),
        (r"a.\b..\...", r"a.\b..\..."),
        (r"a \b", r"a \b"),
        (r"a\", r"a\"),
        (r"a\..", "."),
        (r"C:a\..", "C:"),
        (r"\\s\h", r"\\s\h"),
        ("", ""),
    ];
    for (input, want) in cases {
        assert_eq!(p(input).lexically_normal().to_str(), Some(want), "input {input:?}");
    }
}

/// A first name that reads as a drive keeps a `.` before it, so the normal form stays relative.
///
/// Mutant: the `.` is dropped, so `.\a:` becomes the drive-relative `a:`.
#[skuld::test]
fn lexically_normal_keeps_a_drive_like_name_relative() {
    for (input, want) in [(r".\a:", r".\a:"), (r"x\..\a:b", r".\a:b"), (r".\.\a:\", r".\a:\")] {
        let normal = p(input).lexically_normal();
        assert_eq!(normal.to_str(), Some(want), "input {input:?}");
        assert_eq!(normal.anchor(), Anchor::None, "input {input:?}");
    }
}

/// For every small path, the normal form is a fixed point, has the same anchor, and holds no `.`,
/// no empty name but a last one after a name, and no `..` after a name or at a root.
///
/// Mutant: `..` at a drive's root is kept.
#[skuld::test]
fn lexically_normal_result_is_normal() {
    for input in small_paths() {
        let Ok(path) = PathBuf::parse(input.as_str()) else {
            continue;
        };
        let normal = path.lexically_normal();
        assert_eq!(normal.lexically_normal(), normal, "not idempotent on {input:?}");
        assert_eq!(normal.anchor(), path.anchor(), "anchor of {input:?}");
        if normal.to_str() == Some(".") {
            continue;
        }
        let all: Vec<_> = normal.components().collect();
        for (i, c) in all.iter().enumerate() {
            let last = i + 1 == all.len();
            match c {
                // A first name that reads as a drive keeps a `.` before it.
                Component::CurDir if i == 0 && all.get(1).is_some_and(reads_as_drive) => {}
                Component::CurDir => panic!("`.` in the normal form of {input:?}"),
                Component::Empty => assert!(
                    last && i > 0 && matches!(all[i - 1], Component::Normal(_)),
                    "empty name at {i} in the normal form of {input:?}"
                ),
                Component::ParentDir => assert!(
                    (i == 0 && !has_root_separator(&normal)) || (i > 0 && all[i - 1] == Component::ParentDir),
                    "`..` after a name or at a root in the normal form of {input:?}"
                ),
                Component::Normal(_) => {}
            }
        }
    }
}

// Parent and file name ================================================================================================

/// `parent` drops exactly the last component and the separator before it.
///
/// Mutant: std's `parent`, which skips a trailing separator and `.`.
#[skuld::test]
fn parent_drops_only_the_last_component() {
    let cases = [
        (r"C:\a\b", Some(r"C:\a")),
        (r"C:\a\b\", Some(r"C:\a\b")),
        (r"C:\a\.", Some(r"C:\a")),
        (r"C:\a", Some(r"C:\")),
        ("C:a", Some("C:")),
        ("a", Some("")),
        (r"\\s\h\x", Some(r"\\s\h\")),
        (r"\\.\d\x", Some(r"\\.\d\")),
        (r"C:\", None),
        ("C:", None),
        (r"\\s\h", None),
        (r"\\s\h\", None),
        ("", None),
    ];
    for (input, want) in cases {
        assert_eq!(p(input).parent().map(|x| x.to_str().unwrap()), want, "{input:?}");
    }
}

/// `parent` is the path without its last component, for every path that can spell that. A root
/// followed by a single `Empty` component spells only the root, so the parent of `C:\\x` is `C:\`.
///
/// Mutant: `parent` cuts at the offset within the components, dropping the anchor.
#[skuld::test]
fn parent_is_the_components_minus_the_last() {
    for input in small_paths() {
        let Ok(path) = PathBuf::parse(input.as_str()) else {
            continue;
        };
        let all: Vec<_> = path.components().collect();
        let Some(parent) = path.parent() else {
            assert!(all.is_empty(), "{input:?} has components and no parent");
            continue;
        };
        let got: Vec<_> = parent.components().collect();
        let mut want = all[..all.len() - 1].to_vec();
        if has_root_separator(&path) && want == [Component::Empty] {
            want.clear();
        }
        assert_eq!(got, want, "parent of {input:?}");
        assert_eq!(parent.anchor(), path.anchor(), "anchor of the parent of {input:?}");
        let (whole, part) = (path.to_str().unwrap(), parent.to_str().unwrap());
        assert!(whole.starts_with(part), "{input:?}");
    }
}

/// `pop` truncates to the parent and reports whether there was one.
///
/// Mutant: `pop` returns `true` at the root.
#[skuld::test]
fn pop_truncates_to_the_parent() {
    let mut buf = p(r"C:\a\b\");
    assert!(buf.pop());
    assert_eq!(buf.to_str(), Some(r"C:\a\b"));
    let mut root = p(r"C:\");
    assert!(!root.pop());
    assert_eq!(root.to_str(), Some(r"C:\"));
}

/// The file name is the last component when it is a name.
///
/// Mutant: std's `file_name`, which skips a trailing separator.
#[skuld::test]
fn file_name_is_a_trailing_normal_name() {
    assert_eq!(p(r"C:\a\b").file_name(), Some(os("b")));
    assert_eq!(p("C:b").file_name(), Some(os("b")));
    assert_eq!(p(r"a\").file_name(), None);
    assert_eq!(p(r"a\..").file_name(), None);
    assert_eq!(p(r"C:\").file_name(), None);
    assert_eq!(p(r"\\s\h").file_name(), None);
}

/// `set_file_name` replaces a trailing name and otherwise appends, keeping every other component.
///
/// Mutant: it always appends.
#[skuld::test]
fn set_file_name_replaces_only_a_name() {
    let cases = [
        (r"C:\a\b", r"C:\a\z"),
        ("C:b", "C:z"),
        (r"a\", r"a\\z"),
        (r"C:\", r"C:\z"),
        ("C:", "C:z"),
        (r"\\s\h", r"\\s\h\z"),
        (r"C:\\x", r"C:\\z"),
    ];
    for (input, want) in cases {
        let mut buf = p(input);
        buf.set_file_name(os("z"));
        assert_eq!(buf.to_str(), Some(want), "{input:?}");
    }
    // A name that reads as a drive stays a component: after a separator, or after a `.` where it
    // would start the path.
    for (input, want) in [("x", r".\a:"), ("", r".\a:"), ("C:x", "C:a:")] {
        let mut buf = p(input);
        buf.set_file_name(os("a:"));
        assert_eq!(buf.to_str(), Some(want), "{input:?}");
    }
    let mut buf = p(r"C:\a\");
    buf.set_file_name(os("D:"));
    assert_eq!(buf.components().next_back(), Some(n("D:")));
}

/// `set_file_name` changes the last component and nothing else, for every small path.
///
/// Mutant: `set_file_name` is `pop` then `push`, which turns `C:\\x` into `C:\z`.
#[skuld::test]
fn set_file_name_changes_only_the_last_component() {
    for input in small_paths() {
        let Ok(path) = PathBuf::parse(input.as_str()) else {
            continue;
        };
        if has_unfinished_anchor(&path) {
            continue;
        }
        let mut buf = path.clone();
        buf.set_file_name(os("z"));
        let mut want: Vec<_> = path.components().collect();
        if path.file_name().is_some() {
            want.pop();
        }
        want.push(n("z"));
        assert_eq!(buf.components().collect::<Vec<_>>(), want, "set_file_name on {input:?}");
        assert_eq!(buf.anchor(), path.anchor(), "anchor of {input:?}");
    }
}

/// A name holding a separator is not one component: a contract, asserted in debug.
///
/// Mutant: the assertion removed, so `a\b` with `x/y` becomes `a\x/y`.
#[skuld::test]
fn set_file_name_refuses_a_path_in_debug() {
    for name in ["x/y", r"x\y"] {
        let caught = std::panic::catch_unwind(|| p(r"a\b").set_file_name(os(name)));
        assert_eq!(caught.is_err(), cfg!(debug_assertions), "{name:?}");
    }
}

// Strings and encodings ===============================================================================================

/// UTF-16 round-trips through a path, lone surrogates and pairs included.
///
/// Mutant: a lone surrogate becomes U+FFFD on the way in.
#[skuld::test]
fn wide_round_trips() {
    for units in [
        c_root_then(&[0xD800]),
        c_root_then(&[0xDC00, u16::from(b'a')]),
        c_root_then(&[0xD83D, 0xDE00]),
        c_root_then(&[0xDE00, 0xD83D]),
        "é".encode_utf16().collect(),
        vec![],
    ] {
        let path = wide(&units);
        assert_eq!(path.to_wide(), units, "{units:X?}");
        assert_eq!(OsString::from_wide(&units).to_wide(), units, "{units:X?}");
    }
}

/// A surrogate pair from UTF-16 is one character, so the path is valid Unicode.
///
/// Mutant: each half is stored on its own, so `to_str` fails.
#[skuld::test]
fn a_surrogate_pair_is_one_character() {
    assert_eq!(wide(&c_root_then(&[0xD83D, 0xDE00])).to_str(), Some("C:\\\u{1F600}"));
}

/// The native bytes are the UTF-16 units, little-endian.
///
/// Mutant: they are the stored WTF-8.
#[skuld::test]
fn native_bytes_are_utf16le() {
    let path = wide(&[u16::from(b'a'), 0xD800]);
    assert_eq!(path.to_native_bytes(), Cow::<[u8]>::Owned(vec![b'a', 0, 0x00, 0xD8]));
}

/// `to_str` is exact or nothing; `to_string_lossy` replaces each lone surrogate with one U+FFFD.
///
/// Mutant: the lossy form decodes the stored WTF-8 as UTF-8, giving three U+FFFD per surrogate.
#[skuld::test]
fn to_str_is_exact_or_nothing() {
    assert_eq!(p(r"C:\é").to_str(), Some(r"C:\é"));
    let lone = wide(&c_root_then(&[0xD800, u16::from(b'x'), 0xDFFF]));
    assert_eq!(lone.to_str(), None);
    assert_eq!(lone.to_string_lossy(), "C:\\\u{FFFD}x\u{FFFD}");
    assert_eq!(lone.as_os_str().to_str(), None);
}

/// `Debug` is quoted and escaped, and shows a lone surrogate as an escape no real character
/// prints as.
///
/// Mutant: `Debug` is the lossy string.
#[skuld::test]
fn debug_is_faithful_for_a_lone_surrogate() {
    assert_eq!(format!("{:?}", wide(&c_root_then(&[0xD800]))), r#""C:\\\u{D800}""#);
    assert_eq!(format!("{:?}", p(r"C:\u{D800}")), r#""C:\\u{D800}""#);
    assert_eq!(format!("{:?}", p("a\"b\n")), r#""a\"b\n""#);
    assert_eq!(format!("{:?}", os("é")), r#""é""#);
}

/// `display` replaces each lone surrogate with one U+FFFD.
///
/// Mutant: `display` writes the `Debug` form.
#[skuld::test]
fn display_is_lossy() {
    let path = wide(&c_root_then(&[0xD800, 0xDBFF]));
    assert_eq!(path.display().to_string(), "C:\\\u{FFFD}\u{FFFD}");
    assert_eq!(p(r"C:\é b").display().to_string(), r"C:\é b");
}

/// `Debug` of `display()` is `Debug` of the path, so a lone surrogate stays visible in logs.
///
/// Mutant: `Debug` of `display()` debug-prints the lossy string.
#[skuld::test]
fn display_debug_is_the_path_debug() {
    for path in [wide(&c_root_then(&[0xD800])), p("a\"b"), p("")] {
        assert_eq!(format!("{:?}", path.display()), format!("{path:?}"));
    }
}

/// The `std` conversions keep every unit, lone surrogates included.
///
/// Mutant: `to_std_path` goes through the lossy string.
#[cfg(windows)]
#[skuld::test]
fn std_conversions_round_trip() {
    use std::os::windows::ffi::OsStrExt;
    let units = c_root_then(&[0xD800, u16::from(b'x')]);
    let path = wide(&units);
    let std_path = path.to_std_path();
    assert_eq!(std_path.as_os_str().encode_wide().collect::<Vec<_>>(), units);
    assert_eq!(PathBuf::from_std_path(&std_path).unwrap(), path);
    assert_eq!(
        PathBuf::from_std_path(std::path::Path::new(r"\\?\C:\x")).unwrap(),
        p(r"C:\x")
    );
    assert_eq!(path.as_os_str().to_std_os_string(), std_path.into_os_string());
    let std_os = std::ffi::OsString::from("é");
    assert_eq!(OsString::from(std_os.as_os_str()).to_str(), Some("é"));
}

/// Whether `c` is a name that would read as a drive at the start of a path.
fn reads_as_drive(c: &Component<'_, OsStr>) -> bool {
    matches!(c, Component::Normal(name) if p(name.to_str().unwrap()).drive().is_some())
}

/// Every path over `{a, ., :, ?, \, /}` of up to five units.
fn small_paths() -> Vec<String> {
    small_paths_up_to(5)
}

/// Every path over `{a, ., :, ?, \, /}` of up to `max_len` units.
fn small_paths_up_to(max_len: usize) -> Vec<String> {
    let mut all = vec![String::new()];
    let mut level = vec![String::new()];
    for _ in 0..max_len {
        level = level
            .iter()
            .flat_map(|s| ["a", ".", ":", "?", "\\", "/"].map(|c| format!("{s}{c}")))
            .collect();
        all.extend(level.iter().cloned());
    }
    all
}

/// The length of the anchor's text without its root separator.
fn head_len(path: &Path) -> usize {
    parts(path.bytes()).head
}

/// Whether a root separator ends the anchor.
fn has_root_separator(path: &Path) -> bool {
    parts(path.bytes()).root
}

/// Whether the anchor would take a following component as its own: a UNC path with no share or a
/// device path with no name, and no root separator after it.
fn has_unfinished_anchor(path: &Path) -> bool {
    parts(path.bytes()).unfinished().is_some()
}
