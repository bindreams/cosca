use std::ffi::OsStr;

use super::{append, join};

fn s(o: std::ffi::OsString) -> String {
    o.into_string().unwrap()
}

/// A verbatim base is normalised as std's `PathBuf::push` does it: `.` dropped, `..` popped but
/// never into the prefix, `/` a separator. Win32 passes a `\\?\` path through unparsed, so a literal
/// `.`, `..` or `/` left in it names nothing.
#[test]
fn a_verbatim_base_is_normalised() {
    for (base, rest, want) in [
        (r"\\?\C:\work", "./t.exe", r"\\?\C:\work\t.exe"),
        (r"\\?\C:\work", "sub/../t.exe", r"\\?\C:\work\t.exe"),
        (r"\\?\C:\work", r"..\..\..\t.exe", r"\\?\C:\t.exe"),
        (r"\\?\C:\", "t.exe", r"\\?\C:\t.exe"),
        (r"\\?\C:\work\", "t.exe", r"\\?\C:\work\t.exe"),
        (r"\\?\UNC\srv\shr\d", r"..\..\t.exe", r"\\?\UNC\srv\shr\t.exe"),
        // The marker is matched case-insensitively, as NT matches it, where std matches only `UNC`.
        (r"\\?\unc\srv\shr\d", r"..\..\t.exe", r"\\?\unc\srv\shr\t.exe"),
        // The base is rebuilt from its components too: empty ones dropped.
        (r"\\?\C:\bin\\", "t.exe", r"\\?\C:\bin\t.exe"),
        (r"\\?\C:\bin\\x", "t.exe", r"\\?\C:\bin\x\t.exe"),
        (r"\\?\C:", "t.exe", r"\\?\C:\t.exe"),
        // `..` pops only a normal component: a base's own `.` or `..` stays.
        (r"\\?\C:\a\.\b", r"..\t.exe", r"\\?\C:\a\.\t.exe"),
        (r"\\?\C:\a\..", r"..\t.exe", r"\\?\C:\a\..\t.exe"),
        // After a verbatim prefix only `\` separates, so `a/b` is one component.
        (r"\\?\C:\a/b", r"..\t.exe", r"\\?\C:\t.exe"),
        // The prefix's own components split on `\` alone too, as std parses them: server `srv/shr`,
        // share `d`. A drive is the exception: std takes a letter and `:` followed by either
        // separator as drive C, and the `/` after it as the root.
        (r"\\?\UNC\srv/shr\d", r"..\t.exe", r"\\?\UNC\srv/shr\d\t.exe"),
        (r"\\?\C:/x\y", r"..\t.exe", r"\\?\C:\x\t.exe"),
        (r"\\?\C:/x\y", "t.exe", r"\\?\C:\x\y\t.exe"),
        // Only a letter makes a drive there, so `1:/x` is one verbatim namespace.
        (r"\\?\1:/x\y", r"..\t.exe", r"\\?\1:/x\t.exe"),
    ] {
        assert_eq!(
            s(append(OsStr::new(base), OsStr::new(rest), "\\")),
            want,
            "{base:?} + {rest:?}"
        );
    }
}

/// Any other base takes `rest` as units after one separator, none after a bare drive.
#[test]
fn any_other_base_is_appended_as_units() {
    for (base, rest, want) in [
        (r"1:\work", "tool.exe", r"1:\work\tool.exe"),
        (r"1:\work\", "tool.exe", r"1:\work\tool.exe"),
        (r"C:\cwd", r"D:\evil.exe", r"C:\cwd\D:\evil.exe"),
        ("C:", "tool.exe", "C:tool.exe"),
        (r"C:\cwd", "", r"C:\cwd"),
    ] {
        assert_eq!(
            s(append(OsStr::new(base), OsStr::new(rest), "\\")),
            want,
            "{base:?} + {rest:?}"
        );
    }
}

/// A name joins by its type: Rooted takes the base's drive or share, Relative is appended, and
/// anything fully qualified stands alone.
#[test]
fn a_name_joins_by_its_type() {
    for (base, name, want) in [
        (r"1:\work", r"\tool.exe", r"1:\tool.exe"),
        (r"\\srv\shr\d", r"\t.exe", r"\\srv\shr\t.exe"),
        (r"\\?\C:\work", "/t.exe", r"\\?\C:\t.exe"),
        (r"\\?\C:\work", r"\sub\..\t.exe", r"\\?\C:\t.exe"),
        (r"1:\work", "sub\\t.exe", r"1:\work\sub\t.exe"),
        (r"C:\work", r"D:\t.exe", r"D:\t.exe"),
    ] {
        assert_eq!(
            s(join(OsStr::new(base), OsStr::new(name), "\\")),
            want,
            "{base:?} + {name:?}"
        );
    }
}

/// Held to std itself where std parses Windows paths: `PathBuf::push` on a verbatim base is the
/// rule `append` claims to follow.
#[cfg(windows)]
#[test]
fn a_verbatim_append_matches_std() {
    for base in [
        r"\\?\C:\work",
        r"\\?\C:\bin\\",
        r"\\?\C:",
        r"\\?\C:\a\.\b",
        r"\\?\C:\a\..",
        r"\\?\C:\a/b",
        r"\\?\UNC\srv\shr\d",
        r"\\?\UNC\srv/shr\d",
        r"\\?\C:/x\y",
        r"\\?\c:/x",
        r"\\?\1:/x\y",
        r"\\?\C:x\y",
    ] {
        for rest in [
            "t.exe",
            "./t.exe",
            "sub/../t.exe",
            r"..\..\..\t.exe",
            r"\t.exe",
            "/t.exe",
            r".\a\\b",
        ] {
            let mut want = std::path::PathBuf::from(base);
            want.push(rest);
            assert_eq!(
                append(OsStr::new(base), OsStr::new(rest), "\\"),
                want.into_os_string(),
                "{base:?} + {rest:?}"
            );
        }
    }
}
