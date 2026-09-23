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
