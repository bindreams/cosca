use std::io::ErrorKind;

use crate::fs::Filesystem;
use crate::windows::{FakeFilesystem, PathBuf};

fn w(s: &str) -> PathBuf {
    PathBuf::parse(s).unwrap_or_else(|e| panic!("{s:?} does not parse: {e}"))
}

fn kind<T: std::fmt::Debug>(r: std::io::Result<T>) -> ErrorKind {
    r.expect_err("expected an error").kind()
}

/// Whether building the state panics.
fn panics(build: impl FnOnce() -> FakeFilesystem) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(build)).is_err()
}

/// Every question about `q` fails with `want`.
#[track_caller]
fn assert_refused(fs: &FakeFilesystem, q: &str, want: ErrorKind) {
    let p = w(q);
    assert_eq!(kind(fs.is_file(&p)), want, "is_file {q}");
    assert_eq!(kind(fs.is_dir(&p)), want, "is_dir {q}");
    assert_eq!(kind(fs.canonical(&p)), want, "canonical {q}");
    assert_eq!(kind(fs.same_file(&p, &p)), want, "same_file {q}");
}

/// `same_file` of `q` and the existing `other` fails with `want`, in both orders.
#[track_caller]
fn assert_refused_beside(fs: &FakeFilesystem, other: &str, q: &str, want: ErrorKind) {
    assert_eq!(kind(fs.same_file(&w(q), &w(other))), want, "same_file {q} {other}");
    assert_eq!(kind(fs.same_file(&w(other), &w(q))), want, "same_file {other} {q}");
}

/// Every question about `q` says nothing is there.
#[track_caller]
fn assert_absent(fs: &FakeFilesystem, q: &str) {
    let p = w(q);
    assert!(!fs.is_file(&p).unwrap(), "is_file {q}");
    assert!(!fs.is_dir(&p).unwrap(), "is_dir {q}");
    assert_eq!(kind(fs.canonical(&p)), ErrorKind::NotFound, "canonical {q}");
}

/// A path that `to_wide` cannot spell is `InvalidInput` from every question, as on the host, which
/// reads each name as written. Measured on build 26100: `tool.`, `tool `, `C:tool.` and `\tool.` are
/// each `ConversionError { TrailingDotOrSpace }`. A fully qualified path has a string that keeps its
/// trailing dots and spaces, so there `tool.` is an ordinary name, apart from `tool`.
///
/// Mutants: a refusal of the NUL and the empty path only; one that refuses a fully qualified `tool.`;
/// one that reads `tool.` as `tool`.
#[skuld::test]
fn a_path_that_has_no_win32_string_is_invalid_input() {
    let fs = FakeFilesystem::new()
        .with_file(&w(r"C:\x\tool."))
        .with_file(&w(r"C:\x\tool"))
        .with_file(&w("tool"))
        .with_file(&w(r"C:\x\a.\b"));
    for q in [
        "tool.", "tool ", "C:tool.", r"\tool.", r"a\b.", "tool..", r"a.\b", r"C:a.\b",
    ] {
        assert_refused(&fs, q, ErrorKind::InvalidInput);
        assert_refused_beside(&fs, r"C:\x\tool", q, ErrorKind::InvalidInput);
    }
    // Fully qualified, the name is kept as written.
    assert!(fs.is_file(&w(r"C:\x\tool.")).unwrap());
    assert!(fs.is_file(&w(r"C:\x\tool")).unwrap());
    assert!(!fs.is_file(&w(r"C:\x\tool..")).unwrap());
    assert!(!fs.is_file(&w(r"C:\x\tool ")).unwrap());
    assert!(fs.is_file(&w(r"C:\x\a.\b")).unwrap());
    assert!(fs.is_file(&w("tool")).unwrap());
    let fs = FakeFilesystem::new().with_file(&w(r"C:\x\tool"));
    assert!(!fs.is_file(&w(r"C:\x\tool.")).unwrap());
}

/// `\\.\Global\` and `\\.\GLOBALROOT\??\` before a drive or UNC path name that path, in any case and
/// repeated, as on the host (measured on build 26100: each gives the answers of `C:\Windows`,
/// canonical `C:\Windows`). Bare, `\\.\Global` and `\\.\GLOBALROOT\??` are a device the host refuses
/// (error 6, `Other`); with a separator and nothing after, they are absent.
///
/// Mutants: a lookup that keys these apart from the path; one that strips the prefix once, or only in
/// one case; one that keeps the bare prefix as an entry.
#[skuld::test]
fn a_global_device_path_is_the_path_it_names() {
    let fs = FakeFilesystem::new()
        .with_dir(&w(r"C:\Windows"))
        .with_dir(&w(r"\\srv\share\d"));
    for q in [
        r"\\.\Global\C:\Windows",
        r"\\.\global\C:\Windows",
        r"\\.\GLOBAL\C:\Windows",
        r"\\.\Global\Global\C:\Windows",
        r"\\.\GLOBALROOT\??\C:\Windows",
        r"\\.\globalroot\??\C:\Windows",
        r"\\.\GLOBALROOT\??\Global\C:\Windows",
        r"\\.\Global\\C:\Windows",
        "//./Global/C:/Windows",
        r"\\.\Global\C:\Windows\",
        r"\\.\Global\C:\Windows\.",
        r"\\?\GLOBALROOT\??\C:\Windows",
    ] {
        assert!(fs.is_dir(&w(q)).unwrap(), "{q}");
        assert!(!fs.is_file(&w(q)).unwrap(), "{q}");
        assert_eq!(fs.canonical(&w(q)).unwrap(), w(r"C:\Windows"), "{q}");
        assert!(fs.same_file(&w(q), &w(r"C:\Windows")).unwrap(), "{q}");
    }
    assert!(fs.is_dir(&w(r"\\.\Global\C:\")).unwrap());
    assert_eq!(fs.canonical(&w(r"\\.\GLOBALROOT\??\C:\")).unwrap(), w(r"C:\"));
    for q in [
        r"\\.\Global\UNC\srv\share\d",
        r"\\.\Global\unc\srv\share\d",
        r"\\.\GLOBALROOT\??\UNC\srv\share\d",
        r"\\.\GLOBALROOT\??\unc\srv\share\d",
    ] {
        assert!(fs.is_dir(&w(q)).unwrap(), "{q}");
        assert_eq!(fs.canonical(&w(q)).unwrap(), w(r"\\srv\share\d"), "{q}");
    }
    // Case is exact for the name after the prefix, as for any path.
    assert!(!fs.is_dir(&w(r"\\.\Global\c:\Windows")).unwrap());
    // Stated through the prefix, it is the entry of the path.
    let stated = FakeFilesystem::new().with_dir(&w(r"\\.\Global\C:\x"));
    assert!(stated.is_dir(&w(r"C:\x")).unwrap());
    // The prefix alone.
    for bare in [r"\\.\Global", r"\\.\GLOBALROOT\??"] {
        assert_refused(&fs, bare, ErrorKind::Other);
    }
    for empty in [r"\\.\Global\", r"\\.\GLOBALROOT\??\"] {
        assert_absent(&fs, empty);
    }
}

/// The default data stream and the directory index of a name are the name, in any case: `f::$DATA` is
/// the file `f`, `d:$I30:$INDEX_ALLOCATION` and `d::$INDEX_ALLOCATION` are the directory `d` (the root
/// too), each absent where the kind is wrong (a `$DATA` of a directory is `PermissionDenied`, an index
/// of a file is absent). Measured on build 26100 on NTFS.
///
/// Mutants: a fake that keys `f::$DATA` apart from `f`; one that answers a directory's `::$DATA`;
/// one that reads an index of a file as the file; one that is case-sensitive in the stream name.
#[skuld::test]
fn the_default_data_stream_and_the_directory_index_are_the_name() {
    let fs = FakeFilesystem::new()
        .with_file(&w(r"C:\a\f"))
        .with_dir(&w(r"C:\a\d"))
        .with_file(&w(r"C:\a\d\g"));
    for q in [
        r"C:\a\f::$DATA",
        r"C:\a\f::$data",
        r"C:\a\f::$Data",
        r"C:\a\f::$DATA\.",
        r"C:\a\d\..\f::$DATA",
    ] {
        assert!(fs.is_file(&w(q)).unwrap(), "{q}");
        assert!(!fs.is_dir(&w(q)).unwrap(), "{q}");
        assert_eq!(fs.canonical(&w(q)).unwrap(), w(r"C:\a\f"), "{q}");
        assert!(fs.same_file(&w(q), &w(r"C:\a\f")).unwrap(), "{q}");
    }
    // A trailing separator wants a directory.
    for q in [
        r"C:\a\f::$DATA\",
        r"C:\a\missing::$DATA",
        r"C:\a\missing:$I30:$INDEX_ALLOCATION",
    ] {
        assert_absent(&fs, q);
    }
    // A directory has no default data stream to open, and a file no index.
    for q in [r"C:\a\d::$DATA", r"C:\::$DATA"] {
        assert_refused(&fs, q, ErrorKind::PermissionDenied);
    }
    for q in [
        r"C:\a\f:$I30:$INDEX_ALLOCATION",
        r"C:\a\f::$INDEX_ALLOCATION",
        r"C:\a\d::$DATA\g",
        r"C:\a\f::$DATA\x",
    ] {
        assert_absent(&fs, q);
    }
    for q in [
        r"C:\a\d:$I30:$INDEX_ALLOCATION",
        r"C:\a\d::$INDEX_ALLOCATION",
        r"C:\a\d:$i30:$index_allocation",
        r"C:\a\d:$I30:$INDEX_ALLOCATION\",
        r"C:\a\d:$I30:$INDEX_ALLOCATION\.",
    ] {
        assert!(fs.is_dir(&w(q)).unwrap(), "{q}");
        assert!(!fs.is_file(&w(q)).unwrap(), "{q}");
        assert_eq!(fs.canonical(&w(q)).unwrap(), w(r"C:\a\d"), "{q}");
    }
    assert!(fs.is_file(&w(r"C:\a\d:$I30:$INDEX_ALLOCATION\g")).unwrap());
    assert_eq!(fs.canonical(&w(r"C:\:$I30:$INDEX_ALLOCATION")).unwrap(), w(r"C:\"));
    // Stated through the alias, it is the entry of the name.
    let stated = FakeFilesystem::new().with_file(&w(r"C:\a\h::$DATA"));
    assert!(stated.is_file(&w(r"C:\a\h")).unwrap());
    // A stream that is neither (`f:x`, `f:$DATA`) is not modelled: refused, not absent.
    for q in [
        r"C:\a\f:x",
        r"C:\a\f:x:$DATA",
        r"C:\a\f:$DATA",
        r"C:\a\f:$I30",
        r"C:\a\d:y",
        r"C:\a\missing:x",
    ] {
        assert_refused(&fs, q, ErrorKind::InvalidInput);
    }
    // A stream of a name that is not the last is no directory: absent.
    assert_absent(&fs, r"C:\a\f:x\y");
}

/// A name that a directory-only alias contradicts is refused by the builder, as a file with children
/// is.
///
/// Mutants: a builder that keys `d::$INDEX_ALLOCATION` as a file; one that accepts a directory at a
/// `::$DATA` name.
#[skuld::test]
fn a_stream_alias_that_contradicts_the_entry_is_refused() {
    assert!(panics(
        || FakeFilesystem::new().with_file(&w(r"C:\a\d:$I30:$INDEX_ALLOCATION"))
    ));
    assert!(panics(
        || FakeFilesystem::new().with_file(&w(r"C:\a\d::$INDEX_ALLOCATION"))
    ));
    assert!(panics(|| FakeFilesystem::new().with_dir(&w(r"C:\a\f::$DATA"))));
    assert!(panics(
        || FakeFilesystem::new().with_unreadable_dir(&w(r"C:\a\f::$DATA"), ErrorKind::PermissionDenied)
    ));
    let _ = FakeFilesystem::new().with_dir(&w(r"C:\a\d::$INDEX_ALLOCATION"));
    let _ = FakeFilesystem::new().with_file(&w(r"C:\a\f::$DATA"));
}

/// A volume's device, `\\.\C:` (also `//?/C:`, `\\.\Global\C:`, `\\.\GLOBALROOT\??\C:` and after `.`
/// is dropped, `\\.\C:\.`), is a device the host refuses with a handle's error (code 1, `Other`) for
/// a drive that exists, and absent for one that does not (`\\.\Z:`). The fake has the drive if `C:\`
/// is stated or implied. `\\.\C:\` is the root directory.
///
/// Mutants: a fake that keeps the volume as an ordinary entry; one that refuses `\\.\Z:`; one that
/// reads `\\.\C:` as `C:\`.
#[skuld::test]
fn a_volume_device_is_refused_where_the_drive_exists() {
    let fs = FakeFilesystem::new().with_dir(&w(r"C:\Windows"));
    for q in [
        r"\\.\C:",
        r"\\.\C:\.",
        r"\\.\C:\x\..",
        "//?/C:",
        "//?/C:/.",
        r"\\.\Global\C:",
        r"\\.\GLOBALROOT\??\C:",
    ] {
        assert_refused(&fs, q, ErrorKind::Other);
    }
    for q in [r"\\.\Z:", r"\\.\Z:\.", "//?/Z:", r"\\.\Global\Z:", r"\\.\c:"] {
        assert_absent(&fs, q);
    }
    for q in [r"\\.\C:\", "//?/C:/", r"\\.\C:\\"] {
        assert!(fs.is_dir(&w(q)).unwrap(), "{q}");
        assert_eq!(fs.canonical(&w(q)).unwrap(), w(r"C:\"), "{q}");
    }
    // The builder has no volume to put entries in.
    assert!(panics(|| FakeFilesystem::new().with_dir(&w(r"\\.\C:"))));
    assert!(panics(
        || FakeFilesystem::new().with_error(&w(r"\\.\C:"), ErrorKind::Other)
    ));
}

/// A DOS device name directly named under a UNC share is `PermissionDenied`: measured on build 26100
/// against `\\localhost\C$` and `\\localhost\ADMIN$`, for the last name of the path at any depth
/// (`nul`, `NUL`, `aux`, `con`, `prn`, `clock$`, `com1` to `com9`, `lpt1` to `lpt9`), also with a
/// trailing separator, `\.`, a `..` that leads back to it, or `::$DATA`. A name with an extension,
/// a dot or a space after it (`nul.txt`, `nul.`, `nul `), a name that is not on that list (`com0`,
/// `conin$`, `keybd$`, `com¹`), a device name that is not the last name, and a device name on a drive
/// are ordinary.
///
/// Mutants: a refusal at the share root only; one for `nul` alone; one that also refuses `nul.txt`;
/// one that refuses `C:\nul`.
#[skuld::test]
fn a_device_name_under_a_unc_share_is_permission_denied() {
    let fs = FakeFilesystem::new()
        .with_dir(&w(r"\\srv\share\d"))
        .with_dir(&w(r"C:\d"));
    let mut names: Vec<String> = ["nul", "NUL", "Nul", "aux", "con", "prn", "clock$"]
        .map(String::from)
        .into();
    for i in 1..=9 {
        names.push(format!("com{i}"));
        names.push(format!("lpt{i}"));
    }
    for name in names {
        for q in [
            format!(r"\\srv\share\{name}"),
            format!(r"\\srv\share\d\{name}"),
            format!(r"\\srv\share\d\{name}\"),
            format!(r"\\srv\share\d\{name}\."),
            format!(r"\\srv\share\d\..\{name}"),
            format!(r"\\srv\share\d\{name}::$DATA"),
            format!("//srv/share/d/{name}"),
        ] {
            assert_refused(&fs, &q, ErrorKind::PermissionDenied);
        }
    }
    for q in [
        r"\\srv\share\nul.txt",
        r"\\srv\share\nul.",
        r"\\srv\share\nul ",
        r"\\srv\share\d\com0",
        r"\\srv\share\d\conin$",
        r"\\srv\share\d\keybd$",
        "\\\\srv\\share\\d\\com\u{b9}",
        r"\\srv\share\nul\x",
        r"\\srv\share\d\nul\x",
        r"C:\nul",
        r"C:\d\nul",
    ] {
        assert_absent(&fs, q);
    }
    // Stated, it is still refused, as a NUL is.
    let stated = FakeFilesystem::new().with_file(&w(r"\\srv\share\nul"));
    assert_refused(&stated, r"\\srv\share\nul", ErrorKind::PermissionDenied);
}

/// A drive-relative `C:`, the current directory of that drive, is a directory exactly where the drive
/// is (`C:\` is stated or implied), and so is `C:.` or `C:..`. The current directory `.` and its
/// ancestors, and the root of the current drive `\`, are directories on any host. Measured on build
/// 26100: `C:`, `C:.`, `.`, `..`, `a\..` and `\` are directories; `Q:` and `Q:.` are absent.
///
/// Mutants: a fake that finds `.` absent; one that finds `D:` present with no `D:\`; one that finds
/// `a\..` present where `a` is not stated.
#[skuld::test]
fn the_current_directories_exist() {
    let fs = FakeFilesystem::new()
        .with_dir(&w(r"C:\Windows"))
        .with_dir(&w(r"bin\sub"));
    for q in [
        ".",
        r".\",
        "./",
        r".\.",
        "..",
        r"..\..",
        r"..\.\..",
        r"bin\..",
        r"bin\sub\..\..",
        r"\",
        "/",
        r"\.",
        r"\..",
        "C:",
        "C:.",
        r"C:.\",
        "C:..",
        r"C:..\..",
        r"C:bin\..",
        r"missing\..",
        r"C:missing\..",
    ] {
        assert!(fs.is_dir(&w(q)).unwrap(), "{q}");
        assert!(!fs.is_file(&w(q)).unwrap(), "{q}");
        assert!(fs.same_file(&w(q), &w(q)).unwrap(), "{q}");
    }
    // Win32 resolves `..` as text, so `missing\..` is the current directory. Below it, or on a drive
    // with no `\`, nothing is there unless stated.
    for q in [
        "D:",
        "D:.",
        r"D:\",
        "D:..",
        r"..\missing",
        r"\x",
        r"C:x",
        r"bin\missing",
    ] {
        assert_absent(&fs, q);
    }
    assert!(fs.is_dir(&w("bin")).unwrap());
}

/// What a relative path names depends on the current directory, the current drive or the drive's
/// current directory, which the fake has no value for. So `canonical` of one that exists (which the
/// host answers with an absolute path) is refused, and so is `same_file` of two paths that might be
/// one file through those: a relative and a fully qualified one, two relative paths that are
/// relative to different things (`a`, `\a`, `C:a`), and a path that starts with `..` and another.
/// A path that is absent is `NotFound` whatever they are, and a stated link says what `canonical` is.
///
/// Mutants: a `canonical` that returns the relative spelling; a `same_file` that says `false` for a
/// relative and a fully qualified path; one that refuses two names relative to the same thing.
#[skuld::test]
fn a_relative_path_has_no_canonical_form_and_no_identity_against_another_kind() {
    let fs = FakeFilesystem::new()
        .with_file(&w(r"bin\tool.exe"))
        .with_file(&w(r"bin\other.exe"))
        .with_file(&w(r"\rooted\a.exe"))
        .with_file(&w(r"\rooted\b.exe"))
        .with_file(&w(r"C:rel\a.exe"))
        .with_file(&w(r"C:rel\b.exe"))
        .with_file(&w(r"C:\abs\tool.exe"))
        .with_file(&w(r"..\up.exe"))
        .with_file(&w(r"C:\abs\other.exe"))
        .with_canonical(&w(r"bin\other.exe"), &w(r"C:\abs\other.exe"));

    for exists in [
        r"bin\tool.exe",
        "bin",
        ".",
        "..",
        r".\bin\..\bin",
        r"..\up.exe",
        r"\rooted\a.exe",
        "C:",
        r"C:rel\a.exe",
        r"\",
    ] {
        assert_refused_canonical(&fs, exists);
    }
    assert_eq!(kind(fs.canonical(&w(r"bin\missing.exe"))), ErrorKind::NotFound);
    assert_eq!(kind(fs.canonical(&w(r"\rooted\missing"))), ErrorKind::NotFound);
    assert_eq!(fs.canonical(&w(r"bin\other.exe")).unwrap(), w(r"C:\abs\other.exe"));
    // The empty path has no string, as ever.
    assert_eq!(kind(fs.canonical(&w(""))), ErrorKind::InvalidInput);

    // The same spelling, and two names relative to the same thing, are decided.
    assert!(fs.same_file(&w(r"bin\tool.exe"), &w(r".\bin\tool.exe")).unwrap());
    assert!(!fs.same_file(&w(r"bin\tool.exe"), &w(r"bin\")).unwrap());
    assert!(!fs.same_file(&w(r"\rooted\a.exe"), &w(r"\rooted\b.exe")).unwrap());
    assert!(!fs.same_file(&w(r"C:rel\a.exe"), &w(r"C:rel\b.exe")).unwrap());
    assert!(fs.same_file(&w(r"..\up.exe"), &w(r"..\up.exe")).unwrap());
    // Anything else mixes what the fake cannot tell apart.
    for (a, b) in [
        (r"bin\tool.exe", r"C:\abs\tool.exe"),
        (r"C:\abs\tool.exe", r"bin\tool.exe"),
        (r"bin\tool.exe", r"\rooted\a.exe"),
        (r"\rooted\a.exe", r"C:rel\a.exe"),
        (r"C:rel\a.exe", r"C:\abs\tool.exe"),
        (r"..\up.exe", r"bin\tool.exe"),
        (".", ".."),
        (r"C:", r"C:\Windows"),
    ] {
        let fs = fs.clone().with_dir(&w(r"C:\Windows"));
        assert_eq!(kind(fs.same_file(&w(a), &w(b))), ErrorKind::InvalidInput, "{a} {b}");
    }
    // Absent is `NotFound` before anything else, and a link resolves a relative path.
    assert_eq!(
        kind(fs.same_file(&w(r"bin\missing"), &w(r"C:\abs\tool.exe"))),
        ErrorKind::NotFound
    );
    assert!(fs.same_file(&w(r"bin\other.exe"), &w(r"C:\abs\other.exe")).unwrap());
    assert!(!fs.same_file(&w(r"bin\other.exe"), &w(r"C:\abs\tool.exe")).unwrap());
}

#[track_caller]
fn assert_refused_canonical(fs: &FakeFilesystem, q: &str) {
    assert_eq!(kind(fs.canonical(&w(q))), ErrorKind::InvalidInput, "canonical {q}");
}

/// A file cannot be stated where only a directory is: a root, a share root, a drive's current
/// directory, `.`, a final `..` and what these resolve to (`C:\a\..` is the root), a trailing
/// separator. Win32 drops a trailing `\.`, so `C:\a\.` is the file `C:\a`.
///
/// Mutants: a builder that checks only the spelling's end; one that checks only the drive root.
#[skuld::test]
fn a_file_at_a_name_only_a_directory_has_is_refused() {
    for name in [
        r"C:\",
        r"C:\a\..",
        "C:",
        "C:.",
        r"C:a\..",
        r"\\srv\share",
        r"\\srv\share\",
        r"\\srv\share\a\..",
        ".",
        "..",
        r"a\..",
        r"\",
        r"C:\a\",
        r"\\.\C:\",
        r"\\.\Global\C:\",
    ] {
        assert!(
            panics(|| FakeFilesystem::new().with_file(&w(name))),
            "a file at {name:?} was accepted"
        );
    }
    let fs = FakeFilesystem::new().with_file(&w(r"C:\a\."));
    assert!(fs.is_file(&w(r"C:\a")).unwrap());
    for name in [r"C:\", "C:", ".", r"\\srv\share"] {
        let _ = FakeFilesystem::new().with_dir(&w(name));
    }
}
