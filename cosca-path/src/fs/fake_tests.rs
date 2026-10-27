use std::io::ErrorKind;

use crate::fs::{BoundPath, Filesystem};
use crate::PurePath;
use crate::{posix, windows};

fn w(s: &str) -> windows::PathBuf {
    windows::PathBuf::parse(s).unwrap_or_else(|e| panic!("{s:?} does not parse: {e}"))
}

fn kind<T: std::fmt::Debug>(r: std::io::Result<T>) -> ErrorKind {
    r.expect_err("expected an error").kind()
}

/// Only what a test states exists: a stated file implies its ancestor directories, and
/// nothing else is there.
///
/// Mutants: a fake that answers `true` for an unstated path; one that does not imply a file's
/// ancestors; one that takes a stated directory for a file.
#[skuld::test]
fn fake_answers_only_stated_entries() {
    let tool = w(r"C:\a\b\tool.exe");
    let fs = windows::FakeFilesystem::new()
        .with_file(&tool)
        .with_dir(&w(r"C:\d"))
        .with_file(&w(r"C:\link"))
        .with_canonical(&w(r"C:\link"), &tool);

    // The stated file is a file and not a directory.
    assert!(fs.is_file(&tool).unwrap());
    assert!(!fs.is_dir(&tool).unwrap());
    // Its ancestors are directories, up to the root.
    for dir in [r"C:\a\b", r"C:\a", r"C:\"] {
        assert!(fs.is_dir(&w(dir)).unwrap(), "{dir}");
        assert!(!fs.is_file(&w(dir)).unwrap(), "{dir}");
    }
    // A stated directory is a directory and not a file.
    assert!(fs.is_dir(&w(r"C:\d")).unwrap());
    assert!(!fs.is_file(&w(r"C:\d")).unwrap());
    // Anything unstated is absent, not an error.
    for gone in [
        r"C:\a\b\other.exe",
        r"C:\x",
        r"C:\a\b\tool.exe\child",
        r"D:\",
        r"C:\d\a",
    ] {
        assert!(!fs.is_file(&w(gone)).unwrap(), "{gone}");
        assert!(!fs.is_dir(&w(gone)).unwrap(), "{gone}");
    }
    // Paths are compared as paths: `/` is a separator, and case is exact.
    assert!(fs.is_file(&w("C:/a/b/tool.exe")).unwrap());
    assert!(!fs.is_file(&w(r"C:\A\B\TOOL.EXE")).unwrap());

    // `canonical` follows a stated link, returns an existing path as it is, and fails for an
    // absent one.
    assert_eq!(fs.canonical(&w(r"C:\link")).unwrap(), tool);
    assert_eq!(fs.canonical(&tool).unwrap(), tool);
    assert_eq!(fs.canonical(&w(r"C:\a")).unwrap(), w(r"C:\a"));
    assert_eq!(kind(fs.canonical(&w(r"C:\x"))), ErrorKind::NotFound);

    // `same_file` compares what the paths resolve to, and needs both to exist.
    assert!(fs.same_file(&tool, &tool).unwrap());
    assert!(fs.same_file(&w(r"C:\link"), &tool).unwrap());
    assert!(!fs.same_file(&tool, &w(r"C:\d")).unwrap());
    assert_eq!(kind(fs.same_file(&tool, &w(r"C:\x"))), ErrorKind::NotFound);
    assert_eq!(kind(fs.same_file(&w(r"C:\x"), &tool)), ErrorKind::NotFound);

    // The POSIX fake follows the same rules.
    let tool = posix::Path::new("/usr/bin/tool");
    let fs = posix::FakeFilesystem::new()
        .with_file(tool)
        .with_dir(posix::Path::new("/opt"));
    assert!(fs.is_file(tool).unwrap());
    assert!(!fs.is_dir(tool).unwrap());
    assert!(fs.is_dir(posix::Path::new("/usr/bin")).unwrap());
    assert!(fs.is_dir(posix::Path::new("/")).unwrap());
    assert!(fs.is_dir(posix::Path::new("/opt")).unwrap());
    assert!(!fs.is_file(posix::Path::new("/opt")).unwrap());
    assert!(!fs.is_file(posix::Path::new("/usr/bin/other")).unwrap());
    assert!(!fs.is_dir(posix::Path::new("/usr/bin/other")).unwrap());
    assert!(!fs.is_file(posix::Path::new("/USR/BIN/TOOL")).unwrap());
    assert_eq!(kind(fs.canonical(posix::Path::new("/nope"))), ErrorKind::NotFound);
}

/// A stated error is an `Err` from every question about that path, and the fake's other paths
/// are unaffected.
///
/// Mutants: a fake that turns the error into `Ok(false)`; one where the error answers only
/// `is_file`; one where a later `with_error` does not replace an earlier `with_file`.
#[skuld::test]
fn a_stated_error_is_an_error_not_absence() {
    let locked = w(r"C:\locked\tool.exe");
    let fine = w(r"C:\locked\fine.exe");
    let fs = windows::FakeFilesystem::new()
        .with_file(&fine)
        .with_file(&locked)
        .with_error(&locked, ErrorKind::PermissionDenied);

    assert_eq!(kind(fs.is_file(&locked)), ErrorKind::PermissionDenied);
    assert_eq!(kind(fs.is_dir(&locked)), ErrorKind::PermissionDenied);
    assert_eq!(kind(fs.canonical(&locked)), ErrorKind::PermissionDenied);
    assert_eq!(kind(fs.same_file(&locked, &fine)), ErrorKind::PermissionDenied);
    assert_eq!(kind(fs.same_file(&fine, &locked)), ErrorKind::PermissionDenied);

    // The neighbour answers, and an unstated sibling is absent, not an error.
    assert!(fs.is_file(&fine).unwrap());
    assert!(!fs.is_file(&w(r"C:\locked\absent.exe")).unwrap());

    // An error on a path the test never stated as present is still an error.
    let fs = posix::FakeFilesystem::new().with_error(posix::Path::new("/proc/x"), ErrorKind::Other);
    assert_eq!(kind(fs.is_file(posix::Path::new("/proc/x"))), ErrorKind::Other);
    assert_eq!(kind(fs.is_dir(posix::Path::new("/proc/x"))), ErrorKind::Other);
    assert!(!fs.is_file(posix::Path::new("/proc/y")).unwrap());
}

/// A bound path asks its filesystem about its own path.
///
/// Mutants: a `BoundPath` that asks about a different path than the one it holds; a `same_file` that
/// ignores `other` or answers about `self` twice.
#[skuld::test]
fn a_bound_path_asks_its_filesystem() {
    let file = posix::Path::new("/d/f");
    let fs = posix::FakeFilesystem::new().with_file(file);
    let bound = BoundPath::new(&fs, file);
    assert_eq!(bound.path(), file);
    assert!(bound.is_file().unwrap());
    assert!(!bound.is_dir().unwrap());
    assert_eq!(bound.canonical().unwrap(), file.to_path_buf());

    let bound = BoundPath::new(&fs, posix::Path::new("/d"));
    assert!(bound.is_dir().unwrap());
    assert!(!bound.is_file().unwrap());

    // `same_file` compares the two bound paths, in either order, and needs both to exist.
    let (file_b, dir_b) = (BoundPath::new(&fs, file), BoundPath::new(&fs, posix::Path::new("/d/")));
    assert!(file_b.same_file(&file_b).unwrap());
    assert!(!file_b.same_file(&dir_b).unwrap());
    assert!(!dir_b.same_file(&file_b).unwrap());
    let absent = BoundPath::new(&fs, posix::Path::new("/nope"));
    assert_eq!(kind(file_b.same_file(&absent)), ErrorKind::NotFound);
    assert_eq!(kind(absent.same_file(&file_b)), ErrorKind::NotFound);

    // Through a trait object too: the resolver takes `&dyn Filesystem`.
    let dynamic: &dyn Filesystem<Path = posix::Path> = &fs;
    assert!(BoundPath::new(dynamic, file).is_file().unwrap());
}

fn p(s: &str) -> &posix::Path {
    posix::Path::new(s)
}

/// Repeated and trailing separators do not change which entry a query names, as on the real
/// filesystem. A trailing separator still demands a directory.
///
/// Mutants: a fake keyed on spelling (or matching links by `==`); one that lets a trailing
/// separator name a file.
#[skuld::test]
fn separator_spelling_does_not_change_the_entry() {
    let fs = windows::FakeFilesystem::new()
        .with_file(&w(r"C:\bin\tool.exe"))
        .with_canonical(&w(r"C:\bin\tool.exe"), &w(r"C:\real\tool.exe"));
    for dir in [r"C:\bin\", r"C:\bin", r"C:\bin\\", r"C:/bin/"] {
        assert!(fs.is_dir(&w(dir)).unwrap(), "{dir}");
        assert!(!fs.is_file(&w(dir)).unwrap(), "{dir}");
    }
    for file in [r"C:\bin\tool.exe", r"C:/bin/tool.exe", r"C:\bin\\tool.exe"] {
        assert!(fs.is_file(&w(file)).unwrap(), "{file}");
        assert_eq!(fs.canonical(&w(file)).unwrap(), w(r"C:\real\tool.exe"), "{file}");
    }
    // A trailing separator names a directory only.
    let spelled = w(r"C:\bin\tool.exe\");
    assert!(!fs.is_file(&spelled).unwrap());
    assert!(!fs.is_dir(&spelled).unwrap());
    assert_eq!(kind(fs.canonical(&spelled)), ErrorKind::NotFound);

    // The stated spelling may be the odd one: the plain one finds it.
    let fs = windows::FakeFilesystem::new().with_dir(&w(r"C:\bin\"));
    assert!(fs.is_dir(&w(r"C:\bin")).unwrap());

    // POSIX: a `PATH` entry `/usr/bin/` joined with `tool` is `/usr/bin//tool`.
    let fs = posix::FakeFilesystem::new().with_file(p("/usr/bin/tool"));
    let joined = p("/usr/bin/").join(p("tool"));
    assert_eq!(joined, p("/usr/bin//tool").to_path_buf());
    assert!(fs.is_file(&joined).unwrap());
    assert!(fs.is_dir(p("/usr/bin/")).unwrap());
    assert!(fs.is_dir(p("//usr")).unwrap());
    assert!(!fs.is_file(p("/usr/bin/tool/")).unwrap());
    assert!(fs.same_file(&joined, p("/usr/bin/tool")).unwrap());
    assert!(fs.is_file(p("/usr/./bin/tool")).unwrap());
}

/// A stated error on a path covers the path and everything below it, as a denied directory does.
/// Its parent and siblings stay as stated, and it implies no ancestor.
///
/// Mutants: an error that covers only the exact path; one that also covers the parent; one that
/// implies the parent is a directory.
#[skuld::test]
fn a_stated_error_covers_what_is_below() {
    let fs = windows::FakeFilesystem::new()
        .with_file(&w(r"C:\ok\tool.exe"))
        .with_file(&w(r"C:\locked\tool.exe"))
        .with_error(&w(r"C:\locked"), ErrorKind::PermissionDenied);
    for below in [
        r"C:\locked",
        r"C:\locked\tool.exe",
        r"C:\locked\tool",
        r"C:\locked\a\b",
        r"C:\locked\",
    ] {
        assert_eq!(kind(fs.is_file(&w(below))), ErrorKind::PermissionDenied, "{below}");
        assert_eq!(kind(fs.is_dir(&w(below))), ErrorKind::PermissionDenied, "{below}");
        assert_eq!(kind(fs.canonical(&w(below))), ErrorKind::PermissionDenied, "{below}");
    }
    assert_eq!(
        kind(fs.same_file(&w(r"C:\ok\tool.exe"), &w(r"C:\locked\tool.exe"))),
        ErrorKind::PermissionDenied
    );
    // The parent and a sibling answer.
    assert!(fs.is_dir(&w(r"C:\")).unwrap());
    assert!(fs.is_file(&w(r"C:\ok\tool.exe")).unwrap());
    assert!(!fs.is_file(&w(r"C:\lockedx\tool.exe")).unwrap());

    // An error on a leaf says nothing about its parent: unstated, the parent is absent.
    let fs = windows::FakeFilesystem::new().with_error(&w(r"C:\d\tool.exe"), ErrorKind::PermissionDenied);
    assert!(!fs.is_dir(&w(r"C:\d")).unwrap());
    assert_eq!(kind(fs.is_file(&w(r"C:\d\tool.exe"))), ErrorKind::PermissionDenied);
}

/// A relative stated path does not make the empty path a directory.
///
/// Mutant: an ancestor walk that inserts the empty parent.
#[skuld::test]
fn a_relative_path_implies_no_empty_directory() {
    let fs = posix::FakeFilesystem::new().with_file(p("bin/tool"));
    assert!(fs.is_dir(p("bin")).unwrap());
    assert!(!fs.is_dir(p("")).unwrap());
    assert_eq!(kind(fs.canonical(p(""))), ErrorKind::NotFound);

    let fs = windows::FakeFilesystem::new().with_file(&w(r"bin\tool.exe"));
    assert!(fs.is_dir(&w("bin")).unwrap());

    // A test that states the empty path itself gets it.
    let fs = posix::FakeFilesystem::new().with_dir(p(""));
    assert!(fs.is_dir(p("")).unwrap());
}

/// `with_canonical` moves exactly the path it names, creates nothing, and a link's target is
/// returned as stated.
///
/// Mutants: a `with_canonical` that makes its path exist; one that moves the path's descendants
/// (the fake cannot build a path from a component, so it would have to guess); one that checks
/// the target.
#[skuld::test]
fn with_canonical_moves_only_its_path() {
    let fs = posix::FakeFilesystem::new()
        .with_canonical(p("/bin"), p("/usr/bin"))
        .with_file(p("/bin/tool"))
        .with_file(p("/usr/bin/tool"));
    // `/bin` was never stated as present: the link does not create it.
    let only_link = posix::FakeFilesystem::new().with_canonical(p("/ghost"), p("/anywhere"));
    assert!(!only_link.is_dir(p("/ghost")).unwrap());
    assert!(!only_link.is_file(p("/ghost")).unwrap());
    assert_eq!(kind(only_link.canonical(p("/ghost"))), ErrorKind::NotFound);
    assert_eq!(kind(only_link.same_file(p("/ghost"), p("/ghost"))), ErrorKind::NotFound);

    // `/bin` itself moves; a path below it does not, until the test states it too.
    assert_eq!(fs.canonical(p("/bin")).unwrap(), p("/usr/bin").to_path_buf());
    assert_eq!(fs.canonical(p("/bin/tool")).unwrap(), p("/bin/tool").to_path_buf());
    assert!(!fs.same_file(p("/bin/tool"), p("/usr/bin/tool")).unwrap());
    let fs = fs.with_canonical(p("/bin/tool"), p("/usr/bin/tool"));
    assert_eq!(fs.canonical(p("/bin/tool")).unwrap(), p("/usr/bin/tool").to_path_buf());
    assert!(fs.same_file(p("/bin/tool"), p("/usr/bin/tool")).unwrap());
}

/// A later statement about a path replaces an earlier one, in either order, and a stated
/// directory implies its own ancestors.
///
/// Mutants: a `with_file` that does not replace an earlier `with_error`; one that does not
/// replace an earlier `with_dir`; a `with_dir` that implies no ancestors.
#[skuld::test]
fn later_statements_replace_and_directories_imply_ancestors() {
    let fs = posix::FakeFilesystem::new()
        .with_error(p("/a"), ErrorKind::Other)
        .with_file(p("/a"));
    assert!(fs.is_file(p("/a")).unwrap());

    let fs = posix::FakeFilesystem::new().with_file(p("/a")).with_dir(p("/a"));
    assert!(fs.is_dir(p("/a")).unwrap());
    assert!(!fs.is_file(p("/a")).unwrap());

    let fs = posix::FakeFilesystem::new().with_dir(p("/a")).with_file(p("/a"));
    assert!(fs.is_file(p("/a")).unwrap());

    // Only a directory is stated, so nothing else supplies its ancestors.
    let fs = windows::FakeFilesystem::new().with_dir(&w(r"C:\a\b"));
    for dir in [r"C:\a\b", r"C:\a", r"C:\"] {
        assert!(fs.is_dir(&w(dir)).unwrap(), "{dir}");
    }
    let fs = posix::FakeFilesystem::new().with_dir(p("/a/b"));
    for dir in ["/a/b", "/a", "/"] {
        assert!(fs.is_dir(p(dir)).unwrap(), "{dir}");
    }
}

/// A UNC share root is one entry whether or not it ends in a separator: stated descendants
/// imply it, and an error on it covers everything below.
///
/// Mutants: a fake that compares anchors by spelling; one whose error key, spelled without the
/// separator, misses the root the ancestor walk stores with it.
#[skuld::test]
fn a_unc_share_root_is_one_entry_with_or_without_a_separator() {
    let fs = windows::FakeFilesystem::new().with_file(&w(r"\\srv\share\a\b"));
    for root in [r"\\srv\share\", r"\\srv\share"] {
        assert!(fs.is_dir(&w(root)).unwrap(), "{root}");
    }
    let fs = windows::FakeFilesystem::new().with_dir(&w(r"\\srv\share"));
    assert!(fs.is_dir(&w(r"\\srv\share\")).unwrap());
    let fs = windows::FakeFilesystem::new().with_dir(&w(r"\\srv\share\"));
    assert!(fs.is_dir(&w(r"\\srv\share")).unwrap());

    for stated in [r"\\srv\share", r"\\srv\share\"] {
        let fs = windows::FakeFilesystem::new().with_error(&w(stated), ErrorKind::PermissionDenied);
        for below in [
            r"\\srv\share\t.exe",
            r"\\srv\share",
            r"\\srv\share\",
            r"\\srv\share\a\b",
        ] {
            assert_eq!(
                kind(fs.is_file(&w(below))),
                ErrorKind::PermissionDenied,
                "{stated} / {below}"
            );
        }
    }
}

/// The Windows fake reads a query as Win32 does a non-verbatim path: `.` and `..` resolve
/// lexically before any name is matched. (Measured on Windows 11: `C:\Windows\nope\..\System32`
/// and `C:\Windows\.` are directories, `C:\Windows\notepad.exe\.` is the file.) The POSIX fake
/// resolves `..` against the directory it leaves, which has to exist (see `posix::lookup`).
///
/// Mutants: a fake that matches `.` and `..` as names; one that keeps the trailing separator a
/// final `.` or `..` leaves, so the file at `notepad.exe\.` is absent; one that keeps `..` a name on
/// POSIX.
#[skuld::test]
fn the_windows_fake_resolves_dots_as_text_and_the_posix_fake_through_the_directories() {
    let fs = windows::FakeFilesystem::new()
        .with_file(&w(r"C:\Windows\System32\notepad.exe"))
        .with_dir(&w(r"C:\a\b"));
    for dir in [
        r"C:\Windows\.",
        r"C:\Windows\nope\..\System32",
        r"C:\Windows\System32\..\System32\",
        r"C:\a\.\b",
        r"C:\a\b\..\b",
        r"C:\a\b\.\.",
        r"C:\..\a\b",
    ] {
        assert!(fs.is_dir(&w(dir)).unwrap(), "{dir}");
    }
    for file in [
        r"C:\Windows\System32\notepad.exe\.",
        r"C:\Windows\System32\x\..\notepad.exe",
        r"C:\Windows\.\System32\notepad.exe",
    ] {
        assert!(fs.is_file(&w(file)).unwrap(), "{file}");
    }
    // A trailing separator after a resolved name still demands a directory.
    assert!(!fs.is_file(&w(r"C:\Windows\System32\notepad.exe\.\")).unwrap());
    // A stated key resolves the same way, and an error covers what is below.
    let fs = windows::FakeFilesystem::new().with_error(&w(r"C:\x\..\locked"), ErrorKind::PermissionDenied);
    assert_eq!(kind(fs.is_file(&w(r"C:\locked\tool.exe"))), ErrorKind::PermissionDenied);

    // POSIX: `..` leaves a directory, which has to be there; `/a/x` is not.
    let fs = posix::FakeFilesystem::new().with_dir(p("/a/b"));
    assert!(!fs.is_dir(p("/a/x/../b")).unwrap());
    assert!(fs.is_dir(p("/a/b/..")).unwrap());
    assert!(fs.is_dir(p("/a/./b")).unwrap());
}

/// The POSIX fake reads `.` as the kernel does: `a/./b` is `a/b` whatever links `a` holds, so a
/// `PATH` entry `.` joined with `tool` finds `tool`. A final `.` names a directory, so it never
/// reaches a file.
///
/// Mutants: a fake that keeps `.` as a name; one that lets `tool/.` name the file; one that
/// drops every `.`, so the empty path becomes a directory.
#[skuld::test]
fn the_posix_fake_reads_a_single_dot_as_the_host_does() {
    let fs = posix::FakeFilesystem::new()
        .with_file(p("tool"))
        .with_file(p("/usr/bin/tool"));
    for file in ["./tool", "././tool", ".//tool", "/usr/./bin/./tool", "/usr/bin/./tool"] {
        assert!(fs.is_file(p(file)).unwrap(), "{file}");
        if file.starts_with('/') {
            assert_eq!(
                fs.canonical(p(file)).unwrap(),
                p("/usr/bin/tool").to_path_buf(),
                "{file}"
            );
        } else {
            // The host's canonical form of a relative path is absolute (see `posix::lookup`).
            assert_eq!(kind(fs.canonical(p(file))), ErrorKind::InvalidInput, "{file}");
            assert!(fs.same_file(p(file), p("tool")).unwrap(), "{file}");
        }
    }
    // A final `.`, or a `.` before a trailing separator, demands a directory.
    for not_file in ["tool/.", "./tool/", "/usr/bin/tool/.", "/usr/bin/tool/./"] {
        assert!(!fs.is_file(p(not_file)).unwrap(), "{not_file}");
        assert!(!fs.is_dir(p(not_file)).unwrap(), "{not_file}");
    }
    for dir in ["/usr/bin/.", "/usr/bin/./", "/usr/./bin", "/.", "/./", "/usr/."] {
        assert!(fs.is_dir(p(dir)).unwrap(), "{dir}");
    }
    // The empty path stays absent; `.` is a directory on every host, stated or not.
    assert!(!fs.is_dir(p("")).unwrap());
    for dir in [".", "./", "./."] {
        assert!(fs.is_dir(p(dir)).unwrap(), "{dir}");
    }
    let fs = posix::FakeFilesystem::new().with_dir(p("."));
    assert!(!fs.is_dir(p("")).unwrap());
}

/// Drive-relative `C:` is the current directory of drive C, however it is spelled: `C:.`, `C:.\`,
/// `C:./` and `C:a\..\` all name it, and a link stated for one of them is the link of all.
///
/// Mutants: a lookup that strips the trailing separator of `C:.\` and keeps `C:.` as a second
/// key, so that the link of `C:` is missed.
#[skuld::test]
fn the_drive_relative_current_directory_has_one_key() {
    let fs = windows::FakeFilesystem::new()
        .with_dir(&w("C:"))
        .with_canonical(&w("C:"), &w(r"C:\work"));
    for dir in ["C:", "C:.", r"C:.\", "C:./", r"C:a\..\", r"C:.\.\", r"C:a\.."] {
        assert!(fs.is_dir(&w(dir)).unwrap(), "{dir}");
        assert!(!fs.is_file(&w(dir)).unwrap(), "{dir}");
        assert_eq!(fs.canonical(&w(dir)).unwrap(), w(r"C:\work"), "{dir}");
        assert!(fs.same_file(&w(dir), &w("C:")).unwrap(), "{dir}");
    }
    assert!(!fs.is_dir(&w(r"C:\a\..\x")).unwrap());
    // Stated with the odd spelling, the plain one finds it.
    let fs = windows::FakeFilesystem::new().with_dir(&w(r"C:.\"));
    assert!(fs.is_dir(&w("C:")).unwrap());
    // The plain relative current directory is the same shape.
    let fs = windows::FakeFilesystem::new()
        .with_dir(&w("."))
        .with_canonical(&w("."), &w(r"C:\work"));
    for dir in [".", r".\", "./", r"a\..\"] {
        assert!(fs.is_dir(&w(dir)).unwrap(), "{dir}");
        assert_eq!(fs.canonical(&w(dir)).unwrap(), w(r"C:\work"), "{dir}");
    }
}

/// A name holding NUL is `InvalidInput` from every question, as on the host: no filesystem
/// stores it, and it is not "absent". It beats a stated error.
///
/// Mutants: a fake that answers `Ok(false)`; one that checks only `is_file`; one that checks only
/// one path of `same_file`; one that lets a stated error win.
#[skuld::test]
fn a_name_holding_nul_is_invalid_input() {
    let fs = posix::FakeFilesystem::new()
        .with_file(p("/ok"))
        .with_error(p("/locked"), ErrorKind::PermissionDenied);
    for bad in ["/a\0b", "\0", "/ok/\0", "/locked/a\0b"] {
        let bad = p(bad);
        assert_eq!(kind(fs.is_file(bad)), ErrorKind::InvalidInput, "{bad:?}");
        assert_eq!(kind(fs.is_dir(bad)), ErrorKind::InvalidInput, "{bad:?}");
        assert_eq!(kind(fs.canonical(bad)), ErrorKind::InvalidInput, "{bad:?}");
        assert_eq!(kind(fs.same_file(bad, p("/ok"))), ErrorKind::InvalidInput, "{bad:?}");
        assert_eq!(kind(fs.same_file(p("/ok"), bad)), ErrorKind::InvalidInput, "{bad:?}");
    }
    let fs = windows::FakeFilesystem::new()
        .with_file(&w(r"C:\ok"))
        .with_error(&w(r"C:\locked"), ErrorKind::PermissionDenied);
    for bad in ["C:\\a\0b", "a\0", "\\\\s\\h\\\0", "C:\\locked\\a\0b"] {
        let bad = w(bad);
        assert_eq!(kind(fs.is_file(&bad)), ErrorKind::InvalidInput, "{bad:?}");
        assert_eq!(kind(fs.is_dir(&bad)), ErrorKind::InvalidInput, "{bad:?}");
        assert_eq!(kind(fs.canonical(&bad)), ErrorKind::InvalidInput, "{bad:?}");
        assert_eq!(
            kind(fs.same_file(&bad, &w(r"C:\ok"))),
            ErrorKind::InvalidInput,
            "{bad:?}"
        );
        assert_eq!(
            kind(fs.same_file(&w(r"C:\ok"), &bad)),
            ErrorKind::InvalidInput,
            "{bad:?}"
        );
    }
}

// A file has no children, so a statement that puts a path under a file, or a file over a path
// that has children, panics in the builder instead of answering wrongly later.
//
// Mutants: a builder that accepts either order; one that checks only one of them.

#[skuld::test]
#[should_panic(expected = "is a file")]
fn a_path_under_a_stated_file_is_refused_posix() {
    let _ = posix::FakeFilesystem::new().with_file(p("/a")).with_file(p("/a/b"));
}

#[skuld::test]
#[should_panic(expected = "is a file")]
fn a_path_under_a_stated_file_is_refused_windows() {
    let _ = windows::FakeFilesystem::new()
        .with_file(&w(r"C:\a"))
        .with_dir(&w(r"C:\a\b"));
}

#[skuld::test]
#[should_panic(expected = "has entries below it")]
fn a_file_over_a_stated_child_is_refused_posix() {
    let _ = posix::FakeFilesystem::new().with_file(p("/a/b")).with_file(p("/a"));
}

#[skuld::test]
#[should_panic(expected = "has entries below it")]
fn a_file_over_an_implied_directory_is_refused_windows() {
    let _ = windows::FakeFilesystem::new()
        .with_dir(&w(r"C:\a\b"))
        .with_file(&w(r"C:\a"));
}

// A trailing separator names only a directory, and so does `.` on POSIX (the kernel refuses it below
// a file), so stating a file there contradicts itself, as the file-and-children cases above do. Win32
// drops a trailing `\.`: `C:\a\.` is the file `C:\a`, as the host reads it.
//
// Mutant: a builder that drops the "names only a directory" flag and states a file at `/a`.

#[skuld::test]
#[should_panic(expected = "names only a directory")]
fn a_file_with_a_trailing_separator_is_refused_posix() {
    let _ = posix::FakeFilesystem::new().with_file(p("/a/"));
}

#[skuld::test]
#[should_panic(expected = "names only a directory")]
fn a_file_with_a_trailing_dot_is_refused_posix() {
    let _ = posix::FakeFilesystem::new().with_file(p("/a/."));
}

#[skuld::test]
#[should_panic(expected = "names only a directory")]
fn a_file_with_a_trailing_separator_is_refused_windows() {
    let _ = windows::FakeFilesystem::new().with_file(&w(r"C:\a\"));
}

/// Restating an entry, or replacing a file by a directory, is not a contradiction.
///
/// Mutant: a check that fires on a restated file, or on a directory replacing a file.
#[skuld::test]
fn restating_an_entry_is_not_a_contradiction() {
    let fs = posix::FakeFilesystem::new()
        .with_file(p("/a/f"))
        .with_file(p("/a/f"))
        .with_dir(p("/a"))
        .with_dir(p("/a"))
        .with_file(p("/g"))
        .with_dir(p("/g"));
    assert!(fs.is_file(p("/a/f")).unwrap());
    assert!(fs.is_dir(p("/g")).unwrap());
}

/// `canonical` returns the host's spelling: no repeated or trailing separator, and on Windows `\`
/// whatever the query wrote. Windows paths compare `/` equal to `\`, so the Windows spelling is
/// compared as text.
///
/// Mutants: a fake that returns the query as written; one that keeps a trailing separator; one
/// that keeps `/` on Windows.
#[skuld::test]
fn canonical_returns_the_hosts_spelling() {
    let canonical = |fs: &windows::FakeFilesystem, query: &str| {
        let spelled = fs.canonical(&w(query)).unwrap();
        spelled.to_str().expect("the spelling is UTF-8").to_owned()
    };
    let fs = windows::FakeFilesystem::new()
        .with_dir(&w(r"C:\a\b"))
        .with_dir(&w(r"\\srv\share\d"));
    for query in [r"C:\a\\b\", r"C:/a/b", r"C:\a\b\", r"C:\a\.\b", r"C:/a/./b/"] {
        assert_eq!(canonical(&fs, query), r"C:\a\b", "{query}");
    }
    assert_eq!(canonical(&fs, "C:/"), r"C:\");
    assert_eq!(canonical(&fs, r"\\srv\share\\d\"), r"\\srv\share\d");
    assert_eq!(kind(fs.canonical(&w(r"C:\bin\"))), ErrorKind::NotFound);

    let fs = posix::FakeFilesystem::new().with_file(p("/usr/bin/tool"));
    assert_eq!(
        fs.canonical(p("/usr/bin//tool")).unwrap(),
        p("/usr/bin/tool").to_path_buf()
    );
    assert_eq!(fs.canonical(p("//usr/bin/")).unwrap(), p("/usr/bin").to_path_buf());
    assert_eq!(fs.canonical(p("/")).unwrap(), p("/").to_path_buf());
}

/// A directory that stats fine but whose contents cannot be examined: the directory answers, and
/// everything strictly below it fails with the stated kind.
///
/// Mutants: an unreadable directory that fails for itself (as `with_error` does); one that fails
/// nothing; one that covers only its direct children; one that covers its parent or siblings.
#[skuld::test]
fn an_unreadable_dir_answers_for_itself_and_fails_below() {
    let fs = windows::FakeFilesystem::new()
        .with_file(&w(r"C:\ok\tool.exe"))
        .with_unreadable_dir(&w(r"C:\locked"), ErrorKind::PermissionDenied);
    assert!(fs.is_dir(&w(r"C:\locked")).unwrap());
    assert!(fs.is_dir(&w(r"C:\locked\")).unwrap());
    assert!(!fs.is_file(&w(r"C:\locked")).unwrap());
    assert_eq!(fs.canonical(&w(r"C:\locked")).unwrap(), w(r"C:\locked"));
    assert!(fs.same_file(&w(r"C:\locked"), &w(r"C:\locked\")).unwrap());
    for below in [r"C:\locked\tool.exe", r"C:\locked\a\b", r"C:\locked\sub"] {
        assert_eq!(kind(fs.is_file(&w(below))), ErrorKind::PermissionDenied, "{below}");
        assert_eq!(kind(fs.is_dir(&w(below))), ErrorKind::PermissionDenied, "{below}");
        assert_eq!(kind(fs.canonical(&w(below))), ErrorKind::PermissionDenied, "{below}");
    }
    assert_eq!(
        kind(fs.same_file(&w(r"C:\locked"), &w(r"C:\locked\tool.exe"))),
        ErrorKind::PermissionDenied
    );
    // The parent and a sibling are as stated.
    assert!(fs.is_dir(&w(r"C:\")).unwrap());
    assert!(fs.is_file(&w(r"C:\ok\tool.exe")).unwrap());
    assert!(!fs.is_file(&w(r"C:\lockedx\tool.exe")).unwrap());

    // It implies its ancestors, and a later statement replaces it, in either order.
    let fs = posix::FakeFilesystem::new().with_unreadable_dir(p("/a/b"), ErrorKind::PermissionDenied);
    assert!(fs.is_dir(p("/a")).unwrap());
    assert_eq!(kind(fs.is_file(p("/a/b/c"))), ErrorKind::PermissionDenied);
    let fs = fs.with_dir(p("/a/b"));
    assert!(!fs.is_file(p("/a/b/c")).unwrap());
    let fs = fs.with_unreadable_dir(p("/a/b"), ErrorKind::Other);
    assert_eq!(kind(fs.is_file(p("/a/b/c"))), ErrorKind::Other);
}

/// When several ancestors of a path carry a stated error, the one nearest the root answers, as the
/// first one a walk down meets does; an unreadable directory answers for what is below it and not
/// for itself, and the order of the statements does not matter.
///
/// Mutants: a walk that meets the nearest ancestor of the path first; an unreadable directory that
/// fails for itself while a directory above it is unreadable too; a later statement that replaces
/// an earlier one at another path.
#[skuld::test]
fn the_error_nearest_the_root_answers() {
    use ErrorKind::{Other, PermissionDenied};

    let build = |states: &[(&str, ErrorKind, bool)]| {
        states
            .iter()
            .fold(posix::FakeFilesystem::new(), |fs, &(path, kind, unreadable)| {
                if unreadable {
                    fs.with_unreadable_dir(p(path), kind)
                } else {
                    fs.with_error(p(path), kind)
                }
            })
    };
    // (outer, inner, what is asked, who answers).
    let cases = [
        // An unreadable directory in an unreadable directory: the outer one fails the inner one too.
        (
            [("/a", Other, true), ("/a/b", PermissionDenied, true)],
            &[("/a/b", Other), ("/a/b/c", Other), ("/a/b/c/d", Other)][..],
        ),
        // An error in an unreadable directory.
        (
            [("/a", Other, true), ("/a/b", PermissionDenied, false)],
            &[("/a/b", Other), ("/a/b/c", Other)][..],
        ),
        // An unreadable directory in an error.
        (
            [("/a", Other, false), ("/a/b", PermissionDenied, true)],
            &[("/a", Other), ("/a/b", Other), ("/a/b/c", Other)][..],
        ),
        // An error in an error.
        (
            [("/a", Other, false), ("/a/b", PermissionDenied, false)],
            &[("/a", Other), ("/a/b", Other), ("/a/b/c", Other)][..],
        ),
    ];
    for (states, asked) in cases {
        let reversed = [states[1], states[0]];
        for order in [&states, &reversed] {
            let fs = build(order);
            for &(path, want) in asked {
                assert_eq!(kind(fs.is_file(p(path))), want, "{order:?} {path}");
                assert_eq!(kind(fs.is_dir(p(path))), want, "{order:?} {path}");
                assert_eq!(kind(fs.canonical(p(path))), want, "{order:?} {path}");
            }
        }
    }
    // The outer unreadable directory itself answers, as does the inner one beside an error above.
    let fs = build(&[("/a", Other, true), ("/a/b", PermissionDenied, true)]);
    assert!(fs.is_dir(p("/a")).unwrap());
}

/// A device path spelled with `?` reads as the verbatim path it names, as on the host
/// (`//?/C:/Windows` is `C:\Windows`): the fake keys it so, and never panics on one.
///
/// Mutants: a lookup that writes `\` for the `/` after `\\?` (the key is then a verbatim spelling,
/// which no stored path holds, and the builder panics); one that keys `//?/C:/x` apart from `C:\x`.
#[skuld::test]
fn a_question_mark_device_path_reads_as_the_verbatim_path_it_names() {
    // Each spelling is the entry of the plain path it names, stated either way and found either way.
    for (s, plain) in [
        ("//?/C:/Windows", r"C:\Windows"),
        ("//?/x", r"\\.\x"),
        (r"\\?/C:\Windows\System32", r"C:\Windows\System32"),
        (r"/\?\x", r"\\.\x"),
        (r"\\?/", r"\\.\"),
        ("//?/UNC/srv/share/d", r"\\srv\share\d"),
        ("//?/UNC", r"\\.\UNC"),
        ("//?/c:/a/../b", r"c:\b"),
    ] {
        let (q, plain) = (w(s), w(plain));
        let stated = windows::FakeFilesystem::new().with_dir(&plain);
        assert!(stated.is_dir(&q).unwrap(), "{s}");
        assert!(stated.same_file(&q, &plain).unwrap(), "{s}");
        let via_spelling = windows::FakeFilesystem::new().with_dir(&q);
        assert!(via_spelling.is_dir(&plain).unwrap(), "{s}");
        assert!(via_spelling.same_file(&q, &plain).unwrap(), "{s}");
    }

    let drive = windows::FakeFilesystem::new().with_dir(&w(r"C:\Windows"));
    for q in [
        "//?/C:/Windows",
        r"\\?/C:\Windows",
        r"/\?\C:\Windows",
        r"//?/c:/Windows/",
    ] {
        // Case is exact: `c:` is not `C:`.
        assert_eq!(drive.is_dir(&w(q)).unwrap(), !q.contains("c:"), "{q}");
    }
    assert_eq!(drive.canonical(&w("//?/C:/Windows")).unwrap(), w(r"C:\Windows"));
    let device = windows::FakeFilesystem::new().with_dir(&w("//?/C:/Windows"));
    assert!(device.is_dir(&w(r"C:\Windows")).unwrap());

    let unc = windows::FakeFilesystem::new().with_dir(&w(r"\\srv\share\d"));
    assert!(unc.is_dir(&w("//?/UNC/srv/share/d")).unwrap());
    let named = windows::FakeFilesystem::new().with_dir(&w(r"\\.\x"));
    assert!(named.is_dir(&w("//?/x")).unwrap());
    // Not a drive, not UNC: nothing is stated there.
    assert!(!drive.is_dir(&w("//?/UNC")).unwrap());

    // A verbatim UNC server `?` has no plain spelling, so no key could name it: every question
    // is refused, as `parse` refuses the same path with `\\?\`.
    let unc = windows::FakeFilesystem::new().with_dir(&w("//?/UNC/?/x"));
    let q = w("//?/UNC/?/x");
    assert_eq!(kind(unc.is_dir(&q)), ErrorKind::InvalidInput);
    assert_eq!(kind(unc.is_file(&q)), ErrorKind::InvalidInput);
    assert_eq!(kind(unc.canonical(&q)), ErrorKind::InvalidInput);
    assert_eq!(kind(unc.same_file(&q, &q)), ErrorKind::InvalidInput);
}

/// A `.` device path whose name is a drive or `UNC` reads as the path it names, as on the host
/// (`\\.\C:\Windows` is `C:\Windows`, measured), in every spelling of the prefix. The volume
/// device `\\.\C:` is not the root directory and stays its own entry.
///
/// Mutants: a lookup that keys `\\.\C:\x` apart from `C:\x`, or `\\.\UNC\s\h\x` apart from
/// `\\s\h\x`; one that also reads `\\.\C:` as `C:\`; one that folds the `UNC` name case-sensitively.
#[skuld::test]
fn a_dot_device_path_reads_as_the_path_it_names() {
    let drive = windows::FakeFilesystem::new().with_dir(&w(r"C:\Windows"));
    for q in [
        r"\\.\C:\Windows",
        "//./C:/Windows",
        r"\\.\C:\\Windows\",
        r"\\.\C:\Windows\.",
        r"\\.\C:\Windows\x\..",
        r"/\.\C:\Windows",
    ] {
        assert!(drive.is_dir(&w(q)).unwrap(), "{q}");
        assert!(!drive.is_file(&w(q)).unwrap(), "{q}");
        assert_eq!(drive.canonical(&w(q)).unwrap(), w(r"C:\Windows"), "{q}");
    }
    for q in [r"\\.\C:\", "//./C:/", r"\\.\C:\\"] {
        assert!(drive.is_dir(&w(q)).unwrap(), "{q}");
        assert_eq!(drive.canonical(&w(q)).unwrap(), w(r"C:\"), "{q}");
    }
    // Case is exact, as for any other path.
    assert!(!drive.is_dir(&w(r"\\.\c:\Windows")).unwrap());
    assert!(drive.same_file(&w(r"C:\Windows"), &w(r"\\.\C:\Windows")).unwrap());
    // The raw volume is a device the host refuses, not the root directory (see `windows::lookup`).
    for q in [r"\\.\C:", r"\\.\C:\.", "//./C:/."] {
        assert_eq!(kind(drive.is_dir(&w(q))), ErrorKind::Other, "{q}");
    }

    // Stated as a device path, it is the same entry as the drive path.
    let device = windows::FakeFilesystem::new().with_dir(&w(r"\\.\C:\Windows"));
    assert!(device.is_dir(&w(r"C:\Windows")).unwrap());
    assert_eq!(device.canonical(&w(r"\\.\C:\Windows")).unwrap(), w(r"C:\Windows"));
    let files = windows::FakeFilesystem::new()
        .with_file(&w(r"C:\a"))
        .with_file(&w(r"\\.\C:\b"));
    assert!(!files.same_file(&w(r"C:\a"), &w(r"\\.\C:\b")).unwrap());

    let unc = windows::FakeFilesystem::new().with_dir(&w(r"\\srv\share\d"));
    for q in [
        r"\\.\UNC\srv\share\d",
        "//./UNC/srv/share/d",
        r"\\.\unc\srv\share\d",
        r"\\.\UNC\\srv\share\d",
    ] {
        assert!(unc.is_dir(&w(q)).unwrap(), "{q}");
        assert_eq!(unc.canonical(&w(q)).unwrap(), w(r"\\srv\share\d"), "{q}");
    }
    assert!(unc.is_dir(&w(r"\\.\UNC\srv\share")).unwrap());
    assert!(!unc.is_dir(&w(r"\\.\UNC")).unwrap());
    assert!(!unc.is_dir(&w(r"\\.\UNC\")).unwrap());
    // A server `?` has no plain spelling: the path stays a device entry, and nothing panics.
    let odd = windows::FakeFilesystem::new().with_dir(&w(r"\\.\UNC\?\x"));
    assert!(odd.is_dir(&w(r"\\.\UNC\?\x")).unwrap());
}

/// The empty path is `InvalidInput` from every question on the Windows fake, as on the Windows
/// host (`to_wide` refuses it), and absent on the POSIX fake, as on a Unix host.
///
/// Mutants: a Windows fake that answers `Ok(false)` or `NotFound` for the empty path; one that
/// checks only one of the questions or one path of `same_file`; a POSIX fake that refuses it.
#[skuld::test]
fn the_empty_path_is_as_the_host_reads_it() {
    let fs = windows::FakeFilesystem::new().with_file(&w(r"bin\tool.exe"));
    let empty = w("");
    assert_eq!(kind(fs.is_file(&empty)), ErrorKind::InvalidInput);
    assert_eq!(kind(fs.is_dir(&empty)), ErrorKind::InvalidInput);
    assert_eq!(kind(fs.canonical(&empty)), ErrorKind::InvalidInput);
    assert_eq!(kind(fs.same_file(&empty, &w("bin"))), ErrorKind::InvalidInput);
    assert_eq!(kind(fs.same_file(&w("bin"), &empty)), ErrorKind::InvalidInput);

    let fs = posix::FakeFilesystem::new().with_file(p("bin/tool"));
    assert!(!fs.is_file(p("")).unwrap());
    assert!(!fs.is_dir(p("")).unwrap());
    assert_eq!(kind(fs.canonical(p(""))), ErrorKind::NotFound);
    assert_eq!(kind(fs.same_file(p(""), p("bin"))), ErrorKind::NotFound);
}

// An error below a file is refused in either order, as a file over an entry is: the same
// facts do not get two answers.
//
// Mutant: `with_error` or `with_unreadable_dir` that does not look at its ancestors.

#[skuld::test]
#[should_panic(expected = "is a file")]
fn an_error_under_a_stated_file_is_refused_posix() {
    let _ = posix::FakeFilesystem::new()
        .with_file(p("/a"))
        .with_error(p("/a/b"), ErrorKind::PermissionDenied);
}

#[skuld::test]
#[should_panic(expected = "is a file")]
fn an_error_under_a_stated_file_is_refused_windows() {
    let _ = windows::FakeFilesystem::new()
        .with_file(&w(r"C:\a"))
        .with_error(&w(r"C:\a\b"), ErrorKind::PermissionDenied);
}

#[skuld::test]
#[should_panic(expected = "has entries below it")]
fn a_file_over_a_stated_error_is_refused() {
    let _ = posix::FakeFilesystem::new()
        .with_error(p("/a/b"), ErrorKind::PermissionDenied)
        .with_file(p("/a"));
}

#[skuld::test]
#[should_panic(expected = "is a file")]
fn an_unreadable_dir_under_a_stated_file_is_refused() {
    let _ = posix::FakeFilesystem::new()
        .with_file(p("/a"))
        .with_unreadable_dir(p("/a/b"), ErrorKind::PermissionDenied);
}

/// An error on a path beside a file, or on the file itself, is no contradiction.
///
/// Mutant: an ancestor check that also fires on the path itself or its siblings.
#[skuld::test]
fn an_error_beside_or_on_a_file_is_accepted() {
    let fs = posix::FakeFilesystem::new()
        .with_file(p("/a"))
        .with_error(p("/b"), ErrorKind::PermissionDenied)
        .with_error(p("/a"), ErrorKind::PermissionDenied);
    assert_eq!(kind(fs.is_file(p("/a"))), ErrorKind::PermissionDenied);
}

/// `canonical` of a UNC share root has no trailing separator, as on the host
/// (`\\localhost\C$`), whichever way the root is stated or queried.
///
/// Mutant: a fake that returns its internal key, which spells the root with a separator.
#[skuld::test]
fn canonical_of_a_unc_share_root_has_no_trailing_separator() {
    let canonical = |fs: &windows::FakeFilesystem, query: &str| {
        let spelled = fs.canonical(&w(query)).unwrap();
        spelled.to_str().expect("the spelling is UTF-8").to_owned()
    };
    for fs in [
        windows::FakeFilesystem::new().with_dir(&w(r"\\srv\share")),
        windows::FakeFilesystem::new().with_dir(&w(r"\\srv\share\")),
        windows::FakeFilesystem::new().with_file(&w(r"\\srv\share\a")),
    ] {
        for query in [r"\\srv\share", r"\\srv\share\", r"\\srv\share\.", "//srv/share/"] {
            assert_eq!(canonical(&fs, query), r"\\srv\share", "{query}");
        }
        assert!(fs.same_file(&w(r"\\srv\share"), &w(r"\\srv\share\")).unwrap());
    }
    // Below the root nothing changes.
    let fs = windows::FakeFilesystem::new().with_dir(&w(r"\\srv\share\d"));
    assert_eq!(canonical(&fs, r"\\srv\share\d\"), r"\\srv\share\d");
}

/// `BoundPath` is two shared references: `Clone`, `Copy` and `Debug` whatever `F` is, trait
/// objects included. The fakes are `Clone` and `Debug`; a clone is independent of its source.
///
/// Mutants: derives on `BoundPath` (which demand `F: Clone`, so a `dyn Filesystem` does not
/// qualify); a `Clone` of a fake that shares its entries; a `Debug` that omits the statements.
#[skuld::test]
fn bound_paths_and_fakes_are_clone_and_debug() {
    fn bounds<T: Clone + Copy + std::fmt::Debug>() {}
    bounds::<BoundPath<'static, dyn Filesystem<Path = posix::Path>>>();
    bounds::<BoundPath<'static, dyn Filesystem<Path = windows::Path>>>();
    bounds::<BoundPath<'static, windows::FakeFilesystem>>();
    #[cfg(any(unix, windows))]
    bounds::<BoundPath<'static, crate::fs::HostFilesystem>>();

    let file = p("/d/f");
    let fs = posix::FakeFilesystem::new().with_file(file);
    let dynamic: &dyn Filesystem<Path = posix::Path> = &fs;
    let bound = BoundPath::new(dynamic, file);
    let copy = bound;
    assert!(bound.is_file().unwrap() && copy.is_file().unwrap());
    assert!(format!("{bound:?}").contains("/d/f"), "{bound:?}");

    let base = posix::FakeFilesystem::new().with_dir(p("/d"));
    let more = base.clone().with_file(p("/d/f"));
    assert!(more.is_file(p("/d/f")).unwrap());
    assert!(!base.is_file(p("/d/f")).unwrap());
    assert!(base.is_dir(p("/d")).unwrap());
    let shown = format!("{more:?}");
    assert!(shown.contains("/d/f"), "{shown}");
    let win = windows::FakeFilesystem::new().with_file(&w(r"C:\x"));
    let (cloned, shown) = (win.clone(), format!("{win:?}"));
    assert!(cloned.is_file(&w(r"C:\x")).unwrap());
    assert!(shown.contains("x"), "{shown}");
}
