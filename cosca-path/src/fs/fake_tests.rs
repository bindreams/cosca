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
/// Mutant: a `BoundPath` that asks about a different path than the one it holds.
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
    assert!(!fs.is_dir(&w("")).unwrap());

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
/// resolves `.` but not `..`.
///
/// Mutants: a fake that matches `.` and `..` as names; one that keeps the trailing separator a
/// final `.` or `..` leaves, so the file at `notepad.exe\.` is absent; one that resolves `..` on
/// POSIX.
#[skuld::test]
fn the_windows_fake_resolves_dots_and_the_posix_fake_resolves_only_the_single_dot() {
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

    // POSIX: `..` is physical, through links the fake does not model, so it is a name.
    let fs = posix::FakeFilesystem::new().with_dir(p("/a/b"));
    assert!(!fs.is_dir(p("/a/x/../b")).unwrap());
    assert!(!fs.is_dir(p("/a/b/..")).unwrap());
    assert!(fs.is_dir(p("/a/./b")).unwrap());
}

/// The POSIX fake reads `.` as the kernel does: `a/./b` is `a/b` whatever links `a` holds, so a
/// `PATH` entry `.` joined with `tool` finds `tool`. A final `.` names a directory, so it never
/// reaches a file. `..` is the one link-dependent component and stays a name.
///
/// Mutants: a fake that keeps `.` as a name; one that lets `tool/.` name the file; one that
/// drops `..` too; one that drops every `.`, so the empty path becomes a directory.
#[skuld::test]
fn the_posix_fake_reads_a_single_dot_as_the_host_does() {
    let fs = posix::FakeFilesystem::new()
        .with_file(p("tool"))
        .with_file(p("/usr/bin/tool"));
    for file in ["./tool", "././tool", ".//tool", "/usr/./bin/./tool", "/usr/bin/./tool"] {
        let expect = if file.starts_with('/') { "/usr/bin/tool" } else { "tool" };
        assert!(fs.is_file(p(file)).unwrap(), "{file}");
        assert_eq!(fs.canonical(p(file)).unwrap(), p(expect).to_path_buf(), "{file}");
    }
    // A final `.`, or a `.` before a trailing separator, demands a directory.
    for not_file in ["tool/.", "./tool/", "/usr/bin/tool/.", "/usr/bin/tool/./"] {
        assert!(!fs.is_file(p(not_file)).unwrap(), "{not_file}");
        assert!(!fs.is_dir(p(not_file)).unwrap(), "{not_file}");
    }
    for dir in ["/usr/bin/.", "/usr/bin/./", "/usr/./bin", "/.", "/./", "/usr/."] {
        assert!(fs.is_dir(p(dir)).unwrap(), "{dir}");
    }
    // The empty path stays absent; `.` is a directory only where the test states it.
    assert!(!fs.is_dir(p("")).unwrap());
    assert!(!fs.is_dir(p(".")).unwrap());
    let fs = posix::FakeFilesystem::new().with_dir(p("."));
    for dir in [".", "./", "./."] {
        assert!(fs.is_dir(p(dir)).unwrap(), "{dir}");
    }
    assert!(!fs.is_dir(p("")).unwrap());
    // `..` is still a name.
    let fs = posix::FakeFilesystem::new().with_dir(p("/a/b"));
    assert!(!fs.is_dir(p("/a/x/../b")).unwrap());
}

/// Drive-relative `C:` is the current directory of drive C, however it is spelled: `C:.`, `C:.\`,
/// `C:./` and `C:a\..\` all name it, and `canonical` of any of them is a fixed point.
///
/// Mutants: a lookup that strips the trailing separator of `C:.\` and keeps `C:.` as a second
/// key; a `canonical` that returns that second key.
#[skuld::test]
fn the_drive_relative_current_directory_has_one_key() {
    let fs = windows::FakeFilesystem::new().with_dir(&w("C:"));
    for dir in ["C:", "C:.", r"C:.\", "C:./", r"C:a\..\", r"C:.\.\", r"C:a\.."] {
        assert!(fs.is_dir(&w(dir)).unwrap(), "{dir}");
        assert!(!fs.is_file(&w(dir)).unwrap(), "{dir}");
        let once = fs.canonical(&w(dir)).unwrap();
        assert_eq!(once, w("C:"), "{dir}");
        assert_eq!(fs.canonical(&once).unwrap(), once, "{dir}");
    }
    assert!(!fs.is_dir(&w(r"C:\a\..\x")).unwrap());
    // Stated with the odd spelling, the plain one finds it.
    let fs = windows::FakeFilesystem::new().with_dir(&w(r"C:.\"));
    assert!(fs.is_dir(&w("C:")).unwrap());
    // The plain relative current directory is the same shape.
    let fs = windows::FakeFilesystem::new().with_dir(&w("."));
    for dir in [".", r".\", "./", r"a\..\"] {
        assert!(fs.is_dir(&w(dir)).unwrap(), "{dir}");
        assert_eq!(fs.canonical(&w(dir)).unwrap(), w("."), "{dir}");
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
