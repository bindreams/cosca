use std::io::ErrorKind;

use crate::fs::Filesystem;
use crate::posix::{FakeFilesystem, Path};

fn p(s: &str) -> &Path {
    Path::new(s)
}

fn kind<T: std::fmt::Debug>(r: std::io::Result<T>) -> ErrorKind {
    r.expect_err("expected an error").kind()
}

/// Whether building the state panics.
fn panics(build: impl FnOnce() -> FakeFilesystem) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(build)).is_err()
}

/// A `.` or `..` after a name is a lookup inside that directory, so it needs the permission to search
/// it, which `name/` does not. Measured on glibc 2.41 as uid 1000 with `chmod 000 locked`:
/// `stat(locked/)` is fine and `stat(locked/.)` and `stat(locked/..)` are `EACCES`; `realpath` takes
/// `.` and `..` lexically, so `realpath(locked/.)` is `/tmp/locked` and `realpath(locked/..)` is `/tmp`,
/// but `realpath(locked/sub)` is `EACCES`.
///
/// Mutants: a lookup that reads `locked/.` as `locked/`; one that checks the visited directory of a
/// `..` for `canonical` too; one that does not check it for the other questions.
#[skuld::test]
fn a_dot_or_dotdot_inside_an_unreadable_directory_needs_search_permission() {
    let fs = FakeFilesystem::new()
        .with_unreadable_dir(p("/tmp/locked"), ErrorKind::PermissionDenied)
        .with_dir(p("/tmp/d"))
        .with_file(p("/tmp/f"));

    // The name alone, with or without a trailing separator, is fine.
    for ok in ["/tmp/locked", "/tmp/locked/"] {
        assert!(fs.is_dir(p(ok)).unwrap(), "{ok}");
        assert!(!fs.is_file(p(ok)).unwrap(), "{ok}");
        assert_eq!(fs.canonical(p(ok)).unwrap(), p("/tmp/locked").to_path_buf(), "{ok}");
    }
    // `.` and `..` inside it are not, for every question that opens the path.
    for denied in [
        "/tmp/locked/.",
        "/tmp/locked/./",
        "/tmp/locked/..",
        "/tmp/locked/../",
        "/tmp/locked/../d",
        "/tmp/locked/../f",
    ] {
        assert_eq!(kind(fs.is_dir(p(denied))), ErrorKind::PermissionDenied, "{denied}");
        assert_eq!(kind(fs.is_file(p(denied))), ErrorKind::PermissionDenied, "{denied}");
        assert_eq!(
            kind(fs.same_file(p(denied), p("/tmp"))),
            ErrorKind::PermissionDenied,
            "{denied}"
        );
    }
    // `canonical` resolves them lexically, as `realpath` does, so it does not need the permission.
    for (query, canonical) in [
        ("/tmp/locked/.", "/tmp/locked"),
        ("/tmp/locked/./", "/tmp/locked"),
        ("/tmp/locked/..", "/tmp"),
        ("/tmp/locked/../d", "/tmp/d"),
        ("/tmp/locked/../f", "/tmp/f"),
    ] {
        assert_eq!(fs.canonical(p(query)).unwrap(), p(canonical).to_path_buf(), "{query}");
    }
    // Below it, `canonical` is denied too.
    assert_eq!(kind(fs.canonical(p("/tmp/locked/sub"))), ErrorKind::PermissionDenied);
    assert_eq!(kind(fs.canonical(p("/tmp/locked/./sub"))), ErrorKind::PermissionDenied);
}

/// A `..` is a lookup inside the directory before it, so that has to exist and be a directory (the
/// kernel says `ENOENT` and `ENOTDIR`), and the answer is about the parent, with no `..` left in
/// `canonical`. Measured on glibc 2.41: `d/s/..` is the directory `d`; `missing/..`, `d/missing/../s`
/// are `ENOENT`; `f/.`, `f/..`, `f/../d` are `ENOTDIR` for `stat` and `realpath` alike.
///
/// Mutants: a `..` kept as a name (the entry is absent); one resolved lexically with no check of the
/// directory it leaves (`missing/../d` is the directory); `canonical` that returns the query.
#[skuld::test]
fn a_dotdot_resolves_against_the_directory_it_leaves() {
    let fs = FakeFilesystem::new()
        .with_dir(p("/a/b"))
        .with_file(p("/a/f"))
        .with_dir(p("/d/s"));

    for dir in [
        "/a/b/..",
        "/a/b/../",
        "/a/b/../b",
        "/a/b/./..",
        "/d/s/../s",
        "/d/s/../../a/b",
    ] {
        assert!(fs.is_dir(p(dir)).unwrap(), "{dir}");
        assert!(!fs.is_file(p(dir)).unwrap(), "{dir}");
    }
    assert_eq!(fs.canonical(p("/a/b/..")).unwrap(), p("/a").to_path_buf());
    assert_eq!(fs.canonical(p("/d/s/../../a/b")).unwrap(), p("/a/b").to_path_buf());
    assert!(fs.is_file(p("/a/b/../f")).unwrap());
    assert!(fs.same_file(p("/a/b/.."), p("/a")).unwrap());
    assert!(fs.same_file(p("/a/b/../f"), p("/a/f")).unwrap());
    assert!(!fs.same_file(p("/a/b/.."), p("/d")).unwrap());

    // The directory before the `..` must exist and be a directory.
    for absent in [
        "/a/missing/..",
        "/a/missing/../b",
        "/a/f/..",
        "/a/f/../b",
        "/a/f/.",
        "/a/f/./",
        "/d/missing/../s",
    ] {
        assert!(!fs.is_dir(p(absent)).unwrap(), "{absent}");
        assert!(!fs.is_file(p(absent)).unwrap(), "{absent}");
        assert_eq!(kind(fs.canonical(p(absent))), ErrorKind::NotFound, "{absent}");
        assert_eq!(kind(fs.same_file(p(absent), p("/a"))), ErrorKind::NotFound, "{absent}");
    }
    // The root is its own parent.
    assert!(fs.is_dir(p("/a/../..")).unwrap());
    assert_eq!(fs.canonical(p("/a/../..")).unwrap(), p("/").to_path_buf());
}

/// A `..` after a stated link goes through the link's target on a real filesystem, which the fake
/// does not follow for anything but `canonical`'s own answer, so it refuses rather than answer for
/// the wrong directory. Without a link on the path it is lexical.
///
/// Mutants: a `..` resolved lexically below a link (`/bin/..` would be `/`, where the host says the
/// parent of `/usr/bin`); a refusal for every `..`.
#[skuld::test]
fn a_dotdot_below_a_stated_link_is_refused() {
    let fs = FakeFilesystem::new()
        .with_dir(p("/bin"))
        .with_dir(p("/bin/sub"))
        .with_dir(p("/usr/bin"))
        .with_canonical(p("/bin"), p("/usr/bin"));
    for below in ["/bin/..", "/bin/sub/..", "/bin/../usr"] {
        assert_eq!(kind(fs.is_dir(p(below))), ErrorKind::InvalidInput, "{below}");
        assert_eq!(kind(fs.canonical(p(below))), ErrorKind::InvalidInput, "{below}");
    }
    // Beside the link, and below it with no `..`, nothing changes.
    assert!(fs.is_dir(p("/usr/bin/..")).unwrap());
    assert_eq!(fs.canonical(p("/usr/bin/..")).unwrap(), p("/usr").to_path_buf());
    assert_eq!(fs.canonical(p("/bin/sub")).unwrap(), p("/bin/sub").to_path_buf());
}

/// The current directory is always there, as is every ancestor of it: `.`, `..` and `../..` are
/// directories on any host, whatever the test stated. Stating them changes nothing, and a stated
/// error still covers them. A name below one is stated like any other relative name.
///
/// Mutants: a fake that finds `.` absent; one that finds `..` absent; one where a stated error on
/// `.` does not apply.
#[skuld::test]
fn the_current_directory_and_its_ancestors_exist() {
    let fs = FakeFilesystem::new();
    for dir in [".", "./", "./.", "..", "../", "../..", ".././.."] {
        assert!(fs.is_dir(p(dir)).unwrap(), "{dir}");
        assert!(!fs.is_file(p(dir)).unwrap(), "{dir}");
        assert!(fs.same_file(p(dir), p(dir)).unwrap(), "{dir}");
    }
    // The empty path names nothing, and a name below the current directory exists only if stated.
    assert!(!fs.is_dir(p("")).unwrap());
    assert!(!fs.is_dir(p("a")).unwrap());
    assert!(!fs.is_dir(p("../a")).unwrap());

    let fs = FakeFilesystem::new().with_file(p("../x")).with_dir(p("."));
    assert!(fs.is_file(p("../x")).unwrap());
    assert!(fs.is_dir(p("..")).unwrap());
    assert!(fs.is_dir(p(".")).unwrap());
    let fs = FakeFilesystem::new().with_error(p("."), ErrorKind::PermissionDenied);
    assert_eq!(kind(fs.is_dir(p("."))), ErrorKind::PermissionDenied);
    assert_eq!(kind(fs.is_dir(p("./."))), ErrorKind::PermissionDenied);
}

/// What a relative path names depends on the current directory, which the fake has no value for. So
/// `canonical` of one that exists (which the host answers with an absolute path) is refused, and so
/// is `same_file` of two paths that might be one file through the current directory: a relative and an
/// absolute path, or a path that starts with `..` and another. A path that is absent is `NotFound`
/// whatever the current directory is, and a stated link says what `canonical` is.
///
/// Mutants: a `canonical` that returns the relative spelling; a `same_file` that says `false` for a
/// relative path and an absolute one; a refusal of an absent relative path.
#[skuld::test]
fn a_relative_path_has_no_canonical_form_and_no_identity_against_an_absolute_one() {
    let fs = FakeFilesystem::new()
        .with_file(p("bin/tool"))
        .with_file(p("bin/other"))
        .with_file(p("/abs/tool"))
        .with_file(p("/abs/other"))
        .with_file(p("../up"))
        .with_canonical(p("bin/other"), p("/abs/other"));

    for exists in ["bin/tool", "bin", ".", "..", "./bin/../bin", "../up"] {
        assert_eq!(kind(fs.canonical(p(exists))), ErrorKind::InvalidInput, "{exists}");
    }
    assert_eq!(kind(fs.canonical(p("bin/missing"))), ErrorKind::NotFound);
    assert_eq!(kind(fs.canonical(p(""))), ErrorKind::NotFound);
    assert_eq!(fs.canonical(p("bin/other")).unwrap(), p("/abs/other").to_path_buf());

    // The same spelling is the same file, and two relative names that are not the same are two
    // files; but a relative name and an absolute one, or two with a `..`, are for the host to say.
    assert!(fs.same_file(p("bin/tool"), p("./bin/tool")).unwrap());
    assert!(fs.same_file(p("../up"), p("../up")).unwrap());
    assert!(!fs.same_file(p("bin/tool"), p("bin/./")).unwrap());
    assert_eq!(
        kind(fs.same_file(p("bin/tool"), p("/abs/tool"))),
        ErrorKind::InvalidInput
    );
    assert_eq!(
        kind(fs.same_file(p("/abs/tool"), p("bin/tool"))),
        ErrorKind::InvalidInput
    );
    assert_eq!(kind(fs.same_file(p("../up"), p("bin/tool"))), ErrorKind::InvalidInput);
    assert_eq!(kind(fs.same_file(p("."), p(".."))), ErrorKind::InvalidInput);
    // Absent is `NotFound` before anything else.
    assert_eq!(
        kind(fs.same_file(p("bin/missing"), p("/abs/tool"))),
        ErrorKind::NotFound
    );
    // A link resolves both to absolute paths.
    assert!(!fs.same_file(p("bin/other"), p("/abs/tool")).unwrap());
    assert!(fs.same_file(p("bin/other"), p("/abs/other")).unwrap());
}

/// A file cannot be stated at a name that only a directory has: the root, `.`, a final `..` and what
/// they resolve to (`/a/..` is the root, `a/..` is the current directory), as well as a trailing
/// separator or `.` (`/a/.`).
///
/// Mutants: a builder that checks the spelling's end only (so `/a/..` states a file at `/`); one
/// that checks only the root.
#[skuld::test]
fn a_file_at_a_name_only_a_directory_has_is_refused() {
    for name in [
        "/",
        "//",
        ".",
        "..",
        "a/..",
        "/a/..",
        "/a/b/../..",
        "../..",
        "/a/",
        "/a/.",
        "a/./",
    ] {
        assert!(
            panics(|| FakeFilesystem::new().with_file(p(name))),
            "a file at {name:?} was accepted"
        );
    }
    // A name below one is fine, and so is a directory at each of them.
    let fs = FakeFilesystem::new().with_file(p("/a/b/../c")).with_file(p("../x"));
    assert!(fs.is_file(p("/a/c")).unwrap());
    for name in ["/", ".", "..", "/a/.."] {
        let _ = FakeFilesystem::new().with_dir(p(name));
    }
}
