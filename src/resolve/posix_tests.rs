//! [`lookup`]: the rules of the module doc, one test each.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::*;

fn plant(dir: &Path, name: &str, mode: u32) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, b"x").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

/// [`super::lookup`], keeping the match only.
fn lookup(program: &Path, cwd: Option<&Path>, path_var: Option<&OsStr>) -> Result<PathBuf, Error> {
    super::lookup(program, cwd, path_var).map(|found| found.path)
}

fn path_of(dirs: &[&Path]) -> OsString {
    std::env::join_paths(dirs).unwrap()
}

/// A directory entry that cannot be examined, `ELOOP` for every uid: a symlink to itself.
fn looping_entry(root: &Path) -> PathBuf {
    let entry = root.join("loop");
    std::os::unix::fs::symlink("loop", &entry).unwrap();
    entry
}

fn kind_of(result: Result<PathBuf, Error>) -> std::io::ErrorKind {
    match result {
        Err(Error::Io(e)) => e.kind(),
        other => panic!("expected an I/O error, got {other:?}"),
    }
}

/// The first file that exists is the match, with or without the execute bit.
///
/// Mutant: a candidate is skipped when it is not executable.
#[skuld::test]
fn a_file_without_the_execute_bit_is_the_match() {
    let cwd = tempfile::tempdir().unwrap();
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let dud = plant(first.path(), "tool", 0o644);
    plant(second.path(), "tool", 0o755);
    let path = path_of(&[first.path(), second.path()]);
    assert_eq!(lookup(Path::new("tool"), Some(cwd.path()), Some(&path)).unwrap(), dud);
}

/// A located name is the one file it names, whatever its mode.
///
/// Mutant: the execute bit is checked for a located name.
#[skuld::test]
fn a_located_file_without_the_execute_bit_is_the_match() {
    let dir = tempfile::tempdir().unwrap();
    let dud = plant(dir.path(), "tool", 0o600);
    assert_eq!(lookup(&dud, None, None).unwrap(), dud);
    assert_eq!(
        lookup(Path::new("./tool"), Some(dir.path()), None).unwrap(),
        Path::new("./tool")
    );
}

/// A child with no `PATH` searches nothing: not the system's default path. `sh` is in every default
/// path.
///
/// Mutant: an unset `PATH` searches `confstr(_CS_PATH)`.
#[skuld::test]
fn an_unset_path_searches_nothing() {
    let cwd = tempfile::tempdir().unwrap();
    assert_eq!(
        kind_of(lookup(Path::new("sh"), Some(cwd.path()), None)),
        std::io::ErrorKind::NotFound
    );
}

/// An empty element is not the working directory, and a relative one is skipped: `Cargo.toml` is in
/// the working directory of every test of this package, and in the child's directory too.
///
/// Mutants: an empty or relative element is joined and probed against this process's working
/// directory; against the child's directory.
#[skuld::test]
fn empty_and_relative_path_elements_are_skipped() {
    assert!(
        Path::new("Cargo.toml").is_file(),
        "precondition: the test runs in the package root"
    );
    let cwd = tempfile::tempdir().unwrap();
    plant(cwd.path(), "Cargo.toml", 0o644);
    for path in ["", ":", ".", "./", ":.:", "../lookup-no-such-dir:."] {
        assert_eq!(
            kind_of(lookup(
                Path::new("Cargo.toml"),
                Some(cwd.path()),
                Some(OsStr::new(path))
            )),
            std::io::ErrorKind::NotFound,
            "PATH {path:?}"
        );
    }
}

/// An entry that cannot be examined stops the search with an error that names the entry and the
/// candidate, and carries the OS code (`ELOOP` here, the one failure no uid is exempt from) down its
/// `source()` chain, with the cause's kind kept.
///
/// Mutants: the entry is skipped with a warning; the error is the bare OS error, which names no entry.
#[skuld::test]
fn an_unexaminable_entry_stops_the_search_with_an_error_naming_it() {
    let root = tempfile::tempdir().unwrap();
    let looping = looping_entry(root.path());
    let open = root.path().join("open");
    std::fs::create_dir(&open).unwrap();
    plant(&open, "tool", 0o755);
    let cause = std::fs::metadata(looping.join("tool")).unwrap_err();
    assert_eq!(
        cause.raw_os_error(),
        Some(libc::ELOOP),
        "precondition: the entry cannot be examined"
    );

    let path = path_of(&[&looping, &open]);
    match lookup(Path::new("tool"), Some(root.path()), Some(&path)) {
        Err(error @ Error::Io(_)) => {
            let Error::Io(e) = &error else { unreachable!() };
            assert_eq!(e.kind(), cause.kind(), "{error:?}");
            assert_eq!(crate::error::first_os_code(&error), Some(libc::ELOOP), "{error:?}");
            let report = crate::error::Report(&error).to_string();
            for named in [&looping, &looping.join("tool")] {
                assert!(
                    report.contains(&format!("{named:?}")),
                    "{named:?} is not named: {report}"
                );
            }
        }
        other => panic!("the entry must stop the search: {other:?}"),
    }
}

/// A located name whose file cannot be examined has no `PATH` entry to name: the OS's own error
/// stops it, bare, with the code on the error and no cause below it, for a spawn's caller to branch on.
///
/// Mutant: a located name's error is wrapped as a searched name's is (no code on the error).
#[skuld::test]
fn an_unexaminable_located_name_keeps_the_os_error_bare() {
    let root = tempfile::tempdir().unwrap();
    looping_entry(root.path());
    match lookup(Path::new("loop/tool"), Some(root.path()), None) {
        Err(Error::Io(e)) => {
            assert_eq!(e.raw_os_error(), Some(libc::ELOOP), "{e:?}");
            assert!(std::error::Error::source(&e).is_none(), "{e:?}");
        }
        other => panic!("the located name must stop with the OS's error: {other:?}"),
    }
}

/// The errno of each kind of [`lookup`] error, as the elevation shim puts it on its wire: a stop's
/// down its `source()` chain, a located name's own, a miss's `ENOENT`, `EINVAL` for a name that names
/// no file.
///
/// Mutants: the code is read from the top error only (a stop has none); a miss or a refused name is
/// given another code.
#[cfg(target_os = "linux")]
#[skuld::test]
fn the_errno_of_a_lookup_error_is_its_code_down_the_chain_or_einval() {
    let root = tempfile::tempdir().unwrap();
    let looping = looping_entry(root.path());
    let open = root.path().join("open");
    std::fs::create_dir(&open).unwrap();
    let cwd = Some(root.path());
    let stop = super::lookup(Path::new("tool"), cwd, Some(&path_of(&[&looping, &open]))).unwrap_err();
    let located = super::lookup(Path::new("loop/tool"), cwd, None).unwrap_err();
    let miss = super::lookup(Path::new("tool"), cwd, Some(&path_of(&[&open]))).unwrap_err();
    let refused = super::lookup(Path::new("bin/"), cwd, None).unwrap_err();
    for (what, error, errno) in [
        ("a stop", &stop, libc::ELOOP),
        ("a located name's own error", &located, libc::ELOOP),
        ("a miss", &miss, libc::ENOENT),
        ("a name that names no file", &refused, libc::EINVAL),
    ] {
        assert_eq!(errno_of(error), errno, "{what}: {error:?}");
    }
}

/// A stop is no miss, whatever its cause's kind: only the search's own `NotFound`, which has no cause,
/// becomes `ENOENT`.
///
/// Mutant: any code-less `NotFound` is taken for a miss.
#[skuld::test]
fn a_stop_whose_cause_is_not_found_is_not_a_miss() {
    let cause = std::io::Error::new(std::io::ErrorKind::NotFound, "a cause that reads as a miss");
    let stop = Error::Io(crate::error::io_context("could not tell, so the search stops", cause));
    match miss_as_enoent(stop) {
        Error::Io(e) => {
            assert_eq!(e.raw_os_error(), None, "{e:?}");
            assert!(std::error::Error::source(&e).is_some(), "the cause was dropped: {e:?}");
        }
        other => panic!("expected the stop as it was, got {other:?}"),
    }
}

/// A miss carries `ENOENT` itself: a spawn's caller branches on the raw errno.
///
/// Mutant: a miss is a code-less `NotFound`.
#[skuld::test]
fn a_miss_is_enoent() {
    let bin = tempfile::tempdir().unwrap();
    let path = path_of(&[bin.path()]);
    match lookup(Path::new("tool"), Some(bin.path()), Some(&path)) {
        Err(Error::Io(e)) => assert_eq!(e.raw_os_error(), Some(libc::ENOENT), "{e:?}"),
        other => panic!("expected a miss, got {other:?}"),
    }
}

/// A definite absence goes on: a missing directory, and an entry that is a file (`ENOTDIR`).
///
/// Mutant: an absence ends the search.
#[skuld::test]
fn an_absent_or_non_directory_entry_is_skipped() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("missing");
    let file = plant(root.path(), "file", 0o755);
    let open = root.path().join("open");
    std::fs::create_dir(&open).unwrap();
    let tool = plant(&open, "tool", 0o755);
    let path = path_of(&[&missing, &file, &open]);
    assert_eq!(lookup(Path::new("tool"), Some(root.path()), Some(&path)).unwrap(), tool);
}

/// A directory is not a match, and the search goes on past it.
///
/// Mutant: existence, not being a file, is the test.
#[skuld::test]
fn a_directory_is_not_a_match() {
    let cwd = tempfile::tempdir().unwrap();
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    std::fs::create_dir(first.path().join("tool")).unwrap();
    let tool = plant(second.path(), "tool", 0o755);
    let path = path_of(&[first.path(), second.path()]);
    assert_eq!(lookup(Path::new("tool"), Some(cwd.path()), Some(&path)).unwrap(), tool);
}

/// A symlink is read through: one to nothing (dangling) and one to a directory name no file, and the
/// first existing file is the match; a symlink to a file is one.
///
/// Mutants: a dangling symlink is an error, or a match (`symlink_metadata`); a symlink to a
/// directory is a match.
#[skuld::test]
fn a_symlink_is_read_through_and_the_first_existing_file_is_the_match() {
    let cwd = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let dirs: Vec<PathBuf> = ["dangling", "to-a-dir", "to-a-file", "real"]
        .iter()
        .map(|name| root.path().join(name))
        .collect();
    for dir in &dirs {
        std::fs::create_dir(dir).unwrap();
    }
    let a_dir = root.path().join("a-dir");
    std::fs::create_dir(&a_dir).unwrap();
    let a_file = plant(root.path(), "a-file", 0o755);
    std::os::unix::fs::symlink(root.path().join("nothing"), dirs[0].join("tool")).unwrap();
    std::os::unix::fs::symlink(&a_dir, dirs[1].join("tool")).unwrap();
    std::os::unix::fs::symlink(&a_file, dirs[2].join("tool")).unwrap();
    let real = plant(&dirs[3], "tool", 0o755);
    let all = path_of(&dirs.iter().map(PathBuf::as_path).collect::<Vec<_>>());

    // The symlink to a file is the match, not the real file after it.
    assert_eq!(
        lookup(Path::new("tool"), Some(cwd.path()), Some(&all)).unwrap(),
        dirs[2].join("tool")
    );
    // Without it, the dangling symlink and the symlink to a directory are passed over.
    let without = path_of(&[&dirs[0], &dirs[1], &dirs[3]]);
    assert_eq!(
        lookup(Path::new("tool"), Some(cwd.path()), Some(&without)).unwrap(),
        real
    );
}

/// A bare name's match comes with the candidates after it, for a launch that finds the match gone: the
/// `PATH` elements after the match's, joined to the name, in order, the empty and relative ones left
/// out, none of them probed (a missing directory and a directory of the name stay in). A located name has
/// none.
///
/// Mutant: no later candidates; the elements before the match come too; a relative element is joined.
#[skuld::test]
fn a_bare_names_match_comes_with_the_candidates_after_it() {
    let root = tempfile::tempdir().unwrap();
    let before = root.path().join("before");
    let first = root.path().join("first");
    let missing = root.path().join("missing");
    let dir_of_the_name = root.path().join("dir-of-the-name");
    let last = root.path().join("last");
    for dir in [&before, &first, &dir_of_the_name, &last] {
        std::fs::create_dir(dir).unwrap();
    }
    std::fs::create_dir(dir_of_the_name.join("tool")).unwrap();
    plant(&first, "tool", 0o755);
    plant(&last, "tool", 0o755);
    let mut elements = vec![before.clone().into_os_string(), first.clone().into_os_string()];
    elements.extend(["".into(), "relative".into()]);
    elements.extend([missing.clone(), dir_of_the_name.clone(), last.clone()].map(PathBuf::into_os_string));
    let path = elements.join(OsStr::new(":"));

    let found = super::lookup(Path::new("tool"), Some(root.path()), Some(&path)).unwrap();
    assert_eq!(found.path, first.join("tool"));
    assert_eq!(found.entry.as_deref(), Some(first.as_path()));
    let after = |dir: &PathBuf| Candidate {
        path: dir.join("tool"),
        entry: Some(dir.clone()),
    };
    assert_eq!(found.later, [after(&missing), after(&dir_of_the_name), after(&last)]);

    let located = super::lookup(Path::new("./tool"), Some(&first), Some(&path)).unwrap();
    assert!(located.later.is_empty(), "{:?}", located.later);
    assert_eq!(located.entry, None, "a located name has no PATH element");
}

/// A located name is the one entry it names, whatever the entry is: a directory or a device is the
/// match, and starting it is the launch's own error, not a miss.
///
/// Mutant: a located name must name a regular file.
#[skuld::test]
fn a_located_name_that_names_a_non_file_is_the_match() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    assert_eq!(lookup(dir.path(), None, None).unwrap(), dir.path());
    assert_eq!(
        lookup(Path::new("/dev/null"), None, None).unwrap(),
        Path::new("/dev/null")
    );
    assert_eq!(
        lookup(Path::new("./sub"), Some(dir.path()), None).unwrap(),
        Path::new("./sub")
    );
}

/// A located name is read against the child's directory and answered as written, for the child to
/// read against that directory itself; a missing one is `NotFound`, and is not searched for in
/// `PATH`.
///
/// Mutants: a located name is searched; it is answered joined to the directory (wrong once the child
/// enters a relative one).
#[skuld::test]
fn a_located_name_is_read_against_the_childs_directory_and_never_searched() {
    let cwd = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    std::fs::create_dir(cwd.path().join("sub")).unwrap();
    plant(&cwd.path().join("sub"), "tool", 0o755);
    plant(bin.path(), "tool", 0o755);
    let path = path_of(&[bin.path()]);

    assert_eq!(
        lookup(Path::new("sub/tool"), Some(cwd.path()), Some(&path)).unwrap(),
        Path::new("sub/tool")
    );
    assert_eq!(
        kind_of(lookup(Path::new("other/tool"), Some(cwd.path()), Some(&path))),
        std::io::ErrorKind::NotFound
    );
}

/// A relative directory is read against the directory this process was started in, not joined to a
/// path of it: the answer is the name, whatever the directory.
///
/// Mutant: the relative directory is joined to the name.
#[skuld::test]
fn a_located_name_under_a_relative_directory_is_answered_as_written() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("sub");
    std::fs::create_dir(&dir).unwrap();
    plant(&dir, "tool", 0o755);
    let relative = pathdiff_from_current(&dir);
    assert_eq!(
        lookup(Path::new("./tool"), Some(&relative), None).unwrap(),
        Path::new("./tool")
    );
}

/// `dir` as a path relative to this process's directory.
fn pathdiff_from_current(dir: &Path) -> PathBuf {
    let here = std::env::current_dir().unwrap();
    let up = here.components().count() - 1;
    let mut relative: PathBuf = std::iter::repeat_n("..", up).collect();
    relative.push(dir.strip_prefix("/").unwrap());
    relative
}

/// A directory that is missing, or is not a directory, is the answer for a located name: its own
/// error, not the program's `NotFound`. A bare name and an absolute one are not read against it.
///
/// Mutant: the directory is not looked at, so a located name in it is a miss (`ENOENT` for both).
#[skuld::test]
fn a_directory_that_cannot_be_entered_is_its_own_error_for_a_located_name() {
    let root = tempfile::tempdir().unwrap();
    let file = plant(root.path(), "file", 0o755);
    let missing = root.path().join("missing");
    let bin = tempfile::tempdir().unwrap();
    let tool = plant(bin.path(), "tool", 0o755);
    let path = path_of(&[bin.path()]);

    match lookup(Path::new("./tool"), Some(&file), Some(&path)) {
        Err(Error::Io(e)) => assert_eq!(e.raw_os_error(), Some(libc::ENOTDIR), "{e:?}"),
        other => panic!("a file as the directory: {other:?}"),
    }
    match lookup(Path::new("./tool"), Some(&missing), Some(&path)) {
        Err(Error::Io(e)) => assert_eq!(e.raw_os_error(), Some(libc::ENOENT), "{e:?}"),
        other => panic!("a missing directory: {other:?}"),
    }
    // The program is found whatever the directory: the child's `chdir` reports it.
    assert_eq!(lookup(Path::new("tool"), Some(&missing), Some(&path)).unwrap(), tool);
    assert_eq!(lookup(&tool, Some(&missing), Some(&path)).unwrap(), tool);
}

/// A name with a NUL, and a name that names no file, are refused before any search.
///
/// Mutant: the NUL reaches the file system, or `""` is searched.
#[skuld::test]
fn a_name_that_cannot_name_a_file_is_invalid_input() {
    let bin = tempfile::tempdir().unwrap();
    let path = path_of(&[bin.path()]);
    for name in ["to\0ol", "", ".", "..", "bin/"] {
        assert_eq!(
            kind_of(lookup(Path::new(name), None, Some(&path))),
            std::io::ErrorKind::InvalidInput,
            "{name:?}"
        );
    }
    // With nothing to probe, only the check itself can refuse the NUL.
    assert_eq!(
        kind_of(lookup(Path::new("to\0ol"), None, Some(OsStr::new("")))),
        std::io::ErrorKind::InvalidInput
    );
}

/// A name that names no file is refused whatever the directory: a located one under a directory that
/// is missing, or no directory, is `InvalidInput`, not the directory's error.
///
/// Mutant: the directory is looked at before the name.
#[skuld::test]
fn a_name_that_names_no_file_is_refused_before_the_directory_is_looked_at() {
    let root = tempfile::tempdir().unwrap();
    let file = plant(root.path(), "file", 0o755);
    let missing = root.path().join("missing");
    for dir in [&missing, &file] {
        for name in ["sub/", "./", "sub/.", "sub/.."] {
            assert_eq!(
                kind_of(lookup(Path::new(name), Some(dir), None)),
                std::io::ErrorKind::InvalidInput,
                "{name:?} under {dir:?}"
            );
        }
    }
}
