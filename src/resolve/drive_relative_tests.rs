//! A drive-relative name (`E:tool`): the directory [`drive_base`] chooses for it, and the name
//! [`resolve`] makes of it. Every test states the child's directory, the reader of its per-drive
//! directories and the comparison of drives, so none reads this process's cwd or environment, and
//! all run on any host.

use std::cell::RefCell;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use super::drive_base;
use crate::error::Error;
use crate::resolve::resolve_tests::assert_refused_on_shape;
use crate::resolve::{ascii_same_drive, join, no_system_dirs, resolve, ResolveInput};

skuld::default_labels!(crate::test_harness::ROOT);

const CWD: &str = r"D:\cosca-149\work";

/// What [`drive_base`] made of `name` for a child running in `cwd`, whose directory on a drive is
/// `dirs`' answer: the completed path, and the drives the reader was asked about.
fn complete_with(
    name: &str,
    cwd: &str,
    dirs: &[(&str, &str)],
    same_drive: &dyn Fn(&OsStr, &OsStr) -> bool,
) -> (PathBuf, Vec<OsString>) {
    let asked = RefCell::new(Vec::new());
    let (base, rest) = drive_base(OsStr::new(name), Path::new(cwd), same_drive, |drive| {
        asked.borrow_mut().push(drive.to_os_string());
        Ok(dirs
            .iter()
            .find(|(d, _)| drive.eq_ignore_ascii_case(d))
            .map(|(_, dir)| OsString::from(dir)))
    })
    .unwrap();
    let path = PathBuf::from(join::append(base.path().as_os_str(), rest, "\\"));
    (path, asked.into_inner())
}

fn complete(name: &str, cwd: &str, dirs: &[(&str, &str)]) -> (PathBuf, Vec<OsString>) {
    complete_with(name, cwd, dirs, &ascii_same_drive)
}

/// On the drive of the child's directory the rest is appended to that directory, whatever the
/// drive's own directory holds, in either case of the letter. That directory is not asked for.
#[skuld::test]
fn on_the_childs_drive_the_name_is_appended_to_its_directory() {
    for (name, want) in [
        ("D:tool", r"D:\cosca-149\work\tool"),
        ("d:tool", r"D:\cosca-149\work\tool"),
        (r"D:sub\tool", r"D:\cosca-149\work\sub\tool"),
        (r"D:..\tool", r"D:\cosca-149\work\..\tool"),
    ] {
        let (path, asked) = complete(name, CWD, &[("D:", r"D:\cosca-149\elsewhere")]);
        assert_eq!(path, PathBuf::from(want), "{name}");
        assert_eq!(asked, Vec::<OsString>::new(), "{name}");
    }
}

/// On another drive the rest is appended to the child's own directory there, asked for once.
#[skuld::test]
fn on_another_drive_the_name_is_appended_to_the_childs_directory_there() {
    for (name, want) in [
        ("E:tool", r"E:\cosca-149\e\tool"),
        ("e:tool", r"E:\cosca-149\e\tool"),
        (r"E:sub\tool", r"E:\cosca-149\e\sub\tool"),
    ] {
        let (path, asked) = complete(name, CWD, &[("E:", r"E:\cosca-149\e")]);
        assert_eq!(path, PathBuf::from(want), "{name}");
        assert_eq!(asked.len(), 1, "{name}: asked once");
        assert_eq!(asked[0].to_ascii_uppercase(), "E:", "{name}");
    }
}

/// With no directory there, the drive's root. Which directory is usable is the reader's rule, not
/// the policy's.
#[skuld::test]
fn on_another_drive_without_a_directory_the_name_is_appended_to_the_root() {
    assert_eq!(complete(r"E:sub\tool", CWD, &[]).0, PathBuf::from(r"E:\sub\tool"));
}

/// A child directory with no drive, a UNC or a verbatim one, is on none: every drive-relative name
/// asks the reader, even one spelling the drive a verbatim directory names.
#[skuld::test]
fn a_child_directory_with_no_drive_is_on_none() {
    for cwd in [r"\\srv\shr\d", r"\\?\UNC\srv\shr\d", r"\\?\D:\work"] {
        let (path, asked) = complete("D:tool", cwd, &[("D:", r"D:\cosca-149\d")]);
        assert_eq!(path, PathBuf::from(r"D:\cosca-149\d\tool"), "{cwd}");
        assert_eq!(asked, [OsString::from("D:")], "{cwd}");
        assert_eq!(complete("D:tool", cwd, &[]).0, PathBuf::from(r"D:\tool"), "{cwd}");
    }
}

/// A reader that fails fails the completion with its error; a name on the child's own drive never
/// reaches it.
#[skuld::test]
fn a_failing_reader_fails_the_completion() {
    let failing = |_: &OsStr| Err(Error::Io(std::io::Error::other("no reading")));
    match drive_base(OsStr::new("E:tool"), Path::new(CWD), &ascii_same_drive, failing) {
        Err(Error::Io(e)) => assert_eq!(e.to_string(), "no reading"),
        Err(other) => panic!("the reader's own error is the answer, got {other:?}"),
        Ok(_) => panic!("a reader that fails fails the completion"),
    }
    assert!(drive_base(OsStr::new("D:tool"), Path::new(CWD), &ascii_same_drive, failing).is_ok());
}

/// Nothing else is a source: a child on another drive with no `=C:` of its own gets the root of
/// `C:`, not any directory of this process, which the policy cannot reach.
#[skuld::test]
fn this_processs_state_is_not_a_source() {
    assert_eq!(complete("C:tool", CWD, &[]).0, PathBuf::from(r"C:\tool"));
}

/// Any one unit before the `:` is a drive: `1:tool` is read against drive `1`.
#[skuld::test]
fn a_digit_is_a_drive() {
    let (path, asked) = complete("1:tool", CWD, &[("1:", r"C:\cosca-149\one")]);
    assert_eq!(path, PathBuf::from(r"C:\cosca-149\one\tool"));
    assert_eq!(asked, [OsString::from("1:")]);
    let (path, _) = complete("1:tool", r"1:\cosca-149\work", &[("1:", r"C:\cosca-149\one")]);
    assert_eq!(path, PathBuf::from(r"1:\cosca-149\work\tool"));
}

/// Whether two drives are one is the comparator's answer, not a table of this module's: with a
/// comparator that equates `é:` and `É:` they are the child's drive, with an ASCII one they are two.
#[skuld::test]
fn the_drive_comparison_is_the_one_given() {
    let accents = |a: &OsStr, b: &OsStr| a == b || (a == "é:" && b == "É:") || (a == "É:" && b == "é:");
    let cwd = r"É:\cosca-149\work";
    let dirs = [("é:", r"C:\cosca-149\e")];
    let (path, asked) = complete_with("é:tool", cwd, &dirs, &accents);
    assert_eq!(path, PathBuf::from(r"É:\cosca-149\work\tool"));
    assert!(asked.is_empty());
    let (path, asked) = complete_with("é:tool", cwd, &dirs, &ascii_same_drive);
    assert_eq!(path, PathBuf::from(r"C:\cosca-149\e\tool"));
    assert_eq!(asked, [OsString::from("é:")]);
}

/// What [`resolve`] made of `name` for a child running in `cwd`, with the names handed to
/// `normalise` and to the reader. `normalise` answers `answer`.
struct Run {
    got: Result<PathBuf, Error>,
    normalised: Vec<PathBuf>,
    asked: Vec<OsString>,
}

fn run(name: &str, cwd: &str, dirs: &[(&str, &str)], answer: &dyn Fn(&Path) -> std::io::Result<PathBuf>) -> Run {
    let normalised = RefCell::new(Vec::new());
    let asked = RefCell::new(Vec::new());
    let normalise = |p: &Path| {
        normalised.borrow_mut().push(p.to_path_buf());
        answer(p)
    };
    let reader = |drive: &OsStr| {
        asked.borrow_mut().push(drive.to_os_string());
        dirs.iter()
            .find(|(d, _)| drive.eq_ignore_ascii_case(d))
            .map(|(_, dir)| OsString::from(dir))
    };
    let got = resolve(ResolveInput {
        program: Path::new(name),
        cwd: Some(Path::new(cwd)),
        system_dirs: &no_system_dirs,
        path_var: None,
        windows: true,
        loadable_only: false,
        normalise: &normalise,
        child_drive_dir: &reader,
        same_drive: &ascii_same_drive,
    });
    Run {
        got,
        normalised: normalised.into_inner(),
        asked: asked.into_inner(),
    }
}

/// `normalise` answers a path that names no file, which ends the search with a refusal.
fn names_no_file(_: &Path) -> std::io::Result<PathBuf> {
    Ok(PathBuf::from(r"\\?\UNC\srv\shr\"))
}

/// A name that names no file is refused on its shape before the reader or `normalise` is reached.
#[skuld::test]
fn a_drive_relative_name_that_names_no_file_is_refused_before_anything_is_read() {
    for name in ["E:", "E:.", "E:..", r"E:sub\", "D:", "D:."] {
        let run = run(name, CWD, &[("E:", r"E:\cosca-149\e")], &names_no_file);
        assert_refused_on_shape(name, run.got);
        assert!(run.normalised.is_empty() && run.asked.is_empty(), "{name}");
    }
}

/// The reader is asked only for a drive-relative name on another drive: not for any other name, and
/// not for one on the child's own drive.
#[skuld::test]
fn the_reader_is_not_asked_for_any_other_name() {
    for name in [
        "tool",
        r"sub\tool",
        r"E:\abs\tool.exe",
        r"\rooted\tool",
        r"\\srv\shr\tool",
        r"D:\tool",
        "D:tool",
    ] {
        let run = run(name, CWD, &[], &|p| Ok(p.to_path_buf()));
        assert!(run.asked.is_empty(), "{name}");
    }
}

/// A completed name is not handed to `normalise`, which only a located name on a verbatim base is: a
/// drive-relative name's base never is, so a trailing dot or space of its own is not trimmed first
/// (`C:tool.` is `.\tool.`, not `tool`).
#[skuld::test]
fn a_completed_name_is_never_handed_to_normalise() {
    for name in [
        "D:tool",
        "D:tool.",
        "D:tool ",
        r"D:sub.\tool",
        "E:tool",
        "E:tool.",
        r"E:sub.\tool",
    ] {
        let run = run(name, CWD, &[("E:", r"E:\cosca-149\e")], &|p| Ok(p.to_path_buf()));
        assert!(run.normalised.is_empty(), "{name}: {:?}", run.normalised);
    }
}
