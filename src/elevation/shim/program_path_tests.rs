use std::cell::RefCell;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::super::protocol::Errno;
use super::{resolve, resolve_with, Candidate};

fn os(s: &str) -> OsString {
    OsString::from(s)
}

/// A probe that records what it is asked about and answers `Executable` for `executable`.
struct Recording {
    asked: RefCell<Vec<PathBuf>>,
    executable: Vec<PathBuf>,
}

impl Recording {
    fn new(executable: &[&str]) -> Recording {
        Recording {
            asked: RefCell::default(),
            executable: executable.iter().map(PathBuf::from).collect(),
        }
    }

    fn probe(&self) -> impl FnMut(&Path) -> Candidate + '_ {
        |path| {
            self.asked.borrow_mut().push(path.to_owned());
            if self.executable.iter().any(|e| e == path) {
                Candidate::Executable
            } else {
                Candidate::Missing
            }
        }
    }
}

#[skuld::test]
fn a_program_with_a_slash_is_used_as_given_and_an_empty_one_is_enoent() {
    let recording = Recording::new(&[]);
    for program in ["/bin/sh", "./tool", "dir/tool"] {
        assert_eq!(
            resolve_with(OsStr::new(program), Some(OsStr::new("/bin")), recording.probe()),
            Ok(os(program))
        );
    }
    assert_eq!(
        resolve_with(OsStr::new(""), Some(OsStr::new("/bin")), recording.probe()),
        Err(Errno(libc::ENOENT))
    );
    assert!(recording.asked.borrow().is_empty(), "nothing is searched for these");
}

#[skuld::test]
fn bare_name_is_searched_in_order_and_the_first_executable_wins() {
    let recording = Recording::new(&["/b/tool", "/c/tool"]);
    let found = resolve_with(OsStr::new("tool"), Some(OsStr::new("/a:/b:/c")), recording.probe());
    assert_eq!(found, Ok(os("/b/tool")));
    assert_eq!(
        *recording.asked.borrow(),
        [PathBuf::from("/a/tool"), PathBuf::from("/b/tool")],
        "elements in order, and no further once one wins"
    );
}

#[skuld::test]
fn bare_name_not_on_path_never_runs_a_cwd_file() {
    // The working directory holds an executable of that name; the file system answers `Executable`
    // for the bare name itself. A resolver that falls back to the bare name would return it.
    let recording = Recording::new(&["tool", "./tool"]);
    let found = resolve_with(OsStr::new("tool"), Some(OsStr::new("/usr/bin:/bin")), recording.probe());
    assert_eq!(found, Err(Errno(libc::ENOENT)));
    for asked in recording.asked.borrow().iter() {
        assert!(asked.is_absolute(), "probed {}", asked.display());
    }
}

#[skuld::test]
fn relative_and_empty_path_elements_are_never_searched() {
    for path in ["", ":", "::/bin", ".", "./bin", "rel", "rel/dir:", ":/nowhere:."] {
        let recording = Recording::new(&["tool", "./tool", "rel/tool", "./bin/tool", "rel/dir/tool", "/tool"]);
        let found = resolve_with(OsStr::new("tool"), Some(OsStr::new(path)), recording.probe());
        assert_eq!(found, Err(Errno(libc::ENOENT)), "PATH {path:?}");
        for asked in recording.asked.borrow().iter() {
            assert!(asked.is_absolute(), "PATH {path:?} probed {}", asked.display());
        }
    }
}

#[skuld::test]
fn directory_and_non_executable_candidates_are_skipped_then_eacces() {
    let tmp = tempfile::tempdir().unwrap();
    let make = |dir: &str| -> PathBuf {
        let dir = tmp.path().join(dir);
        std::fs::create_dir(&dir).unwrap();
        dir
    };
    let (with_dir, with_plain, with_exe, empty) = (make("d"), make("p"), make("x"), make("e"));
    std::fs::create_dir(with_dir.join("tool")).unwrap();
    std::fs::write(with_plain.join("tool"), b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(with_plain.join("tool"), std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(with_exe.join("tool"), b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(with_exe.join("tool"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let join = |dirs: &[&Path]| -> OsString {
        dirs.iter()
            .map(|d| d.as_os_str())
            .collect::<Vec<_>>()
            .join(OsStr::new(":"))
    };

    let path = join(&[&empty, &with_dir, &with_plain]);
    assert_eq!(resolve(OsStr::new("tool"), Some(&path)), Err(Errno(libc::EACCES)));
    let path = join(&[&empty]);
    assert_eq!(resolve(OsStr::new("tool"), Some(&path)), Err(Errno(libc::ENOENT)));
    // A later executable candidate still wins over skipped ones.
    let path = join(&[&with_dir, &with_plain, &with_exe]);
    assert_eq!(
        resolve(OsStr::new("tool"), Some(&path)),
        Ok(with_exe.join("tool").into_os_string())
    );
}

#[skuld::test]
fn unset_path_means_the_system_default() {
    let found = resolve(OsStr::new("sh"), None).expect("the system's default path has an sh");
    assert!(Path::new(&found).is_absolute(), "{found:?}");
    assert!(found.as_bytes().ends_with(b"/sh"), "{found:?}");
    // An empty PATH is not an unset one.
    assert_eq!(
        resolve(OsStr::new("sh"), Some(OsStr::new(""))),
        Err(Errno(libc::ENOENT))
    );
}
