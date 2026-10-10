use std::cell::RefCell;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::super::protocol::Errno;
use super::{classify, resolve, resolve_with, Candidate};

fn os(s: &str) -> OsString {
    OsString::from(s)
}

/// A probe that records what it is asked about and answers `Executable` for `executable`,
/// `answers` for the paths it names, and `Missing` for the rest.
struct Recording {
    asked: RefCell<Vec<PathBuf>>,
    executable: Vec<PathBuf>,
    answers: Vec<(PathBuf, Candidate)>,
}

impl Recording {
    fn new(executable: &[&str]) -> Recording {
        Recording {
            asked: RefCell::default(),
            executable: executable.iter().map(PathBuf::from).collect(),
            answers: vec![],
        }
    }

    fn answering(mut self, path: &str, answer: Candidate) -> Recording {
        self.answers.push((PathBuf::from(path), answer));
        self
    }

    fn probe(&self) -> impl FnMut(&Path) -> Candidate + '_ {
        |path| {
            self.asked.borrow_mut().push(path.to_owned());
            if let Some((_, answer)) = self.answers.iter().find(|(p, _)| p == path) {
                *answer
            } else if self.executable.iter().any(|e| e == path) {
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
            Ok(vec![os(program)])
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
    // Every candidate goes to the child, in order, in case the winner vanishes before the exec.
    assert_eq!(found, Ok(vec![os("/a/tool"), os("/b/tool"), os("/c/tool")]));
    assert_eq!(
        *recording.asked.borrow(),
        [PathBuf::from("/a/tool"), PathBuf::from("/b/tool")],
        "elements in order, and no further once one wins"
    );
}

#[skuld::test]
fn a_candidate_that_fails_ends_the_search_with_its_errno() {
    // A later executable one is not reached: `execve` would have stopped `execvp` at the failure.
    let recording = Recording::new(&["/c/tool"])
        .answering("/a/tool", Candidate::NotExecutable)
        .answering("/b/tool", Candidate::Failed(libc::ELOOP));
    let found = resolve_with(OsStr::new("tool"), Some(OsStr::new("/a:/b:/c")), recording.probe());
    assert_eq!(found, Err(Errno(libc::ELOOP)));
    assert_eq!(
        *recording.asked.borrow(),
        [PathBuf::from("/a/tool"), PathBuf::from("/b/tool")]
    );
    // An executable one found before the failure wins, and the failure is not reported.
    let recording = Recording::new(&["/a/tool"]).answering("/b/tool", Candidate::Failed(libc::EIO));
    let found = resolve_with(OsStr::new("tool"), Some(OsStr::new("/a:/b")), recording.probe());
    assert_eq!(found, Ok(vec![os("/a/tool"), os("/b/tool")]));
}

#[skuld::test]
fn an_errno_means_what_it_means_to_execvp() {
    let path = Path::new("/d/tool");
    for errno in [libc::ENOENT, libc::ENOTDIR, libc::ESTALE, libc::ENODEV, libc::ETIMEDOUT] {
        assert_eq!(classify(path, errno), Candidate::Missing, "errno {errno}");
    }
    assert_eq!(classify(path, libc::EACCES), Candidate::NotExecutable);
    // These end the search; so does any errno `execvp` does not know.
    for errno in [
        libc::ELOOP,
        libc::ENAMETOOLONG,
        libc::EIO,
        libc::ENOMEM,
        libc::EOVERFLOW,
    ] {
        assert_eq!(classify(path, errno), Candidate::Failed(errno), "errno {errno}");
    }
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
        Ok(vec![
            with_dir.join("tool").into_os_string(),
            with_plain.join("tool").into_os_string(),
            with_exe.join("tool").into_os_string(),
        ])
    );
}

/// A directory this caller cannot search is `EACCES`, remembered, not an absent file. Only a caller
/// without DAC bypass is denied: the fixture runs started without it.
#[skuld::test]
fn an_unsearchable_directory_is_skipped_and_remembered_as_eacces() {
    crate::test_child::run_fixture(crate::test_child::fixture_path!(
        fixture_an_unsearchable_directory_is_skipped_and_remembered_as_eacces
    ));
}

/// The child half of [`an_unsearchable_directory_is_skipped_and_remembered_as_eacces`].
#[skuld::test]
fn fixture_an_unsearchable_directory_is_skipped_and_remembered_as_eacces() {
    if !crate::test_child::is_fixture_reexec() {
        return; // picked up by an ordinary suite run: deliberately inert
    }
    let root = crate::test_child::fixture_scratch_tempdir();
    let locked = root.path().join("locked");
    let open = root.path().join("open");
    for dir in [&locked, &open] {
        std::fs::create_dir(dir).unwrap();
        std::fs::write(dir.join("tool"), b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(dir.join("tool"), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    let _restore = crate::test_child::RestoreMode::new(&locked, 0o755);
    let denied = std::fs::metadata(locked.join("tool")).unwrap_err();
    assert_eq!(
        denied.raw_os_error(),
        Some(libc::EACCES),
        "precondition: the directory must be unsearchable to this caller, not {denied}"
    );

    let only_locked = resolve(OsStr::new("tool"), Some(locked.as_os_str()));
    assert_eq!(
        only_locked,
        Err(Errno(libc::EACCES)),
        "an unsearchable directory is not ENOENT"
    );
    let path = [locked.as_os_str(), open.as_os_str()].join(OsStr::new(":"));
    assert_eq!(
        resolve(OsStr::new("tool"), Some(&path)),
        Ok(vec![
            locked.join("tool").into_os_string(),
            open.join("tool").into_os_string()
        ]),
        "a later executable candidate still wins"
    );
}

#[skuld::test]
fn unset_path_means_the_system_default() {
    let found = resolve(OsStr::new("sh"), None).expect("the system's default path has an sh");
    for candidate in &found {
        assert!(Path::new(candidate).is_absolute(), "{candidate:?}");
        assert!(candidate.as_bytes().ends_with(b"/sh"), "{candidate:?}");
    }
    // An empty PATH is not an unset one.
    assert_eq!(
        resolve(OsStr::new("sh"), Some(OsStr::new(""))),
        Err(Errno(libc::ENOENT))
    );
}
