//! What detection makes of the one `PATH` lookup's answers for `sudo`, `doas` and `pkexec`, and what
//! the planner then does with them. The lookup's own rules are held by `resolve::posix`'s tests.

use super::super::{detect_with, find_fixed_front, front_of};
#[cfg(target_os = "linux")]
use super::super::{rewrite_with_host, run_version_probe};
use crate::elevation::elevation_tests::unavailable;
use crate::elevation::plan::{FrontState, Host, Os, Transition};
use crate::elevation::{Auth, Backend, Privilege};
use crate::error::{ElevationErrorKind, Error};
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn plant(dir: &Path, name: &str, mode: u32) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

/// A `PATH` entry that cannot be examined, `ELOOP` for every uid: a symlink to itself.
fn looping_entry(root: &Path) -> PathBuf {
    let entry = root.join("loop");
    std::os::unix::fs::symlink("loop", &entry).unwrap();
    let e = std::fs::metadata(entry.join("sudo")).unwrap_err();
    assert_eq!(
        e.raw_os_error(),
        Some(libc::ELOOP),
        "precondition: the entry cannot be examined"
    );
    entry
}

fn path_of(dirs: &[&Path]) -> OsString {
    std::env::join_paths(dirs).unwrap()
}

/// A run of pkexec is a failure: these requests never reach a real one.
fn detect(path_var: &OsString, backend: Backend, auth: &Auth) -> Host {
    detect_with(
        Some(path_var.as_os_str()),
        Os::Linux,
        false,
        backend,
        auth,
        |_| panic!("canonicalised a pkexec"),
        |_| panic!("probed a pkexec"),
    )
}

fn is_found(state: &FrontState, path: &Path) -> bool {
    matches!(state, FrontState::Found(found) if found == path)
}

fn is_unexamined_by(state: &FrontState, code: i32) -> bool {
    matches!(state, FrontState::Unexamined(error) if crate::error::first_os_code(error) == Some(code))
}

/// The file the lookup finds is the front, whatever its mode: detection has no rule of its own.
///
/// Mutant: detection skips a front without the execute bit.
#[skuld::test]
fn the_file_the_lookup_finds_is_the_front() {
    let dir = tempfile::tempdir().unwrap();
    let sudo = plant(dir.path(), "sudo", 0o644);
    let doas = plant(dir.path(), "doas", 0o755);
    let pkexec = plant(dir.path(), "pkexec", 0o644);
    let path = path_of(&[dir.path()]);
    let host = detect(&path, Backend::Auto, &Auth::NonInteractive);
    assert!(is_found(&host.available.sudo, &sudo), "{:?}", host.available.sudo);
    assert!(is_found(&host.available.doas, &doas), "{:?}", host.available.doas);
    assert!(is_found(&host.available.pkexec, &pkexec), "{:?}", host.available.pkexec);
    match host.plan(Privilege::Elevated, Backend::Auto, Auth::NonInteractive) {
        Transition::ElevatePosix { backend, path, .. } => assert_eq!((backend, path), (Backend::Sudo, sudo)),
        other => panic!("expected the sudo found, got {other:?}"),
    }
}

/// A miss is an absent front with no error kept: the planner says it is not on `PATH`, with no
/// cause. (The macOS build fills `osascript` whatever `PATH` is, so the
/// three `PATH` fronts are what is asserted.)
#[skuld::test]
fn a_miss_is_an_absent_front_without_an_error() {
    let empty = tempfile::tempdir().unwrap();
    let path = path_of(&[empty.path()]);
    let host = detect(&path, Backend::Auto, &Auth::NonInteractive);
    for front in [&host.available.sudo, &host.available.doas, &host.available.pkexec] {
        assert!(matches!(front, FrontState::Absent), "{front:?}");
    }
    let (detail, cause, _) = unavailable(host.plan(Privilege::Elevated, Backend::Auto, Auth::NonInteractive));
    assert!(detail.contains("no sudo/doas on PATH"), "{detail}");
    assert_eq!(cause, None);
}

/// A front is absent for a miss only: a stop whose cause reads as `NotFound` is the lookup's error and
/// no answer to whether the front is there, as a miss is the search's own `ENOENT`.
///
/// Mutant: a front is absent when the lookup's error has kind `NotFound`.
#[skuld::test]
fn a_stop_whose_cause_is_not_found_is_not_an_absent_front() {
    let cause = std::io::Error::new(std::io::ErrorKind::NotFound, "a cause that reads as a miss");
    let stop = Error::Io(crate::error::io_context("could not tell, so the search stops", cause));
    let state = front_of(Err(stop));
    assert!(matches!(state, FrontState::Unexamined(_)), "{state:?}");
    let miss = Error::Io(std::io::Error::from_raw_os_error(libc::ENOENT));
    let state = front_of(Err(miss));
    assert!(matches!(state, FrontState::Absent), "{state:?}");
}

/// An entry that cannot be examined is not a miss: the front is unexamined with the entry's error,
/// the search does not go on to the `sudo` after the entry, and the planner reports that error as
/// the cause of the `BackendUnavailable`, for `Auto` and for `sudo` named, and the report names the
/// entry.
///
/// Mutants: the error becomes a miss; the search skips the entry and finds the later `sudo`; the
/// lookup's error names no entry.
#[skuld::test]
fn an_error_that_is_not_a_miss_is_the_cause_when_the_plan_picks_the_front() {
    let root = tempfile::tempdir().unwrap();
    let looping = looping_entry(root.path());
    let good = root.path().join("good");
    std::fs::create_dir(&good).unwrap();
    plant(&good, "sudo", 0o755);
    let path = path_of(&[&looping, &good]);
    for backend in [Backend::Auto, Backend::Sudo] {
        let host = detect(&path, backend, &Auth::NonInteractive);
        assert!(
            is_unexamined_by(&host.available.sudo, libc::ELOOP),
            "{backend:?}: {:?}",
            host.available.sudo
        );
        let (detail, cause, report) = unavailable(host.plan(Privilege::Elevated, backend, Auth::NonInteractive));
        assert!(detail.contains("could not be found or opened"), "{backend:?}: {detail}");
        assert_eq!(cause, Some(libc::ELOOP), "{backend:?}");
        assert!(report.contains(&format!("{looping:?}")), "{backend:?}: {report}");
    }
}

/// The same for the front `pkexec`, whose detection is the one that goes on to open and probe it.
#[skuld::test]
fn an_error_that_is_not_a_miss_is_the_cause_when_the_plan_picks_pkexec() {
    let root = tempfile::tempdir().unwrap();
    let looping = looping_entry(root.path());
    let good = root.path().join("good");
    std::fs::create_dir(&good).unwrap();
    plant(&good, "pkexec", 0o755);
    let path = path_of(&[&looping, &good]);
    let host = detect(&path, Backend::Pkexec, &Auth::Gui);
    assert!(
        is_unexamined_by(&host.available.pkexec, libc::ELOOP),
        "{:?}",
        host.available.pkexec
    );
    assert!(host.pkexec_pin.is_none());
    let (_, cause, _) = unavailable(host.plan(Privilege::Elevated, Backend::Pkexec, Auth::Gui));
    assert_eq!(cause, Some(libc::ELOOP));
}

/// The same error for a front the plan does not pick fails nothing: `sudo` is found before the
/// entry, so the `doas` and `pkexec` searches that stop on it change no verdict.
///
/// Mutant: any recorded error rejects the plan.
#[skuld::test]
fn an_error_for_a_front_the_plan_does_not_pick_fails_nothing() {
    let root = tempfile::tempdir().unwrap();
    let looping = looping_entry(root.path());
    let good = root.path().join("good");
    std::fs::create_dir(&good).unwrap();
    let sudo = plant(&good, "sudo", 0o755);
    let path = path_of(&[&good, &looping]);
    for backend in [Backend::Auto, Backend::Sudo] {
        let host = detect(&path, backend, &Auth::NonInteractive);
        assert!(
            is_found(&host.available.sudo, &sudo),
            "{backend:?}: {:?}",
            host.available.sudo
        );
        for front in [&host.available.doas, &host.available.pkexec] {
            assert!(
                is_unexamined_by(front, libc::ELOOP),
                "{backend:?}: the searches that went past the match stop on the entry: {front:?}"
            );
        }
        match host.plan(Privilege::Elevated, backend, Auth::NonInteractive) {
            Transition::ElevatePosix {
                backend: picked, path, ..
            } => {
                assert_eq!((picked, path), (Backend::Sudo, sudo.clone()), "{backend:?}")
            }
            other => panic!("{backend:?}: expected the sudo found, got {other:?}"),
        }
    }
}

/// A `pkexec` without the execute bit, first on `PATH`, is found, and its version probe then cannot
/// start it: the request is `BackendUnavailable` with the launch's error as its cause, not the
/// `Unsupported` that tells the caller to upgrade polkit. (Linux only: a pkexec request is launched
/// through `/proc/self/fd`.)
///
/// Mutant: a probe that could not start the front is `Unsupported`.
#[cfg(target_os = "linux")]
#[skuld::test]
fn a_pkexec_without_the_execute_bit_is_backend_unavailable_with_the_launch_error() {
    let dir = tempfile::tempdir().unwrap();
    plant(dir.path(), "pkexec", 0o644);
    let path = path_of(&[dir.path()]);
    let host = detect_with(
        Some(path.as_os_str()),
        Os::Linux,
        false,
        Backend::Pkexec,
        &Auth::Gui,
        |p| std::fs::canonicalize(p),
        run_version_probe,
    );
    let mut cmd = crate::test_child::command(crate::test_child::Console::Hidden);
    cmd.arg("id")
        .elevation_backend(Backend::Pkexec)
        .elevation_auth(Auth::Gui);
    match rewrite_with_host(&mut cmd, &host) {
        Err(Error::Elevation {
            kind: ElevationErrorKind::BackendUnavailable,
            source: Some(cause),
            ..
        }) => assert_eq!(crate::error::first_os_code(&cause), Some(libc::EACCES)),
        Err(other) => panic!("expected BackendUnavailable caused by EACCES, got {other:?}"),
        Ok(_) => panic!("expected BackendUnavailable caused by EACCES, got a rewrite"),
    }
}

/// The same for a `sudo` without the execute bit: detection finds it, and the failed launch of it is
/// the `BackendUnavailable` the spawn's remapping makes, with the launch's error as its cause.
///
/// Mutant: detection skips the front without the execute bit, so the plan is another verdict.
#[skuld::test]
fn a_sudo_without_the_execute_bit_is_found_and_its_failed_launch_is_backend_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let sudo = plant(dir.path(), "sudo", 0o644);
    let path = path_of(&[dir.path()]);
    let host = detect(&path, Backend::Sudo, &Auth::NonInteractive);
    let Transition::ElevatePosix { path: front, .. } =
        host.plan(Privilege::Elevated, Backend::Sudo, Auth::NonInteractive)
    else {
        panic!("expected the sudo found to be planned");
    };
    assert_eq!(front, sudo);
    let launch = crate::test_spawn::spawn(&mut std::process::Command::new(&front))
        .expect_err("a file without the execute bit cannot be launched");
    match crate::elevation::remap_derived_spawn_error(Error::Io(launch), &front) {
        Error::Elevation {
            kind: ElevationErrorKind::BackendUnavailable,
            source: Some(cause),
            ..
        } => assert_eq!(crate::error::first_os_code(&cause), Some(libc::EACCES)),
        other => panic!("expected BackendUnavailable caused by EACCES, got {other:?}"),
    }
}

/// The fixed front is its file, whatever its mode, as for the `PATH` fronts: a file is found, a
/// missing path or a directory is absent, and a path that cannot be examined is unexamined with the
/// error.
///
/// Mutants: an error is absent; a file without the execute bit is absent; a directory is found.
#[skuld::test]
fn a_fixed_front_is_found_absent_or_unexamined() {
    let root = tempfile::tempdir().unwrap();
    let file = plant(root.path(), "osascript", 0o644);
    assert!(is_found(&find_fixed_front(&file), &file));
    for absent in [root.path().join("missing"), root.path().to_path_buf()] {
        let state = find_fixed_front(&absent);
        assert!(matches!(state, FrontState::Absent), "{absent:?}: {state:?}");
    }
    let unreadable = looping_entry(root.path()).join("osascript");
    let state = find_fixed_front(&unreadable);
    assert!(is_unexamined_by(&state, libc::ELOOP), "{state:?}");
    let FrontState::Unexamined(cause) = &state else {
        unreachable!("{state:?}")
    };
    let report = crate::error::Report(&**cause).to_string();
    assert!(
        report.contains(&format!("{unreadable:?}")),
        "{unreadable:?} is not named: {report}"
    );
}
