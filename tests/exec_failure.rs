//! A tokio spawn whose program cannot be executed does not blame a foreign reaper for the child.
//!
//! tokio can also fail a spawn after `std`'s succeeded, so its error does not prove that the
//! program never ran, and the error may say so. The child of a failed exec is gone because the
//! spawn itself collected it, not because someone else did.

#[cfg(all(feature = "tokio", target_os = "linux"))]
#[path = "common/mod.rs"]
mod common;
#[cfg(all(feature = "tokio", target_os = "linux"))]
use common::test_groups::{cgroup, Group};

/// A program whose exec fails, and the OS error it fails with: its kind, and its code where `std`
/// reports one. The guard keeps the files alive.
#[cfg(feature = "tokio")]
fn failing_programs() -> (
    tempfile::TempDir,
    Vec<(std::ffi::OsString, std::io::ErrorKind, Option<i32>)>,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    #[cfg(unix)]
    let programs = {
        use std::os::unix::fs::PermissionsExt;

        let not_executable = dir.path().join("not-executable");
        std::fs::write(&not_executable, "#!/bin/sh\necho ran\n").expect("write the file");
        std::fs::set_permissions(&not_executable, std::fs::Permissions::from_mode(0o644)).expect("chmod 0644");
        use std::io::ErrorKind;
        vec![
            (
                "cosca-no-such-program-725".into(),
                ErrorKind::NotFound,
                Some(libc::ENOENT),
            ),
            (
                not_executable.clone().into_os_string(),
                ErrorKind::PermissionDenied,
                Some(libc::EACCES),
            ),
            (
                not_executable.join("below-a-file").into_os_string(),
                ErrorKind::NotADirectory,
                Some(libc::ENOTDIR),
            ),
        ]
    };
    // std searches `PATH` itself and reports "program not found" without an OS code.
    #[cfg(windows)]
    let programs = vec![("cosca-no-such-program-725".into(), std::io::ErrorKind::NotFound, None)];
    (dir, programs)
}

/// What a test applies to a command: a containment mode, or none.
#[cfg(feature = "tokio")]
#[derive(Debug, Clone, Copy)]
enum Mode {
    Uncontained,
    #[cfg(unix)]
    Contained(cosca::ContainMode),
}

#[cfg(all(feature = "tokio", unix))]
const MODES: [Mode; 4] = [
    Mode::Uncontained,
    Mode::Contained(cosca::ContainMode::Strongest),
    Mode::Contained(cosca::ContainMode::Session),
    Mode::Contained(cosca::ContainMode::TreeWalk),
];

#[cfg(all(feature = "tokio", windows))]
const MODES: [Mode; 1] = [Mode::Uncontained];

/// Why `error` blames a foreign reaper or lost the exec's own error, if it does.
#[cfg(feature = "tokio")]
fn dishonest(error: &cosca::error::Error, kind: std::io::ErrorKind, errno: Option<i32>) -> Option<String> {
    use cosca::error::Error;

    let mut cause = error;
    while let Error::MayHaveStarted { source, .. } = cause {
        cause = source;
    }
    let message = error.to_string();
    if message.contains("reaped by someone else") {
        Some(format!("blames a reaper: {message}"))
    } else if !matches!(cause, Error::Io(e) if e.kind() == kind && e.raw_os_error() == errno) {
        Some(format!(
            "is not the exec's own error ({kind:?}, code {errno:?}): {error:?}"
        ))
    } else {
        None
    }
}

/// Fails with every case that was dishonest.
#[cfg(feature = "tokio")]
#[track_caller]
fn assert_all_honest(failures: Vec<String>) {
    assert!(
        failures.is_empty(),
        "{} failed exec(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Mutant: the tokio spawn answers `Gone` ("reaped by someone else") for a child that the failed
/// spawn collected itself.
#[cfg(feature = "tokio")]
#[skuld::test]
async fn a_failed_tokio_exec_blames_no_foreign_reaper() {
    let (_dir, programs) = failing_programs();
    let mut failures = Vec::new();
    for mode in MODES {
        for (program, kind, errno) in &programs {
            let mut cmd = cosca::tokio::Command::new();
            cmd.args([program]);
            #[cfg(unix)]
            if let Mode::Contained(mode) = mode {
                cmd.contain_with(mode);
            }
            let error = cmd.spawn().expect_err("the exec fails");
            failures.extend(dishonest(&error, *kind, *errno).map(|why| format!("{program:?} {mode:?}: {why}")));
        }
    }
    assert_all_honest(failures);
}

/// [`a_failed_tokio_exec_blames_no_foreign_reaper`] in a cgroup leaf, which the failed spawn removes.
///
/// Mutant: as there.
#[cfg(all(feature = "tokio", target_os = "linux"))]
#[skuld::test]
async fn cgroup_a_failed_tokio_exec_blames_no_foreign_reaper(#[fixture(cgroup)] _group: &Group) {
    let (_dir, programs) = failing_programs();
    let mut failures = Vec::new();
    for (program, kind, errno) in &programs {
        let mut cmd = cosca::tokio::Command::new();
        cmd.args([program]).contain();
        let error = cmd.spawn().expect_err("the exec fails");
        failures.extend(dishonest(&error, *kind, *errno).map(|why| format!("{program:?} in a cgroup leaf: {why}")));
    }
    assert_all_honest(failures);
}

#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
