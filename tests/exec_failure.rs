//! A spawn whose `exec` failed says the program did not start, sync and tokio, under every
//! containment mode: the child reported the failure from before `exec`, so the error is proof.

#[cfg(unix)]
#[path = "common/mod.rs"]
mod common;
#[cfg(target_os = "linux")]
use common::test_groups::{cgroup, Group};

/// A program whose `exec` fails, and the errno it fails with. The guard keeps the files alive.
#[cfg(unix)]
fn failing_programs() -> (tempfile::TempDir, Vec<(std::ffi::OsString, i32)>) {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let not_executable = dir.path().join("not-executable");
    std::fs::write(&not_executable, "#!/bin/sh\necho ran\n").expect("write the file");
    std::fs::set_permissions(&not_executable, std::fs::Permissions::from_mode(0o644)).expect("chmod 0644");
    let programs = vec![
        ("cosca-no-such-program-725".into(), libc::ENOENT),
        (not_executable.clone().into_os_string(), libc::EACCES),
        (not_executable.join("below-a-file").into_os_string(), libc::ENOTDIR),
    ];
    (dir, programs)
}

/// What a test applies to a command: a containment mode, or none.
#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
enum Mode {
    Uncontained,
    Contained(cosca::ContainMode),
}

#[cfg(unix)]
const MODES: [Mode; 4] = [
    Mode::Uncontained,
    Mode::Contained(cosca::ContainMode::Strongest),
    Mode::Contained(cosca::ContainMode::Session),
    Mode::Contained(cosca::ContainMode::TreeWalk),
];

/// Why `error` does not say that the program did not start with the OS's `errno`, if it does not.
#[cfg(unix)]
fn not_proof(error: &cosca::error::Error, errno: i32) -> Option<String> {
    let message = error.to_string();
    if matches!(error, cosca::error::Error::MayHaveStarted { .. }) || error.fate().is_some() {
        Some(format!("says the program may have started: {error:?}"))
    } else if message.contains("reaped by someone else") {
        Some(format!("blames a reaper: {message}"))
    } else if !matches!(error, cosca::error::Error::Io(e) if e.raw_os_error() == Some(errno)) {
        Some(format!("is not the exec's own errno {errno}: {error:?}"))
    } else {
        None
    }
}

/// Fails with every case whose spawn did not prove that the program did not start.
#[cfg(unix)]
#[track_caller]
fn assert_all_proved(failures: Vec<String>) {
    assert!(
        failures.is_empty(),
        "{} failed exec(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Mutant: the sync spawn wraps std's exec-failure error in `MayHaveStarted`.
#[cfg(unix)]
#[skuld::test]
fn a_failed_exec_did_not_start() {
    let (_dir, programs) = failing_programs();
    let mut failures = Vec::new();
    for mode in MODES {
        for (program, errno) in &programs {
            let mut cmd = cosca::Command::new();
            cmd.args([program]);
            if let Mode::Contained(mode) = mode {
                cmd.contain_with(mode);
            }
            let error = cmd.spawn().expect_err("the exec fails");
            failures.extend(not_proof(&error, *errno).map(|why| format!("{program:?} {mode:?}: {why}")));
        }
    }
    assert_all_proved(failures);
}

/// Mutant: the tokio spawn cannot tell std's exec-failure error from tokio's own failure after
/// `exec`, and answers that the program may have started.
#[cfg(all(feature = "tokio", unix))]
#[skuld::test]
async fn a_failed_tokio_exec_did_not_start() {
    let (_dir, programs) = failing_programs();
    let mut failures = Vec::new();
    for mode in MODES {
        for (program, errno) in &programs {
            let mut cmd = cosca::tokio::Command::new();
            cmd.args([program]);
            if let Mode::Contained(mode) = mode {
                cmd.contain_with(mode);
            }
            let error = cmd.spawn().expect_err("the exec fails");
            failures.extend(not_proof(&error, *errno).map(|why| format!("{program:?} {mode:?}: {why}")));
        }
    }
    assert_all_proved(failures);
}

/// [`a_failed_exec_did_not_start`] in a cgroup leaf, which the failed spawn removes.
///
/// Mutant: as there.
#[cfg(target_os = "linux")]
#[skuld::test]
fn cgroup_a_failed_exec_did_not_start(#[fixture(cgroup)] _group: &Group) {
    let (_dir, programs) = failing_programs();
    let mut failures = Vec::new();
    for (program, errno) in &programs {
        let mut cmd = cosca::Command::new();
        cmd.args([program]).contain();
        let error = cmd.spawn().expect_err("the exec fails");
        failures.extend(not_proof(&error, *errno).map(|why| format!("{program:?} in a cgroup leaf: {why}")));
    }
    assert_all_proved(failures);
}

/// [`a_failed_tokio_exec_did_not_start`] in a cgroup leaf, which the failed spawn removes.
///
/// Mutant: as there.
#[cfg(all(feature = "tokio", target_os = "linux"))]
#[skuld::test]
async fn cgroup_a_failed_tokio_exec_did_not_start(#[fixture(cgroup)] _group: &Group) {
    let (_dir, programs) = failing_programs();
    let mut failures = Vec::new();
    for (program, errno) in &programs {
        let mut cmd = cosca::tokio::Command::new();
        cmd.args([program]).contain();
        let error = cmd.spawn().expect_err("the exec fails");
        failures.extend(not_proof(&error, *errno).map(|why| format!("{program:?} in a cgroup leaf: {why}")));
    }
    assert_all_proved(failures);
}

#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
