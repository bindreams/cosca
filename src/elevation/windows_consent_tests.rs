//! The consent phase's private steps, driven directly.

use std::path::PathBuf;

use crate::command::Command;

/// `lp_file_for` passes an `Exact` program through as `elevated_program` completed it: routing it
/// through the resolver instead would search for it, turning `raw_executable("cmd")` into
/// `System32\cmd.exe`.
#[test]
fn an_exact_elevated_program_is_completed_without_being_searched() {
    let mut c = Command::new();
    c.raw_executable("cmd").args(["cmd"]).elevate();
    let token = super::super::elevated_program(
        &c,
        super::super::elevated_argv(&c).unwrap(),
        &super::ProcessOnce::new(&super::ProcessDirs::real()),
    )
    .expect("validation passes")
    .0;
    let program = super::lp_file_for(&c, &token, None, &super::ProcessOnce::new(&super::ProcessDirs::real()))
        .expect("an exact program is completed, never searched");
    let p = std::path::Path::new(&program);
    assert!(
        p.is_absolute(),
        "an Exact lpFile must still be absolute, got {program:?}"
    );
    // Completed, NOT searched: the file name is untouched — no `.exe` appended, and it did not
    // come from System32 the way the `Search` arm's `cmd` does.
    assert_eq!(
        p.file_name().unwrap(),
        std::ffi::OsStr::new("cmd"),
        "no extension may be invented for an Exact program, got {program:?}"
    );
}

/// A failed read is cached like a successful one: asking again returns the same failure without a
/// second read, so "at most once" holds whatever a caller does with the first error.
#[test]
fn a_failed_read_is_not_retried() {
    let cwd_reads = std::cell::Cell::new(0);
    let env_reads = std::cell::Cell::new(0);
    let cwd = || {
        cwd_reads.set(cwd_reads.get() + 1);
        if cwd_reads.get() == 1 {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        } else {
            Ok(PathBuf::from(r"C:\late"))
        }
    };
    let env = || {
        env_reads.set(env_reads.get() + 1);
        if env_reads.get() == 1 {
            Err(crate::error::Error::Io(std::io::Error::from(
                std::io::ErrorKind::OutOfMemory,
            )))
        } else {
            Ok(crate::child::spawn::windows_raw::env_snapshot::EnvSnapshot::from_block(
                vec![0],
            ))
        }
    };
    let dirs = super::ProcessDirs { cwd: &cwd, env: &env };
    let state = super::ProcessOnce::new(&dirs);
    for _ in 0..2 {
        match state.cwd() {
            Err(crate::error::Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied),
            other => panic!("the first failure must stand: {other:?}"),
        }
        match state.path_var() {
            Err(crate::error::Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::OutOfMemory),
            other => panic!("the first failure must stand: {other:?}"),
        }
    }
    assert_eq!((cwd_reads.get(), env_reads.get()), (1, 1));
}

/// A cached failure keeps its variant: an environment reader's `Unsupported` is handed out again as
/// `Unsupported`, not rebuilt as an I/O error.
#[test]
fn a_cached_failure_keeps_its_variant() {
    let reads = std::cell::Cell::new(0);
    let env = || {
        reads.set(reads.get() + 1);
        Err(crate::error::Error::Unsupported {
            op: "reading the environment".into(),
            platform: "windows",
            detail: "injected".into(),
        })
    };
    let dirs = super::ProcessDirs {
        cwd: &|| Ok(PathBuf::from(r"C:\x")),
        env: &env,
    };
    let state = super::ProcessOnce::new(&dirs);
    for _ in 0..2 {
        match state.path_var() {
            Err(crate::error::Error::Unsupported { detail, .. }) => assert_eq!(detail, "injected"),
            other => panic!("the first failure must stand as it was: {other:?}"),
        }
    }
    assert_eq!(reads.get(), 1);
}

/// `lpDirectory` carries a set `current_dir`'s completed base.
#[test]
fn a_current_dir_yields_an_lp_directory() {
    let got = super::lp_directory(Some(std::path::Path::new("sub")), Some(PathBuf::from(r"C:\x\sub"))).unwrap();
    assert_eq!(got, Some(r"C:\x\sub".encode_utf16().chain([0]).collect::<Vec<u16>>()));
    assert_eq!(super::lp_directory(None, None).unwrap(), None);
}

/// A set `current_dir` with no base would run the child in this process's cwd instead of the one
/// asked for; `consent_base` never returns that, and this is what catches it if it ever did.
#[cfg(debug_assertions)] // the contract is a debug assertion: release has none to trigger
#[test]
#[should_panic(expected = "a current_dir always yields a base")]
fn a_current_dir_without_a_base_is_a_contract_violation() {
    let _ = super::lp_directory(Some(std::path::Path::new("sub")), None);
}

/// `lp_file_for` resolves on this process's `PATH`, which is right only because
/// `reject_unsupported_config` refused every env op first. Called without that gate, the
/// assertion catches it.
#[cfg(debug_assertions)] // the contract is a debug assertion: release has none to trigger
#[test]
#[should_panic(expected = "reject_unsupported_config refuses env ops")]
fn env_ops_reaching_lp_file_for_are_a_contract_violation() {
    let mut c = Command::new();
    c.args(["whoami"]).env("COSCA_X", "1").elevate();
    let dirs = super::ProcessDirs::real();
    let state = super::ProcessOnce::new(&dirs);
    let _ = super::lp_file_for(&c, std::ffi::OsStr::new("whoami"), None, &state);
}

/// `lpFile` must reach `ShellExecuteEx` absolute. An `Exact` token handed over uncompleted,
/// skipping `elevated_program`, is what the assertion catches.
#[cfg(debug_assertions)] // the contract is a debug assertion: release has none to trigger
#[test]
#[should_panic(expected = "lpFile must reach ShellExecuteEx absolute")]
fn a_relative_lp_file_is_a_contract_violation() {
    let mut c = Command::new();
    c.raw_executable("tool.exe").args(["tool.exe"]).elevate();
    let dirs = super::ProcessDirs::real();
    let state = super::ProcessOnce::new(&dirs);
    let _ = super::lp_file_for(&c, std::ffi::OsStr::new("tool.exe"), None, &state);
}
