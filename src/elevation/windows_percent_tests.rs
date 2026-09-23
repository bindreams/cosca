//! Without a class, `ShellExecuteEx` runs `lpFile` and `lpDirectory` through
//! `ExpandEnvironmentStringsW`, so the consent launch refuses a `%` in either as sent.

use std::path::{Path, PathBuf};

use super::windows_tests::win_host;
use crate::command::Command;
use crate::error::Error;

fn assert_refused(c: &Command, process_cwd: &Path, what: &str) {
    let cwd = process_cwd.to_path_buf();
    let dirs = super::ProcessDirs {
        cwd: &|| Ok::<PathBuf, _>(cwd.clone()),
        env: &|| {
            Ok(crate::child::spawn::windows_raw::env_snapshot::EnvSnapshot::from_block(
                vec![0],
            ))
        },
    };
    match super::plan_runas_with(c, &win_host(false), &dirs).map(|_| ()) {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput => assert!(
            e.to_string().contains("may not hold a %"),
            "{what}: the reason must be named: {e}"
        ),
        other => panic!("{what}: expected Io(InvalidInput), got {other:?}"),
    }
}

/// A directory whose name holds `%COSCA_V%`, with `tool.exe` in it.
fn percent_dir() -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("%COSCA_V%");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("tool.exe"), b"x").unwrap();
    (root, dir)
}

#[test]
fn a_percent_in_the_resolved_lp_file_is_refused() {
    let (_root, dir) = percent_dir();
    let unused = Path::new(r"C:\cosca-unused");

    let mut written = Command::new();
    written
        .executable(dir.join("tool.exe"))
        .args([dir.join("tool.exe")])
        .elevate();
    assert_refused(&written, unused, "a % the caller wrote");

    // The caller's token has no `%`; the directory it is resolved against does.
    let mut from_cwd = Command::new();
    from_cwd.args([r".\tool.exe"]).current_dir(&dir).elevate();
    assert_refused(&from_cwd, unused, "a % from current_dir");

    let mut from_process_cwd = Command::new();
    from_process_cwd.args([r".\tool.exe"]).elevate();
    assert_refused(&from_process_cwd, &dir, "a % from the process cwd");

    let mut exact = Command::new();
    exact
        .raw_executable(dir.join("tool.exe"))
        .args([dir.join("tool.exe")])
        .elevate();
    assert_refused(&exact, unused, "an Exact program");
}

#[test]
fn a_percent_in_the_lp_directory_is_refused() {
    let (_root, dir) = percent_dir();
    let mut c = Command::new();
    c.args(["whoami.exe"]).current_dir("sub").elevate();
    assert_refused(&c, &dir, "a % from the process cwd");
}

const PERCENT_PATH_NAME: &str = "cosca-elevate-percent-path-7e2a";
const PERCENT_PATH_DIR_ENV: &str = "COSCA_FIXTURE_ELEVATE_PERCENT_PATH_DIR";

/// A `%` the caller never wrote, from a `PATH` entry. The tool sits in a directory literally named
/// `%COSCA_V%\bin`; the `PATH` is given to a re-exec of this test binary, whose own environment
/// must not change, and [`fixture_a_percent_from_path`] plans the launch there.
#[test]
fn a_percent_from_a_path_entry_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("%COSCA_V%").join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(bin.join(format!("{PERCENT_PATH_NAME}.exe")), b"x").unwrap();
    let mut path = std::ffi::OsString::from(&bin);
    if let Some(inherited) = std::env::var_os("PATH") {
        path.push(";");
        path.push(inherited);
    }
    crate::test_child::run_fixture_with_env(
        crate::test_child::fixture_path!(fixture_a_percent_from_path),
        &[("PATH", &path), (PERCENT_PATH_DIR_ENV, bin.as_os_str())],
    );
}

/// Inert in an ordinary suite run, where [`PERCENT_PATH_DIR_ENV`] is unset.
#[test]
fn fixture_a_percent_from_path() {
    if std::env::var_os(PERCENT_PATH_DIR_ENV).is_none() {
        return;
    }
    let mut c = Command::new();
    c.executable(PERCENT_PATH_NAME).args([PERCENT_PATH_NAME]).elevate();
    // The real environment, which carries the `PATH` under test.
    match super::plan_runas(&c, &win_host(false)).map(|_| ()) {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput => {
            assert!(
                e.to_string().contains("may not hold a %"),
                "the reason must be named: {e}"
            )
        }
        other => panic!("a % from a PATH entry: expected Io(InvalidInput), got {other:?}"),
    }
}
