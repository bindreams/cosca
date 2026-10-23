//! Regression guard: `std::fs::metadata` calls an app execution alias a file. Following the alias
//! fails (`ERROR_CANT_ACCESS_FILE`), and std falls back to the alias's own attributes; a bare-name
//! search that counts only files relies on that to find `winget` and its kin. M19
//! (`windows_path_resolution`) measured that a test can make such an alias in its own temp
//! directory. It ran on an elevated token with every privilege disabled (the new file is owned by
//! Administrators), which shows no privilege is needed, not that a non-elevated user can do it.

#[cfg(windows)]
#[path = "common/mod.rs"]
mod common;

#[cfg(windows)]
#[skuld::test]
fn an_app_execution_alias_is_a_file() {
    use common::windows_reparse::{app_exec_link_data, set_reparse, IO_REPARSE_TAG_APPEXECLINK};

    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("target.exe");
    std::fs::copy(env!("CARGO_BIN_EXE_cosca_testbin_image"), &target).expect("copy the image");
    let alias = dir.path().join("alias.exe");
    std::fs::write(&alias, b"").expect("create the alias file");
    set_reparse(
        &alias,
        IO_REPARSE_TAG_APPEXECLINK,
        &app_exec_link_data(target.as_os_str()),
    )
    .expect("make the alias");

    let metadata = std::fs::metadata(&alias).expect("metadata of the alias");
    assert!(metadata.is_file(), "{metadata:?}");
}

#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
