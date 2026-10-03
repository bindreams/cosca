//! A dropped-identity fixture command names a skuld DB directory its own identity can write.

use std::os::unix::fs::MetadataExt as _;

fn db_dir_of(cmd: &std::process::Command) -> std::path::PathBuf {
    cmd.get_envs()
        .find(|(k, _)| *k == "SKULD_DB_DIR")
        .and_then(|(_, v)| v)
        .expect("the fixture command sets SKULD_DB_DIR")
        .into()
}

/// The uid the fixture runs as: the driver's own, except where a root driver drops to
/// `UNPRIVILEGED` (non-Linux).
fn fixture_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions.
    let euid = unsafe { libc::geteuid() };
    #[cfg(not(target_os = "linux"))]
    if euid == 0 {
        return crate::test_privilege::UNPRIVILEGED;
    }
    euid
}

#[skuld::test]
fn a_dropped_identity_fixture_gets_an_absolute_existing_skuld_db_dir_it_owns() {
    let (cmd, _dirs) = crate::test_child::fixture_command_without_dac_bypass("unused::fixture");
    let dir = db_dir_of(&cmd);
    assert!(dir.is_absolute(), "{dir:?}");
    let meta = std::fs::metadata(&dir).unwrap_or_else(|e| panic!("{dir:?}: {e}"));
    assert!(meta.is_dir(), "{dir:?}");
    assert_eq!(
        meta.uid(),
        fixture_uid(),
        "{dir:?} is not owned by the fixture's identity"
    );
}

#[skuld::test]
fn each_dropped_identity_fixture_gets_its_own_skuld_db_dir() {
    let (a, _da) = crate::test_child::fixture_command_without_dac_bypass("unused::a");
    let (b, _db) = crate::test_child::fixture_command_without_dac_bypass("unused::b");
    assert_ne!(db_dir_of(&a), db_dir_of(&b));
}

#[skuld::test]
fn the_skuld_db_dir_outlives_the_command_and_goes_with_its_guard() {
    let (cmd, dirs) = crate::test_child::fixture_command_without_dac_bypass("unused::fixture");
    let dir = db_dir_of(&cmd);
    drop(cmd);
    assert!(
        dir.is_dir(),
        "{dir:?} must survive the command, so the fixture can use it"
    );
    drop(dirs);
    assert!(!dir.exists(), "{dir:?} must be removed with its guard");
}
