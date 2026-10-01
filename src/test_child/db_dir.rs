//! The coordination-DB directory of a fixture that has dropped identity.
//!
//! Skuld opens its DB for every test, in the directory its executable derives, or in
//! `SKULD_DB_DIR`. A fixture that dropped DAC bypass or changed uid usually cannot write beside
//! its executable, and skuld then panics naming the directory. The driver hands it a directory of
//! its own instead.

/// The variable skuld reads for the directory of its coordination DB.
pub(super) const SKULD_DB_DIR_ENV: &str = "SKULD_DB_DIR";

/// What a dropped-identity fixture needs the driver to keep alive until the fixture has exited.
pub(crate) struct FixtureDirs {
    _exe_copy: Option<tempfile::TempDir>,
    _db_dir: tempfile::TempDir,
}

impl FixtureDirs {
    pub(super) fn new(exe_copy: Option<tempfile::TempDir>, db_dir: tempfile::TempDir) -> Self {
        Self {
            _exe_copy: exe_copy,
            _db_dir: db_dir,
        }
    }
}

/// A fresh directory directly under `/tmp` (searchable end to end, unlike the ambient `TMPDIR`)
/// that a fixture dropping DAC bypass can create files in. Where a root driver changes uid
/// (non-Linux), it belongs to the identity the fixture drops to; elsewhere the fixture keeps the
/// driver's uid, which owns it.
pub(super) fn fixture_db_dir() -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .prefix("cosca-skuld-db-")
        .tempdir_in("/tmp")
        .expect("tempdir directly under /tmp for the fixture's skuld DB");
    #[cfg(not(target_os = "linux"))]
    // SAFETY: `geteuid` has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        let uid = crate::test_privilege::UNPRIVILEGED;
        std::os::unix::fs::chown(dir.path(), Some(uid), Some(uid))
            .expect("chown the fixture's skuld DB directory to its post-drop identity");
    }
    dir
}

#[cfg(test)]
#[path = "db_dir_tests.rs"]
mod db_dir_tests;
