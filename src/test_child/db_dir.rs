//! The coordination-DB directory of a fixture that has dropped identity.
//!
//! Skuld opens its DB for every test, in the directory its executable derives, or in
//! `SKULD_DB_DIR`. A fixture that dropped DAC bypass or changed uid usually cannot write beside
//! its executable, and skuld then panics naming the directory. The driver hands it a directory of
//! its own instead.

/// The variable skuld reads for the directory of its coordination DB.
pub(crate) const SKULD_DB_DIR_ENV: &str = "SKULD_DB_DIR";

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

/// A fresh directory directly under `/tmp` (searchable end to end, unlike the ambient `TMPDIR`) that the
/// fixture's post-drop identity can write.
pub(super) fn fixture_db_dir() -> tempfile::TempDir {
    let dir = tmp_dir();
    #[cfg(not(target_os = "linux"))]
    // SAFETY: `geteuid` has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        chown_to(dir.path(), crate::test_privilege::UNPRIVILEGED);
    }
    dir
}

/// [`fixture_db_dir`] for a root fixture that drops to `uid` mid-test. Skuld opened the DB as root,
/// and its end-of-test check of the DB's path needs every directory on it searchable by `uid`; a
/// root-owned `0700` directory is not.
#[cfg(target_os = "linux")]
pub(super) fn fixture_db_dir_owned_by(uid: libc::uid_t) -> tempfile::TempDir {
    let dir = tmp_dir();
    chown_to(dir.path(), uid);
    dir
}

fn tmp_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("cosca-skuld-db-")
        .tempdir_in("/tmp")
        .expect("tempdir directly under /tmp for the fixture's skuld DB")
}

fn chown_to(dir: &std::path::Path, uid: libc::uid_t) {
    std::os::unix::fs::chown(dir, Some(uid), Some(uid))
        .expect("chown the fixture's skuld DB directory to its post-drop identity");
}

#[cfg(test)]
#[path = "db_dir_tests.rs"]
mod db_dir_tests;
