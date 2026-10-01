/// A `/tmp` directory only `uid` can use, for a re-exec's `SKULD_DB_DIR` (it cannot write beside the
/// executable). The caller must be root.
pub fn skuld_db_dir_for(uid: u32) -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .prefix("cosca-skuld-db-")
        .tempdir_in("/tmp")
        .expect("tempdir directly under /tmp for a re-exec's skuld DB");
    std::os::unix::fs::chown(dir.path(), Some(uid), Some(uid))
        .unwrap_or_else(|e| panic!("chown the skuld DB directory to {uid}: {e}"));
    dir
}
