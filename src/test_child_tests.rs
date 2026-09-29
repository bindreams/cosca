//! Unit tests for [`super::RestoreMode`].

#[cfg(unix)]
mod restore_mode_tests {
    use crate::test_child::RestoreMode;
    use std::os::unix::fs::PermissionsExt as _;

    /// `TempDir::drop` needs to list a directory to remove it, so a locked one would leak without
    /// the restore. This mirrors the declaration order callers rely on (`dir`, then `_restore`).
    #[test]
    fn a_locked_dir_is_removed_on_drop() {
        let path = {
            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir(dir.path().join("inner")).unwrap();
            let locked = dir.path().join("inner");
            let _restore = RestoreMode::new(&locked, 0o755);
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
            dir.path().to_path_buf()
        };
        assert!(!path.exists(), "{path:?} was not removed on drop");
    }
}
