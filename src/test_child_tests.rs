//! Unit tests for the fixtures in `test_child`: [`super::RestoreMode`], plus controls for the
//! assumptions a test's assertion leans on, run against the fixture alone so a wrong one fails
//! here and not as a confusing failure elsewhere.

/// Skuld's capture is fd-level and drops a passing test's bytes, so the gate line and every
/// stdout-based handshake need the child to run uncaptured.
#[test]
fn fixture_command_disables_capture() {
    let cmd = crate::test_child::fixture_command("m::t");
    assert!(
        cmd.get_args().any(|arg| arg == "--nocapture"),
        "{:?}",
        cmd.get_args().collect::<Vec<_>>()
    );
}

#[cfg(windows)]
#[test]
fn fixture_argv_disables_capture() {
    assert!(crate::test_child::fixture_argv("m::t").contains(&"--nocapture"));
}

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

/// [`windows_more`](super::windows_more) exits 0 when its stdin closes. Every Windows test that
/// takes a non-zero exit as proof of a kill relies on this: were it non-zero, a natural end would
/// read as a kill.
#[cfg(windows)]
#[test]
fn windows_more_exits_zero_when_its_stdin_closes() {
    let mut cmd = crate::Command::new();
    cmd.args([super::windows_more()]);
    cmd.stdin(crate::Stdio::pipe()).expect("set stdin pipe");
    cmd.stdout(crate::Stdio::null()).expect("set stdout null");
    let mut child = cmd.spawn().expect("spawn");
    drop(child.stdin().expect("piped stdin"));
    let status = child.wait().expect("wait");
    assert!(
        status.success(),
        "more.com must exit 0 on stdin EOF, or a natural end reads as a kill: {status:?}"
    );
}
