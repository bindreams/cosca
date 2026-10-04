use super::{check_facts, DirFacts, PrivateDir, PrivateDirError, Removal};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

const STICKY: u32 = 0o1000;

fn euid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[skuld::test]
fn path_check_accepts_sticky_root_and_own_0700_and_refuses_the_rest() {
    let me = 1000;
    let other = 2000;
    // (owner, mode, accepted)
    let table = [
        (0, 0o755, true),
        (0, STICKY | 0o777, true),
        (0, 0o775, false),
        (0, 0o757, false),
        (me, 0o700, true),
        (me, 0o755, true),
        (me, 0o770, false),
        (me, 0o777, false),
        (me, STICKY | 0o777, true),
        // Sticky stops others deleting our entries, not their owner renaming the directory itself.
        (other, STICKY | 0o777, false),
        (other, 0o755, false),
        (other, 0o700, false),
    ];
    for (uid, mode, accepted) in table {
        assert_eq!(
            check_facts(&DirFacts { uid, mode }, me),
            accepted,
            "owner {uid}, mode {mode:o}"
        );
    }
}

#[skuld::test]
fn ancestor_writable_by_others_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let wide = root.path().join("wide");
    let tmp = wide.join("tmp");
    fs::create_dir_all(&tmp).unwrap();
    chmod(&tmp, 0o700);
    chmod(&wide, 0o777);
    let Err(PrivateDirError::Unsafe { offender, .. }) = PrivateDir::create_in(&tmp) else {
        panic!("a 0777 ancestor must be refused");
    };
    assert_eq!(offender, fs::canonicalize(&wide).unwrap());
}

#[skuld::test]
fn world_writable_tmpdir_itself_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let tmp = root.path().join("tmp");
    fs::create_dir(&tmp).unwrap();
    chmod(&tmp, 0o777);
    let Err(PrivateDirError::Unsafe { tmpdir, offender }) = PrivateDir::create_in(&tmp) else {
        panic!("a 0777 tmpdir must be refused");
    };
    assert_eq!(offender, fs::canonicalize(&tmp).unwrap());
    assert_eq!(tmpdir, tmp);
}

#[skuld::test]
fn accepts_the_real_system_tmpdir() {
    let tmp = std::env::temp_dir();
    let dir = PrivateDir::create_in(&tmp).unwrap_or_else(|e| panic!("{}: {e}", tmp.display()));
    let meta = fs::symlink_metadata(dir.path()).unwrap();
    assert!(meta.is_dir());
    assert_eq!(meta.mode() & 0o7777, 0o700);
    assert_eq!(meta.uid(), euid());
    let other = PrivateDir::create_in(&tmp).unwrap();
    assert_ne!(dir.path(), other.path(), "the name is random");
    let (gone, also_gone) = (dir.path().to_owned(), other.path().to_owned());
    assert_eq!(dir.remove(), Removal::Removed);
    assert_eq!(other.remove(), Removal::Removed);
    assert!(!gone.exists() && !also_gone.exists());
}

#[skuld::test]
fn cleanup_leaves_a_directory_swapped_in_under_our_name() {
    crate::log_capture::install();
    let root = tempfile::tempdir().unwrap();
    let dir = PrivateDir::create_in(root.path()).unwrap();
    let path = dir.path().to_owned();
    fs::rename(&path, root.path().join("moved")).unwrap();
    fs::create_dir(&path).unwrap();
    let mark = crate::log_capture::mark();
    assert_eq!(dir.remove(), Removal::NotOurs);
    assert!(path.is_dir(), "the stranger's directory under our name must stay");
    let path_text = path.display().to_string();
    assert!(crate::log_capture::levels_since(mark, &path_text).contains(&log::Level::Warn));
}

#[skuld::test]
fn leftover_file_reports_not_empty_and_warns() {
    crate::log_capture::install();
    let root = tempfile::tempdir().unwrap();
    let dir = PrivateDir::create_in(root.path()).unwrap();
    let path = dir.path().to_owned();
    fs::write(path.join("leftover"), b"x").unwrap();
    let mark = crate::log_capture::mark();
    assert_eq!(dir.remove(), Removal::NotEmpty);
    assert!(path.join("leftover").exists(), "nothing inside is deleted");
    let path_text = path.display().to_string();
    assert!(crate::log_capture::levels_since(mark, &path_text).contains(&log::Level::Warn));
}

#[skuld::test]
fn already_removed_directory_is_gone_and_not_a_warning() {
    crate::log_capture::install();
    let root = tempfile::tempdir().unwrap();
    let dir = PrivateDir::create_in(root.path()).unwrap();
    let path = dir.path().to_owned();
    fs::remove_dir(&path).unwrap();
    let mark = crate::log_capture::mark();
    assert_eq!(dir.remove(), Removal::Gone);
    let path_text = path.display().to_string();
    assert!(!crate::log_capture::levels_since(mark, &path_text)
        .iter()
        .any(|l| *l <= log::Level::Warn));
}

#[skuld::test]
fn relative_or_missing_tmpdir_is_an_error_naming_it() {
    let relative = Path::new("relative/tmp");
    let Err(e @ PrivateDirError::TmpdirNotAbsolute(_)) = PrivateDir::create_in(relative) else {
        panic!("a relative tmpdir must be refused");
    };
    assert!(e.to_string().contains("relative/tmp"), "{e}");

    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("missing");
    let Err(e @ PrivateDirError::Tmpdir { .. }) = PrivateDir::create_in(&missing) else {
        panic!("a missing tmpdir must be refused");
    };
    assert!(e.to_string().contains(&missing.display().to_string()), "{e}");
}
