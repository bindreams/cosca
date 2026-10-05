use super::{check_facts, DirFacts, PrivateDir, PrivateDirError, Removal};
use crate::identity::ProcessId;
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
            check_facts(
                &DirFacts {
                    uid,
                    mode,
                    ignores_ownership: false,
                    acl_grants_others: false
                },
                me
            ),
            accepted,
            "owner {uid}, mode {mode:o}"
        );
    }
}

#[skuld::test]
fn path_check_refuses_an_acl_grant_and_an_ownerless_volume() {
    let facts = |ignores_ownership, acl_grants_others| DirFacts {
        uid: 1000,
        mode: 0o700,
        ignores_ownership,
        acl_grants_others,
    };
    assert!(check_facts(&facts(false, false), 1000));
    assert!(!check_facts(&facts(false, true), 1000));
    assert!(!check_facts(&facts(true, false), 1000));
}

/// Another test's `stat`, for the facts a `statfs` and an ACL are added to.
#[cfg(target_os = "macos")]
fn some_stat() -> rustix::fs::Stat {
    rustix::fs::stat(std::env::temp_dir()).unwrap()
}

/// XNU reports every file as the caller's on a volume with `MNT_IGNORE_OWNERSHIP`.
#[cfg(target_os = "macos")]
#[skuld::test]
fn an_ignore_ownership_volume_is_refused() {
    let mut st = some_stat();
    st.st_uid = euid();
    st.st_mode = 0o40700;
    let flags = libc::MNT_IGNORE_OWNERSHIP as u32;
    assert!(check_facts(&DirFacts::from_parts(&st, 0, false), euid()));
    assert!(!check_facts(&DirFacts::from_parts(&st, flags, false), euid()));
    assert!(!check_facts(&DirFacts::from_parts(&st, flags | 1, false), euid()));
}

/// Under uid 99 XNU reports every file as the caller's, whatever the volume.
#[cfg(target_os = "macos")]
#[skuld::test]
fn euid_99_is_refused_on_macos() {
    let facts = DirFacts {
        uid: 99,
        mode: 0o700,
        ignores_ownership: false,
        acl_grants_others: false,
    };
    assert!(!check_facts(&facts, 99));
}

#[cfg(target_os = "macos")]
fn chmod_acl(dir: &Path, ace: &str) {
    let out = crate::test_spawn::output_captured(std::process::Command::new("/bin/chmod").arg("+a").arg(ace).arg(dir))
        .unwrap();
    assert!(
        out.status.success(),
        "chmod +a {ace:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(target_os = "macos")]
fn acl_dir(ace: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("tmp");
    fs::create_dir(&dir).unwrap();
    chmod(&dir, 0o700);
    chmod_acl(&dir, ace);
    (root, dir)
}

/// An allow entry for another user lets them rename entries whatever the mode bits say.
#[cfg(target_os = "macos")]
#[skuld::test]
fn an_acl_allow_entry_that_changes_entries_is_refused() {
    for perm in ["add_file", "add_subdirectory", "delete_child", "writesecurity", "chown"] {
        for flags in ["", ",file_inherit,directory_inherit,only_inherit"] {
            let ace = format!("user:nobody allow {perm}{flags}");
            let (_root, dir) = acl_dir(&ace);
            let Err(PrivateDirError::Unsafe { offender, .. }) = PrivateDir::create_in(&dir) else {
                panic!("{ace:?} must be refused");
            };
            assert_eq!(offender, fs::canonicalize(&dir).unwrap(), "{ace:?}");
        }
    }
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn an_acl_with_only_denials_reads_and_our_own_entries_is_accepted() {
    for ace in [
        "everyone deny delete",
        "user:nobody deny add_file,delete_child",
        "user:nobody allow list,search,readattr",
    ] {
        let (_root, dir) = acl_dir(ace);
        let made = PrivateDir::create_in(&dir).unwrap_or_else(|e| panic!("{ace:?}: {e}"));
        assert_eq!(made.remove(), Removal::Removed);
    }
    let me = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(euid()))
        .unwrap()
        .expect("the euid has a user name")
        .name;
    let (_root, dir) = acl_dir(&format!("user:{me} allow add_file"));
    let made = PrivateDir::create_in(&dir).unwrap();
    assert_eq!(made.remove(), Removal::Removed);
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

#[skuld::test]
fn the_directory_is_0700_whatever_the_umask_says() {
    let Some(_done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(the_directory_is_0700_whatever_the_umask_says),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    // SAFETY: `umask` has no preconditions; this test runs alone in its process.
    unsafe { libc::umask(0o277) };
    let dir = PrivateDir::create_in(root.path()).unwrap();
    assert_eq!(fs::symlink_metadata(dir.path()).unwrap().mode() & 0o7777, 0o700);
}

#[skuld::test]
fn drop_in_the_owning_pid_removes_the_directory() {
    let root = tempfile::tempdir().unwrap();
    let dir = PrivateDir::create_in(root.path()).unwrap();
    let path = dir.path().to_owned();
    drop(dir);
    assert!(!path.exists());
}

#[skuld::test]
fn drop_logs_what_remove_logs() {
    crate::log_capture::install();
    let root = tempfile::tempdir().unwrap();
    let dir = PrivateDir::create_in(root.path()).unwrap();
    let path = dir.path().to_owned();
    fs::write(path.join("leftover"), b"x").unwrap();
    let mark = crate::log_capture::mark();
    drop(dir);
    assert!(path.join("leftover").exists());
    let path_text = path.display().to_string();
    assert!(crate::log_capture::levels_since(mark, &path_text).contains(&log::Level::Warn));
}

/// `who`, released as if it were the current process.
fn drop_as(dir: &mut PrivateDir, who: ProcessId) {
    dir.release(who);
}

#[skuld::test]
fn a_fork_copys_drop_leaves_the_directory() {
    let root = tempfile::tempdir().unwrap();
    let mut dir = PrivateDir::create_in(root.path()).unwrap();
    let path = dir.path().to_owned();
    drop_as(&mut dir, ProcessId::from_parts(std::process::id().wrapping_add(1), 7));
    assert!(
        path.is_dir(),
        "a pid that did not make the directory must not remove it"
    );
    drop(dir);
    assert!(!path.exists(), "the creator's drop still removes it");
}

/// In another pid namespace a fork copy can have the creator's pid (1, for a namespace's init); only
/// its start identity differs.
#[skuld::test]
fn a_process_with_the_creators_pid_but_another_identity_leaves_the_directory() {
    let root = tempfile::tempdir().unwrap();
    let mut dir = PrivateDir::create_in(root.path()).unwrap();
    let path = dir.path().to_owned();
    let me = ProcessId::current();
    drop_as(
        &mut dir,
        ProcessId::from_parts(me.pid(), me.start_token_raw().wrapping_add(1)),
    );
    assert!(
        path.is_dir(),
        "the same pid with another start identity is another process"
    );
    drop(dir);
    assert!(!path.exists());
}

fn open_fails(_: &std::os::fd::OwnedFd, _: &std::ffi::OsStr) -> rustix::io::Result<rustix::fs::Stat> {
    Err(rustix::io::Errno::IO)
}

/// Removes the directory itself, so the cleanup that follows fails with `ENOENT`.
fn open_fails_after_removing(
    parent: &std::os::fd::OwnedFd,
    name: &std::ffi::OsStr,
) -> rustix::io::Result<rustix::fs::Stat> {
    rustix::fs::unlinkat(parent, name, rustix::fs::AtFlags::REMOVEDIR)?;
    Err(rustix::io::Errno::IO)
}

#[skuld::test]
fn a_failure_after_mkdirat_removes_the_directory() {
    let root = tempfile::tempdir().unwrap();
    let Err(PrivateDirError::Create { path, .. }) = PrivateDir::create_with(root.path(), open_fails) else {
        panic!("a failing open must be a Create error");
    };
    assert!(!path.exists(), "the half-made directory must not be left");
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[skuld::test]
fn a_failed_cleanup_after_a_failure_warns() {
    crate::log_capture::install();
    let root = tempfile::tempdir().unwrap();
    let mark = crate::log_capture::mark();
    let Err(PrivateDirError::Create { path, .. }) = PrivateDir::create_with(root.path(), open_fails_after_removing)
    else {
        panic!("a failing open must be a Create error");
    };
    let path_text = path.display().to_string();
    assert!(crate::log_capture::levels_since(mark, &path_text).contains(&log::Level::Warn));
}
