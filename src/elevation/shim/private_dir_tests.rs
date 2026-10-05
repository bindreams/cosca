use super::super::fork_guard::Origin;
use super::facts::{check_dir, check_facts, refused_filesystem, FsOverride, Unfit};
use super::{DirFacts, NotOriginal, PrivateDir, PrivateDirError, Removal};
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
                    acl_grants_others: false,
                    fs_type: 0,
                    not_local: false,
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
        fs_type: 0,
        not_local: false,
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
    assert!(check_facts(&DirFacts::from_parts(&st, 0, 0, false), euid()));
    assert!(!check_facts(&DirFacts::from_parts(&st, flags, 0, false), euid()));
    assert!(!check_facts(&DirFacts::from_parts(&st, flags | 1, 0, false), euid()));
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
        fs_type: 0,
        not_local: false,
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
        assert_eq!(made.remove(Origin::Original).unwrap(), Removal::Removed);
    }
    let me = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(euid()))
        .unwrap()
        .expect("the euid has a user name")
        .name;
    let (_root, dir) = acl_dir(&format!("user:{me} allow add_file"));
    let made = PrivateDir::create_in(&dir).unwrap();
    assert_eq!(made.remove(Origin::Original).unwrap(), Removal::Removed);
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
    assert_eq!(dir.remove(Origin::Original).unwrap(), Removal::Removed);
    assert_eq!(other.remove(Origin::Original).unwrap(), Removal::Removed);
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
    assert_eq!(dir.remove(Origin::Original).unwrap(), Removal::NotOurs);
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
    assert_eq!(dir.remove(Origin::Original).unwrap(), Removal::NotEmpty);
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
    assert_eq!(dir.remove(Origin::Original).unwrap(), Removal::Gone);
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

#[skuld::test]
fn a_fork_copys_drop_leaves_the_directory() {
    let root = tempfile::tempdir().unwrap();
    let mut dir = PrivateDir::create_in(root.path()).unwrap();
    let path = dir.path().to_owned();
    dir.release(Origin::Copy);
    assert!(
        path.is_dir(),
        "a process that did not make the directory must not remove it"
    );
    drop(dir);
    assert!(!path.exists(), "the creator's drop still removes it");
}

/// The real thing: a forked child drops its copy of the directory.
#[skuld::test]
fn a_real_fork_copys_drop_leaves_the_directory() {
    let root = tempfile::tempdir().unwrap();
    let dir = PrivateDir::create_in(root.path()).unwrap();
    let path = dir.path().to_owned();
    // SAFETY: the child only drops its copy (which takes malloc's lock, and glibc and libmalloc
    // reset that across fork) and `_exit`s.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(dir)));
        // SAFETY: `_exit` never returns.
        unsafe { libc::_exit(if dropped.is_ok() { 0 } else { 101 }) };
    }
    let mut status = 0;
    // SAFETY: `pid` is this test's own unreaped child.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "child status {status:#x}"
    );
    assert!(path.is_dir(), "the copy's drop must not remove the directory");
    drop(dir);
    assert!(!path.exists(), "the creator's drop removes it");
}

/// With no descriptor left, removing and dropping the directory neither panics nor fails: neither
/// needs a new descriptor. A panic in `Drop` during an unwind aborts the process.
#[skuld::test]
fn dropping_with_a_full_fd_table_does_not_panic() {
    let Some(done) = crate::test_own_process::own_process(
        crate::test_own_process::test_path!(dropping_with_a_full_fd_table_does_not_panic),
        crate::test_spawn::spawn,
    ) else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let dir = PrivateDir::create_in(root.path()).unwrap();
    let path = dir.path().to_owned();
    let _restore = crate::test_child::exhaust_fds(&done);
    assert!(
        std::fs::File::open("/dev/null").is_err(),
        "the precondition: no descriptor can be opened"
    );
    drop(dir);
    assert!(!path.exists(), "the drop still removed the directory");
}

/// `remove` refuses, as an error in release builds too, for any origin but the creator's.
#[skuld::test]
fn remove_refuses_a_copy_and_an_unknown_origin() {
    for origin in [Origin::Copy, Origin::Unknown] {
        let root = tempfile::tempdir().unwrap();
        let dir = PrivateDir::create_unguarded(root.path()).unwrap();
        let path = dir.path().to_owned();
        assert_eq!(dir.remove(origin), Err(NotOriginal(origin)));
        assert!(path.is_dir(), "{origin:?} must not remove the directory");
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
        fs::remove_dir(&path).unwrap();
    }
}

/// An unguarded directory is removed by its owner only: dropping it does nothing.
#[skuld::test]
fn dropping_an_unguarded_directory_leaves_it() {
    let root = tempfile::tempdir().unwrap();
    let dir = PrivateDir::create_unguarded(root.path()).unwrap();
    let path = dir.path().to_owned();
    drop(dir);
    assert!(path.is_dir());
}

/// A process whose origin cannot be told leaves the directory: from a copy, removing it would take
/// the original's.
#[skuld::test]
fn an_unknown_origin_leaves_the_directory() {
    let root = tempfile::tempdir().unwrap();
    let mut dir = PrivateDir::create_in(root.path()).unwrap();
    let path = dir.path().to_owned();
    dir.release(Origin::Unknown);
    assert!(path.is_dir());
    drop(dir);
    assert!(!path.exists(), "the creator's drop still removes it");
}

fn open_fails(
    _: &std::os::fd::OwnedFd,
    _: &std::ffi::OsStr,
) -> rustix::io::Result<(std::os::fd::OwnedFd, rustix::fs::Stat)> {
    Err(rustix::io::Errno::IO)
}

/// Removes the directory itself, so the cleanup that follows fails with `ENOENT`.
fn open_fails_after_removing(
    parent: &std::os::fd::OwnedFd,
    name: &std::ffi::OsStr,
) -> rustix::io::Result<(std::os::fd::OwnedFd, rustix::fs::Stat)> {
    rustix::fs::unlinkat(parent, name, rustix::fs::AtFlags::REMOVEDIR)?;
    Err(rustix::io::Errno::IO)
}

#[skuld::test]
fn a_failure_after_mkdirat_removes_the_directory() {
    let root = tempfile::tempdir().unwrap();
    let Err(PrivateDirError::Create { path, .. }) = PrivateDir::create_with(root.path(), open_fails, true) else {
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
    let Err(PrivateDirError::Create { path, .. }) =
        PrivateDir::create_with(root.path(), open_fails_after_removing, true)
    else {
        panic!("a failing open must be a Create error");
    };
    let path_text = path.display().to_string();
    assert!(crate::log_capture::levels_since(mark, &path_text).contains(&log::Level::Warn));
}

/// Network and user-space filesystems are refused, and local ones are not. Mutant: the type is
/// ignored.
#[skuld::test]
fn network_and_fuse_filesystems_are_refused() {
    let facts = |fs_type| DirFacts {
        uid: 1000,
        mode: 0o700,
        ignores_ownership: false,
        acl_grants_others: false,
        fs_type,
        not_local: false,
    };
    let refused = [
        (0x6969, "NFS"),
        (0x6573_5546, "FUSE"),
        (0x517B, "SMB"),
        (0xFE53_4D42, "SMB2"),
        (0xFF53_4D42, "CIFS"),
        (0x00C3_6400, "Ceph"),
        (0x5346_414F, "AFS"),
        (0x6B41_4653, "kAFS"),
        (0x7375_7245, "Coda"),
        (0x564C, "NCP"),
        (0x0BD0_0BD0, "Lustre"),
        (0x0102_1997, "9p"),
        (0x786F_4256, "vboxsf"),
        (0x7C7C_6673, "prl_fs"),
        (0xBACB_ACBC, "vmhgfs"),
        (0x4750_4653, "GPFS"),
        (0x1983_0326, "BeeGFS"),
        (0xAAD7_AAEA, "PanFS"),
    ];
    for (magic, name) in refused {
        assert_eq!(refused_filesystem(magic), Some(name));
        assert_eq!(check_dir(&facts(magic), 1000), Err(Unfit::Filesystem(name)));
        // A sign-extended `f_type`, as some architectures report it.
        assert_eq!(refused_filesystem(magic | 0xFFFF_FFFF_0000_0000), Some(name));
    }
    // ext4, tmpfs, btrfs, xfs, overlayfs, zfs, and "unknown".
    for local in [
        0xEF53,
        0x0102_1994,
        0x9123_683E,
        0x5846_5342,
        0x794C_7630,
        0x2FC1_2FC1,
        0,
    ] {
        assert_eq!(check_dir(&facts(local), 1000), Ok(()), "{local:#x}");
    }
}

/// The real `fstatfs` of a directory reports a type, and the system temp directory's is not one
/// that is refused.
#[cfg(target_os = "linux")]
#[skuld::test]
fn the_real_filesystem_type_of_the_system_tmpdir_is_read_and_accepted() {
    let tmp = std::env::temp_dir();
    let real = std::fs::canonicalize(&tmp).unwrap();
    let dir = std::fs::File::open(&real).unwrap();
    let st = rustix::fs::fstat(&dir).unwrap();
    let facts = DirFacts::read_fd(std::os::fd::AsFd::as_fd(&dir), &real, &st, euid(), None).unwrap();
    assert_ne!(facts.fs_type, 0, "fstatfs reports a type");
    assert_eq!(refused_filesystem(facts.fs_type), None);
}

/// Mount flags of a local volume.
#[cfg(target_os = "macos")]
fn local_mount_flags() -> u32 {
    libc::MNT_LOCAL as u32
}

#[cfg(not(target_os = "macos"))]
fn local_mount_flags() -> u32 {
    0
}

/// The temp directory's own filesystem decides, through `create_in`'s path: an NFS one is refused
/// naming the filesystem and `TMPDIR`; a tmpfs one is accepted, whatever its ancestors are on (they
/// are never asked). Mutant: `check_facts` where `check_dir` is.
#[skuld::test]
fn the_temp_directorys_own_filesystem_decides() {
    let over = |fs_type| {
        Some(FsOverride {
            mount_flags: local_mount_flags(),
            fs_type,
        })
    };
    let root = tempfile::tempdir().unwrap();
    let real = PrivateDir::resolve(root.path()).unwrap();
    let Err(error @ PrivateDirError::Filesystem { .. }) =
        PrivateDir::create_resolved(root.path(), real.clone(), super::open_and_harden, true, over(0x6969))
    else {
        panic!("an NFS temp directory must be refused");
    };
    let text = error.to_string();
    assert!(
        text.contains("NFS") && text.contains("TMPDIR") && text.contains(&real.display().to_string()),
        "{text}"
    );
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0, "nothing is made");
    let dir = PrivateDir::create_resolved(root.path(), real, super::open_and_harden, true, over(0x0102_1994)).unwrap();
    drop(dir);
}

/// A volume that is not local (macOS: no `MNT_LOCAL`) is refused like a network filesystem.
#[skuld::test]
fn a_volume_that_is_not_local_is_refused() {
    let facts = DirFacts {
        uid: 1000,
        mode: 0o700,
        ignores_ownership: false,
        acl_grants_others: false,
        fs_type: 0,
        not_local: true,
    };
    assert_eq!(
        check_dir(&facts, 1000),
        Err(Unfit::Filesystem("a volume that is not local"))
    );
}

/// On macOS the mount flags decide: a volume without `MNT_LOCAL` is refused through `create_in`.
#[cfg(target_os = "macos")]
#[skuld::test]
fn macos_a_temp_directory_without_mnt_local_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let real = PrivateDir::resolve(root.path()).unwrap();
    let over = Some(FsOverride {
        mount_flags: 0,
        fs_type: 0,
    });
    let Err(PrivateDirError::Filesystem { filesystem, .. }) =
        PrivateDir::create_resolved(root.path(), real, super::open_and_harden, true, over)
    else {
        panic!("a volume without MNT_LOCAL must be refused");
    };
    assert_eq!(filesystem, "a volume that is not local");
}

#[skuld::test]
fn the_directory_fd_names_the_directory() {
    let root = tempfile::tempdir().unwrap();
    let dir = PrivateDir::create_in(root.path()).unwrap();
    let by_fd = rustix::fs::fstat(dir.dir_fd()).unwrap();
    let by_path = fs::metadata(dir.path()).unwrap();
    assert_eq!(
        (by_fd.st_dev as u64, by_fd.st_ino as u64),
        (by_path.dev(), by_path.ino())
    );
}
