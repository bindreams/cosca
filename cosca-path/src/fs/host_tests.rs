use std::io;

use super::{absence_as_not_found, is_absence};
use crate::fs::{Filesystem, HostFilesystem};
#[cfg(windows)]
use crate::PurePath;

#[cfg(unix)]
use crate::posix::PathBuf;
#[cfg(windows)]
use crate::windows::PathBuf;

/// `p`, a `std` path, as a cosca-path path.
fn host(p: &std::path::Path) -> PathBuf {
    #[cfg(windows)]
    return PathBuf::from_std_path(p).unwrap();
    #[cfg(unix)]
    return crate::posix::Path::from_std_path(p).to_path_buf();
}

/// The raw codes that mean "nothing there" are absence; the ones that only look like it are not.
///
/// Mutants: a list missing one of the six codes; deciding on `ErrorKind::NotFound`, which `std`
/// also gives `ERROR_BAD_NETPATH` and `ERROR_BAD_NET_NAME` (an unreachable share may only be
/// unreachable for now).
#[skuld::test]
fn host_filesystem_treats_not_found_codes_as_absence() {
    #[cfg(windows)]
    let (absent, present): (&[i32], &[i32]) = (
        // FILE_NOT_FOUND, PATH_NOT_FOUND, INVALID_DRIVE, INVALID_NAME, BAD_PATHNAME, DIRECTORY.
        &[2, 3, 15, 123, 161, 267],
        // ACCESS_DENIED, SHARING_VIOLATION, BAD_NETPATH, BAD_NET_NAME, NOT_READY.
        &[5, 32, 53, 67, 21],
    );
    #[cfg(unix)]
    let (absent, present): (&[i32], &[i32]) = (
        &[libc::ENOENT, libc::ENOTDIR],
        &[libc::EACCES, libc::EIO, libc::ELOOP, libc::ENAMETOOLONG],
    );
    for &code in absent {
        assert!(is_absence(&io::Error::from_raw_os_error(code)), "code {code}");
    }
    for &code in present {
        assert!(!is_absence(&io::Error::from_raw_os_error(code)), "code {code}");
    }
    // An error with no OS code is judged by its kind.
    assert!(is_absence(&io::Error::from(io::ErrorKind::NotFound)));
    assert!(!is_absence(&io::Error::from(io::ErrorKind::PermissionDenied)));
}

/// `HostFilesystem` answers for a directory the test creates.
///
/// Mutants: `is_file` and `is_dir` swapped; an absent path reported as an error; `same_file`
/// comparing spellings instead of identity.
#[skuld::test]
fn host_filesystem_probes_a_temp_directory() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file");
    std::fs::write(&file, b"").unwrap();
    let (dir_p, file_p) = (host(dir.path()), host(&file));
    let fs = HostFilesystem;

    assert!(fs.is_file(&file_p).unwrap());
    assert!(!fs.is_dir(&file_p).unwrap());
    assert!(fs.is_dir(&dir_p).unwrap());
    assert!(!fs.is_file(&dir_p).unwrap());

    // Absent: nothing there, a non-directory in the path, and (Windows) a name no filesystem takes.
    let mut gone = vec![
        host(&dir.path().join("missing")),
        host(&dir.path().join("missing").join("x")),
        host(&file.join("below")),
    ];
    // `|` is not a Windows name character (INVALID_NAME); on Unix it is an ordinary one.
    gone.extend(cfg!(windows).then(|| host(&dir.path().join("bad|name"))));
    for p in &gone {
        assert!(!fs.is_file(p).unwrap(), "{p:?}");
        assert!(!fs.is_dir(p).unwrap(), "{p:?}");
    }

    // Identity, not spelling: `dir/./file` is the same file as `dir/file`.
    let dotted = host(&dir.path().join(".").join("file"));
    assert_ne!(dotted, file_p);
    assert!(fs.same_file(&dotted, &file_p).unwrap());
    assert!(!fs.same_file(&file_p, &dir_p).unwrap());
    assert_eq!(
        fs.same_file(&file_p, &host(&dir.path().join("missing")))
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );

    // `canonical` resolves the path, not echoes it: `dir/./file` and `dir/file` canonicalise alike,
    // and the Windows `\\?\` prefix `std` adds does not leak.
    let canonical = fs.canonical(&dotted).unwrap();
    assert_ne!(canonical, dotted);
    assert_eq!(canonical, fs.canonical(&file_p).unwrap());
    let std_canonical = std::fs::canonicalize(&file).unwrap();
    #[cfg(windows)]
    {
        let verbatim = std_canonical.to_str().unwrap();
        let plain = verbatim
            .strip_prefix(r"\\?\")
            .expect("std canonicalises to a verbatim path");
        assert_eq!(canonical, PathBuf::parse(plain).unwrap());
        assert!(!canonical.to_str().unwrap().starts_with(r"\\?\"), "{canonical:?}");
    }
    #[cfg(unix)]
    assert_eq!(canonical, host(&std_canonical));
    // An absent path has no canonical form.
    assert_eq!(
        fs.canonical(&host(&dir.path().join("missing"))).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

/// A Windows path reaches `std` as the string that names what its names spell: `dir\tool.` is the
/// file `tool.`, which is absent beside `tool`. A path with no such string is an error, not
/// absence.
///
/// Mutant: `HostFilesystem` hands `std` the stored text, which Win32 reads as `dir\tool`.
#[cfg(windows)]
#[skuld::test]
fn host_filesystem_probes_what_the_path_names() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("tool"), b"").unwrap();
    let fs = HostFilesystem;

    assert!(fs.is_file(&host(&dir.path().join("tool"))).unwrap());
    let dotted = host(&dir.path().join("tool."));
    assert!(!fs.is_file(&dotted).unwrap(), "{dotted:?}");
    assert!(!fs.is_dir(&dotted).unwrap(), "{dotted:?}");

    let relative = PathBuf::parse("tool.").unwrap();
    assert_eq!(fs.is_file(&relative).unwrap_err().kind(), io::ErrorKind::InvalidInput);
}

/// An error that is not absence never has the kind `NotFound`, whatever `std` calls it: an
/// unreachable server or share (`ERROR_BAD_NETPATH`, `ERROR_BAD_NET_NAME`) may only be unreachable
/// for now. The OS error stays inside (`get_ref`). Checked for every OS code, so a sibling that
/// `std` maps to `NotFound` is caught too.
///
/// Mutants: `canonical` and `same_file` passing such an error through unchanged; a mapping that
/// turns every `NotFound`-kind error into absence.
#[skuld::test]
fn host_filesystem_does_not_say_absence_for_what_is_not() {
    for code in 1..=65535 {
        let raw = io::Error::from_raw_os_error(code);
        let absent = is_absence(&raw);
        let mapped = absence_as_not_found(raw);
        assert_eq!(mapped.kind() == io::ErrorKind::NotFound, absent, "code {code}");
        if mapped.raw_os_error().is_none() {
            let source = mapped.get_ref().and_then(|e| e.downcast_ref::<io::Error>());
            assert_eq!(source.and_then(io::Error::raw_os_error), Some(code), "code {code}");
        }
    }
    #[cfg(windows)]
    for code in [53, 67] {
        let kind = absence_as_not_found(io::Error::from_raw_os_error(code)).kind();
        assert_ne!(kind, io::ErrorKind::NotFound, "code {code}");
    }
}

/// A share that cannot be reached is an `Err` from every question, never `Ok(false)` and never
/// `NotFound`. `localhost` resolves without network traffic, and a share it does not hold is
/// `ERROR_BAD_NET_NAME` (or `ERROR_BAD_NETPATH` where no server answers).
///
/// Mutant: `is_file`, `is_dir`, `canonical` or `same_file` keeping `std`'s `NotFound` kind for it.
#[cfg(windows)]
#[skuld::test]
fn host_filesystem_does_not_take_an_unreachable_share_for_absence() {
    let share = PathBuf::parse(r"\\localhost\cosca-no-such-share\x").unwrap();
    let here = host(&std::env::current_dir().unwrap());
    let fs = HostFilesystem;
    let not_absence = |what: &str, r: io::Result<bool>| {
        let e = r.expect_err(what);
        assert_ne!(e.kind(), io::ErrorKind::NotFound, "{what}: {e:?}");
    };
    not_absence("is_file", fs.is_file(&share));
    not_absence("is_dir", fs.is_dir(&share));
    assert_ne!(fs.canonical(&share).unwrap_err().kind(), io::ErrorKind::NotFound);
    not_absence("same_file", fs.same_file(&here, &share));
    not_absence("same_file", fs.same_file(&share, &here));
}

/// The empty path is `InvalidInput` on Windows (no string names it) and absent on Unix, from every
/// question: the fakes answer the same.
///
/// Mutant: a host that answers one question differently from the others.
#[skuld::test]
fn host_filesystem_reads_the_empty_path_per_os() {
    let (empty, here) = (PathBuf::new(), host(&std::env::current_dir().unwrap()));
    let fs = HostFilesystem;
    #[cfg(windows)]
    {
        let invalid = io::ErrorKind::InvalidInput;
        assert_eq!(fs.is_file(&empty).unwrap_err().kind(), invalid);
        assert_eq!(fs.is_dir(&empty).unwrap_err().kind(), invalid);
        assert_eq!(fs.canonical(&empty).unwrap_err().kind(), invalid);
        assert_eq!(fs.same_file(&empty, &here).unwrap_err().kind(), invalid);
        assert_eq!(fs.same_file(&here, &empty).unwrap_err().kind(), invalid);
    }
    #[cfg(unix)]
    {
        let not_found = io::ErrorKind::NotFound;
        assert!(!fs.is_file(&empty).unwrap());
        assert!(!fs.is_dir(&empty).unwrap());
        assert_eq!(fs.canonical(&empty).unwrap_err().kind(), not_found);
        assert_eq!(fs.same_file(&empty, &here).unwrap_err().kind(), not_found);
        assert_eq!(fs.same_file(&here, &empty).unwrap_err().kind(), not_found);
    }
}

/// A link canonicalises to its target, and is the same file as it.
///
/// Mutant: `canonical` returning its argument.
#[cfg(unix)]
#[skuld::test]
fn host_filesystem_follows_a_link() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file");
    let link = dir.path().join("link");
    std::fs::write(&file, b"").unwrap();
    std::os::unix::fs::symlink(&file, &link).unwrap();
    let fs = HostFilesystem;

    assert!(fs.is_file(&host(&link)).unwrap());
    assert!(fs.same_file(&host(&link), &host(&file)).unwrap());
    assert_eq!(
        fs.canonical(&host(&link)).unwrap(),
        host(&std::fs::canonicalize(&file).unwrap())
    );
}

/// The `non_root` precondition, as `src/test_groups.rs` shapes a group's: `COSCA_TEST_NON_ROOT=0`
/// turns the tests that need it off, and without that opt-out they run and fail under root.
#[cfg(unix)]
mod non_root {
    pub(super) fn enabled() -> Result<(), String> {
        match std::env::var("COSCA_TEST_NON_ROOT").as_deref() {
            Ok("0") => Err("COSCA_TEST_NON_ROOT=0".to_owned()),
            _ => Ok(()),
        }
    }
}

/// Fails the test unless the process is not root: root reads any file, so a test of what needs no
/// read access would pass whatever the code does.
#[cfg(unix)]
#[skuld::fixture(requires = [non_root::enabled])]
fn non_root() -> Result<(), String> {
    // SAFETY: `geteuid` has no preconditions.
    match unsafe { libc::geteuid() } {
        0 => Err(
            "this test needs a non-root user, and this process is root; set COSCA_TEST_NON_ROOT=0 to turn it off"
                .to_owned(),
        ),
        _ => Ok(()),
    }
}

/// An executable the caller may not read, and another file.
#[cfg(unix)]
fn unreadable_tool(dir: &std::path::Path) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let (tool, other) = (dir.join("tool"), dir.join("other"));
    std::fs::write(&tool, b"").unwrap();
    std::fs::write(&other, b"").unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o111)).unwrap();
    (host(&tool), host(&other))
}

/// On Linux `same_file` examines identity without access to the data (`O_PATH`): a file the caller
/// may execute but not read is `Ok`, as it is for `is_file`.
///
/// Mutant: `same_file` opens the paths for reading (`EACCES`).
#[cfg(any(target_os = "linux", target_os = "android"))]
#[skuld::test]
fn host_filesystem_same_file_needs_no_read_access(#[fixture(non_root)] _non_root: &()) {
    let dir = tempfile::tempdir().unwrap();
    let (tool, other) = unreadable_tool(dir.path());
    let fs = HostFilesystem;

    assert!(fs.is_file(&tool).unwrap());
    assert!(fs.same_file(&tool, &tool).unwrap());
    assert!(!fs.same_file(&tool, &other).unwrap());
}

/// Where there is no `O_PATH`, `same_file` holds both files open to read them, so a file the caller
/// may not read is `PermissionDenied`, not a comparison of two path lookups that a deleted file's
/// reused inode could fool (see `identity::open`).
///
/// Mutant: `same_file` that falls back to comparing `metadata` by path.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
#[skuld::test]
fn host_filesystem_same_file_needs_read_access_without_o_path(#[fixture(non_root)] _non_root: &()) {
    let dir = tempfile::tempdir().unwrap();
    let (tool, other) = unreadable_tool(dir.path());
    let fs = HostFilesystem;

    assert!(fs.is_file(&tool).unwrap());
    assert_eq!(
        fs.same_file(&tool, &other).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
}

/// `same_file` holds both files while it compares them: once each is open, no change to the paths
/// changes the answer, so an inode number freed by a delete cannot be reused by the other path in
/// between. Here two names of one file are both removed after the files are open, and the answer is
/// still `true`.
///
/// Mutant: `same_file` that reads each file's identity by path, one after the other, without a
/// handle on the first.
#[cfg(unix)]
#[skuld::test]
fn host_filesystem_same_file_holds_both_files_while_comparing() {
    use super::identity::same_file_with;

    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    std::fs::write(&a, b"").unwrap();
    std::fs::hard_link(&a, &b).unwrap();

    let same = same_file_with(&a, &b, || {
        std::fs::remove_file(&a).unwrap();
        std::fs::remove_file(&b).unwrap();
    });
    assert!(same.expect("the open files answer, whatever happened to their names"));
}

/// `same_file` does not wait for a writer on a FIFO.
///
/// Mutant: `same_file` opens the paths, which blocks until a writer appears. The bound for that
/// hang is the `slow-timeout` override in `.config/nextest.toml`.
#[cfg(unix)]
#[skuld::test]
fn host_filesystem_same_file_does_not_block_on_a_fifo() {
    use std::os::unix::ffi::OsStrExt;

    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("fifo");
    let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: `c_path` is a NUL-terminated string that outlives the call.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0, "mkfifo");
    let fifo = host(&fifo);
    let fs = HostFilesystem;

    assert!(fs.same_file(&fifo, &fifo).unwrap());
    assert!(!fs.same_file(&fifo, &host(dir.path())).unwrap());
}

/// `same_file` examines identity without data access or a share mode of its own: a file another
/// handle holds with share mode 0 is `Ok`, as it is for `is_file`.
///
/// Mutant: `same_file` opens the paths for reading, which a share-mode-0 holder refuses
/// (`ERROR_SHARING_VIOLATION`).
#[cfg(windows)]
#[skuld::test]
fn host_filesystem_same_file_ignores_an_exclusive_holder() {
    use std::os::windows::fs::OpenOptionsExt;

    let dir = tempfile::tempdir().unwrap();
    let held = dir.path().join("held");
    let other = dir.path().join("other");
    std::fs::write(&held, b"").unwrap();
    std::fs::write(&other, b"").unwrap();
    let _holder = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&held)
        .unwrap();
    let (held, other) = (host(&held), host(&other));
    let fs = HostFilesystem;

    assert!(fs.is_file(&held).unwrap());
    assert!(fs.same_file(&held, &held).unwrap());
    assert!(!fs.same_file(&held, &other).unwrap());
}

/// Identity on Windows: a directory is a file for `same_file`, two names of one file are one file,
/// two files are two, and a missing path is `NotFound`.
///
/// Mutants: no `FILE_FLAG_BACKUP_SEMANTICS` (a directory cannot be opened); comparing the volume
/// only; comparing the file id only when the volume differs.
#[cfg(windows)]
#[skuld::test]
fn host_filesystem_same_file_identifies_by_file_id() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file");
    let link = dir.path().join("link");
    let other = dir.path().join("other");
    std::fs::write(&file, b"").unwrap();
    std::fs::write(&other, b"").unwrap();
    std::fs::hard_link(&file, &link).unwrap();
    let (dir_p, file_p, link_p, other_p) = (host(dir.path()), host(&file), host(&link), host(&other));
    let fs = HostFilesystem;

    assert!(fs.same_file(&dir_p, &dir_p).unwrap());
    assert!(!fs.same_file(&dir_p, &file_p).unwrap());
    assert!(fs.same_file(&file_p, &link_p).unwrap());
    assert!(!fs.same_file(&file_p, &other_p).unwrap());
    let missing = host(&dir.path().join("missing"));
    assert_eq!(
        fs.same_file(&file_p, &missing).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    assert_eq!(
        fs.same_file(&missing, &file_p).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

/// An object with no file id (a device) fails `same_file` with the Win32 code, as every other
/// error of the module carries it, not the `HRESULT` of the `windows` crate.
///
/// Mutant: the id query's error converted through `From<windows::core::Error>`, whose code is
/// `0x80070001`.
#[cfg(windows)]
#[skuld::test]
fn host_filesystem_same_file_reports_the_win32_code() {
    let nul = PathBuf::parse(r"\\.\NUL").unwrap();
    // ERROR_INVALID_FUNCTION.
    let err = HostFilesystem.same_file(&nul, &nul).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(1), "{err}");
}

/// `canonical` and `same_file` say absence as `NotFound`, as the `Filesystem` trait documents,
/// for every spelling of "nothing there": a missing leaf, a missing directory, a non-directory in
/// the path, and (Windows) a name no filesystem takes.
///
/// Mutants: `canonical` or `same_file` passing the raw error through (`ENOTDIR` is
/// `NotADirectory`; `ERROR_INVALID_NAME` is `InvalidInput`); mapping every error to `NotFound`.
#[skuld::test]
fn host_filesystem_reports_every_absence_as_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file");
    std::fs::write(&file, b"").unwrap();
    let file_p = host(&file);
    let mut gone = vec![
        host(&dir.path().join("missing")),
        host(&dir.path().join("missing").join("x")),
        host(&file.join("below")),
    ];
    // `|` is not a Windows name character (INVALID_NAME); on Unix it is an ordinary one.
    gone.extend(cfg!(windows).then(|| host(&dir.path().join("bad|name"))));
    let fs = HostFilesystem;

    for p in &gone {
        assert_eq!(
            fs.canonical(p).unwrap_err().kind(),
            io::ErrorKind::NotFound,
            "canonical {p:?}"
        );
        assert_eq!(
            fs.same_file(&file_p, p).unwrap_err().kind(),
            io::ErrorKind::NotFound,
            "same_file {p:?}"
        );
        assert_eq!(
            fs.same_file(p, &file_p).unwrap_err().kind(),
            io::ErrorKind::NotFound,
            "same_file {p:?}"
        );
    }
}

/// Where `FileIdInfo` fails (a filesystem that lacks it), `same_file` answers from
/// `GetFileInformationByHandle` on the same handles: the same file is `true`, two files `false`,
/// a hard link `true`, a directory works. The failure of either handle's query moves both
/// handles to the fallback, so two different kinds of id are never compared.
///
/// Mutants: no fallback (the error is returned); a fallback that compares the volume only; a
/// fallback used for the failing handle alone.
#[cfg(windows)]
#[skuld::test]
fn host_filesystem_same_file_falls_back_without_file_id_info() {
    use std::cell::Cell;

    use windows::Win32::Storage::FileSystem::FILE_ID_INFO;

    use super::identity::{same_file_with, wide_file_id};

    // ERROR_INVALID_PARAMETER: what a filesystem without the class answers.
    let unsupported = || Err::<FILE_ID_INFO, _>(io::Error::from_raw_os_error(87));
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file");
    let link = dir.path().join("link");
    let other = dir.path().join("other");
    std::fs::write(&file, b"").unwrap();
    std::fs::write(&other, b"").unwrap();
    std::fs::hard_link(&file, &link).unwrap();

    // Both queries fail.
    let both = |a: &std::path::Path, b: &std::path::Path| same_file_with(a, b, |_| unsupported());
    assert!(both(&file, &file).expect("fallback answers"));
    assert!(both(&file, &link).expect("fallback answers"));
    assert!(!both(&file, &other).expect("fallback answers"));
    assert!(both(dir.path(), dir.path()).expect("fallback answers"));
    assert!(!both(dir.path(), &file).expect("fallback answers"));

    // Only the second handle's query fails: the first is not compared by its wide id.
    let second = |a: &std::path::Path, b: &std::path::Path| {
        let calls = Cell::new(0);
        same_file_with(a, b, |f| {
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                unsupported()
            } else {
                wide_file_id(f)
            }
        })
    };
    assert!(second(&file, &link).expect("fallback answers"));
    assert!(!second(&file, &other).expect("fallback answers"));

    // An absent path is still `NotFound` through the seam: the fallback is not a way around it.
    let missing = dir.path().join("missing");
    assert_eq!(both(&file, &missing).unwrap_err().kind(), io::ErrorKind::NotFound);
}
