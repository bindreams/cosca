use std::io;

use super::is_absence;
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
    assert!(fs.same_file(&file_p, &host(&dir.path().join("missing"))).is_err());

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
