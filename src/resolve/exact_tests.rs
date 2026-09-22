use super::*;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

fn never() -> std::io::Result<PathBuf> {
    panic!("the process cwd must not be consulted here")
}

fn complete(program: &str, child_cwd: Option<&str>) -> Result<PathBuf, Error> {
    complete_posix(OsStr::new(program), child_cwd.map(Path::new), || {
        Ok(PathBuf::from("/proc-cwd"))
    })
}

fn invalid_input_message(r: Result<PathBuf, Error>) -> String {
    match r {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput => e.to_string(),
        other => panic!("expected Io(InvalidInput), got {other:?}"),
    }
}

#[test]
fn a_bare_name_is_joined_onto_the_childs_cwd() {
    assert_eq!(complete("tool", Some("/work")).unwrap(), Path::new("/work/tool"));
}

#[test]
fn without_a_child_cwd_the_process_cwd_is_the_base() {
    assert_eq!(complete("tool", None).unwrap(), Path::new("/proc-cwd/tool"));
}

/// std resolves a relative `current_dir` against this process's cwd at `chdir`, so the base does
/// too.
#[test]
fn a_relative_child_cwd_is_itself_joined_onto_the_process_cwd() {
    assert_eq!(complete("tool", Some("sub")).unwrap(), Path::new("/proc-cwd/sub/tool"));
}

/// A pure join: `.`/`..` components are left for the kernel, which resolves them against the same
/// directory the child's own exec would have.
#[test]
fn a_pathed_name_is_joined_without_normalisation() {
    // `OsStr`, not `Path`: `Path`'s equality skips `.` components, so it could not see a
    // normalisation.
    let got = complete("./bin/tool", Some("/work")).unwrap();
    assert_eq!(got.as_os_str(), OsStr::new("/work/./bin/tool"));
    let got = complete("../tool", Some("/work")).unwrap();
    assert_eq!(got.as_os_str(), OsStr::new("/work/../tool"));
}

#[test]
fn a_root_base_gets_no_doubled_separator() {
    assert_eq!(complete("tool", Some("/")).unwrap().as_os_str(), OsStr::new("/tool"));
}

#[test]
fn an_absolute_program_is_returned_unchanged_without_reading_any_cwd() {
    let got = complete_posix(OsStr::new("/usr/bin/id"), Some(Path::new("rel")), never).unwrap();
    assert_eq!(got, Path::new("/usr/bin/id"));
}

/// An absolute child cwd is the whole base; the process cwd is not read, so a deleted process
/// cwd cannot fail the spawn.
#[test]
fn an_absolute_child_cwd_does_not_read_the_process_cwd() {
    let got = complete_posix(OsStr::new("tool"), Some(Path::new("/work")), never).unwrap();
    assert_eq!(got, Path::new("/work/tool"));
}

/// Nothing is appended and nothing is checked on disk.
#[test]
fn no_extension_is_appended_and_no_existence_is_checked() {
    let got = complete("no-such-file-983471", Some("/nonexistent-dir")).unwrap();
    assert_eq!(got, Path::new("/nonexistent-dir/no-such-file-983471"));
}

/// POSIX grammar on every host: `\` is a filename byte, `C:` is not a prefix.
#[test]
fn backslashes_and_drive_letters_are_ordinary_bytes() {
    assert_eq!(
        complete(r"C:\t\tool", Some("/work")).unwrap().as_os_str(),
        OsStr::new(r"/work/C:\t\tool")
    );
}

#[test]
fn a_name_that_names_no_file_is_refused_before_any_cwd_is_read() {
    for n in ["", ".", "..", "dir/", "a/.", "a/..", "/"] {
        let msg = invalid_input_message(complete_posix(OsStr::new(n), None, never));
        assert!(msg.contains("names no file"), "{n:?}: {msg}");
    }
}

/// Blamed on the NUL even where the untruncated spelling is also shapeless (`x` + NUL + `/`).
#[test]
fn an_interior_nul_is_refused_and_named() {
    for n in ["to\0ol", "x\0/"] {
        let msg = invalid_input_message(complete_posix(OsStr::new(n), None, never));
        assert!(msg.contains("NUL"), "{n:?}: {msg}");
        assert!(!msg.contains('\0'), "the refusal must not carry a raw NUL: {msg:?}");
    }
}

#[test]
fn a_process_cwd_failure_is_reported() {
    let got = complete_posix(OsStr::new("tool"), None, || Err(std::io::Error::other("cwd gone")));
    match got {
        Err(Error::Io(e)) => assert!(e.to_string().contains("cwd gone"), "{e}"),
        other => panic!("expected the cwd error, got {other:?}"),
    }
}
