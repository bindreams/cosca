use super::*;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

fn invalid_input_message(r: Result<Anchored, Error>) -> String {
    match r {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput => e.to_string(),
        other => panic!("expected Io(InvalidInput), got {other:?}"),
    }
}

#[skuld::test]
fn an_absolute_program_is_returned_unchanged_without_reading_any_cwd() {
    let got = anchor_posix(OsStr::new("/usr/bin/id"), Some(Path::new("rel"))).unwrap();
    assert_eq!(got.program, Path::new("/usr/bin/id"));
}

/// Nothing is appended and nothing is checked on disk.
#[skuld::test]
fn no_extension_is_appended_and_no_existence_is_checked() {
    let got = anchor_posix(OsStr::new("no-such-file-983471"), Some(Path::new("/nonexistent-dir"))).unwrap();
    assert_eq!(got.program.as_os_str(), OsStr::new("./no-such-file-983471"));
}

/// POSIX grammar on every host: `\` is a filename byte, `C:` is not a prefix.
#[skuld::test]
fn backslashes_and_drive_letters_are_ordinary_bytes() {
    let got = anchor_posix(OsStr::new(r"C:\t\tool"), Some(Path::new("/work"))).unwrap();
    assert_eq!(got.program.as_os_str(), OsStr::new(r"./C:\t\tool"));
    assert!(got.enter);
}

#[skuld::test]
fn a_name_that_names_no_file_is_refused_before_any_cwd_is_read() {
    for n in ["", ".", "..", "dir/", "a/.", "a/..", "/"] {
        let msg = invalid_input_message(anchor_posix(OsStr::new(n), None));
        assert!(msg.contains("names no file"), "{n:?}: {msg}");
    }
}

/// Blamed on the NUL even where the untruncated spelling is also shapeless (`x` + NUL + `/`).
#[skuld::test]
fn an_interior_nul_is_refused_and_named() {
    for n in ["to\0ol", "x\0/"] {
        let msg = invalid_input_message(anchor_posix(OsStr::new(n), None));
        assert!(msg.contains("NUL"), "{n:?}: {msg}");
        assert!(!msg.contains('\0'), "the refusal must not carry a raw NUL: {msg:?}");
    }
}

/// A name with no `/` gets one, so `execvp` cannot search it; one with a `/` is already unsearched.
#[skuld::test]
fn a_relative_program_is_anchored_to_the_childs_cwd_without_reading_it() {
    for (program, want) in [("tool", "./tool"), ("bin/tool", "bin/tool"), ("./tool", "./tool")] {
        let got = anchor_posix(OsStr::new(program), Some(Path::new("sub"))).unwrap();
        // `OsStr`, not `Path`: `Path`'s equality skips `.` components, so it could not see a
        // missing `./`.
        assert_eq!(got.program.as_os_str(), OsStr::new(want), "{program}");
        assert_eq!(
            got,
            Anchored {
                program: PathBuf::from(want),
                cwd: Some(PathBuf::from("sub")),
                enter: true,
            }
        );
    }
}

/// An absolute program needs no anchoring, so std is handed the cwd.
#[skuld::test]
fn an_absolute_program_is_not_anchored() {
    let got = anchor_posix(OsStr::new("/usr/bin/id"), Some(Path::new("sub"))).unwrap();
    assert!(!got.enter);
    assert_eq!(got.program, Path::new("/usr/bin/id"));
}

#[skuld::test]
fn anchoring_refuses_a_program_that_names_no_file() {
    for n in ["", ".", "dir/", "a\0b"] {
        invalid_input_message(anchor_posix(OsStr::new(n), None));
    }
}
