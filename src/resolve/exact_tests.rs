use super::*;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

fn never() -> std::io::Result<PathBuf> {
    panic!("the process cwd must not be consulted here")
}

fn completed(program: &str, child_cwd: Option<&str>) -> Result<Completed, Error> {
    complete_posix(OsStr::new(program), child_cwd.map(Path::new), || {
        Ok(PathBuf::from("/proc-cwd"))
    })
}

fn complete(program: &str, child_cwd: Option<&str>) -> Result<PathBuf, Error> {
    completed(program, child_cwd).map(|c| c.program)
}

fn invalid_input_message(r: Result<Completed, Error>) -> String {
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

/// A relative `current_dir` names a directory under this process's cwd, so the base does too.
#[test]
fn a_relative_child_cwd_is_itself_joined_onto_the_process_cwd() {
    assert_eq!(complete("tool", Some("sub")).unwrap(), Path::new("/proc-cwd/sub/tool"));
}

/// `chdir("")` fails with `ENOENT`, which is what a `Search` program's spawn reports; joining the
/// empty directory onto the process cwd would instead name a real one.
#[test]
fn an_empty_child_cwd_is_not_found_as_chdir_would_report_it() {
    match complete_posix(OsStr::new("tool"), Some(Path::new("")), never) {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
        other => panic!("expected Io(NotFound), got {other:?}"),
    }
}

/// A base read from the process cwd is handed back as the child's cwd, so the sink runs the child
/// where the program was completed rather than re-reading the process cwd at `fork`.
#[test]
fn a_base_read_from_the_process_cwd_becomes_the_childs_cwd() {
    for (cwd, want) in [(Some("sub"), "/proc-cwd/sub"), (None, "/proc-cwd")] {
        assert_eq!(
            completed("tool", cwd).unwrap().child_cwd.as_deref(),
            Some(Path::new(want))
        );
    }
}

/// Where the process cwd is not read, the child's cwd is left as given.
#[test]
fn a_child_cwd_is_left_as_given_when_the_process_cwd_is_not_read() {
    let got = complete_posix(OsStr::new("tool"), Some(Path::new("/work")), never).unwrap();
    assert_eq!(got.child_cwd.as_deref(), Some(Path::new("/work")));
    for cwd in [Some("rel"), None] {
        let got = complete_posix(OsStr::new("/usr/bin/id"), cwd.map(Path::new), never).unwrap();
        assert_eq!(got.child_cwd.as_deref(), cwd.map(Path::new));
    }
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
    assert_eq!(got.program, Path::new("/usr/bin/id"));
}

/// An absolute child cwd is the whole base; the process cwd is not read, so a deleted process
/// cwd cannot fail the spawn.
#[test]
fn an_absolute_child_cwd_does_not_read_the_process_cwd() {
    let got = complete_posix(OsStr::new("tool"), Some(Path::new("/work")), never).unwrap();
    assert_eq!(got.program, Path::new("/work/tool"));
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

/// A name with no `/` gets one, so `execvp` cannot search it; one with a `/` is already unsearched.
#[test]
fn a_relative_program_is_anchored_to_the_childs_cwd_without_reading_it() {
    for (program, want) in [("tool", "./tool"), ("bin/tool", "bin/tool"), ("./tool", "./tool")] {
        let got = anchor_posix(OsStr::new(program), Some(Path::new("sub"))).unwrap();
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
#[test]
fn an_absolute_program_is_not_anchored() {
    let got = anchor_posix(OsStr::new("/usr/bin/id"), Some(Path::new("sub"))).unwrap();
    assert!(!got.enter);
    assert_eq!(got.program, Path::new("/usr/bin/id"));
}

#[test]
fn anchoring_refuses_what_completion_refuses() {
    for n in ["", ".", "dir/", "a\0b"] {
        invalid_input_message(anchor_posix(OsStr::new(n), None).map(|a| Completed {
            program: a.program,
            child_cwd: a.cwd,
        }));
    }
}

/// For a shell that `cd`s by path and then execs: the absolute directory to enter, and the name
/// to exec there, `./`-prefixed so no shell reads it as an option or searches `PATH` for it.
#[test]
fn a_program_to_run_after_entering_its_directory_is_dot_slash_anchored() {
    let entered = |program: &str, cwd: Option<&str>| {
        let reads = std::cell::Cell::new(0);
        let got = enter_posix(OsStr::new(program), cwd.map(Path::new), || {
            reads.set(reads.get() + 1);
            Ok(PathBuf::from("/proc-cwd"))
        })
        .unwrap();
        assert!(reads.get() <= 1, "{program} {cwd:?}");
        (got.program, got.dir)
    };
    let p = PathBuf::from;
    assert_eq!(entered("tool", None), (p("./tool"), Some(p("/proc-cwd"))));
    assert_eq!(entered("-x/tool", Some("/work")), (p("./-x/tool"), Some(p("/work"))));
    assert_eq!(
        entered("bin/tool", Some("sub")),
        (p("./bin/tool"), Some(p("/proc-cwd/sub")))
    );
    assert_eq!(entered("./tool", Some("/work")), (p("./tool"), Some(p("/work"))));
    assert_eq!(entered("/usr/bin/id", Some("/w")), (p("/usr/bin/id"), Some(p("/w"))));
    assert_eq!(entered("/usr/bin/id", None), (p("/usr/bin/id"), None));
}
