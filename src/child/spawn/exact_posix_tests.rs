//! `raw_executable()` on the POSIX std backend, spawned for real: which `tool` a child loads is
//! read back from its exit code (see [`crate::test_child::cwd_and_path_tools`]).

use crate::command::Command;
use crate::error::Error;
use crate::test_child::{cwd_and_path_tools, CWD_TOOL_EXIT, PATH_TOOL_EXIT};

fn exit_code(c: &mut Command) -> Option<i32> {
    c.spawn().expect("spawn").wait().expect("wait").code()
}

#[test]
fn a_bare_exact_name_loads_the_file_in_the_childs_cwd_not_one_on_path() {
    let (cwd, on_path) = cwd_and_path_tools();
    let mut c = Command::new();
    c.raw_executable("tool")
        .args(["tool"])
        .current_dir(cwd.path())
        .env("PATH", on_path.path());
    assert_eq!(exit_code(&mut c), Some(CWD_TOOL_EXIT));
}

#[test]
fn a_bare_exact_name_missing_from_the_childs_cwd_is_not_found_on_path() {
    let (_cwd, on_path) = cwd_and_path_tools();
    let empty = tempfile::tempdir().expect("tempdir");
    let mut c = Command::new();
    c.raw_executable("tool")
        .args(["tool"])
        .current_dir(empty.path())
        .env("PATH", on_path.path());
    match c.spawn() {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
        other => panic!("expected Io(NotFound), got {other:?}"),
    }
}

#[test]
fn an_exact_name_that_names_no_file_is_refused_on_posix() {
    let (cwd, on_path) = cwd_and_path_tools();
    std::fs::create_dir(cwd.path().join("dir")).expect("mkdir");
    for n in ["", ".", "..", "dir/", "tool/..", "/"] {
        let mut c = Command::new();
        c.raw_executable(n)
            .args(["tool"])
            .current_dir(cwd.path())
            .env("PATH", on_path.path());
        match c.spawn() {
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput => {}
            other => panic!("{n:?} names no file and must be Io(InvalidInput), got {other:?}"),
        }
    }
}

/// Negative control: `executable()` still searches `PATH` for a bare name, and never the cwd.
#[test]
fn a_bare_search_name_still_loads_the_file_on_path() {
    let (cwd, on_path) = cwd_and_path_tools();
    let mut c = Command::new();
    c.executable("tool")
        .args(["tool"])
        .current_dir(cwd.path())
        .env("PATH", on_path.path());
    assert_eq!(exit_code(&mut c), Some(PATH_TOOL_EXIT));
}

/// The commandline arm reaches the same completion as the argv arm.
#[test]
fn a_bare_exact_name_with_a_commandline_loads_the_childs_cwd_file() {
    let (cwd, on_path) = cwd_and_path_tools();
    let mut c = Command::new();
    c.raw_executable("tool")
        .commandline("tool")
        .current_dir(cwd.path())
        .env("PATH", on_path.path());
    assert_eq!(exit_code(&mut c), Some(CWD_TOOL_EXIT));
}
