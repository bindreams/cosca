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

// One reading of the process cwd =====

/// A `tool` in `dir` that prints its working directory and exits with `code`.
fn pwd_tool(dir: &std::path::Path, code: i32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir).expect("mkdir");
    let tool = dir.join("tool");
    // Under the lock for the reason `cwd_and_path_tools` gives.
    let _guard = crate::child::spawn::spawn_lock();
    std::fs::write(&tool, format!("#!/bin/sh\npwd -P\nexit {code}\n")).expect("write tool");
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).expect("chmod tool");
}

/// Builds `c` with the process cwd at `a`, moves the process cwd to `b`, then forks: the window
/// between cosca's reading of the cwd and the child's, forced rather than raced. Returns the
/// child's exit code and working directory.
///
/// The lock is held across the RAW std fork, as every fork in this binary must be (see
/// `cwd_and_path_tools`); cosca's own `spawn()`, which takes it itself, is never called under it.
fn build_move_fork(c: &Command, a: &std::path::Path, b: &std::path::Path) -> (Option<i32>, std::path::PathBuf) {
    let _guard = crate::child::spawn::spawn_lock();
    let _restore = crate::test_child::RestoreCwd::capture();
    std::env::set_current_dir(a).expect("cd a");
    let mut std_cmd = crate::child::spawn::build_std_command(c).expect("build");
    std::env::set_current_dir(b).expect("cd b");
    let out = std_cmd.stdout(std::process::Stdio::piped()).output().expect("spawn");
    let pwd = String::from_utf8(out.stdout).expect("utf-8 pwd");
    (out.status.code(), pwd.trim_end_matches('\n').into())
}

/// A relative `current_dir` is pinned to the directory the program was completed against, so a
/// cwd move before the fork cannot run A's `sub/tool` in B's `sub`.
#[test]
fn a_relative_exact_program_and_relative_cwd_come_from_one_process_cwd_reading() {
    let (a, b) = (
        tempfile::tempdir().expect("tempdir"),
        tempfile::tempdir().expect("tempdir"),
    );
    pwd_tool(&a.path().join("sub"), CWD_TOOL_EXIT);
    pwd_tool(&b.path().join("sub"), PATH_TOOL_EXIT);
    let mut c = Command::new();
    c.raw_executable("tool").args(["tool"]).current_dir("sub");
    let want = a.path().canonicalize().expect("canonicalize").join("sub");
    assert_eq!(build_move_fork(&c, a.path(), b.path()), (Some(CWD_TOOL_EXIT), want));
}

/// With no `current_dir`, the child is run in the directory the program was completed against.
#[test]
fn a_relative_exact_program_without_a_cwd_runs_where_it_was_completed() {
    let (a, b) = (
        tempfile::tempdir().expect("tempdir"),
        tempfile::tempdir().expect("tempdir"),
    );
    pwd_tool(a.path(), CWD_TOOL_EXIT);
    pwd_tool(b.path(), PATH_TOOL_EXIT);
    let mut c = Command::new();
    c.raw_executable("tool").args(["tool"]);
    let want = a.path().canonicalize().expect("canonicalize");
    assert_eq!(build_move_fork(&c, a.path(), b.path()), (Some(CWD_TOOL_EXIT), want));
}

/// Negative control: a `Search` program is not completed by cosca, so a relative `current_dir`
/// is left for the child to read at the fork.
#[test]
fn a_search_programs_relative_cwd_is_passed_through() {
    let mut c = Command::new();
    c.executable("tool").args(["tool"]).current_dir("sub");
    let std_cmd = crate::child::spawn::build_std_command(&c).expect("build");
    assert_eq!(std_cmd.get_current_dir(), Some(std::path::Path::new("sub")));
}

// argv[0] =====

/// An empty argv gives the child the name as written, as a non-empty one does, not the completed
/// path. `sh` reading its script from stdin reports `argv[0]` as `$0`.
#[test]
fn an_exact_program_with_an_empty_argv_gets_the_written_name_as_argv0() {
    let mut c = Command::new();
    c.raw_executable("sh").args(Vec::<&str>::new()).current_dir("/bin");
    c.stdin(crate::Stdio::pipe()).expect("stdin");
    c.stdout(crate::Stdio::pipe()).expect("stdout");
    let out = c
        .spawn()
        .expect("spawn")
        .communicate(Some(b"echo \"$0\"\n"))
        .expect("communicate");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "sh\n");
}
