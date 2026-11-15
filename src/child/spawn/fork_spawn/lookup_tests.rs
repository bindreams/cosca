//! How the ordinary Linux spawn finds its program: the parent searches ([`crate::resolve::posix`]),
//! and the child only `execve`s what was found. One test per lookup rule.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::Stdio;

/// A script in `dir` called `name`, with `body` and `mode`.
fn script(dir: &Path, name: &str, body: &str, mode: u32) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).expect("write the script");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    path
}

fn command() -> crate::Command {
    crate::test_child::command(crate::test_child::Console::Hidden)
}

/// The exit code of `cmd`'s program.
fn exit_code(mut cmd: crate::Command) -> Option<i32> {
    cmd.spawn().expect("spawn").wait().expect("wait").code()
}

/// The error a spawn of `cmd` fails with.
fn spawn_error(mut cmd: crate::Command, what: &str) -> Error {
    match cmd.spawn() {
        Err(e) => e,
        Ok(child) => panic!("{what}: the spawn succeeded (child {:?})", child.pid()),
    }
}

fn assert_kind(error: &Error, kind: std::io::ErrorKind, what: &str) {
    match error {
        Error::Io(e) => assert_eq!(e.kind(), kind, "{what}: {e:?}"),
        other => panic!("{what}: expected {kind:?}, got {other:?}"),
    }
}

/// The child's own `PATH` is searched: not this process's.
///
/// Mutant: the search reads this process's `PATH`.
#[skuld::test]
fn the_childs_path_is_searched() {
    let dir = tempfile::tempdir().expect("tempdir");
    script(dir.path(), "cosca-lookup-tool", "#!/bin/sh\nexit 7\n", 0o755);
    let mut cmd = command();
    cmd.args(["cosca-lookup-tool"]).env("PATH", dir.path());
    assert_eq!(exit_code(cmd), Some(7));
}

/// An empty or relative `PATH` element is skipped, not read against the child's directory.
///
/// Mutant: such an element is joined to the child's directory.
#[skuld::test]
fn an_empty_or_relative_path_element_is_not_searched() {
    let dir = tempfile::tempdir().expect("tempdir");
    script(dir.path(), "tool", "#!/bin/sh\nexit 7\n", 0o755);
    for path in ["", ".", ":", "./", ":."] {
        let mut cmd = command();
        cmd.args(["tool"]).env("PATH", path).current_dir(dir.path());
        assert_kind(
            &spawn_error(cmd, path),
            std::io::ErrorKind::NotFound,
            &format!("PATH {path:?}"),
        );
    }
}

/// A child with no `PATH` searches nothing: not the system's default path, in which `sh` is.
///
/// Mutant: the search falls back to `confstr(_CS_PATH)`.
#[skuld::test]
fn a_child_with_no_path_searches_nothing() {
    let mut cmd = command();
    cmd.args(["sh", "-c", "exit 3"]).env_clear();
    assert_kind(&spawn_error(cmd, "env_clear"), std::io::ErrorKind::NotFound, "no PATH");

    let mut removed = command();
    removed.args(["sh", "-c", "exit 3"]).env_remove("PATH");
    assert_kind(
        &spawn_error(removed, "env_remove"),
        std::io::ErrorKind::NotFound,
        "PATH removed",
    );
}

/// The first file that exists is the match, whatever its mode: the spawn fails `PermissionDenied`,
/// and the executable file after it does not run in its place.
///
/// Mutants: the execute bit is part of the search; the failure is `NotFound`.
#[skuld::test]
fn a_match_without_the_execute_bit_is_permission_denied_and_no_later_entry_runs() {
    let first = tempfile::tempdir().expect("tempdir");
    let second = tempfile::tempdir().expect("tempdir");
    script(first.path(), "tool", "#!/bin/sh\nexit 5\n", 0o644);
    script(second.path(), "tool", "#!/bin/sh\nexit 7\n", 0o755);
    let path = std::env::join_paths([first.path(), second.path()]).expect("join");
    let mut cmd = command();
    cmd.args(["tool"]).env("PATH", path);
    assert_kind(
        &spawn_error(cmd, "the first match"),
        std::io::ErrorKind::PermissionDenied,
        "a file without the execute bit",
    );
}

/// An executable file that is no executable format is `ENOEXEC`: it is not handed to `/bin/sh`.
///
/// Mutant: the child retries `ENOEXEC` through `/bin/sh`.
#[skuld::test]
fn a_file_that_is_no_executable_format_is_enoexec() {
    let dir = tempfile::tempdir().expect("tempdir");
    let no_format = script(dir.path(), "no-format", "exit 5\n", 0o755);
    let mut cmd = command();
    cmd.args([no_format.as_os_str()]);
    let error = spawn_error(cmd, "no format");
    assert_eq!(crate::error::first_os_code(&error), Some(libc::ENOEXEC), "{error:?}");
}

/// A located name is the one file it names, read against the child's directory: it is not searched
/// for in `PATH`.
///
/// Mutants: the directory is ignored; a name with a `/` is searched.
#[skuld::test]
fn a_located_name_is_read_against_the_childs_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("sub")).expect("mkdir");
    script(&dir.path().join("sub"), "tool", "#!/bin/sh\nexit 7\n", 0o755);
    let mut found = command();
    found.args(["sub/tool"]).current_dir(dir.path());
    assert_eq!(exit_code(found), Some(7));

    let on_path = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(on_path.path().join("sub")).expect("mkdir");
    script(&on_path.path().join("sub"), "tool", "#!/bin/sh\nexit 5\n", 0o755);
    let mut missing = command();
    missing
        .args(["elsewhere/tool"])
        .env("PATH", on_path.path())
        .current_dir(dir.path());
    assert_kind(
        &spawn_error(missing, "missing"),
        std::io::ErrorKind::NotFound,
        "a located miss",
    );
}

/// A located or absolute name that names an existing entry which is no file (a directory, a device)
/// fails the spawn with the launch's own error, `EACCES`: not as a missing program.
///
/// Mutant: a located name must name a regular file to be the match.
#[skuld::test]
fn a_located_name_that_names_a_non_file_is_permission_denied() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("sub")).expect("mkdir");
    for (name, cwd) in [
        (dir.path().to_path_buf(), None),
        (PathBuf::from("/dev/null"), None),
        (PathBuf::from("./sub"), Some(dir.path())),
    ] {
        let mut cmd = command();
        cmd.args([name.as_os_str()]);
        if let Some(cwd) = cwd {
            cmd.current_dir(cwd);
        }
        let error = spawn_error(cmd, "a non-file");
        assert_eq!(
            crate::error::first_os_code(&error),
            Some(libc::EACCES),
            "{name:?}: {error:?}"
        );
    }
}

/// `argv[0]` is the name the caller wrote, not the path the search found.
///
/// Mutant: `argv[0]` is the found path.
#[skuld::test]
fn argv0_is_the_written_name_not_the_found_path() {
    let mut cmd = command();
    cmd.args(["cat", "/proc/self/cmdline"]).env("PATH", "/usr/bin:/bin");
    cmd.stdout(Stdio::pipe()).expect("stdout");
    let out = cmd.spawn().expect("spawn").communicate(None).expect("communicate");
    assert_eq!(out.stdout, b"cat\0/proc/self/cmdline\0");
}

/// A program that cannot be found fails the spawn before anything is made: a stdio setup the spawn would
/// refuse (a merge into a merge, which the spawn refuses before any clone) is not reached, so the error
/// is the program's `NotFound`. The same setup with a program that exists is the stdio refusal, so
/// the refusal is reachable. (The cgroup lane's
/// `containment::strongest_tests::a_missing_program_is_not_found_before_any_leaf_is_made` pins the
/// leaf.)
///
/// Mutant: the search runs after the stdio setup, or in the child.
#[skuld::test]
fn a_miss_fails_the_spawn_before_the_stdio_is_set_up() {
    use crate::stdio::{Fd, Stdio};

    let setup = |program: &str| {
        let mut cmd = command();
        cmd.args([program]).env("PATH", "/usr/bin:/bin");
        cmd.stdout(Stdio::merge(Fd::STDERR)).expect("stdout");
        cmd.stderr(Stdio::merge(Fd::STDOUT)).expect("stderr");
        cmd
    };
    assert_kind(
        &spawn_error(setup("cosca-lookup-no-such-program"), "a name on no PATH"),
        std::io::ErrorKind::NotFound,
        "a miss",
    );
    let found = spawn_error(setup("true"), "a program that exists");
    assert!(
        matches!(found, Error::Unsupported { .. }),
        "the stdio setup is refused for a program that exists: {found:?}"
    );
}

// An inherited environment with `PATH` twice =====

const TWICE_MARKER: &str = "COSCA_TESTCFG_LOOKUP_PATH_TWICE";
const TWICE_CASE_ENV: &str = "COSCA_TESTCFG_LOOKUP_PATH_TWICE_CASE";

/// The program found is the one in the `PATH` the child gets, when the inherited environment carries
/// `PATH` twice: a child whose environment nothing changes gets both and reads the first, and a
/// contained root's, which carries the nesting marker, gets the sorted map, whose one `PATH` is the
/// last. Each case runs in a fresh re-exec: the environment is process-wide.
///
/// Mutant: the program is searched over the environment as an unmarked spawn would have it.
#[skuld::test]
fn the_program_found_is_in_the_path_the_child_gets() {
    if !crate::test_child::is_marked_fixture_reexec(TWICE_MARKER) {
        for case in ["plain", "contained"] {
            crate::test_child::run_fixture_case(
                crate::test_child::fixture_path!(the_program_found_is_in_the_path_the_child_gets),
                TWICE_MARKER,
                TWICE_CASE_ENV,
                case,
            );
        }
        return;
    }
    let first = tempfile::tempdir().expect("tempdir");
    let last = tempfile::tempdir().expect("tempdir");
    script(first.path(), "tool", "#!/bin/sh\nexit 5\n", 0o755);
    script(last.path(), "tool", "#!/bin/sh\nexit 7\n", 0o755);
    install_environment_with_path_twice(first.path(), last.path());

    let case = std::env::var(TWICE_CASE_ENV).expect("case");
    let mut cmd = command();
    cmd.args(["tool"]);
    let want = match case.as_str() {
        "plain" => 5,
        "contained" => {
            cmd.contain_with(crate::ContainMode::Session);
            7
        }
        other => panic!("no case {other:?}"),
    };
    assert_eq!(exit_code(cmd), Some(want), "{case}");
}

/// Replaces this process's environment with its own, but `PATH` twice: `first`, then `last`. A
/// throwaway re-exec: nothing else reads the environment meanwhile.
fn install_environment_with_path_twice(first: &Path, last: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let entry = |key: &[u8], value: &[u8]| {
        std::ffi::CString::new([key, b"=", value].concat()).expect("no NUL in an environment entry")
    };
    let mut entries: Vec<std::ffi::CString> = std::env::vars_os()
        .filter(|(key, _)| key != "PATH")
        .map(|(key, value)| entry(key.as_bytes(), value.as_bytes()))
        .collect();
    entries.push(entry(b"PATH", first.as_os_str().as_bytes()));
    entries.push(entry(b"PATH", last.as_os_str().as_bytes()));
    let mut pointers: Vec<*mut libc::c_char> = entries.iter().map(|e| e.as_ptr().cast_mut()).collect();
    pointers.push(std::ptr::null_mut());
    // The new environment lives as long as the process.
    let pointers = Box::leak(pointers.into_boxed_slice());
    std::mem::forget(entries);
    // SAFETY: `environ` is this process's own, and nothing else reads or writes the environment while
    // this re-exec runs its one test; the array is NULL-terminated and never freed.
    unsafe { libc::environ = pointers.as_mut_ptr() };
}

// A located name in a process whose own directory has no path =====

const UNLINKED_CWD_MARKER: &str = "COSCA_FIXTURE_UNLINKED_CWD";

/// A located relative name is read against the directory the child inherits, so a process whose
/// directory has no path (removed here; one outside a chroot is the same) still spawns `../tool`,
/// with or without a relative `current_dir`. `./tool` would name a file in the removed directory:
/// nothing can be there.
///
/// Mutant: the search reads this process's directory path (`std::env::current_dir`) to make the name
/// absolute. Runs in a process of its own: removing the directory is process-wide.
#[skuld::test]
fn a_located_name_spawns_from_a_process_whose_directory_has_no_path() {
    let root = tempfile::tempdir().expect("tempdir");
    script(root.path(), "tool", "#!/bin/sh\nexit 7\n", 0o755);
    std::fs::create_dir(root.path().join("other")).expect("mkdir");
    script(&root.path().join("other"), "tool", "#!/bin/sh\nexit 9\n", 0o755);
    let cwd = root.path().join("gone");
    std::fs::create_dir(&cwd).expect("mkdir");
    crate::test_child::run_fixture_with_cwd(
        crate::test_child::fixture_path!(fixture_a_located_name_spawns_from_a_process_whose_directory_has_no_path),
        &cwd,
        UNLINKED_CWD_MARKER,
    );
}

/// The child half of [`a_located_name_spawns_from_a_process_whose_directory_has_no_path`].
#[skuld::test]
fn fixture_a_located_name_spawns_from_a_process_whose_directory_has_no_path() {
    let Some(cwd) = crate::test_child::expected_cwd(UNLINKED_CWD_MARKER) else {
        return; // picked up by an ordinary suite run: inert
    };
    std::fs::remove_dir(&cwd).expect("remove this process's own directory");
    assert!(
        std::env::current_dir().is_err(),
        "precondition: this process's directory has no path"
    );

    let mut bare = command();
    bare.args(["../tool"]);
    assert_eq!(exit_code(bare), Some(7), "no current_dir");

    let mut entered = command();
    entered.args(["./tool"]).current_dir("../other");
    assert_eq!(exit_code(entered), Some(9), "a relative current_dir");
}

/// A `current_dir` that is missing, or not a directory, is the spawn's error for a located name: the
/// directory's own, not the program's `NotFound`.
///
/// Mutant: the directory's error is reported as the program being missing.
#[skuld::test]
fn a_bad_current_dir_is_the_error_for_a_located_name() {
    let root = tempfile::tempdir().expect("tempdir");
    let file = script(root.path(), "file", "x", 0o644);
    for (dir, errno) in [(root.path().join("missing"), libc::ENOENT), (file, libc::ENOTDIR)] {
        let mut cmd = command();
        cmd.args(["./tool"]).current_dir(&dir);
        let error = spawn_error(cmd, "a bad current_dir");
        assert_eq!(crate::error::first_os_code(&error), Some(errno), "{dir:?}: {error:?}");
    }
}
