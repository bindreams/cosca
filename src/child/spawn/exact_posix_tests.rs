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

// A working directory with no path =====

/// A `tool` in `dir` that exits with `code` if run in `dir` (it finds `./<marker>`), else with 3.
fn marker_tool(dir: &std::path::Path, marker: &str, code: i32) {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    // Created 0o700 so the chmod is what makes `dir` traversable to a dropped uid, whatever the
    // ambient umask; the umask is process-global, so a test must not change it.
    std::fs::DirBuilder::new().mode(0o700).create(dir).expect("mkdir");
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).expect("chmod dir");
    std::fs::write(dir.join(marker), "").expect("write marker");
    let tool = dir.join("tool");
    // Under the lock for the reason `cwd_and_path_tools` gives.
    let _guard = crate::child::spawn::spawn_lock();
    std::fs::write(&tool, format!("#!/bin/sh\n[ -f ./{marker} ] || exit 3\nexit {code}\n")).expect("write tool");
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).expect("chmod tool");
}

const FIXTURE_UNREACHABLE_CWD_TEST: &str =
    "child::spawn::exact_posix_tests::fixture_spawn_exact_tool_in_an_unreachable_cwd";
/// The fixture's own directory as a path, which it must fail to reach. A deliberate re-exec also
/// needs [`crate::test_child::is_fixture_reexec`].
const FIXTURE_UNREACHABLE_CWD_ENV: &str = "COSCA_FIXTURE_UNREACHABLE_CWD";
/// The `current_dir()` the fixture sets, if any.
const FIXTURE_CURRENT_DIR_ENV: &str = "COSCA_FIXTURE_UNREACHABLE_CWD_CURRENT_DIR";
/// When set, the fixture spawns through the already-elevated rewrite, as root's `.elevate()` does.
const FIXTURE_ALREADY_ELEVATED_ENV: &str = "COSCA_FIXTURE_UNREACHABLE_CWD_ALREADY_ELEVATED";
/// The fixture's exit code when a precondition does not hold or cosca's spawn fails.
const PRECONDITION_FAILED: i32 = 90;
const SPAWN_FAILED: i32 = 91;

/// Inert in an ordinary suite run. Re-executed by [`spawn_exact_tool_in_an_unreachable_cwd`], it
/// waits for one byte on stdin — sent once its directory's parent is unsearchable — then spawns
/// `raw_executable("tool")` and exits with that child's code.
#[test]
fn fixture_spawn_exact_tool_in_an_unreachable_cwd() {
    use std::io::Read;
    let Some(own_path) = std::env::var_os(FIXTURE_UNREACHABLE_CWD_ENV) else {
        return;
    };
    if !crate::test_child::is_fixture_reexec() {
        return;
    }
    let mut gate = [0u8; 1];
    std::io::stdin().read_exact(&mut gate).expect("gate byte");
    if std::fs::metadata(&own_path).is_ok() {
        report(&format!("precondition: {own_path:?} is still reachable by path"));
        std::process::exit(PRECONDITION_FAILED);
    }
    // The control: std runs `./tool` here.
    let std_code = std::process::Command::new("./tool").status().map(|s| s.code());
    if !matches!(std_code, Ok(Some(CWD_TOOL_EXIT))) {
        report(&format!("precondition: std's ./tool gave {std_code:?}"));
        std::process::exit(PRECONDITION_FAILED);
    }
    let mut c = Command::new();
    c.raw_executable("tool").args(["tool"]);
    if let Some(dir) = std::env::var_os(FIXTURE_CURRENT_DIR_ENV) {
        c.current_dir(dir);
    }
    if std::env::var_os(FIXTURE_ALREADY_ELEVATED_ENV).is_some() {
        c = match already_elevated(&mut c) {
            Ok(derived) => derived,
            Err(e) => {
                report(&format!("rewrite: {e}"));
                std::process::exit(SPAWN_FAILED);
            }
        };
    }
    let code = match c.spawn() {
        Ok(child) => child.wait().expect("wait").code().unwrap_or(SPAWN_FAILED),
        Err(e) => {
            report(&format!("spawn: {e}"));
            SPAWN_FAILED
        }
    };
    std::process::exit(code);
}

/// The command `.elevate()` spawns from a process that is already root, on any host.
fn already_elevated(c: &mut Command) -> Result<Command, Error> {
    use crate::elevation::plan::{BackendSet, Host, Os};
    c.elevation_backend(crate::elevation::Backend::Sudo)
        .elevation_auth(crate::elevation::Auth::NonInteractive);
    let host = Host {
        elevated: true,
        has_tty: false,
        available: BackendSet {
            sudo: Some("/usr/bin/sudo".into()),
            ..BackendSet::default()
        },
        os: Os::Unix,
        arg_max: None,
        pkexec_version: crate::elevation::pkexec::PkexecVersion::NotProbed,
        pkexec_pin: None,
    };
    let rw = crate::elevation::posix::rewrite_with_host(c, &host)?;
    Ok(rw.derived.expect("the already-elevated rewrite derives a command"))
}

/// Write to the real stderr: libtest captures `eprintln!`, and the fixture exits without
/// returning, so a captured line would never be printed.
fn report(line: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "{line}");
}

/// Runs the fixture in `<root>/p/d` with `p` unsearchable, so its cwd has no path it can use —
/// `getcwd` fails on macOS, and a `chdir` to the path fails everywhere. `d/tool` exits with
/// [`CWD_TOOL_EXIT`] and `d/sub/tool` with [`PATH_TOOL_EXIT`], each only when run in its own
/// directory. The fixture starts without DAC bypass, so `p` binds a root driver too. Returns the
/// fixture's exit code, and its stderr prefixed with the gate write's result.
///
/// Root, `d` and `d/sub` are `chmod 0o755` explicitly: where a root driver drops uid, the fixture
/// is not their owner. `p` needs no mode: it is `0o000` before the dropped uid looks at it.
///
/// The write can fail: a fixture that refused a precondition has exited before reading it. Its exit
/// code and stderr then say why, so the write result is reported rather than panicked on.
///
/// The fixture's cwd is set by the spawner, so no process in this test moves its own.
fn spawn_exact_tool_in_an_unreachable_cwd(current_dir: Option<&str>, already_elevated: bool) -> (Option<i32>, String) {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    // `tempdir` creates 0o700, so the chmod is what makes `root` traversable to a dropped uid.
    let root = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).expect("chmod root");
    let (p, d) = (root.path().join("p"), root.path().join("p").join("d"));
    std::fs::create_dir(&p).expect("mkdir p");
    marker_tool(&d, "d-marker", CWD_TOOL_EXIT);
    marker_tool(&d.join("sub"), "sub-marker", PATH_TOOL_EXIT);
    let (mut fixture, _exe_copy) = crate::test_child::fixture_command_without_dac_bypass(FIXTURE_UNREACHABLE_CWD_TEST);
    fixture
        .env(FIXTURE_UNREACHABLE_CWD_ENV, &d)
        .current_dir(&d)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null());
    if let Some(dir) = current_dir {
        fixture.env(FIXTURE_CURRENT_DIR_ENV, dir);
    }
    if already_elevated {
        fixture.env(FIXTURE_ALREADY_ELEVATED_ENV, "1");
    }
    let mut child = {
        // Every fork in this binary holds it; see `cwd_and_path_tools`.
        let _guard = crate::child::spawn::spawn_lock();
        fixture.spawn().expect("spawn the fixture")
    };
    let _restore = crate::test_child::RestoreMode::new(&p, 0o755);
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");
    let gate = child.stdin.take().expect("stdin").write_all(b"x");
    let out = child.wait_with_output().expect("wait");
    (
        out.status.code(),
        format!("gate write: {gate:?}\n{}", String::from_utf8_lossy(&out.stderr)),
    )
}

/// A cwd with no usable path still runs a bare `raw_executable()`, as `./tool` does under std:
/// the child resolves the name against the cwd it inherits, and is left in it.
#[test]
fn an_exact_program_runs_in_a_cwd_that_has_no_path() {
    let (code, stderr) = spawn_exact_tool_in_an_unreachable_cwd(None, false);
    assert_eq!(code, Some(CWD_TOOL_EXIT), "{stderr}");
}

/// An already-root `.elevate()` runs no backend, so it spawns as the unelevated path does and
/// needs no path to the cwd either.
#[test]
fn an_already_elevated_exact_program_runs_in_a_cwd_that_has_no_path() {
    for (dir, want) in [(None, CWD_TOOL_EXIT), (Some("sub"), PATH_TOOL_EXIT)] {
        let (code, stderr) = spawn_exact_tool_in_an_unreachable_cwd(dir, true);
        assert_eq!(code, Some(want), "{dir:?}: {stderr}");
    }
}

/// A relative `current_dir` is entered from the inherited cwd too, and the program is loaded from
/// there: `sub/tool`, run in `sub`.
#[test]
fn a_relative_current_dir_is_entered_from_a_cwd_that_has_no_path() {
    let (code, stderr) = spawn_exact_tool_in_an_unreachable_cwd(Some("sub"), false);
    assert_eq!(code, Some(PATH_TOOL_EXIT), "{stderr}");
}

/// `current_dir("")` fails `chdir` for a `Search` program; an `Exact` one fails the same way.
#[test]
fn an_empty_cwd_fails_an_exact_program_as_it_fails_a_search_one() {
    let (cwd, _on_path) = cwd_and_path_tools();
    let kind = |c: &mut Command| match c.spawn() {
        Err(Error::Io(e)) => e.kind(),
        other => panic!("expected Io, got {other:?}"),
    };
    let mut exact = Command::new();
    exact.raw_executable("tool").args(["tool"]).current_dir("");
    let mut search = Command::new();
    search
        .executable(cwd.path().join("tool"))
        .args([cwd.path().join("tool")])
        .current_dir("");
    assert_eq!(kind(&mut search), std::io::ErrorKind::NotFound);
    assert_eq!(kind(&mut exact), std::io::ErrorKind::NotFound);
}

/// The directory is entered by cosca's hook, not std: std leaves a relative program with a
/// `current_dir` "platform specific and unstable". Its hook cannot be inspected, so this pins that
/// std is handed no directory to apply; the unreachable-cwd tests pin that the hook enters it.
#[test]
fn a_relative_exact_program_hands_std_no_current_dir() {
    for dir in ["sub", "/work"] {
        let mut c = Command::new();
        c.raw_executable("tool").args(["tool"]).current_dir(dir);
        let std_cmd = crate::child::spawn::build_std_command(&c).expect("build");
        assert_eq!(std_cmd.get_current_dir(), None, "{dir}");
        assert_eq!(std_cmd.get_program(), "./tool", "{dir}");
    }
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
