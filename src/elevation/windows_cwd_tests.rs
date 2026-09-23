//! The consent launch reads this process's cwd at most once, and uses that one read for both the
//! resolver's base and `lpDirectory`. Every test injects the reader, so none touches the real cwd.

use std::cell::Cell;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use super::windows_tests::win_host;
use super::{RunasLaunch, RunasStep};
use crate::command::Command;

/// A cwd reader returning `dir` and counting its calls.
struct Reader {
    dir: PathBuf,
    reads: Cell<u32>,
}

impl Reader {
    fn new(dir: &Path) -> Self {
        Reader {
            dir: dir.to_path_buf(),
            reads: Cell::new(0),
        }
    }
    fn read(&self) -> std::io::Result<PathBuf> {
        self.reads.set(self.reads.get() + 1);
        Ok(self.dir.clone())
    }
}

fn plan(c: &Command, reader: &Reader) -> RunasLaunch {
    let dirs = super::ProcessDirs {
        cwd: &|| reader.read(),
        env: &|| {
            Ok(crate::child::spawn::windows_raw::env_snapshot::EnvSnapshot::from_block(
                vec![0],
            ))
        },
    };
    match super::plan_runas_with(c, &win_host(false), &dirs) {
        Ok(RunasStep::Launch(launch)) => *launch,
        Ok(RunasStep::AlreadyElevated) => panic!("an unelevated host must not short-circuit"),
        Err(e) => panic!("must plan a launch: {e:?}"),
    }
}

fn unwide(w: &[u16]) -> PathBuf {
    assert_eq!(w.last(), Some(&0), "NUL-terminated");
    PathBuf::from(OsString::from_wide(&w[..w.len() - 1]))
}

fn tempdir_with_tool(sub: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(sub)).unwrap();
    std::fs::write(dir.path().join(sub).join("tool.exe"), b"x").unwrap();
    dir
}

/// A relative `current_dir` is joined onto ONE read, and both fields use the result.
#[test]
fn a_relative_current_dir_is_read_once_for_both_fields() {
    let dir = tempdir_with_tool("sub");
    let reader = Reader::new(dir.path());
    let mut c = Command::new();
    c.args([r".\tool.exe"]).current_dir("sub").elevate();
    let launch = plan(&c, &reader);
    assert_eq!(reader.reads.get(), 1);
    assert_eq!(unwide(&launch.file_w), dir.path().join("sub").join(r".\tool.exe"));
    assert_eq!(
        unwide(launch.dir_w.as_ref().expect("lpDirectory is set")),
        dir.path().join("sub")
    );
}

/// With no `current_dir`, a relative located name reads the cwd once, and the child is run in the
/// directory it was resolved against rather than left to `ShellExecuteEx`'s own read.
#[test]
fn no_current_dir_and_a_relative_name_reads_once_for_both_fields() {
    let dir = tempdir_with_tool("");
    let reader = Reader::new(dir.path());
    let mut c = Command::new();
    c.args([r".\tool.exe"]).elevate();
    let launch = plan(&c, &reader);
    assert_eq!(reader.reads.get(), 1);
    assert_eq!(unwide(&launch.file_w), dir.path().join(r".\tool.exe"));
    assert_eq!(unwide(launch.dir_w.as_ref().expect("lpDirectory is set")), dir.path());
}

/// Nothing needs the process cwd: an absolute `current_dir`, or none with a bare name.
#[test]
fn the_cwd_is_not_read_when_nothing_needs_it() {
    let dir = tempdir_with_tool("");
    let reader = Reader::new(Path::new(r"C:\cosca-must-not-be-read"));
    let mut abs = Command::new();
    abs.args([r".\tool.exe"]).current_dir(dir.path()).elevate();
    let launch = plan(&abs, &reader);
    assert_eq!(unwide(&launch.file_w), dir.path().join(r".\tool.exe"));
    let mut bare = Command::new();
    bare.args(["whoami"]).elevate();
    let launch = plan(&bare, &reader);
    assert_eq!(
        launch.dir_w, None,
        "no current_dir and no base read: lpDirectory stays null"
    );
    assert_eq!(reader.reads.get(), 0);
}

/// A relative `raw_executable()` token is completed against the same one read, which also pins
/// the child's directory, whatever `current_dir` is.
#[test]
fn a_relative_exact_token_shares_the_one_read() {
    let process = PathBuf::from(r"C:\cosca-process-cwd");
    let absolute = PathBuf::from(r"C:\cosca-child-cwd");
    for (cwd, want_dir) in [
        (None, process.clone()),
        (Some(PathBuf::from("sub")), process.join("sub")),
        (Some(absolute.clone()), absolute.clone()),
    ] {
        let reader = Reader::new(&process);
        let mut c = Command::new();
        c.raw_executable("tool.exe").args(["tool.exe"]).elevate();
        if let Some(cwd) = &cwd {
            c.current_dir(cwd);
        }
        let launch = plan(&c, &reader);
        assert_eq!(reader.reads.get(), 1, "current_dir {cwd:?}");
        assert_eq!(unwide(&launch.file_w), process.join("tool.exe"), "current_dir {cwd:?}");
        assert_eq!(
            unwide(launch.dir_w.as_ref().expect("lpDirectory is set")),
            want_dir,
            "current_dir {cwd:?}"
        );
    }
}

/// An absolute `raw_executable()` token needs no read, and with no `current_dir` the child's
/// directory is left to `ShellExecuteEx` as before.
#[test]
fn an_absolute_exact_token_reads_nothing() {
    let reader = Reader::new(Path::new(r"C:\cosca-must-not-be-read"));
    let mut c = Command::new();
    c.raw_executable(r"C:\t\tool.exe").args([r"C:\t\tool.exe"]).elevate();
    let launch = plan(&c, &reader);
    assert_eq!(reader.reads.get(), 0);
    assert_eq!(launch.dir_w, None);
}

fn plan_err(c: &Command, reader: &Reader) -> crate::error::Error {
    let dirs = super::ProcessDirs {
        cwd: &|| reader.read(),
        env: &|| {
            Ok(crate::child::spawn::windows_raw::env_snapshot::EnvSnapshot::from_block(
                vec![0],
            ))
        },
    };
    match super::plan_runas_with(c, &win_host(false), &dirs) {
        Ok(_) => panic!("must be refused"),
        Err(e) => e,
    }
}

/// A drive-relative `current_dir` is completed as Win32 completes it: onto the one read when it
/// names the current drive, onto that drive's own directory (here unset, so its root) when not.
/// Either way `lpDirectory` is absolute, and the cwd is read at most once. Both arms.
#[test]
fn a_drive_relative_current_dir_is_completed_absolute() {
    let process = PathBuf::from(r"C:\cosca-process-cwd");
    for (cwd, want) in [("C:sub", process.join("sub")), ("Q:sub", PathBuf::from(r"Q:\sub"))] {
        let mut search = Command::new();
        search.args(["whoami"]).current_dir(cwd).elevate();
        let mut exact = Command::new();
        exact
            .raw_executable(r"C:\t\tool.exe")
            .args([r"C:\t\tool.exe"])
            .current_dir(cwd)
            .elevate();
        for (arm, c) in [("Search", search), ("Exact", exact)] {
            let reader = Reader::new(&process);
            let launch = plan(&c, &reader);
            let dir = unwide(launch.dir_w.as_ref().expect("lpDirectory is set"));
            assert!(dir.is_absolute(), "{arm}, {cwd:?}: {dir:?}");
            assert_eq!(dir, want, "{arm}, {cwd:?}");
            assert!(reader.reads.get() <= 1, "{arm}, {cwd:?}: {} reads", reader.reads.get());
        }
    }
}

/// A `raw_executable()` token relative to another drive takes nothing from this process's cwd, so
/// the cwd, fetched at most once to learn the current drive, does not pin `lpDirectory`.
#[test]
fn another_drives_exact_token_leaves_lp_directory_null() {
    let reader = Reader::new(Path::new(r"C:\cosca-process-cwd"));
    let mut c = Command::new();
    c.raw_executable("Q:tool.exe").args(["Q:tool.exe"]).elevate();
    let launch = plan(&c, &reader);
    assert!(reader.reads.get() <= 1);
    assert_eq!(unwide(&launch.file_w), PathBuf::from(r"Q:\tool.exe"));
    assert_eq!(launch.dir_w, None);
}

/// A rooted `Search` token takes the read's drive, for both fields, from one read.
#[test]
fn a_rooted_search_token_takes_the_reads_drive() {
    let dir = tempdir_with_tool("");
    let rooted: PathBuf = dir.path().components().skip(1).collect();
    assert!(
        rooted.has_root() && rooted.to_string_lossy().starts_with('\\'),
        "{rooted:?}"
    );
    let reader = Reader::new(dir.path());
    let mut c = Command::new();
    c.args([rooted.join("tool.exe")]).elevate();
    let launch = plan(&c, &reader);
    assert_eq!(reader.reads.get(), 1);
    assert_eq!(unwide(&launch.file_w), dir.path().join("tool.exe"));
    assert_eq!(unwide(launch.dir_w.as_ref().expect("lpDirectory is set")), dir.path());
}

/// Win32 reads a name starting with two separators as UNC. One naming no share is refused on every
/// arm, never completed onto the cwd's drive, and nothing is read.
#[test]
fn a_unc_shaped_name_with_no_share_is_refused_without_a_read() {
    for name in [r"\\tool.exe", "//tool.exe"] {
        let mut exact = Command::new();
        exact.raw_executable(name).args([name]).elevate();
        let mut search = Command::new();
        search.executable(name).args([name]).elevate();
        let mut dir = Command::new();
        dir.args(["whoami"]).current_dir(r"\\server").elevate();
        for (what, c) in [("raw_executable", exact), ("executable", search), ("current_dir", dir)] {
            let reader = Reader::new(Path::new(r"C:\cosca-must-not-be-read"));
            match plan_err(&c, &reader) {
                crate::error::Error::Io(e) => {
                    assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{what} {name:?}: {e}")
                }
                other => panic!("{what} {name:?}: expected Io(InvalidInput), got {other:?}"),
            }
            assert_eq!(reader.reads.get(), 0, "{what} {name:?}");
        }
    }
}

/// A drive's rest is appended as units: `current_dir(r"C:D:\elsewhere")` on drive C is a directory
/// under the cwd, never `D:\elsewhere`.
#[test]
fn a_second_drive_in_a_drive_relative_current_dir_stays_under_the_cwd() {
    let process = PathBuf::from(r"C:\cosca-process-cwd");
    let reader = Reader::new(&process);
    let mut c = Command::new();
    c.args(["whoami"]).current_dir(r"C:D:\elsewhere").elevate();
    let launch = plan(&c, &reader);
    let dir = unwide(launch.dir_w.as_ref().expect("lpDirectory is set"));
    assert_eq!(dir, PathBuf::from(r"C:\cosca-process-cwd\D:\elsewhere"));
    assert_eq!(reader.reads.get(), 1);
}

/// `1:tool.exe` is drive-relative to both arms: `raw_executable()` completes it on drive `1`'s own
/// directory (here its root), and `executable()` refuses it, as every drive-relative name.
#[test]
fn a_digit_drive_is_drive_relative_on_both_arms() {
    let reader = Reader::new(Path::new(r"C:\cosca-process-cwd"));
    let mut exact = Command::new();
    exact.raw_executable("1:tool.exe").args(["1:tool.exe"]).elevate();
    let launch = plan(&exact, &reader);
    assert_eq!(unwide(&launch.file_w), PathBuf::from(r"1:\tool.exe"));
    assert_eq!(launch.dir_w, None);

    let mut search = Command::new();
    search.executable("1:tool.exe").args(["1:tool.exe"]).elevate();
    match plan_err(&search, &reader) {
        crate::error::Error::Io(e) => {
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}");
            assert!(e.to_string().contains("drive"), "{e}");
        }
        other => panic!("expected Io(InvalidInput), got {other:?}"),
    }
}

/// One environment snapshot per launch serves both `PATH` and a drive's own directory.
#[test]
fn the_environment_is_read_once_for_path_and_a_drive_directory() {
    let reads = std::cell::Cell::new(0);
    let block: Vec<u16> = "=Q:=Q:\\qcwd\0PATH=C:\\cosca-empty\0\0".encode_utf16().collect();
    let env = || {
        reads.set(reads.get() + 1);
        Ok(crate::child::spawn::windows_raw::env_snapshot::EnvSnapshot::from_block(
            block.clone(),
        ))
    };
    let dirs = super::ProcessDirs {
        cwd: &|| Ok(PathBuf::from(r"C:\cosca-process-cwd")),
        env: &env,
    };
    let mut c = Command::new();
    c.args(["whoami"]).current_dir("Q:sub").elevate();
    let launch = match super::plan_runas_with(&c, &win_host(false), &dirs) {
        Ok(RunasStep::Launch(launch)) => *launch,
        other => panic!("must plan a launch: {:?}", other.map(|_| ())),
    };
    assert_eq!(unwide(launch.dir_w.as_ref().unwrap()), PathBuf::from(r"Q:\qcwd\sub"));
    assert_eq!(reads.get(), 1);
}

/// A drive-absolute `current_dir` on a non-letter drive is already a base, so the resolver reads
/// nothing more. `std` does not know drive `1`, which is why the resolver's own classifier decides.
/// The candidate is searched on drive `1` and is simply absent there.
#[test]
fn a_digit_drive_current_dir_is_a_base_without_a_read() {
    let reader = Reader::new(Path::new(r"C:\cosca-must-not-be-read"));
    let mut c = Command::new();
    c.args([r".\tool.exe"]).current_dir(r"1:\sub").elevate();
    match plan_err(&c, &reader) {
        crate::error::Error::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}"),
        other => panic!("expected NotFound on drive 1, got {other:?}"),
    }
    assert_eq!(reader.reads.get(), 0);
}

/// A verbatim `current_dir` at the consent launch: `./tool.exe` resolves inside it.
#[test]
fn a_verbatim_current_dir_resolves_a_dot_relative_name() {
    let dir = tempdir_with_tool("");
    let mut verbatim = std::ffi::OsString::from(r"\\?\");
    verbatim.push(dir.path());
    let reader = Reader::new(Path::new(r"C:\cosca-must-not-be-read"));
    let mut c = Command::new();
    c.args([r"./tool.exe"]).current_dir(&verbatim).elevate();
    let launch = plan(&c, &reader);
    assert_eq!(unwide(&launch.file_w), Path::new(&verbatim).join("tool.exe"));
    assert_eq!(reader.reads.get(), 0);
}

/// `current_dir("")` at the consent launch names no directory, as on the raw backend.
#[test]
fn an_empty_current_dir_is_refused_at_the_consent_launch() {
    let reader = Reader::new(Path::new(r"C:\cosca-must-not-be-read"));
    let mut c = Command::new();
    c.args(["whoami"]).current_dir("").elevate();
    match plan_err(&c, &reader) {
        crate::error::Error::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}"),
        other => panic!("expected Io(NotFound), got {other:?}"),
    }
    assert_eq!(reader.reads.get(), 0);
}

/// Under consent a verbatim `raw_executable()` is sent as written: `tool.exe.` is refused by the
/// allowlist rather than normalised into its sibling `tool.exe`, and a literal `..` stays literal.
#[test]
fn a_verbatim_exact_token_reaches_the_consent_launch_as_written() {
    let reader = Reader::new(Path::new(r"C:\cosca-must-not-be-read"));
    let mut dotted = Command::new();
    dotted.raw_executable(r"\\?\C:\t\tool.exe.").args(["tool"]).elevate();
    match plan_err(&dotted, &reader) {
        crate::error::Error::Io(e) => assert!(e.to_string().contains("PATHEXT"), "{e}"),
        other => panic!("expected the allowlist's refusal, got {other:?}"),
    }
    let mut dotdot = Command::new();
    dotdot
        .raw_executable(r"\\?\C:\t\x\..\tool.exe")
        .args(["tool"])
        .elevate();
    let launch = plan(&dotdot, &reader);
    assert_eq!(unwide(&launch.file_w), PathBuf::from(r"\\?\C:\t\x\..\tool.exe"));
    assert_eq!(reader.reads.get(), 0);
}
