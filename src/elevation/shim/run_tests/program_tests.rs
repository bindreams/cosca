//! The program the shim starts: what it is resolved to, and what it inherits.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::elevation::shim::protocol::{Errno, NotExecuted};

fn not_executed(cause: NotExecuted) -> LinkOutcome {
    LinkOutcome::NotStarted(NotStarted {
        shim_connected: true,
        cause: NotStartedCause::NotExecuted(cause),
    })
}

/// An executable shell script `name` in `dir` that writes `ran` to `marker`.
fn script(dir: &Path, name: &str, marker: &Path, mode: u32) {
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\necho ran > '{}'\n", marker.display())).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Starts `spec` and returns its outcome and exit code.
fn outcome_of(spec: Spec) -> (LinkOutcome, Option<i32>) {
    let rig = ShimRig::new();
    let mut run = rig.spawn(spec);
    run.wait_for("first byte: A");
    let outcome = rig.link.link.wait().unwrap();
    (outcome, run.finish().code)
}

#[skuld::test]
fn bare_name_not_on_path_never_runs_a_cwd_file() {
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("ran");
    script(tmp.path(), "tool", &marker, 0o755);
    let spec = Spec::new("tool", &[]).search_path("/usr/bin:/bin").cwd(tmp.path());
    let (outcome, code) = outcome_of(spec);
    assert_eq!(outcome, not_executed(NotExecuted::ExecFailed(Errno(libc::ENOENT))));
    assert_eq!(code, Some(117));
    assert!(!marker.exists(), "a file in the working directory ran");
}

#[skuld::test]
fn relative_and_empty_path_elements_are_never_searched() {
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("ran");
    script(tmp.path(), "tool", &marker, 0o755);
    for path in ["", ":", ".", ":/usr/bin", "/usr/bin::/bin", "./"] {
        let spec = Spec::new("tool", &[]).search_path(path).cwd(tmp.path());
        let (outcome, _) = outcome_of(spec);
        assert_eq!(
            outcome,
            not_executed(NotExecuted::ExecFailed(Errno(libc::ENOENT))),
            "PATH {path:?}"
        );
        assert!(!marker.exists(), "PATH {path:?} ran a file in the working directory");
    }
}

#[skuld::test]
fn a_directory_is_skipped_and_the_first_file_is_the_match_whatever_its_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("ran");
    let dirs: Vec<PathBuf> = ["d", "p", "x"].iter().map(|n| tmp.path().join(n)).collect();
    for dir in &dirs {
        std::fs::create_dir(dir).unwrap();
    }
    std::fs::create_dir(dirs[0].join("tool")).unwrap();
    script(&dirs[1], "tool", &marker, 0o644);
    script(&dirs[2], "tool", &marker, 0o755);
    let join = |list: &[&PathBuf]| {
        list.iter()
            .map(|d| d.display().to_string())
            .collect::<Vec<_>>()
            .join(":")
    };
    // A directory is skipped; the first file is the match, whatever its mode: its exec is refused, and
    // the executable file after it does not run in its place.
    let (outcome, _) = outcome_of(Spec::new("tool", &[]).search_path(join(&[&dirs[0], &dirs[1]])));
    assert_eq!(outcome, not_executed(NotExecuted::ExecFailed(Errno(libc::EACCES))));
    assert!(!marker.exists());
    let (outcome, _) = outcome_of(Spec::new("tool", &[]).search_path(join(&[&dirs[0], &dirs[1], &dirs[2]])));
    assert_eq!(outcome, not_executed(NotExecuted::ExecFailed(Errno(libc::EACCES))));
    assert!(!marker.exists(), "the search went on past the first file");
    // Without the file without the bit, the executable one runs.
    let (outcome, code) = outcome_of(Spec::new("tool", &[]).search_path(join(&[&dirs[0], &dirs[2]])));
    assert_eq!(outcome, LinkOutcome::Exited(0));
    assert_eq!(code, Some(0));
    assert!(marker.exists(), "the executable candidate did not run");
}

/// An executable file that is no executable format is `ENOEXEC`, and does not run through `/bin/sh`.
///
/// Mutant: the shim retries `ENOEXEC` through `/bin/sh`.
#[skuld::test]
fn a_file_that_is_no_executable_format_is_enoexec() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");
    let path = tmp.path().join("noshebang");
    std::fs::write(&path, format!("echo ran > '{}'\n", out.display())).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (outcome, _) = outcome_of(Spec::new(path.as_os_str(), &["one", "two words"]));
    assert_eq!(outcome, not_executed(NotExecuted::ExecFailed(Errno(libc::ENOEXEC))));
    assert!(!out.exists(), "the script ran");
}

/// A program that names no file is refused by its shape: `EINVAL`, not a miss.
///
/// Mutant: the shim reports every refusal as `ENOENT`.
#[skuld::test]
fn a_program_that_names_no_file_is_einval() {
    for name in ["", ".", "..", "bin/", "/usr/bin/"] {
        let (outcome, _) = outcome_of(Spec::new(name, &[]).search_path("/usr/bin:/bin"));
        assert_eq!(
            outcome,
            not_executed(NotExecuted::ExecFailed(Errno(libc::EINVAL))),
            "{name:?}"
        );
    }
}

/// The signal masks of a program that prints `/proc/self/status`.
fn program_signal_masks(spec: Spec) -> (u64, u64) {
    let rig = ShimRig::new();
    let mut run = rig.spawn(spec);
    let mut stdout = run.take_stdout();
    run.wait_for("first byte: A");
    let mut text = String::new();
    stdout.read_to_string(&mut text).unwrap();
    assert_eq!(rig.link.link.wait().unwrap(), LinkOutcome::Exited(0));
    run.finish();
    let field = |name: &str| {
        let value = text.lines().find_map(|l| l.strip_prefix(name)).expect("the field");
        u64::from_str_radix(value.trim_start_matches(':').trim(), 16).unwrap()
    };
    (field("SigIgn"), field("SigCgt"))
}

fn bit(signal: i32) -> u64 {
    1 << (signal - 1)
}

#[skuld::test]
fn elevated_program_sees_sigpipe_at_sig_dfl() {
    // The caller ignores SIGPIPE before spawning, as a Rust runtime does for itself.
    let rig = ShimRig::new();
    let mut run = rig.spawn(Spec::new("cat", &["/proc/self/status"]).ignoring(libc::SIGPIPE));
    let mut stdout = run.take_stdout();
    let mut text = String::new();
    stdout.read_to_string(&mut text).unwrap();
    run.finish();
    let ignored = text
        .lines()
        .find_map(|l| l.strip_prefix("SigIgn:"))
        .map(|v| u64::from_str_radix(v.trim(), 16).unwrap())
        .expect("SigIgn");
    assert_eq!(
        ignored & bit(libc::SIGPIPE),
        0,
        "the program started with SIGPIPE ignored: {ignored:#x}"
    );
}

#[skuld::test]
fn program_keeps_the_callers_other_ignored_signals() {
    let spec = Spec::new("cat", &["/proc/self/status"])
        .ignoring(libc::SIGHUP)
        .ignoring(libc::SIGUSR1);
    let (ignored, caught) = program_signal_masks(spec);
    assert_ne!(ignored & bit(libc::SIGHUP), 0, "SIGHUP: {ignored:#x}");
    assert_ne!(ignored & bit(libc::SIGUSR1), 0, "SIGUSR1: {ignored:#x}");
    assert_eq!(caught, 0, "exec resets every handler");
}

// The file found changes between the search and the exec -----

/// Two directories, searched in this order, and the `PATH` that names them.
struct Tools {
    _tmp: tempfile::TempDir,
    first: PathBuf,
    second: PathBuf,
    path: std::ffi::OsString,
}

fn two_tool_dirs() -> Tools {
    let tmp = tempfile::tempdir().unwrap();
    let (first, second) = (tmp.path().join("first"), tmp.path().join("second"));
    std::fs::create_dir(&first).unwrap();
    std::fs::create_dir(&second).unwrap();
    let path = std::env::join_paths([&first, &second]).unwrap();
    Tools {
        _tmp: tmp,
        first,
        second,
        path,
    }
}

/// Runs `tool` over `tools.path`, holding the shim just before the clone while `change` alters the
/// directories, and returns the outcome. Both candidates were executable when the shim searched.
fn changed_before_the_clone(tools: &Tools, args: &[&str], change: impl FnOnce()) -> LinkOutcome {
    let rig = ShimRig::new();
    let mut run = rig.spawn(
        Spec::new("tool", args)
            .search_path(tools.path.clone())
            .gate(crate::elevation::shim::hooks::Gate::BeforeClone),
    );
    run.wait_for("gate: waiting at before-clone");
    change();
    run.release(crate::elevation::shim::hooks::Gate::BeforeClone);
    let outcome = rig.link.link.wait().unwrap();
    run.finish();
    outcome
}

/// The file found is gone at the exec: the child goes on to the next candidate on the `PATH`, as it
/// would had the first never been there, and the program runs.
///
/// Mutant: the child tries the file found only.
#[skuld::test]
fn a_match_that_vanishes_before_the_exec_runs_the_next_candidate() {
    let tools = two_tool_dirs();
    let marker = tools.second.join("ran");
    script(&tools.first, "tool", &tools.first.join("ran"), 0o755);
    script(&tools.second, "tool", &marker, 0o755);
    let outcome = changed_before_the_clone(&tools, &[], || std::fs::remove_file(tools.first.join("tool")).unwrap());
    assert_eq!(outcome, LinkOutcome::Exited(0));
    assert!(marker.exists(), "the next candidate did not run");
}

/// A match the exec is denied is `EACCES`, whatever follows it.
#[skuld::test]
fn a_match_that_is_denied_at_the_exec_is_eacces_and_the_next_does_not_run() {
    let tools = two_tool_dirs();
    let marker = tools.first.join("ran");
    script(&tools.first, "tool", &marker, 0o755);
    script(&tools.second, "tool", &marker, 0o755);
    let outcome = changed_before_the_clone(&tools, &[], || {
        std::fs::set_permissions(tools.first.join("tool"), std::fs::Permissions::from_mode(0o000)).unwrap();
    });
    assert_eq!(outcome, not_executed(NotExecuted::ExecFailed(Errno(libc::EACCES))));
    assert!(!marker.exists());
}

/// Any other exec failure is the answer as it is.
#[skuld::test]
fn a_match_that_fails_otherwise_at_the_exec_is_the_answer() {
    let tools = two_tool_dirs();
    let marker = tools.second.join("ran");
    script(&tools.first, "tool", &marker, 0o755);
    script(&tools.second, "tool", &marker, 0o755);
    let outcome = changed_before_the_clone(&tools, &[], || {
        // A symlink to itself: `execve` answers `ELOOP`.
        let first = tools.first.join("tool");
        std::fs::remove_file(&first).unwrap();
        std::os::unix::fs::symlink("tool", &first).unwrap();
    });
    assert_eq!(outcome, not_executed(NotExecuted::ExecFailed(Errno(libc::ELOOP))));
    assert!(!marker.exists(), "the search went on past a failure");
}
