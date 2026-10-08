//! The program the shim starts: what it is resolved to, and what it inherits (plan F, D1b, D11).

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
fn directory_and_non_executable_candidates_are_skipped_then_eacces() {
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
    // Only skipped candidates: EACCES, and nothing ran.
    let (outcome, _) = outcome_of(Spec::new("tool", &[]).search_path(join(&[&dirs[0], &dirs[1]])));
    assert_eq!(outcome, not_executed(NotExecuted::ExecFailed(Errno(libc::EACCES))));
    assert!(!marker.exists());
    // A later executable one still wins.
    let (outcome, code) = outcome_of(Spec::new("tool", &[]).search_path(join(&[&dirs[0], &dirs[1], &dirs[2]])));
    assert_eq!(outcome, LinkOutcome::Exited(0));
    assert_eq!(code, Some(0));
    assert!(marker.exists(), "the executable candidate did not run");
}

#[skuld::test]
fn no_shebang_script_runs_via_bin_sh() {
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");
    let path = tmp.path().join("noshebang");
    std::fs::write(&path, format!("echo \"$0|$1|$2\" > '{}'\n", out.display())).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (outcome, _) = outcome_of(Spec::new(path.as_os_str(), &["one", "two words"]));
    assert_eq!(outcome, LinkOutcome::Exited(0));
    // `/bin/sh <script> args…`: the script's path is `$0`, and the arguments are intact.
    assert_eq!(
        std::fs::read_to_string(out).unwrap(),
        format!("{}|one|two words\n", path.display())
    );
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
    // The caller ignores SIGPIPE before spawning; the shim confirms it inherited that.
    let rig = ShimRig::new();
    let mut run = rig.spawn(Spec::new("cat", &["/proc/self/status"]).ignoring(libc::SIGPIPE));
    let mut stdout = run.take_stdout();
    run.wait_for("sigpipe at entry: ignored");
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
