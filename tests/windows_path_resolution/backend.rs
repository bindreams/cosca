//! Surveys of what `main`'s two Windows routes do today, for a change that unifies them to assert.
//! Each records its rows as `M<n> <key>=<value>` and asserts only its preconditions.
//!
//! A route is named by how `main` sends the command: `std` is `std::process::Command`, `cosca`
//! an argv-only `cosca::Command` (std's route on `main`), `raw_fd3` the same with fd 3 mapped and
//! `raw_exe` one with `executable()`, both the raw backend.

use std::process::Command;

use crate::common::testbin;
use crate::measure::{canonical, probe, record, value};
use crate::provenance::survey_platform;
use crate::test_groups::{path_probes, Group};

/// M2: a child spawned while all three of the parent's std handles are null. std sets no
/// `STARTF_USESTDHANDLES` then. The raw backend fails the spawn with `ERROR_INVALID_HANDLE` (6).
#[skuld::test]
fn m2_null_std_handles(#[fixture(path_probes)] _group: &Group) {
    survey_platform();
    let dir = tempfile::tempdir().expect("tempdir");
    let report = probe(Command::new(testbin()).args(["handles-probe", "null"]).arg(dir.path()));
    record("M2", &report);
    assert_eq!(
        value(&report, "parent_std_handles"),
        "null",
        "precondition: the probe's own std handles are null while it spawns"
    );
}

/// M3: a handle the parent marked inheritable and gave to no `Command`. Whether it reaches the
/// child, per route.
#[skuld::test]
fn m3_stray_inheritable_handles(#[fixture(path_probes)] _group: &Group) {
    survey_platform();
    let dir = tempfile::tempdir().expect("tempdir");
    let report = probe(Command::new(testbin()).args(["handles-probe", "stray"]).arg(dir.path()));
    record("M3", &report);
    assert_eq!(
        value(&report, "stray_inheritable"),
        "true",
        "precondition: the stray handle is inheritable in the parent"
    );
}

/// M4: the argv a child parses from `commandline()`, and from argument shapes given through
/// `arg()`/`args()` on `std`, `cosca` and `raw_fd3`. The child's mode comes from
/// `COSCA_TESTBIN_MODE`, so a shifted argv cannot change what it does.
#[skuld::test]
fn m4_commandline_argv(#[fixture(path_probes)] _group: &Group) {
    survey_platform();
    let bin = testbin();
    assert!(
        !bin.contains(' '),
        "precondition: the testbin path {bin:?} needs no quoting"
    );
    for (row, line) in [
        ("leading_whitespace", format!(" {bin} x")),
        ("glued_after_quote", format!("\"{bin}\"x")),
    ] {
        for route in ["cosca", "raw_fd3"] {
            let mut cmd = cosca::Command::new();
            cmd.commandline(&line).env("COSCA_TESTBIN_MODE", "dump-argv");
            if route == "raw_fd3" {
                cmd.fd(3, cosca::Stdio::null()).expect("map fd 3");
            }
            let outcome = match cmd.output() {
                Ok(out) if out.status.success() => argv_of(&String::from_utf8_lossy(&out.stdout), bin),
                Ok(out) => format!("exit={:?}", out.status.code()),
                Err(e) => format!("err({e})"),
            };
            println!("M4 {row}_{route}={outcome}");
        }
    }
    for (row, args) in [
        ("empty_arg", &[""][..]),
        ("embedded_quotes", &[r#"a"b"#, r#""quoted""#]),
        ("trailing_backslashes", &[r"C:\dir\", r"C:\two\\"]),
        ("space", &["a b"]),
        ("space_and_trailing_backslash", &[r"C:\a b\"]),
    ] {
        for route in ["std", "cosca", "raw_fd3"] {
            let outcome = if route == "std" {
                let mut cmd = Command::new(bin);
                cmd.args(args).env("COSCA_TESTBIN_MODE", "dump-argv");
                match crate::common::output_locked(&mut cmd) {
                    Ok(out) if out.status.success() => argv_of(&String::from_utf8_lossy(&out.stdout), bin),
                    Ok(out) => format!("exit={:?}", out.status.code()),
                    Err(e) => format!("err({e})"),
                }
            } else {
                let mut cmd = cosca::Command::new();
                cmd.arg(bin).args(args).env("COSCA_TESTBIN_MODE", "dump-argv");
                if route == "raw_fd3" {
                    cmd.fd(3, cosca::Stdio::null()).expect("map fd 3");
                }
                match cmd.output() {
                    Ok(out) if out.status.success() => argv_of(&String::from_utf8_lossy(&out.stdout), bin),
                    Ok(out) => format!("exit={:?}", out.status.code()),
                    Err(e) => format!("err({e})"),
                }
            };
            println!("M4 argv_{row}_{route}={outcome}");
        }
    }
}

/// `dump-argv`'s `argN=` lines as a list, the testbin path rendered `<testbin>`.
fn argv_of(stdout: &str, bin: &str) -> String {
    let args: Vec<String> = stdout
        .lines()
        .filter(|line| !line.starts_with("argc="))
        .map(|line| line.split_once('=').map_or(line, |(_, v)| v).replace(bin, "<testbin>"))
        .collect();
    format!("{args:?}")
}

/// M13: a verbatim process cwd and no `current_dir`: a child given `NULL` (std's route), the cwd
/// string explicitly (std's and the raw backend's), and the raw backend with no `current_dir`
/// (`unset_raw`), which passes the cwd string, not `NULL`.
#[skuld::test]
fn m13_a_verbatim_process_cwd_without_current_dir(#[fixture(path_probes)] _group: &Group) {
    survey_platform();
    let base = tempfile::tempdir().expect("tempdir");
    let report = probe(
        Command::new(env!("CARGO_BIN_EXE_cosca_testbin_cwd"))
            .arg("verbatim-null")
            .arg(base.path())
            .arg(env!("CARGO_BIN_EXE_cosca_testbin_image")),
    );
    record("M13", &report);
    assert_eq!(
        value(&report, "set"),
        "ok",
        "precondition: the probe entered its verbatim cwd"
    );
}

/// M15: `CreateProcessW` with an `lpApplicationName` of 259, 260 and 300 units, plain and `\\?\`
/// (the prefix counted), from the long-path-aware `cosca_testbin_cwd` and the unaware
/// `cosca_testbin`.
#[skuld::test]
fn m15_image_name_lengths_and_forms(#[fixture(path_probes)] _group: &Group) {
    survey_platform();
    for (half, bin, enabled) in [
        ("aware", env!("CARGO_BIN_EXE_cosca_testbin_cwd"), "true"),
        ("unaware", testbin(), "false"),
    ] {
        let base = tempfile::tempdir().expect("tempdir");
        let base = canonical(base.path());
        let report = probe(
            Command::new(bin)
                .arg("long-image")
                .arg(&base)
                .arg(env!("CARGO_BIN_EXE_cosca_testbin_image")),
        );
        record(&format!("M15 {half}"), &report);
        assert_eq!(
            value(&report, "long_paths_enabled"),
            enabled,
            "precondition: {half} half's manifest and LongPathsEnabled=1"
        );
    }
}
