//! M21: what a verbatim `current_dir` ending in a dot does, per route.

use std::process::Command;

use crate::common::drive_rule::{canonical, Render};
use crate::common::testbin;
use crate::provenance::survey_platform;
use crate::test_groups::{path_probes, Group};

/// M21: `current_dir(\\?\<d>\a.)` where only `<d>\a` exists, per spawn route (std, argv-only cosca,
/// raw `executable()`, bare CreateProcessW). The child opens the relative `cosca-marker`, which
/// exists only in `<d>\a`, so `marker=ok` proves its cwd is `a`, not just that it prints a string.
/// `verbatim` and `plain_dot` are controls.
#[skuld::test]
fn m21_a_verbatim_trailing_dot_current_dir(#[fixture(path_probes)] _group: &Group) {
    survey_platform();
    let tmp = tempfile::tempdir().expect("tempdir");
    let d = canonical(tmp.path());
    std::fs::create_dir(format!(r"{d}\a")).expect("create the row directory");
    std::fs::write(format!(r"{d}\a\cosca-marker"), "marker").expect("create the marker file");
    assert!(
        std::fs::metadata(format!(r"\\?\{d}\a")).is_ok_and(|m| m.is_dir()),
        r"precondition: verbatim <d>\a is a directory"
    );
    assert!(
        std::fs::metadata(format!(r"\\?\{d}\a\cosca-marker")).is_ok_and(|m| m.is_file()),
        r"precondition: verbatim <d>\a holds the marker file"
    );
    assert!(
        std::fs::metadata(format!(r"\\?\{d}\a.")).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        r"precondition: verbatim <d>\a. does not exist"
    );
    let bin = testbin();
    // Non-I/O cosca errors print the path with doubled backslashes.
    let render = Render(vec![(d.clone(), "<d>".into()), (d.replace('\\', r"\\"), "<d>".into())]);

    for (key, cwd) in [
        ("verbatim_dot", format!(r"\\?\{d}\a.")),
        ("verbatim", format!(r"\\?\{d}\a")),
        ("plain_dot", format!(r"{d}\a.")),
    ] {
        let mut std_cmd = Command::new(bin);
        std_cmd.arg("cwd-marker").current_dir(&cwd);
        let std_col = finished(
            crate::common::output_locked(&mut std_cmd).map(|o| (o.status.success(), o.status.code(), o.stdout)),
        );

        let mut cosca_cmd = cosca::Command::new();
        cosca_cmd.arg(bin).arg("cwd-marker").current_dir(&cwd);
        let cosca_col = finished(
            cosca_cmd
                .output()
                .map(|o| (o.status.success(), o.status.code(), o.stdout))
                .map_err(into_io),
        );

        let mut raw_cmd = cosca::Command::new();
        raw_cmd.executable(bin).commandline("x cwd-marker").current_dir(&cwd);
        let raw_col = finished(
            raw_cmd
                .output()
                .map(|o| (o.status.success(), o.status.code(), o.stdout))
                .map_err(into_io),
        );

        let mut bare = Command::new(bin);
        bare.args(["try-cwd", &cwd]);
        let out = crate::common::output_locked(&mut bare).expect("spawn the try-cwd probe");
        assert!(out.status.success(), "the try-cwd probe failed: {}", out.status);
        let report = String::from_utf8_lossy(&out.stdout);
        let bare_col = match report.lines().last() {
            Some("ok") => format!("ok,{}", child_report(&report)),
            Some(last) => last.to_owned(),
            None => "no output".to_owned(),
        };

        let std_marker_ok = std_col.ends_with("marker=ok");
        for (route, col) in [
            ("std", std_col),
            ("cosca", cosca_col),
            ("raw_exe", raw_col),
            ("create_process", bare_col),
        ] {
            println!("M21 {key} {route}={}", render.apply(&col));
        }
        if key == "verbatim" {
            assert!(
                std_marker_ok,
                "the control: std's route on the existing verbatim directory runs in it"
            );
        }
    }
}

/// A finished child as `ok,<report>`, `exit=<code>` or `err=<code>`.
fn finished(run: std::io::Result<(bool, Option<i32>, Vec<u8>)>) -> String {
    match run {
        Ok((true, _, stdout)) => format!("ok,{}", child_report(&String::from_utf8_lossy(&stdout))),
        Ok((false, code, _)) => match code {
            Some(code) => format!("exit={code}"),
            None => "exit=<none>".to_owned(),
        },
        Err(e) => match e.raw_os_error() {
            Some(code) => format!("err={code}"),
            None => format!("err({:?}: {e})", e.kind()),
        },
    }
}

fn child_report(stdout: &str) -> String {
    let lines: Vec<&str> = stdout
        .lines()
        .filter(|l| ["cwd=", "cwd-error=", "marker="].iter().any(|k| l.starts_with(k)))
        .collect();
    if lines.is_empty() {
        "no report".to_owned()
    } else {
        lines.join(",")
    }
}

fn into_io(e: cosca::error::Error) -> std::io::Error {
    match e {
        cosca::error::Error::Io(io) => io,
        other => std::io::Error::other(other.to_string()),
    }
}
