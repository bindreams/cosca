//! M21: what a verbatim `current_dir` ending in a dot does, per route.

use std::process::Command;

use crate::common::drive_rule::{canonical, Render};
use crate::common::testbin;
use crate::measure::value;
use crate::provenance::survey_platform;
use crate::test_groups::{path_probes, Group};

/// M21: `current_dir(\\?\<d>\a.)` where only `<d>\a` exists, so the verbatim name `a.` is absent.
/// Four routes each run `cosca_testbin_image`, which reports its cwd: `std` (`std::process::Command`),
/// `cosca` (an argv-only `cosca::Command`, std's route on `main`), `raw_exe` (`executable()`, the raw
/// backend) and `create_process` (`cosca_testbin try-cwd`, a bare `CreateProcessW` with that
/// `lpCurrentDirectory`). The rows around it are controls: the verbatim `\\?\<d>\a` and the plain
/// `<d>\a.`, which Win32 normalises to `<d>\a`.
///
/// Preconditions, asserted: `<d>\a` is a directory and verbatim `a.` does not exist.
#[skuld::test]
fn m21_a_verbatim_trailing_dot_current_dir(#[fixture(path_probes)] _group: &Group) {
    survey_platform();
    let tmp = tempfile::tempdir().expect("tempdir");
    let d = canonical(tmp.path());
    std::fs::create_dir(format!(r"{d}\a")).expect("create the row directory");
    assert!(
        std::fs::metadata(format!(r"\\?\{d}\a")).is_ok_and(|m| m.is_dir()),
        r"precondition: verbatim <d>\a is a directory"
    );
    assert!(
        std::fs::metadata(format!(r"\\?\{d}\a.")).is_err(),
        r"precondition: verbatim <d>\a. does not exist"
    );
    let image = env!("CARGO_BIN_EXE_cosca_testbin_image");
    let render = Render(vec![(d.clone(), "<d>".into())]);

    for (key, cwd) in [
        ("verbatim_dot", format!(r"\\?\{d}\a.")),
        ("verbatim", format!(r"\\?\{d}\a")),
        ("plain_dot", format!(r"{d}\a.")),
    ] {
        let mut std_cmd = Command::new(image);
        std_cmd.current_dir(&cwd);
        let std_col = finished(
            crate::common::output_locked(&mut std_cmd).map(|o| (o.status.success(), o.status.code(), o.stdout)),
        );

        let mut cosca_cmd = cosca::Command::new();
        cosca_cmd.arg(image).current_dir(&cwd);
        let cosca_col = finished(
            cosca_cmd
                .output()
                .map(|o| (o.status.success(), o.status.code(), o.stdout))
                .map_err(into_io),
        );

        let mut raw_cmd = cosca::Command::new();
        raw_cmd.executable(image).commandline("x").current_dir(&cwd);
        let raw_col = finished(
            raw_cmd
                .output()
                .map(|o| (o.status.success(), o.status.code(), o.stdout))
                .map_err(into_io),
        );

        // `try-cwd` prints the child's cwd line and then `ok`, or `err=<code>` alone.
        let mut bare = Command::new(testbin());
        bare.args(["try-cwd", &cwd]);
        let out = crate::common::output_locked(&mut bare).expect("spawn the try-cwd probe");
        assert!(out.status.success(), "the try-cwd probe failed: {}", out.status);
        let report = String::from_utf8_lossy(&out.stdout);
        let bare_col = match report.lines().last() {
            Some(last) if last.starts_with("err=") => last.to_owned(),
            _ => format!("ok,cwd={}", report.lines().next().unwrap_or("no cwd line")),
        };

        for (route, col) in [
            ("std", std_col),
            ("cosca", cosca_col),
            ("raw_exe", raw_col),
            ("create_process", bare_col),
        ] {
            println!("M21 {key} {route}={}", render.apply(&col));
        }
    }
}

/// A finished child as `ok,<cwd line>`, `exit=<code>` or `err=<code>`.
fn finished(run: std::io::Result<(bool, Option<i32>, Vec<u8>)>) -> String {
    match run {
        Ok((true, _, stdout)) => format!("ok,cwd={}", value(&String::from_utf8_lossy(&stdout), "cwd")),
        Ok((false, code, _)) => format!("exit={code:?}"),
        Err(e) => match e.raw_os_error() {
            Some(code) => format!("err={code}"),
            None => format!("err({:?}: {e})", e.kind()),
        },
    }
}

/// A cosca error as an I/O error: an I/O error as is, any other by its text.
fn into_io(e: cosca::error::Error) -> std::io::Error {
    match e {
        cosca::error::Error::Io(io) => io,
        other => std::io::Error::other(other.to_string()),
    }
}
