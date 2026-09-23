//! On the CI runners, a process cannot make a directory longer than `MAX_PATH` its cwd, by the plain
//! path or the `\\?\` form: both fail with `ERROR_FILENAME_EXCED_RANGE` (206). So the raw backend
//! never gets a long process cwd to pass as `lpCurrentDirectory` where a NULL one would have
//! spawned. Measured in a `cosca_testbin` that moves its own cwd, so this test process's cwd never
//! changes; if entering the directory ever succeeds, the probe's spawn outcomes appear and this
//! test fails.
#![cfg(windows)]

#[path = "common/mod.rs"]
mod common;

#[test]
fn a_process_cannot_enter_a_cwd_longer_than_max_path() {
    let base = tempfile::tempdir().unwrap();
    let mut cmd = std::process::Command::new(common::testbin());
    cmd.arg("long-cwd-probe").arg(base.path());
    let out = common::output_locked(&mut cmd).expect("spawn the probe");
    let report = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "probe failed: {report}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let facts: Vec<&str> = report.lines().filter(|l| !l.starts_with("len=")).collect();
    let expected = ["set_plain=err=206", "set_verbatim=err=206"];
    assert_eq!(facts, expected, "full report:\n{report}");
}
