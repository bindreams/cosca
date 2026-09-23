//! A process whose own cwd is longer than `MAX_PATH` spawning a child: the raw backend now passes
//! that cwd as `lpCurrentDirectory`, where main passed NULL. Measured in a `cosca_testbin` that
//! moves its own cwd, so this test process's cwd never changes.
#![cfg(windows)]

#[path = "common/mod.rs"]
mod common;

#[test]
fn a_process_with_a_long_cwd_spawns_as_it_did_with_a_null_lp_current_directory() {
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
    // Measured on the CI runners: see the PR for the record.
    let expected = ["set_plain=err=206", "set_verbatim=err=206"];
    assert_eq!(facts, expected, "full report:\n{report}");
}
