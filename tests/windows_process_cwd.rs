//! Spawning from a process cwd that only a separate process may move: `cosca_testbin_cwd` enters
//! it and reports, so this test process's cwd never changes. See that binary's module doc for the
//! report lines.
//!
//! Precondition, asserted rather than skipped: long paths are enabled for the probe, which needs
//! its `longPathAware` manifest (embedded by `build.rs` on MSVC) and the machine's
//! `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled` set to 1.
#![cfg(windows)]

#[path = "common/mod.rs"]
mod common;

fn probe(mode: &str, child: &str) -> String {
    let base = tempfile::tempdir().unwrap();
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_cosca_testbin_cwd"));
    cmd.arg(mode).arg(base.path()).arg(child);
    let out = common::output_locked(&mut cmd).expect("spawn the probe");
    let report = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "probe failed: {report}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    report
}

#[test]
fn a_long_path_aware_process_spawns_from_a_long_cwd_on_every_route() {
    let report = probe("long", env!("CARGO_BIN_EXE_cosca_testbin_image"));
    let facts: Vec<&str> = report.lines().collect();
    assert_eq!(
        facts.first(),
        Some(&"long_paths_enabled=true"),
        "precondition: the probe's manifest and LongPathsEnabled=1; full report:\n{report}"
    );
    let expected = [
        "long_paths_enabled=true",
        "set_plain=ok",
        "cosca_raw_aware=ok,cwd=<long>",
        "null_cwd_aware=ok,cwd=<long>",
        "explicit_cwd_aware=ok,cwd=<long>",
        "cosca_raw_unaware=ok,cwd=<long>",
        "null_cwd_unaware=ok,cwd=<long>",
        "explicit_cwd_unaware=ok,cwd=<long>",
    ];
    assert_eq!(facts, expected, "full report:\n{report}");
}

/// A relative name against a verbatim process cwd: cosca loads and runs where Win32 does.
#[test]
fn a_verbatim_process_cwd_completes_a_relative_name_as_win32_does() {
    let report = probe("verbatim", env!("CARGO_BIN_EXE_cosca_testbin_image"));
    let facts: Vec<&str> = report.lines().collect();
    let expected = [
        "set=ok",
        r"gfpn_tool=<vd>\tool.exe",
        r"gfpn_sub=<vd>\sub",
        r"win32_tool=ok,image=<d>\tool.exe",
        r"raw_tool=ok,image=<d>\tool.exe",
        r"raw_sub=ok,cwd=<vd>\sub",
        r"std_sub=ok,cwd=<vd>\sub",
    ];
    assert_eq!(facts, expected, "full report:\n{report}");
}
