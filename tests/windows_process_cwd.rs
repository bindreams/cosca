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

/// No route spawns from a cwd past `MAX_PATH`, even in a long-path-aware process with the policy
/// on: `CreateProcessW` refuses a NULL `lpCurrentDirectory` inherited from it as
/// `ERROR_INVALID_PARAMETER` (87), and the same directory passed explicitly as `ERROR_DIRECTORY`
/// (267). It fails before any child runs, so the child's own manifest changes nothing.
#[test]
fn no_route_spawns_from_a_long_cwd_even_when_long_path_aware() {
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
        "cosca_raw_aware=err=267",
        "null_cwd_aware=err=87",
        "explicit_cwd_aware=err=267",
        "cosca_raw_unaware=err=267",
        "null_cwd_unaware=err=87",
        "explicit_cwd_unaware=err=267",
    ];
    assert_eq!(facts, expected, "full report:\n{report}");
}

/// A relative name against a verbatim process cwd: cosca loads and runs where Win32 does, by
/// `raw_executable()` and by `executable()`'s search alike.
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
        r"raw_nested=ok,image=<d>\sub\tool.exe",
        r"exe_nested=ok,image=<d>\sub\tool.exe",
        r"raw_sub=ok,cwd=<vd>\sub",
        r"std_sub=ok,cwd=<vd>\sub",
    ];
    assert_eq!(facts, expected, "full report:\n{report}");
}

/// A drive-relative `current_dir` on another drive takes that drive's own directory, `=X:`, as
/// Win32 does: cosca's raw backend runs the child where `GetFullPathNameW` and std do, for every
/// shape of that variable.
#[test]
fn a_drive_relative_current_dir_takes_the_drives_own_directory_as_win32_does() {
    let report = probe("drive-dir", env!("CARGO_BIN_EXE_cosca_testbin_image"));
    let facts: Vec<&str> = report.lines().collect();
    let expected = [
        "cwd_set=ok",
        r"gfpn_unset=X:\sub",
        r"cosca_unset=ok,cwd=X:\sub",
        r"std_unset=ok,cwd=X:\sub",
        r"gfpn_exists=X:\exists\sub",
        r"cosca_exists=ok,cwd=X:\exists\sub",
        r"std_exists=ok,cwd=X:\exists\sub",
        r"gfpn_gone=X:\sub",
        r"cosca_gone=ok,cwd=X:\sub",
        r"std_gone=ok,cwd=X:\sub",
        r"gfpn_drive_rel=X:\sub",
        r"cosca_drive_rel=ok,cwd=X:\sub",
        r"std_drive_rel=ok,cwd=X:\sub",
        r"gfpn_relative=X:\sub",
        r"cosca_relative=ok,cwd=X:\sub",
        r"std_relative=ok,cwd=X:\sub",
        r"gfpn_rooted=X:\sub",
        r"cosca_rooted=ok,cwd=X:\sub",
        r"std_rooted=ok,cwd=X:\sub",
        r"gfpn_other_drive=<d>\exists\sub",
        r"cosca_other_drive=ok,cwd=<d>\exists\sub",
        r"std_other_drive=ok,cwd=<d>\exists\sub",
    ];
    assert_eq!(facts, expected, "full report:\n{report}");
}

/// A UNC `current_dir` runs the child there, plainly and verbatim; and against a verbatim UNC
/// process cwd, `GetFullPathNameW` completes a rooted name and a `..` run as measured here.
#[test]
fn a_unc_current_dir_runs_there_and_a_verbatim_unc_cwd_completes_as_win32_does() {
    let report = probe("verbatim-unc", env!("CARGO_BIN_EXE_cosca_testbin_image"));
    let facts: Vec<&str> = report.lines().collect();
    let expected = [
        "cosca_unc_cwd=ok,cwd=<unc>",
        "std_unc_cwd=ok,cwd=<unc>",
        "cosca_vunc_cwd=ok,cwd=<vd>",
        "std_vunc_cwd=ok,cwd=<vd>",
        "set=ok",
        r"gfpn_rooted=\\?\UNC\t.exe",
        r"gfpn_up_depth=<vshare>\t.exe",
        r"gfpn_up_depth_1=\\?\UNC\localhost\t.exe",
        r"gfpn_up_depth_2=\\?\UNC\t.exe",
        r"gfpn_written_up=<vd>\..\t.exe",
        r"gfpn_written_past_share=<vd>\..\t.exe",
    ];
    assert_eq!(facts, expected, "full report:\n{report}");
}
