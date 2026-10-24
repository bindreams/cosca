//! Spawning from a process cwd that only a separate process may move: `cosca_testbin_cwd` enters
//! it and reports, so this test process's cwd never changes. See that binary's module doc for the
//! report lines.
//!
//! Precondition, asserted rather than skipped: long paths are enabled for the probe, which needs
//! its `longPathAware` manifest (embedded by `build.rs` on MSVC) and the machine's
//! `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\LongPathsEnabled` set to 1.

#[cfg(windows)]
#[path = "common/mod.rs"]
mod common;

#[cfg(windows)]
use common::test_groups::{drive_mapping, Group};

#[cfg(windows)]
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

#[cfg(windows)]
/// No route spawns from a cwd past `MAX_PATH`, even in a long-path-aware process with the policy
/// on: `CreateProcessW` refuses a NULL `lpCurrentDirectory` inherited from it as
/// `ERROR_INVALID_PARAMETER` (87), and the same directory passed explicitly as `ERROR_DIRECTORY`
/// (267). It fails before any child runs, so the child's own manifest changes nothing.
#[skuld::test]
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

#[cfg(windows)]
/// A relative name against a verbatim process cwd: cosca loads and runs where Win32 does, by
/// `raw_executable()` and by `executable()`'s search alike.
#[skuld::test]
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
        r"gfpn_rooted=\\t.exe",
        // Win32's floor on a verbatim drive cwd is after `\\?\`, not after the drive.
        r"gfpn_up_past_root=\\?\t.exe",
        "cosca_rooted_cwd=err(InvalidInput)",
        "std_rooted_cwd=err=267",
    ];
    assert_eq!(facts, expected, "full report:\n{report}");
}

#[cfg(windows)]
/// A drive-relative `current_dir` on another drive takes that drive's own directory, `=X:`, as
/// Win32 does: cosca's raw backend runs the child where `GetFullPathNameW` and std do, for every
/// shape of that variable. Only a fully qualified value naming an existing directory is used; any
/// other falls back to the drive's root, and `GetFullPathNameW` then rewrites `=X:` to it.
///
/// System-affecting: the probe maps a drive letter (`DefineDosDeviceW`) for the whole logon
/// session, so it is the `DRIVE_MAPPING` group (`src/test_groups.rs`).
#[skuld::test]
fn a_drive_relative_current_dir_takes_the_drives_own_directory_as_win32_does(#[fixture(drive_mapping)] _group: &Group) {
    let report = probe("drive-dir", env!("CARGO_BIN_EXE_cosca_testbin_image"));
    let facts: Vec<&str> = report.lines().collect();
    let mut expected = vec!["cwd_set=ok".to_owned()];
    for (label, cwd, after) in [
        ("unset", r"X:\sub", r"X:\"),
        ("exists", r"X:\exists\sub", r"X:\exists"),
        ("gone", r"X:\sub", r"X:\"),
        ("file", r"X:\sub", r"X:\"),
        ("drive_rel", r"X:\sub", r"X:\"),
        ("relative", r"X:\sub", r"X:\"),
        ("rooted", r"X:\sub", r"X:\"),
        ("other_drive", r"<d>\exists\sub", r"<d>\exists"),
    ] {
        expected.push(format!("cosca_{label}=ok,cwd={cwd}"));
        expected.push(format!("gfpn_{label}={cwd}"));
        expected.push(format!("after_{label}={after}"));
        expected.push(format!("std_{label}=ok,cwd={cwd}"));
    }
    assert_eq!(facts, expected, "full report:\n{report}");
}

#[cfg(windows)]
/// M7 (#156, untangling P1a), the rows whose `=X:` value names a directory on drive X itself, and
/// the partially qualified values whose target must exist: what a child's `GetFullPathNameW` makes
/// of `X:tool` given a block with that value and a cwd on another drive (for those values, of
/// `T:tool` with the child's cwd on X), against D1's prediction. `tests/common/drive_rule.rs` has
/// the runner, and `windows_path_resolution`'s `m7_` survey the rows that need no mapping.
///
/// Records only. Preconditions, asserted: the mapping serves its directories, the child runs in
/// the row's cwd and sees the row's `=X:` value.
///
/// System-affecting: it maps a drive letter (`DefineDosDeviceW`) for the whole logon session, and
/// removes it when done, so it is the `DRIVE_MAPPING` group.
#[skuld::test]
fn m7_a_drive_relative_name_against_a_drive_directory_on_its_own_drive(#[fixture(drive_mapping)] _group: &Group) {
    use common::drive_rule::{canonical, free_drive, run, Cwd, Render, Row, Var};
    use common::subst::Subst;

    let tmp = tempfile::tempdir().unwrap();
    let d = canonical(tmp.path());
    let m = format!(r"{d}\m");
    let long_rel = format!(r"long\{}\{}\{}", "a".repeat(100), "a".repeat(100), "a".repeat(60));
    for sub in [r"e", r"m\exists", r"m\vx", r"m\e\exists", &format!(r"m\{long_rel}")] {
        std::fs::create_dir_all(format!(r"{d}\{sub}")).expect("create the row directories");
    }
    std::fs::write(format!(r"{m}\afile"), b"x").expect("create the file");
    let letter = free_drive((b'M'..=b'Z').rev());
    let x = format!("{letter}:");
    let mut mapping = Subst::new(&x, std::path::Path::new(&m)).unwrap_or_else(|e| panic!("map {x} to {m}: {e}"));
    let long = format!(r"{x}\{long_rel}");
    assert!(
        long.encode_utf16().count() > 260,
        "precondition: {long} is longer than MAX_PATH"
    );
    for dir in [
        format!(r"{x}\exists"),
        format!(r"{x}\e\exists"),
        format!(r"\\?\{x}\vx"),
        long.clone(),
    ] {
        assert!(
            std::path::Path::new(&dir).is_dir(),
            "precondition: the mapping serves {dir}"
        );
    }
    let e = format!(r"{d}\e");
    let sr = format!("SystemRoot={}", std::env::var("SystemRoot").expect("SystemRoot"));
    let render = Render(vec![(d.clone(), "<d>".into()), (long_rel.clone(), "<long>".into())]);
    let row = |key, value: &str, name: &str, arm, predicted: String| Row {
        key,
        cwd: Cwd::Given(e.clone()),
        block: vec![sr.clone(), format!("={x}={value}")],
        name: name.to_owned(),
        arm,
        predicted,
        var: Var::Is(Some(value.to_owned())),
    };
    let tool = format!("{x}tool");
    let verbatim = format!(r"\\?\{x}\vx");
    let rows = [
        row(
            "existing",
            &format!(r"{x}\exists"),
            &tool,
            "Value",
            format!(r"{x}\exists\tool"),
        ),
        row("missing", &format!(r"{x}\gone"), &tool, "Root", format!(r"{x}\tool")),
        row("a_file", &format!(r"{x}\afile"), &tool, "Root", format!(r"{x}\tool")),
        row(
            "trailing_separator",
            &format!(r"{x}\exists\"),
            &tool,
            "Value",
            format!(r"{x}\exists\tool"),
        ),
        // The child (`cosca_testbin`) has no `longPathAware` manifest: this records its behaviour,
        // not ntdll's threshold, which M7b measures.
        row("longer_than_max_path", &long, &tool, "Value", format!(r"{long}\tool")),
        // A verbatim value: the plan expects the name it makes verbatim normalised. ntdll ignores
        // the value (observed_arm=Root), so these three rows block P4 and P5 under the plan's rule
        // (blocking if Win32 takes the value literally or ignores it).
        row(
            "verbatim_dotted_name",
            &verbatim,
            &format!(r"{x}sub.\tool.exe"),
            "Value",
            format!(r"{verbatim}\sub\tool.exe"),
        ),
        row(
            "verbatim_dotted_dir",
            &verbatim,
            &format!("{x}sub."),
            "Value",
            format!(r"{verbatim}\sub"),
        ),
        // `main`'s `append` stops `..` at the drive, giving the prediction. Win32's floor question
        // is unanswered, since ntdll ignores the value: the row blocks, like the two above.
        row(
            "verbatim_up_past_root",
            &verbatim,
            &format!(r"{x}..\..\t.exe"),
            "Value",
            format!(r"\\?\{x}\t.exe"),
        ),
    ];
    for row in &rows {
        run(row, &render, Some((letter, 'D')));
    }

    // A value that is not fully qualified must be refused even when it names an existing directory.
    // `exists` and `\exists` resolve against the child's own cwd, so it runs on X, and the name's
    // drive is T. The parent has asserted above that each target exists.
    let t = &d[..2];
    let cwd_x = format!(r"{x}\e");
    let partial = |key, value: String| Row {
        key,
        cwd: Cwd::Given(cwd_x.clone()),
        block: vec![sr.clone(), format!("={t}={value}")],
        name: format!("{t}tool"),
        arm: "Root",
        predicted: format!(r"{t}\tool"),
        var: Var::Is(Some(value)),
    };
    for row in [
        partial("drive_relative", format!("{x}exists")),
        partial("relative", "exists".to_owned()),
        partial("rooted", r"\exists".to_owned()),
    ] {
        run(&row, &render, Some((letter, 'D')));
    }

    mapping
        .remove()
        .unwrap_or_else(common::test_groups::fail_unless_panicking);
}

#[cfg(windows)]
/// A UNC `current_dir` runs the child there, plainly and verbatim; and against a verbatim UNC
/// process cwd, `GetFullPathNameW` completes a rooted name and a `..` run as measured here.
///
/// Precondition, asserted rather than skipped: the machine serves its administrative share
/// (`\\localhost\C$`) and this process's token may open it, which takes an administrator's
/// elevated token. CI runners have both.
#[skuld::test]
fn a_unc_current_dir_runs_there_and_a_verbatim_unc_cwd_completes_as_win32_does() {
    let report = probe("verbatim-unc", env!("CARGO_BIN_EXE_cosca_testbin_image"));
    let facts: Vec<&str> = report.lines().collect();
    let expected = [
        "cosca_unc_cwd=ok,cwd=<unc>",
        "std_unc_cwd=ok,cwd=<unc>",
        "cosca_vunc_cwd=ok,cwd=<vd>",
        // std runs a verbatim `current_dir` as its plain spelling; cosca passes it as written.
        "std_vunc_cwd=ok,cwd=<unc>",
        "set=ok",
        "cosca_rooted_cwd=err(InvalidInput)",
        "std_rooted_cwd=err=267",
        // Win32 completes a rooted name off the verbatim cwd's volume, and a `..` run past the
        // share rather than stopping at it: its floor is after `\\?\UNC\`. A written verbatim
        // `..` is collapsed the same way.
        r"gfpn_rooted=\\t.exe",
        r"gfpn_up_depth=<vshare>\t.exe",
        r"gfpn_up_depth_1=\\?\UNC\localhost\t.exe",
        r"gfpn_up_depth_2=\\?\UNC\t.exe",
        r"gfpn_written_up=<vparent>\t.exe",
        r"gfpn_written_past_share=\\?\UNC\localhost\t.exe",
    ];
    assert_eq!(facts, expected, "full report:\n{report}");
}

#[cfg(windows)]
mod drive_mapping_group {
    //! Re-execs this binary on one `DRIVE_MAPPING` test. Its body never runs here: each case is
    //! either opted out or refused at setup, so these are safe on any host.

    use crate::common::test_reexec::{command, suite_outcome, with_json_events, SuiteOutcome, NOCAPTURE};

    const DRIVE_TEST: &str = "a_drive_relative_current_dir_takes_the_drives_own_directory_as_win32_does";

    fn run_drive_test(
        extra: &[&str],
        group: Option<&str>,
        consent: Option<&str>,
        labels: Option<&str>,
    ) -> (SuiteOutcome, bool, String) {
        let mut cmd = command(std::env::current_exe().expect("current_exe"));
        cmd.args(["--test-threads=1", "--exact", DRIVE_TEST, NOCAPTURE]);
        cmd.args(extra);
        with_json_events(&mut cmd);
        for (var, value) in [
            ("COSCA_TEST_DRIVE_MAPPING", group),
            ("COSCA_TEST_DRIVE_MAPPING_CONSENT", consent),
            ("SKULD_LABELS", labels),
        ] {
            match value {
                Some(value) => cmd.env(var, value),
                None => cmd.env_remove(var),
            };
        }
        let out = crate::common::output_locked(&mut cmd).expect("re-exec this test binary");
        let outcome = suite_outcome(&out.stdout).expect("the child reports its suite");
        (
            outcome,
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    }

    /// The `failed` event of [`DRIVE_TEST`]: its message tells a setup refusal from a body failure.
    fn failure_message(stdout: &str) -> String {
        stdout
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|e| e["type"] == "test" && e["event"] == "failed" && e["name"] == DRIVE_TEST)
            .unwrap_or_else(|| panic!("no `failed` event for the test: {stdout}"))["stdout"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }

    /// Mutant: the group's `requires` never fails, so `=0` runs the test.
    #[skuld::test]
    fn drive_mapping_group_zero_reports_ignored() {
        let (outcome, success, stdout) = run_drive_test(&[], Some("0"), None, None);
        assert_eq!(
            outcome,
            SuiteOutcome {
                test_count: 1,
                passed: 0,
                failed: 0,
                ignored: 1
            },
            "{stdout}"
        );
        assert!(success, "{stdout}");
    }

    /// Mutant: the group's setup does not check consent (the body then maps a drive).
    #[skuld::test]
    fn drive_mapping_unset_consent_fails() {
        let (outcome, success, stdout) = run_drive_test(&[], None, None, None);
        assert_eq!((outcome.failed, outcome.passed, outcome.ignored), (1, 0, 0), "{stdout}");
        assert!(!success, "{stdout}");
        assert!(
            failure_message(&stdout).contains("COSCA_TEST_DRIVE_MAPPING_CONSENT=1"),
            "{stdout}"
        );
    }

    /// Mutant: any non-empty consent counts.
    #[skuld::test]
    fn drive_mapping_consent_other_than_1_fails() {
        let (outcome, success, stdout) = run_drive_test(&[], None, Some("yes"), None);
        assert_eq!((outcome.failed, outcome.passed, outcome.ignored), (1, 0, 0), "{stdout}");
        assert!(!success, "{stdout}");
        assert!(
            failure_message(&stdout).contains("COSCA_TEST_DRIVE_MAPPING_CONSENT=1"),
            "{stdout}"
        );
    }

    /// Mutant: the setup grants a group that is off, so `--ignored` runs the body.
    #[skuld::test]
    fn drive_mapping_group_zero_never_runs_the_body_under_run_ignored() {
        let (outcome, success, stdout) = run_drive_test(&["--ignored"], Some("0"), None, None);
        assert_eq!(
            (outcome.test_count, outcome.passed, outcome.failed, outcome.ignored),
            (1, 0, 1, 0),
            "{stdout}"
        );
        assert!(!success, "{stdout}");
        // Only the fixture's refusal carries this message; a body that ran cannot.
        assert!(
            failure_message(&stdout).contains("setup failed: COSCA_TEST_DRIVE_MAPPING=0"),
            "{stdout}"
        );
    }

    /// Mutant: the fixture carries no label, so `SKULD_LABELS=drive_mapping` selects none of its tests.
    #[skuld::test]
    fn the_drive_mapping_label_selects_its_test() {
        let (outcome, _, stdout) = run_drive_test(&[], Some("0"), None, Some("drive_mapping"));
        assert_eq!(outcome.test_count, 1, "{stdout}");
        let (outcome, _, stdout) = run_drive_test(&[], Some("0"), None, Some("!drive_mapping"));
        assert_eq!(outcome.test_count, 0, "{stdout}");
    }
}

#[path = "../src/test_harness.rs"]
mod test_harness;

fn main() {
    let mut runner = skuld::TestRunner::new();
    runner.libtest_names();
    runner.require_known_labels();
    runner.run()
}
