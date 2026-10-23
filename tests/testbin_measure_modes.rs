//! The testbin modes the single-backend measurements (`windows_path_resolution`'s `m*_` surveys)
//! are built from, each checked on a trivial input. The surveys only record, so a broken mode
//! would otherwise show up as a wrong measurement rather than a failure.

#[path = "common/mod.rs"]
mod common;

use std::process::Command;

/// Runs `cmd` and returns its stdout, failing the test on a non-zero exit.
fn stdout_of(cmd: &mut Command) -> String {
    let out = common::output_locked(cmd).expect("spawn cosca_testbin");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "{}: {stdout}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
}

/// Mutant: the mode is read from argv[1], so `echo-argv` runs and prints only `x`.
#[skuld::test]
fn the_mode_comes_from_cosca_testbin_mode_before_argv() {
    let out = stdout_of(
        Command::new(common::testbin())
            .env("COSCA_TESTBIN_MODE", "dump-argv")
            .args(["echo-argv", "x"]),
    );
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 4, "{out}");
    assert_eq!(lines[0], "argc=3", "{out}");
    assert!(lines[1].starts_with("arg0="), "{out}");
    assert_eq!(&lines[2..], ["arg1=echo-argv", "arg2=x"], "{out}");
}

#[cfg(windows)]
mod windows {
    use super::{common, stdout_of};
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::process::Command;

    /// `dump-env-block`'s lines (each UTF-16 unit as four hex digits), decoded.
    fn decode(hex_lines: &str) -> Vec<String> {
        hex_lines
            .lines()
            .map(|hex| {
                let units: Vec<u16> = (0..hex.len())
                    .step_by(4)
                    .map(|i| u16::from_str_radix(&hex[i..i + 4], 16).unwrap())
                    .collect();
                OsString::from_wide(&units).to_string_lossy().into_owned()
            })
            .collect()
    }

    fn system_root() -> String {
        format!("SystemRoot={}", std::env::var("SystemRoot").expect("SystemRoot"))
    }

    /// Mutant: the entries are passed through a std `Command`, which sorts and merges them, so
    /// `PATH` and `Path` collapse and `b` moves before `a`.
    #[skuld::test]
    fn with_env_block_gives_the_child_exactly_those_entries() {
        let entries = [
            "b=1".to_owned(),
            "a=2 with space".to_owned(),
            "Path=x".to_owned(),
            "PATH=y".to_owned(),
            system_root(),
        ];
        let out = stdout_of(
            Command::new(common::testbin())
                .arg("with-env-block")
                .args(&entries)
                .args(["--", "dump-env-block"]),
        );
        assert_eq!(decode(&out), entries);
    }

    /// Mutant: the probe dumps once, at the end, so the `before` section is missing.
    #[skuld::test]
    fn env_set_probe_dumps_the_block_before_and_after_each_op() {
        let out = stdout_of(
            Command::new(common::testbin())
                .arg("with-env-block")
                .args(["B=1".to_owned(), system_root()])
                .args(["--", "env-set-probe", "set:A=1", "remove:B"]),
        );
        let mut sections: Vec<(String, Vec<String>)> = Vec::new();
        let mut body = String::new();
        for line in out.lines() {
            if let Some(label) = line.strip_prefix("# ") {
                if let Some((_, lines)) = sections.last_mut() {
                    *lines = decode(&std::mem::take(&mut body));
                }
                sections.push((label.to_owned(), Vec::new()));
            } else {
                body.push_str(line);
                body.push('\n');
            }
        }
        if let Some((_, lines)) = sections.last_mut() {
            *lines = decode(&body);
        }
        // Where Windows places a new name is what M17 measures, so only the sets are compared.
        let sorted = |mut v: Vec<String>| {
            v.sort();
            v
        };
        let sr = system_root();
        let labels: Vec<&str> = sections.iter().map(|(label, _)| label.as_str()).collect();
        assert_eq!(labels, ["before", "after set:A=1", "after remove:B"], "{out}");
        assert_eq!(sections[0].1, ["B=1".to_owned(), sr.clone()], "{out}");
        assert_eq!(
            sorted(sections[1].1.clone()),
            sorted(vec!["A=1".to_owned(), "B=1".to_owned(), sr.clone()]),
            "{out}"
        );
        assert_eq!(
            sorted(sections[2].1.clone()),
            sorted(vec!["A=1".to_owned(), sr]),
            "{out}"
        );
    }

    /// Mutant: the child reports the parent's view, or never reads `STARTUPINFO`.
    #[skuld::test]
    fn report_handles_reports_the_startup_flags_and_a_probed_handle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let report = dir.path().join("report.txt");
        // Handle value 4 is not inherited by anything here: the probe must say so, not fail.
        stdout_of(
            Command::new(common::testbin())
                .arg("report-handles")
                .arg(&report)
                .arg("4"),
        );
        let text = std::fs::read_to_string(&report).expect("the report");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "usestdhandles=true", "{text}");
        assert!(lines[1].starts_with("stdin="), "{text}");
        assert_eq!(lines[2], "stdout=pipe", "{text}");
        assert_eq!(lines[3], "stderr=pipe", "{text}");
        assert!(lines[4].starts_with("probed="), "{text}");
        assert_eq!(lines.len(), 5, "{text}");
    }

    /// Mutant: the child reports only its cwd string, which cannot tell two directories reached
    /// through one drive letter apart.
    #[skuld::test]
    fn report_cwd_final_lists_what_the_cwd_holds() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("marker-x"), b"").unwrap();
        let out = stdout_of(
            Command::new(env!("CARGO_BIN_EXE_cosca_testbin_cwd"))
                .arg("report-cwd-final")
                .current_dir(dir.path()),
        );
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("cwd="), "{out}");
        assert_eq!(lines[1], "markers=marker-x", "{out}");
        assert_eq!(lines.len(), 2, "{out}");
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
