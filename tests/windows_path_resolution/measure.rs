//! What the single-backend measurements (the `m<n>_` surveys) share: running a probe and printing
//! its report as `M<n> <key>=<value>` lines, the form the results are read from.

use std::process::Command;

/// Runs `cmd` to completion and returns its stdout. A probe that fails has measured nothing, so
/// that fails the test, with its stderr.
pub(crate) fn probe(cmd: &mut Command) -> String {
    let out = crate::common::output_locked(cmd).expect("spawn the probe");
    let report = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "the probe failed ({}): {report}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    report
}

/// Prints each line of `report` as `<id> <line>`.
pub(crate) fn record(id: &str, report: &str) {
    for line in report.lines() {
        println!("{id} {line}");
    }
}

/// The value of the first `key=` line of `report`; a missing key fails the test.
pub(crate) fn value<'a>(report: &'a str, key: &str) -> &'a str {
    let prefix = format!("{key}=");
    report
        .lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("the report has no {key}= line:\n{report}"))
}

/// A path without its `\\?\`, as `canonicalize` spells it otherwise, so every report renders it alike.
pub(crate) fn canonical(path: &std::path::Path) -> std::path::PathBuf {
    let full = std::fs::canonicalize(path).expect("canonicalize");
    let full = full.to_str().expect("a UTF-8 path");
    std::path::PathBuf::from(full.strip_prefix(r"\\?\").expect("a verbatim canonical path"))
}
