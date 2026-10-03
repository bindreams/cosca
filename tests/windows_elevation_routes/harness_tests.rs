//! The environment block a probe hands a child under another account or a lowered token.

use super::{env_block_from, helper_from_args, report_cmdline, Helper};
use std::ffi::OsString;
use std::path::Path;

/// The `KEY=value` entries of a NUL-separated, double-NUL-terminated UTF-16 block.
fn entries(block: &[u16]) -> Vec<String> {
    block
        .split(|&u| u == 0)
        .filter(|e| !e.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

fn inherited(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    pairs.iter().map(|&(k, v)| (k.into(), v.into())).collect()
}

/// A child under another account gets its report path and scratch `TEMP` only through `extra`.
/// Mutants: the `extra` loop is dropped (the entry never arrives); it runs before the inherited
/// loop (the caller's own `TEMP` wins). The key keeps the inherited spelling (`Temp`).
#[skuld::test]
fn extra_reaches_the_block_and_overrides_an_inherited_key() {
    let block = env_block_from(
        inherited(&[("PATH", "p"), ("Temp", r"C:\caller")]),
        &[
            ("TEMP", r"C:\scratch".to_owned()),
            ("COSCA_PROBE_REPORT_TO", r"C:\scratch\r.txt".to_owned()),
        ],
    );
    assert_eq!(
        entries(&block),
        [r"COSCA_PROBE_REPORT_TO=C:\scratch\r.txt", "PATH=p", r"Temp=C:\scratch"]
    );
}

/// The child is a helper that never runs skuld, so it has no use for the parent's coordination directory.
#[skuld::test]
fn an_inherited_skuld_db_dir_is_not_forwarded() {
    let block = env_block_from(inherited(&[("PATH", "p"), ("SKULD_DB_DIR", r"C:\parent")]), &[]);
    let entries = entries(&block);
    assert!(entries.iter().all(|e| !e.starts_with("SKULD_DB_DIR=")), "{entries:?}");
}

/// The helper checks no group, so no `COSCA_TEST_*` variable crosses to a child under another account.
#[skuld::test]
fn no_test_group_variable_is_forwarded() {
    let block = env_block_from(
        inherited(&[
            ("PATH", "p"),
            ("COSCA_TEST_ELEVATION_ROUTES", "1"),
            ("COSCA_TEST_ELEVATION_ROUTES_CONSENT", "1"),
        ]),
        &[],
    );
    assert_eq!(entries(&block), ["PATH=p"]);
}

fn args(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

/// Mutant: the helper flag is ignored, so a re-exec'd child runs the whole suite.
#[skuld::test]
fn the_measure_token_flag_selects_its_helper() {
    assert_eq!(
        helper_from_args(args(&["--cosca-probe-helper", "measure-token"])),
        Ok(Some(Helper::MeasureToken))
    );
}

/// Mutant: any first argument selects a helper, so a skuld argument such as `--list` is swallowed.
#[skuld::test]
fn arguments_that_are_not_the_helper_flag_run_the_tests() {
    assert_eq!(helper_from_args(args(&[])), Ok(None));
    assert_eq!(helper_from_args(args(&["--list", "--format", "terse"])), Ok(None));
    assert_eq!(helper_from_args(args(&["measure-token"])), Ok(None));
}

/// Mutant: an unknown helper falls through to the tests, which then run inside the child.
#[skuld::test]
fn a_helper_flag_without_a_known_helper_is_an_error() {
    assert!(helper_from_args(args(&["--cosca-probe-helper"])).is_err());
    assert!(helper_from_args(args(&["--cosca-probe-helper", "nope"])).is_err());
}

/// The child's command line is the helper's, not a test selection: it runs before skuld starts.
#[skuld::test]
fn the_report_command_line_names_the_helper() {
    assert_eq!(
        report_cmdline(Path::new(r"C:\t\probe.exe")),
        r#""C:\t\probe.exe" --cosca-probe-helper measure-token"#
    );
}
