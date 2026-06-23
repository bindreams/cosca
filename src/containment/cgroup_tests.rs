// Pure-parser tests for cgroup v2 path detection and cgroup.procs membership.
// These run on any host (including Windows) with synthetic inputs — no filesystem access.

use super::{cgroup_procs_contains, parse_v2_relative_path};

// parse_v2_relative_path tests =====

/// The canonical v2-only format: a single `0::` line.
#[test]
fn v2_only_single_line() {
    let input = "0::/user.slice/user-1000.slice/session-3.scope\n";
    assert_eq!(
        parse_v2_relative_path(input),
        Some("/user.slice/user-1000.slice/session-3.scope")
    );
}

/// Hybrid cgroup (v1 controllers + v2 unified): the `0::` line is present but
/// so are named v1 controllers. The v2 unified path is still the `0::` line.
#[test]
fn v2_hybrid_with_v1_controllers() {
    let input = concat!(
        "12:freezer:/\n",
        "11:memory:/user.slice\n",
        "1:name=systemd:/user.slice/user-1000.slice\n",
        "0::/user.slice/user-1000.slice/user@1000.service/app.slice\n",
    );
    assert_eq!(
        parse_v2_relative_path(input),
        Some("/user.slice/user-1000.slice/user@1000.service/app.slice")
    );
}

/// v2 `0::` line with path `"/"` (root cgroup) — returns the root path.
#[test]
fn v2_root_cgroup_path() {
    let input = "0::/\n";
    assert_eq!(parse_v2_relative_path(input), Some("/"));
}

/// v1-only system: no `0::` line. Must return None.
#[test]
fn v1_only_no_unified_line() {
    let input = concat!(
        "10:cpuset:/\n",
        "9:cpu,cpuacct:/user.slice\n",
        "8:memory:/user.slice/user-1000.slice\n",
    );
    assert_eq!(parse_v2_relative_path(input), None);
}

/// Empty input (no cgroup file or empty): returns None.
#[test]
fn empty_input_returns_none() {
    assert_eq!(parse_v2_relative_path(""), None);
}

/// A line starting with `0:` but NOT `0::` (e.g. a v1 controller named "0") must not match.
#[test]
fn line_with_single_colon_does_not_match() {
    let input = "0:somectrl:/path\n";
    assert_eq!(parse_v2_relative_path(input), None);
}

/// The `0::` line can appear anywhere in the file, not just first.
#[test]
fn v2_line_not_first() {
    let input = concat!(
        "1:name=systemd:/user.slice\n",
        "0::/user.slice/user-1000.slice\n",
        "2:cpuset:/\n",
    );
    assert_eq!(parse_v2_relative_path(input), Some("/user.slice/user-1000.slice"));
}

/// No trailing newline on the `0::` line — still parses.
#[test]
fn v2_no_trailing_newline() {
    let input = "0::/user.slice/user-1000.slice";
    assert_eq!(parse_v2_relative_path(input), Some("/user.slice/user-1000.slice"));
}

// cgroup_procs_contains tests -----

/// Empty file contents — pid is absent.
#[test]
fn procs_empty_file() {
    assert!(!cgroup_procs_contains("", 1234));
}

/// Single pid that matches.
#[test]
fn procs_single_match() {
    assert!(cgroup_procs_contains("1234\n", 1234));
}

/// Single pid that does not match.
#[test]
fn procs_single_no_match() {
    assert!(!cgroup_procs_contains("5678\n", 1234));
}

/// Multiple pids; target is present.
#[test]
fn procs_multiple_present() {
    let contents = "100\n200\n1234\n300\n";
    assert!(cgroup_procs_contains(contents, 1234));
}

/// Multiple pids; target is absent.
#[test]
fn procs_multiple_absent() {
    let contents = "100\n200\n300\n";
    assert!(!cgroup_procs_contains(contents, 1234));
}

/// Trailing newline at end of file — should not cause a false negative.
#[test]
fn procs_trailing_newline() {
    assert!(cgroup_procs_contains("42\n", 42));
}

/// Whitespace around the pid (e.g. spaces) is trimmed.
#[test]
fn procs_whitespace_trimmed() {
    assert!(cgroup_procs_contains("  99  \n", 99));
}
