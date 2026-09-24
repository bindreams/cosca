// Pure-parser tests for cgroup v2 path detection and cgroup.events.
// These run on any host (including Windows) with synthetic inputs — no filesystem access.

use crate::containment::cgroup::{parse_populated, parse_proc_stat_state, parse_v2_relative_path};

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

// parse_populated tests =====

/// The real kernel format: `populated 0\nfrozen 0\n`.
#[test]
fn populated_zero_means_drained() {
    assert_eq!(parse_populated("populated 0\nfrozen 0\n"), Some(false));
}

/// `populated 1` means at least one process remains.
#[test]
fn populated_one_means_members_remain() {
    assert_eq!(parse_populated("populated 1\nfrozen 0\n"), Some(true));
}

/// Field order is not guaranteed by the kernel doc — `populated` may not be first.
#[test]
fn populated_field_not_first_line() {
    assert_eq!(parse_populated("frozen 0\npopulated 1\n"), Some(true));
}

/// No `populated` line at all (wrong file / malformed) — must not silently default.
#[test]
fn populated_missing_returns_none() {
    assert_eq!(parse_populated("frozen 0\n"), None);
}

/// Empty file — must not silently default.
#[test]
fn populated_empty_returns_none() {
    assert_eq!(parse_populated(""), None);
}

/// An unrecognized value after `populated ` — must not silently default to either state.
#[test]
fn populated_garbage_value_returns_none() {
    assert_eq!(parse_populated("populated 2\n"), None);
}

/// No trailing newline on the last line — must still parse.
#[test]
fn populated_no_trailing_newline() {
    assert_eq!(parse_populated("frozen 0\npopulated 0"), Some(false));
}

// parse_proc_stat_state tests -----

/// The ordinary case: a zombie child, the state that explains "placed, then left the set".
#[test]
fn proc_stat_state_reads_zombie() {
    assert_eq!(
        parse_proc_stat_state("42 (cosca_testbin) Z 1 42 42 0 -1 4194560\n"),
        Some('Z')
    );
}

/// `comm` is arbitrary bytes inside parentheses: a name containing spaces AND parentheses
/// must not shift the field index, so the scan starts after the LAST `)`.
#[test]
fn proc_stat_state_survives_a_hostile_comm() {
    assert_eq!(parse_proc_stat_state("42 (weird ) name (x) R 1 42\n"), Some('R'));
}

/// Truncated or malformed input yields no state rather than a guessed one.
#[test]
fn proc_stat_state_malformed_is_none() {
    assert_eq!(parse_proc_stat_state(""), None);
    assert_eq!(parse_proc_stat_state("42 (noparen"), None);
    assert_eq!(parse_proc_stat_state("42 (comm)"), None);
}

/// A child is in a leaf when its cgroup is the leaf's own path or nested under it — not when some
/// other cgroup merely shares the leaf's name or a prefix of it.
#[test]
fn a_cgroup_path_is_inside_a_leaf_only_at_or_under_its_own_path() {
    let leaf = "/slice/cosca-7-0";
    for (path, inside) in [
        ("/slice/cosca-7-0", true),
        ("/slice/cosca-7-0/nested", true),
        ("/slice/cosca-7-0/nested/deeper", true),
        ("/other/cosca-7-0", false),
        ("/slice/cosca-7-0-sibling", false),
        ("/slice/cosca-7-01", false),
        ("/slice", false),
        ("/", false),
    ] {
        assert_eq!(
            crate::containment::cgroup::is_at_or_under(path, leaf),
            inside,
            "{path} in {leaf}"
        );
    }
    assert!(
        crate::containment::cgroup::is_at_or_under("/cosca-7-0/x", "/cosca-7-0"),
        "a leaf under the root cgroup"
    );
}
