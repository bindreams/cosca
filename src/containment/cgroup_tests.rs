// Pure-parser tests for cgroup v2 path detection and cgroup.procs membership.
// These run on any host (including Windows) with synthetic inputs — no filesystem access.

use super::{cgroup_procs_contains, parse_populated, parse_v2_relative_path};

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

// removed_after_drain tests -----
// Linux-only: the function itself is `#[cfg(target_os = "linux")]` (it interprets raw kernel
// errno values that only mean anything against a real cgroupfs).

/// `ENODEV` — a syscall through an fd opened before the leaf was removed, once the kernel
/// deactivates the underlying kernfs node — is proof of drain.
#[cfg(target_os = "linux")]
#[test]
fn enodev_is_removed_after_drain() {
    let e = std::io::Error::from_raw_os_error(libc::ENODEV);
    assert!(super::removed_after_drain(&e));
}

/// `ENOENT` — a fresh `open` through the now-unlinked leaf directory — is proof of drain too.
#[cfg(target_os = "linux")]
#[test]
fn enoent_is_removed_after_drain() {
    let e = std::io::Error::from_raw_os_error(libc::ENOENT);
    assert!(super::removed_after_drain(&e));
}

/// Every other errno is a genuine failure, not proof of anything — must NOT be folded into a
/// guessed drain verdict. `EACCES` (permission denied) and `EIO` (real device/backing-store
/// failure) are both plausible `cgroup.events` failures unrelated to removal.
#[cfg(target_os = "linux")]
#[test]
fn unrelated_errnos_are_not_removed_after_drain() {
    for errno in [libc::EACCES, libc::EIO, libc::EBUSY, libc::EPERM] {
        let e = std::io::Error::from_raw_os_error(errno);
        assert!(
            !super::removed_after_drain(&e),
            "errno {errno} must not be classified as proof of drain"
        );
    }
}

// CgroupLeaf::wait_drained real-mechanism test -----
// Linux + cgroup-v2 only, and only when CI provisions a delegated leaf (COSCA_TEST_CGROUP=1) —
// the same gating convention `tests/spawn_io.rs`'s `linux_cgroup_v2_*` tests already use: a true
// no-op without the marker, but a loud panic (never a silent pass) if the marker is set and no
// usable delegated cgroup v2 leaf actually exists.

/// Two real, simultaneously live processes placed directly in the same leaf via the crate's own
/// `place_self_in_cgroup_pre_exec` — not a synthetic membership list — exercising `wait_drained`'s
/// full mechanism: the read-before-arm check, the `poll(2)` block-then-timeout path (a bounded
/// deadline, not `Duration::ZERO`, so the call actually reaches `poll`), and the real kernel
/// `populated` 1→0 transition once both members are gone.
#[cfg(target_os = "linux")]
#[test]
fn cgroup_wait_drained_tracks_two_real_members_through_exit() {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use crate::containment::TreeDrain;

    if std::env::var_os("COSCA_TEST_CGROUP").is_none() {
        // Unprovisioned: not a CI-cgroup environment — true no-op, never a false "ok".
        return;
    }
    let leaf = super::try_create_leaf().expect(
        "COSCA_TEST_CGROUP is set but no usable delegated cgroup v2 leaf could be created — is \
         this process running inside a writable, delegated cgroup v2 slice with cgroup.kill \
         support (kernel >= 5.14)?",
    );

    let spawn_member = |leaf: &super::CgroupLeaf| -> std::process::Child {
        let procs_fd = leaf.procs_fd();
        let mut cmd = Command::new("sleep");
        cmd.arg("30").stdout(Stdio::null()).stderr(Stdio::null());
        // SAFETY: `Command::pre_exec` runs this closure only between `fork` and `exec` in the
        // child; `procs_fd` is a valid, open, writable fd owned by `leaf` for the parent's whole
        // lifetime (fork gives the child its own fd-table entry pointing at the same underlying
        // open file description, and `place_self_in_cgroup_pre_exec` closes only that child-side
        // copy) — exactly its own documented contract. `leaf` outlives every member spawned
        // through it in this test.
        unsafe {
            cmd.pre_exec(move || super::place_self_in_cgroup_pre_exec(procs_fd));
        }
        cmd.spawn().expect("spawn a real long-lived cgroup leaf member")
    };

    let mut a = spawn_member(&leaf);
    let mut b = spawn_member(&leaf);

    // A real bounded wait with both members alive: must report MembersRemain. The 250ms bound
    // is not a synchronization guess — it is the deadline `wait_drained` itself blocks on via a
    // real `poll(2)` call (never expiring early, since neither member exits during it), so this
    // doubles as the settling time for the two `pre_exec` writes above before the membership
    // checks below.
    let bounded = || Some(Some(Instant::now() + Duration::from_millis(250)));
    assert_eq!(
        leaf.wait_drained(bounded())
            .expect("wait_drained with two live members"),
        TreeDrain::MembersRemain,
        "both members are alive; must report MembersRemain"
    );
    assert!(
        leaf.contains_pid(a.id()),
        "member a must actually be placed in the leaf"
    );
    assert!(
        leaf.contains_pid(b.id()),
        "member b must actually be placed in the leaf"
    );

    // One survivor: `populated` never flips (still nonzero), so the verdict must not change.
    a.kill().expect("kill member a");
    a.wait().expect("reap member a");
    assert_eq!(
        leaf.wait_drained(bounded()).expect("wait_drained with one live member"),
        TreeDrain::MembersRemain,
        "one member is still alive; must still report MembersRemain"
    );

    // Both gone: an UNBOUNDED wait_drained blocks on the real kernel `populated` 1→0 edge, not a
    // chosen interval — the "external event that might never happen" case the crate's no-sleep-
    // sync rule allows a real wait for. A bug here hangs the test, surfaced by the CI job's own
    // timeout, not a duration this test invented.
    b.kill().expect("kill member b");
    b.wait().expect("reap member b");
    assert_eq!(
        leaf.wait_drained(None).expect("wait_drained once both are gone"),
        TreeDrain::AllMembersExited,
        "both members exited; must report AllMembersExited"
    );
}
