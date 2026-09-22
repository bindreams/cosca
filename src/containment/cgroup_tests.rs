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
    let leaf = super::try_create_leaf().unwrap_or_else(|e| {
        panic!(
            "COSCA_TEST_CGROUP is set but no usable delegated cgroup v2 leaf could be created \
             ({e}) — is this process running inside a writable, delegated cgroup v2 slice with \
             cgroup.kill support (kernel >= 5.14)?"
        )
    });

    let spawn_member = |leaf: &super::CgroupLeaf| -> std::process::Child {
        let procs_fd = leaf.procs_fd();
        let slot = leaf.placement_slot();
        let mut cmd = Command::new("sleep");
        cmd.arg("30").stdout(Stdio::null()).stderr(Stdio::null());
        // SAFETY: `Command::pre_exec` runs this closure only between `fork` and `exec` in the
        // child; `procs_fd` is a valid, open, writable fd owned by `leaf` for the parent's whole
        // lifetime (fork gives the child its own fd-table entry pointing at the same underlying
        // open file description, and `place_self_in_cgroup_pre_exec` closes only that child-side
        // copy) — exactly its own documented contract. `leaf` outlives every member spawned
        // through it in this test.
        unsafe {
            cmd.pre_exec(move || super::place_self_in_cgroup_pre_exec(procs_fd, slot));
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
    for (name, member) in [("a", &a), ("b", &b)] {
        let placement = leaf.placement_of(member.id());
        assert!(
            matches!(placement, super::Placement::Confirmed),
            "member {name} must actually be placed in the leaf: {placement}"
        );
    }

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

// Degrade-reason reporting =====
// The diagnostic types are pure data, so their formatting is tested on every host.

use std::path::PathBuf;

use super::{log_degrade, parse_proc_stat_state, LeafError, Placement, PlacementReport};

/// Every `LeafError` names the step, the path it touched, and the kernel's own reason.
/// Asserted per variant: a step whose message drops any of the three is the silence this
/// type exists to remove.
#[test]
fn leaf_error_names_step_path_and_reason() {
    let cases: Vec<(LeafError, &[&str])> = vec![
        (
            LeafError::ReadProcSelfCgroup(std::io::Error::from_raw_os_error(13)),
            &["/proc/self/cgroup", "denied"],
        ),
        (
            LeafError::NoUnifiedLine("9:memory:/foo\n".into()),
            &["/proc/self/cgroup", "0::", "9:memory:/foo"],
        ),
        (
            LeafError::CreateLeafDir {
                path: PathBuf::from("/sys/fs/cgroup/slice/cosca-7-0"),
                source: std::io::Error::from_raw_os_error(13),
            },
            &["/sys/fs/cgroup/slice/cosca-7-0", "denied"],
        ),
        (
            LeafError::KillUnsupported {
                path: PathBuf::from("/sys/fs/cgroup/slice/cosca-7-0"),
            },
            &["/sys/fs/cgroup/slice/cosca-7-0", "cgroup.kill"],
        ),
        (
            LeafError::OpenProcs {
                path: PathBuf::from("/sys/fs/cgroup/slice/cosca-7-0/cgroup.procs"),
                source: std::io::Error::from_raw_os_error(13),
            },
            &["cgroup.procs", "denied"],
        ),
        (
            LeafError::ReadCloexec {
                path: PathBuf::from("/sys/fs/cgroup/slice/cosca-7-0/cgroup.procs"),
                source: std::io::Error::from_raw_os_error(9),
            },
            &["cgroup.procs", "FD_CLOEXEC"],
        ),
        (
            LeafError::ClearCloexec {
                path: PathBuf::from("/sys/fs/cgroup/slice/cosca-7-0/cgroup.procs"),
                source: std::io::Error::from_raw_os_error(9),
            },
            &["cgroup.procs", "FD_CLOEXEC"],
        ),
        (
            LeafError::MapReportPage(std::io::Error::from_raw_os_error(12)),
            &["report", "memory"],
        ),
    ];
    for (err, needles) in cases {
        let rendered = err.to_string();
        for needle in needles {
            assert!(
                rendered.contains(needle),
                "{err:?} renders as {rendered:?}, which does not mention {needle:?}"
            );
        }
    }
}

/// The child's own self-placement outcome is reported verbatim, errno included — the one
/// step whose reason lives in the forked child and is otherwise unobservable to the parent.
#[test]
fn placement_report_renders_the_childs_errno() {
    assert!(PlacementReport::WriteFailed(16).to_string().contains("errno 16"));
    assert!(PlacementReport::WriteFailed(16).to_string().contains("busy"));
    assert!(PlacementReport::Placed.to_string().contains("succeeded"));
    assert!(PlacementReport::NotReported.to_string().contains("did not run"));
}

/// An absent child renders the pid, the leaf path, the file's actual contents and the child's
/// own state — the four facts that separate "the write failed" from "the child already exited".
#[test]
fn placement_absent_renders_every_observed_fact() {
    let absent = Placement::Absent {
        pid: 4242,
        path: PathBuf::from("/sys/fs/cgroup/slice/cosca-7-0/cgroup.procs"),
        procs: String::new(),
        report: PlacementReport::Placed,
        child_state: Some('Z'),
    };
    let rendered = absent.to_string();
    for needle in ["4242", "cosca-7-0/cgroup.procs", "empty", "succeeded", "zombie"] {
        assert!(
            rendered.contains(needle),
            "absent placement renders as {rendered:?}, which does not mention {needle:?}"
        );
    }
}

/// A live child that is nonetheless not a member is a different diagnosis from a zombie one,
/// and must not be described as having exited.
#[test]
fn placement_absent_distinguishes_a_live_child() {
    let rendered = Placement::Absent {
        pid: 4242,
        path: PathBuf::from("/cg/cgroup.procs"),
        procs: "99\n".into(),
        report: PlacementReport::WriteFailed(16),
        child_state: Some('S'),
    }
    .to_string();
    assert!(rendered.contains("99"), "the file's real contents must be quoted");
    assert!(rendered.contains("errno 16"), "the child's errno must be carried");
    assert!(!rendered.contains("zombie"), "a live child must not be called a zombie");
}

/// An unreadable `cgroup.procs` is its own diagnosis, never folded into "not a member".
#[test]
fn placement_unreadable_names_the_io_error() {
    let rendered = Placement::Unreadable {
        pid: 4242,
        path: PathBuf::from("/cg/cgroup.procs"),
        source: std::io::Error::from_raw_os_error(13),
        report: PlacementReport::Placed,
    }
    .to_string();
    assert!(rendered.contains("/cg/cgroup.procs"));
    assert!(rendered.contains("denied"));
}

/// The degrade is logged at `warn` with the reason attached — the single line a human reading
/// CI output needs to tell WHICH step failed from the bare fact that containment degraded.
#[test]
fn degrade_logs_the_reason_at_warn() {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    log_degrade(&LeafError::KillUnsupported {
        path: PathBuf::from("/sys/fs/cgroup/slice/cosca-degrade-probe-a41f"),
    });
    assert!(
        crate::log_capture::contains_since(mark, "cosca-degrade-probe-a41f"),
        "the degrade log must carry the failing step's own path"
    );
    assert!(
        crate::log_capture::contains_since(mark, "process group"),
        "the degrade log must say what containment degraded TO"
    );
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

// Linux failure-path tests -----
// Real filesystem, no cgroup v2 required: `create_leaf_under` is parameterised by the
// directory it creates the leaf in, so every precondition it checks can be failed for real
// against a temp directory on any Linux host.

/// A `mkdir` the kernel refuses reports the `mkdir` step, its path and its errno — not a
/// bare "cgroups unavailable".
///
/// The refusal is a parent directory that does not exist (`ENOENT`), not one whose mode
/// forbids writing: CI's cgroup lane runs as root, and root ignores directory permissions, so
/// a mode-based refusal would be a no-op there and this test would assert nothing. `ENOENT`
/// is uid-independent, and the step maps every errno the same way — it carries the kernel's
/// reason rather than classifying it.
#[cfg(target_os = "linux")]
#[test]
fn create_leaf_under_reports_a_refused_mkdir() {
    let dir = tempfile::tempdir().expect("tempdir");
    let parent = dir.path().join("no-such-slice");

    let err = match super::create_leaf_under(&parent) {
        Err(e) => e,
        Ok(_) => panic!("creating a leaf under a nonexistent directory must fail"),
    };
    assert!(
        matches!(err, LeafError::CreateLeafDir { .. }),
        "expected CreateLeafDir, got {err:?}"
    );
    let rendered = err.to_string();
    assert!(rendered.contains("no-such-slice"), "path missing from {rendered:?}");
    assert!(
        rendered.contains("No such file or directory"),
        "errno missing from {rendered:?}"
    );
}

/// A writable directory with no `cgroup.kill` in the created leaf (i.e. not a cgroupfs, or a
/// kernel older than 5.14) reports THAT, and leaves no stray directory behind.
#[cfg(target_os = "linux")]
#[test]
fn create_leaf_under_reports_a_missing_cgroup_kill() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = match super::create_leaf_under(dir.path()) {
        Err(e) => e,
        Ok(_) => panic!("a plain directory has no cgroup.kill; leaf creation must fail"),
    };
    assert!(
        matches!(err, LeafError::KillUnsupported { .. }),
        "expected KillUnsupported, got {err:?}"
    );
    assert!(err.to_string().contains("cgroup.kill"), "got {err}");
    let strays: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read tempdir")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert!(strays.is_empty(), "a failed leaf creation left {strays:?} behind");
}

/// The child's self-placement errno crosses `fork` into the parent. Deterministic and
/// cgroup-free: fd -1 is never writable, so the child's `write` always fails with `EBADF`,
/// and the parent must read back that exact errno rather than a guess.
#[cfg(target_os = "linux")]
#[test]
fn placement_report_crosses_fork_with_the_childs_errno() {
    use std::os::unix::process::CommandExt;

    let page = super::ReportPage::new().expect("map the report page");
    assert_eq!(
        page.read(),
        PlacementReport::NotReported,
        "a fresh page must report nothing, not a fabricated success"
    );

    let slot = page.slot();
    let mut cmd = std::process::Command::new("/bin/true");
    // SAFETY: the closure runs between fork and exec; it performs only the documented
    // async-signal-safe operations (write, close, one atomic store into a shared page).
    unsafe {
        cmd.pre_exec(move || {
            let _ = super::place_self_in_cgroup_pre_exec(-1, slot);
            Ok(())
        });
    }
    let status = cmd.spawn().expect("spawn").wait().expect("wait");
    assert!(status.success(), "the failed placement must not abort the spawn");
    assert_eq!(
        page.read(),
        PlacementReport::WriteFailed(libc::EBADF),
        "the child's own errno must reach the parent verbatim"
    );
}

/// A successful self-placement is reported too — the fact that separates "the write failed"
/// from "the write worked and the child then left the set".
#[cfg(target_os = "linux")]
#[test]
fn placement_report_records_a_successful_write() {
    use std::os::unix::process::CommandExt;

    let page = super::ReportPage::new().expect("map the report page");
    let slot = page.slot();
    // /dev/null accepts any write, standing in for a writable cgroup.procs.
    let sink = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .expect("open /dev/null");
    let fd = std::os::fd::IntoRawFd::into_raw_fd(sink);
    let mut cmd = std::process::Command::new("/bin/true");
    // SAFETY: as above; `fd` is a valid writable descriptor inherited by the fork, and the
    // closure closes only the child's copy.
    unsafe {
        cmd.pre_exec(move || {
            let _ = super::place_self_in_cgroup_pre_exec(fd, slot);
            Ok(())
        });
    }
    cmd.spawn().expect("spawn").wait().expect("wait");
    assert_eq!(page.read(), PlacementReport::Placed);
    // SAFETY: the parent's own copy of the descriptor, closed exactly once.
    unsafe { libc::close(fd) };
}
