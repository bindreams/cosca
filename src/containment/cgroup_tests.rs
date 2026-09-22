// Pure-parser tests for cgroup v2 path detection and cgroup.events.
// These run on any host (including Windows) with synthetic inputs — no filesystem access.

use super::{parse_populated, parse_v2_relative_path};

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

    // Each member reports through its OWN page. The leaf's slot is one word for the whole leaf
    // (see `ReportPage`), so two members sharing it would overwrite each other and this test
    // would be asserting the second member's outcome twice.
    let spawn_member = |leaf: &super::CgroupLeaf, page: &super::ReportPage| -> std::process::Child {
        let procs_fd = leaf.procs_fd();
        let slot = page.slot();
        let mut cmd = Command::new("sleep");
        cmd.arg("30").stdout(Stdio::null()).stderr(Stdio::null());
        // SAFETY: `Command::pre_exec` runs this closure only between `fork` and `exec` in the
        // child; `procs_fd` is a valid, open, writable fd owned by `leaf` for the parent's whole
        // lifetime (fork gives the child its own fd-table entry pointing at the same underlying
        // open file description, and `place_self_in_cgroup_pre_exec` closes only that child-side
        // copy) — exactly its own documented contract. `leaf` and `page` both outlive every
        // member spawned through them in this test.
        unsafe {
            cmd.pre_exec(move || super::place_self_in_cgroup_pre_exec(procs_fd, slot));
        }
        cmd.spawn().expect("spawn a real long-lived cgroup leaf member")
    };

    let page_a = super::ReportPage::new().expect("map member a's report page");
    let page_b = super::ReportPage::new().expect("map member b's report page");
    let mut a = spawn_member(&leaf, &page_a);
    let mut b = spawn_member(&leaf, &page_b);

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
    let procs = std::fs::read_to_string(leaf.leaf_path.join("cgroup.procs")).expect("read cgroup.procs");
    for (name, member, page) in [("a", &a, &page_a), ("b", &b, &page_b)] {
        assert!(
            procs.lines().any(|line| line.trim() == member.id().to_string()),
            "member {name} must actually be placed in the leaf; cgroup.procs is {procs:?}"
        );
        assert_eq!(
            page.read(),
            PlacementReport::Placed,
            "member {name}'s own report must survive the other member's spawn"
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

/// The parent's `cgroup.procs` fd stays close-on-exec for the leaf's whole life. The child's
/// `pre_exec` write needs it only between `fork` and `exec`, where a CLOEXEC fd is still open;
/// any other program this process starts meanwhile must not inherit a writable `cgroup.procs`,
/// through which it could move itself into the leaf and be killed with it.
#[cfg(target_os = "linux")]
#[test]
fn cgroup_leaf_procs_fd_is_not_inherited_across_exec() {
    if std::env::var_os("COSCA_TEST_CGROUP").is_none() {
        return; // unprovisioned: not a CI-cgroup environment.
    }
    let leaf = super::try_create_leaf().unwrap_or_else(|e| {
        panic!("COSCA_TEST_CGROUP is set but no usable delegated cgroup v2 leaf could be created ({e})")
    });
    // SAFETY: `procs_fd` is open for as long as `leaf` lives.
    let flags = unsafe { libc::fcntl(leaf.procs_fd(), libc::F_GETFD) };
    assert_ne!(flags, -1, "F_GETFD: {}", std::io::Error::last_os_error());
    assert_ne!(
        flags & libc::FD_CLOEXEC,
        0,
        "the parent-held cgroup.procs fd must be CLOEXEC"
    );

    // An unrelated program started while the leaf is alive lists its own open descriptors.
    let out = std::process::Command::new("/bin/sh")
        .args(["-c", "ls -l /proc/$$/fd"])
        .output()
        .expect("run sh");
    assert!(out.status.success(), "ls failed: {out:?}");
    let fds = String::from_utf8_lossy(&out.stdout);
    let procs = leaf.leaf_path.join("cgroup.procs");
    assert!(
        !fds.contains(&*procs.to_string_lossy()),
        "an unrelated program inherited {}:\n{fds}",
        procs.display()
    );
}

// Degrade-reason reporting =====
// The diagnostic types are pure data, so their formatting is tested on every host.

use std::path::PathBuf;

use super::{log_degrade, parse_proc_stat_state, LeafError, NotEntered, NotPlaced, PlacementReport};

/// Every `LeafError` names the step, the path it touched, and the kernel's own reason.
/// Asserted per variant: a step whose message drops any of the three is the silence this
/// type exists to remove.
///
/// The reason is asserted as the source error's own rendering, not as `strerror` text: the same
/// raw code renders differently per host (13 is "Permission denied" on Linux and macOS, "The data
/// is invalid." on Windows), and "carried verbatim" is the claim.
#[test]
fn leaf_error_names_step_path_and_reason() {
    let reason = |code: i32| std::io::Error::from_raw_os_error(code).to_string();
    let cases: Vec<(LeafError, &[&str], Option<String>)> = vec![
        (
            LeafError::ReadProcSelfCgroup(std::io::Error::from_raw_os_error(13)),
            &["/proc/self/cgroup"],
            Some(reason(13)),
        ),
        (
            LeafError::NoUnifiedLine {
                line_count: 1,
                controllers: "9:memory".into(),
            },
            &["/proc/self/cgroup", "0::", "9:memory"],
            None,
        ),
        (
            LeafError::CreateLeafDir {
                path: PathBuf::from("/sys/fs/cgroup/slice/cosca-7-0"),
                source: std::io::Error::from_raw_os_error(13),
            },
            &["/sys/fs/cgroup/slice/cosca-7-0"],
            Some(reason(13)),
        ),
        (
            LeafError::KillUnsupported {
                path: PathBuf::from("/sys/fs/cgroup/slice/cosca-7-0"),
            },
            &["/sys/fs/cgroup/slice/cosca-7-0", "cgroup.kill"],
            None,
        ),
        (
            LeafError::CheckKill {
                path: PathBuf::from("/sys/fs/cgroup/slice/cosca-7-0/cgroup.kill"),
                source: std::io::Error::from_raw_os_error(13),
            },
            &["/sys/fs/cgroup/slice/cosca-7-0/cgroup.kill"],
            Some(reason(13)),
        ),
        (
            LeafError::OpenProcs {
                path: PathBuf::from("/sys/fs/cgroup/slice/cosca-7-0/cgroup.procs"),
                source: std::io::Error::from_raw_os_error(13),
            },
            &["cgroup.procs"],
            Some(reason(13)),
        ),
        (
            LeafError::MapReportPage(std::io::Error::from_raw_os_error(12)),
            &["report"],
            Some(reason(12)),
        ),
    ];
    for (err, needles, reason) in cases {
        let rendered = err.to_string();
        for needle in needles.iter().copied().chain(reason.as_deref()) {
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
    let busy = std::io::Error::from_raw_os_error(16).to_string();
    assert!(PlacementReport::WriteFailed(16).to_string().contains(&busy));
    assert!(PlacementReport::Placed.to_string().contains("succeeded"));
    assert!(PlacementReport::NotReported.to_string().contains("did not run"));
}

/// A child whose write failed renders the pid, the leaf path, the file's actual contents, its
/// errno and its state — and never claims a membership that never began.
#[test]
fn placement_absent_renders_every_observed_fact() {
    let absent = NotPlaced::Absent {
        pid: 4242,
        path: PathBuf::from("/sys/fs/cgroup/slice/cosca-7-0/cgroup.procs"),
        procs: String::new(),
        report: NotEntered::WriteFailed(16),
        child_state: Some('Z'),
    };
    let rendered = absent.to_string();
    for needle in [
        "4242",
        "cosca-7-0/cgroup.procs",
        "empty",
        "errno 16",
        "never entered",
        "already exited",
    ] {
        assert!(
            rendered.contains(needle),
            "absent placement renders as {rendered:?}, which does not mention {needle:?}"
        );
    }
    assert!(
        !rendered.contains("membership ended"),
        "a child whose write failed was never a member: {rendered:?}"
    );
}

/// A child whose `pre_exec` closure never ran made no write at all, and is reported as such.
#[test]
fn placement_absent_renders_a_child_that_reported_nothing() {
    let rendered = NotPlaced::Absent {
        pid: 4242,
        path: PathBuf::from("/cg/cgroup.procs"),
        procs: String::new(),
        report: NotEntered::NotReported,
        child_state: Some('S'),
    }
    .to_string();
    assert!(rendered.contains("did not run"), "got {rendered:?}");
    assert!(rendered.contains("never entered"), "got {rendered:?}");
}

/// A live child that is nonetheless not a member is a different diagnosis from a zombie one,
/// and must not be described as having exited.
#[test]
fn placement_absent_distinguishes_a_live_child() {
    let rendered = NotPlaced::Absent {
        pid: 4242,
        path: PathBuf::from("/cg/cgroup.procs"),
        procs: "99\n".into(),
        report: NotEntered::WriteFailed(16),
        child_state: Some('S'),
    }
    .to_string();
    assert!(rendered.contains("99"), "the file's real contents must be quoted");
    assert!(rendered.contains("errno 16"), "the child's errno must be carried");
    assert!(!rendered.contains("zombie"), "a live child must not be called a zombie");
}

/// An unreadable `cgroup.procs` is reported with its own error, not as an empty file.
#[test]
fn placement_unreadable_names_the_io_error() {
    let rendered = NotPlaced::Unreadable {
        pid: 4242,
        path: PathBuf::from("/cg/cgroup.procs"),
        source: std::io::Error::from_raw_os_error(13),
        report: NotEntered::WriteFailed(16),
    }
    .to_string();
    assert!(rendered.contains("/cg/cgroup.procs"));
    assert!(rendered.contains(&std::io::Error::from_raw_os_error(13).to_string()));
}

/// The degrade is logged at `warn` with the reason attached — the single line a human reading
/// CI output needs to tell WHICH step failed from the bare fact that containment degraded.
///
/// Driven against this test's own "already warned" set: the process-wide one is shared with
/// every other test in this binary, so a first-report assertion made through it would silently
/// become an assertion about libtest's scheduling.
#[test]
fn degrade_logs_the_reason_at_warn() {
    crate::log_capture::install();
    let warned = std::sync::Mutex::default();
    let mark = crate::log_capture::mark();
    super::log_degrade_into(
        &warned,
        &LeafError::KillUnsupported {
            path: PathBuf::from("/sys/fs/cgroup/slice/cosca-degrade-probe-a41f"),
        },
    );
    assert_eq!(
        crate::log_capture::levels_since(mark, "cosca-degrade-probe-a41f"),
        vec![log::Level::Warn],
        "a spawn that did not get the containment it asked for is news the first time"
    );
    let records = crate::log_capture::records_since(mark, "cosca-degrade-probe-a41f");
    assert!(
        records.iter().all(|record| record.contains("process group")),
        "the degrade log must say what containment degraded TO: {records:?}"
    );
}

/// The process-wide entry point reports against a set that is shared and STICKY: whatever has
/// degraded before it in this binary, a reason reported twice is at `debug` the second time.
///
/// Asserting the second report rather than the first is what makes this independent of test
/// order — the bit is set either way by the time it runs.
#[test]
fn log_degrade_reports_through_a_sticky_process_wide_set() {
    crate::log_capture::install();
    let reason = || LeafError::OpenProcs {
        path: PathBuf::from("/sys/fs/cgroup/slice/cosca-process-wide-probe-d582/cgroup.procs"),
        source: std::io::Error::from_raw_os_error(9),
    };
    log_degrade(&reason());

    let mark = crate::log_capture::mark();
    log_degrade(&reason());

    assert_eq!(
        crate::log_capture::levels_since(mark, "cosca-process-wide-probe-d582"),
        vec![log::Level::Debug],
        "the second report of one reason is a repeat, and still carries its own full text"
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
    let reason = std::io::Error::from_raw_os_error(libc::ENOENT).to_string();
    assert!(rendered.contains(&reason), "errno missing from {rendered:?}");
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

/// A degrade whose leaf cannot be removed says so, the way `Drop` does for a leaf it could not
/// remove: a stray `cosca-*` cgroup stays on the host, and this record is all anyone will have.
#[cfg(target_os = "linux")]
#[test]
fn create_leaf_under_reports_a_leaf_its_unwind_could_not_remove() {
    crate::log_capture::install();
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().to_string_lossy().into_owned();
    super::fault::set_force_occupy_before_unwind(true);

    let mark = crate::log_capture::mark();
    let err = match super::create_leaf_under(dir.path()) {
        Err(e) => e,
        Ok(_) => panic!("a plain directory has no cgroup.kill; leaf creation must fail"),
    };
    assert!(
        !super::fault::occupy_before_unwind_armed(),
        "the seam must be consumed by the unwind it stands in for"
    );
    assert!(matches!(err, LeafError::KillUnsupported { .. }), "got {err:?}");
    assert_eq!(
        crate::log_capture::levels_since(mark, &marker),
        vec![log::Level::Warn],
        "the unwind left a leaf behind and must say so"
    );
    let enotempty = std::io::Error::from_raw_os_error(libc::ENOTEMPTY).to_string();
    assert!(
        crate::log_capture::records_since(mark, &marker)
            .iter()
            .any(|record| record.contains(&enotempty)),
        "the record must carry the kernel's reason"
    );
}

/// A `cgroup.kill` the kernel cannot even look up is not a missing one: the errno is the
/// diagnosis, and "the kernel is older than 5.14" would be a confident false cause.
///
/// The failing lookup is a path one component too long: the leaf itself fits in `PATH_MAX`,
/// `<leaf>/cgroup.kill` does not, so the `stat` fails with `ENAMETOOLONG` for any uid.
#[cfg(target_os = "linux")]
#[test]
fn create_leaf_under_reports_a_cgroup_kill_it_could_not_check() {
    let dir = tempfile::tempdir().expect("tempdir");
    // The leaf is `<parent>/cosca-<pid>-<seq>`. Size `parent` so the leaf's length is 4084 plus
    // the digits of `seq` — under PATH_MAX (4096, NUL included) for any seq below 10^11 — while
    // the 12 bytes of "/cgroup.kill" push the lookup past it.
    let pid_len = std::process::id().to_string().len();
    let parent_len = 4084 - "/cosca-".len() - pid_len - "-".len();
    let mut parent = dir.path().to_path_buf();
    while parent.as_os_str().len() < parent_len {
        let room = parent_len - parent.as_os_str().len() - 1;
        parent.push("d".repeat(room.min(200)));
    }
    assert_eq!(parent.as_os_str().len(), parent_len, "the parent must be sized exactly");
    std::fs::create_dir_all(&parent).expect("create the long parent");

    let err = match super::create_leaf_under(&parent) {
        Err(e) => e,
        Ok(_) => panic!("a plain directory has no cgroup.kill; leaf creation must fail"),
    };
    assert!(
        matches!(err, LeafError::CheckKill { .. }),
        "expected CheckKill, got {err:?}"
    );
    let reason = std::io::Error::from_raw_os_error(libc::ENAMETOOLONG).to_string();
    assert!(err.to_string().contains(&reason), "the errno is the diagnosis: {err}");
    let strays: Vec<_> = std::fs::read_dir(&parent)
        .expect("read the parent")
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

// hard_kill outcome reporting -----
// `cgroup.kill` is the whole of the CgroupV2 mechanism's teardown promise, so whether the write
// landed is the caller's answer, not a detail. Real filesystem, no cgroupfs: a `cgroup.kill`
// that is a DIRECTORY makes the kernel refuse the write with `EISDIR` on any Linux host, which
// is the same shape as the production failures (`EACCES` after a privilege drop, `EROFS` on a
// remounted cgroupfs) — a kill that did NOT happen.

/// A `cgroup.kill` write the kernel refused must reach the caller through the public
/// `Attached::hard_kill` arm, exactly as every sibling mechanism's failure does. Swallowing it
/// makes `Child::kill_tree()` return `Ok(())` over a tree that is still running.
#[cfg(target_os = "linux")]
#[test]
fn hard_kill_propagates_a_kill_the_kernel_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-refused-kill");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    // A directory where the kernel expects a writable file: `write` fails with EISDIR.
    std::fs::create_dir(leaf_path.join("cgroup.kill")).expect("create cgroup.kill as a directory");

    let leaf = super::CgroupLeaf::for_test_at(leaf_path);
    let err = leaf
        .hard_kill()
        .expect_err("a refused cgroup.kill write must not read as success");
    let reason = std::io::Error::from_raw_os_error(libc::EISDIR).to_string();
    assert!(
        err.to_string().contains(&reason),
        "the kernel's own reason must reach the caller, got {err}"
    );

    let attached = crate::containment::Attached::Cgroup(leaf);
    assert!(
        attached.hard_kill().is_err(),
        "Attached::Cgroup must propagate like every sibling arm; swallowing it makes \
         kill_tree() report a completed teardown over a live tree"
    );
}

/// An already-removed leaf is a COMPLETED teardown, not a failed kill: `rmdir` on a cgroup v2
/// leaf succeeds only once the leaf is empty, so its absence is proof every member had already
/// exited. It must stay `Ok`, and must not be narrated at `warn` — nothing was reduced.
#[cfg(target_os = "linux")]
#[test]
fn hard_kill_reads_an_already_removed_leaf_as_a_completed_teardown() {
    crate::log_capture::install();
    let mark = crate::log_capture::mark();

    let leaf = super::CgroupLeaf::placeholder_for_test();
    leaf.hard_kill()
        .expect("an already-removed leaf is a completed teardown, not a failure");

    let levels = crate::log_capture::levels_since(mark, "cosca-cgroup-placeholder");
    assert!(
        !levels.contains(&log::Level::Warn),
        "an already-gone leaf is routine and must not be reported at warn, got {levels:?}"
    );
}

// Drop's leaf-removal reporting -----
// `Drop` is the only place a leaf cosca could not remove is ever mentioned: it has returned by
// the time anything could look, and nothing — cosca or a cgroup manager — revisits a `cosca-*`
// leaf by name. A host accumulating them is diagnosable only if each one says so as it
// happens.

/// A leaf the host refuses to remove is reported through the real `Drop`. Real filesystem, any
/// Linux host: a leaf directory holding a subdirectory refuses both `rmdir`s.
#[cfg(target_os = "linux")]
#[test]
fn drop_reports_a_leaf_it_could_not_remove() {
    crate::log_capture::install();
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-undeletable-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::create_dir(leaf_path.join("occupant")).expect("make the leaf unremovable");

    let mark = crate::log_capture::mark();
    drop(super::CgroupLeaf::for_test_at(leaf_path));

    assert_eq!(
        crate::log_capture::levels_since(mark, "cosca-undeletable-leaf"),
        vec![log::Level::Warn],
        "a leaf that outlived its Drop is reported, or never known about"
    );
}

/// A leaf that is already GONE is not a leak at all: `rmdir` failing with `ENOENT` means some
/// other party removed it, which on a cgroup v2 leaf can only happen once it was empty. There
/// is nothing left on this host, so `Drop` must not report one — `hard_kill`'s own `debug` note
/// that the leaf is gone is the whole of what this path may say.
#[cfg(target_os = "linux")]
#[test]
fn drop_reports_nothing_for_a_leaf_that_is_already_gone() {
    crate::log_capture::install();
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-already-gone-leaf");

    let mark = crate::log_capture::mark();
    drop(super::CgroupLeaf::for_test_at(leaf_path));

    let levels = crate::log_capture::levels_since(mark, "cosca-already-gone-leaf");
    assert!(
        !levels.contains(&log::Level::Warn),
        "an already-removed leaf left nothing on this host; reporting one as a leak is \
         narrating a non-event, got {levels:?}"
    );
}

// Degrade-report volume -----
// A degrade's REASON is usually a permanent property of the host (an unprivileged container's
// read-only /sys/fs/cgroup, a kernel older than 5.14): an embedder spawning thousands of
// contained children can act on the first report and on nothing after it.

/// The first spawn to hit a given condition is news and warns; every later spawn hitting the
/// SAME condition still reports, at `debug`. Driven against the test's own "already warned"
/// state rather than the process-wide one, so the assertion does not depend on what other
/// tests in this binary degraded first.
#[test]
fn a_repeated_degrade_reason_warns_once_then_reports_at_debug() {
    crate::log_capture::install();
    let warned = std::sync::Mutex::default();
    let reason = || LeafError::KillUnsupported {
        path: PathBuf::from("/sys/fs/cgroup/slice/cosca-once-probe-7c13"),
    };

    let mark = crate::log_capture::mark();
    for _ in 0..3 {
        super::log_degrade_into(&warned, &reason());
    }

    assert_eq!(
        crate::log_capture::levels_since(mark, "cosca-once-probe-7c13"),
        vec![log::Level::Warn, log::Level::Debug, log::Level::Debug],
        "an embedder cannot act twice on one host property, and every repeat is still on \
         record for a reader who turns the level up"
    );
}

/// A condition nobody has been told about yet is news, whatever else has already degraded —
/// the once-per-reason rule must not collapse distinct reasons into one report.
#[test]
fn a_newly_seen_degrade_reason_still_warns() {
    crate::log_capture::install();
    let warned = std::sync::Mutex::default();
    super::log_degrade_into(
        &warned,
        &LeafError::KillUnsupported {
            path: PathBuf::from("/sys/fs/cgroup/slice/cosca-distinct-probe-3b90"),
        },
    );

    let mark = crate::log_capture::mark();
    super::log_degrade_into(
        &warned,
        &LeafError::MapReportPage(std::io::Error::from_raw_os_error(12)),
    );

    assert_eq!(
        crate::log_capture::levels_since(mark, "placement-report memory page"),
        vec![log::Level::Warn],
        "a second, different reason is a second thing the embedder has not been told"
    );
}

/// One step failing for two different reasons is two conditions: a transient `ENOMEM` warning
/// first must not silence a standing `EACCES` behind it.
#[test]
fn the_same_step_failing_with_a_new_errno_still_warns() {
    crate::log_capture::install();
    let warned = std::sync::Mutex::default();
    let refused = |errno: i32, marker: &str| LeafError::CreateLeafDir {
        path: PathBuf::from(format!("/sys/fs/cgroup/slice/{marker}")),
        source: std::io::Error::from_raw_os_error(errno),
    };

    let mark = crate::log_capture::mark();
    super::log_degrade_into(&warned, &refused(libc::ENOMEM, "cosca-errno-probe-e1c4"));
    super::log_degrade_into(&warned, &refused(libc::EACCES, "cosca-errno-probe-e1c4"));
    super::log_degrade_into(&warned, &refused(libc::EACCES, "cosca-errno-probe-e1c4"));

    assert_eq!(
        crate::log_capture::levels_since(mark, "cosca-errno-probe-e1c4"),
        vec![log::Level::Warn, log::Level::Warn, log::Level::Debug],
    );
}

/// A child that reported nothing and a child whose write failed are different conditions, and
/// so are two write failures with different errnos.
#[test]
fn each_placement_report_is_its_own_condition() {
    crate::log_capture::install();
    let warned = std::sync::Mutex::default();
    let absent = |report: NotEntered| NotPlaced::Absent {
        pid: 4242,
        path: PathBuf::from("/sys/fs/cgroup/slice/cosca-report-probe-9d27/cgroup.procs"),
        procs: String::new(),
        report,
        child_state: None,
    };

    let mark = crate::log_capture::mark();
    super::log_degrade_into(&warned, &absent(NotEntered::NotReported));
    super::log_degrade_into(&warned, &absent(NotEntered::WriteFailed(libc::EBUSY)));
    super::log_degrade_into(&warned, &absent(NotEntered::WriteFailed(libc::EINVAL)));
    super::log_degrade_into(&warned, &absent(NotEntered::WriteFailed(libc::EBUSY)));

    assert_eq!(
        crate::log_capture::levels_since(mark, "cosca-report-probe-9d27"),
        vec![log::Level::Warn, log::Level::Warn, log::Level::Warn, log::Level::Debug],
    );
}

/// Every reason carries its OWN kind. Two reasons sharing one kind would make the second one
/// ever seen silently arrive at `debug` — the exact silence this PR removes, reintroduced.
#[test]
fn every_degrade_reason_has_its_own_kind() {
    use super::DegradeReason;

    let reasons: Vec<Box<dyn DegradeReason>> = vec![
        Box::new(LeafError::ReadProcSelfCgroup(std::io::Error::from_raw_os_error(13))),
        Box::new(LeafError::NoUnifiedLine {
            line_count: 1,
            controllers: "9:memory".into(),
        }),
        Box::new(LeafError::CreateLeafDir {
            path: PathBuf::from("/cg/leaf"),
            source: std::io::Error::from_raw_os_error(13),
        }),
        Box::new(LeafError::KillUnsupported {
            path: PathBuf::from("/cg/leaf"),
        }),
        Box::new(LeafError::CheckKill {
            path: PathBuf::from("/cg/leaf/cgroup.kill"),
            source: std::io::Error::from_raw_os_error(13),
        }),
        Box::new(LeafError::OpenProcs {
            path: PathBuf::from("/cg/leaf/cgroup.procs"),
            source: std::io::Error::from_raw_os_error(13),
        }),
        Box::new(LeafError::MapReportPage(std::io::Error::from_raw_os_error(12))),
        Box::new(NotPlaced::Absent {
            pid: 1,
            path: PathBuf::from("/cg/leaf/cgroup.procs"),
            procs: String::new(),
            report: NotEntered::NotReported,
            child_state: None,
        }),
        Box::new(NotPlaced::Unreadable {
            pid: 1,
            path: PathBuf::from("/cg/leaf/cgroup.procs"),
            source: std::io::Error::from_raw_os_error(13),
            report: NotEntered::WriteFailed(16),
        }),
    ];
    let mut seen = Vec::new();
    for reason in &reasons {
        let kind = reason.condition().kind;
        assert!(!seen.contains(&kind), "{kind:?} is claimed by two different reasons");
        seen.push(kind);
    }
}

// /proc/self/cgroup summary -----
// `/proc/self/cgroup` is a whole-system dump of every hierarchy the caller is in, read to look
// up one `0::` line. When there is no such line, none of its paths is one cosca touched, and
// none of them separates a v1-only host from an unmounted unified hierarchy from an empty
// file — so only the line count and controllers come back. The sibling variants keep their
// paths for the opposite reason, pinned by `leaf_error_names_step_path_and_reason` and by
// `the_leaf_path_reaches_the_record_verbatim` below.

/// The summary keeps every fact that separates a v1-only host from an unmounted unified
/// hierarchy from an empty file, and drops every path.
#[test]
fn no_unified_line_reports_the_shape_of_the_file_not_its_paths() {
    let real = concat!(
        "12:freezer:/kubepods/burstable/pod4f8c1e2a-9d3b-11ee-b9d1-0242ac120002/\
         3dc1f9a06b8e4a1c9f2b7d5e8a0c6413\n",
        "11:memory:/user.slice/user-1000.slice\n",
        "1:name=systemd:/user.slice/user-1000.slice/session-3.scope\n",
    );
    let (line_count, controllers) = super::summarize_cgroup_controllers(real);
    assert_eq!(line_count, 3);
    assert_eq!(controllers, "12:freezer, 11:memory, 1:name=systemd");

    let rendered = LeafError::NoUnifiedLine {
        line_count,
        controllers,
    }
    .to_string();
    for identifier in [
        "user-1000",
        "session-3",
        "pod4f8c1e2a",
        "3dc1f9a06b8e4a1c9f2b7d5e8a0c6413",
        "kubepods",
    ] {
        assert!(
            !rendered.contains(identifier),
            "{identifier:?} identifies the caller and must not reach an arbitrary sink; got \
             {rendered:?}"
        );
    }
    assert!(!rendered.contains('\n'), "one record, one line: {rendered:?}");
    for kept in ["0::", "freezer", "memory", "name=systemd", "3"] {
        assert!(rendered.contains(kept), "{kept:?} is the diagnosis; got {rendered:?}");
    }
}

/// An empty `/proc/self/cgroup` is its own diagnosis and must still read as one.
#[test]
fn no_unified_line_summarizes_an_empty_file() {
    let (line_count, controllers) = super::summarize_cgroup_controllers("");
    assert_eq!(line_count, 0);
    let rendered = LeafError::NoUnifiedLine {
        line_count,
        controllers,
    }
    .to_string();
    assert!(rendered.contains('0'), "the line count is the fact here: {rendered:?}");
}

/// The asymmetry is deliberate, not an oversight in the summary's reach: a step that FAILED on
/// a path reports that path in full, identifiers and all. It is the one path the syscall
/// touched, it is the diagnosis, and a record without it says only that some mkdir somewhere
/// was refused.
#[test]
fn the_leaf_path_reaches_the_record_verbatim() {
    let leaf = "/sys/fs/cgroup/kubepods/pod4f8c1e2a-9d3b-11ee-b9d1-0242ac120002/cosca-7-0";
    let rendered = LeafError::CreateLeafDir {
        path: PathBuf::from(leaf),
        source: std::io::Error::from_raw_os_error(13),
    }
    .to_string();
    assert!(
        rendered.contains(leaf),
        "the failing mkdir's own path is the diagnosis and must not be summarized away: got \
         {rendered:?}"
    );
}

/// A line the kernel format does not explain is reported as unparseable, never quoted: an
/// unrecognized line is exactly the case where cosca cannot know which part is a path.
#[test]
fn no_unified_line_never_quotes_a_line_it_could_not_parse() {
    let (line_count, controllers) = super::summarize_cgroup_controllers("nonsense-with-no-colons\n");
    assert_eq!(line_count, 1);
    assert!(
        !controllers.contains("nonsense"),
        "an unparsed line's content must not be echoed: {controllers:?}"
    );
}

// Leaf-creation steps past the cgroup.kill check -----
// `create_leaf_under` refuses a leaf with no `cgroup.kill` before it reaches any later step, so
// a temp directory cannot exercise those steps at all. The fault seam supplies exactly the one
// fact a temp directory cannot (`cgroup.kill` is present); everything after it — the open, the
// mapping, the unwind — then runs for real against the kernel's own errnos.

/// A `cgroup.procs` that cannot be opened reports THAT step, and takes the leaf it just created
/// with it. The leaf must not survive the degrade: a stray `cosca-*` cgroup is permanent on the
/// host, since nothing ever revisits it.
#[cfg(target_os = "linux")]
#[test]
fn create_leaf_under_reports_an_unopenable_cgroup_procs_and_removes_the_leaf() {
    let dir = tempfile::tempdir().expect("tempdir");
    super::fault::set_force_kill_supported(true);
    let err = match super::create_leaf_under(dir.path()) {
        Err(e) => e,
        Ok(_) => panic!("a plain directory has no cgroup.procs to open; leaf creation must fail"),
    };
    assert!(
        !super::fault::kill_supported_armed(),
        "the seam must be consumed by the step it stands in for"
    );
    assert!(
        matches!(err, LeafError::OpenProcs { .. }),
        "expected OpenProcs, got {err:?}"
    );
    assert!(err.to_string().contains("cgroup.procs"), "got {err}");

    let strays: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read tempdir")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert!(
        strays.is_empty(),
        "the degrade left {strays:?} behind — a cosca-* cgroup this host then keeps forever"
    );
}

/// A report page that cannot be mapped is its own degrade reason, and unwinds the leaf too.
/// `MapReportPage` is a condition that did not exist before the placement report did, so the
/// step it names, and the fact it leaves nothing behind, are both worth pinning.
#[cfg(target_os = "linux")]
#[test]
fn create_leaf_under_reports_an_unmappable_report_page_and_removes_the_leaf() {
    let dir = tempfile::tempdir().expect("tempdir");
    super::fault::set_force_kill_supported(true);
    super::fault::set_force_map_report_page_failure(true);
    let err = match super::create_leaf_under(dir.path()) {
        Err(e) => e,
        Ok(_) => panic!("the report page could not be mapped; leaf creation must fail"),
    };
    assert!(
        !super::fault::map_report_page_failure_armed(),
        "the seam must be consumed by the mapping it fails"
    );
    assert!(
        matches!(err, LeafError::MapReportPage(_)),
        "expected MapReportPage, got {err:?}"
    );
    let reason = std::io::Error::from_raw_os_error(libc::ENOMEM).to_string();
    assert!(err.to_string().contains(&reason), "got {err}");

    let strays: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read tempdir")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert!(strays.is_empty(), "a failed mapping left {strays:?} behind");
}

/// A `cgroup.procs` that cannot be read is reported with the read's own error.
#[cfg(target_os = "linux")]
#[test]
fn placement_of_reports_an_unreadable_cgroup_procs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-unreadable-procs");
    std::fs::create_dir(&leaf_path).expect("create the leaf");

    let leaf = super::CgroupLeaf::for_test_at(leaf_path.clone());
    match leaf.placement_of(4242) {
        Err(NotPlaced::Unreadable {
            pid,
            path,
            source,
            report,
        }) => {
            assert_eq!(pid, 4242);
            assert_eq!(path, leaf_path.join("cgroup.procs"));
            assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            assert_eq!(report, NotEntered::NotReported, "no child ever ran");
        }
        Err(other) => panic!("an unreadable cgroup.procs must not read as an empty one: {other}"),
        Ok(()) => panic!("no child reported a placement"),
    }
}

/// A child that reported a failed write is diagnosed from the real `cgroup.procs` and its real
/// `/proc` state. The child is a zombie — exited, not yet reaped — so its state is known.
#[cfg(target_os = "linux")]
#[test]
fn placement_of_reads_the_real_procs_and_state_of_a_child_that_did_not_enter() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-absent-procs");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let listed = format!("{}\n", std::process::id());
    std::fs::write(leaf_path.join("cgroup.procs"), &listed).expect("write cgroup.procs");

    let leaf = super::CgroupLeaf::for_test_at(leaf_path.clone());
    // SAFETY: fd -1 is never writable, so the write fails with EBADF; closing -1 is a no-op.
    let _ = unsafe { super::place_self_in_cgroup_pre_exec(-1, leaf.placement_slot()) };

    let mut child = std::process::Command::new("/bin/true").spawn().expect("spawn");
    let pid = child.id();
    // Block until the child has exited, leaving it unreaped (WNOWAIT): a zombie.
    // SAFETY: `info` is a valid, writable siginfo_t; `pid` is this process's own child.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let waited = unsafe { libc::waitid(libc::P_PID, pid, &mut info, libc::WEXITED | libc::WNOWAIT) };
    assert_eq!(waited, 0, "waitid: {}", std::io::Error::last_os_error());

    let verdict = leaf.placement_of(pid);
    child.wait().expect("reap the child");
    match verdict {
        Err(NotPlaced::Absent {
            pid: reported,
            path,
            procs,
            report,
            child_state,
        }) => {
            assert_eq!(reported, pid);
            assert_eq!(path, leaf_path.join("cgroup.procs"));
            assert_eq!(procs, listed, "the file's real contents");
            assert_eq!(report, NotEntered::WriteFailed(libc::EBADF));
            assert_eq!(child_state, Some('Z'), "the child's real /proc state");
        }
        Err(other) => panic!("a readable cgroup.procs must be quoted: {other}"),
        Ok(()) => panic!("the child reported a failed write"),
    }
}
