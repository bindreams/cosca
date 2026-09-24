use crate::containment::cgroup::test_support::{block_on, childs_copy, entered_leaf_at, fork_running, reap};
use crate::containment::cgroup::{LeafError, NotEntered, NotPlaced, PlacementReport};

// removed_after_drain tests -----
// Linux-only: the function itself is `#[cfg(target_os = "linux")]` (it interprets raw kernel
// errno values that only mean anything against a real cgroupfs).

/// `ENODEV` — a syscall through an fd opened before the leaf was removed, once the kernel
/// deactivates the underlying kernfs node — is proof of drain.
#[cfg(target_os = "linux")]
#[test]
fn enodev_is_removed_after_drain() {
    let e = std::io::Error::from_raw_os_error(libc::ENODEV);
    assert!(crate::containment::cgroup::removed_after_drain(&e));
}

/// `ENOENT` — a fresh `open` through the now-unlinked leaf directory — is proof of drain too.
#[cfg(target_os = "linux")]
#[test]
fn enoent_is_removed_after_drain() {
    let e = std::io::Error::from_raw_os_error(libc::ENOENT);
    assert!(crate::containment::cgroup::removed_after_drain(&e));
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
            !crate::containment::cgroup::removed_after_drain(&e),
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
    let leaf = crate::containment::cgroup::try_create_leaf().unwrap_or_else(|e| {
        panic!(
            "COSCA_TEST_CGROUP is set but no usable delegated cgroup v2 leaf could be created \
             ({e}) — is this process running inside a writable, delegated cgroup v2 slice with \
             cgroup.kill support (kernel >= 5.14)?"
        )
    });

    // Each member reports through its OWN channel. The leaf's channel carries one report for the whole
    // leaf (see `ReportChannel`), so two members sharing it would read as whichever wrote first.
    let spawn_member = |leaf: &crate::containment::cgroup::CgroupLeaf,
                        channel: &crate::containment::cgroup::ReportChannel|
     -> std::process::Child {
        let procs_fd = leaf.procs_fd();
        let slot = channel.slot();
        let mut cmd = Command::new("sleep");
        cmd.arg("30").stdout(Stdio::null()).stderr(Stdio::null());
        // SAFETY: `Command::pre_exec` runs this closure only between `fork` and `exec` in the
        // child; `procs_fd` is a valid, open, writable fd owned by `leaf` for the parent's whole
        // lifetime (fork gives the child its own fd-table entry pointing at the same underlying
        // open file description, and `place_self_in_cgroup_pre_exec` closes only that child-side
        // copy) — exactly its own documented contract. `leaf` and `channel` both outlive every
        // member spawned through them in this test.
        unsafe {
            cmd.pre_exec(move || crate::containment::cgroup::place_self_in_cgroup_pre_exec(procs_fd, slot));
        }
        cmd.spawn().expect("spawn a real long-lived cgroup leaf member")
    };

    let channel_a = crate::containment::cgroup::ReportChannel::new().expect("open member a's report channel");
    let channel_b = crate::containment::cgroup::ReportChannel::new().expect("open member b's report channel");
    let mut a = spawn_member(&leaf, &channel_a);
    let mut b = spawn_member(&leaf, &channel_b);

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
    for (name, member, mut channel) in [("a", &a, channel_a), ("b", &b, channel_b)] {
        assert!(
            procs.lines().any(|line| line.trim() == member.id().to_string()),
            "member {name} must actually be placed in the leaf; cgroup.procs is {procs:?}"
        );
        assert_eq!(
            channel.wait(member.id()).expect("open a pidfd"),
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

/// The parent's `cgroup.procs` fd stays close-on-exec for as long as the parent holds it. The
/// child's `pre_exec` write needs it only between `fork` and `exec`, where a CLOEXEC fd is still
/// open; any other program this process starts meanwhile must not inherit a writable
/// `cgroup.procs`, through which it could move itself into the leaf and be killed with it.
#[cfg(target_os = "linux")]
#[test]
fn cgroup_leaf_procs_fd_is_not_inherited_across_exec() {
    if std::env::var_os("COSCA_TEST_CGROUP").is_none() {
        return; // unprovisioned: not a CI-cgroup environment.
    }
    let leaf = crate::containment::cgroup::try_create_leaf().unwrap_or_else(|e| {
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

    let err = match crate::containment::cgroup::create_leaf_under(&parent) {
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
    let err = match crate::containment::cgroup::create_leaf_under(dir.path()) {
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
    crate::containment::cgroup::fault::set_force_occupy_before_unwind(true);

    let mark = crate::log_capture::mark();
    let err = match crate::containment::cgroup::create_leaf_under(dir.path()) {
        Err(e) => e,
        Ok(_) => panic!("a plain directory has no cgroup.kill; leaf creation must fail"),
    };
    assert!(
        !crate::containment::cgroup::fault::occupy_before_unwind_armed(),
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
/// diagnosis, and "the kernel is older than 5.14" would be a confident false cause. The lookup is
/// through the held leaf directory, where a temp directory yields only `ENOENT`, so the fault
/// seam supplies the errno.
#[cfg(target_os = "linux")]
#[test]
fn create_leaf_under_reports_a_cgroup_kill_it_could_not_check() {
    let dir = tempfile::tempdir().expect("tempdir");
    let parent = dir.path().to_path_buf();
    crate::containment::cgroup::fault::set_force_kill_check_errno(libc::EACCES);

    let err = match crate::containment::cgroup::create_leaf_under(&parent) {
        Err(e) => e,
        Ok(_) => panic!("a plain directory has no cgroup.kill; leaf creation must fail"),
    };
    assert!(
        matches!(err, LeafError::CheckKill { .. }),
        "expected CheckKill, got {err:?}"
    );
    let reason = std::io::Error::from_raw_os_error(libc::EACCES).to_string();
    assert!(err.to_string().contains(&reason), "the errno is the diagnosis: {err}");
    let strays: Vec<_> = std::fs::read_dir(&parent)
        .expect("read the parent")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert!(strays.is_empty(), "a failed leaf creation left {strays:?} behind");
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

    let leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path);
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

    // Its OWN leaf name, not the shared placeholder: `log_capture` is process-wide and
    // libtest runs this file in parallel, so a marker a sibling test also emits makes the
    // count below a count of whatever else happened to run alongside.
    let leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(std::path::PathBuf::from(
        "/nonexistent/cosca-hard-kill-already-gone",
    ));
    leaf.hard_kill()
        .expect("an already-removed leaf is a completed teardown, not a failure");

    assert_eq!(
        crate::log_capture::levels_since(mark, "cosca-hard-kill-already-gone"),
        vec![log::Level::Debug],
        "an already-gone leaf is routine: exactly one record, and not at warn"
    );
}

/// `terminate` reads an already-removed leaf as a completed teardown, as `hard_kill` does.
#[cfg(target_os = "linux")]
#[test]
fn terminate_reads_an_already_removed_leaf_as_a_completed_teardown() {
    // Its own leaf name, for the reason `hard_kill`'s twin above gives.
    let leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(std::path::PathBuf::from(
        "/nonexistent/cosca-terminate-already-gone",
    ));
    leaf.terminate()
        .expect("an already-removed leaf has no member left to signal");

    let attached = crate::containment::Attached::Cgroup(leaf);
    assert!(
        attached.terminate(0).is_ok(),
        "terminate and hard_kill must agree about an already-gone leaf"
    );
    assert!(attached.hard_kill().is_ok());
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
    // A file, not a directory: `rmdir` refuses it, and no child-cgroup sweep removes it.
    std::fs::write(leaf_path.join("occupant"), "").expect("make the leaf unremovable");

    let mark = crate::log_capture::mark();
    drop(crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path));

    assert_eq!(
        crate::log_capture::levels_since(mark, "cosca-undeletable-leaf"),
        vec![log::Level::Warn],
        "a leaf that outlived its Drop is reported, or never known about"
    );
}

/// `Drop` writes `cgroup.kill` through an unremovable leaf only when the child reported `Placed`
/// (see the module's report contract). Before the verdict, `Drop` abandons the exchange first,
/// which makes what was received final: nothing received then means the child never execs.
#[cfg(target_os = "linux")]
#[test]
fn drop_kills_through_a_leaf_unless_the_child_provably_never_entered() {
    crate::log_capture::install();
    let reports = [
        PlacementReport::NotReported,
        PlacementReport::WriteFailed(libc::EBADF),
        PlacementReport::Placed,
    ];
    // Before the verdict `Drop` reads the report from the channel; after it, from what the
    // verdict recorded when it released the channel.
    for (report, verdict_taken) in reports.into_iter().flat_map(|report| [(report, false), (report, true)]) {
        let kills = report == PlacementReport::Placed;
        let dir = tempfile::tempdir().expect("tempdir");
        let leaf_path = dir.path().join("cosca-drop-kill-leaf");
        std::fs::create_dir(&leaf_path).expect("create the leaf");
        // A file, not a directory: `rmdir` refuses it, and no child-cgroup sweep removes it.
        std::fs::write(leaf_path.join("occupant"), "").expect("make the leaf unremovable");

        let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path.clone());
        match report {
            PlacementReport::NotReported => {}
            // SAFETY: fd -1 is never writable, so the write fails with EBADF; closing -1 is a
            // no-op. The slot's channel lives as long as `leaf`.
            PlacementReport::WriteFailed(_) => {
                let _ = unsafe { crate::containment::cgroup::place_self_in_cgroup_pre_exec(-1, leaf.placement_slot()) };
            }
            // SAFETY: the slot's channel lives as long as `leaf`.
            PlacementReport::Placed => unsafe { leaf.placement_slot().report_placed_for_test() },
        }
        if verdict_taken {
            // The verdict needs a live pid: this process's own stands in for the child.
            assert_eq!(
                leaf.take_placement(std::process::id()).expect("decidable").is_ok(),
                report == PlacementReport::Placed
            );
            assert!(!leaf.holds_spawn_resources());
        }
        let mark = crate::log_capture::mark();
        drop(leaf);

        assert_eq!(
            leaf_path.join("cgroup.kill").exists(),
            kills,
            "a child that reported {report:?} (verdict taken: {verdict_taken}): cgroup.kill \
             written must be {kills}"
        );
        assert_eq!(
            crate::log_capture::levels_since(mark, &leaf_path.to_string_lossy()),
            vec![log::Level::Warn],
            "the unremoved leaf is reported either way"
        );
    }
}

// detach's disarm -----
// See `CgroupLeaf::disarm`.

/// A disarmed leaf never writes `cgroup.kill`, and leaves the occupied directory alone. The
/// occupant stands in for the detached tree; a real leaf refuses both `rmdir`s while one runs.
#[cfg(target_os = "linux")]
#[test]
fn a_disarmed_leaf_does_not_kill_the_tree_it_was_detached_from() {
    crate::log_capture::install();
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-detached-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("occupant"), "").expect("stand in for the detached tree");
    std::fs::write(leaf_path.join("cgroup.kill"), b"").expect("create cgroup.kill");

    let attached = crate::containment::Attached::Cgroup(entered_leaf_at(leaf_path.clone()));
    let mark = crate::log_capture::mark();
    attached.disarm();
    drop(attached);

    assert_eq!(
        std::fs::read(leaf_path.join("cgroup.kill")).expect("read cgroup.kill"),
        b"",
        "a detached tree must not be killed: cgroup.kill must never be written"
    );
    assert!(leaf_path.is_dir(), "the detached tree's leaf must survive with it");
    assert_eq!(
        crate::log_capture::levels_since(mark, "cosca-detached-leaf"),
        vec![log::Level::Debug],
        "a leaf left behind for a detached tree is what the caller asked for, not a leak"
    );
}

/// The same leaf, left armed, DOES fire `cgroup.kill` — so the test above pins the disarm, not
/// an inert path.
#[cfg(target_os = "linux")]
#[test]
fn an_armed_leaf_still_kills_the_tree_on_drop() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-armed-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("occupant"), "").expect("keep the leaf unremovable");
    std::fs::write(leaf_path.join("cgroup.kill"), b"").expect("create cgroup.kill");

    drop(entered_leaf_at(leaf_path.clone()));

    assert_eq!(
        std::fs::read(leaf_path.join("cgroup.kill")).expect("read cgroup.kill"),
        b"1",
        "an occupied leaf that was NOT detached must still be killed on Drop"
    );
}

/// A disarmed leaf whose tree has already gone still removes the empty directory: detach gives
/// up the KILL, not the tidying. cosca does not come back for a leaf it left.
#[cfg(target_os = "linux")]
#[test]
fn a_disarmed_leaf_still_removes_itself_once_it_is_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-detached-empty-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");

    let attached = crate::containment::Attached::Cgroup(entered_leaf_at(leaf_path.clone()));
    attached.disarm();
    drop(attached);

    assert!(
        !leaf_path.exists(),
        "an empty leaf is removable, and cosca does not come back for one it left"
    );
}

/// A disarmed leaf whose tree the caller KILLED is not left behind for a live detached tree: it
/// is a leaf `cgroup.kill` had not yet drained when the handle dropped (`kill_on_drop(false)`,
/// `kill_tree()`, no `wait_tree()`). It is reported as the leak it is, at `warn`, like every
/// other leaf cosca fails to remove.
#[cfg(target_os = "linux")]
#[test]
fn a_disarmed_leaf_whose_tree_was_killed_warns_that_it_was_not_removed() {
    crate::log_capture::install();
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-killed-opted-out-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("occupant"), "").expect("stand in for the still-dying tree");
    std::fs::write(leaf_path.join("cgroup.kill"), b"").expect("create cgroup.kill");

    let leaf = entered_leaf_at(leaf_path);
    leaf.disarm();
    leaf.hard_kill().expect("kill the tree");
    let mark = crate::log_capture::mark();
    drop(leaf);

    let records = crate::log_capture::records_since(mark, "cosca-killed-opted-out-leaf");
    assert_eq!(
        crate::log_capture::levels_since(mark, "cosca-killed-opted-out-leaf"),
        vec![log::Level::Warn],
        "a killed tree's leaf that outlived its Drop is a leak, got {records:?}"
    );
    assert!(
        records.iter().all(|r| !r.contains("detached")),
        "the caller killed this tree; it was not left running, got {records:?}"
    );
}

/// A SIGTERM is catchable, so `terminate_tree()` proves no teardown: a disarmed leaf whose tree
/// ignored it is a live opted-out tree keeping its leaf, reported at `debug`, not a leak.
#[cfg(target_os = "linux")]
#[test]
fn a_disarmed_leaf_whose_tree_survived_terminate_is_not_reported_as_a_leak() {
    crate::log_capture::install();
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-terminate-survivor-leaf");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let mut ready = [0 as std::os::fd::RawFd; 2];
    // SAFETY: `ready` is a valid two-element array for `pipe` to fill.
    assert_eq!(unsafe { libc::pipe(ready.as_mut_ptr()) }, 0, "pipe");
    let member = fork_running(move || {
        // SAFETY (in the child): `signal`, `write` and `pause` are async-signal-safe.
        unsafe {
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
            libc::write(ready[1], b"r".as_ptr().cast(), 1);
            libc::pause();
        }
    });
    // SAFETY: the parent's copy of the write end, closed once.
    unsafe { libc::close(ready[1]) };
    block_on(ready[0]); // the member ignores SIGTERM from here on
                        // SAFETY: the parent's copy of the read end, closed once.
    unsafe { libc::close(ready[0]) };
    std::fs::write(leaf_path.join("cgroup.procs"), format!("{member}\n")).expect("list the member");

    let leaf = entered_leaf_at(leaf_path);
    leaf.disarm();
    leaf.terminate().expect("signal the tree");
    let mark = crate::log_capture::mark();
    drop(leaf);
    // SAFETY: `member` is this process's own unreaped child.
    unsafe { libc::kill(member as i32, libc::SIGKILL) };
    reap(member);

    let records = crate::log_capture::records_since(mark, "cosca-terminate-survivor-leaf");
    assert_eq!(
        crate::log_capture::levels_since(mark, "cosca-terminate-survivor-leaf"),
        vec![log::Level::Debug],
        "a tree that survived SIGTERM is left running, not leaked, got {records:?}"
    );
}

/// A disarmed leaf whose directory is already GONE leaves nothing behind, so `Drop` must not
/// say it did. `rmdir` failing with `ENOENT` is proof of removal, not of survival — the armed
/// path already reads it that way, and a detached leaf's one `rmdir` is the only reading it
/// gets.
#[cfg(target_os = "linux")]
#[test]
fn a_disarmed_leaf_that_is_already_gone_reports_nothing() {
    crate::log_capture::install();
    let leaf = entered_leaf_at(std::path::PathBuf::from("/nonexistent/cosca-detached-gone-leaf"));
    leaf.disarm();

    let mark = crate::log_capture::mark();
    drop(leaf);

    assert_eq!(
        crate::log_capture::levels_since(mark, "cosca-detached-gone-leaf"),
        Vec::<log::Level>::new(),
        "nothing is left behind for the detached tree, so there is nothing to report"
    );
}

// Drop's two flags -----
// See the truth table in `CgroupLeaf`'s `Drop`.

/// All four combinations, each against an occupied leaf whose verdict is taken: only both-set
/// writes `cgroup.kill`.
#[cfg(target_os = "linux")]
#[test]
fn drop_kills_only_a_leaf_its_child_entered_and_that_is_armed() {
    for (entered, armed) in [(true, true), (true, false), (false, true), (false, false)] {
        let dir = tempfile::tempdir().expect("tempdir");
        let leaf_path = dir.path().join("cosca-two-flags-leaf");
        std::fs::create_dir(&leaf_path).expect("create the leaf");
        std::fs::write(leaf_path.join("occupant"), "").expect("keep the leaf unremovable");
        std::fs::write(leaf_path.join("cgroup.kill"), b"").expect("create cgroup.kill");

        let leaf = if entered {
            entered_leaf_at(leaf_path.clone())
        } else {
            let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path.clone());
            // SAFETY: fd -1 is never writable, so the write fails with EBADF; closing -1 is a
            // no-op. The slot's channel lives as long as `leaf`.
            let _ = unsafe { crate::containment::cgroup::place_self_in_cgroup_pre_exec(-1, leaf.placement_slot()) };
            assert!(
                leaf.take_placement(std::process::id()).expect("decidable").is_err(),
                "a failed write is not a placement"
            );
            leaf
        };
        if !armed {
            leaf.disarm();
        }
        drop(leaf);

        let expected: &[u8] = if entered && armed { b"1" } else { b"" };
        assert_eq!(
            std::fs::read(leaf_path.join("cgroup.kill")).expect("read cgroup.kill"),
            expected,
            "entered={entered}, armed={armed}"
        );
    }
}

// An armed Drop's drain -----
// Each test gives a fake leaf cgroupfs's `rmdir` answers through the rmdir hook, and drives it from
// another thread that acts only once the drop's drain wait is about to block.

/// Run `act` on another thread each time a drain wait on THIS thread is about to block, until the
/// returned guard drops. `act` gets the number of the block, from 0.
#[cfg(target_os = "linux")]
fn on_each_drain_block(mut act: impl FnMut(usize) + Send + 'static) -> impl Drop {
    struct Stop(Option<std::thread::JoinHandle<()>>);
    impl Drop for Stop {
        fn drop(&mut self) {
            // Dropping the only sender ends the actor's loop.
            crate::containment::cgroup::fault::take_drain_blocking_notifier();
            self.0.take().expect("actor").join().expect("actor thread");
        }
    }
    let (blocking_tx, blocking_rx) = std::sync::mpsc::channel();
    let actor = std::thread::spawn(move || {
        let mut n = 0;
        while blocking_rx.recv().is_ok() {
            act(n);
            n += 1;
        }
    });
    crate::containment::cgroup::fault::set_drain_blocking_notifier(blocking_tx);
    Stop(Some(actor))
}

/// An armed `Drop` that kills through its leaf removes it only once the leaf has drained: no
/// `rmdir` after the `cgroup.kill` write sees `populated 1`.
#[cfg(target_os = "linux")]
#[test]
fn an_armed_drop_removes_its_leaf_only_after_it_drains() {
    use crate::containment::cgroup::fault;
    use crate::containment::cgroup::test_support::FakeLeaf;

    let fake = FakeLeaf::new("cosca-draining-leaf", true);
    let (leaf, events) = (fake.leaf.clone(), fake.events.clone());
    fault::set_rmdir_hook(move |_| FakeLeaf::rmdir(&leaf, &events));
    let events = fake.events.clone();
    let actor = on_each_drain_block(move |_| FakeLeaf::set_populated(&events, false));

    fault::record_leaf_steps();
    drop(entered_leaf_at(fake.leaf.clone()));
    let steps = fault::take_leaf_steps();
    drop(actor);
    fault::take_rmdir_hook();

    assert!(
        !fake.leaf.exists(),
        "the drop must remove the drained leaf, got {steps:?}"
    );
    let killed_at = steps
        .iter()
        .position(|s| s == "kill")
        .unwrap_or_else(|| panic!("an occupied armed leaf must be killed through, got {steps:?}"));
    let after_kill = &steps[killed_at + 1..];
    assert!(!after_kill.is_empty(), "the drop must retry the rmdir, got {steps:?}");
    assert!(
        after_kill.iter().all(|s| s.starts_with("rmdir populated 0")),
        "every rmdir after the kill must wait for the drain, got {steps:?}"
    );
}

/// A drain wait wakes when the leaf is removed, even with no event on `cgroup.events`: removing a
/// cgroup cancels a `populated` notification the kernel had postponed (see `DrainWatch`), so a
/// third party can remove a drained leaf while the wait still reads it populated.
#[cfg(target_os = "linux")]
#[test]
fn a_drain_wait_wakes_when_the_leaf_is_removed_without_a_populated_event() {
    use crate::containment::cgroup::test_support::FakeLeaf;
    use crate::containment::TreeDrain;

    let fake = FakeLeaf::new("cosca-removed-while-waited", true);
    let waited = fake.leaf.clone();
    let removed = fake.leaf.clone();
    let waiter = std::thread::spawn(move || {
        let _actor = on_each_drain_block(move |_| FakeLeaf::remove(&removed));
        crate::containment::cgroup::CgroupLeaf::for_test_at(waited).wait_drained(None)
    });

    assert_eq!(
        waiter.join().expect("waiter").expect("wait_drained"),
        TreeDrain::AllMembersExited,
        "a removed leaf holds no member"
    );
}

/// The same for a `Drop` killing through its leaf: it wakes, finds the leaf gone, and reports
/// nothing, since nothing was left behind.
#[cfg(target_os = "linux")]
#[test]
fn an_armed_drop_whose_leaf_a_third_party_removes_reports_nothing() {
    use crate::containment::cgroup::fault;
    use crate::containment::cgroup::test_support::FakeLeaf;

    crate::log_capture::install();
    let fake = FakeLeaf::new("cosca-removed-under-drop", true);
    let (leaf, events) = (fake.leaf.clone(), fake.events.clone());
    fault::set_rmdir_hook(move |_| FakeLeaf::rmdir(&leaf, &events));
    let removed = fake.leaf.clone();
    let actor = on_each_drain_block(move |_| FakeLeaf::remove(&removed));

    let mark = crate::log_capture::mark();
    drop(entered_leaf_at(fake.leaf.clone()));
    drop(actor);
    fault::take_rmdir_hook();

    let records = crate::log_capture::records_since(mark, "cosca-removed-under-drop");
    assert!(
        !crate::log_capture::levels_since(mark, "cosca-removed-under-drop").contains(&log::Level::Warn),
        "a leaf a third party removed was not left behind, got {records:?}"
    );
}

/// An `rmdir` that fails `EBUSY` after the kill, drain and sweep is terminal: `Drop` tries once,
/// then reports the leaf once, naming what can have held it. A retry would only make a third
/// party's race rarer, never impossible.
#[cfg(target_os = "linux")]
#[test]
fn an_armed_drop_reports_an_rmdir_refused_after_its_drain_once_without_retrying() {
    use crate::containment::cgroup::fault;
    use crate::containment::cgroup::test_support::FakeLeaf;

    crate::log_capture::install();
    let fake = FakeLeaf::new("cosca-refused-after-drain", true);
    let (leaf, events) = (fake.leaf.clone(), fake.events.clone());
    let drained_rmdirs = std::rc::Rc::new(std::cell::Cell::new(0));
    let counted = drained_rmdirs.clone();
    fault::set_rmdir_hook(move |_| {
        if !FakeLeaf::is_populated(&events) {
            counted.set(counted.get() + 1);
            // Something a third party did since the sweep.
            return Err(std::io::Error::from_raw_os_error(libc::EBUSY));
        }
        FakeLeaf::rmdir(&leaf, &events)
    });
    let events = fake.events.clone();
    let actor = on_each_drain_block(move |_| FakeLeaf::set_populated(&events, false));

    let mark = crate::log_capture::mark();
    drop(entered_leaf_at(fake.leaf.clone()));
    drop(actor);
    fault::take_rmdir_hook();

    let records = crate::log_capture::records_since(mark, "cosca-refused-after-drain");
    assert_eq!(drained_rmdirs.get(), 1, "one rmdir after the drain, no retry");
    assert_eq!(
        crate::log_capture::levels_since(mark, "cosca-refused-after-drain"),
        vec![log::Level::Warn],
        "reported once, got {records:?}"
    );
    for cause in ["moved into it after the kill", "child cgroup", "mount"] {
        assert!(
            records[0].contains(cause),
            "the report must name {cause:?}: {}",
            records[0]
        );
    }
}

/// A child-cgroup sweep of a leaf that is already gone removes nothing, and is no failure.
#[cfg(target_os = "linux")]
#[test]
fn sweeping_a_leaf_that_is_already_gone_removes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    assert_eq!(
        crate::containment::cgroup::LeafDir::open_for_test(&dir.path().join("cosca-gone"))
            .remove_children()
            .expect("sweep"),
        0
    );
}

/// A real leaf whose one member, a `sleep`, entered it. For the lane tests.
#[cfg(target_os = "linux")]
fn entered_real_leaf() -> (crate::containment::cgroup::CgroupLeaf, std::process::Child) {
    use std::os::unix::process::CommandExt;

    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "this #[ignore]d test was requested explicitly, but COSCA_TEST_CGROUP is unset"
    );
    let mut leaf = crate::containment::cgroup::try_create_leaf().expect("create a real leaf");
    let (procs_fd, slot) = (leaf.procs_fd(), leaf.placement_slot());
    let mut cmd = std::process::Command::new("sleep");
    cmd.arg("300");
    // SAFETY: as `cgroup_wait_drained_tracks_two_real_members_through_exit`'s member spawn: the
    // closure runs between fork and exec, and `leaf` outlives the spawn.
    unsafe {
        cmd.pre_exec(move || crate::containment::cgroup::place_self_in_cgroup_pre_exec(procs_fd, slot));
    }
    let member = cmd.spawn().expect("spawn a member");
    leaf.take_placement(member.id())
        .expect("decidable")
        .expect("the member entered the leaf");
    (leaf, member)
}

/// Give the calling thread alone a mount namespace, private, so that every mount it makes stays in
/// it and is gone with the thread.
#[cfg(target_os = "linux")]
fn enter_a_private_mount_namespace() {
    // SAFETY: plain syscalls on valid NUL-terminated strings.
    unsafe {
        assert_eq!(
            libc::unshare(libc::CLONE_NEWNS),
            0,
            "unshare: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null()
            ),
            0,
            "make / private: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Mount a tmpfs over `over`, in the calling thread's mount namespace.
#[cfg(target_os = "linux")]
fn mount_a_tmpfs_over(over: &std::path::Path) {
    let over = std::ffi::CString::new(over.as_os_str().as_encoded_bytes()).expect("no NUL");
    // SAFETY: a plain syscall on valid NUL-terminated strings.
    let mounted = unsafe { libc::mount(c"tmpfs".as_ptr(), over.as_ptr(), c"tmpfs".as_ptr(), 0, std::ptr::null()) };
    assert_eq!(mounted, 0, "mount a tmpfs: {}", std::io::Error::last_os_error());
}

/// Drop `leaf` on a thread of its own mount namespace, private to it, with a tmpfs mounted over
/// `over`, and return the levels and texts of the records its `Drop` made about `marker`. The mount is
/// gone with the thread.
#[cfg(target_os = "linux")]
fn drop_under_a_mount(
    leaf: crate::containment::cgroup::CgroupLeaf,
    over: std::path::PathBuf,
    marker: String,
) -> (Vec<log::Level>, Vec<String>) {
    crate::log_capture::install();
    std::thread::spawn(move || {
        enter_a_private_mount_namespace();
        mount_a_tmpfs_over(&over);
        let mark = crate::log_capture::mark();
        drop(leaf);
        (
            crate::log_capture::levels_since(mark, &marker),
            crate::log_capture::records_since(mark, &marker),
        )
    })
    .join()
    .expect("the dropping thread")
}

/// A mount over the leaf itself: `rmdir` of its name fails `EBUSY` in the VFS, before cgroupfs is
/// asked. `Drop` kills the real tree through the held leaf, and reports the leaf it cannot remove
/// rather than retrying forever.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn cgroup_an_armed_drop_under_a_mount_over_its_leaf_kills_the_tree_and_reports_the_leaf() {
    use std::os::unix::process::ExitStatusExt as _;

    let (leaf, mut member) = entered_real_leaf();
    let leaf_path = leaf.leaf_path.clone();
    let name = leaf_path.file_name().expect("a name").to_string_lossy().into_owned();

    let (levels, records) = drop_under_a_mount(leaf, leaf_path.clone(), name);
    let status = member.wait().expect("reap the member");
    // Outside the dropping thread's namespace nothing is mounted over the leaf.
    std::fs::remove_dir(&leaf_path).expect("remove the drained leaf");

    assert_eq!(status.signal(), Some(libc::SIGKILL), "the real tree must be killed");
    assert_eq!(levels, vec![log::Level::Warn], "the leaf left behind is reported, once");
    assert!(
        records[0].contains("mount"),
        "the report must name a mount as a cause: {}",
        records[0]
    );
}

/// A mount over the leaf's name in the namespace its held descriptors were opened in: the name
/// no longer reaches the leaf, which says nothing about whether the leaf is gone. `Drop` kills the
/// real tree through the held leaf, and reports the leaf it cannot remove.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn cgroup_an_armed_drop_under_a_mount_over_its_name_in_its_own_namespace_kills_the_tree_and_reports_the_leaf() {
    use std::os::unix::process::ExitStatusExt as _;

    crate::log_capture::install();
    let (leaf_path, mut member, levels, records) = std::thread::spawn(|| {
        enter_a_private_mount_namespace();
        let (leaf, member) = entered_real_leaf();
        let leaf_path = leaf.leaf_path.clone();
        let name = leaf_path.file_name().expect("a name").to_string_lossy().into_owned();
        mount_a_tmpfs_over(&leaf_path);
        let mark = crate::log_capture::mark();
        drop(leaf);
        (
            leaf_path,
            member,
            crate::log_capture::levels_since(mark, &name),
            crate::log_capture::records_since(mark, &name),
        )
    })
    .join()
    .expect("the dropping thread");
    let status = member.wait().expect("reap the member");
    // Outside the dropping thread's namespace nothing is mounted over the leaf.
    std::fs::remove_dir(&leaf_path).expect("remove the drained leaf");

    assert_eq!(status.signal(), Some(libc::SIGKILL), "the real tree must be killed");
    assert_eq!(levels, vec![log::Level::Warn], "the leaf left behind is reported, once");
    assert!(
        records[0].contains("mount"),
        "the report must name a mount as a cause: {}",
        records[0]
    );
}

/// A mount over the leaf's parent: the leaf's path finds nothing, which says nothing about the
/// leaf. `Drop` kills, drains and removes the real leaf through the held directories.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn cgroup_an_armed_drop_under_a_mount_over_its_parent_still_removes_the_leaf() {
    let (leaf, mut member) = entered_real_leaf();
    let leaf_path = leaf.leaf_path.clone();
    let parent = leaf_path.parent().expect("a parent").to_path_buf();
    let name = leaf_path.file_name().expect("a name").to_string_lossy().into_owned();

    let (levels, _) = drop_under_a_mount(leaf, parent, name);
    let removed = !leaf_path.exists();
    if !removed {
        member.kill().expect("kill the member");
    }
    member.wait().expect("reap the member");
    if !removed {
        crate::containment::cgroup::test_support::remove_drained_leaf(&leaf_path);
    }

    assert!(removed, "the real leaf must be killed through and removed");
    assert!(
        !levels.contains(&log::Level::Warn),
        "nothing was left behind, got {levels:?}"
    );
}

/// Without an inotify instance — `fs.inotify.max_user_instances` reached — no leaf is created:
/// the spawn degrades as for any other failed step, rather than leaving a leaf whose teardown
/// could not be watched. The half-made leaf is removed.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn cgroup_a_leaf_whose_drain_cannot_be_watched_is_not_created() {
    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "this #[ignore]d test was requested explicitly, but COSCA_TEST_CGROUP is unset"
    );
    crate::containment::cgroup::fault::set_force_inotify_failure(true);
    let result = crate::containment::cgroup::try_create_leaf();
    let consumed = !crate::containment::cgroup::fault::take_force_inotify_failure();

    assert!(consumed, "the creation must have tried, and failed, to watch");
    // The error names the leaf it made, so the check needs no view of what else is in its parent.
    let leaf = match result {
        Err(LeafError::WatchDrain { source, path }) => {
            assert_eq!(source.raw_os_error(), Some(libc::EMFILE));
            path.parent().expect("cgroup.events is in the leaf").to_path_buf()
        }
        Err(e) => panic!("expected WatchDrain, got {e:?}"),
        Ok(_) => panic!("a leaf whose drain cannot be watched must not be created"),
    };
    assert!(!leaf.exists(), "the half-made leaf must be removed: {}", leaf.display());
}

// The leaf's shared watcher -----
// A leaf holds one inotify instance. Its pump, a thread the leaf owns, blocks on it and broadcasts
// every change; waits only listen and re-read the leaf.

/// A thread's own notifier for "a wait is about to block", as a sender to share.
#[cfg(all(target_os = "linux", feature = "tokio"))]
fn signal_when_blocking(tx: std::sync::mpsc::Sender<()>) {
    crate::containment::cgroup::fault::set_drain_blocking_notifier(tx);
}

/// A wait polled once and then never again holds nothing another wait needs: a second wait on
/// the same leaf, already blocked when the leaf drains, still returns.
#[cfg(all(target_os = "linux", feature = "tokio"))]
#[test]
fn a_parked_async_wait_does_not_hold_up_another() {
    use std::future::Future as _;

    use crate::containment::cgroup::test_support::FakeLeaf;
    use crate::containment::TreeDrain;

    let fake = FakeLeaf::new("cosca-parked-waiter", true);
    let leaf = std::sync::Arc::new(crate::containment::cgroup::CgroupLeaf::for_test_at(fake.leaf.clone()));
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        let mut parked = std::pin::pin!(crate::tokio::wait::cgroup_wait_tree_drained(&leaf, None));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(parked.as_mut().poll(&mut context).is_pending(), "the leaf is populated");

        let (blocking, blocking_rx) = std::sync::mpsc::channel();
        let other_leaf = leaf.clone();
        let other = std::thread::spawn(move || {
            signal_when_blocking(blocking);
            let runtime = ::tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime");
            runtime.block_on(crate::tokio::wait::cgroup_wait_tree_drained(&other_leaf, None))
        });
        blocking_rx.recv().expect("the second wait blocks");
        FakeLeaf::set_populated(&fake.events, false);
        assert_eq!(
            other.join().expect("the second waiter").expect("wait"),
            TreeDrain::AllMembersExited
        );
        // Still parked, never polled again: it held nothing the second wait needed.
        let _ = &parked;
    });
}

/// A sync and an async wait on one leaf both return once it drains, on the leaf's one watch: no
/// second inotify instance is armed.
#[cfg(all(target_os = "linux", feature = "tokio"))]
#[test]
fn a_sync_and_an_async_wait_share_the_leafs_one_watch() {
    use crate::containment::cgroup::test_support::FakeLeaf;
    use crate::containment::TreeDrain;

    let fake = FakeLeaf::new("cosca-two-waiters", true);
    let leaf = std::sync::Arc::new(crate::containment::cgroup::CgroupLeaf::for_test_at(fake.leaf.clone()));
    let (blocking, blocking_rx) = std::sync::mpsc::channel();

    let (sync_leaf, sync_blocking) = (leaf.clone(), blocking.clone());
    let sync_waiter = std::thread::spawn(move || {
        signal_when_blocking(sync_blocking);
        sync_leaf.wait_drained(None)
    });
    let (async_leaf, async_blocking) = (leaf.clone(), blocking.clone());
    let async_waiter = std::thread::spawn(move || {
        signal_when_blocking(async_blocking);
        let runtime = ::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        runtime.block_on(crate::tokio::wait::cgroup_wait_tree_drained(&async_leaf, None))
    });

    blocking_rx.recv().expect("a waiter blocks");
    blocking_rx.recv().expect("the other waiter blocks");
    FakeLeaf::set_populated(&fake.events, false);

    assert_eq!(
        sync_waiter.join().expect("sync waiter").expect("sync wait"),
        TreeDrain::AllMembersExited
    );
    assert_eq!(
        async_waiter.join().expect("async waiter").expect("async wait"),
        TreeDrain::AllMembersExited
    );
    assert_eq!(
        crate::containment::cgroup::fault::arms_of("cosca-two-waiters"),
        1,
        "only the leaf's own watch is armed, at creation"
    );
}

/// A cancelled async wait leaves the others waiting as before.
#[cfg(all(target_os = "linux", feature = "tokio"))]
#[test]
fn a_cancelled_async_wait_leaves_the_others_waiting() {
    use crate::containment::cgroup::test_support::FakeLeaf;
    use crate::containment::TreeDrain;

    let fake = FakeLeaf::new("cosca-cancelled-waiter", true);
    let leaf = std::sync::Arc::new(crate::containment::cgroup::CgroupLeaf::for_test_at(fake.leaf.clone()));
    let (blocking, blocking_rx) = std::sync::mpsc::channel();
    let (cancel, cancelled) = ::tokio::sync::oneshot::channel::<()>();

    let async_leaf = leaf.clone();
    let async_waiter = std::thread::spawn(move || {
        signal_when_blocking(blocking);
        let runtime = ::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        runtime.block_on(async {
            ::tokio::select! {
                drained = crate::tokio::wait::cgroup_wait_tree_drained(&async_leaf, None) => {
                    panic!("the leaf was never drained, got {drained:?}")
                }
                _ = cancelled => {}
            }
        });
    });
    blocking_rx.recv().expect("the async wait blocks");
    cancel.send(()).expect("cancel the async wait");
    async_waiter.join().expect("the async waiter");

    FakeLeaf::set_populated(&fake.events, false);
    assert_eq!(leaf.wait_drained(None).expect("wait"), TreeDrain::AllMembersExited);
}

/// A wait whose deadline has passed answers from the leaf's state at once.
#[cfg(target_os = "linux")]
#[test]
fn a_wait_past_its_deadline_answers_from_the_leafs_state() {
    use crate::containment::cgroup::test_support::FakeLeaf;
    use crate::containment::TreeDrain;

    let fake = FakeLeaf::new("cosca-past-deadline", true);
    let leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(fake.leaf.clone());
    assert_eq!(
        leaf.wait_drained(Some(Some(std::time::Instant::now()))).expect("wait"),
        TreeDrain::MembersRemain
    );
    FakeLeaf::set_populated(&fake.events, false);
    assert_eq!(
        leaf.wait_drained(Some(Some(std::time::Instant::now()))).expect("wait"),
        TreeDrain::AllMembersExited
    );
}

/// Block a wait on `leaf` on a thread of its own, returning once it blocks.
#[cfg(target_os = "linux")]
fn blocked_wait(
    leaf: &std::sync::Arc<crate::containment::cgroup::CgroupLeaf>,
) -> std::thread::JoinHandle<Result<crate::containment::TreeDrain, crate::error::Error>> {
    let (blocking, blocking_rx) = std::sync::mpsc::channel();
    let leaf = leaf.clone();
    let waiter = std::thread::spawn(move || {
        crate::containment::cgroup::fault::set_drain_blocking_notifier(blocking);
        leaf.wait_drained(None)
    });
    blocking_rx.recv().expect("the wait blocks");
    waiter
}

/// The pump starts with the first wait that blocks, and dropping the leaf stops and joins it
/// before `drop` returns.
#[cfg(target_os = "linux")]
#[test]
fn dropping_the_leaf_stops_and_joins_its_pump() {
    use crate::containment::cgroup::fault;
    use crate::containment::cgroup::test_support::FakeLeaf;
    use crate::containment::TreeDrain;

    let fake = FakeLeaf::new("cosca-pumped-leaf", true);
    let leaf = std::sync::Arc::new(crate::containment::cgroup::CgroupLeaf::for_test_at(fake.leaf.clone()));
    let _ = leaf.wait_drained(Some(Some(std::time::Instant::now())));
    assert_eq!(
        fault::pumps_of("cosca-pumped-leaf"),
        (0, 0),
        "a wait that cannot block starts none"
    );

    let waiter = blocked_wait(&leaf);
    assert_eq!(
        fault::pumps_of("cosca-pumped-leaf"),
        (1, 0),
        "a blocking wait starts the pump"
    );
    FakeLeaf::set_populated(&fake.events, false);
    assert_eq!(
        waiter.join().expect("waiter").expect("wait"),
        TreeDrain::AllMembersExited
    );

    FakeLeaf::set_populated(&fake.events, true);
    let waiter = blocked_wait(&leaf);
    FakeLeaf::set_populated(&fake.events, false);
    assert_eq!(
        waiter.join().expect("waiter").expect("wait"),
        TreeDrain::AllMembersExited
    );
    assert_eq!(fault::pumps_of("cosca-pumped-leaf"), (1, 0), "one pump per leaf");

    drop(std::sync::Arc::into_inner(leaf).expect("the waiters are joined"));
    assert_eq!(
        fault::pumps_of("cosca-pumped-leaf"),
        (1, 1),
        "the drop joins the pump it stopped"
    );
}

/// A drained leaf is answered from one read: no pump is started for it.
#[cfg(target_os = "linux")]
#[test]
fn a_drained_leaf_is_answered_without_a_pump() {
    use crate::containment::cgroup::fault;
    use crate::containment::cgroup::test_support::FakeLeaf;
    use crate::containment::TreeDrain;

    let fake = FakeLeaf::new("cosca-drained-unpumped", false);
    let leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(fake.leaf.clone());
    assert_eq!(leaf.wait_drained(None).expect("wait"), TreeDrain::AllMembersExited);
    assert_eq!(
        leaf.wait_drained(Some(Some(std::time::Instant::now()))).expect("wait"),
        TreeDrain::AllMembersExited
    );
    #[cfg(feature = "tokio")]
    {
        let runtime = ::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        assert_eq!(
            runtime
                .block_on(crate::tokio::wait::cgroup_wait_tree_drained(&leaf, None))
                .expect("wait"),
            TreeDrain::AllMembersExited
        );
    }
    assert_eq!(fault::pumps_of("cosca-drained-unpumped"), (0, 0));
}

/// A pump that stops on its own wakes every wait, and each reports why.
#[cfg(target_os = "linux")]
#[test]
fn a_failed_pump_wakes_every_wait_with_its_error() {
    use crate::containment::cgroup::fault;
    use crate::containment::cgroup::test_support::FakeLeaf;

    let fake = FakeLeaf::new("cosca-failed-pump", true);
    let leaf = std::sync::Arc::new(crate::containment::cgroup::CgroupLeaf::for_test_at(fake.leaf.clone()));
    let waiters = [blocked_wait(&leaf), blocked_wait(&leaf)];
    fault::set_force_pump_failure("cosca-failed-pump");
    // Readable once more: the pump wakes, and fails.
    FakeLeaf::set_populated(&fake.events, true);

    for waiter in waiters {
        let e = waiter.join().expect("waiter").expect_err("the pump failed");
        assert!(e.to_string().contains("can no longer be watched"), "{e}");
    }
    assert!(
        !fault::take_force_pump_failure("cosca-failed-pump".as_ref()),
        "the pump took it"
    );
}

/// A sibling's removal reaches the pump, which wakes no wait for it.
#[cfg(target_os = "linux")]
#[test]
fn a_siblings_removal_wakes_no_wait() {
    use crate::containment::cgroup::fault;
    use crate::containment::cgroup::test_support::FakeLeaf;
    use crate::containment::TreeDrain;

    let fake = FakeLeaf::new("cosca-sibling-watcher", true);
    let leaf = std::sync::Arc::new(crate::containment::cgroup::CgroupLeaf::for_test_at(fake.leaf.clone()));
    let (batches, batches_rx) = std::sync::mpsc::channel();
    fault::set_pump_batch_notifier("cosca-sibling-watcher", batches);
    let waiter = blocked_wait(&leaf);

    let sibling = fake.leaf.with_file_name("cosca-sibling");
    std::fs::create_dir(&sibling).expect("make a sibling");
    std::fs::remove_dir(&sibling).expect("remove the sibling");
    assert!(
        !batches_rx.recv().expect("a batch"),
        "a sibling's removal notifies no one"
    );

    FakeLeaf::set_populated(&fake.events, false);
    assert!(batches_rx.recv().expect("a batch"), "a write to cgroup.events notifies");
    assert_eq!(
        waiter.join().expect("waiter").expect("wait"),
        TreeDrain::AllMembersExited
    );
}

/// A pump started with no watch fails, waking its waits with the reason, rather than exiting
/// silently. Debug builds also assert it: every leaf that can be waited on holds a watch.
#[cfg(target_os = "linux")]
#[test]
fn a_pump_without_a_watch_fails_loudly() {
    use event_listener::Listener as _;

    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let watcher = crate::containment::cgroup::Watcher::new(None, "cosca-unwatched".into());
    let listener = watcher.listen().expect("start the pump");
    listener.wait();
    assert!(
        watcher.failure().is_some_and(|why| why.contains("never armed")),
        "{:?}",
        watcher.failure()
    );
    drop(watcher);
    assert_eq!(
        crate::log_capture::contains_since(mark, "cosca-unwatched"),
        cfg!(debug_assertions),
        "the joined pump panicked on its debug assertion in exactly the builds that keep it"
    );
}

/// The pump's thread name fits Linux's 15 bytes, which would truncate it.
#[cfg(target_os = "linux")]
#[test]
fn the_pump_thread_name_fits_the_kernels_limit() {
    assert!(crate::containment::cgroup::PUMP_THREAD.len() <= 15);
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
    drop(crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path));

    let levels = crate::log_capture::levels_since(mark, "cosca-already-gone-leaf");
    assert!(
        !levels.contains(&log::Level::Warn),
        "an already-removed leaf left nothing on this host; reporting one as a leak is \
         narrating a non-event, got {levels:?}"
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
    crate::containment::cgroup::fault::set_force_kill_supported(true);
    let err = match crate::containment::cgroup::create_leaf_under(dir.path()) {
        Err(e) => e,
        Ok(_) => panic!("a plain directory has no cgroup.procs to open; leaf creation must fail"),
    };
    assert!(
        !crate::containment::cgroup::fault::kill_supported_armed(),
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

/// A report channel that cannot be opened is its own degrade reason, and unwinds the leaf too.
/// `OpenReportChannel` is a condition that did not exist before the placement report did, so the
/// step it names, and the fact it leaves nothing behind, are both worth pinning.
#[cfg(target_os = "linux")]
#[test]
fn create_leaf_under_reports_an_unopenable_report_channel_and_removes_the_leaf() {
    let dir = tempfile::tempdir().expect("tempdir");
    crate::containment::cgroup::fault::set_force_kill_supported(true);
    crate::containment::cgroup::fault::set_force_report_channel_failure(true);
    let err = match crate::containment::cgroup::create_leaf_under(dir.path()) {
        Err(e) => e,
        Ok(_) => panic!("the report channel could not be opened; leaf creation must fail"),
    };
    assert!(
        !crate::containment::cgroup::fault::report_channel_failure_armed(),
        "the seam must be consumed by the channel it fails"
    );
    assert!(
        matches!(err, LeafError::OpenReportChannel(_)),
        "expected OpenReportChannel, got {err:?}"
    );
    let reason = std::io::Error::from_raw_os_error(libc::EMFILE).to_string();
    assert!(err.to_string().contains(&reason), "got {err}");

    let strays: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read tempdir")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert!(strays.is_empty(), "a failed channel left {strays:?} behind");
}

/// A `cgroup.procs` that cannot be read is reported with the read's own error.
#[cfg(target_os = "linux")]
#[test]
fn take_placement_reports_an_unreadable_cgroup_procs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-unreadable-procs");
    std::fs::create_dir(&leaf_path).expect("create the leaf");

    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path.clone());
    match leaf.take_placement(std::process::id()).expect("decidable") {
        Err(NotPlaced::Unreadable {
            pid,
            path,
            source,
            report,
        }) => {
            assert_eq!(pid, std::process::id());
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
fn take_placement_reads_the_real_procs_and_state_of_a_child_that_did_not_enter() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-absent-procs");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let listed = format!("{}\n", std::process::id());
    std::fs::write(leaf_path.join("cgroup.procs"), &listed).expect("write cgroup.procs");

    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path.clone());
    // SAFETY: fd -1 is never writable, so the write fails with EBADF; closing -1 is a no-op.
    let _ = unsafe { crate::containment::cgroup::place_self_in_cgroup_pre_exec(-1, leaf.placement_slot()) };

    let mut child = std::process::Command::new("/bin/true").spawn().expect("spawn");
    let pid = child.id();
    // Block until the child has exited, leaving it unreaped (WNOWAIT): a zombie.
    // SAFETY: `info` is a valid, writable siginfo_t; `pid` is this process's own child.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let waited = unsafe { libc::waitid(libc::P_PID, pid, &mut info, libc::WEXITED | libc::WNOWAIT) };
    assert_eq!(waited, 0, "waitid: {}", std::io::Error::last_os_error());

    let verdict = leaf.take_placement(pid).expect("decidable");
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

/// The child's `/proc` state is read BEFORE `cgroup.procs`, so a `Z` in the diagnosis means the
/// child had exited before the file was read.
///
/// `cgroup.procs` is a FIFO here, so the read of it is an event the test can act on: its writer
/// makes the child a zombie only once the read has begun, and lets the read finish only after.
/// Read first, the state is the live child's; read second, it would be `Z`.
#[cfg(target_os = "linux")]
#[test]
fn take_placement_reads_the_childs_state_before_cgroup_procs() {
    use std::io::Write;

    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-ordered-reads");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let procs_path = leaf_path.join("cgroup.procs");
    nix::unistd::mkfifo(&procs_path, nix::sys::stat::Mode::S_IRWXU).expect("mkfifo cgroup.procs");
    // No report was stored, so the verdict reads both to diagnose the child.
    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path);

    // A live child, blocked reading a pipe nothing writes to.
    let mut child = std::process::Command::new("/bin/cat")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    let pid = child.id();
    let writer = std::thread::spawn(move || {
        // Blocks until the verdict opens the FIFO to read it.
        let mut fifo = std::fs::OpenOptions::new()
            .write(true)
            .open(&procs_path)
            .expect("open the FIFO");
        child.kill().expect("kill the child");
        // Block until the child has exited, leaving it unreaped (WNOWAIT): a zombie.
        // SAFETY: `info` is a valid, writable siginfo_t; `pid` is this process's own child.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let waited = unsafe { libc::waitid(libc::P_PID, pid, &mut info, libc::WEXITED | libc::WNOWAIT) };
        assert_eq!(waited, 0, "waitid: {}", std::io::Error::last_os_error());
        fifo.write_all(b"listed\n").expect("write the FIFO");
        child
    });

    let verdict = leaf.take_placement(pid).expect("decidable");
    writer.join().expect("the writer").wait().expect("reap the child");
    match verdict {
        Err(NotPlaced::Absent { procs, child_state, .. }) => {
            assert_eq!(procs, "listed\n");
            assert!(
                child_state.is_some_and(|state| state != 'Z'),
                "the state was read after cgroup.procs: {child_state:?}"
            );
        }
        Err(other) => panic!("a readable cgroup.procs must be quoted: {other}"),
        Ok(()) => panic!("no child reported a placement"),
    }
}

// Deciding without a pidfd -----
// `pidfd_open` can fail (a full fd table, a seccomp filter). Waiting on the report channel's EOF
// instead could block forever, so the verdict closes the leaf or learns the child is in it.

/// A leaf with no report and no member is removed, so the child can never enter it, and the spawn
/// degrades once per errno — warned the first time, `debug` after.
#[cfg(target_os = "linux")]
#[test]
fn without_a_pidfd_an_unentered_leaf_is_closed_and_degrades() {
    use crate::containment::cgroup::{DegradeCondition, DegradeKind, DegradeReason};

    crate::log_capture::install();
    let warned = std::sync::Mutex::default();
    let mut levels = Vec::new();
    for _ in 0..2 {
        let dir = tempfile::tempdir().expect("tempdir");
        let leaf_path = dir.path().join("cosca-unwaitable");
        std::fs::create_dir(&leaf_path).expect("create the leaf");
        let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path.clone());

        crate::containment::cgroup::fault::set_force_pidfd_failure(true);
        let verdict = leaf.take_placement(std::process::id()).expect("decidable");
        assert!(
            !crate::containment::cgroup::fault::pidfd_failure_armed(),
            "the seam must be consumed by the wait"
        );

        let reason = match verdict {
            Err(reason @ NotPlaced::Unwaitable { .. }) => reason,
            other => panic!("expected Unwaitable, got {other:?}"),
        };
        assert_eq!(
            reason.condition(),
            DegradeCondition {
                kind: DegradeKind::PidfdUnavailable,
                errno: Some(libc::EMFILE),
            }
        );
        assert!(!leaf_path.exists(), "the leaf must be closed to the child");
        levels.push(crate::containment::cgroup::log_degrade_into(&warned, &reason));
    }
    assert_eq!(levels, [log::Level::Warn, log::Level::Debug]);
}

/// A report already sent is final, pidfd or not, and the leaf is left alone.
#[cfg(target_os = "linux")]
#[test]
fn without_a_pidfd_a_report_already_sent_decides() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-sent");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path.clone());
    // SAFETY: the slot's channel lives as long as `leaf`.
    unsafe { leaf.placement_slot().report_placed_for_test() };

    crate::containment::cgroup::fault::set_force_pidfd_failure(true);
    assert!(matches!(leaf.take_placement(std::process::id()), Ok(Ok(()))));
    assert!(leaf_path.exists(), "a placed child's leaf must not be removed");
}

/// A `Placed` that arrives after the report was checked, from a child whose tree has since
/// exited: the leaf is gone, and the verdict is still the child's own report.
#[cfg(target_os = "linux")]
#[test]
fn without_a_pidfd_a_removed_leaf_reads_the_report_again() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-late");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path.clone());
    let channel = leaf.report.take().expect("the channel");
    // SAFETY: `channel` is open.
    unsafe { channel.slot().report_placed_for_test() };

    let source = std::io::Error::from_raw_os_error(libc::EMFILE);
    let verdict = leaf.decide_unwaitable(std::process::id(), channel, source);
    assert!(matches!(verdict, Ok(Ok(()))), "got {verdict:?}");
    assert!(leaf.entered);
    assert!(!leaf_path.exists());
}

/// A leaf that can be neither waited on nor removed fails the spawn: its child is killed, which
/// ends its chance to enter. The child's report is then final, and the leaf is killed through
/// only if it says `Placed` — otherwise nothing in it came from the child.
#[cfg(target_os = "linux")]
#[test]
fn without_a_pidfd_an_unremovable_leaf_kills_the_child_and_fails() {
    use std::os::unix::process::ExitStatusExt;

    for placed in [false, true] {
        let dir = tempfile::tempdir().expect("tempdir");
        let leaf_path = dir.path().join("cosca-unremovable");
        std::fs::create_dir(&leaf_path).expect("create the leaf");
        // `rmdir` fails with ENOTEMPTY: neither closed nor proven entered.
        std::fs::create_dir(leaf_path.join("occupant")).expect("occupy the leaf");
        let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path.clone());
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("300")
            .spawn()
            .expect("spawn");

        let err = if placed {
            // A `Placed` the wait missed: sent after the check, as a child that just placed
            // itself would.
            let channel = leaf.report.take().expect("the channel");
            // SAFETY: `channel` is open.
            unsafe { channel.slot().report_placed_for_test() };
            leaf.fail_closed(child.id(), channel, "the test cannot decide")
        } else {
            crate::containment::cgroup::fault::set_force_pidfd_failure(true);
            match leaf.take_placement(child.id()) {
                Err(e) => e,
                Ok(verdict) => panic!("an undecidable verdict must fail the spawn, got {verdict:?}"),
            }
        };
        assert!(
            err.to_string().contains("the child and its process group were killed"),
            "got {err}"
        );
        assert_eq!(
            child.wait().expect("reap the child").signal(),
            Some(libc::SIGKILL),
            "the child must be killed"
        );
        assert_eq!(
            leaf_path.join("cgroup.kill").exists(),
            placed,
            "cgroup.kill must be written only for a child that reported Placed"
        );
    }
}

/// A child already in its real leaf is contained, pidfd or not: `rmdir` refuses an occupied leaf
/// with `EBUSY`, and the child's own `/proc/<pid>/cgroup` shows the leaf.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn cgroup_without_a_pidfd_a_child_in_its_leaf_is_contained() {
    use std::os::unix::process::CommandExt;

    use crate::containment::TreeDrain;

    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "requires COSCA_TEST_CGROUP and a delegated cgroup"
    );
    let mut leaf = crate::containment::cgroup::try_create_leaf().expect("a delegated cgroup v2 leaf");
    // The member reports through a channel of its own, so the leaf's has nothing queued.
    let own = crate::containment::cgroup::ReportChannel::new().expect("open the member's channel");
    let (procs_fd, slot) = (leaf.procs_fd(), own.slot());
    let mut cmd = std::process::Command::new("/bin/sleep");
    cmd.arg("300");
    // SAFETY: the closure runs between fork and exec, and performs only async-signal-safe calls
    // on descriptors `leaf` and `own` keep open across the spawn.
    unsafe { cmd.pre_exec(move || crate::containment::cgroup::place_self_in_cgroup_pre_exec(procs_fd, slot)) };
    let mut member = cmd.spawn().expect("spawn the member");

    crate::containment::cgroup::fault::set_force_pidfd_failure(true);
    let verdict = leaf.take_placement(member.id());
    assert!(matches!(verdict, Ok(Ok(()))), "got {verdict:?}");
    assert!(leaf.leaf_path.exists(), "a contained child's leaf must not be removed");

    leaf.hard_kill().expect("kill through the leaf");
    assert_eq!(leaf.wait_drained(None).expect("drain"), TreeDrain::AllMembersExited);
    member.wait().expect("reap the member");
}

/// A real leaf occupied by something other than the child can be neither waited on nor closed,
/// so the spawn fails and its child is killed. Its report then proves it never entered, so
/// nothing in the leaf is cosca's to kill: the occupant survives.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn cgroup_without_a_pidfd_a_leaf_occupied_by_another_process_fails_without_killing_it() {
    use std::io::{Read, Write};
    use std::os::unix::process::{CommandExt, ExitStatusExt};

    use crate::containment::TreeDrain;

    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "requires COSCA_TEST_CGROUP and a delegated cgroup"
    );
    let mut leaf = crate::containment::cgroup::try_create_leaf().expect("a delegated cgroup v2 leaf");
    let own = crate::containment::cgroup::ReportChannel::new().expect("open the occupant's channel");
    let (procs_fd, slot) = (leaf.procs_fd(), own.slot());
    // `cat` echoes, so a round trip through it proves it alive.
    let mut cmd = std::process::Command::new("/bin/cat");
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    // SAFETY: the closure runs between fork and exec, and performs only async-signal-safe calls
    // on descriptors `leaf` and `own` keep open across the spawn.
    unsafe { cmd.pre_exec(move || crate::containment::cgroup::place_self_in_cgroup_pre_exec(procs_fd, slot)) };
    let mut occupant = cmd.spawn().expect("spawn the occupant");
    // The child whose verdict is taken never touches the leaf.
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("300")
        .spawn()
        .expect("spawn the child");

    crate::containment::cgroup::fault::set_force_pidfd_failure(true);
    assert!(leaf.take_placement(child.id()).is_err(), "the spawn must fail");
    assert_eq!(
        child.wait().expect("reap the child").signal(),
        Some(libc::SIGKILL),
        "the child must be killed"
    );
    let mut echo = [0u8; 1];
    occupant
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"x")
        .expect("write to the occupant");
    occupant
        .stdout
        .as_mut()
        .expect("stdout")
        .read_exact(&mut echo)
        .expect("the occupant must still be alive to echo");
    assert_eq!(&echo, b"x");

    occupant.kill().expect("kill the occupant");
    occupant.wait().expect("reap the occupant");
    assert_eq!(leaf.wait_drained(None).expect("drain"), TreeDrain::AllMembersExited);
}

// What the placement hook returns -----
// `pre_exec` failing aborts the spawn. A failed placement must not (the child degrades to its
// process group); a report the waiting parent can never receive must (it would read as never
// placed for as long as the child lives).

/// A failed placement whose report is delivered lets the spawn proceed.
#[cfg(target_os = "linux")]
#[test]
fn placement_hook_proceeds_past_a_failed_placement() {
    let channel = crate::containment::cgroup::ReportChannel::new().expect("open the report channel");
    // SAFETY: fd -1 is never writable, so the placement fails with EBADF; the channel is open.
    let result = unsafe { crate::containment::cgroup::place_self_in_cgroup_pre_exec(-1, channel.slot()) };
    assert!(
        result.is_ok(),
        "a failed placement must not abort the spawn: {result:?}"
    );
    assert_eq!(channel.report_for_test(), PlacementReport::WriteFailed(libc::EBADF));
}

/// A report that cannot be sent to a parent still waiting for it fails the spawn.
#[cfg(target_os = "linux")]
#[test]
fn placement_hook_fails_when_its_report_cannot_be_sent() {
    let sink = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .expect("open /dev/null");
    let procs_fd = std::os::fd::IntoRawFd::into_raw_fd(sink);
    // fd -1 is never open, so the send fails with EBADF.
    let slot = crate::containment::cgroup::ReportSlot { fd: -1, parent_fd: -1 };
    // SAFETY: `procs_fd` is open and closed by the hook; the slot's fd is deliberately invalid.
    let result = unsafe { crate::containment::cgroup::place_self_in_cgroup_pre_exec(procs_fd, slot) };
    assert_eq!(
        result.map_err(|e| e.raw_os_error()),
        Err(Some(libc::EBADF)),
        "an undeliverable report must abort the spawn"
    );
}

/// A parent that decided without the exchange sends *proceed* and closes its end. In a real
/// spawn the child's own inherited copy of that end would keep the socket open, so the hook closes
/// it first; the child's send then fails, finds *proceed*, and the child carries on to `exec` —
/// without `SIGPIPE`, and without touching the leaf it no longer needs.
///
/// Ordered by primitives: the forked child signals, then waits on a gate that the deciding thread
/// opens only after it has decided.
///
/// Runs in a copy of this test binary running only this test. Any other process this one forks
/// while the channel is open holds a copy of the parent's end until its own `exec`, and would keep
/// the socket open past the parent's close — the child's send would then queue, and the child
/// carry on having written its placement: a decision honoured, but not the branch under test.
#[cfg(target_os = "linux")]
#[test]
fn placement_hook_proceeds_when_the_parent_decided_without_the_exchange() {
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, IntoRawFd};
    use std::os::unix::process::CommandExt;

    const NAME: &str =
        "containment::cgroup::leaf::leaf_tests::placement_hook_proceeds_when_the_parent_decided_without_the_exchange";
    const INNER: &str = "COSCA_TEST_DECIDED_ALONE";
    if std::env::var_os(INNER).is_none() {
        let out = std::process::Command::new(std::env::current_exe().expect("this test binary"))
            .args([NAME, "--exact", "--nocapture", "--test-threads=1"])
            .env(INNER, "1")
            .output()
            .expect("run the case alone");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "{}\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }

    let channel = crate::containment::cgroup::ReportChannel::new().expect("open the report channel");
    let slot = channel.slot();
    let (procs_read, procs_write) = std::io::pipe().expect("a pipe standing in for cgroup.procs");
    let procs_fd = procs_write.into_raw_fd();
    let (mut forked_read, forked_write) = std::io::pipe().expect("open the forked signal");
    let (gate_read, mut gate_write) = std::io::pipe().expect("open the gate");
    let (forked_fd, gate_fd) = (forked_write.as_raw_fd(), gate_read.as_raw_fd());
    let decider = std::thread::spawn(move || {
        let mut byte = [0u8; 1];
        forked_read.read_exact(&mut byte).expect("the child forked");
        channel.proceed();
        gate_write.write_all(b"x").expect("release the child");
    });
    let mut cmd = std::process::Command::new("/bin/true");
    // SAFETY: the closure runs between fork and exec, and makes only async-signal-safe calls on
    // descriptors this test keeps open across the spawn.
    unsafe {
        cmd.pre_exec(move || {
            libc::write(forked_fd, b"x".as_ptr().cast(), 1);
            block_on(gate_fd);
            crate::containment::cgroup::placement_hook(procs_fd, slot)
        })
    };
    let status = cmd.spawn().expect("a decided exchange must not abort the spawn").wait();
    // SAFETY: the parent's own copy, closed once.
    unsafe { libc::close(procs_fd) };
    decider.join().expect("the deciding thread");
    drop(forked_write);
    assert!(status.expect("wait").success(), "the child must have exec'd");
    assert_eq!(
        std::io::read_to_string(procs_read).expect("read the pipe"),
        "",
        "no placement write"
    );
}

/// A parent that abandoned the spawn shut its end without *proceed*: the child's first send fails,
/// and the hook fails the spawn with `ECANCELED` before touching the leaf — so the child exits
/// instead of exec'ing.
#[cfg(target_os = "linux")]
#[test]
fn placement_hook_fails_a_spawn_the_parent_abandoned_before_touching_the_leaf() {
    let channel = crate::containment::cgroup::ReportChannel::new().expect("open the report channel");
    let (_end, slot) = childs_copy(&channel);
    let (procs_read, procs_write) = std::io::pipe().expect("a pipe standing in for cgroup.procs");
    let received = channel.shut();
    assert!(received.pid.is_none(), "nothing was sent before the shut");
    // SAFETY: as above.
    let result = unsafe {
        crate::containment::cgroup::place_self_in_cgroup_pre_exec(
            std::os::fd::IntoRawFd::into_raw_fd(procs_write),
            slot,
        )
    };
    assert_eq!(result.map_err(|e| e.raw_os_error()), Err(Some(libc::ECANCELED)));
    assert_eq!(
        std::io::read_to_string(procs_read).expect("read the pipe"),
        "",
        "no placement write"
    );
}

/// A child held before its hook while the parent abandons the spawn never execs: released, its
/// first send fails with no *proceed*, and it exits from inside its hook with `ABANDONED_EXIT`,
/// rather than return an error to `std` — which would write its error record to the fd number its
/// error channel had, a stdio slot once `std` returned early. A regression exits 0 here (the
/// forked body's own `_exit`).
#[cfg(target_os = "linux")]
#[test]
fn a_child_released_after_its_spawn_was_abandoned_never_execs() {
    use std::io::Write;
    use std::os::fd::{AsRawFd, IntoRawFd};

    let channel = crate::containment::cgroup::ReportChannel::new().expect("open the report channel");
    let slot = channel.slot();
    let (procs_read, procs_write) = std::io::pipe().expect("a pipe standing in for cgroup.procs");
    let procs_fd = procs_write.into_raw_fd();
    let (gate_read, mut gate_write) = std::io::pipe().expect("open the gate");
    let gate = gate_read.as_raw_fd();
    let pid = fork_running(move || {
        block_on(gate);
        // SAFETY: this child's inherited copies of the channel's ends and the pipe.
        let _ = unsafe { crate::containment::cgroup::placement_hook(procs_fd, slot) };
    });
    // SAFETY: the parent's own copy, closed once; the child keeps its own.
    unsafe { libc::close(procs_fd) };
    let received = channel.shut();
    assert!(received.pid.is_none(), "the child was held before its hook");
    gate_write.write_all(b"x").expect("release the child");

    let mut status = 0;
    // SAFETY: `pid` is this process's own child; `status` is a valid, writable int.
    assert_eq!(unsafe { libc::waitpid(pid as i32, &mut status, 0) }, pid as i32);
    assert!(libc::WIFEXITED(status), "status {status:#x}");
    assert_eq!(
        libc::WEXITSTATUS(status),
        crate::containment::cgroup::ABANDONED_EXIT,
        "the abandoned child must exit from its hook, not exec"
    );
    assert_eq!(
        std::io::read_to_string(procs_read).expect("read the pipe"),
        "",
        "no placement write"
    );
}

/// Through a real spawn: an undeliverable report aborts it rather than exec'ing a child the
/// parent would misread as never placed.
#[cfg(target_os = "linux")]
#[test]
fn placement_hook_aborts_a_spawn_whose_report_cannot_be_sent() {
    use std::os::unix::process::CommandExt;

    let sink = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .expect("open /dev/null");
    let procs_fd = std::os::fd::IntoRawFd::into_raw_fd(sink);
    let slot = crate::containment::cgroup::ReportSlot { fd: -1, parent_fd: -1 };
    let mut cmd = std::process::Command::new("/bin/true");
    // SAFETY: the closure runs between fork and exec, and performs only async-signal-safe calls.
    unsafe { cmd.pre_exec(move || crate::containment::cgroup::place_self_in_cgroup_pre_exec(procs_fd, slot)) };
    let result = cmd.spawn();
    // SAFETY: the parent's own copy of the descriptor, closed exactly once.
    unsafe { libc::close(procs_fd) };
    assert!(result.is_err(), "the spawn must fail");
}

/// A child that something else in this process already reaped — a `waitpid(-1)` reaper, or
/// `SIGCHLD` set to `SIG_IGN` — breaks the verdict's precondition. In release the verdict still
/// decides without a pidfd, and never signals a pid that is not this process's unreaped child.
/// (Debug builds assert the precondition instead.)
///
/// No freed pid is ever obtained: a reaped pid may already be another process's. `pidfd_open`'s
/// `ESRCH` is injected, and "not this process's child" is a live grandchild, which its own parent
/// has not reaped, so its number cannot be reused.
#[cfg(all(target_os = "linux", not(debug_assertions)))]
#[test]
fn a_child_reaped_elsewhere_is_decided_without_signalling_its_pid() {
    use std::io::{BufRead, Read, Write};

    // `pidfd_open` fails with ESRCH: the leaf is closed, and the spawn degrades.
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-reaped");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path.clone());
    crate::containment::cgroup::fault::set_force_pidfd_errno(rustix::io::Errno::SRCH);
    match leaf.take_placement(std::process::id()).expect("decidable") {
        Err(NotPlaced::Unwaitable { source, .. }) => assert_eq!(source.raw_os_error(), Some(libc::ESRCH)),
        other => panic!("expected Unwaitable, got {other:?}"),
    }
    assert!(!leaf_path.exists(), "the leaf must be closed");

    // A pid that is not this process's child is never signalled. `cat` reads the shell's stdin
    // through fd 3: an asynchronous list's own stdin is /dev/null.
    let mut shell = std::process::Command::new("/bin/sh")
        .args(["-c", "exec 3<&0; cat <&3 & echo $!; wait"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the shell");
    let mut stdout = std::io::BufReader::new(shell.stdout.take().expect("stdout"));
    let mut line = String::new();
    stdout.read_line(&mut line).expect("read the grandchild's pid");
    let grandchild: u32 = line.trim().parse().expect("a pid");

    std::fs::create_dir(&leaf_path).expect("recreate the leaf");
    std::fs::create_dir(leaf_path.join("occupant")).expect("occupy the leaf");
    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path.clone());
    let channel = leaf.report.take().expect("the channel");
    let err = leaf.fail_closed(grandchild, channel, "the test cannot decide");
    assert!(err.to_string().contains("not signalled"), "got {err}");

    let mut stdin = shell.stdin.take().expect("stdin");
    stdin.write_all(b"x").expect("write to the grandchild");
    let mut echo = [0u8; 1];
    stdout
        .read_exact(&mut echo)
        .expect("the grandchild must be alive to echo: it must not have been signalled");
    assert_eq!(&echo, b"x");
    drop(stdin);
    shell.wait().expect("reap the shell");
}

/// A leaf dropped before its verdict, with no report received and nothing in it, is removed: a
/// removed leaf admits no member, so the in-flight report cannot matter.
#[cfg(target_os = "linux")]
#[test]
fn drop_removes_an_empty_leaf_whose_report_is_in_flight_without_a_kill() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-in-flight-empty");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    drop(crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path.clone()));
    assert!(!leaf_path.exists(), "the leaf must be removed");
}

/// A real leaf dropped before its verdict, occupied by a process that is not its child: the
/// abandoned exchange received nothing, so nothing of the child's is there, and the occupant is
/// not cosca's to kill. It survives — proven by an echo — and the leaf is reported, not killed.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn cgroup_drop_of_an_abandoned_spawn_spares_an_occupant_that_is_not_its_child() {
    use std::io::{Read, Write};
    use std::os::unix::process::CommandExt;

    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "requires COSCA_TEST_CGROUP and a delegated cgroup"
    );
    let leaf = crate::containment::cgroup::try_create_leaf().expect("a delegated cgroup v2 leaf");
    let leaf_path = leaf.leaf_path.clone();
    // The occupant reports through a channel of its own, so the leaf's receives nothing.
    let own = crate::containment::cgroup::ReportChannel::new().expect("open the occupant's channel");
    let (procs_fd, slot) = (leaf.procs_fd(), own.slot());
    let mut cmd = std::process::Command::new("/bin/cat");
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    // SAFETY: the closure runs between fork and exec, and performs only async-signal-safe calls
    // on descriptors `leaf` and `own` keep open across the spawn.
    unsafe { cmd.pre_exec(move || crate::containment::cgroup::place_self_in_cgroup_pre_exec(procs_fd, slot)) };
    let mut occupant = cmd.spawn().expect("spawn the occupant");

    drop(leaf);

    let mut echo = [0u8; 1];
    occupant
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"x")
        .expect("write to the occupant");
    occupant
        .stdout
        .as_mut()
        .expect("stdout")
        .read_exact(&mut echo)
        .expect("the occupant must still be alive to echo");
    assert_eq!(&echo, b"x");
    assert!(leaf_path.exists(), "an occupied leaf is left, and reported");

    occupant.kill().expect("kill the occupant");
    occupant.wait().expect("reap the occupant");
    std::fs::remove_dir(&leaf_path).expect("remove the emptied leaf");
}

/// An abandoned spawn's child is killed and reaped through the pidfd its intent carried, whatever
/// `cgroup.kill` returns — it may have left the leaf. Here `cgroup.kill` is a directory, so the
/// leaf's kill fails for real.
#[cfg(target_os = "linux")]
#[test]
fn an_abandoned_child_is_killed_and_reaped_by_its_pidfd_when_the_leaf_kill_fails() {
    use std::os::unix::process::CommandExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-abandoned-kill-fails");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::create_dir(leaf_path.join("cgroup.kill")).expect("make cgroup.kill unwritable");
    let leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path);
    let sink = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .expect("open /dev/null");
    let procs_fd = std::os::fd::IntoRawFd::into_raw_fd(sink);
    let slot = leaf.placement_slot();
    let mut cmd = std::process::Command::new("/bin/sleep");
    cmd.arg("300").process_group(0);
    // SAFETY: the closure runs between fork and exec; /dev/null stands in for cgroup.procs.
    unsafe { cmd.pre_exec(move || crate::containment::cgroup::place_self_in_cgroup_pre_exec(procs_fd, slot)) };
    let child = cmd.spawn().expect("spawn");
    let pid = child.id();
    let pidfd = pidfd_of(pid);
    // SAFETY: the parent's own copy, closed once.
    unsafe { libc::close(procs_fd) };
    // No handle owns the child once its spawn is abandoned: the leaf reaps it.
    drop(child);

    drop(leaf);

    assert!(
        crate::containment::cgroup::fault::take_reaped_orphans().contains(&(pid, Some(libc::SIGKILL))),
        "the child must be killed by its pidfd"
    );
    assert!(reaped(&pidfd), "and reaped");
}

/// A pidfd for `pid`, this process's own unreaped child, taken while its pid is pinned.
#[cfg(target_os = "linux")]
fn pidfd_of(pid: u32) -> std::os::fd::OwnedFd {
    rustix::process::pidfd_open(
        rustix::process::Pid::from_raw(pid as i32).expect("a positive pid"),
        rustix::process::PidfdFlags::empty(),
    )
    .expect("open a pidfd")
}

/// Whether the child `pidfd` names has been reaped — a question a pidfd, unlike a pid, can answer
/// after the reap, since it cannot come to name another process.
#[cfg(target_os = "linux")]
fn reaped(pidfd: &std::os::fd::OwnedFd) -> bool {
    use std::os::fd::AsFd;

    use rustix::process::{waitid, WaitId, WaitIdOptions};

    matches!(
        waitid(
            WaitId::PidFd(pidfd.as_fd()),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        ),
        Err(rustix::io::Errno::CHILD)
    )
}

/// Spawn `argv` as a child that leads its own group and places itself through `leaf`'s channel,
/// reporting `Placed` (`/dev/null` stands in for `cgroup.procs`) or, with `fail`, the write's
/// `EBADF`. `before` runs in the forked child first. Returns the child, never waited on here.
#[cfg(target_os = "linux")]
fn spawn_placing(
    leaf: &crate::containment::cgroup::CgroupLeaf,
    argv: &[&str],
    fail: bool,
    stdout: std::process::Stdio,
) -> std::process::Child {
    use std::os::unix::process::CommandExt;

    let procs_fd = if fail {
        -1
    } else {
        let sink = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .expect("open /dev/null");
        std::os::fd::IntoRawFd::into_raw_fd(sink)
    };
    let slot = leaf.placement_slot();
    let mut cmd = std::process::Command::new(argv[0]);
    cmd.args(&argv[1..]).stdout(stdout).process_group(0);
    // SAFETY: the closure runs between fork and exec, and makes only async-signal-safe calls on
    // descriptors this test and `leaf` keep open across the spawn.
    unsafe { cmd.pre_exec(move || crate::containment::cgroup::placement_hook(procs_fd, slot)) };
    let child = cmd.spawn().expect("spawn");
    if procs_fd >= 0 {
        // SAFETY: the parent's own copy, closed once.
        unsafe { libc::close(procs_fd) };
    }
    child
}

/// An abandoned child whose intent carried no pidfd — `pidfd_open` denied in the child — is still
/// killed and reaped, named by the `/proc/self` directory it sent: a handle on that process, not on
/// its number.
#[cfg(target_os = "linux")]
#[test]
fn an_abandoned_child_without_a_pidfd_is_killed_and_reaped_through_its_proc_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-abandoned-no-pidfd");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path);
    // Inherited by the child forked from this thread, which takes it.
    crate::containment::cgroup::fault::set_force_child_pidfd_failure(true);
    let child = spawn_placing(&leaf, &["/bin/sleep", "300"], false, std::process::Stdio::null());
    crate::containment::cgroup::fault::set_force_child_pidfd_failure(false);
    let pid = child.id();
    let pidfd = pidfd_of(pid);
    drop(child);

    drop(leaf);

    assert!(
        crate::containment::cgroup::fault::take_reaped_orphans().contains(&(pid, Some(libc::SIGKILL))),
        "the child must be killed through its /proc directory"
    );
    assert!(reaped(&pidfd), "and reaped");
}

/// An intent that carries no handle on its sender — neither a pidfd nor a `/proc` directory — names
/// its child by a number alone, which `std` may have freed by reaping it. It is never signalled, even
/// when the number names a live child of this process: that child is not this spawn's. Out of
/// reach, and said so.
#[cfg(target_os = "linux")]
#[test]
fn an_abandoned_intent_without_a_handle_is_never_signalled() {
    use std::io::{Read, Write};

    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-abandoned-no-handle");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path);
    let mut other = std::process::Command::new("/bin/cat")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn another child");
    // SAFETY: the leaf's channel is open; the intent claims `other`'s pid and carries no handle.
    unsafe {
        leaf.placement_slot()
            .send(crate::containment::cgroup::TAG_INTENT, other.id() as i32, 0, -1)
            .expect("send a forged intent");
    }

    assert!(matches!(
        leaf.abandon_before_verdict(),
        crate::containment::cgroup::Abandoned::OutOfReach
    ));
    assert_eq!(crate::containment::cgroup::fault::take_signalled_by_pid(), 0);

    let mut echo = [0u8; 1];
    other
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"x")
        .expect("write to the other child");
    other
        .stdout
        .as_mut()
        .expect("stdout")
        .read_exact(&mut echo)
        .expect("the other child must be alive to echo");
    other.kill().expect("kill the other child");
    other.wait().expect("reap the other child");
}

/// A real spawn whose child could open neither a pidfd nor its `/proc` directory sends an intent
/// with no handle: its abandoned child is out of reach, and is not signalled.
#[cfg(target_os = "linux")]
#[test]
fn an_abandoned_child_with_no_handle_on_itself_is_out_of_reach() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-abandoned-no-handle-spawn");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path);
    // Inherited by the child forked from this thread, which takes them.
    crate::containment::cgroup::fault::set_force_child_pidfd_failure(true);
    crate::containment::cgroup::fault::set_force_child_proc_dir_failure(true);
    let mut child = spawn_placing(&leaf, &["/bin/sleep", "300"], true, std::process::Stdio::null());
    crate::containment::cgroup::fault::set_force_child_pidfd_failure(false);
    crate::containment::cgroup::fault::set_force_child_proc_dir_failure(false);

    assert!(matches!(
        leaf.abandon_before_verdict(),
        crate::containment::cgroup::Abandoned::OutOfReach
    ));
    assert_eq!(crate::containment::cgroup::fault::take_signalled_by_pid(), 0);
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "the child was not signalled"
    );
    child.kill().expect("kill the child");
    child.wait().expect("reap the child");
}

/// `std` reaps the child of a spawn it failed before returning the error, freeing its pid. The
/// abandoned exchange then holds that child's `/proc` directory, which no longer opens anything:
/// the child is gone, and nothing is signalled — whatever process the number names by now.
#[cfg(target_os = "linux")]
#[test]
fn an_abandoned_child_std_already_reaped_is_never_signalled() {
    use std::io::Write;
    use std::os::fd::AsRawFd;

    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-abandoned-reaped");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path);
    let slot = leaf.placement_slot();
    let (gate_read, mut gate_write) = std::io::pipe().expect("open the gate");
    let gate = gate_read.as_raw_fd();
    crate::containment::cgroup::fault::set_force_child_pidfd_failure(true);
    let pid = fork_running(move || {
        // SAFETY: this child's inherited copy of the channel's child end.
        let _ = unsafe { slot.send_intent() };
        block_on(gate);
    });
    crate::containment::cgroup::fault::set_force_child_pidfd_failure(false);
    gate_write.write_all(b"x").expect("release the child");
    // Reaped as `std` reaps it: before the exchange is abandoned.
    reap(pid);

    assert!(matches!(
        leaf.abandon_before_verdict(),
        crate::containment::cgroup::Abandoned::Ended
    ));
    assert_eq!(crate::containment::cgroup::fault::take_signalled_by_pid(), 0);
    assert_eq!(crate::containment::cgroup::fault::take_reaped_orphans(), Vec::new());
}

/// A spawn abandoned before its child sent anything cannot tell whether it forked: a child that
/// exists exits at its first send, but nothing holds its pid to reap it. That is not `Ended`.
#[cfg(target_os = "linux")]
#[test]
fn an_abandoned_spawn_whose_child_sent_nothing_may_leave_it_unreaped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-abandoned-silent");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path.clone());

    assert!(matches!(
        leaf.abandon_before_verdict(),
        crate::containment::cgroup::Abandoned::MaybeUnreaped
    ));
    assert!(!leaf_path.exists(), "the empty leaf is removed");
    assert_eq!(crate::containment::cgroup::fault::take_signalled_by_pid(), 0);
}

/// A child reaped between the check that it lives and the kill — only by a reaper the crate's
/// contract forbids — is signalled through its handle, which now names nothing: no other process
/// can be hit. The kill finds it gone, and nothing is reaped twice.
#[cfg(target_os = "linux")]
#[test]
fn a_child_reaped_between_the_check_and_the_kill_is_not_signalled_by_number() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-abandoned-window");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path);
    let child = spawn_placing(&leaf, &["/bin/true"], false, std::process::Stdio::null());
    let pid = child.id();
    drop(child);
    crate::containment::cgroup::fault::set_between_check_and_kill(move || reap(pid));

    assert!(matches!(
        leaf.abandon_before_verdict(),
        crate::containment::cgroup::Abandoned::Ended
    ));
    assert_eq!(crate::containment::cgroup::fault::take_signalled_by_pid(), 0);
    assert_eq!(crate::containment::cgroup::fault::take_reaped_orphans(), Vec::new());
}

/// An abandoned child cosca may not kill is handed back, held by its handle, and never left a
/// zombie: whoever holds it reaps it on its exit, however that comes — here, the test's own kill.
/// No thread of cosca's waits for it.
#[cfg(target_os = "linux")]
#[test]
fn an_abandoned_child_that_refuses_the_kill_is_handed_back() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-abandoned-refuses");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path);
    // Its placement write fails, so the leaf does not hold it either.
    let child = spawn_placing(&leaf, &["/bin/sleep", "300"], true, std::process::Stdio::null());
    let pid = child.id();
    let pidfd = pidfd_of(pid);
    drop(child);
    crate::containment::cgroup::fault::set_force_child_kill_denied(true);

    let crate::containment::cgroup::Abandoned::HandedBack { kill, child } = leaf.abandon_before_verdict() else {
        panic!("the child that refused the kill must be handed back");
    };
    assert_eq!(kill.raw_os_error(), Some(libc::EPERM));
    assert_eq!(child.pid(), pid, "the handed-back child is the abandoned one");
    assert!(!reaped(&pidfd), "the child refused the kill and is still running");

    // Its pid is pinned while it is unreaped.
    rustix::process::pidfd_send_signal(&pidfd, rustix::process::Signal::KILL).expect("kill the child");
    child.wait().expect("wait for the handed-back child");
    assert!(reaped(&pidfd), "the child must be reaped once it exits");
}

/// An abandoned child is killed as the process group it leads: what it forked after `exec` is in
/// that group, whether or not it is in the leaf. Here the leaf's own kill kills nothing (a
/// directory, not a cgroup), so only the group kill can end the descendant, which holds the
/// child's stdout: reading it to EOF proves both dead. A regression hangs this test on the read.
#[cfg(target_os = "linux")]
#[test]
fn an_abandoned_child_is_killed_with_the_group_it_leads() {
    use std::io::{BufRead, Read};

    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-abandoned-group");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path);
    let mut child = spawn_placing(
        &leaf,
        &["/bin/sh", "-c", "sleep 300 & echo forked; wait"],
        false,
        std::process::Stdio::piped(),
    );
    let mut stdout = std::io::BufReader::new(child.stdout.take().expect("stdout"));
    let mut line = String::new();
    stdout.read_line(&mut line).expect("read the child's line");
    assert_eq!(
        line, "forked\n",
        "the descendant must exist before the spawn is abandoned"
    );
    drop(child);

    drop(leaf);

    let mut rest = Vec::new();
    stdout
        .read_to_end(&mut rest)
        .expect("read to EOF: every process holding stdout is dead");
}

/// A child cosca gives up on is killed as a group: between the last look at its report and the
/// kill it can report, exec, and fork, and what it forks is in its process group, not the leaf.
/// Each process in the tree holds the child's stdout, so reading it to EOF proves all are dead.
/// A regression hangs this test on the read.
#[cfg(target_os = "linux")]
#[test]
fn fail_closed_kills_the_childs_whole_process_group() {
    use std::io::{BufRead, Read};
    use std::os::unix::process::CommandExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-abandon-group");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::create_dir(leaf_path.join("occupant")).expect("make the leaf unremovable");
    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path);
    // The child leads its own group, as a contained child does, and forks a descendant into it.
    let mut child = std::process::Command::new("/bin/sh")
        .args(["-c", "sleep 300 & echo forked; wait"])
        .stdout(std::process::Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("spawn");
    let mut stdout = std::io::BufReader::new(child.stdout.take().expect("stdout"));
    let mut line = String::new();
    stdout.read_line(&mut line).expect("read the child's line");
    assert_eq!(
        line, "forked\n",
        "the descendant must exist before the child is given up on"
    );

    crate::containment::cgroup::fault::set_force_pidfd_failure(true);
    assert!(leaf.take_placement(child.id()).is_err(), "the spawn must fail");
    let mut rest = Vec::new();
    stdout
        .read_to_end(&mut rest)
        .expect("read to EOF: every process holding stdout is dead");
    child.wait().expect("reap the child");
}

/// A child cosca may not signal — it exec'd a setuid program — cannot be waited out: `fail_closed`
/// would block for that program's whole life. It exec'd, so its report is final: the spawn fails
/// at once, and the child, which cosca could not kill, is left running.
#[cfg(target_os = "linux")]
#[test]
fn fail_closed_does_not_wait_on_a_child_it_may_not_signal() {
    use std::io::{Read, Write};
    use std::os::unix::process::CommandExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-abandon-eperm");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::create_dir(leaf_path.join("occupant")).expect("make the leaf unremovable");
    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path);
    // `cat` echoes, so a round trip through it proves it alive.
    let mut child = std::process::Command::new("/bin/cat")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("spawn");

    crate::containment::cgroup::fault::set_force_pidfd_failure(true);
    crate::containment::cgroup::fault::set_force_signal_denied(true);
    let err = match leaf.take_placement(child.id()) {
        Err(e) => e,
        Ok(verdict) => panic!("an undecidable verdict must fail the spawn, got {verdict:?}"),
    };
    assert!(
        !crate::containment::cgroup::fault::signal_denied_armed(),
        "the seam must be consumed by the kill"
    );
    assert!(err.to_string().contains("could not be signalled"), "got {err}");

    let mut echo = [0u8; 1];
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"x")
        .expect("write to the child");
    child
        .stdout
        .as_mut()
        .expect("stdout")
        .read_exact(&mut echo)
        .expect("the child must be alive: it could not be signalled");
    assert_eq!(&echo, b"x");
    child.kill().expect("kill the child");
    child.wait().expect("reap the child");
}

/// An occupied leaf whose child's membership cannot be read is undecided, not "not the child":
/// the spawn fails closed — its child killed — and the read's own error is the reason given.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn cgroup_without_a_pidfd_an_unreadable_membership_fails_closed() {
    use std::os::unix::process::{CommandExt, ExitStatusExt};

    use crate::containment::TreeDrain;

    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "requires COSCA_TEST_CGROUP and a delegated cgroup"
    );
    let mut leaf = crate::containment::cgroup::try_create_leaf().expect("a delegated cgroup v2 leaf");
    // The child reports through a channel of its own, so the leaf's has nothing queued.
    let own = crate::containment::cgroup::ReportChannel::new().expect("open the child's channel");
    let (procs_fd, slot) = (leaf.procs_fd(), own.slot());
    let mut cmd = std::process::Command::new("/bin/sleep");
    cmd.arg("300").process_group(0);
    // SAFETY: the closure runs between fork and exec, and performs only async-signal-safe calls
    // on descriptors `leaf` and `own` keep open across the spawn.
    unsafe { cmd.pre_exec(move || crate::containment::cgroup::place_self_in_cgroup_pre_exec(procs_fd, slot)) };
    let mut child = cmd.spawn().expect("spawn the child");

    crate::containment::cgroup::fault::set_force_pidfd_failure(true);
    crate::containment::cgroup::fault::set_force_membership_unreadable(true);
    let err = match leaf.take_placement(child.id()) {
        Err(e) => e,
        Ok(verdict) => panic!("an unreadable membership must fail closed, got {verdict:?}"),
    };
    assert!(
        !crate::containment::cgroup::fault::membership_unreadable_armed(),
        "the seam must be consumed by the membership read"
    );
    assert!(err.to_string().contains("could not be read"), "got {err}");
    assert_eq!(
        child.wait().expect("reap the child").signal(),
        Some(libc::SIGKILL),
        "the child must be killed"
    );
    assert_eq!(leaf.wait_drained(None).expect("drain"), TreeDrain::AllMembersExited);
}

/// Only a write of the whole `"0"` is a placement. A write that returns without writing it — 0,
/// where no errno is set — is a failed placement, reported as `EIO`, never as `Placed`.
#[cfg(target_os = "linux")]
#[test]
fn placement_hook_reports_a_write_that_wrote_nothing_as_failed() {
    let channel = crate::containment::cgroup::ReportChannel::new().expect("open the report channel");
    let sink = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .expect("open /dev/null");
    let procs_fd = std::os::fd::IntoRawFd::into_raw_fd(sink);
    crate::containment::cgroup::fault::set_force_placement_write_result(0);
    // SAFETY: `procs_fd` is open and closed by the hook; the channel is open.
    let result = unsafe { crate::containment::cgroup::place_self_in_cgroup_pre_exec(procs_fd, channel.slot()) };
    assert!(
        result.is_ok(),
        "a failed placement must not abort the spawn: {result:?}"
    );
    assert_eq!(channel.report_for_test(), PlacementReport::WriteFailed(libc::EIO));
}

/// `rmdir` refuses a leaf that holds a child cgroup with the same `EBUSY` it gives a populated
/// one, and killing through the leaf removes no directory. A leaf dropped with its report in
/// flight must remove the empty child cgroups itself rather than kill-and-retry forever. A
/// regression hangs this test in `drop`.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires COSCA_TEST_CGROUP and a delegated cgroup"]
fn cgroup_drop_removes_a_leaf_holding_child_cgroups() {
    assert!(
        std::env::var_os("COSCA_TEST_CGROUP").is_some(),
        "requires COSCA_TEST_CGROUP and a delegated cgroup"
    );
    // Placed: killed through, drained, swept. Nothing received: swept without a kill.
    for placed in [true, false] {
        let leaf = crate::containment::cgroup::try_create_leaf().expect("a delegated cgroup v2 leaf");
        let leaf_path = leaf.leaf_path.clone();
        std::fs::create_dir_all(leaf_path.join("nested").join("deeper")).expect("create child cgroups");
        if placed {
            // SAFETY: the slot's channel lives as long as `leaf`.
            unsafe { leaf.placement_slot().report_placed_for_test() };
        }

        drop(leaf);

        assert!(
            !leaf_path.exists(),
            "placed: {placed}: the leaf and its child cgroups must be removed"
        );
    }
}

/// A child cosca may not signal, but whose report says `Placed`, is killed through its leaf — no
/// credential check stands in `cgroup.kill`'s way. The error must say so, not that it is left
/// running.
#[cfg(target_os = "linux")]
#[test]
fn fail_closed_reports_a_child_it_may_not_signal_as_killed_through_its_leaf_when_placed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-abandon-eperm-placed");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path.clone());
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("300")
        .spawn()
        .expect("spawn");
    let channel = leaf.report.take().expect("the channel");
    // SAFETY: `channel` is open.
    unsafe { channel.slot().report_placed_for_test() };

    crate::containment::cgroup::fault::set_force_signal_denied(true);
    let err = leaf.fail_closed(child.id(), channel, "the test cannot decide");
    let err = err.to_string();
    assert!(err.contains("killed through its leaf"), "got {err}");
    assert!(!err.contains("left running"), "got {err}");
    assert_eq!(
        std::fs::read_to_string(leaf_path.join("cgroup.kill")).expect("cgroup.kill"),
        "1"
    );

    child.kill().expect("kill the child");
    child.wait().expect("reap the child");
}

/// A child `fail_closed` may not signal, and whose report it has read, can still send: its report
/// is final only because nothing it sends later is accepted. Its late intent fails, so it exits with
/// `ABANDONED_EXIT` before touching the leaf, rather than enter a leaf the spawn was told it had not.
#[cfg(target_os = "linux")]
#[test]
fn a_send_after_fail_closed_read_the_report_is_refused() {
    use std::os::fd::{AsRawFd, IntoRawFd};

    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-fail-closed-late-send");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path);
    let channel = leaf.report.take().expect("the channel");
    let slot = channel.slot();
    let (procs_read, procs_write) = std::io::pipe().expect("a pipe standing in for cgroup.procs");
    let procs_fd = procs_write.into_raw_fd();
    let (gate_read, gate_write) = std::io::pipe().expect("open the gate");
    let gate = gate_read.as_raw_fd();
    let pid = fork_running(move || {
        block_on(gate);
        // SAFETY: this child's inherited copies of the channel's ends and the pipe.
        let _ = unsafe { crate::containment::cgroup::placement_hook(procs_fd, slot) };
    });
    // SAFETY: the parent's own copy, closed once.
    unsafe { libc::close(procs_fd) };
    drop(gate_read);

    crate::containment::cgroup::fault::set_force_signal_denied(true);
    crate::containment::cgroup::fault::set_after_final_read(move |pid| {
        let mut gate_write = gate_write;
        std::io::Write::write_all(&mut gate_write, b"x").expect("release the child");
        // Its exit, not its reaping: the test reaps it below.
        let pid = rustix::process::Pid::from_raw(pid as i32).expect("a positive pid");
        while let Err(rustix::io::Errno::INTR) = rustix::process::waitid(
            rustix::process::WaitId::Pid(pid),
            rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOWAIT,
        ) {}
    });
    let err = leaf.fail_closed(pid, channel, "the test cannot decide").to_string();
    assert!(err.contains("could not be signalled"), "got {err}");

    let mut status = 0;
    // SAFETY: `pid` is this process's own child; `status` is a valid, writable int.
    assert_eq!(unsafe { libc::waitpid(pid as i32, &mut status, 0) }, pid as i32);
    assert!(libc::WIFEXITED(status), "status {status:#x}");
    assert_eq!(libc::WEXITSTATUS(status), crate::containment::cgroup::ABANDONED_EXIT);
    assert_eq!(
        std::io::read_to_string(procs_read).expect("read the pipe"),
        "",
        "no placement write"
    );
}

/// After killing through a placed child's leaf, a drain `fail_closed` cannot watch is reported, as
/// `Drop`'s own kill-and-drain reports it — never dropped. A `cgroup.events` that is a directory
/// opens but cannot be read, so the watch fails for real.
#[cfg(target_os = "linux")]
#[test]
fn fail_closed_reports_a_drain_it_could_not_watch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-abandon-unwatchable");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::create_dir(leaf_path.join("cgroup.events")).expect("make cgroup.events unreadable");
    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path);
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("300")
        .spawn()
        .expect("spawn");
    let channel = leaf.report.take().expect("the channel");
    // SAFETY: `channel` is open.
    unsafe { channel.slot().report_placed_for_test() };

    let err = leaf
        .fail_closed(child.id(), channel, "the test cannot decide")
        .to_string();
    assert!(err.contains("drain could not be watched"), "got {err}");
    child.wait().expect("reap the child");
}

/// A leaf's name carries 64 random bits past the pid and sequence number, which repeat across
/// pid namespaces sharing a delegated parent, and across processes reusing a pid.
#[cfg(target_os = "linux")]
#[test]
fn leaf_names_carry_random_bits_past_the_pid_and_sequence() {
    let suffix = |name: String| {
        let parts = name.split('-').collect::<Vec<_>>();
        assert_eq!(parts.len(), 4, "cosca-<pid>-<seq>-<random>: {name}");
        assert_eq!((parts[0], parts[1]), ("cosca", std::process::id().to_string().as_str()));
        assert!(
            parts[3].len() == 16 && parts[3].bytes().all(|b| b.is_ascii_hexdigit()),
            "{name}"
        );
        parts[3].to_owned()
    };
    let a = suffix(crate::containment::cgroup::leaf_name().expect("a name"));
    let b = suffix(crate::containment::cgroup::leaf_name().expect("a name"));
    assert_ne!(a, b);
}

/// A failed kill of the process group an abandoned child leads is not silent: it is logged at
/// `debug`. The child's own kill still ends it, and it is still reaped.
#[cfg(target_os = "linux")]
#[test]
fn a_failed_group_kill_of_an_abandoned_child_is_logged() {
    crate::log_capture::install();
    let marker = "cosca-group-kill-fail-5e3d";
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-abandoned-group-kill-fails");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path);
    // Its placement write fails, so the leaf does not hold it either.
    let child = spawn_placing(&leaf, &["/bin/sleep", "300"], true, std::process::Stdio::null());
    let pidfd = pidfd_of(child.id());
    drop(child);
    let mark = crate::log_capture::mark();
    crate::containment::cgroup::fault::set_force_group_kill_failure(marker);

    let _ = leaf.abandon_before_verdict();
    assert_eq!(
        crate::containment::cgroup::fault::take_force_group_kill_failure(),
        None,
        "the group kill must be attempted"
    );
    assert_eq!(
        crate::log_capture::levels_since(mark, marker),
        vec![log::Level::Debug],
        "the failed group kill must be logged at debug"
    );
    assert!(reaped(&pidfd), "the child's own kill still ends it, and it is reaped");
}

/// A placed child that refuses its own kill is handed back even when the kill through its leaf
/// succeeds: that kill reaches only what is still in the leaf, and a child moved out — as
/// `pam_systemd` moves a `sudo -i` into its session scope — survives it, so a wait for it here
/// would last as long as it runs. Here the leaf is a directory, not a cgroup, so its kill succeeds
/// and kills nothing, as for a child that left.
#[cfg(target_os = "linux")]
#[test]
fn a_placed_child_that_refuses_the_kill_is_handed_back_though_its_leaf_was_killed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-abandoned-moved-out");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path);
    let child = spawn_placing(&leaf, &["/bin/sleep", "300"], false, std::process::Stdio::null());
    let pid = child.id();
    let pidfd = pidfd_of(pid);
    drop(child);
    crate::containment::cgroup::fault::set_force_child_kill_denied(true);

    let crate::containment::cgroup::Abandoned::HandedBack { child, .. } = leaf.abandon_before_verdict() else {
        panic!("the child that refused the kill must be handed back, not waited on");
    };
    assert!(!reaped(&pidfd), "the child survived the leaf's kill");
    rustix::process::pidfd_send_signal(&pidfd, rustix::process::Signal::KILL).expect("kill the child");
    child.wait().expect("wait for the handed-back child");
    assert!(reaped(&pidfd), "the child must be reaped once it exits");
}

/// A leaf whose child entered it, still occupied, as its `Drop` finds it: the directory holds a
/// file, so the removal fails and an armed `Drop` goes on to write `cgroup.kill`. Returns the leaf
/// and the path of that `cgroup.kill`.
#[cfg(target_os = "linux")]
fn occupied_entered_leaf(dir: &std::path::Path) -> (crate::containment::cgroup::CgroupLeaf, std::path::PathBuf) {
    let leaf_path = dir.join("cosca-occupied");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("occupant"), b"").expect("occupy the leaf");
    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path.clone());
    leaf.report = None;
    leaf.entered = true;
    (leaf, leaf_path.join("cgroup.kill"))
}

/// The control: an armed leaf's `Drop` kills through an occupied leaf it cannot remove.
#[cfg(target_os = "linux")]
#[test]
fn an_armed_leaf_kills_through_itself_on_drop() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (leaf, kill) = occupied_entered_leaf(dir.path());
    drop(leaf);
    assert_eq!(std::fs::read(&kill).expect("cgroup.kill written"), b"1");
}

/// `Child::detach` disarms its leaf: the leaf's `Drop` neither kills nor waits, and the leaf is
/// left for the delegated parent's owner to remove.
#[cfg(target_os = "linux")]
#[test]
fn detach_leaves_a_contained_child_running() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (leaf, kill) = occupied_entered_leaf(dir.path());
    let (child, stdin) = cat_child();
    let child = contained_child(child, leaf);
    child.detach();
    assert!(!kill.exists(), "a detached child's leaf must not be killed through");
    drop(stdin);
}

/// `Unreaped::leak` disarms the leaf it retains the same way: nothing the leaked child leads is
/// killed.
#[cfg(target_os = "linux")]
#[test]
fn leaking_a_contained_child_leaves_it_running() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (leaf, kill) = occupied_entered_leaf(dir.path());
    let (child, stdin) = cat_child();
    let pid = child.id();
    crate::Unreaped::with_retained(
        crate::child::unreaped::Held::Std(child),
        Some(crate::child::unreaped::Retained {
            attached: crate::containment::Attached::Cgroup(leaf),
        }),
    )
    .leak();
    assert!(!kill.exists(), "a leaked child's leaf must not be killed through");
    drop(stdin);
    reap(pid);
}

/// A plain child blocked on stdin, and that stdin.
#[cfg(target_os = "linux")]
fn cat_child() -> (std::process::Child, std::process::ChildStdin) {
    let mut child = {
        let _guard = crate::child::spawn::spawn_lock();
        std::process::Command::new("/bin/cat")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn cat")
    };
    let stdin = child.stdin.take().expect("stdin");
    (child, stdin)
}

/// `child` as a cosca `Child` contained by `leaf`.
#[cfg(target_os = "linux")]
fn contained_child(child: std::process::Child, leaf: crate::containment::cgroup::CgroupLeaf) -> crate::Child {
    let crate::identity::Resolved::Found(id) = crate::identity::ProcessId::of(child.id()) else {
        panic!("an unreaped child resolves");
    };
    crate::Child::from_parts(
        crate::child::proc_handle::ProcHandle::Std(shared_child::SharedChild::new(child).expect("adopt")),
        id,
        Default::default(),
        true,
        crate::containment::Attachment {
            containment: crate::containment::Containment::CgroupV2,
            attached: crate::containment::Attached::Cgroup(leaf),
            graceful: crate::graceful::GracefulMechanism::Process,
        },
    )
}

/// A child that could send no pidfd on itself — only its `/proc` directory — and refuses the kill
/// is still handed back with a pidfd, opened on the pid that directory proved its own, so an async
/// holder can await it.
#[cfg(target_os = "linux")]
#[test]
fn a_handed_back_child_that_sent_no_pidfd_is_given_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-abandoned-no-pidfd");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path);
    // Inherited by the child forked from this thread, which takes it.
    crate::containment::cgroup::fault::set_force_child_pidfd_failure(true);
    let child = spawn_placing(&leaf, &["/bin/sleep", "300"], true, std::process::Stdio::null());
    crate::containment::cgroup::fault::set_force_child_pidfd_failure(false);
    let pid = child.id();
    let pidfd = pidfd_of(pid);
    drop(child);
    crate::containment::cgroup::fault::set_force_child_kill_denied(true);

    let crate::containment::cgroup::Abandoned::HandedBack { child, .. } = leaf.abandon_before_verdict() else {
        panic!("the child that refused the kill must be handed back");
    };
    // Read before the child is ended, asserted after: a failure then does not leave the
    // handed-back child's drop waiting out the sleep.
    let holds_pidfd = child.holds_pidfd();
    rustix::process::pidfd_send_signal(&pidfd, rustix::process::Signal::KILL).expect("kill the child");
    child.wait().expect("wait for the handed-back child");
    assert!(reaped(&pidfd), "the child must be reaped once it exits");
    assert!(
        holds_pidfd,
        "the handed-back child must hold a pidfd to be awaited through"
    );
}

/// A child already exited when its kill is refused is reaped by its one check, not handed back:
/// only a child that check finds running is. Here it is a zombie before the leaf is abandoned.
#[cfg(target_os = "linux")]
#[test]
fn an_abandoned_child_already_exited_when_its_kill_is_refused_is_reaped_not_handed_back() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-abandoned-zombie-refuses");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let mut leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path);
    let child = spawn_placing(&leaf, &["/bin/true"], true, std::process::Stdio::null());
    let pid = child.id();
    let pidfd = pidfd_of(pid);
    drop(child);
    crate::child::unreaped::block_until_reapable(pid).expect("wait until it is a zombie");
    crate::containment::cgroup::fault::set_force_child_kill_denied(true);

    let abandoned = leaf.abandon_before_verdict();
    assert!(
        matches!(abandoned, crate::containment::cgroup::Abandoned::Ended),
        "an exited child must be reaped, not handed back: {abandoned:?}"
    );
    assert!(reaped(&pidfd), "its one check reaped it");
}

/// A leaf dropped with its exchange still open never waits in `Drop` for a child that refused its
/// kill: every spawn path abandons the exchange itself, and hands such a child back, so reaching
/// one here breaks that contract. It is asserted in debug builds and leaked with a warning — never
/// waited for, which could block a runtime worker for as long as the child runs.
#[cfg(target_os = "linux")]
#[test]
fn dropping_a_leaf_never_waits_for_a_child_that_refused_its_kill() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-dropped-refuses");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    let leaf = crate::containment::cgroup::CgroupLeaf::for_test_at(leaf_path);
    let child = spawn_placing(&leaf, &["/bin/sleep", "300"], true, std::process::Stdio::null());
    let pid = child.id();
    let pidfd = pidfd_of(pid);
    drop(child);
    crate::containment::cgroup::fault::set_force_child_kill_denied(true);

    let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(leaf)));
    assert_eq!(
        dropped.is_err(),
        cfg!(debug_assertions),
        "asserted in exactly the builds that keep it"
    );
    assert!(!reaped(&pidfd), "the child was left running, not waited for");
    rustix::process::pidfd_send_signal(&pidfd, rustix::process::Signal::KILL).expect("kill the child");
    reap(pid);
}

/// Leaking a `cosca::tokio::Unreaped` while a cancelled wait's blocking reap holds the child still
/// disarms the leaf it retains, and says so: nothing the leaked child leads is killed. Dropping the
/// runtime ends the blocking reap — run, or cancelled before it ran — so what it retained has been
/// released, disarmed or not, by the time this test looks.
#[cfg(all(target_os = "linux", feature = "tokio"))]
#[test]
fn leaking_during_a_blocking_reap_disarms_the_retained_leaf() {
    crate::log_capture::install();
    // Before the child's stdin, so a failing assertion drops that first: the runtime's drop waits
    // for a blocking reap that waits for the child to exit.
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let dir = tempfile::tempdir().expect("tempdir");
    let (leaf, kill) = occupied_entered_leaf(dir.path());
    let (child, stdin) = cat_child();
    let pid = child.id();
    let pidfd = pidfd_of(pid);
    let mark = crate::log_capture::mark();
    runtime.block_on(async {
        let mut unreaped = crate::tokio::Unreaped::with_retained(
            crate::child::unreaped::Held::Std(child),
            Some(crate::child::unreaped::Retained {
                attached: crate::containment::Attached::Cgroup(leaf),
            }),
        );
        crate::tokio::unreaped::fault::set_force_not_yet_reapable();
        {
            use std::future::Future;
            let mut wait = std::pin::pin!(unreaped.wait());
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(wait.as_mut().poll(&mut cx).is_pending(), "the child is still running");
        }
        assert!(
            unreaped.hands_child_to_blocking_task(),
            "the blocking task owns the child now"
        );
        unreaped.leak();
    });
    assert!(
        crate::log_capture::contains_since(mark, &format!("leaking unkillable child {pid}")),
        "a leak is logged"
    );
    drop(stdin);
    drop(runtime);
    assert!(!kill.exists(), "a leaked child's leaf must not be killed through");
    if !reaped(&pidfd) {
        reap(pid);
    }
}

/// Leaking a `cosca::tokio::Unreaped` whose blocking reap has finished, unawaited, disarms the leaf
/// it retains, and says the child was already reaped.
#[cfg(all(target_os = "linux", feature = "tokio"))]
#[test]
fn leaking_after_a_blocking_reap_finished_disarms_the_retained_leaf() {
    crate::log_capture::install();
    // Before the child's stdin, so a failing assertion drops that first: the runtime's drop waits
    // for a blocking reap that waits for the child to exit.
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let dir = tempfile::tempdir().expect("tempdir");
    let (leaf, kill) = occupied_entered_leaf(dir.path());
    let (child, stdin) = cat_child();
    let pid = child.id();
    let pidfd = pidfd_of(pid);
    let mark = crate::log_capture::mark();
    runtime.block_on(async {
        let mut unreaped = crate::tokio::Unreaped::with_retained(
            crate::child::unreaped::Held::Std(child),
            Some(crate::child::unreaped::Retained {
                attached: crate::containment::Attached::Cgroup(leaf),
            }),
        );
        crate::tokio::unreaped::fault::set_force_not_yet_reapable();
        {
            use std::future::Future;
            let mut wait = std::pin::pin!(unreaped.wait());
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(wait.as_mut().poll(&mut cx).is_pending(), "the child is still running");
        }
        drop(stdin);
        unreaped.block_until_blocking_reap_finished();
        unreaped.leak();
    });
    assert!(
        crate::log_capture::contains_since(mark, &format!("leaking unkillable child {pid}, already reaped")),
        "the leak says the child was already reaped"
    );
    assert!(!kill.exists(), "a leaked child's leaf must not be killed through");
    assert!(reaped(&pidfd), "its blocking reap reaped it");
}
