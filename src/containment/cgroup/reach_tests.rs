//! Placing a task in a leaf's subtree by its cgroup id, and deciding before a spawn whether a front
//! can be placed. Unprivileged: the ids are forced, and the probe reads a child of this process.

use std::os::fd::{AsFd as _, OwnedFd};
use std::sync::Arc;

use super::ProbeEnd;
use super::{dying_in, front_placement, Subtree};
use crate::containment::cgroup::fault::{self, ProbeStep};
use crate::containment::cgroup::test_support::{alone, kill_record};
use crate::identity::{FakeKernel, HostKernel, Kernel, ProcDir, ViewUnreadable, UNREADABLE_STATUS_REASON};
use crate::log_capture::warns_since;
use crate::test_groups::{cgroup, Group};

/// A cgroup id with bits above the low 32, as kernfs gives once its 32-bit counter wraps.
const HIGH: u64 = 0x1_0000_0007;

fn own_pidfd() -> OwnedFd {
    rustix::process::pidfd_open(rustix::process::getpid(), rustix::process::PidfdFlags::empty()).expect("pidfd_open")
}

fn subtree(leaf_id: u64, killed: bool) -> Subtree {
    Subtree::new(
        Some(leaf_id),
        None,
        None,
        crate::containment::cgroup::Swept::default(),
        super::PlacedAtRemoval::default(),
        kill_record(killed),
    )
}

/// A subtree whose leaf directory is a stand-in, an ordinary empty directory with `stat` as its
/// `cgroup.stat` (none: `None`), with a path, so a task it cannot place is placed through `/proc`.
/// The directory is returned to outlive the subtree.
fn stand_in_subtree(stat: Option<&str>) -> (Subtree, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    // A live cgroup's file, which the walk reads to tell its root was not removed.
    std::fs::write(dir.path().join("cgroup.events"), "populated 0\n").expect("write the stand-in cgroup.events");
    if let Some(stat) = stat {
        std::fs::write(dir.path().join("cgroup.stat"), stat).expect("write the stand-in cgroup.stat");
    }
    let fd = rustix::fs::open(
        dir.path(),
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .expect("open the stand-in leaf");
    (subtree_of(fd, crate::containment::cgroup::Swept::default()), dir)
}

/// A subtree of the leaf `fd` holds, with a path, killed through.
fn subtree_of(fd: OwnedFd, swept: crate::containment::cgroup::Swept) -> Subtree {
    Subtree::new(
        Some(HIGH),
        Some(Arc::new(fd)),
        Some("/stand-in-leaf".to_owned()),
        swept,
        super::PlacedAtRemoval::default(),
        kill_record(true),
    )
}

/// Whether `leaf` holds this process, read as a task whose pidfd's cgroup id is `id`, with `/proc`
/// hidden: only the id, the sweep's record and the walk may place it.
fn holds_hidden(leaf: &Subtree, id: u64) -> std::io::Result<bool> {
    let _id = fault::force_pidfd_cgroup_id(id);
    let _hidden = fault::hide_proc();
    let pidfd = own_pidfd();
    leaf.holds(std::process::id(), Some(pidfd.as_fd()))
}

/// A task is in the leaf only when all 64 bits of its cgroup id are the leaf's: an id equal in
/// its low 32 bits names another cgroup.
#[skuld::test]
fn a_subtree_compares_all_64_bits_of_a_cgroup_id() {
    let pidfd = own_pidfd();
    let pid = std::process::id();
    let leaf = subtree(HIGH, false);
    {
        let _id = fault::force_pidfd_cgroup_id(HIGH);
        assert!(leaf.holds(pid, Some(pidfd.as_fd())).expect("a forced id"));
    }
    {
        let _id = fault::force_pidfd_cgroup_id(HIGH & u64::from(u32::MAX));
        assert!(
            !leaf.holds(pid, Some(pidfd.as_fd())).expect("a forced id"),
            "an id equal only in its low 32 bits is another cgroup"
        );
    }
    let low = subtree(HIGH & u64::from(u32::MAX), false);
    let _id = fault::force_pidfd_cgroup_id(HIGH);
    assert!(!low.holds(pid, Some(pidfd.as_fd())).expect("a forced id"));
}

/// A kill reached a task only if the leaf's own kill landed: a task in the leaf whose kill failed
/// was reached by nothing.
#[skuld::test]
fn a_subtree_reached_a_task_only_once_its_kill_landed() {
    let pidfd = own_pidfd();
    let pid = std::process::id();
    let _id = fault::force_pidfd_cgroup_id(HIGH);
    assert!(subtree(HIGH, false)
        .holds(pid, Some(pidfd.as_fd()))
        .expect("a forced id"));
    assert!(!subtree(HIGH, false)
        .reached_by(pid, Some(pidfd.as_fd()), None)
        .expect("a forced id"));
    assert!(subtree(HIGH, true)
        .reached_by(pid, Some(pidfd.as_fd()), None)
        .expect("a forced id"));
}

/// With `PIDFD_GET_INFO`, fronts are placeable whatever `/proc` hides.
#[skuld::test]
fn with_pidfd_info_a_front_is_placeable_whatever_proc_hides() {
    let _id = fault::force_pidfd_cgroup_id(HIGH);
    let _hidden = fault::hide_proc();
    front_placement(&HostKernel, || Ok(HIGH)).expect("placeable by a pidfd's cgroup id");
}

/// Without `PIDFD_GET_INFO`, a `/proc` that shows a process this one may not trace makes fronts
/// placeable. The probe is real: a non-dumpable child of this process, read and reaped.
///
/// A precondition, declared by the cgroup group: the lane runs as root, whose `CAP_SYS_PTRACE` reads
/// a non-dumpable child's cgroup through `/proc` whatever its mount options (`hidepid` hides it from
/// anyone else). The refusal where `/proc` hides it is tested by forcing it.
#[skuld::test]
fn cgroup_without_pidfd_info_a_proc_that_shows_untraceable_processes_places_fronts(#[fixture(cgroup)] _group: &Group) {
    let _missing = fault::miss_pidfd_info();
    front_placement(&HostKernel, || Ok(HIGH)).expect("the lane's /proc shows its root every process");
}

/// Without `PIDFD_GET_INFO`, a `/proc` that hides a process this one may not trace refuses an
/// elevated, contained spawn, naming `hidepid`.
#[skuld::test]
fn without_pidfd_info_a_hidepid_proc_refuses_naming_hidepid() {
    let _missing = fault::miss_pidfd_info();
    let _hidden = fault::hide_proc();
    match front_placement(&HostKernel, || Ok(HIGH)) {
        Err(err @ crate::error::Error::Unsupported { .. }) => {
            let crate::error::Error::Unsupported { detail, .. } = &err else {
                unreachable!()
            };
            assert!(detail.contains("hidepid"), "{detail}");
            assert!(detail.contains("before anything is spawned"), "{detail}");
            assert_eq!(crate::error::first_os_code(&err), Some(libc::ENOENT), "{err:?}");
            let named = std::io::Error::from_raw_os_error(libc::ENOENT).to_string();
            assert!(!detail.contains(&named), "{detail}");
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

/// Without `PIDFD_GET_INFO`, a `/proc` of an outer pid namespace refuses, naming that, not
/// `hidepid`.
#[skuld::test]
fn without_pidfd_info_a_diverged_proc_view_refuses_naming_the_view() {
    let _missing = fault::miss_pidfd_info();
    let kernel = FakeKernel::over(&HostKernel).diverged_view();
    match front_placement(&kernel, || Ok(HIGH)) {
        Err(crate::error::Error::Unsupported { detail, .. }) => {
            assert!(detail.contains("an outer pid namespace's"), "{detail}");
            assert!(!detail.contains("hidepid"), "{detail}");
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

/// Without `PIDFD_GET_INFO`, an unassessable `/proc` view refuses, naming that, not `hidepid`.
#[skuld::test]
fn without_pidfd_info_an_unassessable_proc_view_refuses_naming_the_view() {
    let _missing = fault::miss_pidfd_info();
    let kernel = FakeKernel::over(&HostKernel).unreadable_view();
    match front_placement(&kernel, || Ok(HIGH)) {
        Err(crate::error::Error::Unsupported { detail, .. }) => {
            assert!(
                detail.contains(&format!("could not be established ({UNREADABLE_STATUS_REASON})")),
                "{detail}"
            );
            assert!(!detail.contains("hidepid"), "{detail}");
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

/// The probe's socket lands on whatever descriptors are free, std's own included: with fds 0 and 1
/// closed it still reads, and still refuses where `/proc` hides. Runs in a process of its own:
/// closing 0 and 1 is process-wide. Its precondition is the cgroup group's root, as above.
#[skuld::test]
fn cgroup_the_placement_probe_answers_with_fds_0_and_1_closed(#[fixture(cgroup)] _group: &Group) {
    use crate::test_own_process::{own_process, test_path};
    use crate::test_spawn::spawn;
    use crate::test_stdio::RestoreStdio;

    let Some(done) = own_process(
        test_path!(cgroup_the_placement_probe_answers_with_fds_0_and_1_closed),
        spawn,
    ) else {
        return;
    };
    let _missing = fault::miss_pidfd_info();
    let restore = RestoreStdio::close(&done, &[0, 1]);
    let shown = front_placement(&HostKernel, || Ok(HIGH));
    let hidden = {
        let _hidden = fault::hide_proc();
        front_placement(&HostKernel, || Ok(HIGH))
    };
    drop(restore);
    shown.expect("this test's /proc hides nothing");
    assert!(
        matches!(hidden, Err(crate::error::Error::Unsupported { .. })),
        "{hidden:?}"
    );
}

/// `cgroup.stat`'s count of removed cgroups not yet freed.
#[skuld::test]
fn dying_cgroups_are_read_from_cgroup_stat() {
    assert_eq!(dying_in("nr_descendants 0\nnr_dying_descendants 0\n"), Some(0));
    assert_eq!(
        dying_in("nr_descendants 2\nnr_dying_descendants 1\nnr_subsys_cpu 3\n"),
        Some(1)
    );
    assert_eq!(dying_in("nr_descendants 0\n"), None);
    assert_eq!(dying_in("nr_dying_descendants_x 0\n"), None);
}

/// A task in a cgroup nested under the leaf is in the subtree, found by the walk with no `/proc`.
#[skuld::test]
fn cgroup_a_task_in_a_nested_cgroup_is_found_by_the_walk(#[fixture(cgroup)] _group: &Group) {
    use crate::containment::cgroup::dir_walk_tests::{id_at, Scratch};
    let scratch = Scratch::new("reach-nested");
    let nested = id_at(&scratch.make("a/b/c"));
    scratch.make("d");
    let leaf = subtree_of(scratch.fd(), crate::containment::cgroup::Swept::default());
    assert!(holds_hidden(&leaf, nested).expect("no /proc read"));
}

/// A task in a cgroup the walk finds nowhere, under a leaf with no cgroup removed but not freed,
/// is outside it, read with no `/proc`.
#[skuld::test]
fn a_task_the_walk_finds_nowhere_is_outside() {
    let (leaf, _dir) = stand_in_subtree(Some("nr_descendants 0\nnr_dying_descendants 0\n"));
    assert!(!holds_hidden(&leaf, HIGH + 1).expect("no /proc read"));
}

/// A walk that finds nothing, but cannot show the cgroup is not one removed and not yet freed (the
/// leaf's `cgroup.stat` counts some, holds no count, or cannot be read), says so at `debug`, with the
/// cause; one that proves it says nothing. Mutant: "the unproven absence is silent".
#[skuld::test]
fn a_walk_that_finds_nothing_but_cannot_prove_it_says_why() {
    crate::log_capture::install();
    let says = "so it is not shown to be outside";
    for (stat, cause) in [
        (Some("nr_dying_descendants 2\n"), Some("2 are removed")),
        (Some("nr_descendants 0\n"), Some("an unknown number")),
        (None, Some("cgroup.stat cannot be read")),
        (Some("nr_dying_descendants 0\n"), None),
    ] {
        let (leaf, _dir) = stand_in_subtree(stat);
        let mark = crate::log_capture::mark();
        let held = holds_hidden(&leaf, HIGH + 1);
        let logs = crate::log_capture::records_since_on_current_thread(mark, says);
        match cause {
            Some(cause) => {
                held.expect_err("not shown outside, so placed through the hidden /proc");
                assert_eq!(logs.len(), 1, "{stat:?}: {logs:?}");
                assert_eq!(logs[0].0, log::Level::Debug, "{stat:?}");
                assert!(logs[0].1.contains(cause), "{stat:?}: {logs:?}");
            }
            None => {
                assert!(!held.expect("proven outside"));
                assert_eq!(logs, [], "{stat:?}");
            }
        }
    }
}

/// A task in a cgroup the sweep removed is in the subtree, once the leaf is gone too.
#[skuld::test]
fn cgroup_a_task_in_a_cgroup_the_sweep_removed_is_in_the_subtree(#[fixture(cgroup)] _group: &Group) {
    use crate::containment::cgroup::dir_walk_tests::{id_at, Scratch};
    let scratch = Scratch::new("reach-swept");
    let sub = id_at(&scratch.make("sub"));
    let leaf = crate::containment::cgroup::LeafDir::open_for_test(scratch.path());
    assert_eq!(leaf.remove_children().expect("sweep"), 1);
    leaf.rmdir().expect("remove the scratch leaf");
    let subtree = Subtree::new(
        Some(HIGH),
        Some(leaf.shared()),
        Some("/stand-in-leaf".to_owned()),
        leaf.swept(),
        super::PlacedAtRemoval::default(),
        kill_record(true),
    );
    assert!(holds_hidden(&subtree, sub).expect("no /proc read"));
}

/// A task the walk cannot place, because a cgroup under the leaf is removed but not freed, the
/// leaf's `cgroup.stat` cannot be read, or the walk itself cannot list a cgroup (the stand-in's
/// own directories are no cgroups), is placed through `/proc`, and where that is hidden, not at all.
#[skuld::test]
fn a_task_the_walk_cannot_place_is_placed_through_proc() {
    for (stat, sub) in [
        (Some("nr_dying_descendants 1\n"), false),
        (None, false),
        (Some("nr_dying_descendants 0\n"), true),
    ] {
        let (leaf, dir) = stand_in_subtree(stat);
        if sub {
            std::fs::create_dir(dir.path().join("sub")).expect("mkdir");
        }
        let err = holds_hidden(&leaf, HIGH + 1).expect_err("placed through the hidden /proc");
        assert!(err.to_string().contains("maybe one under it"), "{stat:?} {sub}: {err}");
        // What `/proc` answered is the cause, with its code.
        assert_eq!(
            crate::error::first_os_code(&err),
            Some(libc::ENOENT),
            "{stat:?} {sub}: {err:?}"
        );
    }
}

/// A task whose cgroup id is the one it had when it was found in the subtree is still where it was:
/// it is placed with no walk and no `/proc`. One whose id differs is placed as any other.
///
/// Mutant: the id seen at the listing is ignored, so every task under the leaf is walked for.
#[skuld::test]
fn a_task_still_in_the_cgroup_it_was_seen_in_is_placed_without_a_walk() {
    let (leaf, _dir) = stand_in_subtree(None);
    let _id = fault::force_pidfd_cgroup_id(HIGH + 1);
    let _hidden = fault::hide_proc();
    let pidfd = own_pidfd();
    let pid = std::process::id();

    let (inside, by) = leaf
        .holds_seen(pid, Some(pidfd.as_fd()), Some(HIGH + 1))
        .expect("no walk and no /proc read");
    assert!(inside);
    assert_eq!(
        by,
        Some(HIGH + 1),
        "the cgroup id that placed it is named, for a listing to keep"
    );
    assert!(leaf
        .reached_by(pid, Some(pidfd.as_fd()), Some(HIGH + 1))
        .expect("no walk and no /proc read"));
    leaf.holds_seen(pid, Some(pidfd.as_fd()), Some(HIGH + 2))
        .expect_err("a task that moved is placed by the walk, which cannot tell here");
    leaf.holds_seen(pid, Some(pidfd.as_fd()), None)
        .expect_err("a task not seen before is placed by the walk");
}

/// A task seen in a cgroup is placed by that id alone, so a leaf whose own id cannot be read (a
/// subtree with none) still places it without a walk or `/proc`; one that moved is placed through
/// `/proc`, hidden here, and so not at all.
///
/// Mutant: the shortcut is taken only when the leaf's id is known.
#[skuld::test]
fn a_task_still_in_the_cgroup_it_was_seen_in_is_placed_without_the_leafs_id() {
    let leaf = Subtree::new(
        None,
        None,
        Some("/stand-in-leaf".to_owned()),
        crate::containment::cgroup::Swept::default(),
        super::PlacedAtRemoval::default(),
        kill_record(true),
    );
    let _id = fault::force_pidfd_cgroup_id(HIGH + 1);
    let _hidden = fault::hide_proc();
    let pidfd = own_pidfd();
    let pid = std::process::id();

    let (inside, by) = leaf
        .holds_seen(pid, Some(pidfd.as_fd()), Some(HIGH + 1))
        .expect("no walk and no /proc read");
    assert!(inside);
    assert_eq!(by, Some(HIGH + 1), "the id that placed it is named");
    assert!(leaf
        .reached_by(pid, Some(pidfd.as_fd()), Some(HIGH + 1))
        .expect("no walk and no /proc read"));
    leaf.holds_seen(pid, Some(pidfd.as_fd()), Some(HIGH + 2))
        .expect_err("a task that moved is placed through the hidden /proc");
}

/// A task in a cgroup known to be under the leaf is placed by that id alone: a subtree with no leaf
/// id places it without a walk or `/proc`, and places one in no known cgroup through `/proc`,
/// hidden here, and so not at all.
///
/// Mutant: with no leaf id, the set of known cgroups is not asked.
#[skuld::test]
fn cgroup_a_task_in_a_known_cgroup_is_placed_without_the_leafs_id(#[fixture(cgroup)] _group: &Group) {
    use crate::containment::cgroup::dir_walk_tests::{id_at, Scratch};
    let scratch = Scratch::new("reach-known");
    let known_id = id_at(&scratch.make("a"));
    let known = crate::containment::cgroup::Swept::default();
    let (_, failure) = crate::containment::cgroup::procs_under(scratch.fd().as_fd(), &known);
    assert!(failure.is_none(), "{failure:?}");
    let leaf = Subtree::new(
        None,
        None,
        Some("/stand-in-leaf".to_owned()),
        known,
        super::PlacedAtRemoval::default(),
        kill_record(true),
    );
    let _hidden = fault::hide_proc();
    let pidfd = own_pidfd();
    let pid = std::process::id();

    {
        let _id = fault::force_pidfd_cgroup_id(known_id);
        let (inside, by) = leaf
            .holds_seen(pid, Some(pidfd.as_fd()), None)
            .expect("no walk and no /proc read");
        assert!(inside);
        assert_eq!(by, Some(known_id), "the known cgroup's id placed it");
    }
    let _id = fault::force_pidfd_cgroup_id(known_id + 1);
    leaf.holds_seen(pid, Some(pidfd.as_fd()), None)
        .expect_err("a task in no known cgroup is placed through the hidden /proc");
}

/// A task whose cgroup the leaf's set lacks is placed by a walk even when a cgroup under the leaf has
/// an unreadable id: the walk visits the task's cgroup before the unreadable one, and finds it.
///
/// Mutant: an unreadable id anywhere under the leaf skips the walk.
#[skuld::test]
fn cgroup_a_task_is_found_by_the_walk_before_a_cgroup_whose_id_cannot_be_read(#[fixture(cgroup)] _group: &Group) {
    use crate::containment::cgroup::dir_walk_tests::{id_at, Scratch};
    use crate::containment::cgroup::WalkStep;
    let scratch = Scratch::new("reach-unreadable");
    let target = id_at(&scratch.make("a"));
    scratch.make("a/b");
    let leaf = subtree_of(scratch.fd(), crate::containment::cgroup::Swept::default());
    let _refused = fault::fail_walk_step("./a/b", WalkStep::Id, libc::EIO);

    assert!(holds_hidden(&leaf, target).expect("found by the walk, no /proc read"));
}

/// A subtree with no leaf id, asked about a task seen in a cgroup, falls through to `/proc` when its
/// pidfd's cgroup id cannot be read, as it did with no `seen`: the refusal is not the placement's
/// failure. `/proc` is hidden, so the error that comes back is `/proc`'s, not the id's.
///
/// Mutant: an unreadable pidfd id fails the placement of a task seen in a cgroup.
#[skuld::test]
fn an_unreadable_pidfd_id_places_a_seen_task_through_proc_without_the_leafs_id() {
    let leaf = Subtree::new(
        None,
        None,
        Some("/stand-in-leaf".to_owned()),
        crate::containment::cgroup::Swept::default(),
        super::PlacedAtRemoval::default(),
        kill_record(true),
    );
    let _failing = fault::fail_pidfd_info();
    let _hidden = fault::hide_proc();
    let pidfd = own_pidfd();

    let e = leaf
        .holds_seen(std::process::id(), Some(pidfd.as_fd()), Some(HIGH))
        .expect_err("the hidden /proc places nothing");
    assert_eq!(
        e.raw_os_error(),
        Some(libc::ENOENT),
        "/proc's error, not the id's EIO: {e}"
    );
}

/// A subtree with no leaf id, asked about a task seen in a cgroup, takes `ESRCH` from the pidfd's
/// cgroup id as the task's exit, not a refusal: it propagates, so a caller reads the exit, and
/// `/proc` is not asked.
///
/// Mutant: `ESRCH` from the pidfd's id falls through to `/proc`.
#[skuld::test]
fn an_exited_task_has_no_pidfd_id_and_is_not_placed_through_proc_without_the_leafs_id() {
    let leaf = Subtree::new(
        None,
        None,
        Some("/stand-in-leaf".to_owned()),
        crate::containment::cgroup::Swept::default(),
        super::PlacedAtRemoval::default(),
        kill_record(true),
    );
    let _failing = fault::fail_pidfd_info_with(libc::ESRCH);
    let _hidden = fault::hide_proc();
    let pidfd = own_pidfd();

    let e = leaf
        .holds_seen(std::process::id(), Some(pidfd.as_fd()), Some(HIGH))
        .expect_err("the task's exit is the answer");
    assert_eq!(e.raw_os_error(), Some(libc::ESRCH), "the id's ESRCH, not /proc's: {e}");
}

/// The id a placement names is the one that placed the task: here the leaf's own.
#[skuld::test]
fn a_placement_by_the_leafs_own_id_names_it() {
    let _id = fault::force_pidfd_cgroup_id(HIGH);
    let pidfd = own_pidfd();

    let (inside, by) = subtree(HIGH, true)
        .holds_seen(std::process::id(), Some(pidfd.as_fd()), None)
        .expect("the leaf's own id");
    assert!(inside);
    assert_eq!(by, Some(HIGH), "the leaf's own id placed it");
}

/// `/proc`'s ` (deleted)` after the leaf's own path is the removed leaf or a live namesake beside
/// it: it is answered by the place recorded before the leaf's removal alone, undecidable without
/// one, and never the leaf when the task's pidfd gave another cgroup id. A path under the leaf is
/// under it either way.
#[skuld::test]
fn a_removed_leaf_is_answered_by_the_place_recorded_before_its_removal() {
    use super::names_leaf;
    let unasked = || -> Option<bool> { panic!("not asked") };
    let (leaf, deleted) = ("/a/leaf", "/a/leaf (deleted)");
    assert!(names_leaf(leaf, leaf, false, unasked).expect("decided"));
    assert!(names_leaf("/a/leaf/sub (deleted)", leaf, true, unasked).expect("decided"));
    assert!(
        names_leaf(deleted, leaf, false, || Some(true)).expect("decided"),
        "recorded in the leaf"
    );
    assert!(
        !names_leaf(deleted, leaf, false, || Some(false)).expect("decided"),
        "recorded outside"
    );
    names_leaf(deleted, leaf, false, || None).expect_err("no record: the leaf or its namesake");
    assert!(
        !names_leaf(deleted, leaf, true, unasked).expect("decided"),
        "another cgroup id"
    );
    assert!(!names_leaf("/a/leafx (deleted)", leaf, false, unasked).expect("decided"));
}

/// A record answers only for the task it was made for.
#[skuld::test]
fn a_recorded_place_answers_for_its_own_task_alone() {
    let placed = super::PlacedAtRemoval::default();
    assert_eq!(placed.of(7), None);
    placed.record(7, true);
    assert_eq!((placed.of(7), placed.of(8)), (Some(true), None));
    placed.clear();
    assert_eq!(placed.of(7), None);
}

/// A `/proc` that hides a process this one may not trace with `EPERM` (`hidepid=1`) refuses as one
/// that hides it with `ENOENT`.
#[skuld::test]
fn without_pidfd_info_a_hidepid_1_proc_refuses_naming_hidepid() {
    let _missing = fault::miss_pidfd_info();
    let _hidden = fault::hide_proc_as(libc::EPERM);
    match front_placement(&HostKernel, || Ok(HIGH)) {
        Err(crate::error::Error::Unsupported { detail, .. }) => assert!(detail.contains("hidepid"), "{detail}"),
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

/// A probe child that stays dumpable proves nothing about a front: the probe fails, naming that.
#[skuld::test]
fn a_probe_child_that_stays_dumpable_fails_the_probe() {
    let _missing = fault::miss_pidfd_info();
    let _dumpable = fault::keep_probe_dumpable();
    match front_placement(&HostKernel, || Ok(HIGH)) {
        Err(e @ crate::error::Error::Io(_)) => {
            assert!(crate::error::said(&e).contains("non-dumpable"), "{e:?}");
        }
        other => panic!("expected Io, got {other:?}"),
    }
}

/// `PIDFD_GET_INFO` refused on this process's own pidfd will refuse a front's too: the spawn is
/// refused, naming it.
#[skuld::test]
fn a_refused_pidfd_info_refuses_naming_it() {
    let _failing = fault::fail_pidfd_info();
    match front_placement(&HostKernel, || Ok(HIGH)) {
        Err(err @ crate::error::Error::Unsupported { .. }) => {
            let crate::error::Error::Unsupported { detail, .. } = &err else {
                unreachable!()
            };
            assert!(detail.contains("PIDFD_GET_INFO failed"), "{detail}");
            assert_eq!(crate::error::first_os_code(&err), Some(libc::EIO), "{err:?}");
            let named = std::io::Error::from_raw_os_error(libc::EIO).to_string();
            assert!(!detail.contains(&named), "{detail}");
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

/// A host that gives no cgroup's id by `name_to_handle_at` (`ENOSYS` without `CONFIG_FHANDLE`,
/// `EOPNOTSUPP` without export operations, `EPERM` from a seccomp filter) gives no place to
/// compare with: the spawn is refused as unsupported, naming the errno, before anything else.
#[skuld::test]
fn a_host_that_gives_no_cgroup_id_refuses_naming_the_errno() {
    for errno in [libc::ENOSYS, libc::EOPNOTSUPP, libc::EPERM] {
        match front_placement(&HostKernel, || Err(std::io::Error::from_raw_os_error(errno))) {
            Err(err @ crate::error::Error::Unsupported { .. }) => {
                let crate::error::Error::Unsupported { detail, .. } = &err else {
                    unreachable!()
                };
                let named = std::io::Error::from_raw_os_error(errno).to_string();
                assert!(!detail.contains(&named), "{errno}: {detail}");
                assert_eq!(crate::error::first_os_code(&err), Some(errno), "{err:?}");
                assert!(detail.contains("before anything is spawned"), "{errno}: {detail}");
            }
            other => panic!("{errno}: expected Unsupported, got {other:?}"),
        }
    }
}

/// Any other failure to read the leaf's id is the spawn's I/O error, not a claim about the host.
#[skuld::test]
fn any_other_failure_to_read_the_leaf_id_is_an_io_error() {
    match front_placement(&HostKernel, || Err(std::io::Error::from_raw_os_error(libc::ENOMEM))) {
        Err(crate::error::Error::Io(e)) => assert!(e.to_string().contains("leaf"), "{e}"),
        other => panic!("expected Io, got {other:?}"),
    }
}

/// A `/proc` view that could not be established fails a read of a task's cgroup with the view's error
/// as its cause, of its kind, with its OS code.
///
/// Mutant: the error keeps the view's kind and drops the error.
#[skuld::test]
fn a_task_read_through_an_unusable_view_has_the_views_error_as_its_cause() {
    let why = crate::identity::ViewUnreadable::from_open_errno(rustix::io::Errno::MFILE);
    let kind = std::io::Error::from_raw_os_error(libc::EMFILE).kind();

    let err = super::view_unreadable(7, why);

    assert_eq!(err.kind(), kind);
    assert_eq!(crate::error::first_os_code(&err), Some(libc::EMFILE), "{err:?}");
    assert!(err.to_string().contains("pid 7's cgroup cannot be read"), "{err}");
}

/// A forked probe, killed and reaped when dropped, so a probe a failing assertion would leave
/// running does not outlive the test.
struct ProbeGuard(OwnedFd);

impl Drop for ProbeGuard {
    fn drop(&mut self) {
        // Already reaped by the test: nothing to signal.
        if rustix::process::pidfd_send_signal(self.0.as_fd(), rustix::process::Signal::KILL).is_ok() {
            _ = rustix::process::waitid(
                rustix::process::WaitId::PidFd(self.0.as_fd()),
                rustix::process::WaitIdOptions::EXITED,
            );
        }
    }
}

impl ProbeGuard {
    fn of(pid: libc::pid_t) -> ProbeGuard {
        ProbeGuard(
            rustix::process::pidfd_open(
                rustix::process::Pid::from_raw(pid).expect("a positive pid"),
                rustix::process::PidfdFlags::empty(),
            )
            .expect("pidfd_open the probe"),
        )
    }
}

/// This test process's own `/proc`.
fn proc_dir() -> crate::identity::ProcDir {
    match crate::identity::proc_view_with(&crate::identity::HostKernel) {
        crate::identity::ProcView::Same(dir) => dir,
        _ => panic!("precondition: this test's /proc is its own pid namespace's"),
    }
}

/// The probe child reports that it is non-dumpable and asks to die with its parent, both before it
/// is read, and dies of `SIGKILL` once the thread that forked it has exited: a supervisor that dies
/// mid-probe leaves no process waiting for good. Mutant: "the probe sets no parent-death signal" (the
/// report names it, so the test fails by assertion before it waits for the death).
#[skuld::test]
fn the_probe_child_dies_with_the_thread_that_forked_it() {
    use std::io::Read as _;

    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    // `move`: a failing assertion unwinds out of this closure and drops `go_tx` before the scope
    // joins the forking thread, which waits for it.
    std::thread::scope(move |scope| {
        scope.spawn(move || {
            let parent = rustix::process::getpid().as_raw_nonzero().get();
            let probe = super::fork_probe(&proc_dir(), parent, false).expect("fork the probe");
            let mut report = [0u8; 2];
            probe.channel().read_exact(&mut report).expect("the probe reports");
            // Kept past this thread's end: the child must die of its parent-death signal, which the
            // probe's own end (a kill) would pre-empt.
            ready_tx.send((probe, report)).expect("report the probe");
            // The thread ends when the test lets it go, or when the test fails and drops `go_tx`.
            _ = go_rx.recv();
        });
        let (probe, report) = ready_rx.recv().expect("the probe");
        let pidfd = ProbeGuard::of(probe.pid);
        assert_eq!(
            report,
            [0, libc::SIGKILL as u8],
            "non-dumpable, and killed with its parent"
        );
        go_tx.send(()).expect("let the forking thread end");
        let status = rustix::process::waitid(
            rustix::process::WaitId::PidFd(pidfd.0.as_fd()),
            rustix::process::WaitIdOptions::EXITED,
        )
        .expect("the probe ends with its forking thread")
        .expect("a blocking waitid returns a status");
        assert_eq!(status.terminating_signal(), Some(libc::SIGKILL));
    });
}

/// A probe whose parent is already gone when it starts (so `getppid` is no longer the pid recorded
/// before the fork) exits without reporting. Mutant: "the probe does not compare its parent".
#[skuld::test]
fn a_probe_whose_parent_is_gone_exits_without_reporting() {
    use std::io::Read as _;

    // Not this process's pid, so the child's `getppid` differs from it, as after a reparenting.
    let not_the_parent = rustix::process::getpid().as_raw_nonzero().get() + 1;
    let probe = super::fork_probe(&proc_dir(), not_the_parent, false).expect("fork the probe");
    let pidfd = ProbeGuard::of(probe.pid);
    // The child's end of the socket closes with the child: end of file, with nothing reported. One
    // read, so a probe that reports instead fails the assertion, and does not leave the read
    // waiting for the end of a probe that waits to be killed.
    let mut reported = [0u8; 2];
    let read = probe.channel().read(&mut reported).expect("read the probe's report");
    assert_eq!(read, 0, "the probe reported {reported:?}");
    let status = rustix::process::waitid(
        rustix::process::WaitId::PidFd(pidfd.0.as_fd()),
        rustix::process::WaitIdOptions::EXITED,
    )
    .expect("reap the probe")
    .expect("a blocking waitid returns a status");
    assert_eq!(status.exit_status(), Some(super::ABANDONED));
}

/// The descriptors open in the process `pid`, each with what it names (`readlink`).
fn descriptors_of(pid: libc::pid_t) -> std::collections::BTreeMap<i32, String> {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .expect("list the probe child's descriptors")
        .map(|entry| {
            let entry = entry.expect("a descriptor entry");
            let fd = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse().ok())
                .expect("a numbered entry");
            let target = std::fs::read_link(entry.path()).expect("read what the descriptor names");
            (fd, target.to_string_lossy().into_owned())
        })
        .collect()
}

/// What this process's descriptor `fd` names.
fn own_descriptor(fd: &impl std::os::fd::AsRawFd) -> String {
    let target = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).expect("read an own descriptor");
    target.to_string_lossy().into_owned()
}

/// Forks two probes, the second while the first's parent end is open here, and checks each child holds
/// only its own socket end. Dumpable, so `/proc/<pid>/fd` is readable without `CAP_SYS_PTRACE`.
fn assert_two_probes_hold_only_their_own() {
    use std::io::Read as _;

    let proc = proc_dir();
    let parent = rustix::process::getpid().as_raw_nonzero().get();
    let first = super::fork_probe(&proc, parent, true).expect("fork the first probe");
    let second = super::fork_probe(&proc, parent, true).expect("fork the second probe");
    // Each child closes what it inherited before it reports.
    let mut report = [0u8; 2];
    first
        .channel()
        .read_exact(&mut report)
        .expect("the first probe reports");
    second
        .channel()
        .read_exact(&mut report)
        .expect("the second probe reports");
    for (name, probe) in [("first", &first), ("second", &second)] {
        let held: Vec<_> = descriptors_of(probe.pid).into_values().collect();
        assert!(
            matches!(held.as_slice(), [one] if one.starts_with("socket:")),
            "the {name} probe's child holds only its end of the socket: {held:?}"
        );
        assert_ne!(
            held[0],
            own_descriptor(probe.channel()),
            "the {name} probe's child holds its parent's end"
        );
    }
    let first_parent_end = own_descriptor(first.channel());
    assert!(
        !descriptors_of(second.pid)
            .values()
            .any(|target| *target == first_parent_end),
        "the second probe's child holds the first's parent end"
    );
}

/// Two concurrent probes' children each hold only their own descriptors, so neither keeps the
/// other's parent end open. Mutant: "the child keeps the descriptors it inherited".
#[skuld::test]
fn concurrent_probes_children_each_hold_only_their_own_descriptors() {
    assert_two_probes_hold_only_their_own();
}

/// The same where `close_range` is refused (a kernel before 5.9, or a seccomp filter): the child
/// closes the rest by a walk of its `/proc/self/fd`. Mutant: "the walk closes nothing".
#[skuld::test]
fn probes_children_hold_only_their_own_descriptors_without_close_range() {
    let _refused = fault::refuse_probe_close_range();
    assert_two_probes_hold_only_their_own();
}

/// A `close_range` that closes the first range and is refused the next leaves the child to close the
/// rest by the walk: the walk's directory is opened before any range is closed. Mutant: "the walk
/// opens its directory only after the ranges ran" (the first range closes the `/proc` handle it opens
/// through, and the child dies `ABANDONED`).
#[skuld::test]
fn probes_children_hold_only_their_own_descriptors_when_a_later_close_range_is_refused() {
    let _refused = fault::refuse_probe_close_range_after(1);
    assert_two_probes_hold_only_their_own();
}

/// The probe's child is killed through its pidfd and reaped through it. Mutant: "the kill is recorded
/// and not made" (the child then exits by itself, unkilled, once released).
#[skuld::test]
fn the_probe_child_is_killed_through_its_pidfd() {
    let _missing = fault::miss_pidfd_info();
    let _hidden = fault::hide_proc();
    fault::take_probe_steps();
    front_placement(&HostKernel, || Ok(HIGH)).expect_err("a hidden /proc refuses");
    assert_eq!(
        fault::take_probe_steps(),
        [
            ProbeStep::Kill(libc::SIGKILL),
            ProbeStep::Reap(ProbeEnd::Signal(libc::SIGKILL))
        ]
    );
}

/// Whether no child of this process holds `pid`: a probe's child that was reaped, by anyone.
fn no_child_holds(pid: libc::pid_t) -> Result<bool, rustix::io::Errno> {
    use rustix::process::{waitid, Pid, WaitId, WaitIdOptions};
    let pid = Pid::from_raw(pid).expect("a positive pid");
    match waitid(
        WaitId::Pid(pid),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    ) {
        Err(rustix::io::Errno::CHILD) => Ok(true),
        Err(e) => Err(e),
        Ok(_) => Ok(false),
    }
}

/// A probe's child whose kill through its pidfd fails other than `ESRCH` is released, exits by
/// itself, and is reaped through the pidfd that still names it. The failed kill is a `warn` naming
/// the child. Mutants: "the failed kill is logged below `warn`", "the child is released only by its
/// socket's close" (it then exits with another status).
#[skuld::test]
fn a_probe_child_whose_pidfd_kill_fails_is_released_and_reaped_through_its_pidfd() {
    crate::log_capture::install();
    let _missing = fault::miss_pidfd_info();
    let _hidden = fault::hide_proc();
    let forked = std::rc::Rc::new(std::cell::Cell::new(None));
    let _failed = fault::set_before_probe_kill({
        let forked = forked.clone();
        move |pid| {
            forked.set(Some(pid));
            Some(libc::EPERM)
        }
    });
    fault::take_probe_steps();
    let mark = crate::log_capture::mark();
    front_placement(&HostKernel, || Ok(HIGH)).expect_err("a hidden /proc refuses");
    let pid = forked.get().expect("the probe's child was to be killed");
    assert_eq!(
        fault::take_probe_steps(),
        [
            ProbeStep::Kill(libc::SIGKILL),
            ProbeStep::Reap(ProbeEnd::Exit(super::RELEASED))
        ]
    );
    let warns = warns_since(mark, "");
    assert!(
        warns.iter().any(|w| w.contains(&format!("child {pid}"))),
        "a warn names the probe's child {pid}: {warns:?}"
    );
    assert_eq!(no_child_holds(pid), Ok(true), "the probe's child {pid} is left");
}

/// A failed kill of one probe's child is not held up by a second probe's child forked while the
/// first's parent end was open in this process: the first child is released and reaped, while the
/// second still runs. Mutant: "the child keeps the descriptors it inherited, and is released only by
/// its socket's close" (the first's reap would then wait on the second child).
#[skuld::test]
fn a_failed_kill_of_one_probe_is_not_stalled_by_another_probes_child() {
    let _missing = fault::miss_pidfd_info();
    let _hidden = fault::hide_proc();
    let second = std::rc::Rc::new(std::cell::RefCell::new(None));
    let _failed = fault::set_before_probe_kill({
        let second = second.clone();
        move |_| {
            use std::io::Read as _;
            let parent = rustix::process::getpid().as_raw_nonzero().get();
            let probe = super::fork_probe(&proc_dir(), parent, false).expect("fork the second probe");
            let mut report = [0u8; 2];
            probe
                .channel()
                .read_exact(&mut report)
                .expect("the second probe reports");
            *second.borrow_mut() = Some(probe);
            Some(libc::EPERM)
        }
    });
    fault::take_probe_steps();
    front_placement(&HostKernel, || Ok(HIGH)).expect_err("a hidden /proc refuses");
    assert_eq!(
        fault::take_probe_steps(),
        [
            ProbeStep::Kill(libc::SIGKILL),
            ProbeStep::Reap(ProbeEnd::Exit(super::RELEASED))
        ]
    );
    let second = second.borrow_mut().take().expect("the second probe forked");
    let pid = second.pid;
    assert_eq!(
        no_child_holds(pid),
        Ok(false),
        "the second probe's child {pid} still runs"
    );
    second.end().expect("end the second probe");
    assert_eq!(
        fault::take_probe_steps(),
        [
            ProbeStep::Kill(libc::SIGKILL),
            ProbeStep::Reap(ProbeEnd::Signal(libc::SIGKILL))
        ]
    );
}

/// `SIGCHLD` set to `SIG_IGN` while the guard lives: the kernel reaps every child of this process
/// as it exits, as on a host that ignores `SIGCHLD`.
struct SigchldIgnored(nix::sys::signal::SigAction);

fn ignore_sigchld() -> SigchldIgnored {
    use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
    let ignore = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
    // SAFETY: installs no handler; the callers run [`alone`], so no other test shares the process.
    SigchldIgnored(unsafe { sigaction(Signal::SIGCHLD, &ignore) }.expect("ignore SIGCHLD"))
}

impl Drop for SigchldIgnored {
    fn drop(&mut self) {
        // SAFETY: restores the disposition `ignore_sigchld` saved.
        _ = unsafe { nix::sys::signal::sigaction(nix::sys::signal::Signal::SIGCHLD, &self.0) };
    }
}

/// A probe's child the kernel reaps itself (`SIGCHLD` ignored) is gone, not a failure: the reap's
/// `ECHILD` keeps the verdict already read, here that `/proc` hides the child. Mutant: "`ECHILD` at
/// the reap fails the probe" (the spawn's error is then `Io`, not the refusal). Run [`alone`]: the
/// disposition is process-wide.
#[skuld::test]
fn a_probe_child_reaped_by_an_ignored_sigchld_keeps_the_verdict() {
    if !alone("containment::cgroup::reach::reach_tests::a_probe_child_reaped_by_an_ignored_sigchld_keeps_the_verdict") {
        return;
    }
    let _ignored = ignore_sigchld();
    let _missing = fault::miss_pidfd_info();
    let _hidden = fault::hide_proc();
    fault::take_probe_steps();
    let err = front_placement(&HostKernel, || Ok(HIGH)).expect_err("a hidden /proc refuses");
    assert!(matches!(err, crate::error::Error::Unsupported { .. }), "{err:?}");
    assert_eq!(
        fault::take_probe_steps(),
        [ProbeStep::Kill(libc::SIGKILL), ProbeStep::Reap(ProbeEnd::Elsewhere)]
    );
}

/// A probe's child that dies before it reports, with `SIGCHLD` ignored, is reaped by the kernel as it
/// exits: the probe's error and the record of its reap say so, and do not blame another reaper
/// alone. Mutant: "the words name only another reaper". Run [`alone`]: the disposition is
/// process-wide.
#[skuld::test]
fn a_probe_child_that_dies_early_with_sigchld_ignored_says_so() {
    if !alone("containment::cgroup::reach::reach_tests::a_probe_child_that_dies_early_with_sigchld_ignored_says_so") {
        return;
    }
    crate::log_capture::install();
    let _ignored = ignore_sigchld();
    let _missing = fault::miss_pidfd_info();
    let _no_dir = fault::fail_probe_fd_dir(libc::EMFILE);
    fault::take_probe_steps();
    let mark = crate::log_capture::mark();
    let err = front_placement(&HostKernel, || Ok(HIGH)).expect_err("the probe's child is gone");
    assert_eq!(
        fault::take_probe_steps().last(),
        Some(&ProbeStep::Reap(ProbeEnd::Elsewhere))
    );
    assert!(
        crate::error::said(&err).contains("SIGCHLD"),
        "the error names the ignored SIGCHLD: {err:?}"
    );
    let records = crate::log_capture::records_since_on_current_thread(mark, "was reaped by another reaper");
    assert!(
        records.iter().any(|(_, record)| record.contains("SIGCHLD")),
        "the record names the ignored SIGCHLD: {records:?}"
    );
}

/// A [`Kernel`] over the host's that, once it has read a probe child's `<pid>/cgroup`, kills that
/// child and waits until it is a zombie, reaping nothing: the child exits between the read and the
/// probe's confirmation that the read named it. `killed` says it did.
struct ChildExitsAfterCgroupRead {
    killed: std::sync::atomic::AtomicBool,
}

impl Kernel for ChildExitsAfterCgroupRead {
    fn pidfd_open(
        &self,
        target: rustix::process::Pid,
        flags: rustix::process::PidfdFlags,
    ) -> Result<OwnedFd, rustix::io::Errno> {
        HostKernel.pidfd_open(target, flags)
    }

    fn pidfs_ino(&self, fd: std::os::fd::BorrowedFd<'_>) -> Result<Option<u64>, rustix::io::Errno> {
        HostKernel.pidfs_ino(fd)
    }

    fn open_proc(&self) -> Result<ProcDir, ViewUnreadable> {
        HostKernel.open_proc()
    }

    fn read(&self, dir: &ProcDir, path: &str) -> std::io::Result<Vec<u8>> {
        let read = HostKernel.read(dir, path);
        if let Some(pid) = path.strip_suffix("/cgroup").and_then(|pid| pid.parse().ok()) {
            // SAFETY: `pid` is this test's own unreaped child.
            assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0, "kill the probe's child");
            // Waits for the exit itself, and leaves the zombie for the probe's reap.
            rustix::process::waitid(
                rustix::process::WaitId::Pid(rustix::process::Pid::from_raw(pid).expect("a positive pid")),
                rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOWAIT,
            )
            .expect("wait for the probe's child to exit");
            self.killed.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        read
    }

    fn pids(&self, dir: &ProcDir) -> std::io::Result<Vec<u32>> {
        HostKernel.pids(dir)
    }

    fn signal_probe(&self, target: rustix::process::Pid) -> Result<(), rustix::io::Errno> {
        HostKernel.signal_probe(target)
    }
}

/// A probe's child that exits after its cgroup is read, before the probe confirms through its pidfd
/// that the read named it, is reported as having exited by then, and gives no verdict from the
/// read. Mutant: "the probe does not confirm" (the read stands, and the probe answers with its
/// verdict).
#[skuld::test]
fn a_probe_child_that_exits_before_the_read_is_confirmed_is_reported_gone() {
    let _missing = fault::miss_pidfd_info();
    let kernel = ChildExitsAfterCgroupRead {
        killed: std::sync::atomic::AtomicBool::new(false),
    };
    fault::take_probe_steps();
    let err = front_placement(&kernel, || Ok(HIGH)).expect_err("the probe's child is gone");
    assert!(
        kernel.killed.load(std::sync::atomic::Ordering::SeqCst),
        "the kernel read the child's cgroup and killed the child"
    );
    assert!(
        crate::error::said(&err).contains("had exited by the time its cgroup read was confirmed"),
        "the probe reports its child gone: {err:?}"
    );
    assert_eq!(
        fault::take_probe_steps().last(),
        Some(&ProbeStep::Reap(ProbeEnd::Signal(libc::SIGKILL)))
    );
}

/// A probe's child that another waiter in the process reaps after the verdict is read, before its
/// kill, is gone: the kill answers `ESRCH`, the reap `ECHILD`, and the verdict stands. Mutant:
/// "`ECHILD` at the reap fails the probe".
#[skuld::test]
fn a_probe_child_reaped_by_another_waiter_keeps_the_verdict() {
    let _missing = fault::miss_pidfd_info();
    let _hidden = fault::hide_proc();
    let _reaped = fault::set_before_probe_kill(|pid| {
        // SAFETY: `pid` is this test's own unreaped child.
        assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0, "kill the probe's child");
        crate::test_child::reaped_elsewhere::reap_behind(pid as u32);
        None
    });
    fault::take_probe_steps();
    let err = front_placement(&HostKernel, || Ok(HIGH)).expect_err("a hidden /proc refuses");
    assert!(matches!(err, crate::error::Error::Unsupported { .. }), "{err:?}");
    assert_eq!(
        fault::take_probe_steps(),
        [ProbeStep::Kill(libc::SIGKILL), ProbeStep::Reap(ProbeEnd::Elsewhere)]
    );
}

/// A probe's child that is already dead when its kill through the pidfd answers `ESRCH` is reaped
/// through that pidfd. Mutant: "`ESRCH` returns, leaving the zombie".
#[skuld::test]
fn a_probe_child_already_dead_at_its_pidfd_send_is_reaped_through_the_pidfd() {
    let _missing = fault::miss_pidfd_info();
    let _hidden = fault::hide_proc();
    let forked = std::rc::Rc::new(std::cell::Cell::new(None));
    let _dead = fault::set_before_probe_kill({
        let forked = forked.clone();
        move |pid| {
            forked.set(Some(pid));
            // SAFETY: `pid` is this test's own unreaped child; it dies, and stays a zombie for its
            // pidfd to reap.
            assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0, "kill the probe's child");
            Some(libc::ESRCH)
        }
    });
    fault::take_probe_steps();
    front_placement(&HostKernel, || Ok(HIGH)).expect_err("a hidden /proc refuses");
    let pid = forked.get().expect("the probe's child was to be killed");
    assert_eq!(
        fault::take_probe_steps(),
        [
            ProbeStep::Kill(libc::SIGKILL),
            ProbeStep::Reap(ProbeEnd::Signal(libc::SIGKILL))
        ]
    );
    assert_eq!(no_child_holds(pid), Ok(true), "the probe's child {pid} is left");
}

/// The soft `RLIMIT_NOFILE` lowered to leave exactly `spare` (at least 1) descriptor numbers free
/// below it, counting the holes among the descriptors open now; the limit it replaced is put back
/// when the guard drops.
struct NofileLimit(libc::rlimit);

fn limit_nofile(spare: usize) -> NofileLimit {
    let open: std::collections::BTreeSet<i32> = descriptors_of(std::process::id() as libc::pid_t)
        .into_iter()
        // The listing's own directory descriptor is open only while it is read.
        .filter(|(_, target)| !target.ends_with("/fd"))
        .map(|(fd, _)| fd)
        .collect();
    let last_free = (0..)
        .filter(|fd| !open.contains(fd))
        .nth(spare - 1)
        .expect("a free descriptor number");
    let mut before = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `before` is a valid out-pointer.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut before) },
        0,
        "getrlimit"
    );
    let lowered = libc::rlimit {
        rlim_cur: last_free as libc::rlim_t + 1,
        rlim_max: before.rlim_max,
    };
    // SAFETY: `lowered` is a valid rlimit; the callers run [`alone`], so no other test shares the limit.
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) },
        0,
        "setrlimit"
    );
    NofileLimit(before)
}

impl Drop for NofileLimit {
    fn drop(&mut self) {
        // SAFETY: puts back the limit `limit_nofile` read.
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.0) };
    }
}

/// The placement probe answers its verdict (here that `/proc` hides the child) with only `spare`
/// descriptor numbers free below the soft limit: its child is killed and reaped through its pidfd,
/// with no `warn`.
fn assert_probe_answers_with_spare_descriptors(spare: usize) {
    crate::log_capture::install();
    let _missing = fault::miss_pidfd_info();
    let _hidden = fault::hide_proc();
    let _limit = limit_nofile(spare);
    fault::take_probe_steps();
    let mark = crate::log_capture::mark();
    let err = front_placement(&HostKernel, || Ok(HIGH)).expect_err("a hidden /proc refuses");
    assert!(
        matches!(&err, crate::error::Error::Unsupported { detail, .. } if detail.contains("hides the cgroup")),
        "the refusal is the hidden /proc's: {err:?}"
    );
    assert_eq!(
        fault::take_probe_steps(),
        [
            ProbeStep::Kill(libc::SIGKILL),
            ProbeStep::Reap(ProbeEnd::Signal(libc::SIGKILL))
        ]
    );
    assert_eq!(warns_since(mark, ""), Vec::<String>::new());
}

/// A low `RLIMIT_NOFILE` does not turn the probe's verdict into an `Io` failure: with 4 descriptor
/// numbers free (the `/proc` handle, the socket's two ends, and the child's pidfd, which the clone
/// makes while the child's end is still open), the child still reports: it opens nothing beyond its
/// walk's directory. Mutants: "the child copies its descriptors to the lowest free numbers above its
/// own" (it then needs three more than its parent holds, and dies `ABANDONED`), "this process's own
/// pidfd stays open during the probe" (the clone then fails with `EMFILE`, as the pidfd needs a
/// number too). Run [`alone`]: the limit is process-wide.
#[skuld::test]
fn the_probe_answers_with_the_fewest_descriptors_its_parent_needs() {
    if !alone("containment::cgroup::reach::reach_tests::the_probe_answers_with_the_fewest_descriptors_its_parent_needs")
    {
        return;
    }
    assert_probe_answers_with_spare_descriptors(4);
}

/// One descriptor fewer than that, the clone cannot make the child's pidfd: the probe fails with the
/// clone's errno, `EMFILE`, before anything runs. Mutant: "the child's pidfd is not made at the fork"
/// (3 descriptors then suffice, and the probe answers its verdict). Run [`alone`]: the limit is
/// process-wide.
#[skuld::test]
fn a_probe_with_no_descriptor_for_its_childs_pidfd_fails_with_the_clones_errno() {
    if !alone(
        "containment::cgroup::reach::reach_tests::a_probe_with_no_descriptor_for_its_childs_pidfd_fails_with_the_clones_errno",
    ) {
        return;
    }
    let _missing = fault::miss_pidfd_info();
    let _hidden = fault::hide_proc();
    let _limit = limit_nofile(3);
    let err = front_placement(&HostKernel, || Ok(HIGH)).expect_err("the probe cannot fork");
    assert!(matches!(err, crate::error::Error::Io(_)), "{err:?}");
    assert_eq!(crate::error::first_os_code(&err), Some(libc::EMFILE), "{err:?}");
}

/// `keep_only_own` closes the parent's end before it opens the walk's directory, so it needs no
/// free descriptor number: a child whose table is full (its soft limit lowered to its first free
/// number, with both ends below it) still closes everything but its own end. The probe cannot show
/// this: the kernel copies the child's table before it makes the pidfd in the parent, so the probe's
/// child always has one number free. A child of this test has none. Mutant: "`keep_only_own` opens
/// `/proc/self/fd` before it closes `ends.parent`" (the directory then fails to open, and the child
/// answers `false`). Run [`alone`]: the numbers the socket takes must be this process's lowest.
#[skuld::test]
fn keep_only_own_needs_no_free_descriptor_number() {
    use std::os::fd::AsRawFd as _;

    use crate::os_process::linux::fork::{fork_with_pidfd, Fork};

    const KEPT: i32 = 0;
    const WALK_FAILED: i32 = 1;
    const NOT_FULL: i32 = 2;

    if !alone("containment::cgroup::reach::reach_tests::keep_only_own_needs_no_free_descriptor_number") {
        return;
    }
    let proc = proc_dir();
    let (parent_end, child_end) = std::os::unix::net::UnixStream::pair().expect("socketpair");
    let ends = super::Ends {
        child: child_end.as_raw_fd(),
        parent: parent_end.as_raw_fd(),
    };
    let new = {
        let _lock = crate::child::spawn::spawn_lock();
        // SAFETY: this thread holds `spawn_lock`, and the child makes only raw system calls and
        // `keep_only_own`'s, and ends in `_exit`.
        match unsafe { fork_with_pidfd() }.expect("fork") {
            // SAFETY: this is the forked child.
            Fork::Child => unsafe {
                let mut full: libc::c_int = 0;
                while libc::fcntl(full, libc::F_GETFD) != -1 {
                    full += 1;
                }
                let limit = libc::rlimit {
                    rlim_cur: full as libc::rlim_t,
                    rlim_max: full as libc::rlim_t,
                };
                if ends.child >= full || ends.parent >= full || libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                    libc::_exit(NOT_FULL);
                }
                libc::_exit(if super::keep_only_own(&proc, ends) {
                    KEPT
                } else {
                    WALK_FAILED
                });
            },
            Fork::Parent(new) => new,
        }
    };
    let status = rustix::process::waitid(
        rustix::process::WaitId::PidFd(new.pidfd.as_fd()),
        rustix::process::WaitIdOptions::EXITED,
    )
    .expect("waitid on the child's pidfd")
    .expect("a waitid without NOHANG returns a status");
    assert_eq!(status.exit_status(), Some(KEPT), "{status:?}");
}

/// A probe dropped before it was ended, as by an unwind between its fork and its end, kills and reaps
/// its child. Mutant: "`Probe` has no `Drop`" (the child, exiting by itself on its socket's close, is
/// left a zombie).
#[skuld::test]
fn a_probe_dropped_unended_is_killed_and_reaped() {
    fault::take_probe_steps();
    let parent = rustix::process::getpid().as_raw_nonzero().get();
    let pid = {
        let probe = super::fork_probe(&proc_dir(), parent, false).expect("fork the probe");
        probe.pid
    };
    assert_eq!(
        fault::take_probe_steps(),
        [
            ProbeStep::Kill(libc::SIGKILL),
            ProbeStep::Reap(ProbeEnd::Signal(libc::SIGKILL))
        ]
    );
    assert_eq!(no_child_holds(pid), Ok(true), "the probe's child {pid} is left");
}

/// A probe's child that cannot open its `/proc/self/fd` for a reason that is no refusal reports the
/// errno and exits `ABANDONED` by itself, whether or not `close_range` works: the probe reaps it
/// without a kill, so its end is always that exit; the error states the reported cause and the
/// errno, and the end is logged at `debug`, not `warn`. Mutant: "the child's errno is dropped" (the
/// error has no code), "the probe kills a child that reported" (a kill step, a status that follows
/// the scheduler).
#[skuld::test]
fn a_probe_child_that_cannot_close_its_descriptors_is_reported_abandoned() {
    crate::log_capture::install();
    let _missing = fault::miss_pidfd_info();
    let _no_dir = fault::fail_probe_fd_dir(libc::EMFILE);
    fault::take_probe_steps();
    let mark = crate::log_capture::mark();
    let err = front_placement(&HostKernel, || Ok(HIGH)).expect_err("the probe fails");
    let said = crate::error::said(&err);
    assert!(
        matches!(&err, crate::error::Error::Io(_))
            && said.contains(
                "the probe's child could not open its /proc/self/fd: it exited ABANDONED (1) after reporting that failure"
            ),
        "the error states the reported cause and the child's status: {said}"
    );
    assert!(
        !said.contains("its parent was gone"),
        "the error does not offer the causes of an unreported exit: {said}"
    );
    assert_eq!(
        crate::error::first_os_code(&err),
        Some(libc::EMFILE),
        "the error carries the errno the child reported: {err:?}"
    );
    assert_eq!(
        fault::take_probe_steps(),
        [ProbeStep::Reap(ProbeEnd::Exit(super::ABANDONED))],
        "a child that reported is reaped, not killed"
    );
    let records = crate::log_capture::records_since_on_current_thread(mark, "placement probe's child");
    assert!(
        records
            .iter()
            .any(|(level, text)| *level == log::Level::Debug && text.contains("ABANDONED")),
        "the end is logged at debug: {records:?}"
    );
    assert!(
        records.iter().all(|(level, _)| *level > log::Level::Warn),
        "the child's reported failure does not warn: {records:?}"
    );
}

/// The errnos by which `openat2` is refused (see `identity::Refusal`).
const REFUSALS: [i32; 3] = [libc::ENOSYS, libc::EPERM, libc::ENODEV];

/// `err` is the spawn's refusal for an `openat2` that answered `errno`: `Unsupported` naming the
/// requirement, not `hidepid`, with `errno` as its source.
fn assert_refused_openat2(err: &crate::error::Error, errno: i32) {
    let crate::error::Error::Unsupported { op, detail, .. } = err else {
        panic!("{errno}: expected Unsupported, got {err:?}");
    };
    assert_eq!(op, "contain() on an elevated command", "{errno}");
    assert!(detail.contains("requires openat2"), "{errno}: {detail}");
    assert!(!detail.contains("hidepid"), "{errno}: {detail}");
    assert_eq!(crate::error::first_os_code(err), Some(errno), "{err:?}");
}

/// A probe child whose open of its `/proc/self/fd` is refused reports the errno on the probe's
/// channel, and the spawn is refused as `Unsupported`, as for a refused view. Mutant: "the child's
/// errno is dropped" (the spawn's error is the generic `ABANDONED` one).
#[skuld::test]
fn a_probe_childs_refused_openat2_refuses_the_spawn_naming_it() {
    let _missing = fault::miss_pidfd_info();
    for errno in REFUSALS {
        let _no_dir = fault::fail_probe_fd_dir(errno);
        let err = front_placement(&HostKernel, || Ok(HIGH)).expect_err("the probe's child cannot set up");
        assert_refused_openat2(&err, errno);
    }
}

/// A refused read of the probe child's `<pid>/cgroup` refuses the spawn as `Unsupported` naming
/// `openat2`, not as an I/O error of the probe. Mutant: "only `EPERM` and `ENOENT` are classified".
#[skuld::test]
fn a_refused_cgroup_read_of_the_probes_child_refuses_the_spawn_naming_openat2() {
    let _missing = fault::miss_pidfd_info();
    for errno in [libc::ENOSYS, libc::ENODEV] {
        let _refused = fault::hide_proc_as(errno);
        let err = front_placement(&HostKernel, || Ok(HIGH)).expect_err("a refused read refuses");
        assert_refused_openat2(&err, errno);
    }
}

/// `EPERM` is `hidepid`'s answer, and a refusal only if the checked directory refuses `self/stat`
/// too, as for a pid's `stat` in a scan: the re-check's errno is the refusal, the read's `EPERM` a
/// second cause. Mutant: "an `EPERM` read is always `hidepid`".
#[skuld::test]
fn an_eperm_cgroup_read_beside_a_refusing_proc_directory_is_a_refusal() {
    let _missing = fault::miss_pidfd_info();
    let _hidden = fault::hide_proc_as(libc::EPERM);
    for errno in REFUSALS {
        let kernel = FakeKernel::over(&HostKernel)
            .same_view()
            .on_read("self/stat", Err(errno));
        let err = front_placement(&kernel, || Ok(HIGH)).expect_err("a refused re-check refuses");
        assert_refused_openat2(&err, errno);
        let said = crate::error::Report(&err).to_string();
        assert!(
            said.contains("cgroup was refused, and the checked /proc refused self/stat too"),
            "{said}"
        );
    }
}

/// `EPERM` beside a checked directory that still answers, or whose re-check fails without refusing,
/// is `hidepid`'s: the refusal says so.
#[skuld::test]
fn an_eperm_cgroup_read_beside_a_proc_directory_that_is_no_refusal_is_hidepid() {
    let _missing = fault::miss_pidfd_info();
    let _hidden = fault::hide_proc_as(libc::EPERM);
    let kernel = FakeKernel::over(&HostKernel)
        .same_view()
        .on_read("self/stat", Err(libc::EIO));
    match front_placement(&kernel, || Ok(HIGH)) {
        Err(crate::error::Error::Unsupported { detail, .. }) => assert!(detail.contains("hidepid"), "{detail}"),
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

/// A task's `<pid>/cgroup` read that is refused is an error that says what cosca requires, of kind
/// `Unsupported`, with the refusing errno as its code, so the placement's callers carry it.
/// Mutant: "the read's error is returned as it is".
#[skuld::test]
fn a_refused_cgroup_read_of_a_task_says_what_cosca_requires() {
    let (leaf, _dir) = stand_in_subtree(None);
    for errno in [libc::ENOSYS, libc::ENODEV] {
        let _refused = fault::hide_proc_as(errno);
        let err = leaf.holds(std::process::id(), None).expect_err("a refused read");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported, "{errno}: {err}");
        assert_eq!(crate::error::first_os_code(&err), Some(errno), "{err:?}");
        let said = crate::error::Report(&err).to_string();
        assert!(said.contains("requires openat2"), "{errno}: {said}");
    }
}

/// A `<pid>/cgroup` read that is no refusal stays the read's own error: `EIO`, `ENOENT` (a task
/// that left), and `EPERM` while the checked directory still answers (`hidepid`).
#[skuld::test]
fn a_cgroup_read_of_a_task_that_is_no_refusal_is_the_reads_own_error() {
    let (leaf, _dir) = stand_in_subtree(None);
    for errno in [libc::EIO, libc::ENOENT, libc::EPERM] {
        let _failing = fault::hide_proc_as(errno);
        let err = leaf.holds(std::process::id(), None).expect_err("a failed read");
        assert_eq!(err.raw_os_error(), Some(errno), "{err:?}");
        assert!(
            !crate::error::Report(&err).to_string().contains("requires"),
            "{errno}: {err}"
        );
    }
}

/// With fds 0 and 1 closed and `close_range` refused, the lowest numbers hold the `/proc` handle, the
/// socket's parent end and the walk's directory, and the walk still closes all but the child's end.
/// Mutant: "the walk skips the entry for descriptor 0". Runs in a process of its own: closing 0 and 1
/// is process-wide.
#[skuld::test]
fn the_walk_closes_the_lowest_descriptors_with_fds_0_and_1_closed() {
    use crate::test_own_process::{own_process, test_path};
    use crate::test_spawn::spawn;
    use crate::test_stdio::RestoreStdio;
    use std::io::Read as _;

    let Some(done) = own_process(
        test_path!(the_walk_closes_the_lowest_descriptors_with_fds_0_and_1_closed),
        spawn,
    ) else {
        return;
    };
    let _refused = fault::refuse_probe_close_range();
    // Declared before `proc`, which takes descriptor 0: it is closed before the restore puts back
    // the standard descriptor there.
    let restore = RestoreStdio::close(&done, &[0, 1]);
    let proc = proc_dir();
    let parent = rustix::process::getpid().as_raw_nonzero().get();
    let probe = super::fork_probe(&proc, parent, true).expect("fork the probe");
    let mut report = [0u8; 2];
    probe.channel().read_exact(&mut report).expect("the probe reports");
    let held: Vec<_> = descriptors_of(probe.pid).into_values().collect();
    drop(probe);
    drop(proc);
    drop(restore);
    assert!(
        matches!(held.as_slice(), [one] if one.starts_with("socket:")),
        "the probe's child holds only its end of the socket: {held:?}"
    );
}

/// The walk closes a long listing: with about 100 descriptors open, two of the low ones freed so the
/// socket lands below the rest, and `close_range` refused, the child still holds only its socket. The
/// listing outgrows one `getdents64` buffer, and each pass closes entries it is reading. Mutant: "the
/// walk stops after its first batch". Run [`alone`]: the descriptor numbers are process-wide.
#[skuld::test]
fn the_walk_closes_a_listing_longer_than_one_batch() {
    use std::io::Read as _;

    if !alone("containment::cgroup::reach::reach_tests::the_walk_closes_a_listing_longer_than_one_batch") {
        return;
    }
    let mut files: Vec<_> = (0..100)
        .map(|_| std::fs::File::open("/dev/null").expect("open /dev/null"))
        .collect();
    drop(files.drain(10..12));
    let _refused = fault::refuse_probe_close_range();
    let parent = rustix::process::getpid().as_raw_nonzero().get();
    let probe = super::fork_probe(&proc_dir(), parent, true).expect("fork the probe");
    let mut report = [0u8; 2];
    probe.channel().read_exact(&mut report).expect("the probe reports");
    let held: Vec<_> = descriptors_of(probe.pid).into_values().collect();
    assert!(
        matches!(held.as_slice(), [one] if one.starts_with("socket:")),
        "the probe's child holds only its end of the socket: {held:?}"
    );
}

/// A release byte that cannot be sent is a `warn` naming the probe's child. Mutant: "the failed send is
/// ignored".
#[skuld::test]
fn a_release_that_cannot_be_sent_is_a_warn_naming_the_child() {
    crate::log_capture::install();
    // Not a socket: the send fails with `ENOTSOCK`, not the `EPIPE` of a child already gone.
    let not_a_socket =
        std::os::unix::net::UnixStream::from(OwnedFd::from(std::fs::File::open("/dev/null").expect("open /dev/null")));
    let mark = crate::log_capture::mark();
    super::release_probe(4242, not_a_socket);
    let warns = warns_since(mark, "");
    assert!(
        warns.iter().any(|w| w.contains("child 4242")),
        "a warn names the probe's child: {warns:?}"
    );
}

/// The ranges `keep_only_own` closes leave exactly the kept descriptor and the walk's directory open,
/// and none is empty, which `close_range` refuses. Mutant: "the first range ends at the lower kept
/// descriptor, not below it".
#[skuld::test]
fn the_ranges_around_two_descriptors_cover_every_other_number() {
    use super::ranges_around;
    const MAX: u32 = u32::MAX;
    assert_eq!(ranges_around(0, 1), [None, None, Some((2, MAX))]);
    assert_eq!(ranges_around(1, 0), [None, None, Some((2, MAX))]);
    assert_eq!(ranges_around(5, 2), [Some((0, 1)), Some((3, 4)), Some((6, MAX))]);
    assert_eq!(ranges_around(2, 5), [Some((0, 1)), Some((3, 4)), Some((6, MAX))]);
    assert_eq!(ranges_around(0, 3), [None, Some((1, 2)), Some((4, MAX))]);
    assert_eq!(ranges_around(MAX, 0), [None, Some((1, MAX - 1)), None]);
}

/// A subtree asked about a child with no pid cannot place it, though its kill landed: it has no
/// number to ask `/proc` with, so whether the kill reached it is unknown, not "no".
///
/// Mutant: the pid-less child is taken for not reached, or asked as pid 0.
#[skuld::test]
fn a_subtree_asked_about_a_pidless_child_cannot_place_it() {
    use crate::child::owned::teardown::Reach;

    let child = crate::child::owned::OwnedChild::new(Box::new(crate::os_process::fake::FakeProcess::new([])));
    assert!(subtree(HIGH, true).reached(&child).is_err());
}
