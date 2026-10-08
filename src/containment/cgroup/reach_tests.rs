//! Placing a task in a leaf's subtree by its cgroup id, and deciding before a spawn whether a front
//! can be placed. Unprivileged: the ids are forced, and the probe reads a child of this process.

use std::os::fd::{AsFd as _, OwnedFd};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use super::{dying_in, front_placement, Subtree};
use crate::containment::cgroup::fault;
use crate::test_groups::{cgroup, Group};

/// A cgroup id with bits above the low 32, as kernfs gives once its 32-bit counter wraps.
const HIGH: u64 = 0x1_0000_0007;

fn own_pidfd() -> OwnedFd {
    rustix::process::pidfd_open(rustix::process::getpid(), rustix::process::PidfdFlags::empty()).expect("pidfd_open")
}

fn subtree(leaf_id: u64, killed: bool) -> Subtree {
    Subtree::new(
        leaf_id,
        None,
        None,
        None,
        crate::containment::cgroup::Swept::default(),
        Arc::new(AtomicBool::new(killed)),
    )
}

/// A subtree whose leaf directory is a stand-in, an ordinary empty directory with `stat` as its
/// `cgroup.stat` (none: `None`), with a path, so a task it cannot place is placed through `/proc`.
/// The directory is returned to outlive the subtree.
fn stand_in_subtree(stat: Option<&str>) -> (Subtree, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
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
        HIGH,
        Some(Arc::new(fd)),
        None,
        Some("/stand-in-leaf".to_owned()),
        swept,
        Arc::new(AtomicBool::new(true)),
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
        .reached(pid, Some(pidfd.as_fd()))
        .expect("a forced id"));
    assert!(subtree(HIGH, true)
        .reached(pid, Some(pidfd.as_fd()))
        .expect("a forced id"));
}

/// With `PIDFD_GET_INFO`, fronts are placeable whatever `/proc` hides.
#[skuld::test]
fn with_pidfd_info_a_front_is_placeable_whatever_proc_hides() {
    let _id = fault::force_pidfd_cgroup_id(HIGH);
    let _hidden = fault::hide_proc();
    front_placement().expect("placeable by a pidfd's cgroup id");
}

/// Without `PIDFD_GET_INFO`, a `/proc` that shows a process this one may not trace makes fronts
/// placeable. The probe is real: a non-dumpable child of this process, read and reaped.
#[skuld::test]
fn without_pidfd_info_a_proc_that_shows_untraceable_processes_places_fronts() {
    let _missing = fault::miss_pidfd_info();
    front_placement().expect("this test's /proc hides nothing");
}

/// Without `PIDFD_GET_INFO`, a `/proc` that hides a process this one may not trace refuses an
/// elevated, contained spawn, naming `hidepid`.
#[skuld::test]
fn without_pidfd_info_a_hidepid_proc_refuses_naming_hidepid() {
    let _missing = fault::miss_pidfd_info();
    let _hidden = fault::hide_proc();
    match front_placement() {
        Err(crate::error::Error::Unsupported { detail, .. }) => {
            assert!(detail.contains("hidepid"), "{detail}");
            assert!(detail.contains("before anything is spawned"), "{detail}");
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

/// Without `PIDFD_GET_INFO`, a `/proc` of an outer pid namespace refuses, naming that, not
/// `hidepid`.
#[skuld::test]
fn without_pidfd_info_a_diverged_proc_view_refuses_naming_the_view() {
    use crate::identity::proc_view_fault::{force_proc_view_once, ForcedView};
    let _missing = fault::miss_pidfd_info();
    let _view = force_proc_view_once(ForcedView::Diverged);
    match front_placement() {
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
    use crate::identity::proc_view_fault::{force_proc_view_once, ForcedView};
    let _missing = fault::miss_pidfd_info();
    let _view = force_proc_view_once(ForcedView::Unassessable);
    match front_placement() {
        Err(crate::error::Error::Unsupported { detail, .. }) => {
            assert!(
                detail.contains("could not be established (forced by a test)"),
                "{detail}"
            );
            assert!(!detail.contains("hidepid"), "{detail}");
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

/// The probe's pipe lands on whatever descriptors are free, std's own included: with fds 0 and 1
/// closed it still reads, and still refuses where `/proc` hides. Runs in a process of its own:
/// closing 0 and 1 is process-wide.
#[skuld::test]
fn the_placement_probe_answers_with_fds_0_and_1_closed() {
    use crate::test_own_process::{own_process, test_path};
    use crate::test_spawn::spawn;
    use crate::test_stdio::RestoreStdio;

    let Some(done) = own_process(test_path!(the_placement_probe_answers_with_fds_0_and_1_closed), spawn) else {
        return;
    };
    let _missing = fault::miss_pidfd_info();
    let restore = RestoreStdio::close(&done, &[0, 1]);
    let shown = front_placement();
    let hidden = {
        let _hidden = fault::hide_proc();
        front_placement()
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
        HIGH,
        Some(leaf.shared()),
        None,
        Some("/stand-in-leaf".to_owned()),
        leaf.swept(),
        Arc::new(AtomicBool::new(true)),
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
    }
}

/// `/proc`'s ` (deleted)` names the leaf only once the leaf is verifiably removed, and not when a
/// live cgroup beside it bears the suffix in its name; a path under the leaf is under it either
/// way.
#[skuld::test]
fn a_removed_leaf_is_named_only_once_it_is_verifiably_removed() {
    use super::names_leaf;
    let ok = |b: bool| move || Ok::<bool, std::io::Error>(b);
    let leaf = "/a/leaf";
    assert!(names_leaf("/a/leaf", leaf, ok(false), ok(false)).expect("decided"));
    assert!(names_leaf("/a/leaf/sub (deleted)", leaf, ok(false), ok(false)).expect("decided"));
    assert!(
        !names_leaf("/a/leaf (deleted)", leaf, ok(false), ok(false)).expect("decided"),
        "a live leaf"
    );
    assert!(names_leaf("/a/leaf (deleted)", leaf, ok(true), ok(false)).expect("decided"));
    names_leaf("/a/leaf (deleted)", leaf, ok(true), ok(true)).expect_err("the leaf or its namesake");
    assert!(!names_leaf("/a/leafx (deleted)", leaf, ok(true), ok(false)).expect("decided"));
    assert!(!names_leaf("/a/other", leaf, ok(true), ok(false)).expect("decided"));
}

/// A `/proc` that hides a process this one may not trace with `EPERM` (`hidepid=1`) refuses as one
/// that hides it with `ENOENT`.
#[skuld::test]
fn without_pidfd_info_a_hidepid_1_proc_refuses_naming_hidepid() {
    let _missing = fault::miss_pidfd_info();
    let _hidden = fault::hide_proc_as(libc::EPERM);
    match front_placement() {
        Err(crate::error::Error::Unsupported { detail, .. }) => assert!(detail.contains("hidepid"), "{detail}"),
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

/// A probe child that stays dumpable proves nothing about a front: the probe fails, naming that.
#[skuld::test]
fn a_probe_child_that_stays_dumpable_fails_the_probe() {
    let _missing = fault::miss_pidfd_info();
    let _dumpable = fault::keep_probe_dumpable();
    match front_placement() {
        Err(crate::error::Error::Io(e)) => assert!(e.to_string().contains("non-dumpable"), "{e}"),
        other => panic!("expected Io, got {other:?}"),
    }
}

/// `PIDFD_GET_INFO` refused on this process's own pidfd will refuse a front's too: the spawn is
/// refused, naming it.
#[skuld::test]
fn a_refused_pidfd_info_refuses_naming_it() {
    let _failing = fault::fail_pidfd_info();
    match front_placement() {
        Err(crate::error::Error::Unsupported { detail, .. }) => {
            assert!(detail.contains("PIDFD_GET_INFO failed"), "{detail}");
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}
