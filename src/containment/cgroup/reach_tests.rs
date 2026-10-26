//! Placing a task in a leaf's subtree by its cgroup id, and deciding before a spawn whether a front
//! can be placed. Unprivileged: the ids are forced, and the probe reads a child of this process.

use std::os::fd::{AsFd as _, OwnedFd};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use super::{dying_in, front_placement, Subtree};
use crate::containment::cgroup::fault::{self, ProbeEnd, ProbeStep};
use crate::containment::cgroup::test_support::alone;
use crate::send_log::Via;
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
        crate::containment::cgroup::Swept::default(),
        super::PlacedAtRemoval::default(),
        Arc::new(AtomicBool::new(killed)),
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
        HIGH,
        Some(Arc::new(fd)),
        Some("/stand-in-leaf".to_owned()),
        swept,
        super::PlacedAtRemoval::default(),
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
    front_placement(|| Ok(HIGH)).expect("placeable by a pidfd's cgroup id");
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
    front_placement(|| Ok(HIGH)).expect("the lane's /proc shows its root every process");
}

/// Without `PIDFD_GET_INFO`, a `/proc` that hides a process this one may not trace refuses an
/// elevated, contained spawn, naming `hidepid`.
#[skuld::test]
fn without_pidfd_info_a_hidepid_proc_refuses_naming_hidepid() {
    let _missing = fault::miss_pidfd_info();
    let _hidden = fault::hide_proc();
    match front_placement(|| Ok(HIGH)) {
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
    match front_placement(|| Ok(HIGH)) {
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
    match front_placement(|| Ok(HIGH)) {
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
    let shown = front_placement(|| Ok(HIGH));
    let hidden = {
        let _hidden = fault::hide_proc();
        front_placement(|| Ok(HIGH))
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
        HIGH,
        Some(leaf.shared()),
        Some("/stand-in-leaf".to_owned()),
        leaf.swept(),
        super::PlacedAtRemoval::default(),
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
    match front_placement(|| Ok(HIGH)) {
        Err(crate::error::Error::Unsupported { detail, .. }) => assert!(detail.contains("hidepid"), "{detail}"),
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

/// A probe child that stays dumpable proves nothing about a front: the probe fails, naming that.
#[skuld::test]
fn a_probe_child_that_stays_dumpable_fails_the_probe() {
    let _missing = fault::miss_pidfd_info();
    let _dumpable = fault::keep_probe_dumpable();
    match front_placement(|| Ok(HIGH)) {
        Err(crate::error::Error::Io(e)) => assert!(e.to_string().contains("non-dumpable"), "{e}"),
        other => panic!("expected Io, got {other:?}"),
    }
}

/// `PIDFD_GET_INFO` refused on this process's own pidfd will refuse a front's too: the spawn is
/// refused, naming it.
#[skuld::test]
fn a_refused_pidfd_info_refuses_naming_it() {
    let _failing = fault::fail_pidfd_info();
    match front_placement(|| Ok(HIGH)) {
        Err(crate::error::Error::Unsupported { detail, .. }) => {
            assert!(detail.contains("PIDFD_GET_INFO failed"), "{detail}");
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
        match front_placement(|| Err(std::io::Error::from_raw_os_error(errno))) {
            Err(crate::error::Error::Unsupported { detail, .. }) => {
                let named = std::io::Error::from_raw_os_error(errno).to_string();
                assert!(detail.contains(&named), "{errno}: {detail}");
                assert!(detail.contains("before anything is spawned"), "{errno}: {detail}");
            }
            other => panic!("{errno}: expected Unsupported, got {other:?}"),
        }
    }
}

/// Any other failure to read the leaf's id is the spawn's I/O error, not a claim about the host.
#[skuld::test]
fn any_other_failure_to_read_the_leaf_id_is_an_io_error() {
    match front_placement(|| Err(std::io::Error::from_raw_os_error(libc::ENOMEM))) {
        Err(crate::error::Error::Io(e)) => assert!(e.to_string().contains("leaf"), "{e}"),
        other => panic!("expected Io, got {other:?}"),
    }
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
    match crate::identity::proc_view() {
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
            let mut probe = super::fork_probe(&proc_dir(), parent, false).expect("fork the probe");
            let mut report = [0u8; 2];
            probe.ready_read.read_exact(&mut report).expect("the probe reports");
            // Kept past this thread's end: the probe exits by itself once it closes.
            ready_tx
                .send((probe.pid, report, probe.release))
                .expect("report the probe");
            // The thread ends when the test lets it go, or when the test fails and drops `go_tx`.
            _ = go_rx.recv();
        });
        let (pid, report, _release) = ready_rx.recv().expect("the probe's pid");
        let pidfd = ProbeGuard::of(pid);
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
    let mut probe = super::fork_probe(&proc_dir(), not_the_parent, false).expect("fork the probe");
    let pidfd = ProbeGuard::of(probe.pid);
    // The child's end of the pipe closes with the child: end of file, with nothing reported. One
    // read, so a probe that reports instead fails the assertion, and does not leave the read
    // waiting for the end of a probe that waits to be killed.
    let mut reported = [0u8; 2];
    let read = probe.ready_read.read(&mut reported).expect("read the probe's report");
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

/// Forks two probes, the second while the first's descriptors are open in this process, and checks
/// that each child holds only its own report pipe (fd 3) and release socket (fd 4): no other
/// probe's descriptor, nor anything else of this process's. Dumpable, so its `/proc/<pid>/fd` is
/// readable without `CAP_SYS_PTRACE`.
fn assert_two_probes_hold_only_their_own() {
    use std::io::Read as _;

    let proc = proc_dir();
    let parent = rustix::process::getpid().as_raw_nonzero().get();
    let mut first = super::fork_probe(&proc, parent, true).expect("fork the first probe");
    let _first_guard = ProbeGuard::of(first.pid);
    let mut second = super::fork_probe(&proc, parent, true).expect("fork the second probe");
    let _second_guard = ProbeGuard::of(second.pid);
    // Each child closes what it inherited before it reports.
    let mut report = [0u8; 2];
    first
        .ready_read
        .read_exact(&mut report)
        .expect("the first probe reports");
    second
        .ready_read
        .read_exact(&mut report)
        .expect("the second probe reports");
    for (name, probe) in [("first", &first), ("second", &second)] {
        let held = descriptors_of(probe.pid);
        assert_eq!(
            held.keys().copied().collect::<Vec<_>>(),
            [3, 4],
            "the {name} probe's child holds {held:?}"
        );
        assert_eq!(
            held[&3],
            own_descriptor(&probe.ready_read),
            "the {name} probe's report pipe"
        );
        assert!(
            held[&4].starts_with("socket:"),
            "the {name} probe's release socket: {held:?}"
        );
    }
    assert_ne!(
        descriptors_of(second.pid)[&4],
        own_descriptor(&first.release),
        "the second probe's child holds the first's release end"
    );
}

/// Two concurrent probes' children each hold only their own descriptors, so neither keeps the
/// other's release end open. Mutant: "the child keeps the descriptors it inherited".
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

/// The probe's child is killed through a pidfd that names it, never by its number, and reaped
/// through it. Mutants: "kill the probe's child by pid" (the route is recorded by the helper that
/// makes the syscall), "the kill is recorded and not made" (the child then exits by itself, unkilled,
/// once released).
#[skuld::test]
fn the_probe_child_is_killed_through_its_pidfd() {
    let _missing = fault::miss_pidfd_info();
    let _hidden = fault::hide_proc();
    fault::take_probe_steps();
    front_placement(|| Ok(HIGH)).expect_err("a hidden /proc refuses");
    assert_eq!(
        fault::take_probe_steps(),
        [
            ProbeStep::Kill(Via::Pidfd, libc::SIGKILL),
            ProbeStep::Reap(Via::Pidfd, ProbeEnd::Signal(libc::SIGKILL))
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

/// The `warn`s on this thread since `mark`.
fn warns_since(mark: usize) -> Vec<String> {
    crate::log_capture::records_since_on_current_thread(mark, "")
        .into_iter()
        .filter(|(level, _)| *level == log::Level::Warn)
        .map(|(_, text)| text)
        .collect()
}

/// A probe's child that no pidfd can pin (`pidfd_open` fails with `EMFILE`) is killed and reaped by
/// its number, as before pidfds, and no probe process is left. Mutants: "a failed `pidfd_open`
/// returns, leaving the probe's child unreaped", "the kill by number is not made".
#[skuld::test]
fn a_probe_child_no_pidfd_can_pin_is_killed_and_reaped_by_its_number() {
    let _missing = fault::miss_pidfd_info();
    let _hidden = fault::hide_proc();
    let forked = std::rc::Rc::new(std::cell::Cell::new(None));
    let _unpinned = fault::set_before_probe_pin({
        let forked = forked.clone();
        move |pid| {
            forked.set(Some(pid));
            Some(libc::EMFILE)
        }
    });
    fault::take_probe_steps();
    front_placement(|| Ok(HIGH)).expect_err("a hidden /proc refuses");
    let pid = forked.get().expect("the probe forked");
    assert_eq!(
        fault::take_probe_steps(),
        [
            ProbeStep::Kill(Via::Pid, libc::SIGKILL),
            ProbeStep::Reap(Via::Pid, ProbeEnd::Signal(libc::SIGKILL))
        ]
    );
    assert_eq!(no_child_holds(pid), Ok(true), "the probe's child {pid} is left");
}

/// A probe's child reaped elsewhere before its pidfd was opened is not this process's to kill: its
/// number is sent nothing, and the probe fails. Mutant: "a probe reaped elsewhere is killed by its
/// number".
#[skuld::test]
fn a_probe_child_reaped_elsewhere_before_its_pin_is_sent_nothing() {
    let _missing = fault::miss_pidfd_info();
    let _reaped = fault::set_before_probe_pin(|pid| {
        // SAFETY: `pid` is this test's own unreaped child.
        assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0, "kill the probe's child");
        crate::test_child::reaped_elsewhere::reap_behind(pid as u32);
        None
    });
    fault::take_probe_steps();
    let err = front_placement(|| Ok(HIGH)).expect_err("the probe has no child left");
    assert_eq!(fault::take_probe_steps(), [], "nothing was sent");
    assert!(matches!(err, crate::error::Error::Io(_)), "{err:?}");
}

/// A probe's child whose kill through its pidfd fails other than `ESRCH` is sent nothing by its
/// number: it is released, exits by itself, and is reaped through the pidfd that still names it.
/// The failed kill is a `warn` naming the child. Mutants: "a failed kill falls back to the number",
/// "the failed kill is logged below `warn`", "the child is released only by its socket's close" (it
/// then exits with another status), "the reap goes by number".
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
    front_placement(|| Ok(HIGH)).expect_err("a hidden /proc refuses");
    let pid = forked.get().expect("the probe's child was to be killed");
    assert_eq!(
        fault::take_probe_steps(),
        [
            ProbeStep::Kill(Via::Pidfd, libc::SIGKILL),
            ProbeStep::Reap(Via::Pidfd, ProbeEnd::Exit(super::RELEASED))
        ]
    );
    let warns = warns_since(mark);
    assert!(
        warns.iter().any(|w| w.contains(&format!("child {pid}"))),
        "a warn names the probe's child {pid}: {warns:?}"
    );
    assert_eq!(no_child_holds(pid), Ok(true), "the probe's child {pid} is left");
}

/// A probe's child that no pidfd can pin, and whose kill by number fails, is released and reaped by
/// its number, and the failed kill is a `warn` naming it. Mutants: "the kill's answer is ignored",
/// "the child is released only by its socket's close".
#[skuld::test]
fn a_probe_child_whose_kill_by_number_fails_is_released_and_warned() {
    crate::log_capture::install();
    let _missing = fault::miss_pidfd_info();
    let _hidden = fault::hide_proc();
    let forked = std::rc::Rc::new(std::cell::Cell::new(None));
    let _unpinned = fault::set_before_probe_pin({
        let forked = forked.clone();
        move |pid| {
            forked.set(Some(pid));
            Some(libc::EMFILE)
        }
    });
    let _failed = fault::set_before_probe_kill(|_| Some(libc::EPERM));
    fault::take_probe_steps();
    let mark = crate::log_capture::mark();
    front_placement(|| Ok(HIGH)).expect_err("a hidden /proc refuses");
    let pid = forked.get().expect("the probe forked");
    assert_eq!(
        fault::take_probe_steps(),
        [
            ProbeStep::Kill(Via::Pid, libc::SIGKILL),
            ProbeStep::Reap(Via::Pid, ProbeEnd::Exit(super::RELEASED))
        ]
    );
    let warns = warns_since(mark);
    assert!(
        warns.iter().any(|w| w.contains(&format!("child {pid}"))),
        "a warn names the probe's child {pid}: {warns:?}"
    );
    assert_eq!(no_child_holds(pid), Ok(true), "the probe's child {pid} is left");
}

/// A failed kill of one probe's child is not held up by a second probe's child forked while the
/// first's release end was open in this process: the first child is released and reaped, while the
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
            let mut probe = super::fork_probe(&proc_dir(), parent, false).expect("fork the second probe");
            let mut report = [0u8; 2];
            probe
                .ready_read
                .read_exact(&mut report)
                .expect("the second probe reports");
            *second.borrow_mut() = Some(probe);
            Some(libc::EPERM)
        }
    });
    fault::take_probe_steps();
    front_placement(|| Ok(HIGH)).expect_err("a hidden /proc refuses");
    assert_eq!(
        fault::take_probe_steps(),
        [
            ProbeStep::Kill(Via::Pidfd, libc::SIGKILL),
            ProbeStep::Reap(Via::Pidfd, ProbeEnd::Exit(super::RELEASED))
        ]
    );
    let super::Probe {
        pid,
        hold,
        ready_read: _,
        release,
    } = second.borrow_mut().take().expect("the second probe forked");
    assert_eq!(
        no_child_holds(pid),
        Ok(false),
        "the second probe's child {pid} still runs"
    );
    super::kill_and_reap(pid, hold, release).expect("end the second probe");
    assert_eq!(
        fault::take_probe_steps(),
        [
            ProbeStep::Kill(Via::Pidfd, libc::SIGKILL),
            ProbeStep::Reap(Via::Pidfd, ProbeEnd::Signal(libc::SIGKILL))
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
    let err = front_placement(|| Ok(HIGH)).expect_err("a hidden /proc refuses");
    assert!(matches!(err, crate::error::Error::Unsupported { .. }), "{err:?}");
    assert_eq!(
        fault::take_probe_steps(),
        [
            ProbeStep::Kill(Via::Pidfd, libc::SIGKILL),
            ProbeStep::Reap(Via::Pidfd, ProbeEnd::Elsewhere)
        ]
    );
}

/// The same for a child no pidfd pins, killed and reaped by its number. Mutant: "`ECHILD` at the
/// reap by number fails the probe". Run [`alone`].
#[skuld::test]
fn a_probe_child_no_pidfd_pins_reaped_by_an_ignored_sigchld_keeps_the_verdict() {
    if !alone(
        "containment::cgroup::reach::reach_tests::a_probe_child_no_pidfd_pins_reaped_by_an_ignored_sigchld_keeps_the_verdict",
    ) {
        return;
    }
    let _ignored = ignore_sigchld();
    let _missing = fault::miss_pidfd_info();
    let _hidden = fault::hide_proc();
    let _unpinned = fault::set_before_probe_pin(|_| Some(libc::EMFILE));
    fault::take_probe_steps();
    let err = front_placement(|| Ok(HIGH)).expect_err("a hidden /proc refuses");
    assert!(matches!(err, crate::error::Error::Unsupported { .. }), "{err:?}");
    assert_eq!(
        fault::take_probe_steps(),
        [
            ProbeStep::Kill(Via::Pid, libc::SIGKILL),
            ProbeStep::Reap(Via::Pid, ProbeEnd::Elsewhere)
        ]
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
    let err = front_placement(|| Ok(HIGH)).expect_err("a hidden /proc refuses");
    assert!(matches!(err, crate::error::Error::Unsupported { .. }), "{err:?}");
    assert_eq!(
        fault::take_probe_steps(),
        [
            ProbeStep::Kill(Via::Pidfd, libc::SIGKILL),
            ProbeStep::Reap(Via::Pidfd, ProbeEnd::Elsewhere)
        ]
    );
}

/// A probe's child that is already dead when its kill through the pidfd answers `ESRCH` is reaped
/// through that pidfd, and nothing is sent by its number. Mutants: "`ESRCH` returns, leaving the
/// zombie", "`ESRCH` falls back to the number".
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
    front_placement(|| Ok(HIGH)).expect_err("a hidden /proc refuses");
    let pid = forked.get().expect("the probe's child was to be killed");
    assert_eq!(
        fault::take_probe_steps(),
        [
            ProbeStep::Kill(Via::Pidfd, libc::SIGKILL),
            ProbeStep::Reap(Via::Pidfd, ProbeEnd::Signal(libc::SIGKILL))
        ]
    );
    assert_eq!(no_child_holds(pid), Ok(true), "the probe's child {pid} is left");
}
