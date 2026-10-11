//! The sweep of a leaf's child cgroups, on real cgroups: the cgroup lane (the `cgroup` group, as
//! root). Each test makes a scratch cgroup under the lane's own, which its guard removes.

use std::os::fd::AsFd as _;
use std::path::Path;

use super::{cgroup_id, find_descendant, LeafDir, Walked};
use crate::containment::cgroup::dir_walk_tests::{enter_private_mount_ns, id_at, DeepTree, Scratch, TmpfsOver};
use crate::containment::cgroup::fault::{fail_walk_step, set_before_sweep_remove};
use crate::containment::cgroup::WalkStep;
use crate::test_groups::{cgroup, Group};

/// The descriptors a walk or a sweep holds at once beyond those held before it: two, whether it
/// lists a cgroup (the cgroup and its listing) or opens one in pieces (the piece before and the one
/// opening).
const PEAK: libc::rlim_t = 2;

/// The highest descriptor number open, plus one: a limit at it allows no further descriptor.
fn fds_in_use() -> libc::rlim_t {
    std::fs::read_dir("/proc/self/fd")
        .expect("list fds")
        .map(|entry| {
            entry
                .expect("an fd entry")
                .file_name()
                .to_string_lossy()
                .parse::<libc::rlim_t>()
                .expect("a number")
        })
        .max()
        .expect("some fd is open")
        + 1
}

/// The sweep holds no descriptor from one cgroup to the next, however wide or deep the tree: each
/// time it is about to open a cgroup, this process holds the descriptors it held before the sweep.
/// Mutant: "the sweep holds one descriptor per level".
#[skuld::test]
fn cgroup_the_sweep_holds_no_descriptor_between_cgroups(#[fixture(cgroup)] _group: &Group) {
    let scratch = Scratch::new("sweep-fds");
    for i in 0..20 {
        scratch.make(&format!("w{i}/{}", ["d"; 10].join("/")));
    }
    let leaf = LeafDir::open_for_test(scratch.path());
    let open_fds = || std::fs::read_dir("/proc/self/fd").expect("list fds").count();
    let before = open_fds();
    let counts = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let _hook = crate::containment::cgroup::fault::set_before_walk_open({
        let counts = std::rc::Rc::clone(&counts);
        move |_| counts.borrow_mut().push(open_fds())
    });
    assert_eq!(leaf.remove_children().expect("the sweep"), 20 * 11);
    let counts = counts.borrow();
    assert_eq!(counts.len(), 1 + 20 * 11, "the sweep visits every cgroup once");
    assert!(
        counts.iter().all(|&n| n == before),
        "{before} before the sweep, then {counts:?}"
    );
    assert_eq!(subdirs(scratch.path()), 0, "every cgroup is removed");
}

/// A tree nested deeper than the descriptor limit is swept whole: every cgroup removed, deepest
/// first, and every id recorded. Runs in a process of its own: the limit is process-wide.
/// Mutant: "the sweep holds one descriptor per level".
#[skuld::test]
fn cgroup_a_sweep_of_a_tree_deeper_than_the_fd_limit_removes_every_cgroup(#[fixture(cgroup)] _group: &Group) {
    use crate::test_own_process::{own_process, test_path};
    use crate::test_spawn::spawn;

    const DEPTH: usize = 100;

    let Some(done) = own_process(
        test_path!(cgroup_a_sweep_of_a_tree_deeper_than_the_fd_limit_removes_every_cgroup),
        spawn,
    ) else {
        return;
    };
    let scratch = Scratch::new("sweep-deep");
    let mut chain = Vec::new();
    for depth in 1..=DEPTH {
        chain.push(id_at(&scratch.make(&["d"; DEPTH][..depth].join("/"))));
    }
    let leaf = LeafDir::open_for_test(scratch.path());
    let lowered = crate::test_child::lower_fd_limit(&done, fds_in_use() + PEAK);
    let swept = leaf.remove_children();
    drop(lowered);
    assert_eq!(swept.expect("the sweep"), DEPTH);
    assert_eq!(subdirs(scratch.path()), 0, "every cgroup is removed");
    let swept = leaf.swept();
    assert!(chain.iter().all(|&id| swept.holds(id)), "every id is recorded");
}

/// A tree whose path to the bottom is longer than `PATH_MAX` is swept whole: every cgroup removed
/// and the bottom's id recorded. Mutant: "a path past `PATH_MAX` is opened in one piece".
#[skuld::test]
fn cgroup_a_sweep_of_a_path_longer_than_path_max_removes_every_cgroup(#[fixture(cgroup)] _group: &Group) {
    const DEPTH: usize = 30;
    let scratch = Scratch::new("sweep-long");
    let root = scratch.fd();
    let chain = DeepTree::new(&root, &"n".repeat(200), DEPTH);
    let bottom = super::cgroup_id(std::os::fd::AsFd::as_fd(chain.bottom())).expect("the bottom's id");
    let leaf = LeafDir::open_for_test(scratch.path());
    let open_fds = || std::fs::read_dir("/proc/self/fd").expect("list fds").count();
    let before = open_fds();
    let counts = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let _hook = crate::containment::cgroup::fault::set_before_walk_open({
        let counts = std::rc::Rc::clone(&counts);
        move |_| counts.borrow_mut().push(open_fds())
    });
    assert_eq!(leaf.remove_children().expect("the sweep"), DEPTH);
    assert_eq!(subdirs(scratch.path()), 0, "every cgroup is removed");
    assert!(leaf.swept().holds(bottom), "the bottom's id is recorded");
    let counts = counts.borrow();
    assert_eq!(counts.len(), 1 + DEPTH, "the sweep visits every cgroup once");
    assert!(
        counts.iter().all(|&n| n == before),
        "{before} before the sweep, then {counts:?}"
    );
}

/// How many directories lie under `path`.
fn subdirs(path: &std::path::Path) -> usize {
    std::fs::read_dir(path)
        .expect("list the scratch cgroup")
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| 1 + subdirs(&e.path()))
        .sum()
}

/// A walk and a sweep of a chain whose path takes many pieces hold no more than [`PEAK`]
/// descriptors beyond those held before them, however many pieces. Runs in a process of its own:
/// the limit is process-wide. Mutants: "`open_cgroup` keeps every piece"; "the traversal keeps
/// every cgroup it opened".
#[skuld::test]
fn cgroup_a_walk_and_a_sweep_of_a_many_piece_chain_hold_at_most_the_peak(#[fixture(cgroup)] _group: &Group) {
    use crate::test_own_process::{own_process, test_path};
    use crate::test_spawn::spawn;

    /// Two names to a piece.
    const NAME: usize = 1500;
    const DEPTH: usize = 30;

    let Some(done) = own_process(
        test_path!(cgroup_a_walk_and_a_sweep_of_a_many_piece_chain_hold_at_most_the_peak),
        spawn,
    ) else {
        return;
    };
    let scratch = Scratch::new("pieces-fds");
    let root = scratch.fd();
    let chain = DeepTree::new(&root, &"n".repeat(NAME), DEPTH);
    let bottom = cgroup_id(chain.bottom().as_fd()).expect("the bottom's id");
    let leaf = LeafDir::open_for_test(scratch.path());
    let lowered = crate::test_child::lower_fd_limit(&done, fds_in_use() + PEAK);
    let found = find_descendant(root.as_fd(), bottom);
    let absent = find_descendant(root.as_fd(), 1);
    let swept = leaf.remove_children();
    drop(lowered);
    assert!(matches!(found, Walked::Found), "{found:?}");
    assert!(matches!(absent, Walked::Absent), "{absent:?}");
    assert_eq!(swept.expect("the sweep"), DEPTH);
}

// control flow -----

/// A listing that fails part-way, at a cgroup the sweep already found, still has what was found
/// removed, and then fails with the listing's own `errno`. Mutants: "the sweep fails before it
/// removes anything"; "a failed traversal is a success".
#[skuld::test]
fn cgroup_a_sweep_whose_traversal_fails_removes_what_it_found_then_fails(#[fixture(cgroup)] _group: &Group) {
    let scratch = Scratch::new("sweep-fails");
    scratch.make("a/x");
    scratch.make("b");
    let leaf = LeafDir::open_for_test(scratch.path());
    let failing = fail_walk_step("./b", WalkStep::List, libc::EIO);
    let swept = leaf.remove_children();
    drop(failing);
    match swept {
        Err(e) => assert_eq!(e.raw_os_error(), Some(libc::EIO), "{e}"),
        Ok(n) => panic!("the sweep removed {n} and did not fail"),
    }
    assert!(!scratch.path().join("b").exists(), "`b` was found, so it is removed");
    assert!(scratch.path().join("a/x").exists(), "`a/x` was never found");
}

/// A root that is gone has nothing to remove: `Ok(0)`, whichever step found it gone. Mutant: "a gone
/// root fails the sweep".
#[skuld::test]
fn cgroup_a_sweep_of_a_gone_root_removes_nothing(#[fixture(cgroup)] _group: &Group) {
    let scratch = Scratch::new("sweep-gone-root");
    scratch.make("a");
    let leaf = LeafDir::open_for_test(scratch.path());
    for step in [WalkStep::Open, WalkStep::List, WalkStep::Entries] {
        for errno in [libc::ENOENT, libc::ENODEV] {
            let _failing = fail_walk_step(".", step, errno);
            let swept = leaf.remove_children();
            assert!(matches!(swept, Ok(0)), "{step:?} {errno}: {swept:?}");
        }
    }
    assert!(scratch.path().join("a").exists());
}

/// A cgroup whose parent is gone by the time it is removed is skipped, not an error: the sweep
/// removes nothing and succeeds. Mutant: "a gone parent fails the sweep".
#[skuld::test]
fn cgroup_a_sweep_skips_a_cgroup_whose_parent_is_gone(#[fixture(cgroup)] _group: &Group) {
    let scratch = Scratch::new("sweep-parent-gone");
    scratch.make("p/x");
    let leaf = LeafDir::open_for_test(scratch.path());
    let (p, x) = (scratch.path().join("p"), scratch.path().join("p/x"));
    let _hook = set_before_sweep_remove(move |path| {
        if path == Path::new("./p/x") {
            std::fs::remove_dir(&x).expect("remove `p/x` before the sweep does");
            std::fs::remove_dir(&p).expect("remove `p` before the sweep does");
        }
    });
    let swept = leaf.remove_children();
    assert!(matches!(swept, Ok(0)), "{swept:?}");
}

/// A cgroup whose parent has a mount over it by the time it is removed is skipped, and said so at
/// debug; the parent, a mount point, is refused `EBUSY`, and said so too. Nothing under the mount
/// is removed. Mutants: "a parent behind a mount fails the sweep"; "the skips are silent".
#[skuld::test]
fn cgroup_a_sweep_skips_a_cgroup_whose_parent_is_behind_a_mount(#[fixture(cgroup)] _group: &Group) {
    crate::log_capture::install();
    let scratch = Scratch::new("sweep-parent-mounted");
    scratch.make("p/x");
    let p = scratch.path().join("p");
    let (swept, logs) = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                enter_private_mount_ns();
                let leaf = LeafDir::open_for_test(scratch.path());
                let mounted = std::rc::Rc::new(std::cell::RefCell::new(None));
                let _hook = set_before_sweep_remove({
                    let (mounted, p) = (std::rc::Rc::clone(&mounted), p.clone());
                    move |path| {
                        if path == Path::new("./p/x") {
                            *mounted.borrow_mut() = Some(TmpfsOver::new(&p));
                        }
                    }
                });
                let mark = crate::log_capture::mark();
                let swept = leaf.remove_children();
                let logs = crate::log_capture::records_since_on_current_thread(mark, "cgroup v2: ./p");
                drop(mounted.borrow_mut().take());
                (swept, logs)
            })
            .join()
            .expect("the sweeping thread")
    });
    assert!(matches!(swept, Ok(0)), "{swept:?}");
    assert!(p.join("x").exists(), "`p/x` is still there, under the mount");
    let said = |what: &str| {
        logs.iter()
            .any(|(level, text)| *level == log::Level::Debug && text.contains(what))
    };
    assert!(said("./p/x is under a mount"), "{logs:?}");
    assert!(said("./p is busy"), "{logs:?}");
}

/// A cgroup with a live task in it survives the sweep, and is not counted; its empty sibling is
/// removed. The sweep says at debug that it is busy. Mutants: "a busy cgroup fails the sweep"; "a
/// busy cgroup is counted".
#[skuld::test]
fn cgroup_a_sweep_leaves_a_busy_cgroup_and_does_not_count_it(#[fixture(cgroup)] _group: &Group) {
    crate::log_capture::install();
    let scratch = Scratch::new("sweep-busy");
    let busy = scratch.make("busy");
    scratch.make("idle");
    let task = crate::containment::cgroup::test_support::fork_running(|| loop {
        // SAFETY: `pause` is async-signal-safe.
        unsafe { libc::pause() };
    });
    std::fs::write(busy.join("cgroup.procs"), task.pid().to_string()).expect("place the task in `busy`");
    let leaf = LeafDir::open_for_test(scratch.path());
    let mark = crate::log_capture::mark();
    let swept = leaf.remove_children();
    let logs = crate::log_capture::records_since_on_current_thread(mark, "cgroup v2: ./busy");
    drop(task);
    assert!(matches!(swept, Ok(1)), "{swept:?}");
    assert!(busy.exists(), "the busy cgroup survives");
    assert!(!scratch.path().join("idle").exists(), "its idle sibling is removed");
    assert!(
        logs.iter()
            .any(|(level, text)| *level == log::Level::Debug && text.contains("is busy")),
        "{logs:?}"
    );
}

/// An `rmdir` refused for any reason but gone or busy fails the sweep with the `errno`. The
/// stand-in's directories are no cgroups, so one that holds a file is refused `ENOTEMPTY`. Mutant:
/// "any `rmdir` refusal is skipped".
#[skuld::test]
fn a_sweep_whose_rmdir_is_refused_fails_with_its_errno() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("c")).expect("make the child");
    std::fs::write(dir.path().join("c/f"), b"").expect("make a file in it");
    let leaf = LeafDir::open_for_test(dir.path());
    match leaf.remove_children() {
        Err(e) => assert_eq!(e.raw_os_error(), Some(libc::ENOTEMPTY), "{e}"),
        Ok(n) => panic!("the sweep removed {n} and did not fail"),
    }
    assert!(dir.path().join("c/f").exists());
}
