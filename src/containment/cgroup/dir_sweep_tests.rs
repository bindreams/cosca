//! The sweep of a leaf's child cgroups, on real cgroups: the cgroup lane (the `cgroup` group, as
//! root). Each test makes a scratch cgroup under the lane's own, which its guard removes.

use super::LeafDir;
use crate::containment::cgroup::dir_walk_tests::{id_at, Scratch};
use crate::test_groups::{cgroup, Group};

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
    /// The descriptors the sweep may hold at once, with room to spare.
    const SPARE: libc::rlim_t = 24;

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
    let highest: libc::rlim_t = std::fs::read_dir("/proc/self/fd")
        .expect("list fds")
        .map(|entry| {
            entry
                .expect("an fd entry")
                .file_name()
                .to_string_lossy()
                .parse()
                .expect("a number")
        })
        .max()
        .expect("some fd is open");
    let lowered = crate::test_child::lower_fd_limit(&done, highest + 1 + SPARE);
    let swept = leaf.remove_children();
    drop(lowered);
    assert_eq!(swept.expect("the sweep"), DEPTH);
    assert_eq!(subdirs(scratch.path()), 0, "every cgroup is removed");
    let swept = leaf.swept();
    assert!(chain.iter().all(|&id| swept.holds(id)), "every id is recorded");
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
