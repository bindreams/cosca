//! Linux: what a spawn gets when the host offers a delegated cgroup and a step of its leaf fails.
//! `Strongest` fails the spawn, and the program never runs. `BestEffort` degrades to the process
//! group the spawn set up before the leaf. The `cgroup` group's end-of-test check fails any test
//! that leaves its `cosca-*` leaf behind, which is how each row shows the failed spawn removed it.

use crate::containment::cgroup::fault;
use crate::error::Error;
use crate::test_child::Console;
use crate::test_groups::{cgroup, Group};
use crate::{ContainMode, Containment};

/// A command that writes `marker` when it runs: its absence proves the program never started.
fn writes_marker(marker: &std::path::Path, mode: ContainMode) -> crate::Command {
    let mut cmd = crate::test_child::command(Console::Hidden);
    cmd.args(["sh", "-c", "touch \"$0\""]).arg(marker);
    cmd.contain_with(mode);
    cmd
}

/// Clears this thread's forced placement result, which only the forked child takes, and a forced
/// leaf failure the spawn did not reach.
struct Forced;

impl Drop for Forced {
    fn drop(&mut self) {
        fault::take_force_placement_write_result();
        fault::take_force_leaf_open_failure();
    }
}

/// How the leaf's setup is made to fail.
#[derive(Debug, Clone, Copy)]
enum Step {
    /// The leaf directory cannot be held after its `mkdir`.
    Leaf,
    /// The child's `cgroup.procs` write writes nothing.
    Placement,
}

impl Step {
    fn force(self) -> Forced {
        match self {
            Step::Leaf => fault::set_force_leaf_open_failure(true),
            Step::Placement => fault::set_force_placement_write_result(0),
        }
        Forced
    }
}

/// A host that offers a cgroup, and a leaf step that fails: `Strongest` is an error that names the
/// cgroup, and the program never ran.
fn assert_strongest_fails(step: Step) {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("ran");
    let _forced = step.force();

    let spawned = writes_marker(&marker, ContainMode::Strongest).spawn();

    let Err(error) = spawned else {
        panic!("{step:?}: a failed leaf step must fail a Strongest spawn");
    };
    assert!(matches!(error, Error::Containment { .. }), "{step:?}: {error:?}");
    let said = crate::error::Report(&error).to_string();
    assert!(said.contains("cgroup"), "{step:?}: the error names the cgroup: {said}");
    assert!(!marker.exists(), "{step:?}: the program ran");
}

/// The same failure under `BestEffort`: the spawn degrades to its process group and the program
/// runs.
fn assert_best_effort_degrades(step: Step) {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("ran");
    let _forced = step.force();

    let child = writes_marker(&marker, ContainMode::BestEffort)
        .spawn()
        .unwrap_or_else(|e| panic!("{step:?}: BestEffort degrades: {e}"));

    assert_eq!(child.containment(), Containment::ProcessGroup, "{step:?}");
    child.wait().expect("wait");
    assert!(marker.exists(), "{step:?}: the program ran");
}

/// `Strongest` follows what the host offers, whichever host this is: a leaf where the inspection
/// finds a delegated cgroup, and a process group, not an error, where it finds none.
#[skuld::test]
fn a_strongest_spawn_gets_what_the_inspection_offers() {
    let offered = crate::containment::cgroup::offered_cgroup()
        .expect("this host's /proc/self/cgroup can be read")
        .is_some();
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("ran");

    let child = writes_marker(&marker, ContainMode::Strongest)
        .spawn()
        .unwrap_or_else(|e| panic!("cgroup offered: {offered}, and the spawn failed: {e}"));

    let want = if offered {
        Containment::CgroupV2
    } else {
        Containment::ProcessGroup
    };
    assert_eq!(child.containment(), want);
    child.wait().expect("wait");
    assert!(marker.exists(), "the program ran");
}

#[skuld::test]
fn strongest_fails_the_spawn_when_its_leaf_cannot_be_made(#[fixture(cgroup)] _group: &Group) {
    assert_strongest_fails(Step::Leaf);
}

#[skuld::test]
fn strongest_fails_the_spawn_when_its_child_cannot_be_placed(#[fixture(cgroup)] _group: &Group) {
    assert_strongest_fails(Step::Placement);
}

#[skuld::test]
fn best_effort_degrades_when_its_leaf_cannot_be_made(#[fixture(cgroup)] _group: &Group) {
    assert_best_effort_degrades(Step::Leaf);
}

#[skuld::test]
fn best_effort_degrades_when_its_child_cannot_be_placed(#[fixture(cgroup)] _group: &Group) {
    assert_best_effort_degrades(Step::Placement);
}
