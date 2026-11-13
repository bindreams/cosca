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
            Step::Placement => fault::set_force_placement_write_result(fault::ForcedWrite::Returns0),
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
    assert!(error.fate().is_none(), "{step:?}: the program did not start: {error:?}");
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

/// The `cgroup` group's host has a delegated cgroup v2 with `cgroup.kill`, so a `Strongest` spawn
/// gets a leaf in it. This makes a leaf in the host's real tree, so the group is declared: it asks
/// for consent and fails the test if the leaf is left behind.
#[skuld::test]
fn a_strongest_spawn_on_a_host_with_a_delegated_cgroup_gets_a_leaf(#[fixture(cgroup)] _group: &Group) {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("ran");

    let child = writes_marker(&marker, ContainMode::Strongest)
        .spawn()
        .unwrap_or_else(|e| panic!("the spawn failed on a host with a delegated cgroup: {e}"));

    assert_eq!(child.containment(), Containment::CgroupV2);
    child.wait().expect("wait");
    assert!(marker.exists(), "the program ran");
}

/// A host that offers no cgroup this process can use is a process group for a `Strongest` spawn,
/// not an error, and the program runs. The own cgroup is one the mount does not show (the setup
/// call answers `ENOENT`, whoever runs it), in a directory standing for the cgroup filesystem, so
/// no real cgroup is touched.
#[skuld::test(labels = [])]
fn a_strongest_spawn_on_a_host_offering_no_usable_cgroup_gets_a_process_group() {
    let root = tempfile::tempdir().expect("tempdir");
    fault::set_force_own_cgroup("0::/not/here\n", root.path());
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("ran");

    let child = writes_marker(&marker, ContainMode::Strongest)
        .spawn()
        .unwrap_or_else(|e| panic!("a host offering no cgroup is a process group, not an error: {e}"));

    assert_eq!(child.containment(), Containment::ProcessGroup);
    child.wait().expect("wait");
    assert!(marker.exists(), "the program ran");
}

/// A refused placement is the same not-started `Error::Containment` whichever of fds 0 to 2 the
/// caller had open: with fds 0 and 2 closed, `std`'s status pipe takes the child's stderr number
/// and `std` returns before the child's hooks run, so the child must not hand `std` an error to
/// write there (its stderr is the caller's file, which stays empty). Runs in a process of its own,
/// since closing fds is process-wide.
///
/// Mutants: the refused child returns an error to `std`; the failure is `MayHaveStarted`.
#[skuld::test]
fn strongest_refuses_an_unplaced_child_as_not_started_with_fds_0_and_2_closed(#[fixture(cgroup)] _group: &Group) {
    use crate::test_own_process::{own_process, test_path};
    use crate::test_spawn::spawn;
    use crate::test_stdio::RestoreStdio;

    let Some(done) = own_process(
        test_path!(strongest_refuses_an_unplaced_child_as_not_started_with_fds_0_and_2_closed),
        spawn,
    ) else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("ran");
    let stderr_file = dir.path().join("stderr");
    let null = || crate::stdio::Stdio::from_file(std::fs::File::open("/dev/null").expect("open /dev/null"));
    let mut cmd = writes_marker(&marker, ContainMode::Strongest);
    // Opened before the close, so they land above stdio.
    cmd.stdin(null()).expect("set stdin");
    cmd.stdout(null()).expect("set stdout");
    cmd.stderr(crate::stdio::Stdio::from_file(
        std::fs::File::create(&stderr_file).expect("create the stderr file"),
    ))
    .expect("set stderr");
    let _forced = Step::Placement.force();

    let restore = RestoreStdio::close(&done, &[0, 2]);
    let spawned = cmd.spawn();
    drop(restore);

    let Err(error) = spawned else {
        panic!("a refused placement must fail a Strongest spawn");
    };
    assert!(matches!(error, Error::Containment { .. }), "not started: {error:?}");
    assert!(error.fate().is_none(), "the program did not start: {error:?}");
    assert!(!marker.exists(), "the program ran");
    assert_eq!(
        std::fs::read(&stderr_file).expect("read the stderr file"),
        b"",
        "the child wrote into its stderr"
    );
}

/// A refused placement is the same not-started `Error::Containment` when another party reaps the
/// refused child before the spawn reads its identity (here `SIGCHLD` is ignored, so the kernel
/// reaps it): the identity is gone, but the leaf's verdict says the program never ran, and the
/// error names the cgroup. Runs in a process of its own, since the disposition is process-wide.
///
/// Mutant: the vanished identity answers `MayHaveStarted` with an identity error.
#[skuld::test]
fn strongest_refuses_an_unplaced_child_as_not_started_when_another_party_reaps_it(#[fixture(cgroup)] _group: &Group) {
    use crate::test_own_process::{own_process, test_path};
    use crate::test_spawn::spawn;

    let Some(_done) = own_process(
        test_path!(strongest_refuses_an_unplaced_child_as_not_started_when_another_party_reaps_it),
        spawn,
    ) else {
        return;
    };
    // SAFETY: setting a disposition is async-signal-safe; this process runs this test alone.
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("ran");
    let _forced = Step::Placement.force();

    let spawned = writes_marker(&marker, ContainMode::Strongest).spawn();

    let Err(error) = spawned else {
        panic!("a refused placement must fail a Strongest spawn");
    };
    assert!(matches!(error, Error::Containment { .. }), "not started: {error:?}");
    assert!(error.fate().is_none(), "the program did not start: {error:?}");
    let said = crate::error::Report(&error).to_string();
    assert!(
        said.contains("could not be placed"),
        "the error names the placement: {said}"
    );
    assert!(!marker.exists(), "the program ran");
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
