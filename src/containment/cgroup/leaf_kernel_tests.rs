//! A leaf asks the kernel its spawn started with, in every read it makes of a task by its number:
//! each test states a row for a pid the host does not have (above Linux's `PID_MAX_LIMIT`), which a
//! kernel of the leaf's own would not answer. A leaf made by a real spawn reads the spawn's kernel
//! the same way (`cgroup_a_created_leaf_reads_through_the_kernel_it_was_created_over`).

use super::{CgroupLeaf, Unsignalled};
use crate::containment::cgroup::test_support::{handle_of, kill_record, pidfd_of};
use crate::containment::cgroup::{NotPlaced, PlacedAtRemoval, Subtree, Swept};
use crate::containment::mechanism::Contains;
use crate::identity::{spawn_kernel, FakeKernel, HostKernel};
use crate::test_groups::{cgroup, Group};

/// A pid above any `pid_max`: no host process has it.
const STATED: u32 = 2_000_000_000;

/// A leaf over `kernel`, with the unified-hierarchy path `/leaf` and its own directory.
fn leaf_over(kernel: FakeKernel<'static>, dir: &std::path::Path) -> CgroupLeaf {
    let mut leaf = CgroupLeaf::for_test_at(dir.to_path_buf()).asking_for_test(spawn_kernel(kernel));
    leaf.set_cgroup_path_for_test("/leaf".to_owned());
    leaf
}

/// A leaf reads where its watched front is through the kernel its spawn started with: the row states
/// the front's `<pid>/cgroup` for a pid the host does not have.
///
/// Mutant: the leaf reads `/proc` through a host kernel of its own, so the pid has no cgroup to read
/// and the place is cleared instead of recorded.
#[skuld::test]
fn a_leaf_records_its_fronts_place_through_the_kernel_it_was_given() {
    let dir = tempfile::tempdir().expect("tempdir");
    let kernel = FakeKernel::over(&HostKernel)
        .same_view()
        .on_read(&format!("{STATED}/cgroup"), Ok(b"0::/elsewhere\n"));
    let mut leaf = leaf_over(kernel, dir.path());
    leaf.watch_front(STATED);

    leaf.record_watched_place();

    assert_eq!(leaf.placed_for_test().of(STATED), Some(false));
}

/// A leaf pins the members it lists through the kernel its spawn started with: the row refuses the
/// pidfd of a pid the host does not have, which the host answers `ESRCH` (no member, nothing said).
///
/// Mutant: the pin opens its pidfd through a host kernel of its own.
#[skuld::test]
fn a_leaf_pins_the_members_it_lists_through_the_kernel_it_was_given() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("cgroup.procs"), format!("{STATED}\n")).expect("state the leaf's member");
    let kernel = FakeKernel::over(&HostKernel).on_pidfd_open(STATED, Err(rustix::io::Errno::MFILE));
    let leaf = leaf_over(kernel, dir.path());

    let (listed, unobserved) = leaf.list_members(None);

    assert!(
        listed.is_empty(),
        "a member that could not be pinned is not listed: {listed:?}"
    );
    assert_eq!(unobserved.len(), 1, "it is reported: {unobserved:?}");
    assert_eq!(unobserved[0].pid, Some(STATED), "{unobserved:?}");
}

/// A member `terminate` is to signal is pinned through the leaf's kernel: its row refuses the pidfd,
/// so the member is unproven, where the host answers `ESRCH` (gone, so nothing to signal).
///
/// Mutant: `terminate_member` opens the pin through a host kernel.
#[skuld::test]
fn terminate_pins_a_member_through_the_kernel_the_leaf_was_given() {
    let dir = tempfile::tempdir().expect("tempdir");
    let kernel = FakeKernel::over(&HostKernel).on_pidfd_open(STATED, Err(rustix::io::Errno::MFILE));
    let leaf = leaf_over(kernel, dir.path());
    let subtree = leaf.subtree_with(None);

    let result = leaf.terminate_member(STATED, &subtree, crate::signal::Signal::Term);

    assert!(
        matches!(result, Err(Unsignalled::Unproven(_))),
        "a member that could not be pinned is unproven"
    );
}

/// A member `terminate` has pinned is placed through the leaf's kernel: its row says the member is in
/// another cgroup, so it is no member of the leaf and is not signalled. Where the host is asked, the
/// pid has no cgroup to read and the member is unproven.
///
/// Mutant: `terminate_member` places the member through a host kernel.
#[skuld::test]
fn terminate_places_a_pinned_member_through_the_kernel_the_leaf_was_given() {
    let dir = tempfile::tempdir().expect("tempdir");
    // The pin is this process's own pidfd, which is never signalled: the member is outside the leaf.
    let kernel = FakeKernel::over(&HostKernel)
        .same_view()
        .on_pidfd_open(STATED, Ok(pidfd_of(std::process::id())))
        .on_read(&format!("{STATED}/cgroup"), Ok(b"0::/elsewhere\n"));
    let leaf = leaf_over(kernel, dir.path());
    let subtree = leaf.subtree_with(None);

    let result = leaf.terminate_member(STATED, &subtree, crate::signal::Signal::Term);

    assert!(
        matches!(result, Ok(crate::signal::Sent::Gone)),
        "a pinned member outside the leaf is not signalled, and is no error"
    );
}

/// `would_reach` places a task through the leaf's kernel: its row says the task is under the leaf.
/// Where the host is asked, the pid has no cgroup to read and the question fails. A real leaf, whose
/// cgroup id `would_reach` reads.
///
/// Mutant: `would_reach` places the task through a host kernel.
#[skuld::test]
fn cgroup_would_reach_places_a_task_through_the_kernel_the_leaf_was_given(#[fixture(cgroup)] _group: &Group) {
    let kernel = spawn_kernel(
        FakeKernel::over(&HostKernel)
            .same_view()
            .on_read(&format!("{STATED}/cgroup"), Ok(b"0::/leaf/inner\n")),
    );
    let mut leaf = crate::containment::cgroup::try_create_leaf(&kernel, None).expect("create a real leaf");
    leaf.set_cgroup_path_for_test("/leaf".to_owned());

    assert!(leaf.would_reach(STATED, None).expect("the stated row places the task"));
}

/// A leaf reads the `/proc` state of a child that did not enter it through the kernel its spawn
/// started with: the row states a state for a pid the host does not have.
///
/// Mutant: `take_placement` reads the state through a host kernel, so the state is unknown.
#[skuld::test]
fn take_placement_reads_the_childs_state_through_the_kernel_the_leaf_was_given() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaf_path = dir.path().join("cosca-stated-state");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("cgroup.procs"), "").expect("write cgroup.procs");
    let kernel = FakeKernel::over(&HostKernel).same_view().on_read(
        &format!("{STATED}/stat"),
        Ok(format!("{STATED} (stated) D 1\n").as_bytes()),
    );
    let mut leaf = leaf_over(kernel, &leaf_path);
    // A pidfd that has not exited: this process's own.
    let pidfd = pidfd_of(std::process::id());

    let verdict = leaf.take_placement(handle_of(STATED, &pidfd));

    match verdict {
        Err(NotPlaced::Absent { child_state, .. }) => {
            assert_eq!(child_state, Some('D'), "the state the leaf's kernel was told");
        }
        Err(other) => panic!("a readable cgroup.procs is quoted: {other}"),
        Ok(()) => panic!("no child reported a placement"),
    }
}

/// A leaf created over a kernel keeps it: a read through the created leaf answers the row stated for
/// it, and the leaf's hold on the kernel ends with the leaf.
///
/// Mutant: `create_leaf_under` builds the leaf over a host kernel of its own, so the pid has no
/// cgroup to read and the place is cleared instead of recorded.
#[skuld::test]
fn cgroup_a_created_leaf_reads_through_the_kernel_it_was_created_over(#[fixture(cgroup)] _group: &Group) {
    let kernel = spawn_kernel(
        FakeKernel::over(&HostKernel)
            .same_view()
            .on_read(&format!("{STATED}/cgroup"), Ok(b"0::/elsewhere\n")),
    );
    let mut leaf = crate::containment::cgroup::try_create_leaf(&kernel, None).expect("create a real leaf");
    assert_eq!(std::sync::Arc::strong_count(&kernel), 2, "the leaf owns a clone");
    leaf.watch_front(STATED);

    leaf.record_watched_place();

    assert_eq!(leaf.placed_for_test().of(STATED), Some(false));
    drop(leaf);
    assert_eq!(std::sync::Arc::strong_count(&kernel), 1, "the leaf's hold ends with it");
}

/// A subtree asked whether a kill reached a child reads the child's place through the kernel the
/// child's box owns (`OsChild::kernel`): its row says the child is under the leaf. Where the host is
/// asked, the pid has no cgroup to read and the question fails.
///
/// Mutant: `Subtree::reached` places the child through a host kernel.
#[skuld::test]
fn a_subtree_places_a_child_through_the_kernel_its_box_owns() {
    use crate::child::owned::teardown::Reach;
    use crate::child::owned::OwnedChild;
    use crate::os_process::fake::FakeProcess;

    let kernel = FakeKernel::over(&HostKernel)
        .same_view()
        .on_read(&format!("{STATED}/cgroup"), Ok(b"0::/leaf/inner\n"));
    let child = OwnedChild::new(
        Box::new(FakeProcess::new([]).with_pid(STATED).with_kernel(spawn_kernel(kernel))),
        crate::elevation::front::TrackedKind::Own,
    );
    let subtree = Subtree::new(
        None,
        None,
        Some("/leaf".to_owned()),
        Swept::default(),
        PlacedAtRemoval::default(),
        kill_record(true),
    );

    assert!(subtree.reached(&child).expect("the stated row places the child"));
}
