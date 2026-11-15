//! A placement verdict for a child that something else reaped, and whose pid a stranger may hold.
//! Each test runs as pid 1 of a fresh pid namespace (see `test_child::pid_reuse`). The leaf is a
//! test leaf: the verdict reads the report recorded on it, not a real cgroup.

use std::os::fd::AsFd;

use crate::containment::cgroup::test_support::{handle_of, pidfd_of};
use crate::containment::cgroup::{fault, CgroupLeaf, NotEntered, NotPlaced};
use crate::test_child::pid_reuse::{in_fresh_pid_ns, reap_behind_and_reuse, sigusr1_and_wait, wait_pollin};
use crate::test_groups::namespaces;

/// A test leaf whose child recorded no report.
fn silent_leaf(dir: &tempfile::TempDir) -> CgroupLeaf {
    let leaf_path = dir.path().join("cosca-placement-reuse");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("cgroup.procs"), "1\n").expect("write cgroup.procs");
    CgroupLeaf::for_test_at(leaf_path)
}

/// Starts a blocker and returns its pid. Nothing waits on it through `std`: each test ends it through
/// its pidfd and reaps it itself, behind the leaf's back. The forgotten `Child` keeps the write end
/// of its stdin open, so only that kill ends it.
fn spawn_blocker() -> u32 {
    let mut cmd = crate::test_child::held_std_blocker(std::process::Stdio::null());
    let child = crate::test_spawn::spawn(&mut cmd).expect("spawn the child");
    let pid = child.id();
    std::mem::forget(child);
    pid
}

/// Ends the child `pidfd` names.
fn end(pidfd: std::os::fd::BorrowedFd<'_>) {
    rustix::process::pidfd_send_signal(pidfd, rustix::process::Signal::KILL).expect("end the child");
}

/// What the verdict must say of a child that exited unreported: not placed, and exited.
#[track_caller]
fn assert_absent_and_exited(verdict: Result<(), NotPlaced>, pid: u32) {
    match verdict {
        Err(NotPlaced::Absent {
            pid: reported,
            report,
            child_state,
            ..
        }) => {
            assert_eq!(reported, pid);
            assert_eq!(report, NotEntered::NotReported, "the child reported nothing");
            assert_eq!(
                child_state,
                Some('Z'),
                "the held pidfd says the child exited, whoever holds its pid now"
            );
        }
        other => panic!("a child that exited unreported is not placed: {other:?}"),
    }
}

/// The child is reaped behind the leaf's back and a stranger takes its pid. The diagnosis asks the
/// pidfd held since the spawn, which says the child exited, and never opens one by number, which
/// would name the stranger.
///
/// Mutant: the diagnosis opens `pidfd_open(pid)`, or reads `/proc/<pid>` unchecked.
fn verdict_after_foreign_reap_and_reuse_body() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut leaf = silent_leaf(&dir);
    let pid = spawn_blocker();
    let held = pidfd_of(pid);
    end(held.as_fd());
    let reuser = reap_behind_and_reuse(pid);

    let verdict = leaf.take_placement(handle_of(pid, &held));
    assert_absent_and_exited(verdict, pid);
    assert_eq!(
        sigusr1_and_wait(reuser),
        Some(libc::SIGUSR1),
        "the reuser must have been signalled by the test alone"
    );
}
in_fresh_pid_ns!(
    namespaces_placement_after_foreign_reap_and_reuse_never_watches_the_reuser,
    fixture_placement_reuse_driver,
    fixture_placement_reuse_init,
    verdict_after_foreign_reap_and_reuse_body
);

/// The child is reaped behind the leaf's back and nothing takes its pid. The diagnosis still comes
/// from the held pidfd: opening one by number finds nothing (`ESRCH`).
///
/// Mutant: the diagnosis opens `pidfd_open(pid)`, which asserts `ESRCH` away in a debug build.
fn verdict_after_foreign_reap_body() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut leaf = silent_leaf(&dir);
    let pid = spawn_blocker();
    let held = pidfd_of(pid);
    end(held.as_fd());
    wait_pollin(held.as_fd());
    let reaped = rustix::process::waitid(
        rustix::process::WaitId::PidFd(held.as_fd()),
        rustix::process::WaitIdOptions::EXITED,
    )
    .expect("raw reap");
    assert!(reaped.is_some(), "the raw reap must consume an exit record");

    let verdict = leaf.take_placement(handle_of(pid, &held));
    assert_absent_and_exited(verdict, pid);
}
in_fresh_pid_ns!(
    namespaces_placement_after_foreign_reap_is_decided_from_the_held_pidfd,
    fixture_placement_reaped_driver,
    fixture_placement_reaped_init,
    verdict_after_foreign_reap_body
);

/// The child exits and its pid changes hands between the first pidfd look and the /proc read; the
/// diagnosis must be `Z`, not the stranger's `S`.
///
/// Mutant: no look after the read.
fn state_read_over_a_reused_number_is_discarded_body() {
    use std::cell::RefCell;
    use std::rc::Rc;

    let pid = spawn_blocker();
    let held = pidfd_of(pid);
    let reuser = Rc::new(RefCell::new(None));
    let _hook = fault::set_before_state_read({
        let (reuser, held) = (Rc::clone(&reuser), held.try_clone().expect("dup the held pidfd"));
        move || {
            end(held.as_fd());
            *reuser.borrow_mut() = Some(reap_behind_and_reuse(pid));
        }
    });

    assert_eq!(
        super::proc_state(&crate::identity::HostKernel, handle_of(pid, &held)),
        Some('Z'),
        "a state read over a number that changed hands is not the child's"
    );
    let reuser = reuser.borrow_mut().take().expect("the hook ran");
    assert_eq!(
        sigusr1_and_wait(reuser),
        Some(libc::SIGUSR1),
        "the reuser must have been signalled by the test alone"
    );
}
in_fresh_pid_ns!(
    namespaces_a_state_read_over_a_reused_number_is_discarded,
    fixture_state_reuse_driver,
    fixture_state_reuse_init,
    state_read_over_a_reused_number_is_discarded_body
);
