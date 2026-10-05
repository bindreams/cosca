//! A placement verdict for a child that something else reaped, and whose pid a stranger may hold.
//! Each test runs as pid 1 of a fresh pid namespace (see `test_child::pid_reuse`). The leaf is a
//! test leaf: the verdict reads the child's report, not a real cgroup.

use std::os::fd::{AsFd, AsRawFd, OwnedFd};

use crate::containment::cgroup::test_support::{handle_of, pidfd_of};
use crate::containment::cgroup::{fault, CgroupLeaf, NotEntered, NotPlaced};
use crate::test_child::pid_reuse::{in_fresh_pid_ns, reap_behind_and_reuse, sigusr1_and_wait, wait_pollin};
use crate::test_groups::namespaces;

/// A test leaf, and a duplicate of its channel's child end that keeps the channel open, so the
/// verdict has only the child's exit to wait for.
fn silent_leaf(dir: &tempfile::TempDir) -> (CgroupLeaf, OwnedFd) {
    let leaf_path = dir.path().join("cosca-placement-reuse");
    std::fs::create_dir(&leaf_path).expect("create the leaf");
    std::fs::write(leaf_path.join("cgroup.procs"), "1\n").expect("write cgroup.procs");
    let leaf = CgroupLeaf::for_test_at(leaf_path);
    let child_end = leaf
        .report
        .as_ref()
        .expect("the verdict is not taken")
        .dup_child_end_for_test();
    (leaf, child_end)
}

/// Starts a `sleep` and returns its pid. Nothing waits on it through `std`: each test reaps it itself,
/// behind the leaf's back.
fn spawn_sleeper() -> u32 {
    let mut cmd = std::process::Command::new("sleep");
    cmd.arg("3600");
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
            assert_eq!(report, NotEntered::NotReported, "the child sent nothing");
            assert_eq!(
                child_state,
                Some('Z'),
                "the held pidfd says the child exited, whoever holds its pid now"
            );
        }
        other => panic!("a child that exited unreported is not placed: {other:?}"),
    }
}

/// The child is reaped behind the leaf's back and a stranger takes its pid. The verdict waits on the
/// pidfd held since the spawn, which says the child exited, and never opens one by number, which
/// would name the stranger.
///
/// Mutant: the wait opens `pidfd_open(pid)`, or the diagnosis reads `/proc/<pid>` unchecked.
fn verdict_after_foreign_reap_and_reuse_body() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut leaf, _child_end) = silent_leaf(&dir);
    let pid = spawn_sleeper();
    let held = pidfd_of(pid);
    end(held.as_fd());
    let reuser = reap_behind_and_reuse(pid);

    let held_fd = held.as_raw_fd();
    let _hook = fault::set_on_wait(move || {
        assert_eq!(
            fault::waited_pidfd(),
            Some(held_fd),
            "the verdict must wait on the child's own pidfd"
        );
    });
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

/// The child is reaped behind the leaf's back and nothing takes its pid. The verdict still comes
/// from the held pidfd: opening one by number finds nothing (`ESRCH`).
///
/// Mutant: the wait opens `pidfd_open(pid)`, which asserts `ESRCH` away in a debug build.
fn verdict_after_foreign_reap_body() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut leaf, _child_end) = silent_leaf(&dir);
    let pid = spawn_sleeper();
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

    let pid = spawn_sleeper();
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
        super::proc_state(handle_of(pid, &held)),
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
