//! A failed spawn's teardown of an elevation front in a cgroup leaf: the cgroup lane (the `cgroup`
//! group, as root). The front is an ordinary `cat`, contained in a leaf.
//!
//! The teardown sees a front its leaf's kill reached as not yet exited: in the kernel a task leaves
//! its cgroup before its parent can collect it, so a drained leaf does not mean a waitable front.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::{teardown_unadopted_or_front, FrontFate, PidfdChild, Unadopted};
use crate::child::front_cgroup_tests::{move_out_of_its_leaf, pidfd_of, reaped};
use crate::child::front_kill_tests::cat;
use crate::command::Command;
use crate::elevation::{Backend, ElevatedVia};
use crate::error::ChildFate;
use crate::test_groups::{cgroup, Group};
use crate::ContainMode;

/// A front the teardown finds not yet exited. `wait` is recorded; it reaps through the pidfd only
/// where `reaps`, and otherwise fails, so a wait on a running front fails the test, not hangs it.
struct NotYetExited {
    inner: PidfdChild,
    reaps: bool,
    waited: Arc<AtomicBool>,
}

impl Unadopted for NotYetExited {
    fn pid(&self) -> Option<u32> {
        self.inner.pid()
    }
    fn kill(&mut self) -> std::io::Result<()> {
        panic!("a front is never signalled")
    }
    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        Ok(None)
    }
    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.waited.store(true, Ordering::SeqCst);
        if self.reaps {
            self.inner.wait()
        } else {
            Err(std::io::Error::other("waited on a front the leaf's kill did not reach"))
        }
    }
    fn pidfd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        self.inner.pidfd()
    }
}

/// A contained `cat` whose drop neither kills nor reaps it, with its pid and its stdin, which
/// keeps it running.
fn contained_cat() -> (crate::Child, u32, std::io::PipeWriter) {
    let mut cmd: Command = cat();
    cmd.contain_with(ContainMode::Strongest);
    cmd.kill_on_drop(false);
    cmd.stdin(crate::Stdio::pipe_in()).expect("stdin pipe");
    let mut child = cmd.spawn().expect("spawn a contained cat");
    let pid = child.id().pid();
    let stdin = child.stdin().expect("stdin pipe");
    (child, pid, stdin)
}

fn leaf_of(child: &crate::Child) -> &crate::containment::cgroup::CgroupLeaf {
    match &child.attached {
        crate::containment::Attached::Cgroup(leaf) => leaf,
        other => panic!("expected a cgroup leaf, got {other:?}"),
    }
}

fn sudo_front() -> Option<crate::elevation::front::Front> {
    crate::elevation::front::front(Some(&ElevatedVia::Wrapped(Backend::Sudo)))
}

/// A front its leaf's kill reached is waited for, through its pidfd, and reaped.
#[skuld::test]
fn cgroup_a_front_the_leaf_kill_reached_is_waited_for_and_reaped(#[fixture(cgroup)] _group: &Group) {
    let (child, pid, _stdin) = contained_cat();
    let id = Some(child.id());
    let observer = pidfd_of(pid);
    let subtree = leaf_of(&child).subtree().expect("the leaf's subtree");
    child.attached.hard_kill().expect("cgroup.kill");
    let waited = Arc::new(AtomicBool::new(false));
    let front = NotYetExited {
        inner: PidfdChild::new(Some(pid), pidfd_of(pid)),
        reaps: true,
        waited: Arc::clone(&waited),
    };
    let (fate, child_fate) = teardown_unadopted_or_front(front, sudo_front(), id, Some(&subtree));
    assert_eq!(fate, FrontFate::Reaped);
    assert_eq!(child_fate, ChildFate::Reaped);
    assert!(waited.load(Ordering::SeqCst));
    assert!(reaped(&observer), "the teardown reaps the front");
}

/// A front outside its leaf (moved, as pam_systemd moves sudo) is not waited for: the leaf's kill
/// landed, but did not reach it, and it may run on.
#[skuld::test]
fn cgroup_a_front_outside_its_leaf_is_left_unwaited(#[fixture(cgroup)] _group: &Group) {
    let (child, pid, _stdin) = contained_cat();
    let id = Some(child.id());
    let observer = pidfd_of(pid);
    let subtree = leaf_of(&child).subtree().expect("the leaf's subtree");
    move_out_of_its_leaf(pid);
    child.attached.hard_kill().expect("cgroup.kill of the emptied leaf");
    let waited = Arc::new(AtomicBool::new(false));
    let front = NotYetExited {
        inner: PidfdChild::new(Some(pid), pidfd_of(pid)),
        reaps: false,
        waited: Arc::clone(&waited),
    };
    let (fate, child_fate) = teardown_unadopted_or_front(front, sudo_front(), id, Some(&subtree));
    assert_eq!(fate, FrontFate::LeftUnreaped);
    assert_eq!(child_fate, ChildFate::Running { id });
    assert!(
        !waited.load(Ordering::SeqCst),
        "a front outside the leaf is not waited for"
    );
    assert!(!reaped(&observer));
    // The test's own cleanup: the cat it moved out of the leaf.
    let mut cleanup = PidfdChild::new(Some(pid), observer);
    cleanup.kill().expect("kill the moved cat");
    cleanup.wait().expect("reap the moved cat");
}

/// A front in its leaf whose kill failed is not waited for: nothing reached it, and it may run on.
#[skuld::test]
fn cgroup_a_front_its_leaf_could_not_kill_is_left_unwaited(#[fixture(cgroup)] _group: &Group) {
    let (child, pid, stdin) = contained_cat();
    let id = Some(child.id());
    let observer = pidfd_of(pid);
    let subtree = leaf_of(&child).subtree().expect("the leaf's subtree");
    {
        let _failing = crate::containment::cgroup::fault::fail_kill_writes();
        assert!(child.attached.hard_kill().is_err(), "the forced cgroup.kill failure");
    }
    let waited = Arc::new(AtomicBool::new(false));
    let front = NotYetExited {
        inner: PidfdChild::new(Some(pid), pidfd_of(pid)),
        reaps: false,
        waited: Arc::clone(&waited),
    };
    let (fate, child_fate) = teardown_unadopted_or_front(front, sudo_front(), id, Some(&subtree));
    assert_eq!(fate, FrontFate::LeftUnreaped);
    assert_eq!(child_fate, ChildFate::Running { id });
    assert!(
        !waited.load(Ordering::SeqCst),
        "a front no kill reached is not waited for"
    );
    assert!(!reaped(&observer));
    // The test's own cleanup: the cat ends on its stdin's close and is reaped, then the child's
    // drop removes its emptied leaf.
    drop(stdin);
    let mut cleanup = PidfdChild::new(Some(pid), observer);
    assert!(cleanup.wait().expect("reap the cat").success());
    drop(child);
}

/// A front whose place the teardown cannot read is left unreaped and unwaited, with a debug note of
/// the cause: the leaf's kill landed, but nothing shows it reached the front. Mutant: "an unreadable
/// place is waited for".
#[skuld::test]
fn cgroup_a_front_whose_place_cannot_be_read_is_left_unwaited(#[fixture(cgroup)] _group: &Group) {
    crate::log_capture::install();
    let (child, pid, stdin) = contained_cat();
    let id = Some(child.id());
    let observer = pidfd_of(pid);
    let subtree = leaf_of(&child).subtree().expect("the leaf's subtree");
    child.attached.hard_kill().expect("cgroup.kill");
    let waited = Arc::new(AtomicBool::new(false));
    let front = NotYetExited {
        inner: PidfdChild::new(Some(pid), pidfd_of(pid)),
        reaps: false,
        waited: Arc::clone(&waited),
    };
    let mark = crate::log_capture::mark();
    let (fate, child_fate) = {
        let _unreadable = crate::containment::cgroup::fault::fail_pidfd_info();
        teardown_unadopted_or_front(front, sudo_front(), id, Some(&subtree))
    };
    assert_eq!(fate, FrontFate::LeftUnreaped);
    assert_eq!(child_fate, ChildFate::Unknown);
    assert!(!waited.load(Ordering::SeqCst), "an unplaced front is not waited for");
    let notes = crate::log_capture::records_since_on_current_thread(mark, "cgroup cannot be read");
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert_eq!(notes[0].0, log::Level::Debug);
    assert!(notes[0].1.contains("Input/output error"), "{notes:?}");
    // The cat died of the leaf's kill; the teardown left it unreaped.
    drop(stdin);
    assert!(!reaped(&observer));
    let mut cleanup = PidfdChild::new(Some(pid), observer);
    cleanup.wait().expect("reap the cat");
    drop(child);
}

/// A front the leaf's kill reached whose wait fails is unaccounted for, and the warning names the
/// cause. Mutant: "a failed wait answers `Reaped`".
#[skuld::test]
fn cgroup_a_front_the_leaf_kill_reached_whose_wait_fails_is_unaccounted_for(#[fixture(cgroup)] _group: &Group) {
    crate::log_capture::install();
    let (child, pid, stdin) = contained_cat();
    let id = Some(child.id());
    let observer = pidfd_of(pid);
    let subtree = leaf_of(&child).subtree().expect("the leaf's subtree");
    child.attached.hard_kill().expect("cgroup.kill");
    let waited = Arc::new(AtomicBool::new(false));
    let front = NotYetExited {
        inner: PidfdChild::new(Some(pid), pidfd_of(pid)),
        reaps: false,
        waited: Arc::clone(&waited),
    };
    let mark = crate::log_capture::mark();
    let (fate, child_fate) = teardown_unadopted_or_front(front, sudo_front(), id, Some(&subtree));
    assert_eq!(fate, FrontFate::Unaccounted);
    assert_eq!(child_fate, ChildFate::Killed);
    assert!(waited.load(Ordering::SeqCst), "a front the kill reached is waited for");
    let warns = crate::log_capture::records_since_on_current_thread(mark, "could not be reaped");
    assert_eq!(warns.len(), 1, "{warns:?}");
    assert!(
        warns[0].1.contains("waited on a front the leaf's kill did not reach"),
        "{warns:?}"
    );
    drop(stdin);
    let mut cleanup = PidfdChild::new(Some(pid), observer);
    cleanup.wait().expect("reap the cat");
    drop(child);
}
