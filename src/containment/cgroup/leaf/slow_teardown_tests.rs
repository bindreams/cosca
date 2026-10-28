//! A leaf abandoned by a failed async spawn waits for the child it kills, and warns once when the
//! wait passes 1 s (principle 2). A foreign tracer holds the killed child's zombie, so the wait
//! cannot end before the tracer lets go; it lets go only once the abandonment's thread sleeps in a
//! blocking `waitid`, which it reaches only after the warn.
//!
//! The intent the leaf receives is forged, naming a tracee the test spawned.

use std::os::fd::{AsRawFd as _, OwnedFd};

use super::super::{HANDLE_PIDFD, HANDLE_PROC_DIR, TAG_INTENT};
use super::{Abandoned, CgroupLeaf, WarnAfter};
use crate::test_groups::{tracer_group, Group};
use crate::test_support::foreign_tracer::{self, assert_warns_once_after_seizing, Names};

/// Abandons a leaf that warns past 1 s, after `intent` told it of a tracee a foreign tracer holds
/// once killed, and asserts the one warn, naming `names`.
///
/// `intent(pid, pidfd)` sends the intent; `handshake(pidfd)` is the pidfd the handshake left.
fn assert_abandonment_warns_once(
    names: Names,
    intent: fn(&CgroupLeaf, u32, &OwnedFd),
    handshake: fn(OwnedFd) -> Option<OwnedFd>,
) {
    let child = foreign_tracer::blocker();
    let pid = child.id();
    let pidfd = crate::containment::cgroup::test_support::pidfd_of(pid);
    let abandoned = assert_warns_once_after_seizing(names, pid, move || {
        let dir = tempfile::tempdir().expect("tempdir");
        let leaf_path = dir.path().join("cosca-slow-teardown");
        std::fs::create_dir(&leaf_path).expect("create the leaf");
        let mut leaf = CgroupLeaf::for_test_at(leaf_path);
        intent(&leaf, pid, &pidfd);
        let mut warn = WarnAfter(crate::tokio::slow_teardown_after());
        leaf.abandon_before_verdict(false, handshake(pidfd), &mut warn)
    });
    assert_eq!(abandoned, Abandoned::Ended);
    drop(child);
}

/// A child named by its pidfd, killed and waited for by `end_child`.
///
/// Mutants: `end_child` waits with no warn; `abandon_before_verdict` hands it no warn.
#[skuld::test]
fn an_abandoned_child_named_by_its_pidfd_is_waited_for_with_a_warn(#[fixture(tracer_group)] _group: &Group) {
    assert_abandonment_warns_once(
        Names::Pid,
        |leaf, pid, pidfd| {
            // SAFETY: the leaf's channel is open; the intent carries a pidfd on the tracee.
            unsafe {
                leaf.placement_slot()
                    .send(TAG_INTENT, pid as i32, HANDLE_PIDFD, pidfd.as_raw_fd())
                    .expect("send the intent");
            }
        },
        |_| None,
    );
}

/// A child that sent only its `/proc` directory is waited for by its pid, and the warn watches it
/// through a pidfd opened for the message.
///
/// Mutant: `end_child` warns only for a child named by a pidfd.
#[skuld::test]
fn an_abandoned_child_named_by_its_proc_directory_is_waited_for_with_a_warn(#[fixture(tracer_group)] _group: &Group) {
    assert_abandonment_warns_once(
        Names::Pid,
        |leaf, pid, _| {
            let proc_dir = std::fs::File::open(format!("/proc/{pid}")).expect("open the /proc directory");
            // SAFETY: the leaf's channel is open; the intent carries a directory handle on the tracee.
            unsafe {
                leaf.placement_slot()
                    .send(TAG_INTENT, pid as i32, HANDLE_PROC_DIR, proc_dir.as_raw_fd())
                    .expect("send the intent");
            }
        },
        |_| None,
    );
}

/// A child that never named itself, and whose pidfd only the handshake holds, is torn down through
/// that pidfd.
///
/// Mutant: the abandonment tears it down with no warn.
#[skuld::test]
fn an_abandoned_child_the_handshake_holds_is_waited_for_with_a_warn(#[fixture(tracer_group)] _group: &Group) {
    assert_abandonment_warns_once(Names::Unknown, |_, _, _| {}, Some);
}
