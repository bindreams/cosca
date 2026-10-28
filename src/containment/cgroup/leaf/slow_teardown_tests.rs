//! A leaf abandoned by a failed async spawn waits for the child it kills, and warns once when the
//! wait passes 1 s (principle 2). A foreign tracer holds the killed child's zombie, so the wait
//! cannot end before the tracer lets go; it lets go only once the abandonment's thread sleeps in a
//! blocking `waitid`, which it reaches only after the warn.
//!
//! The intent the leaf receives is forged, naming a tracee the test spawned. The tracee ends only by
//! a kill, or by its stdin closing. The abandonment's thread drops the stdin once the kill returned
//! (`set_before_exit_wait`, `set_between_kill_and_wait`), so a kill that sent nothing leaves a
//! tracee that exits `0` into the tracer's hold, and the test fails on the status it was reaped as
//! instead of hanging.

use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::process::ExitStatusExt as _;

use super::super::{fault, HANDLE_PIDFD, HANDLE_PROC_DIR, TAG_INTENT};
use super::{Abandoned, CgroupLeaf, TeardownWarn, Waiting, WarnAfter};
use crate::child::spawn::fault as spawn_fault;
use crate::test_groups::{tracer_group, Group};
use crate::test_support::foreign_tracer::{self, assert_warns_once_after_seizing, Names};
use crate::wait::teardown_warn::Due;

/// Abandons a leaf that warns past 1 s, after `intent` told it of a tracee a foreign tracer holds
/// once killed, and asserts the one warn, naming `names`.
///
/// `intent(pid, pidfd)` sends the intent; `handshake(pidfd)` is the pidfd the handshake left.
/// `warn` makes the warn the abandonment gets, on the thread that abandons; it is answered back.
/// Asserts that the abandonment reaped the tracee, and that its kill ended it.
fn assert_abandonment_warns_once<W: TeardownWarn + Send>(
    names: Names,
    intent: fn(&CgroupLeaf, u32, &OwnedFd),
    handshake: fn(OwnedFd) -> Option<OwnedFd>,
    warn: fn() -> W,
) -> W {
    let mut child = foreign_tracer::blocker();
    let pid = child.id();
    let pidfd = crate::containment::cgroup::test_support::pidfd_of(pid);
    let stdin = child.stdin.take().expect("piped stdin");
    let (abandoned, signals, warn) = assert_warns_once_after_seizing(names, pid, move || {
        // Whichever wait the abandonment reaches (`end_child`'s, or the pidfd teardown's) releases it.
        let held = std::rc::Rc::new(std::cell::Cell::new(Some(stdin)));
        let release = || {
            let held = std::rc::Rc::clone(&held);
            move || drop(held.take())
        };
        let _at_the_exit_wait = fault::set_before_exit_wait(release());
        let _between_kill_and_wait = spawn_fault::set_between_kill_and_wait(release());
        let reaps = spawn_fault::record_teardown_reaps();
        let dir = tempfile::tempdir().expect("tempdir");
        let leaf_path = dir.path().join("cosca-slow-teardown");
        std::fs::create_dir(&leaf_path).expect("create the leaf");
        let mut leaf = CgroupLeaf::for_test_at(leaf_path);
        intent(&leaf, pid, &pidfd);
        let mut warn = warn();
        let abandoned = leaf.abandon_before_verdict(false, handshake(pidfd), &mut warn);
        let reaped = fault::take_reaped_orphans().into_iter().map(|(_, signal)| signal);
        let signals: Vec<_> = reaped
            .chain(reaps.recorded().into_iter().map(|(_, status)| status.signal()))
            .collect();
        (abandoned, signals, warn)
    });
    assert_eq!(abandoned, Abandoned::Ended);
    assert!(!signals.is_empty(), "the abandonment must have reaped the tracee");
    assert!(
        signals.iter().all(|signal| *signal == Some(libc::SIGKILL)),
        "the tracee must die of the abandonment's kill, not exit once its stdin was released: {signals:?}"
    );
    drop(child);
    warn
}

/// The warn a failed async spawn's abandonment gets: past the threshold the test thread has set.
fn slow() -> WarnAfter {
    WarnAfter(crate::tokio::slow_teardown_after())
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
        slow,
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
        slow,
    );
}

/// A child that never named itself, and whose pidfd only the handshake holds, is torn down through
/// that pidfd.
///
/// Mutant: the abandonment tears it down with no warn.
#[skuld::test]
fn an_abandoned_child_the_handshake_holds_is_waited_for_with_a_warn(#[fixture(tracer_group)] _group: &Group) {
    assert_abandonment_warns_once(Names::Unknown, |_, _, _| {}, Some, slow);
}

/// The warn of an abandonment that keeps count. Its `Due` has passed already.
struct Recording {
    due: Due,
    warned: u32,
}

impl TeardownWarn for Recording {
    fn due(&self) -> Option<Due> {
        (self.warned == 0).then_some(self.due)
    }

    fn warn(&mut self, waiting: Waiting<'_>) {
        self.warned += 1;
        let Waiting::Child(pid) = waiting else {
            panic!("an abandonment's wait for a child names a child");
        };
        crate::child::spawn::warn_still_waiting(pid, self.due.after);
    }
}

/// The pidfd-only teardown warns through the caller's warn, which learns that its warn went out.
///
/// Mutant: the teardown warns on its own, from the threshold's length alone, so the object's count
/// stays 0.
#[skuld::test]
fn the_pidfd_teardown_of_an_abandonment_warns_through_the_callers_warn(#[fixture(tracer_group)] _group: &Group) {
    let warn = assert_abandonment_warns_once(
        Names::Unknown,
        |_, _, _| {},
        Some,
        || {
            let passed = std::time::Instant::now() - std::time::Duration::from_secs(10);
            Recording {
                due: Due {
                    until: passed,
                    after: std::time::Duration::ZERO,
                },
                warned: 0,
            }
        },
    );
    assert_eq!(warn.warned, 1, "the warn object is told of its one warn");
}
