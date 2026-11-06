//! A leaf abandoned by a failed async spawn waits for the child it kills, and warns once when the
//! wait passes 1 s (principle 2). A foreign tracer holds the killed child's zombie, so the wait
//! cannot end before the tracer lets go; it lets go only once the abandonment's thread sleeps in a
//! blocking `waitid`, which it reaches only after the warn.
//!
//! The intent the leaf receives is forged, naming a tracee the test spawned, whose pidfd the test
//! hands the abandonment as the handshake does. The tracee ends only by a kill, or by its stdin
//! closing, which the test holds until the tracer has let go: a kill that sent nothing leaves a
//! tracee that never exits, and the runner's bound fails the test.

use std::os::unix::process::ExitStatusExt as _;

use super::super::TAG_INTENT;
use super::{Abandoned, CgroupLeaf, TeardownWarn, WarnAfter};
use crate::child::owned::teardown::Past;
use crate::child::spawn::fault as spawn_fault;
use crate::error::ChildFate;
use crate::test_groups::{tracer_group, Group};
use crate::test_support::foreign_tracer::{self, assert_warns_once_after_seizing, Names};

/// Abandons a leaf that warns past 1 s, after an intent told it of a tracee a foreign tracer holds
/// once killed, and asserts the one warn, naming the tracee.
///
/// `warn` makes the warn the abandonment gets, on the thread that abandons; it is answered back.
/// Asserts that the abandonment reaped the tracee, and that its kill ended it.
fn assert_abandonment_warns_once<W: TeardownWarn + Send>(warn: fn() -> W) -> W {
    let mut child = foreign_tracer::blocker();
    let pid = child.id();
    let pidfd = crate::containment::cgroup::test_support::pidfd_of(pid);
    let _stdin = child.stdin.take().expect("piped stdin");
    let (abandoned, signals, warn) = assert_warns_once_after_seizing(Names::Pid, pid, move || {
        let reaps = spawn_fault::record_teardown_reaps();
        let dir = tempfile::tempdir().expect("tempdir");
        let leaf_path = dir.path().join("cosca-slow-teardown");
        std::fs::create_dir(&leaf_path).expect("create the leaf");
        let mut leaf = CgroupLeaf::for_test_at(leaf_path);
        // SAFETY: the leaf's channel is open.
        unsafe {
            leaf.placement_slot()
                .send(TAG_INTENT, pid as i32)
                .expect("send the intent");
        }
        let mut warn = warn();
        let abandoned = leaf.abandon_before_verdict(false, (pidfd, Past::Clean), &mut warn);
        let signals: Vec<_> = reaps
            .recorded()
            .into_iter()
            .map(|(_, status)| status.signal())
            .collect();
        (abandoned, signals, warn)
    });
    assert_eq!(abandoned, Abandoned::Ended(ChildFate::Reaped));
    assert!(!signals.is_empty(), "the abandonment must have reaped the tracee");
    assert!(
        signals.iter().all(|signal| *signal == Some(libc::SIGKILL)),
        "the tracee must die of the abandonment's kill: {signals:?}"
    );
    drop(child);
    warn
}

/// The warn a failed async spawn's abandonment gets: past the threshold the test thread has set.
fn slow() -> WarnAfter {
    WarnAfter(crate::tokio::slow_teardown_after())
}

/// A child the handshake holds a pidfd on is torn down through it, and the wait for it warns.
///
/// Mutants: the teardown waits with no warn; `abandon_before_verdict` hands it no threshold.
#[skuld::test]
fn an_abandoned_child_the_handshake_holds_is_waited_for_with_a_warn(#[fixture(tracer_group)] _group: &Group) {
    assert_abandonment_warns_once(slow);
}
