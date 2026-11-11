//! What [`Tree`] adds: the containment each kind of tree reports, and a consumer that drives a tree
//! only through the trait, over a mechanism of stated answers.

use crate::containment::dispatch::TreeKillOutcome;
use crate::containment::fake::FakeContains;
use crate::containment::treewalk::Walker;
use crate::containment::{Containment, Mechanism, Tree};
use crate::error::Error;

/// `Tree::containment()` is the one source of what a child reports: it answers for each kind of
/// tree this platform has, with no `Containment` stored beside it.
///
/// Mutant: a mechanism reports another mechanism's containment; a delegated tree reports `None`.
#[skuld::test]
fn a_tree_reports_the_containment_of_what_holds_it() {
    assert_eq!(Tree::None.containment(), Containment::None);
    assert_eq!(Tree::Delegated.containment(), Containment::Delegated);
    let walk = Tree::contained(Mechanism::Walk(Walker::new(crate::identity::ProcessId::current())));
    assert_eq!(walk.containment(), Containment::TreeWalk);
    #[cfg(unix)]
    {
        use crate::containment::unix::Group;
        let group = Tree::contained(Mechanism::Group(Group::process_group(1)));
        assert_eq!(group.containment(), Containment::ProcessGroup);
        let session = Tree::contained(Mechanism::Group(Group::session(1)));
        assert_eq!(session.containment(), Containment::Session);
    }
    #[cfg(target_os = "linux")]
    {
        let leaf = crate::containment::cgroup::CgroupLeaf::placeholder_for_test();
        assert_eq!(
            Tree::contained(Mechanism::Cgroup(leaf)).containment(),
            Containment::CgroupV2
        );
    }
    #[cfg(windows)]
    {
        let job = crate::containment::windows::JobHandle::create_empty_for_test();
        assert_eq!(
            Tree::contained(Mechanism::Job(job)).containment(),
            Containment::JobObject
        );
    }
}

/// A tree is driven only through what a mechanism answers: its kind, its sends, its drain edge, its
/// reach and its release are the fake's stated ones, and a child's own calls go through them.
///
/// Mutant: a consumer matches on the mechanism and bypasses the trait; the tree answers a stated
/// edge where the mechanism has none.
#[skuld::test]
fn a_consumer_drives_a_tree_only_through_what_its_mechanism_answers() {
    let (fake, sends) = FakeContains::new(Containment::ProcessGroup, true);
    let tree = Tree::contained(Mechanism::Fake(fake));

    assert_eq!(tree.containment(), Containment::ProcessGroup);
    tree.require_contained().expect("a contained tree is actionable");
    assert!(matches!(tree.kill(None), TreeKillOutcome::Ran(Ok(()))));
    assert_eq!(*sends.lock().unwrap(), ["kill"]);
    let err = tree.drain_edge().err().expect("the fake states no drain edge");
    assert!(matches!(err, Error::Unsupported { .. }), "{err:?}");
    #[cfg(unix)]
    assert!(tree.would_reach(1, None).expect("stated"));
    tree.disarm().expect("nothing to neutralize");
    let _ = tree.release().wait();
}

/// A child over a mechanism of stated answers: what it reports and what its tree calls do come from
/// the mechanism alone.
///
/// Mutant: `Child::containment` is read from a field the mechanism does not decide;
/// `terminate_tree` skips the mechanism.
#[skuld::test]
fn a_child_over_a_stated_mechanism_reports_and_signals_through_it() {
    use crate::os_process::fake::FakeProcess;
    use crate::test_child::over_fake::child_over;

    let (fake, sends) = FakeContains::new(Containment::Session, false);
    let mut child = child_over(&FakeProcess::new([]));
    child.tree = Tree::contained(Mechanism::Fake(fake));

    assert_eq!(child.containment(), Containment::Session);
    child.terminate_tree().expect("the fake's terminate succeeds");
    assert_eq!(*sends.lock().unwrap(), ["terminate"]);
    let err = child.wait_tree().expect_err("the fake states no drain edge");
    assert!(matches!(err, Error::Unsupported { .. }), "{err:?}");
}
