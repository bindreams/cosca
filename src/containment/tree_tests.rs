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
    assert_eq!(Tree::none().containment(), Containment::None);
    assert_eq!(Tree::delegated().containment(), Containment::Delegated);
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
    #[cfg_attr(not(unix), allow(unused_mut, reason = "only a Unix tree is released"))]
    let mut tree = Tree::contained(Mechanism::Fake(fake));

    assert_eq!(tree.containment(), Containment::ProcessGroup);
    tree.require_contained().expect("a contained tree is actionable");
    assert!(matches!(tree.kill(None), TreeKillOutcome::Ran(Ok(()))));
    assert_eq!(*sends.lock().unwrap(), ["kill"]);
    let err = tree.drain_edge().err().expect("the fake states no drain edge");
    assert!(matches!(err, Error::Unsupported { .. }), "{err:?}");
    #[cfg(unix)]
    assert!(tree.would_reach(1, None).expect("stated"));
    tree.disarm().expect("nothing to neutralize");
    #[cfg(unix)]
    tree.release().wait();
}

/// What names a tree in a message about its teardown is the text it always had, for each kind of
/// tree this platform has.
///
/// Mutant: a kind words itself as its `Debug` (`Group { pgid: 123, session: false }`); a cgroup leaf
/// words itself without its path.
#[skuld::test]
fn a_teardown_names_its_tree_as_it_always_did() {
    assert_eq!(Tree::none().teardown_subject(), "None");
    assert_eq!(Tree::delegated().teardown_subject(), "Delegated");
    let id = crate::identity::ProcessId::current();
    let walk = Tree::contained(Mechanism::Walk(Walker::new(id)));
    assert_eq!(walk.teardown_subject(), format!("TreeWalk({id:?})"));
    #[cfg(unix)]
    {
        use crate::containment::unix::Group;
        let group = Tree::contained(Mechanism::Group(Group::process_group(123)));
        assert_eq!(group.teardown_subject(), "ProcessGroup(123)");
        let session = Tree::contained(Mechanism::Group(Group::session(123)));
        assert_eq!(session.teardown_subject(), "ProcessGroup(123)");
    }
    #[cfg(target_os = "linux")]
    {
        let leaf = crate::containment::cgroup::CgroupLeaf::placeholder_for_test();
        let path = leaf.path().display().to_string();
        let leaf = Tree::contained(Mechanism::Cgroup(leaf));
        assert_eq!(leaf.teardown_subject(), format!("cgroup leaf {path}"));
    }
    #[cfg(windows)]
    {
        let job = crate::containment::windows::JobHandle::create_empty_for_test();
        let subject = Tree::contained(Mechanism::Job(job)).teardown_subject();
        assert!(subject.starts_with("JobObject(JobHandle {"), "{subject}");
    }
}

/// A tree released keeps what its kills settled: the settle that follows a release (a drop's report,
/// a failed spawn's cleanup) reads the handle's real state, which the release does not reset.
///
/// Mutant: `release` takes the whole tree, settlement included, and leaves a fresh one.
#[cfg(unix)]
#[skuld::test]
fn a_released_tree_keeps_what_its_kills_settled() {
    let (fake, _) = FakeContains::new(Containment::ProcessGroup, false);
    let mut tree = Tree::contained(Mechanism::Fake(fake));
    tree.settle(TreeKillOutcome::Ran(Ok(())), true)
        .expect("a kill that left nothing");
    assert!(tree.is_killed());

    tree.release().wait();

    assert!(tree.is_killed(), "the release reset the settlement");
    assert_eq!(tree.containment(), Containment::None, "nothing holds the tree");
}

/// A kill is reached by what a mechanism says, and by nothing for a tree no mechanism holds.
///
/// Mutant: a tree that holds nothing answers what a mechanism states.
#[cfg(unix)]
#[skuld::test]
fn a_tree_reaches_the_child_only_as_its_mechanism_says() {
    use crate::child::owned::teardown::Reach;
    use crate::os_process::fake::FakeProcess;
    use crate::test_child::over_fake::child_over;

    let child = child_over(&FakeProcess::new([]));
    for (reaches, tree) in [
        (
            true,
            Tree::contained(Mechanism::Fake(FakeContains::new(Containment::ProcessGroup, true).0)),
        ),
        (
            false,
            Tree::contained(Mechanism::Fake(FakeContains::new(Containment::ProcessGroup, false).0)),
        ),
        (false, Tree::none()),
        (false, Tree::delegated()),
    ] {
        assert_eq!(tree.reached(&child.proc).expect("stated"), reaches, "{tree:?}");
    }
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
