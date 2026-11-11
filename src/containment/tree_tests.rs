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

/// Only a cgroup leaf has awaitable release steps: the awaited teardown asks every mechanism the same
/// question and takes the steps of the one that answers.
///
/// Mutant: a mechanism other than the leaf answers `Some`; the leaf answers `None`.
#[cfg(all(feature = "tokio", target_os = "linux"))]
#[skuld::test]
fn only_a_cgroup_leaf_has_awaitable_release_steps() {
    use crate::containment::mechanism::Contains;
    use crate::containment::unix::Group;
    let (fake, _) = FakeContains::new(Containment::ProcessGroup, false);
    let others = [
        Mechanism::Walk(Walker::new(crate::identity::ProcessId::current())),
        Mechanism::Group(Group::process_group(1)),
        Mechanism::Fake(fake),
    ];
    for other in &others {
        assert!(other.awaitable_release().is_none(), "{other:?}");
    }
    let leaf = Mechanism::Cgroup(crate::containment::cgroup::CgroupLeaf::placeholder_for_test());
    assert!(leaf.awaitable_release().is_some());
}

/// A tree is driven only through what a mechanism answers: its kind, its sends, its drain edge, its
/// reach and its release are the fake's stated ones, and the fake is sent every call the tree makes.
///
/// Mutant: a `Tree` stops forwarding a call to its mechanism (`disarm` or `release` answers without
/// asking it); the tree answers a stated edge where the mechanism has none.
#[skuld::test]
fn a_consumer_drives_a_tree_only_through_what_its_mechanism_answers() {
    let (fake, sends) = FakeContains::new(Containment::ProcessGroup, true);
    #[cfg_attr(not(unix), allow(unused_mut, reason = "only a Unix tree is released"))]
    let mut tree = Tree::contained(Mechanism::Fake(fake));

    assert_eq!(tree.containment(), Containment::ProcessGroup);
    tree.require_contained().expect("a contained tree is actionable");
    assert!(matches!(tree.kill(None), TreeKillOutcome::Ran(Ok(()))));
    assert_eq!(*sends.lock().unwrap(), ["kill"]);
    assert!(tree.drain_edge().is_none(), "the fake states no drain edge");
    let err = tree.wait_drained(None).expect_err("no edge to wait on");
    assert!(matches!(err, Error::Unsupported { .. }), "{err:?}");
    #[cfg(unix)]
    assert!(tree.would_reach(1, None).expect("stated"));
    tree.disarm().expect("nothing to neutralize");
    #[cfg(unix)]
    tree.release().wait();
    #[cfg(unix)]
    assert_eq!(*sends.lock().unwrap(), ["kill", "disarm", "release"]);
    #[cfg(not(unix))]
    assert_eq!(*sends.lock().unwrap(), ["kill", "disarm"]);
}

/// A tree that is none or delegated holds no mechanism to reach with, and a fake whose kill does not
/// reach the child asked about answers so through the tree.
///
/// Mutant: a tree that is none or delegated answers `true`; the tree answers `true` for a mechanism
/// whose `reaches` is stated `false`, or asks it for the other call's answer.
#[cfg(unix)]
#[skuld::test]
fn a_tree_reaches_only_what_its_mechanism_says_it_reaches() {
    use crate::child::owned::teardown::Reach;
    use crate::os_process::fake::FakeProcess;
    use crate::test_child::over_fake::child_over;

    let child = child_over(&FakeProcess::new([]));
    for tree in [Tree::none(), Tree::delegated()] {
        assert!(!tree.would_reach(1, None).expect("a tree with no mechanism answers"));
        assert!(!tree.reached(&child.proc).expect("a tree with no mechanism answers"));
    }

    let (fake, _) = FakeContains::new(Containment::ProcessGroup, false);
    let tree = Tree::contained(Mechanism::Fake(fake));
    assert!(!tree.would_reach(1, None).expect("stated"));
    assert!(!tree.reached(&child.proc).expect("stated"));
}

/// What names a tree in a message about its teardown is the text it always had, for each kind of
/// tree this platform has. Only a Unix teardown words its tree.
///
/// Mutant: a kind words itself as its `Debug` (`Group { pgid: 123, session: false }`); a cgroup leaf
/// words itself without its path.
#[cfg(unix)]
#[skuld::test]
fn a_teardown_names_its_tree_as_it_always_did() {
    assert_eq!(Tree::none().teardown_subject(), "None");
    assert_eq!(Tree::delegated().teardown_subject(), "Delegated");
    let id = crate::identity::ProcessId::current();
    let walk = Tree::contained(Mechanism::Walk(Walker::new(id)));
    assert_eq!(walk.teardown_subject(), format!("TreeWalk({id:?})"));
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
}

/// A tree released still is what it was: it reports its containment, and a settle after the release
/// is a walk's when the tree was a walk's (its held members and its root left are the walk's own).
///
/// Mutant: `release` leaves a tree that reports `None` and settles as a tree that is not a walk's.
#[cfg(unix)]
#[skuld::test]
fn a_released_tree_keeps_its_kind() {
    use crate::containment::dispatch::Unkilled;

    let (fake, _) = FakeContains::new(Containment::ProcessGroup, false);
    let mut group = Tree::contained(Mechanism::Fake(fake));
    group.release().wait();
    assert_eq!(group.containment(), Containment::ProcessGroup);

    let mut walk = Tree::contained(Mechanism::Walk(Walker::new(crate::identity::ProcessId::current())));
    walk.release().wait();
    assert_eq!(walk.containment(), Containment::TreeWalk);
    // Only a walk leaves the root: a settle that is not a walk's asserts against it.
    let root_left = TreeKillOutcome::Ran(Err(Unkilled {
        members: Vec::new(),
        root: Some(Error::MemberNotKilled {
            pid: 1,
            source: Box::new(Error::Unassessable {
                detail: "its identity could not be read".into(),
                source: None,
            }),
            note: None,
        }),
        resolved: Vec::new(),
    }));
    walk.settle(root_left, true)
        .expect("a root the walk left is not left once it has ended");
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
