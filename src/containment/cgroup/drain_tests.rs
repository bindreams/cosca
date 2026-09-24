use super::DrainWatch;
use crate::containment::cgroup::test_support::FakeLeaf;
use crate::containment::cgroup::LeafDir;

fn armed(fake: &FakeLeaf) -> DrainWatch {
    DrainWatch::arm(&LeafDir::open_for_test(&fake.leaf))
        .expect("arm")
        .expect("the leaf exists")
}

/// A sibling's removal is queued on the parent's watch, and bears on nothing here.
#[test]
fn a_siblings_removal_is_not_a_change_to_the_leaf() {
    let fake = FakeLeaf::new("cosca-watched", true);
    let mut watch = armed(&fake);
    let sibling = fake.leaf.with_file_name("cosca-sibling");
    std::fs::create_dir(&sibling).expect("make a sibling");
    std::fs::remove_dir(&sibling).expect("remove the sibling");

    assert!(!watch.consume().expect("consume"), "a sibling's removal is no change");
    assert!(!watch.saw_removal());
}

/// A write to `cgroup.events`, and the leaf's own removal, are each a change.
#[test]
fn an_events_write_and_the_leafs_removal_are_changes() {
    let fake = FakeLeaf::new("cosca-watched", true);
    let mut watch = armed(&fake);
    assert!(!watch.consume().expect("consume"), "nothing happened yet");

    FakeLeaf::set_populated(&fake.events, false);
    assert!(watch.consume().expect("consume"), "cgroup.events was written");

    FakeLeaf::remove(&fake.leaf);
    assert!(watch.consume().expect("consume"), "the leaf was removed");
    assert!(watch.saw_removal());
}

/// An overflowed queue may have lost a change, so it counts as one.
#[test]
fn an_overflowed_queue_is_a_change() {
    let max: usize = std::fs::read_to_string("/proc/sys/fs/inotify/max_queued_events")
        .expect("read fs.inotify.max_queued_events")
        .trim()
        .parse()
        .expect("a count");
    let fake = FakeLeaf::new("cosca-watched", true);
    let siblings = (0..=max)
        .map(|i| fake.leaf.with_file_name(format!("cosca-sibling-{i}")))
        .collect::<Vec<_>>();
    for sibling in &siblings {
        std::fs::create_dir(sibling).expect("make a sibling");
    }
    let mut watch = armed(&fake);
    for sibling in &siblings {
        std::fs::remove_dir(sibling).expect("remove a sibling");
    }

    assert!(watch.consume().expect("consume"), "the queue overflowed");
    assert!(!watch.saw_removal());
}
