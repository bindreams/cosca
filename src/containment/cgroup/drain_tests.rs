use super::DrainWatch;
use crate::containment::cgroup::test_support::FakeLeaf;
use crate::containment::cgroup::LeafDir;

fn armed(fake: &FakeLeaf) -> DrainWatch {
    DrainWatch::arm(&LeafDir::open_for_test(&fake.leaf))
        .expect("arm")
        .expect("the leaf exists")
}

/// A sibling's removal is queued on the parent's watch, and bears on nothing here.
#[skuld::test]
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
#[skuld::test]
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
///
/// `max_queued_events` is a host sysctl the test doesn't control, and on some hosts (observed:
/// 1048576) is far larger than the documented default (16384). Queuing that many `IN_DELETE`s
/// takes that many events, but not that many *directories* — reusing sibling names keeps
/// disk/inode use flat regardless of the sysctl's size. Alternating the name on each round
/// matters — inotify coalesces adjacent identical events, so reusing one name would collapse the
/// whole run into a handful of queued events and never overflow. Wall-clock time still scales
/// with the sysctl, and so does kernel memory: each queued event is a 48-byte kmalloc (a 32-byte
/// `inotify_event_info` plus the 16-byte name "cosca-sibling-a" with its NUL), which lands in
/// kmalloc-64 — about 64 MiB at 1048576 (128 MiB on arm64 before 6.5).
#[skuld::test]
fn an_overflowed_queue_is_a_change() {
    let max: usize = std::fs::read_to_string("/proc/sys/fs/inotify/max_queued_events")
        .expect("read fs.inotify.max_queued_events")
        .trim()
        .parse()
        .expect("a count");
    let fake = FakeLeaf::new("cosca-watched", true);
    let siblings = [
        fake.leaf.with_file_name("cosca-sibling-a"),
        fake.leaf.with_file_name("cosca-sibling-b"),
    ];
    let mut watch = armed(&fake);
    for i in 0..=max {
        let sibling = &siblings[i % siblings.len()];
        std::fs::create_dir(sibling).expect("make a sibling");
        std::fs::remove_dir(sibling).expect("remove the sibling");
    }

    assert!(watch.consume().expect("consume"), "the queue overflowed");
    assert!(!watch.saw_removal());
}

/// `drained_by` with a deadline that has passed: it looks once and answers.
fn drained_by_now(watch: &mut DrainWatch) -> bool {
    watch.drained_by(std::time::Instant::now())
}

/// A leaf that has drained is drained by any deadline.
///
/// Mutant: `drained_by` answers `false` for a leaf that read unpopulated.
#[skuld::test]
fn a_drained_leaf_is_drained_by_the_deadline() {
    let fake = FakeLeaf::new("cosca-watched", false);
    let mut watch = armed(&fake);
    assert!(drained_by_now(&mut watch));
}

/// A leaf still populated at the deadline is not drained by it, so the warn runs.
///
/// Mutant: `drained_by` answers `true` for a leaf its last look found populated.
#[skuld::test]
fn a_leaf_still_populated_at_the_deadline_is_not_drained_by_it() {
    let fake = FakeLeaf::new("cosca-watched", true);
    let mut watch = armed(&fake);
    assert!(!drained_by_now(&mut watch));
}

/// A leaf removed during the last round, which read it populated, is drained: the read after the
/// round finds the removal the round took in.
///
/// Mutant: the answer after a round that found nothing is `false` without that read.
#[skuld::test]
fn a_leaf_removed_during_the_last_round_is_drained() {
    let fake = FakeLeaf::new("cosca-watched", true);
    let mut watch = armed(&fake);
    FakeLeaf::remove(&fake.leaf);
    assert!(drained_by_now(&mut watch));
    assert!(watch.saw_removal());
}

/// A leaf whose state cannot be read answers `true`, leaving the failure to the wait that follows,
/// which returns it.
///
/// Mutant: `drained_by` answers `false` for a failed look (a spurious warn).
#[skuld::test]
fn a_leaf_whose_state_cannot_be_read_is_left_to_the_wait() {
    let fake = FakeLeaf::new("cosca-watched", true);
    let mut watch = armed(&fake);
    std::fs::write(&fake.events, "frozen 0\n").expect("write a cgroup.events with no populated field");
    assert!(drained_by_now(&mut watch));
    assert!(watch.wait().is_err(), "the wait finds the failure the look left it");
}
