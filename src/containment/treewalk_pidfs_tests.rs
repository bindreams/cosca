//! The tree walk over `pidfs` ids (and, at the end, `ticks` ids), on a [`FakeKernel`] that states
//! the table. A process's key
//! (its start time, from `stat`) and its identity (its pidfd's inode) are different numbers here, so
//! a wrapper that hands the filter one for the other fails.
//!
//! Rows run everywhere: nothing here needs a real pidfd.

use std::os::fd::OwnedFd;

use rustix::io::Errno;
use rustix::process::Pid;

use crate::error::Error;
use crate::identity::{FakeKernel, HostKernel, Key, OrderKey, ProcessId};

const ROOT: u32 = 4242;
const CHILD: u32 = 4243;
/// The inodes and start times: the child's inode is below the root's start time, and the root
/// started before the child.
const ROOT_INO: u64 = 900;
const CHILD_INO: u64 = 5;
const ROOT_START: u64 = 1_000;
const CHILD_START: u64 = 2_000;

fn stand_in() -> OwnedFd {
    OwnedFd::from(std::fs::File::open("/dev/null").expect("/dev/null opens"))
}

/// `pid`'s `stat`, with parent `ppid` and start time `start`.
fn stat(pid: u32, ppid: u32, start: u64) -> Vec<u8> {
    format!("{pid} (x) S {ppid} {ppid} 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {start} 0 0").into_bytes()
}

fn root() -> ProcessId {
    ProcessId::from_parts_for_test(ROOT, Key::Pidfs(ROOT_INO))
}

fn child() -> ProcessId {
    ProcessId::from_parts_for_test(CHILD, Key::Pidfs(CHILD_INO))
}

/// A kernel in which `ROOT` has inode `ROOT_INO` and `CHILD` (its child) has `CHILD_INO`, each
/// showing its start time.
fn table() -> FakeKernel<'static> {
    FakeKernel::over(&HostKernel)
        .same_view()
        .on_pidfd_open(ROOT, Ok(stand_in()))
        .on_pidfs_ino(ROOT, Ok(Some(ROOT_INO)))
        .on_pidfd_open(CHILD, Ok(stand_in()))
        .on_pidfs_ino(CHILD, Ok(Some(CHILD_INO)))
        .on_read(&format!("{ROOT}/stat"), Ok(&stat(ROOT, 1, ROOT_START)))
        .on_read(&format!("{CHILD}/stat"), Ok(&stat(CHILD, ROOT, CHILD_START)))
}

const EDGES: [(u32, u32); 1] = [(CHILD, ROOT)];

/// The resolver hands the filter the child's identity (its inode) and its key (its start time), each
/// in its place. Mutants: "the id carries the start time", "the key is the inode" (5 orders before
/// the root's 1000, so the child is dropped).
#[skuld::test]
fn resolve_or_drop_pairs_a_pidfs_id_with_its_start_time() {
    assert_eq!(
        super::resolve_or_drop(&table(), CHILD, root()),
        Some((child(), OrderKey::for_test(CHILD_START)))
    );
}

#[skuld::test]
fn descendants_and_children_of_keep_the_child_of_a_pidfs_root_by_start_time() {
    assert_eq!(
        super::descendants(&table(), root(), &EDGES).expect("a readable root"),
        vec![child()]
    );
    assert_eq!(
        super::children_of(&table(), root(), &EDGES).expect("a readable root"),
        vec![child()]
    );
}

/// A child that started before the root is a recycled pid or a stale parent, whatever its inode.
/// Mutant: "the root's key is its inode" (a start time of 500 is below 1000, but above 5).
#[skuld::test]
fn a_child_that_started_before_a_pidfs_root_is_dropped() {
    let kernel = table().on_read(&format!("{CHILD}/stat"), Ok(&stat(CHILD, ROOT, 500)));
    assert!(super::descendants(&kernel, root(), &EDGES).unwrap().is_empty());
    assert!(super::children_of(&kernel, root(), &EDGES).unwrap().is_empty());
}

/// A root whose start time is gone from `/proc` while its pidfd still opens (it was reaped between)
/// has nothing to walk, and that is not an error.
#[skuld::test]
fn the_walk_of_a_pidfs_root_whose_stat_is_gone_is_empty() {
    let kernel = table()
        .on_read(&format!("{ROOT}/stat"), Err(libc::ENOENT))
        .on_signal_probe(Pid::from_raw(ROOT as i32).unwrap(), Err(Errno::SRCH));
    assert!(super::descendants(&kernel, root(), &EDGES).unwrap().is_empty());
    assert!(super::children_of(&kernel, root(), &EDGES).unwrap().is_empty());
}

/// A root whose start time cannot be read (`hidepid`) is an error, never an empty walk: an empty one
/// would let a caller kill the root and leave its descendants running.
#[skuld::test]
fn the_walk_of_a_pidfs_root_whose_stat_cannot_be_read_is_unassessable() {
    let kernel = table()
        .on_read(&format!("{ROOT}/stat"), Err(libc::EACCES))
        .on_signal_probe(Pid::from_raw(ROOT as i32).unwrap(), Ok(()));
    for result in [
        super::descendants(&kernel, root(), &EDGES),
        super::children_of(&kernel, root(), &EDGES),
    ] {
        match result {
            Err(Error::Unassessable { detail, .. }) => {
                assert!(
                    detail.contains(&format!("pid {ROOT} exists but could not be queried")),
                    "{detail}"
                );
            }
            other => panic!("expected Unassessable, got {other:?}"),
        }
    }
}

// The accepted parent is proved again after its child's read =====

const GRAND: u32 = 4244;
const GRAND_INO: u64 = 7;
const GRAND_START: u64 = 3_000;

/// [`table`], and `GRAND` (a child of `CHILD`) with inode `GRAND_INO`.
fn table_with_a_grandchild() -> FakeKernel<'static> {
    table()
        .on_pidfd_open(GRAND, Ok(stand_in()))
        .on_pidfs_ino(GRAND, Ok(Some(GRAND_INO)))
        .on_read(&format!("{GRAND}/stat"), Ok(&stat(GRAND, CHILD, GRAND_START)))
}

const EDGES_WITH_A_GRANDCHILD: [(u32, u32); 2] = [(CHILD, ROOT), (GRAND, CHILD)];

/// The child's `ppid` names the root's number, and only the root's number: after the child's read
/// the number may belong to a process that reaped the root and took it. So the root is proved again
/// then, and a number that opens to another inode is not the root. Mutant: "the parent is not
/// proved again".
#[skuld::test]
fn a_child_read_after_its_parents_number_changed_hands_is_dropped() {
    // A kernel per walk: the row waits for a read of the child's `stat`, which a walk makes.
    let kernel = || table().on_pidfs_ino_after_read(ROOT, &format!("{CHILD}/stat"), Ok(Some(ROOT_INO + 1)));
    assert!(super::descendants(&kernel(), root(), &EDGES).unwrap().is_empty());
    assert!(super::children_of(&kernel(), root(), &EDGES).unwrap().is_empty());
}

/// The same for a parent that the walk accepted itself, deeper down. Mutant: "only the root is
/// proved again".
#[skuld::test]
fn a_grandchild_read_after_its_accepted_parents_number_changed_hands_is_dropped() {
    let kernel =
        table_with_a_grandchild().on_pidfs_ino_after_read(CHILD, &format!("{GRAND}/stat"), Ok(Some(CHILD_INO + 1)));
    assert_eq!(
        super::descendants(&kernel, root(), &EDGES_WITH_A_GRANDCHILD).unwrap(),
        vec![child()]
    );
    let kept = super::descendants(&table_with_a_grandchild(), root(), &EDGES_WITH_A_GRANDCHILD).unwrap();
    assert_eq!(
        kept.len(),
        2,
        "with the parent still holding its number the grandchild is kept"
    );
}

/// A parent whose proof cannot be made (here: its pidfd's inode cannot be read) verifies nothing, so
/// the child is dropped like a pid the walk cannot query, not walked.
#[skuld::test]
fn a_child_whose_parent_cannot_be_proved_again_is_dropped() {
    let kernel = || table().on_pidfs_ino_after_read(ROOT, &format!("{CHILD}/stat"), Err(Errno::BADF));
    assert!(super::descendants(&kernel(), root(), &EDGES).unwrap().is_empty());
    assert!(super::children_of(&kernel(), root(), &EDGES).unwrap().is_empty());
}

/// On a host whose pidfds have no inode the proof is the ticks compare: the root's `stat` shows the
/// ticks the id has, or another process's.
fn ticks_table(root_start_now: u64) -> FakeKernel<'static> {
    FakeKernel::over(&HostKernel)
        .same_view()
        .on_pidfd_open(CHILD, Ok(stand_in()))
        .on_pidfs_ino(CHILD, Ok(None))
        .on_read(&format!("{ROOT}/stat"), Ok(&stat(ROOT, 1, root_start_now)))
        .on_read(&format!("{CHILD}/stat"), Ok(&stat(CHILD, ROOT, CHILD_START)))
}

fn ticks_root() -> ProcessId {
    ProcessId::from_parts_for_test(ROOT, Key::Ticks(ROOT_START))
}

/// Mutant: "the parent is not proved again" (ticks).
#[skuld::test]
fn on_a_ticks_host_a_child_is_kept_only_while_its_parent_shows_its_ticks() {
    let kept = ticks_table(ROOT_START);
    assert_eq!(super::descendants(&kept, ticks_root(), &EDGES).unwrap().len(), 1);
    assert_eq!(super::children_of(&kept, ticks_root(), &EDGES).unwrap().len(), 1);

    let changed_hands = ticks_table(ROOT_START + 1);
    assert!(super::descendants(&changed_hands, ticks_root(), &EDGES)
        .unwrap()
        .is_empty());
    assert!(super::children_of(&changed_hands, ticks_root(), &EDGES)
        .unwrap()
        .is_empty());
}
