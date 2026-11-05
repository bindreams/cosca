//! `ProcessId::parent` of a `pidfs` id, on a [`FakeKernel`] that states the table: a process's key
//! (its start time) and its identity (its inode) are different numbers, and the key is read bracketed.
//!
//! Rows run everywhere: nothing here needs a real pidfd.

use std::os::fd::OwnedFd;

use rustix::io::Errno;
use rustix::process::Pid;

use crate::error::Error;
use crate::identity::{FakeKernel, HostKernel, Key, ProcessId};

const PARENT: u32 = 4242;
const SELF: u32 = 4243;
const PARENT_INO: u64 = 900;
const SELF_INO: u64 = 5;

fn stand_in() -> OwnedFd {
    OwnedFd::from(std::fs::File::open("/dev/null").expect("/dev/null opens"))
}

fn stat(pid: u32, ppid: u32, start: u64) -> Vec<u8> {
    format!("{pid} (x) S {ppid} {ppid} 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {start} 0 0").into_bytes()
}

fn me() -> ProcessId {
    ProcessId::from_parts_for_test(SELF, Key::Pidfs(SELF_INO))
}

/// `SELF` is a child of `PARENT`; the parent started at `parent_start` and `SELF` at 2000.
fn table(parent_start: u64) -> FakeKernel<'static> {
    FakeKernel::over(&HostKernel)
        .same_view()
        .on_pids(Ok(&[PARENT, SELF]))
        .on_pidfd_open(PARENT, Ok(stand_in()))
        .on_pidfs_ino(PARENT, Ok(Some(PARENT_INO)))
        .on_pidfd_open(SELF, Ok(stand_in()))
        .on_pidfs_ino(SELF, Ok(Some(SELF_INO)))
        .on_read(&format!("{PARENT}/stat"), Ok(&stat(PARENT, 1, parent_start)))
        .on_read(&format!("{SELF}/stat"), Ok(&stat(SELF, PARENT, 2_000)))
}

#[skuld::test]
fn the_parent_of_a_pidfs_id_is_the_pidfs_id_of_its_parent() {
    let parent = me().parent_with(&table(1_000)).expect("a readable table");
    assert_eq!(
        parent,
        Some(ProcessId::from_parts_for_test(PARENT, Key::Pidfs(PARENT_INO)))
    );
}

/// A parent that started after its child is a recycled ppid. Mutant: "the keys compared are the
/// inodes" (900 > 5 would reject the genuine parent above, and 5 < 900 would keep this one).
#[skuld::test]
fn a_parent_that_started_after_its_pidfs_child_is_rejected() {
    assert_eq!(me().parent_with(&table(3_000)).expect("a readable table"), None);
}

/// `self`'s `stat` is read by the snapshot and by its own read, which gives the ppid and the key: a
/// pid gone by the second read has no parent.
#[skuld::test]
fn a_pidfs_id_whose_start_time_is_gone_has_no_parent() {
    let kernel = table(1_000)
        .on_read_after(&format!("{SELF}/stat"), 1, Err(libc::ENOENT))
        .on_signal_probe(Pid::from_raw(SELF as i32).unwrap(), Err(Errno::SRCH));
    assert_eq!(me().parent_with(&kernel).expect("gone is not an error"), None);
}

/// A live process whose start time cannot be read (`hidepid`) is an error naming the pid, never "no
/// parent".
#[skuld::test]
fn a_pidfs_id_whose_start_time_cannot_be_read_is_unassessable() {
    let kernel = table(1_000)
        .on_read_after(&format!("{SELF}/stat"), 1, Err(libc::EACCES))
        .on_signal_probe(Pid::from_raw(SELF as i32).unwrap(), Ok(()));
    match me().parent_with(&kernel) {
        Err(Error::Unassessable { detail, .. }) => {
            assert!(
                detail.contains(&format!("pid {SELF} exists but could not be queried")),
                "{detail}"
            );
        }
        other => panic!("expected Unassessable, got {other:?}"),
    }
}

/// The ppid `self`'s first read gives is only a number. If `self`'s read under the parent it named,
/// which follows the parent's own, shows another ppid, the process changed parents (or its pid
/// changed hands) and has no parent to name. `self`'s `stat` is read by the snapshot, by the ppid
/// read, then by that second read. Mutant: "the second read's ppid is not compared with the first's":
/// the old parent is named.
#[skuld::test]
fn an_id_whose_own_read_shows_another_ppid_has_no_parent() {
    let kernel = table(1_000).on_read_after(&format!("{SELF}/stat"), 2, Ok(&stat(SELF, 1, 2_000)));
    assert_eq!(me().parent_with(&kernel).expect("a readable table"), None);
}

/// [`table`] on a host whose pidfds have no inode: the ticks are the proof, read from `stat`.
fn ticks_table() -> FakeKernel<'static> {
    FakeKernel::over(&HostKernel)
        .same_view()
        .on_pids(Ok(&[PARENT, SELF]))
        .on_pidfd_open(PARENT, Ok(stand_in()))
        .on_pidfs_ino(PARENT, Ok(None))
        .on_pidfd_open(SELF, Ok(stand_in()))
        .on_pidfs_ino(SELF, Ok(None))
        .on_read(&format!("{PARENT}/stat"), Ok(&stat(PARENT, 1, 1_000)))
        .on_read(&format!("{SELF}/stat"), Ok(&stat(SELF, PARENT, 2_000)))
}

fn ticks_me() -> ProcessId {
    ProcessId::from_parts_for_test(SELF, Key::Ticks(2_000))
}

/// The parent's number is proved again after `self`'s read: the parent's `stat` is read by the
/// snapshot, by its own resolve, and then by that proof, which finds another start time. Mutant:
/// "the parent is not proved again after `self`'s read": the parent is named.
#[skuld::test]
fn a_parent_that_loses_its_number_after_the_childs_read_is_not_named() {
    let held = ticks_table();
    assert_eq!(
        ticks_me().parent_with(&held).expect("a readable table"),
        Some(ProcessId::from_parts_for_test(PARENT, Key::Ticks(1_000)))
    );
    let lost = ticks_table().on_read_after(&format!("{PARENT}/stat"), 2, Ok(&stat(PARENT, 1, 1_001)));
    assert_eq!(ticks_me().parent_with(&lost).expect("a readable table"), None);
}

/// A parent whose proof after `self`'s read cannot be made is an error naming the parent, not
/// `self`, whose own read succeeded. Mutant: "the error names `self` whatever left the read
/// `Unknown`".
#[skuld::test]
fn a_parent_that_cannot_be_proved_again_is_the_subject_of_the_error() {
    let kernel = ticks_table()
        .on_read_after(&format!("{PARENT}/stat"), 2, Err(libc::EACCES))
        .on_signal_probe(Pid::from_raw(PARENT as i32).unwrap(), Ok(()));
    match ticks_me().parent_with(&kernel) {
        Err(Error::Unassessable { detail, .. }) => {
            assert!(
                detail.contains(&format!("ppid {PARENT} exists but could not be queried")),
                "{detail}"
            );
        }
        other => panic!("expected Unassessable, got {other:?}"),
    }
}
