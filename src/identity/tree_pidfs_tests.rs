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

/// [`table`] with no `stat` for `SELF`: the row states it.
fn table_without_self_stat(parent_start: u64) -> FakeKernel<'static> {
    FakeKernel::over(&HostKernel)
        .same_view()
        .on_pids(Ok(&[PARENT, SELF]))
        .on_pidfd_open(PARENT, Ok(stand_in()))
        .on_pidfs_ino(PARENT, Ok(Some(PARENT_INO)))
        .on_pidfd_open(SELF, Ok(stand_in()))
        .on_pidfs_ino(SELF, Ok(Some(SELF_INO)))
        .on_read(&format!("{PARENT}/stat"), Ok(&stat(PARENT, 1, parent_start)))
}

/// `SELF` is a child of `PARENT`; the parent started at `parent_start` and `SELF` at 2000.
fn table(parent_start: u64) -> FakeKernel<'static> {
    table_without_self_stat(parent_start).on_read(&format!("{SELF}/stat"), Ok(&stat(SELF, PARENT, 2_000)))
}

#[skuld::test]
fn the_parent_of_a_pidfs_id_is_the_pidfs_id_of_its_parent() {
    let parent = me().parent_with(&table(1_000)).expect("a readable table");
    assert_eq!(
        parent,
        Some(ProcessId::from_parts_for_test(PARENT, Key::Pidfs(PARENT_INO)))
    );
}

/// Where the creator is updated, the proof is `self`'s own `ppid` after the parent's read, not an
/// order: a parent that started after `self` (a tracer, or a clock step) is named while its pid
/// still shows as `self`'s `ppid`. `SELF` started at 2000. Mutant: "`parent` orders `self` after its
/// parent (`keeps_order`) after the second read": no parent is named.
#[skuld::test]
fn a_parent_that_started_after_its_child_is_named_while_the_childs_ppid_still_names_it() {
    for parent_start in [2_000, 3_000] {
        assert_eq!(
            me().parent_with(&table(parent_start)).expect("a readable table"),
            Some(ProcessId::from_parts_for_test(PARENT, Key::Pidfs(PARENT_INO))),
            "a parent started at {parent_start}"
        );
    }
}

/// `self`'s own read gives the ppid and the key: a pid gone by that read has no parent.
#[skuld::test]
fn a_pidfs_id_whose_start_time_is_gone_has_no_parent() {
    let kernel = table_without_self_stat(1_000)
        .on_read(&format!("{SELF}/stat"), Err(libc::ENOENT))
        .on_signal_probe(Pid::from_raw(SELF as i32).unwrap(), Err(Errno::SRCH));
    assert_eq!(me().parent_with(&kernel).expect("gone is not an error"), None);
}

/// A pid that another process holds has no parent to name, whether or not that process can be read:
/// its pidfd's inode is not `self`'s, so its `stat` (here refused, as under `hidepid`) is never asked
/// about. Mutant: "the key is compared only after the whole read succeeds": the refusal is an error.
#[skuld::test]
fn a_recycled_pidfs_id_whose_new_holder_cannot_be_read_has_no_parent() {
    let kernel = table_without_self_stat(1_000)
        .on_pidfs_ino(SELF, Ok(Some(SELF_INO + 1)))
        .on_read(&format!("{SELF}/stat"), Err(libc::EACCES))
        .on_signal_probe(Pid::from_raw(SELF as i32).unwrap(), Ok(()));
    assert_eq!(me().parent_with(&kernel).expect("a recycled pid is not an error"), None);
}

/// A live process whose start time cannot be read (`hidepid`) is an error naming the pid, never "no
/// parent".
#[skuld::test]
fn a_pidfs_id_whose_start_time_cannot_be_read_is_unassessable() {
    let kernel = table_without_self_stat(1_000)
        .on_read(&format!("{SELF}/stat"), Err(libc::EACCES))
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
/// changed hands) and has no parent to name, even when the parent's pid went to a process started in
/// `self`'s own tick, which the order rule alone would pass. `self`'s `stat` is read by the ppid read,
/// then by that second read. Mutant: "the second read's ppid is not compared with the first's": the
/// old parent is named.
#[skuld::test]
fn an_id_whose_own_read_shows_another_ppid_has_no_parent() {
    for parent_start in [1_000, 2_000] {
        let kernel = table(parent_start).on_read_after(&format!("{SELF}/stat"), 1, Ok(&stat(SELF, 1, 2_000)));
        assert_eq!(
            me().parent_with(&kernel).expect("a readable table"),
            None,
            "a parent started at {parent_start}"
        );
    }
}

/// `self`'s pid changes hands after the parent was read, to a process that cannot be read (as under
/// `hidepid`): the second read names the key it means, so it finds another process there and `self` is
/// gone, whether or not its new holder can be read. Mutant: "the second read does not name `self`'s
/// key": the refusal is an error.
#[skuld::test]
fn a_pidfs_id_recycled_between_the_reads_whose_new_holder_cannot_be_read_has_no_parent() {
    let kernel = table(1_000)
        .on_pidfs_ino_after_read(SELF, &format!("{PARENT}/stat"), Ok(Some(SELF_INO + 1)))
        .on_read_after(&format!("{SELF}/stat"), 1, Err(libc::EACCES))
        .on_signal_probe(Pid::from_raw(SELF as i32).unwrap(), Ok(()));
    assert_eq!(me().parent_with(&kernel).expect("a recycled pid is not an error"), None);
}

/// `self`'s own second read fails while it still names the parent: the answer is the shared read's
/// (`Unknown` blaming `self`, the parent being held), an error naming `self`, not "no parent". Mutant:
/// "a failed second read is no parent".
#[skuld::test]
fn a_childs_second_read_that_fails_is_the_subject_of_the_error() {
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

/// A host whose pidfds have no inode, so the ticks are the proof, read from `stat`: `SELF` has its
/// `stat` and `PARENT` has none, which the row states.
fn ticks_table_without_parent_stat() -> FakeKernel<'static> {
    FakeKernel::over(&HostKernel)
        .same_view()
        .on_pids(Ok(&[PARENT, SELF]))
        .on_pidfd_open(PARENT, Ok(stand_in()))
        .on_pidfs_ino(PARENT, Ok(None))
        .on_pidfd_open(SELF, Ok(stand_in()))
        .on_pidfs_ino(SELF, Ok(None))
        .on_read(&format!("{SELF}/stat"), Ok(&stat(SELF, PARENT, 2_000)))
}

fn ticks_me() -> ProcessId {
    ProcessId::from_parts_for_test(SELF, Key::Ticks(2_000))
}

/// [`ticks_table_without_parent_stat`], and the parent started at 1000.
fn ticks_table() -> FakeKernel<'static> {
    ticks_table_without_parent_stat().on_read(&format!("{PARENT}/stat"), Ok(&stat(PARENT, 1, 1_000)))
}

/// The parent's number is proved again after `self`'s read: the parent's `stat` is read by its own
/// resolve, and then by that proof, which finds another start time. Mutant: "the parent is not
/// proved again after `self`'s read": the parent is named.
#[skuld::test]
fn a_parent_that_loses_its_number_after_the_childs_read_is_not_named() {
    let held = ticks_table();
    assert_eq!(
        ticks_me().parent_with(&held).expect("a readable table"),
        Some(ProcessId::from_parts_for_test(PARENT, Key::Ticks(1_000)))
    );
    let lost = ticks_table().on_read_after(&format!("{PARENT}/stat"), 1, Ok(&stat(PARENT, 1, 1_001)));
    assert_eq!(ticks_me().parent_with(&lost).expect("a readable table"), None);
}

/// A parent whose proof after `self`'s read cannot be made is an error naming the parent, not
/// `self`, whose own read succeeded. Mutant: "the error names `self` whatever left the read
/// `Unknown`".
#[skuld::test]
fn a_parent_that_cannot_be_proved_again_is_the_subject_of_the_error() {
    let kernel = ticks_table()
        .on_read_after(&format!("{PARENT}/stat"), 1, Err(libc::EACCES))
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

/// A parent whose number cannot be read is an error naming the parent, not `self`, whose own read
/// succeeded. Mutant: "the error names `self` whatever left the read `Unknown`".
#[skuld::test]
fn a_parent_that_cannot_be_read_is_the_subject_of_the_error() {
    let kernel = ticks_table_without_parent_stat()
        .on_read(&format!("{PARENT}/stat"), Err(libc::EACCES))
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
