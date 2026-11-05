//! A `Pidfs` id's start time is read from `/proc`, bracketed: the `stat` is read, then the id is
//! proved again. The process that the proof finds holding the pid has held it throughout, so the
//! `stat` is its own and a reuser's is never taken for it.

use std::os::fd::OwnedFd;

use rustix::io::Errno;
use rustix::process::Pid;

use crate::identity::stat_parse::stat_fixture;
use crate::identity::{FakeKernel, HostKernel, Key, OrderKey, ProcessId, Resolved};

const PID: u32 = 4242;
const STAT: &str = "4242/stat";

fn id(ino: u64) -> ProcessId {
    ProcessId::from_parts_for_test(PID, Key::Pidfs(ino))
}

/// A descriptor to stand for the pidfd, and the writer that keeps it from polling readable.
fn pidfd() -> (OwnedFd, std::io::PipeWriter) {
    let (reader, writer) = std::io::pipe().expect("a pipe");
    (reader.into(), writer)
}

/// A kernel in which pid `PID` holds the process with inode `ino` and shows `stat`.
fn kernel_showing(stat: &[u8], ino: u64) -> (FakeKernel<'static>, std::io::PipeWriter) {
    let (fd, writer) = pidfd();
    let kernel = FakeKernel::over(&HostKernel)
        .same_view()
        .on_read(STAT, Ok(stat))
        .on_pidfd_open(PID, Ok(fd))
        .on_pidfs_ino(PID, Ok(Some(ino)));
    (kernel, writer)
}

fn key_of(read: Resolved<OrderKey>) -> OrderKey {
    match read {
        Resolved::Found(key) => key,
        other => panic!("expected a key, got {other:?}"),
    }
}

/// The order key of a `Pidfs` id is the start time in the `stat`, not the inode.
#[skuld::test]
fn a_pidfs_ids_order_key_is_the_start_time_its_stat_shows() {
    let (kernel, _writer) = kernel_showing(&stat_fixture("S", 777), 100);
    let (read, _) = id(100).order_key_with(&kernel);
    assert_eq!(key_of(read), OrderKey::for_test(777));
}

/// A zombie keeps its `stat`, and its key.
#[skuld::test]
fn a_zombies_order_key_is_read() {
    let (kernel, _writer) = kernel_showing(&stat_fixture("Z", 777), 100);
    assert_eq!(key_of(id(100).order_key_with(&kernel).0), OrderKey::for_test(777));
}

/// Mutant: "the id is proved before the `stat` is read": a pid that a reuser takes after the proof
/// and before the read gives the reuser's `stat` to the id. The kernel states that the pid opens
/// to another inode once the `stat` has been read.
#[skuld::test]
fn a_stat_read_before_the_pid_changed_hands_is_not_the_ids() {
    let (fd, _writer) = pidfd();
    let kernel = FakeKernel::over(&HostKernel)
        .same_view()
        .on_read(STAT, Ok(&stat_fixture("S", 777)))
        .on_pidfd_open(PID, Ok(fd))
        .on_pidfs_ino(PID, Ok(Some(100)))
        .on_pidfs_ino_after_read(PID, STAT, Ok(Some(101)));
    assert!(matches!(id(100).order_key_with(&kernel).0, Resolved::Gone));
}

#[skuld::test]
fn a_stat_that_cannot_be_read_is_gone_only_when_kill_says_esrch() {
    let cases: [(Result<(), Errno>, bool); 2] = [(Err(Errno::SRCH), true), (Ok(()), false)];
    for (probe, gone) in cases {
        let kernel = FakeKernel::over(&HostKernel)
            .same_view()
            .on_read(STAT, Err(libc::ENOENT))
            .on_signal_probe(Pid::from_raw(PID as i32).unwrap(), probe);
        match (gone, id(100).order_key_with(&kernel).0) {
            (true, Resolved::Gone) | (false, Resolved::Unknown) => {}
            (_, got) => panic!("kill {probe:?}: got {got:?}"),
        }
    }
}

/// A `stat` with no start time is unreadable, not a key of zero.
#[skuld::test]
fn a_stat_without_a_start_time_gives_no_key() {
    let (kernel, _writer) = kernel_showing(b"4242 (x) S 1", 100);
    assert!(matches!(id(100).order_key_with(&kernel).0, Resolved::Unknown));
}

/// A `Ticks` id's key is its ticks, and nothing is read: a kernel with no rows panics on a read.
#[skuld::test]
fn a_ticks_ids_order_key_is_its_ticks_with_no_read() {
    let ticks = ProcessId::from_parts_for_test(PID, Key::Ticks(555));
    assert_eq!(
        key_of(ticks.order_key_with(&FakeKernel::new()).0),
        OrderKey::for_test(555)
    );
}

/// `created_at` of a `Pidfs` id reads the same bracketed start time, and says `None` once the
/// process is gone.
#[skuld::test]
fn a_pidfs_ids_creation_time_comes_from_its_start_time() {
    let (kernel, _writer) = kernel_showing(&stat_fixture("S", 777), 100);
    let ticks = ProcessId::from_parts_for_test(PID, Key::Ticks(777));
    let created = id(100).created_at_with(&kernel);
    assert!(created.is_some(), "the process started after boot");
    assert_eq!(created, ticks.created_at_with(&FakeKernel::new()));

    let gone = FakeKernel::over(&HostKernel)
        .same_view()
        .on_read(STAT, Err(libc::ENOENT))
        .on_signal_probe(Pid::from_raw(PID as i32).unwrap(), Err(Errno::SRCH));
    assert_eq!(id(100).created_at_with(&gone), None);
}
