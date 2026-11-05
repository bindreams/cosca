//! A `Pidfs` id's start time is read from `/proc`, bracketed: the `stat` is read, then the id is
//! proved again. The process that the proof finds holding the pid has held it throughout, so the
//! `stat` is its own and a reuser's is never taken for it.

use std::os::fd::OwnedFd;

use rustix::io::Errno;
use rustix::process::Pid;

use crate::identity::stat_parse::stat_fixture;
use crate::identity::{ticks_host, FakeKernel, HostKernel, Key, ProcessId, Resolved};

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

/// The read of the `Pidfs` id `id(100)`'s pid with no parent named: its identity when it is found.
fn read_of(kernel: &FakeKernel<'_>) -> Resolved<ProcessId> {
    ProcessId::of_ordered_with(kernel, PID, None, Some(id(100).key()), None)
        .0
        .map(|(read, _)| read)
}

/// A zombie keeps its `stat`, and it is read. Mutant: "a zombie's read is `Unknown` or `Gone`".
#[skuld::test]
fn a_zombies_stat_is_read() {
    let (kernel, _writer) = kernel_showing(&stat_fixture("Z", 777), 100);
    assert_eq!(read_of(&kernel), Resolved::Found(id(100)));
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
    assert_eq!(read_of(&kernel), Resolved::Gone);
}

#[skuld::test]
fn a_stat_that_cannot_be_read_is_gone_only_when_kill_says_esrch() {
    let cases: [(Result<(), Errno>, Resolved<ProcessId>); 2] =
        [(Err(Errno::SRCH), Resolved::Gone), (Ok(()), Resolved::Unknown)];
    for (probe, expected) in cases {
        let (fd, _writer) = pidfd();
        let kernel = FakeKernel::over(&HostKernel)
            .same_view()
            .on_read(STAT, Err(libc::ENOENT))
            .on_pidfd_open(PID, Ok(fd))
            .on_pidfs_ino(PID, Ok(Some(100)))
            .on_signal_probe(Pid::from_raw(PID as i32).unwrap(), probe);
        assert_eq!(read_of(&kernel), expected, "kill {probe:?}");
    }
}

/// A `Pidfs` id is the pidfd's inode: nothing off Windows orders by the start time, so a `stat`
/// without one still gives the process, and its ppid. A `Ticks` id is the start time, which a `stat`
/// without one does not give: `Unknown`, not a start of zero.
///
/// Mutant: the `Pidfs` read requires the start time (`Unknown`); the `Ticks` read takes zero for it.
#[skuld::test]
fn a_stat_without_a_start_time_is_a_pidfs_id_but_no_ticks_id() {
    let (kernel, _writer) = kernel_showing(b"4242 (x) S 1", 100);
    assert_eq!(read_of(&kernel), Resolved::Found(id(100)));

    let kernel = ticks_host(PID).on_read(STAT, Ok(b"4242 (x) S 1"));
    assert_eq!(
        ProcessId::of_ordered_with(&kernel, PID, None, None, None).0,
        Resolved::Unknown
    );
}

/// How Linux's `ordered_read` reports the ppid of a `stat`, through `of_ordered_with` against a named
/// parent: the number shown is another parent's (`Gone`, the pid changed hands), or none can be read
/// from it (`Unknown`). What the shared step does with each is the row in `identity_tests`.
///
/// Mutant: "an unreadable ppid is read as a number".
#[skuld::test]
fn a_stat_with_no_readable_ppid_is_unknown_not_another_parent() {
    let parent = ProcessId::from_parts_for_test(7, Key::Pidfs(9));
    let with_ppid = |ppid: &str| {
        let stat = String::from_utf8(stat_fixture("S", 777))
            .expect("a fixture is text")
            .replacen(" S 1 ", &format!(" S {ppid} "), 1);
        kernel_showing(stat.as_bytes(), 100)
    };

    let (another, _writer) = with_ppid("8");
    assert!(matches!(
        ProcessId::of_ordered_with(&another, PID, Some(parent), None, None).0,
        Resolved::Gone
    ));
    // The parent is held, so the candidate's own failure stands.
    let (unreadable, _writer) = with_ppid("x");
    let (parent_fd, _parent_writer) = pidfd();
    let unreadable = unreadable.on_pidfd_open(7, Ok(parent_fd)).on_pidfs_ino(7, Ok(Some(9)));
    assert!(matches!(
        ProcessId::of_ordered_with(&unreadable, PID, Some(parent), None, None).0,
        Resolved::Unknown
    ));
}

/// A `stat` that cannot be read at all, for a candidate under a parent that is gone, is `Gone`: the
/// read is `Unknown` blaming the candidate only once the parent is held.
///
/// Mutant: Linux's `ordered_read` does not say it asked for the parent number when the `stat` is
/// missing.
#[skuld::test]
fn a_gone_parent_is_gone_before_a_refused_stat_is_unknown() {
    let parent = ProcessId::from_parts_for_test(7, Key::Pidfs(9));
    let (fd, _writer) = pidfd();
    let gone = FakeKernel::over(&HostKernel)
        .same_view()
        .on_read(STAT, Err(libc::EACCES))
        .on_pidfd_open(PID, Ok(fd))
        .on_pidfs_ino(PID, Ok(Some(100)))
        .on_pidfd_open(7, Err(Errno::SRCH));
    let (read, _) = ProcessId::of_ordered_with(&gone, PID, Some(parent), None, None);
    assert!(matches!(read, Resolved::Gone), "{read:?}");
}

/// A `Pidfs` candidate that names another parent is `Gone` though its `stat` shows no start time:
/// none is read. The named parent is held, so only the other parent's number can make it `Gone`.
///
/// Mutant: a missing start time hides the other parent's number.
#[skuld::test]
fn another_parent_is_gone_even_when_the_start_time_is_missing() {
    let parent = ProcessId::from_parts_for_test(7, Key::Pidfs(9));
    let (kernel, _writer) = kernel_showing(b"4242 (x) S 8", 100);
    let (parent_fd, _parent_writer) = pidfd();
    let kernel = kernel.on_pidfd_open(7, Ok(parent_fd)).on_pidfs_ino(7, Ok(Some(9)));
    assert!(matches!(
        ProcessId::of_ordered_with(&kernel, PID, Some(parent), None, None).0,
        Resolved::Gone
    ));
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
