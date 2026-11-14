//! Whether a Linux process's exit has begun: every thread of its group shows `PF_EXITING` in its
//! `stat`, read through the checked `/proc`, the thread list read again until it shows no thread not
//! yet read, and the id proved after the reads. Every row is a [`FakeKernel`]'s stated facts: the
//! kernel's own order (the flag before the reparent) is measured, in the finding the module names,
//! and a held exit needs root and a FUSE mount.

use std::os::fd::OwnedFd;

use rustix::io::Errno;
use rustix::process::Pid;

use crate::identity::{ticks_host, FakeKernel, HostKernel, Key, ProcessId, Resolved};

const PID: u32 = 4242;
const INO: u64 = 100;
const START: u64 = 777;
/// A thread's flags before its exit, and once `exit_signals` has run (`0x4`, with `0x8` beside it):
/// the values measured on Linux 6.12.113.
const LIVE: u32 = 0x40_0140;
const EXITING: u32 = 0x40_014c;

fn pidfs_id() -> ProcessId {
    ProcessId::from_parts_for_test(PID, Key::Pidfs(INO))
}

fn ticks_id() -> ProcessId {
    ProcessId::from_parts_for_test(PID, Key::Ticks(START))
}

fn stat_with(flags: u32, start: u64) -> Vec<u8> {
    format!("{PID} (t) S 1 {PID} {PID} 0 -1 {flags} 0 0 0 0 0 0 0 0 20 0 1 0 {start} 0 0").into_bytes()
}

fn task_stat(tid: u32) -> String {
    format!("{PID}/task/{tid}/stat")
}

fn pidfd() -> (OwnedFd, std::io::PipeWriter) {
    let (reader, writer) = std::io::pipe().expect("a pipe");
    (reader.into(), writer)
}

/// A kernel in which pid `PID` holds the process with pidfs inode `INO`, whose threads are `threads`,
/// each a thread id and its flags.
fn pidfs_kernel(threads: &[(u32, u32)]) -> (FakeKernel<'static>, std::io::PipeWriter) {
    let (fd, writer) = pidfd();
    let kernel = FakeKernel::over(&HostKernel)
        .same_view()
        .on_pidfd_open(PID, Ok(fd))
        .on_pidfs_ino(PID, Ok(Some(INO)));
    (with_threads(kernel, threads), writer)
}

/// `kernel` listing the threads `threads` of `PID` and showing each one's flags.
fn with_threads(mut kernel: FakeKernel<'static>, threads: &[(u32, u32)]) -> FakeKernel<'static> {
    let tids: Vec<u32> = threads.iter().map(|(tid, _)| *tid).collect();
    kernel = kernel.on_tids(PID, Ok(&tids));
    for (tid, flags) in threads {
        kernel = kernel.on_read(&task_stat(*tid), Ok(&stat_with(*flags, START)));
    }
    kernel
}

/// A host before Linux 6.9 whose `PID` has start time `start` now and the threads `threads`.
fn ticks_kernel(threads: &[(u32, u32)], start: u64) -> FakeKernel<'static> {
    with_threads(
        ticks_host(PID)
            .same_view()
            .on_read(&format!("{PID}/stat"), Ok(&stat_with(LIVE, start))),
        threads,
    )
}

fn begun(id: ProcessId, kernel: &FakeKernel<'_>) -> Resolved<bool> {
    id.exit_begun_with(kernel).0
}

/// The exit has begun when every thread of the group shows the flag, never when one does not: a
/// leader that `pthread_exit`s while another thread runs is exiting alone. Mutants: "only the leader's
/// flag is read"; "one exiting thread is enough"; "equality with `PF_EXITING`".
#[skuld::test]
fn a_group_has_begun_to_exit_only_when_every_thread_is_exiting() {
    let rows: [(&[(u32, u32)], bool); 5] = [
        (&[(PID, EXITING)], true),
        (&[(PID, EXITING), (4243, EXITING), (4244, EXITING)], true),
        (&[(PID, EXITING), (4243, LIVE)], false),
        (&[(PID, LIVE), (4243, EXITING)], false),
        (&[(PID, LIVE)], false),
    ];
    for (threads, expected) in rows {
        let (kernel, _writer) = pidfs_kernel(threads);
        assert_eq!(
            begun(pidfs_id(), &kernel),
            Resolved::Found(expected),
            "pidfs {threads:?}"
        );
        let kernel = ticks_kernel(threads, START);
        assert_eq!(
            begun(ticks_id(), &kernel),
            Resolved::Found(expected),
            "ticks {threads:?}"
        );
    }
}

/// A thread created after a listing is read by the next one, until a listing shows nothing new:
/// the third list adds a live thread, which a read that stopped after one re-list would miss.
/// Mutants: "the list is read once"; "the list is read twice".
#[skuld::test]
fn a_thread_that_appears_in_a_later_listing_is_read() {
    let (fd, _writer) = pidfd();
    let kernel = FakeKernel::over(&HostKernel)
        .same_view()
        .on_pidfd_open(PID, Ok(fd))
        .on_pidfs_ino(PID, Ok(Some(INO)))
        .on_tids(PID, Ok(&[PID]))
        .on_tids_after(PID, 1, Ok(&[PID, 4243]))
        .on_tids_after(PID, 2, Ok(&[PID, 4243, 4244]))
        .on_read(&task_stat(PID), Ok(&stat_with(EXITING, START)))
        .on_read(&task_stat(4243), Ok(&stat_with(EXITING, START)))
        .on_read(&task_stat(4244), Ok(&stat_with(LIVE, START)));
    assert_eq!(begun(pidfs_id(), &kernel), Resolved::Found(false));
}

/// Threads that all show the flag are begun once a listing is covered by the one before it, though the
/// listing grew in between. Mutant: the first complete pass is the answer.
#[skuld::test]
fn a_listing_covered_by_the_one_before_it_ends_the_reads() {
    let (fd, _writer) = pidfd();
    let kernel = FakeKernel::over(&HostKernel)
        .same_view()
        .on_pidfd_open(PID, Ok(fd))
        .on_pidfs_ino(PID, Ok(Some(INO)))
        .on_tids(PID, Ok(&[PID]))
        .on_tids_after(PID, 1, Ok(&[PID, 4243]))
        .on_read(&task_stat(PID), Ok(&stat_with(EXITING, START)))
        .on_read(&task_stat(4243), Ok(&stat_with(EXITING, START)));
    assert_eq!(begun(pidfs_id(), &kernel), Resolved::Found(true));
}

/// A thread id can change hands: a thread that calls `execve` takes the leader's id and the process
/// runs on. The leader showed the flag in the first pass (its thread was being ended), and the id shows
/// a running thread in the second, so every pass reads every thread of its listing. Mutant: a thread
/// already read is not read again.
#[skuld::test]
fn a_thread_id_that_changed_hands_is_read_again_by_the_next_pass() {
    let (fd, _writer) = pidfd();
    let kernel = FakeKernel::over(&HostKernel)
        .same_view()
        .on_pidfd_open(PID, Ok(fd))
        .on_pidfs_ino(PID, Ok(Some(INO)))
        .on_tids(PID, Ok(&[PID]))
        .on_tids_after(PID, 1, Ok(&[PID]))
        .on_read(&task_stat(PID), Ok(&stat_with(EXITING, START)))
        .on_read_after(&task_stat(PID), 1, Ok(&stat_with(LIVE, START)));
    assert_eq!(begun(pidfs_id(), &kernel), Resolved::Found(false));
}

/// A thread that is gone when it is read is no evidence of an exit: the listing is read afresh. In the
/// shape of an `execve` by a thread of a live group, the old leader shows the flag and the thread that
/// called is gone under its own id (it holds the leader's now): the next listing holds the leader's id
/// alone, and it shows a running thread. Mutants: a vanished thread counts as exiting (`true`); it
/// counts as running or unknown.
#[skuld::test]
fn a_thread_that_vanished_is_not_an_exit_and_the_listing_is_read_afresh() {
    for errno in [libc::ENOENT, libc::ESRCH] {
        let (fd, _writer) = pidfd();
        let exec = FakeKernel::over(&HostKernel)
            .same_view()
            .on_pidfd_open(PID, Ok(fd))
            .on_pidfs_ino(PID, Ok(Some(INO)))
            .on_tids(PID, Ok(&[PID, 4243]))
            .on_tids_after(PID, 1, Ok(&[PID]))
            .on_read(&task_stat(PID), Ok(&stat_with(EXITING, START)))
            .on_read_after(&task_stat(PID), 1, Ok(&stat_with(LIVE, START)))
            .on_read(&task_stat(4243), Err(errno));
        assert_eq!(begun(pidfs_id(), &exec), Resolved::Found(false), "exec, errno {errno}");

        // The vanished thread was one of a group that exits: the fresh listing shows the rest exiting.
        let (fd, _writer) = pidfd();
        let exiting = FakeKernel::over(&HostKernel)
            .same_view()
            .on_pidfd_open(PID, Ok(fd))
            .on_pidfs_ino(PID, Ok(Some(INO)))
            .on_tids(PID, Ok(&[PID, 4243]))
            .on_tids_after(PID, 1, Ok(&[PID]))
            .on_read(&task_stat(PID), Ok(&stat_with(EXITING, START)))
            .on_read(&task_stat(4243), Err(errno));
        assert_eq!(
            begun(pidfs_id(), &exiting),
            Resolved::Found(true),
            "exiting, errno {errno}"
        );
    }
}

/// A thread whose read is refused, or whose record has no flags, leaves the exit unassessed.
#[skuld::test]
fn a_thread_that_cannot_be_read_leaves_the_exit_unknown() {
    for stat in [Err(libc::EACCES), Err(libc::EIO), Ok(&b"4242 (t) S 1"[..])] {
        let (kernel, _writer) = pidfs_kernel(&[(PID, EXITING), (4243, EXITING)]);
        let kernel = kernel.on_read(&task_stat(4243), stat);
        assert_eq!(begun(pidfs_id(), &kernel), Resolved::Unknown, "{stat:?}");
    }
}

/// The id is proved after the reads, so the threads read are its own: a pid that another process holds
/// then is `Gone`, never the other process's flags. Mutants: the proof comes before the reads; the
/// proof is not made.
#[skuld::test]
fn a_pid_that_changed_hands_during_the_reads_is_gone() {
    let (kernel, _writer) = pidfs_kernel(&[(PID, EXITING)]);
    let kernel = kernel.on_pidfs_ino_after_read(PID, &task_stat(PID), Ok(Some(INO + 1)));
    assert_eq!(begun(pidfs_id(), &kernel), Resolved::Gone);

    // On a host before 6.9 the proof is the start time, read after the threads.
    assert_eq!(
        begun(ticks_id(), &ticks_kernel(&[(PID, EXITING)], START + 1)),
        Resolved::Gone
    );
}

/// A proof that cannot be made leaves the answer `Unknown`, with the flags that were read not taken
/// for the process's.
#[skuld::test]
fn a_proof_that_cannot_be_made_is_unknown() {
    let (kernel, _writer) = pidfs_kernel(&[(PID, EXITING)]);
    let kernel = kernel.on_pidfs_ino_after_read(PID, &task_stat(PID), Err(Errno::BADF));
    assert_eq!(begun(pidfs_id(), &kernel), Resolved::Unknown);
}

/// A listing that cannot be read, or lists no thread, is settled by what holds the pid then, as a read
/// that succeeded is: `Gone` when the process was reaped meanwhile, else `Unknown`. Mutants: a failed
/// listing is `Unknown` whatever holds the pid; the kill probe alone decides.
#[skuld::test]
fn a_listing_that_says_nothing_is_gone_when_the_process_was_reaped_and_unknown_when_it_holds_the_pid() {
    let target = Pid::from_raw(PID as i32).expect("a positive pid");
    // The pid held by the process (the proof passes) or by none (`pidfd_open` says `ESRCH`).
    let holders: [(Result<(), Errno>, Resolved<bool>); 2] =
        [(Ok(()), Resolved::Unknown), (Err(Errno::SRCH), Resolved::Gone)];
    type Listing = fn(FakeKernel<'static>) -> FakeKernel<'static>;
    let listings: [(&str, Listing); 3] = [
        ("an absent listing", |k| k.on_tids(PID, Err(libc::ENOENT))),
        ("a listing that failed after the open", |k| {
            k.on_tids_failing_after_open(PID, libc::EIO)
        }),
        ("an empty listing", |k| k.on_tids(PID, Ok(&[]))),
    ];
    for (holds, expected) in holders {
        for (name, listing) in listings {
            let kernel = FakeKernel::over(&HostKernel).same_view();
            let (kernel, _writer) = match holds {
                Ok(()) => {
                    let (fd, writer) = pidfd();
                    (
                        kernel.on_pidfd_open(PID, Ok(fd)).on_pidfs_ino(PID, Ok(Some(INO))),
                        Some(writer),
                    )
                }
                Err(errno) => (kernel.on_pidfd_open(PID, Err(errno)), None),
            };
            // `kill(pid, 0)` says nothing here: it answers `ESRCH` for both rows.
            let kernel = listing(kernel).on_signal_probe(target, Err(Errno::SRCH));
            assert_eq!(begun(pidfs_id(), &kernel), expected, "{name}, holder {holds:?}");
        }
    }
}

/// A `/proc` that is not this pid namespace's names another process under the number, so the flags it
/// shows are no answer. Mutant: the read goes by a view that was not checked.
#[skuld::test]
fn an_unusable_proc_view_leaves_the_exit_unknown() {
    let target = Pid::from_raw(PID as i32).expect("a positive pid");
    let (kernel, _writer) = pidfs_kernel(&[(PID, EXITING)]);
    let kernel = kernel.diverged_view().on_signal_probe(target, Ok(()));
    let (read, cause) = pidfs_id().exit_begun_with(&kernel);
    assert_eq!(read, Resolved::Unknown);
    let error = cause.into_error("pid 4242").expect("the view's reason is kept");
    assert!(error.to_string().contains("outer pid namespace"), "{error}");
}
