//! `ProcessId::of_with` and `of_stat_with` on a pid whose pidfd opens in each way the kernel
//! answers. The rows state the answers; a `FakeKernel::new()` panics on a `/proc` read it has no row
//! for, so a row that must not read `/proc` fails when it does.

use std::error::Error as _;
use std::os::fd::OwnedFd;

use rustix::io::Errno;
use rustix::process::PidfdFlags;

use super::kernel::PIDFD_THREAD;
use crate::error::Error;
use crate::identity::stat_parse::stat_fixture;
use crate::identity::{FakeKernel, HostKernel, Key, ProcessId, Resolved, UnknownCause};

const PID: u32 = 4242;
const STAT: &str = "4242/stat";

/// This process's number: the pid whose pidfd tells which kind of key the host's processes have.
fn own() -> u32 {
    std::process::id()
}

/// A descriptor to stand for a pidfd the kernel hands out.
fn stand_in() -> OwnedFd {
    OwnedFd::from(std::fs::File::open("/dev/null").expect("/dev/null opens"))
}

/// A kernel on which this process's own pidfd has a pidfs inode.
fn pidfs_host() -> FakeKernel<'static> {
    FakeKernel::new()
        .on_pidfd_open(own(), Ok(stand_in()))
        .on_pidfs_ino(own(), Ok(Some(1)))
}

/// A kernel on which this process's own pidfd has no inode, and `PID` shows `stat` in `/proc`.
fn ticks_host_showing(stat: &[u8]) -> FakeKernel<'static> {
    FakeKernel::over(&HostKernel)
        .same_view()
        .on_read(STAT, Ok(stat))
        .on_pidfd_open(own(), Ok(stand_in()))
        .on_pidfs_ino(own(), Ok(None))
}

/// `PID` is refused `first` and then, with `PIDFD_THREAD`, `retry`.
fn refused_twice(kernel: FakeKernel<'static>, first: Errno, retry: Errno) -> FakeKernel<'static> {
    kernel
        .on_pidfd_open_flags(PID, PidfdFlags::empty(), Err(first))
        .on_pidfd_open_flags(PID, PIDFD_THREAD, Err(retry))
}

/// `of_with` and `of_stat_with`, which share the open.
fn both(kernel: &FakeKernel<'_>) -> [(&'static str, Resolved<ProcessId>, UnknownCause); 2] {
    let (id, id_cause) = ProcessId::of_with(kernel, PID);
    let (with_stat, stat_cause) = ProcessId::of_stat_with(kernel, PID);
    [
        ("of_with", id, id_cause),
        ("of_stat_with", with_stat.map(|(id, _)| id), stat_cause),
    ]
}

/// Mutants: "`(EINVAL, EINVAL)` is ticks on every host", and "`/proc` is read for every
/// `(EINVAL, EINVAL)`" (a process that takes the number meanwhile would be misread as ticks).
#[skuld::test]
fn a_pid_both_opens_refuse_with_einval_is_gone_on_pidfs_with_no_proc_read() {
    for (name, got, _) in both(&refused_twice(pidfs_host(), Errno::INVAL, Errno::INVAL)) {
        assert!(matches!(got, Resolved::Gone), "{name}: got {got:?}");
    }
}

/// Mutant: "`(EINVAL, EINVAL)` is `Gone` on every host": a ticks host's thread that leads no group
/// refuses both opens, and is told by `/proc`.
#[skuld::test]
fn a_pid_both_opens_refuse_with_einval_takes_the_ticks_path_on_a_ticks_host() {
    let kernel = refused_twice(ticks_host_showing(&stat_fixture("S", 777)), Errno::INVAL, Errno::INVAL);
    for (name, got, _) in both(&kernel) {
        match got {
            Resolved::Found(id) => assert_eq!(id.key(), Key::Ticks(777), "{name}"),
            other => panic!("{name}: got {other:?}"),
        }
    }
}

/// Mutant: "`ESRCH` falls to the catch-all", which is `Unknown`.
#[skuld::test]
fn a_pid_the_open_answers_esrch_is_gone() {
    let kernel = FakeKernel::new().on_pidfd_open_flags(PID, PidfdFlags::empty(), Err(Errno::SRCH));
    // A row for `PIDFD_THREAD` is absent: a retry would panic.
    for (name, got, _) in both(&kernel) {
        assert!(matches!(got, Resolved::Gone), "{name}: got {got:?}");
    }
}

/// `prove` answers `Lost` for an `ENOENT` retry, so `look` answers `Gone`. Mutant: "`ENOENT` falls
/// to the catch-all".
#[skuld::test]
fn a_pid_the_thread_retry_answers_enoent_is_gone() {
    for first in [Errno::INVAL, Errno::NOENT] {
        for (name, got, _) in both(&refused_twice(FakeKernel::new(), first, Errno::NOENT)) {
            assert!(matches!(got, Resolved::Gone), "{first}, {name}: got {got:?}");
        }
    }
}

/// The errno of a failed call is the `Unknown`'s cause.
fn assert_unknown_with(errno: Errno, row: &str, (name, got, cause): (&str, Resolved<ProcessId>, UnknownCause)) {
    assert!(matches!(got, Resolved::Unknown), "{row}, {name}: got {got:?}");
    let err = cause.into_error("pid 4242").expect("the errno is the cause");
    assert!(matches!(err, Error::Unassessable { .. }), "{row}, {name}: {err:?}");
    let source = err.source().expect("the errno is the source");
    let source = source.downcast_ref::<std::io::Error>().expect("an OS error");
    assert_eq!(source.raw_os_error(), Some(errno.raw_os_error()), "{row}, {name}");
}

/// Mutant: "any open errno is `Gone`", or "is retried with `PIDFD_THREAD`" (the row for it is absent,
/// and a retry would panic).
#[skuld::test]
fn a_pid_the_open_cannot_take_for_want_of_descriptors_is_unknown_with_the_errno() {
    let kernel = FakeKernel::new().on_pidfd_open_flags(PID, PidfdFlags::empty(), Err(Errno::MFILE));
    for got in both(&kernel) {
        assert_unknown_with(Errno::MFILE, "pidfd_open", got);
    }
}

/// Mutant: "the own pidfd's failure is `Gone`, or a guess at ticks".
#[skuld::test]
fn a_failing_own_pidfd_open_is_unknown_with_the_errno() {
    let kernel = refused_twice(
        FakeKernel::new().on_pidfd_open(own(), Err(Errno::MFILE)),
        Errno::INVAL,
        Errno::INVAL,
    );
    for got in both(&kernel) {
        assert_unknown_with(Errno::MFILE, "own pidfd_open", got);
    }
}

#[skuld::test]
fn a_failing_own_pidfs_ino_is_unknown_with_the_errno() {
    let kernel = refused_twice(
        FakeKernel::new()
            .on_pidfd_open(own(), Ok(stand_in()))
            .on_pidfs_ino(own(), Err(Errno::BADF)),
        Errno::INVAL,
        Errno::INVAL,
    );
    for got in both(&kernel) {
        assert_unknown_with(Errno::BADF, "own pidfs_ino", got);
    }
}

/// Mutant: "the pidfd's failing inode read is dropped".
#[skuld::test]
fn a_failing_pidfs_ino_of_the_pid_is_unknown_with_the_errno() {
    let kernel = FakeKernel::new()
        .on_pidfd_open(PID, Ok(stand_in()))
        .on_pidfs_ino(PID, Err(Errno::BADF));
    for got in both(&kernel) {
        assert_unknown_with(Errno::BADF, "pidfs_ino", got);
    }
}
