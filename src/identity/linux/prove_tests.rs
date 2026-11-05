//! `exists` and `is_alive` on a `Pidfs` id open the pid and compare the pidfd's inode with the id's.
//!
//! The fake rows state what the kernel would answer and run everywhere. The host rows open real
//! pidfds, so they need pidfs (Linux 6.9+): they join the `pidfd_group_signal` group, whose
//! precondition is that kernel.

use std::os::fd::{AsFd as _, OwnedFd};

use rustix::io::Errno;
use rustix::process::PidfdFlags;

use super::super::kernel::{HostKernel, Kernel, PIDFD_THREAD};
use crate::error::Error;
use crate::identity::{Existence, FakeKernel, Key, Liveness, ProcessId};
use crate::test_groups::{pidfd_group_signal, Group};

const PID: u32 = 4242;

fn id(ino: u64) -> ProcessId {
    ProcessId::from_parts_for_test(PID, Key::Pidfs(ino))
}

/// A descriptor that does not poll readable, and the writer that keeps it so.
fn unreadable() -> (OwnedFd, std::io::PipeWriter) {
    let (reader, writer) = std::io::pipe().expect("a pipe");
    (reader.into(), writer)
}

/// A descriptor that polls readable.
fn readable() -> OwnedFd {
    let (reader, writer) = std::io::pipe().expect("a pipe");
    drop(writer);
    reader.into()
}

/// A kernel whose `pidfd_open` of `PID` hands out `fd`, and whose pidfd has inode `ino`.
fn kernel_with(fd: OwnedFd, ino: u64) -> FakeKernel<'static> {
    FakeKernel::new()
        .on_pidfd_open(PID, Ok(fd))
        .on_pidfs_ino(PID, Ok(Some(ino)))
}

/// A kernel whose `pidfd_open` of `PID` answers `errno`.
fn refusing(errno: Errno) -> FakeKernel<'static> {
    FakeKernel::new().on_pidfd_open(PID, Err(errno))
}

#[skuld::test]
fn a_pid_that_opens_to_the_ids_inode_exists() {
    let (fd, _writer) = unreadable();
    assert_eq!(id(100).exists_with(&kernel_with(fd, 100)).0, Existence::Present);
}

/// Mutant: "the open is taken as proof".
#[skuld::test]
fn a_pid_that_opens_to_another_inode_is_gone() {
    let (fd, _writer) = unreadable();
    assert_eq!(id(100).exists_with(&kernel_with(fd, 101)).0, Existence::Gone);
}

#[skuld::test]
fn a_pid_with_no_process_is_gone_and_dead() {
    assert_eq!(id(100).exists_with(&refusing(Errno::SRCH)).0, Existence::Gone);
    assert_eq!(id(100).is_alive_with(&refusing(Errno::SRCH)), Liveness::Dead);
}

/// A descriptor limit is no answer about the pid, and says so.
#[skuld::test]
fn a_pid_that_cannot_be_opened_for_want_of_descriptors_is_unknown_with_the_errno() {
    use std::error::Error as _;

    for errno in [Errno::MFILE, Errno::NFILE] {
        let (existence, cause) = id(100).exists_with(&refusing(errno));
        assert_eq!(existence, Existence::Unknown, "{errno}");
        assert_eq!(id(100).is_alive_with(&refusing(errno)), Liveness::Unknown, "{errno}");
        let err = cause.into_error("pid 4242").expect("the errno is the cause");
        assert!(matches!(err, Error::Unassessable { .. }), "{err:?}");
        let source = err.source().expect("the errno is the source");
        let source = source.downcast_ref::<std::io::Error>().expect("an OS error");
        assert_eq!(source.raw_os_error(), Some(errno.raw_os_error()));
    }
}

/// A refused `pidfd_open` is `Unsupported`, never a fallback to `/proc`.
#[skuld::test]
fn a_refused_pidfd_open_is_unknown_and_unsupported() {
    for errno in [Errno::PERM, Errno::NOSYS, Errno::ACCESS, Errno::NODEV] {
        let (existence, cause) = id(100).exists_with(&refusing(errno));
        assert_eq!(existence, Existence::Unknown, "{errno}");
        assert_eq!(id(100).is_alive_with(&refusing(errno)), Liveness::Unknown, "{errno}");
        let err = cause.into_error("pid 4242").expect("the refusal is the cause");
        assert!(matches!(err, Error::Unsupported { .. }), "{errno}: {err:?}");
    }
}

/// A thread that leads no group opens only with `PIDFD_THREAD`: `EINVAL` before 6.16, `ENOENT` from
/// 6.16. Mutant: "the retry is skipped", or "the retry is for every errno".
#[skuld::test]
fn a_thread_that_leads_no_group_opens_with_pidfd_thread() {
    for first in [Errno::INVAL, Errno::NOENT] {
        let (fd, _writer) = unreadable();
        let kernel = FakeKernel::new()
            .on_pidfd_open_flags(PID, PidfdFlags::empty(), Err(first))
            .on_pidfd_open_flags(PID, PIDFD_THREAD, Ok(fd))
            .on_pidfs_ino(PID, Ok(Some(100)));
        assert_eq!(id(100).exists_with(&kernel).0, Existence::Present, "{first}");
        assert_eq!(id(100).is_alive_with(&kernel), Liveness::Alive, "{first}");
    }
}

#[skuld::test]
fn a_refused_open_is_not_retried_with_pidfd_thread() {
    let kernel = FakeKernel::new().on_pidfd_open_flags(PID, PidfdFlags::empty(), Err(Errno::MFILE));
    // A row for `PIDFD_THREAD` is absent: a retry would panic.
    assert_eq!(id(100).exists_with(&kernel).0, Existence::Unknown);
}

/// On 6.12 a reaped group leader whose number lives only as a process-group id answers `EINVAL` to
/// both opens, as a kernel before 6.9 does. A `Pidfs` id is of a kernel that has pidfs, so no process
/// has that number: `Gone`, and `/proc` is not asked.
#[skuld::test]
fn a_pid_both_opens_refuse_with_einval_holds_no_process_a_pidfs_id_names() {
    let kernel = FakeKernel::new()
        .on_pidfd_open_flags(PID, PidfdFlags::empty(), Err(Errno::INVAL))
        .on_pidfd_open_flags(PID, PIDFD_THREAD, Err(Errno::INVAL));
    assert_eq!(id(100).exists_with(&kernel).0, Existence::Gone);
    assert_eq!(id(100).is_alive_with(&kernel), Liveness::Dead);
}

#[skuld::test]
fn a_pidfd_whose_inode_cannot_be_read_is_unknown() {
    let (fd, _writer) = unreadable();
    let kernel = FakeKernel::new()
        .on_pidfd_open(PID, Ok(fd))
        .on_pidfs_ino(PID, Err(Errno::BADF));
    let (existence, cause) = id(100).exists_with(&kernel);
    assert_eq!(existence, Existence::Unknown);
    assert!(cause.into_error("pid 4242").is_some(), "the errno is the cause");
    assert_eq!(id(100).is_alive_with(&kernel), Liveness::Unknown);
}

#[skuld::test]
fn a_pidfd_that_polls_readable_is_dead_and_one_that_does_not_is_alive() {
    assert_eq!(id(100).is_alive_with(&kernel_with(readable(), 100)), Liveness::Dead);
    let (fd, _writer) = unreadable();
    assert_eq!(id(100).is_alive_with(&kernel_with(fd, 100)), Liveness::Alive);
}

/// A pid reused by another process is dead to the id, whatever its pidfd polls. Mutant: "liveness
/// polls without proving".
#[skuld::test]
fn a_reused_pid_is_dead_to_the_id_it_does_not_hold() {
    let (fd, _writer) = unreadable();
    assert_eq!(id(100).is_alive_with(&kernel_with(fd, 101)), Liveness::Dead);
}

// Host rows =====

/// A live child is `Present` and `Alive`; once it has exited and is not reaped it is `Present` and
/// `Dead`; once reaped it is `Gone` and `Dead`.
#[skuld::test]
fn a_real_child_is_alive_then_a_zombie_then_gone(#[fixture(pidfd_group_signal)] _group: &Group) {
    let mut child =
        crate::test_spawn::spawn(&mut crate::test_child::held_std_killable_blocker()).expect("spawn the child");
    let pid = child.id();
    let pidfd = HostKernel
        .pidfd_open(
            rustix::process::Pid::from_raw(pid as i32).expect("a pid"),
            PidfdFlags::empty(),
        )
        .expect("pidfd_open of the child");
    let ino = HostKernel
        .pidfs_ino(pidfd.as_fd())
        .expect("fstatfs and fstat")
        .expect("the host has pidfs");
    let id = ProcessId::from_parts_for_test(pid, Key::Pidfs(ino));

    assert_eq!(id.exists(), Existence::Present);
    assert_eq!(id.is_alive(), Liveness::Alive);

    child.kill().expect("kill the child");
    // The child's exit is the condition: its pidfd turns readable at exit, before any reap.
    crate::os_process::poll::poll_readable(pidfd.as_fd(), None).expect("poll the child's pidfd");
    assert_eq!(id.exists(), Existence::Present, "a zombie is still resolvable");
    assert_eq!(id.is_alive(), Liveness::Dead, "a zombie is not running");

    child.wait().expect("reap the child");
    assert_eq!(id.exists(), Existence::Gone);
    assert_eq!(id.is_alive(), Liveness::Dead);
}

/// Mutant: "the inode is the pid's, not the process's": another process's pidfd has another inode.
#[skuld::test]
fn two_pidfds_of_one_process_share_an_inode_and_two_processes_do_not(#[fixture(pidfd_group_signal)] _group: &Group) {
    let mut first =
        crate::test_spawn::spawn(&mut crate::test_child::held_std_killable_blocker()).expect("spawn the child");
    let mut second =
        crate::test_spawn::spawn(&mut crate::test_child::held_std_killable_blocker()).expect("spawn the child");
    let ino = |pid: u32| {
        let target = rustix::process::Pid::from_raw(pid as i32).expect("a pid");
        let one = HostKernel.pidfd_open(target, PidfdFlags::empty()).expect("pidfd_open");
        let two = HostKernel.pidfd_open(target, PidfdFlags::empty()).expect("pidfd_open");
        let (a, b) = (
            HostKernel.pidfs_ino(one.as_fd()).expect("ino").expect("pidfs"),
            HostKernel.pidfs_ino(two.as_fd()).expect("ino").expect("pidfs"),
        );
        assert_eq!(a, b, "one process, one inode");
        a
    };
    assert_ne!(ino(first.id()), ino(second.id()));
    for child in [&mut first, &mut second] {
        child.kill().expect("kill the child");
        child.wait().expect("reap the child");
    }
}
