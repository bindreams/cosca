//! `open_verified_with` for a `Pidfs` id: opening the pid and finding the id's inode on the pidfd is
//! the whole proof. No `/proc` is read, so every kernel here is a [`FakeKernel::new`], which panics
//! on a call it has no row for: `open_proc`, a `fdinfo` read or a `stat` read would fail the row.
//!
//! Rows run everywhere but the host row, which needs pidfs (Linux 6.9+) and so joins the
//! `pidfd_group_signal` group.

use std::os::fd::{AsFd as _, OwnedFd};

use rustix::io::Errno;
use rustix::process::PidfdFlags;

use super::open_verified_error_with;
use crate::error::Error;
use crate::identity::{FakeKernel, HostKernel, Kernel as _, Key, ProcessId};
use crate::test_groups::{pidfd_group_signal, Group};

const PID: u32 = 4242;
const THREAD: PidfdFlags = crate::identity::PIDFD_THREAD;

fn id(ino: u64) -> ProcessId {
    ProcessId::from_parts_for_test(PID, Key::Pidfs(ino))
}

/// A descriptor that does not poll readable, and the writer that keeps it so.
fn unreadable() -> (OwnedFd, std::io::PipeWriter) {
    let (reader, writer) = std::io::pipe().expect("a pipe");
    (reader.into(), writer)
}

fn readable() -> OwnedFd {
    let (reader, writer) = std::io::pipe().expect("a pipe");
    drop(writer);
    reader.into()
}

fn refusing(errno: Errno) -> FakeKernel<'static> {
    FakeKernel::new().on_pidfd_open(PID, Err(errno))
}

/// The proof is the inode: no fdinfo, no stat, no `/proc`. Mutant: "the pidfs path verifies through
/// `/proc` as the ticks path does" (the kernel has no row for it, so the call panics).
#[skuld::test]
fn a_pid_that_opens_to_the_ids_inode_opens_with_no_proc_read() {
    let (fd, _writer) = unreadable();
    let kernel = FakeKernel::new()
        .on_pidfd_open(PID, Ok(fd))
        .on_pidfs_ino(PID, Ok(Some(100)));
    assert!(matches!(open_verified_error_with(&kernel, id(100)), Ok(Some(_))));
}

#[skuld::test]
fn a_pid_that_opens_to_another_inode_is_none() {
    let (fd, _writer) = unreadable();
    let kernel = FakeKernel::new()
        .on_pidfd_open(PID, Ok(fd))
        .on_pidfs_ino(PID, Ok(Some(101)));
    assert!(matches!(open_verified_error_with(&kernel, id(100)), Ok(None)));
}

#[skuld::test]
fn a_pid_with_no_process_and_one_no_pidfd_opens_for_are_none() {
    assert!(matches!(
        open_verified_error_with(&refusing(Errno::SRCH), id(100)),
        Ok(None)
    ));
    let kernel = FakeKernel::new()
        .on_pidfd_open_flags(PID, PidfdFlags::empty(), Err(Errno::INVAL))
        .on_pidfd_open_flags(PID, THREAD, Err(Errno::INVAL));
    assert!(matches!(open_verified_error_with(&kernel, id(100)), Ok(None)));
}

/// A thread that leads no group is no process to signal: `NotThreadGroupLeader` carrying the errno
/// the open of the leader answered, as the ticks path does.
#[skuld::test]
fn a_live_thread_that_leads_no_group_is_not_a_thread_group_leader() {
    for first in [Errno::INVAL, Errno::NOENT] {
        let (fd, _writer) = unreadable();
        let kernel = FakeKernel::new()
            .on_pidfd_open_flags(PID, PidfdFlags::empty(), Err(first))
            .on_pidfd_open_flags(PID, THREAD, Ok(fd))
            .on_pidfs_ino(PID, Ok(Some(100)));
        match open_verified_error_with(&kernel, id(100)) {
            Err(Error::NotThreadGroupLeader { pid, source, .. }) => {
                assert_eq!(pid, PID);
                assert_eq!(source.raw_os_error(), Some(first.raw_os_error()), "{first}");
            }
            other => panic!("{first}: expected NotThreadGroupLeader, got {other:?}"),
        }
    }
}

/// A ptraced zombie thread is kept until its tracer waits; its `PIDFD_THREAD` pidfd polls readable.
/// It has exited: `None`, not an error.
#[skuld::test]
fn a_thread_that_has_exited_is_none() {
    let kernel = FakeKernel::new()
        .on_pidfd_open_flags(PID, PidfdFlags::empty(), Err(Errno::INVAL))
        .on_pidfd_open_flags(PID, THREAD, Ok(readable()))
        .on_pidfs_ino(PID, Ok(Some(100)));
    assert!(matches!(open_verified_error_with(&kernel, id(100)), Ok(None)));
}

/// A `poll` of a `PIDFD_THREAD` pidfd that reports `POLLERR` has no errno to carry: it is `Io`
/// naming `poll`, not a thread that leads no group and not gone. A pipe's write end with no reader
/// reports `POLLERR`. The `poll` that fails with an errno cannot be stated: the kernel's rows answer
/// the opens and the inode read, and the `poll` is of the descriptor they return.
#[skuld::test]
fn a_poll_that_reports_pollerr_is_io_naming_poll() {
    let (reader, writer) = std::io::pipe().expect("a pipe");
    drop(reader);
    let kernel = FakeKernel::new()
        .on_pidfd_open_flags(PID, PidfdFlags::empty(), Err(Errno::INVAL))
        .on_pidfd_open_flags(PID, THREAD, Ok(writer.into()))
        .on_pidfs_ino(PID, Ok(Some(100)));
    let result = open_verified_error_with(&kernel, id(100));
    assert!(
        matches!(&result, Err(Error::Io(e)) if e.to_string().starts_with("poll: ")),
        "{result:?}"
    );
}

/// A refusal is `Unsupported`; anything else the open fails with stays `Io`. The group's resend
/// reaches neither (it is `Reached::Unknown` for both) and does not fall back to a send by number.
#[skuld::test]
fn a_refused_open_is_unsupported_and_a_transient_one_is_io() {
    for errno in [Errno::PERM, Errno::NOSYS, Errno::ACCESS, Errno::NODEV] {
        let result = open_verified_error_with(&refusing(errno), id(100));
        assert!(matches!(result, Err(Error::Unsupported { .. })), "{errno}: {result:?}");
    }
    for errno in [Errno::MFILE, Errno::NFILE, Errno::NOMEM] {
        let result = open_verified_error_with(&refusing(errno), id(100));
        assert!(matches!(result, Err(Error::Io(_))), "{errno}: {result:?}");
    }
}

#[skuld::test]
fn a_pidfd_whose_inode_cannot_be_read_is_io() {
    let (fd, _writer) = unreadable();
    let kernel = FakeKernel::new()
        .on_pidfd_open(PID, Ok(fd))
        .on_pidfs_ino(PID, Err(Errno::BADF));
    let result = open_verified_error_with(&kernel, id(100));
    assert!(
        matches!(&result, Err(Error::Io(e)) if e.to_string().starts_with("pidfs_ino: ")),
        "{result:?}"
    );
}

/// An inode read the OS refuses is the read's failure, `Io` naming it with the raw errno, not a
/// refusal of `pidfd_open`. Mutant: "the refusal rule ignores the call".
#[skuld::test]
fn a_refused_inode_read_is_io_not_unsupported() {
    for errno in [Errno::PERM, Errno::NOSYS, Errno::ACCESS, Errno::NODEV] {
        let (fd, _writer) = unreadable();
        let kernel = FakeKernel::new()
            .on_pidfd_open(PID, Ok(fd))
            .on_pidfs_ino(PID, Err(errno));
        let result = open_verified_error_with(&kernel, id(100));
        let Err(Error::Io(e)) = &result else {
            panic!("{errno}: {result:?}");
        };
        let raw = e
            .get_ref()
            .and_then(|context| context.source())
            .and_then(|source| source.downcast_ref::<std::io::Error>())
            .and_then(std::io::Error::raw_os_error);
        assert!(e.to_string().starts_with("pidfs_ino: "), "{errno}: {e}");
        assert_eq!(raw, Some(errno.raw_os_error()), "{errno}");
    }
}

/// A live child opens on its inode; once reaped the id opens to nothing.
#[skuld::test]
fn a_real_child_opens_by_its_inode_and_is_none_once_reaped(#[fixture(pidfd_group_signal)] _group: &Group) {
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

    let held = open_verified_error_with(&HostKernel, id).expect("a live process opens");
    assert!(held.is_some(), "a live child opens");
    drop(held);

    child.kill().expect("kill the child");
    child.wait().expect("reap the child");
    assert!(matches!(open_verified_error_with(&HostKernel, id), Ok(None)));
}
