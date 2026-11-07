//! A parent pipe end that tokio refuses to register makes each taker return `None` and warn, and
//! drops the end so its peer observes the close. Unix: an end of the wrong direction. Windows: an
//! overlapped end that a completion port already holds (the registration fails with os error 87),
//! which fails in debug and release alike; a synchronous end, which `adopt` forbids, would trip its
//! debug assertion instead. Each test keys its log assertion on an fd number no other test uses,
//! so a concurrent test's warn cannot satisfy it. Each test holds `spawn_lock` for its whole body
//! for Unix's sake: a concurrent fork would otherwise inherit the pipe ends and keep them open
//! past the drop. Windows ends are created non-inheritable, so the lock is unneeded there.

use std::io::{ErrorKind, Read, Write};

use crate::containment::Containment;
use crate::identity::ProcessId;
use crate::pipe::ParentEnd;
use crate::stdio::Fd;

use super::{Child, OsResources};

/// A `Child` with no process, built as a struct literal (not through `spawn`) so the tests need no
/// child; its `Drop` returns at once (`kill_on_drop: false`, nothing attached).
fn a_child_without_a_process() -> Child {
    Child {
        os: OsResources::default(),
        id: Some(ProcessId::from_parts_for_test(1, crate::identity::Key::for_test(0))),
        kill_on_drop: false,
        containment: Containment::None,
        tree_killed: Default::default(),
        graceful: crate::graceful::GracefulMechanism::Process,
        elevation: None,
        front: None,
        #[cfg(unix)]
        reported: Vec::new(),
    }
}

/// What proves a refused end closed: run after the taker returned.
type Closed = Box<dyn FnOnce()>;

/// A parent `Reader` that tokio refuses, and the check that its peer saw it close.
///
/// Unix: planted over a pipe's WRITE end, which tokio's `Receiver` rejects (not readable); the
/// pipe's read end sees EOF.
#[cfg(unix)]
fn refused_reader() -> (ParentEnd, Closed) {
    use std::os::fd::OwnedFd;

    let (peer, write) = std::io::pipe().expect("pipe");
    nonblocking(&peer);
    (
        ParentEnd::Reader(crate::PipeReader::from(OwnedFd::from(write))),
        Box::new(move || assert_read_peer_saw_eof(peer)),
    )
}

/// A parent `Writer` that tokio refuses, and the check that its peer saw it close.
///
/// Unix: planted over a pipe's READ end, which tokio's `Sender` rejects (not writable); the pipe's
/// write end sees EPIPE.
#[cfg(unix)]
fn refused_writer() -> (ParentEnd, Closed) {
    use std::os::fd::OwnedFd;

    let (read, peer) = std::io::pipe().expect("pipe");
    nonblocking(&peer);
    (
        ParentEnd::Writer(crate::PipeWriter::from(OwnedFd::from(read))),
        Box::new(move || assert_write_peer_saw_epipe(peer)),
    )
}

#[cfg(unix)]
fn nonblocking(fd: &impl std::os::fd::AsFd) {
    let flags = rustix::fs::fcntl_getfl(fd).expect("F_GETFL");
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK).expect("F_SETFL");
}

/// A child pipe of the spawn's own kind whose parent end a completion port already holds: tokio's
/// registration of it fails with os error 87. Returns the parent end, the child's end (`File`), and
/// the port, which must outlive the taker call.
#[cfg(windows)]
fn associated_pipe(dir: crate::stdio::Direction) -> (ParentEnd, std::fs::File, std::os::windows::io::OwnedHandle) {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::IO::CreateIoCompletionPort;

    let (theirs, ours) = crate::pipe::child_pipe(dir).expect("make the pipe");
    let handle = ours.as_raw_handle();
    // SAFETY: no file handle and no existing port: makes a new port, which the guard closes.
    let port = unsafe { CreateIoCompletionPort(HANDLE(-1isize as *mut _), None, 0, 0) }.expect("make the port");
    // SAFETY: `port` is new and ours alone.
    let port = unsafe { OwnedHandle::from_raw_handle(port.0) };
    // SAFETY: both handles are live; the end is overlapped and associated with no other port.
    unsafe { CreateIoCompletionPort(HANDLE(handle), Some(HANDLE(port.as_raw_handle())), 0, 0) }
        .expect("associate the end with the port");
    (ours, std::fs::File::from(theirs), port)
}

/// Windows: a parent `Reader` the port holds; the child's write end sees a broken pipe.
#[cfg(windows)]
fn refused_reader() -> (ParentEnd, Closed) {
    let (ours, peer, port) = associated_pipe(crate::stdio::Direction::Out);
    (
        ours,
        Box::new(move || {
            assert_write_peer_saw_epipe(peer);
            drop(port);
        }),
    )
}

/// Windows: a parent `Writer` the port holds; the child's read end sees EOF.
#[cfg(windows)]
fn refused_writer() -> (ParentEnd, Closed) {
    let (ours, peer, port) = associated_pipe(crate::stdio::Direction::In);
    (
        ours,
        Box::new(move || {
            assert_read_peer_saw_eof(peer);
            drop(port);
        }),
    )
}

/// The one warn the failed conversion logged: `prefix` is where the record must START, so a
/// doubled `fd fd N` cannot match.
fn assert_one_warn_starting_with(mark: usize, marker: &str, prefix: &str) {
    assert_eq!(
        crate::log_capture::levels_since(mark, marker),
        [log::Level::Warn],
        "a failed conversion must be logged once, at warn"
    );
    let records = crate::log_capture::records_since(mark, marker);
    assert!(
        records[0].starts_with(prefix),
        "malformed warn record: {:?}",
        records[0]
    );
}

fn assert_read_peer_saw_eof(mut peer: impl Read) {
    let n = peer
        .read(&mut [0u8; 1])
        .expect("a closed write end reads as EOF, not an error");
    assert_eq!(n, 0, "the failed end must have been closed");
}

fn assert_write_peer_saw_epipe(mut peer: impl Write) {
    let err = peer.write(&[0u8]).expect_err("a closed read end must fail the write");
    assert_eq!(
        err.kind(),
        ErrorKind::BrokenPipe,
        "the failed end must have been closed"
    );
}

#[skuld::test]
async fn fd_read_end_warns_returns_none_and_closes_the_end_on_a_failed_conversion() {
    crate::tokio::test_runtime::assert_current_thread();
    let _no_fork = crate::child::spawn::spawn_lock();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let mut child = a_child_without_a_process();
    let (end, closed) = refused_reader();
    child.os.pipes.insert(Fd::from(91), end);
    assert!(child.fd_read_end(91).is_none());
    assert_one_warn_starting_with(mark, "fd 91 read end dropped", "fd 91 read end dropped");
    assert!(
        !child.os.pipes.contains_key(&Fd::from(91)),
        "the failed end must leave the map"
    );
    closed();
}

#[skuld::test]
async fn fd_write_end_warns_returns_none_and_closes_the_end_on_a_failed_conversion() {
    crate::tokio::test_runtime::assert_current_thread();
    let _no_fork = crate::child::spawn::spawn_lock();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let mut child = a_child_without_a_process();
    let (end, closed) = refused_writer();
    child.os.pipes.insert(Fd::from(92), end);
    assert!(child.fd_write_end(92).is_none());
    assert_one_warn_starting_with(mark, "fd 92 write end dropped", "fd 92 write end dropped");
    assert!(
        !child.os.pipes.contains_key(&Fd::from(92)),
        "the failed end must leave the map"
    );
    closed();
}

#[skuld::test]
async fn take_owned_out_warns_returns_none_and_closes_the_end_on_a_failed_conversion() {
    crate::tokio::test_runtime::assert_current_thread();
    let _no_fork = crate::child::spawn::spawn_lock();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let mut child = a_child_without_a_process();
    let (end, closed) = refused_reader();
    child.os.owned_std.insert(Fd::from(93), end);
    assert!(child.take_owned_out(Fd::from(93)).is_none());
    assert_one_warn_starting_with(
        mark,
        "fd 93 merge-target read end dropped",
        "fd 93 merge-target read end dropped",
    );
    assert!(
        !child.os.owned_std.contains_key(&Fd::from(93)),
        "the failed end must leave the map"
    );
    closed();
}

#[skuld::test]
async fn take_owned_in_warns_returns_none_and_closes_the_end_on_a_failed_conversion() {
    crate::tokio::test_runtime::assert_current_thread();
    let _no_fork = crate::child::spawn::spawn_lock();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let mut child = a_child_without_a_process();
    let (end, closed) = refused_writer();
    child.os.owned_std.insert(Fd::from(94), end);
    assert!(child.take_owned_in(Fd::from(94)).is_none());
    assert_one_warn_starting_with(
        mark,
        "fd 94 merge-target write end dropped",
        "fd 94 merge-target write end dropped",
    );
    assert!(
        !child.os.owned_std.contains_key(&Fd::from(94)),
        "the failed end must leave the map"
    );
    closed();
}
