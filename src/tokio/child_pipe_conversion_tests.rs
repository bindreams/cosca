//! A parent pipe end that tokio refuses to register (here: a pipe end of the wrong direction)
//! makes each taker return `None` and warn, in debug and release alike, and drops the end so its
//! peer observes the close. Each test keys its log assertion on an fd number no other test uses,
//! so a concurrent test's warn cannot satisfy it. Each test holds `spawn_lock` for its whole body:
//! a concurrent fork would otherwise inherit the pipe ends and keep them open past the drop.

use std::io::{ErrorKind, Read, Write};
use std::os::fd::OwnedFd;

use crate::child::ParentEnd;
use crate::containment::Containment;
use crate::identity::ProcessId;
use crate::stdio::Fd;

use super::{Child, OsResources};

/// A `Child` with no process, built as a struct literal (not through `spawn`) so the tests need no
/// child; its `Drop` returns at once (`kill_on_drop: false`, nothing attached).
fn a_child_without_a_process() -> Child {
    Child {
        os: OsResources::default(),
        id: ProcessId::from_parts_for_test(1, 0),
        kill_on_drop: false,
        containment: Containment::None,
        tree_killed: Default::default(),
        graceful: crate::graceful::GracefulMechanism::Process,
        elevation: None,
        front: None,
        #[cfg(unix)]
        reported: false,
    }
}

fn nonblocking(fd: &impl std::os::fd::AsFd) {
    let flags = rustix::fs::fcntl_getfl(fd).expect("F_GETFL");
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK).expect("F_SETFL");
}

/// `Reader` planted over a pipe's WRITE end: tokio's `Receiver` rejects it (not readable). Returns
/// the end and the pipe's read end, whose EOF proves the planted end closed.
fn reader_over_a_write_end() -> (ParentEnd, std::io::PipeReader) {
    let (peer, write) = std::io::pipe().expect("pipe");
    nonblocking(&peer);
    (ParentEnd::Reader(std::io::PipeReader::from(OwnedFd::from(write))), peer)
}

/// `Writer` planted over a pipe's READ end: tokio's `Sender` rejects it (not writable). Returns
/// the end and the pipe's write end, whose EPIPE proves the planted end closed.
fn writer_over_a_read_end() -> (ParentEnd, std::io::PipeWriter) {
    let (read, peer) = std::io::pipe().expect("pipe");
    nonblocking(&peer);
    (ParentEnd::Writer(std::io::PipeWriter::from(OwnedFd::from(read))), peer)
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

fn assert_read_peer_saw_eof(mut peer: std::io::PipeReader) {
    let n = peer
        .read(&mut [0u8; 1])
        .expect("a closed write end reads as EOF, not an error");
    assert_eq!(n, 0, "the failed end must have been closed");
}

fn assert_write_peer_saw_epipe(mut peer: std::io::PipeWriter) {
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
    let (end, peer) = reader_over_a_write_end();
    child.os.pipes.insert(Fd::from(91), end);
    assert!(child.fd_read_end(91).is_none());
    assert_one_warn_starting_with(mark, "fd 91 read end dropped", "fd 91 read end dropped");
    assert!(
        !child.os.pipes.contains_key(&Fd::from(91)),
        "the failed end must leave the map"
    );
    assert_read_peer_saw_eof(peer);
}

#[skuld::test]
async fn fd_write_end_warns_returns_none_and_closes_the_end_on_a_failed_conversion() {
    crate::tokio::test_runtime::assert_current_thread();
    let _no_fork = crate::child::spawn::spawn_lock();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let mut child = a_child_without_a_process();
    let (end, peer) = writer_over_a_read_end();
    child.os.pipes.insert(Fd::from(92), end);
    assert!(child.fd_write_end(92).is_none());
    assert_one_warn_starting_with(mark, "fd 92 write end dropped", "fd 92 write end dropped");
    assert!(
        !child.os.pipes.contains_key(&Fd::from(92)),
        "the failed end must leave the map"
    );
    assert_write_peer_saw_epipe(peer);
}

#[skuld::test]
async fn take_owned_out_warns_returns_none_and_closes_the_end_on_a_failed_conversion() {
    crate::tokio::test_runtime::assert_current_thread();
    let _no_fork = crate::child::spawn::spawn_lock();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let mut child = a_child_without_a_process();
    let (end, peer) = reader_over_a_write_end();
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
    assert_read_peer_saw_eof(peer);
}

#[skuld::test]
async fn take_owned_in_warns_returns_none_and_closes_the_end_on_a_failed_conversion() {
    crate::tokio::test_runtime::assert_current_thread();
    let _no_fork = crate::child::spawn::spawn_lock();
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let mut child = a_child_without_a_process();
    let (end, peer) = writer_over_a_read_end();
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
    assert_write_peer_saw_epipe(peer);
}
