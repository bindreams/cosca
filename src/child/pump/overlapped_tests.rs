use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::os::windows::io::AsHandle;

use windows::Win32::System::Threading::{WaitForSingleObject, INFINITE};

use super::{Drain, Op};
use crate::pipe::windows::child_pipe;
use crate::pipe::ParentEnd;
use crate::stdio::Direction;
use crate::{PipeReader, PipeWriter};

/// The pipe a child reads: our writer in an `Op`, and the child's end as a file.
fn writer_pipe() -> (Op<PipeWriter>, File) {
    let (theirs, ours) = child_pipe(Direction::In).expect("pipe");
    let ParentEnd::Writer(ours) = ours else {
        unreachable!("an In pipe has a writer")
    };
    (Op::new(ours).expect("op"), File::from(theirs))
}

/// The pipe a child writes: our reader in an `Op`, and the child's end as a file.
fn reader_pipe() -> (Op<PipeReader>, File) {
    let (theirs, ours) = child_pipe(Direction::Out).expect("pipe");
    let ParentEnd::Reader(ours) = ours else {
        unreachable!("an Out pipe has a reader")
    };
    (Op::new(ours).expect("op"), File::from(theirs))
}

/// Waits for the operation's event, which the test has arranged to fire.
fn wait_for<E: AsHandle>(op: &Op<E>) {
    // SAFETY: the event is the operation's own, live for the call.
    let waited = unsafe { WaitForSingleObject(op.event(), INFINITE) };
    assert_eq!(waited.0, 0, "the wait for the operation's event");
}

/// A read completes with the bytes the child wrote, in the operation's own buffer.
///
/// Mutant: the byte count of a completed read is not the one `GetOverlappedResult` reports.
#[skuld::test]
fn a_read_completes_with_the_bytes_the_child_wrote() {
    let (mut op, mut theirs) = reader_pipe();
    op.start_read().expect("start");
    theirs.write_all(b"hello").expect("write");
    wait_for(&op);
    let moved = op.complete().expect("complete");
    assert_eq!(&op.buffer()[..moved], b"hello");
}

/// A write completes with the number of bytes the child can read.
///
/// Mutant: a write reports the length asked for, not the length moved.
#[skuld::test]
fn a_write_completes_with_its_byte_count() {
    let (mut op, mut theirs) = writer_pipe();
    // SAFETY: a literal outlives the operation.
    unsafe { op.start_write(b"abc") }.expect("start");
    wait_for(&op);
    assert_eq!(op.complete().expect("complete"), 3);
    let mut got = [0u8; 3];
    theirs.read_exact(&mut got).expect("read");
    assert_eq!(&got, b"abc");
}

/// A read that succeeds with no bytes is not the end of the stream: only `ERROR_BROKEN_PIPE` is. The
/// stream stays open and the next read collects what the child wrote.
///
/// A zero-length `ReadFile` on a pipe completes with success and 0 bytes once data arrives; no child
/// can cause one (a 0-byte `WriteFile` to a byte-mode pipe wakes no reader, measured on Windows 11
/// 26100), so the row starts one itself.
///
/// Mutant: a successful empty read ends the stream.
#[skuld::test]
fn an_empty_read_is_not_the_end_of_the_stream() {
    let (theirs, ours) = child_pipe(Direction::Out).expect("pipe");
    let ParentEnd::Reader(ours) = ours else {
        unreachable!("an Out pipe has a reader")
    };
    let mut theirs = File::from(theirs);
    let mut drain = Drain::open(Some(ours), Op::new);

    let op = drain.pipe.as_mut().expect("open");
    let handle = op.handle();
    // SAFETY: the empty buffer needs no storage; the end is the op's own.
    unsafe { op.operation.read(handle, &mut []) }.expect("start");
    theirs.write_all(b"x").expect("write");
    wait_for(op);
    drain.complete();
    assert!(drain.pipe.is_some(), "an empty read ended the stream");

    drain.issue();
    wait_for(drain.pipe.as_ref().expect("open"));
    drain.complete();
    assert_eq!(drain.collected.finish().expect("no error"), b"x");
}

/// An operation dropped while its read is pending is cancelled and waited out before its buffer is
/// freed: the drop returns, the process lives, and our end is closed (the child's write now fails).
///
/// Mutant: the drop does not cancel, so it waits for data that never comes; or it frees the buffer
/// with the read still in the kernel's hands.
#[skuld::test]
fn a_pending_read_dropped_is_cancelled_and_its_end_closed() {
    let (mut op, mut theirs) = reader_pipe();
    op.start_read().expect("start");
    drop(op);
    let error = theirs.write(b"x").expect_err("our end is closed");
    assert_eq!(error.kind(), ErrorKind::BrokenPipe);
}

/// The same for a pending write: the write is larger than the pipe's buffer, so it is still in
/// progress when the operation is dropped.
///
/// Mutant: as for the read.
#[skuld::test]
fn a_pending_write_dropped_is_cancelled_and_its_end_closed() {
    let (mut op, mut theirs) = writer_pipe();
    let bytes = vec![0u8; 1 << 20];
    // SAFETY: `bytes` outlives the operation, which the drop below ends.
    unsafe { op.start_write(&bytes) }.expect("start");
    drop(op);
    // Our end is closed: the child reads what the pipe held, then the end of the stream.
    let mut got = Vec::new();
    theirs.read_to_end(&mut got).expect("read to the end");
    assert!(got.len() < 1 << 20, "the write did not complete");
}
