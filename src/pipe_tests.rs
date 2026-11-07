//! Tests for [`PipeReader`] and [`PipeWriter`] over a pipe made the way a spawn makes one: our end is
//! the type under test, the other end a plain [`File`] the test holds.

use std::fs::File;
use std::io::{Read, Write};

use super::{PipeReader, PipeWriter};
use crate::pipe::ParentEnd;
use crate::stdio::Direction;

const MIB: usize = 1024 * 1024;

/// Byte `i` of the stream every test sends: a period coprime to every power of two, so a chunk that
/// lost or repeated bytes cannot sum to the right total by accident.
fn pattern(i: usize) -> u8 {
    (i % 251) as u8
}

/// A pipe as a spawn makes one, which on macOS is under `spawn_lock`.
fn pipe(dir: Direction) -> (impl Into<File>, ParentEnd) {
    #[cfg(target_os = "macos")]
    let _lock = crate::child::spawn::spawn_lock();
    super::child_pipe(dir).expect("make the pipe")
}

/// A pipe whose reading end is ours and whose writing end is `File`.
fn reader_pair() -> (PipeReader, File) {
    let (theirs, ours) = pipe(Direction::Out);
    let ParentEnd::Reader(ours) = ours else {
        panic!("an Out pipe keeps the read end")
    };
    (ours, theirs.into())
}

/// A pipe whose writing end is ours and whose reading end is `File`.
fn writer_pair() -> (PipeWriter, File) {
    let (theirs, ours) = pipe(Direction::In);
    let ParentEnd::Writer(ours) = ours else {
        panic!("an In pipe keeps the write end")
    };
    (ours, theirs.into())
}

/// Read `from` to its end, in chunks of at most 4096 bytes. Each chunk must continue the pattern
/// from some offset, which is what a torn or doubled read would break.
fn chunks(mut from: impl Read) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = from.read(&mut buf).expect("read");
        if n == 0 {
            return out;
        }
        out.push(buf[..n].to_vec());
    }
}

fn is_contiguous(chunk: &[u8]) -> bool {
    chunk.windows(2).all(|w| w[1] == ((w[0] as u16 + 1) % 251) as u8)
}

fn sum(bytes: impl IntoIterator<Item = u8>) -> u64 {
    bytes.into_iter().map(u64::from).sum()
}

/// Whether `a` and `b`, the chunks two threads read, each thread's in the order it read them,
/// interleave into the pattern from byte 0 with no gap and no overlap. `tiled[i][j]` holds if the
/// first `i` chunks of `a` and the first `j` of `b` tile the stream up to their total length.
fn tile_the_stream(a: &[Vec<u8>], b: &[Vec<u8>]) -> bool {
    let continues_at = |chunk: &[u8], at: usize| chunk.iter().enumerate().all(|(i, &byte)| byte == pattern(at + i));
    let prefix = |chunks: &[Vec<u8>]| {
        let mut lens = vec![0];
        for chunk in chunks {
            lens.push(lens.last().expect("starts with 0") + chunk.len());
        }
        lens
    };
    let (len_a, len_b) = (prefix(a), prefix(b));
    let mut tiled = vec![vec![false; b.len() + 1]; a.len() + 1];
    tiled[0][0] = true;
    for i in 0..=a.len() {
        for j in 0..=b.len() {
            if !tiled[i][j] {
                continue;
            }
            let at = len_a[i] + len_b[j];
            if i < a.len() && continues_at(&a[i], at) {
                tiled[i + 1][j] = true;
            }
            if j < b.len() && continues_at(&b[j], at) {
                tiled[i][j + 1] = true;
            }
        }
    }
    tiled[a.len()][b.len()]
}

#[skuld::test]
fn two_threads_read_one_end_without_abort() {
    for _ in 0..20 {
        let (reader, mut theirs) = reader_pair();
        let sent: Vec<u8> = (0..MIB).map(pattern).collect();
        // One thread reads through a shared reference, the other through a clone.
        let clone = reader.try_clone().expect("clone");
        let (a, b) = std::thread::scope(|scope| {
            scope.spawn(|| {
                theirs.write_all(&sent).expect("send");
                drop(theirs);
            });
            let a = scope.spawn(|| chunks(&reader));
            let b = scope.spawn(|| chunks(&clone));
            (a.join().expect("reader a"), b.join().expect("reader b"))
        });
        assert_eq!(a.iter().chain(&b).map(Vec::len).sum::<usize>(), MIB);
        assert!(
            tile_the_stream(&a, &b),
            "the chunks do not tile the stream: a gap, an overlap or a torn chunk"
        );
    }
}

/// A clone reads the same stream as its original: what one took, the other does not see again.
/// (Which thread reads what in the two-thread row is the scheduler's; this pins the clone itself.)
#[skuld::test]
fn a_clone_reads_on_where_its_original_stopped() {
    let (reader, mut theirs) = reader_pair();
    let clone = reader.try_clone().expect("clone");
    theirs.write_all(b"ab").expect("send");
    drop(theirs);
    let mut first = [0; 1];
    (&reader).read_exact(&mut first).expect("the original reads");
    let mut rest = Vec::new();
    (&clone).read_to_end(&mut rest).expect("the clone reads");
    assert_eq!((&first[..], &rest[..]), (&b"a"[..], &b"b"[..]));
}

#[skuld::test]
fn two_threads_write_one_end_without_abort() {
    for _ in 0..20 {
        let (writer, theirs) = writer_pair();
        // One thread writes through a shared reference, the other through a clone. Each owns its
        // end, so the stream ends when both are done.
        let clone = writer.try_clone().expect("clone");
        let shared = std::sync::Arc::new(writer);
        let each: Vec<u8> = (0..2 * MIB).map(pattern).collect();
        let drained = std::thread::scope(|scope| {
            let drain = scope.spawn(|| chunks(theirs));
            let each = &each;
            scope.spawn(move || (&*shared).write_all(each).expect("write a"));
            scope.spawn(move || (&clone).write_all(each).expect("write b"));
            drain.join().expect("drain")
        });
        let each_sum = sum((0..2 * MIB).map(pattern));
        assert_eq!(drained.iter().map(|c| c.len()).sum::<usize>(), 4 * MIB);
        assert_eq!(sum(drained.iter().flat_map(|c| c.iter().copied())), 2 * each_sum);
    }
}

/// More than the pipe holds, so the write cannot finish before the drain has taken most of it.
#[skuld::test]
fn a_write_to_a_full_pipe_completes() {
    let (mut writer, theirs) = writer_pair();
    let sent: Vec<u8> = (0..4 * MIB).map(pattern).collect();
    let drained = std::thread::scope(|scope| {
        let drain = scope.spawn(|| chunks(theirs));
        writer.write_all(&sent).expect("write");
        drop(writer);
        drain.join().expect("drain")
    });
    assert_eq!(drained.iter().map(|c| c.len()).sum::<usize>(), sent.len());
    assert!(drained.iter().all(|c| is_contiguous(c)));
    assert_eq!(sum(drained.iter().flat_map(|c| c.iter().copied())), sum(sent));
}

/// A std pipe end, which on Windows is a synchronous handle, goes through the same type.
#[skuld::test]
fn a_std_pipe_end_round_trips() {
    let (r, w) = std::io::pipe().expect("make the pipe");
    let (mut r, mut w) = (PipeReader::from(r), PipeWriter::from(w));
    w.write_all(b"through").expect("write");
    drop(w);
    let mut got = Vec::new();
    r.read_to_end(&mut got).expect("read to the end");
    assert_eq!(got, b"through");
}

#[skuld::test]
fn a_read_at_eof_is_zero() {
    let (mut reader, theirs) = reader_pair();
    drop(theirs);
    let mut buf = [0u8; 16];
    assert_eq!(reader.read(&mut buf).expect("first read"), 0);
    assert_eq!(reader.read(&mut buf).expect("read again"), 0);
}

/// The other end is open and idle, so a zero-length read that waited for data would never return.
#[skuld::test]
fn a_zero_length_read_returns_zero_at_once() {
    let (mut reader, _theirs) = reader_pair();
    assert_eq!(reader.read(&mut []).expect("zero-length read"), 0);
    assert_eq!((&reader).read(&mut []).expect("shared zero-length read"), 0);
}

/// Nobody reads, so a zero-length write that waited for a reader would never return.
#[skuld::test]
fn a_zero_length_write_returns_zero_at_once() {
    let (mut writer, _theirs) = writer_pair();
    assert_eq!(writer.write(&[]).expect("zero-length write"), 0);
    assert_eq!((&writer).write(&[]).expect("shared zero-length write"), 0);
}

#[skuld::test]
fn a_write_after_the_reader_left_is_broken_pipe() {
    let (mut writer, theirs) = writer_pair();
    drop(theirs);
    let e = writer.write(b"x").expect_err("nobody reads");
    assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
}

/// The async half takes an end the sync type already read from: the sync I/O associates nothing
/// with a completion port, so tokio's registration succeeds.
#[cfg(all(windows, feature = "tokio"))]
#[skuld::test]
async fn tokio_adopts_an_end_the_sync_type_used() {
    use std::os::windows::io::{IntoRawHandle, OwnedHandle};
    use tokio::io::AsyncReadExt;
    use tokio::net::windows::named_pipe::NamedPipeServer;

    let (mut reader, mut theirs) = reader_pair();
    let sent: Vec<u8> = (0..200_000).map(pattern).collect();
    // More than the pipe holds, so it is written from a thread that ends when the stream does.
    let sender = std::thread::spawn({
        let sent = sent.clone();
        move || theirs.write_all(&sent).expect("send")
    });
    let mut head = [0u8; 100];
    reader.read_exact(&mut head).expect("sync read");
    assert_eq!(head[..], sent[..100]);

    let handle = OwnedHandle::from(reader).into_raw_handle();
    // SAFETY: the handle is the one `reader` owned, handed over whole.
    let mut server = unsafe { NamedPipeServer::from_raw_handle(handle) }.expect("tokio takes the end");
    let mut rest = Vec::new();
    server.read_to_end(&mut rest).await.expect("async read to the end");
    assert_eq!(rest[..], sent[100..]);
    assert_eq!(server.read(&mut head).await.expect("read at EOF"), 0);
    sender.join().expect("sender");
}

/// A clone of an end a completion port is associated with shares the association, so a synchronous
/// read through the other clone would queue a packet pointing at the read's own stack frame unless
/// its `OVERLAPPED` opts out. Tokio's reactor is such a port; this test makes its own, and looks at
/// it directly.
///
/// Mutant: `overlapped_io` stores the event handle in `hEvent` without its low bit.
#[cfg(windows)]
#[skuld::test]
fn a_sync_read_on_a_clone_of_an_associated_end_queues_nothing() {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

    use windows::Win32::Foundation::{HANDLE, WAIT_TIMEOUT};
    use windows::Win32::System::Pipes::PeekNamedPipe;
    use windows::Win32::System::IO::{CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED};

    let (reader, mut theirs) = reader_pair();
    let associated = reader.try_clone().expect("clone");

    // SAFETY: no file handle and no existing port: makes a new port, which the guard closes.
    let port = unsafe { CreateIoCompletionPort(HANDLE(-1isize as *mut _), None, 0, 0) }.expect("make the port");
    // SAFETY: `port` is new and ours alone.
    let port = unsafe { OwnedHandle::from_raw_handle(port.0) };
    // SAFETY: both handles are live; the end is overlapped and associated with no other port.
    unsafe {
        CreateIoCompletionPort(
            HANDLE(associated.as_raw_handle()),
            Some(HANDLE(port.as_raw_handle())),
            0,
            0,
        )
    }
    .expect("associate the clone with the port");

    theirs.write_all(b"sync").expect("send");
    // The bytes are in the pipe before the read starts, so `ReadFile` completes synchronously, and
    // any packet it queued was queued before it returned: the zero-timeout poll below cannot miss
    // one that is still on its way.
    let mut available = 0u32;
    // SAFETY: the handle is live; only the available-byte count is asked for.
    unsafe {
        PeekNamedPipe(
            HANDLE(reader.as_raw_handle()),
            None,
            0,
            None,
            Some(&mut available),
            None,
        )
    }
    .expect("peek the pipe");
    assert_eq!(available, 4, "the read would not complete synchronously");
    let mut got = [0u8; 4];
    (&reader)
        .read_exact(&mut got)
        .expect("sync read through the other clone");
    assert_eq!(&got, b"sync");

    let (mut bytes, mut key, mut overlapped) = (0u32, 0usize, std::ptr::null_mut::<OVERLAPPED>());
    // SAFETY: the out-pointers are to live locals; a zero timeout polls.
    let status =
        unsafe { GetQueuedCompletionStatus(HANDLE(port.as_raw_handle()), &mut bytes, &mut key, &mut overlapped, 0) };
    let e = status.expect_err("the port holds no packet");
    assert!(
        overlapped.is_null() && e.code() == windows::core::HRESULT::from_win32(WAIT_TIMEOUT.0),
        "a packet was queued for the sync read: {e}"
    );
}

/// An end taken out as a raw descriptor and wrapped again, as std's own pipe ends allow.
#[cfg(unix)]
#[skuld::test]
fn a_pipe_end_round_trips_through_a_raw_fd() {
    use std::os::fd::{FromRawFd, IntoRawFd};

    let (reader, mut theirs) = reader_pair();
    let fd = reader.into_raw_fd();
    // SAFETY: `fd` is the descriptor `reader` owned, handed over whole.
    let mut reader = unsafe { PipeReader::from_raw_fd(fd) };
    theirs.write_all(b"raw").expect("send");
    drop(theirs);
    let mut got = Vec::new();
    reader.read_to_end(&mut got).expect("read to the end");
    assert_eq!(got, b"raw");
}
