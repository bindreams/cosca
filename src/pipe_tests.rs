//! Tests for [`PipeReader`] and [`PipeWriter`] over a pipe made the way a spawn makes one: our end is
//! the type under test, the other end a plain [`File`] the test holds.

use std::fs::File;
use std::io::{Read, Write};

use super::{PipeReader, PipeWriter};

const MIB: usize = 1024 * 1024;

/// Byte `i` of the stream every test sends: a period coprime to every power of two, so a chunk that
/// lost or repeated bytes cannot sum to the right total by accident.
fn pattern(i: usize) -> u8 {
    (i % 251) as u8
}

/// A pipe whose reading end is ours and whose writing end is `File`.
fn reader_pair() -> (PipeReader, File) {
    #[cfg(windows)]
    {
        let (ours, theirs) = super::windows::child_pipe(true).expect("make the pipe");
        (PipeReader::from_overlapped(ours), File::from(theirs))
    }
    #[cfg(unix)]
    {
        let (r, w) = std::io::pipe().expect("make the pipe");
        (PipeReader::from(r), File::from(std::os::fd::OwnedFd::from(w)))
    }
}

/// A pipe whose writing end is ours and whose reading end is `File`.
fn writer_pair() -> (PipeWriter, File) {
    #[cfg(windows)]
    {
        let (ours, theirs) = super::windows::child_pipe(false).expect("make the pipe");
        (PipeWriter::from_overlapped(ours), File::from(theirs))
    }
    #[cfg(unix)]
    {
        let (r, w) = std::io::pipe().expect("make the pipe");
        (PipeWriter::from(w), File::from(std::os::fd::OwnedFd::from(r)))
    }
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
        let all: Vec<&Vec<u8>> = a.iter().chain(&b).collect();
        assert!(
            all.iter().all(|c| is_contiguous(c)),
            "a chunk is not a stretch of the stream"
        );
        assert_eq!(all.iter().map(|c| c.len()).sum::<usize>(), MIB);
        assert_eq!(sum(all.iter().flat_map(|c| c.iter().copied())), sum(sent));
    }
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

/// A clone of an end tokio adopted shares its completion port, so a synchronous read through the
/// clone would queue a packet pointing at the read's own stack frame unless its `OVERLAPPED` opts
/// out. The reactor dequeues whatever the port holds on its next turn, so each round ends with an
/// async read that makes it turn: a stray packet crashes the process there.
///
/// Mutant: `overlapped_io` stores the event handle in `hEvent` without its low bit.
#[cfg(all(windows, feature = "tokio"))]
#[skuld::test]
async fn a_sync_read_on_a_clone_tokio_adopted_queues_nothing() {
    use std::os::windows::io::{IntoRawHandle, OwnedHandle};
    use tokio::io::AsyncReadExt;
    use tokio::net::windows::named_pipe::NamedPipeServer;

    for _ in 0..20 {
        let (reader, mut theirs) = reader_pair();
        let clone = reader.try_clone().expect("clone");
        let handle = OwnedHandle::from(reader).into_raw_handle();
        // SAFETY: the handle is the one `reader` owned, handed over whole.
        let mut server = unsafe { NamedPipeServer::from_raw_handle(handle) }.expect("tokio takes the end");

        // Tokio reads ahead into its own buffer from the moment it adopts an end, and keeps one
        // read outstanding until that buffer is taken: this byte fills it, so the bytes after it
        // stay in the pipe for the synchronous read.
        theirs.write_all(b"A").expect("send");
        theirs.write_all(b"sync").expect("send");
        let mut sync = [0u8; 4];
        (&clone).read_exact(&mut sync).expect("sync read through the clone");
        assert_eq!(&sync, b"sync");

        let mut ahead = [0u8; 1];
        server.read_exact(&mut ahead).await.expect("tokio's first read");
        assert_eq!(&ahead, b"A");
        theirs.write_all(b"async").expect("send");
        let mut asynchronous = [0u8; 5];
        server
            .read_exact(&mut asynchronous)
            .await
            .expect("async read through tokio");
        assert_eq!(&asynchronous, b"async");
    }
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

/// A wrapped handle records whether it is overlapped, by asking, whichever way it arrives.
///
/// Mutant: a conversion records `true` without asking.
#[cfg(windows)]
#[skuld::test]
fn a_wrapped_handle_records_whether_it_is_overlapped() {
    use std::os::windows::io::{FromRawHandle, IntoRawHandle, OwnedHandle};

    let (overlapped, _theirs) = super::windows::child_pipe(true).expect("make the pipe");
    let (synchronous, _writer) = std::io::pipe().expect("make a std pipe");
    let synchronous = OwnedHandle::from(synchronous);

    assert!(
        PipeReader::from(overlapped).is_overlapped(),
        "From<OwnedHandle> of an overlapped handle"
    );
    assert!(
        !PipeReader::from(synchronous.try_clone().expect("clone")).is_overlapped(),
        "From<OwnedHandle> of a synchronous handle"
    );
    let (r, w) = std::io::pipe().expect("make a std pipe");
    assert!(!PipeReader::from(r).is_overlapped(), "From<std PipeReader>");
    assert!(!PipeWriter::from(w).is_overlapped(), "From<std PipeWriter>");

    let (overlapped, _theirs) = super::windows::child_pipe(true).expect("make the pipe");
    let raw = PipeReader::from_overlapped(overlapped).into_raw_handle();
    // SAFETY: `raw` is the handle the reader owned, handed over whole.
    let again = unsafe { PipeReader::from_raw_handle(raw) };
    assert!(again.is_overlapped(), "FromRawHandle of an overlapped handle");
    let raw = PipeReader::from(synchronous).into_raw_handle();
    // SAFETY: as above.
    let again = unsafe { PipeReader::from_raw_handle(raw) };
    assert!(!again.is_overlapped(), "FromRawHandle of a synchronous handle");
}
