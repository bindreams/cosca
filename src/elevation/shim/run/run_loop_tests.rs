use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

use super::{drain_control, drain_status, Status};
use crate::elevation::shim::protocol::{Errno, NotExecuted};
use crate::elevation::shim::run::log::Log;
use crate::elevation::shim::step::Control;

/// A pipe, the read end non-blocking.
fn pipe() -> (OwnedFd, OwnedFd) {
    let (reader, writer) = std::io::pipe().unwrap();
    let (reader, writer): (OwnedFd, OwnedFd) = (reader.into(), writer.into());
    let flags = rustix::fs::fcntl_getfl(&reader).unwrap();
    rustix::fs::fcntl_setfl(&reader, flags | rustix::fs::OFlags::NONBLOCK).unwrap();
    (reader, writer)
}

/// A log whose lines can be read back, and the reader of them.
fn captured_log() -> (Log, OwnedFd, OwnedFd) {
    let (reader, writer) = pipe();
    (Log::new(Some(writer.as_raw_fd())), reader, writer)
}

fn logged(reader: &OwnedFd) -> String {
    let mut text = Vec::new();
    let mut buf = [0u8; 256];
    while let Ok(n) = rustix::io::read(reader, &mut buf) {
        if n == 0 {
            break;
        }
        text.extend_from_slice(&buf[..n]);
    }
    String::from_utf8_lossy(&text).into_owned()
}

// The status pipe -----

#[skuld::test]
fn the_status_pipe_says_nothing_until_the_child_writes() {
    let (reader, _writer) = pipe();
    let (log, _, _keep) = captured_log();
    assert!(matches!(drain_status(reader.as_fd(), &log), Status::Nothing));
}

#[skuld::test]
fn a_status_report_is_decoded_and_a_closed_pipe_is_eof() {
    let (reader, writer) = pipe();
    let (log, _, _keep) = captured_log();
    let exec_failed = (2i32 << 16) | libc::ENOENT;
    rustix::io::write(&writer, &exec_failed.to_le_bytes()).unwrap();
    match drain_status(reader.as_fd(), &log) {
        Status::Report(report) => assert_eq!(report, NotExecuted::ExecFailed(Errno(libc::ENOENT))),
        _ => panic!("a report"),
    }
    drop(writer);
    assert!(matches!(drain_status(reader.as_fd(), &log), Status::Eof));
}

#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "a short read of 2 bytes from the status pipe")]
fn a_short_status_read_is_a_bug() {
    let (reader, writer) = pipe();
    let (log, _, _keep) = captured_log();
    rustix::io::write(&writer, &[1, 2]).unwrap();
    drain_status(reader.as_fd(), &log);
}

/// Without `debug_assertions` the short read is logged and says nothing.
#[cfg(not(debug_assertions))]
#[skuld::test]
fn a_short_status_read_is_logged_and_says_nothing() {
    let (reader, writer) = pipe();
    let (log, lines, _keep) = captured_log();
    rustix::io::write(&writer, &[1, 2]).unwrap();
    assert!(matches!(drain_status(reader.as_fd(), &log), Status::Nothing));
    assert!(logged(&lines).contains("a short read of 2 bytes"));
}

#[skuld::test]
fn a_status_read_error_is_logged_and_says_nothing() {
    // Reading a pipe's write end fails with `EBADF`: not `EAGAIN`, so not silence.
    let (_reader, writer) = pipe();
    let (log, lines, _keep) = captured_log();
    assert!(matches!(drain_status(writer.as_fd(), &log), Status::Nothing));
    let text = logged(&lines);
    assert!(
        text.contains(&format!("reading the status pipe: errno {}", libc::EBADF)),
        "{text:?}"
    );
}

// Cosca's connection -----

#[skuld::test]
fn control_bytes_are_read_in_order_and_the_end_of_the_connection_last() {
    let (ours, theirs) = UnixStream::pair().unwrap();
    let (log, _, _keep) = captured_log();
    rustix::io::write(&theirs, b"KD").unwrap();
    assert_eq!(
        drain_control(ours.as_fd(), &log),
        [Control::Byte(b'K'), Control::Byte(b'D')],
        "then nothing more yet"
    );
    drop(theirs);
    assert_eq!(drain_control(ours.as_fd(), &log), [Control::Eof]);
}

#[skuld::test]
fn a_reset_connection_is_the_end_of_it_and_is_not_a_warning() {
    // The peer closes with our bytes unread: our next read is `ECONNRESET`.
    let (ours, theirs) = UnixStream::pair().unwrap();
    let (log, lines, _keep) = captured_log();
    rustix::io::write(&ours, b"x").unwrap();
    drop(theirs);
    assert_eq!(drain_control(ours.as_fd(), &log), [Control::Eof]);
    assert_eq!(logged(&lines), "");
}

#[skuld::test]
fn any_other_receive_error_is_logged_with_its_errno_and_ends_the_connection() {
    // A pipe is not a socket: `ENOTSOCK`, which is neither silence nor a reset.
    let (reader, _writer) = pipe();
    let (log, lines, _keep) = captured_log();
    assert_eq!(drain_control(reader.as_fd(), &log), [Control::Eof]);
    let text = logged(&lines);
    assert!(
        text.contains(&format!("recv from cosca: errno {}", libc::ENOTSOCK)),
        "{text:?}"
    );
}

#[cfg(debug_assertions)]
#[skuld::test]
#[should_panic(expected = "recv on the shim's own connection")]
fn a_receive_on_a_bad_descriptor_is_a_bug() {
    let (log, _, _keep) = captured_log();
    // An `O_PATH` descriptor answers every `recv` with `EBADF`.
    let path = rustix::fs::open(
        "/",
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    drain_control(path.as_fd(), &log);
}

/// Without `debug_assertions` a bad descriptor is logged like any other receive error.
#[cfg(not(debug_assertions))]
#[skuld::test]
fn a_receive_on_a_bad_descriptor_is_logged_and_ends_the_connection() {
    let (log, lines, _keep) = captured_log();
    let path = rustix::fs::open(
        "/",
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    assert_eq!(drain_control(path.as_fd(), &log), [Control::Eof]);
    assert!(logged(&lines).contains(&format!("recv from cosca: errno {}", libc::EBADF)));
}
