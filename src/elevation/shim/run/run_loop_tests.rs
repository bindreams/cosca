use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

use super::{drain_control, drained, Drained};
use crate::child::spawn::fork_exec::{Failure, Progress, RefusalKind, SpawnError, StepFailure};
use crate::elevation::shim::protocol::{Errno, NotExecuted, Signal};
use crate::elevation::shim::run::child::{died_before_exec, not_spawned};
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

/// Nothing yet, and a ready record, leave the `exec` pending.
///
/// Mutant: a ready record is taken for the `exec`.
#[skuld::test]
fn nothing_and_a_ready_record_say_nothing_yet() {
    let (log, _, _keep) = captured_log();
    assert!(matches!(drained(Ok(Progress::Pending), &log), Drained::Nothing));
    assert!(matches!(drained(Ok(Progress::Ready), &log), Drained::Nothing));
}

/// Each failure of the child is the report of its kind, and the channel's end is the `exec`.
///
/// Mutants: a kind is reported as another; an end that followed a ready record, or did not, is a report.
#[skuld::test]
fn a_failure_is_the_report_of_its_kind_and_the_end_is_eof() {
    let (log, _, _keep) = captured_log();
    let report = |failure| match drained(Ok(Progress::Failed(failure)), &log) {
        Drained::Report(report) => report,
        _ => panic!("a report for {failure:?}"),
    };
    assert_eq!(
        report(Failure::Exec(libc::ENOENT)),
        NotExecuted::ExecFailed(Errno(libc::ENOENT))
    );
    assert_eq!(
        report(Failure::Step(StepFailure {
            kind: 3,
            value: libc::EACCES as u16
        })),
        NotExecuted::SetupFailed(Errno(libc::EACCES))
    );
    assert_eq!(
        report(Failure::Step(StepFailure {
            kind: 4,
            value: libc::SIGTERM as u16
        })),
        NotExecuted::TerminatedBeforeExec(Signal(libc::SIGTERM))
    );
    assert!(matches!(
        drained(Ok(Progress::Ended { ready: true }), &log),
        Drained::Eof
    ));
}

/// A channel that ended with no ready record means the child died inside its steps and no `execve`
/// ran, which is not the `exec`.
///
/// Mutant: an end without a ready record is the `exec`.
#[skuld::test]
fn an_end_with_no_ready_record_is_the_child_dying_before_exec() {
    let (log, _, _keep) = captured_log();
    assert!(matches!(
        drained(Ok(Progress::Ended { ready: false }), &log),
        Drained::Died
    ));
}

/// The report of a child that died before its ready record: the signal it died of, and `EIO` when the
/// wait status names none.
///
/// Mutant: the signal is dropped, or a plain exit is taken for a signal.
#[skuld::test]
fn a_child_that_died_before_exec_is_reported_by_how_it_died() {
    assert_eq!(
        died_before_exec(Some(libc::SIGSEGV)),
        NotExecuted::TerminatedBeforeExec(Signal(libc::SIGSEGV))
    );
    // A core dump sets bit 7 of the status.
    assert_eq!(
        died_before_exec(Some(libc::SIGSEGV | 0x80)),
        NotExecuted::TerminatedBeforeExec(Signal(libc::SIGSEGV))
    );
    for status in [Some(119 << 8), None] {
        assert_eq!(died_before_exec(status), NotExecuted::SetupFailed(Errno(libc::EIO)));
    }
}

/// Each way the core makes no child is its own report: a clone refused on both paths is the
/// `Unsupported` of principle 4, not a fork failure, and an exhausted descriptor table is a setup
/// failure with the pipe's errno.
///
/// Mutants: `Unsupported` is reported as `ForkFailed`; `Pipe` as `ForkFailed`.
#[skuld::test]
fn a_spawn_that_made_no_child_reports_its_own_cause() {
    let (unsupported, what, errno) = not_spawned(SpawnError::Unsupported(RefusalKind::Eperm));
    assert_eq!(unsupported, NotExecuted::Unsupported(Errno(libc::EPERM)));
    assert_eq!(
        (what, errno),
        ("the kernel cannot make a child with a pidfd", libc::EPERM)
    );
    assert_eq!(
        not_spawned(SpawnError::Fork(libc::EAGAIN)).0,
        NotExecuted::ForkFailed(Errno(libc::EAGAIN))
    );
    assert_eq!(
        not_spawned(SpawnError::Pipe(libc::EMFILE)).0,
        NotExecuted::SetupFailed(Errno(libc::EMFILE))
    );
}

#[skuld::test]
fn a_status_read_error_is_logged_and_says_nothing() {
    let (log, lines, _keep) = captured_log();
    let failed = std::io::Error::from_raw_os_error(libc::EBADF);
    assert!(matches!(drained(Err(failed), &log), Drained::Nothing));
    let text = logged(&lines);
    assert!(text.contains("reading the status pipe"), "{text:?}");
}

/// A step failure whose kind the shim never gives its child is the channel being wrong, not a report
/// of some kind: it is logged, and says nothing.
///
/// Mutant: it is reported as an exec failure with `EIO`.
#[skuld::test]
fn a_step_failure_of_no_kind_is_logged_and_says_nothing() {
    let (log, lines, _keep) = captured_log();
    let unknown = Failure::Step(StepFailure { kind: 9, value: 1 });
    assert!(matches!(drained(Ok(Progress::Failed(unknown)), &log), Drained::Nothing));
    let text = logged(&lines);
    assert!(text.contains("no kind names"), "{text:?}");
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
