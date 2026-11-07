//! The `communicate` rows that hold on every platform. `pump_tests.rs` holds the Unix-only ones:
//! those about signals and `RLIMIT_NPROC`, which Windows does not have.

use std::io;

use super::{merge, Finished, Pump};
use crate::error::Error;
use crate::pipe::{PipeReader, PipeWriter};
use crate::stdio::Fd;
use crate::test_child::Console;
use crate::test_pattern::pattern_bytes;
use crate::Stdio;

/// A `cosca_testbin` child running `mode`, with all three standard streams piped.
fn testbin_child(mode: &[&str]) -> crate::Child {
    let mut c = crate::test_child::command(Console::Hidden);
    // `args` is the whole argv, program name included.
    c.executable(crate::test_child::testbin("cosca_testbin"))
        .args(["cosca_testbin"])
        .args(mode.iter().copied());
    c.stdin(Stdio::pipe()).expect("stdin");
    c.stdout(Stdio::pipe()).expect("stdout");
    c.stderr(Stdio::pipe()).expect("stderr");
    c.spawn().expect("spawn")
}

/// A child running `unix` under `/bin/sh -c` or `windows` under `cmd /C`, with all three standard
/// streams piped.
pub(super) fn shell(unix: &str, windows: &str) -> crate::Child {
    let mut c = crate::test_child::command(Console::Hidden);
    if cfg!(windows) {
        c.args(["cmd", "/C", windows]);
    } else {
        c.args(["/bin/sh", "-c", unix]);
    }
    c.stdin(Stdio::pipe()).expect("stdin");
    c.stdout(Stdio::pipe()).expect("stdout");
    c.stderr(Stdio::pipe()).expect("stderr");
    c.spawn().expect("spawn")
}

/// A child that exits without reading its input ends the input: `communicate` returns what it
/// printed, not an error. The input is larger than a pipe buffer, so the write is still in progress
/// when the child exits.
///
/// Mutant: a broken pipe on stdin is an `Err`.
#[skuld::test]
fn a_child_that_stops_reading_stdin_ends_the_input() {
    let mut child = shell("echo out; exit 3", "echo out& exit 3");
    let input = vec![b'x'; 1 << 20];
    let out = child.communicate(Some(&input)).expect("communicate");
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(out.stdout, if cfg!(windows) { &b"out\r\n"[..] } else { &b"out\n"[..] });
}

/// `path` as text for a command line that does not quote it, refused if the shell (`cmd` on Windows,
/// `sh` elsewhere) would read part of it as syntax.
fn unquotable(path: &std::path::Path) -> String {
    let path = path.display().to_string();
    let syntax: &[char] = if cfg!(windows) {
        &['"', '%', '!', '&', '|', '<', '>', '(', ')', '^', ',', ';', '=']
    } else {
        &[
            '"', '\'', '\\', '$', '`', '&', '|', ';', '<', '>', '(', ')', '*', '?', '[', ']', '{', '}',
        ]
    };
    assert!(
        !path.contains(|c: char| c.is_whitespace() || syntax.contains(&c)),
        "the temp path {path} has whitespace or a character the shell reads as syntax: set TMPDIR (TEMP on Windows) to a path that has not"
    );
    path
}

/// Each output stream is read while the other is idle: a child that fills stderr past a pipe
/// buffer before it writes stdout, and the reverse, both finish.
///
/// Mutant: stdout is read to EOF before stderr is read at all, or the reverse.
#[skuld::test]
fn each_stream_is_read_while_the_other_is_idle() {
    // `cmd` cannot make output of a size, so both shells print a file of that size. The path cannot
    // be quoted in the command: the spawn escapes a `"` in an argument as `\"`, which `cmd` does not
    // read. So the path must hold nothing the shell treats as syntax.
    let dir = tempfile::tempdir().expect("tempdir");
    let big = dir.path().join("big");
    let expected = pattern_bytes(1_000_000);
    std::fs::write(&big, &expected).expect("write the file");
    let big = unquotable(&big);
    for (unix, windows) in [
        (
            format!("cat {big} >&2; cat {big}"),
            format!("type {big} 1>&2& type {big}"),
        ),
        (
            format!("cat {big}; cat {big} >&2"),
            format!("type {big}& type {big} 1>&2"),
        ),
    ] {
        let mut child = shell(&unix, &windows);
        let out = child.communicate(None).expect("communicate");
        assert!(out.status.success(), "{unix}");
        assert!(out.stdout == expected, "stdout, {unix}");
        assert!(out.stderr == expected, "stderr, {unix}");
    }
}

/// A piped stdin that gets no input, or an empty one, is closed at once: the child sees EOF.
///
/// Mutant: the stdin pipe is held open until the child exits.
#[skuld::test]
fn no_input_closes_stdin() {
    for input in [None, Some(&[][..])] {
        let mut child = shell("cat", "sort");
        let out = child.communicate(input).expect("communicate");
        assert!(out.status.success(), "{input:?}");
        assert!(out.stdout.is_empty(), "{input:?}");
    }
}

/// Input for a child whose stdin is not piped is an `InvalidInput` error, and the streams that are
/// piped are left in place for the next call.
///
/// Mutant: the bytes are dropped and `communicate` returns `Ok`.
#[skuld::test]
fn input_without_a_piped_stdin_is_invalid_input() {
    let mut c = crate::test_child::command(Console::Hidden);
    if cfg!(windows) {
        c.args(["cmd", "/C", "echo out"]);
    } else {
        c.args(["/bin/sh", "-c", "echo out"]);
    }
    c.stdin(Stdio::null()).expect("stdin");
    c.stdout(Stdio::pipe()).expect("stdout");
    let mut child = c.spawn().expect("spawn");
    let error = child.communicate(Some(b"x")).expect_err("input has nowhere to go");
    assert!(
        matches!(&error, crate::error::Error::Io(e) if e.kind() == std::io::ErrorKind::InvalidInput),
        "{error:?}"
    );
    let out = child.communicate(None).expect("the pipes were not taken");
    assert_eq!(out.stdout, if cfg!(windows) { &b"out\r\n"[..] } else { &b"out\n"[..] });
}

/// A child that closes its stdin ends the input but not the output: everything it goes on to
/// print is still collected, though input was left unwritten.
///
/// Mutant: a broken pipe on stdin ends the draining of stdout and stderr (the child then hangs
/// on a full pipe, or the output is cut short).
#[skuld::test]
fn a_child_that_closes_stdin_is_still_drained() {
    let mut child = testbin_child(&["close-std", "stdin", "1000000"]);
    let input = pattern_bytes(1 << 20);
    let out = child.communicate(Some(&input)).expect("communicate");
    assert!(out.status.success());
    assert!(out.stdout == pattern_bytes(1_000_000), "stdout");
    assert!(out.stderr.is_empty());
}

/// A stream that reaches EOF early does not end the others: a child that closes stdout and keeps
/// writing stderr has all of it collected.
///
/// Mutant: the first EOF ends the loop, so the rest of stderr is lost.
#[skuld::test]
fn a_stream_at_eof_does_not_end_the_others() {
    let mut child = testbin_child(&["close-std", "stdout", "1000000"]);
    let out = child.communicate(None).expect("communicate");
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
    assert!(out.stderr == pattern_bytes(1_000_000), "stderr");
}

/// A grandchild that inherited stdout and outlives the child keeps `communicate` waiting until it
/// closes it: everything it prints is collected. The grandchild prints only once its stdin, whose
/// only writer is the child, reaches EOF, so after the child has exited and after its own line.
///
/// Mutant: `communicate` returns once the child has exited.
#[skuld::test]
fn a_grandchild_holding_stdout_keeps_communicate_waiting() {
    let mut child = testbin_child(&["print-then-leave-grandchild"]);
    let out = child.communicate(None).expect("communicate");
    assert!(out.status.success());
    assert_eq!(out.stdout, b"early\nlate\n");
}

// Errors of the shared merge =====
//
// `Pump::assemble` takes the platform's way of making an end ready as closures, and the state the
// platform's loop feeds (`wrote`, `Collected::took`) is shared, so these rows run the merge with
// closures of their own and no loop.

/// A child's three ends, and the child, which must outlive them being closed.
fn ends() -> (crate::Child, Option<PipeWriter>, Option<PipeReader>, Option<PipeReader>) {
    let mut child = shell("cat", "sort");
    let stdin = child.take_stdin_writer();
    let stdout = child.take_reader(Fd::STDOUT);
    let stderr = child.take_reader(Fd::STDERR);
    (child, stdin, stdout, stderr)
}

fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "refused")
}

fn kind<T>(result: io::Result<T>) -> Option<io::ErrorKind> {
    result.err().map(|e| e.kind())
}

/// An end that cannot be made ready fails its own stream and no other, whichever of stdout and
/// stderr it is.
///
/// Mutant: the failure of one end is dropped, or reported on the other stream.
#[skuld::test]
fn an_end_that_cannot_be_made_ready_fails_only_its_stream() {
    let (_child, stdin, stdout, _stderr) = ends();
    let finished = Pump::<(), ()>::assemble(stdin, &[], stdout, None, |_| Ok(()), |_| Err(refused())).finish();
    assert_eq!(kind(finished.stdout), Some(io::ErrorKind::PermissionDenied));
    assert!(finished.stderr.expect("stderr was not opened").is_empty());
    assert!(finished.stdin.is_ok());

    let (_child, stdin, _stdout, stderr) = ends();
    let finished = Pump::<(), ()>::assemble(stdin, &[], None, stderr, |_| Ok(()), |_| Err(refused())).finish();
    assert_eq!(kind(finished.stderr), Some(io::ErrorKind::PermissionDenied));
    assert!(finished.stdout.expect("stdout was not opened").is_empty());
    assert!(finished.stdin.is_ok());
}

/// An stdin end that cannot be made ready fails the stdin stream, and the input is not written.
///
/// Mutant: the failure is dropped, so the call reports the input as delivered.
#[skuld::test]
fn a_stdin_that_cannot_be_made_ready_fails_the_stdin_stream() {
    let (_child, stdin, stdout, stderr) = ends();
    let pump = Pump::<(), ()>::assemble(stdin, b"input", stdout, stderr, |_| Err(refused()), |_| Ok(()));
    assert!(pump.feed.is_none());
    let finished = pump.finish();
    assert_eq!(kind(finished.stdin), Some(io::ErrorKind::PermissionDenied));
    assert!(finished.stdout.is_ok() && finished.stderr.is_ok());
}

/// An end whose reads fail, for the stdout of a pump, and the stdin end the child keeps: Unix, a
/// directory (`read` is `EISDIR`); Windows, the child's own stdin writer, which `ReadFile` refuses
/// as access denied.
fn unreadable(stdin: Option<PipeWriter>) -> (Option<PipeWriter>, PipeReader) {
    #[cfg(unix)]
    {
        let dir = std::fs::File::open(std::env::temp_dir()).expect("open a directory");
        (stdin, PipeReader::from(std::os::fd::OwnedFd::from(dir)))
    }
    #[cfg(windows)]
    {
        let writer = stdin.expect("the child's stdin");
        (None, PipeReader::from(std::os::windows::io::OwnedHandle::from(writer)))
    }
}

/// The loop of the platform's pump ends a stream whose read fails and fails that stream alone: the
/// other stream's bytes are all collected.
///
/// Mutant: the loop reads a failed read as the stream's EOF, drops the error, or stops the loop.
#[skuld::test]
fn a_read_the_loop_gets_an_error_from_fails_its_stream_and_keeps_the_others_bytes() {
    let mut child = shell("echo keep >&2", "echo keep>&2");
    let (stdin, bad) = unreadable(child.take_stdin_writer());
    let mut pump = Pump::new(stdin, &[], Some(bad), child.take_reader(Fd::STDERR));
    pump.run().expect("a read error does not fail the loop");
    let finished = pump.finish();
    assert!(finished.stdout.is_err(), "stdout's read error is its own");
    assert_eq!(
        finished.stderr.expect("stderr"),
        if cfg!(windows) {
            &b"keep\r\n"[..]
        } else {
            &b"keep\n"[..]
        }
    );
    child.wait().expect("wait");
}

/// A read error on a stream ends and fails that stream, and the bytes of the other stay. This row
/// pins `Collected::took`, the bookkeeping both platforms' loops share;
/// the row above reaches the loop's own handling.
///
/// Mutant: a read error on one stream discards the other's bytes, or is read as its EOF.
#[skuld::test]
fn a_read_error_fails_its_stream_and_keeps_the_others_bytes() {
    let reset = || io::Error::from(io::ErrorKind::ConnectionReset);

    let (_child, stdin, stdout, stderr) = ends();
    let mut pump = Pump::<(), ()>::assemble(stdin, &[], stdout, stderr, |_| Ok(()), |_| Ok(()));
    assert!(pump.stderr.collected.took(Ok(3), b"abc"));
    assert!(!pump.stdout.collected.took(Err(reset()), &[]));
    let finished = pump.finish();
    assert_eq!(kind(finished.stdout), Some(io::ErrorKind::ConnectionReset));
    assert_eq!(finished.stderr.expect("stderr"), b"abc");

    let (_child, stdin, stdout, stderr) = ends();
    let mut pump = Pump::<(), ()>::assemble(stdin, &[], stdout, stderr, |_| Ok(()), |_| Ok(()));
    assert!(pump.stdout.collected.took(Ok(3), b"abc"));
    assert!(!pump.stderr.collected.took(Err(reset()), &[]));
    let finished = pump.finish();
    assert_eq!(kind(finished.stderr), Some(io::ErrorKind::ConnectionReset));
    assert_eq!(finished.stdout.expect("stdout"), b"abc");
}

// Precedence of the merge -----

fn exit_zero() -> std::process::ExitStatus {
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    #[cfg(windows)]
    use std::os::windows::process::ExitStatusExt;
    std::process::ExitStatus::from_raw(0)
}

fn finished(stdin: io::Result<()>, stdout: io::Result<Vec<u8>>, stderr: io::Result<Vec<u8>>) -> Finished {
    Finished { stdin, stdout, stderr }
}

fn failed(kind: io::ErrorKind) -> io::Error {
    io::Error::from(kind)
}

fn merged_kind(
    status: Result<std::process::ExitStatus, Error>,
    pump: Option<io::Error>,
    finished: Finished,
) -> Option<io::ErrorKind> {
    match merge(status, pump, finished) {
        Err(Error::Io(e)) => Some(e.kind()),
        Err(other) => panic!("not an I/O error: {other:?}"),
        Ok(_) => None,
    }
}

/// With several failures the first is returned, in the order wait, pump, stdout, stderr, stdin.
/// Each is the one returned when every later one is present too.
///
/// Mutant: any two of the five swapped, or the wait's error returned after a stream's.
#[skuld::test]
fn the_first_failure_is_returned_in_the_documented_order() {
    use io::ErrorKind::{BrokenPipe, ConnectionReset, NotFound, PermissionDenied, TimedOut, Unsupported};
    let all = || {
        finished(
            Err(failed(Unsupported)),
            Err(failed(PermissionDenied)),
            Err(failed(NotFound)),
        )
    };
    let wait = || Err(Error::Io(failed(TimedOut)));
    assert_eq!(merged_kind(wait(), Some(failed(BrokenPipe)), all()), Some(TimedOut));
    assert_eq!(
        merged_kind(Ok(exit_zero()), Some(failed(BrokenPipe)), all()),
        Some(BrokenPipe)
    );
    assert_eq!(merged_kind(Ok(exit_zero()), None, all()), Some(PermissionDenied));
    let no_stdout = finished(Err(failed(Unsupported)), Ok(Vec::new()), Err(failed(NotFound)));
    assert_eq!(merged_kind(Ok(exit_zero()), None, no_stdout), Some(NotFound));
    let only_stdin = finished(Err(failed(ConnectionReset)), Ok(Vec::new()), Ok(Vec::new()));
    assert_eq!(merged_kind(Ok(exit_zero()), None, only_stdin), Some(ConnectionReset));
}

/// A failure of a stream is returned even when the child exited successfully, and no failure
/// leaves the bytes of both streams in the `Output`.
///
/// Mutant: a stream's failure is dropped when the wait succeeds, or the bytes are not returned.
#[skuld::test]
fn a_stream_failure_after_a_successful_exit_is_returned_and_none_returns_the_bytes() {
    let failing = finished(Ok(()), Ok(b"out".to_vec()), Err(failed(io::ErrorKind::NotFound)));
    assert_eq!(
        merged_kind(Ok(exit_zero()), None, failing),
        Some(io::ErrorKind::NotFound)
    );

    let out = merge(
        Ok(exit_zero()),
        None,
        finished(Ok(()), Ok(b"out".to_vec()), Ok(b"err".to_vec())),
    )
    .expect("nothing failed");
    assert!(out.status.success());
    assert_eq!((out.stdout, out.stderr), (b"out".to_vec(), b"err".to_vec()));
}

/// A write error on stdin that is not a broken pipe fails the stdin stream and ends the input; a
/// broken pipe only ends it.
///
/// Mutant: any write error is an end of input, or a broken pipe fails the stream.
#[skuld::test]
fn only_a_broken_pipe_is_a_benign_end_of_stdin() {
    let (_child, stdin, stdout, stderr) = ends();
    let mut pump = Pump::<(), ()>::assemble(stdin, b"input", stdout, stderr, |_| Ok(()), |_| Ok(()));
    assert!(pump.feed.is_some());
    pump.wrote(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
    assert!(pump.feed.is_none());
    assert!(pump.finish().stdin.is_ok());

    let (_child, stdin, stdout, stderr) = ends();
    let mut pump = Pump::<(), ()>::assemble(stdin, b"input", stdout, stderr, |_| Ok(()), |_| Ok(()));
    pump.wrote(Err(refused()));
    assert!(pump.feed.is_none());
    assert_eq!(kind(pump.finish().stdin), Some(io::ErrorKind::PermissionDenied));
}
