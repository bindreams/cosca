//! The `communicate` rows that hold on every platform. `pump_tests.rs` holds the Unix-only ones:
//! a child that closes its own stdin or stdout (`cmd` cannot close a standard handle), and the ones
//! about signals, `RLIMIT_NPROC`, FIFOs and process groups, which Windows does not have.

use crate::test_child::Console;
use crate::Stdio;

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

/// Each output stream is read while the other is idle: a child that fills stderr past a pipe
/// buffer before it writes stdout, and the reverse, both finish.
///
/// Mutant: stdout is read to EOF before stderr is read at all, or the reverse.
#[skuld::test]
fn each_stream_is_read_while_the_other_is_idle() {
    // `cmd` cannot make output of a size, so it prints a file of that size. The path has no space
    // or quote, which `cmd` would not read as the spawn quotes them.
    let dir = tempfile::tempdir().expect("tempdir");
    let big = dir.path().join("big");
    std::fs::write(&big, vec![b'x'; 1_000_000]).expect("write the file");
    let big = big.display().to_string();
    assert!(
        !big.contains([' ', '"']),
        "the temp path {big} has a space or quote: set TEMP to one that has not"
    );
    for (unix, windows) in [
        (
            "head -c 1000000 /dev/zero >&2; head -c 1000000 /dev/zero".to_owned(),
            format!("type {big} 1>&2& type {big}"),
        ),
        (
            "head -c 1000000 /dev/zero; head -c 1000000 /dev/zero >&2".to_owned(),
            format!("type {big}& type {big} 1>&2"),
        ),
    ] {
        let mut child = shell(&unix, &windows);
        let out = child.communicate(None).expect("communicate");
        assert!(out.status.success(), "{unix}");
        assert_eq!(out.stdout.len(), 1_000_000, "{unix}");
        assert_eq!(out.stderr.len(), 1_000_000, "{unix}");
    }
}

/// With a piped stdin and no input, the child sees EOF at once.
///
/// Mutant: the stdin pipe is held open until the child exits.
#[skuld::test]
fn no_input_closes_stdin() {
    let mut child = shell("cat", "sort");
    let out = child.communicate(None).expect("communicate");
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
}
