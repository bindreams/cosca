//! The `communicate` rows that hold on every platform; the ones that need a Unix shell are in
//! `pump_tests.rs`.

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

/// The input is closed the moment its last byte is written, not when the output ends: a child that
/// prints only after it has seen the end of its input still gets that end while `communicate` is
/// draining.
///
/// Mutant: stdin's end is held open until the pump finishes.
#[skuld::test]
fn the_input_is_closed_once_it_is_written() {
    let mut child = shell("cat", "sort");
    let out = child.communicate(Some(b"b\nb\n")).expect("communicate");
    assert!(out.status.success());
    assert_eq!(out.stdout, b"b\nb\n");
}
