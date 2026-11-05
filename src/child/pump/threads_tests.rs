use crate::test_child::Console;
use crate::Stdio;

/// A child that exits without reading its input ends the input: `communicate` returns what it
/// printed, not an error. The input is larger than a pipe buffer, so the write is still in progress
/// when the child exits.
///
/// Mutant: a broken pipe on stdin is an `Err`.
#[skuld::test]
fn a_child_that_stops_reading_stdin_ends_the_input() {
    let mut c = crate::test_child::command(Console::Hidden);
    c.args(["cmd", "/C", "echo out& exit 3"]);
    c.stdin(Stdio::pipe()).expect("stdin");
    c.stdout(Stdio::pipe()).expect("stdout");
    let mut child = c.spawn().expect("spawn");
    let input = vec![b'x'; 1 << 20];
    let out = child.communicate(Some(&input)).expect("communicate");
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(out.stdout, b"out\r\n");
}
