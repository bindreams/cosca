//! Finding a re-exec'd test's readiness marker in its stdout.

use std::io::{BufRead as _, BufReader, Read};

/// Whether `stream` carries `marker` before it ends, wherever on a line it sits: a child run with
/// `--nocapture` and a single libtest thread (`--test-threads=1`, or one CPU) has already printed
/// `test <name> ... ` on the line its first output lands on.
///
/// Reads until the marker, so a caller that keeps the child's stdin open must pass `&mut` to keep
/// the pipe open as well: libtest in the child reports after the body and fails if it cannot.
/// A read error panics rather than reading as "no marker".
pub fn marker_seen(stream: impl Read, marker: &str) -> bool {
    BufReader::new(stream).split(b'\n').any(|line| {
        line.expect("read the child's stdout")
            .windows(marker.len())
            .any(|w| w == marker.as_bytes())
    })
}
