//! How the testbin writes to its stdout and stderr: a parent that closed its read end has hung up,
//! which is a normal end for the mode, never a panic.
//!
//! Only a write or flush that fails with `BrokenPipe` is quiet. Every other error, and any read
//! error (a `BrokenPipe` from a read included), panics with a message naming the operation.

#![allow(
    dead_code,
    unused_macros,
    reason = "shared by several binaries, each of which uses some of it"
)]

use std::io::{self, Read, Write};

/// Whether `result` delivered: `true` for `Ok`, `false` for a broken pipe (the reader is gone).
/// Any other error panics, naming `op`.
fn delivered(result: io::Result<()>, op: &str) -> bool {
    match result {
        Ok(()) => true,
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => false,
        Err(e) => panic!("{op}: {e}"),
    }
}

/// Write `bytes` to `w` and flush; `false` once the reader is gone. Flushing matters: stdout is
/// line-buffered, so bytes with no trailing newline would otherwise wait for process exit.
pub fn put(w: &mut impl Write, bytes: &[u8], op: &str) -> bool {
    delivered(w.write_all(bytes).and_then(|()| w.flush()), op)
}

/// [`put`] to this process's stdout.
pub fn put_stdout(bytes: &[u8], op: &str) -> bool {
    put(&mut io::stdout().lock(), bytes, op)
}

/// Run `body` on `w`, then flush; `false` once the reader is gone. The target of [`out!`],
/// [`outln!`] and [`errln!`].
pub fn with<W: Write>(w: &mut W, op: &str, body: impl FnOnce(&mut W) -> io::Result<()>) -> bool {
    delivered(body(w).and_then(|()| w.flush()), op)
}

/// Copy `r` to `w` until EOF or until the reader of `w` is gone. A read error panics, naming
/// `read_op`; an interrupted read is retried.
pub fn copy(r: &mut impl Read, w: &mut impl Write, read_op: &str, write_op: &str) {
    let mut buf = [0u8; 8192];
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("{read_op}: {e}"),
        };
        if !put(w, &buf[..n], write_op) {
            return;
        }
    }
}

/// `print!` to stdout, quiet on a broken pipe.
macro_rules! out {
    ($($t:tt)*) => {{
        $crate::quiet_io::with(&mut ::std::io::stdout().lock(), "write stdout", |w| {
            ::std::io::Write::write_fmt(w, format_args!($($t)*))
        });
    }};
}

/// `println!` to stdout, quiet on a broken pipe.
macro_rules! outln {
    ($($t:tt)*) => {{
        $crate::quiet_io::with(&mut ::std::io::stdout().lock(), "write stdout", |w| {
            ::std::io::Write::write_fmt(w, format_args!($($t)*))?;
            ::std::io::Write::write_all(w, b"\n")
        });
    }};
}

/// `eprintln!` to stderr, quiet on a broken pipe.
macro_rules! errln {
    ($($t:tt)*) => {{
        $crate::quiet_io::with(&mut ::std::io::stderr().lock(), "write stderr", |w| {
            ::std::io::Write::write_fmt(w, format_args!($($t)*))?;
            ::std::io::Write::write_all(w, b"\n")
        });
    }};
}
