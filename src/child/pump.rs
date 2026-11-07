//! Deadlock-free `communicate`: stdin is fed while stdout and stderr are drained, all on the calling
//! thread, so no full pipe buffer wedges the child and nothing after the spawn needs a thread.
//!
//! The merging of results is written once, here, with the state of the three streams. Each platform
//! supplies how its pipe ends are made ready to be served (`Pump::new`) and the loop that moves the
//! bytes (`Pump::run`): `poll` on Unix, overlapped operations on Windows.

use std::io;

use crate::child::Child;
use crate::error::Error;
use crate::pipe::{PipeReader, PipeWriter};
use crate::stdio::Fd;
use crate::Output;

#[cfg(windows)]
#[path = "pump/overlapped.rs"]
mod overlapped;
#[cfg(unix)]
#[path = "pump/poll.rs"]
mod poll;

/// How many bytes one read or write moves.
const CHUNK: usize = 64 * 1024;

/// The error of `communicate` given input with no stdin to take it to. Nothing has been taken yet.
pub(crate) fn input_without_stdin() -> Error {
    Error::Io(io::Error::new(
        io::ErrorKind::InvalidInput,
        "communicate was given input, but the child's stdin is not piped or was already taken",
    ))
}

pub(crate) fn communicate(child: &mut Child, input: Option<&[u8]>) -> Result<Output, Error> {
    let stdin = child.take_stdin_writer();
    if input.is_some() && stdin.is_none() {
        return Err(input_without_stdin());
    }
    let stdout = child.take_reader(Fd::STDOUT);
    let stderr = child.take_reader(Fd::STDERR);

    let mut pump = Pump::new(stdin, input.unwrap_or(&[]), stdout, stderr);
    let pump_error = pump.run().err();
    // Every pipe end is closed from here on: the child sees EOF, or a broken pipe.
    let finished = pump.finish();

    merge(child.wait(), pump_error, finished)
}

/// The first failure is returned: the wait's, else the pump's, else stdout's, stderr's or stdin's,
/// in that order. The others are logged, each with its stream named.
fn merge(
    status: Result<std::process::ExitStatus, Error>,
    pump_error: Option<io::Error>,
    Finished { stdin, stdout, stderr }: Finished,
) -> Result<Output, Error> {
    let mut failures: Vec<(&str, io::Error)> = Vec::new();
    failures.extend(pump_error.map(|e| ("pump", e)));
    let stdout = stdout.unwrap_or_else(|e| {
        failures.push(("stdout", e));
        Vec::new()
    });
    let stderr = stderr.unwrap_or_else(|e| {
        failures.push(("stderr", e));
        Vec::new()
    });
    failures.extend(stdin.err().map(|e| ("stdin", e)));
    let mut failures = failures.into_iter();
    let result = match status {
        Err(e) => Err(e),
        Ok(status) => match failures.next() {
            Some((_, e)) => Err(Error::Io(e)),
            None => Ok(status),
        },
    };
    match result {
        Ok(status) => Ok(Output { status, stdout, stderr }),
        Err(first) => {
            for (stream, e) in failures {
                log::debug!("communicate: the {stream} error was not returned: {e}");
            }
            Err(first)
        }
    }
}

/// The three streams of one `communicate`, each present while it is still open. `W` and `R` are the
/// platform's write and read ends.
struct Pump<'a, W, R> {
    feed: Option<Feed<'a, W>>,
    stdin_error: Option<io::Error>,
    stdout: Drain<R>,
    stderr: Drain<R>,
}

/// Input not yet written, and the pipe it goes to.
struct Feed<'a, W> {
    pipe: W,
    rest: &'a [u8],
}

// A pending write reads `rest`, and the pipe's drop cancels it. This empty `Drop` (no
// `#[may_dangle]`) makes the borrow checker require the input to be live at that drop.
impl<W> Drop for Feed<'_, W> {
    fn drop(&mut self) {}
}

/// A pipe read to EOF, and what came out of it.
struct Drain<R> {
    pipe: Option<R>,
    collected: Collected,
}

/// What one output stream yielded so far.
struct Collected {
    bytes: Vec<u8>,
    error: Option<io::Error>,
}

struct Finished {
    stdin: io::Result<()>,
    stdout: io::Result<Vec<u8>>,
    stderr: io::Result<Vec<u8>>,
}

#[derive(Clone, Copy)]
enum Slot {
    Stdin,
    Stdout,
    Stderr,
}

impl<'a, W, R> Pump<'a, W, R> {
    /// An end that cannot be made ready is closed and its stream fails.
    fn assemble(
        stdin: Option<PipeWriter>,
        input: &'a [u8],
        stdout: Option<PipeReader>,
        stderr: Option<PipeReader>,
        open_writer: impl FnOnce(PipeWriter) -> io::Result<W>,
        open_reader: impl Fn(PipeReader) -> io::Result<R>,
    ) -> Self {
        let mut stdin_error = None;
        // With no input, closing the pipe at once is the child's EOF.
        let feed = stdin.filter(|_| !input.is_empty()).and_then(|pipe| {
            open_writer(pipe)
                .map(|pipe| Feed { pipe, rest: input })
                .map_err(|e| stdin_error = Some(e))
                .ok()
        });
        Pump {
            feed,
            stdin_error,
            stdout: Drain::open(stdout, &open_reader),
            stderr: Drain::open(stderr, &open_reader),
        }
    }

    /// Takes the result of one write of the input: the bytes written. The end closes with the last
    /// of the input, so the child sees EOF then.
    fn wrote(&mut self, written: io::Result<usize>) {
        let Some(feed) = &mut self.feed else { return };
        match written {
            Ok(n) => {
                feed.rest = &feed.rest[n..];
                if feed.rest.is_empty() {
                    self.feed = None;
                }
            }
            // The child stopped reading: end of input, as Python's `subprocess.communicate` treats it.
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => self.feed = None,
            Err(e) => {
                self.stdin_error = Some(e);
                self.feed = None;
            }
        }
    }

    fn finish(self) -> Finished {
        Finished {
            stdin: self.stdin_error.map_or(Ok(()), Err),
            stdout: self.stdout.collected.finish(),
            stderr: self.stderr.collected.finish(),
        }
    }
}

impl<R> Drain<R> {
    fn open(pipe: Option<PipeReader>, open_reader: impl Fn(PipeReader) -> io::Result<R>) -> Self {
        let mut error = None;
        let pipe = pipe.and_then(|pipe| open_reader(pipe).map_err(|e| error = Some(e)).ok());
        Drain {
            pipe,
            collected: Collected {
                bytes: Vec::new(),
                error,
            },
        }
    }
}

impl Collected {
    /// Takes the result of one read: the bytes read, held in `chunk`. Whether the stream is still
    /// open: `Ok(0)` is its EOF (the caller maps the platform's own EOF to it), and an error ends it.
    fn took(&mut self, read: io::Result<usize>, chunk: &[u8]) -> bool {
        match read {
            Ok(0) => false,
            Ok(n) => {
                self.bytes.extend_from_slice(&chunk[..n]);
                true
            }
            Err(e) => {
                self.error = Some(e);
                false
            }
        }
    }

    fn finish(self) -> io::Result<Vec<u8>> {
        self.error.map_or(Ok(self.bytes), Err)
    }
}

#[cfg(test)]
#[path = "pump_common_tests.rs"]
mod pump_common_tests;
#[cfg(all(test, unix))]
#[path = "pump_tests.rs"]
mod pump_tests;
