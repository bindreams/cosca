//! Deadlock-free `communicate`: stdin is fed while stdout and stderr are drained, so no full pipe
//! buffer wedges the child.
//!
//! The merging of results is written once, here, with the state of the three streams. Each platform
//! supplies how its pipe ends are made ready to be served (`Pump::new`) and the loop that moves the
//! bytes (`Pump::run`).

#[cfg(unix)]
use std::io;

#[cfg(unix)]
use crate::child::Child;
#[cfg(unix)]
use crate::error::Error;
#[cfg(unix)]
use crate::pipe::{PipeReader, PipeWriter};
#[cfg(unix)]
use crate::stdio::Fd;
#[cfg(unix)]
use crate::Output;

#[cfg(unix)]
#[path = "pump/poll.rs"]
mod poll;
#[cfg(windows)]
#[path = "pump/threads.rs"]
mod threads;

#[cfg(windows)]
pub(crate) use threads::communicate;

/// How many bytes one read or write moves.
#[cfg(unix)]
const CHUNK: usize = 64 * 1024;

#[cfg(unix)]
pub(crate) fn communicate(child: &mut Child, input: Option<&[u8]>) -> Result<Output, Error> {
    let stdin = child.take_stdin_writer();
    let stdout = child.take_reader(Fd::STDOUT);
    let stderr = child.take_reader(Fd::STDERR);
    // Caller contract: input can only be delivered if stdin was piped; surface the misuse rather
    // than silently dropping the bytes.
    debug_assert!(
        input.is_none() || stdin.is_some(),
        "communicate given input but stdin was not piped"
    );

    let mut pump = Pump::new(stdin, input.unwrap_or(&[]), stdout, stderr);
    let pump_error = pump.run().err();
    // Every pipe end is closed from here on: the child sees EOF, or a broken pipe.
    let Finished { stdin, stdout, stderr } = pump.finish();

    let status = child.wait();
    // The first failure is returned: the wait's, else the pump's, else a stream's. The others are
    // logged, each with its stream named.
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
#[cfg(unix)]
struct Pump<'a, W, R> {
    feed: Option<Feed<'a, W>>,
    stdin_error: Option<io::Error>,
    stdout: Drain<R>,
    stderr: Drain<R>,
}

/// Input not yet written, and the pipe it goes to.
#[cfg(unix)]
struct Feed<'a, W> {
    pipe: W,
    rest: &'a [u8],
}

/// A pipe read to EOF, and what came out of it.
#[cfg(unix)]
struct Drain<R> {
    pipe: Option<R>,
    collected: Collected,
}

/// What one output stream yielded so far.
#[cfg(unix)]
struct Collected {
    bytes: Vec<u8>,
    error: Option<io::Error>,
}

#[cfg(unix)]
struct Finished {
    stdin: io::Result<()>,
    stdout: io::Result<Vec<u8>>,
    stderr: io::Result<Vec<u8>>,
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum Slot {
    Stdin,
    Stdout,
    Stderr,
}

#[cfg(unix)]
impl<'a, W, R> Pump<'a, W, R> {
    /// The pump over the ends `open_writer` and `open_reader` make ready; an end that cannot be made
    /// ready is closed and its stream fails.
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

    /// Takes the result of one write of the input: the bytes written.
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

#[cfg(unix)]
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

#[cfg(unix)]
impl Collected {
    /// Takes the result of one read: the bytes read, held in `chunk`. Whether the stream is still
    /// open: an empty read is its EOF, and an error ends it.
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

#[cfg(all(test, unix))]
#[path = "pump_tests.rs"]
mod pump_tests;
