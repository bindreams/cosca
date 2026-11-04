//! Unix: stdin, stdout and stderr go through one `poll` loop on the calling thread. No pipe can
//! fill and stall the child, and nothing after the spawn needs a thread, so a caller under a task
//! limit (`RLIMIT_NPROC`, a cgroup's `TasksMax`) cannot fail for want of one.
//!
//! This polls the pipe ends directly, through `wait::poll_ready`, not `os_process::poll`, which
//! asks whether a process has exited.

use std::io::{self, ErrorKind, PipeReader, PipeWriter, Read, Write};
use std::os::fd::AsFd;

use rustix::event::{PollFd, PollFlags};
use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};

use crate::child::Child;
use crate::error::Error;
use crate::stdio::Fd;
use crate::wait;
use crate::Output;

/// Bytes read from a pipe per call.
const CHUNK: usize = 64 * 1024;

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
    let poll_error = pump.run().err();
    // Every pipe end is closed from here on: the child sees EOF, or a broken pipe.
    let Finished { stdin, stdout, stderr } = pump.finish();

    let status = child.wait()?;
    if let Some(error) = poll_error {
        return Err(Error::Io(error));
    }
    let stdout = stdout.map_err(Error::Io)?;
    let stderr = stderr.map_err(Error::Io)?;
    stdin.map_err(Error::Io)?;
    Ok(Output { status, stdout, stderr })
}

/// The three streams of one `communicate`, each present while it is still open.
struct Pump<'a> {
    feed: Option<Feed<'a>>,
    stdin_error: Option<io::Error>,
    stdout: Drain,
    stderr: Drain,
}

/// Input not yet written, and the pipe it goes to.
struct Feed<'a> {
    pipe: PipeWriter,
    rest: &'a [u8],
}

/// A pipe read to EOF, and what came out of it.
struct Drain {
    pipe: Option<PipeReader>,
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

impl<'a> Pump<'a> {
    fn new(stdin: Option<PipeWriter>, input: &'a [u8], stdout: Option<PipeReader>, stderr: Option<PipeReader>) -> Self {
        let mut stdin_error = None;
        // With no input, closing the pipe at once is the child's EOF.
        let feed = stdin.filter(|_| !input.is_empty()).and_then(|pipe| {
            nonblocking(&pipe)
                .map(|()| Feed { pipe, rest: input })
                .map_err(|e| stdin_error = Some(e))
                .ok()
        });
        Pump {
            feed,
            stdin_error,
            stdout: Drain::new(stdout),
            stderr: Drain::new(stderr),
        }
    }

    /// Moves bytes until every stream is closed. Fails only when `poll` does.
    fn run(&mut self) -> io::Result<()> {
        let mut chunk = vec![0u8; CHUNK];
        loop {
            let mut slots = Vec::with_capacity(3);
            let mut fds = Vec::with_capacity(3);
            if let Some(feed) = &self.feed {
                slots.push(Slot::Stdin);
                fds.push(PollFd::new(&feed.pipe, PollFlags::OUT));
            }
            if let Some(pipe) = &self.stdout.pipe {
                slots.push(Slot::Stdout);
                fds.push(PollFd::new(pipe, PollFlags::IN));
            }
            if let Some(pipe) = &self.stderr.pipe {
                slots.push(Slot::Stderr);
                fds.push(PollFd::new(pipe, PollFlags::IN));
            }
            if fds.is_empty() {
                return Ok(());
            }
            wait::poll_ready(&mut fds)?;
            // Any event (readable, writable, hung up, error) is served by trying the operation:
            // it reports EOF or a broken pipe itself.
            let ready: Vec<Slot> = slots
                .iter()
                .zip(&fds)
                .filter(|(_, fd)| !fd.revents().is_empty())
                .map(|(slot, _)| *slot)
                .collect();
            drop(fds);
            for slot in ready {
                match slot {
                    Slot::Stdin => self.write_some(),
                    Slot::Stdout => self.stdout.read_some(&mut chunk),
                    Slot::Stderr => self.stderr.read_some(&mut chunk),
                }
            }
        }
    }

    fn write_some(&mut self) {
        let Some(feed) = &mut self.feed else { return };
        match write_without_sigpipe(&mut feed.pipe, feed.rest) {
            Ok(n) => {
                feed.rest = &feed.rest[n..];
                if feed.rest.is_empty() {
                    self.feed = None;
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
            // The child stopped reading: end of input, as `std::process::Command::output` treats it.
            Err(e) if e.kind() == ErrorKind::BrokenPipe => self.feed = None,
            Err(e) => {
                self.stdin_error = Some(e);
                self.feed = None;
            }
        }
    }

    fn finish(self) -> Finished {
        Finished {
            stdin: self.stdin_error.map_or(Ok(()), Err),
            stdout: self.stdout.finish(),
            stderr: self.stderr.finish(),
        }
    }
}

impl Drain {
    fn new(pipe: Option<PipeReader>) -> Self {
        let mut error = None;
        let pipe = pipe.and_then(|pipe| nonblocking(&pipe).map(|()| pipe).map_err(|e| error = Some(e)).ok());
        Drain {
            pipe,
            bytes: Vec::new(),
            error,
        }
    }

    fn read_some(&mut self, chunk: &mut [u8]) {
        let Some(pipe) = &mut self.pipe else { return };
        match pipe.read(chunk) {
            Ok(0) => self.pipe = None,
            Ok(n) => self.bytes.extend_from_slice(&chunk[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
            Err(e) => {
                self.error = Some(e);
                self.pipe = None;
            }
        }
    }

    fn finish(self) -> io::Result<Vec<u8>> {
        self.error.map_or(Ok(self.bytes), Err)
    }
}

/// Sets `O_NONBLOCK` on the pipe's own open file description. The child holds the other end of the
/// pipe, a different description, so it is unaffected.
fn nonblocking(pipe: &impl AsFd) -> io::Result<()> {
    let flags = fcntl_getfl(pipe)?;
    fcntl_setfl(pipe, flags | OFlags::NONBLOCK)?;
    Ok(())
}

/// One `write` that cannot kill the host. Writing to a pipe nobody reads raises `SIGPIPE` on the
/// calling thread, and a host that left its disposition at the default dies of it (a C host, a
/// cdylib, `-Zon-broken-pipe=kill`); Rust's runtime ignores it, but a library cannot rely on that.
/// `SIGPIPE` is blocked on this thread around the write; the one the write raised is consumed, and
/// one already pending (the host's own) is left for the host.
fn write_without_sigpipe(pipe: &mut PipeWriter, bytes: &[u8]) -> io::Result<usize> {
    // SAFETY: plain signal-mask calls on a set initialised by `sigemptyset`, restoring the mask
    // before returning. `sigwait` runs only when `SIGPIPE` is pending and blocked here, so it
    // returns at once.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGPIPE);
        let mut old: libc::sigset_t = std::mem::zeroed();
        let blocked = libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old);
        debug_assert_eq!(blocked, 0, "block SIGPIPE");
        let was_pending = sigpipe_pending();
        let written = pipe.write(bytes);
        if matches!(&written, Err(e) if e.kind() == ErrorKind::BrokenPipe) && !was_pending && sigpipe_pending() {
            let mut signo = 0;
            let waited = libc::sigwait(&set, &mut signo);
            debug_assert_eq!(waited, 0, "consume SIGPIPE");
        }
        let restored = libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
        debug_assert_eq!(restored, 0, "restore the signal mask");
        written
    }
}

/// Whether `SIGPIPE` is pending for the calling thread or the process.
fn sigpipe_pending() -> bool {
    // SAFETY: `sigpending` fills a zeroed set the call owns; `sigismember` only reads it.
    unsafe {
        let mut pending: libc::sigset_t = std::mem::zeroed();
        let status = libc::sigpending(&mut pending);
        debug_assert_eq!(status, 0, "read the pending signals");
        libc::sigismember(&pending, libc::SIGPIPE) == 1
    }
}
