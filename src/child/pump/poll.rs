//! Unix: stdin, stdout and stderr go through one `poll` loop on the calling thread. No pipe can
//! fill and stall the child, and nothing after the spawn needs a thread, so a caller under a task
//! limit (`RLIMIT_NPROC`, a cgroup's `TasksMax`) cannot fail for want of one.

use std::io::{self, ErrorKind, Read, Write};
use std::os::fd::AsFd;

use rustix::event::{PollFd, PollFlags};
use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};

use super::{Drain, Pump, Slot, CHUNK};
use crate::pipe::{PipeReader, PipeWriter};
use crate::wait;

impl<'a> Pump<'a, PipeWriter, PipeReader> {
    pub(super) fn new(
        stdin: Option<PipeWriter>,
        input: &'a [u8],
        stdout: Option<PipeReader>,
        stderr: Option<PipeReader>,
    ) -> Self {
        Pump::assemble(
            stdin,
            input,
            stdout,
            stderr,
            |pipe| {
                nonblocking(&pipe)?;
                forbid_sigpipe(&pipe)?;
                Ok(pipe)
            },
            |pipe| {
                nonblocking(&pipe)?;
                Ok(pipe)
            },
        )
    }

    /// Moves bytes until every stream is closed. Fails only when `poll` does.
    pub(super) fn run(&mut self) -> io::Result<()> {
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
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
            written => self.wrote(written),
        }
    }
}

impl Drain<PipeReader> {
    fn read_some(&mut self, chunk: &mut [u8]) {
        let Some(pipe) = &mut self.pipe else { return };
        match pipe.read(chunk) {
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
            read => {
                if !self.collected.took(read, chunk) {
                    self.pipe = None;
                }
            }
        }
    }
}

/// Sets `O_NONBLOCK` on the pipe's own open file description. The child holds the other end of the
/// pipe, a different description, so it is unaffected.
fn nonblocking(pipe: &impl AsFd) -> io::Result<()> {
    let flags = fcntl_getfl(pipe)?;
    fcntl_setfl(pipe, flags | OFlags::NONBLOCK)?;
    Ok(())
}

// SIGPIPE =====
//
// Writing to a pipe nobody reads raises `SIGPIPE`, and a host that left its disposition at the
// default dies of it (a C host, a cdylib, `-Zon-broken-pipe=kill`); Rust's runtime ignores it, but a
// library cannot rely on that. Either way the write reports `EPIPE`.

/// macOS: marks the pipe `F_SETNOSIGPIPE` once, before the first write, so a write to a broken pipe
/// fails with `EPIPE` and raises nothing. macOS delivers that signal to the process, not the writing
/// thread, so the guard of the other systems cannot catch it.
#[cfg(target_os = "macos")]
fn forbid_sigpipe(pipe: &PipeWriter) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: `fcntl(F_SETNOSIGPIPE, int)` on a descriptor `pipe` keeps open. rustix has no wrapper.
    let status = unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_SETNOSIGPIPE, 1 as libc::c_int) };
    if status == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// One `write`. `forbid_sigpipe` already stopped the pipe from raising `SIGPIPE`.
#[cfg(target_os = "macos")]
fn write_without_sigpipe(pipe: &mut PipeWriter, bytes: &[u8]) -> io::Result<usize> {
    pipe.write(bytes)
}

/// Other Unixes: nothing to set up; `write_without_sigpipe` blocks the signal around each write.
#[cfg(not(target_os = "macos"))]
fn forbid_sigpipe(_: &PipeWriter) -> io::Result<()> {
    Ok(())
}

/// One `write` that cannot kill the host. `SIGPIPE` is blocked on this thread around the write
/// (the signal is thread-directed here); the one the write raised is consumed, and one already
/// pending (the host's own) is left for the host.
#[cfg(not(target_os = "macos"))]
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
#[cfg(not(target_os = "macos"))]
fn sigpipe_pending() -> bool {
    // SAFETY: `sigpending` fills a zeroed set the call owns; `sigismember` only reads it.
    unsafe {
        let mut pending: libc::sigset_t = std::mem::zeroed();
        let status = libc::sigpending(&mut pending);
        debug_assert_eq!(status, 0, "read the pending signals");
        libc::sigismember(&pending, libc::SIGPIPE) == 1
    }
}
