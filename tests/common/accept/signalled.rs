//! The drain-signalled accept, for a target whose own pid cannot be watched.

use std::fmt::{Debug, Display};

use rustix::fd::OwnedFd;

use super::{first_ready, run_watcher, DrainOutcome, Ready};

/// Wakes [`accept_or_signalled`] when a tree's drain wait ends; see [`DrainOutcome`].
pub struct DrainSignal {
    fd: OwnedFd,
    outcome: DrainOutcome,
}

impl Default for DrainSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl DrainSignal {
    pub fn new() -> Self {
        Self {
            fd: rustix::event::eventfd(0, rustix::event::EventfdFlags::CLOEXEC).expect("create the drain eventfd"),
            outcome: DrainOutcome::default(),
        }
    }

    fn wake(&self) {
        rustix::io::write(&self.fd, &1u64.to_ne_bytes()).expect("signal the drain");
    }

    /// Records the result of `wait_tree` and wakes the acceptor.
    pub fn record<T: Debug, E: Display>(&self, result: Result<T, E>) {
        self.outcome.store(result);
        self.wake();
    }

    /// Runs `wait` (a `wait_tree`) and records its result; a `wait` that panics records an error.
    pub fn watch<T: Debug, E: Display>(&self, wait: impl FnOnce() -> Result<T, E>) {
        run_watcher(&self.outcome, || self.wake(), wait);
    }
}

/// Accepts a connection on `listener` and acks it (the handshake in `common::accept`), or fails
/// loudly once `drained` is signalled. For a target whose own pid cannot be watched because it is
/// EXPECTED to exit at once while a descendant it left in the leaf is the one that connects: the
/// leaf emptying is the death of every possible connector.
///
/// `drained` is a [`DrainSignal`] that a watcher thread records into when the leaf drains
/// (`wait_tree` returning, Ok or Err); only this thread accepts. One `poll()` waits on both. A
/// connector waits for the ack after connecting, so a drain with nothing accepted is a failure.
pub fn accept_or_signalled(listener: &std::net::TcpListener, drained: &DrainSignal) -> std::net::TcpStream {
    use std::os::fd::AsRawFd as _;

    let mut fds = [
        libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: drained.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: `fds` is a valid, correctly-sized array for the call's duration.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            panic!("poll while waiting for a connection: {e}");
        }
        if fds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            panic!("the listener reported an error (revents={:#x})", fds[0].revents);
        }
        let drain = fds[1].revents & libc::POLLIN != 0;
        let connection = fds[0].revents & libc::POLLIN != 0;
        match first_ready(drain, connection) {
            Some(Ready::Exit) => drained.outcome.fail("leaf"),
            Some(Ready::Source) => return super::accept_and_ack(listener),
            None => {}
        }
    }
}
