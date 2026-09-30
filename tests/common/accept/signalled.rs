//! The drain-signalled accept, for a target whose own pid cannot be watched.

use std::fmt::{Debug, Display};
use std::sync::Mutex;

use rustix::fd::OwnedFd;

/// How a tree's drain wait ended, handed from the watcher thread to [`accept_or_signalled`]: a
/// wait that FAILED must not be reported as the tree having drained.
pub struct DrainSignal {
    fd: OwnedFd,
    outcome: Mutex<Option<Result<String, String>>>,
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
            outcome: Mutex::new(None),
        }
    }

    /// Records the result of `wait_tree` and wakes the acceptor. The outcome is stored before
    /// the eventfd is written, so an acceptor woken by the eventfd always finds it.
    pub fn record<T: Debug, E: Display>(&self, result: Result<T, E>) {
        let outcome = result.map(|drain| format!("{drain:?}")).map_err(|e| e.to_string());
        *self.outcome.lock().expect("the drain outcome lock") = Some(outcome);
        rustix::io::write(&self.fd, &1u64.to_ne_bytes()).expect("signal the drain");
    }

    fn fail(&self) -> ! {
        match self.outcome.lock().expect("the drain outcome lock").take() {
            Some(Ok(drain)) => panic!("the leaf drained ({drain}) before anything connected"),
            Some(Err(e)) => panic!("wait_tree failed while waiting for a connection: {e}"),
            None => unreachable!("the drain eventfd is written only after the outcome is stored"),
        }
    }
}

/// Accepts a connection on `listener` and acks it (the handshake in `common::accept`), or fails
/// loudly once `drained` is signalled. For a target whose own pid cannot be watched because it is
/// EXPECTED to exit at once while a descendant it left in the leaf is the one that connects: the
/// leaf emptying is the death of every possible connector.
///
/// `drained` is a [`DrainSignal`] that a watcher thread records into when the leaf drains
/// (`wait_tree` returning, Ok or Err). The watcher only signals; this thread is the only one that ever calls `accept()`.
/// One `poll()` waits on both. A connector waits for the ack after connecting, so it cannot have
/// drained the leaf with a connection still queued: a drain with nothing accepted is a failure.
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
        // The drain is checked first, as `accept_or_die` checks exits first.
        if fds[1].revents & libc::POLLIN != 0 {
            drained.fail();
        }
        if fds[0].revents & libc::POLLIN != 0 {
            let (stream, _) = listener.accept().expect("accept a connection");
            return super::ack_now(stream);
        }
    }
}
