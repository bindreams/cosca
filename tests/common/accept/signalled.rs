//! The drain-signalled accept, for a target whose own pid cannot be watched.

/// Accepts a connection on `listener` and acks it (the handshake in `common::accept`), or fails
/// loudly once `drained` is signalled. For a target whose own pid cannot be watched because it is
/// EXPECTED to exit at once while a descendant it left in the leaf is the one that connects: the
/// leaf emptying is the death of every possible connector.
///
/// `drained` is an `eventfd` that a watcher thread writes when the leaf drains (`wait_tree`
/// returning). The watcher only signals; this thread is the only one that ever calls `accept()`.
/// One `poll()` waits on both. A connector waits for the ack after connecting, so it cannot have
/// drained the leaf with a connection still queued: a drain with nothing accepted is a failure.
pub fn accept_or_signalled(listener: &std::net::TcpListener, drained: &rustix::fd::OwnedFd) -> std::net::TcpStream {
    use std::os::fd::AsRawFd as _;

    let mut fds = [
        libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: drained.as_raw_fd(),
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
            panic!("the leaf drained before anything connected");
        }
        if fds[0].revents & libc::POLLIN != 0 {
            let (stream, _) = listener.accept().expect("accept a connection");
            return super::ack_now(stream);
        }
    }
}
