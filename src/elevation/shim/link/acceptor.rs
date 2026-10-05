//! The acceptor thread (D4): answers each root shim that says hello, under the state lock, without
//! any call from the owner. The link owns it and joins it in `Drop`.

use std::io::{self, PipeReader, PipeWriter};
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;

use rustix::event::{PollFd, PollFlags};

use super::outcome::AcceptorFailure;
use super::probe::{DropReason, LinkEvent};
use super::state::Shared;
use super::sys::{self, Read};

/// The wake pipe: the acceptor polls `reader`; teardown writes the stop byte to `writer`. Both ends
/// belong to the link, so writing never meets a closed reader.
pub(super) struct Wake {
    pub(super) reader: PipeReader,
    pub(super) writer: PipeWriter,
}

/// What ends the thread, normally or by unwinding.
struct ExitGuard<'a>(&'a Shared);

impl Drop for ExitGuard<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.fail_closed(AcceptorFailure::Panicked);
        }
        self.0.probe.event(|| LinkEvent::AcceptorExited);
    }
}

/// The thread body. Dropping `listener` on return closes it: a shim still queued sees EOF.
pub(super) fn run(shared: Arc<Shared>, listener: UnixListener, wake: Arc<Wake>) {
    let _exit = ExitGuard(&shared);
    let mut acceptor = Acceptor {
        shared: &shared,
        listener: &listener,
        pending: Vec::new(),
    };
    if let Err(failure) = acceptor.serve(&wake) {
        shared.fail_closed(failure);
    }
}

struct Acceptor<'a> {
    shared: &'a Shared,
    listener: &'a UnixListener,
    /// Root peers that have not said hello.
    pending: Vec<UnixStream>,
}

impl Acceptor<'_> {
    fn serve(&mut self, wake: &Wake) -> Result<(), AcceptorFailure> {
        loop {
            let mut fds = vec![
                PollFd::new(&wake.reader, PollFlags::IN),
                PollFd::new(self.listener, PollFlags::IN),
            ];
            fds.extend(self.pending.iter().map(|c| PollFd::new(c, PollFlags::IN)));
            sys::poll_ready(&mut fds).map_err(|e| AcceptorFailure::Errno(e.raw_os_error()))?;
            let woken = !fds[0].revents().is_empty();
            // A byte nobody here asked for came from a fork copy of the link: consume it.
            let stop = woken && self.shared.is_stopping();
            if woken && !stop {
                let mut byte = [0u8];
                if let Err(e) = rustix::io::read(&wake.reader, &mut byte) {
                    log::debug!("consuming a stray wake byte: {e}");
                }
            }
            let incoming = !fds[1].revents().is_empty();
            let ready: Vec<bool> = fds[2..].iter().map(|f| !f.revents().is_empty()).collect();
            drop(fds);
            self.shared.probe.acceptor_gate();
            if let Some(errno) = self.shared.probe.poll_error() {
                return Err(AcceptorFailure::Errno(errno.raw_os_error()));
            }

            // The listener before the wake pipe: a shim queued before the stop is answered.
            let accepted = if incoming || stop {
                self.accept_all(stop)
            } else {
                Ok(())
            };
            if stop {
                // The drain answers the peers already held whatever `accept` said. At teardown the
                // state is settled, so there is nothing to fail closed: the error is only reported.
                self.drain();
                if let Err(failure) = accepted {
                    log::warn!(
                        "accept on {} failed during teardown ({failure:?}); the backlog may be closed unanswered",
                        self.shared.sock_path.display()
                    );
                }
                return Ok(());
            }
            accepted?;
            self.say_hellos(&ready);
        }
    }

    /// Takes every connection queued, root ones into `pending`.
    fn accept_all(&mut self, stopping: bool) -> Result<(), AcceptorFailure> {
        loop {
            let accepted = match self.shared.probe.accept_error(stopping) {
                Some(errno) => Err(io::Error::from(errno)),
                None => sys::accept(&self.shared.probe, self.listener),
            };
            match accepted {
                Ok(Some(conn)) => self.admit(conn),
                Ok(None) => return Ok(()),
                Err(e) if matches!(e.raw_os_error(), Some(libc::EINTR | libc::ECONNABORTED)) => {
                    log::debug!("accept on {} was interrupted: {e}", self.shared.sock_path.display());
                }
                Err(e) => return Err(AcceptorFailure::Errno(e.raw_os_error().unwrap_or(libc::EIO))),
            }
        }
    }

    /// Keeps `conn` if its peer is root; closes it unanswered otherwise.
    fn admit(&mut self, conn: UnixStream) {
        let path = self.shared.sock_path.display();
        let peer = sys::prepare_conn(&conn).and_then(|()| sys::peer_euid(conn.as_fd()));
        match peer {
            Err(e) => {
                log::debug!("cannot read the credentials of a peer at {path}: {e}");
                self.shared.probe.event(|| LinkEvent::Dropped(DropReason::Unreadable));
            }
            Ok(uid) if uid != self.shared.peer_euid => {
                log::warn!(
                    "a peer at {path} runs as uid {uid}, not {}; closed unanswered",
                    self.shared.peer_euid
                );
                self.shared.probe.event(|| LinkEvent::Dropped(DropReason::NonRoot));
            }
            Ok(_) => {
                self.shared.probe.event(|| LinkEvent::Accepted);
                self.pending.push(conn);
            }
        }
    }

    /// Reads the hello of each pending peer that `ready` marks, in order of `pending` when polled.
    fn say_hellos(&mut self, ready: &[bool]) {
        let mut ready = ready.iter();
        let mut kept = Vec::with_capacity(self.pending.len());
        for conn in std::mem::take(&mut self.pending) {
            // Peers admitted since the poll were not polled; they are checked next time round.
            if !ready.next().copied().unwrap_or(false) {
                kept.push(conn);
                continue;
            }
            let mut byte = [0u8; 1];
            match sys::read_some(conn.as_fd(), &mut byte) {
                Read::Bytes(_) if byte[0] == b'H' => self.shared.answer_hello(conn),
                Read::Bytes(_) => {
                    log::warn!(
                        "a peer at {} sent {:#04x} instead of hello; closed unanswered",
                        self.shared.sock_path.display(),
                        byte[0]
                    );
                    self.shared.probe.event(|| LinkEvent::Dropped(DropReason::NotHello));
                }
                Read::Eof | Read::Failed(_) => {
                    log::debug!("a peer at {} closed before hello", self.shared.sock_path.display());
                    self.shared
                        .probe
                        .event(|| LinkEvent::Dropped(DropReason::ClosedBeforeHello));
                }
                Read::Empty => kept.push(conn),
            }
        }
        self.pending = kept;
    }

    /// The final drain (D14): every peer still held is answered `N`, hello or not.
    fn drain(&mut self) {
        self.shared.probe.event(|| LinkEvent::DrainStarted {
            path_exists: self.shared.sock_path.exists(),
        });
        for conn in self.pending.drain(..) {
            self.shared.deny(&conn);
        }
    }
}
