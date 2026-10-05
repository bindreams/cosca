//! Test seams of the link. Outside tests, [`Probe`] is a unit struct whose methods do
//! nothing, so no seam exists in a shipped build.

use crate::elevation::shim::protocol::Command;

/// Why the acceptor closed a connection without answering it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code, reason = "only a test probe receives events"))]
pub(crate) enum DropReason {
    NonRoot,
    Unreadable,
    ClosedBeforeHello,
    NotHello,
    AnswerFailed,
}

/// An event the link emits at a point a test can order its steps by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code, reason = "only a test probe receives events"))]
pub(crate) enum LinkEvent {
    Accepted,
    Dropped(DropReason),
    /// An answer was written (`A` or `N`) and the state updated.
    Answered(Command),
    /// A waiter is about to block for the frame.
    Parked(std::thread::ThreadId),
    Read(usize, std::thread::ThreadId),
    /// The final drain began; whether the socket path still existed then.
    DrainStarted {
        path_exists: bool,
    },
    AcceptorExited,
    /// A waiter is about to poll `fds` descriptors; whether the outcome's settled signal is already
    /// raised.
    Polling {
        fds: usize,
        settled_readable: bool,
    },
    /// `Drop` could not tell whether this process made the link, and did what is safe either way.
    UnknownOriginHandled {
        refused: bool,
        stop_written: bool,
    },
    /// Injected by a test thread that waited for a child process.
    ChildExited,
}

#[cfg(not(test))]
#[derive(Clone, Default)]
pub(crate) struct Probe;

#[cfg(not(test))]
impl Probe {
    pub(super) fn none() -> Self {
        Probe
    }
    pub(super) fn event(&self, _: impl FnOnce() -> LinkEvent) {}
    pub(super) fn acceptor_gate(&self) {}
    pub(super) fn waiter_gate(&self) {}
    pub(super) fn proc_root(&self) -> std::path::PathBuf {
        "/proc".into()
    }
    pub(super) fn stop_write_error(&self) -> Option<rustix::io::Errno> {
        None
    }
    pub(super) fn settled_write_error(&self) -> Option<rustix::io::Errno> {
        None
    }
    pub(super) fn wait_poll_error(&self) -> Option<rustix::io::Errno> {
        None
    }
    pub(super) fn send_error(&self) -> Option<rustix::io::Errno> {
        None
    }
    pub(super) fn credentials_error(&self) -> Option<std::io::Error> {
        None
    }
    pub(super) fn listener_made(&self, _: std::os::fd::BorrowedFd<'_>) {}
    pub(super) fn poll_error(&self) -> Option<rustix::io::Errno> {
        None
    }
    pub(super) fn accept_error(&self, _stopping: bool) -> Option<rustix::io::Errno> {
        None
    }
    pub(super) fn fd_created(&self, _spawn_lock_held: bool) {}
    pub(super) fn release(&self) {}
}

#[cfg(test)]
pub(crate) use hooks::Probe;

#[cfg(test)]
mod hooks {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{channel, Receiver, Sender};
    use std::sync::{Arc, Condvar, Mutex, PoisonError};

    use rustix::io::Errno;

    use super::LinkEvent;

    struct Hooks {
        events: Sender<LinkEvent>,
        /// While `true`, the acceptor waits after each wake, before it serves anything.
        held: Mutex<bool>,
        /// While `true`, a waiter waits after finding no outcome, before it polls.
        waiters_held: Mutex<bool>,
        held_changed: Condvar,
        /// The waiters' own: a condvar must only ever be used with one mutex.
        waiters_changed: Condvar,
        accept_errors: Mutex<VecDeque<Errno>>,
        stop_accept_errors: Mutex<VecDeque<Errno>>,
        poll_errors: Mutex<VecDeque<Errno>>,
        wait_poll_errors: Mutex<VecDeque<Errno>>,
        send_errors: Mutex<VecDeque<Errno>>,
        stop_write_error: Mutex<Option<Errno>>,
        settled_write_error: Mutex<Option<Errno>>,
        credential_failures: Mutex<usize>,
        listener_cloexec: Mutex<Option<bool>>,
        proc_root: Mutex<Option<std::path::PathBuf>>,
        panic_at_gate: AtomicBool,
        fds: Mutex<Vec<bool>>,
    }

    /// What a test controls and observes in a link.
    #[derive(Clone)]
    pub(crate) struct Probe(Option<Arc<Hooks>>);

    impl Probe {
        pub(in crate::elevation::shim) fn none() -> Self {
            Probe(None)
        }

        /// A probe and the receiver of its events.
        pub(crate) fn new() -> (Probe, Receiver<LinkEvent>) {
            let (events, rx) = channel();
            let hooks = Hooks {
                events,
                held: Mutex::new(false),
                waiters_held: Mutex::new(false),
                held_changed: Condvar::new(),
                waiters_changed: Condvar::new(),
                accept_errors: Mutex::new(VecDeque::new()),
                stop_accept_errors: Mutex::new(VecDeque::new()),
                poll_errors: Mutex::new(VecDeque::new()),
                wait_poll_errors: Mutex::new(VecDeque::new()),
                send_errors: Mutex::new(VecDeque::new()),
                stop_write_error: Mutex::new(None),
                settled_write_error: Mutex::new(None),
                credential_failures: Mutex::new(0),
                listener_cloexec: Mutex::new(None),
                proc_root: Mutex::new(None),
                panic_at_gate: AtomicBool::new(false),
                fds: Mutex::new(Vec::new()),
            };
            (Probe(Some(Arc::new(hooks))), rx)
        }

        fn hooks(&self) -> &Hooks {
            self.0.as_ref().expect("a test seam needs a probe from Probe::new")
        }

        /// Holds the acceptor in its next wake, before it serves anything.
        pub(crate) fn hold_acceptor(&self) {
            *self.hooks().held.lock().unwrap_or_else(PoisonError::into_inner) = true;
        }

        pub(crate) fn release_acceptor(&self) {
            *self.hooks().held.lock().unwrap_or_else(PoisonError::into_inner) = false;
            self.hooks().held_changed.notify_all();
        }

        /// Holds each waiter after it found no outcome, before it polls.
        pub(crate) fn hold_waiters(&self) {
            *self.hooks().waiters_held.lock().unwrap_or_else(PoisonError::into_inner) = true;
        }

        pub(crate) fn release_waiters(&self) {
            *self.hooks().waiters_held.lock().unwrap_or_else(PoisonError::into_inner) = false;
            self.hooks().waiters_changed.notify_all();
        }

        /// Puts `event` in the event stream, from a thread of the test's.
        pub(crate) fn inject(&self, event: LinkEvent) {
            self.event(|| event);
        }

        /// The acceptor's next `accept` fails with `errno`.
        pub(crate) fn fail_next_accept(&self, errno: Errno) {
            self.hooks()
                .accept_errors
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push_back(errno);
        }

        /// The next waiter's poll fails with `errno`.
        pub(crate) fn fail_next_wait_poll(&self, errno: Errno) {
            self.hooks()
                .wait_poll_errors
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push_back(errno);
        }

        /// The stop byte's next write fails with `errno`.
        pub(crate) fn fail_next_stop_write(&self, errno: Errno) {
            *self
                .hooks()
                .stop_write_error
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(errno);
        }

        /// The settled byte's next write fails with `errno`.
        pub(crate) fn fail_next_settled_write(&self, errno: Errno) {
            *self
                .hooks()
                .settled_write_error
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(errno);
        }

        /// `/proc` is looked for at `root` instead.
        pub(crate) fn use_proc_root(&self, root: std::path::PathBuf) {
            *self.hooks().proc_root.lock().unwrap_or_else(PoisonError::into_inner) = Some(root);
        }

        /// The next `K` send fails with `errno`.
        pub(crate) fn fail_next_send(&self, errno: Errno) {
            self.hooks()
                .send_errors
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push_back(errno);
        }

        /// The acceptor cannot prepare or read the credentials of the next accepted connection.
        pub(crate) fn fail_next_credentials(&self) {
            *self
                .hooks()
                .credential_failures
                .lock()
                .unwrap_or_else(PoisonError::into_inner) += 1;
        }

        /// Whether the listener was made `CLOEXEC`.
        pub(crate) fn listener_cloexec(&self) -> Option<bool> {
            *self
                .hooks()
                .listener_cloexec
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
        }

        /// The acceptor's `accept` fails with `errno` in the wake that stops it, and in no other.
        pub(crate) fn fail_accept_at_stop(&self, errno: Errno) {
            self.hooks()
                .stop_accept_errors
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push_back(errno);
        }

        /// The acceptor's next wake fails as if `poll` had failed with `errno`.
        pub(crate) fn fail_next_poll(&self, errno: Errno) {
            self.hooks()
                .poll_errors
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push_back(errno);
        }

        /// The acceptor panics in its next wake.
        pub(crate) fn panic_acceptor(&self) {
            self.hooks().panic_at_gate.store(true, Ordering::SeqCst);
        }

        /// For each descriptor creation so far, whether `spawn_lock` was held.
        pub(crate) fn fd_creations(&self) -> Vec<bool> {
            self.hooks().fds.lock().unwrap_or_else(PoisonError::into_inner).clone()
        }

        pub(in crate::elevation::shim::link) fn event(&self, make: impl FnOnce() -> LinkEvent) {
            if let Some(h) = &self.0 {
                // A test that dropped its receiver does not want events.
                h.events.send(make()).ok();
            }
        }

        pub(in crate::elevation::shim::link) fn acceptor_gate(&self) {
            let Some(h) = &self.0 else { return };
            let mut held = h.held.lock().unwrap_or_else(PoisonError::into_inner);
            while *held {
                held = h.held_changed.wait(held).unwrap_or_else(PoisonError::into_inner);
            }
            drop(held);
            if h.panic_at_gate.swap(false, Ordering::SeqCst) {
                panic!("injected acceptor panic");
            }
        }

        pub(in crate::elevation::shim::link) fn waiter_gate(&self) {
            let Some(h) = &self.0 else { return };
            let mut held = h.waiters_held.lock().unwrap_or_else(PoisonError::into_inner);
            while *held {
                held = h.waiters_changed.wait(held).unwrap_or_else(PoisonError::into_inner);
            }
        }

        /// macOS: a test clears `SO_NOSIGPIPE` on the listener, so that a connection's option can
        /// only have come from `prepare_conn`.
        #[cfg_attr(
            not(target_os = "macos"),
            allow(unused_variables, reason = "only macOS has the option")
        )]
        pub(in crate::elevation::shim::link) fn listener_made(&self, listener: std::os::fd::BorrowedFd<'_>) {
            if let Some(h) = &self.0 {
                let cloexec = rustix::io::fcntl_getfd(listener).map(|f| f.contains(rustix::io::FdFlags::CLOEXEC));
                *h.listener_cloexec.lock().unwrap_or_else(PoisonError::into_inner) = cloexec.ok();
            }
            #[cfg(target_os = "macos")]
            if self.0.is_some() {
                rustix::net::sockopt::set_socket_nosigpipe(listener, false).expect("the listener's option clears");
            }
        }

        pub(in crate::elevation::shim::link) fn wait_poll_error(&self) -> Option<Errno> {
            let h = self.0.as_ref()?;
            h.wait_poll_errors
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop_front()
        }

        pub(in crate::elevation::shim::link) fn stop_write_error(&self) -> Option<Errno> {
            let h = self.0.as_ref()?;
            h.stop_write_error.lock().unwrap_or_else(PoisonError::into_inner).take()
        }

        pub(in crate::elevation::shim::link) fn settled_write_error(&self) -> Option<Errno> {
            let h = self.0.as_ref()?;
            h.settled_write_error
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
        }

        pub(in crate::elevation::shim::link) fn proc_root(&self) -> std::path::PathBuf {
            let configured = self
                .0
                .as_ref()
                .and_then(|h| h.proc_root.lock().unwrap_or_else(PoisonError::into_inner).clone());
            configured.unwrap_or_else(|| "/proc".into())
        }

        pub(in crate::elevation::shim::link) fn send_error(&self) -> Option<Errno> {
            let h = self.0.as_ref()?;
            h.send_errors.lock().unwrap_or_else(PoisonError::into_inner).pop_front()
        }

        pub(in crate::elevation::shim::link) fn credentials_error(&self) -> Option<std::io::Error> {
            let h = self.0.as_ref()?;
            let mut failures = h.credential_failures.lock().unwrap_or_else(PoisonError::into_inner);
            (*failures > 0).then(|| {
                *failures -= 1;
                std::io::Error::from(Errno::IO)
            })
        }

        pub(in crate::elevation::shim::link) fn poll_error(&self) -> Option<Errno> {
            let h = self.0.as_ref()?;
            h.poll_errors.lock().unwrap_or_else(PoisonError::into_inner).pop_front()
        }

        pub(in crate::elevation::shim::link) fn accept_error(&self, stopping: bool) -> Option<Errno> {
            let h = self.0.as_ref()?;
            let queue = if stopping {
                &h.stop_accept_errors
            } else {
                &h.accept_errors
            };
            queue.lock().unwrap_or_else(PoisonError::into_inner).pop_front()
        }

        pub(in crate::elevation::shim::link) fn fd_created(&self, spawn_lock_held: bool) {
            if let Some(h) = &self.0 {
                h.fds
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(spawn_lock_held);
            }
        }

        /// Teardown opens the gate, so a held acceptor cannot deadlock the join.
        pub(in crate::elevation::shim::link) fn release(&self) {
            if self.0.is_some() {
                self.release_acceptor();
                self.release_waiters();
            }
        }
    }
}
