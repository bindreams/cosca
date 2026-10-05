//! Test seams of the link (T4, T5). Outside tests, [`Probe`] is a unit struct whose methods do
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
    /// A root peer was accepted.
    Accepted,
    /// A connection was closed unanswered.
    Dropped(DropReason),
    /// An answer was written (`A` or `N`) and the state updated.
    Answered(Command),
    /// A waiter is about to block for the frame.
    Parked,
    /// Bytes of the frame were read.
    Read(usize),
    /// The final drain began; whether the socket path still existed then.
    DrainStarted { path_exists: bool },
    /// The acceptor thread ended.
    AcceptorExited,
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
    pub(super) fn poll_error(&self) -> Option<rustix::io::Errno> {
        None
    }
    pub(super) fn accept_error(&self) -> Option<rustix::io::Errno> {
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
        held_changed: Condvar,
        accept_errors: Mutex<VecDeque<Errno>>,
        poll_errors: Mutex<VecDeque<Errno>>,
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
                held_changed: Condvar::new(),
                accept_errors: Mutex::new(VecDeque::new()),
                poll_errors: Mutex::new(VecDeque::new()),
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

        /// The acceptor's next `accept` fails with `errno`.
        pub(crate) fn fail_next_accept(&self, errno: Errno) {
            self.hooks()
                .accept_errors
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

        pub(in crate::elevation::shim::link) fn poll_error(&self) -> Option<Errno> {
            let h = self.0.as_ref()?;
            h.poll_errors.lock().unwrap_or_else(PoisonError::into_inner).pop_front()
        }

        pub(in crate::elevation::shim::link) fn accept_error(&self) -> Option<Errno> {
            let h = self.0.as_ref()?;
            h.accept_errors
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop_front()
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
            }
        }
    }
}
