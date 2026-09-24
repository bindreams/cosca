//! Turns on a leaf's one held [`DrainWatch`].
//!
//! A leaf holds a single inotify instance for its life (see `drain.rs`), and two waiters cannot
//! share one: each would consume events the other needs. So waits take turns. A waiter queues
//! without blocking a runtime thread, counts its time queued against its own deadline, and on
//! getting its turn reads the leaf's state itself: a leaf that drained meanwhile returns at once,
//! one repopulated meanwhile is waited on again. Dropping a [`Turn`] — a waiter finishing, or an
//! async one cancelled — hands the watch to the next.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use event_listener::{Event, Listener};

use super::DrainWatch;

/// A leaf's held drain watch, used by one waiter at a time.
pub(crate) struct WatchTurns {
    busy: AtomicBool,
    released: Event,
    /// Locked only by the waiter whose turn it is, so never contended.
    watch: Mutex<Option<DrainWatch>>,
}

/// One waiter's turn on the watch.
pub(crate) struct Turn<'a>(&'a WatchTurns);

impl WatchTurns {
    /// `None` only for a test leaf with no `cgroup.events`, which reads as drained.
    pub(crate) fn new(watch: Option<DrainWatch>) -> WatchTurns {
        WatchTurns {
            busy: AtomicBool::new(false),
            released: Event::new(),
            watch: Mutex::new(watch),
        }
    }

    /// The watch, for the leaf's owner, which no waiter can hold a turn against.
    pub(crate) fn get_mut(&mut self) -> Option<&mut DrainWatch> {
        self.watch.get_mut().unwrap_or_else(|e| e.into_inner()).as_mut()
    }

    fn try_take(&self) -> Option<Turn<'_>> {
        self.busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
            // Lazily: a `Turn` made and dropped on failure would release the holder's.
            .then(|| Turn(self))
    }

    /// Take a turn, blocking this thread, until `deadline` (see [`crate::wait::remaining`]).
    /// `None`: the deadline passed first.
    pub(crate) fn take_until(&self, deadline: Option<Option<std::time::Instant>>) -> Option<Turn<'_>> {
        loop {
            if let Some(turn) = self.try_take() {
                return Some(turn);
            }
            let listener = self.released.listen();
            // A release between the attempt and the listen notified no one: look again.
            if let Some(turn) = self.try_take() {
                return Some(turn);
            }
            #[cfg(test)]
            super::fault::notify_turn_queued();
            match crate::wait::remaining(deadline) {
                None => listener.wait(),
                Some(left) => {
                    if listener.wait_timeout(left).is_none() {
                        return self.try_take();
                    }
                }
            }
        }
    }

    /// Take a turn, without blocking the thread. Dropping the future while queued takes none.
    #[cfg(feature = "tokio")]
    pub(crate) async fn take(&self) -> Turn<'_> {
        loop {
            if let Some(turn) = self.try_take() {
                return turn;
            }
            let listener = self.released.listen();
            if let Some(turn) = self.try_take() {
                return turn;
            }
            #[cfg(test)]
            super::fault::notify_turn_queued();
            listener.await;
        }
    }
}

impl Turn<'_> {
    /// The watch.
    pub(crate) fn watch(&self) -> MutexGuard<'_, Option<DrainWatch>> {
        self.0.watch.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        self.0.busy.store(false, Ordering::Release);
        // Every queued waiter looks again; one gets the turn, the rest queue again.
        self.0.released.notify(usize::MAX);
    }
}
