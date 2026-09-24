//! Turns on a leaf's one held [`DrainWatch`].
//!
//! A leaf holds a single inotify instance for its life (see `drain.rs`), and two waiters cannot
//! share one: each would consume events the other needs. So waits take turns, first come first
//! served. A waiter queues without blocking a runtime thread, counts its time queued against its
//! own deadline, and on getting its turn reads the leaf's state itself: a leaf that drained
//! meanwhile returns at once, one repopulated meanwhile is waited on again. Dropping a [`Turn`] — a waiter finishing, or an
//! async one cancelled — hands the watch to the next.

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};

use event_listener::{Event, Listener};

use super::DrainWatch;

/// A leaf's held drain watch, used by one waiter at a time, first come, first served.
pub(crate) struct WatchTurns {
    queue: Mutex<Queue>,
    /// Notified on every change a queued waiter may be waiting for.
    changed: Event,
    /// Locked only by the waiter whose turn it is, so never contended.
    watch: Mutex<Option<DrainWatch>>,
}

/// Who holds the turn, and who waits for it, oldest first.
#[derive(Default)]
struct Queue {
    held: bool,
    waiting: VecDeque<u64>,
    next_ticket: u64,
}

/// One waiter's turn on the watch.
pub(crate) struct Turn<'a>(&'a WatchTurns);

/// A waiter's place in the queue, given up when dropped: a waiter that times out or is
/// cancelled leaves no gap.
struct Place<'a> {
    turns: &'a WatchTurns,
    ticket: u64,
    served: bool,
}

impl WatchTurns {
    /// `None`: the leaf had no `cgroup.events` when its watch was armed — a test leaf, which reads
    /// as drained.
    pub(crate) fn new(watch: Option<DrainWatch>) -> WatchTurns {
        WatchTurns {
            queue: Mutex::new(Queue::default()),
            changed: Event::new(),
            watch: Mutex::new(watch),
        }
    }

    /// The watch, for the leaf's owner, which no waiter can hold a turn against.
    pub(crate) fn get_mut(&mut self) -> Option<&mut DrainWatch> {
        self.watch.get_mut().unwrap_or_else(|e| e.into_inner()).as_mut()
    }

    fn queue(&self) -> MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Take the turn at once if it is free and no one is waiting; otherwise join the queue.
    fn arrive(&self) -> Result<Turn<'_>, Place<'_>> {
        let mut queue = self.queue();
        if !queue.held && queue.waiting.is_empty() {
            queue.held = true;
            return Ok(Turn(self));
        }
        let ticket = queue.next_ticket;
        queue.next_ticket += 1;
        queue.waiting.push_back(ticket);
        Err(Place {
            turns: self,
            ticket,
            served: false,
        })
    }

    /// Take a turn, blocking this thread, until `deadline` (see [`crate::wait::remaining`]).
    /// `None`: the deadline passed first.
    pub(crate) fn take_until(&self, deadline: Option<Option<std::time::Instant>>) -> Option<Turn<'_>> {
        let mut place = match self.arrive() {
            Ok(turn) => return Some(turn),
            Err(place) => place,
        };
        #[cfg(test)]
        super::fault::notify_turn_queued();
        loop {
            let listener = self.changed.listen();
            if let Some(turn) = place.try_serve() {
                return Some(turn);
            }
            match crate::wait::remaining(deadline) {
                None => listener.wait(),
                Some(left) => {
                    if listener.wait_timeout(left).is_none() {
                        return place.try_serve();
                    }
                }
            }
        }
    }

    /// Take a turn, without blocking the thread. Dropping the future while queued gives up its
    /// place.
    #[cfg(feature = "tokio")]
    pub(crate) async fn take(&self) -> Turn<'_> {
        let mut place = match self.arrive() {
            Ok(turn) => return turn,
            Err(place) => place,
        };
        #[cfg(test)]
        super::fault::notify_turn_queued();
        loop {
            let listener = self.changed.listen();
            if let Some(turn) = place.try_serve() {
                return turn;
            }
            listener.await;
        }
    }
}

impl<'a> Place<'a> {
    /// The turn, if it is free and this place is first in line.
    fn try_serve(&mut self) -> Option<Turn<'a>> {
        let mut queue = self.turns.queue();
        if queue.held || queue.waiting.front() != Some(&self.ticket) {
            return None;
        }
        queue.waiting.pop_front();
        queue.held = true;
        self.served = true;
        Some(Turn(self.turns))
    }
}

impl Drop for Place<'_> {
    fn drop(&mut self) {
        if self.served {
            return;
        }
        let mut queue = self.turns.queue();
        queue.waiting.retain(|&t| t != self.ticket);
        drop(queue);
        // It may have been first in line: the next one looks again.
        self.turns.changed.notify(usize::MAX);
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
        self.0.queue().held = false;
        // Every queued waiter looks again; the first in line takes the turn.
        self.0.changed.notify(usize::MAX);
    }
}

#[cfg(test)]
#[path = "turn_tests.rs"]
mod turn_tests;
