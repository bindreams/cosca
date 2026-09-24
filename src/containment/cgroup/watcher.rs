//! A leaf's shared watcher: one [`DrainWatch`], one pump, any number of waits.
//!
//! A leaf holds a single inotify instance for its life (see `drain.rs`), and two waits cannot read
//! one: each would consume events the other needs. So one thread reads it — the leaf's *pump* —
//! and broadcasts: every batch of events it takes in that bears on the leaf notifies every listener
//! (an `event_listener::Event`). Waits never touch the descriptor. Each reads the leaf's state
//! first, and answers from it if the leaf has drained or the wait cannot block; only then does it
//! listen, starting the pump, read the leaf again, and wait for the next notification.
//!
//! **No lost wake-up.** A wait that blocks listens *before* the read it blocks on. A change the read missed
//! happened after it, so its event reaches the pump after the listener existed, and the pump's
//! notification wakes it. A removal the kernel sends no `cgroup.events` event for still sends
//! `IN_DELETE` to the parent (see `drain.rs`), which the pump takes in the same way.
//!
//! **Ownership and teardown.** The pump is a thread owned by the leaf, not by the process: it is
//! started by the leaf's first wait that blocks, and stopped (an eventfd it polls alongside the watch) and
//! joined by the leaf's `Drop`, before that `Drop` uses the watch itself. It holds nothing but the
//! leaf's own watch. A wait cancelled or never polled again holds nothing at all.

use std::os::fd::{AsFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;

use event_listener::{Event, EventListener};

use super::DrainWatch;

/// The pump thread's name: at most 15 bytes, or Linux truncates it.
pub(crate) const PUMP_THREAD: &str = "cosca-cgrp-pump";

/// A leaf's watch, and the pump that reads it once a wait needs it.
pub(crate) struct Watcher {
    shared: Arc<Shared>,
    pump: Mutex<Option<Pump>>,
}

/// What the pump and the waits share.
struct Shared {
    /// The watch. The pump locks it for its whole life; no wait ever does.
    watch: Mutex<Option<DrainWatch>>,
    /// Notified after every batch of events that bears on the leaf.
    changed: Event,
    /// Whether the pump saw the leaf removed.
    gone: AtomicBool,
    /// Why the pump stopped on its own, if it did: waits then report it rather than wait on a
    /// pump that will not broadcast again.
    failure: Mutex<Option<String>>,
    /// The leaf's name, for the test seams.
    #[cfg_attr(not(test), allow(dead_code))]
    name: std::ffi::OsString,
}

/// The running pump.
struct Pump {
    /// Written once to stop it.
    stop: OwnedFd,
    thread: JoinHandle<()>,
}

impl Watcher {
    /// `None`: the leaf had no `cgroup.events` when its watch was armed — a test leaf, which
    /// reads as drained.
    pub(crate) fn new(watch: Option<DrainWatch>, name: std::ffi::OsString) -> Watcher {
        Watcher {
            shared: Arc::new(Shared {
                watch: Mutex::new(watch),
                changed: Event::new(),
                gone: AtomicBool::new(false),
                failure: Mutex::new(None),
                name,
            }),
            pump: Mutex::new(None),
        }
    }

    /// Start listening for the pump's next broadcast, starting the pump if it is not running.
    /// Listen before reading the leaf: a change after the read is then always heard.
    pub(crate) fn listen(&self) -> std::io::Result<EventListener> {
        let listener = self.shared.changed.listen();
        self.start_pump()?;
        Ok(listener)
    }

    /// Whether the pump saw the leaf removed.
    pub(crate) fn saw_removal(&self) -> bool {
        self.shared.gone.load(Ordering::Acquire)
    }

    /// Why the pump stopped on its own, if it did.
    pub(crate) fn failure(&self) -> Option<String> {
        self.shared.failure.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The watch, for the leaf's owner: the pump stopped and joined first, so the watch is
    /// no one else's.
    pub(crate) fn get_mut(&mut self) -> Option<&mut DrainWatch> {
        self.stop_pump();
        let shared = Arc::get_mut(&mut self.shared).expect("the joined pump holds no reference");
        shared.watch.get_mut().unwrap_or_else(|e| e.into_inner()).as_mut()
    }

    /// Stop and join the pump, if one runs. Called by the leaf's `Drop` first of all.
    pub(crate) fn stop_pump(&mut self) {
        let Some(pump) = self.pump.get_mut().unwrap_or_else(|e| e.into_inner()).take() else {
            return;
        };
        // An eventfd write fails only on counter overflow, which one write cannot reach.
        let _ = rustix::io::write(&pump.stop, &1u64.to_ne_bytes());
        if pump.thread.join().is_err() {
            log::warn!("a cgroup leaf's drain pump panicked");
        }
    }

    fn pumps(&self) -> MutexGuard<'_, Option<Pump>> {
        self.pump.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn start_pump(&self) -> std::io::Result<()> {
        let mut pump = self.pumps();
        if pump.is_some() {
            return Ok(());
        }
        let stop = rustix::event::eventfd(0, rustix::event::EventfdFlags::CLOEXEC)?;
        let stop = super::above_stdio(stop)?;
        let polled = stop.try_clone()?;
        let shared = self.shared.clone();
        let thread = std::thread::Builder::new()
            .name(PUMP_THREAD.into())
            .spawn(move || run_pump(&shared, &polled))?;
        #[cfg(test)]
        super::fault::record_pump(&self.shared.name, false);
        *pump = Some(Pump { stop, thread });
        Ok(())
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.stop_pump();
    }
}

/// Record why the pump stops, and wake every wait to read it.
fn fail(shared: &Shared, why: String) {
    *shared.failure.lock().unwrap_or_else(|e| e.into_inner()) = Some(why);
    shared.changed.notify(usize::MAX);
}

/// The pump: take in the watch's events and broadcast each batch that bears on the leaf, until
/// `stop` is written.
fn run_pump(shared: &Shared, stop: &OwnedFd) {
    use rustix::event::{poll, PollFd, PollFlags};

    let mut watch = shared.watch.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(watch) = watch.as_mut() {
        loop {
            let mut fds = [
                PollFd::from_borrowed_fd(watch.as_fd(), PollFlags::IN),
                PollFd::from_borrowed_fd(stop.as_fd(), PollFlags::IN),
            ];
            match poll(&mut fds, None) {
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => break fail(shared, format!("its watch could not be polled ({e})")),
            }
            if !fds[1].revents().is_empty() {
                break;
            }
            #[cfg(test)]
            if super::fault::take_force_pump_failure(&shared.name) {
                break fail(shared, "its watch could not be read (forced)".into());
            }
            let changed = match watch.consume() {
                Ok(changed) => changed,
                Err(e) => break fail(shared, format!("its watch could not be read ({e})")),
            };
            if watch.saw_removal() {
                shared.gone.store(true, Ordering::Release);
            }
            if changed {
                shared.changed.notify(usize::MAX);
            }
            #[cfg(test)]
            super::fault::notify_pump_batch(&shared.name, changed);
        }
    }
    drop(watch);
    #[cfg(test)]
    super::fault::record_pump(&shared.name, true);
}
