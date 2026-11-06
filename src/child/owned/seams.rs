//! Test seams for `OwnedChild`. Thread-local, take-once, armed on the thread that makes the
//! call; each returns a guard that disarms an unconsumed force on drop.

use std::cell::{Cell, RefCell};
use std::sync::mpsc::{Receiver, Sender};

/// The two ends of a gate the holder parks on: it sends on `reached`, then blocks on `release`.
pub(crate) struct ParkGate {
    reached: Sender<()>,
    release: Receiver<()>,
}

/// A gate and the test's two ends of it.
pub(crate) fn park_gate() -> (ParkGate, Receiver<()>, Sender<()>) {
    let (reached_tx, reached_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    (
        ParkGate {
            reached: reached_tx,
            release: release_rx,
        },
        reached_rx,
        release_tx,
    )
}

thread_local! {
    static PARK_AFTER_REAP: RefCell<Option<ParkGate>> = const { RefCell::new(None) };
    static PANIC_AFTER_RELOCK: Cell<bool> = const { Cell::new(false) };
    static ROOT_TEARDOWNS: Cell<Option<u32>> = const { Cell::new(None) };
}

/// From now on every root teardown a drop starts on THIS thread ([`OwnedChild::tear_down`]:
/// a kill and a wait) is counted. It still runs.
///
/// [`OwnedChild::tear_down`]: super::OwnedChild::tear_down
pub(crate) fn record_root_teardowns() -> RootTeardownRecorder {
    ROOT_TEARDOWNS.with(|c| c.set(Some(0)));
    RootTeardownRecorder(())
}

#[must_use = "recording stops as soon as the recorder is dropped"]
pub(crate) struct RootTeardownRecorder(());

impl RootTeardownRecorder {
    pub(crate) fn count(&self) -> u32 {
        ROOT_TEARDOWNS.with(|c| c.get().expect("the recorder is live"))
    }
}

impl Drop for RootTeardownRecorder {
    fn drop(&mut self) {
        ROOT_TEARDOWNS.with(|c| c.set(None));
    }
}

pub(super) fn note_root_teardown() {
    ROOT_TEARDOWNS.with(|c| {
        if let Some(n) = c.get() {
            c.set(Some(n + 1));
        }
    });
}

/// Disarms an unconsumed force on drop.
#[must_use = "dropping this immediately disarms the force; bind it for the probe's duration"]
pub(crate) struct Forced(fn());

impl Drop for Forced {
    fn drop(&mut self) {
        (self.0)();
    }
}

/// This thread's next `wait` that reaps parks on `gate` once the
/// `E` write is done and the lock is released, before it returns.
pub(crate) fn park_after_reap_recorded_on(gate: ParkGate) -> Forced {
    PARK_AFTER_REAP.with(|p| *p.borrow_mut() = Some(gate));
    Forced(|| PARK_AFTER_REAP.with(|p| *p.borrow_mut() = None))
}

pub(super) fn park_after_reap_recorded() {
    if let Some(gate) = PARK_AFTER_REAP.with(|p| p.borrow_mut().take()) {
        // A closed channel means the test is gone: carry on rather than hang.
        _ = gate.reached.send(());
        _ = gate.release.recv();
    }
}

/// The next holder on this thread panics just after `relock()`, while it holds the lock: which
/// also poisons the mutex.
pub(crate) fn panic_after_relock_once() -> Forced {
    PANIC_AFTER_RELOCK.with(|f| f.set(true));
    Forced(|| PANIC_AFTER_RELOCK.with(|f| f.set(false)))
}

pub(super) fn panic_after_relock_if_armed() {
    if PANIC_AFTER_RELOCK.with(Cell::take) {
        panic!("forced panic just after the holder's relock (test seam)");
    }
}

/// Run on any thread whose lock of a `OwnedChild` finds it held, before it blocks.
#[cfg(unix)]
type ContendedHook = Box<dyn Fn() + Send>;

/// Process-wide, unlike the rest: the thread that contends is not the test's own.
#[cfg(unix)]
static ON_LOCK_CONTENDED: std::sync::Mutex<Option<ContendedHook>> = std::sync::Mutex::new(None);

/// Disarms [`on_lock_contended`] on drop.
#[cfg(unix)]
#[must_use = "dropping this immediately disarms the hook; bind it for the probe's duration"]
pub(crate) struct ContendedArmed(());

#[cfg(unix)]
impl Drop for ContendedArmed {
    fn drop(&mut self) {
        *ON_LOCK_CONTENDED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}

/// Run `hook` each time a thread's lock of a `OwnedChild` finds it held, just before that thread
/// blocks on it: proof the thread has not got past the lock.
#[cfg(unix)]
pub(crate) fn on_lock_contended(hook: impl Fn() + Send + 'static) -> ContendedArmed {
    *ON_LOCK_CONTENDED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(hook));
    ContendedArmed(())
}

pub(super) fn lock_contended() {
    #[cfg(unix)]
    if let Some(hook) = ON_LOCK_CONTENDED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
    {
        hook();
    }
}
