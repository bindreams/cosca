//! Test seams for `SharedChild`. Thread-local, take-once, armed on the thread that makes the
//! call; each returns a guard that disarms an unconsumed force on drop.

use std::cell::{Cell, RefCell};
use std::io;
use std::sync::mpsc::{Receiver, Sender};

use super::unlocked::Unlocked;

/// What `force_unlocked_wait` makes the holder's unlocked wait do.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ForcedWait {
    ExitSeen,
    DeadlinePassed,
    Gone,
    /// The wait fails with this errno.
    Errno(i32),
    /// The wait panics.
    Panic,
}

impl ForcedWait {
    pub(super) fn into_result(self) -> io::Result<Unlocked> {
        match self {
            ForcedWait::ExitSeen => Ok(Unlocked::ExitSeen),
            ForcedWait::DeadlinePassed => Ok(Unlocked::DeadlinePassed),
            ForcedWait::Gone => Ok(Unlocked::Gone),
            ForcedWait::Errno(e) => Err(io::Error::from_raw_os_error(e)),
            ForcedWait::Panic => panic!("forced panic in the holder's unlocked wait (test seam)"),
        }
    }
}

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
    static PARK: RefCell<Option<ParkGate>> = const { RefCell::new(None) };
    static FORCED_WAIT: Cell<Option<ForcedWait>> = const { Cell::new(None) };
    static PANIC_AFTER_RELOCK: Cell<bool> = const { Cell::new(false) };
    static ON_CONDVAR_BLOCK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    #[cfg(windows)]
    static FORCE_DUPLICATE_HANDLE_ERROR: Cell<bool> = const { Cell::new(false) };
}

/// Disarms an unconsumed force on drop.
#[must_use = "dropping this immediately disarms the force; bind it for the probe's duration"]
pub(crate) struct Forced(fn());

impl Drop for Forced {
    fn drop(&mut self) {
        (self.0)();
    }
}

/// The next holder on this thread parks on `gate` inside its unlocked wait, before its platform
/// wait.
pub(crate) fn park_in_unlocked_wait(gate: ParkGate) -> Forced {
    PARK.with(|p| *p.borrow_mut() = Some(gate));
    Forced(|| PARK.with(|p| *p.borrow_mut() = None))
}

pub(super) fn park_if_armed() {
    if let Some(gate) = PARK.with(|p| p.borrow_mut().take()) {
        // A closed channel means the test is gone: carry on rather than hang.
        _ = gate.reached.send(());
        _ = gate.release.recv();
    }
}

/// The next holder on this thread gets `wait` from its unlocked wait instead of the platform
/// wait.
pub(crate) fn force_unlocked_wait(wait: ForcedWait) -> Forced {
    FORCED_WAIT.with(|f| f.set(Some(wait)));
    Forced(|| FORCED_WAIT.with(|f| f.set(None)))
}

pub(super) fn take_forced_unlocked_wait() -> Option<ForcedWait> {
    FORCED_WAIT.with(Cell::take)
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

/// Run `hook`, under the lock, just before this thread's next `Condvar::wait` or `wait_timeout`.
/// A test's hook sends on a channel it then `recv()`s, so it knows the waiter is inside the
/// `Condvar` before it releases anything: the wait releases the lock atomically, so the release
/// cannot overtake it.
pub(crate) fn on_condvar_block(hook: impl FnOnce() + 'static) -> Forced {
    ON_CONDVAR_BLOCK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    Forced(|| ON_CONDVAR_BLOCK.with(|h| *h.borrow_mut() = None))
}

pub(super) fn before_condvar_block() {
    if let Some(hook) = ON_CONDVAR_BLOCK.with(|h| h.borrow_mut().take()) {
        hook();
    }
}

/// The next `adopt` on this thread fails its `DuplicateHandle` with `ERROR_ACCESS_DENIED`.
#[cfg(windows)]
pub(crate) fn force_duplicate_handle_error_once() -> Forced {
    FORCE_DUPLICATE_HANDLE_ERROR.with(|f| f.set(true));
    Forced(|| FORCE_DUPLICATE_HANDLE_ERROR.with(|f| f.set(false)))
}

#[cfg(windows)]
pub(super) fn take_forced_duplicate_handle_error() -> bool {
    FORCE_DUPLICATE_HANDLE_ERROR.with(Cell::take)
}
