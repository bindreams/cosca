//! Test-only record of every signal cosca sends to a process, and how it addressed it.
//!
//! An entry is written immediately BEFORE the syscall, whatever the syscall answers: a `kill(2)`
//! that fails with `ESRCH` still records, so a test sees an attempt that reached the OS.

use std::cell::RefCell;

use crate::signal::Sig;

/// What addressed the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "each platform and later unit feeds a subset")]
pub(crate) enum Via {
    Pidfd,
    Pid,
    Handle,
    Identity,
}

pub(crate) type Entry = (u32, Sig, Via);

/// A signal sent to a process by number after re-checking its identity: the pid and the signal
/// number. Kept apart from [`Entry`] so the by-handle log of the drops keeps its shape.
pub(crate) type IdentityEntry = (u32, i32);

thread_local! {
    static LOG: RefCell<Option<Vec<Entry>>> = const { RefCell::new(None) };
    static BY_IDENTITY: RefCell<Option<Vec<IdentityEntry>>> = const { RefCell::new(None) };
}

/// Records one identity-checked send attempt by number (`signo`), if a [`Capture`] is live.
#[cfg(unix)]
pub(crate) fn record_by_identity(pid: u32, signo: i32) {
    BY_IDENTITY.with(|log| {
        if let Some(entries) = log.borrow_mut().as_mut() {
            entries.push((pid, signo));
        }
    });
}

/// Records one send attempt on this thread, if a [`Capture`] is live.
pub(crate) fn record(pid: u32, sig: Sig, via: Via) {
    LOG.with(|log| {
        if let Some(entries) = log.borrow_mut().as_mut() {
            entries.push((pid, sig, via));
        }
    });
}

/// Collects this thread's send attempts until dropped.
pub(crate) struct Capture(());

impl Capture {
    pub(crate) fn start() -> Capture {
        LOG.with(|log| {
            let mut log = log.borrow_mut();
            assert!(log.is_none(), "a send-log capture is already live on this thread");
            *log = Some(Vec::new());
        });
        BY_IDENTITY.with(|log| *log.borrow_mut() = Some(Vec::new()));
        Capture(())
    }

    pub(crate) fn entries(&self) -> Vec<Entry> {
        LOG.with(|log| log.borrow().clone().expect("a live capture has a log"))
    }
}

impl Capture {
    /// The identity-checked sends by number (`wait::kill`/`terminate`, the tree walk).
    #[cfg(unix)]
    pub(crate) fn by_identity(&self) -> Vec<IdentityEntry> {
        BY_IDENTITY.with(|log| log.borrow().clone().expect("a live capture has a log"))
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        LOG.with(|log| *log.borrow_mut() = None);
        BY_IDENTITY.with(|log| *log.borrow_mut() = None);
    }
}
