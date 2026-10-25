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

/// One step of a send to a process group, in order: a check of the root, or a send.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GroupStep {
    /// The root's pid was checked to still name its group.
    Check,
    /// The signal to the whole group.
    Group(Route),
    /// The signal to the leader alone, after the group's was refused.
    Leader(Route),
    /// A member's resend.
    Member(Route),
}

/// How a [`GroupStep`] send named its target.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "only Linux sends through a pidfd")]
pub(crate) enum Route {
    Pidfd,
    Number,
}

thread_local! {
    static LOG: RefCell<Option<Vec<Entry>>> = const { RefCell::new(None) };
    static BY_IDENTITY: RefCell<Option<Vec<IdentityEntry>>> = const { RefCell::new(None) };
    #[cfg(unix)]
    static GROUP: RefCell<Option<Vec<GroupStep>>> = const { RefCell::new(None) };
}

/// Records one step of a send to a process group on this thread, if a [`Capture`] is live.
#[cfg(unix)]
pub(crate) fn record_group(step: GroupStep) {
    GROUP.with(|log| {
        if let Some(steps) = log.borrow_mut().as_mut() {
            steps.push(step);
        }
    });
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
        #[cfg(unix)]
        GROUP.with(|log| *log.borrow_mut() = Some(Vec::new()));
        Capture(())
    }

    pub(crate) fn entries(&self) -> Vec<Entry> {
        LOG.with(|log| log.borrow().clone().expect("a live capture has a log"))
    }
}

impl Capture {
    /// The identity-checked sends by number (`wait::kill`/`terminate`, the tree walk).
    #[cfg(target_os = "macos")]
    pub(crate) fn by_identity(&self) -> Vec<IdentityEntry> {
        BY_IDENTITY.with(|log| log.borrow().clone().expect("a live capture has a log"))
    }
}

impl Capture {
    /// The steps of the sends to process groups, in order.
    #[cfg(unix)]
    pub(crate) fn group_steps(&self) -> Vec<GroupStep> {
        GROUP.with(|log| log.borrow().clone().expect("a live capture has a log"))
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        LOG.with(|log| *log.borrow_mut() = None);
        BY_IDENTITY.with(|log| *log.borrow_mut() = None);
        #[cfg(unix)]
        GROUP.with(|log| *log.borrow_mut() = None);
    }
}
