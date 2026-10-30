//! Test-only record of every signal cosca sends to a process, and how it addressed it.
//!
//! An entry is written immediately AFTER the syscall, whatever the syscall answers: a `kill(2)`
//! that fails with `ESRCH` still records, so a test sees an attempt that reached the OS. A send
//! that was skipped leaves no record, so an entry is evidence the call was made, not that the
//! signal arrived: a test that needs the effect reads the target's status. A [`GroupStep`] send (to
//! a group, its leader or a member, signal 0 included) is written by
//! [`send_signal`](crate::containment::unix::send_signal) or
//! [`probe_signal`](crate::containment::unix::probe_signal) after the syscall returned, with the
//! signal number it handed the syscall. Where a test seam answers in the kernel's place, no syscall
//! is made, and the step is still recorded.

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
    /// The signal (its number) to the whole group.
    Group(Route, i32),
    /// The signal (its number) to the leader alone, after the group's was refused.
    Leader(Route, i32),
    /// A member's resend: the member's pid, and the signal's number.
    Member(Route, u32, i32),
}

#[cfg(unix)]
impl GroupStep {
    /// A send of signal 0, which asks whether its target exists and delivers nothing.
    fn is_probe(self) -> bool {
        matches!(
            self,
            GroupStep::Group(_, 0) | GroupStep::Leader(_, 0) | GroupStep::Member(_, _, 0)
        )
    }
}

/// Asserts that the first step is `signo` sent to the whole group through the root's pidfd, before
/// any resend, and that nothing went to the group by its number.
#[cfg(all(target_os = "linux", test))]
#[track_caller]
pub(crate) fn assert_group_signalled_first_through_the_pidfd(steps: &[GroupStep], signo: i32) {
    assert_eq!(steps.first(), Some(&GroupStep::Group(Route::Pidfd, signo)), "{steps:?}");
    assert!(
        !steps.iter().any(|s| matches!(s, GroupStep::Group(Route::Number, _))),
        "nothing went by the group's number: {steps:?}"
    );
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

    /// Whether `sig` was sent to `pid`, by whatever route: the send was made, which a root reaped
    /// before its status could be read still shows.
    #[cfg(feature = "tokio")]
    pub(crate) fn sent(&self, pid: u32, sig: Sig) -> bool {
        self.entries().iter().any(|&(p, s, _)| p == pid && s == sig)
    }
}

impl Capture {
    /// The identity-checked sends by number: the tree walk on every unix, and on macOS also
    /// the signals `os_process::kill_by_id` and `terminate_by_id` send (`src/os_process/macos.rs`).
    #[cfg(unix)]
    pub(crate) fn by_identity(&self) -> Vec<IdentityEntry> {
        BY_IDENTITY.with(|log| log.borrow().clone().expect("a live capture has a log"))
    }
}

impl Capture {
    /// The checks and the signals of the sends to process groups, in order: no signal-0 probe.
    #[cfg(unix)]
    pub(crate) fn group_steps(&self) -> Vec<GroupStep> {
        let mut steps = self.group_steps_with_probes();
        steps.retain(|step| !step.is_probe());
        steps
    }

    /// Every step of the sends to process groups, in order, the signal-0 probes included.
    #[cfg(unix)]
    pub(crate) fn group_steps_with_probes(&self) -> Vec<GroupStep> {
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
