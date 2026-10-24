//! The watch a wait keeps on the tracers that hold its child. The XNU behaviour below is read from
//! xnu-12377.121.6: `kern_event.c`, `kern_exit.c`, `kern_sig.c` and `mach_process.c`.
//!
//! While a tracer holds a child, XNU sends the child's `NOTE_EXIT` to the tracer alone, and to the
//! parent only at the hand-back, when the tracer collects the zombie. A tracer that exits hands back
//! a zombie child at once and kills one still traced, which then exits as the parent's child. A
//! child in neither state, exiting but not yet a zombie (`P_LTRACED` already cleared), goes to
//! launchd with `p_oppid` still naming the parent: its `NOTE_EXIT` and `SIGCHLD` reach the parent
//! only if launchd waits on it. So a wait that finds its child traced also watches the tracer's
//! exit, whose `NOTE_EXIT` fires after that hand-over, and checks the child again when it wakes.
//!
//! The same holds for a tracer that is itself traced: its `NOTE_EXIT` reaches only its own tracer,
//! but its exit sends that tracer `SIGCHLD`. So the watch follows the chain, tracer by tracer, to
//! one whose `NOTE_EXIT` reaches this process, and registers `NOTE_EXIT` and `NOTE_SIGNAL` on each.
//! A tracer that attaches later, to the child or to a tracer on the chain, reparents it and sends it
//! `SIGSTOP`, which `NOTE_SIGNAL` reports before any check of the signal's disposition; the wait
//! registers `NOTE_SIGNAL` on the child itself.
//!
//! A tracer that began its exit and then lost its own tracer goes to launchd with `p_oppid` set,
//! so neither its `NOTE_EXIT` nor its `SIGCHLD` reaches anything the wait watches. It hands the
//! child over once its exit reaches its children. Until then the wait checks again on a backoff, as
//! it does for a tracer already gone.
//!
//! A tracer whose `NOTE_EXIT` never reached this process leaves its knote registered but detached
//! once it is reaped, and an `EV_ADD` on that pid only updates the detached knote. So the watch
//! deletes a pid's registration once a walk finds the pid gone or naming another process, before it
//! registers that pid again.

use std::time::Duration;

use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};

use super::arm_exit_and_signals_on;
#[cfg(not(test))]
use crate::identity::link;
use crate::identity::{uniq_info, Link, ReadPurpose, UniqRead, LAUNCHD};

/// The backoff's first interval after a walk finds a tracer gone, and its cap.
const GONE_START: Duration = Duration::from_millis(1);
const GONE_CAP: Duration = Duration::from_millis(50);

/// What a wait does after its check found the child held by a tracer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnTracer {
    /// Block until an event: every tracer on the chain is watched.
    Block,
    /// Check the child again first, after waiting at most this long (zero: at once).
    Recheck(Duration),
}

/// The tracers a wait watches. One per wait, on the wait's own kqueue.
#[derive(Debug, Default)]
pub(crate) struct TracerWatch {
    /// The processes, by pid and unique id, whose `NOTE_EXIT` and `NOTE_SIGNAL` are registered,
    /// each by a registration made while the pid named that process.
    armed: Vec<(u32, u64)>,
    /// The backoff before the next check, while each walk since it was set found a tracer gone or
    /// exiting at launchd.
    gone: Option<Duration>,
}

impl TracerWatch {
    /// The wait's check found the child held by `tracer`, a process that is neither this one nor
    /// launchd. Walks the chain from `tracer` up, through each tracer that is itself traced, to one
    /// whose `NOTE_EXIT` reaches this process, and registers `NOTE_EXIT` and `NOTE_SIGNAL` on every
    /// process on it. The chain has no length cap: it ends where a process has no tracer, or is
    /// traced by this process, or where it meets itself.
    ///
    /// The wait may block only on a check whose walk registered nothing new: before a
    /// registration, the process may have changed unseen. A tracer that is gone, or exiting at
    /// launchd, has not necessarily released the child yet, so the wait checks again: at once the
    /// first time, then after 1 ms, doubling to 50 ms, with no cap on rounds, while walks keep
    /// finding one. Each wake re-checks the child and walks again; the elapsed time decides nothing.
    pub(crate) fn held_by(&mut self, kq: &Kqueue, tracer: u32) -> std::io::Result<OnTracer> {
        let me = std::process::id();
        let mut walked = Vec::new();
        let mut fresh = false;
        let mut at = tracer;
        while !walked.contains(&at) {
            walked.push(at);
            let (unique, parent, at_attach) = match link(at) {
                Link::Found {
                    unique,
                    parent,
                    at_attach,
                } => (unique, parent, at_attach),
                Link::Gone => {
                    self.disarm(kq, at)?;
                    return Ok(self.gone());
                }
                Link::Refused(errno) => return Err(refused(at, errno)),
                Link::Unreadable => {
                    return Err(std::io::Error::other(format!(
                        "tracer {at}: who holds it could not be read (kinfo_proc refused)"
                    )))
                }
            };
            if !self.armed.contains(&(at, unique)) {
                self.disarm(kq, at)?;
                let armed = arm_exit_and_signals_on(kq, at).map_err(into_io)?;
                if armed.is_none() {
                    return Ok(self.gone());
                }
                match uniq_info(at, ReadPurpose::Link) {
                    UniqRead::Found(info) if info.unique_id == unique => {}
                    UniqRead::Found(_) | UniqRead::Gone => {
                        // The registration may name another process: deleted, so a later one attaches.
                        delete(kq, at)?;
                        return Ok(self.gone());
                    }
                    UniqRead::Refused(errno) => return Err(refused(at, errno)),
                }
                self.armed.push((at, unique));
                fresh = true;
            }
            // No tracer, or this process traces it: its `NOTE_EXIT` reaches this process.
            if at_attach == 0 || parent == me {
                break;
            }
            // Traced, yet held by launchd: exiting, its tracer died after `P_LTRACED` was cleared.
            if parent == LAUNCHD {
                return Ok(self.gone());
            }
            at = parent;
        }
        self.gone = None;
        Ok(if fresh {
            OnTracer::Recheck(Duration::ZERO)
        } else {
            OnTracer::Block
        })
    }

    /// Deletes the registration on `pid`, if one was made, and forgets it.
    fn disarm(&mut self, kq: &Kqueue, pid: u32) -> std::io::Result<()> {
        if self.armed.iter().any(|&(armed, _)| armed == pid) {
            delete(kq, pid)?;
            self.armed.retain(|&(armed, _)| armed != pid);
        }
        Ok(())
    }

    /// The re-check after a walk that found a tracer gone or exiting at launchd.
    fn gone(&mut self) -> OnTracer {
        let wait = self
            .gone
            .map_or(Duration::ZERO, |wait| (wait * 2).clamp(GONE_START, GONE_CAP));
        self.gone = Some(wait);
        OnTracer::Recheck(wait)
    }

    /// Whether `event` is an event of a watched tracer, for a wait on `child`: its exit, or a signal
    /// sent to it. An exit's knote is one-shot, so the next walk registers that pid again.
    pub(crate) fn fired(&mut self, event: &KEvent, child: u32) -> bool {
        let fired = event.filter() == Ok(EventFilter::EVFILT_PROC) && event.ident() != child as usize;
        if fired && event.fflags().contains(FilterFlag::NOTE_EXIT) {
            self.armed.retain(|&(pid, _)| pid as usize != event.ident());
        }
        fired
    }
}

/// Deletes the `EVFILT_PROC` registration on `pid`. `ENOENT`: none is left, as after a `NOTE_EXIT`
/// was delivered, which deletes its one-shot knote.
fn delete(kq: &Kqueue, pid: u32) -> std::io::Result<()> {
    let change = KEvent::new(
        pid as usize,
        EventFilter::EVFILT_PROC,
        EvFlags::EV_DELETE | EvFlags::EV_RECEIPT,
        FilterFlag::empty(),
        0,
        0,
    );
    match super::add_with_receipt(kq, change).map_err(into_io)? {
        0 => Ok(()),
        e if e == libc::ENOENT as i64 => Ok(()),
        e => Err(std::io::Error::from_raw_os_error(e as i32)),
    }
}

fn into_io(e: crate::error::Error) -> std::io::Error {
    match e {
        crate::error::Error::Io(e) => e,
        other => std::io::Error::other(other),
    }
}

fn refused(pid: u32, errno: i32) -> std::io::Error {
    std::io::Error::new(
        std::io::Error::from_raw_os_error(errno).kind(),
        format!("tracer {pid}: its identity could not be read (errno {errno})"),
    )
}

/// [`crate::identity::link`], or the answer a test queued for it.
#[cfg(test)]
fn link(pid: u32) -> Link {
    seams::take_link().unwrap_or_else(|| crate::identity::link(pid))
}

/// Test seams.
#[cfg(test)]
pub(crate) mod seams {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use crate::identity::Link;

    thread_local! {
        static LINKS: RefCell<VecDeque<Link>> = const { RefCell::new(VecDeque::new()) };
    }

    /// While the guard lives, the walks on this thread take their `link` reads from `links`, in
    /// order, and read for real once the queue is empty.
    pub(crate) fn force_links(links: impl IntoIterator<Item = Link>) -> ForcedLinks {
        LINKS.with(|l| *l.borrow_mut() = links.into_iter().collect());
        ForcedLinks(())
    }

    #[must_use = "the reads are real again as soon as the guard is dropped"]
    pub(crate) struct ForcedLinks(());

    impl ForcedLinks {
        /// How many of the queued answers no walk has taken yet.
        pub(crate) fn left(&self) -> usize {
            LINKS.with(|l| l.borrow().len())
        }

        /// Queues `links` after those not taken yet.
        pub(crate) fn then(&self, links: impl IntoIterator<Item = Link>) {
            LINKS.with(|l| l.borrow_mut().extend(links));
        }
    }

    impl Drop for ForcedLinks {
        fn drop(&mut self) {
            LINKS.with(|l| l.borrow_mut().clear());
        }
    }

    pub(super) fn take_link() -> Option<Link> {
        LINKS.with(|l| l.borrow_mut().pop_front())
    }
}

#[cfg(test)]
#[path = "tracer_watch_tests.rs"]
mod tracer_watch_tests;
