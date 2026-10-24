//! The watch a wait keeps on the tracers that hold its child.
//!
//! While a tracer holds a child, XNU sends the child's `NOTE_EXIT` to the tracer alone, and to the
//! parent only at the hand-back, when the tracer collects the zombie (xnu-12377.121.6
//! `kern_event.c:1200`, `kern_exit.c:2863-2902`). A tracer that exits hands back a zombie child at
//! once (`:2549`) and kills one still traced, which then exits as the parent's child
//! (`:2556-2603`). A child in neither state, exiting but not yet a zombie (`P_LTRACED` is cleared
//! at `:2278`), goes to launchd with `p_oppid` still naming the parent (`:2612-2613`): its
//! `NOTE_EXIT` and `SIGCHLD` reach the parent only if launchd waits on it. So a wait that finds its
//! child traced also watches the tracer's exit, whose `NOTE_EXIT` fires after that hand-over
//! (`:2704` against `:2528-2614`), and checks the child again when it wakes.
//!
//! The same holds for a tracer that is itself traced: its `NOTE_EXIT` reaches only its own tracer,
//! but its exit sends that tracer `SIGCHLD` (`:2747-2779`, taken whenever `p_oppid` is set). So the
//! watch follows the chain, tracer by tracer, to one whose `NOTE_EXIT` reaches this process, and
//! registers `NOTE_EXIT` and `NOTE_SIGNAL` on each. A tracer that attaches later, to the child or
//! to a tracer on the chain, reparents it and sends it `SIGSTOP` (`mach_process.c:295`, `:304`),
//! which `NOTE_SIGNAL` reports (`kern_sig.c:2126`, before any check of the signal's disposition);
//! the wait registers `NOTE_SIGNAL` on the child itself.
//!
//! A tracer that began its exit and then lost its own tracer goes to launchd with `p_oppid` set,
//! so neither its `NOTE_EXIT` nor its `SIGCHLD` reaches anything the wait watches. It hands the
//! child over once its exit reaches its children (`:2528`). Until then the wait checks again on a
//! backoff, as it does for a tracer already gone.

use std::time::Duration;

use nix::sys::event::{EventFilter, FilterFlag, KEvent, Kqueue};

use super::arm_exit_and_signals_on;
use crate::identity::{link, uniq_info, Link, ReadPurpose, UniqRead, LAUNCHD};

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
                Link::Gone => return Ok(self.gone()),
                Link::Refused(errno) => return Err(refused(at, errno)),
                Link::Unreadable => {
                    return Err(std::io::Error::other(format!(
                        "tracer {at}: who holds it could not be read (kinfo_proc refused)"
                    )))
                }
            };
            if !self.armed.contains(&(at, unique)) {
                let armed = arm_exit_and_signals_on(kq, at).map_err(|e| match e {
                    crate::error::Error::Io(e) => e,
                    other => std::io::Error::other(other),
                })?;
                if armed.is_none() {
                    return Ok(self.gone());
                }
                match uniq_info(at, ReadPurpose::Link) {
                    UniqRead::Found(info) if info.unique_id == unique => {}
                    UniqRead::Found(_) | UniqRead::Gone => return Ok(self.gone()),
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

fn refused(pid: u32, errno: i32) -> std::io::Error {
    std::io::Error::new(
        std::io::Error::from_raw_os_error(errno).kind(),
        format!("tracer {pid}: its identity could not be read (errno {errno})"),
    )
}
