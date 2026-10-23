//! The watch a wait keeps on the tracer that holds its child.
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
//! What it cannot see: a tracer that attaches after the wait's last check, or a tracer that is
//! itself traced, whose own `NOTE_EXIT` reaches the wait only at its tracer's hand-back.

use std::time::Duration;

use nix::sys::event::{EventFilter, KEvent, Kqueue};

use super::arm_note_exit_on;

/// The first re-check after a tracer is found gone, and the cap on the backoff between later ones.
const GONE_START: Duration = Duration::from_millis(1);
const GONE_CAP: Duration = Duration::from_millis(50);

/// What a wait does after its check found the child held by a tracer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnTracer {
    /// Block until an event: the tracer's exit is watched.
    Block,
    /// Check the child again first, after waiting at most this long (zero: at once).
    Recheck(Duration),
}

/// The tracer a wait watches. One per wait, on the wait's own kqueue.
#[derive(Debug, Default)]
pub(crate) struct TracerWatch {
    /// The tracer whose `NOTE_EXIT` is registered, by a registration made before the check that
    /// last named it.
    armed: Option<u32>,
    /// The tracer last found gone (`ESRCH`), and the backoff before the next check.
    gone: Option<(u32, Duration)>,
}

impl TracerWatch {
    /// The wait's check found the child held by `tracer`, a process that is neither this one nor
    /// launchd. Registers `NOTE_EXIT` on it once. The wait may block only on a check made after
    /// that registration: before it, the tracer may have exited unseen. A tracer already gone
    /// (`ESRCH`) has not necessarily released the child yet (its exit hands the child over after
    /// the point where it can no longer be found), so the wait checks again, at once the first
    /// time and then with a backoff (1 ms doubling to 50 ms, no cap on rounds) while the child
    /// still names it.
    pub(crate) fn held_by(&mut self, kq: &Kqueue, tracer: u32) -> std::io::Result<OnTracer> {
        if self.armed == Some(tracer) {
            return Ok(OnTracer::Block);
        }
        let armed = arm_note_exit_on(kq, tracer).map_err(|e| match e {
            crate::error::Error::Io(e) => e,
            other => std::io::Error::other(other),
        })?;
        if armed.is_some() {
            self.armed = Some(tracer);
            self.gone = None;
            return Ok(OnTracer::Recheck(Duration::ZERO));
        }
        let wait = match self.gone {
            Some((gone, wait)) if gone == tracer => (wait * 2).clamp(GONE_START, GONE_CAP),
            _ => Duration::ZERO,
        };
        self.gone = Some((tracer, wait));
        Ok(OnTracer::Recheck(wait))
    }

    /// Whether `event` is the watched tracer's exit, for a wait on `child`. Its knote is one-shot,
    /// so the next check registers again.
    pub(crate) fn fired(&mut self, event: &KEvent, child: u32) -> bool {
        let fired = event.filter() == Ok(EventFilter::EVFILT_PROC) && event.ident() != child as usize;
        if fired {
            self.armed = None;
        }
        fired
    }
}
