//! Signalling a child whose tracked process an elevation wrapper chose: a *front*.
//!
//! `sudo` and `doas` without a pty, and macOS `osascript`, leave cosca tracking a process that runs
//! as the caller and outlives the elevated program it launched. A `SIGKILL` to that front is
//! allowed, and orphans the program instead of ending it. With direct exec (`!use_pty`,
//! `!pam_session`, or doas without PAM) the tracked process is the root program itself, whose
//! signal is refused. Which of the two cosca holds is not known at spawn.
//!
//! So a forced kill of a live front sends nothing, and the answer is `Unkillable`. Left alone, a
//! wrapper front exits only after its program, so `wait()` returns once the program is gone.
//!
//! A child contained in a Linux cgroup is not gated: its forced kills signal the tracked process
//! as any child's do.
//!
//! A `SIGTERM` is gated only for osascript, which would end and leave the program running, so
//! `terminate()` on it is refused like a kill. A sudo or doas front relays it to the program; with
//! direct exec the tracked process is the root program itself, which refuses it (`EPERM`).
//!
//! pkexec, a UAC child and an already-elevated child track the program itself and are signalled
//! like any child.

use std::io;

use super::{Backend, ElevatedVia};
use crate::error::{ElevationErrorKind, Error};

/// How a signal to a child may go.
#[derive(Debug)]
pub(crate) enum Gate {
    /// Not a front, or a child contained in a cgroup: signal it like any child.
    Open,
    /// A front that has exited. A kill answers `Ok`, as for any exited child, even where the
    /// signal to it would be refused (a root zombie keeps its credentials). `Ok` then means only
    /// that the front has exited: a front something else killed (the OOM killer, or this user) may
    /// have left its program running.
    Exited,
    /// A live front that nothing reaches past: send nothing, and answer this `Unkillable`.
    Closed(Error),
}

/// A front, and what a signal to it does. A tag, so a `Child` holding one stays small.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Front {
    Sudo,
    Doas,
    Osascript,
}

impl Front {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Front::Sudo => "sudo",
            Front::Doas => "doas",
            Front::Osascript => "osascript",
        }
    }

    /// The tracked process may be the program itself (direct exec), not the wrapper.
    fn may_be_the_program(self) -> bool {
        !matches!(self, Front::Osascript)
    }

    /// A `SIGTERM` to the front reaches the program.
    fn relays_term(self) -> bool {
        !matches!(self, Front::Osascript)
    }
}

/// The front `via` leaves this process tracking, if it does.
pub(crate) fn front(via: Option<&ElevatedVia>) -> Option<Front> {
    match via? {
        ElevatedVia::Wrapped(Backend::Sudo) => Some(Front::Sudo),
        ElevatedVia::Wrapped(Backend::Doas) => Some(Front::Doas),
        ElevatedVia::MacosOsascript => Some(Front::Osascript),
        // pkexec execs the program, and a report never names `Auto`.
        ElevatedVia::Wrapped(_) | ElevatedVia::WindowsUac | ElevatedVia::AlreadyElevated => None,
    }
}

/// The gate for a forced kill of the child `pid`, the `front` its spawn launched (if any).
/// `in_cgroup`: the child is contained in a Linux cgroup, whose children are not gated. `running`
/// reads, without reaping, whether the tracked process still runs, and is asked only about a front
/// outside a cgroup; one that cannot be read is taken to run.
pub(crate) fn kill_gate(
    front: Option<Front>,
    pid: u32,
    in_cgroup: bool,
    running: impl FnOnce() -> io::Result<bool>,
) -> Gate {
    #[cfg(test)]
    seams::note_kill_gate();
    let Some(front) = front.filter(|_| !in_cgroup) else {
        return Gate::Open;
    };
    match running() {
        Ok(false) => Gate::Exited,
        Ok(true) => Gate::Closed(refused(front, pid, Signal::Kill, None)),
        Err(e) => Gate::Closed(refused(
            front,
            pid,
            Signal::Kill,
            Some(format!("whether it had exited could not be read: {e}")),
        )),
    }
}

/// The gate for a `SIGTERM` to the child `pid`, the `front` its spawn launched (if any): closed only
/// for a live front that does not relay it. `running` is asked only about such a front.
pub(crate) fn terminate_gate(front: Option<Front>, pid: u32, running: impl FnOnce() -> io::Result<bool>) -> Gate {
    let Some(front) = front.filter(|f| !f.relays_term()) else {
        return Gate::Open;
    };
    match running() {
        Ok(false) => Gate::Open,
        Ok(true) => Gate::Closed(refused(front, pid, Signal::Term, None)),
        Err(e) => Gate::Closed(refused(
            front,
            pid,
            Signal::Term,
            Some(format!("whether it had exited could not be read: {e}")),
        )),
    }
}

/// What a front's detail names, for the child `pid` (unknown: `None`).
pub(crate) fn describe(front: Front, pid: impl Into<Option<u32>>) -> String {
    let subject = pid
        .into()
        .map_or_else(|| "the spawned child".to_owned(), |pid| format!("pid {pid}"));
    if front.may_be_the_program() {
        format!(
            "{subject} is what {name} left this process tracking: {name} itself, which runs as this user and \
             outlives the elevated program it launched, so a kill would orphan the program, or, with direct exec, \
             the root program itself, whose kill is refused",
            name = front.name()
        )
    } else {
        format!(
            "{subject} is {name}, which runs as this user and outlives the elevated program it launched, so a signal \
             would end {name} and orphan the program",
            name = front.name()
        )
    }
}

#[derive(Clone, Copy)]
enum Signal {
    Kill,
    Term,
}

fn refused(front: Front, pid: u32, signal: Signal, unread: Option<String>) -> Error {
    let what = match signal {
        Signal::Kill => "no kill",
        Signal::Term => "no SIGTERM",
    };
    let mut detail = format!("{}; {what} was sent.", describe(front, pid));
    if let Some(why) = unread {
        detail.push_str(&format!(" ({why})"));
    }
    Error::Elevation {
        kind: ElevationErrorKind::Unkillable,
        detail,
    }
}

/// Test seams.
#[cfg(test)]
pub(crate) mod seams {
    use std::cell::Cell;

    thread_local! {
        static GATES: Cell<Option<u32>> = const { Cell::new(None) };
    }

    /// From now on kill-gate evaluations on THIS thread are counted.
    pub(crate) fn count_kill_gates() -> GateCounter {
        GATES.with(|g| g.set(Some(0)));
        GateCounter(())
    }

    #[must_use = "counting stops as soon as the counter is dropped"]
    pub(crate) struct GateCounter(());

    impl GateCounter {
        pub(crate) fn count(&self) -> u32 {
            GATES.with(|g| g.get().expect("the counter is live"))
        }
    }

    impl Drop for GateCounter {
        fn drop(&mut self) {
            GATES.with(|g| g.set(None));
        }
    }

    pub(super) fn note_kill_gate() {
        GATES.with(|g| {
            if let Some(n) = g.get() {
                g.set(Some(n + 1));
            }
        });
    }
}

#[cfg(test)]
#[path = "front_tests.rs"]
mod front_tests;
