//! Signalling a child whose tracked process an elevation wrapper chose: a *front*.
//!
//! `sudo` and `doas` without a pty, and macOS `osascript`, leave cosca tracking a process that runs
//! as the caller and outlives the elevated program it launched. A `SIGKILL` to that front is
//! allowed, and orphans the program instead of ending it. With direct exec (`!use_pty`,
//! `!pam_session`, or doas without PAM) the tracked process is the root program itself, whose
//! signal is refused. Which of the two cosca holds is not known at spawn.
//!
//! So a forced kill never signals a live front. It goes through a cgroup whose `cgroup.kill`
//! reaches the tracked process whatever its credentials, and nothing is signalled after it. Whether
//! the kill reached the tracked process is read after the write ([`cgroup_kill_reached`]): a front
//! that left the cgroup in between was not killed. Without a cgroup, nothing is sent and the answer
//! is `Unkillable`.
//!
//! Left alone, a wrapper front exits only after its program, so `wait()` returns once the program
//! is gone. A cgroup kill is asynchronous, though: `wait()` then returns once the front is reaped,
//! and a program stuck in uninterruptible sleep can outlive it. Only `wait_tree()` observes the
//! program's own end.
//!
//! A `SIGTERM` is gated only for osascript. sudo and doas relay it to the program; osascript would
//! end, leaving the program running, so `terminate()` on it is refused like a kill.
//!
//! pkexec, a UAC child and an already-elevated child track the program itself and are signalled
//! like any child.

use std::io;

use super::{Backend, ElevatedVia};
use crate::error::{ElevationErrorKind, Error};

/// How a signal to a child may go.
#[derive(Debug)]
pub(crate) enum Gate {
    /// Not a front: signal it like any child.
    Open,
    /// A front that has exited. A kill answers `Ok`, as for any exited child, even where the
    /// signal to it would be refused (a root zombie keeps its credentials). `Ok` then means only
    /// that the front has exited: a front something else killed (the OOM killer, or this user) may
    /// have left its program running.
    Exited,
    /// A live front in a cgroup: kill the cgroup, and signal nothing after it.
    CgroupOnly,
    /// A live front that nothing reaches past: send nothing, and answer this `Unkillable`.
    Closed(Error),
}

/// A front, and what a signal to it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Front {
    pub(crate) name: &'static str,
    /// The tracked process may be the program itself (direct exec), not the wrapper.
    may_be_the_program: bool,
    /// A `SIGTERM` to the front reaches the program.
    relays_term: bool,
}

/// The front `via` leaves this process tracking, if it does.
pub(crate) fn front(via: Option<&ElevatedVia>) -> Option<Front> {
    let wrapper = |name| Front {
        name,
        may_be_the_program: true,
        relays_term: true,
    };
    match via? {
        ElevatedVia::Wrapped(Backend::Sudo) => Some(wrapper("sudo")),
        ElevatedVia::Wrapped(Backend::Doas) => Some(wrapper("doas")),
        ElevatedVia::MacosOsascript => Some(Front {
            name: "osascript",
            may_be_the_program: false,
            relays_term: false,
        }),
        // pkexec execs the program, and a report never names `Auto`. run0 is left as it was: its
        // backend is being removed (#354).
        ElevatedVia::Wrapped(_) | ElevatedVia::WindowsUac | ElevatedVia::AlreadyElevated => None,
    }
}

/// The gate for a forced kill of the child `pid` that `via` launched. `running` reads, without
/// reaping, whether the tracked process still runs; `in_cgroup` whether it is in a cgroup whose
/// kill reaches it. Both are asked only about a front, and `in_cgroup` only about one that may run:
/// one that cannot be read is taken to run.
pub(crate) fn kill_gate(
    via: Option<&ElevatedVia>,
    pid: u32,
    running: impl FnOnce() -> io::Result<bool>,
    in_cgroup: impl FnOnce() -> io::Result<bool>,
) -> Gate {
    #[cfg(test)]
    seams::note_kill_gate();
    let Some(front) = front(via) else {
        return Gate::Open;
    };
    let running = match running() {
        Ok(false) => return Gate::Exited,
        Ok(true) => None,
        Err(e) => Some(format!("whether it had exited could not be read: {e}")),
    };
    match in_cgroup() {
        Ok(true) => Gate::CgroupOnly,
        Ok(false) => Gate::Closed(refused(front, pid, Signal::Kill, running)),
        Err(e) => {
            let why = format!("whether its cgroup kill reaches it could not be read: {e}");
            let why = running.map_or(why.clone(), |r| format!("{r}; {why}"));
            Gate::Closed(refused(front, pid, Signal::Kill, Some(why)))
        }
    }
}

/// Whether a cgroup kill, just written, reached the tracked process `pid` of the front `via`
/// launched. The kill and a move out of the cgroup are serialised by the kernel (both writes take
/// `cgroup_mutex`), so what holds after the write says which came first:
///
/// - `listed`: `pid` is in the leaf's `cgroup.procs`, so it was there for the kill.
/// - `exited`: it has exited, so nothing of it is left to kill.
/// - `under_leaf`: its `/proc/<pid>/cgroup` names the leaf or a cgroup under it. A killed task
///   keeps naming its cgroup until it is freed, after it has left `cgroup.procs` on its way out.
///
/// A front none of these places in the leaf left it before the kill, as pam_systemd moves sudo into
/// a session scope: it was not killed, and the answer is `Unkillable`, so nothing waits for it. So
/// is one whose place cannot be read (a `hidepid` `/proc` hides a root program): nothing shows the
/// kill reached it. A front killed and then moved before it exited reads as moved too (measured on
/// Linux 7.0): that answer is a refusal of a kill that did land, never an `Ok` for one that did not.
pub(crate) fn cgroup_kill_reached(
    via: Option<&ElevatedVia>,
    pid: u32,
    listed: impl FnOnce() -> io::Result<bool>,
    exited: impl FnOnce() -> io::Result<bool>,
    under_leaf: impl FnOnce() -> io::Result<bool>,
) -> Result<(), Error> {
    let Some(front) = front(via) else {
        debug_assert!(false, "only a front's cgroup kill is checked");
        return Ok(());
    };
    let mut unread = Vec::new();
    match listed() {
        Ok(true) => return Ok(()),
        Ok(false) => {}
        Err(e) => unread.push(format!("its cgroup's member list could not be read: {e}")),
    }
    match exited() {
        Ok(true) => return Ok(()),
        Ok(false) => {}
        Err(e) => unread.push(format!("whether it had exited could not be read: {e}")),
    }
    let why = match under_leaf() {
        Ok(true) => return Ok(()),
        Ok(false) => "it had left the cgroup before its kill, which did not reach it".to_owned(),
        Err(e) => {
            unread.push(format!("its cgroup could not be read: {e}"));
            "nothing shows the cgroup kill reached it".to_owned()
        }
    };
    let why = if unread.is_empty() {
        why
    } else {
        format!("{why} ({})", unread.join("; "))
    };
    Err(refused(front, pid, Signal::Kill, Some(why)))
}

/// The gate for a `SIGTERM` to the child `pid` that `via` launched: closed only for a live front
/// that does not relay it. `running` is asked only about such a front.
pub(crate) fn terminate_gate(via: Option<&ElevatedVia>, pid: u32, running: impl FnOnce() -> io::Result<bool>) -> Gate {
    let Some(front) = front(via).filter(|f| !f.relays_term) else {
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

/// What a front's detail names, for a child left running elsewhere (a failed spawn's teardown).
pub(crate) fn describe(front: Front, pid: u32) -> String {
    if front.may_be_the_program {
        format!(
            "pid {pid} is what {name} left this process tracking: {name} itself, which runs as this user and \
             outlives the elevated program it launched, so a kill would orphan the program, or, with direct exec, \
             the root program itself, whose kill is refused",
            name = front.name
        )
    } else {
        format!(
            "pid {pid} is {name}, which runs as this user and outlives the elevated program it launched, so a signal \
             would end {name} and orphan the program",
            name = front.name
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
    if matches!(signal, Signal::Kill) {
        detail.push_str(" Only a cgroup (Linux containment) that holds it reaches the program.");
    }
    if let Some(why) = unread {
        detail.push_str(&format!(" ({why})"));
    }
    Error::Elevation {
        kind: ElevationErrorKind::Unkillable,
        detail,
    }
}

/// Test seam counting kill-gate evaluations on this thread, so a test can show a kill path decides
/// once and does not re-ask the gate after its cgroup kill. Thread-local, with an RAII reset.
#[cfg(test)]
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "only the Linux cgroup lane's tests count gates")
)]
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
