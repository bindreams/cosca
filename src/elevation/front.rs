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
/// `running` reads, without reaping, whether the tracked process still runs; `in_cgroup` whether it
/// is in a cgroup whose kill reaches it. Both are asked only about a front, and `in_cgroup` only
/// about one that may run: one that cannot be read is taken to run. A front `in_cgroup` cannot
/// place is asked `running` again: one that exited meanwhile, and that another thread's `wait`
/// reaped, has no cgroup left to read.
pub(crate) fn kill_gate(
    front: Option<Front>,
    pid: u32,
    running: impl Fn() -> io::Result<bool>,
    in_cgroup: impl FnOnce() -> io::Result<bool>,
) -> Gate {
    #[cfg(test)]
    seams::note_kill_gate();
    let Some(front) = front else {
        return Gate::Open;
    };
    let unread = match running() {
        Ok(false) => return Gate::Exited,
        Ok(true) => None,
        Err(e) => Some(format!("whether it had exited could not be read: {e}")),
    };
    #[cfg(test)]
    seams::run_between_gate_reads();
    let placed = in_cgroup();
    if !matches!(placed, Ok(true)) && matches!(running(), Ok(false)) {
        return Gate::Exited;
    }
    match placed {
        Ok(true) => Gate::CgroupOnly,
        Ok(false) => Gate::Closed(refused(front, pid, Signal::Kill, unread)),
        Err(e) => {
            let why = format!("whether its cgroup kill reaches it could not be read: {e}");
            let why = unread.map_or(why.clone(), |r| format!("{r}; {why}"));
            Gate::Closed(refused(front, pid, Signal::Kill, Some(why)))
        }
    }
}

/// Whether a cgroup kill, just written, reached the tracked process `pid`, the `front` its spawn
/// launched. The kill and a move out of the cgroup are serialised by the kernel (both writes take
/// `cgroup_mutex`), so what holds after the write says which came first:
///
/// - `exited`: it has exited, so nothing of it is left to kill.
/// - `under_leaf`: its cgroup is the leaf or one under it: by its pidfd's cgroup id on Linux 6.13
///   and later, then by `/proc/<pid>/cgroup` (see `containment::cgroup::Subtree::holds`). A killed
///   task keeps its cgroup until it is freed.
///
/// A front `under_leaf` does not place is asked `exited` again: one the kill ended meanwhile, and
/// that another thread's `wait` reaped, has no cgroup left to read, and has exited.
///
/// A front none of these places in the leaf left it before the kill, as pam_systemd moves sudo into
/// a session scope: it was not killed, and the answer is `Unkillable`, so nothing waits for it. So
/// is one whose place cannot be read: nothing shows the kill reached it. A front killed and then
/// moved before it exited reads as moved before its kill (measured on Linux 7.0): that answer is a
/// refusal of a kill that did land, never an `Ok` for one that did not.
pub(crate) fn cgroup_kill_reached(
    front: Option<Front>,
    pid: u32,
    exited: impl Fn() -> io::Result<bool>,
    under_leaf: impl FnOnce() -> io::Result<bool>,
) -> Result<(), Error> {
    let Some(front) = front else {
        debug_assert!(false, "only a front's cgroup kill is checked");
        return Ok(());
    };
    let mut unread = Vec::new();
    match exited() {
        Ok(true) => return Ok(()),
        Ok(false) => {}
        Err(e) => unread.push(format!("whether it had exited could not be read: {e}")),
    }
    #[cfg(test)]
    seams::run_between_reach_reads();
    let placed = under_leaf();
    if !matches!(placed, Ok(true)) && matches!(exited(), Ok(true)) {
        return Ok(());
    }
    let why = match placed {
        Ok(true) => return Ok(()),
        Ok(false) => "it reads as having left the cgroup before its kill, which did not reach it".to_owned(),
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

/// The refusal of a kill of the front `pid` whose cgroup kill failed with `error`: nothing else was
/// sent, since a kill of the front itself would orphan its elevated program.
pub(crate) fn cgroup_kill_failed(front: Option<Front>, pid: u32, error: Error) -> Error {
    let Some(front) = front else {
        debug_assert!(false, "only a front's cgroup kill is refused so");
        return error;
    };
    refused(
        front,
        pid,
        Signal::Kill,
        Some(format!("its cgroup kill failed: {error}")),
    )
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
    // Only Linux has a cgroup to reach the program through; osascript runs on macOS.
    if matches!(signal, Signal::Kill) && !matches!(front, Front::Osascript) {
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
        static BETWEEN_GATE_READS: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
        static BETWEEN_REACH_READS: crate::oneshot_hook::OneShotHook = const { crate::oneshot_hook::OneShotHook::new() };
    }

    /// Run `hook` once in the next kill gate on this thread, between its read of whether the front
    /// runs and its read of the front's cgroup.
    pub(crate) fn set_between_gate_reads(hook: impl FnOnce() + 'static) -> crate::oneshot_hook::Armed {
        crate::oneshot_hook::arm(&BETWEEN_GATE_READS, hook)
    }
    pub(super) fn run_between_gate_reads() {
        crate::oneshot_hook::fire(&BETWEEN_GATE_READS);
    }

    /// Run `hook` once in the next check of a cgroup kill on this thread, after the kill's write
    /// and its read of whether the front exited, before its read of the front's cgroup.
    pub(crate) fn set_between_reach_reads(hook: impl FnOnce() + 'static) -> crate::oneshot_hook::Armed {
        crate::oneshot_hook::arm(&BETWEEN_REACH_READS, hook)
    }
    pub(super) fn run_between_reach_reads() {
        crate::oneshot_hook::fire(&BETWEEN_REACH_READS);
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
