//! A forced kill of a child whose tracked process is an elevation *front*.
//!
//! `sudo` and `doas` without a pty, and macOS `osascript`, leave cosca tracking a process that runs
//! as the caller and outlives the elevated program it launched. A `SIGKILL` to that front is
//! allowed, and orphans the program instead of ending it. So no forced kill signals a live front:
//! it goes through a cgroup, whose `cgroup.kill` reaches the program whatever its credentials, or
//! it sends nothing and answers `Unkillable`. The front is left alone, so `wait()` still returns
//! only once the program is gone. `terminate()` is not gated: `sudo` and `doas` relay `SIGTERM`.
//!
//! `sudo` with a pty would end the program when its front dies, and `sudo` with direct exec tracks
//! the root program itself, whose signal is refused. Neither is known at spawn, so both are
//! treated as fronts; for direct exec that is the answer the refused signal gives. pkexec, a UAC
//! child and an already-elevated child track the program itself and are signalled like any child.

use std::io;

use super::{Backend, ElevatedVia};
use crate::error::{ElevationErrorKind, Error};

/// How a forced kill of a child may go.
#[derive(Debug)]
pub(crate) enum Gate {
    /// Not a front, or a front that has exited: kill it like any child.
    Open,
    /// A live front in a cgroup: kill the cgroup, and signal the front only if that succeeded.
    CgroupFirst,
    /// A live front that nothing reaches past: send nothing, and answer this `Unkillable`.
    Closed(Error),
}

/// The front `via`'s tracked process is, if it is one.
pub(crate) fn front(via: Option<&ElevatedVia>) -> Option<&'static str> {
    match via? {
        ElevatedVia::Wrapped(Backend::Sudo) => Some("sudo"),
        ElevatedVia::Wrapped(Backend::Doas) => Some("doas"),
        ElevatedVia::MacosOsascript => Some("osascript"),
        // pkexec execs the program, and a report never names `Auto`. run0 is left as it was: its
        // backend is being removed (#354).
        ElevatedVia::Wrapped(_) | ElevatedVia::WindowsUac | ElevatedVia::AlreadyElevated => None,
    }
}

/// The gate for a forced kill of the child `pid` that `via` launched. `cgroup`: its tree is a
/// cgroup. `running` reads, without reaping, whether the tracked process is still running; it is
/// asked only about a front. A front that cannot be read is taken to be running.
pub(crate) fn gate(
    via: Option<&ElevatedVia>,
    pid: u32,
    cgroup: bool,
    running: impl FnOnce() -> io::Result<bool>,
) -> Gate {
    let Some(front) = front(via) else {
        return Gate::Open;
    };
    match running() {
        Ok(false) => Gate::Open,
        _ if cgroup => Gate::CgroupFirst,
        Ok(true) => Gate::Closed(unkillable(front, pid, None)),
        Err(e) => Gate::Closed(unkillable(front, pid, Some(e))),
    }
}

fn unkillable(front: &str, pid: u32, unread: Option<io::Error>) -> Error {
    let mut detail = format!(
        "pid {pid} is {front}, which runs as this user and outlives the elevated program it launched; killing it \
         would orphan the program, not end it, so nothing was sent. Only cgroup containment (Linux) reaches the \
         program"
    );
    if let Some(e) = unread {
        detail.push_str(&format!(". Whether {front} had exited could not be read: {e}"));
    }
    Error::Elevation {
        kind: ElevationErrorKind::Unkillable,
        detail,
    }
}

#[cfg(test)]
#[path = "front_tests.rs"]
mod front_tests;
