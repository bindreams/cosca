//! Which cooperative shutdown signal a spawned child can be sent, and how far it reaches.
//!
//! Tree ownership and cooperative-signal mechanism are independent axes.
//! [`Containment`](crate::containment::Containment) / `Attached` answer "who tears this tree
//! down"; [`GracefulMechanism`] answers "what cooperative signal `terminate()` sends to this
//! child, and how far it goes". On Windows the two are correlated only because containment is
//! currently the only thing that sets `CREATE_NEW_PROCESS_GROUP` — a coincidence deliberately
//! encoded nowhere.
//!
//! The mechanism is a **spawn-time** fact, derived on Windows from the creation-flag word the
//! spawn actually passed to `CreateProcessW`. That word is a sound negative and an unsound
//! positive: a detaching or window-suppressing flag being present is enough to know the child is
//! not in this process's console, but no flag can establish that it is. A GUI-subsystem image
//! never attaches to its spawner's console whatever the flags say, and any child may
//! `FreeConsole`/`AllocConsole`/`AttachConsole` after it starts. So the mechanism says which
//! signal would be sent and whether this process has a route to send it — never that a given
//! call will arrive.

/// Which cooperative signal [`Child::terminate`](crate::Child::terminate) sends to a child, how
/// far that signal reaches when it is delivered, and whether this process has a route to deliver
/// it. Queried via [`Child::graceful_mechanism`](crate::Child::graceful_mechanism).
///
/// A spawn-time fact, not a delivery guarantee: see the module doc for what the value does and
/// does not claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GracefulMechanism {
    /// Unix: an identity-bound `SIGTERM` to this process alone.
    Process,
    /// Windows: a console control event to the child's own console process group, whose
    /// delivery **from this process** the creation flags do not exclude. Not a guarantee, and
    /// not established per call.
    ConsoleGroup,
    /// Windows: **no in-process route.** This process's console is not the one the child would
    /// receive an event in; whether the child leads a group of its own is not knowable from
    /// here. Not "unreachable": a process attached to the child's own console can deliver an
    /// event.
    OtherConsoleGroup,
    /// Windows: the child leads no process group of its own, and group leadership is fixed at
    /// creation — so no per-child console control event can be addressed to it by any process,
    /// ever.
    None,
}

impl std::fmt::Display for GracefulMechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            GracefulMechanism::Process => "process",
            GracefulMechanism::ConsoleGroup => "own console group",
            GracefulMechanism::OtherConsoleGroup => "own console group in another console",
            GracefulMechanism::None => "none",
        };
        f.write_str(s)
    }
}

/// Send the cooperative signal `mechanism` names to the child with identity `id`. Signal-only:
/// does not wait or reap. The crate's single dispatch point — every cooperative signal to an
/// owned child funnels through here.
///
/// Matched exhaustively with no wildcard, so a future variant is a compile error at the one
/// place this decision is made.
pub(crate) fn signal(mechanism: GracefulMechanism, id: crate::identity::ProcessId) -> Result<(), crate::error::Error> {
    match mechanism {
        GracefulMechanism::Process => crate::wait::terminate(id),
        // One arm for both, because nothing in this process can tell them apart at signal time:
        // a console control event aimed at a group in another console reports success and
        // delivers nothing, and refusing `OtherConsoleGroup` would refuse a child that
        // re-attached itself to our console after it started.
        #[cfg(windows)]
        GracefulMechanism::ConsoleGroup | GracefulMechanism::OtherConsoleGroup => {
            crate::containment::windows::terminate(id.pid())
        }
        #[cfg(not(windows))]
        GracefulMechanism::ConsoleGroup | GracefulMechanism::OtherConsoleGroup => {
            debug_assert!(false, "a console-group mechanism is unconstructible off Windows");
            Err(crate::error::Error::Unsupported {
                op: "graceful terminate".into(),
                platform: std::env::consts::OS,
                detail: "internal invariant: a console-group mechanism reached signal off Windows".into(),
            })
        }
        GracefulMechanism::None => Err(crate::error::Error::Unsupported {
            op: "graceful terminate".into(),
            platform: std::env::consts::OS,
            detail: "this child leads no console process group of its own, so no console control \
                     event can be addressed to it by any process; group leadership is fixed at \
                     creation. Spawn it with contain() to give it one, or use kill() for a hard \
                     teardown."
                .into(),
        }),
    }
}

#[cfg(test)]
#[path = "graceful_tests.rs"]
mod graceful_tests;
