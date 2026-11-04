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
//!
//! One child has no such word at all: a UAC-elevated one, created on cosca's behalf by a system
//! service. It reports [`GracefulMechanism::Unknown`], which
//! [`Child::terminate`](crate::Child::terminate) refuses.

use crate::error::Error;

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
    /// Windows: **cosca did not create this child.** A system service creates the UAC-elevated
    /// child, with creation flags this process never sees, so whether it leads a console process
    /// group of its own is unknowable from here — and a pid that leads none addresses its
    /// leader's whole group instead. Refused, not attempted.
    Unknown,
    /// Windows: the child leads no process group of its own, and group leadership is fixed at
    /// creation — so no console control event can be addressed to it ALONE by any process,
    /// ever; one aimed at its pid reaches its leader's whole group instead.
    None,
}

// Gated on `tokio` as well as Windows: the async `Child` is the only handle that can stop
// pinning its child's pid, so it is the only caller this distinction exists for.
#[cfg(all(windows, feature = "tokio"))]
impl GracefulMechanism {
    /// Whether the signal this mechanism names is addressed to a **bare pid** — no handle, no
    /// identity check — so a caller whose handle has stopped pinning that pid must refuse rather
    /// than fire it at whatever the OS has since reissued it to. The mechanisms that send
    /// nothing at all are false: their refusal is permanent and pid-independent, and reporting
    /// it as a pinning problem would name the wrong cause and the wrong error variant.
    ///
    /// Matched exhaustively, like [`signal`], so a future variant must decide this too.
    pub(crate) fn addresses_a_bare_pid(self) -> bool {
        match self {
            GracefulMechanism::ConsoleGroup | GracefulMechanism::OtherConsoleGroup => true,
            // Identity-bound (`crate::os_process::terminate_by_id`), and unconstructible on Windows anyway.
            GracefulMechanism::Process => false,
            GracefulMechanism::Unknown | GracefulMechanism::None => false,
        }
    }
}

impl std::fmt::Display for GracefulMechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            GracefulMechanism::Process => "process",
            GracefulMechanism::ConsoleGroup => "own console group",
            GracefulMechanism::OtherConsoleGroup => "own console group in another console",
            GracefulMechanism::Unknown => "unknown",
            GracefulMechanism::None => "none",
        };
        f.write_str(s)
    }
}

/// Send the cooperative signal `mechanism` names to the child with identity `id`. Signal-only:
/// does not wait or reap. The crate's single dispatch point — every cooperative signal to an
/// owned child funnels through here.
///
/// `signal_root` sends a [`Sig`](crate::signal::Sig) to the root through the caller's own handle;
/// the Unix `Process` mechanism calls it with `Sig::Term`. On Windows that mechanism is
/// `Unsupported` and does not call it. The console mechanisms address `id`'s pid and do not call
/// it.
///
/// Matched exhaustively with no wildcard, so a future variant is a compile error at the one
/// place this decision is made.
pub(crate) fn signal(
    mechanism: GracefulMechanism,
    id: crate::identity::ProcessId,
    signal_root: impl FnOnce(crate::signal::Sig) -> Result<(), crate::error::Error>,
) -> Result<(), crate::error::Error> {
    // Each platform's arms use one of the two.
    #[cfg(unix)]
    let _ = id;
    #[cfg(windows)]
    drop(signal_root);
    match mechanism {
        #[cfg(unix)]
        GracefulMechanism::Process => signal_root(crate::signal::Sig::Term),
        #[cfg(windows)]
        GracefulMechanism::Process => crate::os_process::terminate_by_id(id),
        // One arm for both. This process's console list is readable, but absence from it does
        // not imply undeliverable (see `containment::windows::terminate`), and refusing
        // `OtherConsoleGroup` would refuse a child that re-attached itself to our console after
        // it started.
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
        GracefulMechanism::Unknown => Err(crate::error::Error::Unsupported {
            op: "graceful terminate".into(),
            platform: std::env::consts::OS,
            detail: "cosca did not create this child — a system elevation service did — so \
                     whether it leads a console process group of its own is unknown, and an \
                     event addressed to its pid would reach its leader's whole group instead. \
                     Use kill() for a hard teardown."
                .into(),
        }),
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

/// What a graceful shutdown does once its grace wait has returned, for a lone process. `watch` is
/// the wait's result: `Ok(true)` means the process exited in time and `kill` is not called.
/// Otherwise (the grace ran out, or the wait itself failed, so the grace was unobservable)
/// `kill` runs. A kill error wins; a watch error surfaces only after the kill succeeded.
pub(crate) fn after_grace(watch: Result<bool, Error>, kill: impl FnOnce() -> Result<(), Error>) -> Result<(), Error> {
    if matches!(watch, Ok(true)) {
        return Ok(());
    }
    if let Err(ref e) = watch {
        log::debug!("graceful_shutdown watch error before kill escalation (subsumed): {e}");
    }
    kill()?;
    watch.map(|_| ())
}

/// The tree twin of [`after_grace`]: `sweep` always runs, because a root that exited in grace
/// does not mean its descendants drained. A sweep error wins; a watch error surfaces only after
/// the sweep succeeded.
pub(crate) fn after_tree_grace(
    watch: Result<bool, Error>,
    sweep: impl FnOnce() -> Result<(), Error>,
) -> Result<(), Error> {
    if let Err(ref e) = watch {
        log::debug!("graceful_shutdown_tree watch error before the sweep (may be subsumed): {e}");
    }
    sweep()?;
    watch.map(|_| ())
}

#[cfg(test)]
#[path = "graceful_tests.rs"]
mod graceful_tests;
