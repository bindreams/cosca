//! `Child` bounded waits. A submodule of `child` so it can reach `Child`'s private
//! `proc` handle.

use std::io;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use super::owned::teardown::Disposition;
use super::owned::{ChildWaitOutcome, OwnedChild};
use super::spawn::FrontFate;
use super::Child;
use crate::error::{ChildFate, Error};
use crate::identity::ProcessId;
use crate::os_process::child::{ExitRecord, Foreign};
use crate::os_process::PIDLESS_CHILD;
use crate::wait::teardown_warn::{wait_warning, Due};

/// Whether a wait that finds the child's zombie held by launchd (macOS) says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Orphaned {
    /// The wait reports it: the caller has nobody else to.
    Warn,
    /// The caller reports it itself, with the refusal it goes on to make, or has nothing to report.
    Quiet,
}

/// A wait's `outcome` on the child `pid` as the status `Child` answers: `Some` for an exit
/// (`Unreadable` is `InvalidData`), `None` for a deadline that passed.
pub(super) fn status_of_outcome(
    pid: Option<u32>,
    outcome: ChildWaitOutcome,
    orphaned: Orphaned,
) -> Result<Option<ExitStatus>, Error> {
    match outcome {
        ChildWaitOutcome::Exited(ExitRecord::Status(status)) => Ok(Some(status)),
        ChildWaitOutcome::Exited(ExitRecord::Unreadable { si_code }) => Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            unreadable(si_code),
        ))),
        ChildWaitOutcome::Foreign(foreign) => {
            if foreign == Foreign::Orphaned && orphaned == Orphaned::Warn {
                log::warn!("{}", orphaned_note(pid));
            }
            Err(Error::Io(echild()))
        }
        ChildWaitOutcome::DeadlinePassed => Ok(None),
    }
}

/// What became of a child after a wait, or a look at the present moment, answered `answer`
/// (`killed`: a kill reached the child, delivered by this handle or by a containment kill that
/// reached it). The one classification of that answer, which every teardown, `finish_elevated` and
/// `Unreaped` asks for the fate, the fate of an elevation front, and what to say. Whether the child
/// is left uncollected (still this process's: neither reaped by it nor shown reaped elsewhere, so a
/// caller can hand it back) is the [`Wording`] variant, which is what the clause is built from.
///
/// | answer                       | [`fate`](Self::fate)  | uncollected                        | [`front_fate`](Self::front_fate) | [`wording`](Self::wording)                                  |
/// | ---------------------------- | --------------------- | ---------------------------------- | -------------------------------- | ----------------------------------------------------------- |
/// | `Exited(Status)`             | `Reaped`              | no                                 | `Reaped`                         | debug "reaped it" ("after the kill" only if `killed`)       |
/// | `Exited(Unreadable)`         | `Reaped`              | no                                 | `Reaped`                         | warn "reaped it; e" ("after the kill" only if `killed`)     |
/// | `Foreign(Gone, Other)`       | `f.fate(killed)`      | no                                 | `Unaccounted`                    | debug "reaped by someone else"                              |
/// | `Foreign(Orphaned)`          | `f.fate(killed)`      | no                                 | `Unaccounted`                    | warn "not ours to reap (launchd holds its zombie, ...)"     |
/// | `Err(e)`, `killed`           | `Killed`              | yes                                | `Unaccounted`                    | warn "the wait failed: e", and where the child goes         |
/// | `Err(e)`, not `killed`       | `Unknown`             | yes                                | `Unaccounted`                    | as above                                                    |
/// | `DeadlinePassed`, not killed | `Running { id }`      | yes                                | `LeftUnreaped`                   | warn: the caller's running clause, or "its wait ended with no exit" for a wait with no deadline |
/// | `DeadlinePassed`, `killed`   | none: a kill is followed by a wait with no deadline, and [`new`](Self::new) asserts it | | |                                                  |
///
/// Every row has a clause, and every line leads with the caller's subject, a zombie launchd holds
/// included.
///
/// An unreadable record means the consuming reap took the zombie: the child was collected, only its
/// exit is lost, so it is `Reaped` whether or not a kill reached it.
#[derive(Debug)]
pub(crate) struct Settlement {
    answer: Result<ChildWaitOutcome, Error>,
    killed: bool,
}

impl Settlement {
    pub(crate) fn new(answer: Result<ChildWaitOutcome, Error>, killed: bool) -> Settlement {
        debug_assert!(
            !(killed && matches!(answer, Ok(ChildWaitOutcome::DeadlinePassed))),
            "a kill is followed by a wait with no deadline"
        );
        Settlement { answer, killed }
    }

    /// What became of the child, whose identity the caller read as `id`, if it did.
    pub(crate) fn fate(&self, id: Option<ProcessId>) -> ChildFate {
        match &self.answer {
            Ok(ChildWaitOutcome::Exited(_)) => ChildFate::Reaped,
            Ok(ChildWaitOutcome::Foreign(foreign)) => foreign.fate(self.killed),
            Err(_) if self.killed => ChildFate::Killed,
            Err(_) => ChildFate::Unknown,
            Ok(ChildWaitOutcome::DeadlinePassed) => ChildFate::Running { id },
        }
    }

    /// What became of an elevation front, which is sent nothing.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "only the Linux spawn words a front it looked at")
    )]
    pub(crate) fn front_fate(&self) -> FrontFate {
        match &self.answer {
            Ok(ChildWaitOutcome::Exited(_)) => FrontFate::Reaped,
            Ok(ChildWaitOutcome::Foreign(_)) | Err(_) => FrontFate::Unaccounted,
            Ok(ChildWaitOutcome::DeadlinePassed) => FrontFate::LeftUnreaped,
        }
    }

    /// Whether the wait ended with an answer about the child: everything but a deadline that passed.
    pub(crate) fn ended(&self) -> bool {
        !matches!(self.answer, Ok(ChildWaitOutcome::DeadlinePassed))
    }

    /// The exit status, if the child exited and its record was read.
    pub(crate) fn status(&self) -> Option<ExitStatus> {
        match &self.answer {
            Ok(ChildWaitOutcome::Exited(ExitRecord::Status(status))) => Some(*status),
            _ => None,
        }
    }

    /// Why the child's exit record could not be read, if it could not: the child was reaped, and
    /// only its exit is lost.
    #[cfg(unix)]
    pub(crate) fn unreadable_record(&self) -> Option<String> {
        match &self.answer {
            Ok(ChildWaitOutcome::Exited(ExitRecord::Unreadable { si_code })) => Some(unreadable(*si_code)),
            _ => None,
        }
    }

    /// What to say of the child, and at what level: a clause for every answer, which the caller logs
    /// at that level or folds into its own warn. `subject` leads it. `running` is the whole line for
    /// a child still running; `None` for a wait with no deadline, which says it ended with no exit.
    /// `disposition` adds where an uncollected child goes; `None` for a caller that says so itself.
    pub(crate) fn wording(&self, subject: &str, running: Option<&str>, disposition: Option<Disposition>) -> Wording {
        let after = if self.killed { " after the kill" } else { "" };
        match &self.answer {
            Ok(ChildWaitOutcome::Exited(ExitRecord::Status(_))) => {
                Wording::Collected(log::Level::Debug, format!("{subject}: reaped it{after}"))
            }
            Ok(ChildWaitOutcome::Exited(ExitRecord::Unreadable { si_code })) => Wording::Collected(
                log::Level::Warn,
                format!("{subject}: reaped it{after}; {}", unreadable(*si_code)),
            ),
            Ok(ChildWaitOutcome::Foreign(Foreign::Orphaned)) => {
                Wording::Collected(log::Level::Warn, format!("{subject}: {ORPHANED}"))
            }
            Ok(ChildWaitOutcome::Foreign(_)) => {
                Wording::Collected(log::Level::Debug, format!("{subject}: reaped by someone else"))
            }
            Err(e) => Wording::Uncollected(format!(
                "{subject}: the wait failed: {e}{}",
                disposition.map_or("", |disposition| disposition.suffix(true))
            )),
            Ok(ChildWaitOutcome::DeadlinePassed) => Wording::Uncollected(
                running.map_or_else(|| format!("{subject}: its wait ended with no exit"), str::to_owned),
            ),
        }
    }
}

/// What a [`Settlement`] says of the child: the clause of a child the caller collected, at the level
/// it is said at, or the warn of one it did not. A child still this process's has no level to
/// choose: its clause is a warn, so a clause that is not cannot be built for it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Wording {
    /// Reaped by this process, or shown reaped elsewhere.
    Collected(log::Level, String),
    /// Still this process's: neither reaped by it nor shown reaped elsewhere; the text is a warn.
    Uncollected(String),
}

impl Wording {
    /// The level the clause is said at.
    pub(crate) fn level(&self) -> log::Level {
        match self {
            Wording::Collected(level, _) => *level,
            Wording::Uncollected(_) => log::Level::Warn,
        }
    }

    /// The clause.
    pub(crate) fn text(&self) -> &str {
        match self {
            Wording::Collected(_, text) | Wording::Uncollected(text) => text,
        }
    }
}

/// Block until `proc` is reaped, and answer how the wait ended, never with a deadline passed.
///
/// With `due`, it first waits as the handle does, bounded by the threshold, and warns once if the
/// wait ends with the deadline passed ([`wait_warning`]). That watch is the handle's own wait, not a
/// look at whether the child exited: a zombie a tracer holds is visible as exited but cannot be
/// reaped, so it is "not ended" until it can be. Any other outcome of the bounded wait (an exit, a
/// foreign reap, a failure) is the result, and nothing waits again. Only after the warn does the
/// unbounded wait run.
pub(super) fn wait_to_exit(proc: &OwnedChild, due: Option<Due>) -> Result<ChildWaitOutcome, Error> {
    #[cfg(feature = "tokio")]
    crate::bounded::assert_may_block("a wait for a child's exit");
    let pid = proc.pid();
    // The state carries the bounded wait's answer to `wait` when it is the result.
    let answer = wait_warning(
        (proc, None),
        due,
        |(proc, answer), until| {
            let bounded = proc.wait(Some(until));
            let ended = !matches!(bounded, Ok(ChildWaitOutcome::DeadlinePassed));
            if ended {
                *answer = Some(bounded);
            }
            ended
        },
        |after| crate::child::spawn::warn_still_waiting(pid, after),
        |(proc, answer)| answer.unwrap_or_else(|| proc.wait(None)),
    );
    debug_assert!(
        !matches!(answer, Ok(ChildWaitOutcome::DeadlinePassed)),
        "an unbounded wait ended with no exit"
    );
    answer
}

/// [`wait_to_exit`] with no threshold, as the status the public blocking waits answer:
/// `Child::wait`, `Unreaped::wait` and `Child::wait_root` with `None`. `Unreaped::wait_async` does
/// not go through it (it blocks nowhere); it shares only [`unbounded_status`].
pub(super) fn wait_for_status(proc: &OwnedChild, orphaned: Orphaned) -> Result<ExitStatus, Error> {
    unbounded_status(proc.pid(), wait_to_exit(proc, None)?, orphaned)
}

/// The status an unbounded wait's `outcome` on the child `pid` answers: a deadline that passed is
/// an error, since there was none.
pub(super) fn unbounded_status(
    pid: Option<u32>,
    outcome: ChildWaitOutcome,
    orphaned: Orphaned,
) -> Result<ExitStatus, Error> {
    status_of_outcome(pid, outcome, orphaned)?
        .ok_or_else(|| Error::Io(io::Error::other("an unbounded wait ended with no exit")))
}

/// The error of an exit record a consuming `waitid` could not read.
fn unreadable(si_code: i32) -> String {
    format!("the child's exit record was unreadable (si_code {si_code})")
}

/// What to say of a zombie launchd holds, after the child's name.
const ORPHANED: &str = "not ours to reap (launchd holds its zombie, because its tracer died)";

/// What to say of a child whose zombie launchd holds.
pub(super) fn orphaned_note(pid: Option<u32>) -> String {
    format!(
        "{}: {ORPHANED}",
        pid.map_or_else(|| PIDLESS_CHILD.to_owned(), |pid| format!("pid {pid}"))
    )
}

/// The `ECHILD` every wait answers when the child was reaped by someone else.
fn echild() -> io::Error {
    #[cfg(unix)]
    {
        io::Error::from_raw_os_error(libc::ECHILD)
    }
    #[cfg(windows)]
    {
        io::Error::other("the child was already reaped elsewhere")
    }
}

impl Child {
    /// Block up to `timeout` for the root process to exit. `Ok(Some(status))` =
    /// exited; `Ok(None)` = still running at expiry (not an error); `Err` = a wait
    /// failure. `Duration::ZERO` acts like [`try_wait`](Child::try_wait). Event-driven
    /// (no poll loop) and concurrent-safe with `kill` (the handle pins the child: a
    /// pidfd on Linux, the process handle on Windows, an unreaped zombie on macOS). Reaps **only the root**: a contained tree's descendants have
    /// no waitable handle. A `timeout` so large it would overflow `Instant` is treated as
    /// unbounded (blocks until exit) rather than panicking.
    pub fn wait_timeout(&self, timeout: Duration) -> Result<Option<ExitStatus>, Error> {
        self.wait_timeout_by(timeout, Orphaned::Warn)
    }

    /// [`wait_timeout`](Child::wait_timeout) that does not report a zombie launchd holds (macOS):
    /// for a caller that reports it with its own refusal.
    #[cfg(unix)]
    pub(crate) fn wait_timeout_quiet(&self, timeout: Duration) -> Result<Option<ExitStatus>, Error> {
        self.wait_timeout_by(timeout, Orphaned::Quiet)
    }

    fn wait_timeout_by(&self, timeout: Duration, orphaned: Orphaned) -> Result<Option<ExitStatus>, Error> {
        // The sync lone path's watch goes through `OwnedChild::wait`, not
        // `exited_by`, so it needs its own head of the shared watch fault seam.
        #[cfg(test)]
        if crate::wait::fault::take_force_watch_error() {
            return Err(crate::wait::fault::forced_watch_error());
        }
        // `Instant + Duration` panics on overflow (e.g. Duration::MAX). Convert to a deadline
        // with a saturating checked_add: on overflow the timeout is effectively infinite, so
        // block until exit.
        self.wait_root(crate::wait::now().checked_add(timeout), orphaned)
    }

    /// Like [`wait_timeout`](Child::wait_timeout) but against an absolute `deadline`
    /// (at or before now behaves like [`try_wait`](Child::try_wait)).
    ///
    /// Never returns `None` before the clock reaches `deadline`: `OwnedChild` decides expiry
    /// from the clock after every wake, never from a primitive's own "timed out".
    pub fn wait_deadline(&self, deadline: Instant) -> Result<Option<ExitStatus>, Error> {
        self.wait_root(Some(deadline), Orphaned::Warn)
    }

    /// One wait on the root through its handle, until `deadline` (`None`: for ever). `Ok(None)` is
    /// a deadline that passed with the root still running.
    pub(super) fn wait_root(&self, deadline: Option<Instant>, orphaned: Orphaned) -> Result<Option<ExitStatus>, Error> {
        match deadline {
            Some(deadline) => status_of_outcome(Some(self.pid()), self.proc.wait(Some(deadline))?, orphaned),
            None => wait_for_status(&self.proc, orphaned).map(Some),
        }
    }

    /// Block until every member of the contained tree has EXITED — not reaped; a status is
    /// never collected by this call, only the root's own `wait`/`wait_timeout` does that.
    /// Requires a mechanism with a real kernel drain edge (`Unsupported` otherwise — cgroup v2,
    /// a Windows job object, and the macOS fd marker have one; `ProcessGroup`/`Session`/
    /// `TreeWalk` and an uncontained or nested-`Delegated` child do not). Event-driven: no
    /// interval is chosen internally anywhere in this call's path.
    pub fn wait_tree(&self) -> Result<crate::containment::TreeDrain, Error> {
        self.require_drainable()?;
        self.attached.wait_drained(None)
    }

    /// Like [`wait_tree`](Child::wait_tree) but bounded by `timeout`. `TreeDrain::MembersRemain`
    /// at expiry is not an error. A `timeout` so large it would overflow `Instant` is treated as
    /// unbounded, matching [`wait_timeout`](Child::wait_timeout).
    pub fn wait_tree_timeout(&self, timeout: Duration) -> Result<crate::containment::TreeDrain, Error> {
        self.require_drainable()?;
        self.attached.wait_drained(crate::wait::deadline_from(timeout))
    }
}

#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod lifecycle_tests;
