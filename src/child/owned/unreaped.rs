//! [`Unreaped`]: a child a failed spawn or a failed `status`, `output` or `read` could not end,
//! handed to the caller who owns it.

use std::process::ExitStatus;

use super::slot::ChildSlot;
use super::teardown::{Disposition, LEAVING_RUNNING, LEFT};
use super::OwnedChild;
#[cfg(feature = "tokio")]
use crate::child::lifecycle::unbounded_status;
use crate::child::lifecycle::{wait_for_status, wait_to_exit, Orphaned, Settlement};
use crate::error::Error;
use crate::identity::ProcessId;
use crate::os_process::child_named;
use crate::signal::{Sent, Sig};

/// A child a failed spawn, or a sync [`Command::status`](crate::Command::status),
/// [`output`](crate::Command::output) or [`read`](crate::Command::read) that failed after it, could
/// not end: its kill was refused (`EPERM`, `ACCESS_DENIED`), or it is an elevation front, which is
/// sent none, or the wait for it failed after the kill; and it is not known to have been collected.
/// Its fate in the error is one of a child not known to be collected; see [`Error::MayHaveStarted`],
/// which it comes back in and the caller owns from then on.
///
/// Settle it with [`wait`](Unreaped::wait), which blocks until the child exits and reaps it, or
/// [`leak`](Unreaped::leak), which gives it up. A value dropped otherwise does what `wait` does,
/// then logs one line naming the child. So the drop blocks: in async code, settle it with
/// [`wait_async`](Unreaped::wait_async) (the `tokio` feature) or `leak` it. A front is waited for
/// until it exits, which the failed call would have done anyway.
///
/// A value dropped while its thread is panicking does not wait: it gives the child up, which keeps
/// running unreaped until this process exits, and logs one `warn` naming its pid. A cancelled
/// [`wait_async`](Unreaped::wait_async) does not block either: see there.
///
/// ```
/// use cosca::error::Error;
///
/// fn settle(error: Error) {
///     if let Error::MayHaveStarted { unreaped: Some(child), .. } = error {
///         eprintln!("waiting for pid {:?}", child.pid());
///         match child.wait() {
///             Ok(status) => eprintln!("it exited: {status}"),
///             Err(e) => eprintln!("could not wait for it: {e}"),
///         }
///     }
/// }
/// ```
#[derive(Debug)]
pub struct Unreaped {
    /// Empty once `wait`, `leak` or the drop has taken the child: it is settled once.
    child: ChildSlot,
    id: Option<ProcessId>,
    /// Whether the child is an elevation front, which the drop sends no kill.
    front: bool,
    drop_kind: DropKind,
}

/// What dropping an [`Unreaped`] that still holds its child does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DropKind {
    /// Block until the child exits and reap it; while the thread is panicking, give it up and warn.
    Wait,
    /// Kill it once more (not a front), look once without waiting and reap it if it exited; warn
    /// once naming the pid, and if it was not reaped, give it up, unreaped. A child someone else
    /// reaped is logged at `debug` instead, unless the kill was refused.
    LetGo,
}

impl Unreaped {
    /// Own `child`, whose identity the spawn read as `id`, if it did; `front`: it is an elevation
    /// front. Its drop waits.
    pub(crate) fn new(child: OwnedChild, id: Option<ProcessId>, front: bool) -> Unreaped {
        Unreaped {
            child: ChildSlot::new(child),
            id,
            front,
            drop_kind: DropKind::Wait,
        }
    }

    /// The child's pid; `None` for a Linux child whose spawn learned only its pidfd.
    pub fn pid(&self) -> Option<u32> {
        self.child.pid()
    }

    /// The child's identity, if the spawn read one.
    pub fn id(&self) -> Option<ProcessId> {
        self.id
    }

    /// Block until the child exits and reap it. `Err` if someone else reaped it, or the wait
    /// failed; the child is settled either way.
    pub fn wait(mut self) -> Result<ExitStatus, Error> {
        let child = self.child.take().expect("a live Unreaped holds its child");
        wait_for_status(&child, Orphaned::Warn)
    }

    /// [`wait`](Unreaped::wait), awaited: the same status and errors, without blocking the runtime
    /// thread. Dropping the future, polled or not, lets the child go, warned: it kills the child
    /// once more (a front, which is sent nothing, excepted), looks at it once without waiting and
    /// reaps it if it exited. It warns once naming the pid, except a child someone else reaped,
    /// which is logged at `debug` (a refused kill is warned regardless); a child not reaped is
    /// given up, unreaped.
    ///
    /// Needs the `tokio` feature. Portable code needs a runtime with the IO and time drivers (the
    /// `#[tokio::main]` / `#[tokio::test]` defaults): on Unix a runtime missing either makes tokio
    /// panic. On Windows the wait runs on the blocking pool and needs neither.
    #[cfg(feature = "tokio")]
    pub fn wait_async(mut self) -> impl std::future::Future<Output = Result<ExitStatus, Error>> {
        // Before the future exists, so a future dropped unpolled never blocks either.
        self.drop_kind = DropKind::LetGo;
        async move {
            let outcome = self.child.wait_async().await;
            // Settled once, whatever the outcome, as `wait` does.
            let child = self.child.take().expect("a live Unreaped holds its child");
            unbounded_status(child.pid(), outcome?, Orphaned::Warn)
        }
    }

    /// Give the child up, unreaped. Logs nothing.
    pub fn leak(mut self) {
        drop(self.child.take());
    }
}

/// What the [`LetGo`](DropKind::LetGo) drop's kill came to.
#[derive(Debug)]
pub(crate) enum LetGoKill {
    /// None was sent: the child is an elevation front.
    NotSent,
    /// The signal was handed to the OS.
    Delivered,
    /// The signal found nothing to send to: the child is gone.
    Gone,
    /// The signal was not sent: nothing could verify the child. It may be running.
    Unverified,
    /// The kill failed; the text of its error.
    Refused(String),
}

impl LetGoKill {
    /// The kill as a clause of the line; `None` when none was sent.
    fn clause(&self) -> Option<String> {
        match self {
            LetGoKill::NotSent => None,
            LetGoKill::Delivered => Some("killed it".to_owned()),
            LetGoKill::Gone => Some("its kill found nothing to signal".to_owned()),
            LetGoKill::Unverified => Some("its kill was not sent: the child could not be verified".to_owned()),
            LetGoKill::Refused(error) => Some(format!("its kill was refused: {error}")),
        }
    }
}

/// What both drops say of the child before anything else; `who` is [`child_named`].
fn dropped(who: &str) -> String {
    format!("{who} was dropped without wait or leak")
}

/// What both drops say of a child they reaped.
fn reaped_it(status: ExitStatus) -> String {
    format!("reaped it ({status})")
}

/// The one line of a [`LetGo`](DropKind::LetGo) drop, and its level: `kill` is what the kill came
/// to and `look` the one look at the present moment after it (never given the kill: it has a
/// deadline, and a settlement after a kill has none). Every case is worded here and nowhere else.
///
/// - The level is `warn`, except a child someone else reaped, which is `debug` (principle 7), and
///   a refused kill, which is at least `warn` whatever the look found.
/// - The kill is said whenever one was sent, a refusal with its error.
/// - A child the look did not collect says where it goes: given up, so nothing waits for it
///   ([`LEFT`], [`LEAVING_RUNNING`]).
pub(crate) fn let_go_line(pid: Option<u32>, kill: &LetGoKill, look: &Settlement) -> (log::Level, String) {
    let dropped = dropped(&child_named(pid));
    let subject = match kill.clause() {
        Some(clause) => format!("{dropped} ({clause})"),
        None => dropped,
    };
    let (level, line) = match look.status() {
        Some(status) => (log::Level::Warn, format!("{subject}: {}", reaped_it(status))),
        None => {
            let running = match kill {
                LetGoKill::Delivered => format!("{subject}; it had not exited yet{LEFT}"),
                _ => format!("{subject}{LEAVING_RUNNING}"),
            };
            let said = look.wording(&subject, Some(&running), Some(Disposition::Leave));
            (said.level(), said.text().to_owned())
        }
    };
    // Principle 7: a failed kill logs at least at `warn`.
    let level = if matches!(kill, LetGoKill::Refused(_)) {
        level.min(log::Level::Warn)
    } else {
        level
    };
    (level, line)
}

impl Unreaped {
    /// The [`LetGo`](DropKind::LetGo) drop: the one kill (a front is sent none), the one look, and
    /// the one line [`let_go_line`] words.
    fn let_go(&self, child: &OwnedChild) {
        let kill = if self.front {
            LetGoKill::NotSent
        } else {
            match child.signal(Sig::Kill) {
                Ok(Sent::Delivered) => LetGoKill::Delivered,
                Ok(Sent::Gone) => LetGoKill::Gone,
                Ok(Sent::Unverified) => LetGoKill::Unverified,
                Err(refused) => LetGoKill::Refused(refused.to_string()),
            }
        };
        let look = Settlement::new(child.wait(Some(crate::wait::now())), false);
        let (level, line) = let_go_line(child.pid(), &kill, &look);
        log::log!(level, "{line}");
    }
}

impl Drop for Unreaped {
    fn drop(&mut self) {
        let Some(child) = self.child.take() else {
            return;
        };
        if self.drop_kind == DropKind::LetGo {
            self.let_go(&child);
            return;
        }
        let who = child_named(child.pid());
        // A destructor that blocks on a child during unwinding can hang the panic for good.
        if std::thread::panicking() {
            log::warn!("{} while the thread is panicking; gave it up, unreaped", dropped(&who));
            return;
        }
        let settlement = Settlement::new(wait_to_exit(&child, None), false);
        // The drop's own warn for a status, which the table words at debug: it names the status.
        if let Some(status) = settlement.status() {
            log::warn!("{}; waited for it and {}", dropped(&who), reaped_it(status));
            return;
        }
        let said = settlement.wording(&dropped(&who), None, Some(Disposition::Leave));
        log::log!(said.level(), "{}", said.text());
    }
}
