//! [`Unreaped`]: a child a failed spawn or a failed `status`, `output` or `read` could not end,
//! handed to the caller who owns it.

use std::process::ExitStatus;

use super::slot::ChildSlot;
use super::teardown::Disposition;
use super::OwnedChild;
#[cfg(feature = "tokio")]
use crate::child::lifecycle::unbounded_status;
use crate::child::lifecycle::{wait_for_status, wait_to_exit, Orphaned, Settlement};
use crate::error::Error;
use crate::identity::ProcessId;
use crate::os_process::child_named;
use crate::signal::Sig;

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
    /// Kill it once more (not a front), look once without waiting and reap it if it exited; if it
    /// did not, warn once naming the pid and give it up, unreaped.
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
    /// reaps it if it exited, and otherwise warns once naming the pid and gives it up, unreaped.
    ///
    /// Needs the `tokio` feature and a runtime with the IO and time drivers (the `#[tokio::main]` /
    /// `#[tokio::test]` defaults); a hand-built runtime missing one makes tokio panic rather than
    /// return an error.
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

impl Drop for Unreaped {
    fn drop(&mut self) {
        let Some(child) = self.child.take() else {
            return;
        };
        let pid = child.pid();
        let who = child_named(pid);
        if self.drop_kind == DropKind::LetGo {
            // Whether the kill is refused does not change the look below, which says what is left.
            if !self.front {
                _ = child.signal(Sig::Kill);
            }
            let settlement = Settlement::new(child.wait(Some(crate::wait::now())), false);
            let subject = format!("{who} was dropped without wait or leak");
            let running = format!("{subject}; it still runs, so gave it up, unreaped");
            let said = settlement.wording(&subject, Some(&running), Some(Disposition::Leave));
            log::log!(said.level(), "{}", said.text());
            return;
        }
        // A destructor that blocks on a child during unwinding can hang the panic for good.
        if std::thread::panicking() {
            log::warn!("{who} was dropped without wait or leak while the thread is panicking; gave it up, unreaped");
            return;
        }
        let settlement = Settlement::new(wait_to_exit(&child, None), false);
        // The drop's own warn for a status, which the table words at debug: it names the status.
        if let Some(status) = settlement.status() {
            log::warn!("{who} was dropped without wait or leak; waited for it and reaped it ({status})");
            return;
        }
        let subject = format!("{who} was dropped without wait or leak");
        let said = settlement.wording(&subject, None, Some(Disposition::Leave));
        log::log!(said.level(), "{}", said.text());
    }
}
