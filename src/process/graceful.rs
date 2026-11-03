//! Foreign `Process` graceful shutdown — the soft-then-hard escalation trio over a process
//! the crate does not own (no stdio, no reap). Lone ops are identity-bound and surface real
//! failures; tree ops are best-effort identity-walk sweeps (the `TreeWalk` contract).

use std::time::Duration;

use super::Process;
use crate::error::Error;

impl Process {
    /// Send `SIGTERM` to the process — a cooperative request to exit. Signal-only. Bound to the
    /// process this handle opened, as for [`kill`](Process::kill). Already-dead ⇒ `Ok`; a real
    /// failure (`EPERM`) ⇒ `Err`.
    ///
    /// **Windows: `Unsupported`.** `GenerateConsoleCtrlEvent` takes a raw pid, and Win32 exposes
    /// no way to learn whether a foreign pid leads a console process group, so a non-leader would
    /// silently signal *its* leader's whole group instead. An owned [`Child`](crate::Child) has
    /// no such problem: it created its group, so the pid can only ever name that child's own
    /// group.
    pub fn terminate(&self) -> Result<(), Error> {
        crate::os_process::terminate(&*self.os)
    }

    /// Cooperative-then-forced lone shutdown of the process: `SIGTERM`, wait up to
    /// `grace` for it to exit, then `SIGKILL` if it has not. No `ExitStatus` — the kernel hands
    /// exit status only to the real parent. Escalation proceeds even if `SIGTERM` is ignored.
    /// Unix only; Windows returns `Unsupported`. `grace` is relative; `ZERO` signals, polls
    /// once, then escalates.
    ///
    /// A watch failure surfaces only after the kill runs; a kill error wins over it.
    pub fn graceful_shutdown(&self, grace: Duration) -> Result<(), Error> {
        self.terminate()?;
        #[cfg(test)]
        crate::graceful_hooks::run_hook(crate::graceful_hooks::HookPoint::AfterTerminate);
        crate::graceful::after_grace(self.wait_timeout(grace), || self.kill())
    }

    /// Best-effort hard sweep of the foreign process's tree: an identity-walk that re-verifies
    /// each `(pid, ppid)` before `SIGKILL`/`TerminateProcess`, root then descendants. Cannot be
    /// atomic against a forking tree and does not surface per-process failures — the `TreeWalk`
    /// contract. All platforms. For a guaranteed, failure-surfacing single-process kill use
    /// [`kill`](Process::kill).
    ///
    /// # Errors
    ///
    /// [`Error::Unassessable`] when the process table cannot be read: nothing is killed, the root
    /// included.
    pub fn kill_tree(&self) -> Result<(), Error> {
        crate::containment::treewalk::hard_kill(self.id).map(|_| ())
    }

    /// Best-effort graceful (`SIGTERM`) sweep of the foreign process's tree (identity-walk, root
    /// then descendants). Signal-only. Unix only: on Windows this rests on
    /// [`terminate`](Process::terminate), whose two absences — no pinned pid, and no way to
    /// learn whether a foreign pid leads a group — apply here too, so it returns `Unsupported`
    /// (use [`kill_tree`](Process::kill_tree) for a hard sweep).
    ///
    /// # Errors
    ///
    /// [`Error::Unassessable`] when the process table cannot be read: nothing is signalled.
    pub fn terminate_tree(&self) -> Result<(), Error> {
        #[cfg(unix)]
        {
            crate::containment::treewalk::terminate(self.id)
        }
        #[cfg(windows)]
        {
            let _ = self.id;
            Err(Error::Unsupported {
                op: "foreign tree graceful terminate".into(),
                platform: "windows",
                detail: "Windows has no per-process graceful signal, and a foreign process \
                         shares no addressable process group with us; use kill_tree for a hard \
                         identity-walk sweep"
                    .into(),
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = self.id;
            Ok(())
        }
    }

    /// Cooperative-then-forced shutdown of the foreign process's tree: `SIGTERM`-walk, wait up
    /// to `grace` for the **root** to exit, then a hard identity-walk sweep. Best-effort (the
    /// `TreeWalk` contract); no `ExitStatus`. Unix only (Windows `terminate_tree` is
    /// `Unsupported`).
    ///
    /// A grace-watch failure does not strand the tree between the soft signal and the sweep:
    /// the hard sweep still runs (an unobservable grace escalates immediately), and the watch
    /// error is surfaced afterward; a sweep failure would win over it.
    pub fn graceful_shutdown_tree(&self, grace: Duration) -> Result<(), Error> {
        self.terminate_tree()?; // SIGTERM-walk (Windows: Unsupported, early return)
        #[cfg(test)]
        crate::graceful_hooks::run_hook(crate::graceful_hooks::HookPoint::AfterTerminate);

        crate::graceful::after_tree_grace(self.wait_timeout(grace), || self.kill_tree())
    }
}

#[cfg(test)]
#[path = "graceful_tests.rs"]
mod graceful_tests;
