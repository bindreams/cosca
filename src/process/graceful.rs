//! Foreign `Process` graceful shutdown — the soft-then-hard escalation trio over a process
//! the crate does not own (no stdio, no reap). Lone ops are identity-bound and surface real
//! failures; tree ops are best-effort identity-walk sweeps (the `TreeWalk` contract).

use std::time::Duration;

use super::Process;
use crate::error::Error;

impl Process {
    /// Send `SIGTERM` to the foreign process — a cooperative request to exit. Signal-only.
    /// Identity-bound (Linux `pidfd_send_signal`; macOS reverify-then-`kill`). Already-dead ⇒
    /// `Ok`; a real failure (`EPERM`) ⇒ `Err`.
    ///
    /// **Windows: `Unsupported`, for two concrete absences.** A `Process` holds only a pid,
    /// nothing that pins it, and `GenerateConsoleCtrlEvent` takes a raw pid with no
    /// verify-then-signal form — so a foreign console-group signal cannot be made
    /// identity-bound, unlike every other op on this type. And Win32 exposes no way to learn
    /// whether a foreign pid leads a console process group, so a non-leader would silently
    /// signal *its* leader's whole group instead. An owned [`Child`](crate::Child) has neither
    /// problem: its held process handle keeps the pid allocated, so the pid can only ever name
    /// that child's own group.
    pub fn terminate(&self) -> Result<(), Error> {
        crate::wait::terminate(self.id)
    }

    /// Cooperative-then-forced lone shutdown of the foreign process: `SIGTERM`, wait up to
    /// `grace` for it to exit, then `SIGKILL` if it has not. No `ExitStatus` — the kernel hands
    /// exit status only to the real parent. Escalation proceeds even if `SIGTERM` is ignored.
    /// Unix only; Windows returns `Unsupported`. `grace` is relative; `ZERO` signals, polls
    /// once, then escalates.
    ///
    /// A watch failure surfaces only after the kill runs; a kill error wins over it.
    pub fn graceful_shutdown(&self, grace: Duration) -> Result<(), Error> {
        crate::wait::terminate(self.id)?;
        // A watch failure must not strand the process between the soft signal and the
        // escalation — the kill still runs (grace unobservable => escalate now); the watch
        // error surfaces only after it succeeds (a kill error wins — deliberate subsumption,
        // mirroring the owned twins' disposition).
        let watch = crate::wait::block_until_exit(self.id, Some(grace));
        if matches!(watch, Ok(true)) {
            return Ok(()); // exited within grace
        }
        // Hard SIGKILL (no reap — not the parent); an Err returns HERE, subsuming any watch Err.
        crate::wait::kill(self.id)?;
        watch?;
        Ok(())
    }

    /// Best-effort hard sweep of the foreign process's tree: an identity-walk that re-verifies
    /// each `(pid, ppid)` before `SIGKILL`/`TerminateProcess`, root then descendants. Cannot be
    /// atomic against a forking tree and does not surface per-process failures — the `TreeWalk`
    /// contract. All platforms. For a guaranteed, failure-surfacing single-process kill use
    /// [`kill`](Process::kill).
    pub fn kill_tree(&self) -> Result<(), Error> {
        crate::containment::treewalk::hard_kill(self.id);
        Ok(())
    }

    /// Best-effort graceful (`SIGTERM`) sweep of the foreign process's tree (identity-walk, root
    /// then descendants). Signal-only. Unix only: on Windows this rests on
    /// [`terminate`](Process::terminate), whose two absences — no pinned pid, and no way to
    /// learn whether a foreign pid leads a group — apply here too, so it returns `Unsupported`
    /// (use [`kill_tree`](Process::kill_tree) for a hard sweep).
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

        // Watch-Err ordering: sweep first, then surface (see graceful_shutdown above).
        let watch = crate::wait::block_until_exit(self.id, Some(grace));
        // The sweep is unconditional — a gracefully-exited root does NOT mean the descendants
        // drained. A sweep Err subsumes any watch Err; there is no reap to order against (the
        // real parent collects the zombie).
        self.kill_tree()?;
        watch?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "graceful_tests.rs"]
mod graceful_tests;
