//! Foreign `Process` graceful shutdown — the soft-then-hard escalation trio over a process we
//! do not own (no stdio, no reap). A submodule of `process` so it can reach the private `id`.
//! Lone ops are identity-bound and surface real failures; tree ops are best-effort identity-
//! walk sweeps (the `TreeWalk` contract).

use std::time::Duration;

use super::Process;
use crate::error::Error;

impl Process {
    /// Send `SIGTERM` to the foreign process — a cooperative request to exit. Signal-only.
    /// Identity-bound (Linux `pidfd_send_signal`; macOS reverify-then-`kill`). Already-dead ⇒
    /// `Ok`; a real failure (`EPERM`) ⇒ `Err`. Unix only; Windows returns `Unsupported`.
    pub fn terminate(&self) -> Result<(), Error> {
        crate::wait::terminate(self.id)
    }

    /// Cooperative-then-forced lone shutdown of the foreign process: `SIGTERM`, wait up to
    /// `grace` for it to exit, then `SIGKILL` if it has not. No `ExitStatus` — the kernel hands
    /// exit status only to the real parent. Escalation proceeds even if `SIGTERM` is ignored.
    /// Unix only; Windows returns `Unsupported`. `grace` is relative; `ZERO` signals, polls
    /// once, then escalates.
    pub fn graceful_shutdown(&self, grace: Duration) -> Result<(), Error> {
        crate::wait::terminate(self.id)?;
        if crate::wait::block_until_exit(self.id, Some(grace))? {
            return Ok(()); // exited within grace
        }
        crate::wait::kill(self.id) // timeout → hard SIGKILL (no reap — not the parent)
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
    /// then descendants). Signal-only. Unix only: Windows has no per-process graceful signal and
    /// a foreign process shares no addressable group with us, so this returns `Unsupported`
    /// there (use [`kill_tree`](Process::kill_tree) for a hard sweep).
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
    pub fn graceful_shutdown_tree(&self, grace: Duration) -> Result<(), Error> {
        self.terminate_tree()?; // SIGTERM-walk (Windows: Unsupported, early return)
        let _ = crate::wait::block_until_exit(self.id, Some(grace))?;
        self.kill_tree()
    }
}
