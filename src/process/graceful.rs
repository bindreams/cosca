//! Foreign `Process` graceful shutdown — the soft-then-hard escalation trio over a process
//! the crate does not own (no stdio, no reap). Lone ops are identity-bound and surface real
//! failures; tree ops are best-effort identity-walk sweeps (the `TreeWalk` contract). A tree op
//! sends the root its signal through the held handle, with no second open of it.

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
    /// each `(pid, ppid)` before `SIGKILL`/`TerminateProcess`, root then descendants. The root is
    /// killed through this handle, each descendant through a handle opened by its identity. Cannot be
    /// atomic against a forking tree — the `TreeWalk` contract. All platforms. A member it
    /// leaves running is an error. For a single-process kill that surfaces a failure use
    /// [`kill`](Process::kill).
    ///
    /// # Errors
    ///
    /// [`Error::Unassessable`] when the process table cannot be read, or the root exists but cannot
    /// be queried: nothing is killed, the root included. Also when the root is gone, or no longer
    /// holds its pid: no walk ran, and nothing was killed.
    ///
    /// [`Error::MemberNotKilled`] when the walk killed what it could and left a member running,
    /// naming the first and why: its identity could not be read, or its kill was refused.
    pub fn kill_tree(&self) -> Result<(), Error> {
        self.kill_tree_with(&crate::identity::HostKernel)
    }

    /// [`kill_tree`](Self::kill_tree), reading through `kernel`.
    pub(crate) fn kill_tree_with(&self, kernel: &dyn crate::identity::Kernel) -> Result<(), Error> {
        // No handle backstop: the root is left as any member is, and the first member left is the
        // error. This call's one report of the others.
        crate::containment::treewalk::hard_kill(kernel, self.id, &|sig| self.os.signal(sig))
            .into_result()
            .or_else(|left| left.unsettled(false))
            .map_err(|left| left.report("Process::kill_tree"))
    }

    /// Best-effort graceful (`SIGTERM`) sweep of the foreign process's tree (identity-walk, root
    /// then descendants; the root through this handle). Signal-only. Unix only: on Windows this rests on
    /// [`terminate`](Process::terminate), whose absence — no way to learn whether a foreign
    /// pid leads a group — applies here too, so it returns `Unsupported`
    /// (use [`kill_tree`](Process::kill_tree) for a hard sweep).
    ///
    /// # Errors
    ///
    /// [`Error::Unassessable`] when the process table cannot be read, or the root exists but cannot
    /// be queried: nothing is signalled.
    pub fn terminate_tree(&self) -> Result<(), Error> {
        self.terminate_tree_with(&crate::identity::HostKernel)
    }

    /// [`terminate_tree`](Self::terminate_tree), reading through `kernel`.
    pub(crate) fn terminate_tree_with(&self, kernel: &dyn crate::identity::Kernel) -> Result<(), Error> {
        #[cfg(unix)]
        {
            crate::containment::treewalk::terminate(kernel, self.id, &|sig| self.os.signal(sig))
        }
        #[cfg(windows)]
        {
            let _ = (kernel, self.id);
            Err(Error::Unsupported {
                op: "foreign tree graceful terminate".into(),
                platform: "windows",
                detail: "Windows has no per-process graceful signal, and a foreign process \
                         shares no addressable process group with us; use kill_tree for a hard \
                         identity-walk sweep"
                    .into(),
                source: None,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (kernel, self.id);
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
    /// error is surfaced afterward; a sweep failure would win over it. The sweep's errors are those
    /// of [`kill_tree`](Process::kill_tree), a member it left running included.
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
