//! Foreign `Process` graceful shutdown — the soft-then-hard escalation trio over a process
//! the crate does not own (no stdio, no reap). Lone ops are identity-bound and surface real
//! failures; tree ops are best-effort identity-walk sweeps (the `TreeWalk` contract). A tree op
//! sends the root its signal through the held handle, with no second open of it.

use std::time::Duration;

use super::Process;
use crate::containment::mechanism::Mechanism;
use crate::containment::treewalk::{Terminated, WalkToken, Walker};
use crate::containment::Tree;
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
    /// A watch failure surfaces only after the kill runs. A kill error is the call's error, and the
    /// watch failure joins it as a peer (`Error::with_peers_or_warn`).
    pub fn graceful_shutdown(&self, grace: Duration) -> Result<(), Error> {
        self.terminate()?;
        #[cfg(test)]
        crate::graceful_hooks::run_hook(crate::graceful_hooks::HookPoint::AfterTerminate);
        let call = || format!("graceful_shutdown({})", self.id.pid());
        crate::graceful::after_grace(call, self.wait_timeout(grace), || self.kill())?.map_or(Ok(()), Err)
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
    /// be queried: nothing is killed, the root included. Also when the root has exited, reaped or not
    /// (its children were reparented at its exit, so a walk from its pid says nothing of the tree), or
    /// no longer holds its pid, and the walk finds no member: no walk ran, and nothing was killed.
    ///
    /// [`Error::MembersLeft`] when the walk killed what it could and left members running, each a
    /// [`Error::MemberNotKilled`] naming it and why: its identity could not be read, or its kill was
    /// refused.
    ///
    /// **`Ok` means every member the walk killed has exited**, and so has the root: the call waits
    /// for each, with no deadline. A member forked after the walk's snapshot is not seen. On Linux
    /// below 6.9 a member that was killed and reaped, and whose pid was taken again within its own
    /// start tick, is waited for in its successor's place. A member whose exit cannot be observed is
    /// an [`Error::Unassessable`] naming it, returned once the others have been waited for. [`send_kill_tree`](Process::send_kill_tree) only sends.
    pub fn kill_tree(&self) -> Result<(), Error> {
        self.kill_tree_with("kill_tree", &crate::identity::HostKernel)
    }

    /// [`kill_tree`](Self::kill_tree) that sends and does not wait: `Ok` says every member the walk
    /// found was sent its kill, not that any has exited.
    pub fn send_kill_tree(&self) -> Result<(), Error> {
        self.send_kill_tree_with(&crate::identity::HostKernel)
    }

    /// [`kill_tree`](Self::kill_tree) for the call `op`, which a warn about its failed wait names,
    /// reading through `kernel`.
    pub(crate) fn kill_tree_with(&self, op: &str, kernel: &dyn crate::identity::Kernel) -> Result<(), Error> {
        self.kill_tree_settling(op, kernel, None)
    }

    /// [`kill_tree_with`](Self::kill_tree_with) for a graceful call, which keeps the members its
    /// `SIGTERM` walk reached in a settlement of its own (see [`sweep`](Self::sweep)).
    pub(crate) fn kill_tree_settling(
        &self,
        op: &str,
        kernel: &dyn crate::identity::Kernel,
        call: Option<&Settling>,
    ) -> Result<(), Error> {
        let (answer, wait) = self.sweep(kernel, call);
        let waited = wait.wait();
        crate::containment::tree_kill::answer_after_wait(op, answer, waited, |error| error)
    }

    /// [`kill_tree_with`](Self::kill_tree_with), awaited, with no runtime thread blocked.
    #[cfg(feature = "tokio")]
    pub(crate) async fn kill_tree_with_async(
        &self,
        op: &str,
        kernel: &dyn crate::identity::Kernel,
    ) -> Result<(), Error> {
        self.kill_tree_settling_async(op, kernel, None).await
    }

    /// [`kill_tree_settling`](Self::kill_tree_settling), awaited, with no runtime thread blocked.
    #[cfg(feature = "tokio")]
    pub(crate) async fn kill_tree_settling_async(
        &self,
        op: &str,
        kernel: &dyn crate::identity::Kernel,
        call: Option<&Settling>,
    ) -> Result<(), Error> {
        let (answer, wait) = self.sweep(kernel, call);
        let waited = wait.wait_async().await;
        crate::containment::tree_kill::answer_after_wait(op, answer, waited, |error| error)
    }

    /// [`send_kill_tree`](Self::send_kill_tree), reading through `kernel`.
    pub(crate) fn send_kill_tree_with(&self, kernel: &dyn crate::identity::Kernel) -> Result<(), Error> {
        self.sweep(kernel, None).0
    }

    /// The walk's kills, the answer they come to, and the wait for what they reached: the members, and
    /// the root through this handle once its kill landed.
    ///
    /// A root that has exited, reaped or not, whose walk finds no member answers [`Error::Unassessable`]:
    /// its children were reparented at its exit. A graceful call's `call` settles the walk as a
    /// `Child`'s tree does ([`TreeKilled::settle`](crate::containment::dispatch::TreeKilled::settle)):
    /// the members its `SIGTERM` walk reached are killed by identity and waited for, whether the root
    /// exited (and the walk's own complete listing then answers `Ok`, as for a `Child`) or outlived the
    /// grace and they were reparented meanwhile.
    fn sweep<'a>(
        &'a self,
        kernel: &'a dyn crate::identity::Kernel,
        call: Option<&Settling>,
    ) -> (Result<(), Error>, crate::containment::KillWait<'a>) {
        let (outcome, mut wait) = crate::containment::treewalk::hard_kill(kernel, self.id, self).split();
        let landed = wait.root_killed();
        // No handle backstop: the root is left as any member is, and the error holds every member.
        let answer = match call {
            Some(Settling { tree, walk }) => {
                let settled = tree.settle_for_kill_tree(outcome.in_call(walk.as_ref()), landed);
                wait.reaching(settled.killed_again);
                settled.answer
            }
            None => outcome.into_result().or_else(|left| left.unsettled(false)),
        };
        (answer, wait.with_root(&*self.os, self.id.pid(), landed))
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
    /// be queried: nothing is signalled. Also when the root has exited, reaped or not, and its walk
    /// finds no member: its children were reparented at its exit, so a walk from its pid says nothing
    /// of the tree, and nothing is signalled.
    pub fn terminate_tree(&self) -> Result<(), Error> {
        self.terminate_tree_with(&crate::identity::HostKernel)
    }

    /// [`terminate_tree`](Self::terminate_tree), reading through `kernel`.
    pub(crate) fn terminate_tree_with(&self, kernel: &dyn crate::identity::Kernel) -> Result<(), Error> {
        self.terminate_walk(kernel).and_then(Terminated::into_result)
    }

    /// The `SIGTERM` walk of [`terminate_tree`](Self::terminate_tree), with what it found: the members it
    /// listed, which a graceful shutdown stands on ([`sweep`](Self::sweep)).
    pub(crate) fn terminate_walk(&self, kernel: &dyn crate::identity::Kernel) -> Result<Terminated, Error> {
        #[cfg(unix)]
        {
            crate::containment::treewalk::terminate(kernel, self.id, self)
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
            Ok(Terminated::Walked {
                members: Vec::new(),
                complete: true,
            })
        }
    }

    /// The `SIGTERM` walk of a graceful shutdown, and the settlement its sweep answers to: the same type
    /// a `Child` keeps its tree in, local to the call. The members the walk reached are held in it, and
    /// the call's token is set when the walk read every candidate. A root that exited before the call
    /// sent nothing and has no walk of its own: the sweep answers as `kill_tree` does.
    ///
    /// # Errors
    ///
    /// As [`terminate_tree`](Process::terminate_tree) for a walk that could not be made: nothing is
    /// signalled. Windows: `Unsupported`.
    pub(crate) fn begin_graceful(&self) -> Result<Settling, Error> {
        let walked = self.terminate_walk(&crate::identity::HostKernel)?;
        let tree = Tree::contained(Mechanism::Walk(Walker::new(self.id)));
        let walk = match walked {
            Terminated::Walked { members, complete } => tree.hold_walked(members, complete, Some(&WalkToken::new())),
            Terminated::RootExited(_) => None,
        };
        Ok(Settling { tree, walk })
    }

    /// Cooperative-then-forced shutdown of the foreign process's tree: `SIGTERM`-walk, wait up
    /// to `grace` for the **root** to exit, then a hard identity-walk sweep. Best-effort (the
    /// `TreeWalk` contract); no `ExitStatus`. Unix only (Windows `terminate_tree` is
    /// `Unsupported`).
    ///
    /// A grace-watch failure does not strand the tree between the soft signal and the sweep:
    /// the hard sweep still runs (an unobservable grace escalates immediately), and the watch
    /// error is surfaced afterward. A sweep failure is the call's error, and the watch failure joins
    /// it as a peer, as for [`graceful_shutdown`](Process::graceful_shutdown). The sweep's errors
    /// are those of [`kill_tree`](Process::kill_tree); one that left members running carries the watch
    /// failure in its `others`.
    ///
    /// A root that exits within the grace reparents its children, so the sweep cannot walk to them: the
    /// members the call's own `SIGTERM` walk found, while the root ran, are its listing. It kills those
    /// still running by their identities, waits for them, and is `Ok` when every one is gone or killed;
    /// a root with no descendants is an empty listing. The limit is `kill_tree`'s: a process forked
    /// after the listing is not seen. A root that had exited before the call is
    /// [`Error::Unassessable`], as for [`terminate_tree`](Process::terminate_tree).
    pub fn graceful_shutdown_tree(&self, grace: Duration) -> Result<(), Error> {
        // SIGTERM-walk (Windows: Unsupported, early return).
        let settling = self.begin_graceful()?;
        #[cfg(test)]
        crate::graceful_hooks::run_hook(crate::graceful_hooks::HookPoint::AfterTerminate);

        let call = format!("graceful_shutdown_tree({})", self.id.pid());
        crate::graceful::after_tree_grace(&call, self.wait_timeout(grace), || {
            self.kill_tree_settling("graceful_shutdown_tree", &crate::identity::HostKernel, Some(&settling))
        })
    }
}

/// A graceful shutdown's settlement ([`Process::begin_graceful`]): the tree its `SIGTERM` walk held its
/// members in, and the token of that walk, if it read every candidate.
pub(crate) struct Settling {
    tree: Tree,
    walk: Option<WalkToken>,
}

#[cfg(test)]
#[path = "graceful_tests.rs"]
mod graceful_tests;
