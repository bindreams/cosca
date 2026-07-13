//! Async `Child` handle, wrapping `::tokio::process::Child` plus the stable `ProcessId` and the
//! contained-tree `Attached`.

#[path = "child/graceful.rs"]
mod graceful;

use std::process::ExitStatus;

use crate::containment::{Attached, Containment};
use crate::error::Error;
use crate::identity::ProcessId;

#[derive(Debug)]
pub struct Child {
    // `pub(super)`: the sibling `pump` module borrows the inner tokio child for `communicate`'s
    // `wait` future.
    pub(super) child: ::tokio::process::Child,
    id: ProcessId,
    attached: Attached,
    kill_on_drop: bool,
    containment: Containment,
}

impl Child {
    pub(crate) fn from_parts(
        child: ::tokio::process::Child,
        id: ProcessId,
        attached: Attached,
        kill_on_drop: bool,
        containment: Containment,
    ) -> Child {
        Child {
            child,
            id,
            attached,
            kill_on_drop,
            containment,
        }
    }

    /// The child's stable identity — valid after `wait`.
    pub fn id(&self) -> ProcessId {
        self.id
    }
    pub fn is_alive(&self) -> bool {
        self.id.is_alive()
    }
    pub fn containment(&self) -> Containment {
        self.containment
    }

    pub fn stdin(&mut self) -> Option<::tokio::process::ChildStdin> {
        self.child.stdin.take()
    }
    pub fn stdout(&mut self) -> Option<::tokio::process::ChildStdout> {
        self.child.stdout.take()
    }
    pub fn stderr(&mut self) -> Option<::tokio::process::ChildStderr> {
        self.child.stderr.take()
    }

    /// Block until the child exits, returning its status. For a bounded wait use
    /// `tokio::time::timeout(d, child.wait())`.
    pub async fn wait(&mut self) -> Result<ExitStatus, Error> {
        self.child.wait().await.map_err(Error::Io)
    }
    /// Exit status if the child has already exited (non-blocking).
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, Error> {
        self.child.try_wait().map_err(Error::Io)
    }

    /// Hard-kill the (lone) child. Handle-bound, so it cannot race a recycled pid.
    /// `Ok(())` if the child already exited or was reaped by a prior `wait` (tokio's
    /// `start_kill` maps the reaped state to `Ok`). Signal-only: does not reap —
    /// `wait().await` (or `Drop`) collects the exit status.
    pub fn kill(&mut self) -> Result<(), Error> {
        self.child.start_kill().map_err(Error::Io)
    }

    /// Hard-kill the contained tree. Requires an actionable containment mechanism
    /// (errors `Unsupported` otherwise — use [`kill`](Child::kill) for a lone process).
    /// If both the group teardown and the handle backstop fail, the group error is returned.
    pub fn kill_tree(&mut self) -> Result<(), Error> {
        self.require_contained()?;
        let group_result = self.attached.hard_kill();
        // Backstop for the TreeWalk mechanism: its hard_kill kills the root by identity, which
        // no-ops if `ProcessId::of` transiently fails to resolve — this handle-based kill
        // covers that, so its failure is contract-relevant.
        let backstop = self.kill();
        // Both-fail: the group error is surfaced; subsuming the backstop's is deliberate.
        group_result.and(backstop)
    }

    /// Send the graceful termination signal to the contained group — `SIGTERM` via
    /// `killpg`/cgroup, or `CTRL_BREAK` to the job/console group. **Signal-only:** does
    /// not wait or reap. Requires an actionable containment mechanism (errors
    /// `Unsupported` otherwise). Cooperative best-effort: on the `TreeWalk` mechanism a
    /// descendant whose identity transiently fails to resolve is intentionally left
    /// unsignaled; [`kill_tree`](Child::kill_tree) is the guaranteed hard teardown.
    pub fn terminate_tree(&self) -> Result<(), Error> {
        self.require_contained()?;
        self.attached.terminate(self.id.pid())
    }

    /// Guard for the `_tree` operations (single-sourced with the sync `Child`).
    fn require_contained(&self) -> Result<(), Error> {
        crate::containment::require_contained(self.containment, &self.attached)
    }
}

impl Child {
    /// Leave the child (and its contained tree) running after this handle drops.
    pub fn detach(&mut self) {
        self.kill_on_drop = false;
        self.attached.disarm();
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if !self.kill_on_drop {
            return;
        }
        // Tree teardown — the SOLE coverage for descendants (reap_now only guarantees the root),
        // so surface a real mechanism failure in debug. A no-op for an uncontained child.
        let tree = self.attached.hard_kill();
        debug_assert!(
            tree.is_ok(),
            "contained-tree teardown failed on async Drop: {:?}",
            tree.err()
        );
        let _ = tree;
        // Guaranteed reap of the root on the real exit event (no park dependence). Briefly blocks
        // the dropping thread; the child is SIGKILL'd so it exits at once. `true`: a prior wait()
        // (a Done child) is legal on Drop.
        let pid = self.id.pid();
        reap_now(&mut self.child, pid, true);
    }
}

/// Guaranteed synchronous teardown, shared by `Drop` and the spawn error path: kill the child,
/// then block until it has exited. On Unix we wait with `WNOWAIT` (NOT reaping), so tokio's own
/// `Child` field-drop reaps the zombie synchronously in its drop (its `try_wait` returns
/// `Ok(Some)`, not a park-dependent orphan enqueue) — a guaranteed reap before `Drop` returns.
/// We only wait while tokio still owns the child (`id().is_some()`), which pins the pid; once
/// tokio is `Done` (a prior `wait()` reaped it), the pid may be recycled and we must not wait on
/// it. `done_ok` says whether an already-`Done` child is legal here: `true` for `Drop` (the user
/// may have `wait()`ed), `false` for the spawn-error path (the child was never awaited).
/// **Invariant:** no `wait()` future for this child is in flight when this runs.
pub(crate) fn reap_now(child: &mut ::tokio::process::Child, pid: u32, done_ok: bool) {
    // `start_kill` bounds the wait below — it MUST run in release (NOT inside `debug_assert!`,
    // whose argument is stripped in release). A no-op on an already-exited child.
    let killed = child.start_kill();
    debug_assert!(killed.is_ok(), "start_kill of an owned child should not fail");
    // A failed start_kill means this is not a live process to wait on (ESRCH = already exited;
    // EPERM is impossible for our own child) — skip, so a kill failure can never turn the bounded
    // exit-wait into an unbounded block. tokio's field-drop reaps any leftover zombie.
    if killed.is_err() {
        return;
    }
    // tokio `Done` ⇒ already reaped, pid possibly recycled ⇒ nothing to do (the recycled-pid wait
    // hazard the sync side avoids by holding a handle).
    if child.id().is_none() {
        debug_assert!(
            done_ok,
            "reap_now found an already-reaped child where one was impossible"
        );
        return;
    }
    #[cfg(unix)]
    {
        // `nix` doesn't expose `waitid` on macOS (0.31 configures it out), so call `libc::waitid`
        // directly (WEXITED | WNOWAIT: block until exit without reaping) — portable across every Unix
        // target and the identical syscall.
        debug_assert!(pid <= i32::MAX as u32, "pid {pid} exceeds i32::MAX");
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        loop {
            // SAFETY: a well-formed `waitid` call; `info` is a valid, owned, zeroed `siginfo_t` the
            // kernel fills in. WNOWAIT leaves the child reapable for tokio's in-drop reap.
            let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) };
            if rc == 0 {
                break;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            // id() was Some above (tokio un-reaped ⇒ pid pinned), so no ECHILD / other errno should
            // occur — a debug tripwire, with a safe release `break`.
            debug_assert!(false, "waitid in reap_now failed unexpectedly: {err}");
            break;
        }
    }
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
        use windows::Win32::System::Threading::{WaitForSingleObject, INFINITE};
        let _ = pid;
        let h = child.raw_handle().expect("tokio owns the handle while id() is Some");
        // SAFETY: tokio owns and (on its field-drop) closes the handle; we only wait on it.
        // INFINITE is bounded by `start_kill` above.
        let waited = unsafe { WaitForSingleObject(HANDLE(h), INFINITE) };
        debug_assert!(
            waited == WAIT_OBJECT_0,
            "reap_now did not observe the child's exit: {waited:?}"
        );
    }
}
