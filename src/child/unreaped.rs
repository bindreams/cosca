//! A child a failed spawn could not kill, handed back to the caller rather than reaped behind its
//! back: cosca keeps no thread, queue or state of its own to reap it with.
//!
//! **The ownership rule.** A child is waited on only once it is confirmed ours and unreaped: its
//! one check, a `try_wait`, finds it still running. The one thing that leaves its ownership
//! uncertain is a `try_wait` failing with `ECHILD` (see [`releases_ownership`]): its pid may
//! already name another process, and a wait would block on that process or steal its status. Such
//! a child is released without any wait, and a tokio one without running
//! its `Drop`, which would hand the pid to tokio's orphan queue to wait on. Any other `try_wait`
//! failure (a too-old kernel's `EINVAL` from `waitid(P_PIDFD)`, a transient failure) says nothing
//! about ownership, and is kept the same way a running check is. An [`Unreaped`] is only ever
//! built for a child its check did not find exited or reaped elsewhere: running, or a check that
//! failed without saying anything about ownership.
//!
//! **Releasing.** A child still ours — one given up by [`Unreaped::leak`] — is released by dropping
//! its handle: std's `Child` and a raw handle only close descriptors, a pidfd only closes, and a
//! tokio child goes to tokio's own orphan queue, which is process-global tokio state. That reap is
//! best-effort: on Unix it runs only when a live runtime's signal driver sees a later `SIGCHLD`, so
//! with no runtime left, or no further child exiting, the leaked child stays a zombie. Its pid is
//! pinned until then, so the reap, when it comes, is its own. A child of uncertain ownership is
//! released the same way,
//! except a tokio one on Unix: tokio's orphan handling would `waitpid` a pid that may be another
//! process's, so it is forgotten instead, leaking tokio's pidfd and its reactor registration. That
//! leak is bounded by uncertain-ownership events, which only a caller reaping cosca's children
//! behind its back produces. On Windows a handle names its process whatever else reaps, so a tokio
//! child is always dropped.

use std::process::ExitStatus;

/// The child an [`Unreaped`] holds: by whichever handle its spawn had on it.
pub(crate) enum Held {
    Std(std::process::Child),
    /// Boxed: tokio's `Child` is several times the size of the others.
    #[cfg(feature = "tokio")]
    Tokio(Box<::tokio::process::Child>),
    /// The raw `CreateProcessW` backend's handle.
    #[cfg(windows)]
    Raw(crate::child::spawn::windows_raw::RawChild),
    /// The async raw backend's handle, which `cosca::tokio::Unreaped` awaits without blocking.
    #[cfg(all(windows, feature = "tokio"))]
    RawAsync(crate::tokio::spawn::windows_raw::RawAsyncChild),
    /// A child no `Child` holds — one a cgroup leaf found abandoned — named by its own pidfd if it
    /// has one, else by its pid. Either way it is this process's unreaped child, which nothing
    /// else may reap, so its pid names it until its reap.
    #[cfg(target_os = "linux")]
    Bare {
        pid: u32,
        pidfd: Option<std::os::fd::OwnedFd>,
    },
}

/// What a child's one check found.
pub(crate) enum Checked {
    /// Ours and unreaped: running, or a check that failed without saying anything about
    /// ownership — the only child an [`Unreaped`] may hold.
    Running(Held),
    /// It had exited, and the check reaped it.
    Reaped,
    /// The check failed, so its pid may name another process now. The child is already
    /// released; this says why, for the caller to log. Unix only: on Windows a held handle keeps
    /// naming its process (see [`Held::check`]).
    #[cfg_attr(windows, allow(dead_code))]
    Uncertain(std::io::Error),
}

/// Whether a failed wait/reap means "something else already reaped this child" — the single Unix
/// condition under which this process must give up ownership of a pid: a genuine `ECHILD`. tokio
/// 1.53's `try_wait` reports a foreign reap the same way std's does — as `ECHILD`, not `Ok(None)`
/// — so `Ok(None)` after a confirmed-reapable exit is never treated as a foreign reap (see
/// `tokio_wait_blocking`). Every other errno (a too-old kernel's `EINVAL` from
/// `waitid(P_PIDFD)`, a transient failure) says nothing about ownership either — the pid is still
/// pinned to our own unreaped child for as long as we hold it, and is kept, not released.
///
/// The single classification every wait/reap error passes through on Unix — `Held::check`,
/// `settle_after_wait` (the sync and async `Unreaped::wait`/`Drop`), the async `reap_failed`, and
/// `crate::tokio::child::wait_and_reap` (the teardown path's own wait, past its own kill) all
/// release on this alone.
#[cfg(unix)]
pub(crate) fn releases_ownership(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::ECHILD)
}

impl Held {
    pub(crate) fn pid(&self) -> u32 {
        match self {
            Held::Std(child) => child.id(),
            #[cfg(feature = "tokio")]
            // Some while unreaped, and a `Held` is only ever an unreaped child.
            Held::Tokio(child) => child.id().unwrap_or(0),
            #[cfg(windows)]
            Held::Raw(child) => child.id(),
            #[cfg(all(windows, feature = "tokio"))]
            Held::RawAsync(child) => child.id(),
            #[cfg(target_os = "linux")]
            Held::Bare { pid, .. } => *pid,
        }
    }

    /// The child's one ownership check: reaps it if it has exited, releases it if the check fails
    /// in a way that gives up ownership (see `releases_ownership`), and hands it back running
    /// otherwise — including every other check failure. On Windows a failed check always keeps
    /// the child as running: the held handle pins its process regardless of the failure.
    pub(crate) fn check(mut self) -> Checked {
        #[cfg(test)]
        let checked = match crate::child::spawn::fault::take_force_teardown_try_wait_error() {
            Some(marker) => Err(std::io::Error::other(marker)),
            #[cfg(unix)]
            None if crate::child::spawn::fault::take_force_teardown_try_wait_echild() => {
                Err(std::io::Error::from_raw_os_error(libc::ECHILD))
            }
            None => self.try_reap(),
        };
        #[cfg(not(test))]
        let checked = self.try_reap();
        match checked {
            Ok(None) => Checked::Running(self),
            Ok(Some(_)) => Checked::Reaped,
            #[cfg(windows)]
            Err(e) => {
                log::debug!("checking pid {} failed ({e}); its handle still holds it", self.pid());
                Checked::Running(self)
            }
            #[cfg(unix)]
            Err(e) if releases_ownership(&e) => {
                self.release_uncertain();
                Checked::Uncertain(e)
            }
            #[cfg(unix)]
            Err(e) => {
                log::debug!("checking pid {} failed ({e}); its handle still holds it", self.pid());
                Checked::Running(self)
            }
        }
    }

    /// Reap the child if it has exited, without blocking.
    pub(crate) fn try_reap(&mut self) -> std::io::Result<Option<ExitStatus>> {
        match self {
            Held::Std(child) => child.try_wait(),
            #[cfg(feature = "tokio")]
            Held::Tokio(child) => child.try_wait(),
            #[cfg(windows)]
            Held::Raw(child) => child.try_wait(),
            #[cfg(all(windows, feature = "tokio"))]
            Held::RawAsync(child) => child.try_wait().map_err(error_to_io),
            #[cfg(target_os = "linux")]
            Held::Bare { pid, pidfd } => bare_wait(*pid, pidfd.as_ref(), false),
        }
    }

    /// Block until the child exits, and reap it. Only for a child its check did not find exited
    /// or reaped elsewhere: ours, and unreaped, so its pid cannot have been reused.
    pub(crate) fn wait(&mut self) -> std::io::Result<ExitStatus> {
        #[cfg(test)]
        if let Some(marker) = crate::child::spawn::fault::take_force_teardown_wait_error() {
            return Err(std::io::Error::other(marker));
        }
        match self {
            Held::Std(child) => child.wait(),
            #[cfg(feature = "tokio")]
            Held::Tokio(child) => tokio_wait_blocking(child),
            #[cfg(windows)]
            Held::Raw(child) => child.wait(),
            #[cfg(all(windows, feature = "tokio"))]
            Held::RawAsync(child) => {
                // `wait_blocking`, not `wait_and_reap`: this generic wait carries no precondition
                // that a kill preceded it — an `Unreaped` child may never have been killed at all.
                child.wait_blocking()?;
                child
                    .try_wait()
                    .map_err(error_to_io)?
                    .ok_or_else(|| std::io::Error::other("the child's wait returned before its exit"))
            }
            #[cfg(target_os = "linux")]
            Held::Bare { pid, pidfd } => bare_wait(*pid, pidfd.as_ref(), true)?
                .ok_or_else(|| std::io::Error::other("a blocking wait returned no status")),
        }
    }

    /// Let go of a child still ours without waiting on it: its handles are dropped (see the
    /// module's **Releasing**).
    pub(crate) fn release(self) {
        drop(self);
    }

    /// Let go of a child whose ownership is uncertain: as [`release`](Held::release), except a
    /// tokio child on Unix is forgotten (see the module's **Releasing**).
    pub(crate) fn release_uncertain(self) {
        match self {
            #[cfg(all(unix, feature = "tokio"))]
            Held::Tokio(child) => std::mem::forget(child),
            other => drop(other),
        }
    }
}

/// Settle `held` after a `wait` that produced `waited`: released as [`Held::release_uncertain`]
/// does if the failure makes its ownership uncertain (see `releases_ownership`), or as
/// [`Held::release`] does otherwise — the single call site the sync and async `Unreaped::wait` and
/// `Drop` share, so no one of them can special-case the classification on its own.
#[cfg(unix)]
pub(crate) fn settle_after_wait(held: Held, waited: &std::io::Result<ExitStatus>) {
    match waited {
        Err(e) if releases_ownership(e) => held.release_uncertain(),
        _ => held.release(),
    }
}

/// tokio has no blocking wait: wait for the exit without reaping — the child is this process's
/// unreaped one, so its pid is not reused meanwhile — then let tokio reap it.
///
/// On Unix, `try_wait` after a confirmed-reapable exit can still report `Ok(None)`. This is not a
/// foreign reap: tokio's `try_wait`, like std's, reports a foreign reap as `ECHILD` (measured
/// against tokio 1.53), so the pid is still ours, and is kept, not released — releasing it here
/// would zombie-leak it.
#[cfg(feature = "tokio")]
fn tokio_wait_blocking(child: &mut ::tokio::process::Child) -> std::io::Result<ExitStatus> {
    #[cfg(unix)]
    {
        block_until_reapable(
            child
                .id()
                .ok_or_else(|| std::io::Error::other("tokio already reaped the child"))?,
        )?;
        #[cfg(test)]
        if crate::child::spawn::fault::take_force_tokio_wait_blocking_miss() {
            return Err(std::io::Error::other(
                "the child was reapable, yet its reap found no exit waiting for it (test seam)",
            ));
        }
        child
            .try_wait()?
            .ok_or_else(|| std::io::Error::other("the child was reapable, yet its reap found no exit waiting for it"))
    }
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
        use windows::Win32::System::Threading::{WaitForSingleObject, INFINITE};
        let handle = child
            .raw_handle()
            .ok_or_else(|| std::io::Error::other("tokio already reaped the child"))?;
        // SAFETY: tokio owns the handle and keeps it open while the child is unreaped.
        if unsafe { WaitForSingleObject(HANDLE(handle), INFINITE) } != WAIT_OBJECT_0 {
            return Err(std::io::Error::last_os_error());
        }
        child
            .try_wait()?
            .ok_or_else(|| std::io::Error::other("the child exited, yet tokio could not reap it"))
    }
}

/// A kill's crate error as the `io::Error` an `Error::Unreaped` carries: an elevated child's typed
/// refusal (`ElevationErrorKind::Unkillable`) is the `PermissionDenied` it was.
#[cfg(unix)]
pub(crate) fn kill_error_to_io<C: std::fmt::Debug + Send + Sync + 'static>(
    e: crate::error::Error<C>,
) -> std::io::Error {
    match e {
        crate::error::Error::Elevation {
            kind: crate::error::ElevationErrorKind::Unkillable,
            detail,
        } => std::io::Error::new(std::io::ErrorKind::PermissionDenied, detail),
        other => error_to_io(other),
    }
}

/// A crate [`Error`](crate::error::Error) as the `io::Error` an [`Unreaped`]'s wait returns.
#[cfg(any(unix, feature = "tokio"))]
pub(crate) fn error_to_io<C: std::fmt::Debug + Send + Sync + 'static>(e: crate::error::Error<C>) -> std::io::Error {
    match e {
        crate::error::Error::Io(e) => e,
        other => std::io::Error::other(other.to_string()),
    }
}

/// What an [`Unreaped`] releases only after its child is reaped: the containment of the spawn
/// that created it, whose tree teardown belongs after the root's reap. Given up with the child,
/// it is disarmed first, so nothing the leaked child leads is killed; a cgroup leaf it still
/// occupies is then never removed by cosca, and stays until the delegated parent's owner removes
/// it.
pub(crate) struct Retained {
    pub(crate) attached: crate::containment::Attached,
}

impl Retained {
    fn give_up(self) {
        self.attached.disarm();
    }
}

/// Block until this process's unreaped child `pid` is reapable — a zombie — without reaping it:
/// `waitid(P_PID, WEXITED | WNOWAIT)`. An exit watch can fire before that point (macOS's
/// `NOTE_EXIT` arrives before the zombie exists), so a reap right after one waits here first. The
/// wait is bounded by the exit, which has happened, and by any tracer's release: a traced child
/// (`strace -f`) becomes reapable by its parent only once its tracer lets it go. Blocking, so the
/// async wait runs it on the blocking pool. `ECHILD`: something else reaped it.
#[cfg(all(unix, any(test, feature = "tokio")))]
pub(crate) fn block_until_reapable(pid: u32) -> std::io::Result<()> {
    // SAFETY: a well-formed `waitid`; `info` is an owned, zeroed `siginfo_t`.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    loop {
        let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) };
        if rc == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(err);
        }
    }
}

/// `waitid` for a [`Held::Bare`] child, through its pidfd if it has one, else by its pid.
/// `block`ing waits for its exit; otherwise it returns at once, `None` if it is still running.
/// Either way an exited child is reaped.
///
/// `waitid(P_PIDFD, ...)` needs Linux >= 5.4; cosca's documented pidfd floor is `pidfd_open` alone
/// (Linux >= 5.3, see `crate::wait::linux`). On such a kernel `pidfd_open` succeeds but the wait
/// itself returns `EINVAL` — this falls back to waiting by pid, which the kernel has supported
/// unconditionally. The pid is pinned to this unreaped child for as long as it is held, so the
/// fallback still names the same process.
#[cfg(target_os = "linux")]
fn bare_wait(pid: u32, pidfd: Option<&std::os::fd::OwnedFd>, block: bool) -> std::io::Result<Option<ExitStatus>> {
    use std::os::fd::AsFd;
    use std::os::unix::process::ExitStatusExt;

    use rustix::process::{waitid, Pid, WaitId, WaitIdOptions};
    let pid = Pid::from_raw(pid as i32).ok_or_else(|| std::io::Error::other("pid 0"))?;
    let options = if block {
        WaitIdOptions::EXITED
    } else {
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG
    };
    let mut by_pid = pidfd.is_none();
    let status = loop {
        let id = if by_pid {
            WaitId::Pid(pid)
        } else {
            WaitId::PidFd(pidfd.expect("by_pid is false only when pidfd is Some").as_fd())
        };
        match waitid(id, options) {
            Err(rustix::io::Errno::INTR) => continue,
            Err(rustix::io::Errno::INVAL) if !by_pid => {
                by_pid = true;
                continue;
            }
            other => break other?,
        }
    };
    Ok(status.map(|status| {
        ExitStatus::from_raw(wait_status_raw(
            status.exit_status(),
            status.terminating_signal(),
            status.dumped(),
        ))
    }))
}

/// A wait status as `waitpid` would report it, from `waitid`'s decoded fields: an exit code in the
/// second byte, else the terminating signal in the first, with the core-dump bit (`0x80`) set
/// alongside the signal when the child dumped core. `waitid`'s own `terminating_signal()` is
/// already `Some` for a core-dumped exit (rustix's `killed() || dumped()`), so `dumped` only ever
/// applies alongside a signal.
#[cfg(target_os = "linux")]
fn wait_status_raw(exit_status: Option<i32>, terminating_signal: Option<i32>, dumped: bool) -> i32 {
    match (exit_status, terminating_signal) {
        (Some(code), _) => (code & 0xff) << 8,
        (None, Some(signal)) => (signal & 0x7f) | if dumped { 0x80 } else { 0 },
        (None, None) => 0,
    }
}

/// A child a failed spawn created but could not kill — a setuid child refuses the kill with
/// `EPERM` — handed back to the caller in [`Error::Unreaped`](crate::error::Error::Unreaped).
/// cosca keeps no background thread to reap it: the caller does, in its own scope.
///
/// Its **`Drop` blocks** until the child exits, then reaps it, so it never lingers as a zombie.
/// [`wait`](Unreaped::wait) does the same and returns the exit status; [`leak`](Unreaped::leak)
/// gives the child up without reaping it.
#[must_use = "an unkillable child must be waited for or explicitly leaked"]
pub struct Unreaped {
    /// `None` once waited for or leaked, so `Drop` does nothing more. Boxed, so an [`Error`] that
    /// carries it stays small.
    ///
    /// [`Error`]: crate::error::Error
    held: Option<Box<Held>>,
    /// Released after the child's reap.
    retained: Option<Box<Retained>>,
    pid: u32,
}

impl Unreaped {
    /// Hold `held`, which its one check did not find exited or reaped elsewhere, with nothing
    /// retained. Its remaining production callers are Linux's cgroup teardown
    /// (`containment::cgroup::leaf`) and Windows' elevation/raw-spawn teardown — both of which
    /// never have containment to retain at their call site — so it is dead code on a macOS build,
    /// where every production path now goes through `with_retained` instead (see L4: the
    /// identity-failure teardown arms retain what they attached, rather than dropping it).
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub(crate) fn new(held: Held) -> Unreaped {
        Unreaped::with_retained(held, None)
    }

    /// Hold `held`, which its one check did not find exited or reaped elsewhere, and `retained`
    /// until its reap.
    pub(crate) fn with_retained(held: Held, retained: Option<Retained>) -> Unreaped {
        Unreaped {
            pid: held.pid(),
            held: Some(Box::new(held)),
            retained: retained.map(Box::new),
        }
    }

    /// The child's process id. It stays this child's until the child is reaped.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Whether the child is held by a pidfd, for a test.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn holds_pidfd(&self) -> bool {
        matches!(self.held.as_deref(), Some(Held::Bare { pidfd: Some(_), .. }))
    }

    /// The held child and what it retains, for the async spawn to hand back as a
    /// `cosca::tokio::Unreaped`.
    #[cfg(feature = "tokio")]
    pub(crate) fn into_parts(mut self) -> (Held, Option<Retained>) {
        let held = *self
            .held
            .take()
            .expect("an Unreaped holds its child until it is consumed");
        (held, self.retained.take().map(|r| *r))
    }

    /// Block until the child exits, and reap it. A failed wait always releases the child — this
    /// `Unreaped` never returns still holding it. On Unix only the manner depends on
    /// `releases_ownership`: [`release_uncertain`](Held::release_uncertain) if the failure makes
    /// ownership uncertain, [`release`](Held::release) otherwise (see the module's **Releasing**
    /// for what each does). On Windows the held handle always pins its process, so `release` is
    /// the only manner either way — unlike [`leak`](Unreaped::leak), which always releases a
    /// still-owned child.
    pub fn wait(mut self) -> std::io::Result<ExitStatus> {
        let mut held = *self
            .held
            .take()
            .expect("an Unreaped holds its child until it is consumed");
        let waited = held.wait();
        #[cfg(unix)]
        settle_after_wait(held, &waited);
        #[cfg(windows)]
        drop(held);
        if let Some(retained) = self.retained.take() {
            // A successful reap leaves what it retained armed: its own teardown belongs after
            // the root's reap (see `Retained`'s doc), so it still kills through a failed spawn's
            // grandchildren left behind. Only a failed wait, which never confirmed the reap, gives
            // it up disarmed.
            if waited.is_err() {
                retained.give_up();
            }
        }
        waited
    }

    /// Give the child up without waiting for it: it runs on, and nothing of cosca's reaps it (see
    /// the module's **Releasing** for what closes, per kind of child). Logged at `warn`.
    ///
    /// Nothing the child leads is killed. A cgroup v2 leaf it still occupies is left in place, and
    /// cosca never removes it — not even once the tree has exited: the empty `cosca-*` leaf stays
    /// until the owner of the delegated parent cgroup removes it.
    pub fn leak(mut self) {
        if let Some(held) = self.held.take() {
            (*held).release();
            if let Some(retained) = self.retained.take() {
                retained.give_up();
            }
            log::warn!("leaking unkillable child {}, unreaped", self.pid);
        }
    }
}

impl Drop for Unreaped {
    /// Blocks until the child exits, then reaps it. A failed wait is logged at `warn`, and always
    /// releases the child, the same way [`wait`](Unreaped::wait) does — see its doc for the two
    /// manners a Unix failure can take, by `releases_ownership`.
    fn drop(&mut self) {
        // Only the fallback synchronous wait below can still leave `retained` to settle here:
        // `wait` and `leak` both take it themselves before this ever runs.
        let mut failed = false;
        if let Some(held) = self.held.take() {
            let mut held = *held;
            let waited = held.wait();
            if let Err(e) = &waited {
                failed = true;
                log::warn!(
                    "waiting for unkillable child {} failed ({e}); it stays unreaped",
                    self.pid
                );
            }
            #[cfg(unix)]
            settle_after_wait(held, &waited);
            #[cfg(windows)]
            drop(held);
        }
        if let Some(retained) = self.retained.take() {
            // See `wait`: a successful reap leaves what it retained armed.
            if failed {
                retained.give_up();
            }
        }
    }
}

impl std::fmt::Debug for Unreaped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unreaped")
            .field("pid", &self.pid)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[path = "unreaped_tests.rs"]
mod unreaped_tests;
