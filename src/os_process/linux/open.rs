//! Linux pidfd primitives for [`crate::os_process`]. `pidfd_open` returns a fd that
//! becomes readable (POLLIN) when the task becomes a zombie (exits); polling never reaps.
//! A signal through the pidfd is identity-bound (no pid-reuse race). A refused `pidfd_open` is
//! [`Error::Unsupported`], a transient one [`Error::Io`] prefixed `pidfd_open:`; the errno
//! classification is documented once, on [`Error::Unsupported`].
//!
//! The kernel floor, the per-syscall versions, and how a refused syscall is classified
//! (`Unsupported` versus `Io`) are in the crate root's "Platform requirements". Without `openat2`
//! the checked `/proc` view cannot be built, and `open_verified` is `Unsupported` naming `openat2`.
//! `spawn` probes `pidfd_open` on this process's own pid before it forks ([`probe_pidfd_support`]),
//! so a refusal fails the spawn with no child; see `child::spawn::pidfd_handshake` for the rest.

use std::os::fd::AsFd;

use rustix::process::{pidfd_open, Pid, PidfdFlags};

use crate::error::Error;
use crate::identity::{Existence, Liveness, PidfdTarget, ProcDir, ProcView, ProcessId, ViewUnreadable};
use crate::os_process::Op;

/// Open a pidfd for `id`, re-verifying identity. `Ok(None)` => already gone (treat as exited).
///
/// Every `/proc` read goes through one checked `/proc` dirfd shown to describe `id`'s pid
/// namespace; otherwise [`Error::Unassessable`], never a `Gone` off a foreign `/proc`.
pub(crate) fn open_verified(id: ProcessId, op: Op) -> Result<Option<rustix::fd::OwnedFd>, Error> {
    debug_assert!(
        id.pid() <= i32::MAX as u32,
        "pid {} exceeds i32::MAX; pidfd cast would truncate",
        id.pid()
    );
    let raw = Pid::from_raw(id.pid() as i32).expect("a resolvable ProcessId is never pid 0");
    match pidfd_open_checked(raw) {
        Ok(pidfd) => verify_pidfd_target(id, pidfd, op),
        Err(rustix::io::Errno::SRCH) => Ok(None),
        // pidfd_open needs a pid that resolves to a thread-group leader task. EINVAL (< 6.16) /
        // ENOENT (>= 6.16) means either a reaped process-group leader whose pid lives on as a PGID
        // (gone), or a non-leader tid: live, or a ptraced zombie thread kept until its tracer
        // waits. Errno alone can't tell, so re-verify.
        Err(e @ (rustix::io::Errno::INVAL | rustix::io::Errno::NOENT)) => verify_without_pidfd(id, op, e),
        Err(e) => match refusal_name(e) {
            Some(name) => Err(pidfd_open_unsupported(op.name(), name)),
            None => Err(Error::Io(crate::error::io_context(
                "pidfd_open",
                std::io::Error::from(e),
            ))),
        },
    }
}

impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::Wait => "process wait",
            Op::Kill => "process kill",
            Op::Terminate => "process terminate",
            Op::GroupTeardown => "process-group teardown",
        }
    }

    /// What is left undone when this operation cannot go ahead, for an [`Error::Unassessable`].
    fn consequence(self) -> &'static str {
        match self {
            Op::Wait => "its exit cannot be observed",
            Op::Kill | Op::Terminate => "no signal was sent",
            Op::GroupTeardown => "process-group teardown verification",
        }
    }
}

/// The name of `errno` if `pidfd_open` answering it is a refusal: no pidfd is possible here.
/// The classification is documented on [`Error::Unsupported`].
fn refusal_name(errno: rustix::io::Errno) -> Option<&'static str> {
    match errno {
        rustix::io::Errno::NOSYS => Some("ENOSYS"),
        rustix::io::Errno::PERM => Some("EPERM"),
        rustix::io::Errno::ACCESS => Some("EACCES"),
        rustix::io::Errno::NODEV => Some("ENODEV"),
        _ => None,
    }
}

fn pidfd_open_unsupported(op: &str, errno_name: &str) -> Error {
    Error::Unsupported {
        op: op.into(),
        platform: "linux",
        detail: format!(
            "cosca requires pidfd_open (Linux \u{2265} 5.3), refused here: pidfd_open answered {errno_name}"
        ),
    }
}

/// A `pidfd_open` failure while spawning: a refusal is [`Error::Unsupported`], anything else `Io`.
pub(crate) fn spawn_open_error(errno: rustix::io::Errno) -> Error {
    match refusal_name(errno) {
        Some(name) => pidfd_open_unsupported("spawn", name),
        None => Error::Io(crate::error::io_context("pidfd_open", std::io::Error::from(errno))),
    }
}

/// The pre-fork probe: `pidfd_open` on this process's own pid, closed at once. Spawning forks
/// through std, which cannot hand back a pidfd, so a kernel or filter that refuses `pidfd_open`
/// has to be found out BEFORE the fork, or the child would exist with no pidfd. A refusal is
/// [`Error::Unsupported`] naming `spawn`; any other failure (`EMFILE`, `ENFILE`, `ENOMEM`) is `Io`
/// naming `pidfd_open`. Either way no child exists.
///
/// Two syscalls per spawn, and no cached verdict: a cache is process-global state, and a filter
/// can be installed after the first spawn.
pub(crate) fn probe_pidfd_support() -> Result<(), Error> {
    pidfd_open_checked(rustix::process::getpid())
        .map(drop)
        .map_err(spawn_open_error)
}

/// The next scripted `pidfd_open` outcome on THIS thread, for a `pidfd_open` made elsewhere: the
/// spawn handshake's is made by the child. See [`fault::force_pidfd_open_script`].
#[cfg(test)]
pub(crate) fn take_scripted_pidfd_open() -> Option<rustix::io::Errno> {
    fault::take_forced_pidfd_open_errno()
}

/// `pidfd_open` refused `id`'s pid with `errno`. `Ok(None)` when the process is provably gone;
/// otherwise an error, since a live target cannot be waited on or signalled through a pidfd.
///
/// - `kill(pid, 0)` answering `ESRCH` is `Gone` whatever `/proc` shows.
/// - Else the `/proc` view must be [`ProcView::Same`]: `Gone` means the process is gone.
///   `Present` is a non-leader thread: `Dead` (a ptraced zombie) is exited, `Alive` is
///   [`Error::NotThreadGroupLeader`]. `Unknown` from either query is `Unassessable`.
/// - `Diverged`, or a view that could not be established, is `Unassessable` naming the view and
///   the `pidfd_open` errno. A raw `Io` here would surface as a bare `NotFound` on 6.16+, which
///   reads as "gone", and `containment::unix::group` treats `Io` as "no pidfd" and falls back to
///   `kill(2)`.
///
/// No pidfd to cross-check against, so the view comes from [`proc_view`](crate::identity::proc_view).
fn verify_without_pidfd(id: ProcessId, op: Op, errno: rustix::io::Errno) -> Result<Option<rustix::fd::OwnedFd>, Error> {
    if id.signal_says_no_such_process() {
        return Ok(None);
    }
    match crate::identity::proc_view() {
        ProcView::Same(proc_dir) => match exists_checked(id, &proc_dir) {
            Existence::Gone => Ok(None),
            Existence::Present => match alive_checked(id, &proc_dir) {
                Liveness::Dead => Ok(None),
                Liveness::Alive => Err(Error::NotThreadGroupLeader {
                    pid: id.pid(),
                    detail: op.consequence().into(),
                    source: std::io::Error::from(errno),
                }),
                Liveness::Unknown => Err(unassessable(
                    id,
                    op,
                    "the OS refused the liveness query",
                    None,
                    Some(errno),
                )),
            },
            Existence::Unknown => Err(unassessable(
                id,
                op,
                "the OS refused the existence query",
                None,
                Some(errno),
            )),
        },
        ProcView::Diverged => Err(unassessable(
            id,
            op,
            "this process's /proc is an outer pid namespace's",
            None,
            Some(errno),
        )),
        ProcView::Unassessable(why) => Err(view_unreadable(id, op, why, Some(errno))),
    }
}

/// `pidfd_open` succeeded. Confirm that this process's `/proc` describes the target before
/// comparing its start token, and read that token through the same `/proc` dirfd.
///
/// The pidfd's fdinfo `Pid:` is the target as the mounted procfs numbers it (`0` if invisible
/// there). Equal to `id.pid()` means that procfs names the target under this number, so
/// `{pid}/stat` describes it: the start token then tells a recycled pid from the original.
/// Anything else is `Unassessable`.
fn verify_pidfd_target(
    id: ProcessId,
    pidfd: rustix::fd::OwnedFd,
    op: Op,
) -> Result<Option<rustix::fd::OwnedFd>, Error> {
    let proc_dir = crate::identity::ProcDir::open().map_err(|why| view_unreadable(id, op, why, None))?;
    match crate::identity::pidfd_pid_in_view(&proc_dir, pidfd.as_fd()) {
        Ok(PidfdTarget::Pid(pid)) if pid == id.pid() => {}
        // Reaped after `pidfd_open`: gone, and nothing to signal.
        Ok(PidfdTarget::Reaped) => return Ok(None),
        Ok(PidfdTarget::Pid(pid)) => {
            return Err(unassessable(
                id,
                op,
                &format!(
                    "the mounted /proc numbers the target {pid} (0 = invisible), so it is an outer pid namespace's"
                ),
                None,
                None,
            ));
        }
        Err(why) => return Err(unassessable(id, op, &why.reason, why.source, None)),
    }
    // A pid recycled before open means the original is already gone. An unassessable pid
    // (hidepid, EPERM) is NOT gone and must not be treated as one.
    match exists_checked(id, &proc_dir) {
        Existence::Present => Ok(Some(pidfd)),
        Existence::Gone => Ok(None),
        Existence::Unknown => Err(unassessable(id, op, "the OS refused the existence query", None, None)),
    }
}

/// `why`, the `/proc` view that could not be established, as an error for `id`:
/// [`Error::Unsupported`] naming `openat2` when that is missing, else [`unassessable`].
fn view_unreadable(id: ProcessId, op: Op, why: ViewUnreadable, pidfd_errno: Option<rustix::io::Errno>) -> Error {
    match why.unsupported(op.name()) {
        Some(unsupported) => {
            log::warn!("wait: pid {} {}: {unsupported}", id.pid(), op.name());
            unsupported
        }
        None => unassessable(id, op, &why.reason, why.source, pidfd_errno),
    }
}

/// [`Error::Unassessable`] for `id`, logged at `warn`. `why` (with `source`'s text, if any) and
/// the `pidfd_open` errno, if there was one, are in the message, so the cause survives a
/// caller that only prints it; `source()` is the OS error behind `why`, else the errno.
fn unassessable(
    id: ProcessId,
    op: Op,
    why: &str,
    source: Option<std::io::Error>,
    pidfd_errno: Option<rustix::io::Errno>,
) -> Error {
    let mut detail = format!("pid {} identity could not be confirmed: {why}", id.pid());
    if let Some(source) = &source {
        detail.push_str(&format!(": {source}"));
    }
    if let Some(errno) = pidfd_errno {
        detail.push_str(&format!(" (pidfd_open: {errno})"));
    }
    detail.push_str(&format!("; {}", op.consequence()));
    log::warn!("wait: {detail}");
    Error::Unassessable {
        detail,
        source: source.or_else(|| pidfd_errno.map(std::io::Error::from)),
    }
}

/// `pidfd_open`, with a test seam: a forced errno (see [`fault::force_pidfd_open_errno_once`])
/// replaces the syscall once.
#[cfg(test)]
pub(crate) fn pidfd_open_checked(raw: Pid) -> Result<rustix::fd::OwnedFd, rustix::io::Errno> {
    match fault::take_forced_pidfd_open_errno() {
        Some(errno) => Err(errno),
        None => pidfd_open(raw, PidfdFlags::empty()),
    }
}
#[cfg(not(test))]
fn pidfd_open_checked(raw: Pid) -> Result<rustix::fd::OwnedFd, rustix::io::Errno> {
    pidfd_open(raw, PidfdFlags::empty())
}

/// `id.exists_in(proc_dir)`, with a test seam: a forced [`Existence`] (see
/// [`fault::force_exists_once`]) replaces the `/proc` read once, to drive the `Unknown` arms; runs
/// [`fault::between_check_and_read`]'s hook first.
#[cfg(test)]
pub(crate) fn exists_checked(id: ProcessId, proc_dir: &ProcDir) -> Existence {
    fault::run_between_hook();
    match fault::take_forced_exists() {
        Some(existence) => existence,
        None => id.exists_in(proc_dir),
    }
}
#[cfg(not(test))]
fn exists_checked(id: ProcessId, proc_dir: &ProcDir) -> Existence {
    id.exists_in(proc_dir)
}

/// `id.is_alive_in(proc_dir)`, with a test seam: a forced [`Liveness`] (see
/// [`fault::force_alive_once`]) replaces the `/proc` read once.
#[cfg(test)]
fn alive_checked(id: ProcessId, proc_dir: &ProcDir) -> Liveness {
    match fault::take_forced_alive() {
        Some(liveness) => liveness,
        None => id.is_alive_in(proc_dir),
    }
}
#[cfg(not(test))]
fn alive_checked(id: ProcessId, proc_dir: &ProcDir) -> Liveness {
    id.is_alive_in(proc_dir)
}

#[cfg(test)]
pub(crate) mod fault {
    use crate::identity::{Existence, Liveness};
    use std::cell::Cell;
    thread_local! {
        static FORCE_PIDFD_OPEN_ERRNO: std::cell::RefCell<std::collections::VecDeque<Option<rustix::io::Errno>>> =
            const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
        static FORCE_EXISTS: Cell<Option<Existence>> = const { Cell::new(None) };
        static FORCE_ALIVE: Cell<Option<Liveness>> = const { Cell::new(None) };
        static BETWEEN_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    }

    /// Clears the between-check-and-read hook on drop, consumed or not.
    #[must_use = "dropping this immediately disarms the hook; bind it for the probe's duration"]
    pub(crate) struct BetweenHook(());

    /// Run `hook` once on THIS thread, after `open_verified` has checked that `/proc` describes
    /// the target and before it reads `{pid}/stat`: the window in which a `/proc` looked up by
    /// path could differ from the one that was checked.
    pub(crate) fn between_check_and_read(hook: impl FnOnce() + 'static) -> BetweenHook {
        BETWEEN_HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
        BetweenHook(())
    }

    impl Drop for BetweenHook {
        fn drop(&mut self) {
            BETWEEN_HOOK.with(|h| h.borrow_mut().take());
        }
    }

    pub(super) fn run_between_hook() {
        if let Some(hook) = BETWEEN_HOOK.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }

    /// Disarms the forced errno on drop, so an unconsumed force can't leak into the next test on
    /// this thread.
    #[must_use = "dropping this immediately disarms the forced errno; bind it for the probe's duration"]
    pub(crate) struct ForcedPidfdOpenErrno(());

    /// Force the NEXT `pidfd_open` inside `open_verified` on THIS thread to fail with `errno`,
    /// consumed the first time it's read.
    pub(crate) fn force_pidfd_open_errno_once(errno: rustix::io::Errno) -> ForcedPidfdOpenErrno {
        force_pidfd_open_script([Some(errno)])
    }

    /// Script the next `pidfd_open` calls inside `open_verified` on THIS thread, one entry per
    /// call: `Some(errno)` fails it, `None` lets it through. Calls past the script run for real.
    pub(crate) fn force_pidfd_open_script(
        script: impl IntoIterator<Item = Option<rustix::io::Errno>>,
    ) -> ForcedPidfdOpenErrno {
        FORCE_PIDFD_OPEN_ERRNO.with(|f| *f.borrow_mut() = script.into_iter().collect());
        ForcedPidfdOpenErrno(())
    }

    impl Drop for ForcedPidfdOpenErrno {
        fn drop(&mut self) {
            FORCE_PIDFD_OPEN_ERRNO.with(|f| f.borrow_mut().clear());
        }
    }

    pub(crate) fn take_forced_pidfd_open_errno() -> Option<rustix::io::Errno> {
        FORCE_PIDFD_OPEN_ERRNO.with(|f| f.borrow_mut().pop_front().flatten())
    }

    /// Disarms the forced `Existence` on drop; see [`ForcedPidfdOpenErrno`].
    #[must_use = "dropping this immediately disarms the forced existence; bind it for the probe's duration"]
    pub(crate) struct ForcedExists(());

    /// Force the NEXT `id.exists()` re-verify inside `open_verified` on THIS thread to answer
    /// `existence`, consumed the first time it's read.
    pub(crate) fn force_exists_once(existence: Existence) -> ForcedExists {
        FORCE_EXISTS.with(|f| f.set(Some(existence)));
        ForcedExists(())
    }

    impl Drop for ForcedExists {
        fn drop(&mut self) {
            FORCE_EXISTS.with(|f| f.set(None));
        }
    }

    pub(crate) fn take_forced_exists() -> Option<Existence> {
        FORCE_EXISTS.with(|f| f.take())
    }

    /// Disarms the forced `Liveness` on drop; see [`ForcedPidfdOpenErrno`].
    #[must_use = "dropping this immediately disarms the forced liveness; bind it for the probe's duration"]
    pub(crate) struct ForcedAlive(());

    /// Force the NEXT `id.is_alive_in(..)` inside `open_verified` on THIS thread to answer
    /// `liveness`, consumed the first time it's read.
    pub(crate) fn force_alive_once(liveness: Liveness) -> ForcedAlive {
        FORCE_ALIVE.with(|f| f.set(Some(liveness)));
        ForcedAlive(())
    }

    impl Drop for ForcedAlive {
        fn drop(&mut self) {
            FORCE_ALIVE.with(|f| f.set(None));
        }
    }

    pub(crate) fn take_forced_alive() -> Option<Liveness> {
        FORCE_ALIVE.with(|f| f.take())
    }
}

#[cfg(test)]
#[path = "open_tests.rs"]
mod open_tests;

#[cfg(test)]
#[path = "open_namespace_tests.rs"]
mod open_namespace_tests;

#[cfg(test)]
#[path = "open_openat2_tests.rs"]
mod open_openat2_tests;
