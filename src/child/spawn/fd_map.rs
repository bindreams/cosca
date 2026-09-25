//! cosca-owned fd-mapping `pre_exec`: dup2's parent-process descriptors onto child descriptor
//! numbers, replacing the `command-fds` dependency.
//!
//! # Why cosca owns this now (I14)
//! `command-fds` 0.3.3 has two bugs that together made an out-of-range or negative
//! [`Fd`](crate::stdio::Fd) either abort the child or silently vanish rather than fail the
//! spawn cleanly:
//!  - its `map_fds` computes `max(every parent/child fd) + 1` as a temporary-fd floor with
//!    unchecked `i32` arithmetic, which overflows for `child_fd == i32::MAX`;
//!  - it calls nix 0.31.3's `dup2_raw`, which does not check `dup2`'s return value before
//!    wrapping it in an `OwnedFd` — on ANY `dup2` failure (e.g. `EBADF` for an out-of-range
//!    target) that constructs an `OwnedFd` around the sentinel `-1`, which aborts when std's
//!    own file-descriptor validity checks later see it. Reported upstream as
//!    nix-rust/nix#2797 (unfixed as of nix 0.31.3); not cosca's to fix.
//!
//! This module ports `command-fds`' actual algorithm (the collision-avoiding temporary-fd
//! shuffle, and the `FD_CLOEXEC`-clearing `preserved_fds` the macOS fd marker uses) but:
//!  - computes the temporary-fd floor with checked arithmetic in the PARENT, before any fork,
//!    so an unrepresentable floor (only possible when a `child_fd` or `parent_fd` is
//!    `i32::MAX`) is an ordinary `Err` from [`install`] rather than a child-side overflow;
//!  - makes every syscall through raw `libc` calls whose return value is checked, never
//!    through nix's `dup2_raw`;
//!  - retries a syscall interrupted by `EINTR`, with no arbitrary bound (mirrors the
//!    codebase's other `pre_exec`/raw-syscall retry sites — see e.g.
//!    `containment::cgroup::channel`).
//!
//! An out-of-range but syscall-representable `child_fd` (e.g. 1_000_000) is deliberately NOT
//! rejected here: it is a normal spawn-time condition (bounded by the child's own
//! `RLIMIT_NOFILE`) and is left to fail exactly the way any other post-fork syscall failure
//! does — `dup2` returns `EBADF`, the checked closure returns that as an `io::Error`, and
//! std's own child-to-parent error pipe turns it into an ordinary `Err` from
//! `Command::spawn`. Only a negative `Fd` ([`Command::fd`](crate::Command::fd)) and the
//! checked temporary-fd arithmetic here are pre-empted in the parent; everything else is the
//! kernel's call.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;

/// A parent-fd -> child-fd mapping to install as part of `std_cmd`'s `pre_exec` dup2 plan.
/// Owns `parent_fd` so it stays open (and valid to dup2 from) until the spawn completes.
#[derive(Debug)]
pub(crate) struct FdMapping {
    pub(crate) parent_fd: OwnedFd,
    pub(crate) child_fd: RawFd,
}

/// Register `mappings` as the LAST `pre_exec` hook on `std_cmd`. Callers MUST register this
/// after every containment pre_exec hook (see the ordering rationale in
/// `child::spawn::spawn_unelevated` and `tokio::spawn::spawn_uncommitted`): it must run last so
/// it cannot dup2 over an fd a containment hook still needs.
///
/// A no-op (registers nothing) for an empty `mappings`.
///
/// Every `child_fd` must already be non-negative — enforced once, upstream, at
/// [`Command::fd`](crate::Command::fd); only asserted here, not re-checked (it is a contract,
/// not user input at this point). An out-of-range `child_fd` is NOT rejected here — see the
/// module docs for why that is a normal (child-side, `EBADF`) spawn failure rather than a
/// parent-side refusal.
///
/// Parent-side failure mode: the temporary-fd floor a parent/child fd collision would need is
/// computed with checked arithmetic before any fork; if it does not fit in an `i32` (only
/// possible when some `child_fd` or `parent_fd` is `i32::MAX`), this returns
/// `Err(InvalidInput)` here rather than letting the post-fork computation overflow.
pub(crate) fn install(std_cmd: &mut std::process::Command, mappings: Vec<FdMapping>) -> io::Result<()> {
    if mappings.is_empty() {
        return Ok(());
    }
    for m in &mappings {
        debug_assert!(
            m.child_fd >= 0,
            "Command::fd must reject a negative fd before it reaches fd_map::install, got {}",
            m.child_fd
        );
    }
    debug_assert!(
        {
            let mut child_fds: Vec<RawFd> = mappings.iter().map(|m| m.child_fd).collect();
            let before = child_fds.len();
            child_fds.sort_unstable();
            child_fds.dedup();
            child_fds.len() == before
        },
        "duplicate child fd in a mapping set: child fd numbers must be unique \
         (callers build this from a BTreeMap<Fd, _>, whose keys already are)"
    );

    let mut plan = Plan::build(mappings)?;
    // SAFETY: `Plan::apply` makes only raw `dup2`/`fcntl` syscalls, checks every return value,
    // and reads the failure errno without allocating — the async-signal-safety `pre_exec`
    // requires.
    unsafe {
        std_cmd.pre_exec(move || plan.apply());
    }
    Ok(())
}

/// Register `fds` to survive `exec` without renumbering — clears `FD_CLOEXEC` on each, in the
/// child only. The cosca-owned equivalent of `command-fds`' `preserved_fds`, used by
/// `containment::fdmarker` to keep the marker write end open at the fd number it was placed
/// at.
///
/// `cfg`-gated to macOS, the only platform with a caller (`containment::fdmarker`): an
/// unconditional definition is dead code (and so a `-D warnings` clippy failure) on every other
/// Unix this module also compiles for.
#[cfg(target_os = "macos")]
pub(crate) fn install_preserved(std_cmd: &mut std::process::Command, fds: Vec<OwnedFd>) {
    if fds.is_empty() {
        return;
    }
    // SAFETY: as `install` — `preserve` only calls `fcntl(F_SETFD)`, checked, no allocation.
    unsafe {
        std_cmd.pre_exec(move || preserve(&fds));
    }
}

/// The dup2 plan, precomputed in the parent so the `pre_exec` closure does no allocation and no
/// unchecked arithmetic.
struct Plan {
    mappings: Vec<FdMapping>,
    /// Every child fd number in `mappings`, sorted+deduped — used post-fork to detect a parent
    /// fd that collides with ANOTHER mapping's child fd (needs a temporary first).
    child_fds: Vec<RawFd>,
    /// The first fd number provably clear of every parent AND child fd `mappings` mentions —
    /// safe to hand to `F_DUPFD_CLOEXEC` as a floor for a temporary. `None` only when
    /// `mappings` is empty (`install` returns before `Plan::build` in that case, so `apply`
    /// never actually needs it then either).
    first_safe_fd: Option<RawFd>,
}

impl Plan {
    fn build(mappings: Vec<FdMapping>) -> io::Result<Plan> {
        let mut child_fds: Vec<RawFd> = mappings.iter().map(|m| m.child_fd).collect();
        child_fds.sort_unstable();
        child_fds.dedup();

        let mut first_safe_fd: Option<RawFd> = None;
        for m in &mappings {
            let hi = m.parent_fd.as_raw_fd().max(m.child_fd);
            let bumped = hi.checked_add(1).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "fd {hi} has no representable fd number above it to use as a \
                         temporary during fd-mapping setup"
                    ),
                )
            })?;
            first_safe_fd = Some(match first_safe_fd {
                Some(cur) => cur.max(bumped),
                None => bumped,
            });
        }

        Ok(Plan {
            mappings,
            child_fds,
            first_safe_fd,
        })
    }

    /// Async-signal-safe: no allocation, every syscall's return value is checked, `EINTR` is
    /// retried with no arbitrary bound (matches the codebase's other `pre_exec`/raw-syscall
    /// retry sites).
    fn apply(&mut self) -> io::Result<()> {
        if self.mappings.is_empty() {
            return Ok(());
        }
        let first_safe_fd = self
            .first_safe_fd
            .expect("computed in build() for every non-empty mapping set");

        // Pass 1: move any parent fd that collides with ANOTHER mapping's child fd to an
        // FD_CLOEXEC temporary above `first_safe_fd`, so pass 2's dup2 onto that child fd
        // number cannot close a not-yet-processed parent fd out from under it. Mappings whose
        // parent fd already sits on its OWN child fd number are exempt (pass 2 handles that
        // case by clearing CLOEXEC in place, without a dup2).
        for m in self.mappings.iter_mut() {
            let parent_raw = m.parent_fd.as_raw_fd();
            if parent_raw != m.child_fd && self.child_fds.contains(&parent_raw) {
                let tmp = dup_fd_cloexec_at_or_above(parent_raw, first_safe_fd)?;
                // SAFETY: `tmp` was just returned by a successful F_DUPFD_CLOEXEC — a fresh,
                // uniquely-owned descriptor nothing else references yet.
                m.parent_fd = unsafe { OwnedFd::from_raw_fd(tmp) };
            }
        }

        // Pass 2: land each parent fd on its requested child fd number.
        for m in &self.mappings {
            let parent_raw = m.parent_fd.as_raw_fd();
            if parent_raw == m.child_fd {
                clear_cloexec(parent_raw)?;
            } else {
                dup2_onto(parent_raw, m.child_fd)?;
            }
        }

        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn preserve(fds: &[OwnedFd]) -> io::Result<()> {
    for fd in fds {
        clear_cloexec(fd.as_raw_fd())?;
    }
    Ok(())
}

/// `fcntl(fd, F_DUPFD_CLOEXEC, min)` — a fresh, `FD_CLOEXEC`-set duplicate of `fd`, at the
/// lowest available number `>= min`. Retries `EINTR`.
fn dup_fd_cloexec_at_or_above(fd: RawFd, min: RawFd) -> io::Result<RawFd> {
    retry_eintr(|| unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, min) })
}

/// `dup2(oldfd, newfd)` — closes `newfd` first if it was already open. Retries `EINTR`.
fn dup2_onto(oldfd: RawFd, newfd: RawFd) -> io::Result<()> {
    retry_eintr(|| unsafe { libc::dup2(oldfd, newfd) }).map(|_| ())
}

/// `fcntl(fd, F_SETFD, 0)` — clears every fd flag (in practice just `FD_CLOEXEC`). Retries
/// `EINTR`.
fn clear_cloexec(fd: RawFd) -> io::Result<()> {
    retry_eintr(|| unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }).map(|_| ())
}

/// Retry a raw libc call that reports failure as `-1` with `errno` set, absorbing `EINTR`. No
/// arbitrary retry bound: a syscall that is not interrupted returns on its first attempt; this
/// only loops while a signal keeps re-interrupting it.
///
/// Async-signal-safe: `f` is a plain syscall wrapper, and `io::Error::last_os_error()` reads
/// `errno` (via the platform's own thread-local accessor — `__errno_location` on Linux,
/// `__error` on macOS) without allocating.
fn retry_eintr(mut f: impl FnMut() -> libc::c_int) -> io::Result<libc::c_int> {
    loop {
        let ret = f();
        if ret != -1 {
            return Ok(ret);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(test)]
#[path = "fd_map_tests.rs"]
mod fd_map_tests;
