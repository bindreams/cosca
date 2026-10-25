//! The steps cosca runs in a POSIX child between `fork` and `exec`, run from one `pre_exec` hook.
//!
//! Each module that needs a step adds it here instead of registering a hook of its own, and the
//! spawn registers the hook once, right before it spawns. The hook runs the steps in a fixed order,
//! whatever order they were added in:
//!
//! 1. enter the child's directory (`raw_executable()`; see `child::spawn::enter_in_child`);
//! 2. `setsid` (session containment);
//! 3. cgroup self-placement (Linux), whose descriptor a later `dup2` could replace;
//! 4. keep the fd marker open across `exec` (macOS);
//! 5. the fd map's `dup2`s, last, so they cannot replace a descriptor an earlier step still needs.
//!
//! std's stdio `dup2`s, and the [`fd_channel`](super::fd_channel) hook registered before this one,
//! run before it. The first step that fails fails the spawn through std's error channel.
//!
//! A command with no step gets no hook, so std is free to take its `posix_spawn` route.

use std::ffi::CString;
use std::io;
#[cfg(target_os = "macos")]
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::os::fd::RawFd;
use std::os::unix::process::CommandExt;

use super::fd_map;
#[cfg(target_os = "linux")]
use crate::containment::cgroup::ReportSlot;

/// The in-child steps of one spawn. Every field is made in the parent, so running them allocates
/// nothing.
#[derive(Default)]
pub(crate) struct InChild {
    enter: Option<CString>,
    session: bool,
    #[cfg(target_os = "linux")]
    placement: Option<(RawFd, ReportSlot)>,
    #[cfg(target_os = "macos")]
    preserved: Vec<OwnedFd>,
    fd_map: Option<fd_map::Plan>,
}

impl InChild {
    /// `chdir` to `dir` in the child.
    pub(crate) fn enter(&mut self, dir: CString) {
        debug_assert!(self.enter.is_none(), "a spawn enters one directory");
        self.enter = Some(dir);
    }

    /// Make the child a session leader.
    pub(crate) fn session(&mut self) {
        debug_assert!(!self.session, "a spawn asks for its session once");
        self.session = true;
    }

    /// Place the child in its cgroup leaf; see `containment::cgroup::placement_hook`.
    ///
    /// # Safety
    ///
    /// `procs_fd` must stay open, and `slot`'s channel open, until the command has spawned.
    #[cfg(target_os = "linux")]
    pub(crate) unsafe fn place(&mut self, procs_fd: RawFd, slot: ReportSlot) {
        debug_assert!(self.placement.is_none(), "a spawn places its child once");
        self.placement = Some((procs_fd, slot));
    }

    /// Keep `fd` open across `exec` at its own number, in the child only.
    #[cfg(target_os = "macos")]
    pub(crate) fn preserve(&mut self, fd: OwnedFd) {
        self.preserved.push(fd);
    }

    /// Apply `plan`'s `dup2`s; see [`fd_map::install`].
    pub(super) fn map_fds(&mut self, plan: fd_map::Plan) {
        debug_assert!(self.fd_map.is_none(), "a spawn has one fd map");
        self.fd_map = Some(plan);
    }

    /// Register the hook on `cmd`, unless there is no step. The hook owns every descriptor the steps
    /// hold, so they stay open for as long as `cmd` does.
    pub(crate) fn register(self, cmd: &mut std::process::Command) {
        if self.is_empty() {
            return;
        }
        let mut steps = self;
        // SAFETY: every step makes only raw syscalls on values made before the fork, and allocates
        // nothing; see `run`.
        unsafe { cmd.pre_exec(move || steps.run()) };
    }

    fn is_empty(&self) -> bool {
        let Self {
            enter,
            session,
            #[cfg(target_os = "linux")]
            placement,
            #[cfg(target_os = "macos")]
            preserved,
            fd_map,
        } = self;
        #[cfg(target_os = "linux")]
        let other = placement.is_none();
        #[cfg(target_os = "macos")]
        let other = preserved.is_empty();
        enter.is_none() && !session && other && fd_map.is_none()
    }

    /// Runs in the forked child: every step in the module's order, stopping at the first failure.
    fn run(&mut self) -> io::Result<()> {
        if let Some(dir) = &self.enter {
            #[expect(
                clippy::disallowed_methods,
                reason = "this closure runs in the forked child, between fork and exec, so the chdir \
                          moves that child's cwd and never this process's — see `enter_in_child`'s doc"
            )]
            // SAFETY: `chdir` is async-signal-safe, and `dir` was allocated before the fork.
            let status = unsafe { libc::chdir(dir.as_ptr()) };
            if status != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        // EPERM if the child already leads a session.
        // SAFETY: `setsid` is async-signal-safe.
        if self.session && unsafe { libc::setsid() } == -1 {
            return Err(io::Error::last_os_error());
        }
        #[cfg(target_os = "linux")]
        if let Some((procs_fd, slot)) = self.placement {
            // SAFETY: this is the forked child, and `place`'s caller keeps both descriptors open.
            unsafe { crate::containment::cgroup::placement_hook(procs_fd, slot) }?;
        }
        #[cfg(target_os = "macos")]
        fd_map::preserve(&self.preserved)?;
        if let Some(plan) = &mut self.fd_map {
            plan.apply()?;
        }
        Ok(())
    }
}

/// Register a hook on `cmd` with only the steps `add` adds; returns what `add` returned.
#[cfg(test)]
pub(crate) fn register_alone<R>(cmd: &mut std::process::Command, add: impl FnOnce(&mut InChild) -> R) -> R {
    let mut steps = InChild::default();
    let added = add(&mut steps);
    steps.register(cmd);
    added
}

#[cfg(test)]
#[path = "in_child_tests.rs"]
mod in_child_tests;
