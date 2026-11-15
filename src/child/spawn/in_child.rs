//! The steps cosca runs in a POSIX child between `fork` and `exec`.
//!
//! Each module that needs a step adds it here instead of registering a hook of its own. The steps run
//! in a fixed order, whatever order they were added in:
//!
//! 1. Linux: the `dup2`s of stdio (0 to 2);
//! 2. enter the child's directory (`raw_executable()`; see `child::spawn::enter_in_child`; on Linux
//!    the directory of `current_dir` too);
//! 3. Linux: the new process group (`setpgid`), then `SIGPIPE` back to its default, in std's order;
//! 4. `setsid` (session containment);
//! 5. cgroup self-placement (Linux), whose `cgroup.procs` descriptor, and the channel it reports
//!    through, a later `dup2` could replace: the write would then miss, silently downgrading
//!    `CgroupV2` to a process group, or put a stray "0" into the caller's descriptor;
//! 6. keep the fd marker open across `exec` (macOS);
//! 7. the fd map's `dup2`s, last, so they cannot replace a descriptor an earlier step still needs.
//!
//! On Linux the first step that fails is a record on the core's status channel, whose write end is on
//! none of the numbers the fd map `dup2`s onto (`InChild::mapped_fds`); cgroup self-placement
//! `_exit`s from the hook and reports through its own channel (see `containment::cgroup::placement_hook`).
//! On macOS the steps are one `pre_exec` hook of std's, and a failure goes through std's error channel.
//!
//! On macOS a command with no step gets no hook, so std is free to take its `posix_spawn` route.

use std::ffi::CString;
use std::io;
#[cfg(target_os = "macos")]
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::os::fd::RawFd;
#[cfg(not(target_os = "linux"))]
use std::os::unix::process::CommandExt;

use super::fd_map;
#[cfg(target_os = "linux")]
use crate::containment::cgroup::ReportSlot;

/// The in-child steps of one spawn. Every field is made in the parent, so running them allocates
/// nothing.
#[derive(Default)]
pub(crate) struct InChild {
    /// Linux: the `dup2`s that put the child's stdio on 0 to 2.
    #[cfg(target_os = "linux")]
    stdio: Option<fd_map::Plan>,
    enter: Option<CString>,
    /// Linux: `setpgid(0, 0)`.
    #[cfg(target_os = "linux")]
    process_group: bool,
    /// Linux: `SIGPIPE` back to its default.
    #[cfg(target_os = "linux")]
    sigpipe_default: bool,
    session: bool,
    #[cfg(target_os = "linux")]
    placement: Option<(RawFd, ReportSlot)>,
    #[cfg(target_os = "macos")]
    preserved: Vec<OwnedFd>,
    fd_map: Option<fd_map::Plan>,
}

impl InChild {
    /// Linux: put the child's stdio on 0 to 2 by `plan` (a mapping per slot), and set `SIGPIPE` back to its
    /// default after it, as std does unless the binary was built with `-Zon-broken-pipe`.
    #[cfg(target_os = "linux")]
    pub(super) fn map_stdio(&mut self, plan: fd_map::Plan) {
        debug_assert!(self.stdio.is_none(), "a spawn has one stdio plan");
        self.stdio = Some(plan);
        self.sigpipe_default = true;
    }

    /// Linux: the child leads a new process group.
    #[cfg(target_os = "linux")]
    pub(crate) fn process_group(&mut self) {
        debug_assert!(!self.process_group, "a spawn asks for its process group once");
        self.process_group = true;
    }

    /// The descriptor numbers the fd map `dup2`s onto, in the child, ascending.
    #[cfg(target_os = "linux")]
    pub(crate) fn mapped_fds(&self) -> Vec<RawFd> {
        self.fd_map
            .as_ref()
            .map_or_else(Vec::new, |plan| plan.child_fds().to_vec())
    }

    pub(crate) fn enter(&mut self, dir: CString) {
        debug_assert!(self.enter.is_none(), "a spawn enters one directory");
        self.enter = Some(dir);
    }

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
    /// hold, so they stay open for as long as `cmd` does. Not the Linux spawn's way: that runs
    /// [`run`](Self::run) in the child of `child::spawn::fork_exec`.
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn register(self, cmd: &mut std::process::Command) {
        if self.is_empty() {
            return;
        }
        let mut steps = self;
        // SAFETY: every step makes only raw syscalls on values made before the fork, and allocates
        // nothing; see `run`.
        unsafe { cmd.pre_exec(move || steps.run()) };
    }

    #[cfg(not(target_os = "linux"))]
    fn is_empty(&self) -> bool {
        let Self {
            enter,
            session,
            #[cfg(target_os = "macos")]
            preserved,
            fd_map,
        } = self;
        #[cfg(target_os = "macos")]
        let other = preserved.is_empty();
        #[cfg(not(target_os = "macos"))]
        let other = true;
        enter.is_none() && !session && other && fd_map.is_none()
    }

    /// Runs in the forked child: every step in the module's order, stopping at the first failure.
    /// Bound by the child's contract in `child::spawn::fork_exec` on Linux.
    pub(super) fn run(&mut self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(plan) = &mut self.stdio {
            plan.apply()?;
        }
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
        // std's own order: the process group, then `SIGPIPE`.
        // SAFETY: `setpgid` is async-signal-safe.
        #[cfg(target_os = "linux")]
        if self.process_group && unsafe { libc::setpgid(0, 0) } == -1 {
            return Err(io::Error::last_os_error());
        }
        #[cfg(target_os = "linux")]
        if self.sigpipe_default {
            // SAFETY: `signal` of a disposition that is not a handler is async-signal-safe.
            if unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) } == libc::SIG_ERR {
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
#[cfg(all(test, not(target_os = "linux")))]
pub(crate) fn register_alone<R>(cmd: &mut std::process::Command, add: impl FnOnce(&mut InChild) -> R) -> R {
    let mut steps = InChild::default();
    let added = add(&mut steps);
    steps.register(cmd);
    added
}

/// Linux: `/bin/sh -c script`, spawned through the ordinary spawn's own entry ([`super::fork_spawn::start`]) with
/// `steps` as the child's steps, in this process's environment. The spawn's error is the `io::Error` of its errno.
#[cfg(all(test, target_os = "linux"))]
pub(super) fn spawn_sh(script: &str, steps: &mut InChild) -> io::Result<super::fork_spawn::Started> {
    use std::ffi::OsStr;

    let argv = [OsStr::new("sh"), OsStr::new("-c"), OsStr::new(script)];
    let program = super::fork_exec::Program::new(&[OsStr::new("/bin/sh")], &argv, std::env::vars_os()).expect("no NUL");
    let lock = super::spawn_lock();
    super::fork_spawn::start(
        &program,
        steps,
        crate::identity::spawn_kernel(crate::identity::HostKernel),
        super::fork_spawn::OnFailure {
            policy: super::policy::SpawnPolicy::SYNC,
            front: None,
            placement: None,
            refusing_placement: false,
        },
        &lock,
    )
    .map_err(|failure| failure.expect_not_started().into_io())
}

/// Linux: waits for a child [`spawn_sh`] started and returns its exit code.
#[cfg(all(test, target_os = "linux"))]
pub(super) fn exit_code(started: &super::fork_spawn::Started) -> Option<i32> {
    use crate::child::owned::ChildWaitOutcome;
    use crate::os_process::child::ExitRecord;

    match started.owned.wait(None).expect("wait") {
        ChildWaitOutcome::Exited(ExitRecord::Status(status)) => status.code(),
        other => panic!("the child did not exit with a status: {other:?}"),
    }
}

#[cfg(test)]
#[path = "in_child_tests.rs"]
mod in_child_tests;
