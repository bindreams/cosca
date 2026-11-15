//! Linux: the ordinary spawn, on the fork-exec core ([`fork_exec`]).
//!
//! The child is cloned with [`CloneKind::Vfork`]: the parent is suspended until the child's `execve` or
//! exit, so every record the child wrote is in the status channel when the clone returns, and the
//! parent reads them without waiting. The pidfd comes from the clone, so the box over the child exists
//! at once. The spawn's answer is decided by the records alone:
//!
//! - an errno record: a step or the `execve` failed, the program did not start, and the errno is the
//!   spawn's error;
//! - no ready record: the child ended before it got to the `execve`; the program did not start, and the
//!   child is torn down through its box ([`Past::Unexecuted`]). A child placed in a cgroup leaf that
//!   left with the exit status of the placement hook says its placement step is where it ended; any other
//!   end is not blamed on the placement, even when the child reported its placement write failed (a slot
//!   that does not refuse a failed write goes on to its exec). The one exception is a refused placement (a
//!   refusing slot whose child reported its write failed, and exited): the child is handed to the attach,
//!   which reads the report, says why and tears it down;
//! - a ready record and no errno: the program started, or was killed between the ready record and the
//!   `execve`. `Ok` means the spawn could not prove the program did not start, and the child's wait
//!   reports the signal.
//!
//! The clone's pidfd is the first thing the spawn moves above the stdio slots, before the channel is read.
//!
//! The child's steps are [`InChild`]'s (stdio, directory, process group, then cosca's own). Neither side
//! waits for the other: no step may wait on the parent.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use super::fork_exec::{self, Failure, Program, Progress, SpawnError, Spawned, Status, StepFailure};
use super::in_child::InChild;
use super::policy::SpawnPolicy;
use super::{held_teardown, Diagnosis, Invocation, SpawnFailure, SpawnLockGuard};
use crate::child::drop_teardown::Torn;
use crate::child::owned::teardown::{Disposition, Past};
use crate::child::owned::OwnedChild;
use crate::command::EnvOp;
use crate::containment::cgroup::{PlacementReport, ReportChannel, ABANDONED_EXIT, REFUSED_EXIT, UNSENT_EXIT};
use crate::elevation::front::Front;
use crate::error::Error;
use crate::identity::SpawnKernel;
use crate::os_process::linux::fork::{fork_with_pidfd, CloneKind, ForkFn, NewChild};

/// The kind of step failure the child reports: an in-child step failed, with this errno.
const KIND_STEP: u8 = 1;

/// The exit status of a child whose step failed: not the 127 of a failed `execve`.
const STEP_EXIT: i32 = 126;

/// A spawned child, in the box over the pidfd its clone gave it.
pub(super) struct Started {
    pub(super) pid: u32,
    pub(super) owned: OwnedChild,
}

/// What a failed spawn does with the child it made.
pub(super) struct OnFailure<'a> {
    /// The spawn's: when the wait for a child it killed warns, and what an `Unreaped` it hands back does.
    pub(super) policy: SpawnPolicy,
    /// The elevation front the child is, if it is one: a teardown sends it nothing.
    pub(super) front: Option<Front>,
    /// The placement channel of the cgroup leaf the child is placed in, if it has one: a refused
    /// placement it reports hands a child that ended before its ready record to the attach, and the
    /// child's exit status is read as the placement hook's only when the child has one.
    pub(super) placement: Option<&'a mut ReportChannel>,
    /// Whether the child must not run without its placement (its slot refuses a failed write). A child
    /// of such a spawn that ended before its ready record, having reported its placement refused, is
    /// handed over as it is: the attach reads the report and ends it.
    pub(super) refusing_placement: bool,
}

/// The program `invocation` runs, searched for as `execvp` searches (it is `std::process::Command`'s own
/// search), with this process's environment changed by `ops` and the nesting marker if `marker`, which
/// survives an `env_clear`. Everything the child needs is made here, before the clone.
pub(super) fn program(invocation: &Invocation, ops: &[EnvOp], marker: bool) -> Result<Program, Error> {
    let argv0 = invocation.arg0.as_deref().unwrap_or(invocation.program.as_os_str());
    let argv: Vec<&OsStr> = std::iter::once(argv0)
        .chain(invocation.args.iter().map(OsString::as_os_str))
        .collect();
    Program::searching(&invocation.program, &argv, child_env(ops, marker).into_iter()).map_err(|_| {
        Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "nul byte found in provided data",
        ))
    })
}

/// This process's environment with `ops` applied in order, then the nesting marker, as std gives it to a
/// child: in key order and without duplicates when anything changes it, and with every `name=value` entry
/// as it is (in `environ`'s order, duplicates kept) when nothing does. An entry with no `=` is not a
/// variable and is dropped, as std drops it under any env op.
fn child_env(ops: &[EnvOp], marker: bool) -> Vec<(OsString, OsString)> {
    child_env_over(std::env::vars_os(), ops, marker)
}

/// [`child_env`] over the environment `inherited`.
fn child_env_over(
    inherited: impl Iterator<Item = (OsString, OsString)>,
    ops: &[EnvOp],
    marker: bool,
) -> Vec<(OsString, OsString)> {
    if ops.is_empty() && !marker {
        return inherited.collect();
    }
    let mut env: BTreeMap<OsString, OsString> = inherited.collect();
    for op in ops {
        match op {
            EnvOp::Set(key, value) => {
                env.insert(key.clone(), value.clone());
            }
            EnvOp::Remove(key) => {
                env.remove(key);
            }
            EnvOp::Clear => env.clear(),
        }
    }
    if marker {
        env.insert(OsString::from(crate::containment::NESTED_ENV), OsString::from("1"));
    }
    env.into_iter().collect()
}

/// Spawns `program`, after `steps`, under `lock`, the caller's `spawn_lock`. The box owns `kernel`.
pub(super) fn start(
    program: &Program,
    steps: &mut InChild,
    kernel: SpawnKernel,
    on_failure: OnFailure<'_>,
    lock: &SpawnLockGuard,
) -> Result<Started, SpawnFailure> {
    start_via(fork_with_pidfd, program, steps, kernel, on_failure, lock)
}

/// [`start`] with the clone `fork`, which a test replaces.
pub(super) fn start_via(
    fork: ForkFn,
    program: &Program,
    steps: &mut InChild,
    kernel: SpawnKernel,
    on_failure: OnFailure<'_>,
    _lock: &SpawnLockGuard,
) -> Result<Started, SpawnFailure> {
    let keep_off = steps.mapped_fds();
    // SAFETY: the caller holds `spawn_lock` (`_lock`), and `InChild::run` makes raw system calls only
    // and never waits on the parent.
    let spawned = unsafe {
        fork_exec::spawn(
            CloneKind::Vfork,
            fork,
            program,
            &keep_off,
            &mut || steps.run().map_err(step_failure),
            STEP_EXIT,
        )
    };
    match spawned {
        Ok(Spawned { child, status }) => conclude(child, status, kernel, on_failure),
        Err(error) => Err(SpawnFailure::NotStarted(not_spawned(error))),
    }
}

fn step_failure(error: io::Error) -> StepFailure {
    StepFailure {
        kind: KIND_STEP,
        // An error with no errno is an `EINVAL`.
        value: error.raw_os_error().unwrap_or(libc::EINVAL) as u16,
    }
}

fn not_spawned(error: SpawnError) -> Error {
    match error {
        SpawnError::Unsupported(refusal) => Error::Unsupported {
            op: "spawn".into(),
            platform: "linux",
            detail: format!(
                "cosca requires a clone that returns the child's pidfd (clone3, or clone with CLONE_PIDFD; \
                 Linux \u{2265} 5.3), refused here: clone answered {} (kernel {})",
                refusal.name(),
                kernel_release()
            ),
            source: Some(std::sync::Arc::new(Error::Io(io::Error::from_raw_os_error(
                refusal.errno(),
            )))),
        },
        SpawnError::Fork(errno) | SpawnError::Pipe(errno) => Error::Io(io::Error::from_raw_os_error(errno)),
    }
}

/// The running kernel's release string, as `uname -r` gives it.
fn kernel_release() -> String {
    // SAFETY: an all-zero `utsname` is a valid out-parameter, and `uname` fills `release` with a NUL-terminated
    // string.
    unsafe {
        let mut name: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut name) != 0 {
            return "unknown".into();
        }
        std::ffi::CStr::from_ptr(name.release.as_ptr())
            .to_string_lossy()
            .into_owned()
    }
}

/// The error of a child that ended before the program started, from its record.
fn failed(failure: Failure) -> Error {
    let errno = match failure {
        Failure::Exec(errno) => errno,
        Failure::Step(StepFailure { kind: KIND_STEP, value }) => i32::from(value),
        Failure::Step(other) => {
            debug_assert!(
                false,
                "a step failure of kind {} is not one this spawn reports",
                other.kind
            );
            libc::EIO
        }
    };
    Error::Io(io::Error::from_raw_os_error(errno))
}

/// The error of a child that ended with no ready record and no record of a failure. `in_hook`: it left
/// with the exit status of the placement hook, which is the placement step's own end; any other end is
/// not blamed on the placement, whatever the hook reported (a slot that does not refuse a failed write
/// goes on to its exec).
fn died_before_exec(pid: u32, in_hook: bool) -> Error {
    let named = super::named(Some(pid));
    if in_hook {
        Error::Containment {
            detail: format!(
                "the spawned child ({named}) died before exec in its cgroup placement step: the program never ran"
            ),
            source: None,
        }
    } else {
        Error::Io(io::Error::other(format!(
            "the spawned child ({named}) died before exec: the program never ran"
        )))
    }
}

/// The exit code of the child `pidfd` names, which ended: it closed its status channel with no ready
/// record, which only its exit does, so the wait is for the exit that is under way. Nothing is reaped.
/// `None` for a child killed by a signal (it has no exit code), and, logged at debug, when the wait or the
/// look fails.
fn exit_code_of_ended(pidfd: BorrowedFd<'_>) -> Option<i32> {
    use rustix::event::{PollFd, PollFlags};

    use crate::os_process::child::{ExitRecord, PeekOutcome};
    use crate::wait::exit_only::{linux::peek, Target};

    // The pidfd is readable once the child has exited, whoever reaps it.
    if let Err(e) = crate::wait::poll_ready(&mut [PollFd::new(&pidfd, PollFlags::IN)]) {
        log::debug!("waiting for an ended child's pidfd failed ({e}); its exit code is unknown");
        return None;
    }
    match peek(&Target::PidFd(pidfd)) {
        Ok(PeekOutcome::Exit(ExitRecord::Status(status))) => status.code(),
        Ok(_) => None,
        Err(e) => {
            log::debug!("looking at an ended child through its pidfd failed ({e}); its exit code is unknown");
            None
        }
    }
}

/// What the status channel says of `child`: started, or torn down, and the program did not start.
fn conclude(
    child: NewChild,
    mut status: Status,
    kernel: SpawnKernel,
    mut on_failure: OnFailure<'_>,
) -> Result<Started, SpawnFailure> {
    let pid = child.pid.unsigned_abs();
    // First of all: the clone's pidfd takes the lowest free number, which can be a stdio slot that another
    // thread of the application may `dup2` over, closing it. A pidfd that cannot be moved is a failed spawn
    // of a child that may be running, whatever the channel would have said.
    let pidfd = match crate::above_stdio::above_stdio_keeping(child.pidfd) {
        Ok(pidfd) => pidfd,
        Err((e, pidfd)) => return Err(unmovable(pid, pidfd, e, kernel, on_failure)),
    };
    // `Some`: the program did not start, for this reason.
    let did_not_start = match status.progress() {
        Ok(Progress::Failed(failure)) => Some(failed(failure)),
        progress => match progress.and_then(|_| status.could_have_started()) {
            Ok(true) => None,
            // A refused placement ended the child in its placement step: the attach reads the report, which
            // says why, and ends the child. Any other child with no ready record is torn down here, with its
            // placement named when its exit status is the placement hook's.
            Ok(false) => {
                let report = on_failure.placement.as_mut().and_then(|channel| channel.reported());
                match report {
                    Some(PlacementReport::WriteFailed(_)) if on_failure.refusing_placement => None,
                    _ => {
                        let in_hook = on_failure.placement.is_some() && {
                            let code = exit_code_of_ended(pidfd.as_fd());
                            matches!(code, Some(UNSENT_EXIT | REFUSED_EXIT | ABANDONED_EXIT))
                        };
                        Some(died_before_exec(pid, in_hook))
                    }
                }
            }
            // A status channel that cannot be read proves nothing: the program did start, as far as this
            // spawn can tell.
            Err(e) => {
                log::warn!(
                    "{}: its status channel is unreadable ({}); taken to have started",
                    super::named(Some(pid)),
                    crate::error::Report(&e)
                );
                None
            }
        },
    };
    let owned = OwnedChild::over_pidfd(kernel, Some(pid), pidfd);
    match did_not_start {
        Some(cause) => {
            let torn = held_teardown::tear_down_unexecuted(
                owned,
                None,
                Past::Unexecuted,
                on_failure.policy,
                &mut Diagnosis::default(),
            );
            Err(SpawnFailure::NotStartedWithChild { cause, fate: torn.fate })
        }
        None => Ok(Started { pid, owned }),
    }
}

/// The failed spawn of the child `pid`, whose pidfd `e` kept from moving above stdio: the child may be
/// running, so it is torn down through the box over the pidfd as it is, as any other failure of a held child.
fn unmovable(pid: u32, pidfd: OwnedFd, e: io::Error, kernel: SpawnKernel, on_failure: OnFailure<'_>) -> SpawnFailure {
    let owned = OwnedChild::over_pidfd(kernel, Some(pid), pidfd);
    let how = held_teardown::HeldTeardown {
        front: on_failure.front,
        id: None,
        reach: None,
        disposition: Disposition::HandBack,
        policy: on_failure.policy,
    };
    let (detail, torn) = held_teardown::tear_down_held(owned, how, &mut Diagnosis::default());
    let Torn {
        fate,
        unreaped,
        cleanup,
    } = torn;
    SpawnFailure::started(
        Error::Io(crate::error::io_context("moving the child's pidfd above stdio", e)),
        fate,
        unreaped,
    )
    .with_detail(detail)
    .with_cleanup(cleanup)
}

#[cfg(test)]
#[path = "fork_spawn_tests.rs"]
mod fork_spawn_tests;

#[cfg(all(test, feature = "tokio"))]
#[path = "fork_spawn/slow_teardown_tests.rs"]
mod slow_teardown_tests;
