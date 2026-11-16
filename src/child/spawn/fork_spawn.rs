//! Linux: the ordinary spawn, on the fork-exec core ([`fork_exec`]).
//!
//! The child is cloned with [`CloneKind::Vfork`]: the parent is suspended until the child's `execve` or
//! exit, so every record the child wrote is in the status channel when the clone returns, and the
//! parent reads them without waiting. The pidfd comes from the clone, so the box over the child exists
//! at once. The spawn's answer is decided by the records alone:
//!
//! - an errno record: a step or the `execve` failed, the program did not start, and the errno is the
//!   spawn's error;
//! - no ready record: the child ended before its `execve`; the program did not start, and the child is
//!   torn down through its box ([`Past::Unexecuted`]). Exception: a refused placement, which goes to the
//!   attach (see `OnFailure::refusing_placement`);
//! - a ready record and no errno: the program started, or was killed between the ready record and the
//!   `execve`. `Ok` means the spawn could not prove the program did not start, and the child's wait
//!   reports the signal.
//!
//! The channel also carries the child's placement report when it has a cgroup leaf: the spawn records it
//! on the leaf, whatever becomes of the child, and the leaf's verdict reads it without waiting. A channel
//! the spawn cannot read leaves the placement unknown
//! ([`PlacementReport::Unknown`]): the child may be in the leaf, in its process group, or neither, so the
//! attach fails the spawn and tears the child down, and the leaf is killed through.
//!
//! The child's steps are [`InChild`]'s (stdio, directory, process group, then cosca's own). Neither side
//! waits for the other: no step may wait on the parent.
//!
//! The program is found before the clone ([`program`]), by cosca's own search over the child's `PATH`
//! (`crate::resolve::posix`): the child only `execve`s the path. A program that is not found is an error
//! with no child made.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::OwnedFd;
use std::path::PathBuf;

use super::fork_exec::{self, Failure, Program, Progress, SpawnError, Spawned, Status, StepFailure};
use super::in_child::{InChild, Step, StepError};
use super::policy::SpawnPolicy;
use super::{held_teardown, Diagnosis, Invocation, SpawnFailure, SpawnLockGuard};
use crate::child::drop_teardown::Torn;
use crate::child::owned::teardown::{Disposition, Past};
use crate::child::owned::OwnedChild;
use crate::containment::cgroup::{CgroupLeaf, PlacementReport};
use crate::elevation::front::TrackedKind;
use crate::error::Error;
use crate::identity::SpawnKernel;
use crate::os_process::linux::fork::{fork_with_pidfd, CloneKind, ForkFn, NewChild};

/// The kind of step failure the child reports: an in-child step failed, with this errno.
const KIND_STEP: u8 = 1;

/// The kind of step failure of the placement step: the child's cgroup placement failed, with this errno.
const KIND_PLACEMENT: u8 = 2;

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
    /// Who the process the child tracks is: the box holds it, and a front is sent nothing.
    pub(super) tracked: TrackedKind,
    /// The cgroup leaf the child is placed in, if it has one: the child's placement report is recorded
    /// on it, whatever becomes of the child.
    pub(super) placement: Option<&'a mut CgroupLeaf>,
    /// Whether the child must not run without its placement (its slot refuses a failed write). A child
    /// of such a spawn that reported its placement refused is handed over as it is, ended: the attach
    /// reads the report.
    pub(super) refusing_placement: bool,
}

/// The program `invocation` runs, which [`Invocation::find`] has found, with `later`, the candidates it
/// returned, and the environment `env` the search read its `PATH` from. Everything the child needs is
/// made here, before the clone.
pub(super) fn program(
    invocation: &Invocation,
    later: &[PathBuf],
    env: Vec<(OsString, OsString)>,
) -> Result<Program, Error> {
    let argv0 = invocation.arg0.as_deref().unwrap_or(invocation.program.as_os_str());
    let argv: Vec<&OsStr> = std::iter::once(argv0)
        .chain(invocation.args.iter().map(OsString::as_os_str))
        .collect();
    let paths: Vec<&OsStr> = std::iter::once(invocation.program.as_os_str())
        .chain(later.iter().map(|p| p.as_os_str()))
        .collect();
    Program::new(&paths, &argv, env.into_iter()).map_err(|_| {
        Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "nul byte found in provided data",
        ))
    })
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
            &mut |reporter| steps.run(reporter).map_err(step_failure),
            STEP_EXIT,
        )
    };
    match spawned {
        Ok(Spawned { child, status }) => conclude(child, status, kernel, on_failure),
        Err(error) => Err(SpawnFailure::NotStarted(not_spawned(error))),
    }
}

/// The failure record of a failed step: the placement step's own kind, or the other steps'.
fn step_failure(failed: StepError) -> StepFailure {
    StepFailure {
        kind: match failed.step {
            Step::Placement => KIND_PLACEMENT,
            _ => KIND_STEP,
        },
        // An error with no errno is an `EINVAL`.
        value: failed.error.raw_os_error().unwrap_or(libc::EINVAL) as u16,
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

/// The error of the child `pid`, which ended before the program started, from its record: a failure of the
/// placement step is [`Error::Containment`]; any other is the errno.
fn failed(pid: u32, failure: Failure) -> Error {
    let errno = match failure {
        Failure::Exec(errno) => errno,
        Failure::Step(StepFailure { kind: KIND_STEP, value }) => i32::from(value),
        Failure::Step(StepFailure {
            kind: KIND_PLACEMENT,
            value,
        }) => {
            return Error::Containment {
                detail: format!(
                    "the spawned child ({}) died before exec in its cgroup placement step: the program never ran",
                    super::named(Some(pid))
                ),
                source: Some(Error::io_cause(io::Error::from_raw_os_error(i32::from(value)))),
            };
        }
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

/// The error of a child that ended with no ready record and no record of a failure.
fn died_before_exec(pid: u32) -> Error {
    Error::Io(io::Error::other(format!(
        "the spawned child ({}) died before exec: the program never ran",
        super::named(Some(pid))
    )))
}

/// What `status` says so far and what the child reported of its placement, which is recorded on `leaf`
/// when there is one. The records are final once the progress is a failure, the end or `Ready`.
///
/// A channel that cannot be read does not say where the child is, nor whether it reported: that is
/// [`PlacementReport::Unknown`], not a placement and not an absence (a kill through the leaf is owed
/// wherever there is no proof of absence, and the attach builds nothing on a proof it lacks).
fn read_records(status: &mut Status, leaf: Option<&mut CgroupLeaf>) -> (io::Result<Progress>, Option<PlacementReport>) {
    let progress = status.progress();
    let reported = status.reported().map(PlacementReport::of_record);
    let report = match (&progress, reported) {
        (_, Some(report)) => Some(report),
        // An error with no errno is an `EIO`.
        (Err(e), None) => Some(PlacementReport::Unknown(e.raw_os_error().unwrap_or(libc::EIO))),
        (Ok(progress), None) => {
            // The child's placement step writes the report before its ready record.
            debug_assert!(
                leaf.is_none() || !matches!(progress, Progress::Ready | Progress::Ended { ready: true }),
                "a child with a cgroup leaf reached its execve with no placement report"
            );
            None
        }
    };
    if let (Some(leaf), Some(report)) = (leaf, report) {
        leaf.record_placement(report);
    }
    (progress, report)
}

/// What the status channel says of `child`: started, or torn down, and the program did not start. The
/// child's placement report, if the channel holds one, is recorded on `on_failure.placement`.
fn conclude(
    child: NewChild,
    mut status: Status,
    kernel: SpawnKernel,
    mut on_failure: OnFailure<'_>,
) -> Result<Started, SpawnFailure> {
    let pid = child.pid.unsigned_abs();
    // First of all: the clone's pidfd takes the lowest free number, which can be a stdio slot that another
    // thread of the application may `dup2` over, closing it. A pidfd that cannot be moved is a failed spawn
    // of a child that may be running, whatever the channel would have said (the leaf still learns what the
    // child reported of its placement).
    let pidfd = match crate::above_stdio::above_stdio_keeping(child.pidfd) {
        Ok(pidfd) => pidfd,
        Err((e, pidfd)) => {
            _ = read_records(&mut status, on_failure.placement.as_deref_mut());
            return Err(unmovable(pid, pidfd, e, kernel, on_failure));
        }
    };
    let (progress, report) = read_records(&mut status, on_failure.placement.as_deref_mut());
    // A child whose refusing placement failed ended in its placement step: the attach reads the report,
    // which says why, and ends the child.
    let refused = on_failure.refusing_placement && matches!(report, Some(PlacementReport::WriteFailed(_)));
    // `Some`: the program did not start, for this reason.
    let did_not_start = if refused {
        None
    } else {
        match progress {
            Ok(Progress::Failed(failure)) => Some(failed(pid, failure)),
            progress => match progress.and_then(|_| status.could_have_started()) {
                Ok(true) => None,
                Ok(false) => Some(died_before_exec(pid)),
                // A status channel that cannot be read proves nothing: the program did start, as far as
                // this spawn can tell.
                Err(e) => {
                    log::warn!(
                        "{}: its status channel is unreadable ({}); taken to have started",
                        super::named(Some(pid)),
                        crate::error::Report(&e)
                    );
                    None
                }
            },
        }
    };
    let owned = OwnedChild::over_pidfd(kernel, Some(pid), pidfd, on_failure.tracked);
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
    let owned = OwnedChild::over_pidfd(kernel, Some(pid), pidfd, on_failure.tracked);
    let how = held_teardown::HeldTeardown {
        front: on_failure.tracked.front(),
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

#[cfg(test)]
#[path = "fork_spawn/lookup_tests.rs"]
mod lookup_tests;

#[cfg(all(test, feature = "tokio"))]
#[path = "fork_spawn/slow_teardown_tests.rs"]
mod slow_teardown_tests;
