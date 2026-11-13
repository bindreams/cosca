//! Degrade reasons: pure data — no OS calls — so these compile, and their formatting is
//! unit-tested, on every host rather than only where the mechanism exists.

use std::fmt;
use std::io;
use std::path::PathBuf;

/// Why a cgroup v2 leaf could not be created. Each variant names its step, and its path where it
/// has one; a variant for a failed call keeps that call's OS error as its `source`. A
/// `BestEffort` caller degrades to a process group, stating which precondition was missing; a
/// `Strongest` one fails the spawn with it ([`LeafError::into_containment`]).
#[derive(Debug, thiserror::Error)]
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "produced and consumed only by the linux-gated cgroup leaf machinery"
    )
)]
pub(crate) enum LeafError {
    /// `/proc/self/cgroup` could not be read (no procfs, or it is not mounted).
    #[error("could not read /proc/self/cgroup")]
    ReadProcSelfCgroup(#[source] io::Error),
    /// `/proc/self/cgroup` has no `0::` line: a v1-only host, or no unified hierarchy.
    ///
    /// Carries a summary of the file, never the file. See [`summarize_cgroup_controllers`].
    #[error(
        "/proc/self/cgroup has no cgroup v2 unified (`0::`) line — a v1-only host, or the \
         unified hierarchy is not mounted; the file has {line_count} line(s), naming \
         {controllers} (their paths are dropped: none of them is one cosca touched, and they \
         do not tell these cases apart)"
    )]
    NoUnifiedLine { line_count: usize, controllers: String },
    /// Whether this process may use its own cgroup could not be determined: the check failed with
    /// something other than a refusal or a path that is not there.
    #[error("could not check whether {} may be used for a leaf", path.display())]
    CheckAccess {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// As [`LeafError::CheckAccess`], on a kernel before Linux 5.8 for a process whose effective
    /// ids differ from its real ones: the kernel has no `faccessat2`, and the older `faccessat`
    /// checks the real ids.
    #[error(
        "could not check whether {} may be used for a leaf: the kernel has no faccessat2 (before \
         Linux 5.8), and the older faccessat checks real ids, which differ from this process's \
         effective ids",
        path.display()
    )]
    CheckAccessUnavailable {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// `mkdir` of the leaf failed — most often an undelegated slice the supervisor may not
    /// write to (`EACCES`/`EPERM`), or a read-only cgroupfs (`EROFS`).
    #[error("could not create the leaf cgroup {}", path.display())]
    CreateLeafDir {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The leaf exists but exposes no `cgroup.kill`, so there is no atomic, fork-proof kill
    /// and the mechanism would not be what `Containment::CgroupV2` promises.
    #[error(
        "the leaf cgroup {} has no cgroup.kill — the kernel is older than 5.14, so there is \
         no atomic tree kill to back CgroupV2 containment",
        path.display()
    )]
    KillUnsupported { path: PathBuf },
    /// Whether the leaf has a `cgroup.kill` could not be determined: the lookup itself failed.
    #[error("could not check for {}", path.display())]
    CheckKill {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// `cgroup.procs` could not be opened for writing, or moved to fd 3 or above.
    #[error("could not open {} for writing", path.display())]
    OpenProcs {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The channel the child reports its self-placement outcome through could not be opened, or
    /// its ends moved to fd 3 or above. Without it the child's own report would be
    /// unobservable, so the leaf is not created half-instrumented.
    #[error("could not open the placement-report channel shared with the forked child")]
    OpenReportChannel(#[source] io::Error),
    /// The watch the leaf's removal waits on could not be armed: an inotify instance or watch
    /// (`fs.inotify.max_user_instances`, `fs.inotify.max_user_watches`), or `cgroup.events`
    /// itself. It is armed at creation so that no later teardown can find itself without one.
    #[error("could not watch {} for its drain", path.display())]
    WatchDrain {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl LeafError {
    /// The failure of a spawn that asked for a cgroup and could not have it: [`Error::Containment`]
    /// naming the failed step and its path, with the OS error that failed it as its source.
    ///
    /// [`Error::Containment`]: crate::error::Error::Containment
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "called only by the linux-gated spawn")
    )]
    pub(crate) fn into_containment(self) -> crate::error::Error {
        let detail = format!("cgroup v2: {self}");
        let source = match self {
            LeafError::ReadProcSelfCgroup(source)
            | LeafError::OpenReportChannel(source)
            | LeafError::CheckAccess { source, .. }
            | LeafError::CheckAccessUnavailable { source, .. }
            | LeafError::CreateLeafDir { source, .. }
            | LeafError::CheckKill { source, .. }
            | LeafError::OpenProcs { source, .. }
            | LeafError::WatchDrain { source, .. } => Some(crate::error::Error::io_cause(source)),
            LeafError::NoUnifiedLine { .. } | LeafError::KillUnsupported { .. } => None,
        };
        crate::error::Error::Containment { detail, source }
    }
}

/// What the child's own `pre_exec` self-placement write reported back to the parent.
///
/// This is the one step whose reason lives entirely in the forked child: it runs after
/// `fork`, in a copy-on-write address space, under async-signal-safety rules that forbid
/// allocating or formatting anything. The child therefore reports a single word through a
/// socket pair (see [`ReportChannel`]), which this enum names.
///
/// The channel belongs to the LEAF, not to a child. Production creates one leaf per spawn, so the
/// distinction is invisible there; several children sharing one leaf would share one channel, and
/// the first report written would stand for all of them (see [`ReportChannel`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "produced and consumed only by the linux-gated cgroup leaf machinery"
    )
)]
pub(crate) enum PlacementReport {
    /// The child exited before reporting its placement outcome: its `pre_exec` may not have run,
    /// or may have been interrupted between the write and the send. It never exec'd either way.
    NotReported,
    /// The child's `write` to `cgroup.procs` succeeded — at that instant it WAS a member.
    Placed,
    /// The child's `write` to `cgroup.procs` failed with this errno.
    WriteFailed(i32),
}

impl fmt::Display for PlacementReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlacementReport::NotReported => f.write_str(
                "the child exited before reporting its placement outcome (its pre_exec may not \
                     have run, or may have been interrupted)",
            ),
            PlacementReport::Placed => f.write_str("the child's pre_exec self-placement write succeeded"),
            PlacementReport::WriteFailed(errno) => write!(
                f,
                "the child's pre_exec write to cgroup.procs failed: {} (errno {errno})",
                io::Error::from_raw_os_error(*errno)
            ),
        }
    }
}

/// What a child with nothing in its leaf reported: never a successful write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "produced and consumed only by the linux-gated cgroup leaf machinery"
    )
)]
pub(crate) enum NotEntered {
    /// It exited before reporting its placement outcome (see [`PlacementReport::NotReported`]).
    NotReported,
    /// Its hook could not send its report and stopped before `exec`: it exited with
    /// `UNSENT_EXIT` (`leaf.rs`). The program never ran.
    ReportUnsent,
    /// Its `write` to `cgroup.procs` failed with this errno.
    WriteFailed(i32),
}

impl fmt::Display for NotEntered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            NotEntered::NotReported => PlacementReport::NotReported.fmt(f),
            NotEntered::ReportUnsent => f.write_str(
                "the child could not send its placement report to this process, and stopped \
                 before exec",
            ),
            NotEntered::WriteFailed(errno) => PlacementReport::WriteFailed(errno).fmt(f),
        }
    }
}

/// Why a spawned child is not in its leaf, with every fact the diagnosis rests on.
///
/// The child's own report decides membership (see [`CgroupLeaf::take_placement`]).
/// `cgroup.procs` and the child's `/proc` state are read only to diagnose a child that
/// reported no successful write.
#[derive(Debug)]
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "produced and consumed only by the linux-gated cgroup leaf machinery"
    )
)]
pub(crate) enum NotPlaced {
    /// `cgroup.procs` was read.
    Absent {
        pid: u32,
        /// The `cgroup.procs` that was read.
        path: PathBuf,
        /// Its verbatim contents.
        procs: String,
        /// The leaf's placement report — the outcome of the last self-placement write made
        /// through it, which for a production leaf is `pid`'s own.
        report: NotEntered,
        /// The child's state letter, found BEFORE `procs` is read: `Z` means its pidfd showed it
        /// exited (reaped or not), and any other letter is its `/proc/<pid>` state while it had
        /// not.
        child_state: Option<char>,
    },
    /// `cgroup.procs` could not be read.
    Unreadable {
        pid: u32,
        path: PathBuf,
        source: io::Error,
        /// As in [`NotPlaced::Absent`]: the leaf's report, not `pid`'s in general.
        report: NotEntered,
    },
}

impl NotPlaced {
    /// What the child reported, which is why it is not in the leaf.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "read only by the linux-gated attach")
    )]
    pub(crate) fn report(&self) -> NotEntered {
        match self {
            NotPlaced::Absent { report, .. } | NotPlaced::Unreadable { report, .. } => *report,
        }
    }
}

impl fmt::Display for NotPlaced {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NotPlaced::Absent {
                pid,
                path,
                procs,
                report,
                child_state,
            } => {
                let listed = procs.trim();
                let listed = if listed.is_empty() {
                    "empty".to_string()
                } else {
                    format!("{listed:?}")
                };
                // The state was read before `cgroup.procs`, so `Z` means the child had exited
                // before the file was read.
                let state = match child_state {
                    Some('Z') => "it had already exited when cgroup.procs was read".to_string(),
                    Some(state) => format!("it is still running (/proc state {state})"),
                    None => "its /proc state could not be read".to_string(),
                };
                write!(
                    f,
                    "child {pid} is not in the leaf cgroup: {report}; {} is {listed}; {state}",
                    path.display()
                )
            }
            NotPlaced::Unreadable { pid, path, report, .. } => write!(
                f,
                "child {pid} is not in the leaf cgroup: {report}; {} could not be read",
                path.display()
            ),
        }
    }
}

impl std::error::Error for NotPlaced {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NotPlaced::Absent { .. } => None,
            NotPlaced::Unreadable { source, .. } => Some(source),
        }
    }
}

/// Record that this spawn is not getting the containment it asked for, and why.
///
/// One function for every degrade site so the wording is composed once: whichever step failed,
/// the log carries a single line naming the achieved mechanism and the reason the stronger one
/// was unavailable.
///
/// Logged at `warn` on every call; deduplication is the log handler's job.
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "dispatch.rs's only call sites are behind cgroup::try_create_leaf/CgroupLeaf::take_placement, both linux-gated"
    )
)]
pub(crate) fn log_degrade(reason: &(dyn std::error::Error + 'static)) {
    log::warn!(
        "cgroup v2 containment: degrading to a process group — {report}",
        report = crate::error::Report(reason)
    );
}

#[cfg(test)]
#[path = "degrade_tests.rs"]
mod degrade_tests;
