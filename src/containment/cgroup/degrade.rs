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
    /// The own cgroup's directory or its `cgroup.procs` could not be opened for a leaf.
    #[error("could not open {} for a leaf", path.display())]
    OpenOwnCgroup {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// `mkdir` of the leaf failed. A refusal (`EACCES`, `EPERM`, `EROFS`) is the host not offering
    /// the cgroup: an undelegated slice, a read-only cgroupfs, or a policy such as Landlock or
    /// AppArmor.
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
            | LeafError::OpenOwnCgroup { source, .. }
            | LeafError::CreateLeafDir { source, .. }
            | LeafError::CheckKill { source, .. }
            | LeafError::OpenProcs { source, .. }
            | LeafError::WatchDrain { source, .. } => Some(crate::error::Error::io_cause(source)),
            LeafError::NoUnifiedLine { .. } | LeafError::KillUnsupported { .. } => None,
        };
        crate::error::Error::Containment { detail, source }
    }
}

/// What the child's own self-placement write reported back to the parent.
///
/// This is the one step whose reason lives entirely in the forked child: it runs after the clone,
/// in a copy-on-write address space, under async-signal-safety rules that forbid allocating or
/// formatting anything. The child therefore reports a single word, a report record on the spawn
/// core's status channel (see `child::spawn::fork_exec`), which this enum names.
///
/// The report belongs to the LEAF, not to a child: the spawn records what it read on the leaf of
/// the spawn ([`CgroupLeaf::record_placement`]). Production creates one leaf per spawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "produced and consumed only by the linux-gated cgroup leaf machinery"
    )
)]
pub(crate) enum PlacementReport {
    /// The child's report is not in its status channel: it ended before its placement step wrote it,
    /// or the spawn has recorded none.
    NotReported,
    /// The child's `write` to `cgroup.procs` succeeded — at that instant it WAS a member.
    Placed,
    /// The child's `write` to `cgroup.procs` failed with this errno.
    WriteFailed(i32),
    /// The spawn could not read the child's status channel (this errno), so what the child reported, and
    /// whether it exec'd, is not known: it may be in the leaf, in its process group, or neither.
    Unknown(i32),
}

impl PlacementReport {
    /// The report a child's report record `value` says: 0 is a placement, any other value the write's
    /// errno.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "read only by the linux-gated spawn")
    )]
    pub(crate) fn of_record(value: u16) -> PlacementReport {
        match value {
            0 => PlacementReport::Placed,
            errno => PlacementReport::WriteFailed(i32::from(errno)),
        }
    }
}

impl fmt::Display for PlacementReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlacementReport::NotReported => f.write_str(
                "the child exited before reporting its placement outcome (its placement step may not \
                     have run, or may have been interrupted)",
            ),
            PlacementReport::Placed => f.write_str("the child's self-placement write succeeded"),
            PlacementReport::WriteFailed(errno) => write!(
                f,
                "the child's write to cgroup.procs failed: {} (errno {errno})",
                io::Error::from_raw_os_error(*errno)
            ),
            PlacementReport::Unknown(errno) => write!(
                f,
                "the spawn could not read the child's status channel, so it is not known whether the child \
                 entered its leaf: {} (errno {errno})",
                io::Error::from_raw_os_error(*errno)
            ),
        }
    }
}

/// What a child that is not proven to be in its leaf reported: never a successful write.
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
    /// Its `write` to `cgroup.procs` failed with this errno.
    WriteFailed(i32),
    /// The spawn could not read what it reported (see [`PlacementReport::Unknown`]): it may be in the leaf.
    Unknown(i32),
}

impl fmt::Display for NotEntered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            NotEntered::NotReported => PlacementReport::NotReported.fmt(f),
            NotEntered::WriteFailed(errno) => PlacementReport::WriteFailed(errno).fmt(f),
            NotEntered::Unknown(errno) => PlacementReport::Unknown(errno).fmt(f),
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

impl NotPlaced {
    /// The error of the `cgroup.procs` read that failed, if it did: the diagnosis's own failure,
    /// which is not why the child is not in the leaf.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "read only by the linux-gated attach")
    )]
    pub(crate) fn into_read_failure(self) -> Option<io::Error> {
        match self {
            NotPlaced::Absent { .. } => None,
            NotPlaced::Unreadable { source, .. } => Some(source),
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
