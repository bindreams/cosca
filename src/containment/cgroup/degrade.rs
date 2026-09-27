//! Degrade reasons: pure data — no OS calls — so these compile, and their formatting is
//! unit-tested, on every host rather than only where the mechanism exists.

use std::fmt;
use std::io;
use std::path::PathBuf;

/// Why a cgroup v2 leaf could not be created. Each variant names the step that failed, the
/// path it touched, and the kernel's own reason: the caller degrades to a process group
/// either way, but it degrades *stating which precondition was missing*.
#[derive(Debug, thiserror::Error)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum LeafError {
    /// `/proc/self/cgroup` could not be read (no procfs, or it is not mounted).
    #[error("could not read /proc/self/cgroup: {0}")]
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
    /// `mkdir` of the leaf failed — most often an undelegated slice the supervisor may not
    /// write to (`EACCES`/`EPERM`), or a read-only cgroupfs (`EROFS`).
    #[error("could not create the leaf cgroup {}: {source}", path.display())]
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
    #[error("could not check for {}: {source}", path.display())]
    CheckKill {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// `cgroup.procs` could not be opened for writing, or moved to fd 3 or above.
    #[error("could not open {} for writing: {source}", path.display())]
    OpenProcs {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The channel the child reports its self-placement outcome through could not be opened, or
    /// its ends moved to fd 3 or above. Without it the child's own report would be
    /// unobservable, so the leaf is not created half-instrumented.
    #[error("could not open the placement-report channel shared with the forked child: {0}")]
    OpenReportChannel(#[source] io::Error),
    /// The watch the leaf's removal waits on could not be armed: an inotify instance or watch
    /// (`fs.inotify.max_user_instances`, `fs.inotify.max_user_watches`), or `cgroup.events`
    /// itself. It is armed at creation so that no later teardown can find itself without one.
    #[error("could not watch {} for its drain: {source}", path.display())]
    WatchDrain {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
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
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum NotEntered {
    /// It exited before reporting its placement outcome (see [`PlacementReport::NotReported`]).
    NotReported,
    /// Its `write` to `cgroup.procs` failed with this errno.
    WriteFailed(i32),
}

impl fmt::Display for NotEntered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            NotEntered::NotReported => PlacementReport::NotReported.fmt(f),
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
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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
        /// The child's `/proc/<pid>` state letter, read BEFORE `procs`: `Z` means it had
        /// exited before the file was read.
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
    /// The child's exit could not be watched, so its report could not be waited for, and the
    /// leaf was removed before the child entered it: it never can.
    Unwaitable {
        pid: u32,
        /// `pidfd_open`'s error.
        source: io::Error,
    },
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
            NotPlaced::Unreadable {
                pid,
                path,
                source,
                report,
            } => write!(
                f,
                "child {pid} is not in the leaf cgroup: {report}; {} could not be read: {source}",
                path.display()
            ),
            NotPlaced::Unwaitable { pid, source } => write!(
                f,
                "child {pid}'s placement report cannot be waited for: pidfd_open failed: {source}; \
                 the leaf cgroup was removed before the child entered it"
            ),
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
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn log_degrade(reason: &dyn fmt::Display) {
    log::warn!("cgroup v2 containment: degrading to a process group — {reason}");
}

#[cfg(test)]
#[path = "degrade_tests.rs"]
mod degrade_tests;
