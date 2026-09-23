//! Linux cgroup v2 leaf containment.
//!
//! When cgroup v2 is mounted, delegated, and writable with `cgroup.kill`
//! support, the spawned child is placed in a freshly created leaf sub-cgroup.
//! Teardown writes `"1"` to `cgroup.kill` — the kernel atomically kills every
//! process in the leaf (fork-proof). Falls back to the process-group mechanism
//! when any precondition fails (see `try_create_leaf`).
//!
//! # Delegation prerequisite
//! cgroup v2 requires "no internal processes": a non-root cgroup may not
//! contain processes AND child cgroups simultaneously. This implementation
//! creates the leaf as a direct child of the supervisor's cgroup, which works
//! correctly only when the supervisor's cgroup is already an inner node (i.e.
//! it contains no processes itself). This is the normal case in properly
//! delegated slices (systemd user slices, container environments). On hosts
//! where the supervisor IS a leaf (root cgroup, or an undelegated slice), the
//! child's `cgroup.procs` write will fail with EBUSY/EINVAL; the `pre_exec`
//! closure handles this gracefully by falling back to the process-group
//! mechanism without aborting the spawn.
//!
//! # Async-signal-safety
//! `place_self_in_cgroup_pre_exec` is called inside a `pre_exec` closure
//! (after `fork`, before `exec`). The only async-signal-safe operations there
//! are raw `libc::write`, `libc::close` and `libc::send` — no allocation, no
//! `format!`, no `String`. Its outcome crosses back through a socket pair
//! (`ReportChannel`).
//!
//! # Placement reports: when one is final, and what cosca may kill
//! Every decision about a leaf rests on these rules. `take_placement`, `decide_unwaitable`,
//! `abandon` and `Drop` each apply them; none has a rule of its own.
//!
//! **Final.** The child sends at most one report, before `exec`. A report is final once it has
//! been received, or once the child can no longer send one: it has exited (seen through a pidfd
//! or `waitid`), or the leaf is removed (a removed leaf admits no member, so the child's write
//! fails). Until then the report is in flight, whatever `spawn` returned — std's `spawn` can
//! return before the child has run any `pre_exec`. Nothing received is not "not entered".
//!
//! **Absence.** Nothing of the child's is in the leaf only when there is proof of it:
//! - a final report other than `Placed` — the child either never entered, or exited before
//!   reporting (its placement may have been interrupted between the write and the send). Either
//!   way it never exec'd, so it never ran a program that could fork into the leaf; or
//! - the leaf's own removal — `rmdir` succeeds only on a leaf with no live member.
//!
//! **Kill.** cosca kills through a leaf whenever it lacks proof of absence, and never when it has
//! it: an occupant of a leaf that provably holds nothing of the child's is not cosca's to kill. So an
//! occupied leaf whose report is still in flight is killed through, and then removed — killed
//! again for as long as anything re-enters it before the removal lands.
//!
//! **Ownership.** Until `spawn` returns, the child is this process's own unreaped child, and cosca
//! is the only thing that may signal it (see `Command::contain`). It leads its own process group
//! (`process_group(0)`), and anything it forks after `exec` starts in that group. A child cosca
//! gives up on is killed as a group: its descendants are its to answer for, in or out of the
//! leaf. The group's id cannot name another group while the child is unreaped — a pid number is
//! not reused while any task, a zombie leader or a group member, still holds it.

// The parsers below are pure (no OS deps) — compiled on all platforms so their unit tests run
// on any host.

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};

/// Whether the cgroup at `path` is `leaf` itself or nested under it. Both are unified-hierarchy
/// paths as `/proc/<pid>/cgroup` prints them.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn is_at_or_under(path: &str, leaf: &str) -> bool {
    path.strip_prefix(leaf)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Parse the `0::` (cgroup v2 unified hierarchy) line from the contents of
/// `/proc/self/cgroup`. Returns the relative path (e.g. `/user.slice/…`) on
/// success, or `None` when no such line is present (v1-only or empty).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn parse_v2_relative_path(proc_self_cgroup: &str) -> Option<&str> {
    for line in proc_self_cgroup.lines() {
        // The v2 unified line has the form `0::<path>` — hierarchy id 0, empty
        // controller list, followed by the path. v1 lines have non-empty
        // controller fields: `<id>:<controller>:<path>`.
        if let Some(rest) = line.strip_prefix("0::") {
            return Some(rest);
        }
    }
    None
}

/// Summarize the contents of `/proc/self/cgroup` for a degrade record: how many lines it had,
/// and the `<hierarchy-id>:<controller-list>` prefix of each — never the paths.
///
/// What separates "a v1-only host" from "the unified hierarchy is not mounted" from "the file
/// was empty" is the line count and the controllers named, and that is the whole of what comes
/// back. The paths add nothing to it: this file is a whole-system dump of every hierarchy the
/// caller is in, cosca reads it for one `0::` line, and in the case this error reports there
/// is no such line — so none of those paths is one cosca ever touched. They are, however, the
/// caller's identity (uid, systemd session and scope, pod UID and container id under
/// Kubernetes or Docker), handed to a sink cosca knows nothing about.
///
/// **This is not a rule about paths in general, and the sibling variants deliberately do not
/// follow it.** `CreateLeafDir`, `OpenProcs`, `KillUnsupported` and the rest each carry their
/// path verbatim, because there it is the single path the failing syscall touched — the
/// diagnosis itself, and what every library reports. "mkdir failed: EACCES" with the directory
/// removed would be unactionable. The line drawn here is between a path cosca acted on and a
/// file it only read to look something up in.
///
/// A line the documented `<id>:<controllers>:<path>` shape does not explain is reported as
/// unparseable rather than quoted: an unrecognized line is precisely the case where cosca
/// cannot know which part of it is a path.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn summarize_cgroup_controllers(proc_self_cgroup: &str) -> (usize, String) {
    let mut controllers: Vec<&str> = Vec::new();
    for line in proc_self_cgroup.lines() {
        match line.match_indices(':').nth(1) {
            Some((path_start, _)) => controllers.push(&line[..path_start]),
            None => controllers.push("<unparseable line>"),
        }
    }
    let rendered = if controllers.is_empty() {
        "no controllers".to_string()
    } else {
        controllers.join(", ")
    };
    (controllers.len(), rendered)
}

/// Parse the `populated` field out of the contents of a cgroup v2 `cgroup.events` file
/// (`populated 0`/`populated 1`, one `key value` pair per line, order not guaranteed).
/// `None` means the file had no `populated` line, or an unrecognized value — the caller
/// must treat this as "could not be assessed", never silently default to either state.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn parse_populated(contents: &str) -> Option<bool> {
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("populated ") {
            return match rest.trim() {
                "0" => Some(false),
                "1" => Some(true),
                _ => None,
            };
        }
    }
    None
}

/// Extract the process state letter (`R`, `S`, `Z`, …) from the contents of a
/// `/proc/<pid>/stat` line. `None` when the line is absent or malformed — never a guessed
/// state.
///
/// Field 2 (`comm`) is arbitrary bytes wrapped in parentheses and may itself contain spaces
/// and parentheses, so splitting on whitespace from the start misplaces every later field.
/// The scan therefore begins after the LAST `)` in the line, which is where the kernel's
/// fixed-shape, whitespace-separated tail starts; field 3 there is the state.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn parse_proc_stat_state(stat: &str) -> Option<char> {
    let tail = &stat[stat.rfind(')')? + 1..];
    tail.split_whitespace().next()?.chars().next()
}

// Degrade reasons =====
// Pure data — no OS calls — so these compile, and their formatting is unit-tested, on every
// host rather than only where the mechanism exists.

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

/// The step a contained spawn degraded at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum DegradeKind {
    ReadProcSelfCgroup,
    NoUnifiedLine,
    CreateLeafDir,
    KillUnsupported,
    CheckKill,
    OpenProcs,
    OpenReportChannel,
    PidfdUnavailable,
    PlacementNotReported,
    PlacementWriteFailed,
}

/// One condition a contained spawn can degrade for: the step, and the errno it failed with
/// where it has one.
///
/// A reason's TEXT varies per spawn (paths, the child's own state); its condition is what an
/// embedder can act on, and is what [`log_degrade`] warns about once per process. The errno is
/// part of it because one step fails for different reasons that need different fixes: a
/// transient `ENOMEM` from `mkdir` is not the standing `EACCES` of an undelegated slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct DegradeCondition {
    pub(crate) kind: DegradeKind,
    pub(crate) errno: Option<i32>,
}

/// A reason a spawn degraded: its full text, plus which condition it is an instance of.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) trait DegradeReason: fmt::Display {
    fn condition(&self) -> DegradeCondition;
}

impl DegradeReason for LeafError {
    fn condition(&self) -> DegradeCondition {
        let (kind, source) = match self {
            LeafError::ReadProcSelfCgroup(e) => (DegradeKind::ReadProcSelfCgroup, Some(e)),
            LeafError::NoUnifiedLine { .. } => (DegradeKind::NoUnifiedLine, None),
            LeafError::CreateLeafDir { source, .. } => (DegradeKind::CreateLeafDir, Some(source)),
            LeafError::KillUnsupported { .. } => (DegradeKind::KillUnsupported, None),
            LeafError::CheckKill { source, .. } => (DegradeKind::CheckKill, Some(source)),
            LeafError::OpenProcs { source, .. } => (DegradeKind::OpenProcs, Some(source)),
            LeafError::OpenReportChannel(e) => (DegradeKind::OpenReportChannel, Some(e)),
        };
        DegradeCondition {
            kind,
            errno: source.and_then(io::Error::raw_os_error),
        }
    }
}

impl DegradeReason for NotPlaced {
    /// The child's own report, never how `cgroup.procs` read: that is diagnosis, not cause.
    fn condition(&self) -> DegradeCondition {
        let (NotPlaced::Absent { report, .. } | NotPlaced::Unreadable { report, .. }) = self else {
            let NotPlaced::Unwaitable { source, .. } = self else {
                unreachable!("every other variant carries a report")
            };
            return DegradeCondition {
                kind: DegradeKind::PidfdUnavailable,
                errno: source.raw_os_error(),
            };
        };
        match *report {
            NotEntered::NotReported => DegradeCondition {
                kind: DegradeKind::PlacementNotReported,
                errno: None,
            },
            NotEntered::WriteFailed(errno) => DegradeCondition {
                kind: DegradeKind::PlacementWriteFailed,
                errno: Some(errno),
            },
        }
    }
}

/// The degrade conditions this process has already reported at `warn`.
static WARNED: Mutex<BTreeSet<DegradeCondition>> = Mutex::new(BTreeSet::new());

/// Record that this spawn is not getting the containment it asked for, and why.
///
/// One function for every degrade site so the wording is composed once: whichever step failed,
/// the log carries a single line naming the achieved mechanism and the reason the stronger one
/// was unavailable.
///
/// **Once per condition at `warn`, every time after that at `debug`.** Nearly every degrade
/// condition is a standing property of the host — an unprivileged container's read-only
/// `/sys/fs/cgroup`, an undelegated slice, a kernel older than 5.14 — so it holds for every
/// `.contain()` spawn this process will ever make. The first report is a real reduction in the
/// guarantee the caller asked for and warns; the ten-thousandth tells an embedder nothing new
/// about something it cannot fix, and a log an embedder learns to filter out is worse than no
/// log. A genuinely NEW condition — see [`DegradeCondition`] — warns whatever has degraded
/// before it.
///
/// Repeats carry their own full text, so a process whose `log` max level admits `debug` keeps
/// every degrading spawn on record. Below that they are gone, not merely hidden: `log!` tests
/// `max_level()` before reaching any logger, so a `warn`-filtered process emits nothing for
/// them and no amount of capturing downstream brings them back.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn log_degrade(reason: &dyn DegradeReason) {
    log_degrade_into(&WARNED, reason);
}

/// [`log_degrade`] against an explicit "already warned" set, and reporting the level it chose.
///
/// The set is a parameter, not a hard-wired static, so a test drives the first-then-repeat
/// transition against its own state instead of racing every other test in the binary for the
/// process-wide one.
fn log_degrade_into(warned: &Mutex<BTreeSet<DegradeCondition>>, reason: &dyn DegradeReason) -> log::Level {
    let level = report_level(warned, reason.condition());
    log::log!(level, "cgroup v2 containment: degrading to a process group — {reason}");
    level
}

/// The level to report `condition` at: `Warn` the first time `seen` meets it, `Debug` after.
///
/// Generic over the condition so every once-per-condition report in the crate shares this one
/// policy while keying on its own conditions.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn report_level<C: Ord>(seen: &Mutex<BTreeSet<C>>, condition: C) -> log::Level {
    // A panic elsewhere while holding the lock cannot leave a set half-inserted; recover it
    // rather than turn a log call into a second panic.
    if seen.lock().unwrap_or_else(PoisonError::into_inner).insert(condition) {
        log::Level::Warn
    } else {
        log::Level::Debug
    }
}

// Everything below is Linux-only. =====

#[cfg(target_os = "linux")]
use std::fs::{self, File, OpenOptions};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-wide monotonic counter; combined with the pid, gives a unique leaf
/// name even when the same process spawns on multiple threads simultaneously.
#[cfg(target_os = "linux")]
static SEQ: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "linux")]
use nix::sys::signal::{kill, Signal};
#[cfg(target_os = "linux")]
use nix::unistd::Pid;

/// Whether `e` is the kernel's proof that this leaf's `cgroup.events` node is already gone —
/// either because the whole path was already removed (`ENOENT`, on a fresh `open` through the
/// now-unlinked leaf directory) or because THIS fd was opened before removal and the
/// underlying kernfs node has since been deactivated (`ENODEV`, on `seek`/`read` through an
/// already-open fd). `rmdir` on a cgroup v2 leaf — whether `Drop`'s own retry or an external
/// cgroup manager's cleanup of an empty leaf — succeeds ONLY once `populated` has already read
/// 0 (see `CgroupLeaf::wait_drained`'s doc); observing the leaf's removal is therefore always
/// proof every member had already exited, never proof of anything else, so no other errno is
/// folded in here (a genuine mechanism failure — `EACCES`, `EIO`, ...— must still surface as
/// `Error::Io`, not be silently reinterpreted as a drain).
#[cfg(target_os = "linux")]
pub(crate) fn removed_after_drain(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::ENODEV) | Some(libc::ENOENT))
}

/// Seek to the start of `file` (a `cgroup.events` handle) and read its current `populated`
/// value. Shared verbatim by `CgroupLeaf::wait_drained`'s sync loop and its tokio twin,
/// `cgroup_wait_tree_drained` — the only difference between the two callers is how each awaits
/// the next readiness edge, not how either reads or classifies the file.
///
/// A leaf removed after every member has exited (see [`removed_after_drain`]) is reported as
/// `Ok(false)`: the leaf's own removal is itself proof of a full drain, indistinguishable in
/// meaning from an explicit `populated 0`.
#[cfg(target_os = "linux")]
pub(crate) fn read_populated(file: &mut File, buf: &mut String) -> Result<bool, crate::error::Error> {
    use std::io::{Read, Seek, SeekFrom};

    buf.clear();
    if let Err(e) = file.seek(SeekFrom::Start(0)) {
        return if removed_after_drain(&e) {
            Ok(false)
        } else {
            Err(crate::error::Error::Io(e))
        };
    }
    if let Err(e) = file.read_to_string(buf) {
        return if removed_after_drain(&e) {
            Ok(false)
        } else {
            Err(crate::error::Error::Io(e))
        };
    }
    parse_populated(buf).ok_or_else(|| {
        crate::error::Error::Io(io::Error::other(
            "cgroup.events has no 'populated' field — unexpected kernel format",
        ))
    })
}

/// The kernel's current state letter for `pid`, or `None` when `/proc/<pid>/stat` cannot be
/// read or parsed. A not-yet-reaped child reads as `Z`, which is what separates "the
/// placement write failed" from "the child exited before membership was checked".
#[cfg(target_os = "linux")]
fn proc_state(pid: u32) -> Option<char> {
    parse_proc_stat_state(&fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// A report of a successful placement. Negative so it can never collide with an errno, which
/// `write(2)` only ever reports as positive.
#[cfg(target_os = "linux")]
const REPORT_PLACED: i32 = -1;

/// The channel the forked child reports its self-placement outcome through: a `SOCK_SEQPACKET`
/// socket pair carrying one message, a native-endian `i32` — the write's errno or
/// [`REPORT_PLACED`].
///
/// `pre_exec` runs after `fork`, where async-signal-safety forbids allocating, formatting or
/// locking, and nothing the child computes survives its `exec`. One `send(2)` of four bytes is
/// all a report needs. It is sent with `MSG_NOSIGNAL`: a parent that has stopped listening makes
/// it fail with `EPIPE` instead of killing the child with `SIGPIPE`.
///
/// # When the report is final
/// Not when `spawn` returns. `std`'s Unix spawn returns once its own close-on-exec error channel
/// reads EOF, normally at the child's `exec`. But that channel takes the lowest free fds: with two
/// of this process's 0, 1 and 2 closed, its child end is one of them. When `std` `dup2`s the
/// child's stdio for that slot into place, before any `pre_exec` runs, it closes that end, and
/// `spawn` returns before the child has placed itself.
///
/// [`ReportChannel::wait`] therefore waits for the child itself: for the report, or for the
/// child's exit, watched through a pidfd. The report is always sent before `exec`, so a child that
/// exits without one never exec'd, so nothing of its is in the leaf, and `NotReported` says so. The channel's
/// EOF is no substitute for the pidfd: every process this one forks while the channel is open
/// inherits the child's end, so EOF would also wait for other threads' children to exec or exit —
/// and forever on one that never execs.
///
/// Both ends sit at fd 3 or above. The child's stdio `dup2` cannot close its end there. The only
/// later `dup2` is command-fds' mapping of fds 3 and up, whose hook the spawn registers after the
/// placement hook: it can replace the child's end only once the report is sent.
///
/// The wait is no longer than the one `std` intends: the child reaches its report on `std`'s own
/// path from `fork` to `exec`, all of which `spawn` normally waits out.
///
/// **One report per channel.** A caller that routes several children through one channel reads
/// the first report sent, whoever sent it.
///
/// # What this costs, and what it can cost a spawn
/// Two fds per contained spawn in flight, held from the leaf's creation until `attach` takes the
/// placement verdict; a live contained child costs the supervisor none. A channel that cannot be
/// opened (`EMFILE`, `ENFILE`) DEGRADES the spawn — it keeps its process group and loses the
/// fork-proof kill — rather than failing it. `LeafError::OpenReportChannel` is what makes that
/// audible.
#[cfg(target_os = "linux")]
pub(crate) struct ReportChannel {
    /// The parent's end.
    read: OwnedFd,
    /// The parent's copy of the child's end. Closed before waiting.
    write: Option<OwnedFd>,
}

#[cfg(target_os = "linux")]
impl ReportChannel {
    pub(crate) fn new() -> io::Result<ReportChannel> {
        use rustix::net::{socketpair, AddressFamily, SocketFlags, SocketType};

        // Test-only fault seam: fail the channel (take semantics — see `fault`).
        #[cfg(test)]
        if fault::take_force_report_channel_failure() {
            return Err(io::Error::from_raw_os_error(libc::EMFILE));
        }
        // Both ends close-on-exec: the child needs its end only until `exec`, and no program this
        // process starts may inherit either. Both at fd 3 or above: the child's end so the child's
        // stdio cannot replace it, and the parent's so it takes no std slot this process left
        // closed — that gap is the host's, not cosca's to fill.
        let (read, write) = socketpair(AddressFamily::UNIX, SocketType::SEQPACKET, SocketFlags::CLOEXEC, None)?;
        Ok(ReportChannel {
            read: rustix::io::fcntl_dupfd_cloexec(&read, 3)?,
            write: Some(rustix::io::fcntl_dupfd_cloexec(&write, 3)?),
        })
    }

    /// A `Copy` handle to the child's end for capture by the `pre_exec` closure (which must not
    /// capture the owning `ReportChannel`: the leaf keeps it).
    pub(crate) fn slot(&self) -> ReportSlot {
        ReportSlot {
            fd: self
                .write
                .as_ref()
                .expect("the child's end is open until the wait")
                .as_raw_fd(),
        }
    }

    /// Block until the report of `pid`, the child spawned with this channel's slot, is final, and
    /// return it. See [`ReportChannel`] for why `spawn` returning is not enough.
    ///
    /// `pid` must be this process's own unreaped child, so no other process can hold its number
    /// (see [`Command::contain`](crate::Command::contain) for what breaks that). If something
    /// else reaped it, `pidfd_open` fails with `ESRCH` and the verdict decides without a pidfd.
    ///
    /// `Err` is `pidfd_open`'s: the child's exit cannot be watched, so only a report already
    /// sent is final. Nothing blocks in that case; [`CgroupLeaf::take_placement`] decides without
    /// the report.
    pub(crate) fn wait(&mut self, pid: u32) -> Result<PlacementReport, io::Error> {
        use rustix::event::{poll, PollFd, PollFlags};

        // The parent's own copy would otherwise keep the channel open forever.
        self.write = None;
        let pid = i32::try_from(pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .expect("a spawned child's pid is a positive i32");
        #[cfg(test)]
        let pidfd = if let Some(errno) = fault::take_force_pidfd_failure() {
            Err(errno)
        } else {
            rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
        };
        #[cfg(not(test))]
        let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty());
        let pidfd = match pidfd {
            Ok(pidfd) => pidfd,
            Err(e) => {
                debug_assert_ne!(
                    e,
                    rustix::io::Errno::SRCH,
                    "{pid:?} is not an unreaped child of this process: something else reaped it"
                );
                return match self.read_final() {
                    PlacementReport::NotReported => Err(e.into()),
                    sent => Ok(sent),
                };
            }
        };
        let mut fds = [
            PollFd::new(&self.read, PollFlags::IN),
            PollFd::new(&pidfd, PollFlags::IN),
        ];
        // No timeout: the child reports or exits on its way to `exec`, like `std`'s own wait.
        loop {
            match poll(&mut fds, None) {
                Ok(_) => break,
                // `ENOMEM` is the kernel's transient shortage, not an answer.
                Err(rustix::io::Errno::INTR | rustix::io::Errno::NOMEM) => continue,
                Err(e) => panic!("poll on the placement report channel failed: {e}"),
            }
        }
        Ok(self.read_final())
    }

    /// The report sent so far, read without blocking: final once the child has reported or can
    /// no longer report.
    fn read_final(&mut self) -> PlacementReport {
        let queued = rustix::io::ioctl_fionread(&self.read).expect("FIONREAD on the report channel");
        if queued == 0 {
            return PlacementReport::NotReported;
        }
        let mut report = [0u8; 4];
        // A queued message makes this return at once. SOCK_SEQPACKET delivers it whole.
        let read = loop {
            match rustix::io::read(&self.read, &mut report) {
                Err(rustix::io::Errno::INTR) => continue,
                other => break other.expect("read a report that is already queued"),
            }
        };
        debug_assert_eq!(read, report.len(), "a report is one 4-byte message");
        match i32::from_ne_bytes(report) {
            REPORT_PLACED => PlacementReport::Placed,
            errno => {
                debug_assert!(errno > 0, "a failed write reports its positive errno, got {errno}");
                PlacementReport::WriteFailed(errno)
            }
        }
    }
}

#[cfg(all(target_os = "linux", test))]
impl ReportChannel {
    /// The report of a child that has already been reaped, or of reports sent from this process.
    pub(crate) fn report_for_test(mut self) -> PlacementReport {
        self.write = None;
        self.read_final()
    }
}

/// The child-side half of a [`ReportChannel`]: its end's number, with one async-signal-safe
/// operation. Owns nothing — the parent's `ReportChannel` closes the channel.
///
/// The closure holding it can OUTLIVE the channel: `attach` closes the channel once the spawn has
/// returned, and on the spawn-FAILURE path `Prepared` (and with it the leaf) drops first — both
/// before the `Command` that still owns the closure. The number is stale from then on, which is
/// sound only because nothing ever invokes the closure again: each `Command` is spawned once.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
pub(crate) struct ReportSlot {
    fd: RawFd,
}

#[cfg(target_os = "linux")]
impl ReportSlot {
    /// Send the child's outcome. Async-signal-safe: one `send(2)`, no allocation.
    ///
    /// `EPIPE` is `Ok`: the parent closes its end before the report arrives only after deciding
    /// without it (see [`CgroupLeaf::decide_unwaitable`]), and that decision already holds for
    /// this child. Either the leaf was closed, so this child's placement failed with `ENODEV`;
    /// or this child was found in the leaf; or it is being killed. Every other failure is `Err`.
    ///
    /// # Safety
    /// The child's end must still be open at this number, which holds from the leaf's creation
    /// until the parent has taken the verdict.
    unsafe fn report(self, value: i32) -> io::Result<()> {
        let bytes = value.to_ne_bytes();
        loop {
            // Safety: `bytes` is a valid buffer; the caller guarantees the fd.
            let sent = unsafe { libc::send(self.fd, bytes.as_ptr().cast(), bytes.len(), libc::MSG_NOSIGNAL) };
            if sent == bytes.len() as isize {
                return Ok(());
            }
            // Safety: errno is this thread's own; `__errno_location` is async-signal-safe.
            let errno = unsafe { *libc::__errno_location() };
            match (sent, errno) {
                (-1, libc::EINTR) => continue,
                (-1, libc::EPIPE) => return Ok(()),
                (-1, errno) => return Err(io::Error::from_raw_os_error(errno)),
                // SOCK_SEQPACKET sends a message whole or not at all.
                _ => return Err(io::Error::from_raw_os_error(libc::EMSGSIZE)),
            }
        }
    }
}

#[cfg(all(target_os = "linux", test))]
impl ReportSlot {
    /// Report `Placed` without a `cgroup.procs` write, for tests of what cosca does with a report.
    ///
    /// # Safety
    /// As [`ReportSlot::report`].
    pub(crate) unsafe fn report_placed_for_test(self) {
        // Safety: the caller guarantees the channel is open.
        unsafe { self.report(REPORT_PLACED) }.expect("send the report");
    }
}

/// A live leaf sub-cgroup created for a single spawned process tree.
///
/// The `pre_exec` closure writes `"0"` to `procs_fd` to place the forked
/// child into the leaf, then immediately closes the fd so it does not
/// propagate to grandchildren. If the write fails (e.g. EBUSY — the
/// supervisor's cgroup is itself a leaf, violating the "no internal processes"
/// rule), the closure returns an error and the spawn falls back to the
/// process-group mechanism.
///
/// [`CgroupLeaf::take_placement`] releases the `cgroup.procs` fd and the report channel: the child
/// needs them only until its `exec`.
///
/// `Drop` removes the leaf directory. If the leaf is still occupied, it fires `cgroup.kill` and
/// retries — but only if the child reported entering it.
#[cfg(target_os = "linux")]
pub(crate) struct CgroupLeaf {
    /// Absolute path to the leaf directory, e.g. `/sys/fs/cgroup/…/cosca-<pid>`.
    leaf_path: PathBuf,
    /// Pre-opened `cgroup.procs` fd for the `pre_exec` write. Close-on-exec: the write happens
    /// between `fork` and `exec`, and no program this process starts may inherit it. Numbered
    /// 3 or above, so it never shares a number with the child's stdio. `None` once the
    /// placement verdict is taken.
    procs_fd: Option<OwnedFd>,
    /// Where the forked child reports whether its self-placement write succeeded. `None` once
    /// the placement verdict is taken.
    report: Option<ReportChannel>,
    /// Whether the child reported entering the leaf, recorded when `report` is released.
    entered: bool,
    /// The leaf's unified-hierarchy path, as `/proc/<pid>/cgroup` prints it. `None` for a leaf
    /// created outside the cgroup filesystem.
    cgroup_path: Option<String>,
}

/// Why a spawn-side resource of a [`CgroupLeaf`] is missing.
#[cfg(target_os = "linux")]
const RELEASED: &str = "the leaf's spawn-side resources are released once its placement verdict is taken";

#[cfg(target_os = "linux")]
impl CgroupLeaf {
    /// Returns the raw `cgroup.procs` fd for capture in a `pre_exec` closure. Only before the
    /// placement verdict is taken.
    pub(crate) fn procs_fd(&self) -> RawFd {
        self.procs_fd.as_ref().expect(RELEASED).as_raw_fd()
    }

    /// Whether the child reported entering this leaf, once the verdict is taken.
    fn child_entered(&self) -> bool {
        debug_assert!(self.report.is_none(), "the verdict is not taken yet");
        self.entered
    }

    /// The leaf's `cgroup.events` path — the drain edge. Both watches open it for themselves:
    /// the sync one polls it directly, while the reactor-native async one cannot reuse that
    /// `poll(2)` loop and registers the descriptor instead.
    pub(crate) fn events_path(&self) -> PathBuf {
        self.leaf_path.join("cgroup.events")
    }

    /// Remove a leaf that holds nothing of its child's: close the fd and `rmdir`, never
    /// `cgroup.kill`.
    ///
    /// The child's final report is not `Placed`, so it never exec'd a program that could fork
    /// into the leaf (see the module's report contract).
    /// Whatever keeps the `rmdir` from succeeding, cosca did not put there, and killing it would
    /// kill a process cosca was never asked to contain.
    pub(crate) fn remove_unentered(self) {
        debug_assert!(!self.child_entered(), "remove_unentered on a leaf its child entered");
    }

    /// A `Copy` handle to this leaf's placement-report slot, for capture by the `pre_exec`
    /// closure. Only before the placement verdict is taken.
    pub(crate) fn placement_slot(&self) -> ReportSlot {
        self.report.as_ref().expect(RELEASED).slot()
    }

    /// Whether `pid` entered this leaf: `Ok` when its own write into it succeeded.
    ///
    /// Used once, post-spawn (parent side). Blocks until the report is final — `spawn` returning
    /// does not make it so (see [`ReportChannel`]) — or, when it cannot wait, decides without it
    /// (see [`CgroupLeaf::decide_unwaitable`]). The child's report is the verdict: `cgroup.procs`
    /// lists only live tasks, so a placed child that has already exited reads back absent from
    /// it. Only a child that reported no successful write has `cgroup.procs` and its `/proc`
    /// state read, to diagnose why — see [`NotPlaced`].
    ///
    /// Taking the verdict closes the `cgroup.procs` fd and the report channel: nothing
    /// needs either after the child's `exec`, and otherwise every live contained child would
    /// hold three fds in the supervisor.
    ///
    /// The outer `Err` is a spawn that must fail: membership could not be decided, so the child
    /// was killed (see [`CgroupLeaf::decide_unwaitable`]).
    pub(crate) fn take_placement(&mut self, pid: u32) -> Result<Result<(), NotPlaced>, crate::error::Error> {
        let mut channel = self.report.take().expect(RELEASED);
        self.procs_fd = None;
        let report = match channel.wait(pid) {
            Ok(report) => report,
            Err(source) => return self.decide_unwaitable(pid, &mut channel, source),
        };
        self.entered = report == PlacementReport::Placed;
        let report = match report {
            PlacementReport::Placed => return Ok(Ok(())),
            PlacementReport::NotReported => NotEntered::NotReported,
            PlacementReport::WriteFailed(errno) => NotEntered::WriteFailed(errno),
        };
        let path = self.leaf_path.join("cgroup.procs");
        let child_state = proc_state(pid);
        Ok(Err(match fs::read_to_string(&path) {
            Ok(procs) => NotPlaced::Absent {
                pid,
                path,
                procs,
                report,
                child_state,
            },
            Err(source) => NotPlaced::Unreadable {
                pid,
                path,
                source,
                report,
            },
        }))
    }

    /// Decide membership for a child whose report has not arrived and cannot be waited for:
    /// `pidfd_open` failed with `source`, and waiting on the channel's EOF could block forever
    /// (see [`ReportChannel`]).
    ///
    /// The leaf is removed. `rmdir` succeeds only on a leaf with no live member, and a removed
    /// leaf admits none: the child's later `cgroup.procs` write fails with `ENODEV`. So:
    /// - removed, no `Placed` sent: the child is not in the leaf and never will be — degrade;
    /// - removed, `Placed` sent: the child entered, and every member has since exited;
    /// - `EBUSY` with the child's own `/proc/<pid>/cgroup` inside the leaf: it entered;
    /// - anything else: the child may still enter a leaf cosca can neither wait on nor close.
    ///   It is killed and the spawn fails (see [`CgroupLeaf::abandon`]).
    fn decide_unwaitable(
        &mut self,
        pid: u32,
        channel: &mut ReportChannel,
        source: io::Error,
    ) -> Result<Result<(), NotPlaced>, crate::error::Error> {
        let why = match fs::remove_dir(&self.leaf_path) {
            Ok(()) => None,
            Err(e) if removed_after_drain(&e) => None,
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => match self.holds(pid) {
                Ok(true) => {
                    log::debug!(
                        "cgroup v2: pidfd_open failed ({source}), but child {pid} is already in its leaf {}",
                        self.leaf_path.display()
                    );
                    self.entered = true;
                    return Ok(Ok(()));
                }
                Ok(false) => Some(format!("its leaf is occupied ({e}) but not by the child")),
                // Unknown membership is not absence: deciding "not the child" on it would leave a
                // child that may be in the leaf unkilled. Undecided fails closed.
                Err(read) => Some(format!(
                    "its leaf is occupied ({e}) and the child's membership could not be read ({read})"
                )),
            },
            Err(e) => Some(format!("its leaf could not be removed ({e})")),
        };
        let Some(why) = why else {
            self.entered = channel.read_final() == PlacementReport::Placed;
            return Ok(if self.entered {
                Ok(())
            } else {
                Err(NotPlaced::Unwaitable { pid, source })
            });
        };
        Err(self.abandon(pid, channel, &format!("pidfd_open failed ({source}) and {why}")))
    }

    /// Whether `pid`'s own cgroup is this leaf or nested under it, or why that could not be read.
    /// A leaf with no known unified-hierarchy path (a test leaf) holds nothing.
    fn holds(&self, pid: u32) -> io::Result<bool> {
        let Some(leaf) = &self.cgroup_path else {
            return Ok(false);
        };
        #[cfg(test)]
        if fault::take_force_membership_unreadable() {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        let text = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
        let path = parse_v2_relative_path(&text)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no cgroup v2 `0::` line"))?;
        Ok(is_at_or_under(path, leaf))
    }

    /// Fail a spawn whose membership cannot be decided: kill the child as a group, which ends its
    /// chance to enter the leaf and makes its report final, then apply the module's report
    /// contract — kill through the leaf only on `Placed`.
    ///
    /// The group, not only the pid: between the last look at the report and the kill, the child
    /// can report, exec and fork, and its descendants start in its process group, outside the
    /// leaf. The pid too: a child killed before its own `setpgid` leads no group yet.
    ///
    /// There is no pidfd here — its failure is why the verdict is undecidable — so the child is
    /// signalled by number. That is sound while `pid` is this process's own unreaped child (see
    /// [`Command::contain`](crate::Command::contain)): the kernel does not reuse a pid, nor so a
    /// process-group id, while any task holds it, and the unreaped child does. A child something
    /// else already reaped is detected and never signalled; one reaped between that check and the
    /// kill — only possible when the precondition is broken — is not.
    fn abandon(&mut self, pid: u32, channel: &mut ReportChannel, why: &str) -> crate::error::Error {
        use nix::sys::wait::{waitid, Id, WaitPidFlag};

        let child = Pid::from_raw(i32::try_from(pid).expect("a spawned child's pid is a positive i32"));
        // Whether `pid` is still this process's child, live or exited, without reaping it.
        let ours = loop {
            match waitid(
                Id::Pid(child),
                WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
            ) {
                Err(nix::errno::Errno::EINTR) => continue,
                Err(nix::errno::Errno::ECHILD) => break false,
                _ => break true,
            }
        };
        debug_assert!(
            ours,
            "{child} is not an unreaped child of this process: something else reaped it"
        );
        let fate = if ours {
            #[cfg(test)]
            let denied = fault::take_force_signal_denied();
            #[cfg(not(test))]
            let denied = false;
            let killed = if denied {
                Err(nix::errno::Errno::EPERM)
            } else {
                kill(child, Signal::SIGKILL)
            };
            // The child leads its group; the unreaped child holds the group's id.
            if !denied {
                let _ = nix::sys::signal::killpg(child, Signal::SIGKILL);
            }
            match killed {
                Ok(()) => {
                    // Its exit, not its reaping: the spawn's error path reaps it.
                    while let Err(nix::errno::Errno::EINTR) =
                        waitid(Id::Pid(child), WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT)
                    {}
                    "the child and its process group were killed"
                }
                // cosca changes no credentials before the placement hook, so a child it may not
                // signal has exec'd a program that runs as someone else, and its report, sent
                // before `exec`, is final. Waiting for it would last that program's whole life.
                Err(nix::errno::Errno::EPERM) => {
                    "the child could not be signalled (EPERM): it exec'd a program this process may \
                     not kill, and is left running"
                }
                // ESRCH cannot happen to an unreaped child; nothing else is a kill(2) errno.
                Err(_) => "the child could not be signalled",
            }
        } else {
            // Reaped, so it has exited — but its number may already be another process's.
            "the child was already reaped by something else in this process, so it was not signalled"
        };
        // The child has exited, so its report is final.
        self.entered = channel.read_final() == PlacementReport::Placed;
        let leaf = if self.entered {
            match self.hard_kill() {
                Ok(()) => {
                    // Every member was just sent SIGKILL, so the leaf drains; `Drop` then removes it.
                    let _ = self.wait_drained(None);
                    "its leaf was killed through".to_string()
                }
                Err(e) => format!("killing through its leaf failed ({e})"),
            }
        } else {
            "it had not entered its leaf".to_string()
        };
        crate::error::Error::Containment {
            detail: format!("cannot tell whether child {pid} entered its cgroup leaf: {why}; {fate}, and {leaf}"),
        }
    }

    /// Hard-kill all processes in the cgroup via `cgroup.kill` (kernel ≥ 5.14).
    ///
    /// `Ok` means the tree is dead: either the atomic kill fired, or the leaf was already gone
    /// ([`removed_after_drain`]), which is itself proof every member had exited — `rmdir` on a
    /// cgroup v2 leaf succeeds only once `populated` reads 0.
    ///
    /// Every other errno means the atomic kill did NOT happen — the tree may still be running
    /// (a delegated subtree whose `cgroup.kill` stopped being writable after a privilege drop,
    /// or a cgroupfs remounted `ro`). That is a teardown-mechanism failure and is returned, the
    /// same way every sibling mechanism's is (`Attached::hard_kill`): a caller that reads
    /// `Child::kill_tree() -> Ok(())` over a live tree has been told the opposite of the truth.
    pub(crate) fn hard_kill(&self) -> Result<(), crate::error::Error> {
        let path = self.leaf_path.join("cgroup.kill");
        match fs::write(&path, b"1") {
            Ok(()) => Ok(()),
            Err(e) if removed_after_drain(&e) => {
                log::debug!("cgroup.kill: leaf {} is already gone", path.display());
                Ok(())
            }
            Err(e) => Err(crate::error::Error::Io(e)),
        }
    }

    /// Block until every process in the leaf has EXITED (not reaped), observed via
    /// `cgroup.events`'s `populated` key — the kernel flips it 1→0 exactly when the leaf's
    /// last task exits, fork-proof (no cooperation from the tree, no re-enumeration race).
    ///
    /// Read-before-arm: `populated` is checked BEFORE every `poll`, not only after — a
    /// transition that already happened (leaf drained between a caller's previous check and
    /// this call) must be observed on the read, not require a fresh kernel edge that will
    /// never fire again. `POLLPRI` fires on every transition (both 1→0 and 0→1), so an
    /// intervening 0→1 (a leaf that reused-then-repopulated between reads) is also picked up
    /// by looping back to re-read rather than trusting readiness to imply the value dropped.
    ///
    /// `deadline` follows the crate's watch convention (see [`crate::wait::remaining`]). No
    /// interval is chosen anywhere in this path: every round blocks in one `poll(2)` call for
    /// exactly the caller's own remaining time, and returns as soon as either the kernel
    /// reports a transition or the deadline is reached.
    ///
    /// Leaf-removal race: `rmdir` on this leaf (`Drop`'s own retry, or an external cgroup
    /// manager cleaning up an empty leaf — either succeeds only once `populated` has already
    /// read 0) can land at any point after the last member exits, including between this
    /// call's own `poll` waking on the 1→0 transition and its very next read. Once that
    /// happens, `open`/`seek`/`read` on this leaf's `cgroup.events` fail (`ENOENT` for a fresh
    /// `open` through the now-unlinked directory; `ENODEV` for a syscall through an fd that was
    /// opened before removal, once the kernel deactivates the underlying kernfs node) — proof
    /// the leaf is gone, which is itself proof every member had already exited (removal can
    /// never precede full drain), not a failure. See [`removed_after_drain`].
    pub(crate) fn wait_drained(
        &self,
        deadline: Option<Option<std::time::Instant>>,
    ) -> Result<crate::containment::TreeDrain, crate::error::Error> {
        use rustix::event::{poll, PollFd, PollFlags};

        use crate::containment::TreeDrain;
        use crate::error::Error;

        let mut file = match File::open(self.events_path()) {
            Ok(f) => f,
            Err(e) if removed_after_drain(&e) => return Ok(TreeDrain::AllMembersExited),
            Err(e) => return Err(Error::Io(e)),
        };
        let mut buf = String::new();
        loop {
            if !read_populated(&mut file, &mut buf)? {
                return Ok(TreeDrain::AllMembersExited);
            }
            let remaining = crate::wait::remaining(deadline);
            if remaining == Some(std::time::Duration::ZERO) {
                return Ok(TreeDrain::MembersRemain);
            }
            let ts = remaining.map(|d| rustix::event::Timespec {
                tv_sec: d.as_secs().min(i64::MAX as u64) as i64,
                tv_nsec: d.subsec_nanos() as _,
            });
            let mut fds = [PollFd::new(&file, PollFlags::PRI)];
            match poll(&mut fds, ts.as_ref()) {
                Ok(0) => return Ok(TreeDrain::MembersRemain), // genuinely timed out
                Ok(_) => continue,                            // a transition fired — re-read
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => return Err(Error::Io(io::Error::from(e))),
            }
        }
    }

    /// SIGTERM every pid currently listed in `cgroup.procs`.
    ///
    /// # PID-reuse window
    /// This reads the pid list then signals each entry. Between the read and
    /// the signal a pid may exit and be recycled, potentially signalling an
    /// unrelated process. This is the same race as the process-group `SIGTERM`
    /// path; the cgroup mechanism's advantage (atomic, pid-free kill) applies
    /// only to `hard_kill` via `cgroup.kill`.
    pub(crate) fn terminate(&self) -> io::Result<()> {
        let content = fs::read_to_string(self.leaf_path.join("cgroup.procs"))?;
        for line in content.lines() {
            if let Ok(pid) = line.trim().parse::<i32>() {
                let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
            }
        }
        Ok(())
    }
}

#[cfg(all(target_os = "linux", test))]
impl CgroupLeaf {
    /// Test-only placeholder pointing at no real cgroup. Safe to construct and drop —
    /// `remove_dir` of a nonexistent path is a harmless no-op — so it is
    /// usable ONLY for variant-level assertions, never for an operation that touches the
    /// fd or path.
    pub(crate) fn placeholder_for_test() -> CgroupLeaf {
        CgroupLeaf::for_test_at(PathBuf::from("/nonexistent/cosca-cgroup-placeholder"))
    }

    /// Test-only leaf pointing at `leaf_path`, which a test shapes with ordinary files and
    /// directories. Every operation that reads or writes the leaf path (`hard_kill`,
    /// `take_placement`, `Drop`) then runs for real against the kernel's own errnos, on any
    /// Linux host and without a cgroupfs. It has no `cgroup.procs` fd.
    pub(crate) fn for_test_at(leaf_path: PathBuf) -> CgroupLeaf {
        CgroupLeaf {
            leaf_path,
            procs_fd: None,
            report: Some(ReportChannel::new().expect("open a placement-report channel")),
            entered: false,
            cgroup_path: None,
        }
    }

    /// Whether the leaf still holds its `cgroup.procs` fd or its report channel.
    pub(crate) fn holds_spawn_resources(&self) -> bool {
        self.procs_fd.is_some() || self.report.is_some()
    }
}

#[cfg(target_os = "linux")]
impl Drop for CgroupLeaf {
    fn drop(&mut self) {
        self.procs_fd = None;
        // Before the verdict — a spawn that failed, maybe after its fork — the report is final
        // only if it arrived: the child's pid is not known here to wait for it.
        if let Some(mut channel) = self.report.take() {
            channel.write = None;
            match channel.read_final() {
                PlacementReport::NotReported => return self.remove_with_report_in_flight(),
                report => self.entered = report == PlacementReport::Placed,
            }
        }
        // Remove the leaf. If still occupied (e.g. hard_kill not yet called), fire cgroup.kill
        // to drain it, then retry — but only if the child entered it: a final report other than
        // `Placed` proves nothing of the child's is there. A leaf that outlives the removal is
        // reported.
        let Err(first) = fs::remove_dir(&self.leaf_path) else {
            return;
        };
        if !self.child_entered() {
            if !removed_after_drain(&first) {
                warn_leaf_left_behind(
                    &self.leaf_path,
                    format_args!("rmdir failed ({first}); cgroup.kill not written: nothing of the child's is in it"),
                );
            }
            return;
        }
        let kill = self.hard_kill();
        let Err(second) = fs::remove_dir(&self.leaf_path) else {
            return;
        };
        // A leaf that is GONE is not a leak: `rmdir` on a cgroup v2 leaf succeeds only once it
        // is empty, so another party having removed it means it left nothing behind here.
        if removed_after_drain(&second) {
            return;
        }
        warn_leaf_left_behind(
            &self.leaf_path,
            format_args!(
                "first rmdir failed ({first}), cgroup.kill {}, second rmdir failed ({second})",
                match kill {
                    Ok(()) => "succeeded".to_string(),
                    Err(e) => format!("failed ({e})"),
                }
            ),
        );
    }
}

#[cfg(target_os = "linux")]
impl CgroupLeaf {
    /// Remove a leaf whose child's report is still in flight (see the module's report contract):
    /// nothing proves the child absent, so an occupied leaf is killed through, drained, and
    /// removed — again for as long as anything re-enters it before the removal lands. Once
    /// removed, it admits no member, so the in-flight report no longer matters.
    fn remove_with_report_in_flight(&mut self) {
        loop {
            let occupied = match fs::remove_dir(&self.leaf_path) {
                Ok(()) => return,
                Err(e) if removed_after_drain(&e) => return,
                Err(e) => e,
            };
            let why = match self.hard_kill() {
                // Every member was just sent SIGKILL, so the leaf drains.
                Ok(()) if occupied.raw_os_error() == Some(libc::EBUSY) => match self.wait_drained(None) {
                    Ok(_) => continue,
                    Err(e) => format!("its drain could not be watched ({e})"),
                },
                // Not a leaf `rmdir` refuses for its members: killing again cannot remove it.
                Ok(()) => "cgroup.kill succeeded".to_string(),
                Err(e) => format!("cgroup.kill failed ({e})"),
            };
            return warn_leaf_left_behind(
                &self.leaf_path,
                format_args!("rmdir failed ({occupied}) with the child's report in flight; {why}"),
            );
        }
    }
}

/// Report a `cosca-*` leaf cosca failed to remove. Nothing revisits a leaf by name, so this
/// record, made as it happens, is all a host accumulating them has to go on.
#[cfg(target_os = "linux")]
fn warn_leaf_left_behind(leaf_path: &Path, what_failed: fmt::Arguments<'_>) {
    log::warn!(
        "cgroup leaf {} was not removed: {what_failed}; it stays on this host until a cgroup \
         manager reaps it",
        leaf_path.display()
    );
}

/// Test-only fault seams for the leaf-creation steps a temp directory cannot reach.
///
/// Thread-local with take semantics — arm and call on one thread, then assert the flag was
/// consumed — so parallel tests in this binary cannot arm each other's faults, matching
/// `treewalk::fault` and `fdmarker::fault`.
#[cfg(all(target_os = "linux", test))]
pub(crate) mod fault {
    use std::cell::Cell;
    thread_local! {
        static FORCE_KILL_SUPPORTED: Cell<bool> = const { Cell::new(false) };
        static FORCE_REPORT_CHANNEL_FAILURE: Cell<bool> = const { Cell::new(false) };
        static FORCE_PIDFD_FAILURE: Cell<Option<rustix::io::Errno>> = const { Cell::new(None) };
        static FORCE_SIGNAL_DENIED: Cell<bool> = const { Cell::new(false) };
        static FORCE_MEMBERSHIP_UNREADABLE: Cell<bool> = const { Cell::new(false) };
        static FORCE_PLACEMENT_WRITE_RESULT: Cell<Option<isize>> = const { Cell::new(None) };
        static FORCE_OCCUPY_BEFORE_UNWIND: Cell<bool> = const { Cell::new(false) };
    }

    /// Treat the NEXT created leaf as exposing `cgroup.kill`. Supplies the single fact a temp
    /// directory cannot, so every step AFTER the check — the `cgroup.procs` open, the report
    /// channel, and the unwind that removes the leaf — runs for real, against the kernel's own
    /// errnos, on any Linux host.
    pub(crate) fn set_force_kill_supported(on: bool) {
        FORCE_KILL_SUPPORTED.with(|f| f.set(on));
    }
    pub(crate) fn take_force_kill_supported() -> bool {
        FORCE_KILL_SUPPORTED.with(|f| f.replace(false))
    }
    pub(crate) fn kill_supported_armed() -> bool {
        FORCE_KILL_SUPPORTED.with(|f| f.get())
    }

    /// Fail the NEXT `ReportChannel::new` with `EMFILE` — the real exhaustion this channel can hit,
    /// which no test may provoke for real: the fd limit is process-wide, and would fail every
    /// other test running in this binary.
    pub(crate) fn set_force_report_channel_failure(on: bool) {
        FORCE_REPORT_CHANNEL_FAILURE.with(|f| f.set(on));
    }
    pub(crate) fn take_force_report_channel_failure() -> bool {
        FORCE_REPORT_CHANNEL_FAILURE.with(|f| f.replace(false))
    }
    pub(crate) fn report_channel_failure_armed() -> bool {
        FORCE_REPORT_CHANNEL_FAILURE.with(|f| f.get())
    }

    /// Fail the NEXT `pidfd_open` of a report wait with `EMFILE`. The seccomp denial it also
    /// stands for is exercised for real, in a process of its own, by `tests/spawn_io.rs`.
    pub(crate) fn set_force_pidfd_failure(on: bool) {
        FORCE_PIDFD_FAILURE.with(|f| f.set(on.then_some(rustix::io::Errno::MFILE)));
    }
    /// Fail the NEXT `pidfd_open` of a report wait with `errno` — `ESRCH` stands for a child
    /// something else already reaped, whose pid a test must never obtain for real: it may
    /// already be another process's. Release-only, like its one test: debug builds assert the
    /// precondition this breaks.
    #[cfg(not(debug_assertions))]
    pub(crate) fn set_force_pidfd_errno(errno: rustix::io::Errno) {
        FORCE_PIDFD_FAILURE.with(|f| f.set(Some(errno)));
    }
    pub(crate) fn take_force_pidfd_failure() -> Option<rustix::io::Errno> {
        FORCE_PIDFD_FAILURE.with(|f| f.take())
    }
    pub(crate) fn pidfd_failure_armed() -> bool {
        FORCE_PIDFD_FAILURE.with(|f| f.get().is_some())
    }

    /// Deny the NEXT `abandon`'s signals with `EPERM`, as a child that exec'd a setuid program
    /// denies an unprivileged supervisor — which a root test lane cannot reproduce for real.
    pub(crate) fn set_force_signal_denied(on: bool) {
        FORCE_SIGNAL_DENIED.with(|f| f.set(on));
    }
    pub(crate) fn take_force_signal_denied() -> bool {
        FORCE_SIGNAL_DENIED.with(|f| f.replace(false))
    }
    pub(crate) fn signal_denied_armed() -> bool {
        FORCE_SIGNAL_DENIED.with(|f| f.get())
    }

    /// Fail the NEXT read of a child's `/proc/<pid>/cgroup` with `EACCES`, as a `hidepid` or
    /// seccomp-restricted `/proc` can — which a root test lane cannot reproduce for its own child.
    pub(crate) fn set_force_membership_unreadable(on: bool) {
        FORCE_MEMBERSHIP_UNREADABLE.with(|f| f.set(on));
    }
    pub(crate) fn take_force_membership_unreadable() -> bool {
        FORCE_MEMBERSHIP_UNREADABLE.with(|f| f.replace(false))
    }
    pub(crate) fn membership_unreadable_armed() -> bool {
        FORCE_MEMBERSHIP_UNREADABLE.with(|f| f.get())
    }

    /// Replace the NEXT placement write's return value — 0, which no file this test can open
    /// returns for a one-byte write. Called in the test's own process, never after a fork.
    pub(crate) fn set_force_placement_write_result(ret: isize) {
        FORCE_PLACEMENT_WRITE_RESULT.with(|f| f.set(Some(ret)));
    }
    pub(crate) fn take_force_placement_write_result() -> Option<isize> {
        FORCE_PLACEMENT_WRITE_RESULT.with(|f| f.take())
    }

    /// Put a directory inside the NEXT leaf whose creation fails, just before its unwind runs, so
    /// that unwind's `rmdir` fails for real (`ENOTEMPTY`).
    pub(crate) fn set_force_occupy_before_unwind(on: bool) {
        FORCE_OCCUPY_BEFORE_UNWIND.with(|f| f.set(on));
    }
    pub(crate) fn take_force_occupy_before_unwind() -> bool {
        FORCE_OCCUPY_BEFORE_UNWIND.with(|f| f.replace(false))
    }
    pub(crate) fn occupy_before_unwind_armed() -> bool {
        FORCE_OCCUPY_BEFORE_UNWIND.with(|f| f.get())
    }
}

/// Detect the current process's cgroup v2 path and create a leaf sub-cgroup
/// for containment. Returns the failing step on any failure, so the caller can
/// fall back to the process-group mechanism *and say why it had to*.
///
/// Failure conditions include: cgroup v2 not mounted at `/sys/fs/cgroup`,
/// current process not in a v2 cgroup (v1-only system), leaf directory not
/// writable (undelegated slice), or `cgroup.kill` absent (kernel < 5.14).
#[cfg(target_os = "linux")]
pub(crate) fn try_create_leaf() -> Result<CgroupLeaf, LeafError> {
    let cgroup_file = fs::read_to_string("/proc/self/cgroup").map_err(LeafError::ReadProcSelfCgroup)?;
    let rel_path = parse_v2_relative_path(&cgroup_file).ok_or_else(|| {
        let (line_count, controllers) = summarize_cgroup_controllers(&cgroup_file);
        LeafError::NoUnifiedLine {
            line_count,
            controllers,
        }
    })?;

    let mut leaf = create_leaf_under(&Path::new("/sys/fs/cgroup").join(rel_path.trim_start_matches('/')))?;
    let name = leaf.leaf_path.file_name().expect("a leaf has a name").to_string_lossy();
    leaf.cgroup_path = Some(format!("{}/{name}", rel_path.trim_end_matches('/')));
    Ok(leaf)
}

/// Create a containment leaf directly under `current` — the supervisor's own cgroup in
/// production, and a temp directory in the tests that fail each precondition for real.
///
/// Every early return names its step: the caller degrades either way, but never silently.
#[cfg(target_os = "linux")]
pub(crate) fn create_leaf_under(current: &Path) -> Result<CgroupLeaf, LeafError> {
    // Unique leaf name: pid + monotonic sequence counter avoids collisions when
    // the same process spawns on multiple threads simultaneously (same pid, but
    // different seq values mean different leaf names).
    // Safety: getpid() is always valid.
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let leaf_name = format!("cosca-{}-{}", unsafe { libc::getpid() }, seq);
    let leaf_path = current.join(&leaf_name);

    fs::create_dir(&leaf_path).map_err(|source| LeafError::CreateLeafDir {
        path: leaf_path.clone(),
        source,
    })?;

    // Every failure past this point removes the leaf it just created, and reports one it could
    // not remove.
    let fail = |leaf_path: &Path, err: LeafError| -> LeafError {
        #[cfg(test)]
        if fault::take_force_occupy_before_unwind() {
            fs::create_dir(leaf_path.join("occupant")).expect("occupy the leaf");
        }
        if let Err(e) = fs::remove_dir(leaf_path) {
            if !removed_after_drain(&e) {
                warn_leaf_left_behind(
                    leaf_path,
                    format_args!("rmdir failed ({e}) after its creation failed ({err})"),
                );
            }
        }
        err
    };

    // Require cgroup.kill (kernel ≥ 5.14); without it there is no atomic kill. A lookup that
    // fails is not an absent file, and is reported with its own errno.
    let kill_path = leaf_path.join("cgroup.kill");
    // Test-only fault seam: treat the leaf as kill-capable (take semantics — see `fault`).
    #[cfg(test)]
    let kill_supported = if fault::take_force_kill_supported() {
        Ok(true)
    } else {
        kill_path.try_exists()
    };
    #[cfg(not(test))]
    let kill_supported = kill_path.try_exists();
    match kill_supported {
        Ok(true) => {}
        Ok(false) => {
            return Err(fail(
                &leaf_path,
                LeafError::KillUnsupported {
                    path: leaf_path.clone(),
                },
            ))
        }
        Err(source) => {
            return Err(fail(
                &leaf_path,
                LeafError::CheckKill {
                    path: kill_path,
                    source,
                },
            ))
        }
    }

    // The report channel is opened before the procs fd so a failure here unwinds nothing but
    // the directory: a leaf whose child could not report its placement outcome would reopen
    // exactly the silence this module is reporting its way out of.
    let report = match ReportChannel::new() {
        Ok(r) => r,
        Err(e) => return Err(fail(&leaf_path, LeafError::OpenReportChannel(e))),
    };

    // Open cgroup.procs for writing, close-on-exec: the child's pre_exec write runs after fork
    // and before exec, where the fd is still open.
    //
    // Then move it to fd 3 or above. `open` takes the lowest free number, so with 0, 1 or 2
    // closed here the fd would share its number with one of the child's stdio slots, which std
    // `dup2`s into place before any pre_exec runs: the placement write would land in the
    // caller's stdio target instead, and report a placement that never happened.
    let procs_path = leaf_path.join("cgroup.procs");
    let procs_fd = OpenOptions::new()
        .write(true)
        .open(&procs_path)
        .and_then(|file| Ok(rustix::io::fcntl_dupfd_cloexec(&file, 3)?));
    let procs_fd = match procs_fd {
        Ok(fd) => fd,
        Err(source) => {
            return Err(fail(
                &leaf_path,
                LeafError::OpenProcs {
                    path: procs_path,
                    source,
                },
            ))
        }
    };

    Ok(CgroupLeaf {
        leaf_path,
        procs_fd: Some(procs_fd),
        report: Some(report),
        entered: false,
        cgroup_path: None,
    })
}

/// Place the calling process into the pre-created cgroup leaf by writing `"0"`
/// to `procs_fd`, then close the fd so it does not propagate to grandchildren.
///
/// Called inside a `pre_exec` closure (post-fork, pre-exec), whose `Err` aborts the spawn.
///
/// The outcome — success, or the exact errno — is sent to `slot`, the only way it reaches the
/// parent. A failed write (e.g. `EBUSY` when the supervisor's cgroup is itself a leaf — the "no
/// internal processes" rule) returns `Ok`: the child proceeds in the process group already set
/// up, and the parent degrades on the report. `Err` is a report that could not be sent: a parent
/// still waiting for it would read a child that may be in its leaf as never placed, for the
/// child's whole life, so the spawn fails instead (see [`ReportSlot::report`]).
///
/// # Safety
/// Must be called only from a `pre_exec` closure. `procs_fd` must be a valid,
/// open, writable fd in the child process, and `slot`'s channel must still be open.
/// Async-signal-safe: raw `libc::write`, `libc::close` and `libc::send`, no allocation, no
/// format strings.
#[cfg(target_os = "linux")]
pub(crate) unsafe fn place_self_in_cgroup_pre_exec(procs_fd: RawFd, slot: ReportSlot) -> io::Result<()> {
    static ZERO: &[u8] = b"0";
    // Safety: ZERO is a valid buffer; procs_fd is valid (caller guarantees).
    let ret = unsafe { libc::write(procs_fd, ZERO.as_ptr().cast(), ZERO.len()) };
    // Test-only fault seam: replace the write's return value (take semantics — see `fault`).
    #[cfg(test)]
    let ret = fault::take_force_placement_write_result().unwrap_or(ret);
    // Read errno before `close`, which is free to clobber it.
    // Safety: errno is this thread's own; `__errno_location` is async-signal-safe.
    let errno = if ret == -1 {
        unsafe { *libc::__errno_location() }
    } else {
        0
    };
    // Always close the fd — even on error — so it does not propagate to children.
    // Safety: procs_fd is valid; close is async-signal-safe.
    unsafe { libc::close(procs_fd) };
    let report = match ret {
        // Only the whole write is a placement.
        _ if ret == ZERO.len() as isize => REPORT_PLACED,
        // `write(2)` only ever sets a positive errno, but a report of -1 means "placed", so a
        // nonsensical value is mapped to EIO rather than read back as a fabricated placement.
        -1 if errno > 0 => errno,
        // A write that returned without writing (0) sets no errno.
        _ => libc::EIO,
    };
    // Safety: the caller guarantees the slot's channel is open.
    unsafe { slot.report(report) }
}

#[cfg(test)]
#[path = "cgroup_tests.rs"]
mod cgroup_tests;
