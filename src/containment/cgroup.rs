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
//! are raw `libc::write` + `libc::close` — no allocation, no `format!`, no
//! `String`.

// The parsers below are pure (no OS deps) — compiled on all platforms so their unit tests run
// on any host.

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};

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
    /// The shared page the child reports its self-placement outcome through could not be
    /// mapped. Without it the child's own errno would be unobservable, so the leaf is not
    /// created half-instrumented.
    #[error("could not map the placement-report memory page shared with the forked child: {0}")]
    MapReportPage(#[source] io::Error),
}

/// What the child's own `pre_exec` self-placement write reported back to the parent.
///
/// This is the one step whose reason lives entirely in the forked child: it runs after
/// `fork`, in a copy-on-write address space, under async-signal-safety rules that forbid
/// allocating or formatting anything. The child therefore reports a single word through a
/// shared page (see [`ReportPage`]), which this enum names.
///
/// The word belongs to the LEAF, not to a child. Production creates one leaf per spawn, so the
/// distinction is invisible there; several children sharing one leaf would share one slot and
/// overwrite each other's reports (see [`ReportPage`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum PlacementReport {
    /// No outcome was ever stored: the `pre_exec` closure did not run.
    NotReported,
    /// The child's `write` to `cgroup.procs` succeeded — at that instant it WAS a member.
    Placed,
    /// The child's `write` to `cgroup.procs` failed with this errno.
    WriteFailed(i32),
}

impl fmt::Display for PlacementReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlacementReport::NotReported => {
                f.write_str("the child stored no self-placement outcome (its pre_exec closure did not run)")
            }
            PlacementReport::Placed => f.write_str("the child's pre_exec self-placement write succeeded"),
            PlacementReport::WriteFailed(errno) => write!(
                f,
                "the child's pre_exec write to cgroup.procs failed: {} (errno {errno})",
                io::Error::from_raw_os_error(*errno)
            ),
        }
    }
}

/// What a child that did not enter its leaf reported: never a successful write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum NotEntered {
    /// Its `pre_exec` closure did not run.
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
/// The child's own report decides membership (see [`CgroupLeaf::placement_of`]).
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
                    "child {pid} never entered the leaf cgroup: {report}; {} is {listed}; {state}",
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
                "child {pid} never entered the leaf cgroup: {report}; {} could not be read: {source}",
                path.display()
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
    MapReportPage,
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
            LeafError::MapReportPage(e) => (DegradeKind::MapReportPage, Some(e)),
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
        let (NotPlaced::Absent { report, .. } | NotPlaced::Unreadable { report, .. }) = self;
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
use std::os::fd::{IntoRawFd, RawFd};
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

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

/// Sentinel stored in a [`ReportPage`] while the child has reported nothing. A fresh
/// anonymous mapping is zero-filled, so this is also the page's initial state.
#[cfg(target_os = "linux")]
const REPORT_NOT_REPORTED: i32 = 0;
/// Sentinel stored by the child when its `cgroup.procs` write succeeded. Negative so it can
/// never collide with an errno, which `write(2)` only ever reports as positive.
#[cfg(target_os = "linux")]
const REPORT_PLACED: i32 = -1;

/// A single machine word shared with the forked child (`MAP_SHARED | MAP_ANONYMOUS`), so the
/// self-placement write's outcome crosses back out of the child.
///
/// `pre_exec` runs after `fork`, where every ordinary channel is closed to it: the address
/// space is copy-on-write (the parent cannot see a normal store), and async-signal-safety
/// forbids allocating, formatting or locking. A shared anonymous page admits exactly one
/// async-signal-safe operation — an aligned atomic store of one `i32` — which is all a report
/// needs to be.
///
/// **One slot per LEAF, not per child.** The page belongs to the `CgroupLeaf`, and a production
/// spawn creates one leaf per child, so leaf and child coincide there. A caller that routes
/// several children through ONE leaf gets one slot for all of them, and the last store wins —
/// `placement_of` would then attribute the last child's outcome to whichever pid it was asked
/// about. Give each child its own [`ReportPage`] rather than sharing a leaf's.
///
/// # What this costs, and what it can cost a spawn
/// One `mmap` per contained spawn, held for the contained child's whole lifetime: the kernel
/// rounds the 4-byte length up to a page, so a live contained child holds **4 KiB of resident
/// memory and one VMA** in the supervisor.
///
/// The VMA, not the memory, is the ceiling. `vm.max_map_count` defaults to 65530 mappings per
/// process, and every live contained child spends one of them, so a supervisor holding tens of
/// thousands of contained children at once approaches a limit this mechanism introduced. At
/// that point `mmap` fails with `ENOMEM` and the spawn DEGRADES — it keeps its process group
/// and loses the fork-proof kill — rather than failing, which makes exhaustion quiet: weaker
/// containment, not an error. `LeafError::MapReportPage` is what makes it audible at all.
///
/// **Not a race.** The child stores its outcome strictly before `exec`, and `std`'s Unix
/// spawn does not return to the parent until the child has exec'd (it reads the child's
/// CLOEXEC error pipe to EOF). Every parent read therefore happens after the child's store,
/// ordered by the kernel through that pipe, not by timing.
#[cfg(target_os = "linux")]
pub(crate) struct ReportPage {
    ptr: *mut AtomicI32,
}

// Safety: the page is owned solely by this handle (never cloned, `munmap`ed exactly once by
// `Drop`), and every access to it goes through an atomic.
#[cfg(target_os = "linux")]
unsafe impl Send for ReportPage {}
#[cfg(target_os = "linux")]
unsafe impl Sync for ReportPage {}

#[cfg(target_os = "linux")]
impl ReportPage {
    pub(crate) fn new() -> io::Result<ReportPage> {
        // Test-only fault seam: fail the mapping (take semantics — see `fault`).
        #[cfg(test)]
        if fault::take_force_map_report_page_failure() {
            return Err(io::Error::from_raw_os_error(libc::ENOMEM));
        }
        // Safety: a fresh anonymous mapping — no caller-supplied address, length or fd.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                std::mem::size_of::<AtomicI32>(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let ptr = raw.cast::<AtomicI32>();
        // Anonymous pages are zero-filled and REPORT_NOT_REPORTED is 0, so this store changes
        // nothing — it states the initial sentinel instead of inheriting it from mmap's
        // guarantee, so renaming or renumbering the sentinel cannot silently desynchronize.
        // Safety: `ptr` is a live, aligned, writable mapping of exactly one AtomicI32.
        unsafe { (*ptr).store(REPORT_NOT_REPORTED, Ordering::SeqCst) };
        Ok(ReportPage { ptr })
    }

    /// A `Copy` handle to the page for capture by the `pre_exec` closure (which must not
    /// capture the owning `ReportPage`: the leaf keeps it, and the child must not `munmap`).
    pub(crate) fn slot(&self) -> ReportSlot {
        ReportSlot { ptr: self.ptr }
    }

    /// The child's report, read from the parent after the spawn has returned.
    pub(crate) fn read(&self) -> PlacementReport {
        // Safety: as above; the mapping outlives this handle.
        match unsafe { (*self.ptr).load(Ordering::SeqCst) } {
            REPORT_NOT_REPORTED => PlacementReport::NotReported,
            REPORT_PLACED => PlacementReport::Placed,
            errno => PlacementReport::WriteFailed(errno),
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for ReportPage {
    fn drop(&mut self) {
        // Safety: this handle owns the mapping and unmaps it exactly once.
        unsafe { libc::munmap(self.ptr.cast(), std::mem::size_of::<AtomicI32>()) };
    }
}

/// The child-side half of a [`ReportPage`]: a `Copy` pointer with one async-signal-safe
/// operation. Owns nothing — the parent's `ReportPage` unmaps the page.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
pub(crate) struct ReportSlot {
    ptr: *mut AtomicI32,
}

// Safety: a raw pointer to a shared mapping, with one operation — an atomic store — and one
// caller: the `pre_exec` closure, which the kernel invokes only between the fork and the exec
// of the single spawn the owning `CgroupLeaf` was created for. The leaf, and so the mapping, is
// alive across all of that.
//
// The closure can OUTLIVE the mapping: on the spawn-FAILURE path in `child::spawn`, `Prepared`
// (and with it the leaf's `munmap`) drops before the `Command` that still owns the closure. The
// pointer dangles from then on, which is sound only because nothing ever invokes the closure
// again — a `Command` whose spawn failed runs no further `pre_exec`.
//
// `Sync` as well as `Send` because `Command::pre_exec` requires both of its closure, and an
// atomic store adds no unsynchronized access when shared across threads.
#[cfg(target_os = "linux")]
unsafe impl Send for ReportSlot {}
#[cfg(target_os = "linux")]
unsafe impl Sync for ReportSlot {}

#[cfg(target_os = "linux")]
impl ReportSlot {
    /// Store the child's outcome. Async-signal-safe: one aligned atomic store, no allocation.
    ///
    /// # Safety
    /// The page this slot points at must still be mapped, which holds for as long as the
    /// `CgroupLeaf` that produced it is alive.
    unsafe fn report(self, value: i32) {
        // Safety: the caller guarantees the mapping is live; the store is atomic.
        unsafe { (*self.ptr).store(value, Ordering::SeqCst) };
    }
}

#[cfg(all(target_os = "linux", test))]
impl ReportSlot {
    /// Store `Placed` without any write, for tests of what cosca does with a report.
    ///
    /// # Safety
    /// As [`ReportSlot::report`].
    pub(crate) unsafe fn report_placed_for_test(self) {
        // Safety: the caller guarantees the mapping is live.
        unsafe { self.report(REPORT_PLACED) };
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
/// `Drop` closes the parent's `procs_fd` and removes the leaf directory,
/// firing `cgroup.kill` first if the leaf is still occupied — unless
/// [`CgroupLeaf::remove_unentered`] consumed it.
#[cfg(target_os = "linux")]
pub(crate) struct CgroupLeaf {
    /// Absolute path to the leaf directory, e.g. `/sys/fs/cgroup/…/cosca-<pid>`.
    leaf_path: PathBuf,
    /// Pre-opened `cgroup.procs` fd for the `pre_exec` write. Close-on-exec: the write happens
    /// between `fork` and `exec`, and no program this process starts may inherit it. Numbered
    /// 3 or above, so it never shares a number with the child's stdio.
    procs_fd: RawFd,
    /// Where the forked child reports whether its self-placement write succeeded.
    report: ReportPage,
    /// Whether `Drop` may write `cgroup.kill`. Cleared only by
    /// [`CgroupLeaf::remove_unentered`].
    may_hold_members: bool,
}

// Safety: RawFd is an integer. CgroupLeaf is not Clone; the fd is used only in
// the forked child (pre_exec write+close) and closed by Drop in the parent.
#[cfg(target_os = "linux")]
unsafe impl Send for CgroupLeaf {}

#[cfg(target_os = "linux")]
impl CgroupLeaf {
    /// Returns the raw `cgroup.procs` fd for capture in a `pre_exec` closure.
    pub(crate) fn procs_fd(&self) -> RawFd {
        self.procs_fd
    }

    /// The leaf's `cgroup.events` path — the drain edge. Both watches open it for themselves:
    /// the sync one polls it directly, while the reactor-native async one cannot reuse that
    /// `poll(2)` loop and registers the descriptor instead.
    pub(crate) fn events_path(&self) -> PathBuf {
        self.leaf_path.join("cgroup.events")
    }

    /// Remove a leaf its child never entered: close the fd and `rmdir`, never `cgroup.kill`.
    ///
    /// The child reported no successful write, so nothing it forks is in the leaf either.
    /// Whatever keeps the `rmdir` from succeeding, cosca did not put there, and killing it would
    /// kill a process cosca was never asked to contain.
    pub(crate) fn remove_unentered(mut self) {
        self.may_hold_members = false;
    }

    /// A `Copy` handle to this leaf's placement-report slot, for capture by the `pre_exec`
    /// closure.
    pub(crate) fn placement_slot(&self) -> ReportSlot {
        self.report.slot()
    }

    /// Whether `pid` entered this leaf: `Ok` when its own write into it succeeded.
    ///
    /// Used post-spawn (parent side). The child's report is the verdict: `cgroup.procs` lists
    /// only live tasks, so a placed child that has already exited reads back absent from it.
    /// Only a child that reported no successful write has `cgroup.procs` and its `/proc` state
    /// read, to diagnose why — see [`NotPlaced`].
    pub(crate) fn placement_of(&self, pid: u32) -> Result<(), NotPlaced> {
        let report = match self.report.read() {
            PlacementReport::Placed => return Ok(()),
            PlacementReport::NotReported => NotEntered::NotReported,
            PlacementReport::WriteFailed(errno) => NotEntered::WriteFailed(errno),
        };
        let path = self.leaf_path.join("cgroup.procs");
        let child_state = proc_state(pid);
        Err(match fs::read_to_string(&path) {
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
        })
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
    /// `close(-1)` and `remove_dir` of a nonexistent path are harmless no-ops — so it is
    /// usable ONLY for variant-level assertions, never for an operation that touches the
    /// fd or path.
    pub(crate) fn placeholder_for_test() -> CgroupLeaf {
        CgroupLeaf::for_test_at(PathBuf::from("/nonexistent/cosca-cgroup-placeholder"))
    }

    /// Test-only leaf pointing at `leaf_path`, which a test shapes with ordinary files and
    /// directories. Every operation that reads or writes the leaf path (`hard_kill`,
    /// `placement_of`, `Drop`) then runs for real against the kernel's own errnos, on any
    /// Linux host and without a cgroupfs. The fd is -1, so `close` is a no-op and nothing may
    /// write through `procs_fd`.
    pub(crate) fn for_test_at(leaf_path: PathBuf) -> CgroupLeaf {
        CgroupLeaf {
            leaf_path,
            procs_fd: -1,
            report: ReportPage::new().expect("map a placement-report page"),
            may_hold_members: true,
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for CgroupLeaf {
    fn drop(&mut self) {
        // Close the parent-side procs fd.
        // Safety: we own this fd; it was created by try_create_leaf and never cloned.
        unsafe { libc::close(self.procs_fd) };
        // Remove the leaf. If still occupied (e.g. hard_kill not yet called), fire cgroup.kill
        // to drain it, then retry. A leaf that outlives both attempts is reported.
        let Err(first) = fs::remove_dir(&self.leaf_path) else {
            return;
        };
        if !self.may_hold_members {
            if !removed_after_drain(&first) {
                warn_leaf_left_behind(
                    &self.leaf_path,
                    format_args!("rmdir failed ({first}); cgroup.kill not written: the child never entered it"),
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
        static FORCE_MAP_REPORT_PAGE_FAILURE: Cell<bool> = const { Cell::new(false) };
        static FORCE_OCCUPY_BEFORE_UNWIND: Cell<bool> = const { Cell::new(false) };
    }

    /// Treat the NEXT created leaf as exposing `cgroup.kill`. Supplies the single fact a temp
    /// directory cannot, so every step AFTER the check — the `cgroup.procs` open, the report
    /// mapping, and the unwind that removes the leaf — runs for real, against the kernel's own
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

    /// Fail the NEXT `ReportPage::new` with `ENOMEM` — the real exhaustion this mapping can
    /// hit (`vm.max_map_count`), which no test may provoke for real without taking the host's
    /// whole address space with it.
    pub(crate) fn set_force_map_report_page_failure(on: bool) {
        FORCE_MAP_REPORT_PAGE_FAILURE.with(|f| f.set(on));
    }
    pub(crate) fn take_force_map_report_page_failure() -> bool {
        FORCE_MAP_REPORT_PAGE_FAILURE.with(|f| f.replace(false))
    }
    pub(crate) fn map_report_page_failure_armed() -> bool {
        FORCE_MAP_REPORT_PAGE_FAILURE.with(|f| f.get())
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

    create_leaf_under(&Path::new("/sys/fs/cgroup").join(rel_path.trim_start_matches('/')))
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

    // The report page is mapped before the fd is opened so a failure here unwinds nothing but
    // the directory: a leaf whose child could not report its placement outcome would reopen
    // exactly the silence this module is reporting its way out of.
    let report = match ReportPage::new() {
        Ok(r) => r,
        Err(e) => return Err(fail(&leaf_path, LeafError::MapReportPage(e))),
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
        Ok(fd) => fd.into_raw_fd(),
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
        procs_fd,
        report,
        may_hold_members: true,
    })
}

/// Place the calling process into the pre-created cgroup leaf by writing `"0"`
/// to `procs_fd`, then close the fd so it does not propagate to grandchildren.
///
/// Called inside a `pre_exec` closure (post-fork, pre-exec). Returns `Ok` on
/// success. Returns `Err` if the write fails (e.g. `EBUSY` when the
/// supervisor's cgroup is itself a leaf — the "no internal processes" rule);
/// the caller (`pre_exec` registered by `dispatch::prepare`) maps `Err` to
/// `Ok(())` to fall back to the already-configured process group rather than
/// aborting the spawn.
///
/// The outcome — success, or the exact errno — is also stored in `slot` so it reaches the
/// parent. The `Err` return value cannot: it is discarded by design (a failed placement must
/// not abort the spawn), and nothing else the child computes survives its `exec`.
///
/// # Safety
/// Must be called only from a `pre_exec` closure. `procs_fd` must be a valid,
/// open, writable fd in the child process, and `slot`'s page must still be mapped.
/// Async-signal-safe: raw `libc::write` + `libc::close` + one atomic store, no allocation,
/// no format strings.
#[cfg(target_os = "linux")]
pub(crate) unsafe fn place_self_in_cgroup_pre_exec(procs_fd: RawFd, slot: ReportSlot) -> io::Result<()> {
    static ZERO: &[u8] = b"0";
    // Safety: ZERO is a valid buffer; procs_fd is valid (caller guarantees).
    let ret = unsafe { libc::write(procs_fd, ZERO.as_ptr().cast(), ZERO.len()) };
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
    if ret == -1 {
        // `write(2)` only ever sets a positive errno, but the report page's sentinels occupy
        // 0 and -1, so a nonsensical value is mapped to EIO rather than read back as a
        // fabricated "placed" or "not reported".
        let reported = if errno > 0 { errno } else { libc::EIO };
        // Safety: the caller guarantees the slot's page is mapped.
        unsafe { slot.report(reported) };
        Err(io::Error::from_raw_os_error(errno))
    } else {
        // Safety: as above.
        unsafe { slot.report(REPORT_PLACED) };
        Ok(())
    }
}

#[cfg(test)]
#[path = "cgroup_tests.rs"]
mod cgroup_tests;
