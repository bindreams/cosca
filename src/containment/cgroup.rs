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

// parse_v2_relative_path and cgroup_procs_contains are pure (no OS deps) —
// compiled on all platforms so their unit tests run on the Windows dev host.

/// Parse the `0::` (cgroup v2 unified hierarchy) line from the contents of
/// `/proc/self/cgroup`. Returns the relative path (e.g. `/user.slice/…`) on
/// success, or `None` when no such line is present (v1-only or empty).
///
/// Pure function (no I/O); intentionally compiled on all platforms so the unit
/// tests in `cgroup_tests.rs` run on the Windows dev host.
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

/// Check whether `pid` appears in the contents of a `cgroup.procs` file.
/// The file format is one pid per line (decimal, possibly with trailing
/// whitespace/newline); blank lines are skipped.
///
/// Pure function (no I/O); intentionally compiled on all platforms so the unit
/// tests in `cgroup_tests.rs` run on the Windows dev host.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn cgroup_procs_contains(contents: &str, pid: u32) -> bool {
    for line in contents.lines() {
        if let Ok(p) = line.trim().parse::<u32>() {
            if p == pid {
                return true;
            }
        }
    }
    false
}

// Everything below is Linux-only. =====

#[cfg(target_os = "linux")]
use std::fs::{self, File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::{IntoRawFd, RawFd};
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
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
/// firing `cgroup.kill` first if the leaf is still occupied.
#[cfg(target_os = "linux")]
pub(crate) struct CgroupLeaf {
    /// Absolute path to the leaf directory, e.g. `/sys/fs/cgroup/…/subprocess-<pid>`.
    leaf_path: PathBuf,
    /// Pre-opened `cgroup.procs` fd (O_CLOEXEC cleared) for the `pre_exec` write.
    procs_fd: RawFd,
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

    /// Returns `true` when `pid` is listed in `cgroup.procs` of this leaf.
    /// Used post-spawn (parent side) to confirm placement succeeded.
    pub(crate) fn contains_pid(&self, pid: u32) -> bool {
        match fs::read_to_string(self.leaf_path.join("cgroup.procs")) {
            Ok(contents) => cgroup_procs_contains(&contents, pid),
            Err(_) => false,
        }
    }

    /// Hard-kill all processes in the cgroup via `cgroup.kill` (kernel ≥ 5.14).
    /// Best-effort: already-empty leaves are silently fine.
    pub(crate) fn hard_kill(&self) {
        let _ = fs::write(self.leaf_path.join("cgroup.kill"), b"1");
    }

    /// SIGTERM every pid currently listed in `cgroup.procs`.
    ///
    /// # PID-reuse window
    /// This reads the pid list then signals each entry. Between the read and
    /// the signal a pid may exit and be recycled, potentially signalling an
    /// unrelated process. This is the same race as the process-group `SIGTERM`
    /// path; the cgroup mechanism's advantage (atomic, pid-free kill) applies
    /// only to `hard_kill` via `cgroup.kill`. The window is narrow and
    /// equivalent to the pgroup fallback — documented here for honesty.
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
        CgroupLeaf {
            leaf_path: PathBuf::from("/nonexistent/subprocess-cgroup-placeholder"),
            procs_fd: -1,
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for CgroupLeaf {
    fn drop(&mut self) {
        // Close the parent-side procs fd.
        // Safety: we own this fd; it was created by try_create_leaf and never cloned.
        unsafe { libc::close(self.procs_fd) };
        // Remove the leaf. If still occupied (e.g. hard_kill not yet called),
        // fire cgroup.kill to drain it, then retry. The second remove_dir may
        // still fail if the kernel hasn't finished reaping the killed tasks yet;
        // we accept this (the leaf will be cleaned up by the cgroup manager when
        // it finds it empty on next access, or by the slice's own teardown).
        if fs::remove_dir(&self.leaf_path).is_err() {
            let _ = fs::write(self.leaf_path.join("cgroup.kill"), b"1");
            let _ = fs::remove_dir(&self.leaf_path);
        }
    }
}

/// Detect the current process's cgroup v2 path and create a leaf sub-cgroup
/// for containment. Returns `None` on any failure so the caller falls back to
/// the process-group mechanism.
///
/// Failure conditions include: cgroup v2 not mounted at `/sys/fs/cgroup`,
/// current process not in a v2 cgroup (v1-only system), leaf directory not
/// writable (undelegated slice), or `cgroup.kill` absent (kernel < 5.14).
#[cfg(target_os = "linux")]
pub(crate) fn try_create_leaf() -> Option<CgroupLeaf> {
    let cgroup_file = fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel_path = parse_v2_relative_path(&cgroup_file)?;

    let current = Path::new("/sys/fs/cgroup").join(rel_path.trim_start_matches('/'));

    // Unique leaf name: pid + monotonic sequence counter avoids collisions when
    // the same process spawns on multiple threads simultaneously (same pid, but
    // different seq values mean different leaf names).
    // Safety: getpid() is always valid.
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let leaf_name = format!("subprocess-{}-{}", unsafe { libc::getpid() }, seq);
    let leaf_path = current.join(&leaf_name);

    fs::create_dir(&leaf_path).ok()?;

    // Require cgroup.kill (kernel ≥ 5.14); without it there is no atomic kill.
    if !leaf_path.join("cgroup.kill").exists() {
        let _ = fs::remove_dir(&leaf_path);
        return None;
    }

    // Open cgroup.procs for writing. O_CLOEXEC is set by default on Linux; clear
    // it explicitly so the fd survives fork+exec into the child.
    let procs_file: File = OpenOptions::new()
        .write(true)
        .open(leaf_path.join("cgroup.procs"))
        .ok()?;
    let procs_fd = procs_file.into_raw_fd();

    // Safety: procs_fd is valid.
    let flags = unsafe { libc::fcntl(procs_fd, libc::F_GETFD) };
    if flags == -1 {
        unsafe { libc::close(procs_fd) };
        let _ = fs::remove_dir(&leaf_path);
        return None;
    }
    if unsafe { libc::fcntl(procs_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } == -1 {
        unsafe { libc::close(procs_fd) };
        let _ = fs::remove_dir(&leaf_path);
        return None;
    }

    Some(CgroupLeaf { leaf_path, procs_fd })
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
/// # Safety
/// Must be called only from a `pre_exec` closure. `procs_fd` must be a valid,
/// open, writable fd in the child process. Async-signal-safe: raw `libc::write`
/// + `libc::close`, no allocation, no format strings.
#[cfg(target_os = "linux")]
pub(crate) unsafe fn place_self_in_cgroup_pre_exec(procs_fd: RawFd) -> io::Result<()> {
    static ZERO: &[u8] = b"0";
    // Safety: ZERO is a valid buffer; procs_fd is valid (caller guarantees).
    let ret = unsafe { libc::write(procs_fd, ZERO.as_ptr().cast(), ZERO.len()) };
    // Always close the fd — even on error — so it does not propagate to children.
    // Safety: procs_fd is valid; close is async-signal-safe.
    unsafe { libc::close(procs_fd) };
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "cgroup_tests.rs"]
mod cgroup_tests;
