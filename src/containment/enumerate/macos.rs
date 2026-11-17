//! macOS `(pid, ppid)` snapshot: the pid set from `Kernel::pids`, then
//! `identity::macos_ppid_of` per pid (the same `proc_pidinfo`-primary,
//! sysctl-fallback resolver `identity` uses for its own start token / liveness checks).
//!
//! Two things worth knowing (an EPERM gap — an unprivileged caller getting no edge for
//! another user's process — is CLOSED: `identity::macos_ppid_of` falls back to
//! `sysctl(KERN_PROC_PID)` on a `proc_pidinfo` miss, the same fallback `identity` itself uses
//! for zombies and EPERM-hidden cross-user processes):
//!
//! - Even with the fallback, an edge can still be dropped: the target pid genuinely exited
//!   between the snapshot and the query, or a sandbox denies the fallback's own sysctl
//!   (EPERM/EACCES there is a DESIGNED, persistent `Unknown`, not a second EPERM gap). An
//!   `e_ppid == 0` mid fork() on both reads is transient and never surfaces: `ppid_of` re-reads
//!   it until it resolves (pids 0 and 1 excepted — see `identity::macos::trusted_ppid`'s doc).
//! - A failed snapshot, or a pid denied its ppid read, is `Error::Unassessable` from
//!   `process_parents`, never an empty or partial list: a tree walk over one skips the subtree.
//!   [`snapshot`] is the other consumer (the fd-marker sweep): it reports a failure as an empty
//!   pid list, which that sweep treats as a blind pass, and a denial as a count it returns beside
//!   the edges it could read.

use crate::error::Error;
use crate::identity::{Kernel, RawPid, Resolved};

/// How many denied pids to name in a snapshot's log line — enough to start a debugging
/// session from, not so many that a snapshot with hundreds of denials floods the log.
const DENIED_SAMPLE_CAP: usize = 5;

/// Read the parent pid of `pid` via `identity::macos_ppid_of` — `proc_pidinfo` primary,
/// sysctl fallback on a miss, and the shared zero-ppid guard, all owned by `identity::macos`
/// (see that module's `ppid_of` doc for why: this backend reuses it whole rather than
/// keeping a second `proc_pidinfo` call and a second copy of the guard here). The tri-state is
/// forwarded whole, not collapsed to `Option`: [`join_edges`] needs to tell a genuine absence
/// (`Gone` — the pid exited, a legitimate exclusion) apart from a refused query (`Unknown` —
/// a persistent sandboxed sysctl refusal, a real gap in the ppid-walk channel, not a
/// legitimate one; the transient fork-in-progress window is resolved inside `ppid_of`). Silent
/// per-call either way: a dropped edge drops the pid's whole subtree in
/// `treewalk::descendants_with`, and [`snapshot`] is what surfaces the aggregate.
fn ppid_of(kernel: &dyn Kernel, pid: libc::c_int) -> Resolved<RawPid> {
    crate::identity::macos_ppid_of(kernel, pid as RawPid)
}

/// A failure reported as an empty list (logged): [`snapshot`]'s contract.
fn all_pids_or_empty(pids: std::io::Result<Vec<libc::c_int>>) -> Vec<libc::c_int> {
    pids.unwrap_or_else(|e| {
        log::warn!(
            "enumerate: pid snapshot failed ({report}) - callers see an EMPTY process table, \
             so a tree walk over it finds no descendants",
            report = crate::error::Report(&e)
        );
        Vec::new()
    })
}

/// Push `pid` onto `sample` unless it is already at [`DENIED_SAMPLE_CAP`]. Factored out of
/// [`join_edges`] so the cap is unit-testable on its own.
fn push_denied_sample(sample: &mut Vec<libc::c_int>, pid: libc::c_int) {
    if sample.len() < DENIED_SAMPLE_CAP {
        sample.push(pid);
    }
}

/// The edges, the denied-read count, and a sample of the denied pids.
type Joined = (Vec<(RawPid, RawPid)>, usize, Vec<libc::c_int>);

/// Join pids to `(pid, ppid)` edges, filtering non-positive pids first, reading each parent through
/// `kernel`.
///
/// Returns the edges, how many pids the OS DENIED a ppid read for, and a bounded sample of the
/// denied pids for logging. A `Gone` pid is a legitimate exclusion, since it simply exited, and is
/// not counted; only `Unknown` is, since that subtree is a real gap in the ppid-walk channel:
/// [`process_parents`] fails on it, [`snapshot`] returns the count.
fn join_edges(kernel: &dyn Kernel, pids: &[libc::c_int]) -> Joined {
    let mut edges = Vec::with_capacity(pids.len());
    let mut denied = 0usize;
    let mut sample = Vec::new();
    for &pid in pids {
        if pid <= 0 {
            continue; // pid 0 is the kernel process, not a real ppid edge
        }
        match ppid_of(kernel, pid) {
            Resolved::Found(ppid) => edges.push((pid as RawPid, ppid)),
            Resolved::Gone => {}
            Resolved::Unknown => {
                denied += 1;
                push_denied_sample(&mut sample, pid);
            }
        }
    }
    (edges, denied, sample)
}

/// [`Error::Unassessable`] naming the `proc_listallpids` failure when no pid list can be taken,
/// or the count and a sample of the pids denied a ppid read: each leaves its subtree out of the
/// edges, and a walk over them would skip it. [`snapshot`] applies its own policy to the same denial.
/// The pids are listed, and each parent read, through `kernel`.
pub(crate) fn process_parents(kernel: &dyn Kernel) -> Result<Vec<(RawPid, RawPid)>, Error> {
    let raw = kernel.pids().map_err(|e| {
        let error = Error::Unassessable {
            detail: "the process snapshot could not be taken: proc_listallpids failed".to_owned(),
            source: Some(Error::io_cause(e)),
        };
        log::warn!("enumerate::process_parents: {}", crate::error::Report(&error));
        error
    })?;
    let (edges, denied, sample) = join_edges(kernel, &raw);
    if denied > 0 {
        let detail = format!(
            "the process snapshot could not be taken: {denied} of {} pids denied a ppid read, so their \
             subtrees are missing from it; sample: {sample:?}",
            raw.len()
        );
        log::warn!("enumerate::process_parents: {detail}");
        return Err(Error::Unassessable { detail, source: None });
    }
    Ok(edges)
}

/// One `debug` line per snapshot, not per denied pid.
fn log_denied(denied: usize, total: usize, sample: &[libc::c_int]) {
    if denied > 0 {
        log::debug!(
            "containment snapshot: {denied} of {total} pids denied a ppid read; their subtrees are \
             invisible to the ppid-walk channel this round; sample: {sample:?}"
        );
    }
}

/// Every listable pid, the `(pid, ppid)` edges readable from those pids, and how many pids the
/// OS DENIED a ppid read for (as opposed to simply having exited) — all from ONE enumeration,
/// so the ppid-walk teardown channel and macOS's fd-marker sweep (which additionally needs the
/// raw pid list to search for marker holders) cannot disagree about the host. All of it is read
/// through `kernel`.
///
/// A denied pid's subtree is a real gap in the ppid-walk channel — e.g. after a
/// credential-changing `exec`, the same scenario the marker channel already names — not a
/// legitimate absence like a pid that simply exited. `snapshot` logs the count (at `debug`) and
/// returns it; `Marker::sweep` does not fold it into `incomplete`, and its doc says why.
pub(crate) fn snapshot(kernel: &dyn Kernel) -> (Vec<RawPid>, Vec<(RawPid, RawPid)>, usize) {
    let raw = all_pids_or_empty(kernel.pids());
    let (edges, denied, sample) = join_edges(kernel, &raw);
    log_denied(denied, raw.len(), &sample);
    let pids = raw.into_iter().filter(|&p| p > 0).map(|p| p as RawPid).collect();
    (pids, edges, denied)
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;
