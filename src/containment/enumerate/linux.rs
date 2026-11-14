//! Linux `(pid, ppid)` snapshot: list the numeric entries of the checked `/proc`
//! (`identity::linux::proc_view_with`) and read field 4 of each `stat` via the comm-safe `parse_ppid`.

use crate::error::Error;
use crate::identity::pid_file::{self, ReadOutcome};
use crate::identity::stat_parse::parse_ppid;
use crate::identity::Kernel;
use crate::identity::RawPid;
use crate::identity::{warn_refused, Refusal};

/// An outer pid namespace's `/proc` lists pids that mean nothing to the caller, and the tree walk
/// signals by pid, so it is an error, not a snapshot. So is every `stat` read that is not an
/// absence: the walk would miss that process and its subtree (see [`crate::identity::pid_file`]). A
/// [`Refusal`], wherever in the snapshot it is met, is [`Error::Unsupported`], warned about once.
pub(crate) fn process_parents(kernel: &dyn Kernel) -> Result<Vec<(RawPid, RawPid)>, Error> {
    let mut out = Vec::new();
    let dir = crate::identity::proc_view_with(kernel)
        .into_dir()
        .map_err(|why| match why.refusal() {
            Some(refusal) => refused(&refusal),
            None => unassessable(&why.reason, why.source),
        })?;
    let pids = kernel
        .pids(&dir)
        .map_err(|failure| match pid_file::open_refusal(&failure) {
            Some(refusal) => refused(&refusal),
            None => unassessable("/proc could not be listed", Some(failure.into_io())),
        })?;
    for pid in pids {
        let stat = match pid_file::read(kernel, &dir, pid, "stat") {
            Ok(ReadOutcome::Read(stat)) => stat,
            // The process exited between the listing and the read, or `hidepid` hides it.
            Ok(ReadOutcome::Exited(e) | ReadOutcome::Hidden(e)) => {
                log::debug!(
                    "enumerate::process_parents: {pid}/stat unreadable ({report}); omitting it",
                    report = crate::error::Report(&e)
                );
                continue;
            }
            Ok(ReadOutcome::Refused(refusal)) => return Err(refused(&refusal)),
            Err(unreadable) => return Err(stat_unreadable(unreadable)),
        };
        match ppid_of_stat(pid, &stat) {
            Ok(ppid) => out.push((pid, ppid)),
            Err(e) => {
                debug_assert!(
                    false,
                    "the kernel printed an unparseable stat: {}",
                    crate::error::Report(&e)
                );
                return Err(e);
            }
        }
    }
    Ok(out)
}

/// Field 4 of `pid`'s `stat`. The kernel prints a parseable record for every pid, so a failure to
/// parse is [`Error::Unassessable`] naming the pid, never an absence.
fn ppid_of_stat(pid: RawPid, stat: &[u8]) -> Result<RawPid, Error> {
    parse_ppid(stat).ok_or_else(|| unassessable(&format!("{pid}/stat has no parseable ppid field"), None))
}

/// What the snapshot's [`Error::Unsupported`] names as its `op`.
const OP_NAME: &str = "listing the process table";

/// The snapshot that a refusal ended, warned about here.
fn refused(refusal: &Refusal) -> Error {
    warn_refused("enumerate::process_parents", refusal.unsupported(OP_NAME))
}

fn stat_unreadable(unreadable: pid_file::Unreadable) -> Error {
    snapshot_failed(
        "the process snapshot could not be taken".to_owned(),
        Some(std::sync::Arc::new(unreadable.into_cause())),
    )
}

fn unassessable(why: &str, source: Option<std::io::Error>) -> Error {
    snapshot_failed(
        format!("the process snapshot could not be taken: {why}"),
        source.map(Error::io_cause),
    )
}

/// [`Error::Unassessable`] for a snapshot that failed, with the error behind it as its `source`.
fn snapshot_failed(detail: String, source: Option<std::sync::Arc<Error>>) -> Error {
    let error = Error::Unassessable { detail, source };
    log::warn!("enumerate::process_parents: {}", crate::error::Report(&error));
    error
}

#[cfg(test)]
#[path = "linux_tests.rs"]
mod linux_tests;

#[cfg(test)]
#[path = "linux_namespace_tests.rs"]
mod linux_namespace_tests;
