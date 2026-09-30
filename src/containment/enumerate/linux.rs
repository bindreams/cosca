//! Linux `(pid, ppid)` snapshot: list the numeric entries of the checked `/proc`
//! (`identity::linux::proc_view`) and read field 4 of each `stat` via the comm-safe `parse_ppid`.

use crate::error::Error;
use crate::identity::pid_stat::{self, PidStat};
use crate::identity::stat_parse::parse_ppid;
use crate::identity::RawPid;

/// An outer pid namespace's `/proc` lists pids that mean nothing to the caller, and the tree walk
/// signals by pid, so it is an error, not a snapshot. So is every `stat` read that is not an
/// absence: the walk would miss that process and its subtree (see [`crate::identity::pid_stat`]).
pub(crate) fn process_parents() -> Result<Vec<(RawPid, RawPid)>, Error> {
    let mut out = Vec::new();
    let dir =
        crate::identity::proc_view()
            .into_dir()
            .map_err(|why| match why.unsupported("listing the process table") {
                Some(unsupported) => {
                    log::warn!("enumerate::process_parents: {unsupported}");
                    unsupported
                }
                None => unassessable(&why.reason, why.source),
            })?;
    let pids = dir
        .pids()
        .map_err(|e| unassessable("/proc could not be listed", Some(e)))?;
    for pid in pids {
        let stat = match pid_stat::read(&dir, pid) {
            Ok(PidStat::Read(stat)) => stat,
            // The process exited between the listing and the read, or `hidepid` hides it.
            Ok(PidStat::Skipped(e)) => {
                log::debug!("enumerate::process_parents: {pid}/stat unreadable ({e}); omitting it");
                continue;
            }
            Err(unreadable) => return Err(stat_unreadable(unreadable)),
        };
        match ppid_of_stat(pid, &stat) {
            Ok(ppid) => out.push((pid, ppid)),
            Err(e) => {
                debug_assert!(false, "the kernel printed an unparseable stat: {e}");
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

fn stat_unreadable(unreadable: pid_stat::Unreadable) -> Error {
    let detail = format!("the process snapshot could not be taken: {unreadable}");
    log::warn!("enumerate::process_parents: {detail}");
    Error::Unassessable {
        detail,
        source: Some(unreadable.into_source()),
    }
}

fn unassessable(why: &str, source: Option<std::io::Error>) -> Error {
    let mut detail = format!("the process snapshot could not be taken: {why}");
    if let Some(source) = &source {
        detail.push_str(&format!(": {source}"));
    }
    log::warn!("enumerate::process_parents: {detail}");
    Error::Unassessable { detail, source }
}

#[cfg(test)]
#[path = "linux_tests.rs"]
mod linux_tests;

#[cfg(test)]
#[path = "linux_namespace_tests.rs"]
mod linux_namespace_tests;
