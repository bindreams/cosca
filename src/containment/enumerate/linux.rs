//! Linux `(pid, ppid)` snapshot: list the numeric entries of the checked `/proc`
//! (`identity::linux::proc_view`) and read field 4 of each `stat` via the comm-safe `parse_ppid`.

use crate::error::Error;
use crate::identity::stat_parse::parse_ppid;
use crate::identity::RawPid;

/// [`Error::Unassessable`], naming why, when `/proc` cannot be trusted or listed: an outer pid
/// namespace's `/proc` lists pids that mean nothing to the caller, and the tree walk signals by
/// pid. Never an empty snapshot standing in for that: a walk over one finds no descendants.
/// [`Error::Unsupported`] instead, naming the `openat2` requirement, when that is why no view
/// can be checked.
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
        // The process may exit between the listing and the read; that's just absence. A read the
        // checked directory refuses (it would cross a mount) is omitted too, and says so.
        let stat = match dir.read(&format!("{pid}/stat")) {
            Ok(stat) => stat,
            Err(e) if matches!(e.raw_os_error(), Some(libc::EXDEV | libc::ELOOP)) => {
                log::warn!(
                    "enumerate::process_parents: {pid}/stat lies beyond a mount in /proc and was not read ({e})"
                );
                continue;
            }
            Err(_) => continue,
        };
        if let Some(ppid) = parse_ppid(&stat) {
            out.push((pid, ppid));
        }
    }
    Ok(out)
}

/// Field 4 of `pid`'s `stat`. The kernel prints a parseable record for every pid, so a failure to
/// parse is [`Error::Unassessable`] naming the pid, never an absence.
#[allow(dead_code)]
fn ppid_of_stat(pid: RawPid, stat: &[u8]) -> Result<RawPid, Error> {
    parse_ppid(stat).ok_or_else(|| unassessable(&format!("{pid}/stat has no parseable ppid field"), None))
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
