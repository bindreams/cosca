//! Linux `(pid, ppid)` snapshot: list the numeric entries of the checked `/proc`
//! (`identity::linux::proc_view`) and read field 4 of each `stat` via the comm-safe `parse_ppid`.

use crate::identity::stat_parse::parse_ppid;
use crate::identity::RawPid;

/// The snapshot is empty, with a `warn` naming why, when `/proc` cannot be trusted: an outer pid
/// namespace's `/proc` lists pids that mean nothing to the caller, and the tree walk signals by
/// pid.
pub(crate) fn process_parents() -> Vec<(RawPid, RawPid)> {
    let mut out = Vec::new();
    let dir = match crate::identity::proc_view().into_dir() {
        Ok(dir) => dir,
        Err(why) => {
            log::warn!("enumerate::process_parents: {why}; the process snapshot is empty");
            return out;
        }
    };
    let pids = match dir.pids() {
        Ok(pids) => pids,
        Err(e) => {
            log::warn!("enumerate::process_parents: /proc could not be listed ({e}); the process snapshot is empty");
            return out;
        }
    };
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
    out
}

#[cfg(test)]
#[path = "linux_tests.rs"]
mod linux_tests;

#[cfg(test)]
#[path = "linux_namespace_tests.rs"]
mod linux_namespace_tests;
