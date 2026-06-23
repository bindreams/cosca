//! Linux `(pid, ppid)` snapshot: iterate the numeric directories under `/proc`
//! and read field 4 of each `stat` via the comm-safe `parse_ppid`.

use crate::identity::stat_parse::parse_ppid;
use crate::identity::RawPid;

pub(crate) fn process_parents() -> Vec<(RawPid, RawPid)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return out;
    };
    for entry in entries.flatten() {
        // /proc/<pid> directories are named by their decimal pid; skip the rest.
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<RawPid>().ok()) else {
            continue;
        };
        // The process may exit between read_dir and read; that's just absence.
        let Ok(stat) = std::fs::read(format!("/proc/{pid}/stat")) else {
            continue;
        };
        if let Some(ppid) = parse_ppid(&stat) {
            out.push((pid, ppid));
        }
    }
    out
}
