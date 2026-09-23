//! Pure parsers of cgroup and `/proc` text — no OS deps — compiled on all platforms so their
//! unit tests run on any host.

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

#[cfg(test)]
#[path = "parse_tests.rs"]
mod parse_tests;
